#!/usr/bin/env python3
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
#  Single-node integration tests for the blobstore md journal
#  (lib/blob/blob_md_journal.c), cases I1-I5 of md_journal_test_plan.md,
#  without the ultra stack: a real spdk_tgt with an lvstore on a
#  file-backed AIO bdev (large enough that the journal activates),
#  driven over RPC.
#
#  I1  regular ops: lvol/snapshot lifecycle under an active journal
#  I2  sudden power-off: kill -9 mid create/delete workload, restart,
#      every RPC-acked object present, every acked delete gone, no
#      torn-md load abort; repeated rounds
#  I3  torn-write injection: garbage / fake-header 512B sectors written
#      into empty ring slots while down -> load recovers/ignores
#  I4  journal pressure: parallel mass create/delete, all ops succeed
#  I5  restart-recovery drain: ring drains to all-zero after restart,
#      objects intact
#
#  Run as root on the build host:  sudo python3 mdj_integration.py

import json
import os
import random
import signal
import struct
import subprocess
import sys
import threading
import time

SPDK_DIR = os.environ.get("SPDK_DIR", "/home/ec2-user/spdk")
SPDK_TGT = f"{SPDK_DIR}/build/bin/spdk_tgt"
RPC_PY = f"{SPDK_DIR}/scripts/rpc.py"
SOCK = "/var/tmp/mdj_it.sock"
TGT_LOG = "/tmp/mdj_tgt.log"
IMG = os.environ.get("MDJ_IMG", "/home/ec2-user/mdj_aio.img")
IMG_SIZE = 4 * 1024 ** 3
BLOCKLEN = 4096
RING_BYTES = 64 * 1024 ** 2
RING_START = IMG_SIZE - RING_BYTES
ENTRY_BYTES = 8192
NUM_SLOTS = RING_BYTES // ENTRY_BYTES
HDR_MAGIC = 0x4D444A31
LVS = "lvs0"

g_tgt = None
g_failures = []


def fail(msg):
    print(f"    FAIL: {msg}")
    g_failures.append(msg)


def check(cond, msg):
    if cond:
        return True
    fail(msg)
    return False


# ------------------------------------------------------------------ #
# target / rpc plumbing                                               #

def rpc_raw(*args, timeout=90):
    return subprocess.run(
        [sys.executable, RPC_PY, "-s", SOCK, "-t", str(timeout)] + [str(a) for a in args],
        capture_output=True, text=True)


def rpc(*args):
    p = rpc_raw(*args)
    if p.returncode != 0:
        raise RuntimeError(f"rpc {args[0]} failed: {p.stderr.strip()[:300]}")
    return p.stdout


def rpc_json(*args):
    return json.loads(rpc(*args))


def start_tgt():
    global g_tgt
    logf = open(TGT_LOG, "a")
    logf.write(f"\n===== tgt start {time.ctime()} =====\n")
    logf.flush()
    # --disable-cpumask-locks: kill -9 rounds leave stale core-lock files
    g_tgt = subprocess.Popen([SPDK_TGT, "-r", SOCK, "-m", "0x3", "-s", "1024",
                              "--disable-cpumask-locks"],
                             stdout=logf, stderr=logf)
    deadline = time.time() + 60
    while time.time() < deadline:
        if rpc_raw("rpc_get_methods", timeout=2).returncode == 0:
            return
        if g_tgt.poll() is not None:
            raise RuntimeError(f"spdk_tgt exited at startup, rc={g_tgt.returncode}, see {TGT_LOG}")
        time.sleep(0.25)
    raise RuntimeError("spdk_tgt did not come up")


def kill9_tgt():
    g_tgt.send_signal(signal.SIGKILL)
    g_tgt.wait()


def stop_tgt_clean():
    g_tgt.send_signal(signal.SIGTERM)
    try:
        g_tgt.wait(timeout=60)
    except subprocess.TimeoutExpired:
        g_tgt.kill()
        g_tgt.wait()


def attach_and_load():
    """Create the AIO bdev; lvol examine loads the lvstore (journal
    recovery runs inside spdk_bs_load). Returns the loaded lvstore."""
    rpc("bdev_aio_create", IMG, "aio0", BLOCKLEN)
    deadline = time.time() + 120
    while time.time() < deadline:
        stores = rpc_json("bdev_lvol_get_lvstores")
        if stores and stores[0]["name"] == LVS:
            # let examine finish registering all lvol bdevs
            prev = -1
            while time.time() < deadline:
                cur = len(present_lvols())
                if cur == prev:
                    return stores[0]
                prev = cur
                time.sleep(0.5)
        time.sleep(0.25)
    raise RuntimeError("lvstore did not load within 120s (torn-md load abort?)")


def present_lvols():
    """Set of 'name' for every lvol/snapshot bdev of LVS."""
    out = set()
    for b in rpc_json("bdev_get_bdevs"):
        for a in b.get("aliases", []):
            if a.startswith(f"{LVS}/"):
                out.add(a.split("/", 1)[1])
    return out


def journal_active_in_log():
    with open(TGT_LOG) as f:
        return "md journal enabled" in f.read()


# ------------------------------------------------------------------ #
# ring inspection on the raw backing file (target must be down)       #

def ring_slots():
    """Return (valid_slots, nonzero_slots) parsed from the ring.
    The target writes with O_DIRECT, our reads are buffered: drop the
    page cache first so we see the platter state."""
    valid, nonzero = [], []
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("1")
    with open(IMG, "rb") as f:
        f.seek(RING_START)
        ring = f.read(RING_BYTES)
    for s in range(NUM_SLOTS):
        entry = ring[s * ENTRY_BYTES:(s + 1) * ENTRY_BYTES]
        if any(entry):
            nonzero.append(s)
            magic = struct.unpack_from("<I", entry, 0)[0]
            if magic == HDR_MAGIC:
                valid.append(s)
    return valid, nonzero


def corrupt_ring_slot(slot, data):
    with open(IMG, "r+b") as f:
        f.seek(RING_START + slot * ENTRY_BYTES)
        f.write(data)


# ------------------------------------------------------------------ #
# workload with ack tracking (for kill -9 rounds)                     #

class Workload(threading.Thread):
    """Loop of lvol create / snapshot / delete RPCs. Tracks which ops
    were acknowledged (RPC returned success). An op in flight when the
    target dies is 'indeterminate'."""

    def __init__(self, tag):
        super().__init__(daemon=True)
        self.tag = tag
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.acked_alive = set()     # created (or snapshotted), not deleted
        self.acked_deleted = set()
        self.indeterminate = set()
        self.ops = 0

    def _op(self, kind, name, *args):
        with self.lock:
            self.indeterminate.add(name)
        p = rpc_raw(*args)
        with self.lock:
            self.indeterminate.discard(name)
            if p.returncode == 0:
                self.ops += 1
                if kind == "del":
                    self.acked_alive.discard(name)
                    self.acked_deleted.add(name)
                else:
                    self.acked_alive.add(name)
                    self.acked_deleted.discard(name)
            else:
                # failed op (e.g. target died): outcome unknown
                self.indeterminate.add(name)

    def run(self):
        i = 0
        while not self.stop_ev.is_set():
            name = f"{self.tag}_l{i}"
            self._op("add", name, "bdev_lvol_create", "-l", LVS, "-t", name, 8)
            if self.stop_ev.is_set():
                break
            if i % 3 == 0:
                snap = f"{self.tag}_s{i}"
                self._op("add", snap, "bdev_lvol_snapshot", f"{LVS}/{name}", snap)
            if i % 2 == 0:
                self._op("del", name, "bdev_lvol_delete", f"{LVS}/{name}")
            i += 1


def verify_after_restart(workloads, when):
    present = present_lvols()
    alive = set()
    deleted = set()
    indet = set()
    for w in workloads:
        alive |= w.acked_alive
        deleted |= w.acked_deleted
        indet |= w.indeterminate
    ok = True
    missing = (alive - indet) - present
    ok &= check(not missing, f"{when}: acked objects missing after restart: {sorted(missing)[:5]}")
    resurrected = (deleted - indet) & present
    ok &= check(not resurrected, f"{when}: acked-deleted objects resurrected: {sorted(resurrected)[:5]}")
    # anything extra must stem from an in-flight (unacked) op
    ours = {n for n in present if n.startswith("r")}
    extra = ours - alive - indet
    ok &= check(not extra, f"{when}: unexplained objects present: {sorted(extra)[:5]}")
    return ok


# ------------------------------------------------------------------ #
# tests                                                               #

def t1_regular_ops():
    print("I1  regular ops under active journal")
    rpc("bdev_lvol_create_lvstore", "aio0", LVS)
    for i in range(20):
        rpc("bdev_lvol_create", "-l", LVS, "-t", f"base{i}", 8)
    for i in range(0, 20, 4):
        rpc("bdev_lvol_snapshot", f"{LVS}/base{i}", f"basesnap{i}")
    for i in range(0, 20, 5):
        rpc("bdev_lvol_resize", f"{LVS}/base{i}", 16)
    for i in range(1, 20, 4):
        rpc("bdev_lvol_delete", f"{LVS}/base{i}")
    present = present_lvols()
    expect = ({f"base{i}" for i in range(20)} - {f"base{i}" for i in range(1, 20, 4)}) | \
             {f"basesnap{i}" for i in range(0, 20, 4)}
    check(present == expect, f"I1: lvol listing mismatch: missing={expect - present} extra={present - expect}")
    stores = rpc_json("bdev_lvol_get_lvstores")
    check(len(stores) == 1, "I1: lvstore missing")
    check(journal_active_in_log(), "I1: journal not active (no 'md journal enabled' in log)")
    # clean restart must preserve everything
    stop_tgt_clean()
    start_tgt()
    attach_and_load()
    check(present_lvols() == expect, "I1: objects differ after clean restart")
    print(f"    ok ({len(expect)} objects)")


def t2_kill9_rounds(rounds=4):
    print(f"I2  sudden power-off: {rounds} kill -9 rounds mid-workload")
    baseline = present_lvols()
    all_workloads = []
    for r in range(rounds):
        ws = [Workload(f"r{r}w{k}") for k in range(3)]
        for w in ws:
            w.start()
        time.sleep(random.uniform(2.0, 5.0))
        kill9_tgt()                      # power off
        for w in ws:
            w.stop_ev.set()
        for w in ws:
            w.join(timeout=30)
        all_workloads.extend(ws)
        ops = sum(w.ops for w in ws)
        start_tgt()
        attach_and_load()                # must not abort on torn md
        okrnd = verify_after_restart(all_workloads, f"I2 round {r}")
        print(f"    round {r}: {ops} acked ops, "
              f"{len(present_lvols())} objects, verify={'ok' if okrnd else 'FAIL'}")
    missing_base = baseline - present_lvols()
    check(not missing_base, f"I2: pre-existing objects lost: {sorted(missing_base)[:5]}")
    return all_workloads


g_injected_slots = set()


def t3_torn_injection(all_workloads):
    print("I3  torn-write injection into the ring while down")
    kill9_tgt()
    valid, nonzero = ring_slots()
    print(f"    ring at power-off: {len(valid)} valid / {len(nonzero)} non-zero slots")
    # torn header: a copied valid header (magic ok) over a zero payload ->
    # crc mismatch -> must be treated as empty
    with open(IMG, "rb") as f:
        if valid:
            f.seek(RING_START + valid[0] * ENTRY_BYTES)
            fake_hdr = f.read(512)
        else:
            fake_hdr = struct.pack("<IIQ", HDR_MAGIC, 0xDEADBEEF, 12345) + b"\0" * 492
    empties = [s for s in range(NUM_SLOTS) if s not in set(nonzero)]
    # a real torn write sits at the ring head (the in-flight entry at
    # power-off): that slot is reused by the next append. Also inject
    # far from the head - such garbage stays until the head wraps and
    # is treated as empty forever (I5 accounts for it).
    torn1, torn2 = (max(valid) + 1) % NUM_SLOTS if valid else empties[0], empties[-2]
    corrupt_ring_slot(torn1, fake_hdr)                    # fake header, no payload
    corrupt_ring_slot(torn2, os.urandom(512))             # random garbage sector
    g_injected_slots.update({torn1, torn2})
    start_tgt()
    attach_and_load()   # raises on load abort
    check(verify_after_restart(all_workloads, "I3"), "I3: object set wrong after torn injection")
    print(f"    ok (torn slots {torn1},{torn2} ignored, store loaded)")


def t4_mass_pressure():
    print("I4  journal pressure: parallel mass create/delete")
    errs = []

    def storm(k):
        for i in range(40):
            name = f"m{k}_{i}"
            p = rpc_raw("bdev_lvol_create", "-l", LVS, "-t", name, 4)
            if p.returncode != 0:
                errs.append(f"create {name}: {p.stderr.strip()[:120]}")
                continue
            p = rpc_raw("bdev_lvol_delete", f"{LVS}/{name}")
            if p.returncode != 0:
                errs.append(f"delete {name}: {p.stderr.strip()[:120]}")

    ts = [threading.Thread(target=storm, args=(k,)) for k in range(6)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.time() - t0
    check(not errs, f"I4: {len(errs)} ops failed, first: {errs[:2]}")
    check(not any(n.startswith("m") for n in present_lvols()), "I4: leftover mass lvols")
    print(f"    ok (480 create/delete pairs in {dt:.1f}s, 0 errors)")


def t5_ring_drain(all_workloads):
    print("I5  restart-recovery drain: ring empties while live, objects intact")
    # power off with a recovery backlog in the ring, restart, then let
    # the drain poller work it off during idle runtime
    kill9_tgt()
    valid, nonzero = ring_slots()
    print(f"    backlog at power-off: {len(valid)} valid / {len(nonzero)} non-zero slots")
    start_tgt()
    attach_and_load()
    before = present_lvols()
    deadline = time.time() + 120
    valid, leftover = None, None
    while time.time() < deadline:
        time.sleep(3)
        # the target only touches the ring on md writes; idle store ->
        # a read-only look at the backing file is stable
        valid, nonzero = ring_slots()
        # inert garbage injected by I3 far from the head is empty by
        # definition and only reclaimed when the head wraps over it
        leftover = [s for s in nonzero if s not in g_injected_slots]
        if not valid and not leftover:
            break
    check(valid == [], f"I5: {len(valid or [])} valid entries never drained")
    check(leftover == [], f"I5: {len(leftover or [])} unexplained non-zero slots after idle drain")
    check(present_lvols() == before, "I5: objects changed while draining")
    # a final power-off on the fully-drained ring must recover to the
    # same object set (empty-ring recovery path)
    kill9_tgt()
    start_tgt()
    attach_and_load()
    check(present_lvols() == before, "I5: objects differ after empty-ring recovery")
    check(verify_after_restart(all_workloads, "I5"), "I5: final object set wrong")
    print(f"    ok ({len(before)} objects, all journal entries drained+zeroed)")


def crc32c_raw(data):
    """spdk_crc32c_update(buf, len, 0): raw reflected CRC32C (Castagnoli),
    init as passed (0), no final inversion."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


def t6_torn_home_repair(all_workloads):
    """I6: THE torn-write-protection scenario, synthesized deterministically.

    Neither kill -9 (io_submit'ed IOs complete in-kernel; unsubmitted ones
    never start) nor AWS Nitro storage (16 KiB torn-write prevention on
    EBS/instance store) can produce naturally torn 4K writes on this rig,
    so the power-loss state of 512B-atomic storage is synthesized: valid
    ring entries holding the newest md pages, with the corresponding HOME
    pages torn mid-write. Load must repair every one of them byte-exactly
    from the ring."""
    print("I6  torn home md pages repaired from the ring")
    # quiesce with a drained ring (idle store drains fast); inert garbage
    # slots injected by I3 are empty by definition and stay until the
    # head wraps over them
    valid, leftover = None, None
    for _ in range(3):
        kill9_tgt()
        valid, nonzero = ring_slots()
        leftover = [s for s in nonzero if s not in g_injected_slots]
        if not valid and not leftover:
            break
        start_tgt()
        attach_and_load()
        time.sleep(5)
    if not check(valid == [] and leftover == [],
                 f"I6: could not reach a drained ring (valid={valid} other={leftover})"):
        return

    with open(IMG, "rb") as f:
        img_read = f.read(1028 * BLOCKLEN)

    def page(lba):
        return img_read[lba * BLOCKLEN:(lba + 1) * BLOCKLEN]

    # three blob md pages (deep in the md region: stable during idle load)
    victims = [l for l in range(100, 1028) if any(page(l))][:3]
    check(len(victims) == 3, f"I6: found only {len(victims)} blob md pages to tear")
    saved = {l: page(l) for l in victims}
    super_page = page(0)

    with open(IMG, "r+b") as f:
        # synthetic ring entries (slots 0..3): [header][newest page]
        for slot, lba in enumerate(victims + [0]):
            content = saved.get(lba, super_page)
            hdr = struct.pack("<IIQ", HDR_MAGIC, crc32c_raw(content), lba)
            f.seek(RING_START + slot * ENTRY_BYTES)
            f.write(hdr + b"\0" * (BLOCKLEN - len(hdr)) + content)
        # tear the home pages mid-write (512B sectors are atomic, the 4K
        # write is not): garbage in sectors 2-5 of each blob page, sector
        # 2 of the super (signature+flag in sector 0 stay readable)
        for lba in victims:
            f.seek(lba * BLOCKLEN + 1024)
            f.write(b"\xFF" * 2048)
        f.seek(1024)
        f.write(b"\xFF" * 512)

    with open(TGT_LOG) as f:
        log_mark = len(f.read())

    start_tgt()
    attach_and_load()   # torn super/blob pages unrepaired => load abort
    check(verify_after_restart(all_workloads, "I6"), "I6: object set wrong after torn-home repair")

    # the drain must land the ring copies home, byte-exact
    deadline = time.time() + 60
    while time.time() < deadline:
        time.sleep(3)
        valid, _ = ring_slots()
        if not valid:
            break
    check(valid == [], "I6: synthetic entries never drained")
    with open(IMG, "rb") as f:
        for lba in victims:
            f.seek(lba * BLOCKLEN)
            repaired = f.read(BLOCKLEN)
            check(repaired == saved[lba], f"I6: home page lba {lba} not repaired byte-exactly")

    with open(TGT_LOG) as f:
        f.seek(log_mark)
        boot_log = f.read()
    check("crc mismatch" not in boot_log, "I6: md crc errors during repaired load")
    check("Metadata page" not in boot_log, "I6: blob md errors during repaired load")
    print(f"    ok (3 torn blob md pages + torn super repaired from ring, lbas {victims})")


def main():
    random.seed(20260804)
    if os.geteuid() != 0:
        print("must run as root (hugepages/spdk_tgt)")
        return 1
    subprocess.run(["pkill", "-9", "-x", "spdk_tgt"], capture_output=True)
    if os.path.exists(IMG):
        os.unlink(IMG)
    with open(IMG, "wb") as f:
        f.truncate(IMG_SIZE)

    start_tgt()
    rpc("bdev_aio_create", IMG, "aio0", BLOCKLEN)

    t1_regular_ops()
    workloads = t2_kill9_rounds()
    t3_torn_injection(workloads)
    t4_mass_pressure()
    t5_ring_drain(workloads)
    t6_torn_home_repair(workloads)

    stop_tgt_clean()
    print()
    if g_failures:
        print(f"RESULT: {len(g_failures)} FAILURE(S)")
        for m in g_failures:
            print(f"  - {m}")
        return 1
    print("RESULT: all integration tests passed (I1-I6)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
