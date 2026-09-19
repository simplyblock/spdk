#!/usr/bin/env python3
#  Integration test for bdev_lvol_snapshot_group against ONE running spdk_tgt.
#
#  Driven by consistency_group_it.sh, which starts the target and hands us the
#  RPC socket. Members are exported over NVMe-oF TCP on loopback and exercised
#  through the KERNEL nvme initiator, so the freeze window and its release are
#  observed exactly the way a real host observes them.
#
#  T1  group snapshot under live IO: all member snapshots exist, each holds a
#      consistent point-in-time (pre-freeze pattern intact, the concurrently
#      written region contains NO torn block), and IO resumes afterwards.
#  T2  mid-sequence failure (duplicate snapshot name on the 2nd member):
#      RPC fails, NO snapshot of the failed call remains (GC), the colliding
#      original still exists, and IO on every member still flows (unfreeze
#      happened BEFORE GC by contract; observable here as: not frozen after).
#  T3  nonexistent member is rejected up front; nothing is created.
#  T4  member from a different lvstore is rejected; nothing is created.
#  T5  empty snapshot set is rejected.
import json
import os
import subprocess
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "../../python"))
from spdk.rpc.client import JSONRPCClient, JSONRPCException  # noqa: E402

SOCK = sys.argv[1] if len(sys.argv) > 1 else "/var/tmp/spdk.sock"
NQN_M = "nqn.2016-06.io.spdk:cgmembers"
NQN_S = "nqn.2016-06.io.spdk:cgsnaps"
PORT = "4420"
MB = 1024 * 1024

client = JSONRPCClient(SOCK, timeout=120.0)
failures = []


def call(method, **params):
    return client.call(method, params or None)


def check(cond, what, detail=""):
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {what}" + (f" ({detail})" if detail else ""))
    if not cond:
        failures.append(what)


def sh(cmd, check_rc=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"cmd failed rc={r.returncode}: {cmd}\n{r.stderr[-400:]}")
    return r.stdout.strip()


def bdev_exists(name):
    try:
        return bool(call("bdev_get_bdevs", name=name))
    except JSONRPCException:
        return False


def bdev_gone(name, timeout_s=10):
    """Bdev unregistration is asynchronous relative to the RPC response;
    give the GC a bounded moment instead of asserting the very next call."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not bdev_exists(name):
            return True
        time.sleep(0.5)
    return False


def nvme_dev_for(nqn, nsid):
    """Kernel block device for (subsystem, nsid) via sysfs."""
    for _ in range(30):
        out = sh(
            "for s in /sys/class/nvme-subsystem/nvme-subsys*; do "
            f'[ "$(cat $s/subsysnqn 2>/dev/null)" = "{nqn}" ] || continue; '
            "for b in $s/nvme*n*; do bn=$(basename $b); "
            "echo \"$bn $(cat /sys/block/$bn/../nsid 2>/dev/null || sudo nvme get-ns-id /dev/$bn 2>/dev/null | grep -oE '[0-9]+$')\"; "
            "done; done", check_rc=False)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == str(nsid) and parts[0].startswith("nvme"):
                return f"/dev/{parts[0]}"
        time.sleep(1)
    raise RuntimeError(f"no kernel device for {nqn} nsid {nsid}")


def write_pattern(dev, byte_hex, offset_mb, len_mb):
    sh(f"sudo dd if=/dev/zero bs=1M count={len_mb} 2>/dev/null | "
       f"tr '\\0' '\\{int(byte_hex, 16):03o}' | "
       f"sudo dd of={dev} bs=1M seek={offset_mb} count={len_mb} oflag=direct conv=notrunc,fsync 2>/dev/null")


def read_md5(dev, offset_mb, len_mb):
    return sh(f"sudo dd if={dev} bs=1M skip={offset_mb} count={len_mb} iflag=direct 2>/dev/null | md5sum").split()[0]


def pattern_md5(byte_hex, len_mb):
    return sh(f"dd if=/dev/zero bs=1M count={len_mb} 2>/dev/null | "
              f"tr '\\0' '\\{int(byte_hex, 16):03o}' | md5sum").split()[0]


def quick_write_ok(dev, timeout_s=8):
    r = subprocess.run(
        f"sudo timeout {timeout_s} dd if=/dev/zero of={dev} bs=4k count=1 "
        f"seek=1000 oflag=direct conv=notrunc,fsync",
        shell=True, capture_output=True)
    return r.returncode == 0


print("=== setup: lvstore + 3 members over nvmf loopback ===")
call("bdev_malloc_create", num_blocks=512 * MB // 512, block_size=512, name="malloc0")
call("bdev_lvol_create_lvstore", bdev_name="malloc0", lvs_name="cg")
# The fork gates snapshot creation on lvstore leadership; a standalone target
# must be made leader explicitly (production does this via the control plane).
call("bdev_lvol_set_leader_all", lvs_name="cg", lvs_leadership=True, bs_nonleadership=False)
for i in range(3):
    call("bdev_lvol_create", lvol_name=f"m{i}", size_in_mib=64, lvs_name="cg")

call("nvmf_create_transport", trtype="TCP")
call("nvmf_create_subsystem", nqn=NQN_M, allow_any_host=True, serial_number="CG01")
for i in range(3):
    call("nvmf_subsystem_add_ns", nqn=NQN_M, namespace={"bdev_name": f"cg/m{i}"})
call("nvmf_subsystem_add_listener", nqn=NQN_M,
     listen_address={"trtype": "TCP", "adrfam": "IPv4", "traddr": "127.0.0.1", "trsvcid": PORT})

sh("sudo modprobe nvme-tcp")
sh(f"sudo nvme connect -t tcp -a 127.0.0.1 -s {PORT} -n {NQN_M}")
devs = [nvme_dev_for(NQN_M, i + 1) for i in range(3)]
print(f"  member devices: {devs}")

# ---------------------------------------------------------------------------
print("=== T1: group snapshot under live IO ===")
PAT = ["a1", "b2", "c3"]
for i, dev in enumerate(devs):
    write_pattern(dev, PAT[i], 0, 4)          # distinguishable 4M pattern @0
    got = read_md5(dev, 0, 4)
    want = pattern_md5(PAT[i], 4)
    check(got == want, f"T1 member m{i} pattern write verified", f"{got[:8]} vs {want[:8]}")

# Background writer on member 0 @32M: every write is a full 4K block of one
# repeating 4-byte counter, so a torn block in the snapshot would show as a
# block containing two different counters.
sh("touch /tmp/cg_writer_go")
writer = subprocess.Popen(
    ["sudo", "bash", "-c",
     f"c=0; while [ -f /tmp/cg_writer_go ]; do "
     f"printf '%08x' $c | xxd -r -p > /tmp/cg_stamp.bin; "
     f"for k in $(seq 1 1024); do cat /tmp/cg_stamp.bin; done > /tmp/cg_block.bin; "
     f"dd if=/tmp/cg_block.bin of={devs[0]} bs=4k count=1 seek={32 * 256} "
     f"oflag=direct conv=notrunc 2>/dev/null; c=$((c+1)); echo $c > /tmp/cg_writer_count; "
     f"done"])
time.sleep(2)
count_before = int(sh("cat /tmp/cg_writer_count 2>/dev/null || echo 0", check_rc=False) or 0)
check(count_before > 0, "T1 background writer is producing IO", f"count={count_before}")

ret = call("bdev_lvol_snapshot_group", lvs_name="cg", snapshots=[
    {"lvol_name": f"cg/m{i}", "snapshot_name": f"gs{i}"} for i in range(3)])
check(isinstance(ret, list) and len(ret) == 3 and all(r.get("uuid") for r in ret),
      "T1 RPC returned 3 snapshot uuids", json.dumps(ret)[:120])
for i in range(3):
    check(bdev_exists(f"cg/gs{i}"), f"T1 snapshot bdev cg/gs{i} exists")

time.sleep(2)
count_after = int(sh("cat /tmp/cg_writer_count", check_rc=False) or 0)
check(count_after > count_before, "T1 IO resumed after the group snapshot (freeze lifted)",
      f"{count_before} -> {count_after}")
sh("rm -f /tmp/cg_writer_go", check_rc=False)
writer.wait(timeout=15)

# Expose the snapshots through a second subsystem and verify content.
call("nvmf_create_subsystem", nqn=NQN_S, allow_any_host=True, serial_number="CG02")
for i in range(3):
    call("nvmf_subsystem_add_ns", nqn=NQN_S, namespace={"bdev_name": f"cg/gs{i}"})
call("nvmf_subsystem_add_listener", nqn=NQN_S,
     listen_address={"trtype": "TCP", "adrfam": "IPv4", "traddr": "127.0.0.1", "trsvcid": PORT})
sh(f"sudo nvme connect -t tcp -a 127.0.0.1 -s {PORT} -n {NQN_S}")
sdevs = [nvme_dev_for(NQN_S, i + 1) for i in range(3)]
print(f"  snapshot devices: {sdevs}")

for i in range(3):
    got = read_md5(sdevs[i], 0, 4)
    want = pattern_md5(PAT[i], 4)
    ok = got == want
    check(ok, f"T1 snapshot gs{i} holds member m{i}'s pre-freeze pattern",
          f"{got[:8]} vs {want[:8]}")
    if not ok:
        head_s = sh(f"sudo dd if={sdevs[i]} bs=16 count=1 iflag=direct 2>/dev/null | xxd -p", check_rc=False)
        head_m = sh(f"sudo dd if={devs[i]} bs=16 count=1 iflag=direct 2>/dev/null | xxd -p", check_rc=False)
        print(f"    diag: snapshot head={head_s} member head={head_m}")

# Torn-state check on the concurrently written region of member 0's snapshot.
blk = sh(f"sudo dd if={sdevs[0]} bs=4k skip={32 * 256} count=1 iflag=direct 2>/dev/null | xxd -p | tr -d '\\n'")
stamps = {blk[i:i + 8] for i in range(0, len(blk), 8)}
check(len(stamps) == 1,
      "T1 concurrently-written 4K block in the snapshot is NOT torn",
      f"distinct 4-byte stamps in block: {len(stamps)}")

# ---------------------------------------------------------------------------
print("=== T2: duplicate-name failure -> unfreeze, then GC ===")
call("bdev_lvol_snapshot", lvol_name="cg/m1", snapshot_name="dup")
check(bdev_exists("cg/dup"), "T2 baseline snapshot cg/dup exists")

t2_err = None
try:
    call("bdev_lvol_snapshot_group", lvs_name="cg", snapshots=[
        {"lvol_name": "cg/m0", "snapshot_name": "t2s0"},
        {"lvol_name": "cg/m1", "snapshot_name": "dup"},      # collides mid-sequence
        {"lvol_name": "cg/m2", "snapshot_name": "t2s2"}])
except JSONRPCException as e:
    t2_err = str(e)
check(t2_err is not None, "T2 group snapshot with colliding name FAILS", (t2_err or "")[:100])
check(bdev_gone("cg/t2s0"), "T2 first member's partial snapshot was GARBAGE-COLLECTED")
check(bdev_gone("cg/t2s2", timeout_s=2), "T2 no snapshot after the failure point exists")
check(bdev_exists("cg/dup"), "T2 the pre-existing cg/dup was not touched")
for i, dev in enumerate(devs):
    check(quick_write_ok(dev), f"T2 member m{i} accepts writes after the failed call (unfrozen)")

# ---------------------------------------------------------------------------
print("=== T3: nonexistent member rejected ===")
t3_err = None
try:
    call("bdev_lvol_snapshot_group", lvs_name="cg", snapshots=[
        {"lvol_name": "cg/m0", "snapshot_name": "t3s0"},
        {"lvol_name": "cg/nope", "snapshot_name": "t3s1"}])
except JSONRPCException as e:
    t3_err = str(e)
check(t3_err is not None, "T3 nonexistent member fails the call", (t3_err or "")[:80])
check(not bdev_exists("cg/t3s0"), "T3 nothing was created")

# ---------------------------------------------------------------------------
print("=== T4: member from another lvstore rejected ===")
call("bdev_malloc_create", num_blocks=128 * MB // 512, block_size=512, name="malloc1")
call("bdev_lvol_create_lvstore", bdev_name="malloc1", lvs_name="other")
call("bdev_lvol_set_leader_all", lvs_name="other", lvs_leadership=True, bs_nonleadership=False)
call("bdev_lvol_create", lvol_name="o0", size_in_mib=16, lvs_name="other")
t4_err = None
try:
    call("bdev_lvol_snapshot_group", lvs_name="cg", snapshots=[
        {"lvol_name": "cg/m0", "snapshot_name": "t4s0"},
        {"lvol_name": "other/o0", "snapshot_name": "t4s1"}])
except JSONRPCException as e:
    t4_err = str(e)
check(t4_err is not None and "lvs" in t4_err.lower(),
      "T4 cross-lvstore member fails the call", (t4_err or "")[:80])
check(not bdev_exists("cg/t4s0") and not bdev_exists("other/t4s1"),
      "T4 nothing was created")

# ---------------------------------------------------------------------------
print("=== T5: empty snapshot set rejected ===")
t5_err = None
try:
    call("bdev_lvol_snapshot_group", lvs_name="cg", snapshots=[])
except JSONRPCException as e:
    t5_err = str(e)
check(t5_err is not None, "T5 empty set fails the call", (t5_err or "")[:80])

# ---------------------------------------------------------------------------
sh(f"sudo nvme disconnect -n {NQN_M}", check_rc=False)
sh(f"sudo nvme disconnect -n {NQN_S}", check_rc=False)
print(f"\n=== RESULT: {'PASS' if not failures else 'FAIL'} "
      f"({len(failures)} failed check(s)) ===")
for f in failures:
    print(f"  failed: {f}")
sys.exit(1 if failures else 0)
