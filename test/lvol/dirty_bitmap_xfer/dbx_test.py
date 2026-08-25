#!/usr/bin/env python3
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
"""Integration test: dirty-bitmap partial snapshot transfer between two
SPDK processes.

Topology (all on one host):

    process A (source)                     process B (target)
    lvsA/volA --S1,S2 snapshots            lvsB/landing  (map-addressed)
    bdev_lvol_transfer  ---nvmf/tcp--->    lvsB/hublvol  (transfer gateway)

Flow:
  1. full transfer of S1 into the landing volume, byte-compare via the
     kernel nvme-tcp initiator;
  2. small scattered delta, snapshot S2 (its dirty generation must be
     complete), transfer with allow_partial=true;
  3. byte-compare again AND assert from bdev_lvol_transfer_stat that the
     second transfer really was bitmap-driven (partial_reqs > 0,
     full_clusters == 0) and sent a small fraction of the pages a full
     transfer would have.

Run as root (kernel nvme-tcp initiator + hugepages). See run.sh.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time

SPDK_BUILD = os.environ.get("SPDK_BIN", "build/bin/spdk_tgt")
SOCK_A = "/var/tmp/dbx_a.sock"
SOCK_B = "/var/tmp/dbx_b.sock"
NQN_PFX = "nqn.2026-08.io.simplyblock.dbx"
CLUSTER_SZ = 2 * 1024 * 1024
VOL_MIB = 192
PORT_HUB = "4460"
PORT_A = "4461"
PORT_LANDING = "4462"

_req_id = 0


def rpc(sock_path, method, params=None, timeout=60):
    """Minimal JSON-RPC client over the SPDK unix socket."""
    global _req_id
    _req_id += 1
    req = {"jsonrpc": "2.0", "id": _req_id, "method": method}
    if params is not None:
        req["params"] = params
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall(json.dumps(req).encode())
    buf = b""
    decoder = json.JSONDecoder()
    while True:
        buf += s.recv(65536)
        try:
            obj, _ = decoder.raw_decode(buf.decode())
            break
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    s.close()
    if "error" in obj:
        raise RuntimeError(f"{method} failed: {obj['error']}")
    return obj.get("result")


def wait_rpc(sock_path, tries=60):
    for _ in range(tries):
        try:
            rpc(sock_path, "spdk_get_version")
            return
        except (OSError, RuntimeError):
            time.sleep(1)
    raise RuntimeError(f"spdk_tgt on {sock_path} never became ready")


def sh(cmd, check=True):
    print(f"  $ {cmd}", flush=True)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed rc={r.returncode}: {cmd}\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()


def start_tgt(sock, cpumask, auto_examine=True):
    """auto_examine=False matters on the SOURCE: the moment bdev_nvme registers
    the remote hub bdev, gpt auto-examine reads LBA 0 through it -- which the
    hub demux rejects (map id 0 is nobody), and the resulting errors wedge the
    qpair before the first real transfer write."""
    argv = [SPDK_BUILD, "-r", sock, "-m", cpumask, "-s", "1280"]
    if not auto_examine:
        cfg = sock + ".conf.json"
        with open(cfg, "w") as f:
            json.dump({"subsystems": [{"subsystem": "bdev", "config": [
                {"method": "bdev_set_options",
                 "params": {"bdev_auto_examine": False}}]}]}, f)
        argv += ["-c", cfg]
    p = subprocess.Popen(argv, stdout=open(sock + ".log", "w"),
                         stderr=subprocess.STDOUT)
    wait_rpc(sock)
    return p


def nvmf_up(sock, nqn_suffix, bdev, port):
    nqn = f"{NQN_PFX}:{nqn_suffix}"
    try:
        rpc(sock, "nvmf_create_transport", {"trtype": "TCP"})
    except RuntimeError as e:
        if "already" not in str(e):
            raise
    rpc(sock, "nvmf_create_subsystem",
        {"nqn": nqn, "allow_any_host": True, "serial_number": "DBX0001"})
    rpc(sock, "nvmf_subsystem_add_ns", {"nqn": nqn, "namespace": {"bdev_name": bdev}})
    rpc(sock, "nvmf_subsystem_add_listener",
        {"nqn": nqn, "listen_address": {
            "trtype": "TCP", "adrfam": "IPv4", "traddr": "127.0.0.1", "trsvcid": port}})
    return nqn


def host_connect(nqn, port):
    sh(f"nvme connect -t tcp -a 127.0.0.1 -s {port} -n {nqn}")
    for _ in range(30):
        out = sh("for s in /sys/class/nvme-subsystem/nvme-subsys*; do "
                 f"[ \"$(cat $s/subsysnqn 2>/dev/null)\" = \"{nqn}\" ] || continue; "
                 "ls $s | grep -E '^nvme[0-9]+n[0-9]+$' | head -1; done", check=False)
        if out:
            return f"/dev/{out.splitlines()[-1].strip()}"
        time.sleep(1)
    raise RuntimeError(f"no block device appeared for {nqn}")


def chunk_diff(dev_a, dev_b, mib, chunk_mib=16):
    """Print which chunk_mib-sized windows differ (forensics on mismatch)."""
    diffs = []
    for off in range(0, mib, chunk_mib):
        a = md5_range(dev_a, off, chunk_mib)
        b = md5_range(dev_b, off, chunk_mib)
        mark = "DIFF" if a != b else "same"
        print(f"    [{off:4d}..{off + chunk_mib:4d} MiB] {mark}  {a[:10]} {b[:10]}")
        if a != b:
            diffs.append(off)
    return diffs


def md5_range(dev, off_mib, len_mib):
    h = hashlib.md5()
    with open(dev, "rb") as f:
        f.seek(off_mib * 1024 * 1024)
        left = len_mib * 1024 * 1024
        while left:
            chunk = f.read(min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    return h.hexdigest()


def md5_dev(dev, mib):
    h = hashlib.md5()
    with open(dev, "rb") as f:
        left = mib * 1024 * 1024
        while left:
            chunk = f.read(min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    return h.hexdigest()


def wait_transfer_done(sock, lvol, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = rpc(sock, "bdev_lvol_transfer_stat", {"lvol_name": lvol})
        if st["transfer_state"] == "Done":
            return st
        if st["transfer_state"] == "Failed":
            raise RuntimeError(f"transfer of {lvol} failed: {st}")
        time.sleep(1)
    raise RuntimeError(f"transfer of {lvol} did not finish: {st}")


def main():
    procs = []
    devs = []
    fail = None
    try:
        print("=== starting two spdk_tgt processes")
        procs.append(start_tgt(SOCK_B, "[4,5]"))
        procs.append(start_tgt(SOCK_A, "[2,3]", auto_examine=False))

        print("=== target (B): lvstore + landing volume + hublvol + nvmf")
        # 4096-byte blocks: the transfer machinery addresses in 4 KiB pages and
        # production runs on 4K-block devices; a 512-byte-block base device
        # shifts every transfer offset by 8x.
        rpc(SOCK_B, "bdev_malloc_create", {"num_blocks": 131072 + 65536, "block_size": 4096,
                                           "name": "mallocB"})
        rpc(SOCK_B, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocB", "lvs_name": "lvsB", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_B, "bdev_lvol_create",
            {"lvol_name": "landing", "size_in_mib": VOL_MIB, "lvs_name": "lvsB",
             "thin_provision": True})
        lvols_b = rpc(SOCK_B, "bdev_lvol_get_lvols", {"lvs_name": "lvsB"})
        landing = next(l for l in lvols_b if l["name"] == "landing")
        map_id = landing["map_id"]
        print(f"    landing map_id = {map_id}")
        hub_id = rpc(SOCK_B, "bdev_lvol_create_hublvol", {"lvs_name": "lvsB"})
        print(f"    hublvol = {hub_id}")
        rpc(SOCK_B, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsB", "lvs_leadership": True, "bs_nonleadership": False})
        nqn_hub = nvmf_up(SOCK_B, "hub", "lvsB/hublvol", PORT_HUB)
        nqn_landing = nvmf_up(SOCK_B, "landing", "lvsB/landing", PORT_LANDING)

        print("=== source (A): lvstore + volA + nvmf")
        rpc(SOCK_A, "bdev_malloc_create", {"num_blocks": 131072 + 65536, "block_size": 4096,
                                           "name": "mallocA"})
        rpc(SOCK_A, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocA", "lvs_name": "lvsA", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_A, "bdev_lvol_create",
            {"lvol_name": "volA", "size_in_mib": VOL_MIB, "lvs_name": "lvsA",
             "thin_provision": True})
        rpc(SOCK_A, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsA", "lvs_leadership": True, "bs_nonleadership": False})
        # the transfer helper pollers run on lvs POLL GROUPS; without them the
        # ready_ring is never drained and every request times out
        rpc(SOCK_A, "bdev_lvol_create_poller_group", {"cpu_mask": "0x0C"})
        nqn_a = nvmf_up(SOCK_A, "volA", "lvsA/volA", PORT_A)

        print("=== host: connect volA and landing")
        dev_a = host_connect(nqn_a, PORT_A)
        devs.append(nqn_a)
        dev_l = host_connect(nqn_landing, PORT_LANDING)
        devs.append(nqn_landing)
        print(f"    volA={dev_a} landing={dev_l}")

        print("=== base pattern: 64 MiB at 0, 16 MiB at 128 MiB")
        sh(f"dd if=/dev/urandom of={dev_a} bs=1M count=64 oflag=direct status=none")
        sh(f"dd if=/dev/urandom of={dev_a} bs=1M count=16 seek=128 oflag=direct status=none")

        print("=== snapshot S1")
        rpc(SOCK_A, "bdev_lvol_snapshot", {"lvol_name": "lvsA/volA", "snapshot_name": "S1"})
        info = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/S1"})
        print(f"    S1 dirty info: {info}")
        assert info["tracking"] and info["complete"], f"S1 generation not usable: {info}"

        print("=== attach B's hub from A")
        rpc(SOCK_A, "bdev_nvme_attach_controller",
            {"name": "hubr", "trtype": "TCP", "traddr": "127.0.0.1",
             "adrfam": "IPv4", "trsvcid": PORT_HUB, "subnqn": nqn_hub})

        print("=== transfer 1: FULL (no allow_partial)")
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S1", "offset": 0, "cluster_batch": 8,
             "gateway": "hubrn1", "operation": "replicate", "lvol_id": map_id})
        st1 = wait_transfer_done(SOCK_A, "lvsA/S1")
        print(f"    full transfer stat: {st1}")
        assert st1["full_clusters"] > 0, st1
        assert st1["partial_reqs"] == 0, st1

        m_src = md5_dev(dev_a, VOL_MIB)
        m_dst = md5_dev(dev_l, VOL_MIB)
        print(f"    md5 volA={m_src} landing={m_dst}")
        if m_src != m_dst:
            chunk_diff(dev_a, dev_l, VOL_MIB)
        assert m_src == m_dst, "FULL transfer content mismatch"

        print("=== delta: scattered small writes")
        # 8 KiB at 3 distinct clusters + a 32K+24K pair inside one cluster
        for seek_kib in (0, 4096, 65536):
            sh(f"dd if=/dev/urandom of={dev_a} bs=8K count=1 seek={seek_kib // 8} "
               f"oflag=direct status=none")
        sh(f"dd if=/dev/urandom of={dev_a} bs=8K count=4 seek={(10 * 2048) // 8} "
           f"oflag=direct status=none")          # 32K at cluster 10 + 0K
        sh(f"dd if=/dev/urandom of={dev_a} bs=8K count=3 seek={(10 * 2048 + 40) // 8} "
           f"oflag=direct status=none")          # 24K at cluster 10 + 40K
        sh("sync")

        print("=== snapshot S2")
        rpc(SOCK_A, "bdev_lvol_snapshot", {"lvol_name": "lvsA/volA", "snapshot_name": "S2"})
        info2 = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/S2"})
        print(f"    S2 dirty info: {info2}")
        assert info2["tracking"] and info2["complete"], f"S2 generation not usable: {info2}"
        assert info2["clusters_tracked"] == 4, info2      # clusters 0, 2, 32, 10
        assert info2["dirty_bytes"] <= 24 * 8192, info2

        print("=== transfer 2: PARTIAL (allow_partial=true)")
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S2", "offset": 0, "cluster_batch": 8,
             "gateway": "hubrn1", "operation": "replicate", "lvol_id": map_id,
             "allow_partial": True})
        st2 = wait_transfer_done(SOCK_A, "lvsA/S2")
        print(f"    partial transfer stat: {st2}")
        assert st2["partial_reqs"] > 0, f"partial transfer did not use the bitmap: {st2}"
        assert st2["full_clusters"] == 0, f"partial transfer fell back to full clusters: {st2}"
        # 4 dirty clusters would be 4 * 512 pages full; the delta is tiny
        full_pages = 4 * (CLUSTER_SZ // 4096)
        assert st2["pages_sent"] * 10 < full_pages, \
            f"partial transfer sent too much: {st2['pages_sent']} of {full_pages} pages"

        m_src2 = md5_dev(dev_a, VOL_MIB)
        m_dst2 = md5_dev(dev_l, VOL_MIB)
        print(f"    md5 volA={m_src2} landing={m_dst2}")
        assert m_src2 == m_dst2, "PARTIAL transfer content mismatch"

        savings = 100.0 * (1 - st2["pages_sent"] / max(1, st1["pages_sent"]))
        print(f"=== PASS: partial transfer sent {st2['pages_sent']} pages vs "
              f"{st1['pages_sent']} full ({savings:.1f}% less), content byte-identical")
    except BaseException as e:
        fail = e
    finally:
        if fail is not None and os.environ.get("DBX_KEEP"):
            print(f"DBX_KEEP set: leaving processes up for inspection ({fail})")
            return 1
        for nqn in devs:
            sh(f"nvme disconnect -n {nqn}", check=False)
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
        if fail is not None:
            raise fail


if __name__ == "__main__":
    sys.exit(main())
