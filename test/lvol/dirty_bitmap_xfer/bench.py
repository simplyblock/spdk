#!/usr/bin/env python3
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
"""Repeatable throughput benchmark for the snapshot-replication transfer.

Same two-process topology as dbx_test.py (source A --nvmf/tcp--> hublvol on
B, map-addressed landing volume), but sized and timed:

  * DATA_MIB (default 4096) of urandom is written into the source volume
    through the kernel initiator, snapshotted, and the snapshot is
    transferred FULL to the landing volume;
  * wall-clock is measured from the bdev_lvol_transfer RPC returning to
    transfer_state == Done (polled every 25 ms);
  * both spdk_tgt processes' CPU time (utime+stime) is sampled around the
    transfer, so the report carries CPU-seconds per GiB -- on loopback the
    network is free, so cycles per byte is the number that predicts real
    deployments;
  * optional content verification (VERIFY=1) byte-compares source and
    landing through the kernel initiator.

Env knobs:  DATA_MIB, BATCH (cluster_batch, default 16), PG_MASK (poller
group cpu mask, default 0x0C), RUNS (default 2), VERIFY (default 1 -- the
first run only), SPDK_BIN.

Run as root from the repo root:
    test/lvol/dirty_bitmap_xfer/bench_run.sh
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
NQN_PFX = "nqn.2026-08.io.simplyblock.dbxbench"
CLUSTER_SZ = 2 * 1024 * 1024
DATA_MIB = int(os.environ.get("DATA_MIB", "4096"))
VOL_MIB = DATA_MIB + 64
BATCH = int(os.environ.get("BATCH", "16"))
PG_MASK = os.environ.get("PG_MASK", "0x0C")
RUNS = int(os.environ.get("RUNS", "2"))
VERIFY = os.environ.get("VERIFY", "1") == "1"
PORT_HUB = "4470"
PORT_A = "4471"
PORT_LANDING = "4472"

_req_id = 0


def rpc(sock_path, method, params=None, timeout=120):
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
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed rc={r.returncode}: {cmd}\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()


def start_tgt(sock, cpumask, auto_examine=True):
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
        {"nqn": nqn, "allow_any_host": True, "serial_number": "DBXB001"})
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


def cpu_seconds(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().split()
    hz = os.sysconf("SC_CLK_TCK")
    return (int(parts[13]) + int(parts[14])) / hz


def main():
    procs = []
    devs = []
    fail = None
    results = []
    try:
        print(f"=== bench: DATA_MIB={DATA_MIB} BATCH={BATCH} PG_MASK={PG_MASK} "
              f"RUNS={RUNS}", flush=True)
        p_b = start_tgt(SOCK_B, "[4,5,6,7]")
        p_a = start_tgt(SOCK_A, "[2,3]", auto_examine=False)
        procs += [p_b, p_a]

        base_blocks = (VOL_MIB + 512) * 256          # 4K blocks, volume + slack
        rpc(SOCK_B, "bdev_malloc_create", {"num_blocks": base_blocks,
                                           "block_size": 4096, "name": "mallocB"})
        rpc(SOCK_B, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocB", "lvs_name": "lvsB", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_B, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsB", "lvs_leadership": True, "bs_nonleadership": False})
        hub_id = rpc(SOCK_B, "bdev_lvol_create_hublvol", {"lvs_name": "lvsB"})
        nqn_hub = nvmf_up(SOCK_B, "hub", "lvsB/hublvol", PORT_HUB)

        rpc(SOCK_A, "bdev_malloc_create", {"num_blocks": base_blocks,
                                           "block_size": 4096, "name": "mallocA"})
        rpc(SOCK_A, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocA", "lvs_name": "lvsA", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_A, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsA", "lvs_leadership": True, "bs_nonleadership": False})
        rpc(SOCK_A, "bdev_lvol_create_poller_group", {"cpu_mask": PG_MASK})
        rpc(SOCK_A, "bdev_nvme_attach_controller",
            {"name": "hubr", "trtype": "TCP", "traddr": "127.0.0.1",
             "adrfam": "IPv4", "trsvcid": PORT_HUB, "subnqn": nqn_hub})

        for run in range(1, RUNS + 1):
            vol = f"volA{run}"
            landing = f"landing{run}"
            snap = f"S{run}"
            rpc(SOCK_A, "bdev_lvol_create",
                {"lvol_name": vol, "size_in_mib": VOL_MIB, "lvs_name": "lvsA",
                 "thin_provision": True})
            rpc(SOCK_B, "bdev_lvol_create",
                {"lvol_name": landing, "size_in_mib": VOL_MIB, "lvs_name": "lvsB",
                 "thin_provision": True})
            lvols_b = rpc(SOCK_B, "bdev_lvol_get_lvols", {"lvs_name": "lvsB"})
            map_id = next(l for l in lvols_b if l["name"] == landing)["map_id"]

            nqn_a = nvmf_up(SOCK_A, f"vol{run}", f"lvsA/{vol}", str(int(PORT_A) + run * 10))
            dev_a = host_connect(nqn_a, str(int(PORT_A) + run * 10))
            devs.append(nqn_a)

            print(f"--- run {run}: writing {DATA_MIB} MiB of urandom", flush=True)
            sh(f"dd if=/dev/urandom of={dev_a} bs=4M count={DATA_MIB // 4} "
               f"oflag=direct status=none")
            sh("sync")
            rpc(SOCK_A, "bdev_lvol_snapshot",
                {"lvol_name": f"lvsA/{vol}", "snapshot_name": snap})

            cpu_a0, cpu_b0 = cpu_seconds(p_a.pid), cpu_seconds(p_b.pid)
            t0 = time.time()
            rpc(SOCK_A, "bdev_lvol_transfer",
                {"lvol_name": f"lvsA/{snap}", "offset": 0, "cluster_batch": BATCH,
                 "gateway": "hubrn1", "operation": "replicate", "lvol_id": map_id})
            st = None
            while True:
                st = rpc(SOCK_A, "bdev_lvol_transfer_stat", {"lvol_name": f"lvsA/{snap}"})
                if st["transfer_state"] == "Done":
                    break
                if st["transfer_state"] == "Failed":
                    raise RuntimeError(f"transfer failed: {st}")
                time.sleep(0.025)
            wall = time.time() - t0
            cpu_a = cpu_seconds(p_a.pid) - cpu_a0
            cpu_b = cpu_seconds(p_b.pid) - cpu_b0

            gib = st["pages_sent"] * 4096 / (1 << 30)
            mibs = st["pages_sent"] * 4096 / (1 << 20) / wall
            res = {"run": run, "wall_s": round(wall, 2), "MiB_s": round(mibs, 1),
                   "pages_sent": st["pages_sent"],
                   "cpu_src_s": round(cpu_a, 2), "cpu_dst_s": round(cpu_b, 2),
                   "cpu_s_per_GiB": round((cpu_a + cpu_b) / max(gib, 1e-9), 2)}
            results.append(res)
            print(f"    RESULT {json.dumps(res)}", flush=True)

            if VERIFY and run == 1:
                nqn_l = nvmf_up(SOCK_B, f"landing{run}", f"lvsB/{landing}",
                                str(int(PORT_LANDING) + run * 10))
                dev_l = host_connect(nqn_l, str(int(PORT_LANDING) + run * 10))
                devs.append(nqn_l)
                m_a, m_l = md5_dev(dev_a, VOL_MIB), md5_dev(dev_l, VOL_MIB)
                ok = m_a == m_l
                print(f"    verify: src={m_a} dst={m_l} {'OK' if ok else 'MISMATCH'}",
                      flush=True)
                if not ok:
                    raise RuntimeError("content mismatch")

        best = max(r["MiB_s"] for r in results)
        print(f"=== BENCH DONE best={best} MiB/s  results={json.dumps(results)}",
              flush=True)
    except BaseException as e:
        fail = e
    finally:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
