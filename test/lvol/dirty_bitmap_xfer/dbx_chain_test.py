#!/usr/bin/env python3
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
"""Integration test: partial snapshot replication along a chain, the way the
control plane runs it.

Topology as in dbx_test.py (two spdk_tgt processes, transfer over nvmf/tcp
loopback, content read through the kernel nvme-tcp initiator), but every round
lands in a NEW volume, cloned from the copy of the previous snapshot:

    source A: volA --S1--S2--S3--S4 (snapshots, oldest first)
    target B: landing1 (full) -> T1 ; landing2 = clone(T1) -> T2 ; ...

so the clusters a delta touches are built on the destination by CoW from the
base, and the blocks the delta does not carry must read as the base's.
Each delta mixes what broke or could break that:

  * scattered 8 KiB writes, a dense run across 64 KiB segments, a write across
    a cluster boundary, a first write into a cluster the base never had;
  * zeroes written over data, and a discard (unmap) inside an allocated
    cluster: a destination that skips zero blocks keeps the base's data there.

After every round the landing volume must be byte-identical to volA. Then a
transfer with the wrong base must fall back to full clusters and still match.

Run as root (kernel nvme-tcp initiator + hugepages): run_chain.sh.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dbx_test import (CLUSTER_SZ, SOCK_A, SOCK_B, VOL_MIB, chunk_diff,  # noqa: E402
                      host_connect, md5_dev, nvmf_up, rpc, sh, start_tgt,
                      wait_transfer_done)
import subprocess  # noqa: E402
import time  # noqa: E402

PORT_HUB = "4470"
PORT_A = "4471"
PORT_LANDING0 = 4480
CLUSTER_KIB = CLUSTER_SZ // 1024


def blobid(sock, bdev):
    b = rpc(sock, "bdev_get_bdevs", {"name": bdev})[0]
    return b["driver_specific"]["lvol"]["blobid"]


def map_id(sock, lvs, name):
    return next(lv["map_id"] for lv in rpc(sock, "bdev_lvol_get_lvols", {"lvs_name": lvs})
                if lv["name"] == name)


def dd(dev, src, kib_off, kib_len):
    # direct IO in whole 4 KiB sectors: the lvol bdevs have 4 KiB blocks
    assert kib_off % 4 == 0 and kib_len % 4 == 0, (kib_off, kib_len)
    sh(f"dd if={src} of={dev} bs=4K count={kib_len // 4} seek={kib_off // 4} "
       f"oflag=direct status=none")


def delta(dev, rnd):
    """One round's writes, at offsets that move with the round."""
    c = 3 * rnd                                   # first cluster this round touches
    for k in range(4):                            # scattered 8 KiB
        dd(dev, "/dev/urandom", (c + k) * CLUSTER_KIB + 8 * (5 * k + rnd), 8)
    dd(dev, "/dev/urandom", (c + 1) * CLUSTER_KIB + 1024, 100)      # dense, 2 segments
    dd(dev, "/dev/urandom", (c + 3) * CLUSTER_KIB - 8, 16)           # across a boundary
    dd(dev, "/dev/zero", c * CLUSTER_KIB + 256, 16)                  # zeroes over data
    dd(dev, "/dev/urandom", (40 + rnd) * CLUSTER_KIB + 64, 8)        # base never had it
    # discard inside an allocated cluster: the blocks then read as zeroes
    sh(f"blkdiscard -o {(c + 2) * CLUSTER_SZ + 512 * 1024} -l {64 * 1024} {dev}", check=False)
    sh("sync")


def merge(lvol):
    """Start the landing volume's merge with its base (a job) and wait for it;
    starting it again while it runs, or after it is done, must not repeat it."""
    st = rpc(SOCK_B, "bdev_lvol_merge_base", {"lvol_name": lvol})
    again = rpc(SOCK_B, "bdev_lvol_merge_base", {"lvol_name": lvol})
    assert again["state"] in ("running", "done"), again
    for _ in range(600):
        st = rpc(SOCK_B, "bdev_lvol_merge_base_stat", {"lvol_name": lvol})
        if st["state"] != "running":
            break
        time.sleep(0.5)
    assert st["state"] == "done", f"merge of {lvol}: {st}"
    done_again = rpc(SOCK_B, "bdev_lvol_merge_base", {"lvol_name": lvol})
    assert done_again == st, f"a finished merge was repeated: {done_again} vs {st}"
    return st


def main():
    procs, devs, fail = [], [], None
    try:
        print("=== two spdk_tgt processes")
        procs.append(start_tgt(SOCK_B, "[4,5]"))
        procs.append(start_tgt(SOCK_A, "[2,3]", auto_examine=False))

        print("=== target (B): lvstore, hublvol, leadership")
        rpc(SOCK_B, "bdev_malloc_create", {"num_blocks": 4 * 65536, "block_size": 4096,
                                           "name": "mallocB"})
        rpc(SOCK_B, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocB", "lvs_name": "lvsB", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_B, "bdev_lvol_create_hublvol", {"lvs_name": "lvsB"})
        rpc(SOCK_B, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsB", "lvs_leadership": True, "bs_nonleadership": False})
        nqn_hub = nvmf_up(SOCK_B, "chub", "lvsB/hublvol", PORT_HUB)

        print("=== source (A): lvstore, leadership BEFORE the volume (it starts tracking at open)")
        rpc(SOCK_A, "bdev_malloc_create", {"num_blocks": 4 * 65536, "block_size": 4096,
                                           "name": "mallocA"})
        rpc(SOCK_A, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocA", "lvs_name": "lvsA", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_A, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsA", "lvs_leadership": True, "bs_nonleadership": False})
        rpc(SOCK_A, "bdev_lvol_create",
            {"lvol_name": "volA", "size_in_mib": VOL_MIB, "lvs_name": "lvsA",
             "thin_provision": True})
        rpc(SOCK_A, "bdev_lvol_create_poller_group", {"cpu_mask": "0x0C"})
        nqn_a = nvmf_up(SOCK_A, "cvolA", "lvsA/volA", PORT_A)
        dev_a = host_connect(nqn_a, PORT_A)
        devs.append(nqn_a)
        rpc(SOCK_A, "bdev_nvme_attach_controller",
            {"name": "chubr", "trtype": "TCP", "traddr": "127.0.0.1",
             "adrfam": "IPv4", "trsvcid": PORT_HUB, "subnqn": nqn_hub})

        print("=== base pattern: 80 MiB")
        sh(f"dd if=/dev/urandom of={dev_a} bs=1M count=80 oflag=direct status=none")

        def land(rnd, src_snap, base, parent, retry_full=False):
            """Transfer src_snap into a new landing volume, compare, freeze it as T<rnd>.

            With a base, the landing volume is a clone of the base's copy and
            then merged with it (bdev_lvol_merge_base), as the control plane
            does: every cluster was pre-allocated, the delta wrote only its
            blocks, the merge fills the rest from the base.

            retry_full: send it again as a FULL transfer into the same landing
            volume first, as a retry after a failed attempt would: it must
            write its zero blocks too, or the merge fills them from the base."""
            name = f"landing{rnd}"
            if parent is None:
                rpc(SOCK_B, "bdev_lvol_create",
                    {"lvol_name": name, "size_in_mib": VOL_MIB, "lvs_name": "lvsB",
                     "thin_provision": True})
            else:
                rpc(SOCK_B, "bdev_lvol_clone",
                    {"snapshot_name": f"lvsB/{parent}", "clone_name": name})
            params = {"lvol_name": f"lvsA/{src_snap}", "offset": 0, "cluster_batch": 8,
                      "gateway": "chubrn1", "operation": "replicate",
                      "lvol_id": map_id(SOCK_B, "lvsB", name)}
            if base is not None:
                params.update(allow_partial=True, partial_base=base)
            rpc(SOCK_A, "bdev_lvol_transfer", params)
            st = wait_transfer_done(SOCK_A, f"lvsA/{src_snap}")
            if retry_full:
                params.pop("allow_partial")
                rpc(SOCK_A, "bdev_lvol_transfer", params)     # keeps partial_base
                st_retry = wait_transfer_done(SOCK_A, f"lvsA/{src_snap}")
                print(f"    full retry into {name}: {st_retry}")
                assert st_retry["partial_reqs"] == 0, st_retry
            if base is not None:
                merged = merge(f"lvsB/{name}")
                print(f"    merge {name}: {merged}")
                st["merged"] = merged
            nqn = nvmf_up(SOCK_B, f"c{name}", f"lvsB/{name}", str(PORT_LANDING0 + rnd))
            dev = host_connect(nqn, str(PORT_LANDING0 + rnd))
            devs.append(nqn)
            m_src, m_dst = md5_dev(dev_a, VOL_MIB), md5_dev(dev, VOL_MIB)
            print(f"    {src_snap} -> {name}: {st}  md5 {m_src} / {m_dst}")
            if m_src != m_dst:
                chunk_diff(dev_a, dev, VOL_MIB)
            assert m_src == m_dst, f"round {rnd}: {name} differs from volA"
            sh(f"nvme disconnect -n {nqn}", check=False)
            devs.remove(nqn)
            rpc(SOCK_B, "bdev_lvol_snapshot", {"lvol_name": f"lvsB/{name}",
                                               "snapshot_name": f"T{rnd}"})
            return st

        print("=== round 1: S1, full")
        rpc(SOCK_A, "bdev_lvol_snapshot", {"lvol_name": "lvsA/volA", "snapshot_name": "S1"})
        land(1, "S1", None, None)
        # clusters allocated without data into a tracked volume end its bitmap
        t1 = rpc(SOCK_B, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsB/T1"})
        assert not t1["usable"], f"T1's generation survived the allocation step: {t1}"

        for rnd in (2, 3, 4):
            print(f"=== round {rnd}: delta, S{rnd}, partial on top of S{rnd - 1}")
            delta(dev_a, rnd)
            rpc(SOCK_A, "bdev_lvol_snapshot", {"lvol_name": "lvsA/volA",
                                               "snapshot_name": f"S{rnd}"})
            info = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": f"lvsA/S{rnd}"})
            print(f"    S{rnd} dirty info: {info}")
            assert info["usable"], info
            assert info["base_blob_id"] == blobid(SOCK_A, f"lvsA/S{rnd - 1}"), info
            st = land(rnd, f"S{rnd}", blobid(SOCK_A, f"lvsA/S{rnd - 1}"), f"T{rnd - 1}",
                      retry_full=(rnd == 3))
            assert st["partial_reqs"] > 0, f"round {rnd} did not send ranges: {st}"
            if rnd == 3:
                # the full retry wrote every block: nothing left for the merge
                assert st["merged"]["clusters"] == 0, f"round {rnd} merged after a full retry: {st}"
            else:
                assert st["merged"]["clusters"] > 0, f"round {rnd} merged nothing: {st}"

        print("=== round 5: wrong base -> full clusters, same content")
        delta(dev_a, 5)
        rpc(SOCK_A, "bdev_lvol_snapshot", {"lvol_name": "lvsA/volA", "snapshot_name": "S5"})
        st = land(5, "S5", blobid(SOCK_A, "lvsA/S3"), "T4")
        assert st["partial_reqs"] == 0 and st["full_clusters"] > 0, st

        print("=== PASS: 3 partial rounds and a refused base, every landing byte-identical")
    except BaseException as e:
        fail = e
    finally:
        if fail is not None and os.environ.get("DBX_KEEP"):
            print(f"DBX_KEEP set: leaving processes up ({fail})")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
