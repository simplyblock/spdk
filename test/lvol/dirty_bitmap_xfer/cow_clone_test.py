#!/usr/bin/env python3
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
"""Integration test: land a partial snapshot transfer on a COW CLONE.

dbx_test.py proves a partial transfer is byte-exact when it lands on a volume
that already received the previous snapshot in full. That is not how the
control plane will actually run it. A partial transfer only ships the DIRTY
ranges, so the destination has to already contain everything else -- and the
way the control plane gets that is to create the landing volume as a CLONE of
the destination's copy of the previous snapshot, let the blobstore COW-fill
each cluster from that parent on first touch, and convert the clone to a
snapshot when the transfer finishes (it is already chained, so no add_clone).

This test exercises exactly that shape:

  case A  S2 transferred PARTIALLY onto a clone of the destination's S1.
          Only the delta crosses the wire; every untouched cluster has to come
          from the COW parent. Asserts the destination is byte-identical to the
          source and that the transfer really was bitmap-driven.

  case B  S3 transferred in FULL onto a clone of the destination's S2. This is
          the automatic fallback the control plane takes whenever the dirty
          generation is not complete, and it has to be correct too: a full
          transfer carries only the snapshot's OWN clusters, so everything the
          snapshot does not own must still read through to the COW parent.

  case C  tracking deliberately INVALIDATED (a cluster-freeing unmap, which no
          generation can express) and allow_partial requested anyway. The lvol
          layer has to refuse the bitmap and send a full transfer: falling back
          is always safe, whereas honouring a stale generation would silently
          drop whatever it failed to record.

  case D  the control plane's OWN sequence: it does not create the landing
          volume with bdev_lvol_clone (it needs add_lvol_ha for the HA pair and
          the internal=True admission bypass), it creates a fresh volume and
          attaches the parent with bdev_lvol_add_clone before transferring.
          That has to end up with the same COW parent, so this asserts the
          resulting parentage explicitly and not just the bytes.

Cases A, B and D deliberately include a delta cluster that was UNALLOCATED in
the parent, so the COW fill is exercised against real parent data and against
a hole.

Run as root (kernel nvme-tcp initiator + hugepages). See cow_clone_run.sh.
"""

import os
import sys
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dbx_test import (  # noqa: E402
    CLUSTER_SZ, host_connect, md5_dev, nvmf_up, rpc, sh, start_tgt,
    wait_transfer_done, chunk_diff,
)

SOCK_A = "/var/tmp/dbxc_a.sock"
SOCK_B = "/var/tmp/dbxc_b.sock"
VOL_MIB = 128
VOLB_MIB = 32
PORT_HUB = "4470"
PORT_A = "4471"
PORT_L1 = "4472"
PORT_L2 = "4473"
PORT_L3 = "4474"
PORT_L4 = "4475"
PORT_B = "4476"
PORT_L5 = "4477"

MIB = 1024 * 1024
CLUSTER_MIB = CLUSTER_SZ // MIB          # 2
BLK_PER_MIB = MIB // 4096                # 256 blocks of 4 KiB


def dd_8k(dev, cluster_idx, blk_in_cluster, count=1):
    """Write `count` 8 KiB blocks at a cluster-relative 8 KiB slot."""
    seek = (cluster_idx * CLUSTER_SZ + blk_in_cluster * 8192) // 8192
    sh(f"dd if=/dev/urandom of={dev} bs=8K count={count} seek={seek} "
       f"oflag=direct status=none")


def map_id_of(sock, lvs, name):
    for l in rpc(sock, "bdev_lvol_get_lvols", {"lvs_name": lvs}):
        if l["name"] == name:
            return l["map_id"]
    raise RuntimeError(f"lvol {lvs}/{name} not found")


def compare(dev_src, dev_dst, label, mib=None):
    mib = VOL_MIB if mib is None else mib
    m_src = md5_dev(dev_src, mib)
    m_dst = md5_dev(dev_dst, mib)
    print(f"    md5 source={m_src} destination={m_dst}")
    if m_src != m_dst:
        chunk_diff(dev_src, dev_dst, mib)
        raise AssertionError(f"{label}: destination is NOT byte-identical")
    print(f"    [PASS] {label}: destination byte-identical to source")


def main():
    procs = []
    connected = []
    fail = None
    try:
        print("=== starting two spdk_tgt processes")
        procs.append(start_tgt(SOCK_B, "[4,5]"))
        procs.append(start_tgt(SOCK_A, "[2,3]", auto_examine=False))

        print("=== target (B): lvstore + first landing volume + hublvol")
        rpc(SOCK_B, "bdev_malloc_create",
            {"num_blocks": 262144, "block_size": 4096, "name": "mallocB"})
        rpc(SOCK_B, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocB", "lvs_name": "lvsB", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_B, "bdev_lvol_create",
            {"lvol_name": "land1", "size_in_mib": VOL_MIB, "lvs_name": "lvsB",
             "thin_provision": True})
        rpc(SOCK_B, "bdev_lvol_create_hublvol", {"lvs_name": "lvsB"})
        rpc(SOCK_B, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsB", "lvs_leadership": True, "bs_nonleadership": False})
        nqn_hub = nvmf_up(SOCK_B, "cchub", "lvsB/hublvol", PORT_HUB)

        print("=== source (A): lvstore + volA")
        rpc(SOCK_A, "bdev_malloc_create",
            {"num_blocks": 262144, "block_size": 4096, "name": "mallocA"})
        rpc(SOCK_A, "bdev_lvol_create_lvstore",
            {"bdev_name": "mallocA", "lvs_name": "lvsA", "cluster_sz": CLUSTER_SZ})
        rpc(SOCK_A, "bdev_lvol_create",
            {"lvol_name": "volA", "size_in_mib": VOL_MIB, "lvs_name": "lvsA",
             "thin_provision": True})
        rpc(SOCK_A, "bdev_lvol_set_leader_all",
            {"lvs_name": "lvsA", "lvs_leadership": True, "bs_nonleadership": False})
        rpc(SOCK_A, "bdev_lvol_create_poller_group", {"cpu_mask": "0x0C"})
        nqn_a = nvmf_up(SOCK_A, "ccvolA", "lvsA/volA", PORT_A)

        dev_a = host_connect(nqn_a, PORT_A)
        connected.append(nqn_a)
        print(f"    volA = {dev_a}")

        print("=== base pattern: 32 MiB at 0, 8 MiB at 64 MiB")
        sh(f"dd if=/dev/urandom of={dev_a} bs=1M count=32 oflag=direct status=none")
        sh(f"dd if=/dev/urandom of={dev_a} bs=1M count=8 seek=64 oflag=direct status=none")
        sh("sync")

        print("=== snapshot S1 on the source")
        rpc(SOCK_A, "bdev_lvol_snapshot",
            {"lvol_name": "lvsA/volA", "snapshot_name": "S1"})
        info = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/S1"})
        print(f"    S1 dirty info: {info}")
        assert info["tracking"] and info["complete"], f"S1 unusable: {info}"

        rpc(SOCK_A, "bdev_nvme_attach_controller",
            {"name": "cchubr", "trtype": "TCP", "traddr": "127.0.0.1",
             "adrfam": "IPv4", "trsvcid": PORT_HUB, "subnqn": nqn_hub})

        print("=== seed the destination: FULL transfer of S1 into land1")
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S1", "offset": 0, "cluster_batch": 8,
             "gateway": "cchubrn1", "operation": "replicate",
             "lvol_id": map_id_of(SOCK_B, "lvsB", "land1")})
        st = wait_transfer_done(SOCK_A, "lvsA/S1")
        print(f"    seed transfer stat: {st}")
        assert st["full_clusters"] > 0 and st["partial_reqs"] == 0, st

        nqn_l1 = nvmf_up(SOCK_B, "ccland1", "lvsB/land1", PORT_L1)
        dev_l1 = host_connect(nqn_l1, PORT_L1)
        connected.append(nqn_l1)
        compare(dev_a, dev_l1, "seed (full transfer of S1)")
        # release the kernel handle before the volume becomes a read-only snapshot
        sh(f"nvme disconnect -n {nqn_l1}", check=False)
        connected.remove(nqn_l1)

        print("=== convert land1 to a snapshot: it is now the destination's S1")
        rpc(SOCK_B, "bdev_lvol_convert", {"lvol_name": "lvsB/land1"})

        # ---------------------------------------------------------------- case A
        print()
        print("=== CASE A: partial transfer onto a COW clone of the destination S1")
        print("--- sparse delta on the source")
        dd_8k(dev_a, 0, 0)        # cluster 0   -- allocated in S1
        dd_8k(dev_a, 3, 5)        # cluster 3   -- allocated in S1
        dd_8k(dev_a, 40, 2)       # cluster 40  -- NOT allocated in S1 (a hole)
        sh("sync")

        rpc(SOCK_A, "bdev_lvol_snapshot",
            {"lvol_name": "lvsA/volA", "snapshot_name": "S2"})
        info2 = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/S2"})
        print(f"    S2 dirty info: {info2}")
        assert info2["tracking"] and info2["complete"], f"S2 unusable: {info2}"
        assert info2["clusters_tracked"] == 3, info2

        print("--- landing volume = CLONE of the destination S1")
        rpc(SOCK_B, "bdev_lvol_clone",
            {"snapshot_name": "lvsB/land1", "clone_name": "land2"})
        mid2 = map_id_of(SOCK_B, "lvsB", "land2")
        nqn_l2 = nvmf_up(SOCK_B, "ccland2", "lvsB/land2", PORT_L2)
        dev_l2 = host_connect(nqn_l2, PORT_L2)
        connected.append(nqn_l2)
        print(f"    land2 = {dev_l2} (map_id {mid2})")

        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S2", "offset": 0, "cluster_batch": 8,
             "gateway": "cchubrn1", "operation": "replicate", "lvol_id": mid2,
             "allow_partial": True})
        st2 = wait_transfer_done(SOCK_A, "lvsA/S2")
        print(f"    partial transfer stat: {st2}")
        assert st2["partial_reqs"] > 0, f"not bitmap-driven: {st2}"
        assert st2["full_clusters"] == 0, f"fell back to full clusters: {st2}"
        full_pages = 3 * (CLUSTER_SZ // 4096)
        assert st2["pages_sent"] * 10 < full_pages, \
            f"sent too much: {st2['pages_sent']} of {full_pages}"
        compare(dev_a, dev_l2, "case A (partial onto a COW clone)")

        sh(f"nvme disconnect -n {nqn_l2}", check=False)
        connected.remove(nqn_l2)
        print("=== convert land2: it is now the destination's S2, chained to S1")
        rpc(SOCK_B, "bdev_lvol_convert", {"lvol_name": "lvsB/land2"})

        # ---------------------------------------------------------------- case B
        print()
        print("=== CASE B: FULL transfer onto a COW clone (the fallback path)")
        dd_8k(dev_a, 1, 0)        # cluster 1   -- allocated
        dd_8k(dev_a, 5, 9)        # cluster 5   -- allocated
        dd_8k(dev_a, 50, 1)       # cluster 50  -- another hole
        sh("sync")

        rpc(SOCK_A, "bdev_lvol_snapshot",
            {"lvol_name": "lvsA/volA", "snapshot_name": "S3"})

        rpc(SOCK_B, "bdev_lvol_clone",
            {"snapshot_name": "lvsB/land2", "clone_name": "land3"})
        mid3 = map_id_of(SOCK_B, "lvsB", "land3")
        nqn_l3 = nvmf_up(SOCK_B, "ccland3", "lvsB/land3", PORT_L3)
        dev_l3 = host_connect(nqn_l3, PORT_L3)
        connected.append(nqn_l3)
        print(f"    land3 = {dev_l3} (map_id {mid3})")

        # no allow_partial: exactly what the control plane sends when the
        # generation is not complete and it must fall back
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S3", "offset": 0, "cluster_batch": 8,
             "gateway": "cchubrn1", "operation": "replicate", "lvol_id": mid3})
        st3 = wait_transfer_done(SOCK_A, "lvsA/S3")
        print(f"    full transfer stat: {st3}")
        assert st3["partial_reqs"] == 0, f"should not be bitmap-driven: {st3}"
        assert st3["full_clusters"] > 0, st3
        compare(dev_a, dev_l3, "case B (full onto a COW clone)")

        sh(f"nvme disconnect -n {nqn_l3}", check=False)
        connected.remove(nqn_l3)
        print("=== convert land3: it is now the destination's S3")
        rpc(SOCK_B, "bdev_lvol_convert", {"lvol_name": "lvsB/land3"})

        # ---------------------------------------------------------------- case C
        print()
        print("=== CASE C: tracking INVALIDATED -- allow_partial must be ignored")
        # A cluster-freeing unmap takes a cluster out of the blob map, and no
        # generation can express "this cluster is gone", so the blob layer gives
        # the generation up. It only frees anything on a PARENTLESS blob though:
        # on a clone, an unmap has to write zeroes instead, because letting the
        # cluster go would make reads fall through to the parent's data rather
        # than return zeroes. volA has been a clone since its first snapshot, so
        # this case needs its own fresh volume. (bdev_lvol_resize is the other
        # map-shrinking op, but it is refused with EBUSY while exported.)
        rpc(SOCK_A, "bdev_lvol_create",
            {"lvol_name": "volB", "size_in_mib": VOLB_MIB, "lvs_name": "lvsA",
             "thin_provision": True})
        nqn_b = nvmf_up(SOCK_A, "ccvolB", "lvsA/volB", PORT_B)
        dev_b = host_connect(nqn_b, PORT_B)
        connected.append(nqn_b)
        print(f"    volB = {dev_b} (parentless, so an unmap can free a cluster)")

        sh(f"dd if=/dev/urandom of={dev_b} bs=1M count=16 oflag=direct status=none")
        sh("sync")
        pre = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/volB"})
        assert pre["complete"], f"volB should start out tracked: {pre}"

        sh(f"blkdiscard -o {2 * CLUSTER_SZ} -l {CLUSTER_SZ} {dev_b}")
        sh("sync")
        live = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/volB"})
        print(f"    volB dirty info after the cluster-freeing discard: {live}")
        assert not live["complete"], \
            f"a cluster-freeing unmap must invalidate the generation: {live}"

        rpc(SOCK_A, "bdev_lvol_snapshot",
            {"lvol_name": "lvsA/volB", "snapshot_name": "SB1"})
        infob = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/SB1"})
        print(f"    SB1 dirty info: {infob}")
        assert not infob["complete"], \
            f"SB1 inherited the invalidated generation and must not be complete: {infob}"

        rpc(SOCK_B, "bdev_lvol_create",
            {"lvol_name": "land4", "size_in_mib": VOLB_MIB, "lvs_name": "lvsB",
             "thin_provision": True})
        mid4 = map_id_of(SOCK_B, "lvsB", "land4")
        nqn_l4 = nvmf_up(SOCK_B, "ccland4", "lvsB/land4", PORT_L4)
        dev_l4 = host_connect(nqn_l4, PORT_L4)
        connected.append(nqn_l4)
        print(f"    land4 = {dev_l4} (map_id {mid4})")

        # allow_partial IS requested. The lvol layer has to refuse it, because
        # the generation no longer describes every mutation -- honouring the
        # bitmap here would silently drop whatever it failed to record.
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/SB1", "offset": 0, "cluster_batch": 8,
             "gateway": "cchubrn1", "operation": "replicate", "lvol_id": mid4,
             "allow_partial": True})
        st4 = wait_transfer_done(SOCK_A, "lvsA/SB1")
        print(f"    stat with allow_partial on an invalid generation: {st4}")
        assert st4["partial_reqs"] == 0, \
            f"an incomplete generation must NOT drive a partial transfer: {st4}"
        assert st4["full_clusters"] > 0, st4
        compare(dev_b, dev_l4, "case C (invalidated -> full fallback)",
                mib=VOLB_MIB)

        # ---------------------------------------------------------------- case D
        print()
        print("=== CASE D: the control plane's own sequence -- fresh landing "
              "volume, then bdev_lvol_add_clone, then the partial transfer")
        # The control plane does NOT create the landing volume with
        # bdev_lvol_clone: it keeps add_lvol_ha (which it needs for the HA pair
        # and the internal=True admission bypass) and attaches the parent
        # afterwards with bdev_lvol_add_clone. That has to establish the same
        # COW parent, or a partial transfer into it loses everything outside
        # the delta -- so assert the parentage explicitly, not just the bytes.
        dd_8k(dev_a, 6, 0)
        dd_8k(dev_a, 60, 1)     # a hole in the parent again
        sh("sync")
        rpc(SOCK_A, "bdev_lvol_snapshot",
            {"lvol_name": "lvsA/volA", "snapshot_name": "S5"})
        info5 = rpc(SOCK_A, "bdev_lvol_dirty_bitmap_info", {"lvol_name": "lvsA/S5"})
        print(f"    S5 dirty info: {info5}")
        assert info5["complete"], info5

        rpc(SOCK_B, "bdev_lvol_create",
            {"lvol_name": "land5", "size_in_mib": VOL_MIB, "lvs_name": "lvsB",
             "thin_provision": True})
        # Exactly the JSON the control plane sends. Note rpc_client.py's
        # bdev_lvol_add_clone(lvol_name, parent_snapshot_name) SWAPS its two
        # arguments on the way out: the RPC's "lvol_name" is the PARENT and its
        # "child_name" is the volume being chained under it. Sending them the
        # other way round fails with EPERM, because it tries to make the
        # read-only predecessor snapshot into somebody's child.
        rpc(SOCK_B, "bdev_lvol_add_clone", {"lvol_name": "lvsB/land3",
                                            "child_name": "lvsB/land5"})

        for name in ("land5", "land3"):
            b = rpc(SOCK_B, "bdev_get_bdevs", {"name": f"lvsB/{name}"})[0]
            lv = b.get("driver_specific", {}).get("lvol", {})
            print(f"    {name}: clone={lv.get('clone')} snapshot={lv.get('snapshot')} "
                  f"base_snapshot={lv.get('base_snapshot')}")
        land5 = rpc(SOCK_B, "bdev_get_bdevs", {"name": "lvsB/land5"})[0]
        land5_lvol = land5.get("driver_specific", {}).get("lvol", {})
        assert land5_lvol.get("base_snapshot") == "land3", (
            "bdev_lvol_add_clone(landing, predecessor) did NOT make the landing "
            "volume a clone of the predecessor -- its base_snapshot is "
            f"{land5_lvol.get('base_snapshot')!r}. The landing volume has no COW "
            "parent, so a partial transfer into it would silently lose every "
            "cluster outside the delta.")

        mid5 = map_id_of(SOCK_B, "lvsB", "land5")
        nqn_l5 = nvmf_up(SOCK_B, "ccland5", "lvsB/land5", PORT_L5)
        dev_l5 = host_connect(nqn_l5, PORT_L5)
        connected.append(nqn_l5)
        rpc(SOCK_A, "bdev_lvol_transfer",
            {"lvol_name": "lvsA/S5", "offset": 0, "cluster_batch": 8,
             "gateway": "cchubrn1", "operation": "replicate", "lvol_id": mid5,
             "allow_partial": True})
        st5 = wait_transfer_done(SOCK_A, "lvsA/S5")
        print(f"    partial transfer stat: {st5}")
        assert st5["partial_reqs"] > 0 and st5["full_clusters"] == 0, st5
        compare(dev_a, dev_l5, "case D (control-plane add_clone sequence)")

        print()
        print("=== PASS: a partial transfer onto a COW clone is byte-exact; the "
              "full-transfer fallback is byte-exact; an invalidated "
              "generation refuses to go partial at all; and the control "
              "plane's add_clone sequence produces the same COW parent")
    except BaseException as e:
        fail = e
    finally:
        if fail is not None and os.environ.get("DBX_KEEP"):
            print(f"DBX_KEEP set: leaving processes up for inspection ({fail})")
            return 1
        for nqn in connected:
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
