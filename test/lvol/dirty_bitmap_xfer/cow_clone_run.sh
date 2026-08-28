#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
#  Integration test for landing a partial snapshot transfer on a COW CLONE --
#  the shape the control plane actually replicates in. Two spdk_tgt processes
#  on one host, transfer over nvmf/tcp loopback, content verification through
#  the kernel nvme-tcp initiator.
#
#  Usage (as root, from the SPDK repo root):
#      test/lvol/dirty_bitmap_xfer/cow_clone_run.sh
set -euo pipefail

cd "$(dirname "$0")/../../.."

modprobe nvme-tcp

# two processes x -s 1280 plus runtime headroom
HUGE=$(cat /proc/sys/vm/nr_hugepages)
if [ "$HUGE" -lt 3072 ]; then
    echo 3072 > /proc/sys/vm/nr_hugepages
fi

# A wedged reactor never services the app-stop path, so SIGKILL. Match on the
# socket name rather than the binary: these processes rename their comm to
# reactor_0, so pkill -x spdk_tgt does not find them.
pkill -9 -f "spdk_tgt -r /var/tmp/dbxc_" 2>/dev/null || true
sleep 2
rm -f /var/tmp/dbxc_a.sock /var/tmp/dbxc_b.sock
# stale core-lock files from a killed run block core claims of the next one
rm -f /var/tmp/spdk_cpu_lock_*

SPDK_BIN=${SPDK_BIN:-build/bin/spdk_tgt} \
    python3 test/lvol/dirty_bitmap_xfer/cow_clone_test.py
