#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#
#  Integration test for the dirty-bitmap partial snapshot transfer.
#  Two spdk_tgt processes on one host, transfer over nvmf/tcp loopback,
#  content verification through the kernel nvme-tcp initiator.
#
#  Usage (as root, from the SPDK repo root):
#      test/lvol/dirty_bitmap_xfer/run.sh
set -euo pipefail

cd "$(dirname "$0")/../../.."

modprobe nvme-tcp

# two processes x -s 1024 plus runtime headroom
HUGE=$(cat /proc/sys/vm/nr_hugepages)
if [ "$HUGE" -lt 3072 ]; then
    echo 3072 > /proc/sys/vm/nr_hugepages
fi

# SIGKILL, not SIGTERM: a reactor wedged in an nvme reconnect storm never
# services the app-stop path and survives a plain pkill for hours.
pkill -9 -f "spdk_tgt -r /var/tmp/dbx_" 2>/dev/null || true
sleep 2
rm -f /var/tmp/dbx_a.sock /var/tmp/dbx_b.sock
# stale core-lock files from a killed run block core claims of the next one
rm -f /var/tmp/spdk_cpu_lock_*

SPDK_BIN=${SPDK_BIN:-build/bin/spdk_tgt} python3 test/lvol/dirty_bitmap_xfer/dbx_test.py
