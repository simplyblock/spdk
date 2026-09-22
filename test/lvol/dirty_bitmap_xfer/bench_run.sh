#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2026 Simplyblock GmbH.
#  Transfer throughput benchmark wrapper -- see bench.py.
set -euo pipefail
cd "$(dirname "$0")/../../.."
modprobe nvme-tcp
HUGE=$(cat /proc/sys/vm/nr_hugepages)
if [ "$HUGE" -lt 3072 ]; then
    echo 3072 > /proc/sys/vm/nr_hugepages
fi
pkill -9 -f "spdk_tgt -r /var/tmp/dbx_" 2>/dev/null || true
sleep 2
rm -f /var/tmp/dbx_a.sock /var/tmp/dbx_b.sock /var/tmp/spdk_cpu_lock_*
python3 test/lvol/dirty_bitmap_xfer/bench.py
