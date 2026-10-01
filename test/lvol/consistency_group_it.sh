#!/usr/bin/env bash
#  Integration test wrapper for bdev_lvol_snapshot_group.
#
#  Self-contained on purpose (no autotest_common.sh): starts ONE spdk_tgt from
#  this build, hands its RPC socket to consistency_group_it.py, and tears the
#  target down whatever the verdict. Needs: root or passwordless sudo, the
#  nvme-tcp kernel module, nvme-cli, xxd, and ~2G of hugepages.
#
#  Usage: test/lvol/consistency_group_it.sh
set -e

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../..")
SOCK=/var/tmp/spdk_cg_it.sock
TGT_LOG=/tmp/spdk_cg_it_tgt.log

sudo sysctl -w vm.nr_hugepages=1024 >/dev/null

cleanup() {
    sudo nvme disconnect -n nqn.2016-06.io.spdk:cgmembers >/dev/null 2>&1 || true
    sudo nvme disconnect -n nqn.2016-06.io.spdk:cgsnaps >/dev/null 2>&1 || true
    if [[ -n "$tgt_pid" ]] && sudo kill -0 "$tgt_pid" 2>/dev/null; then
        sudo kill "$tgt_pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            sudo kill -0 "$tgt_pid" 2>/dev/null || break
            sleep 0.5
        done
        sudo kill -9 "$tgt_pid" 2>/dev/null || true
    fi
    sudo rm -f "$SOCK" /tmp/cg_writer_go /tmp/cg_writer_count \
        /tmp/cg_stamp.bin /tmp/cg_block.bin
}
trap cleanup EXIT

echo "starting spdk_tgt..."
sudo "$rootdir/build/bin/spdk_tgt" -r "$SOCK" -m 0x3 -s 1024 > "$TGT_LOG" 2>&1 &
tgt_pid=$!

for _ in $(seq 1 60); do
    if sudo "$rootdir/scripts/rpc.py" -s "$SOCK" spdk_get_version >/dev/null 2>&1; then
        break
    fi
    if ! sudo kill -0 "$tgt_pid" 2>/dev/null; then
        echo "spdk_tgt died on startup:" >&2
        tail -30 "$TGT_LOG" >&2
        exit 1
    fi
    sleep 1
done

sudo chmod 777 "$SOCK" 2>/dev/null || true
rc=0
sudo python3 "$testdir/consistency_group_it.py" "$SOCK" || rc=$?
echo "integration test exit code: $rc"
exit $rc
