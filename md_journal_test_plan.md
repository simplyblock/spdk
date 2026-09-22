# md-journal test plan (branch md-journal)

## 1. C unit tests (SPDK CUnit, test/unit/lib/blob/)
New suite `test/unit/lib/blob/blob_md_journal.c/blob_md_journal_ut.c` with an
in-memory mock bs_dev (pattern: existing blob ut bs_dev in test/unit/lib/blob).
Cases:
- U1  append/ack ordering: caller cb only after ring write; entry bytes on "disk"
- U2  read overlay: journaled-not-drained page served from dict, home stale
- U3  drain: home updated, both entry blocks zeroed, dict entry dropped
- U4  supersede-coalescing: two appends same LBA -> older drained without home write
- U5  ring full: 8191 entries stall the next append; drain frees -> proceeds
- U6  recovery: valid contiguous run rebuilt (tail/head/dict), drains after
- U7  recovery with torn entry (bad crc) and zeroed entries -> treated empty
- U8  recovery duplicates: later ring position wins in dict
- U9  power-off simulation: snapshot mock-dev buffer mid-workload, new journal
      instance on snapshot -> every acked write recoverable, unacked may vanish
- U10 proxy geometry: blockcnt shrunk by 64 MB; data write above limit passthrough
- U11 multi-page append (mask-style N-page write) FIFO order + single ack
- U12 destroy with in-flight IO (deferred teardown, no use-after-free)
- U13 read-vs-drain race: home read in flight while drain completes ->
      issue-time dict snapshot must win over stale device data (found
      as blob-md crc mismatch in single-node integration, 2026-08-04)

## 2. Build (EC2 Rocky 9 / Fedora)
Per ultra CI (docker/Dockerfile_spdk_ultra): spdk configured+built, then ultra
(CMake, DISTR_v2) links spdk. For unit tests only: spdk ./configure
--with-fio... not needed; `./configure && make -j` + `./test/unit/unittest.sh`
or direct CUnit binary. Host: i3en/m6i Rocky 9 (AMI ami-0dfc569a8686b9320,
key mtes01) — same constants as sbcli/scripts/setup_perf_test_multipath.py.

## 3. Integration tests (ultra python style, single node)
Model on ultra/testing + scripts/run_lvs_tests.sh (CI: spdk_container_lvstore_
unit_tests.yml — container + python suite driving RPCs):
- I1  regular ops: create lvstore/lvols/snapshots under IO; md reads/writes
      correct while journal active (lvol list/get consistency, blob md intact
      after bdev_lvol_* cycles)
- I2  sudden power-off: kill -9 SPDK container mid md-heavy workload
      (create/delete loop); restart; lvstore must load, all acked objects
      present, no torn-md load abort; repeat N rounds
- I3  torn-write injection: with ALLOW_FAILURE_GENERATION build flag (CI uses
      it), or dd partial 512B overwrite of a ring entry + of a home md page
      while down -> load must recover/ignore correctly
      NOTE representativeness: neither kill -9 (io_submit'ed IOs complete
      in-kernel, unsubmitted ones never start) nor AWS Nitro storage (16 KiB
      torn-write prevention on EBS/instance store) produces naturally torn
      4K writes, so ALL torn states must be synthesized by injection; the
      injected states model the 512B-sector-atomic worst case of the distr
      virtual device (the design's actual target)
- I6  torn HOME page repair (the headline scenario): synthesize valid ring
      entries (bit-exact magic+crc32c) for real md pages, tear those home
      pages (and the super, keeping sector 0) on the raw file -> load must
      succeed and repair every page byte-exactly from the ring
- I4  journal-full pressure: mass create/delete driving ring saturation;
      operations stall but complete; no errors
- I5  restart-recovery drain: fill ring, power off, restart, verify ring
      drains to empty (entries zeroed) and md pages land home

## 4. Failover — DONE (ultra scripts/run_mdj_failover_tests.sh,
##    DISTR_v2/src_scripts_test_local/mdj_failover_tests.py)
Rig: three bdts processes on one host. A device server owns the NVMe, builds
alceml (+jm) -> 2 distribs -> raid0 and exports the raid over nvmf-tcp; nodes
A and B (own RPC socket / shm-id / hugepages, --no-pci) both attach that one
namespace, so the lvstore's backing virtual device is shared exactly as a
primary/secondary pair shares a distr. The device server doubles as an
out-of-band ring observer (dbg_direct_io_read on the raid), so ring state is
read without asking either lvstore node.

- F1  failover integrity, >= 4 rounds alternating roles and takeover mode:
      'load' (peer bdev_examine's after the leader dies — design §8) and
      'preloaded' (peer loaded the lvstore while the leader was alive and is
      promoted with bdev_lvol_update_lvstore + bdev_lvol_set_leader_all — the
      product path). Every acked create present, every sync-acked delete gone.
- F2  recovery with entries: the drain keeps the ring at ~1 entry under any
      workload (6 parallel md clients still left 0 at kill time), so the
      journal exposes bdev_lvol_set_md_journal_drain for tests: pause, build a
      backlog of acked-but-not-home pages, kill -9, and require the takeover
      to replay exactly that many entries and drain to empty.
- F3  single-writer fencing (§11.2): SIGSTOP the leader, promote the peer,
      SIGCONT the old leader and let it attempt md writes.
- F4  journal-full failover: same as F2 with a deep backlog.

## Status / blockers
- Phases 1-3 green. Phase 3 produced one fix (journal rescan on promotion,
  design §8.1) and the drain-pause / ring-stats test interface
  (bdev_lvol_get_md_journal_stats, bdev_lvol_set_md_journal_drain).
- Not covered by the single-host rig: real multi-node behaviour on an
  sbcli-deployed cluster (hublvol redirect IO, ANA multipath, CP-driven
  demote/promote ordering). Those need the multipath harness on a real
  2-3 node cluster.
