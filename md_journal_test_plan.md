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

## 4. Failover (needs >= 2 instances — later phase)
Secondary/tertiary takes over the shared virtual device and runs recovery on
lvstore load (spec §"Sudden power-off and fail-over"). Reuse the multipath
test harness (sbcli/scripts) on a 2-3 node cluster; kill primary mid-md-load,
verify secondary's journal recovery + no md loss. Blocked until single-node
suites are green.

## Status / blockers
- ultra repo local checkout stale (2026-04-22); origin auth (PAT in remote
  URL) broken -> cannot rebase md-journal or build current ultra until
  credentials are fixed. spdk-side work proceeds independently.
