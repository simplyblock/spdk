/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *
 *   LVS metadata (page) journaling with torn-write protection.
 *
 *   Per-LVS 64 MB journal ring reserved at the highest offset of the
 *   backing virtual device.  Every metadata-page write is redirected to
 *   the ring ([header block][4K md page] per entry), acknowledged to the
 *   caller once the journal write is durable, mirrored into an in-memory
 *   buffer + LBA dictionary (read-amplification avoidance), and drained
 *   to its home LBA by an asynchronous poller which then zeroes the
 *   entry.  Recovery re-reads the whole ring (<= 32 parallel 64 KB IOs),
 *   treats zeroed/corrupt entries as empty, rebuilds buffer/dictionary/
 *   pointers and lets the drain poller work off the backlog.
 *
 *   See blobstore_metadata_journal_design.md (rev 3).
 */

#ifndef SPDK_BLOB_MD_JOURNAL_H
#define SPDK_BLOB_MD_JOURNAL_H

#include "spdk/stdinc.h"
#include "spdk/blob.h"

#define BS_MD_JOURNAL_SIZE_BYTES	(64ULL * 1024 * 1024)
#define BS_MD_JOURNAL_PAGE_SIZE		4096ULL
/* One entry = header block + md-page block. */
#define BS_MD_JOURNAL_ENTRY_BYTES	(2 * BS_MD_JOURNAL_PAGE_SIZE)
#define BS_MD_JOURNAL_NUM_SLOTS		(BS_MD_JOURNAL_SIZE_BYTES / BS_MD_JOURNAL_ENTRY_BYTES)
#define BS_MD_JOURNAL_RECOVERY_IO_SIZE	(64ULL * 1024)
#define BS_MD_JOURNAL_RECOVERY_QDEPTH	32
#define BS_MD_JOURNAL_HDR_MAGIC		0x4D444A31 /* "MDJ1" */

struct spdk_bs_md_journal;

/* Wrap @base. The returned bs_dev reports blockcnt shrunk by 64 MB so the
 * blobstore can never allocate over the ring; md-range writes are
 * journaled and md-range reads are overlaid from the in-memory copies
 * once the journal is enabled. *_journal receives the journal handle.
 * Returns NULL on allocation failure (base is left untouched). */
struct spdk_bs_dev *bs_md_journal_dev_create(struct spdk_bs_dev *base,
					     struct spdk_bs_md_journal **_journal);

typedef void (*bs_md_journal_start_cb)(void *cb_arg, int bserrno);

/* Asynchronous bring-up on the blobstore md thread.
 * fresh_format=true  (spdk_bs_init): no disk IO — the caller must zero the
 * ring region (bs_md_journal_ring_lba/_count) in its init batch; completes
 * inline. Interception stays off until bs_md_journal_enable.
 * fresh_format=false (spdk_bs_load): run recovery (parallel scan, checksum
 * validation, buffer/dictionary/pointer rebuild) and arm interception for
 * the WHOLE proxy range — the super block is read before the md layout is
 * known and its newest version may still sit in the ring; the caller
 * tightens the range via bs_md_journal_enable once the super is parsed.
 * Also creates the journal's base-dev channel and registers the drain
 * poller. Must complete before any md read is issued on load. */
void bs_md_journal_start(struct spdk_bs_md_journal *journal, bool fresh_format,
			 bs_md_journal_start_cb cb_fn, void *cb_arg);

/* Ring region in base-dev blocks (above the proxy's blockcnt) — for the
 * spdk_bs_init batch to zero on fresh format. */
uint64_t bs_md_journal_ring_lba(struct spdk_bs_md_journal *journal);
uint64_t bs_md_journal_ring_lba_count(struct spdk_bs_md_journal *journal);

/* Re-run recovery on a journal that is already started, i.e. re-read the
 * ring, rebuild buffer/dictionary/pointers and let the drain poller work off
 * whatever backlog another node left behind.
 *
 * Needed because the ring is shared state on a shared device while the
 * in-memory buffer/dictionary is per process. A secondary that loaded the
 * lvstore while the primary was alive scanned the ring at ITS load time; the
 * entries the primary appended (and acknowledged) afterwards are invisible to
 * it. Recovering only on load is therefore not enough for the product's
 * failover path, which promotes an already-loaded peer
 * (bdev_lvol_update_lvstore + bdev_lvol_set_leader_all) instead of loading
 * the lvstore anew - without a rescan the new leader serves stale home pages
 * and appends over the dead leader's undrained entries.
 *
 * Runs on the md thread; the caller must not have md reads outstanding. The
 * rescan waits for the append/drain pipeline to quiesce first. */
void bs_md_journal_rescan(struct spdk_bs_md_journal *journal,
			  bs_md_journal_start_cb cb_fn, void *cb_arg);

/* Arm interception: every write/read whose LBA range lies entirely below
 * @md_limit_lba (exclusive, in base-dev blocks) goes through the journal.
 * Called once the metadata layout is known (super parsed / init layout). */
void bs_md_journal_enable(struct spdk_bs_md_journal *journal, uint64_t md_limit_lba);

/* Follow the lvstore's leadership: only the leader may drain.
 *
 * The drain poller is a background writer that the pre-journal md path did not
 * have - it keeps pushing this process's in-memory pages to their home LBAs on
 * the SHARED device with no IO to trigger it. A node that stops being the
 * leader but stays alive therefore keeps writing metadata behind the new
 * leader's back. That happens in the product on the network-outage path
 * (spdk_lvs_change_leader_state / groupid 0: freeze, block_port, leader=false,
 * process still running) and in the window before a writer-conflict abort
 * completes. Stopping the drain on demotion is the journal's half of that
 * contract; the buffer it was holding is rebuilt by bs_md_journal_rescan when
 * this node is promoted again.
 *
 * Called from spdk_bs_set_leader(). */
void bs_md_journal_set_leader(struct spdk_bs_md_journal *journal, bool leader);

/* Ring state as this process sees it, and the drain test hook (see
 * spdk_bs_md_journal_stats in include/spdk/blob.h). Pausing the drain lets a
 * test accumulate acknowledged-but-not-home entries: at any md rate the
 * blobstore can produce, the drain otherwise keeps the ring at ~1 entry, so
 * neither recovery-with-entries nor journal-full is reachable by workload
 * alone. */
void bs_md_journal_get_stats(struct spdk_bs_md_journal *journal, bool *enabled,
			     uint32_t *num_slots, uint32_t *used_slots,
			     uint32_t *mem_head, uint32_t *mem_tail,
			     uint32_t *disk_head, uint32_t *disk_tail,
			     bool *drain_paused, bool *drain_demoted);
void bs_md_journal_set_drain_paused(struct spdk_bs_md_journal *journal, bool paused);

/* Teardown happens through the proxy's bs_dev->destroy(): it quiesces
 * in-flight journal IO, frees the journal and destroys the base dev. */

#endif /* SPDK_BLOB_MD_JOURNAL_H */
