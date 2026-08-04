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

/* Arm interception: every write/read whose LBA range lies entirely below
 * @md_limit_lba (exclusive, in base-dev blocks) goes through the journal.
 * Called once the metadata layout is known (super parsed / init layout). */
void bs_md_journal_enable(struct spdk_bs_md_journal *journal, uint64_t md_limit_lba);

/* Teardown happens through the proxy's bs_dev->destroy(): it quiesces
 * in-flight journal IO, frees the journal and destroys the base dev. */

#endif /* SPDK_BLOB_MD_JOURNAL_H */
