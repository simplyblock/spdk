/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *   All rights reserved.
 */

/*
 * In-memory dirty tracking for snapshot replication.
 *
 * One bit per 8 KiB of blob data, kept per cluster, so a delta transfer can
 * ship only the blocks that were actually written instead of every 2 MiB
 * cluster the snapshot owns. Strictly in memory: nothing here is persisted,
 * and after a process restart the absence of a generation makes the transfer
 * fall back to full clusters.
 *
 * Generations mirror the snapshot rotation: the writable clone carries the
 * LIVE generation; when a snapshot is taken the clone's cluster map moves to
 * the snapshot (bs_snapshot_swap_cluster_maps) and its dirty generation moves
 * with it, while the clone starts a fresh, empty generation that is COMPLETE
 * by construction (the clone owns no clusters at that instant). At most three
 * generations exist per family: live + the two newest snapshots; older ones
 * are garbage collected when the next snapshot completes.
 *
 * A generation is COMPLETE only if it tracked every write since its epoch
 * began (blob creation or rotation). Anything that breaks that certainty --
 * a cluster-freeing unmap, a blob loaded from disk -- leaves or marks the
 * generation incomplete and the transfer sends full clusters.
 */

#ifndef SPDK_BLOB_DIRTY_H
#define SPDK_BLOB_DIRTY_H

#include "spdk/stdinc.h"
#include "spdk/blob.h"

#define BLOB_DIRTY_BLOCK_SZ	SPDK_BLOB_DIRTY_BLOCK_SZ	/* 1 bit per 8 KiB */
#define BLOB_DIRTY_SEG_SZ	(64 * 1024)	/* coalescing segment (preferred IO size) */
#define BLOB_DIRTY_SEG_BITS	(BLOB_DIRTY_SEG_SZ / BLOB_DIRTY_BLOCK_SZ)	/* 8 */
/* Cost model for coalescing: issuing one extra IO is worth ~16 KiB of
 * needless payload. An aligned 64 KiB segment is sent WHOLE when
 * dirty_bytes + 16K * (runs - 1) >= 64K -- so 32K+24K in one segment beats
 * two IOs, while 16K+8K (or two 4K writes) stays two small IOs. */
#define BLOB_DIRTY_IO_COST_BYTES	(16 * 1024)

#define BLOB_DIRTY_HASH_BUCKETS	256

struct blob_dirty_cluster {
	uint64_t			idx;
	struct blob_dirty_cluster	*next;
	uint64_t			bits[];
};

struct blob_dirty_gen {
	uint64_t	gen_id;
	/* The blobstore's leadership epoch when the generation started; set by
	 * the blob layer. A different current epoch means the node lost or
	 * gained leadership since, and writes may have bypassed this bitmap. */
	uint64_t	epoch;
	/* The blob whose content the generation's writes apply on top of; set
	 * by the blob layer (see spdk_blob_dirty_gen_base). */
	spdk_blob_id	base;
	/* Clusters were allocated without data while this generation tracked
	 * the blob (the transfer alloc step): until spdk_blob_merge_base fills
	 * their unwritten blocks from the parent, those read as zeroes, not as
	 * the base, and the generation is not a valid delta. Kept here, not on
	 * the blob, so it travels with the generation through a snapshot. */
	bool		merge_pending;
	bool		complete;
	/* One reference for the owning blob plus one per in-flight transfer
	 * that captured this generation. The family-cap GC in
	 * bs_snapshot_origblob_sync_cpl drops the blob's reference while a
	 * replication task may still be walking the bitmaps, so the last
	 * holder -- not the blob -- is what actually destroys it. */
	int		refcnt;
	uint32_t	cluster_sz;
	uint32_t	bits_per_cluster;
	uint32_t	words_per_cluster;
	uint64_t	num_tracked;	/* clusters that have a bitmap */
	uint64_t	dirty_bits;	/* total set bits across all bitmaps */
	pthread_spinlock_t lock;
	struct blob_dirty_cluster *buckets[BLOB_DIRTY_HASH_BUCKETS];
};

struct blob_dirty_gen *blob_dirty_gen_create(uint32_t cluster_sz);

/* Drop the caller's reference; the generation is destroyed when the last one
 * goes away. Named _free because the owning blob is the common caller. */
void blob_dirty_gen_free(struct blob_dirty_gen *gen);

/* Something happened this generation cannot represent (e.g. a cluster-freeing
 * unmap). The generation survives for accounting but is no longer a valid
 * basis for a partial transfer. */
void blob_dirty_gen_invalidate(struct blob_dirty_gen *gen);

/* Record a host write of byte_len bytes at byte_off. Creates the cluster
 * bitmap on first touch. Thread-safe (IO threads race on the same blob). */
void blob_dirty_mark(struct blob_dirty_gen *gen, uint64_t byte_off, uint64_t byte_len);

/* PURE coalescing core (the unit-test surface): translate one cluster's bit
 * words into transfer ranges (in 8 KiB blocks, relative to cluster start),
 * applying the 64 KiB segment rule and merging contiguous output ranges.
 * Returns the number of ranges written to out (at most max_out). */
/* Copy cluster cluster_idx's bit words into out (nwords of them). False when
 * the cluster has no bitmap (nothing of it was written in this generation). */
bool blob_dirty_cluster_words(struct blob_dirty_gen *gen, uint64_t cluster_idx,
			      uint64_t *out, uint32_t nwords);

/* PURE: the runs of CLEAR bits in [0, nbits) -- the blocks NOT written -- as
 * ranges in blocks, each run as long as it goes, in address order. out must hold
 * nbits / 2 + 1 entries (alternating bits); returns the number of runs, which
 * exceeds max_out when out was too short (only max_out are written). */
uint32_t blob_dirty_clean_ranges(const uint64_t *words, uint32_t nbits,
				 struct blob_dirty_range *out, uint32_t max_out);

uint32_t blob_dirty_coalesce(const uint64_t *words, uint32_t nwords,
			     struct blob_dirty_range *out, uint32_t max_out);

#endif /* SPDK_BLOB_DIRTY_H */
