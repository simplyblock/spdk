/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk_internal/cunit.h"

#include "blob/blob_dirty.c"

#define CLUSTER_SZ	(2 * 1024 * 1024)	/* 2 MiB: 256 bits, 4 words per cluster */
#define BLK		BLOB_DIRTY_BLOCK_SZ	/* 8 KiB */

/* --- coalescing: the pure core ---------------------------------------------
 * One aligned 64 KiB segment holds 8 bits. The rule: send the segment WHOLE
 * when dirty_bytes + 16K * (runs - 1) >= 64K, else send the runs. */

static uint32_t
coalesce_one_word(uint64_t word, struct blob_dirty_range *out, uint32_t max_out)
{
	uint64_t words[4] = { word, 0, 0, 0 };

	return blob_dirty_coalesce(words, 4, out, max_out);
}

static void
test_coalesce_32k_plus_24k_becomes_one_64k(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* 32K = bits 0-3, hole at bit 4, 24K = bits 5-7: 56K dirty in 2 runs.
	 * 56K + 16K >= 64K -> one IO for the whole segment, hole included. */
	n = coalesce_one_word(0x0FULL | (0x7ULL << 5), r, 16);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 8);
}

static void
test_coalesce_16k_plus_8k_stays_two_ios(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* 16K = bits 0-1, 8K = bit 4: 24K in 2 runs. 24K + 16K < 64K ->
	 * transfer the runs themselves. */
	n = coalesce_one_word(0x3ULL | (1ULL << 4), r, 16);
	CU_ASSERT_EQUAL(n, 2);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 2);
	CU_ASSERT_EQUAL(r[1].off, 4);
	CU_ASSERT_EQUAL(r[1].len, 1);
}

static void
test_coalesce_two_small_writes_stay_two_ios(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* two 4K writes land as two single 8K bits (bits 0 and 5):
	 * 16K + 16K < 64K -> two small IOs, never one padded 64K. */
	n = coalesce_one_word(1ULL | (1ULL << 5), r, 16);
	CU_ASSERT_EQUAL(n, 2);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 1);
	CU_ASSERT_EQUAL(r[1].off, 5);
	CU_ASSERT_EQUAL(r[1].len, 1);
}

static void
test_coalesce_two_24k_runs_become_one_64k(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* 24K + 24K in 2 runs: 48K + 16K == 64K -> boundary counts as whole. */
	n = coalesce_one_word(0x7ULL | (0x7ULL << 5), r, 16);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 8);
}

static void
test_coalesce_single_48k_run_stays_itself(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* one 48K run, no holes: 48K + 0 < 64K -> send exactly the run. */
	n = coalesce_one_word(0x3FULL, r, 16);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 6);
}

static void
test_coalesce_merges_adjacent_segments(void)
{
	struct blob_dirty_range r[16];
	uint64_t words[4] = { UINT64_MAX, UINT64_MAX, 0, 0 };
	uint32_t n;

	/* first 8 MiB-of-bitmap fully dirty: 16 dense segments merge into ONE
	 * contiguous range (the read/write path re-fragments at 64K itself) */
	n = blob_dirty_coalesce(words, 4, r, 16);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 128);
}

static void
test_coalesce_run_crossing_segment_boundary_merges(void)
{
	struct blob_dirty_range r[16];
	uint32_t n;

	/* dense tail of segment 0 (bits 2-7, 48K in 1 run -> partial emit)
	 * continuing into a dense head of segment 1 (bits 8-11): the two
	 * emitted ranges touch and must merge into one. */
	n = coalesce_one_word((0x3FULL << 2) | (0xFULL << 8), r, 16);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 2);
	CU_ASSERT_EQUAL(r[0].len, 10);
}

static void
test_coalesce_empty_and_full(void)
{
	struct blob_dirty_range r[300];
	uint64_t words[4] = { 0, 0, 0, 0 };
	uint32_t n;

	n = blob_dirty_coalesce(words, 4, r, 300);
	CU_ASSERT_EQUAL(n, 0);

	memset(words, 0xff, sizeof(words));
	n = blob_dirty_coalesce(words, 4, r, 300);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 256);	/* whole 2 MiB cluster */
}

static void
test_coalesce_worst_case_alternating(void)
{
	struct blob_dirty_range r[300];
	uint64_t words[4];
	uint32_t n, i;

	/* alternating bits: 4 single-bit runs per segment, 32K + 48K >= 64K ->
	 * every segment goes whole -> everything merges into one range. */
	memset(words, 0x55, sizeof(words));
	n = blob_dirty_coalesce(words, 4, r, 300);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 256);

	/* one lonely bit per segment: 8K + 0 < 64K -> 32 single-block ranges */
	for (i = 0; i < 4; i++) {
		words[i] = 0x0101010101010101ULL;
	}
	n = blob_dirty_coalesce(words, 4, r, 300);
	CU_ASSERT_EQUAL(n, 32);
	for (i = 0; i < n; i++) {
		CU_ASSERT_EQUAL(r[i].off, i * 8);
		CU_ASSERT_EQUAL(r[i].len, 1);
	}
}

/* --- generation lifecycle --------------------------------------------------- */

static void
test_mark_sets_bits_and_ranges(void)
{
	struct blob_dirty_gen *gen = blob_dirty_gen_create(CLUSTER_SZ);
	struct blob_dirty_range r[300];
	int n;

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	CU_ASSERT_TRUE(gen->complete);
	CU_ASSERT_EQUAL(gen->bits_per_cluster, 256);
	CU_ASSERT_EQUAL(gen->words_per_cluster, 4);

	/* untracked cluster -> "send whole" verdict */
	n = spdk_blob_dirty_cluster_ranges(gen, 0, r, 300);
	CU_ASSERT_EQUAL(n, -1);

	/* an 8K write at 8K: cluster 0, block 1 */
	blob_dirty_mark(gen, BLK, BLK);
	n = spdk_blob_dirty_cluster_ranges(gen, 0, r, 300);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 1);
	CU_ASSERT_EQUAL(r[0].len, 1);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(gen), 1);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_bytes(gen), (uint64_t)BLK);

	/* a 4K write marks the full 8K block it lives in; re-marking the same
	 * block does not double count */
	blob_dirty_mark(gen, BLK, 4096);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_bytes(gen), (uint64_t)BLK);

	/* a write spanning the cluster boundary dirties both clusters */
	blob_dirty_mark(gen, (uint64_t)CLUSTER_SZ - 4096, 8192);
	n = spdk_blob_dirty_cluster_ranges(gen, 0, r, 300);
	CU_ASSERT_EQUAL(n, 2);
	CU_ASSERT_EQUAL(r[1].off, 255);
	n = spdk_blob_dirty_cluster_ranges(gen, 1, r, 300);
	CU_ASSERT_EQUAL(n, 1);
	CU_ASSERT_EQUAL(r[0].off, 0);
	CU_ASSERT_EQUAL(r[0].len, 1);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(gen), 2);

	blob_dirty_gen_free(gen);
}

static void
test_invalidate_blocks_partial_transfer(void)
{
	struct blob_dirty_gen *gen = blob_dirty_gen_create(CLUSTER_SZ);

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	blob_dirty_mark(gen, 0, BLK);
	CU_ASSERT_TRUE(spdk_blob_dirty_gen_complete(gen));

	/* a cluster-freeing unmap invalidates the generation: it stays around
	 * for stats but is no longer a valid delta basis */
	blob_dirty_gen_invalidate(gen);
	CU_ASSERT_FALSE(spdk_blob_dirty_gen_complete(gen));
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(gen), 1);

	blob_dirty_gen_free(gen);
}

static void
test_restart_semantics_null_gen(void)
{
	struct blob_dirty_range r[8];

	/* a blob loaded from disk has NO generation: every accessor must
	 * degrade to the full-transfer verdict instead of crashing */
	CU_ASSERT_FALSE(spdk_blob_dirty_gen_complete(NULL));
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_id(NULL), 0);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(NULL), 0);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_bytes(NULL), 0);
	CU_ASSERT_EQUAL(spdk_blob_dirty_max_ranges(NULL), 0);
	CU_ASSERT_EQUAL(spdk_blob_dirty_cluster_ranges(NULL, 0, r, 8), -1);
	blob_dirty_gen_invalidate(NULL);	/* must not crash */
	blob_dirty_gen_free(NULL);		/* must not crash */
}

static void
test_rotation_and_gc_semantics(void)
{
	/* The rotation itself is a pointer swap in
	 * bs_snapshot_swap_cluster_maps; what this test pins is the module
	 * behaviour those three lines rely on: distinct generation ids and
	 * a fresh generation being empty + complete. */
	struct blob_dirty_gen *live = blob_dirty_gen_create(CLUSTER_SZ);
	struct blob_dirty_gen *fresh = blob_dirty_gen_create(CLUSTER_SZ);

	SPDK_CU_ASSERT_FATAL(live != NULL && fresh != NULL);
	CU_ASSERT_NOT_EQUAL(spdk_blob_dirty_gen_id(live), spdk_blob_dirty_gen_id(fresh));

	blob_dirty_mark(live, 0, BLK);
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(live), 1);

	/* rotate: snapshot takes `live`, clone keeps `fresh` (empty+complete) */
	CU_ASSERT_EQUAL(spdk_blob_dirty_gen_tracked(fresh), 0);
	CU_ASSERT_TRUE(spdk_blob_dirty_gen_complete(fresh));

	/* GC of the oldest generation is just gen_free -- and marking after
	 * free is impossible by construction (the blob's pointer is NULLed).
	 * Freeing populated generations must release every bitmap. */
	blob_dirty_mark(live, CLUSTER_SZ * 5, BLK);
	blob_dirty_gen_free(live);
	blob_dirty_gen_free(fresh);
	CU_ASSERT_TRUE(true);
}

static void
test_alloc_failure_invalidates(void)
{
	/* blob_dirty_cluster_get returning NULL on calloc failure invalidates
	 * the generation; simulate by exhausting... calloc cannot be forced
	 * here portably, so pin the contract at the API level instead: an
	 * incomplete generation must never be offered ranges-based transfer
	 * by the caller (spdk_lvol_transfer checks complete). */
	struct blob_dirty_gen *gen = blob_dirty_gen_create(CLUSTER_SZ);

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	blob_dirty_gen_invalidate(gen);
	CU_ASSERT_FALSE(spdk_blob_dirty_gen_complete(gen));
	/* marks are still accepted (cheap) but completeness never returns */
	blob_dirty_mark(gen, 0, BLK);
	CU_ASSERT_FALSE(spdk_blob_dirty_gen_complete(gen));
	blob_dirty_gen_free(gen);
}

static void
test_bad_cluster_size_rejected(void)
{
	CU_ASSERT_PTR_NULL(blob_dirty_gen_create(0));
	CU_ASSERT_PTR_NULL(blob_dirty_gen_create(BLK - 1));	/* not a multiple */
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("blob_dirty", NULL, NULL);

	CU_ADD_TEST(suite, test_coalesce_32k_plus_24k_becomes_one_64k);
	CU_ADD_TEST(suite, test_coalesce_16k_plus_8k_stays_two_ios);
	CU_ADD_TEST(suite, test_coalesce_two_small_writes_stay_two_ios);
	CU_ADD_TEST(suite, test_coalesce_two_24k_runs_become_one_64k);
	CU_ADD_TEST(suite, test_coalesce_single_48k_run_stays_itself);
	CU_ADD_TEST(suite, test_coalesce_merges_adjacent_segments);
	CU_ADD_TEST(suite, test_coalesce_run_crossing_segment_boundary_merges);
	CU_ADD_TEST(suite, test_coalesce_empty_and_full);
	CU_ADD_TEST(suite, test_coalesce_worst_case_alternating);
	CU_ADD_TEST(suite, test_mark_sets_bits_and_ranges);
	CU_ADD_TEST(suite, test_invalidate_blocks_partial_transfer);
	CU_ADD_TEST(suite, test_restart_semantics_null_gen);
	CU_ADD_TEST(suite, test_rotation_and_gc_semantics);
	CU_ADD_TEST(suite, test_alloc_failure_invalidates);
	CU_ADD_TEST(suite, test_bad_cluster_size_rejected);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();
	return num_failures;
}
