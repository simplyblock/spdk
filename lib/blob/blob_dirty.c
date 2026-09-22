/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *   All rights reserved.
 */

#include "blob_dirty.h"

static uint64_t g_blob_dirty_gen_counter;

struct blob_dirty_gen *
blob_dirty_gen_create(uint32_t cluster_sz)
{
	struct blob_dirty_gen *gen;

	if (cluster_sz == 0 || cluster_sz % BLOB_DIRTY_BLOCK_SZ != 0) {
		return NULL;
	}

	gen = calloc(1, sizeof(*gen));
	if (gen == NULL) {
		return NULL;
	}

	gen->gen_id = __atomic_add_fetch(&g_blob_dirty_gen_counter, 1, __ATOMIC_SEQ_CST);
	gen->complete = true;
	gen->refcnt = 1;	/* the owning blob */
	gen->cluster_sz = cluster_sz;
	gen->bits_per_cluster = cluster_sz / BLOB_DIRTY_BLOCK_SZ;
	gen->words_per_cluster = (gen->bits_per_cluster + 63) / 64;
	if (pthread_spin_init(&gen->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		free(gen);
		return NULL;
	}
	return gen;
}

void
blob_dirty_gen_free(struct blob_dirty_gen *gen)
{
	struct blob_dirty_cluster *c, *next;
	uint32_t i;

	if (gen == NULL) {
		return;
	}
	if (__atomic_sub_fetch(&gen->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
		/* an in-flight transfer still reads these bitmaps */
		return;
	}
	for (i = 0; i < BLOB_DIRTY_HASH_BUCKETS; i++) {
		for (c = gen->buckets[i]; c != NULL; c = next) {
			next = c->next;
			free(c);
		}
	}
	pthread_spin_destroy(&gen->lock);
	free(gen);
}

void
blob_dirty_gen_invalidate(struct blob_dirty_gen *gen)
{
	if (gen == NULL) {
		return;
	}
	__atomic_store_n(&gen->complete, false, __ATOMIC_SEQ_CST);
}

static struct blob_dirty_cluster *
blob_dirty_cluster_get(struct blob_dirty_gen *gen, uint64_t cluster_idx, bool create)
{
	uint32_t bucket = cluster_idx % BLOB_DIRTY_HASH_BUCKETS;
	struct blob_dirty_cluster *c;

	for (c = gen->buckets[bucket]; c != NULL; c = c->next) {
		if (c->idx == cluster_idx) {
			return c;
		}
	}
	if (!create) {
		return NULL;
	}
	c = calloc(1, sizeof(*c) + gen->words_per_cluster * sizeof(uint64_t));
	if (c == NULL) {
		/* Cannot track this write; the generation no longer represents
		 * every mutation, so it must not drive a partial transfer. */
		blob_dirty_gen_invalidate(gen);
		return NULL;
	}
	c->idx = cluster_idx;
	c->next = gen->buckets[bucket];
	gen->buckets[bucket] = c;
	gen->num_tracked++;
	return c;
}

void
blob_dirty_mark(struct blob_dirty_gen *gen, uint64_t byte_off, uint64_t byte_len)
{
	uint64_t first_block, last_block, b;
	struct blob_dirty_cluster *c;
	uint64_t cluster_idx, bit;

	if (gen == NULL || byte_len == 0) {
		return;
	}

	first_block = byte_off / BLOB_DIRTY_BLOCK_SZ;
	last_block = (byte_off + byte_len - 1) / BLOB_DIRTY_BLOCK_SZ;

	pthread_spin_lock(&gen->lock);
	for (b = first_block; b <= last_block; b++) {
		cluster_idx = b / gen->bits_per_cluster;
		bit = b % gen->bits_per_cluster;
		c = blob_dirty_cluster_get(gen, cluster_idx, true);
		if (c == NULL) {
			break;	/* generation already invalidated */
		}
		if (!(c->bits[bit / 64] & (1ULL << (bit % 64)))) {
			c->bits[bit / 64] |= 1ULL << (bit % 64);
			gen->dirty_bits++;
		}
	}
	pthread_spin_unlock(&gen->lock);
}

/* Append a range, merging with the previous one when contiguous. */
static uint32_t
blob_dirty_emit(struct blob_dirty_range *out, uint32_t n, uint32_t max_out,
		uint32_t off, uint32_t len)
{
	if (n > 0 && out[n - 1].off + out[n - 1].len == off) {
		out[n - 1].len += len;
		return n;
	}
	if (n < max_out) {
		out[n].off = off;
		out[n].len = len;
		n++;
	}
	return n;
}

uint32_t
blob_dirty_coalesce(const uint64_t *words, uint32_t nwords,
		    struct blob_dirty_range *out, uint32_t max_out)
{
	uint32_t nsegs = nwords * 64 / BLOB_DIRTY_SEG_BITS;
	uint32_t n = 0;
	uint32_t seg, i;

	for (seg = 0; seg < nsegs; seg++) {
		/* BLOB_DIRTY_SEG_BITS == 8: one byte of the word per segment */
		uint8_t bits = (words[seg / 8] >> ((seg % 8) * 8)) & 0xff;
		uint32_t seg_base = seg * BLOB_DIRTY_SEG_BITS;
		uint32_t popcnt, runs;

		if (bits == 0) {
			continue;
		}

		popcnt = __builtin_popcount(bits);
		/* count 0->1 transitions == number of dirty runs */
		runs = __builtin_popcount((uint32_t)(bits & ~(bits << 1)));

		if ((uint64_t)popcnt * BLOB_DIRTY_BLOCK_SZ +
		    (uint64_t)(runs - 1) * BLOB_DIRTY_IO_COST_BYTES >= BLOB_DIRTY_SEG_SZ) {
			/* dense enough: one IO for the whole segment, holes and all */
			n = blob_dirty_emit(out, n, max_out, seg_base, BLOB_DIRTY_SEG_BITS);
			continue;
		}

		for (i = 0; i < BLOB_DIRTY_SEG_BITS; i++) {
			if (!(bits & (1u << i))) {
				continue;
			}
			uint32_t start = i;
			while (i + 1 < BLOB_DIRTY_SEG_BITS && (bits & (1u << (i + 1)))) {
				i++;
			}
			n = blob_dirty_emit(out, n, max_out, seg_base + start, i - start + 1);
		}
	}
	return n;
}

/* --- accessors used by the lvol transfer layer and RPCs -------------------- */

bool
spdk_blob_dirty_gen_complete(const struct blob_dirty_gen *gen)
{
	return gen != NULL && __atomic_load_n(&gen->complete, __ATOMIC_SEQ_CST);
}

/* A transfer task pins the generation it captured: the snapshot family cap
 * may drop the blob's reference (and NULL the blob's pointer) at any later
 * snapshot, and the task would otherwise walk freed bitmaps. */
void
spdk_blob_dirty_gen_ref(struct blob_dirty_gen *gen)
{
	if (gen == NULL) {
		return;
	}
	__atomic_add_fetch(&gen->refcnt, 1, __ATOMIC_SEQ_CST);
}

void
spdk_blob_dirty_gen_unref(struct blob_dirty_gen *gen)
{
	blob_dirty_gen_free(gen);
}

uint64_t
spdk_blob_dirty_gen_id(const struct blob_dirty_gen *gen)
{
	return gen ? gen->gen_id : 0;
}

uint64_t
spdk_blob_dirty_gen_tracked(const struct blob_dirty_gen *gen)
{
	return gen ? gen->num_tracked : 0;
}

uint64_t
spdk_blob_dirty_gen_bytes(const struct blob_dirty_gen *gen)
{
	return gen ? gen->dirty_bits * BLOB_DIRTY_BLOCK_SZ : 0;
}

uint32_t
spdk_blob_dirty_max_ranges(const struct blob_dirty_gen *gen)
{
	/* worst case: alternating bits -> one range per two blocks, plus one */
	return gen ? gen->bits_per_cluster / 2 + 1 : 0;
}

int
spdk_blob_dirty_cluster_ranges(struct blob_dirty_gen *gen, uint64_t cluster_idx,
			       struct blob_dirty_range *out, uint32_t max_out)
{
	struct blob_dirty_cluster *c;
	uint32_t n;

	if (gen == NULL) {
		return -1;
	}
	pthread_spin_lock(&gen->lock);
	c = blob_dirty_cluster_get(gen, cluster_idx, false);
	if (c == NULL) {
		pthread_spin_unlock(&gen->lock);
		return -1;	/* no bitmap: caller transfers the whole cluster */
	}
	n = blob_dirty_coalesce(c->bits, gen->words_per_cluster, out, max_out);
	pthread_spin_unlock(&gen->lock);
	return (int)n;
}
