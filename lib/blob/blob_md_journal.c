/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *
 *   LVS metadata (page) journaling with torn-write protection.
 *   See blob_md_journal.h and blobstore_metadata_journal_design.md.
 */

#include "spdk/stdinc.h"
#include "spdk/blob.h"
#include "spdk/crc32.h"
#include "spdk/env.h"
#include "spdk/queue.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/log.h"

#include "blob_md_journal.h"

SPDK_LOG_REGISTER_COMPONENT(blob_md_journal)

#define JOURNAL_SLOT_INVALID	UINT32_MAX
#define DICT_EMPTY_KEY		UINT64_MAX
#define DICT_TOMBSTONE_KEY	(UINT64_MAX - 1)
/* twice the slot count, power of two -> low load factor, linear probing */
#define DICT_NUM_BUCKETS	(BS_MD_JOURNAL_NUM_SLOTS * 2)

struct md_journal_entry_hdr {
	uint32_t	magic;
	uint32_t	crc;		/* CRC32C of the 4K md page */
	uint64_t	target_lba;	/* home LBA, base-dev blocks */
	/* bs_io_opts of the originating md write (simplyblock fork routing
	 * hints); persisted so the deferred home write — including one issued
	 * by recovery after a crash — replays with identical routing */
	uint8_t		io_priority;
	uint8_t		io_geometry;
	uint8_t		io_special;
	uint8_t		io_rsvd;
};

/* journal-generated IO (ring writes/reads, entry zeroing) uses default
 * routing, matching bs-level md sequences (request.c: geometry 0) */
static struct spdk_bs_io_opts g_ring_io_opts;

struct md_journal_dict_bucket {
	uint64_t	lba;	/* DICT_EMPTY_KEY / DICT_TOMBSTONE_KEY / target lba */
	uint32_t	slot;
};

struct md_journal_append_op {
	/* caller payload; exactly one of payload / iov is set */
	void				*payload;
	struct iovec			*iov;
	int				iovcnt;
	uint64_t			lba;		/* first target lba */
	uint32_t			lba_count;	/* total blocks */
	uint32_t			blocks_done;
	/* write_zeroes/unmap journaled as all-zero page appends (no payload) */
	bool				zeroes;
	struct spdk_bs_io_opts		io_opts;	/* caller routing, per page */
	struct spdk_bs_dev_cb_args	*cb_args;
	TAILQ_ENTRY(md_journal_append_op) link;
};

struct md_journal_read_ctx {
	struct spdk_bs_md_journal	*jr;
	/* destination description for the overlay */
	void				*payload;
	struct iovec			*iov;
	int				iovcnt;
	uint64_t			lba;
	uint32_t			lba_count;
	/* issue-time snapshot of the dictionary hits (spec §7): the drain
	 * may complete a home write and recycle the slot while the home
	 * read is still in flight, so the newest page copies are captured
	 * when the read is issued, not looked up on completion */
	uint8_t				**hit_pages;	/* [num_pages], NULL = home */
	uint32_t			num_pages;
	struct spdk_bs_dev_cb_args	*orig_cb_args;
	struct spdk_bs_dev_cb_args	shim_cb_args;
};

struct spdk_bs_md_journal {
	struct spdk_bs_dev		*base;
	struct spdk_io_channel		*ch;		/* base-dev channel, md thread */
	struct spdk_thread		*md_thread;

	uint64_t			journal_start_lba;	/* base-dev blocks */
	uint32_t			blocks_per_page;	/* base-dev blocks per 4K page */
	uint64_t			md_limit_lba;		/* 0 = interception off */

	/* ring state; head == next append slot, tail == next drain slot.
	 * mem_* leads (assigned at issue), disk_* mirrors on-IO-completion
	 * state — the two pointer pairs of the specification. */
	uint32_t			mem_head, mem_tail;
	uint32_t			disk_head, disk_tail;
	uint32_t			used_slots;		/* mem view */

	/* in-memory copy of every journaled-but-undrained page (slot-indexed,
	 * DMA-able: it is the source of the drain home write) + header meta */
	uint8_t				*page_buf;		/* NUM_SLOTS * 4K */
	struct md_journal_entry_hdr	*slot_hdr;		/* NUM_SLOTS */
	/* lba -> newest slot dictionary, guarded by lock (spec: reads race
	 * with the drain thread) */
	struct md_journal_dict_bucket	*dict;
	uint32_t			dict_tombstones;
	struct spdk_spinlock		lock;

	/* append pipeline: strict FIFO, one journal write in flight (I3) */
	TAILQ_HEAD(, md_journal_append_op) append_queue;
	bool				append_inflight;
	uint8_t				*hdr_dma;		/* one 4K header staging block */
	/* cb_args must stay valid until IO completion; one append IO in
	 * flight -> one embedded instance */
	struct spdk_bs_dev_cb_args	append_cb_args;
	/* iov array of the in-flight append write: base devs may consume the
	 * iovs long after submit (the distrib bdev copies on its own poller
	 * thread), so it must not live on the submitting stack */
	struct iovec			append_iov[2];

	/* drain state: one entry in flight */
	struct spdk_poller		*drain_poller;
	bool				drain_paused;	/* test hook */
	/* set while this node is not the lvstore leader: the ring belongs to
	 * whoever is, so this process must not write to the shared device */
	bool				drain_demoted;
	/* waits for the append/drain pipeline to quiesce before a rescan */
	struct spdk_poller		*rescan_poller;
	bool				drain_inflight;
	struct spdk_bs_dev_cb_args	drain_cb_args;
	bool				stopping;
	bool				destroy_pending;

	/* start (format/recovery) state */
	bs_md_journal_start_cb		start_cb;
	void				*start_cb_arg;
	uint8_t				*recovery_buf;		/* QDEPTH * 64K */
	uint32_t			recovery_next_chunk;
	uint32_t			recovery_chunks_done;
	uint32_t			recovery_inflight;
	int				recovery_rc;
	uint8_t				*entry_valid;		/* NUM_SLOTS bool */

	struct spdk_bs_dev		proxy;	/* what the blobstore sees */
};

#define __proxy_to_journal(d)	SPDK_CONTAINEROF(d, struct spdk_bs_md_journal, proxy)

static void md_journal_append_pump(struct spdk_bs_md_journal *jr);
static int md_journal_drain_poll(void *arg);
static void md_journal_finish_destroy(struct spdk_bs_md_journal *jr);

/* called from IO completion paths: if a deferred destroy is pending and no
 * base-dev IO remains in flight, finish the teardown. Returns true when the
 * journal was freed (caller must not touch it). */
static bool
md_journal_check_destroy(struct spdk_bs_md_journal *jr)
{
	if (!jr->destroy_pending) {
		return false;
	}
	if (jr->drain_inflight || jr->append_inflight || jr->recovery_inflight != 0) {
		return false;
	}
	md_journal_finish_destroy(jr);
	return true;
}

/* ---------------------------------------------------------------------- */
/* dictionary (linear probe, tombstones; all under jr->lock)              */

static uint32_t
dict_hash(uint64_t lba)
{
	/* splitmix64 finalizer */
	uint64_t z = lba + 0x9e3779b97f4a7c15ULL;

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return (uint32_t)(z ^ (z >> 31)) & (DICT_NUM_BUCKETS - 1);
}

static void
dict_put(struct spdk_bs_md_journal *jr, uint64_t lba, uint32_t slot)
{
	uint32_t i = dict_hash(lba);
	uint32_t first_tomb = UINT32_MAX;

	for (;;) {
		struct md_journal_dict_bucket *b = &jr->dict[i];

		if (b->lba == lba) {
			b->slot = slot;
			return;
		}
		if (b->lba == DICT_TOMBSTONE_KEY && first_tomb == UINT32_MAX) {
			first_tomb = i;
		} else if (b->lba == DICT_EMPTY_KEY) {
			if (first_tomb != UINT32_MAX) {
				i = first_tomb;
				jr->dict_tombstones--;
			}
			jr->dict[i].lba = lba;
			jr->dict[i].slot = slot;
			return;
		}
		i = (i + 1) & (DICT_NUM_BUCKETS - 1);
	}
}

static uint32_t
dict_get(struct spdk_bs_md_journal *jr, uint64_t lba)
{
	uint32_t i = dict_hash(lba);

	for (;;) {
		struct md_journal_dict_bucket *b = &jr->dict[i];

		if (b->lba == lba) {
			return b->slot;
		}
		if (b->lba == DICT_EMPTY_KEY) {
			return JOURNAL_SLOT_INVALID;
		}
		i = (i + 1) & (DICT_NUM_BUCKETS - 1);
	}
}

/* remove only if the mapping still points at @slot (a newer entry for the
 * same lba further up the ring must keep serving reads) */
static void
dict_remove_if_slot(struct spdk_bs_md_journal *jr, uint64_t lba, uint32_t slot)
{
	uint32_t i = dict_hash(lba);

	for (;;) {
		struct md_journal_dict_bucket *b = &jr->dict[i];

		if (b->lba == lba) {
			if (b->slot == slot) {
				b->lba = DICT_TOMBSTONE_KEY;
				jr->dict_tombstones++;
			}
			return;
		}
		if (b->lba == DICT_EMPTY_KEY) {
			return;
		}
		i = (i + 1) & (DICT_NUM_BUCKETS - 1);
	}
}

static void
dict_reset(struct spdk_bs_md_journal *jr)
{
	uint32_t i;

	for (i = 0; i < DICT_NUM_BUCKETS; i++) {
		jr->dict[i].lba = DICT_EMPTY_KEY;
		jr->dict[i].slot = JOURNAL_SLOT_INVALID;
	}
	jr->dict_tombstones = 0;
}

/* ---------------------------------------------------------------------- */
/* geometry helpers                                                        */

static uint64_t
slot_to_lba(struct spdk_bs_md_journal *jr, uint32_t slot)
{
	return jr->journal_start_lba + (uint64_t)slot * 2 * jr->blocks_per_page;
}

static uint8_t *
slot_page(struct spdk_bs_md_journal *jr, uint32_t slot)
{
	return jr->page_buf + (uint64_t)slot * BS_MD_JOURNAL_PAGE_SIZE;
}

static inline uint32_t
ring_next(uint32_t slot)
{
	return (slot + 1) % BS_MD_JOURNAL_NUM_SLOTS;
}

static bool
ring_full(struct spdk_bs_md_journal *jr)
{
	/* one guard slot keeps a completely-valid ring unambiguous */
	return jr->used_slots >= BS_MD_JOURNAL_NUM_SLOTS - 1;
}

/* ---------------------------------------------------------------------- */
/* append path (spec §5): FIFO, ack caller on journal-write completion     */

static void
append_op_complete(struct spdk_bs_md_journal *jr, struct md_journal_append_op *op, int rc)
{
	struct spdk_bs_dev_cb_args *cb_args = op->cb_args;

	free(op);
	cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, rc);
}

/* copy 4K page @page_idx out of the op's payload/iov into @dst */
static void
append_op_copy_page(struct md_journal_append_op *op, uint32_t page_idx, uint8_t *dst)
{
	uint64_t skip, copied = 0, len, n;
	int i;

	if (op->zeroes) {
		memset(dst, 0, BS_MD_JOURNAL_PAGE_SIZE);
		return;
	}

	if (op->payload != NULL) {
		memcpy(dst, (uint8_t *)op->payload + (uint64_t)page_idx * BS_MD_JOURNAL_PAGE_SIZE,
		       BS_MD_JOURNAL_PAGE_SIZE);
		return;
	}

	skip = (uint64_t)page_idx * BS_MD_JOURNAL_PAGE_SIZE;
	for (i = 0; i < op->iovcnt && copied < BS_MD_JOURNAL_PAGE_SIZE; i++) {
		len = op->iov[i].iov_len;
		if (skip >= len) {
			skip -= len;
			continue;
		}
		n = spdk_min(len - skip, BS_MD_JOURNAL_PAGE_SIZE - copied);
		memcpy(dst + copied, (uint8_t *)op->iov[i].iov_base + skip, n);
		copied += n;
		skip = 0;
	}
	assert(copied == BS_MD_JOURNAL_PAGE_SIZE);
}

static void
append_write_cpl(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	struct md_journal_append_op *op = TAILQ_FIRST(&jr->append_queue);
	uint32_t slot;

	assert(op != NULL);
	jr->append_inflight = false;

	if (jr->stopping) {
		TAILQ_REMOVE(&jr->append_queue, op, link);
		append_op_complete(jr, op, -ESHUTDOWN);
		md_journal_check_destroy(jr);
		return;
	}

	if (bserrno != 0) {
		SPDK_ERRLOG("md journal append failed: %d\n", bserrno);
		/* the slot was never acknowledged; roll the head back */
		spdk_spin_lock(&jr->lock);
		jr->mem_head = (jr->mem_head + BS_MD_JOURNAL_NUM_SLOTS - 1) % BS_MD_JOURNAL_NUM_SLOTS;
		jr->used_slots--;
		spdk_spin_unlock(&jr->lock);
		TAILQ_REMOVE(&jr->append_queue, op, link);
		append_op_complete(jr, op, bserrno);
		md_journal_append_pump(jr);
		return;
	}

	/* the entry just written is the one before mem_head */
	slot = (jr->mem_head + BS_MD_JOURNAL_NUM_SLOTS - 1) % BS_MD_JOURNAL_NUM_SLOTS;

	/* spec §5(2): keep the page in memory and index it, only then ack */
	spdk_spin_lock(&jr->lock);
	dict_put(jr, jr->slot_hdr[slot].target_lba, slot);
	jr->disk_head = jr->mem_head;
	spdk_spin_unlock(&jr->lock);

	op->blocks_done += jr->blocks_per_page;
	if (op->blocks_done >= op->lba_count) {
		TAILQ_REMOVE(&jr->append_queue, op, link);
		append_op_complete(jr, op, 0);
	}
	md_journal_append_pump(jr);
}

static void
md_journal_append_pump(struct spdk_bs_md_journal *jr)
{
	struct md_journal_append_op *op;
	struct md_journal_entry_hdr *hdr;
	uint32_t slot, page_idx;
	uint8_t *page;

	if (jr->append_inflight || jr->stopping) {
		return;
	}
	op = TAILQ_FIRST(&jr->append_queue);
	if (op == NULL) {
		return;
	}
	if (ring_full(jr)) {
		/* spec: wait for the drain thread to free a slot */
		return;
	}

	page_idx = op->blocks_done / jr->blocks_per_page;
	slot = jr->mem_head;

	/* stage the page copy first — it doubles as the in-memory copy and
	 * as the (DMA-able) source of the journal write payload block */
	page = slot_page(jr, slot);
	append_op_copy_page(op, page_idx, page);

	hdr = &jr->slot_hdr[slot];
	hdr->magic = BS_MD_JOURNAL_HDR_MAGIC;
	hdr->crc = spdk_crc32c_update(page, BS_MD_JOURNAL_PAGE_SIZE, 0);
	hdr->target_lba = op->lba + (uint64_t)page_idx * jr->blocks_per_page;
	hdr->io_priority = op->io_opts.priority;
	hdr->io_geometry = op->io_opts.geometry;
	hdr->io_special = op->io_opts.special_io;
	hdr->io_rsvd = 0;

	memset(jr->hdr_dma, 0, BS_MD_JOURNAL_PAGE_SIZE);
	memcpy(jr->hdr_dma, hdr, sizeof(*hdr));

	spdk_spin_lock(&jr->lock);
	jr->mem_head = ring_next(jr->mem_head);
	jr->used_slots++;
	spdk_spin_unlock(&jr->lock);
	jr->append_inflight = true;

	jr->append_iov[0].iov_base = jr->hdr_dma;
	jr->append_iov[0].iov_len = BS_MD_JOURNAL_PAGE_SIZE;
	jr->append_iov[1].iov_base = page;
	jr->append_iov[1].iov_len = BS_MD_JOURNAL_PAGE_SIZE;

	jr->append_cb_args.cb_fn = append_write_cpl;
	jr->append_cb_args.channel = jr->ch;
	jr->append_cb_args.cb_arg = jr;
	/* single 8K IO: [header][page] */
	jr->base->writev(jr->base, jr->ch, jr->append_iov, 2, slot_to_lba(jr, slot),
			 2 * jr->blocks_per_page, &jr->append_cb_args, &g_ring_io_opts);
}

static void
md_journal_append(struct spdk_bs_md_journal *jr, void *payload, struct iovec *iov, int iovcnt,
		  uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args,
		  struct spdk_bs_io_opts *bs_io_opts, bool zeroes)
{
	struct md_journal_append_op *op;

	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, -ENOMEM);
		return;
	}
	op->payload = payload;
	op->iov = iov;
	op->iovcnt = iovcnt;
	op->zeroes = zeroes;
	op->lba = lba;
	op->lba_count = lba_count;
	if (bs_io_opts != NULL) {
		op->io_opts = *bs_io_opts;
	}
	op->cb_args = cb_args;
	TAILQ_INSERT_TAIL(&jr->append_queue, op, link);
	md_journal_append_pump(jr);
}

/* ---------------------------------------------------------------------- */
/* drain (spec §6): home write from the in-memory copy, then zero entry    */

static void
drain_zero_cpl(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	uint32_t slot = jr->mem_tail;

	jr->drain_inflight = false;
	if (jr->stopping) {
		md_journal_check_destroy(jr);
		return;
	}
	if (bserrno != 0) {
		SPDK_ERRLOG("md journal entry zeroing failed: %d (retry)\n", bserrno);
		return;
	}

	spdk_spin_lock(&jr->lock);
	dict_remove_if_slot(jr, jr->slot_hdr[slot].target_lba, slot);
	jr->slot_hdr[slot].magic = 0;
	jr->mem_tail = ring_next(jr->mem_tail);
	jr->disk_tail = jr->mem_tail;
	jr->used_slots--;
	spdk_spin_unlock(&jr->lock);

	/* a slot was freed: unblock a waiting append */
	md_journal_append_pump(jr);
}

static void
drain_home_write_cpl(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;

	if (jr->stopping) {
		jr->drain_inflight = false;
		md_journal_check_destroy(jr);
		return;
	}
	if (bserrno != 0) {
		SPDK_ERRLOG("md journal home write failed: %d (retry)\n", bserrno);
		jr->drain_inflight = false;
		return;
	}

	/* spec §6(2): unmap (zero) both blocks of the entry */
	jr->drain_cb_args.cb_fn = drain_zero_cpl;
	jr->drain_cb_args.channel = jr->ch;
	jr->drain_cb_args.cb_arg = jr;
	jr->base->write_zeroes(jr->base, jr->ch, slot_to_lba(jr, jr->mem_tail),
			       2 * jr->blocks_per_page, &jr->drain_cb_args, &g_ring_io_opts);
}

static int
md_journal_drain_poll(void *arg)
{
	struct spdk_bs_md_journal *jr = arg;
	uint32_t slot;
	bool superseded;

	if (jr->drain_inflight || jr->stopping || jr->drain_paused ||
	    jr->drain_demoted) {
		return SPDK_POLLER_IDLE;
	}
	/* only entries whose journal write has completed (disk_head) may be
	 * drained — writing home before the log entry is durable would
	 * reintroduce the torn-write hole (I1/I2) */
	if (jr->mem_tail == jr->disk_head) {
		return SPDK_POLLER_IDLE;
	}

	slot = jr->mem_tail;
	jr->drain_inflight = true;

	/* coalescing: if a newer copy of this lba sits further up the ring,
	 * skip the home write — the newer entry will cover it (still FIFO
	 * per lba) — and just zero this entry. */
	spdk_spin_lock(&jr->lock);
	superseded = dict_get(jr, jr->slot_hdr[slot].target_lba) != slot;
	spdk_spin_unlock(&jr->lock);

	if (superseded) {
		jr->drain_cb_args.cb_fn = drain_zero_cpl;
		jr->drain_cb_args.channel = jr->ch;
		jr->drain_cb_args.cb_arg = jr;
		jr->base->write_zeroes(jr->base, jr->ch, slot_to_lba(jr, slot),
				       2 * jr->blocks_per_page, &jr->drain_cb_args,
				       &g_ring_io_opts);
		return SPDK_POLLER_BUSY;
	}

	{
		/* replay the originating write's routing (consumed synchronously
		 * at submit, a stack copy is fine — same pattern as request.c) */
		struct spdk_bs_io_opts home_opts = {
			.priority = jr->slot_hdr[slot].io_priority,
			.geometry = jr->slot_hdr[slot].io_geometry,
			.special_io = jr->slot_hdr[slot].io_special,
		};

		jr->drain_cb_args.cb_fn = drain_home_write_cpl;
		jr->drain_cb_args.channel = jr->ch;
		jr->drain_cb_args.cb_arg = jr;
		jr->base->write(jr->base, jr->ch, slot_page(jr, slot),
				jr->slot_hdr[slot].target_lba, jr->blocks_per_page,
				&jr->drain_cb_args, &home_opts);
	}
	return SPDK_POLLER_BUSY;
}

/* ---------------------------------------------------------------------- */
/* read overlay (spec §7)                                                  */

static void
overlay_copy_page(struct md_journal_read_ctx *ctx, uint32_t page_idx, const uint8_t *src)
{
	uint64_t skip, copied = 0, len, n;
	int i;

	if (ctx->payload != NULL) {
		memcpy((uint8_t *)ctx->payload + (uint64_t)page_idx * BS_MD_JOURNAL_PAGE_SIZE, src,
		       BS_MD_JOURNAL_PAGE_SIZE);
		return;
	}

	skip = (uint64_t)page_idx * BS_MD_JOURNAL_PAGE_SIZE;
	for (i = 0; i < ctx->iovcnt && copied < BS_MD_JOURNAL_PAGE_SIZE; i++) {
		len = ctx->iov[i].iov_len;
		if (skip >= len) {
			skip -= len;
			continue;
		}
		n = spdk_min(len - skip, BS_MD_JOURNAL_PAGE_SIZE - copied);
		memcpy((uint8_t *)ctx->iov[i].iov_base + skip, src + copied, n);
		copied += n;
		skip = 0;
	}
}

static void
overlay_ctx_free(struct md_journal_read_ctx *ctx)
{
	uint32_t i;

	if (ctx->hit_pages != NULL) {
		for (i = 0; i < ctx->num_pages; i++) {
			free(ctx->hit_pages[i]);
		}
		free(ctx->hit_pages);
	}
	free(ctx);
}

static void
overlay_read_cpl(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct md_journal_read_ctx *ctx = cb_arg;
	struct spdk_bs_dev_cb_args *orig = ctx->orig_cb_args;
	uint32_t i;

	if (bserrno == 0) {
		for (i = 0; i < ctx->num_pages; i++) {
			if (ctx->hit_pages[i] != NULL) {
				overlay_copy_page(ctx, i, ctx->hit_pages[i]);
			}
		}
	}

	overlay_ctx_free(ctx);
	orig->cb_fn(orig->channel, orig->cb_arg, bserrno);
}

static struct md_journal_read_ctx *
overlay_ctx_create(struct spdk_bs_md_journal *jr, void *payload, struct iovec *iov, int iovcnt,
		   uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct md_journal_read_ctx *ctx;
	uint32_t i;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->jr = jr;
	ctx->payload = payload;
	ctx->iov = iov;
	ctx->iovcnt = iovcnt;
	ctx->lba = lba;
	ctx->lba_count = lba_count;
	ctx->num_pages = lba_count / jr->blocks_per_page;
	ctx->orig_cb_args = cb_args;
	ctx->shim_cb_args.cb_fn = overlay_read_cpl;
	ctx->shim_cb_args.channel = cb_args->channel;
	ctx->shim_cb_args.cb_arg = ctx;

	ctx->hit_pages = calloc(ctx->num_pages, sizeof(*ctx->hit_pages));
	if (ctx->hit_pages == NULL) {
		free(ctx);
		return NULL;
	}

	/* snapshot every dictionary hit now — the slot may be drained and
	 * recycled before the home read completes, and the home read may
	 * return the pre-drain content of the page */
	spdk_spin_lock(&jr->lock);
	for (i = 0; i < ctx->num_pages; i++) {
		uint32_t slot = dict_get(jr, lba + (uint64_t)i * jr->blocks_per_page);

		if (slot == JOURNAL_SLOT_INVALID) {
			continue;
		}
		ctx->hit_pages[i] = malloc(BS_MD_JOURNAL_PAGE_SIZE);
		if (ctx->hit_pages[i] == NULL) {
			spdk_spin_unlock(&jr->lock);
			overlay_ctx_free(ctx);
			return NULL;
		}
		memcpy(ctx->hit_pages[i], slot_page(jr, slot), BS_MD_JOURNAL_PAGE_SIZE);
	}
	spdk_spin_unlock(&jr->lock);
	return ctx;
}

/* ---------------------------------------------------------------------- */
/* proxy bs_dev                                                            */

static inline bool
lba_is_md(struct spdk_bs_md_journal *jr, uint64_t lba, uint64_t lba_count)
{
	return jr->md_limit_lba != 0 && lba + lba_count <= jr->md_limit_lba;
}

static struct spdk_io_channel *
proxy_create_channel(struct spdk_bs_dev *dev)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	return jr->base->create_channel(jr->base);
}

static void
proxy_destroy_channel(struct spdk_bs_dev *dev, struct spdk_io_channel *channel)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	jr->base->destroy_channel(jr->base, channel);
}

static void
proxy_destroy(struct spdk_bs_dev *dev)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	jr->stopping = true;
	spdk_poller_unregister(&jr->drain_poller);
	if (jr->drain_inflight || jr->append_inflight || jr->recovery_inflight != 0) {
		/* an IO against the base dev is still in flight; its completion
		 * callback finishes the teardown (md_journal_check_destroy) */
		jr->destroy_pending = true;
		return;
	}
	md_journal_finish_destroy(jr);
}

static void
proxy_read(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	   uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args,
	   struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		struct md_journal_read_ctx *ctx =
			overlay_ctx_create(jr, payload, NULL, 0, lba, lba_count, cb_args);

		if (ctx == NULL) {
			/* a raw fallback read could serve pages the journal
			 * has not written home yet — fail instead */
			cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, -ENOMEM);
			return;
		}
		jr->base->read(jr->base, channel, payload, lba, lba_count, &ctx->shim_cb_args,
			       bs_io_opts);
		return;
	}
	jr->base->read(jr->base, channel, payload, lba, lba_count, cb_args, bs_io_opts);
}

static void
proxy_write(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	    uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args,
	    struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		md_journal_append(jr, payload, NULL, 0, lba, lba_count, cb_args, bs_io_opts, false);
		return;
	}
	jr->base->write(jr->base, channel, payload, lba, lba_count, cb_args, bs_io_opts);
}

static void
proxy_readv(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	    struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
	    struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		struct md_journal_read_ctx *ctx =
			overlay_ctx_create(jr, NULL, iov, iovcnt, lba, lba_count, cb_args);

		if (ctx == NULL) {
			cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, -ENOMEM);
			return;
		}
		jr->base->readv(jr->base, channel, iov, iovcnt, lba, lba_count,
				&ctx->shim_cb_args, bs_io_opts);
		return;
	}
	jr->base->readv(jr->base, channel, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts);
}

static void
proxy_writev(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	     struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
	     struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		md_journal_append(jr, NULL, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts, false);
		return;
	}
	jr->base->writev(jr->base, channel, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts);
}

static void
proxy_readv_ext(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
		struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
		struct spdk_bs_dev_cb_args *cb_args, struct spdk_blob_ext_io_opts *ext_opts,
		struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		struct md_journal_read_ctx *ctx =
			overlay_ctx_create(jr, NULL, iov, iovcnt, lba, lba_count, cb_args);

		if (ctx == NULL) {
			cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, -ENOMEM);
			return;
		}
		jr->base->readv_ext(jr->base, channel, iov, iovcnt, lba, lba_count,
				    &ctx->shim_cb_args, ext_opts, bs_io_opts);
		return;
	}
	jr->base->readv_ext(jr->base, channel, iov, iovcnt, lba, lba_count, cb_args, ext_opts,
			    bs_io_opts);
}

static void
proxy_writev_ext(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
		 struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
		 struct spdk_bs_dev_cb_args *cb_args, struct spdk_blob_ext_io_opts *ext_opts,
		 struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (lba_is_md(jr, lba, lba_count)) {
		md_journal_append(jr, NULL, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts, false);
		return;
	}
	jr->base->writev_ext(jr->base, channel, iov, iovcnt, lba, lba_count, cb_args, ext_opts,
			     bs_io_opts);
}

static void
proxy_flush(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	    struct spdk_bs_dev_cb_args *cb_args)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	jr->base->flush(jr->base, channel, cb_args);
}

static void
proxy_write_zeroes(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
		   uint64_t lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args,
		   struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	/* md-range zeroing (e.g. blob delete / md-chain release zeroing pages
	 * in place, blob_persist_zero_pages) MUST take the same FIFO path as
	 * journaled page writes: a raw passthrough races the deferred home
	 * write of an older journaled copy of the same page, and the drain
	 * would then resurrect the zeroed page on disk. Journal it as an
	 * append of all-zero pages. */
	if (lba_is_md(jr, lba, lba_count) &&
	    lba % jr->blocks_per_page == 0 && lba_count % jr->blocks_per_page == 0) {
		md_journal_append(jr, NULL, NULL, 0, lba, (uint32_t)lba_count, cb_args,
				  bs_io_opts, true);
		return;
	}
	jr->base->write_zeroes(jr->base, channel, lba, lba_count, cb_args, bs_io_opts);
}

static void
proxy_unmap(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	    uint64_t lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args,
	    struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	/* same ordering hazard as proxy_write_zeroes: unmapped md ranges read
	 * back as zeros, so journaling an all-zero page append is equivalent
	 * and keeps FIFO order with pending journaled writes of the page */
	if (lba_is_md(jr, lba, lba_count) &&
	    lba % jr->blocks_per_page == 0 && lba_count % jr->blocks_per_page == 0) {
		md_journal_append(jr, NULL, NULL, 0, lba, (uint32_t)lba_count, cb_args,
				  bs_io_opts, true);
		return;
	}
	jr->base->unmap(jr->base, channel, lba, lba_count, cb_args, bs_io_opts);
}

static struct spdk_bdev *
proxy_get_base_bdev(struct spdk_bs_dev *dev)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	if (jr->base->get_base_bdev != NULL) {
		return jr->base->get_base_bdev(jr->base);
	}
	return NULL;
}

static bool
proxy_is_zeroes(struct spdk_bs_dev *dev, uint64_t lba, uint64_t lba_count)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	return jr->base->is_zeroes(jr->base, lba, lba_count);
}

static bool
proxy_is_range_valid(struct spdk_bs_dev *dev, uint64_t lba, uint64_t lba_count)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	return jr->base->is_range_valid(jr->base, lba, lba_count);
}

static bool
proxy_translate_lba(struct spdk_bs_dev *dev, uint64_t lba, uint64_t *base_lba)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	return jr->base->translate_lba(jr->base, lba, base_lba);
}

static void
proxy_copy(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	   uint64_t dst_lba, uint64_t src_lba, uint64_t lba_count,
	   struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	jr->base->copy(jr->base, channel, dst_lba, src_lba, lba_count, cb_args, bs_io_opts);
}

static bool
proxy_is_degraded(struct spdk_bs_dev *dev)
{
	struct spdk_bs_md_journal *jr = __proxy_to_journal(dev);

	return jr->base->is_degraded(jr->base);
}

/* ---------------------------------------------------------------------- */
/* start: fresh format (zero ring) or recovery scan (spec §8)              */

static void
start_finish(struct spdk_bs_md_journal *jr, int rc)
{
	bs_md_journal_start_cb cb = jr->start_cb;
	void *cb_arg = jr->start_cb_arg;

	spdk_free(jr->recovery_buf);
	jr->recovery_buf = NULL;
	free(jr->entry_valid);
	jr->entry_valid = NULL;
	jr->start_cb = NULL;

	if (rc == 0) {
		jr->drain_poller = SPDK_POLLER_REGISTER(md_journal_drain_poll, jr, 0);
	}
	if (cb != NULL) {
		cb(cb_arg, rc);
	}
}

uint64_t
bs_md_journal_ring_lba(struct spdk_bs_md_journal *jr)
{
	return jr->journal_start_lba;
}

uint64_t
bs_md_journal_ring_lba_count(struct spdk_bs_md_journal *jr)
{
	return (BS_MD_JOURNAL_SIZE_BYTES / BS_MD_JOURNAL_PAGE_SIZE) * jr->blocks_per_page;
}

static void
recovery_rebuild(struct spdk_bs_md_journal *jr)
{
	uint32_t n = BS_MD_JOURNAL_NUM_SLOTS;
	uint32_t first_empty = UINT32_MAX;
	uint32_t i, s, run_len = 0, valid_total = 0;

	for (i = 0; i < n; i++) {
		if (!jr->entry_valid[i] && first_empty == UINT32_MAX) {
			first_empty = i;
		}
		valid_total += jr->entry_valid[i];
	}

	if (valid_total == 0) {
		SPDK_NOTICELOG("md journal recovery: ring empty\n");
		start_finish(jr, 0);
		return;
	}
	if (first_empty == UINT32_MAX) {
		/* cannot happen with the guard slot */
		SPDK_ERRLOG("md journal recovery: ring fully valid, order ambiguous\n");
		start_finish(jr, -EIO);
		return;
	}

	/* the valid entries form one contiguous run in ring order (zero-on-
	 * drain guarantees it): walk from the first empty slot forward, the
	 * run start is the recovered tail. */
	s = first_empty;
	while (!jr->entry_valid[s]) {
		s = ring_next(s);
		if (s == first_empty) {
			break;
		}
	}

	spdk_spin_lock(&jr->lock);
	jr->mem_tail = jr->disk_tail = s;
	for (i = s; jr->entry_valid[i]; i = ring_next(i)) {
		dict_put(jr, jr->slot_hdr[i].target_lba, i);	/* FIFO: later wins */
		run_len++;
	}
	jr->mem_head = jr->disk_head = i;
	jr->used_slots = run_len;
	spdk_spin_unlock(&jr->lock);

	if (run_len != valid_total) {
		SPDK_ERRLOG("md journal recovery: %u valid entries outside the contiguous "
			    "run of %u are treated as empty\n", valid_total - run_len, run_len);
	}
	SPDK_NOTICELOG("md journal recovery: %u entries to drain (tail=%u head=%u)\n",
		       run_len, jr->mem_tail, jr->mem_head);
	start_finish(jr, 0);
}

static void recovery_issue_next(struct spdk_bs_md_journal *jr, uint32_t buf_idx);

static void
recovery_chunk_cpl(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct md_journal_read_ctx *rctx = cb_arg;
	struct spdk_bs_md_journal *jr = rctx->jr;
	uint32_t buf_idx = (uint32_t)rctx->lba_count;	/* stashed buffer index */
	uint32_t chunk = (uint32_t)rctx->lba;		/* stashed chunk index */
	uint32_t entries_per_chunk = BS_MD_JOURNAL_RECOVERY_IO_SIZE / BS_MD_JOURNAL_ENTRY_BYTES;
	uint8_t *buf = jr->recovery_buf + (uint64_t)buf_idx * BS_MD_JOURNAL_RECOVERY_IO_SIZE;
	uint32_t i;

	free(rctx);
	jr->recovery_inflight--;
	jr->recovery_chunks_done++;

	if (jr->stopping) {
		if (!md_journal_check_destroy(jr) && jr->recovery_inflight == 0) {
			start_finish(jr, -ESHUTDOWN);
		}
		return;
	}

	if (bserrno != 0) {
		SPDK_ERRLOG("md journal recovery read (chunk %u) failed: %d\n", chunk, bserrno);
		jr->recovery_rc = bserrno;
	} else if (jr->recovery_rc == 0) {
		for (i = 0; i < entries_per_chunk; i++) {
			uint32_t slot = chunk * entries_per_chunk + i;
			struct md_journal_entry_hdr hdr;
			uint8_t *entry = buf + (uint64_t)i * BS_MD_JOURNAL_ENTRY_BYTES;
			uint8_t *page = entry + BS_MD_JOURNAL_PAGE_SIZE;

			memcpy(&hdr, entry, sizeof(hdr));
			/* zeroed and corrupted entries are both empty */
			if (hdr.magic != BS_MD_JOURNAL_HDR_MAGIC ||
			    spdk_crc32c_update(page, BS_MD_JOURNAL_PAGE_SIZE, 0) != hdr.crc) {
				continue;
			}
			jr->entry_valid[slot] = 1;
			jr->slot_hdr[slot] = hdr;
			memcpy(slot_page(jr, slot), page, BS_MD_JOURNAL_PAGE_SIZE);
		}
	}

	recovery_issue_next(jr, buf_idx);
}

static void
recovery_issue_next(struct spdk_bs_md_journal *jr, uint32_t buf_idx)
{
	uint32_t total_chunks = BS_MD_JOURNAL_SIZE_BYTES / BS_MD_JOURNAL_RECOVERY_IO_SIZE;
	struct md_journal_read_ctx *rctx;
	uint32_t chunk;

	if (jr->recovery_rc != 0 || jr->recovery_next_chunk >= total_chunks) {
		if (jr->recovery_inflight == 0) {
			if (jr->recovery_rc != 0) {
				start_finish(jr, jr->recovery_rc);
			} else {
				recovery_rebuild(jr);
			}
		}
		return;
	}

	chunk = jr->recovery_next_chunk++;
	rctx = calloc(1, sizeof(*rctx));
	if (rctx == NULL) {
		jr->recovery_rc = -ENOMEM;
		if (jr->recovery_inflight == 0) {
			start_finish(jr, -ENOMEM);
		}
		return;
	}
	rctx->jr = jr;
	rctx->lba = chunk;		/* stash chunk index */
	rctx->lba_count = buf_idx;	/* stash buffer index */
	rctx->shim_cb_args.cb_fn = recovery_chunk_cpl;
	rctx->shim_cb_args.channel = jr->ch;
	rctx->shim_cb_args.cb_arg = rctx;

	jr->recovery_inflight++;
	jr->base->read(jr->base, jr->ch,
		       jr->recovery_buf + (uint64_t)buf_idx * BS_MD_JOURNAL_RECOVERY_IO_SIZE,
		       jr->journal_start_lba +
		       (uint64_t)chunk * (BS_MD_JOURNAL_RECOVERY_IO_SIZE / BS_MD_JOURNAL_PAGE_SIZE) *
		       jr->blocks_per_page,
		       (BS_MD_JOURNAL_RECOVERY_IO_SIZE / BS_MD_JOURNAL_PAGE_SIZE) * jr->blocks_per_page,
		       &rctx->shim_cb_args, &g_ring_io_opts);
}

void
bs_md_journal_start(struct spdk_bs_md_journal *jr, bool fresh_format,
		    bs_md_journal_start_cb cb_fn, void *cb_arg)
{
	uint32_t i;

	jr->md_thread = spdk_get_thread();
	jr->start_cb = cb_fn;
	jr->start_cb_arg = cb_arg;

	jr->ch = jr->base->create_channel(jr->base);
	if (jr->ch == NULL) {
		jr->start_cb = NULL;
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	if (fresh_format) {
		/* the ring itself is zeroed by the caller's init batch
		 * (bs_md_journal_ring_lba/_count); nothing to read back */
		start_finish(jr, 0);
		return;
	}

	/* Arm interception for the whole proxy range before the caller
	 * issues its first md read: the super block is read before the
	 * metadata layout is known, and after a crash its newest version
	 * may still sit in the ring (torn or stale home copy). Overlaying
	 * is correct for any LBA — a dictionary miss passes through — and
	 * the caller tightens the limit once the super is parsed. */
	bs_md_journal_enable(jr, jr->journal_start_lba);

	/* recovery: read the whole ring with up to 32 parallel 64K IOs */
	jr->entry_valid = calloc(BS_MD_JOURNAL_NUM_SLOTS, 1);
	jr->recovery_buf = spdk_zmalloc((uint64_t)BS_MD_JOURNAL_RECOVERY_QDEPTH *
					BS_MD_JOURNAL_RECOVERY_IO_SIZE,
					BS_MD_JOURNAL_PAGE_SIZE, NULL,
					SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	if (jr->entry_valid == NULL || jr->recovery_buf == NULL) {
		start_finish(jr, -ENOMEM);
		return;
	}
	jr->recovery_next_chunk = 0;
	jr->recovery_chunks_done = 0;
	jr->recovery_inflight = 0;
	jr->recovery_rc = 0;
	for (i = 0; i < BS_MD_JOURNAL_RECOVERY_QDEPTH; i++) {
		recovery_issue_next(jr, i);
	}
}

/* ---------------------------------------------------------------------- */
/* rescan: recovery on an already-started journal (peer takeover)          */

static int
md_journal_rescan_start(struct spdk_bs_md_journal *jr)
{
	uint32_t i;

	jr->entry_valid = calloc(BS_MD_JOURNAL_NUM_SLOTS, 1);
	jr->recovery_buf = spdk_zmalloc((uint64_t)BS_MD_JOURNAL_RECOVERY_QDEPTH *
					BS_MD_JOURNAL_RECOVERY_IO_SIZE,
					BS_MD_JOURNAL_PAGE_SIZE, NULL,
					SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	if (jr->entry_valid == NULL || jr->recovery_buf == NULL) {
		start_finish(jr, -ENOMEM);
		return -ENOMEM;
	}

	/* drop the view built at load time: every pointer and every cached
	 * page is re-derived from the ring below */
	spdk_spin_lock(&jr->lock);
	dict_reset(jr);
	jr->mem_head = jr->mem_tail = jr->disk_head = jr->disk_tail = 0;
	jr->used_slots = 0;
	spdk_spin_unlock(&jr->lock);

	jr->recovery_next_chunk = 0;
	jr->recovery_chunks_done = 0;
	jr->recovery_inflight = 0;
	jr->recovery_rc = 0;
	SPDK_NOTICELOG("md journal rescan: re-reading the ring on takeover\n");
	for (i = 0; i < BS_MD_JOURNAL_RECOVERY_QDEPTH; i++) {
		recovery_issue_next(jr, i);
	}
	return 0;
}

static int
md_journal_rescan_quiesce_poll(void *arg)
{
	struct spdk_bs_md_journal *jr = arg;

	if (jr->stopping || jr->destroy_pending) {
		spdk_poller_unregister(&jr->rescan_poller);
		start_finish(jr, -ESHUTDOWN);
		return SPDK_POLLER_BUSY;
	}
	if (jr->drain_inflight || jr->append_inflight ||
	    !TAILQ_EMPTY(&jr->append_queue)) {
		return SPDK_POLLER_IDLE;
	}
	spdk_poller_unregister(&jr->rescan_poller);
	md_journal_rescan_start(jr);
	return SPDK_POLLER_BUSY;
}

void
bs_md_journal_rescan(struct spdk_bs_md_journal *jr, bs_md_journal_start_cb cb_fn,
		     void *cb_arg)
{
	assert(spdk_get_thread() == jr->md_thread);

	if (jr->stopping || jr->destroy_pending) {
		cb_fn(cb_arg, -ESHUTDOWN);
		return;
	}
	if (jr->start_cb != NULL || jr->rescan_poller != NULL) {
		/* a start/rescan is already running */
		cb_fn(cb_arg, -EBUSY);
		return;
	}

	jr->start_cb = cb_fn;
	jr->start_cb_arg = cb_arg;

	/* the drain poller must not touch the ring while it is re-read, and
	 * start_finish() re-registers it when the rescan completes */
	spdk_poller_unregister(&jr->drain_poller);

	if (jr->drain_inflight || jr->append_inflight ||
	    !TAILQ_EMPTY(&jr->append_queue)) {
		/* an entry write or home write is in flight: its completion
		 * still writes into the old buffer/pointers, so wait it out */
		jr->rescan_poller = SPDK_POLLER_REGISTER(md_journal_rescan_quiesce_poll,
							 jr, 200);
		return;
	}
	md_journal_rescan_start(jr);
}

void
bs_md_journal_set_leader(struct spdk_bs_md_journal *jr, bool leader)
{
	if (jr->drain_demoted == !leader) {
		return;
	}
	jr->drain_demoted = !leader;
	SPDK_NOTICELOG("md journal drain %s: this node is %s the lvstore leader "
		       "(%u entries held)\n", leader ? "resumed" : "stopped",
		       leader ? "again" : "no longer", jr->used_slots);
}

void
bs_md_journal_get_stats(struct spdk_bs_md_journal *jr, bool *enabled,
			uint32_t *num_slots, uint32_t *used_slots,
			uint32_t *mem_head, uint32_t *mem_tail,
			uint32_t *disk_head, uint32_t *disk_tail,
			bool *drain_paused, bool *drain_demoted)
{
	spdk_spin_lock(&jr->lock);
	*enabled = (jr->md_limit_lba != 0);
	*num_slots = BS_MD_JOURNAL_NUM_SLOTS;
	*used_slots = jr->used_slots;
	*mem_head = jr->mem_head;
	*mem_tail = jr->mem_tail;
	*disk_head = jr->disk_head;
	*disk_tail = jr->disk_tail;
	*drain_paused = jr->drain_paused;
	*drain_demoted = jr->drain_demoted;
	spdk_spin_unlock(&jr->lock);
}

void
bs_md_journal_set_drain_paused(struct spdk_bs_md_journal *jr, bool paused)
{
	SPDK_NOTICELOG("md journal drain %s\n", paused ? "PAUSED (test hook)" : "resumed");
	jr->drain_paused = paused;
}

void
bs_md_journal_enable(struct spdk_bs_md_journal *jr, uint64_t md_limit_lba)
{
	SPDK_NOTICELOG("md journal enabled: md limit lba %" PRIu64 ", ring @ lba %" PRIu64
		       " (%u slots)\n", md_limit_lba, jr->journal_start_lba,
		       (uint32_t)BS_MD_JOURNAL_NUM_SLOTS);
	jr->md_limit_lba = md_limit_lba;
}

static void
md_journal_finish_destroy(struct spdk_bs_md_journal *jr)
{
	struct spdk_bs_dev *base = jr->base;

	spdk_poller_unregister(&jr->drain_poller);
	spdk_poller_unregister(&jr->rescan_poller);
	if (jr->ch != NULL) {
		base->destroy_channel(base, jr->ch);
		jr->ch = NULL;
	}
	spdk_spin_destroy(&jr->lock);
	spdk_free(jr->page_buf);
	spdk_free(jr->hdr_dma);
	spdk_free(jr->recovery_buf);
	free(jr->entry_valid);
	free(jr->slot_hdr);
	free(jr->dict);
	free(jr);
	base->destroy(base);
}

/* ---------------------------------------------------------------------- */

struct spdk_bs_dev *
bs_md_journal_dev_create(struct spdk_bs_dev *base, struct spdk_bs_md_journal **_journal)
{
	struct spdk_bs_md_journal *jr;
	uint64_t journal_blocks;

	if (BS_MD_JOURNAL_PAGE_SIZE % base->blocklen != 0) {
		SPDK_ERRLOG("unsupported base blocklen %u\n", base->blocklen);
		return NULL;
	}
	journal_blocks = BS_MD_JOURNAL_SIZE_BYTES / base->blocklen;
	if (base->blockcnt <= 2 * journal_blocks) {
		SPDK_ERRLOG("device too small for md journal\n");
		return NULL;
	}

	jr = calloc(1, sizeof(*jr));
	if (jr == NULL) {
		return NULL;
	}
	jr->base = base;
	jr->blocks_per_page = BS_MD_JOURNAL_PAGE_SIZE / base->blocklen;
	/* highest offset of the actual (runtime) virtual device size */
	jr->journal_start_lba = base->blockcnt - journal_blocks;

	jr->page_buf = spdk_zmalloc((uint64_t)BS_MD_JOURNAL_NUM_SLOTS * BS_MD_JOURNAL_PAGE_SIZE,
				    BS_MD_JOURNAL_PAGE_SIZE, NULL, SPDK_ENV_SOCKET_ID_ANY,
				    SPDK_MALLOC_DMA);
	jr->hdr_dma = spdk_zmalloc(BS_MD_JOURNAL_PAGE_SIZE, BS_MD_JOURNAL_PAGE_SIZE, NULL,
				   SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	jr->slot_hdr = calloc(BS_MD_JOURNAL_NUM_SLOTS, sizeof(*jr->slot_hdr));
	jr->dict = calloc(DICT_NUM_BUCKETS, sizeof(*jr->dict));
	if (jr->page_buf == NULL || jr->hdr_dma == NULL || jr->slot_hdr == NULL ||
	    jr->dict == NULL) {
		spdk_free(jr->page_buf);
		spdk_free(jr->hdr_dma);
		free(jr->slot_hdr);
		free(jr->dict);
		free(jr);
		return NULL;
	}

	spdk_spin_init(&jr->lock);
	TAILQ_INIT(&jr->append_queue);
	dict_reset(jr);

	/* the blobstore sees a device shrunk by the ring — data clusters can
	 * never collide with the journal region. Every callback that receives
	 * the dev pointer must be an explicit shim (container_of safety); the
	 * base vtable is never exposed directly. */
	jr->proxy.blockcnt = jr->journal_start_lba;
	jr->proxy.blocklen = base->blocklen;
	jr->proxy.create_channel = proxy_create_channel;
	jr->proxy.destroy_channel = proxy_destroy_channel;
	jr->proxy.destroy = proxy_destroy;
	jr->proxy.read = proxy_read;
	jr->proxy.write = proxy_write;
	jr->proxy.readv = proxy_readv;
	jr->proxy.writev = proxy_writev;
	jr->proxy.readv_ext = base->readv_ext != NULL ? proxy_readv_ext : NULL;
	jr->proxy.writev_ext = base->writev_ext != NULL ? proxy_writev_ext : NULL;
	jr->proxy.flush = proxy_flush;
	jr->proxy.write_zeroes = proxy_write_zeroes;
	jr->proxy.unmap = proxy_unmap;
	jr->proxy.get_base_bdev = base->get_base_bdev != NULL ? proxy_get_base_bdev : NULL;
	jr->proxy.is_zeroes = base->is_zeroes != NULL ? proxy_is_zeroes : NULL;
	jr->proxy.is_range_valid = base->is_range_valid != NULL ? proxy_is_range_valid : NULL;
	jr->proxy.translate_lba = base->translate_lba != NULL ? proxy_translate_lba : NULL;
	jr->proxy.copy = base->copy != NULL ? proxy_copy : NULL;
	jr->proxy.is_degraded = base->is_degraded != NULL ? proxy_is_degraded : NULL;

	*_journal = jr;
	return &jr->proxy;
}
