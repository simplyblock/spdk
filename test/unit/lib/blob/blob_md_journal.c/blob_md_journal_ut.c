/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock GmbH.
 *
 *   Unit tests for the LVS metadata (page) journal with torn-write
 *   protection (lib/blob/blob_md_journal.c).  Cases U1-U12 from
 *   md_journal_test_plan.md.
 *
 *   The tests drive the journal through its proxy bs_dev directly (no
 *   full blobstore) against an in-memory mock bs_dev with fully manual
 *   IO completion, so that ack ordering (I1), drain ordering (I2) and
 *   FIFO order (I3) can be asserted at every step.
 */

#include "spdk/stdinc.h"

#include "spdk_internal/cunit.h"
#include "spdk/blob.h"

#include "thread/thread_internal.h"

#include "common/lib/ut_multithread.c"
#include "thread/thread.c"
#include "blob/blob_md_journal.c"

#define UT_BLOCKLEN		4096
#define UT_DEV_SIZE		(192ULL * 1024 * 1024)
#define UT_BLOCKCNT		(UT_DEV_SIZE / UT_BLOCKLEN)
#define UT_JOURNAL_BLOCKS	(BS_MD_JOURNAL_SIZE_BYTES / UT_BLOCKLEN)
#define UT_MD_LIMIT_LBA		16384	/* first 64 MB are "metadata" */

/* ------------------------------------------------------------------ */
/* mock bs_dev: flat buffer, manual completion queue                   */

enum ut_io_type {
	UT_IO_READ,
	UT_IO_WRITE,
	UT_IO_WRITE_ZEROES,
};

struct ut_io {
	enum ut_io_type			type;
	uint64_t			lba;
	uint32_t			lba_count;
	uint8_t				*wdata;		/* write payload copy, applied on completion */
	void				*rpayload;	/* read destination (payload form) */
	struct iovec			*riov;		/* read destination (iov form) */
	int				riovcnt;
	struct spdk_bs_dev_cb_args	*cb_args;
	TAILQ_ENTRY(ut_io)		link;
};

struct ut_dev {
	struct spdk_bs_dev	bs_dev;
	uint8_t			*buf;		/* not owned */
	bool			destroyed;
	uint32_t		pending;
	uint64_t		writes_completed[3];	/* per ut_io_type counter */
	TAILQ_HEAD(, ut_io)	io_queue;
};

struct spdk_io_channel g_ut_io_channel;

static struct spdk_io_channel *
ut_dev_create_channel(struct spdk_bs_dev *dev)
{
	return &g_ut_io_channel;
}

static void
ut_dev_destroy_channel(struct spdk_bs_dev *dev, struct spdk_io_channel *channel)
{
}

static void
ut_dev_destroy(struct spdk_bs_dev *dev)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);

	CU_ASSERT(d->pending == 0);
	d->destroyed = true;
}

static struct ut_io *
ut_io_alloc(struct ut_dev *d, enum ut_io_type type, uint64_t lba, uint32_t lba_count,
	    struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_io *io = calloc(1, sizeof(*io));

	SPDK_CU_ASSERT_FATAL(io != NULL);
	io->type = type;
	io->lba = lba;
	io->lba_count = lba_count;
	io->cb_args = cb_args;
	TAILQ_INSERT_TAIL(&d->io_queue, io, link);
	d->pending++;
	return io;
}

static void
ut_dev_read(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	    uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);
	struct ut_io *io = ut_io_alloc(d, UT_IO_READ, lba, lba_count, cb_args);

	io->rpayload = payload;
}

static void
ut_dev_readv(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	     struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
	     struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);
	struct ut_io *io = ut_io_alloc(d, UT_IO_READ, lba, lba_count, cb_args);

	io->riov = iov;
	io->riovcnt = iovcnt;
}

static void
ut_dev_write(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	     uint64_t lba, uint32_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);
	struct ut_io *io = ut_io_alloc(d, UT_IO_WRITE, lba, lba_count, cb_args);
	uint64_t len = (uint64_t)lba_count * UT_BLOCKLEN;

	io->wdata = malloc(len);
	SPDK_CU_ASSERT_FATAL(io->wdata != NULL);
	memcpy(io->wdata, payload, len);
}

static void
ut_dev_writev(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	      struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
	      struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);
	struct ut_io *io = ut_io_alloc(d, UT_IO_WRITE, lba, lba_count, cb_args);
	uint64_t len = (uint64_t)lba_count * UT_BLOCKLEN;
	uint64_t off = 0;
	int i;

	io->wdata = malloc(len);
	SPDK_CU_ASSERT_FATAL(io->wdata != NULL);
	for (i = 0; i < iovcnt; i++) {
		memcpy(io->wdata + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}
	CU_ASSERT(off == len);
}

static void
ut_dev_write_zeroes(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
		    uint64_t lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);

	ut_io_alloc(d, UT_IO_WRITE_ZEROES, lba, lba_count, cb_args);
}

static void
ut_dev_flush(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	     struct spdk_bs_dev_cb_args *cb_args)
{
	cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, 0);
}

static void
ut_dev_unmap(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	     uint64_t lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct ut_dev *d = SPDK_CONTAINEROF(dev, struct ut_dev, bs_dev);

	ut_io_alloc(d, UT_IO_WRITE_ZEROES, lba, lba_count, cb_args);
}

/* Complete the oldest pending IO: apply its effect to the flat buffer,
 * then run the caller's completion (inline).  Returns false when idle. */
static bool
ut_dev_complete_one(struct ut_dev *d)
{
	struct ut_io *io = TAILQ_FIRST(&d->io_queue);
	struct spdk_bs_dev_cb_args *cb_args;
	uint64_t off, len;
	int i;

	if (io == NULL) {
		return false;
	}
	TAILQ_REMOVE(&d->io_queue, io, link);
	d->pending--;

	off = io->lba * UT_BLOCKLEN;
	len = (uint64_t)io->lba_count * UT_BLOCKLEN;
	SPDK_CU_ASSERT_FATAL(off + len <= UT_DEV_SIZE);

	switch (io->type) {
	case UT_IO_READ:
		if (io->rpayload != NULL) {
			memcpy(io->rpayload, d->buf + off, len);
		} else {
			uint64_t pos = off;

			for (i = 0; i < io->riovcnt; i++) {
				memcpy(io->riov[i].iov_base, d->buf + pos, io->riov[i].iov_len);
				pos += io->riov[i].iov_len;
			}
		}
		break;
	case UT_IO_WRITE:
		memcpy(d->buf + off, io->wdata, len);
		break;
	case UT_IO_WRITE_ZEROES:
		memset(d->buf + off, 0, len);
		break;
	}
	d->writes_completed[io->type]++;

	cb_args = io->cb_args;
	free(io->wdata);
	free(io);
	cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, 0);
	return true;
}

static uint32_t
ut_dev_complete_all(struct ut_dev *d)
{
	uint32_t n = 0;

	while (ut_dev_complete_one(d)) {
		n++;
	}
	return n;
}

/* Alternate pollers (drain) and IO completion until the system is idle. */
static void
ut_settle(struct ut_dev *d)
{
	bool progress = true;

	while (progress) {
		progress = false;
		poll_threads();
		if (ut_dev_complete_all(d) > 0) {
			progress = true;
		}
	}
}

static void
ut_dev_init(struct ut_dev *d, uint8_t *buf)
{
	memset(d, 0, sizeof(*d));
	d->buf = buf;
	TAILQ_INIT(&d->io_queue);
	d->bs_dev.blockcnt = UT_BLOCKCNT;
	d->bs_dev.blocklen = UT_BLOCKLEN;
	d->bs_dev.create_channel = ut_dev_create_channel;
	d->bs_dev.destroy_channel = ut_dev_destroy_channel;
	d->bs_dev.destroy = ut_dev_destroy;
	d->bs_dev.read = ut_dev_read;
	d->bs_dev.write = ut_dev_write;
	d->bs_dev.readv = ut_dev_readv;
	d->bs_dev.writev = ut_dev_writev;
	d->bs_dev.flush = ut_dev_flush;
	d->bs_dev.write_zeroes = ut_dev_write_zeroes;
	d->bs_dev.unmap = ut_dev_unmap;
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */

struct ut_cb_ctx {
	bool	done;
	int	rc;
};

static void
ut_io_cb(struct spdk_io_channel *ch, void *cb_arg, int bserrno)
{
	struct ut_cb_ctx *ctx = cb_arg;

	CU_ASSERT(!ctx->done);
	ctx->done = true;
	ctx->rc = bserrno;
}

static void
ut_start_cb(void *cb_arg, int bserrno)
{
	struct ut_cb_ctx *ctx = cb_arg;

	CU_ASSERT(!ctx->done);
	ctx->done = true;
	ctx->rc = bserrno;
}

static void
ut_fill_page(uint8_t *page, uint64_t lba, uint8_t seed)
{
	uint32_t i;

	for (i = 0; i < BS_MD_JOURNAL_PAGE_SIZE; i++) {
		page[i] = (uint8_t)(seed ^ (lba & 0xff) ^ (i & 0xff));
	}
}

static struct ut_dev g_base;
static uint8_t *g_buf;
static struct spdk_bs_md_journal *g_jr;
static struct spdk_bs_dev *g_proxy;

/* create + start(fresh) + enable a journal over a zeroed mock dev */
static void
ut_journal_setup(void)
{
	struct ut_cb_ctx start_ctx = {};

	g_buf = calloc(1, UT_DEV_SIZE);
	SPDK_CU_ASSERT_FATAL(g_buf != NULL);
	ut_dev_init(&g_base, g_buf);

	g_jr = NULL;
	g_proxy = bs_md_journal_dev_create(&g_base.bs_dev, &g_jr);
	SPDK_CU_ASSERT_FATAL(g_proxy != NULL);
	SPDK_CU_ASSERT_FATAL(g_jr != NULL);

	/* fresh format: ring region already zeroed (calloc); completes inline */
	bs_md_journal_start(g_jr, true, ut_start_cb, &start_ctx);
	CU_ASSERT(start_ctx.done && start_ctx.rc == 0);

	bs_md_journal_enable(g_jr, UT_MD_LIMIT_LBA);
}

static void
ut_journal_teardown(void)
{
	ut_settle(&g_base);
	g_proxy->destroy(g_proxy);
	CU_ASSERT(g_base.destroyed);
	free(g_buf);
	g_buf = NULL;
	g_jr = NULL;
	g_proxy = NULL;
}

/* append one 4K md page and complete its journal write */
static void
ut_append_page(uint64_t lba, uint8_t seed)
{
	struct ut_cb_ctx ctx = {};
	uint8_t *page = malloc(BS_MD_JOURNAL_PAGE_SIZE);
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };

	SPDK_CU_ASSERT_FATAL(page != NULL);
	ut_fill_page(page, lba, seed);
	g_proxy->write(g_proxy, NULL, page, lba, 1, &cb_args);
	CU_ASSERT(!ctx.done);				/* I1: no ack before journal write */
	CU_ASSERT(ut_dev_complete_all(&g_base) >= 1);
	CU_ASSERT(ctx.done && ctx.rc == 0);
	free(page);
}

/* read one page through the proxy (completes the backing read inline) */
static void
ut_read_page(uint64_t lba, uint8_t *dst)
{
	struct ut_cb_ctx ctx = {};
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };

	g_proxy->read(g_proxy, NULL, dst, lba, 1, &cb_args);
	CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
	CU_ASSERT(ctx.done && ctx.rc == 0);
}

static uint8_t *
ut_disk_at(uint64_t lba)
{
	return g_buf + lba * UT_BLOCKLEN;
}

static bool
ut_mem_is_zero(const uint8_t *p, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; i++) {
		if (p[i] != 0) {
			return false;
		}
	}
	return true;
}

/* ------------------------------------------------------------------ */
/* U1: append/ack ordering (I1) + entry bytes on disk                  */

static void
test_append_ack_ordering(void)
{
	struct ut_cb_ctx ctx = {};
	uint8_t *page = malloc(BS_MD_JOURNAL_PAGE_SIZE);
	uint8_t expect[BS_MD_JOURNAL_PAGE_SIZE];
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };
	struct md_journal_entry_hdr hdr;
	struct ut_io *io;
	uint64_t entry_lba;

	SPDK_CU_ASSERT_FATAL(page != NULL);
	ut_journal_setup();

	ut_fill_page(page, 5, 0xA5);
	memcpy(expect, page, sizeof(expect));

	g_proxy->write(g_proxy, NULL, page, 5, 1, &cb_args);

	/* the md write was redirected to the ring, not to LBA 5 */
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	entry_lba = slot_to_lba(g_jr, 0);
	CU_ASSERT(io->type == UT_IO_WRITE);
	CU_ASSERT(io->lba == entry_lba);
	CU_ASSERT(io->lba_count == 2 * g_jr->blocks_per_page);

	/* I1: caller must not be acknowledged before the journal write
	 * completes */
	CU_ASSERT(!ctx.done);
	CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
	CU_ASSERT(ctx.done && ctx.rc == 0);

	/* entry bytes on disk: [header block][md page] */
	memcpy(&hdr, ut_disk_at(entry_lba), sizeof(hdr));
	CU_ASSERT(hdr.magic == BS_MD_JOURNAL_HDR_MAGIC);
	CU_ASSERT(hdr.target_lba == 5);
	CU_ASSERT(hdr.crc == spdk_crc32c_update(expect, BS_MD_JOURNAL_PAGE_SIZE, 0));
	CU_ASSERT(memcmp(ut_disk_at(entry_lba + g_jr->blocks_per_page), expect,
			 BS_MD_JOURNAL_PAGE_SIZE) == 0);

	/* the home LBA is untouched so far */
	CU_ASSERT(ut_mem_is_zero(ut_disk_at(5), BS_MD_JOURNAL_PAGE_SIZE));

	/* the journal keeps its own copy: caller buffer may be reused */
	memset(page, 0xFF, BS_MD_JOURNAL_PAGE_SIZE);
	{
		uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];

		ut_read_page(5, rbuf);
		CU_ASSERT(memcmp(rbuf, expect, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	CU_ASSERT(g_jr->used_slots == 1);
	CU_ASSERT(g_jr->mem_head == 1 && g_jr->disk_head == 1);

	free(page);
	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U2: read overlay serves the journaled page while home is stale      */

static void
test_read_overlay(void)
{
	uint8_t expect[BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t stale[BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];

	ut_journal_setup();

	/* stale home content */
	ut_fill_page(stale, 7, 0x11);
	memcpy(ut_disk_at(7), stale, BS_MD_JOURNAL_PAGE_SIZE);

	ut_fill_page(expect, 7, 0xB7);
	ut_append_page(7, 0xB7);

	/* home is still stale (no drain has run) ... */
	CU_ASSERT(memcmp(ut_disk_at(7), stale, BS_MD_JOURNAL_PAGE_SIZE) == 0);

	/* ... but the proxy read returns the journaled page (payload form) */
	memset(rbuf, 0, sizeof(rbuf));
	ut_read_page(7, rbuf);
	CU_ASSERT(memcmp(rbuf, expect, BS_MD_JOURNAL_PAGE_SIZE) == 0);

	/* iov form (readv) gets the same overlay */
	{
		struct ut_cb_ctx ctx = {};
		struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };
		uint8_t part1[1024], part2[3072];
		struct iovec iov[2] = {
			{ .iov_base = part1, .iov_len = sizeof(part1) },
			{ .iov_base = part2, .iov_len = sizeof(part2) },
		};

		g_proxy->readv(g_proxy, NULL, iov, 2, 7, 1, &cb_args);
		CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
		CU_ASSERT(ctx.done && ctx.rc == 0);
		CU_ASSERT(memcmp(part1, expect, sizeof(part1)) == 0);
		CU_ASSERT(memcmp(part2, expect + sizeof(part1), sizeof(part2)) == 0);
	}

	/* a page that was never journaled comes from home untouched */
	{
		uint8_t other[BS_MD_JOURNAL_PAGE_SIZE];

		ut_fill_page(other, 8, 0x22);
		memcpy(ut_disk_at(8), other, BS_MD_JOURNAL_PAGE_SIZE);
		memset(rbuf, 0, sizeof(rbuf));
		ut_read_page(8, rbuf);
		CU_ASSERT(memcmp(rbuf, other, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U3: drain writes home, zeroes both entry blocks, drops the dict     */

static void
test_drain(void)
{
	uint8_t expect[BS_MD_JOURNAL_PAGE_SIZE];
	uint64_t entry_lba;
	struct ut_io *io;

	ut_journal_setup();

	ut_fill_page(expect, 9, 0xC3);
	ut_append_page(9, 0xC3);
	CU_ASSERT(g_jr->used_slots == 1);
	entry_lba = slot_to_lba(g_jr, 0);

	/* drain step 1: home write from the in-memory copy */
	poll_threads();
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	CU_ASSERT(io->type == UT_IO_WRITE);
	CU_ASSERT(io->lba == 9);
	CU_ASSERT(io->lba_count == g_jr->blocks_per_page);

	/* I2: the entry must not be zeroed before the home write completed */
	CU_ASSERT(!ut_mem_is_zero(ut_disk_at(entry_lba), BS_MD_JOURNAL_ENTRY_BYTES));
	CU_ASSERT(ut_dev_complete_one(&g_base));

	/* drain step 2: zero both blocks of the entry */
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	CU_ASSERT(io->type == UT_IO_WRITE_ZEROES);
	CU_ASSERT(io->lba == entry_lba);
	CU_ASSERT(io->lba_count == 2 * g_jr->blocks_per_page);
	CU_ASSERT(ut_dev_complete_one(&g_base));

	/* end state: page home, entry zeroed, dict dropped, slot freed */
	CU_ASSERT(memcmp(ut_disk_at(9), expect, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	CU_ASSERT(ut_mem_is_zero(ut_disk_at(entry_lba), BS_MD_JOURNAL_ENTRY_BYTES));
	spdk_spin_lock(&g_jr->lock);
	CU_ASSERT(dict_get(g_jr, 9) == JOURNAL_SLOT_INVALID);
	spdk_spin_unlock(&g_jr->lock);
	CU_ASSERT(g_jr->used_slots == 0);
	CU_ASSERT(g_jr->mem_tail == 1 && g_jr->disk_tail == 1);

	/* a read now comes from home */
	{
		uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];

		ut_read_page(9, rbuf);
		CU_ASSERT(memcmp(rbuf, expect, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U4: two appends to the same LBA: the older entry is drained without
 * a home write (supersede-coalescing), the newer one lands home       */

static void
test_supersede_coalescing(void)
{
	uint8_t expect_b[BS_MD_JOURNAL_PAGE_SIZE];
	struct ut_io *io;

	ut_journal_setup();

	ut_append_page(11, 0x0A);		/* version A -> slot 0 */
	ut_append_page(11, 0x0B);		/* version B -> slot 1 */
	ut_fill_page(expect_b, 11, 0x0B);
	CU_ASSERT(g_jr->used_slots == 2);

	/* first drain step on slot 0 must be a zero, not a home write */
	poll_threads();
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	CU_ASSERT(io->type == UT_IO_WRITE_ZEROES);
	CU_ASSERT(io->lba == slot_to_lba(g_jr, 0));
	CU_ASSERT(ut_dev_complete_one(&g_base));
	CU_ASSERT(g_jr->used_slots == 1);
	/* the dictionary still serves version B */
	spdk_spin_lock(&g_jr->lock);
	CU_ASSERT(dict_get(g_jr, 11) == 1);
	spdk_spin_unlock(&g_jr->lock);

	/* second drain: home write of B, then zero of slot 1 */
	poll_threads();
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	CU_ASSERT(io->type == UT_IO_WRITE);
	CU_ASSERT(io->lba == 11);
	ut_settle(&g_base);

	CU_ASSERT(memcmp(ut_disk_at(11), expect_b, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	CU_ASSERT(g_jr->used_slots == 0);
	/* exactly one home write ever hit LBA 11 */
	CU_ASSERT(g_base.writes_completed[UT_IO_WRITE] == 2 /* journal entries */ + 1 /* home */);

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U5: ring full (8191 entries) stalls the next append; a drained slot
 * lets it proceed                                                     */

static void
test_ring_full_stall(void)
{
	struct ut_cb_ctx *ctxs;
	struct spdk_bs_dev_cb_args *cbs;
	uint8_t *page = malloc(BS_MD_JOURNAL_PAGE_SIZE);
	struct ut_cb_ctx stall_ctx = {};
	struct spdk_bs_dev_cb_args stall_cb = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &stall_ctx };
	uint32_t i, fill = BS_MD_JOURNAL_NUM_SLOTS - 1;	/* 8191: guard slot keeps one free */

	SPDK_CU_ASSERT_FATAL(page != NULL);
	ctxs = calloc(fill, sizeof(*ctxs));
	cbs = calloc(fill, sizeof(*cbs));
	SPDK_CU_ASSERT_FATAL(ctxs != NULL && cbs != NULL);

	ut_journal_setup();

	for (i = 0; i < fill; i++) {
		cbs[i].cb_fn = ut_io_cb;
		cbs[i].cb_arg = &ctxs[i];
		ut_fill_page(page, i, 0x55);
		g_proxy->write(g_proxy, NULL, page, i, 1, &cbs[i]);
		/* strict FIFO: exactly one journal write in flight */
		CU_ASSERT(g_base.pending == 1);
		CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
		CU_ASSERT(ctxs[i].done && ctxs[i].rc == 0);
	}
	CU_ASSERT(g_jr->used_slots == fill);
	CU_ASSERT(ring_full(g_jr));

	/* the 8192nd append must stall: no base IO, no ack */
	ut_fill_page(page, 4000, 0x77);
	g_proxy->write(g_proxy, NULL, page, 4000, 1, &stall_cb);
	CU_ASSERT(g_base.pending == 0);
	CU_ASSERT(!stall_ctx.done);

	/* one drain cycle frees one slot -> the stalled append proceeds */
	poll_threads();				/* home write of entry 0 */
	CU_ASSERT(ut_dev_complete_one(&g_base));
	CU_ASSERT(ut_dev_complete_one(&g_base));	/* zero of entry 0 */
	/* freeing the slot pumped the waiting append */
	CU_ASSERT(g_base.pending == 1);
	CU_ASSERT(!stall_ctx.done);			/* I1 still holds */
	CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
	CU_ASSERT(stall_ctx.done && stall_ctx.rc == 0);
	CU_ASSERT(g_jr->used_slots == fill);

	free(page);
	free(ctxs);
	free(cbs);
	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* recovery helpers (U6-U9)                                            */

/* tear down only the journal object, keeping the flat buffer intact
 * (simulates the node going away without a clean drain) */
static void
ut_journal_abandon(void)
{
	CU_ASSERT(g_base.pending == 0);
	g_proxy->destroy(g_proxy);
	CU_ASSERT(g_base.destroyed);
	g_jr = NULL;
	g_proxy = NULL;
}

/* bring up a journal on the existing buffer and run recovery */
static void
ut_journal_recover(int expected_rc)
{
	struct ut_cb_ctx start_ctx = {};

	ut_dev_init(&g_base, g_buf);
	g_jr = NULL;
	g_proxy = bs_md_journal_dev_create(&g_base.bs_dev, &g_jr);
	SPDK_CU_ASSERT_FATAL(g_proxy != NULL && g_jr != NULL);

	bs_md_journal_start(g_jr, false, ut_start_cb, &start_ctx);
	/* the parallel ring scan is outstanding now */
	CU_ASSERT(g_base.pending == BS_MD_JOURNAL_RECOVERY_QDEPTH);
	CU_ASSERT(!start_ctx.done);
	ut_dev_complete_all(&g_base);
	CU_ASSERT(start_ctx.done);
	CU_ASSERT(start_ctx.rc == expected_rc);

	if (expected_rc == 0) {
		bs_md_journal_enable(g_jr, UT_MD_LIMIT_LBA);
	}
}

/* ------------------------------------------------------------------ */
/* U6: recovery rebuilds tail/head/dict from the valid run and the
 * drain poller works the backlog off                                  */

static void
test_recovery_basic(void)
{
	uint8_t expect[3][BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];
	uint32_t i;

	/* recovery over a completely zeroed ring finds nothing */
	g_buf = calloc(1, UT_DEV_SIZE);
	SPDK_CU_ASSERT_FATAL(g_buf != NULL);
	ut_journal_recover(0);
	CU_ASSERT(g_jr->used_slots == 0);
	CU_ASSERT(g_jr->mem_head == g_jr->mem_tail);
	ut_journal_abandon();
	free(g_buf);

	/* populate three entries, then "crash" (no drain) */
	ut_journal_setup();
	for (i = 0; i < 3; i++) {
		ut_fill_page(expect[i], 10 + i, 0x60 + i);
		ut_append_page(10 + i, 0x60 + i);
	}
	ut_journal_abandon();

	ut_journal_recover(0);
	CU_ASSERT(g_jr->used_slots == 3);
	CU_ASSERT(g_jr->mem_tail == 0 && g_jr->disk_tail == 0);
	CU_ASSERT(g_jr->mem_head == 3 && g_jr->disk_head == 3);

	/* every acked page is served via the rebuilt dictionary */
	for (i = 0; i < 3; i++) {
		CU_ASSERT(ut_mem_is_zero(ut_disk_at(10 + i), BS_MD_JOURNAL_PAGE_SIZE));
		ut_read_page(10 + i, rbuf);
		CU_ASSERT(memcmp(rbuf, expect[i], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	/* the drain poller works the backlog off in the background */
	ut_settle(&g_base);
	CU_ASSERT(g_jr->used_slots == 0);
	for (i = 0; i < 3; i++) {
		CU_ASSERT(memcmp(ut_disk_at(10 + i), expect[i], BS_MD_JOURNAL_PAGE_SIZE) == 0);
		CU_ASSERT(ut_mem_is_zero(ut_disk_at(slot_to_lba(g_jr, i)),
					 BS_MD_JOURNAL_ENTRY_BYTES));
	}

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U7: recovery treats a torn (bad-crc) trailing entry and zeroed
 * entries as empty                                                    */

static void
test_recovery_torn_entry(void)
{
	uint8_t expect[2][BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];
	uint64_t torn_page_lba;
	uint32_t i;

	ut_journal_setup();
	for (i = 0; i < 2; i++) {
		ut_fill_page(expect[i], 10 + i, 0x70 + i);
		ut_append_page(10 + i, 0x70 + i);
	}
	ut_append_page(12, 0x72);
	torn_page_lba = slot_to_lba(g_jr, 2);
	ut_journal_abandon();

	/* tear the last entry: corrupt one byte of its payload page, as a
	 * power loss mid-write would (checksum mismatch) */
	g_buf[(torn_page_lba + 1) * UT_BLOCKLEN + 100] ^= 0xFF;

	ut_journal_recover(0);
	/* the torn entry is empty by definition: run = slots 0..1 */
	CU_ASSERT(g_jr->used_slots == 2);
	CU_ASSERT(g_jr->mem_tail == 0);
	CU_ASSERT(g_jr->mem_head == 2);
	spdk_spin_lock(&g_jr->lock);
	CU_ASSERT(dict_get(g_jr, 12) == JOURNAL_SLOT_INVALID);
	spdk_spin_unlock(&g_jr->lock);

	for (i = 0; i < 2; i++) {
		ut_read_page(10 + i, rbuf);
		CU_ASSERT(memcmp(rbuf, expect[i], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}
	/* the torn page reads from home (never acked, so any content is
	 * legal; home was never written -> zeroes) */
	ut_read_page(12, rbuf);
	CU_ASSERT(ut_mem_is_zero(rbuf, BS_MD_JOURNAL_PAGE_SIZE));

	ut_settle(&g_base);
	CU_ASSERT(g_jr->used_slots == 0);
	CU_ASSERT(memcmp(ut_disk_at(10), expect[0], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	CU_ASSERT(memcmp(ut_disk_at(11), expect[1], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	CU_ASSERT(ut_mem_is_zero(ut_disk_at(12), BS_MD_JOURNAL_PAGE_SIZE));

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U8: recovery duplicates: for the same LBA the later ring position
 * wins in the dictionary                                              */

static void
test_recovery_duplicates(void)
{
	uint8_t expect_b[BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];

	ut_journal_setup();
	ut_append_page(10, 0x0A);		/* older, slot 0 */
	ut_append_page(10, 0x0B);		/* newer, slot 1 */
	ut_fill_page(expect_b, 10, 0x0B);
	ut_journal_abandon();

	ut_journal_recover(0);
	CU_ASSERT(g_jr->used_slots == 2);
	spdk_spin_lock(&g_jr->lock);
	CU_ASSERT(dict_get(g_jr, 10) == 1);	/* later ring position wins */
	spdk_spin_unlock(&g_jr->lock);

	ut_read_page(10, rbuf);
	CU_ASSERT(memcmp(rbuf, expect_b, BS_MD_JOURNAL_PAGE_SIZE) == 0);

	ut_settle(&g_base);
	CU_ASSERT(memcmp(ut_disk_at(10), expect_b, BS_MD_JOURNAL_PAGE_SIZE) == 0);

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U9: power-off simulation: snapshot the device mid-workload (with the
 * in-flight journal write torn), recover on the snapshot: every acked
 * write is recoverable, the unacked one vanishes                      */

static void
test_power_off_simulation(void)
{
	uint8_t acked[10][BS_MD_JOURNAL_PAGE_SIZE];	/* newest acked content per lba 20..29 */
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t *snap;
	uint8_t *page = malloc(BS_MD_JOURNAL_PAGE_SIZE);
	struct ut_cb_ctx unacked_ctx = {};
	struct spdk_bs_dev_cb_args unacked_cb = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &unacked_ctx };
	struct ut_io *io;
	uint32_t r, i;

	SPDK_CU_ASSERT_FATAL(page != NULL);
	ut_journal_setup();

	/* three rounds of md updates over ten pages, all acked */
	for (r = 0; r < 3; r++) {
		for (i = 0; i < 10; i++) {
			uint8_t seed = (uint8_t)(0x90 + 16 * r + i);

			ut_append_page(20 + i, seed);
			ut_fill_page(acked[i], 20 + i, seed);
		}
	}

	/* one more write is issued but its journal write never completes:
	 * the caller was never acknowledged */
	ut_fill_page(page, 25, 0xEE);
	g_proxy->write(g_proxy, NULL, page, 25, 1, &unacked_cb);
	CU_ASSERT(g_base.pending == 1);
	CU_ASSERT(!unacked_ctx.done);

	/* power-off: snapshot the device as it is, with the in-flight
	 * entry torn (only its first 512 bytes made it to the platter) */
	snap = malloc(UT_DEV_SIZE);
	SPDK_CU_ASSERT_FATAL(snap != NULL);
	memcpy(snap, g_buf, UT_DEV_SIZE);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL && io->type == UT_IO_WRITE);
	memcpy(snap + io->lba * UT_BLOCKLEN, io->wdata, 512);

	/* let the old world finish cleanly and switch to the snapshot */
	ut_settle(&g_base);
	CU_ASSERT(unacked_ctx.done);
	g_proxy->destroy(g_proxy);
	free(g_buf);
	g_buf = snap;

	ut_journal_recover(0);
	/* 30 acked entries; the torn 31st is empty by definition */
	CU_ASSERT(g_jr->used_slots == 30);
	CU_ASSERT(g_jr->mem_tail == 0 && g_jr->mem_head == 30);

	/* every acked write is recoverable (newest version per lba) */
	for (i = 0; i < 10; i++) {
		ut_read_page(20 + i, rbuf);
		CU_ASSERT(memcmp(rbuf, acked[i], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	/* ... and lands home when the backlog drains */
	ut_settle(&g_base);
	CU_ASSERT(g_jr->used_slots == 0);
	for (i = 0; i < 10; i++) {
		CU_ASSERT(memcmp(ut_disk_at(20 + i), acked[i], BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	free(page);
	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U10: proxy geometry: blockcnt shrunk by 64 MB; data-range IO passes
 * through untouched                                                   */

static void
test_proxy_geometry_passthrough(void)
{
	uint8_t data[BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];
	struct ut_cb_ctx ctx = {};
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };
	uint64_t data_lba = UT_MD_LIMIT_LBA + 100;
	struct ut_io *io;

	ut_journal_setup();

	/* geometry: the ring is carved out of the top of the device */
	CU_ASSERT(g_proxy->blocklen == UT_BLOCKLEN);
	CU_ASSERT(g_proxy->blockcnt == UT_BLOCKCNT - UT_JOURNAL_BLOCKS);
	CU_ASSERT(bs_md_journal_ring_lba(g_jr) == UT_BLOCKCNT - UT_JOURNAL_BLOCKS);
	CU_ASSERT(bs_md_journal_ring_lba_count(g_jr) == UT_JOURNAL_BLOCKS);

	/* a write above the md limit goes straight to its home LBA */
	ut_fill_page(data, data_lba, 0x44);
	g_proxy->write(g_proxy, NULL, data, data_lba, 1, &cb_args);
	CU_ASSERT(g_base.pending == 1);
	io = TAILQ_FIRST(&g_base.io_queue);
	SPDK_CU_ASSERT_FATAL(io != NULL);
	CU_ASSERT(io->type == UT_IO_WRITE);
	CU_ASSERT(io->lba == data_lba);
	CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
	CU_ASSERT(ctx.done && ctx.rc == 0);
	CU_ASSERT(memcmp(ut_disk_at(data_lba), data, BS_MD_JOURNAL_PAGE_SIZE) == 0);
	CU_ASSERT(g_jr->used_slots == 0);	/* nothing journaled */

	/* a range straddling the md limit is not journaled either */
	{
		struct ut_cb_ctx ctx2 = {};
		struct spdk_bs_dev_cb_args cb2 = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx2 };
		uint8_t two_pages[2 * BS_MD_JOURNAL_PAGE_SIZE];

		memset(two_pages, 0x5A, sizeof(two_pages));
		g_proxy->write(g_proxy, NULL, two_pages, UT_MD_LIMIT_LBA - 1, 2, &cb2);
		CU_ASSERT(g_base.pending == 1);
		io = TAILQ_FIRST(&g_base.io_queue);
		SPDK_CU_ASSERT_FATAL(io != NULL);
		CU_ASSERT(io->lba == UT_MD_LIMIT_LBA - 1 && io->lba_count == 2);
		CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
		CU_ASSERT(ctx2.done && ctx2.rc == 0);
		CU_ASSERT(g_jr->used_slots == 0);
	}

	/* data-range reads pass through without overlay interference */
	memset(rbuf, 0, sizeof(rbuf));
	ut_read_page(data_lba, rbuf);
	CU_ASSERT(memcmp(rbuf, data, BS_MD_JOURNAL_PAGE_SIZE) == 0);

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U11: multi-page (mask-style) append: N entries in FIFO order, one
 * single ack once all of them are durable                             */

static void
test_multi_page_append(void)
{
	uint8_t content[3 * BS_MD_JOURNAL_PAGE_SIZE];
	uint8_t rbuf[BS_MD_JOURNAL_PAGE_SIZE];
	struct ut_cb_ctx ctx = {};
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };
	struct iovec iov[2];
	struct md_journal_entry_hdr hdr;
	uint32_t i;

	ut_journal_setup();

	for (i = 0; i < sizeof(content); i++) {
		content[i] = (uint8_t)(i * 7 + 3);
	}
	/* 12K in two unaligned iovs: 8K + 4K */
	iov[0].iov_base = content;
	iov[0].iov_len = 2 * BS_MD_JOURNAL_PAGE_SIZE;
	iov[1].iov_base = content + 2 * BS_MD_JOURNAL_PAGE_SIZE;
	iov[1].iov_len = BS_MD_JOURNAL_PAGE_SIZE;

	g_proxy->writev(g_proxy, NULL, iov, 2, 40, 3, &cb_args);

	/* page-by-page FIFO: three journal writes, strictly one at a time;
	 * the caller is acknowledged only after the last one (I1/I3) */
	for (i = 0; i < 3; i++) {
		CU_ASSERT(!ctx.done);
		CU_ASSERT(g_base.pending == 1);
		CU_ASSERT(ut_dev_complete_one(&g_base));
	}
	CU_ASSERT(ctx.done && ctx.rc == 0);
	CU_ASSERT(g_base.pending == 0);
	CU_ASSERT(g_jr->used_slots == 3);

	/* ring order matches issue order (I3) */
	for (i = 0; i < 3; i++) {
		memcpy(&hdr, ut_disk_at(slot_to_lba(g_jr, i)), sizeof(hdr));
		CU_ASSERT(hdr.magic == BS_MD_JOURNAL_HDR_MAGIC);
		CU_ASSERT(hdr.target_lba == 40 + i);
		CU_ASSERT(memcmp(ut_disk_at(slot_to_lba(g_jr, i) + g_jr->blocks_per_page),
				 content + (uint64_t)i * BS_MD_JOURNAL_PAGE_SIZE,
				 BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	/* each page is readable through the overlay */
	for (i = 0; i < 3; i++) {
		ut_read_page(40 + i, rbuf);
		CU_ASSERT(memcmp(rbuf, content + (uint64_t)i * BS_MD_JOURNAL_PAGE_SIZE,
				 BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	/* and drains home in order */
	ut_settle(&g_base);
	for (i = 0; i < 3; i++) {
		CU_ASSERT(memcmp(ut_disk_at(40 + i),
				 content + (uint64_t)i * BS_MD_JOURNAL_PAGE_SIZE,
				 BS_MD_JOURNAL_PAGE_SIZE) == 0);
	}

	ut_journal_teardown();
}

/* ------------------------------------------------------------------ */
/* U12: destroy with an in-flight journal write defers the teardown to
 * the IO completion (no use-after-free), caller gets -ESHUTDOWN       */

static void
test_destroy_inflight(void)
{
	uint8_t *page = malloc(BS_MD_JOURNAL_PAGE_SIZE);
	struct ut_cb_ctx ctx = {};
	struct spdk_bs_dev_cb_args cb_args = { .cb_fn = ut_io_cb, .channel = NULL, .cb_arg = &ctx };

	SPDK_CU_ASSERT_FATAL(page != NULL);
	ut_journal_setup();

	ut_fill_page(page, 50, 0xD0);
	g_proxy->write(g_proxy, NULL, page, 50, 1, &cb_args);
	CU_ASSERT(g_base.pending == 1);
	CU_ASSERT(!ctx.done);

	/* destroy with the journal write still in flight: the teardown must
	 * be deferred until that IO completes */
	g_proxy->destroy(g_proxy);
	CU_ASSERT(!g_base.destroyed);

	CU_ASSERT(ut_dev_complete_all(&g_base) == 1);
	CU_ASSERT(ctx.done && ctx.rc == -ESHUTDOWN);
	CU_ASSERT(g_base.destroyed);

	free(page);
	free(g_buf);
	g_buf = NULL;
	g_jr = NULL;
	g_proxy = NULL;
}

/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("blob_md_journal", NULL, NULL);

	CU_ADD_TEST(suite, test_append_ack_ordering);
	CU_ADD_TEST(suite, test_read_overlay);
	CU_ADD_TEST(suite, test_drain);
	CU_ADD_TEST(suite, test_supersede_coalescing);
	CU_ADD_TEST(suite, test_ring_full_stall);
	CU_ADD_TEST(suite, test_recovery_basic);
	CU_ADD_TEST(suite, test_recovery_torn_entry);
	CU_ADD_TEST(suite, test_recovery_duplicates);
	CU_ADD_TEST(suite, test_power_off_simulation);
	CU_ADD_TEST(suite, test_proxy_geometry_passthrough);
	CU_ADD_TEST(suite, test_multi_page_append);
	CU_ADD_TEST(suite, test_destroy_inflight);

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	free_threads();

	return num_failures;
}
