/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock.
 *
 *   Unit tests for the transfer dispatch path (xfer_replication +
 *   helper_xfer_poller). Written for the fix that removed the one-item-per-
 *   poller-tick serialization: the dispatcher must fill the whole in-flight
 *   window in one pass, and the helper must drain its ready ring.
 *
 *   Reuses lvol_ut.c wholesale (its stub set is what makes lvol.c link);
 *   its main() is renamed away and only the xfer suite is registered here,
 *   so this binary is independent of the state of the legacy suites.
 */
#define main lvol_ut_main_disabled
#include "../lvol.c/lvol_ut.c"
#undef main

/* blob_dirty.c and the dirty-gen / freeze-probe stubs now come from
 * lvol_ut.c, which this file includes wholesale. */

#define UT_SRC_ID	0x43

static struct spdk_lvol g_xfer_lvol;
static struct spdk_lvol_store g_xfer_lvs;
/* the poll group the requests run on: its iobuf channel is set up in main() */
static struct spdk_lvs_poll_group g_ut_lpg;

static struct spdk_lvs_xfer *
make_xfer(int cluster_batch, uint32_t num_clusters, const int *allocated)
{
	struct spdk_lvs_xfer *xfer = calloc(1, sizeof(*xfer));
	SPDK_CU_ASSERT_FATAL(xfer != NULL);

	memset(&g_xfer_lvol, 0, sizeof(g_xfer_lvol));
	memset(&g_xfer_lvs, 0, sizeof(g_xfer_lvs));
	g_xfer_lvol.lvol_store = &g_xfer_lvs;
	TAILQ_INIT(&g_xfer_lvs.lvols);
	snprintf(g_xfer_lvol.name, sizeof(g_xfer_lvol.name), "xfer_ut_lvol");
	/* the source snapshot's parent is the destination's base (0x42, the
	 * partial_base the tests pass), as in a chain sent snapshot by snapshot */
	ut_chain_clear();
	g_xfer_lvol.blob_id = UT_SRC_ID;
	ut_chain_set(UT_SRC_ID, 0x42, 0);

	xfer->lvol = &g_xfer_lvol;
	xfer->type = XFER_REPLICATE_SNAPSHOT;
	xfer->state = XFER_STATE_TRANSFER_CLUSTERS;
	xfer->final_step = false;
	xfer->cluster_batch = cluster_batch;
	/* 4 KiB pages, 16 KiB clusters: one request per cluster */
	xfer->page_size = 4096;
	xfer->page_per_cluster = 4;
	xfer->num_clusters = num_clusters;
	xfer->clusters = calloc(num_clusters, sizeof(uint64_t));
	SPDK_CU_ASSERT_FATAL(xfer->clusters != NULL);
	for (uint32_t i = 0; i < num_clusters; i++) {
		xfer->clusters[i] = allocated[i] ? 0xABCD0000 + i : 0;
	}

	pthread_spin_init(&xfer->gen_lock, PTHREAD_PROCESS_PRIVATE);
	xfer->free_ring = spdk_ring_create(SPDK_RING_TYPE_MP_MC, cluster_batch,
					   SPDK_ENV_SOCKET_ID_ANY);
	xfer->ready_ring = spdk_ring_create(SPDK_RING_TYPE_MP_MC, cluster_batch,
					    SPDK_ENV_SOCKET_ID_ANY);
	SPDK_CU_ASSERT_FATAL(xfer->free_ring != NULL && xfer->ready_ring != NULL);

	xfer->reqs = calloc(cluster_batch, sizeof(*xfer->reqs));
	SPDK_CU_ASSERT_FATAL(xfer->reqs != NULL);
	for (int i = 0; i < cluster_batch; i++) {
		xfer->reqs[i].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
		SPDK_CU_ASSERT_FATAL(xfer->reqs[i].payload != NULL);
		xfer->reqs[i].xfer = xfer;
		xfer->reqs[i].type = xfer->type;
	}
	/* as spdk_lvol_create_backup_task: a task without a dirty generation
	 * sends each cluster as one range */
	xfer->ranges = calloc(1, sizeof(*xfer->ranges));
	SPDK_CU_ASSERT_FATAL(xfer->ranges != NULL);
	xfer->max_ranges = 1;
	xfer_fill_queue(xfer, cluster_batch);
	xfer->timeout = spdk_get_ticks();
	return xfer;
}

static void
free_xfer(struct spdk_lvs_xfer *xfer)
{
	for (int i = 0; i < xfer->cluster_batch; i++) {
		/* a request left in flight (its read never completes here)
		 * still holds its buffers */
		xfer_req_put_bufs(&xfer->reqs[i]);
		free(xfer->reqs[i].payload);
	}
	poll_threads();		/* a ready message that may still be pending */
	free(xfer->reqs);
	spdk_ring_free(xfer->free_ring);
	spdk_ring_free(xfer->ready_ring);
	free(xfer->clusters);
	free(xfer->ranges);
	free(xfer->bridged);
	free(xfer);
}

static uint32_t
drain_ready(struct spdk_lvs_xfer *xfer, uint64_t *offsets, uint32_t max)
{
	struct spdk_lvs_xfer_req *req;
	uint32_t n = 0;

	while (n < max && spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1) {
		if (offsets != NULL) {
			offsets[n] = req->offset;
		}
		n++;
	}
	return n;
}


/* While a freeze-critical FINAL transfer runs, background transfers must not
 * dispatch a single request: the client is stalled behind the frozen volume,
 * and every tick spent on a background snapshot is added stall. Resuming
 * must not trip the 8s stall detector either. */
static void
xfer_background_pauses_while_priority_active(void)
{
	const int alloc[8] = {1, 1, 1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 8, alloc);

	__atomic_store_n(&g_priority_xfer_cnt, 1, __ATOMIC_SEQ_CST);
	CU_ASSERT(xfer_replication(xfer) == 0);
	CU_ASSERT(xfer->outstanding_io == 0);
	CU_ASSERT(drain_ready(xfer, NULL, 8) == 0);

	/* (the stall-clock refresh is not observable here: the harness stubs
	 * spdk_get_ticks() to 0) */

	__atomic_store_n(&g_priority_xfer_cnt, 0, __ATOMIC_SEQ_CST);
	CU_ASSERT(xfer_replication(xfer) == 8);
	CU_ASSERT(drain_ready(xfer, NULL, 8) == 8);

	free_xfer(xfer);
}

/* A PRIORITY transfer keeps dispatching while the counter is up -- it is the
 * one the counter exists for. */
static void
xfer_priority_task_dispatches_during_priority_window(void)
{
	const int alloc[4] = {1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(4, 4, alloc);

	xfer->priority = true;
	__atomic_store_n(&g_priority_xfer_cnt, 1, __ATOMIC_SEQ_CST);
	CU_ASSERT(xfer_replication(xfer) == 4);
	CU_ASSERT(drain_ready(xfer, NULL, 4) == 4);
	__atomic_store_n(&g_priority_xfer_cnt, 0, __ATOMIC_SEQ_CST);

	free_xfer(xfer);
}

/* The helper poller serves priority rings first and, while a priority
 * transfer is active anywhere, does not touch non-priority rings at all. */
static void
helper_serves_priority_first_and_exclusively(void)
{
	const int alloc[4] = {1, 1, 1, 1};
	struct spdk_lvs_xfer *x_bg = make_xfer(4, 4, alloc);
	struct spdk_lvs_xfer *x_pr = make_xfer(4, 4, alloc);
	struct spdk_lvs_poll_group lpg;
	struct remote_lvol_info rmt_bg, rmt_pr;

	x_pr->priority = true;
	CU_ASSERT(xfer_replication(x_bg) == 4);        /* queue bg work first */
	__atomic_store_n(&g_priority_xfer_cnt, 1, __ATOMIC_SEQ_CST);
	CU_ASSERT(xfer_replication(x_pr) == 4);

	memset(&lpg, 0, sizeof(lpg));
	TAILQ_INIT(&lpg.rmt_lvols);
	memset(&rmt_bg, 0, sizeof(rmt_bg));
	rmt_bg.group = &g_ut_lpg;
	rmt_bg.status = true;
	rmt_bg.type = XFER_REPLICATE_SNAPSHOT;
	rmt_bg.desc = (struct spdk_bdev_desc *)0x1;
	rmt_bg.channel = (struct spdk_io_channel *)0x1;
	rmt_bg.md_channel = (struct spdk_io_channel *)0x1;
	rmt_bg.ready_ring = x_bg->ready_ring;
	rmt_bg.free_ring = x_bg->free_ring;
	rmt_pr = rmt_bg;
	rmt_pr.priority = true;
	rmt_pr.ready_ring = x_pr->ready_ring;
	rmt_pr.free_ring = x_pr->free_ring;
	/* background first in the list: order must come from priority, not
	 * from list position */
	TAILQ_INSERT_TAIL(&lpg.rmt_lvols, &rmt_bg, entry);
	TAILQ_INSERT_TAIL(&lpg.rmt_lvols, &rmt_pr, entry);

	helper_xfer_poller(&lpg);
	CU_ASSERT(rmt_pr.outstanding_io == 4);         /* priority ring drained */
	CU_ASSERT(rmt_bg.outstanding_io == 0);         /* background untouched */

	/* count the still-queued background requests WITHOUT losing them */
	{
		struct spdk_lvs_xfer_req *held[4];
		uint32_t got = 0;

		while (got < 4 && spdk_ring_dequeue(x_bg->ready_ring,
						    (void **)&held[got], 1) == 1) {
			got++;
		}
		CU_ASSERT(got == 4);                   /* still queued */
		for (uint32_t i = 0; i < got; i++) {
			CU_ASSERT(spdk_ring_enqueue(x_bg->ready_ring,
						    (void **)&held[i], 1, NULL) == 1);
		}
	}

	/* priority window over: background is served again */
	__atomic_store_n(&g_priority_xfer_cnt, 0, __ATOMIC_SEQ_CST);
	helper_xfer_poller(&lpg);
	CU_ASSERT(rmt_bg.outstanding_io > 0);

	free_xfer(x_bg);
	free_xfer(x_pr);
}

/* The fix itself: one call must fill the whole window, not one cluster. */
static void
xfer_fills_whole_window(void)
{
	const int alloc[20] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			       1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 20, alloc);

	int count = xfer_replication(xfer);

	CU_ASSERT(count == 8);
	CU_ASSERT(xfer->outstanding_io == 8);
	CU_ASSERT(xfer->idx == 8);
	CU_ASSERT(xfer->hold_idx == 8);
	CU_ASSERT(drain_ready(xfer, NULL, 16) == 8);

	free_xfer(xfer);
}

/* A window larger than the remaining work stops at the work, not the window. */
static void
xfer_stops_at_last_cluster(void)
{
	const int alloc[5] = {1, 1, 1, 0, 0};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 5, alloc);

	int count = xfer_replication(xfer);

	CU_ASSERT(count == 3);
	CU_ASSERT(xfer->outstanding_io == 3);
	CU_ASSERT(drain_ready(xfer, NULL, 16) == 3);

	free_xfer(xfer);
}

/* Sparse maps: unallocated clusters are skipped, offsets match the map. */
static void
xfer_skips_unallocated_clusters(void)
{
	const int alloc[10] = {1, 0, 0, 1, 0, 1, 0, 0, 0, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 10, alloc);
	uint64_t offsets[8] = {0};

	int count = xfer_replication(xfer);

	CU_ASSERT(count == 4);
	CU_ASSERT(drain_ready(xfer, offsets, 8) == 4);
	CU_ASSERT(offsets[0] == 0 * xfer->page_per_cluster);
	CU_ASSERT(offsets[1] == 3 * xfer->page_per_cluster);
	CU_ASSERT(offsets[2] == 5 * xfer->page_per_cluster);
	CU_ASSERT(offsets[3] == 9 * xfer->page_per_cluster);

	free_xfer(xfer);
}

/* Completions recycle requests: the NEXT pass continues where the map left
 * off, and the batch transition still fires when everything succeeded. */
static void
xfer_second_pass_continues_and_completes(void)
{
	const int alloc[6] = {1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(4, 6, alloc);
	struct spdk_lvs_xfer_req *req;

	CU_ASSERT(xfer_replication(xfer) == 4);
	CU_ASSERT(xfer->hold_idx == 4);

	/* complete the four in-flight requests the way local/remote completion
	 * does: status DONE, back on the free ring. success_cnt is NOT touched
	 * here -- xfer_status_check() accounts for completions itself when it
	 * dequeues a DONE request off the free ring. */
	for (int i = 0; i < 4; i++) {
		SPDK_CU_ASSERT_FATAL(spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1);
		req->status = XFER_REQ_STATUS_DONE;
		CU_ASSERT(spdk_ring_enqueue(xfer->free_ring, (void **)&req, 1, NULL) == 1);
	}

	CU_ASSERT(xfer_replication(xfer) == 2);
	CU_ASSERT(xfer->idx == 6);
	CU_ASSERT(xfer->hold_idx == 6);

	/* complete the tail, then keep ticking: once the status check has
	 * absorbed every completion (success_cnt == idx) the state machine
	 * must leave the transfer. Stop the moment it does -- another tick in
	 * XFER_STATE_DONE would tear the task down for real. */
	for (int i = 0; i < 2; i++) {
		SPDK_CU_ASSERT_FATAL(spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1);
		req->status = XFER_REQ_STATUS_DONE;
		CU_ASSERT(spdk_ring_enqueue(xfer->free_ring, (void **)&req, 1, NULL) == 1);
	}
	for (int i = 0; i < 16 && xfer->state != XFER_STATE_DONE; i++) {
		CU_ASSERT(xfer_replication(xfer) == 0);
	}
	CU_ASSERT(xfer->state == XFER_STATE_DONE);

	free_xfer(xfer);
}

/* A poll group takes only its share of the window from the ready ring,
 * leaving the rest to the other poll groups. */
static void
helper_takes_its_share_of_the_window(void)
{
	const int alloc[8] = {1, 1, 1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 8, alloc);
	struct spdk_lvs_poll_group lpg;
	struct remote_lvol_info rmt;

	CU_ASSERT(xfer_replication(xfer) == 8);

	memset(&lpg, 0, sizeof(lpg));
	TAILQ_INIT(&lpg.rmt_lvols);
	memset(&rmt, 0, sizeof(rmt));
	rmt.group = &g_ut_lpg;
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.desc = (struct spdk_bdev_desc *)0x1;
	rmt.channel = (struct spdk_io_channel *)0x1;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	rmt.ready_ring = xfer->ready_ring;
	rmt.free_ring = xfer->free_ring;
	rmt.window_share = 3;			/* ceil(8 / 3) of 3 poll groups */
	TAILQ_INSERT_TAIL(&lpg.rmt_lvols, &rmt, entry);

	helper_xfer_poller(&lpg);
	CU_ASSERT(rmt.outstanding_io == 3);
	helper_xfer_poller(&lpg);		/* still holding its share */
	CU_ASSERT(rmt.outstanding_io == 3);
	CU_ASSERT(drain_ready(xfer, NULL, 8) == 5);

	free_xfer(xfer);
}

/* The helper must drain its ready ring, not take one request per tick. */
static void
helper_drains_ready_ring(void)
{
	const int alloc[8] = {1, 1, 1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(8, 8, alloc);
	struct spdk_lvs_poll_group lpg;
	struct remote_lvol_info rmt;

	CU_ASSERT(xfer_replication(xfer) == 8);

	memset(&lpg, 0, sizeof(lpg));
	TAILQ_INIT(&lpg.rmt_lvols);
	memset(&rmt, 0, sizeof(rmt));
	rmt.group = &g_ut_lpg;
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.desc = (struct spdk_bdev_desc *)0x1;      /* only null-checked */
	rmt.channel = (struct spdk_io_channel *)0x1;  /* only null-checked */
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	rmt.ready_ring = xfer->ready_ring;
	rmt.free_ring = xfer->free_ring;
	TAILQ_INSERT_TAIL(&lpg.rmt_lvols, &rmt, entry);

	helper_xfer_poller(&lpg);

	CU_ASSERT(rmt.outstanding_io == 8);
	CU_ASSERT(drain_ready(xfer, NULL, 8) == 0);   /* ring fully drained */

	free_xfer(xfer);
}

/*
 * Replication write path (submit_req_fragments). A request is at most 64 KiB
 * (16 blocks of 4 KiB), read into a chain of iobuf small-pool buffers (8 KiB
 * here: 8 buffers) taken on the poll group thread, then written to the remote
 * in writes of at most 32 blocks -- so a whole request is one write -- each
 * write describing its part of the chain. Only the data ranges are written
 * (the destination clusters were allocated by the alloc step); an all-zero
 * request sends nothing. Every buffer goes back when the request leaves.
 */
#define UT_CLUSTER_BLOCKS	512
#define UT_REQ_BLOCKS		16
#define UT_DST_OFFSET		0x10000
#define UT_XFER_SMALL_COUNT	256
#define UT_XFER_SMALL_SIZE	8192

static struct spdk_bdev g_ut_rmt_bdev;
static struct spdk_bdev_desc g_ut_rmt_desc;

/* Small-pool buffers not held by anybody: the global pool plus the poll
 * group channel's cache. */
static uint32_t
ut_xfer_bufs_free(void)
{
	struct spdk_iobuf_channel ch;
	void **bufs = calloc(UT_XFER_SMALL_COUNT, sizeof(void *));
	uint32_t n = 0;

	SPDK_CU_ASSERT_FATAL(bufs != NULL);
	SPDK_CU_ASSERT_FATAL(spdk_iobuf_channel_init(&ch, "ut_xfer", 0, 0) == 0);
	while (n < UT_XFER_SMALL_COUNT &&
	       (bufs[n] = spdk_iobuf_get(&ch, UT_XFER_SMALL_SIZE, NULL, NULL)) != NULL) {
		n++;
	}
	for (uint32_t i = 0; i < n; i++) {
		spdk_iobuf_put(&ch, bufs[i], UT_XFER_SMALL_SIZE);
	}
	spdk_iobuf_channel_fini(&ch);
	free(bufs);
	return n + g_ut_lpg.iobuf.cache[0].small.cache_count;
}

/* Take all but `leave` small buffers through the poll group's channel. */
static uint32_t
ut_xfer_drain(void **bufs, uint32_t leave)
{
	uint32_t n = 0;

	while (n < UT_XFER_SMALL_COUNT - leave &&
	       (bufs[n] = spdk_iobuf_get(&g_ut_lpg.iobuf, UT_XFER_SMALL_SIZE, NULL, NULL)) != NULL) {
		n++;
	}
	return n;
}

static void
ut_rmt_init(struct remote_lvol_info *rmt, struct spdk_lvs_xfer *xfer)
{
	memset(rmt, 0, sizeof(*rmt));
	rmt->status = true;
	rmt->type = XFER_REPLICATE_SNAPSHOT;
	rmt->md_channel = (struct spdk_io_channel *)0x1;
	g_ut_rmt_bdev.blocklen = 4096;
	g_ut_rmt_desc.bdev = &g_ut_rmt_bdev;
	rmt->desc = &g_ut_rmt_desc;
	rmt->channel = (struct spdk_io_channel *)0x1;
	rmt->free_ring = xfer->free_ring;
	rmt->group = &g_ut_lpg;
}

/* reqs[i] in flight on rmt: 16 blocks at block i * 16 of the only cluster. */
static struct spdk_lvs_xfer_req *
ut_prep_req(struct spdk_lvs_xfer *xfer, int i, struct remote_lvol_info *rmt)
{
	struct spdk_lvs_xfer_req *req = &xfer->reqs[i];

	req->rmt_lvol = rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->status = XFER_REQ_STATUS_IN_FLIGHT;
	req->offset = (uint64_t)i * UT_REQ_BLOCKS;
	req->dst_offset = UT_DST_OFFSET + req->offset;
	req->len = UT_REQ_BLOCKS;
	rmt->outstanding_io++;
	return req;
}

static struct spdk_lvs_xfer *
make_cluster_xfer(int batch, struct remote_lvol_info *rmt)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;

	xfer = make_xfer(batch, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = UT_CLUSTER_BLOCKS;
	for (int i = 0; i < batch; i++) {
		/* as in the task setup: no payload until a command needs one */
		free(xfer->reqs[i].payload);
		xfer->reqs[i].payload = NULL;
	}
	/* the requests are in flight: take them off the free ring; the task's
	 * only cluster is sent, so nothing is left to refill them with */
	while (spdk_ring_dequeue(xfer->free_ring, (void **)&req, 1) == 1) {
	}
	xfer->hold_idx = 1;
	xfer->idx = batch;
	xfer->outstanding_io = batch;
	ut_rmt_init(rmt, xfer);

	g_ut_bdev_write_cnt = 0;
	g_ut_bdev_write_fail_at = 0;
	g_ut_bdev_write_rc = 0;
	g_ut_blob_readv_cnt = 0;
	return xfer;
}

/* As if the source read zeroes into the request's buffers. */
static void
ut_zero_chain(struct spdk_lvs_xfer_req *req)
{
	for (uint32_t i = 0; i < req->chain.needed; i++) {
		memset(req->chain.iovs[i].iov_base, 0, req->chain.iovs[i].iov_len);
	}
}

/* One request, submitted: it holds its chain (zeroed: the source read zeroes)
 * and its read is out. The request is made by the dispatcher
 * (xfer_repl_next), as in production: the first 64 KiB piece of a whole
 * cluster of a task without a dirty generation. */
static struct spdk_lvs_xfer_req *
make_cluster_req(struct spdk_lvs_xfer **xferp, struct remote_lvol_info *rmt)
{
	struct spdk_lvs_xfer *xfer = make_cluster_xfer(1, rmt);
	struct spdk_lvs_xfer_req *req;

	xfer->hold_idx = 0;
	xfer->idx = 0;
	xfer->outstanding_io = 0;
	SPDK_CU_ASSERT_FATAL(xfer_repl_next(xfer, &xfer->reqs[0]));
	CU_ASSERT(xfer->reqs[0].offset == 0);
	CU_ASSERT(xfer->reqs[0].len == UT_REQ_BLOCKS);
	/* a piece of a whole cluster is not partial: zero detection is on */
	CU_ASSERT(!xfer->reqs[0].partial);
	/* the cluster's other pieces are not part of these tests: the request
	 * is the task's last one, and is done when its writes are */
	xfer->range_pos = xfer->num_ranges;
	req = ut_prep_req(xfer, 0, rmt);

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	SPDK_CU_ASSERT_FATAL(req->chain.nbufs == UT_REQ_BLOCKS * 4096 / UT_XFER_SMALL_SIZE);
	ut_zero_chain(req);
	*xferp = xfer;
	return req;
}

/* Where block b of the request lives in its chain. */
static uint8_t *
chain_block(struct spdk_lvs_xfer_req *req, uint64_t b)
{
	struct iovec iov[2];

	SPDK_CU_ASSERT_FATAL(xfer_iov_slice(req->chain.iovs, (int)req->chain.needed, b * 4096, 4096,
					    iov, 2) == 1);
	return iov[0].iov_base;
}

static void
fill_blocks(struct spdk_lvs_xfer_req *req, uint32_t first, uint32_t count)
{
	for (uint32_t b = first; b < first + count; b++) {
		memset(chain_block(req, b), 0xA5, 4096);
	}
}

/* Check write i: blocks [start, start + n) of the request, from its chain. */
static void
check_write(struct spdk_lvs_xfer_req *req, uint32_t i, uint64_t start, uint64_t n)
{
	SPDK_CU_ASSERT_FATAL(i < g_ut_bdev_write_cnt);
	CU_ASSERT(g_ut_bdev_writes[i].offset_blocks == UT_DST_OFFSET + req->offset + start);
	CU_ASSERT(g_ut_bdev_writes[i].num_blocks == n);
	CU_ASSERT(g_ut_bdev_writes[i].buf == chain_block(req, start));
	CU_ASSERT(g_ut_bdev_writes[i].bytes == n * 4096);
	/* 4 KiB blocks in 8 KiB buffers: one iovec per buffer touched */
	CU_ASSERT(g_ut_bdev_writes[i].iovcnt ==
		  (int)((start + n + 1) / 2 - start / 2));
}

/* Complete every write in flight; the last one finishes the request. */
static void
complete_writes(struct spdk_lvs_xfer_req *req, bool success)
{
	int n = req->fragments_outstanding;

	for (int i = 0; i < n; i++) {
		fragment_write_cb(NULL, success, req);
	}
}

/* The read is one read of the whole request into its 8-buffer chain. */
static void
xfer_read_is_one_cluster_read(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	CU_ASSERT(g_ut_blob_readv_cnt == 1);
	CU_ASSERT(g_ut_blob_readv_arg == req);
	CU_ASSERT(g_ut_blob_readv_iov == req->chain.iovs);
	CU_ASSERT(g_ut_blob_readv_iovcnt == 8);
	CU_ASSERT(g_ut_blob_readv_offset == 0);
	CU_ASSERT(g_ut_blob_readv_length == UT_REQ_BLOCKS);
	for (int i = 0; i < 8; i++) {
		CU_ASSERT(req->chain.iovs[i].iov_len == UT_XFER_SMALL_SIZE);
	}
	CU_ASSERT(req->fragments_outstanding == 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 0);

	local_op_comp(req, -EIO);		/* a failed read gives them back */
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(req->chain.nbufs == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);
}

/* Preallocated, all zero: nothing is sent and the request is done at once,
 * its buffers returned. */
static void
xfer_replicate_zero_cluster_sends_nothing(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 0);
	CU_ASSERT(req->fragments_outstanding == 0);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(req->chain.nbufs == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	free_xfer(xfer);
}

/* All data: one write of the whole request, over all 8 buffers. */
static void
xfer_replicate_full_cluster_is_one_range(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, UT_REQ_BLOCKS);
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 1);
	CU_ASSERT(req->fragments_outstanding == 1);
	check_write(req, 0, 0, UT_REQ_BLOCKS);
	CU_ASSERT(g_ut_bdev_writes[0].iovcnt == 8);
	CU_ASSERT(req->chain.nbufs == 8);	/* held until the write is done */

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(req->chain.nbufs == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	free_xfer(xfer);
}

/* Only the data ranges are written, across buffer boundaries. */
static void
xfer_replicate_sends_only_data_ranges(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, 3);		/* buffers 0-1 */
	fill_blocks(req, 5, 1);		/* second half of buffer 2 */
	fill_blocks(req, 7, 6);		/* buffers 3-6 */
	fill_blocks(req, 15, 1);	/* last block */
	local_op_comp(req, 0);

	CU_ASSERT(g_ut_bdev_write_cnt == 4);
	CU_ASSERT(req->fragments_outstanding == 4);
	check_write(req, 0, 0, 3);
	check_write(req, 1, 5, 1);
	check_write(req, 2, 7, 6);
	check_write(req, 3, 15, 1);
	CU_ASSERT(g_ut_bdev_writes[2].iovcnt == 4);

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	free_xfer(xfer);
}

/* Every other block: eight one-block writes. */
static void
xfer_replicate_too_many_ranges_sends_whole_cluster(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	for (uint32_t b = 0; b < UT_REQ_BLOCKS; b += 2) {
		fill_blocks(req, b, 1);
	}
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 8);
	for (uint32_t i = 0; i < 8; i++) {
		check_write(req, i, 2 * i, 1);
	}

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);

	free_xfer(xfer);
}

/* A submit failure after some writes: the request fails once the writes in
 * flight return. On the first write: it fails at once. Either way its
 * buffers go back. */
static void
xfer_replicate_submit_failure_fails_the_request(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, 1);
	fill_blocks(req, 4, 1);
	fill_blocks(req, 8, 1);
	g_ut_bdev_write_fail_at = 3;
	g_ut_bdev_write_rc = -ENOMEM;
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 2);
	CU_ASSERT(req->fragments_outstanding == 2);
	CU_ASSERT(req->status == XFER_REQ_STATUS_IN_FLIGHT);
	CU_ASSERT(req->chain.nbufs == 8);

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(req->chain.nbufs == 0);
	free_xfer(xfer);

	req = make_cluster_req(&xfer, &rmt);
	fill_blocks(req, 0, 1);
	g_ut_bdev_write_fail_at = 1;
	g_ut_bdev_write_rc = -ENOMEM;
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 0);
	CU_ASSERT(req->fragments_outstanding == 0);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(req->chain.nbufs == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);

	g_ut_bdev_write_fail_at = 0;
}

/* A failed write fails the request, after all writes returned. */
static void
xfer_replicate_write_failure_fails_the_request(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, 1);
	fill_blocks(req, 10, 1);
	local_op_comp(req, 0);
	CU_ASSERT(req->fragments_outstanding == 2);

	fragment_write_cb(NULL, false, req);
	CU_ASSERT(req->status == XFER_REQ_STATUS_IN_FLIGHT);	/* one still out */
	CU_ASSERT(req->chain.nbufs == 8);
	fragment_write_cb(NULL, true, req);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	free_xfer(xfer);
}

/* With the pool empty a request waits -- in flight for the window, no read
 * yet -- and does not fail. The first waiting one keeps the 3 buffers it got,
 * the second holds none; buffers returned on the thread complete them in
 * order and a message submits their reads. */
static void
xfer_replicate_waits_for_buffers(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *a, *b;
	void **bufs = calloc(UT_XFER_SMALL_COUNT, sizeof(void *));
	uint32_t n, i;

	SPDK_CU_ASSERT_FATAL(bufs != NULL);
	xfer = make_cluster_xfer(2, &rmt);
	a = ut_prep_req(xfer, 0, &rmt);
	b = ut_prep_req(xfer, 1, &rmt);

	n = ut_xfer_drain(bufs, 3);
	CU_ASSERT(n == UT_XFER_SMALL_COUNT - 3);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(submit_rw_reqs_local(b) == 0);
	CU_ASSERT(g_ut_blob_readv_cnt == 0);
	CU_ASSERT(a->chain.waiting && a->chain.nbufs == 3);
	CU_ASSERT(b->chain.waiting && b->chain.nbufs == 0);
	CU_ASSERT(TAILQ_FIRST(&g_ut_lpg.bufq.waitq) == &a->chain);
	CU_ASSERT(rmt.outstanding_io == 2);
	CU_ASSERT(a->status == XFER_REQ_STATUS_IN_FLIGHT);

	/* the poller finds nothing in the pool */
	helper_xfer_poller(&g_ut_lpg);
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 0);

	/* 5 more complete the first; it is submitted from a message */
	for (i = 0; i < 5; i++) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	CU_ASSERT(!a->chain.waiting && a->chain.nbufs == 8);
	CU_ASSERT(a->buf_ready);
	CU_ASSERT(g_ut_blob_readv_cnt == 0);
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 1 && g_ut_blob_readv_arg == a);
	CU_ASSERT(!a->buf_ready);
	CU_ASSERT(b->chain.waiting);

	for (i = 0; i < 8; i++) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 2 && g_ut_blob_readv_arg == b);

	while (n > 0) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	ut_zero_chain(a);
	ut_zero_chain(b);
	local_op_comp(a, 0);			/* all zero: done */
	local_op_comp(b, 0);
	CU_ASSERT(a->status == XFER_REQ_STATUS_DONE && b->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	free(bufs);
	free_xfer(xfer);
}

/* Buffers returned on another thread go to the global pool, and the iobuf
 * wait queue is per thread: the helper poller hands them to the waiting
 * request. */
static void
xfer_replicate_kick_takes_other_threads_buffers(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *a;
	struct spdk_iobuf_channel ch1;
	void **bufs = calloc(UT_XFER_SMALL_COUNT, sizeof(void *));
	uint32_t n;

	SPDK_CU_ASSERT_FATAL(bufs != NULL);
	xfer = make_cluster_xfer(1, &rmt);
	a = ut_prep_req(xfer, 0, &rmt);
	n = ut_xfer_drain(bufs, 0);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(a->chain.waiting);

	set_thread(1);
	SPDK_CU_ASSERT_FATAL(spdk_iobuf_channel_init(&ch1, "ut_xfer", 0, 0) == 0);
	while (n > 0) {
		spdk_iobuf_put(&ch1, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	spdk_iobuf_channel_fini(&ch1);
	set_thread(0);
	poll_threads();
	CU_ASSERT(a->chain.waiting);		/* nobody put one on thread 0 */

	helper_xfer_poller(&g_ut_lpg);		/* the kick */
	CU_ASSERT(!a->chain.waiting && a->chain.nbufs == 8);
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 1 && g_ut_blob_readv_arg == a);

	ut_zero_chain(a);
	local_op_comp(a, 0);
	CU_ASSERT(a->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free(bufs);
	free_xfer(xfer);
}

/* Teardown fails the requests that wait for buffers (they have no IO to
 * abort), so the poll group's outstanding_io drains; a request that got its
 * buffers but was not submitted yet is failed the same way. */
static void
xfer_replicate_teardown_fails_waiting_requests(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *a, *b;
	void **bufs = calloc(UT_XFER_SMALL_COUNT, sizeof(void *));
	uint32_t n, i;

	SPDK_CU_ASSERT_FATAL(bufs != NULL);
	xfer = make_cluster_xfer(2, &rmt);
	a = ut_prep_req(xfer, 0, &rmt);
	b = ut_prep_req(xfer, 1, &rmt);
	n = ut_xfer_drain(bufs, 0);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(submit_rw_reqs_local(b) == 0);
	for (i = 0; i < 8; i++) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	CU_ASSERT(a->buf_ready);		/* ready, its message not run yet */
	CU_ASSERT(b->chain.waiting);

	rmt.status = false;
	xfer_bufq_abort_rmt(&g_ut_lpg, &rmt);
	CU_ASSERT(a->status == XFER_REQ_STATUS_FAILED && b->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(!a->buf_ready && !b->chain.waiting);
	CU_ASSERT(a->chain.nbufs == 0 && b->chain.nbufs == 0);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(spdk_ring_count(xfer->free_ring) == 2);
	CU_ASSERT(TAILQ_EMPTY(&g_ut_lpg.bufq.waitq) && TAILQ_EMPTY(&g_ut_lpg.buf_readyq));
	poll_threads();				/* the pending message finds nothing */
	CU_ASSERT(g_ut_blob_readv_cnt == 0);

	while (n > 0) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free(bufs);
	free_xfer(xfer);
}

/* An alloc command travels in a buffer chain too: copied from the request's
 * command buffer, one vectored write of SPDK_LVOL_XFER_CMD_BLOCKS blocks. */
static void
xfer_replicate_command_is_copied_into_a_chain(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *a;
	uint8_t *cmd;

	xfer = make_cluster_xfer(1, &rmt);
	a = ut_prep_req(xfer, 0, &rmt);
	cmd = xfer_req_ctrl_payload(xfer, a);
	SPDK_CU_ASSERT_FATAL(cmd != NULL);
	for (uint32_t i = 0; i < SPDK_LVOL_XFER_CMD_SIZE; i++) {
		cmd[i] = (uint8_t)(i * 7 + 1);
	}
	a->action = REQ_ACTION_WRITE;
	a->len = SPDK_LVOL_XFER_CMD_BLOCKS;
	a->dst_offset = 0x77;
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 1);
	CU_ASSERT(g_ut_bdev_writes[0].offset_blocks == 0x77);
	CU_ASSERT(g_ut_bdev_writes[0].num_blocks == SPDK_LVOL_XFER_CMD_BLOCKS);
	CU_ASSERT(g_ut_bdev_writes[0].iovcnt == SPDK_LVOL_XFER_CMD_SIZE / UT_XFER_SMALL_SIZE);
	CU_ASSERT(g_ut_bdev_writes[0].bytes == SPDK_LVOL_XFER_CMD_SIZE);
	for (uint32_t i = 0; i < a->chain.needed; i++) {
		CU_ASSERT(memcmp(a->chain.iovs[i].iov_base, cmd + i * UT_XFER_SMALL_SIZE,
				 UT_XFER_SMALL_SIZE) == 0);
	}
	complete_op_cb(NULL, true, a);
	CU_ASSERT(a->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(a->chain.nbufs == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);
}

/*
 * Partial (dirty-bitmap) replication. Real sizes: 4 KiB pages, 2 MiB clusters,
 * so a dirty block (8 KiB) is two pages and a 64 KiB request is 16.
 */
#define UT_PPC		512
#define UT_CLUSTER_SZ	(UT_PPC * 4096)

static struct spdk_lvs_xfer *
make_partial_xfer(int batch, uint32_t num_clusters, const int *alloc, struct blob_dirty_gen *gen)
{
	struct spdk_lvs_xfer *xfer = make_xfer(batch, num_clusters, alloc);

	xfer->page_size = 4096;
	xfer->page_per_cluster = UT_PPC;
	for (int i = 0; i < batch; i++) {
		free(xfer->reqs[i].payload);
		xfer->reqs[i].payload = calloc(1, (size_t)UT_CLUSTER_SZ);
		SPDK_CU_ASSERT_FATAL(xfer->reqs[i].payload != NULL);
	}
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = true;
	g_blob_read_only = true;	/* a snapshot */
	free(xfer->ranges);
	xfer->ranges = NULL;
	xfer->max_ranges = 0;
	xfer_setup_partial(xfer, 0, 0x42);
	g_blob_read_only = false;
	if (xfer->ranges == NULL) {
		/* not pinned: spdk_lvol_create_backup_task's one-range array */
		xfer->ranges = calloc(1, sizeof(*xfer->ranges));
		SPDK_CU_ASSERT_FATAL(xfer->ranges != NULL);
		xfer->max_ranges = 1;
	}
	return xfer;
}

static void
free_partial_xfer(struct spdk_lvs_xfer *xfer)
{
	free(xfer->partial);
	spdk_blob_dirty_gen_unref(xfer->dirty_gen);
	free_xfer(xfer);
	g_ut_dirty_gen = NULL;
}

/* Cluster 0: allocated, never written this epoch (no bitmap) -> whole.
 * Cluster 1: one 8 KiB block at 8 KiB, and 100 KiB at 1 MiB -> partial.
 * Cluster 2: written completely -> whole. */
static struct blob_dirty_gen *
make_gen_012(void)
{
	struct blob_dirty_gen *gen = blob_dirty_gen_create(UT_CLUSTER_SZ);

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	blob_dirty_mark(gen, (uint64_t)UT_CLUSTER_SZ + 8192, 8192);
	blob_dirty_mark(gen, (uint64_t)UT_CLUSTER_SZ + 1024 * 1024, 100 * 1024);
	blob_dirty_mark(gen, 2ULL * UT_CLUSTER_SZ, UT_CLUSTER_SZ);
	return gen;
}

/* Only a usable generation, on a fresh snapshot replication, is pinned. */
static void
xfer_partial_setup_gates(void)
{
	const int alloc[1] = {1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer;

	xfer = make_partial_xfer(1, 1, alloc, gen);
	CU_ASSERT(xfer->allow_partial);
	CU_ASSERT(xfer->dirty_gen == gen);
	CU_ASSERT(gen->refcnt == 2);
	free_partial_xfer(xfer);
	CU_ASSERT(gen->refcnt == 1);

	/* unusable generation, resumed task, final step, migration: full */
	xfer = make_xfer(1, 1, alloc);
	g_blob_read_only = true;	/* each case below fails on its own condition */
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = false;
	xfer->page_size = 4096;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	g_ut_dirty_usable = true;
	xfer_setup_partial(xfer, 512, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	xfer->final_step = true;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	xfer->final_step = false;
	xfer->type = XFER_MIGRATE_SNAPSHOT;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	/* a writable source: its generation keeps growing after the scan */
	xfer->type = XFER_REPLICATE_SNAPSHOT;
	g_blob_read_only = false;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	CU_ASSERT(gen->refcnt == 1);
	free_partial_xfer(xfer);

	blob_dirty_gen_free(gen);
}

/* The final step of the live volume sends dirty ranges only into a clone of
 * the base (cow_landing) and only while the volume is frozen; its writable
 * blob is fine then. */
static void
xfer_partial_setup_final_step(void)
{
	const int alloc[1] = {1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->final_step = true;
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = true;
	g_blob_read_only = false;	/* the live volume */

	/* no cow_landing: the destination would need a merge */
	g_xfer_lvol.freezed = true;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);

	/* cow_landing, but not frozen: the generation still moves */
	xfer->cow_landing = true;
	g_xfer_lvol.freezed = false;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);

	/* migration's final step never */
	g_xfer_lvol.freezed = true;
	xfer->type = XFER_MIGRATE_SNAPSHOT;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	CU_ASSERT(gen->refcnt == 1);

	/* replicate, cow_landing, frozen: partial on the writable blob */
	xfer->type = XFER_REPLICATE_SNAPSHOT;
	xfer_setup_partial(xfer, 0, 0x42);
	CU_ASSERT(xfer->allow_partial && xfer->dirty_gen == gen);
	CU_ASSERT(gen->refcnt == 2);
	free_partial_xfer(xfer);
	CU_ASSERT(gen->refcnt == 1);
	g_xfer_lvol.freezed = false;

	blob_dirty_gen_free(gen);
}

/* A final step into a clone of the snapshot ends without the chaining
 * signal (it would be written as data to page 0 of the destination); one
 * into a plain lvol still sends it, one page long. */
static void
xfer_final_step_signal(void)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req = NULL;

	xfer = make_xfer(2, 1, alloc);
	xfer->final_step = true;
	xfer->priority = true;
	xfer->dest_is_clone = true;
	snprintf(xfer->snapshot_name, sizeof(xfer->snapshot_name), "lvs/snap");
	xfer->len = 8;
	xfer->state = XFER_STATE_SIGNAL_TRANSFER;
	xfer_fill_queue(xfer, 1);
	xfer_replication(xfer);
	CU_ASSERT(xfer->state == XFER_STATE_DONE);
	CU_ASSERT(spdk_ring_count(xfer->ready_ring) == 0);
	free_xfer(xfer);

	xfer = make_xfer(2, 1, alloc);
	xfer->page_size = 4096;
	for (int i = 0; i < 2; i++) {
		free(xfer->reqs[i].payload);
		xfer->reqs[i].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
		SPDK_CU_ASSERT_FATAL(xfer->reqs[i].payload != NULL);
	}
	xfer->terminate_timeout = UINT64_MAX;
	xfer->final_step = true;
	xfer->priority = true;
	snprintf(xfer->snapshot_name, sizeof(xfer->snapshot_name), "lvs/snap");
	xfer->len = 8;
	xfer->state = XFER_STATE_SIGNAL_TRANSFER;
	xfer_fill_queue(xfer, 1);
	memset(xfer->reqs[0].payload, 0xff, xfer->page_size * xfer->page_per_cluster);
	xfer_replication(xfer);
	CU_ASSERT(xfer->signal_sent);
	CU_ASSERT(spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1);
	CU_ASSERT(req != NULL && req->len == 1 && req->action == REQ_ACTION_WRITE);
	if (req != NULL) {
		CU_ASSERT(strncmp(req->payload, "transfer_task_completed:lvs/snap", 32) == 0);
		/* only the signal page is cleared */
		CU_ASSERT(((uint8_t *)req->payload)[xfer->page_size] == 0xff);
	}
	free_xfer(xfer);
}

/* Every cluster is pre-allocated on the destination, partial ones too: they
 * receive only their dirty blocks, and the destination fills the rest from the
 * base once, after the transfer (spdk_blob_merge_base), not by a CoW per
 * request. */
static void
xfer_partial_alloc_includes_partial_clusters(void)
{
	const int alloc[3] = {1, 1, 1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer = make_partial_xfer(1, 3, alloc, gen);
	struct spdk_lvol_xfer_cmd_hdr *cmd;
	void *buf = calloc(1, SPDK_LVOL_XFER_CMD_SIZE);

	SPDK_CU_ASSERT_FATAL(buf != NULL && xfer->allow_partial);
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[0] == 0);
	CU_ASSERT(xfer->partial[1] == 1);
	CU_ASSERT(xfer->partial[2] == 0);
	CU_ASSERT(xfer->partial_clusters == 1);

	CU_ASSERT(xfer_build_alloc_cmd(xfer, buf) == 3);
	cmd = buf;
	CU_ASSERT(cmd->entries[0] == 0);
	CU_ASSERT(cmd->entries[1] == 1);
	CU_ASSERT(cmd->entries[2] == 2);

	free(buf);
	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/* cow_landing: a partial cluster is NOT pre-allocated on the destination (its
 * first range write CoWs it from the base the landing blob is chained to, no
 * merge after); whole clusters still are. */
static void
xfer_cow_landing_alloc_skips_partial_clusters(void)
{
	const int alloc[3] = {1, 1, 1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer = make_partial_xfer(1, 3, alloc, gen);
	struct spdk_lvol_xfer_cmd_hdr *cmd;
	void *buf = calloc(1, SPDK_LVOL_XFER_CMD_SIZE);

	SPDK_CU_ASSERT_FATAL(buf != NULL && xfer->allow_partial);
	xfer->cow_landing = true;
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[1] == 1);

	CU_ASSERT(xfer_build_alloc_cmd(xfer, buf) == 2);
	cmd = buf;
	CU_ASSERT(cmd->count == 2);
	CU_ASSERT(cmd->entries[0] == 0);
	CU_ASSERT(cmd->entries[1] == 2);
	CU_ASSERT(xfer_build_alloc_cmd(xfer, buf) == 0);	/* nothing left */

	free(buf);
	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/* cow_landing with only partial clusters: no alloc command at all. */
static void
xfer_cow_landing_all_partial_allocates_nothing(void)
{
	const int alloc[1] = {1};
	struct blob_dirty_gen *gen = blob_dirty_gen_create(UT_CLUSTER_SZ);
	struct spdk_lvs_xfer *xfer;
	void *buf = calloc(1, SPDK_LVOL_XFER_CMD_SIZE);

	SPDK_CU_ASSERT_FATAL(gen != NULL && buf != NULL);
	blob_dirty_mark(gen, 8192, 8192);
	xfer = make_partial_xfer(1, 1, alloc, gen);
	SPDK_CU_ASSERT_FATAL(xfer->allow_partial);
	xfer->cow_landing = true;
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[0] == 1);
	CU_ASSERT(xfer_build_alloc_cmd(xfer, buf) == 0);

	/* Without cow_landing the same cluster is pre-allocated. */
	xfer->cow_landing = false;
	xfer->alloc_next = 0;
	CU_ASSERT(xfer_build_alloc_cmd(xfer, buf) == 1);

	free(buf);
	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/* cow_landing changes only the alloc commands: the partial cluster's dirty
 * ranges are still sent, exactly as without it. */
static void
xfer_cow_landing_still_sends_partial_ranges(void)
{
	const int alloc[3] = {1, 1, 1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer = make_partial_xfer(128, 3, alloc, gen);
	struct spdk_lvs_xfer_req *req;
	uint32_t n = 0, in_c1 = 0;

	xfer->cow_landing = true;
	xfer_classify_partial(xfer);
	xfer->state = XFER_STATE_TRANSFER_CLUSTERS;
	xfer_replication(xfer);

	while (spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1) {
		if (req->offset >= UT_PPC && req->offset < 2 * UT_PPC) {
			in_c1++;
			CU_ASSERT(req->offset == UT_PPC + 2 || req->offset == UT_PPC + 256 ||
				  req->offset == UT_PPC + 272);
		}
		n++;
	}
	CU_ASSERT(in_c1 == 3);
	CU_ASSERT(n == 2 * (UT_PPC / 16) + 3);

	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/* In a partial task every request is at most 64 KiB (16 pages): a partial
 * cluster's coalesced dirty ranges (marked partial), and whole clusters as
 * one range over all of them (not partial: zero detection stays with the
 * task's no_zero_skip) -- so a deep window costs no more buffer memory than
 * a shallow one of whole clusters. */
static void
xfer_partial_dispatch_splits_ranges(void)
{
	const int alloc[3] = {1, 1, 1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer = make_partial_xfer(128, 3, alloc, gen);
	struct spdk_lvs_xfer_req *req;
	struct {
		uint64_t offset, len;
		bool partial;
	} want[80];
	uint32_t nw = 0, n = 0;

	for (uint32_t p = 0; p < UT_PPC; p += 16) {		/* cluster 0, whole */
		want[nw].offset = p;
		want[nw].partial = false;
		want[nw++].len = 16;
	}
	want[nw].offset = UT_PPC + 2;				/* 8 KiB at 8 KiB */
	want[nw].partial = true;
	want[nw++].len = 2;
	want[nw].offset = UT_PPC + 256;				/* 1 MiB: 64 KiB ... */
	want[nw].partial = true;
	want[nw++].len = 16;
	want[nw].offset = UT_PPC + 272;				/* ... + 40 KiB */
	want[nw].partial = true;
	want[nw++].len = 10;
	for (uint32_t p = 0; p < UT_PPC; p += 16) {		/* cluster 2, whole */
		want[nw].offset = 2 * UT_PPC + p;
		want[nw].partial = false;
		want[nw++].len = 16;
	}

	xfer_classify_partial(xfer);
	xfer->state = XFER_STATE_TRANSFER_CLUSTERS;
	xfer_replication(xfer);

	while (spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1) {
		SPDK_CU_ASSERT_FATAL(n < nw);
		CU_ASSERT(req->offset == want[n].offset);
		CU_ASSERT(req->len == want[n].len);
		CU_ASSERT(req->partial == want[n].partial);
		CU_ASSERT(req->len * 4096 <= 64 * 1024);
		n++;
	}
	CU_ASSERT(n == nw);
	CU_ASSERT(xfer->idx == nw);
	CU_ASSERT(g_xfer_lvol.xfer_full_clusters == 2);

	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/* A cluster whose dirty share reaches the whole-cluster threshold is
 * classified whole, not as ranges. Default 100 % (off): only a fully dirty
 * cluster is; at 50 % a mostly dirty one is; at 0 % every cluster is. */
static void
xfer_partial_mostly_dirty_cluster_goes_whole(void)
{
	const int alloc[2] = {1, 1};
	struct blob_dirty_gen *gen = blob_dirty_gen_create(UT_CLUSTER_SZ);
	struct spdk_lvs_xfer *xfer;

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	/* cluster 0: 8 KiB dirty; cluster 1: 1 MiB + 64 KiB of 2 MiB dirty (> 50 %) */
	blob_dirty_mark(gen, 0, 8192);
	blob_dirty_mark(gen, (uint64_t)UT_CLUSTER_SZ + 256 * 1024, 1024 * 1024 + 64 * 1024);

	/* default: only dirty ranges travel */
	CU_ASSERT(spdk_lvol_get_xfer_whole_cluster_pct() == 100);
	xfer = make_partial_xfer(1, 2, alloc, gen);
	SPDK_CU_ASSERT_FATAL(xfer->allow_partial);
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[0] == 1);
	CU_ASSERT(xfer->partial[1] == 1);
	CU_ASSERT(xfer->partial_clusters == 2);
	free_partial_xfer(xfer);

	CU_ASSERT(spdk_lvol_set_xfer_whole_cluster_pct(101) == -EINVAL);
	CU_ASSERT(spdk_lvol_set_xfer_whole_cluster_pct(50) == 0);
	xfer = make_partial_xfer(1, 2, alloc, gen);
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[0] == 1);
	CU_ASSERT(xfer->partial[1] == 0);
	CU_ASSERT(xfer->partial_clusters == 1);
	free_partial_xfer(xfer);

	CU_ASSERT(spdk_lvol_set_xfer_whole_cluster_pct(0) == 0);
	xfer = make_partial_xfer(1, 2, alloc, gen);
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[0] == 0);
	CU_ASSERT(xfer->partial[1] == 0);
	CU_ASSERT(xfer->partial_clusters == 0);
	free_partial_xfer(xfer);

	CU_ASSERT(spdk_lvol_set_xfer_whole_cluster_pct(100) == 0);
	blob_dirty_gen_free(gen);
}

/* A partial request lands on blocks that hold the base's content: its zero
 * blocks are written like any other; so are a resumed task's. */
static void
xfer_partial_and_resumed_requests_write_zeroes(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	/* 64 KiB, all zero */
	req->partial = true;
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 1);
	check_write(req, 0, 0, 16);
	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	free_xfer(xfer);

	req = make_cluster_req(&xfer, &rmt);
	xfer->no_zero_skip = true;	/* whole, all-zero request of a resumed task */
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 1);
	check_write(req, 0, 0, UT_REQ_BLOCKS);
	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	free_xfer(xfer);
}

/* Complete req's one write (as the remote bdev would). */
static void
complete_one_write(struct spdk_lvs_xfer_req *req)
{
	req->fragments_outstanding = 1;
	req->aggregated_status = 0;
	fragment_write_cb(NULL, true, req);
}

/* A completed request becomes the task's next request on the spot, on the
 * poll group it completed on: no trip through the free ring to the
 * dispatcher and back through the ready ring. With nothing left it leaves
 * the window, counted done. */
static void
xfer_completion_refills_in_place(void)
{
	const int alloc[3] = {1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(2, 3, alloc);
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req;

	CU_ASSERT(xfer_replication(xfer) == 2);	/* clusters 0 and 1 */
	SPDK_CU_ASSERT_FATAL(spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1);
	CU_ASSERT(req->offset == 0);

	memset(&rmt, 0, sizeof(rmt));
	rmt.group = &g_ut_lpg;
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	rmt.free_ring = xfer->free_ring;
	rmt.outstanding_io = 1;
	req->rmt_lvol = &rmt;
	req->status = XFER_REQ_STATUS_IN_FLIGHT;

	complete_one_write(req);			/* -> cluster 2, read submitted */
	CU_ASSERT(req->status == XFER_REQ_STATUS_IN_FLIGHT);
	CU_ASSERT(req->offset == 2 * xfer->page_per_cluster);
	CU_ASSERT(xfer->success_cnt == 1);
	CU_ASSERT(xfer->idx == 3);
	CU_ASSERT(xfer->outstanding_io == 2);
	CU_ASSERT(rmt.outstanding_io == 1);
	CU_ASSERT(g_xfer_lvol.xfer_stat_inline_reqs == 1);
	CU_ASSERT(spdk_ring_count(xfer->free_ring) == 0);

	complete_one_write(req);			/* nothing left */
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(xfer->success_cnt == 2);
	CU_ASSERT(xfer->outstanding_io == 1);
	CU_ASSERT(rmt.outstanding_io == 0);
	CU_ASSERT(spdk_ring_count(xfer->free_ring) == 0);

	free_xfer(xfer);
}

/* While a freeze-critical transfer runs, a background request is not
 * refilled in place: it goes back to the free ring, where the paused
 * dispatcher leaves it. */
static void
xfer_completion_hands_back_while_paused(void)
{
	const int alloc[3] = {1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(2, 3, alloc);
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req;

	CU_ASSERT(xfer_replication(xfer) == 2);
	SPDK_CU_ASSERT_FATAL(spdk_ring_dequeue(xfer->ready_ring, (void **)&req, 1) == 1);
	memset(&rmt, 0, sizeof(rmt));
	rmt.group = &g_ut_lpg;
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.free_ring = xfer->free_ring;
	rmt.outstanding_io = 1;
	req->rmt_lvol = &rmt;
	req->status = XFER_REQ_STATUS_IN_FLIGHT;

	__atomic_store_n(&g_priority_xfer_cnt, 1, __ATOMIC_SEQ_CST);
	complete_one_write(req);
	__atomic_store_n(&g_priority_xfer_cnt, 0, __ATOMIC_SEQ_CST);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(xfer->idx == 2);
	CU_ASSERT(xfer->success_cnt == 0);	/* counted by the dispatcher */
	CU_ASSERT(spdk_ring_count(xfer->free_ring) == 1);
	CU_ASSERT(rmt.outstanding_io == 0);

	free_xfer(xfer);
}

/* A resumed attempt starts at the lowest request not yet done: requests
 * complete out of order, and one that completed late must not move the resume
 * point past an earlier one still in flight -- or failed. */
static void
xfer_resume_offset_is_lowest_not_done(void)
{
	const int alloc[8] = {1, 1, 1, 1, 1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(4, 8, alloc);
	struct spdk_lvs_xfer_req *r = xfer->reqs;

	xfer->hold_idx = 6;		/* clusters 0..5 dispatched */
	r[0].offset = 2 * 4; r[0].status = XFER_REQ_STATUS_IN_FLIGHT;
	r[1].offset = 5 * 4; r[1].status = XFER_REQ_STATUS_DONE;	/* the one reused */
	r[2].offset = 3 * 4; r[2].status = XFER_REQ_STATUS_FAILED;
	r[3].offset = 4 * 4; r[3].status = XFER_REQ_STATUS_READY;
	CU_ASSERT(xfer_resume_offset(xfer, &r[1]) == 2 * 4);

	r[0].status = XFER_REQ_STATUS_DONE;
	CU_ASSERT(xfer_resume_offset(xfer, &r[1]) == 3 * 4);	/* the failed one */

	r[2].status = XFER_REQ_STATUS_DONE;
	r[3].status = XFER_REQ_STATUS_DONE;
	CU_ASSERT(xfer_resume_offset(xfer, &r[1]) == 6 * 4);	/* next to send */

	free_xfer(xfer);
}

/* Complete (as all-zero reads) every request that has its buffers and was
 * submitted, until all n are done. */
static uint32_t
ut_complete_submitted(struct spdk_lvs_xfer_req **r, uint32_t n)
{
	uint32_t done = 0, round, i;

	for (round = 0; round < 20 && done < n; round++) {
		poll_threads();
		for (i = 0; i < n; i++) {
			if (r[i]->status == XFER_REQ_STATUS_IN_FLIGHT && !r[i]->chain.waiting &&
			    !r[i]->buf_ready && r[i]->chain.nbufs != 0) {
				ut_zero_chain(r[i]);
				local_op_comp(r[i], 0);
				done++;
			}
		}
	}
	return done;
}

/* A task holds at most its cap of buffers although the pool has more: the
 * third request waits, and goes as soon as one of the first two is done. */
static void
xfer_replicate_task_cap_respected(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *r[3];

	xfer = make_cluster_xfer(3, &rmt);
	spdk_iobuf_chain_budget_init(&xfer->buf_budget, 16);	/* two requests' worth */
	for (int i = 0; i < 3; i++) {
		r[i] = ut_prep_req(xfer, i, &rmt);
		CU_ASSERT(submit_rw_reqs_local(r[i]) == 0);
	}
	CU_ASSERT(g_ut_blob_readv_cnt == 2);
	CU_ASSERT(r[2]->chain.waiting && r[2]->chain.nbufs == 0);
	CU_ASSERT(xfer->buf_budget.used == 16);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT - 16);
	helper_xfer_poller(&g_ut_lpg);		/* a kick finds the cap still full */
	CU_ASSERT(r[2]->chain.waiting);

	ut_zero_chain(r[0]);
	local_op_comp(r[0], 0);
	CU_ASSERT(r[2]->buf_ready);
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 3 && g_ut_blob_readv_arg == r[2]);
	CU_ASSERT(xfer->buf_budget.max_used == 16);

	CU_ASSERT(ut_complete_submitted(&r[1], 2) == 2);
	CU_ASSERT(xfer->buf_budget.used == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);
}

/* All background replication together holds at most the shared cap
 * (SPDK_IOBUF_CHAIN_BG_PCT_DEFAULT % of the pool): the rest of the pool stays
 * for client IO, even with no per-task cap. */
static void
xfer_replicate_leaves_client_reserve(void)
{
	struct spdk_iobuf_chain_budget *bg = spdk_iobuf_chain_bg_budget();
	const uint32_t cap = UT_XFER_SMALL_COUNT * SPDK_IOBUF_CHAIN_BG_PCT_DEFAULT / 100;
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *r[24];

	xfer = make_cluster_xfer(24, &rmt);
	for (int i = 0; i < 24; i++) {
		r[i] = ut_prep_req(xfer, i, &rmt);
		CU_ASSERT(submit_rw_reqs_local(r[i]) == 0);
	}
	CU_ASSERT(g_ut_blob_readv_cnt == cap / 8);
	CU_ASSERT(bg->used == cap);
	CU_ASSERT(ut_xfer_bufs_free() >= UT_XFER_SMALL_COUNT - cap);

	CU_ASSERT(ut_complete_submitted(r, 24) == 24);
	CU_ASSERT(g_ut_blob_readv_cnt == 24);
	CU_ASSERT(bg->max_used <= cap);
	CU_ASSERT(bg->used == 0);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);
}

/* The frozen final step does not wait behind background replication: its
 * request goes ahead of the waiting background ones (the first gives back
 * the 3 buffers it held) and gets the next buffers. */
static void
xfer_final_step_goes_ahead_of_background(void)
{
	struct spdk_lvs_xfer *bg, *fin;
	struct remote_lvol_info rmt, rmt_fin;
	struct spdk_lvs_xfer_req *a, *b, *p;
	struct spdk_lvs_xfer_req *r[3];
	void **bufs = calloc(UT_XFER_SMALL_COUNT, sizeof(void *));
	uint32_t n, i;

	SPDK_CU_ASSERT_FATAL(bufs != NULL);
	bg = make_cluster_xfer(2, &rmt);
	fin = make_cluster_xfer(1, &rmt_fin);
	fin->priority = true;
	a = ut_prep_req(bg, 0, &rmt);
	b = ut_prep_req(bg, 1, &rmt);
	p = ut_prep_req(fin, 0, &rmt_fin);

	n = ut_xfer_drain(bufs, 3);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(submit_rw_reqs_local(b) == 0);
	CU_ASSERT(a->chain.waiting && a->chain.nbufs == 3);
	CU_ASSERT(submit_rw_reqs_local(p) == 0);
	CU_ASSERT(TAILQ_FIRST(&g_ut_lpg.bufq.waitq) == &p->chain);
	CU_ASSERT(p->chain.nbufs == 3);
	CU_ASSERT(a->chain.waiting && a->chain.nbufs == 0);

	for (i = 0; i < 5; i++) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	CU_ASSERT(p->buf_ready && a->chain.waiting);
	poll_threads();
	CU_ASSERT(g_ut_blob_readv_cnt == 1 && g_ut_blob_readv_arg == p);

	while (n > 0) {
		spdk_iobuf_put(&g_ut_lpg.iobuf, bufs[--n], UT_XFER_SMALL_SIZE);
	}
	r[0] = p;
	r[1] = a;
	r[2] = b;
	CU_ASSERT(ut_complete_submitted(r, 3) == 3);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free(bufs);
	free_xfer(fin);
	free_xfer(bg);
}

/* When a task's last requests leave the poll group the iobuf channel goes back
 * (a channel held for the app's life hangs the iobuf shutdown); the next
 * replication request takes it again. */
static void
xfer_poll_group_releases_iobuf_channel(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt, *gone;
	struct spdk_lvs_xfer_req *a;

	CU_ASSERT(g_ut_lpg.iobuf_ok);
	xfer = make_cluster_xfer(1, &rmt);
	a = ut_prep_req(xfer, 0, &rmt);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(ut_complete_submitted(&a, 1) == 1);
	CU_ASSERT(rmt.outstanding_io == 0);

	/* the task's teardown on this poll group, once its IO drained */
	gone = calloc(1, sizeof(*gone));
	SPDK_CU_ASSERT_FATAL(gone != NULL);
	gone->group = &g_ut_lpg;
	gone->xfer_task = xfer;
	CU_ASSERT(spdk_wait_for_xfer_pg_io_cleanup_poller(gone) == -1);
	CU_ASSERT(!g_ut_lpg.iobuf_ok);
	CU_ASSERT(g_ut_lpg.iobuf.parent == NULL);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);

	a = ut_prep_req(xfer, 0, &rmt);
	CU_ASSERT(submit_rw_reqs_local(a) == 0);
	CU_ASSERT(g_ut_lpg.iobuf_ok);
	CU_ASSERT(a->chain.nbufs == 8);
	CU_ASSERT(ut_complete_submitted(&a, 1) == 1);
	CU_ASSERT(ut_xfer_bufs_free() == UT_XFER_SMALL_COUNT);
	free_xfer(xfer);
}

/*
 * Snapshot chains on the source for the bridge tests. Blob ids:
 * 0x40 <- 0x41 <- 0x42 <- UT_SRC_ID (0x43): the destination holds 0x40;
 * 0x41 owns cluster 1, 0x42 owns cluster 2, the source owns cluster 3.
 */
static struct spdk_lvol g_ut_chain_lvols[4];
static struct spdk_blob g_ut_chain_blobs[4];

static void
ut_chain_open(spdk_blob_id id, int slot)
{
	struct spdk_lvol *lvol = &g_ut_chain_lvols[slot];

	memset(lvol, 0, sizeof(*lvol));
	memset(&g_ut_chain_blobs[slot], 0, sizeof(g_ut_chain_blobs[slot]));
	g_ut_chain_blobs[slot].id = id;
	lvol->blob = &g_ut_chain_blobs[slot];
	lvol->blob_id = id;
	lvol->lvol_store = &g_xfer_lvs;
	TAILQ_INSERT_TAIL(&g_xfer_lvs.lvols, lvol, link);
}

/* after make_xfer (which resets g_xfer_lvs and the chain) */
static void
ut_chain_4(void)
{
	ut_chain_clear();
	ut_chain_set(0x41, 0x40, 1u << 1);
	ut_chain_set(0x42, 0x41, 1u << 2);
	ut_chain_set(UT_SRC_ID, 0x42, 1u << 3);
	ut_chain_open(0x41, 0);
	ut_chain_open(0x42, 1);
}

/* The full fallback of a delta request (the generation is unusable) against
 * a base older than the source's parent: the clusters the snapshots in
 * between own are sent too, whole -- not only the source's own. */
static void
xfer_full_fallback_bridges_skipped_snapshots(void)
{
	const int alloc[5] = {0, 0, 0, 0, 0};
	struct spdk_lvs_xfer *xfer = make_xfer(1, 5, alloc);
	int count = 0;

	ut_chain_4();
	g_blob_read_only = true;
	g_ut_dirty_gen = NULL;		/* no generation: full clusters */
	xfer->page_size = 4096;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x40) == 0);
	CU_ASSERT(!xfer->allow_partial);
	SPDK_CU_ASSERT_FATAL(xfer->bridged != NULL);
	CU_ASSERT(xfer->bridge_hops == 2);
	CU_ASSERT(xfer->bridge_clusters == 2);
	CU_ASSERT(!xfer->bridged[0] && xfer->bridged[1] && xfer->bridged[2]);
	CU_ASSERT(!xfer->bridged[3] && !xfer->bridged[4]);

	/* XFER_STATE_NONE: the source's own clusters, then the bridged ones */
	xfer->clusters[3] = 1;
	count = 1;
	count += xfer_add_bridged_clusters(xfer);
	CU_ASSERT(count == 3);
	CU_ASSERT(xfer->clusters[0] == 0 && xfer->clusters[1] != 0 && xfer->clusters[2] != 0);
	CU_ASSERT(xfer->clusters[3] != 0 && xfer->clusters[4] == 0);
	free(xfer->bridged);
	xfer->bridged = NULL;

	/* the base is the source's parent: its own clusters are the difference */
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x42) == 0);
	CU_ASSERT(xfer->bridged == NULL);
	/* a resumed task falls back too, and bridges the same way */
	CU_ASSERT(xfer_setup_partial(xfer, 512, 0x40) == 0);
	CU_ASSERT(xfer->bridged != NULL && xfer->bridge_clusters == 2);

	g_blob_read_only = false;
	free_xfer(xfer);
	ut_chain_clear();
}

/* A full fallback that cannot reach the destination's base refuses to start
 * (the clusters in between would be missing): the base is not an ancestor,
 * an in-between snapshot is not open here, or too many hops. */
static void
xfer_full_fallback_refuses_unreachable_base(void)
{
	const int alloc[5] = {0, 0, 0, 0, 0};
	struct spdk_lvs_xfer *xfer = make_xfer(1, 5, alloc);
	int i;

	ut_chain_4();
	g_blob_read_only = true;
	g_ut_dirty_gen = NULL;
	xfer->page_size = 4096;

	/* not an ancestor */
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x99) == -ENOENT);
	CU_ASSERT(xfer->bridged == NULL);

	/* 0x41 is not open on this node */
	TAILQ_REMOVE(&g_xfer_lvs.lvols, &g_ut_chain_lvols[0], link);
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x40) == -ENOENT);
	CU_ASSERT(xfer->bridged == NULL);
	TAILQ_INSERT_HEAD(&g_xfer_lvs.lvols, &g_ut_chain_lvols[0], link);

	/* a migration's partial_base is not a replication base: as before */
	xfer->type = XFER_MIGRATE_SNAPSHOT;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x99) == 0);
	xfer->type = XFER_REPLICATE_SNAPSHOT;
	/* nor is 0 (no base given) */
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0) == 0);

	/* a long chain: more than XFER_BRIDGE_MAX_HOPS snapshots in between */
	ut_chain_clear();
	ut_chain_set(UT_SRC_ID, 0x200, 0);
	for (i = 0; i <= XFER_BRIDGE_MAX_HOPS; i++) {
		ut_chain_set(0x200 + i, 0x200 + i + 1, 0);
	}
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x200 + XFER_BRIDGE_MAX_HOPS + 1) == -ENOENT);

	g_blob_read_only = false;
	free_xfer(xfer);
	ut_chain_clear();
}

/* The bridged delta (34c538289): the generation started at the source's
 * parent, the destination holds an older snapshot. The delta goes on against
 * it: the clusters the in-between snapshots own (the generation's base
 * included, the destination's base not) are sent whole, the dirty clusters
 * as ranges. */
static void
xfer_bridged_delta_sends_in_between_clusters_whole(void)
{
	const int alloc[5] = {0, 0, 0, 1, 0};
	struct blob_dirty_gen *gen = blob_dirty_gen_create(UT_CLUSTER_SZ);
	struct spdk_lvs_xfer *xfer;
	int count = 1;

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	gen->base = 0x42;
	/* 8 KiB dirty in clusters 2 (bridged too) and 3 (the source's own) */
	blob_dirty_mark(gen, 2ULL * UT_CLUSTER_SZ, 8192);
	blob_dirty_mark(gen, 3ULL * UT_CLUSTER_SZ, 8192);

	xfer = make_xfer(1, 5, alloc);
	ut_chain_4();
	xfer->page_size = 4096;
	xfer->page_per_cluster = UT_PPC;
	g_ut_dirty_usable_own_base = true;
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = true;
	g_blob_read_only = true;
	free(xfer->ranges);
	xfer->ranges = NULL;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x40) == 0);
	g_blob_read_only = false;
	SPDK_CU_ASSERT_FATAL(xfer->allow_partial);
	SPDK_CU_ASSERT_FATAL(xfer->bridged != NULL);
	CU_ASSERT(xfer->dirty_gen == gen);
	CU_ASSERT(xfer->bridge_hops == 2);	/* 0x42 and 0x41 */
	CU_ASSERT(!xfer->bridged[0] && xfer->bridged[1] && xfer->bridged[2] && !xfer->bridged[3]);

	count += xfer_add_bridged_clusters(xfer);
	CU_ASSERT(count == 3);
	xfer_classify_partial(xfer);
	CU_ASSERT(xfer->partial[1] == 0);	/* bridged: whole */
	CU_ASSERT(xfer->partial[2] == 0);	/* bridged, though dirty: whole */
	CU_ASSERT(xfer->partial[3] == 1);	/* the source's own dirty cluster */
	CU_ASSERT(xfer->partial_clusters == 1);

	/* against the generation's own base no bridge is needed */
	free(xfer->partial);
	free(xfer->ranges);
	free(xfer->bridged);
	xfer->partial = NULL;
	xfer->ranges = NULL;
	xfer->bridged = NULL;
	spdk_blob_dirty_gen_unref(xfer->dirty_gen);
	xfer->dirty_gen = NULL;
	xfer->allow_partial = false;
	g_blob_read_only = true;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x42) == 0);
	g_blob_read_only = false;
	CU_ASSERT(xfer->allow_partial && xfer->bridged == NULL);

	g_ut_dirty_usable_own_base = false;
	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
	ut_chain_clear();
}

/* A bridge the delta cannot build (an in-between snapshot is not open) is no
 * delta; the full fallback cannot reach the base either: refused. */
static void
xfer_bridged_delta_unbridgeable_is_refused(void)
{
	const int alloc[5] = {0, 0, 0, 1, 0};
	struct blob_dirty_gen *gen = blob_dirty_gen_create(UT_CLUSTER_SZ);
	struct spdk_lvs_xfer *xfer = make_xfer(1, 5, alloc);

	SPDK_CU_ASSERT_FATAL(gen != NULL);
	gen->base = 0x42;
	ut_chain_4();
	TAILQ_REMOVE(&g_xfer_lvs.lvols, &g_ut_chain_lvols[0], link);	/* 0x41 */
	g_ut_dirty_usable_own_base = true;
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = true;
	g_blob_read_only = true;
	xfer->page_size = 4096;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x40) == -ENOENT);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL && xfer->bridged == NULL);
	CU_ASSERT(gen->refcnt == 1);

	g_blob_read_only = false;
	g_ut_dirty_usable_own_base = false;
	g_ut_dirty_gen = NULL;
	free_xfer(xfer);
	blob_dirty_gen_free(gen);
	ut_chain_clear();
}

/* A transfer into a clone (dest_clone / a cow_landing final step) after one
 * that did not complete sends full clusters, not dirty ranges: the clone may
 * hold clusters the earlier alloc step zero-filled that no data reached, and
 * a range written into one would leave zeroes where the base belongs. */
static void
xfer_dest_clone_after_incomplete_round_sends_full(void)
{
	const int alloc[3] = {1, 1, 1};
	struct blob_dirty_gen *gen = make_gen_012();
	struct spdk_lvs_xfer *xfer;

	/* the round before completed: a delta */
	xfer = make_xfer(1, 3, alloc);
	xfer->dest_is_clone = true;
	g_xfer_lvol.xfer_clone_round_incomplete = false;
	g_ut_dirty_gen = gen;
	g_ut_dirty_usable = true;
	g_blob_read_only = true;
	xfer->page_size = 4096;
	free(xfer->ranges);
	xfer->ranges = NULL;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x42) == 0);
	CU_ASSERT(xfer->allow_partial);
	free(xfer->partial);
	free(xfer->ranges);
	xfer->partial = NULL;
	xfer->ranges = NULL;
	spdk_blob_dirty_gen_unref(xfer->dirty_gen);
	xfer->dirty_gen = NULL;
	xfer->allow_partial = false;

	/* it did not: full clusters */
	g_xfer_lvol.xfer_clone_round_incomplete = true;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x42) == 0);
	CU_ASSERT(!xfer->allow_partial && xfer->dirty_gen == NULL);
	/* a landing volume (not a clone) is new: the flag does not matter */
	xfer->dest_is_clone = false;
	CU_ASSERT(xfer_setup_partial(xfer, 0, 0x42) == 0);
	CU_ASSERT(xfer->allow_partial);
	CU_ASSERT(gen->refcnt == 2);

	g_blob_read_only = false;
	g_xfer_lvol.xfer_clone_round_incomplete = false;
	free_partial_xfer(xfer);
	blob_dirty_gen_free(gen);
}

/*
 * spdk_lvol_transfer end to end, for the task setup: a source lvol on a fake
 * lvol store and transfer device. No poll groups are registered, so no
 * request is ever sent; the md poller runs the task's state machine.
 */
static struct spdk_lvol g_ut_tx_lvol;
static struct spdk_lvol_store g_ut_tx_lvs;
static struct spdk_blob g_ut_tx_blob;
static struct spdk_transfer_dev g_ut_tx_tdev;
static int g_ut_requeued;

static void
ut_tx_setup(void)
{
	memset(&g_ut_tx_lvol, 0, sizeof(g_ut_tx_lvol));
	memset(&g_ut_tx_lvs, 0, sizeof(g_ut_tx_lvs));
	memset(&g_ut_tx_blob, 0, sizeof(g_ut_tx_blob));
	memset(&g_ut_tx_tdev, 0, sizeof(g_ut_tx_tdev));
	TAILQ_INIT(&g_ut_tx_lvs.lvols);
	g_ut_tx_lvs.blobstore = (struct spdk_blob_store *)0x1;	/* only passed to stubs */
	g_ut_tx_blob.id = 0x77;
	g_ut_tx_blob.num_clusters = 4;
	g_ut_tx_lvol.blob = &g_ut_tx_blob;
	g_ut_tx_lvol.blob_id = 0x77;
	g_ut_tx_lvol.lvol_store = &g_ut_tx_lvs;
	TAILQ_INIT(&g_ut_tx_lvol.redirect_migrate_io);
	snprintf(g_ut_tx_lvol.name, sizeof(g_ut_tx_lvol.name), "ut_tx_lvol");
	g_ut_tx_tdev.desc = (struct spdk_bdev_desc *)0x1;	/* only null-checked */
	g_ut_tx_tdev.lvs = &g_ut_tx_lvs;
	g_ut_requeued = 0;
	g_ut_dirty_gen = NULL;
	ut_chain_clear();
	ut_chain_set(0x77, 0x76, 0);		/* the destination holds 0x76 */
	MOCK_SET(spdk_bs_get_page_size, 4096);
}

static void
ut_tx_teardown(void)
{
	MOCK_CLEAR(spdk_bs_get_page_size);
	MOCK_CLEAR(spdk_ring_create);
	ut_chain_clear();
}

static void
ut_tx_cb(void *cb_arg, struct spdk_lvol *lvol, int rc)
{
}

/* the client IO's resubmission (vbdev_lvol_dequeue_io in production) */
static void
ut_requeue_cb(void *arg)
{
	g_ut_requeued++;
	free(arg);
}

/* Client IO queued on the frozen volume, as spdk_lvol_freeze_io does. */
static void
ut_queue_frozen_io(struct spdk_lvol *lvol)
{
	struct spdk_migrate_io *mio = calloc(1, sizeof(*mio));

	SPDK_CU_ASSERT_FATAL(mio != NULL);
	mio->thread = spdk_get_thread();
	mio->cb_fn = ut_requeue_cb;
	TAILQ_INSERT_TAIL(&lvol->redirect_migrate_io, mio, entry);
}

/* The final step freezes the volume before its task is built. If the task
 * cannot be built, the freeze is undone through the unfreeze path: the client
 * IO queued in the meantime is resubmitted, not stranded. A freeze that was
 * in place before the step is someone else's and stays, with its IO. */
static void
xfer_final_step_setup_failure_unfreezes(void)
{
	struct spdk_lvol *lvol = &g_ut_tx_lvol;
	int rc;

	ut_tx_setup();
	MOCK_SET(spdk_ring_create, NULL);	/* spdk_lvol_create_backup_task fails */

	/* the IO a poll group queued between the freeze and the failure */
	ut_queue_frozen_io(lvol);
	rc = spdk_lvol_transfer(lvol, 0, 2, XFER_REPLICATE_SNAPSHOT, &g_ut_tx_tdev, "snap", 1, 0,
				false, 0, true, false, ut_tx_cb, NULL);
	CU_ASSERT(rc == -ENOMEM);
	poll_threads();
	CU_ASSERT(!lvol->freezed);
	CU_ASSERT(g_ut_requeued == 1);
	CU_ASSERT(TAILQ_EMPTY(&lvol->redirect_migrate_io));
	CU_ASSERT(TAILQ_EMPTY(&g_lvs_xfer_tasks));

	/* frozen by someone else before the step: stays frozen, IO stays queued */
	lvol->freezed = true;
	ut_queue_frozen_io(lvol);
	rc = spdk_lvol_transfer(lvol, 0, 2, XFER_REPLICATE_SNAPSHOT, &g_ut_tx_tdev, "snap", 1, 0,
				false, 0, true, false, ut_tx_cb, NULL);
	CU_ASSERT(rc == -ENOMEM);
	poll_threads();
	CU_ASSERT(lvol->freezed);
	CU_ASSERT(g_ut_requeued == 1);
	CU_ASSERT(!TAILQ_EMPTY(&lvol->redirect_migrate_io));
	spdk_lvol_unfreeze_io(lvol);		/* the owner's unfreeze */
	poll_threads();
	CU_ASSERT(g_ut_requeued == 2);

	ut_tx_teardown();
}

/* A final step whose delta falls back to full clusters against a base it
 * cannot reach is refused before its task starts: same freeze undo. */
static void
xfer_final_step_refused_base_unfreezes(void)
{
	struct spdk_lvol *lvol = &g_ut_tx_lvol;
	int rc;

	ut_tx_setup();
	ut_queue_frozen_io(lvol);
	rc = spdk_lvol_transfer(lvol, 0, 2, XFER_REPLICATE_SNAPSHOT, &g_ut_tx_tdev, "snap", 1, 0,
				true, 0x99, true, false, ut_tx_cb, NULL);
	CU_ASSERT(rc == -ENOENT);
	poll_threads();
	CU_ASSERT(!lvol->freezed);
	CU_ASSERT(g_ut_requeued == 1);
	CU_ASSERT(TAILQ_EMPTY(&g_lvs_xfer_tasks));

	ut_tx_teardown();
}

/* Run the md poller until the task list is empty, then let the delayed
 * teardown (destroy_xfer_task_tmo, 200 ms) free the task. */
static void
ut_tx_run_to_done(void)
{
	for (int i = 0; i < 10 && !TAILQ_EMPTY(&g_lvs_xfer_tasks); i++) {
		spdk_delay_us(1000);
		poll_threads();
	}
	CU_ASSERT(TAILQ_EMPTY(&g_lvs_xfer_tasks));
	spdk_delay_us(300 * 1000);
	poll_threads();
}

/* A dest_clone round: its zero blocks are written (the clone owns clusters
 * from earlier rounds, which the alloc step skips), and the source remembers
 * the round as incomplete until its task is done. */
static void
xfer_dest_clone_round_lifecycle(void)
{
	struct spdk_lvol *lvol = &g_ut_tx_lvol;
	struct spdk_lvs_xfer *task;
	int rc;

	ut_tx_setup();
	rc = spdk_lvol_transfer(lvol, 0, 2, XFER_REPLICATE_SNAPSHOT, &g_ut_tx_tdev, NULL, 1, 0,
				false, 0, true, true, ut_tx_cb, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	CU_ASSERT(lvol->xfer_clone_round_incomplete);

	/* the drain delay (50 ms) puts the task on the md poller's list */
	spdk_delay_us(60 * 1000);
	poll_threads();
	task = TAILQ_FIRST(&g_lvs_xfer_tasks);
	SPDK_CU_ASSERT_FATAL(task != NULL && task->lvol == lvol);
	CU_ASSERT(task->dest_is_clone);
	CU_ASSERT(task->no_zero_skip);

	/* nothing to send (the source owns no cluster here): the task is done
	 * and the round complete */
	ut_tx_run_to_done();
	CU_ASSERT(lvol->transfer_status == XFER_DONE);
	CU_ASSERT(!lvol->xfer_clone_round_incomplete);

	/* a plain landing-volume round keeps zero detection */
	rc = spdk_lvol_transfer(lvol, 0, 2, XFER_REPLICATE_SNAPSHOT, &g_ut_tx_tdev, NULL, 1, 0,
				false, 0, false, false, ut_tx_cb, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	CU_ASSERT(!lvol->xfer_clone_round_incomplete);
	spdk_delay_us(60 * 1000);
	poll_threads();
	task = TAILQ_FIRST(&g_lvs_xfer_tasks);
	SPDK_CU_ASSERT_FATAL(task != NULL);
	CU_ASSERT(!task->dest_is_clone);
	CU_ASSERT(!task->no_zero_skip);
	ut_tx_run_to_done();

	spdk_poller_unregister(&g_xfer_md_poller);
	poll_threads();
	ut_tx_teardown();
}

static void
ut_xfer_iobuf_finish_cb(void *ctx)
{
}

int
main(int argc, char **argv)
{
	CU_pSuite suite = NULL;
	struct spdk_iobuf_opts iobuf_opts;
	unsigned int num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("lvol_xfer", NULL, NULL);
	CU_ADD_TEST(suite, xfer_fills_whole_window);
	CU_ADD_TEST(suite, xfer_background_pauses_while_priority_active);
	CU_ADD_TEST(suite, xfer_priority_task_dispatches_during_priority_window);
	CU_ADD_TEST(suite, helper_serves_priority_first_and_exclusively);
	CU_ADD_TEST(suite, xfer_stops_at_last_cluster);
	CU_ADD_TEST(suite, xfer_skips_unallocated_clusters);
	CU_ADD_TEST(suite, xfer_second_pass_continues_and_completes);
	CU_ADD_TEST(suite, helper_drains_ready_ring);
	CU_ADD_TEST(suite, helper_takes_its_share_of_the_window);
	CU_ADD_TEST(suite, xfer_read_is_one_cluster_read);
	CU_ADD_TEST(suite, xfer_replicate_zero_cluster_sends_nothing);
	CU_ADD_TEST(suite, xfer_replicate_full_cluster_is_one_range);
	CU_ADD_TEST(suite, xfer_replicate_sends_only_data_ranges);
	CU_ADD_TEST(suite, xfer_replicate_too_many_ranges_sends_whole_cluster);
	CU_ADD_TEST(suite, xfer_replicate_submit_failure_fails_the_request);
	CU_ADD_TEST(suite, xfer_replicate_write_failure_fails_the_request);
	CU_ADD_TEST(suite, xfer_replicate_waits_for_buffers);
	CU_ADD_TEST(suite, xfer_replicate_kick_takes_other_threads_buffers);
	CU_ADD_TEST(suite, xfer_replicate_teardown_fails_waiting_requests);
	CU_ADD_TEST(suite, xfer_replicate_command_is_copied_into_a_chain);
	CU_ADD_TEST(suite, xfer_partial_setup_gates);
	CU_ADD_TEST(suite, xfer_partial_setup_final_step);
	CU_ADD_TEST(suite, xfer_final_step_signal);
	CU_ADD_TEST(suite, xfer_partial_alloc_includes_partial_clusters);
	CU_ADD_TEST(suite, xfer_cow_landing_alloc_skips_partial_clusters);
	CU_ADD_TEST(suite, xfer_cow_landing_all_partial_allocates_nothing);
	CU_ADD_TEST(suite, xfer_cow_landing_still_sends_partial_ranges);
	CU_ADD_TEST(suite, xfer_partial_dispatch_splits_ranges);
	CU_ADD_TEST(suite, xfer_partial_mostly_dirty_cluster_goes_whole);
	CU_ADD_TEST(suite, xfer_partial_and_resumed_requests_write_zeroes);
	CU_ADD_TEST(suite, xfer_resume_offset_is_lowest_not_done);
	CU_ADD_TEST(suite, xfer_completion_refills_in_place);
	CU_ADD_TEST(suite, xfer_completion_hands_back_while_paused);
	CU_ADD_TEST(suite, xfer_replicate_task_cap_respected);
	CU_ADD_TEST(suite, xfer_replicate_leaves_client_reserve);
	CU_ADD_TEST(suite, xfer_final_step_goes_ahead_of_background);
	CU_ADD_TEST(suite, xfer_poll_group_releases_iobuf_channel);
	CU_ADD_TEST(suite, xfer_full_fallback_bridges_skipped_snapshots);
	CU_ADD_TEST(suite, xfer_full_fallback_refuses_unreachable_base);
	CU_ADD_TEST(suite, xfer_bridged_delta_sends_in_between_clusters_whole);
	CU_ADD_TEST(suite, xfer_bridged_delta_unbridgeable_is_refused);
	CU_ADD_TEST(suite, xfer_dest_clone_after_incomplete_round_sends_full);
	CU_ADD_TEST(suite, xfer_final_step_setup_failure_unfreezes);
	CU_ADD_TEST(suite, xfer_final_step_refused_base_unfreezes);
	CU_ADD_TEST(suite, xfer_dest_clone_round_lifecycle);

	allocate_threads(2);
	set_thread(0);

	spdk_iobuf_get_opts(&iobuf_opts, sizeof(iobuf_opts));
	iobuf_opts.small_pool_count = UT_XFER_SMALL_COUNT;
	iobuf_opts.small_bufsize = UT_XFER_SMALL_SIZE;
	iobuf_opts.large_pool_count = 8;
	if (spdk_iobuf_set_opts(&iobuf_opts) != 0 || spdk_iobuf_initialize() != 0 ||
	    spdk_iobuf_register_module(LVS_XFER_IOBUF_MODULE) != 0 ||
	    spdk_iobuf_register_module("ut_xfer") != 0) {
		fprintf(stderr, "iobuf setup failed\n");
		return 1;
	}
	TAILQ_INIT(&g_ut_lpg.rmt_lvols);
	TAILQ_INIT(&g_ut_lpg.ch_tdev);
	TAILQ_INIT(&g_ut_lpg.buf_readyq);
	g_ut_lpg.thread = spdk_get_thread();
	g_ut_lpg.thread_name = "ut_lpg";
	lvs_poll_group_iobuf_init(&g_ut_lpg);
	if (!g_ut_lpg.iobuf_ok) {
		fprintf(stderr, "poll group iobuf channel failed\n");
		return 1;
	}

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	if (g_ut_lpg.iobuf_ok) {
		spdk_iobuf_channel_fini(&g_ut_lpg.iobuf);
	}
	spdk_iobuf_finish(ut_xfer_iobuf_finish_cb, NULL);
	poll_threads();
	free_threads();
	CU_cleanup_registry();
	return num_failures;
}
