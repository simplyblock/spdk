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

static struct spdk_lvol g_xfer_lvol;
static struct spdk_lvol_store g_xfer_lvs;

static struct spdk_lvs_xfer *
make_xfer(int cluster_batch, uint32_t num_clusters, const int *allocated)
{
	struct spdk_lvs_xfer *xfer = calloc(1, sizeof(*xfer));
	SPDK_CU_ASSERT_FATAL(xfer != NULL);

	memset(&g_xfer_lvol, 0, sizeof(g_xfer_lvol));
	memset(&g_xfer_lvs, 0, sizeof(g_xfer_lvs));
	g_xfer_lvol.lvol_store = &g_xfer_lvs;
	snprintf(g_xfer_lvol.name, sizeof(g_xfer_lvol.name), "xfer_ut_lvol");

	xfer->lvol = &g_xfer_lvol;
	xfer->type = XFER_REPLICATE_SNAPSHOT;
	xfer->state = XFER_STATE_TRANSFER_CLUSTERS;
	xfer->final_step = false;
	xfer->cluster_batch = cluster_batch;
	xfer->page_size = 16;
	xfer->page_per_cluster = 4;
	xfer->num_clusters = num_clusters;
	xfer->clusters = calloc(num_clusters, sizeof(uint64_t));
	SPDK_CU_ASSERT_FATAL(xfer->clusters != NULL);
	for (uint32_t i = 0; i < num_clusters; i++) {
		xfer->clusters[i] = allocated[i] ? 0xABCD0000 + i : 0;
	}

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
	xfer_fill_queue(xfer, cluster_batch);
	xfer->timeout = spdk_get_ticks();
	return xfer;
}

static void
free_xfer(struct spdk_lvs_xfer *xfer)
{
	for (int i = 0; i < xfer->cluster_batch; i++) {
		free(xfer->reqs[i].payload);
	}
	free(xfer->reqs);
	spdk_ring_free(xfer->free_ring);
	spdk_ring_free(xfer->ready_ring);
	free(xfer->clusters);
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
 * Replication write path (submit_req_fragments): the cluster is read whole
 * (one spdk_blob_io_read), then written to the remote in writes of at most
 * 32 blocks of 4 KiB. Only the data ranges are written (the destination
 * clusters were allocated by the alloc step); an all-zero cluster sends
 * nothing; more than 64 ranges send the whole cluster.
 */
#define UT_CLUSTER_BLOCKS	512
#define UT_MAX_WRITE_BLOCKS	32
#define UT_DST_OFFSET		0x10000

static struct spdk_bdev g_ut_rmt_bdev;
static struct spdk_bdev_desc g_ut_rmt_desc;

static struct spdk_lvs_xfer_req *
make_cluster_req(struct spdk_lvs_xfer **xferp, struct remote_lvol_info *rmt)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = UT_CLUSTER_BLOCKS;
	free(xfer->reqs[0].payload);
	xfer->reqs[0].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
	SPDK_CU_ASSERT_FATAL(xfer->reqs[0].payload != NULL);
	/* the request is in flight: take it off the free ring */
	while (spdk_ring_dequeue(xfer->free_ring, (void **)&req, 1) == 1) {
	}

	memset(rmt, 0, sizeof(*rmt));
	rmt->status = true;
	rmt->type = XFER_REPLICATE_SNAPSHOT;
	rmt->md_channel = (struct spdk_io_channel *)0x1;
	g_ut_rmt_bdev.blocklen = 4096;
	g_ut_rmt_desc.bdev = &g_ut_rmt_bdev;
	rmt->desc = &g_ut_rmt_desc;
	rmt->channel = (struct spdk_io_channel *)0x1;
	rmt->outstanding_io = 1;
	rmt->free_ring = xfer->free_ring;

	req = &xfer->reqs[0];
	req->rmt_lvol = rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->status = XFER_REQ_STATUS_IN_FLIGHT;
	req->offset = 0;
	req->dst_offset = UT_DST_OFFSET;
	req->len = UT_CLUSTER_BLOCKS;

	g_ut_bdev_write_cnt = 0;
	g_ut_bdev_write_fail_at = 0;
	g_ut_bdev_write_rc = 0;

	*xferp = xfer;
	return req;
}

static void
fill_blocks(struct spdk_lvs_xfer_req *req, uint32_t first, uint32_t count)
{
	memset((uint8_t *)req->payload + (uint64_t)first * 4096, 0xA5, (uint64_t)count * 4096);
}

/* Check write i: blocks [start, start + n) of the cluster. */
static void
check_write(struct spdk_lvs_xfer_req *req, uint32_t i, uint64_t start, uint64_t n)
{
	SPDK_CU_ASSERT_FATAL(i < g_ut_bdev_write_cnt);
	CU_ASSERT(g_ut_bdev_writes[i].offset_blocks == UT_DST_OFFSET + start);
	CU_ASSERT(g_ut_bdev_writes[i].num_blocks == n);
	CU_ASSERT(g_ut_bdev_writes[i].buf == (uint8_t *)req->payload + start * 4096);
}

/* The whole cluster as 16 writes of 32 blocks, in order. */
static void
check_whole_cluster(struct spdk_lvs_xfer_req *req)
{
	CU_ASSERT(g_ut_bdev_write_cnt == UT_CLUSTER_BLOCKS / UT_MAX_WRITE_BLOCKS);
	CU_ASSERT(req->fragments_outstanding == UT_CLUSTER_BLOCKS / UT_MAX_WRITE_BLOCKS);
	for (uint32_t i = 0; i < UT_CLUSTER_BLOCKS / UT_MAX_WRITE_BLOCKS; i++) {
		check_write(req, i, (uint64_t)i * UT_MAX_WRITE_BLOCKS, UT_MAX_WRITE_BLOCKS);
	}
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

/* The read phase is one whole-cluster read: no fragments armed. */
static void
xfer_read_is_one_cluster_read(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	CU_ASSERT(req->fragments_outstanding == 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 0);

	free_xfer(xfer);
}

/* Preallocated, all zero: nothing is sent and the request is done at once. */
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

	free_xfer(xfer);
}

/* One range covering the whole cluster: the same writes as today. */
static void
xfer_replicate_full_cluster_is_one_range(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, UT_CLUSTER_BLOCKS);
	local_op_comp(req, 0);
	check_whole_cluster(req);

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);

	free_xfer(xfer);
}

/* Only the data ranges are written, each split at 32 blocks. */
static void
xfer_replicate_sends_only_data_ranges(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, 3);		/* 1 write */
	fill_blocks(req, 100, 1);	/* 1 write */
	fill_blocks(req, 200, 100);	/* 32 + 32 + 32 + 4 */
	fill_blocks(req, 511, 1);	/* last block: 1 write */
	local_op_comp(req, 0);

	CU_ASSERT(g_ut_bdev_write_cnt == 7);
	CU_ASSERT(req->fragments_outstanding == 7);
	check_write(req, 0, 0, 3);
	check_write(req, 1, 100, 1);
	check_write(req, 2, 200, 32);
	check_write(req, 3, 232, 32);
	check_write(req, 4, 264, 32);
	check_write(req, 5, 296, 4);
	check_write(req, 6, 511, 1);
	for (uint32_t i = 0; i < g_ut_bdev_write_cnt; i++) {
		CU_ASSERT(g_ut_bdev_writes[i].num_blocks <= UT_MAX_WRITE_BLOCKS);
	}

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(rmt.outstanding_io == 0);

	free_xfer(xfer);
}

/* More than 64 ranges (every other block): the whole cluster is sent. */
static void
xfer_replicate_too_many_ranges_sends_whole_cluster(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	for (uint32_t b = 0; b < UT_CLUSTER_BLOCKS; b += 2) {
		fill_blocks(req, b, 1);
	}
	local_op_comp(req, 0);
	check_whole_cluster(req);

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);

	free_xfer(xfer);
}

/* A submit failure after some writes: the request fails once the writes in
 * flight return. On the first write: it fails at once. */
static void
xfer_replicate_submit_failure_fails_the_request(void)
{
	struct spdk_lvs_xfer *xfer;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_req *req = make_cluster_req(&xfer, &rmt);

	fill_blocks(req, 0, UT_CLUSTER_BLOCKS);
	g_ut_bdev_write_fail_at = 3;
	g_ut_bdev_write_rc = -ENOMEM;
	local_op_comp(req, 0);
	CU_ASSERT(g_ut_bdev_write_cnt == 2);
	CU_ASSERT(req->fragments_outstanding == 2);
	CU_ASSERT(req->status == XFER_REQ_STATUS_IN_FLIGHT);

	complete_writes(req, true);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);
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

	fill_blocks(req, 0, 64);
	local_op_comp(req, 0);
	CU_ASSERT(req->fragments_outstanding == 2);

	fragment_write_cb(NULL, false, req);
	CU_ASSERT(req->status == XFER_REQ_STATUS_IN_FLIGHT);	/* one still out */
	fragment_write_cb(NULL, true, req);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);

	free_xfer(xfer);
}

/* A replication FINAL step, started from the beginning as the final-step RPC
 * starts it: the command-block page size, a snapshot name, and payloads sized
 * for either path's signal write. The clock runs at a real time, because a deadline
 * that was never set reads as 0 and only a clock past 0 exposes that. */
static struct spdk_lvs_xfer *
make_final_step_xfer(void)
{
	const int alloc[4] = {1, 1, 1, 1};
	struct spdk_lvs_xfer *xfer = make_xfer(4, 4, alloc);

	xfer->page_size = SPDK_LVOL_XFER_CMD_BLOCK_SIZE;
	/* The migration path's signal write clears eight pages. */
	xfer->page_per_cluster = 8;
	for (int i = 0; i < xfer->cluster_batch; i++) {
		free(xfer->reqs[i].payload);
		xfer->reqs[i].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
		SPDK_CU_ASSERT_FATAL(xfer->reqs[i].payload != NULL);
	}
	xfer->state = XFER_STATE_NONE;
	xfer->final_step = true;
	xfer->len = snprintf(xfer->snapshot_name, sizeof(xfer->snapshot_name), "LVS_1/LVOL_41");
	return xfer;
}

/* The deadline of a replication final step starts with the step. It was set
 * only on the migration path, so on this one it stayed 0, and the first
 * status check after the first tick failed the cutover at offset 0 with
 * "terminate timeout" -- every cross-cluster cutover, every attempt. */
static void
xfer_replicate_final_step_is_not_failed_by_an_unset_deadline(void)
{
	struct spdk_lvs_xfer *xfer;

	MOCK_SET(spdk_get_ticks, 1000ULL * spdk_get_ticks_hz());
	xfer = make_final_step_xfer();

	xfer_replication(xfer);	/* NONE: no used clusters, on to the signal */
	xfer_replication(xfer);	/* SIGNAL_TRANSFER: the signal is sent */

	CU_ASSERT(xfer->state != XFER_STATE_FAILED);
	CU_ASSERT(g_xfer_lvol.transfer_status != XFER_FAILED);
	CU_ASSERT(xfer->signal_sent);
	CU_ASSERT(drain_ready(xfer, NULL, 4) == 1);

	free_xfer(xfer);
	MOCK_CLEAR(spdk_get_ticks);
}

/* The deadline still ends a final step that makes no progress: one with no
 * completion SPDK_LVOL_TRANSFER_TERMINATE_TIMEOUT seconds in fails. */
static void
xfer_replicate_final_step_fails_past_its_deadline(void)
{
	struct spdk_lvs_xfer *xfer;
	uint64_t start = 1000ULL * spdk_get_ticks_hz();

	MOCK_SET(spdk_get_ticks, start);
	xfer = make_final_step_xfer();
	xfer_replication(xfer);
	xfer_replication(xfer);
	/* Fatal: polling a failed task again destroys it. */
	CU_ASSERT_FATAL(xfer->state != XFER_STATE_FAILED);

	MOCK_SET(spdk_get_ticks, start + (SPDK_LVOL_TRANSFER_TERMINATE_TIMEOUT + 1) * spdk_get_ticks_hz());
	xfer_replication(xfer);

	CU_ASSERT(xfer->state == XFER_STATE_FAILED);
	CU_ASSERT(g_xfer_lvol.transfer_status == XFER_FAILED);

	free_xfer(xfer);
	MOCK_CLEAR(spdk_get_ticks);
}

/* A migration final step with no used clusters goes straight to the signal,
 * and its deadline was set only after that early return: the same unset
 * deadline, on the empty-volume path. */
static void
xfer_migrate_final_step_without_clusters_is_not_failed_by_an_unset_deadline(void)
{
	struct spdk_lvs_xfer *xfer;

	MOCK_SET(spdk_get_ticks, 1000ULL * spdk_get_ticks_hz());
	xfer = make_final_step_xfer();
	xfer->type = XFER_MIGRATE_SNAPSHOT;

	xfer_migration(xfer);
	xfer_migration(xfer);

	CU_ASSERT(xfer->state != XFER_STATE_FAILED);
	CU_ASSERT(g_xfer_lvol.transfer_status != XFER_FAILED);
	CU_ASSERT(xfer->signal_sent);

	free_xfer(xfer);
	MOCK_CLEAR(spdk_get_ticks);
}

int
main(int argc, char **argv)
{
	CU_pSuite suite = NULL;
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
	CU_ADD_TEST(suite, xfer_read_is_one_cluster_read);
	CU_ADD_TEST(suite, xfer_replicate_zero_cluster_sends_nothing);
	CU_ADD_TEST(suite, xfer_replicate_full_cluster_is_one_range);
	CU_ADD_TEST(suite, xfer_replicate_sends_only_data_ranges);
	CU_ADD_TEST(suite, xfer_replicate_too_many_ranges_sends_whole_cluster);
	CU_ADD_TEST(suite, xfer_replicate_submit_failure_fails_the_request);
	CU_ADD_TEST(suite, xfer_replicate_write_failure_fails_the_request);
	CU_ADD_TEST(suite, xfer_replicate_final_step_is_not_failed_by_an_unset_deadline);
	CU_ADD_TEST(suite, xfer_replicate_final_step_fails_past_its_deadline);
	CU_ADD_TEST(suite, xfer_migrate_final_step_without_clusters_is_not_failed_by_an_unset_deadline);

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	free_threads();
	CU_cleanup_registry();
	return num_failures;
}
