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

/* The transfer path calls into the dirty-bitmap module and the fork's
 * blobstore freeze probe. blob_dirty.c is self-contained -- link the real
 * code; the freeze probe is stubbed (no in-flight IO in these tests). */
#include "blob/blob_dirty.c"
int blob_check_io_inflaight(struct spdk_blob *blob);
int
blob_check_io_inflaight(struct spdk_blob *blob)
{
	(void)blob;
	return 0;
}

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

	/* the pause keeps the stall clock fresh */
	uint64_t t = xfer->timeout;
	CU_ASSERT(t != 0);

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
	CU_ASSERT(drain_ready(x_bg, NULL, 4) == 4);    /* still queued */

	/* priority window over: background is served again */
	__atomic_store_n(&g_priority_xfer_cnt, 0, __ATOMIC_SEQ_CST);
	CU_ASSERT(xfer_replication(x_bg) == 0);        /* free ring is empty now */
	struct spdk_lvs_xfer_req *req;
	while (spdk_ring_dequeue(x_bg->free_ring, (void **)&req, 1) == 1) {
		req->status = XFER_REQ_STATUS_READY;
		CU_ASSERT(spdk_ring_enqueue(x_bg->ready_ring, (void **)&req, 1, NULL) == 1);
	}
	helper_xfer_poller(&lpg);
	CU_ASSERT(rmt_bg.outstanding_io > 0);

	free_xfer(x_bg);
	free_xfer(x_pr);
}

/* Special (geometry) IO cannot be split below the blob cluster: with
 * special_io set, the write phase must be ONE cluster-sized write, not
 * 64 KiB fragments. The read phase (never special) stays fragmented. */
static void
xfer_special_io_writes_whole_cluster(void)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;
	struct remote_lvol_info rmt;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = 512;
	xfer->special_io = true;
	free(xfer->reqs[0].payload);
	xfer->reqs[0].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
	SPDK_CU_ASSERT_FATAL(xfer->reqs[0].payload != NULL);

	memset(&rmt, 0, sizeof(rmt));
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	static struct spdk_bdev fake_bdev2;
	static struct spdk_bdev_desc fake_desc2;
	fake_bdev2.blocklen = 4096;
	fake_desc2.bdev = &fake_bdev2;
	rmt.desc = &fake_desc2;
	rmt.channel = (struct spdk_io_channel *)0x1;

	req = &xfer->reqs[0];
	req->rmt_lvol = &rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->offset = 0;
	req->len = xfer->page_per_cluster;

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	CU_ASSERT(req->fragments_outstanding == 32);   /* reads stay fragmented */

	for (int i = 0; i < 32; i++) {
		fragment_read_cb(req, 0);
	}
	/* ONE whole-cluster write via complete_op_cb -- no write fragments armed */
	CU_ASSERT(req->fragments_outstanding == 0);
	CU_ASSERT(req->status != XFER_REQ_STATUS_FAILED);

	free_xfer(xfer);
}


/* The pipelined path must issue a fragment's hub WRITE the moment ITS read
 * completes -- while other reads are still outstanding. That overlap is the
 * whole point: the request costs ~max(read phase, write phase), not their
 * sum. (Requests without a frag_ctx keep the barrier path -- covered by
 * xfer_read_phase_is_fragmented below.) */
static void
xfer_pipeline_overlaps_read_and_write(void)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_frag *frags;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = 512;
	free(xfer->reqs[0].payload);
	xfer->reqs[0].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
	SPDK_CU_ASSERT_FATAL(xfer->reqs[0].payload != NULL);
	frags = calloc(32, sizeof(*frags));
	SPDK_CU_ASSERT_FATAL(frags != NULL);

	memset(&rmt, 0, sizeof(rmt));
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	static struct spdk_bdev fake_bdev3;
	static struct spdk_bdev_desc fake_desc3;
	fake_bdev3.blocklen = 4096;
	fake_desc3.bdev = &fake_bdev3;
	rmt.desc = &fake_desc3;
	rmt.channel = (struct spdk_io_channel *)0x1;
	rmt.outstanding_io = 1;
	rmt.free_ring = xfer->free_ring;

	req = &xfer->reqs[0];
	req->rmt_lvol = &rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->offset = 0;
	req->dst_offset = 0;
	req->len = xfer->page_per_cluster;
	req->frag_ctx = frags;

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	CU_ASSERT(req->reads_outstanding == 32);
	CU_ASSERT(req->writes_outstanding == 0);

	/* first read completes -> ITS write goes out with 31 reads in flight */
	pipelined_read_cb(&req->frag_ctx[0], 0);
	CU_ASSERT(req->reads_outstanding == 31);
	CU_ASSERT(req->writes_outstanding == 1);

	for (int k = 1; k < 32; k++) {
		pipelined_read_cb(&req->frag_ctx[k], 0);
	}
	CU_ASSERT(req->reads_outstanding == 0);
	CU_ASSERT(req->writes_outstanding == 32);
	CU_ASSERT(req->status != XFER_REQ_STATUS_DONE);

	for (int k = 0; k < 32; k++) {
		pipelined_write_cb(NULL, true, &req->frag_ctx[k]);
	}
	CU_ASSERT(req->status == XFER_REQ_STATUS_DONE);
	CU_ASSERT(rmt.outstanding_io == 0);            /* recycled to free ring */

	free(frags);
	free_xfer(xfer);
}

/* A failed read must not send its fragment; the request finalizes FAILED
 * only after everything in flight has drained. */
static void
xfer_pipeline_read_failure_skips_the_write(void)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;
	struct remote_lvol_info rmt;
	struct spdk_lvs_xfer_frag *frags;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = 512;
	free(xfer->reqs[0].payload);
	xfer->reqs[0].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
	SPDK_CU_ASSERT_FATAL(xfer->reqs[0].payload != NULL);
	frags = calloc(32, sizeof(*frags));
	SPDK_CU_ASSERT_FATAL(frags != NULL);

	memset(&rmt, 0, sizeof(rmt));
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	static struct spdk_bdev fake_bdev4;
	static struct spdk_bdev_desc fake_desc4;
	fake_bdev4.blocklen = 4096;
	fake_desc4.bdev = &fake_bdev4;
	rmt.desc = &fake_desc4;
	rmt.channel = (struct spdk_io_channel *)0x1;
	rmt.outstanding_io = 1;
	rmt.free_ring = xfer->free_ring;

	req = &xfer->reqs[0];
	req->rmt_lvol = &rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->len = xfer->page_per_cluster;
	req->frag_ctx = frags;

	CU_ASSERT(submit_rw_reqs_local(req) == 0);

	pipelined_read_cb(&req->frag_ctx[0], -EIO);    /* first read fails */
	CU_ASSERT(req->writes_outstanding == 0);       /* no write for it */

	/* later reads complete fine but the request is already poisoned --
	 * no further writes go out either */
	for (int k = 1; k < 32; k++) {
		pipelined_read_cb(&req->frag_ctx[k], 0);
	}
	CU_ASSERT(req->writes_outstanding == 0);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);
	CU_ASSERT(rmt.outstanding_io == 0);

	free(frags);
	free_xfer(xfer);
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

/* The read phase must be fragmented and parallel, like the write phase: one
 * monolithic cluster-sized spdk_blob_io_read serialized every cluster's read,
 * adding its full latency to each cluster even with a full dispatch window. */
static void
xfer_read_phase_is_fragmented(void)
{
	const int alloc[2] = {1, 1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;
	struct remote_lvol_info rmt;

	xfer = make_xfer(2, 2, alloc);
	/* real-world geometry: 4K pages, 512 pages per 2 MiB cluster */
	xfer->page_size = 4096;
	xfer->page_per_cluster = 512;
	for (int i = 0; i < 2; i++) {
		free(xfer->reqs[i].payload);
		xfer->reqs[i].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
		SPDK_CU_ASSERT_FATAL(xfer->reqs[i].payload != NULL);
	}

	memset(&rmt, 0, sizeof(rmt));
	rmt.status = true;
	rmt.type = XFER_REPLICATE_SNAPSHOT;
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	/* the ut "stubs" dereference desc->bdev->blocklen: give them real fakes */
	static struct spdk_bdev fake_bdev;
	static struct spdk_bdev_desc fake_desc;
	fake_bdev.blocklen = 4096;
	fake_desc.bdev = &fake_bdev;
	rmt.desc = &fake_desc;
	rmt.channel = (struct spdk_io_channel *)0x1;

	req = &xfer->reqs[0];
	req->rmt_lvol = &rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->offset = 0;
	req->len = xfer->page_per_cluster;

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	/* 2 MiB at 64 KiB fragments = 32 parallel reads in flight */
	CU_ASSERT(req->fragments_outstanding == 32);

	/* completing every read fragment must hand the payload to the write
	 * phase (submit_rw_reqs_remote -> submit_req_fragments arms the write
	 * fragment counter) */
	for (int i = 0; i < 32; i++) {
		fragment_read_cb(req, 0);
	}
	/* 512 blocks at 64 KiB fragments (16 x 4096B blocks) = 32 write frags */
	CU_ASSERT(req->fragments_outstanding == 32);
	CU_ASSERT(req->status != XFER_REQ_STATUS_FAILED);

	free_xfer(xfer);
}

static void
xfer_read_fragment_failure_fails_the_request(void)
{
	const int alloc[1] = {1};
	struct spdk_lvs_xfer *xfer;
	struct spdk_lvs_xfer_req *req;
	struct remote_lvol_info rmt;

	xfer = make_xfer(1, 1, alloc);
	xfer->page_size = 4096;
	xfer->page_per_cluster = 512;
	free(xfer->reqs[0].payload);
	xfer->reqs[0].payload = calloc(1, xfer->page_size * xfer->page_per_cluster);
	SPDK_CU_ASSERT_FATAL(xfer->reqs[0].payload != NULL);

	memset(&rmt, 0, sizeof(rmt));
	rmt.md_channel = (struct spdk_io_channel *)0x1;
	/* the failure path recycles the request the way the helper set it up:
	 * one in-flight against this remote, free ring aliased to the task's */
	rmt.outstanding_io = 1;
	rmt.free_ring = xfer->free_ring;

	req = &xfer->reqs[0];
	req->rmt_lvol = &rmt;
	req->action = REQ_ACTION_COPY_BACKUP;
	req->offset = 0;
	req->len = xfer->page_per_cluster;

	CU_ASSERT(submit_rw_reqs_local(req) == 0);
	CU_ASSERT(req->fragments_outstanding == 32);

	/* one bad fragment poisons the request, but only once ALL fragments
	 * returned -- the buffer must not be handed onward half-filled */
	fragment_read_cb(req, -5);
	for (int i = 0; i < 30; i++) {
		fragment_read_cb(req, 0);
	}
	CU_ASSERT(req->status != XFER_REQ_STATUS_FAILED);   /* one still out */
	fragment_read_cb(req, 0);
	CU_ASSERT(req->status == XFER_REQ_STATUS_FAILED);

	free_xfer(xfer);
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
	CU_ADD_TEST(suite, xfer_special_io_writes_whole_cluster);
	CU_ADD_TEST(suite, xfer_pipeline_overlaps_read_and_write);
	CU_ADD_TEST(suite, xfer_pipeline_read_failure_skips_the_write);
	CU_ADD_TEST(suite, xfer_stops_at_last_cluster);
	CU_ADD_TEST(suite, xfer_skips_unallocated_clusters);
	CU_ADD_TEST(suite, xfer_second_pass_continues_and_completes);
	CU_ADD_TEST(suite, helper_drains_ready_ring);
	CU_ADD_TEST(suite, xfer_read_phase_is_fragmented);
	CU_ADD_TEST(suite, xfer_read_fragment_failure_fails_the_request);

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	free_threads();
	CU_cleanup_registry();
	return num_failures;
}
