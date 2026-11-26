/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "thread/thread_internal.h"
#include "bs_scheduler.c"


#define DEV_BUFFER_SIZE (64 * 1024 * 1024)
#define DEV_BUFFER_BLOCKLEN (4096)
#define DEV_BUFFER_BLOCKCNT (DEV_BUFFER_SIZE / DEV_BUFFER_BLOCKLEN)
#define DEV_MAX_PHYS_BLOCKLEN (16384)
#define FIRST_DATA_CLUSTER(bs) \
	((DEV_BUFFER_SIZE / spdk_bs_get_cluster_size(bs)) - spdk_bs_total_data_cluster_count(bs))

uint8_t *g_dev_buffer;
uint64_t g_dev_write_bytes;
uint64_t g_dev_read_bytes;
/* largest single read the device saw (reset by the tests that check it) */
uint64_t g_dev_max_read_bytes;
/* class of the last read the device saw, -1 when it carried no options */
int g_dev_last_read_priority = -1;
int g_dev_last_write_priority = -1;
uint64_t g_dev_copy_bytes;
bool g_dev_writev_ext_called;
bool g_dev_readv_ext_called;
bool g_dev_copy_enabled;
int g_dev_copy_fail;
/*
 * Injected write error: a write, writev, write_zeroes or copy whose
 * destination overlaps [g_dev_write_fail_lba, g_dev_write_fail_lba +
 * g_dev_write_fail_lba_count) writes nothing and completes with
 * g_dev_write_fail_rc (e.g. -ENOSPC, a full device). Off while the rc is 0.
 */
int g_dev_write_fail_rc;
uint64_t g_dev_write_fail_lba;
uint64_t g_dev_write_fail_lba_count;
uint64_t g_dev_write_fail_count;	/* writes failed this way */
uint64_t g_dev_copy_calls;	/* COPYs sent to the dev, declined ones included */
bool g_dev_copy_partial;	/* a declined COPY leaves junk in the destination */
struct spdk_blob_ext_io_opts g_blob_ext_io_opts;
uint32_t g_phys_blocklen;

struct spdk_power_failure_counters {
	uint64_t general_counter;
	uint64_t read_counter;
	uint64_t write_counter;
	uint64_t unmap_counter;
	uint64_t write_zero_counter;
	uint64_t flush_counter;
};

static struct spdk_power_failure_counters g_power_failure_counters = {};

struct spdk_power_failure_thresholds {
	uint64_t general_threshold;
	uint64_t read_threshold;
	uint64_t write_threshold;
	uint64_t unmap_threshold;
	uint64_t write_zero_threshold;
	uint64_t flush_threshold;
};

static struct spdk_power_failure_thresholds g_power_failure_thresholds = {};

static uint64_t g_power_failure_rc;

void dev_reset_power_failure_event(void);
void dev_reset_power_failure_counters(void);
void dev_set_power_failure_thresholds(struct spdk_power_failure_thresholds thresholds);

void
dev_reset_power_failure_event(void)
{
	memset(&g_power_failure_counters, 0, sizeof(g_power_failure_counters));
	memset(&g_power_failure_thresholds, 0, sizeof(g_power_failure_thresholds));
	g_power_failure_rc = 0;
}

void
dev_reset_power_failure_counters(void)
{
	memset(&g_power_failure_counters, 0, sizeof(g_power_failure_counters));
	g_power_failure_rc = 0;
}

/**
 * Set power failure event. Power failure will occur after given number
 * of IO operations. It may occur after number of particular operations
 * (read, write, unmap, write zero or flush) or after given number of
 * any IO operations (general_threshold). Value 0 means that the threshold
 * is disabled. Any other value is the number of operation starting from
 * which power failure event will happen.
 */
void
dev_set_power_failure_thresholds(struct spdk_power_failure_thresholds thresholds)
{
	g_power_failure_thresholds = thresholds;
}

/* Define here for UT only. */
struct spdk_io_channel g_io_channel;

static struct spdk_io_channel *
dev_create_channel(struct spdk_bs_dev *dev)
{
	return &g_io_channel;
}

static void
dev_destroy_channel(struct spdk_bs_dev *dev, struct spdk_io_channel *channel)
{
}

static void
dev_destroy(struct spdk_bs_dev *dev)
{
	free(dev);
}


static void
dev_complete_cb(void *arg)
{
	struct spdk_bs_dev_cb_args *cb_args = arg;

	cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, g_power_failure_rc);
}

static void
dev_complete(void *arg)
{
	_bs_send_msg(dev_complete_cb, arg, NULL);
}

struct dev_write_fail_ctx {
	struct spdk_bs_dev_cb_args *cb_args;
	int rc;
};

static void
dev_write_fail_complete(void *arg)
{
	struct dev_write_fail_ctx *ctx = arg;

	ctx->cb_args->cb_fn(ctx->cb_args->channel, ctx->cb_args->cb_arg, ctx->rc);
	free(ctx);
}

/* true: the write was failed by the injection (see g_dev_write_fail_rc) */
static bool
dev_write_inject_fail(uint64_t lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args)
{
	struct dev_write_fail_ctx *ctx;

	if (g_dev_write_fail_rc == 0 || lba + lba_count <= g_dev_write_fail_lba ||
	    lba >= g_dev_write_fail_lba + g_dev_write_fail_lba_count) {
		return false;
	}
	ctx = calloc(1, sizeof(*ctx));
	SPDK_CU_ASSERT_FATAL(ctx != NULL);
	ctx->cb_args = cb_args;
	ctx->rc = g_dev_write_fail_rc;
	g_dev_write_fail_count++;
	spdk_thread_send_msg(spdk_get_thread(), dev_write_fail_complete, ctx);
	return true;
}

static void
dev_read(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	 uint64_t lba, uint32_t lba_count,
	 struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;

	g_dev_last_read_priority = bs_io_opts ? bs_io_opts->priority : -1;

	if (g_power_failure_thresholds.read_threshold != 0) {
		g_power_failure_counters.read_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.read_threshold == 0 ||
	     g_power_failure_counters.read_counter < g_power_failure_thresholds.read_threshold) &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);

		if (length > 0) {
			memcpy(payload, &g_dev_buffer[offset], length);
			g_dev_read_bytes += length;
			g_dev_max_read_bytes = spdk_max(g_dev_max_read_bytes, length);
		}
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

/*
 * Write hold (test hook): the next g_dev_write_hold_count writes that overlap
 * [g_dev_write_hold_lba, g_dev_write_hold_lba + g_dev_write_hold_lba_count) are kept
 * in flight - nothing written, not completed - until ut_dev_release_held_writes(),
 * which writes their payload then and completes them. A later write to the same
 * blocks that is not held lands first: the held one lands last, as a device may
 * complete two writes in either order.
 */
uint64_t g_dev_write_hold_lba;
uint64_t g_dev_write_hold_lba_count;
uint32_t g_dev_write_hold_count;

struct dev_held_write {
	struct spdk_bs_dev		*dev;
	void				*payload;
	uint64_t			lba;
	uint32_t			lba_count;
	struct spdk_bs_dev_cb_args	*cb_args;
	TAILQ_ENTRY(dev_held_write)	link;
};
static TAILQ_HEAD(, dev_held_write) g_dev_held_writes = TAILQ_HEAD_INITIALIZER(g_dev_held_writes);

static bool
dev_write_hold(struct spdk_bs_dev *dev, void *payload, uint64_t lba, uint32_t lba_count,
	       struct spdk_bs_dev_cb_args *cb_args)
{
	struct dev_held_write *hw;

	if (g_dev_write_hold_count == 0 || lba + lba_count <= g_dev_write_hold_lba ||
	    lba >= g_dev_write_hold_lba + g_dev_write_hold_lba_count) {
		return false;
	}
	hw = calloc(1, sizeof(*hw));
	SPDK_CU_ASSERT_FATAL(hw != NULL);
	hw->dev = dev;
	hw->payload = payload;
	hw->lba = lba;
	hw->lba_count = lba_count;
	hw->cb_args = cb_args;
	TAILQ_INSERT_TAIL(&g_dev_held_writes, hw, link);
	g_dev_write_hold_count--;
	return true;
}

/* Writes and completes the held writes; returns how many there were. */
static int
ut_dev_release_held_writes(void)
{
	struct dev_held_write *hw;
	int n = 0;

	while ((hw = TAILQ_FIRST(&g_dev_held_writes)) != NULL) {
		TAILQ_REMOVE(&g_dev_held_writes, hw, link);
		memcpy(&g_dev_buffer[hw->lba * hw->dev->blocklen], hw->payload,
		       (uint64_t)hw->lba_count * hw->dev->blocklen);
		spdk_thread_send_msg(spdk_get_thread(), dev_complete, hw->cb_args);
		free(hw);
		n++;
	}
	return n;
}

static void
dev_write(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, void *payload,
	  uint64_t lba, uint32_t lba_count,
	  struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;

	g_dev_last_write_priority = bs_io_opts ? bs_io_opts->priority : -1;
	if (dev_write_inject_fail(lba, lba_count, cb_args)) {
		return;
	}
	if (dev_write_hold(dev, payload, lba, lba_count, cb_args)) {
		return;
	}
	if (g_power_failure_thresholds.write_threshold != 0) {
		g_power_failure_counters.write_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.write_threshold == 0 ||
	     g_power_failure_counters.write_counter < g_power_failure_thresholds.write_threshold) &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);

		memcpy(&g_dev_buffer[offset], payload, length);
		g_dev_write_bytes += length;
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static void
__check_iov(struct iovec *iov, int iovcnt, uint64_t length)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		length -= iov[i].iov_len;
	}

	CU_ASSERT(length == 0);
}

static void
dev_readv(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	  struct iovec *iov, int iovcnt,
	  uint64_t lba, uint32_t lba_count,
	  struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;
	int i;

	if (g_power_failure_thresholds.read_threshold != 0) {
		g_power_failure_counters.read_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.read_threshold == 0 ||
	     g_power_failure_counters.read_counter < g_power_failure_thresholds.read_threshold) &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);
		__check_iov(iov, iovcnt, length);
		g_dev_last_read_priority = bs_io_opts ? bs_io_opts->priority : -1;

		for (i = 0; i < iovcnt; i++) {
			memcpy(iov[i].iov_base, &g_dev_buffer[offset], iov[i].iov_len);
			offset += iov[i].iov_len;
		}

		g_dev_read_bytes += length;
		g_dev_max_read_bytes = spdk_max(g_dev_max_read_bytes, length);
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static void
dev_readv_ext(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	      struct iovec *iov, int iovcnt,
	      uint64_t lba, uint32_t lba_count,
	      struct spdk_bs_dev_cb_args *cb_args,
	      struct spdk_blob_ext_io_opts *io_opts, struct spdk_bs_io_opts *bs_io_opts)
{
	g_dev_readv_ext_called = true;
	g_blob_ext_io_opts = *io_opts;
	dev_readv(dev, channel, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts);
}

static void
dev_writev(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	   struct iovec *iov, int iovcnt,
	   uint64_t lba, uint32_t lba_count,
	   struct spdk_bs_dev_cb_args *cb_args,
	   struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;
	int i;

	if (dev_write_inject_fail(lba, lba_count, cb_args)) {
		return;
	}
	if (g_power_failure_thresholds.write_threshold != 0) {
		g_power_failure_counters.write_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.write_threshold == 0 ||
	     g_power_failure_counters.write_counter < g_power_failure_thresholds.write_threshold)  &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);
		__check_iov(iov, iovcnt, length);
		g_dev_last_write_priority = bs_io_opts ? bs_io_opts->priority : -1;

		for (i = 0; i < iovcnt; i++) {
			memcpy(&g_dev_buffer[offset], iov[i].iov_base, iov[i].iov_len);
			offset += iov[i].iov_len;
		}

		g_dev_write_bytes += length;
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static void
dev_writev_ext(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	       struct iovec *iov, int iovcnt,
	       uint64_t lba, uint32_t lba_count,
	       struct spdk_bs_dev_cb_args *cb_args,
	       struct spdk_blob_ext_io_opts *io_opts, struct spdk_bs_io_opts *bs_io_opts)
{
	g_dev_writev_ext_called = true;
	g_blob_ext_io_opts = *io_opts;
	dev_writev(dev, channel, iov, iovcnt, lba, lba_count, cb_args, bs_io_opts);
}

static void
dev_flush(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	  struct spdk_bs_dev_cb_args *cb_args)
{
	if (g_power_failure_thresholds.flush_threshold != 0) {
		g_power_failure_counters.flush_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.flush_threshold != 0 &&
	     g_power_failure_counters.flush_counter >= g_power_failure_thresholds.flush_threshold)  ||
	    (g_power_failure_thresholds.general_threshold != 0 &&
	     g_power_failure_counters.general_counter >= g_power_failure_thresholds.general_threshold)) {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static void
dev_unmap(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
	  uint64_t lba, uint64_t lba_count,
	  struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;

	if (g_power_failure_thresholds.unmap_threshold != 0) {
		g_power_failure_counters.unmap_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.unmap_threshold == 0 ||
	     g_power_failure_counters.unmap_counter < g_power_failure_thresholds.unmap_threshold)  &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);
		memset(&g_dev_buffer[offset], 0, length);
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static void
dev_write_zeroes(struct spdk_bs_dev *dev, struct spdk_io_channel *channel,
		 uint64_t lba, uint64_t lba_count,
		 struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	uint64_t offset, length;

	g_dev_last_write_priority = bs_io_opts ? bs_io_opts->priority : -1;
	if (dev_write_inject_fail(lba, lba_count, cb_args)) {
		return;
	}
	if (g_power_failure_thresholds.write_zero_threshold != 0) {
		g_power_failure_counters.write_zero_counter++;
	}

	if (g_power_failure_thresholds.general_threshold != 0) {
		g_power_failure_counters.general_counter++;
	}

	if ((g_power_failure_thresholds.write_zero_threshold == 0 ||
	     g_power_failure_counters.write_zero_counter < g_power_failure_thresholds.write_zero_threshold)  &&
	    (g_power_failure_thresholds.general_threshold == 0 ||
	     g_power_failure_counters.general_counter < g_power_failure_thresholds.general_threshold)) {
		offset = lba * dev->blocklen;
		length = lba_count * dev->blocklen;
		SPDK_CU_ASSERT_FATAL(offset + length <= DEV_BUFFER_SIZE);
		memset(&g_dev_buffer[offset], 0, length);
		g_dev_write_bytes += length;
	} else {
		g_power_failure_rc = -EIO;
	}

	spdk_thread_send_msg(spdk_get_thread(), dev_complete, cb_args);
}

static bool
dev_translate_lba(struct spdk_bs_dev *dev, uint64_t lba, uint64_t *base_lba)
{
	*base_lba = lba;
	return true;
}

static void
dev_copy(struct spdk_bs_dev *dev, struct spdk_io_channel *channel, uint64_t dst_lba,
	 uint64_t src_lba, uint64_t lba_count, struct spdk_bs_dev_cb_args *cb_args, struct spdk_bs_io_opts *bs_io_opts)
{
	void *dst = &g_dev_buffer[dst_lba * dev->blocklen];
	const void *src = &g_dev_buffer[src_lba * dev->blocklen];
	uint64_t size = lba_count * dev->blocklen;

	if (dev_write_inject_fail(dst_lba, lba_count, cb_args)) {
		return;
	}
	g_dev_copy_calls++;
	if (g_dev_copy_fail != 0) {
		if (g_dev_copy_partial) {
			/* Part of the copy was done (or the destination was touched)
			 * before it failed: the destination holds neither zeroes nor
			 * the source. */
			memset(dst, 0xFF, size);
		}
		/* The base bdev declines the copy (e.g. a distrib page copy at max. chain depth). */
		cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, g_dev_copy_fail);
		return;
	}
	memcpy(dst, src, size);
	g_dev_copy_bytes += size;

	cb_args->cb_fn(cb_args->channel, cb_args->cb_arg, 0);
}

static struct spdk_bs_dev *
init_dev(void)
{
	struct spdk_bs_dev *dev = calloc(1, sizeof(*dev));

	SPDK_CU_ASSERT_FATAL(dev != NULL);

	dev->create_channel = dev_create_channel;
	dev->destroy_channel = dev_destroy_channel;
	dev->destroy = dev_destroy;
	dev->read = dev_read;
	dev->write = dev_write;
	dev->readv = dev_readv;
	dev->writev = dev_writev;
	dev->readv_ext = dev_readv_ext;
	dev->writev_ext = dev_writev_ext;
	dev->flush = dev_flush;
	dev->unmap = dev_unmap;
	dev->write_zeroes = dev_write_zeroes;
	dev->translate_lba = dev_translate_lba;
	dev->copy = g_dev_copy_enabled ? dev_copy : NULL;
	dev->blockcnt = DEV_BUFFER_BLOCKCNT;
	dev->blocklen = DEV_BUFFER_BLOCKLEN;
	// dev->phys_blocklen = g_phys_blocklen;

	return dev;
}
