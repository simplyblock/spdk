/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2019 Intel Corporation.
 *   All rights reserved.
 */

#ifndef SPDK_BDEV_INTERNAL_H
#define SPDK_BDEV_INTERNAL_H

#include "spdk/bdev.h"

#define ZERO_BUFFER_SIZE	0x100000

struct spdk_bdev;
struct spdk_bdev_io;
struct spdk_bdev_channel;

struct spdk_bdev_io *bdev_channel_get_io(struct spdk_bdev_channel *channel);

void bdev_io_init(struct spdk_bdev_io *bdev_io, struct spdk_bdev *bdev, void *cb_arg,
		  spdk_bdev_io_completion_cb cb);

void bdev_io_submit(struct spdk_bdev_io *bdev_io);

struct spdk_bdev_io_stat *bdev_alloc_io_stat(bool io_error_stat);
void bdev_free_io_stat(struct spdk_bdev_io_stat *stat);

enum spdk_bdev_reset_stat_mode;

typedef void (*bdev_reset_device_stat_cb)(struct spdk_bdev *bdev, void *cb_arg, int rc);

void bdev_reset_device_stat(struct spdk_bdev *bdev, enum spdk_bdev_reset_stat_mode mode,
			    bdev_reset_device_stat_cb cb, void *cb_arg);

/* bdev_io pool use, for sizing bdev_io_pool_size (RPC bdev_get_io_pool_stats). */
struct bdev_io_pool_stats {
	uint64_t pool_size;		/* bdev_io_pool_size */
	uint64_t pool_free;		/* in the global pool now */
	uint64_t thread_cache;		/* parked in the per-thread caches now */
	uint64_t outstanding;		/* handed out, not yet freed, all threads */
	uint64_t outstanding_max_sum;	/* sum of each thread's high-water mark */
	uint64_t outstanding_max_thread;	/* highest single-thread high-water mark */
	uint64_t get_nomem;		/* gets that found no bdev_io (caller waited) */
	uint32_t threads;
	uint32_t bdev_io_size;		/* bytes per bdev_io (incl. module context) */
};

typedef void (*bdev_io_pool_stats_cb)(const struct bdev_io_pool_stats *stats, void *cb_arg);

/* Gathers the stats from every thread; with reset_max the high-water marks
 * restart from the current outstanding counts. cb runs on the calling thread. */
void bdev_get_io_pool_stats(bool reset_max, bdev_io_pool_stats_cb cb, void *cb_arg);

#endif /* SPDK_BDEV_INTERNAL_H */
