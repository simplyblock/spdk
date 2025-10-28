/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "blobstore.h"
#include "request.h"

#include "spdk/thread.h"
#include "spdk/queue.h"

#include "spdk/log.h"

static void
check_geometry(struct spdk_blob_store *bs, uint8_t geometry, uint64_t lba)
{
	uint64_t num_md_lba;
	num_md_lba = bs_page_to_lba(bs, bs->md_start + bs->md_len);

	if (num_md_lba < lba && geometry == 0) {
		SPDK_ERRLOG("1- Invalid geometry %u, exceeds metadata size %lu, lba %lu\n",
			    geometry, num_md_lba, lba);
	}

	if (num_md_lba > lba && geometry != 0) {
		SPDK_ERRLOG("2- Invalid geometry %u, metadata size %lu, lba %lu\n",
			    geometry, num_md_lba, lba);
	}
	return;
}

void
bs_call_cpl(struct spdk_bs_cpl *cpl, int bserrno)
{
	switch (cpl->type) {
	case SPDK_BS_CPL_TYPE_BS_BASIC:
		cpl->u.bs_basic.cb_fn(cpl->u.bs_basic.cb_arg,
				      bserrno);
		break;
	case SPDK_BS_CPL_TYPE_BS_HANDLE:
		cpl->u.bs_handle.cb_fn(cpl->u.bs_handle.cb_arg,
				       bserrno == 0 ? cpl->u.bs_handle.bs : NULL,
				       bserrno);
		break;
	case SPDK_BS_CPL_TYPE_BLOB_BASIC:
		cpl->u.blob_basic.cb_fn(cpl->u.blob_basic.cb_arg,
					bserrno);
		break;
	case SPDK_BS_CPL_TYPE_BLOBID:
		cpl->u.blobid.cb_fn(cpl->u.blobid.cb_arg,
				    bserrno == 0 ? cpl->u.blobid.blobid : SPDK_BLOBID_INVALID,
				    bserrno);
		break;
	case SPDK_BS_CPL_TYPE_BLOB_HANDLE:
		cpl->u.blob_handle.cb_fn(cpl->u.blob_handle.cb_arg,
					 bserrno == 0 ? cpl->u.blob_handle.blob : NULL,
					 bserrno);
		break;
	case SPDK_BS_CPL_TYPE_NESTED_SEQUENCE:
		cpl->u.nested_seq.cb_fn(cpl->u.nested_seq.cb_arg,
					cpl->u.nested_seq.parent,
					bserrno);
		break;
	case SPDK_BS_CPL_TYPE_NONE:
		/* this completion's callback is handled elsewhere */
		break;
	}
}

static void
bs_request_set_complete(struct spdk_bs_request_set *set)
{
	struct spdk_bs_cpl cpl = set->cpl;
	int bserrno = set->bserrno;

	TAILQ_INSERT_TAIL(&set->channel->reqs, set, link);

	bs_call_cpl(&cpl, bserrno);
}

static void
bs_sequence_completion(struct spdk_io_channel *channel, void *cb_arg, int bserrno)
{
	struct spdk_bs_request_set *set = cb_arg;

	set->bserrno = bserrno;
	set->u.sequence.cb_fn((spdk_bs_sequence_t *)set, set->u.sequence.cb_arg, bserrno);
}

static inline spdk_bs_sequence_t *
bs_sequence_start(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl,
		  struct spdk_io_channel *back_channel)
{
	struct spdk_bs_channel		*channel;
	struct spdk_bs_request_set	*set;

	channel = spdk_io_channel_get_ctx(_channel);
	assert(channel != NULL);
	set = TAILQ_FIRST(&channel->reqs);
	if (!set) {
		return NULL;
	}
	TAILQ_REMOVE(&channel->reqs, set, link);

	set->cpl = *cpl;
	set->bserrno = 0;
	set->channel = channel;
	set->back_channel = back_channel;

	set->priority_class = channel->bs->priority_class;
	set->geometry = 0; // default geometry
	set->special_io = 0; //default special io
	set->cb_args.cb_fn = bs_sequence_completion;
	set->cb_args.cb_arg = set;
	set->cb_args.channel = channel->dev_channel;
	set->ext_io_opts = NULL;

	return (spdk_bs_sequence_t *)set;
}

/* Use when performing IO directly on the blobstore (e.g. metadata - not a blob). */
spdk_bs_sequence_t *
bs_sequence_start_bs(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl)
{
	return bs_sequence_start(_channel, cpl, _channel);
}

/* Use when performing IO on a blob. */
spdk_bs_sequence_t *
bs_sequence_start_blob(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl,
		       struct spdk_blob *blob)
{
	struct spdk_io_channel	*esnap_ch = _channel;

	if (spdk_blob_is_esnap_clone(blob)) {
		esnap_ch = blob_esnap_get_io_channel(_channel, blob);
		if (esnap_ch == NULL) {
			/*
			 * The most likely reason we are here is because of some logic error
			 * elsewhere that caused channel allocations to fail. We could get here due
			 * to being out of memory as well. If we are out of memory, the process is
			 * this will be just one of many problems that this process will be having.
			 * Killing it off debug builds now due to logic errors is the right thing to
			 * do and killing it off due to ENOMEM is no big loss.
			 */
			assert(false);
			return NULL;
		}
	}
	spdk_bs_sequence_t *seq = bs_sequence_start(_channel, cpl, esnap_ch);
	if (seq) {
		seq->priority_class = blob->priority_class; // set here if blobstore priority is different from this specific blob's priority
		seq->geometry = blob->geometry;
	}
	return seq;
}

spdk_bs_sequence_t *
bs_sequence_start_blob_s(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl,
		       uint8_t special_io, struct spdk_blob *blob)
{
	struct spdk_io_channel	*esnap_ch = _channel;

	if (spdk_blob_is_esnap_clone(blob)) {
		esnap_ch = blob_esnap_get_io_channel(_channel, blob);
		if (esnap_ch == NULL) {
			/*
			 * The most likely reason we are here is because of some logic error
			 * elsewhere that caused channel allocations to fail. We could get here due
			 * to being out of memory as well. If we are out of memory, the process is
			 * this will be just one of many problems that this process will be having.
			 * Killing it off debug builds now due to logic errors is the right thing to
			 * do and killing it off due to ENOMEM is no big loss.
			 */
			assert(false);
			return NULL;
		}
	}
	spdk_bs_sequence_t *seq = bs_sequence_start(_channel, cpl, esnap_ch);
	if (seq) {
		seq->priority_class = blob->priority_class; // set here if blobstore priority is different from this specific blob's priority
		seq->geometry = blob->geometry;
		seq->special_io = special_io;
	}
	return seq;
}

void
bs_sequence_read_bs_dev(spdk_bs_sequence_t *seq, struct spdk_bs_dev *bs_dev,
			void *payload, uint64_t lba, uint32_t lba_count,
			spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)seq;
	struct spdk_io_channel		*back_channel = set->back_channel;
	struct spdk_bs_io_opts bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	bs_dev->read(bs_dev, back_channel, payload, lba, lba_count, &set->cb_args, &bs_io_opts);
}

void
bs_sequence_read_dev(spdk_bs_sequence_t *seq, void *payload,
		     uint64_t lba, uint32_t lba_count,
		     spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel       *channel = set->channel;
	struct spdk_bs_io_opts		bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	channel->dev->read(channel->dev, channel->dev_channel, payload, lba, lba_count, &set->cb_args, &bs_io_opts);
}

void
bs_sequence_write_dev(spdk_bs_sequence_t *seq, void *payload,
		      uint64_t lba, uint32_t lba_count,
		      spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel       *channel = set->channel;
	struct spdk_bs_io_opts 			bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Writing %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;

	check_geometry(set->bs, bs_io_opts.geometry, lba);
	channel->dev->write(channel->dev, channel->dev_channel, payload, lba, lba_count,
			    &set->cb_args, &bs_io_opts);
}

void
bs_sequence_readv_bs_dev(spdk_bs_sequence_t *seq, struct spdk_bs_dev *bs_dev,
			 struct iovec *iov, int iovcnt, uint64_t lba, uint32_t lba_count,
			 spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_io_channel		*back_channel = set->back_channel;
	struct spdk_bs_io_opts			bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;

	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	// check_geometry(set->bs, bs_io_opts.geometry, lba);
	if (set->ext_io_opts) {
		assert(bs_dev->readv_ext);
		bs_dev->readv_ext(bs_dev, back_channel, iov, iovcnt, lba, lba_count,
				  &set->cb_args, set->ext_io_opts, &bs_io_opts);
	} else {
		bs_dev->readv(bs_dev, back_channel, iov, iovcnt, lba, lba_count, &set->cb_args, &bs_io_opts);
	}
}

void
bs_sequence_readv_dev(spdk_bs_sequence_t *seq, struct iovec *iov, int iovcnt,
		      uint64_t lba, uint32_t lba_count, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel       *channel = set->channel;
	struct spdk_bs_io_opts   		bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	if (set->ext_io_opts) {
		assert(channel->dev->readv_ext);
		channel->dev->readv_ext(channel->dev, channel->dev_channel, iov, iovcnt, lba, lba_count,
					&set->cb_args, set->ext_io_opts, &bs_io_opts);
	} else {
		channel->dev->readv(channel->dev, channel->dev_channel, iov, iovcnt, lba, lba_count, &set->cb_args, &bs_io_opts);
	}
}

void
bs_sequence_writev_dev(spdk_bs_sequence_t *seq, struct iovec *iov, int iovcnt,
		       uint64_t lba, uint32_t lba_count,
		       spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel       *channel = set->channel;
	struct spdk_bs_io_opts			bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Writing %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	bs_io_opts.special_io = set->special_io;
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	if (set->ext_io_opts) {
		assert(channel->dev->writev_ext);
		channel->dev->writev_ext(channel->dev, channel->dev_channel, iov, iovcnt, lba, lba_count,
					 &set->cb_args, set->ext_io_opts, &bs_io_opts);
	} else {
		channel->dev->writev(channel->dev, channel->dev_channel, iov, iovcnt, lba, lba_count,
				     &set->cb_args, &bs_io_opts);
	}
}

void
bs_sequence_write_zeroes_dev(spdk_bs_sequence_t *seq,
			     uint64_t lba, uint64_t lba_count,
			     spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set      *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel       	*channel = set->channel;
	struct spdk_bs_io_opts 		  	bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "writing zeroes to %" PRIu64 " blocks at LBA %" PRIu64 "\n",
		      lba_count, lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	channel->dev->write_zeroes(channel->dev, channel->dev_channel, lba, lba_count,
				   &set->cb_args, &bs_io_opts);
}

void
bs_sequence_copy_dev(spdk_bs_sequence_t *seq, uint64_t dst_lba, uint64_t src_lba,
		     uint64_t lba_count, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set *set = (struct spdk_bs_request_set *)seq;
	struct spdk_bs_channel     *channel = set->channel;
	struct spdk_bs_io_opts 		bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Copying %" PRIu64 " blocks from LBA %" PRIu64 " to LBA %" PRIu64 "\n",
		      lba_count, src_lba, dst_lba);

	set->u.sequence.cb_fn = cb_fn;
	set->u.sequence.cb_arg = cb_arg;
	bs_io_opts.priority = set->priority_class;
	bs_io_opts.geometry = set->geometry;
 	check_geometry(set->bs, bs_io_opts.geometry, src_lba);
	channel->dev->copy(channel->dev, channel->dev_channel, dst_lba, src_lba, lba_count, &set->cb_args, &bs_io_opts);
}

void
bs_sequence_finish(spdk_bs_sequence_t *seq, int bserrno)
{
	if (bserrno != 0) {
		seq->bserrno = bserrno;
	}
	bs_request_set_complete((struct spdk_bs_request_set *)seq);
}

void
bs_user_op_sequence_finish(void *cb_arg, int bserrno)
{
	spdk_bs_sequence_t *seq = cb_arg;

	bs_sequence_finish(seq, bserrno);
}

static void
bs_batch_completion(struct spdk_io_channel *_channel,
		    void *cb_arg, int bserrno)
{
	struct spdk_bs_request_set	*set = cb_arg;	
	struct spdk_bs_channel		*channel = set->channel;
	struct spdk_bs_io_opts		bs_io_opts = {0};
	struct limit *ctx;
	set->u.batch.outstanding_ops--;
	if (bserrno != 0) {
		set->bserrno = bserrno;
	}

	if (set->u.batch.is_unmap) {
		if (!TAILQ_EMPTY(&set->u.batch.unmap_queue)) {
			ctx = TAILQ_FIRST(&set->u.batch.unmap_queue);
			assert(ctx != NULL);
			TAILQ_REMOVE(&set->u.batch.unmap_queue, ctx, entries); // Remove it from the queue.
			bs_io_opts.priority = set->priority_class;

			if (set->u.batch.geometry != 0) {
				bs_io_opts.geometry = set->u.batch.geometry;
			} else {
				bs_io_opts.geometry = set->geometry;
			}

			bs_io_opts.special_io = set->u.batch.special_io;

			check_geometry(set->bs, bs_io_opts.geometry, ctx->lba);
			if (spdk_likely(channel->bs->is_leader)) {
				channel->dev->unmap(channel->dev, channel->dev_channel, ctx->lba, ctx->lba_count,
						&set->cb_args, &bs_io_opts);
			} else {
				SPDK_NOTICELOG("The unmap IO return with EIO error due to leader.\n");
				bs_batch_completion(_channel, set->cb_args.cb_arg, -EIO);
			}
			free(ctx);
		}
	}	

	if (set->u.batch.outstanding_ops == 0 && set->u.batch.batch_closed) {
		if (set->u.batch.cb_fn) {
			set->cb_args.cb_fn = bs_sequence_completion;
			set->u.batch.cb_fn((spdk_bs_sequence_t *)set, set->u.batch.cb_arg, bserrno);
		} else {
			bs_request_set_complete(set);
		}
	}
}

spdk_bs_batch_t *
bs_batch_open(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl, struct spdk_blob *blob)
{
	struct spdk_bs_channel		*channel;
	struct spdk_bs_request_set	*set;
	struct spdk_io_channel		*back_channel = _channel;

	if (spdk_blob_is_esnap_clone(blob)) {
		back_channel = blob_esnap_get_io_channel(_channel, blob);
		if (back_channel == NULL) {
			return NULL;
		}
	}

	channel = spdk_io_channel_get_ctx(_channel);
	assert(channel != NULL);
	set = TAILQ_FIRST(&channel->reqs);
	if (!set) {
		return NULL;
	}
	TAILQ_REMOVE(&channel->reqs, set, link);

	set->cpl = *cpl;
	set->bserrno = 0;
	set->channel = channel;
	set->back_channel = back_channel;

	set->u.batch.cb_fn = NULL;
	set->u.batch.cb_arg = NULL;
	set->u.batch.outstanding_ops = 0;
	set->u.batch.batch_closed = 0;
	set->u.batch.geometry = blob->geometry;
	set->u.batch.special_io = 0; // default special io

	set->priority_class = blob->priority_class;
	set->geometry = blob->geometry;
	set->cb_args.cb_fn = bs_batch_completion;
	set->cb_args.cb_arg = set;
	set->cb_args.channel = channel->dev_channel;

	return (spdk_bs_batch_t *)set;
}

spdk_bs_batch_t *
bs_batch_open_s(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl, uint8_t special_io, struct spdk_blob *blob)
{
	struct spdk_bs_channel		*channel;
	struct spdk_bs_request_set	*set;
	struct spdk_io_channel		*back_channel = _channel;

	if (spdk_blob_is_esnap_clone(blob)) {
		back_channel = blob_esnap_get_io_channel(_channel, blob);
		if (back_channel == NULL) {
			return NULL;
		}
	}

	channel = spdk_io_channel_get_ctx(_channel);
	assert(channel != NULL);
	set = TAILQ_FIRST(&channel->reqs);
	if (!set) {
		return NULL;
	}
	TAILQ_REMOVE(&channel->reqs, set, link);

	set->cpl = *cpl;
	set->bserrno = 0;
	set->channel = channel;
	set->back_channel = back_channel;

	set->u.batch.cb_fn = NULL;
	set->u.batch.cb_arg = NULL;
	set->u.batch.outstanding_ops = 0;
	set->u.batch.batch_closed = 0;
	set->u.batch.geometry = blob->geometry;
	set->u.batch.special_io = special_io;

	set->priority_class = blob->priority_class;
	set->geometry = blob->geometry;
	set->special_io = 0;
	set->cb_args.cb_fn = bs_batch_completion;
	set->cb_args.cb_arg = set;
	set->cb_args.channel = channel->dev_channel;

	return (spdk_bs_batch_t *)set;
}

void
bs_batch_read_bs_dev(spdk_bs_batch_t *batch, struct spdk_bs_dev *bs_dev,
		     void *payload, uint64_t lba, uint32_t lba_count)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;
	struct spdk_io_channel		*back_channel = set->back_channel;
	struct spdk_bs_io_opts bs_io_opts = {0};
	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.batch.outstanding_ops++;
	bs_io_opts.priority = set->priority_class;
	if (set->u.batch.geometry != 0) {
		bs_io_opts.geometry = set->u.batch.geometry;
	} else {
		bs_io_opts.geometry = batch->geometry;
	}
	check_geometry(set->bs, bs_io_opts.geometry, lba);
	bs_dev->read(bs_dev, back_channel, payload, lba, lba_count, &set->cb_args, &bs_io_opts);
}

void
bs_batch_read_dev(spdk_bs_batch_t *batch, void *payload,
		  uint64_t lba, uint32_t lba_count)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;
	struct spdk_bs_channel		*channel = set->channel;
	struct spdk_bs_io_opts		bs_io_opts = {0};

	SPDK_DEBUGLOG(blob_rw, "Reading %" PRIu32 " blocks from LBA %" PRIu64 "\n", lba_count,
		      lba);

	set->u.batch.outstanding_ops++;
	bs_io_opts.priority = batch->priority_class;

	if (set->u.batch.geometry != 0) {
		bs_io_opts.geometry = set->u.batch.geometry;
	} else {
		bs_io_opts.geometry = batch->geometry;
	}

	bs_io_opts.special_io = set->u.batch.special_io;

	check_geometry(set->bs, bs_io_opts.geometry, lba);
	channel->dev->read(channel->dev, channel->dev_channel, payload, lba, lba_count, &set->cb_args, &bs_io_opts);
}

void
bs_batch_write_dev(spdk_bs_batch_t *batch, void *payload,
		   uint64_t lba, uint32_t lba_count)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;
	struct spdk_bs_channel		*channel = set->channel;
	struct spdk_bs_io_opts 		bs_io_opts = {0};
	SPDK_DEBUGLOG(blob_rw, "Writing %" PRIu32 " blocks to LBA %" PRIu64 "\n", lba_count, lba);

	set->u.batch.outstanding_ops++;
	bs_io_opts.priority = batch->priority_class;
	if (set->u.batch.geometry != 0) {
		bs_io_opts.geometry = set->u.batch.geometry;
	} else {
		bs_io_opts.geometry = batch->geometry;
	}

	bs_io_opts.special_io = set->u.batch.special_io;

	check_geometry(set->bs, bs_io_opts.geometry, lba);
	channel->dev->write(channel->dev, channel->dev_channel, payload, lba, lba_count,
			    &set->cb_args, &bs_io_opts);
}

void
bs_batch_unmap_dev(spdk_bs_batch_t *batch,
		   uint64_t lba, uint64_t lba_count)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;
	struct spdk_bs_channel		*channel = set->channel;
	struct spdk_bs_io_opts		bs_io_opts = {0};
	struct limit *ctx = NULL;

	SPDK_DEBUGLOG(blob_rw, "Unmapping %" PRIu64 " blocks at LBA %" PRIu64 "\n", lba_count,
		      lba);

	if (set->u.batch.is_unmap && set->u.batch.outstanding_ops > 2000) {
		ctx = calloc(1, sizeof(*ctx));
		if (!ctx) {
			goto out;
		}
		ctx->lba = lba;
		ctx->lba_count = lba_count;
		TAILQ_INSERT_TAIL(&set->u.batch.unmap_queue, ctx, entries);
		set->u.batch.outstanding_ops++;
		return;
	}
out:
	set->u.batch.outstanding_ops++;	
	bs_io_opts.priority = batch->priority_class;
	if (set->u.batch.geometry != 0) {
		bs_io_opts.geometry = set->u.batch.geometry;
	} else {
		bs_io_opts.geometry = batch->geometry;
	}

	bs_io_opts.special_io = set->u.batch.special_io;

	check_geometry(set->bs, bs_io_opts.geometry, lba);
	if (spdk_likely(channel->bs->is_leader)) {
		channel->dev->unmap(channel->dev, channel->dev_channel, lba, lba_count,
					&set->cb_args, &bs_io_opts);
	} else {
		SPDK_NOTICELOG("The unmap IO return with EIO error due to leader 1.\n");
		bs_batch_completion(set->cb_args.channel, set->cb_args.cb_arg, -EIO);
	}
}

void
bs_batch_write_zeroes_dev(spdk_bs_batch_t *batch,
			  uint64_t lba, uint64_t lba_count)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;
	struct spdk_bs_channel		*channel = set->channel;
	struct spdk_bs_io_opts		bs_io_opts = {0};
	SPDK_DEBUGLOG(blob_rw, "Zeroing %" PRIu64 " blocks at LBA %" PRIu64 "\n", lba_count, lba);

	set->u.batch.outstanding_ops++;
	bs_io_opts.priority = batch->priority_class;

	if (set->u.batch.geometry != 0) {
		bs_io_opts.geometry = set->u.batch.geometry;
	} else {
		bs_io_opts.geometry = batch->geometry;
	}

	bs_io_opts.special_io = set->u.batch.special_io;

	check_geometry(set->bs, bs_io_opts.geometry, lba);
	if (spdk_likely(channel->bs->is_leader)) {
		channel->dev->write_zeroes(channel->dev, channel->dev_channel, lba, lba_count,
				   	&set->cb_args, &bs_io_opts);
	} else {
		SPDK_NOTICELOG("The write zero IO return with EIO error due to leader.\n");
		bs_batch_completion(set->cb_args.channel, set->cb_args.cb_arg, -EIO);
	}
}

void
bs_batch_close(spdk_bs_batch_t *batch)
{
	struct spdk_bs_request_set	*set = (struct spdk_bs_request_set *)batch;

	set->u.batch.batch_closed = 1;

	if (set->u.batch.outstanding_ops == 0) {
		if (set->u.batch.cb_fn) {
			set->cb_args.cb_fn = bs_sequence_completion;
			set->u.batch.cb_fn((spdk_bs_sequence_t *)set, set->u.batch.cb_arg, set->bserrno);
		} else {
			bs_request_set_complete(set);
		}
	}
}

spdk_bs_batch_t *
bs_sequence_to_batch(spdk_bs_sequence_t *seq, uint8_t geometry, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set *set = (struct spdk_bs_request_set *)seq;

	set->u.batch.cb_fn = cb_fn;
	set->u.batch.geometry = geometry;
	set->u.batch.special_io = 0; // default special io
	set->u.batch.cb_arg = cb_arg;
	set->u.batch.outstanding_ops = 0;
	set->u.batch.batch_closed = 0;
	set->u.batch.is_unmap = false;
	TAILQ_INIT(&set->u.batch.unmap_queue);

	set->cb_args.cb_fn = bs_batch_completion;

	return set;
}

spdk_bs_batch_t *
bs_sequence_to_batch_s(spdk_bs_sequence_t *seq, uint8_t geometry, uint8_t special_io, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct spdk_bs_request_set *set = (struct spdk_bs_request_set *)seq;

	set->u.batch.cb_fn = cb_fn;
	set->u.batch.geometry = geometry;
	set->u.batch.special_io = special_io;
	set->u.batch.cb_arg = cb_arg;
	set->u.batch.outstanding_ops = 0;
	set->u.batch.batch_closed = 0;
	set->u.batch.is_unmap = false;
	TAILQ_INIT(&set->u.batch.unmap_queue);

	set->cb_args.cb_fn = bs_batch_completion;

	return set;
}

spdk_bs_user_op_t *
bs_user_op_alloc(struct spdk_io_channel *_channel, struct spdk_bs_cpl *cpl,
		 enum spdk_blob_op_type op_type, struct spdk_blob *blob,
		 void *payload, int iovcnt, uint64_t offset, uint64_t length)
{
	struct spdk_bs_channel		*channel;
	struct spdk_bs_request_set	*set;
	struct spdk_bs_user_op_args	*args;

	channel = spdk_io_channel_get_ctx(_channel);
	assert(channel != NULL);
	set = TAILQ_FIRST(&channel->reqs);
	if (!set) {
		return NULL;
	}
	TAILQ_REMOVE(&channel->reqs, set, link);

	set->cpl = *cpl;
	set->channel = channel;
	set->back_channel = NULL;
	set->ext_io_opts = NULL;

	args = &set->u.user_op;

	args->type = op_type;
	args->iovcnt = iovcnt;
	args->blob = blob;
	args->offset = offset;
	args->length = length;
	args->payload = payload;

	return (spdk_bs_user_op_t *)set;
}

void
bs_user_op_execute(spdk_bs_user_op_t *op)
{
	struct spdk_bs_request_set	*set;
	struct spdk_bs_user_op_args	*args;
	struct spdk_io_channel		*ch;

	set = (struct spdk_bs_request_set *)op;
	args = &set->u.user_op;
	ch = spdk_io_channel_from_ctx(set->channel);
	// SPDK_NOTICELOG("IO OP blocks at LBA: %" PRIu64 " blocks CNT %" PRIu64 " and the type is %d \n", args->offset, args->length, args->type);
	switch (args->type) {
	case SPDK_BLOB_READ:
		spdk_blob_io_read(args->blob, ch, args->payload, args->offset, args->length,
				  set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg);
		break;
	case SPDK_BLOB_WRITE:
		spdk_blob_io_write(args->blob, ch, args->payload, args->offset, args->length,
				   set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg);
		break;
	case SPDK_BLOB_UNMAP:
		spdk_blob_io_unmap(args->blob, ch, args->offset, args->length,
				   set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg);
		break;
	case SPDK_BLOB_WRITE_ZEROES:
		spdk_blob_io_write_zeroes(args->blob, ch, args->offset, args->length,
					  set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg);
		break;
	case SPDK_BLOB_READV:
		spdk_blob_io_readv_ext(args->blob, ch, args->payload, args->iovcnt,
				       args->offset, args->length,
				       set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg,
				       set->ext_io_opts);
		break;
	case SPDK_BLOB_WRITEV:
		spdk_blob_io_writev_ext(args->blob, ch, args->payload, args->iovcnt,
					args->offset, args->length,
					set->cpl.u.blob_basic.cb_fn, set->cpl.u.blob_basic.cb_arg,
					set->ext_io_opts);
		break;
	}
	TAILQ_INSERT_TAIL(&set->channel->reqs, set, link);
}

void
bs_user_op_abort(spdk_bs_user_op_t *op, int bserrno)
{
	struct spdk_bs_request_set	*set;

	set = (struct spdk_bs_request_set *)op;

	set->cpl.u.blob_basic.cb_fn(set->cpl.u.blob_basic.cb_arg, bserrno);
	TAILQ_INSERT_TAIL(&set->channel->reqs, set, link);
}

SPDK_LOG_REGISTER_COMPONENT(blob_rw)
