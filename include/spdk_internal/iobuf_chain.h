/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2026 Simplyblock.
 *   All rights reserved.
 */

/*
 * Buffer chains from the iobuf small pool: one request's data in several small
 * buffers (8 KiB by default), described by an iovec array, instead of one
 * contiguous DMA allocation. The small pool is preallocated, so it cannot
 * fragment; a request that finds it empty WAITS for buffers and never fails.
 *
 * A queue serves the chains of one iobuf channel, on that channel's thread
 * (every call below runs there). Its waiting chains are served in order, and
 * only the first one ever holds buffers while it waits: a chain that has to
 * wait gives back what it holds and joins the end of the queue, and the first
 * one keeps what it got while its iobuf entry waits for the rest. So no set of
 * waiting chains can hold the pool between them (at most one chain per queue
 * holds a part of what it needs, and less than one chain's worth), and every
 * other buffer of the queue's chains belongs to a request in flight, which
 * returns it when it completes.
 *
 * The iobuf wait queue is per thread and is served only by a spdk_iobuf_put()
 * on that thread. A queue whose own requests all wait (their buffers were taken
 * by other threads) would not be woken by those threads' puts:
 * spdk_iobuf_chain_kick(), called from a poller of the thread, takes a buffer
 * that came back to the global pool and hands it to the waiting entry.
 *
 * A chain that got its buffers after waiting is handed to the queue's ready_fn,
 * which runs inside spdk_iobuf_put() or spdk_iobuf_chain_kick() of some other
 * request: ready_fn must not submit IO or call into the queue itself, only
 * note the chain and defer its submission (a thread message).
 */

#ifndef SPDK_INTERNAL_IOBUF_CHAIN_H
#define SPDK_INTERNAL_IOBUF_CHAIN_H

#include "spdk/stdinc.h"
#include "spdk/queue.h"
#include "spdk/thread.h"
#include "spdk/util.h"

/* 64 KiB in the smallest small buffers (4 KiB); 8 with the default 8 KiB */
#define SPDK_IOBUF_CHAIN_MAX_IOVS	16

struct spdk_iobuf_chain;
struct spdk_iobuf_chain_queue;

typedef void (*spdk_iobuf_chain_ready_fn)(struct spdk_iobuf_chain *chain);

struct spdk_iobuf_chain {
	struct spdk_iobuf_entry		entry;
	struct spdk_iobuf_chain_queue	*q;	/* NULL until the first get */
	uint64_t			len;	/* bytes the iovs describe */
	uint32_t			nbufs;	/* buffers held */
	uint32_t			needed;
	bool				waiting;
	TAILQ_ENTRY(spdk_iobuf_chain)	link;
	/* [0, needed) describe len bytes once the chain is complete */
	struct iovec			iovs[SPDK_IOBUF_CHAIN_MAX_IOVS];
};

struct spdk_iobuf_chain_queue {
	struct spdk_iobuf_channel	*ch;
	uint32_t			bufsize;	/* the small pool's buffer size */
	/* the first waiting chain's entry is queued in iobuf */
	bool				armed;
	TAILQ_HEAD(, spdk_iobuf_chain)	waitq;
	spdk_iobuf_chain_ready_fn	ready_fn;
	/* chains that had to wait, and buffers handed over by kicks */
	uint64_t			waits;
	uint64_t			kicked;
};

static inline void
spdk_iobuf_chain_queue_init(struct spdk_iobuf_chain_queue *q, struct spdk_iobuf_channel *ch,
			    spdk_iobuf_chain_ready_fn ready_fn)
{
	struct spdk_iobuf_opts opts = {};

	spdk_iobuf_get_opts(&opts, sizeof(opts));
	memset(q, 0, sizeof(*q));
	q->ch = ch;
	q->bufsize = opts.small_bufsize;
	q->ready_fn = ready_fn;
	TAILQ_INIT(&q->waitq);
}

static inline bool
spdk_iobuf_chain_queue_idle(const struct spdk_iobuf_chain_queue *q)
{
	return TAILQ_EMPTY(&q->waitq) && !q->armed;
}

/* Number of buffers a chain of len bytes takes; 0 when it is too long. */
static inline uint32_t
spdk_iobuf_chain_bufs_for(const struct spdk_iobuf_chain_queue *q, uint64_t len)
{
	uint64_t n;

	if (q->bufsize == 0 || len == 0) {
		return 0;
	}
	n = (len + q->bufsize - 1) / q->bufsize;
	return n > SPDK_IOBUF_CHAIN_MAX_IOVS ? 0 : (uint32_t)n;
}

static inline void
_iobuf_chain_set_lens(struct spdk_iobuf_chain *chain)
{
	uint64_t left = chain->len;
	uint32_t i;

	for (i = 0; i < chain->needed; i++) {
		chain->iovs[i].iov_len = spdk_min(left, (uint64_t)chain->q->bufsize);
		left -= chain->iovs[i].iov_len;
	}
}

static inline void
_iobuf_chain_put_bufs(struct spdk_iobuf_chain *chain, uint32_t keep)
{
	struct spdk_iobuf_chain_queue *q = chain->q;

	/* one at a time, from the end: a put can hand the buffer to the first
	 * waiting chain at once (its entry callback), which may be of this queue */
	while (chain->nbufs > keep) {
		chain->nbufs--;
		spdk_iobuf_put(q->ch, chain->iovs[chain->nbufs].iov_base, q->bufsize);
		chain->iovs[chain->nbufs].iov_base = NULL;
	}
}

/* Take buffers without waiting until the chain has all it needs. */
static inline bool
_iobuf_chain_fill(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	void *buf;

	while (chain->nbufs < chain->needed) {
		buf = spdk_iobuf_get(q->ch, q->bufsize, NULL, NULL);
		if (buf == NULL) {
			return false;
		}
		chain->iovs[chain->nbufs++].iov_base = buf;
	}
	_iobuf_chain_set_lens(chain);
	return true;
}

static inline void _iobuf_chain_entry_cb(struct spdk_iobuf_entry *entry, void *buf);

/*
 * The first waiting chain: complete it, or queue its entry for the next buffer.
 * True when it is complete.
 */
static inline bool
_iobuf_chain_try_head(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	void *buf;

	while (!_iobuf_chain_fill(chain)) {
		buf = spdk_iobuf_get(q->ch, q->bufsize, &chain->entry, _iobuf_chain_entry_cb);
		if (buf == NULL) {
			q->armed = true;
			return false;
		}
		/* one came back between the two gets */
		chain->iovs[chain->nbufs++].iov_base = buf;
	}
	return true;
}

/* Complete the waiting chains in order, as far as the pool allows. */
static inline void
_iobuf_chain_service(struct spdk_iobuf_chain_queue *q)
{
	struct spdk_iobuf_chain *head;

	while (!q->armed && (head = TAILQ_FIRST(&q->waitq)) != NULL) {
		if (!_iobuf_chain_try_head(head)) {
			return;
		}
		TAILQ_REMOVE(&q->waitq, head, link);
		head->waiting = false;
		q->ready_fn(head);
	}
}

static inline void
_iobuf_chain_entry_cb(struct spdk_iobuf_entry *entry, void *buf)
{
	struct spdk_iobuf_chain *chain = SPDK_CONTAINEROF(entry, struct spdk_iobuf_chain, entry);
	struct spdk_iobuf_chain_queue *q = chain->q;

	assert(q->armed);
	assert(chain == TAILQ_FIRST(&q->waitq));
	assert(chain->nbufs < chain->needed);
	q->armed = false;
	chain->iovs[chain->nbufs++].iov_base = buf;
	_iobuf_chain_service(q);
}

/*
 * Give the chain len bytes of buffers from q. Buffers it already holds (from
 * the same queue) are kept as far as they fit, the rest returned.
 *
 * \return 0: the chain is complete, chain->iovs[0, needed) describe len bytes;
 * 1: it waits, and q->ready_fn gets it once complete; -EINVAL: len is 0 or
 * more than SPDK_IOBUF_CHAIN_MAX_IOVS buffers.
 */
static inline int
spdk_iobuf_chain_get(struct spdk_iobuf_chain_queue *q, struct spdk_iobuf_chain *chain,
		     uint64_t len)
{
	uint32_t needed = spdk_iobuf_chain_bufs_for(q, len);

	assert(!chain->waiting);
	assert(chain->q == NULL || chain->q == q || chain->nbufs == 0);
	if (needed == 0) {
		return -EINVAL;
	}
	chain->q = q;
	chain->len = len;
	chain->needed = needed;
	if (!TAILQ_EMPTY(&q->waitq)) {
		/* others wait first: behind them, holding nothing */
		_iobuf_chain_put_bufs(chain, 0);
	} else {
		_iobuf_chain_put_bufs(chain, needed);
		if (_iobuf_chain_fill(chain)) {
			return 0;
		}
	}
	chain->waiting = true;
	q->waits++;
	TAILQ_INSERT_TAIL(&q->waitq, chain, link);
	if (chain == TAILQ_FIRST(&q->waitq) && !q->armed && _iobuf_chain_try_head(chain)) {
		/* the pool refilled meanwhile: no wait after all */
		TAILQ_REMOVE(&q->waitq, chain, link);
		chain->waiting = false;
		return 0;
	}
	return 1;
}

/*
 * Return every buffer the chain holds; a waiting chain also leaves the queue
 * (its iobuf entry is withdrawn). Safe on a chain that holds nothing.
 */
static inline void
spdk_iobuf_chain_put(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	bool was_head = false;

	if (q == NULL) {
		return;
	}
	if (chain->waiting) {
		was_head = chain == TAILQ_FIRST(&q->waitq);
		if (was_head && q->armed) {
			spdk_iobuf_entry_abort(q->ch, &chain->entry, q->bufsize);
			q->armed = false;
		}
		TAILQ_REMOVE(&q->waitq, chain, link);
		chain->waiting = false;
	}
	_iobuf_chain_put_bufs(chain, 0);
	if (was_head) {
		/* the next one becomes the first: it waits now */
		_iobuf_chain_service(q);
	}
}

/*
 * Hand buffers that came back to the global pool (from other threads) to the
 * first waiting chain. Cheap when nothing waits; call it from a poller.
 */
static inline void
spdk_iobuf_chain_kick(struct spdk_iobuf_chain_queue *q)
{
	void *buf;
	int i;

	for (i = 0; i < SPDK_IOBUF_CHAIN_MAX_IOVS && q->armed; i++) {
		buf = spdk_iobuf_get(q->ch, q->bufsize, NULL, NULL);
		if (buf == NULL) {
			return;
		}
		q->kicked++;
		/* the thread's first waiting entry (ours, or another module's
		 * that waited longer) gets it */
		spdk_iobuf_put(q->ch, buf, q->bufsize);
	}
}

#endif /* SPDK_INTERNAL_IOBUF_CHAIN_H */
