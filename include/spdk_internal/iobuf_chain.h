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
 * Caps (budgets). The small pool is shared with client IO (nvmf), which has no
 * kick: a background user that empties it can stall client IO. So a chain is
 * charged, before it takes a buffer, against up to two budgets: its owner's
 * (one replication task, one merge) and the cap every background user shares
 * (spdk_iobuf_chain_bg_budget(): a percentage of the small pool, the rest is
 * reserved for client IO). A chain over a cap waits like one that finds the
 * pool empty, but without an iobuf entry (the pool is not empty, no put would
 * wake it): spdk_iobuf_chain_kick() and every chain put on the queue retry it.
 * An empty budget always admits one chain, so a cap below one chain cannot
 * deadlock.
 *
 * Priority. A priority chain (the frozen final step of a replication) is not
 * charged against the shared background cap (only its owner's) and goes ahead
 * of every waiting background chain of its queue: the first background chain
 * gives back the part it holds and waits behind it.
 *
 * The iobuf wait queue is per thread and is served only by a spdk_iobuf_put()
 * on that thread. A queue whose own requests all wait (their buffers were taken
 * by other threads) would not be woken by those threads' puts:
 * spdk_iobuf_chain_kick(), called from a poller of the thread, takes a buffer
 * that came back to the global pool and hands it to the waiting entry.
 *
 * A chain that got its buffers after waiting is handed to the queue's ready_fn,
 * which runs inside spdk_iobuf_put(), spdk_iobuf_chain_put() or
 * spdk_iobuf_chain_kick() of some other request: ready_fn must not submit IO or
 * call into the queue itself, only note the chain and defer its submission (a
 * thread message).
 */

#ifndef SPDK_INTERNAL_IOBUF_CHAIN_H
#define SPDK_INTERNAL_IOBUF_CHAIN_H

#include "spdk/stdinc.h"
#include "spdk/queue.h"
#include "spdk/thread.h"
#include "spdk/util.h"

/* 64 KiB in the smallest small buffers (4 KiB); 8 with the default 8 KiB */
#define SPDK_IOBUF_CHAIN_MAX_IOVS	16

/* Default share of the small pool all background chain users (replication,
 * blob merge) may hold together; the rest stays for client IO. */
#define SPDK_IOBUF_CHAIN_BG_PCT_DEFAULT	50

struct spdk_iobuf_chain;
struct spdk_iobuf_chain_queue;

typedef void (*spdk_iobuf_chain_ready_fn)(struct spdk_iobuf_chain *chain);

/*
 * A cap on the small-pool buffers a set of chains holds, on any thread
 * (atomics). limit 0: no cap.
 */
struct spdk_iobuf_chain_budget {
	uint64_t	limit;
	uint64_t	used;
	uint64_t	max_used;	/* high-water mark, for logs and tests */
	uint64_t	refused;	/* charges refused: a chain waited for the cap */
};

/*
 * The budget every background chain user shares (lib/thread/iobuf.c): its limit
 * is spdk_iobuf_chain_set_bg_pct() percent of the small pool.
 */
struct spdk_iobuf_chain_budget *spdk_iobuf_chain_bg_budget(void);
/* pct 1..100; -EINVAL otherwise. Applies to charges from now on. */
int spdk_iobuf_chain_set_bg_pct(uint32_t pct);
uint32_t spdk_iobuf_chain_get_bg_pct(void);

struct spdk_iobuf_chain {
	struct spdk_iobuf_entry		entry;
	struct spdk_iobuf_chain_queue	*q;	/* NULL until the first get */
	uint64_t			len;	/* bytes the iovs describe */
	uint32_t			nbufs;	/* buffers held */
	uint32_t			needed;
	bool				waiting;
	/* spdk_iobuf_chain_set_budget(): the owner's cap and the shared one
	 * (either NULL: none), and the buffers charged against them (>= nbufs;
	 * 0 unless the chain holds buffers or is the first waiting one) */
	bool				priority;
	struct spdk_iobuf_chain_budget	*budget;
	struct spdk_iobuf_chain_budget	*shared;
	uint32_t			charged;
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
	/* buffers the queue's chains hold now: 0 and idle, the channel can go */
	uint64_t			held;
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
spdk_iobuf_chain_budget_init(struct spdk_iobuf_chain_budget *b, uint64_t limit)
{
	memset(b, 0, sizeof(*b));
	b->limit = limit;
}

static inline bool
_iobuf_budget_take(struct spdk_iobuf_chain_budget *b, uint64_t n)
{
	uint64_t limit, used, max;

	if (b == NULL) {
		return true;
	}
	limit = __atomic_load_n(&b->limit, __ATOMIC_RELAXED);
	used = __atomic_add_fetch(&b->used, n, __ATOMIC_SEQ_CST);
	/* used == n: the budget was empty, it admits one chain whatever its cap */
	if (limit != 0 && used > limit && used != n) {
		__atomic_sub_fetch(&b->used, n, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&b->refused, 1, __ATOMIC_RELAXED);
		return false;
	}
	max = __atomic_load_n(&b->max_used, __ATOMIC_RELAXED);
	while (used > max &&
	       !__atomic_compare_exchange_n(&b->max_used, &max, used, false, __ATOMIC_RELAXED,
					    __ATOMIC_RELAXED)) {
	}
	return true;
}

static inline void
_iobuf_budget_give(struct spdk_iobuf_chain_budget *b, uint64_t n)
{
	if (b != NULL && n != 0) {
		assert(__atomic_load_n(&b->used, __ATOMIC_RELAXED) >= n);
		__atomic_sub_fetch(&b->used, n, __ATOMIC_SEQ_CST);
	}
}

/* Charge the chain for all it needs. False: over a cap, nothing changed. */
static inline bool
_iobuf_chain_charge(struct spdk_iobuf_chain *chain)
{
	uint32_t n;

	if (chain->charged >= chain->needed) {
		return true;
	}
	n = chain->needed - chain->charged;
	if (!_iobuf_budget_take(chain->budget, n)) {
		return false;
	}
	if (!chain->priority && !_iobuf_budget_take(chain->shared, n)) {
		_iobuf_budget_give(chain->budget, n);
		return false;
	}
	chain->charged += n;
	return true;
}

static inline void
_iobuf_chain_uncharge(struct spdk_iobuf_chain *chain, uint32_t keep)
{
	uint32_t n;

	if (chain->charged <= keep) {
		return;
	}
	n = chain->charged - keep;
	chain->charged = keep;
	_iobuf_budget_give(chain->budget, n);
	if (!chain->priority) {
		_iobuf_budget_give(chain->shared, n);
	}
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

	/* the charge first: a put below can complete another chain, which may
	 * charge the same budgets */
	_iobuf_chain_uncharge(chain, keep);
	/* one at a time, from the end: a put can hand the buffer to the first
	 * waiting chain at once (its entry callback), which may be of this queue */
	while (chain->nbufs > keep) {
		chain->nbufs--;
		q->held--;
		spdk_iobuf_put(q->ch, chain->iovs[chain->nbufs].iov_base, q->bufsize);
		chain->iovs[chain->nbufs].iov_base = NULL;
	}
}

/* Take buffers without waiting until the chain has all it needs; false when
 * the pool is empty or the chain is over a cap (charged < needed then). */
static inline bool
_iobuf_chain_fill(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	void *buf;

	if (!_iobuf_chain_charge(chain)) {
		return false;
	}
	while (chain->nbufs < chain->needed) {
		buf = spdk_iobuf_get(q->ch, q->bufsize, NULL, NULL);
		if (buf == NULL) {
			return false;
		}
		q->held++;
		chain->iovs[chain->nbufs++].iov_base = buf;
	}
	_iobuf_chain_set_lens(chain);
	return true;
}

static inline void _iobuf_chain_entry_cb(struct spdk_iobuf_entry *entry, void *buf);

/*
 * The first waiting chain: complete it, or queue its entry for the next buffer
 * (over a cap: no entry, a kick or a put on the queue retries). True when it is
 * complete.
 */
static inline bool
_iobuf_chain_try_head(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	void *buf;

	while (!_iobuf_chain_fill(chain)) {
		if (chain->charged < chain->needed) {
			return false;
		}
		buf = spdk_iobuf_get(q->ch, q->bufsize, &chain->entry, _iobuf_chain_entry_cb);
		if (buf == NULL) {
			q->armed = true;
			return false;
		}
		/* one came back between the two gets */
		q->held++;
		chain->iovs[chain->nbufs++].iov_base = buf;
	}
	return true;
}

/* Complete the waiting chains in order, as far as the pool and caps allow. */
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
	q->held++;
	chain->iovs[chain->nbufs++].iov_base = buf;
	_iobuf_chain_service(q);
}

/* The first waiting chain steps back for a priority chain: it gives back
 * what it holds (and its charge) and withdraws its iobuf entry. */
static inline void
_iobuf_chain_demote_head(struct spdk_iobuf_chain_queue *q, struct spdk_iobuf_chain *head)
{
	if (q->armed) {
		spdk_iobuf_entry_abort(q->ch, &head->entry, q->bufsize);
		q->armed = false;
	}
	_iobuf_chain_put_bufs(head, 0);
}

/*
 * Set the caps a chain is charged against (NULL: none) and whether it is a
 * priority chain, before spdk_iobuf_chain_get(). A chain that changes owner
 * gives back what it holds first.
 */
static inline void
spdk_iobuf_chain_set_budget(struct spdk_iobuf_chain *chain, struct spdk_iobuf_chain_budget *budget,
			    struct spdk_iobuf_chain_budget *shared, bool priority)
{
	assert(!chain->waiting);
	if (chain->budget != budget || chain->shared != shared || chain->priority != priority) {
		if (chain->q != NULL) {
			_iobuf_chain_put_bufs(chain, 0);
		}
		assert(chain->charged == 0);
		chain->budget = budget;
		chain->shared = shared;
		chain->priority = priority;
	}
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
	struct spdk_iobuf_chain *pos = NULL;
	bool head;

	assert(!chain->waiting);
	assert(chain->q == NULL || chain->q == q || chain->nbufs == 0);
	if (needed == 0) {
		return -EINVAL;
	}
	chain->q = q;
	chain->len = len;
	chain->needed = needed;
	if (chain->priority) {
		/* behind the priority chains that wait, ahead of every background
		 * one: the frozen final step must not wait behind background
		 * replication */
		pos = TAILQ_FIRST(&q->waitq);
		while (pos != NULL && pos->priority) {
			pos = TAILQ_NEXT(pos, link);
		}
	}
	/* pos: the chain goes in front of it (NULL: at the end) */
	head = pos == TAILQ_FIRST(&q->waitq);
	if (head) {
		if (pos != NULL) {
			/* the first background chain gives back what it holds */
			_iobuf_chain_demote_head(q, pos);
		}
		_iobuf_chain_put_bufs(chain, needed);
		if (_iobuf_chain_fill(chain)) {
			/* a demoted first chain waits again (re-arms) */
			_iobuf_chain_service(q);
			return 0;
		}
	} else {
		/* others wait first: behind them, holding nothing */
		_iobuf_chain_put_bufs(chain, 0);
	}
	chain->waiting = true;
	q->waits++;
	if (pos == NULL) {
		TAILQ_INSERT_TAIL(&q->waitq, chain, link);
	} else {
		TAILQ_INSERT_BEFORE(pos, chain, link);
	}
	if (head && !q->armed && _iobuf_chain_try_head(chain)) {
		/* the pool refilled meanwhile: no wait after all */
		TAILQ_REMOVE(&q->waitq, chain, link);
		chain->waiting = false;
		_iobuf_chain_service(q);
		return 0;
	}
	return 1;
}

/*
 * Return every buffer the chain holds; a waiting chain also leaves the queue
 * (its iobuf entry is withdrawn). Safe on a chain that holds nothing. A chain
 * of the queue that waits for a cap gets another try.
 */
static inline void
spdk_iobuf_chain_put(struct spdk_iobuf_chain *chain)
{
	struct spdk_iobuf_chain_queue *q = chain->q;
	bool was_head = false;

	/* a chain that holds nothing is not touched (nor its last queue, which
	 * may belong to another thread by now) */
	if (q == NULL || (!chain->waiting && chain->nbufs == 0 && chain->charged == 0)) {
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
	if (was_head || (!q->armed && !TAILQ_EMPTY(&q->waitq))) {
		/* the next one becomes the first, or the first waits for a cap
		 * this chain just made room in */
		_iobuf_chain_service(q);
	}
}

/*
 * Take the first waiting chain off the queue without serving the others: it
 * gives back what it holds (and withdraws its iobuf entry). Call it until it
 * returns NULL to empty the queue, e.g. when its owner fails.
 */
static inline struct spdk_iobuf_chain *
spdk_iobuf_chain_withdraw_waiting(struct spdk_iobuf_chain_queue *q)
{
	struct spdk_iobuf_chain *chain = TAILQ_FIRST(&q->waitq);

	if (chain == NULL) {
		return NULL;
	}
	if (q->armed) {
		spdk_iobuf_entry_abort(q->ch, &chain->entry, q->bufsize);
		q->armed = false;
	}
	TAILQ_REMOVE(&q->waitq, chain, link);
	chain->waiting = false;
	_iobuf_chain_put_bufs(chain, 0);
	return chain;
}

/*
 * Hand buffers that came back to the global pool (from other threads) to the
 * first waiting chain, and retry a first chain that waits for a cap. Cheap
 * when nothing waits; call it from a poller.
 */
static inline void
spdk_iobuf_chain_kick(struct spdk_iobuf_chain_queue *q)
{
	void *buf;
	int i;

	if (!q->armed) {
		if (!TAILQ_EMPTY(&q->waitq)) {
			_iobuf_chain_service(q);
		}
		return;
	}
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
