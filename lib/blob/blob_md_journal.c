#include "blob_md_journal.h"
#include "request.h"
#include "blobstore.h"
#include "spdk/crc32.h"
#include "spdk/queue.h"
#include "spdk/log.h"

#define JM_CRC32C_INITIAL 0xffffffffUL

static bool
md_journal_can_destroy(struct spdk_bs_md_journal *jr)
{
	if (jr->journal_inflight != 0) {
		return false;
	}

	if (jr->active_drain_batch || jr->active_zero_batch) {
		return false;
	}

	if (jr->journal_inflight == 0 && !TAILQ_EMPTY(&jr->reorder_queue)) {
		struct md_journal_elem *elem = TAILQ_FIRST(&jr->reorder_queue);

		SPDK_ERRLOG("MD journal reorder stuck: next_home_seq=%" PRIu64" first_seq=%" PRIu64 " state=%d\n",
			 		jr->next_home_seq, elem->seq, elem->state);

		assert(false);
		return false;
	}

	/*
	 * HOME/ZERO entries still contain successfully journaled
	 * metadata which must finish HOME + ZERO before destruction.
	 */
	if (!TAILQ_EMPTY(&jr->home_queue) ||
	    !TAILQ_EMPTY(&jr->zero_queue)) {
		return false;
	}

	return true;
}

static void
md_journal_free(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;
	uint32_t i;

	assert(jr != NULL);
	assert(jr->journal_inflight == 0);
	assert(!jr->active_drain_batch);
	assert(!jr->active_zero_batch);
	assert(TAILQ_EMPTY(&jr->wait_queue));

	if (jr->home_seq != NULL) {
		bs_sequence_finish(jr->home_seq, 0);
		jr->home_seq = NULL;
	}

	if (jr->zero_seq != NULL) {
		bs_sequence_finish(jr->zero_seq, 0);
		jr->zero_seq = NULL;
	}

	if (jr->elems != NULL) {
		for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
			elem = &jr->elems[i];

			if (elem->hdr != NULL) {
				spdk_free(elem->hdr);
				elem->hdr = NULL;
			}

			if (elem->page != NULL) {
				spdk_free(elem->page);
				elem->page = NULL;
			}
		}

		free(jr->elems);
		jr->elems = NULL;
	}

	free(jr->drain_batch);
	jr->drain_batch = NULL;

	free(jr->zero_batch);
	jr->zero_batch = NULL;

	free(jr->hash_table);
	jr->hash_table = NULL;

	free(jr);
}

static uint32_t
md_journal_entry_calc_crc(struct md_journal_entry_hdr *hdr, const void *payload)
{
	uint32_t saved_crc;
	uint32_t crc;
	saved_crc = hdr->crc;
	hdr->crc = 0;

	crc = JM_CRC32C_INITIAL;
	crc = spdk_crc32c_update(hdr, BS_MD_JOURNAL_PAGE_SIZE, crc);
	crc = spdk_crc32c_update(payload, BS_MD_JOURNAL_PAGE_SIZE, crc);
	crc ^= JM_CRC32C_INITIAL;

	hdr->crc = saved_crc;
	return crc;
}

static void
md_journal_elem_reset(struct md_journal_elem *elem)
{
	elem->state = MD_JOURNAL_ELEM_FREE;

	elem->seq = 0;
	elem->bs_seq = NULL;

	memset(&elem->io_opts, 0, sizeof(elem->io_opts));

	elem->cb_fn = NULL;
	elem->cb_arg = NULL;

	elem->skip_home = false;
}

static inline uint32_t
md_journal_hash_lba(struct spdk_bs_md_journal *jr, uint64_t lba)
{
	assert(jr != NULL);
	assert(jr->hash_size != 0);

	lba ^= lba >> 33;
	lba *= UINT64_C(0xff51afd7ed558ccd);
	lba ^= lba >> 33;

	return (uint32_t)lba & (jr->hash_size - 1);
}

static void
md_journal_hash_reset(struct spdk_bs_md_journal *jr)
{
	assert(jr != NULL);
	assert(jr->hash_table != NULL);
	assert(jr->hash_size != 0);

	memset(jr->hash_table, 0, jr->hash_size * sizeof(jr->hash_table[0]));
}
/*
 * Insert elem using target_lba as key.
 *
 * If the LBA already exists, keep the element with the highest seq.
 *
 * Returns:
 *   0       inserted/replaced successfully
 *  -ENOSPC  hash table unexpectedly full
 */
static int
md_journal_hash_insert(struct spdk_bs_md_journal *jr,
		       struct md_journal_elem *elem)
{
	struct md_journal_hash_entry *entry;
	uint64_t target_lba;
	uint32_t idx;
	uint32_t i;

	assert(jr != NULL);
	assert(jr->hash_table != NULL);
	assert(jr->hash_size != 0);
	assert(elem != NULL);
	assert(elem->hdr != NULL);

	target_lba = elem->hdr->target_lba;
	idx = md_journal_hash_lba(jr, target_lba);

	for (i = 0; i < jr->hash_size; i++) {
		entry = &jr->hash_table[idx];

		if (entry->elem == NULL) {
			entry->elem = elem;
			return 0;
		}

		if (entry->elem->hdr->target_lba == target_lba) {
			if (elem->seq > entry->elem->seq) {
				entry->elem = elem;
			}

			return 0;
		}

		idx = (idx + 1) & (jr->hash_size - 1);
	}

	SPDK_ERRLOG("MD journal hash table is full: size=%u\n",
		    jr->hash_size);

	return -ENOSPC;
}

static struct md_journal_elem *
md_journal_hash_get(struct spdk_bs_md_journal *jr, uint64_t target_lba)
{
	struct md_journal_hash_entry *entry;
	uint32_t idx;
	uint32_t i;

	assert(jr != NULL);
	assert(jr->hash_table != NULL);
	assert(jr->hash_size != 0);

	idx = md_journal_hash_lba(jr, target_lba);

	for (i = 0; i < jr->hash_size; i++) {
		entry = &jr->hash_table[idx];

		if (entry->elem == NULL) {
			return NULL;
		}

		if (entry->elem->hdr->target_lba == target_lba) {
			return entry->elem;
		}

		idx = (idx + 1) & (jr->hash_size - 1);
	}

	return NULL;
}

static int
md_journal_hash_resize(struct spdk_bs_md_journal *jr, uint32_t new_size)
{
	struct md_journal_hash_entry *new_table;

	assert(jr != NULL);
	assert(new_size != 0);
	assert((new_size & (new_size - 1)) == 0);

	if (jr->hash_size == new_size) {
		md_journal_hash_reset(jr);
		return 0;
	}

	new_table = calloc(new_size, sizeof(new_table[0]));
	if (new_table == NULL) {
		return -ENOMEM;
	}

	free(jr->hash_table);

	jr->hash_table = new_table;
	jr->hash_size = new_size;

	return 0;
}

bool
bs_md_journal_read_on_examine(struct spdk_bs_md_journal *jr,
			      uint64_t target_lba, void *payload)
{
	struct md_journal_elem *elem;

	if (jr == NULL || payload == NULL) {
		return false;
	}

	/*
	 * The hash table is a read overlay only while EXAMINE recovery
	 * is active.
	 */
	if (!jr->recovering || !jr->examine) {
		return false;
	}

	elem = md_journal_hash_get(jr, target_lba);
	if (elem == NULL) {
		return false;
	}

	/*
	 * The recovery scan already validated the persistent header,
	 * lba_count and CRC before inserting this element into the hash.
	 */
	memcpy(payload, elem->page, BS_MD_JOURNAL_PAGE_SIZE);

	return true;
}

static struct md_journal_elem *
md_journal_get_free_elem(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;

	elem = TAILQ_FIRST(&jr->free_queue);
	if (elem == NULL) {
		return NULL;
	}

	TAILQ_REMOVE(&jr->free_queue, elem, link);

	assert(jr->free_count > 0);
	jr->free_count--;

	assert(elem->state == MD_JOURNAL_ELEM_FREE);

	return elem;
}

static void
md_journal_put_free_elem(struct spdk_bs_md_journal *jr,
			 struct md_journal_elem *elem)
{
	md_journal_elem_reset(elem);

	TAILQ_INSERT_TAIL(&jr->free_queue, elem, link);
	jr->free_count++;
}

static void
md_journal_fill_elem(struct spdk_bs_md_journal *jr, struct md_journal_elem *elem,
		     const void *payload, uint64_t lba, uint32_t lba_count, enum md_journal_op_type type)
{
	memset(elem->hdr, 0, BS_MD_JOURNAL_PAGE_SIZE);

	elem->seq = jr->next_seq++;

	if (type == MD_JOURNAL_WRITE_ZEROS) {
		memset(elem->page, 0, BS_MD_JOURNAL_PAGE_SIZE);
		elem->hdr->type = MD_JOURNAL_WRITE_ZEROS;
	} else {
		memcpy(elem->page, payload, BS_MD_JOURNAL_PAGE_SIZE);
		elem->hdr->type = MD_JOURNAL_WRITE;
	}

	elem->hdr->magic = BS_MD_JOURNAL_MAGIC;
	elem->hdr->version = BS_MD_JOURNAL_VERSION;
	elem->hdr->hdr_len = BS_MD_JOURNAL_PAGE_SIZE;

	elem->hdr->seq = elem->seq;
	elem->hdr->target_lba = lba;
	elem->hdr->lba_count = lba_count;

	// elem->hdr->io_priority = elem->io_opts.priority;
	// elem->hdr->io_geometry = elem->io_opts.geometry;
	// elem->hdr->io_special = elem->io_opts.special_io;

	elem->hdr->crc = 0;
	elem->hdr->crc = md_journal_entry_calc_crc(elem->hdr, elem->page);
}

static void
md_journal_release_ordered(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;

	while ((elem = TAILQ_FIRST(&jr->reorder_queue)) != NULL) {
		if (elem->seq != jr->next_home_seq) {
			break;
		}

		TAILQ_REMOVE(&jr->reorder_queue, elem, link);

		if (elem->state == MD_JOURNAL_ELEM_JOURNAL_FAILED) {
			md_journal_put_free_elem(jr, elem);
			jr->next_home_seq++;
			continue;
		}

		elem->state = MD_JOURNAL_ELEM_HOME_PENDING;

		TAILQ_INSERT_TAIL(&jr->home_queue, elem, link);

		jr->next_home_seq++;
	}
}

static void
md_journal_reorder_insert(struct spdk_bs_md_journal *jr, struct md_journal_elem *elem)
{
	struct md_journal_elem *it;

	// assert(elem->state == MD_JOURNAL_ELEM_JOURNAL_DONE);

	TAILQ_FOREACH(it, &jr->reorder_queue, link) {
		if (elem->seq < it->seq) {
			TAILQ_INSERT_BEFORE(it, elem, link);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&jr->reorder_queue, elem, link);
}

static void
md_journal_write_cpl(spdk_bs_sequence_t *seq, void *cb_arg, int bserron)
{
	struct md_journal_elem *elem = cb_arg;
	struct spdk_bs_md_journal *jr = elem->journal;
	assert(jr->journal_inflight > 0);
	jr->journal_inflight--;
	spdk_bs_sequence_cpl cb_fn = elem->cb_fn;
	void *_cb_arg = elem->cb_arg;

	if (bserron != 0) {
		SPDK_ERRLOG("\n");
		elem->state = MD_JOURNAL_ELEM_JOURNAL_FAILED;
		md_journal_reorder_insert(jr, elem);
		md_journal_release_ordered(jr);
		cb_fn(seq, _cb_arg, bserron);
		return;
	}
	
	elem->state = MD_JOURNAL_ELEM_JOURNAL_DONE;
	md_journal_reorder_insert(jr, elem);
	md_journal_release_ordered(jr);
	cb_fn(seq, _cb_arg, bserron);
}

static void
md_journal_write_cpl_v2(spdk_bs_sequence_t *seq, void *cb_arg, int bserron)
{
	struct md_journal_wait_req *req = cb_arg;
	spdk_bs_sequence_cpl cb_fn = req->cb_fn;
	void *_cb_arg = req->cb_arg;
	cb_fn(seq, _cb_arg, bserron);
	free(req);
}

static void
md_journal_submit_elem(struct md_journal_elem *elem)
{
	struct spdk_bs_md_journal *jr = elem->journal;
	uint64_t journal_lba, lba_count;

	assert(jr != NULL);
	assert(elem != NULL);
	assert(elem->state == MD_JOURNAL_ELEM_FREE);

	elem->state = MD_JOURNAL_ELEM_JOURNAL_INFLIGHT;

	// elem->journal_cb_args.cb_fn = md_journal_write_cpl;
	// elem->journal_cb_args.cb_arg = elem;
	// elem->journal_cb_args.channel = jr->ch;

	jr->journal_inflight++;

	journal_lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + (elem->slot * jr->blocks_per_entry));
	lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);

	bs_sequence_writev_dev(elem->bs_seq, elem->journal_iov, 2, journal_lba,
			      lba_count, md_journal_write_cpl, elem);

}

static void
md_journal_submit_waiting_single(struct md_journal_wait_req *req) {
	struct md_journal_elem *elem;
	elem = md_journal_get_free_elem(req->journal);
	assert(elem != NULL);

	md_journal_fill_elem(req->journal, elem, req->entry.payload, req->entry.lba, req->entry.lba_count, req->entry.type);

	elem->cb_fn = req->cb_fn;
	elem->cb_arg = req->cb_arg;
	elem->bs_seq = req->seq;

	md_journal_submit_elem(elem);
}

static void
md_journal_terminate_waiting_single(struct md_journal_wait_req *req) {
	req->cb_fn(req->seq, req->cb_arg, -EIO);
}

static void
md_journal_terminate_batch(struct md_journal_batch *batch) {
	batch->cb_fn(batch->seq, batch->cb_arg, -EIO);
	free(batch->entry);
	free(batch);
}

static void
md_journal_batch_write_cpl(spdk_bs_sequence_t *seq, void *cb_arg, int bserron)
{
	struct md_journal_batch *batch = cb_arg;
	struct spdk_bs_md_journal *jr = batch->journal;
	struct md_journal_op *entry = batch->entry;
	struct md_journal_elem *elmnt;

	if (jr->examine) {
		batch->cb_fn(batch->seq, batch->cb_arg, bserron);
		free(batch->entry);
		free(batch);
		return;
	}

	assert(jr->journal_inflight >= batch->count);
	jr->journal_inflight -= batch->count;


	if (bserron != 0) {
		SPDK_ERRLOG("\n");
		for (uint32_t i = 0; i < batch->count; i++) {
			elmnt = entry[i].elemt;
			assert(elmnt != NULL);
			if (elmnt) {
				elmnt->state = MD_JOURNAL_ELEM_JOURNAL_FAILED;
				md_journal_reorder_insert(jr, elmnt);
			} else {
				SPDK_ERRLOG("Elemnt is NULL. program error\n");
			}
		}
		md_journal_release_ordered(jr);
		batch->cb_fn(batch->seq, batch->cb_arg, bserron);
		free(batch->entry);
		free(batch);
		return;
	}
	
	for (uint32_t i = 0; i < batch->count; i++) {
		elmnt = entry[i].elemt;
		assert(elmnt != NULL);
		elmnt->state = MD_JOURNAL_ELEM_JOURNAL_DONE;
		md_journal_reorder_insert(jr, elmnt);
	}

	md_journal_release_ordered(jr);

	batch->cb_fn(batch->seq, batch->cb_arg, bserron);

	free(batch->entry);
	free(batch);
}

static void
md_journal_submit_batch(struct md_journal_batch *batch)
{
	struct spdk_bs_md_journal *jr = batch->journal;
	struct md_journal_op *entry;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *io_batch;
	uint64_t lba, lba_count;

	assert(jr->free_count >= batch->count);

	/*
	 * Convert the existing blobstore sequence into an actual
	 * blobstore IO batch.
	 */
	io_batch = bs_sequence_to_batch(batch->seq, 0, md_journal_batch_write_cpl, batch);
	/*
	 * Reserve/fill one journal element for every metadata page.
	 */
	entry = batch->entry;

	if (jr->examine) {
		for (uint32_t i = 0; i < batch->count; i++) {
			if (entry[i].type == MD_JOURNAL_WRITE) {
				bs_batch_write_dev(io_batch, entry[i].payload, entry[i].lba, entry[i].lba_count);
			} else {
				bs_batch_write_zeroes_dev(io_batch, entry[i].lba, entry[i].lba_count);
			}
		}
		bs_batch_close(io_batch);
		return;
	}

	for (uint32_t i = 0; i < batch->count; i++) {
		elem = md_journal_get_free_elem(jr);
		assert(elem != NULL);

		md_journal_fill_elem(jr, elem, entry[i].payload, entry[i].lba, entry[i].lba_count, entry[i].type);

		batch->entry[i].elemt = elem;
		elem->cb_fn = NULL;
		elem->cb_arg = NULL;

		elem->state = MD_JOURNAL_ELEM_JOURNAL_INFLIGHT;

		jr->journal_inflight++;

		/*
		 * Instead of dev->writev(), add this 8 KiB journal
		 * element to the existing blobstore batch.
		 */

		lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + ((uint64_t)elem->slot * jr->blocks_per_entry));
		lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);
		bs_batch_writev_dev(io_batch, elem->journal_iov, 2, lba, lba_count);
	}

	/*
	 * This is the signal that all journal writes have been added.
	 */
	bs_batch_close(io_batch);
}

static bool
md_journal_process_waiting(struct spdk_bs_md_journal *jr)
{
	struct md_journal_wait_req *waiting_req;
	uint32_t needed;
	bool work = false;

	while ((waiting_req = TAILQ_FIRST(&jr->wait_queue)) != NULL) {
		switch (waiting_req->type) {
		case MD_JOURNAL_WAIT_SINGLE:
			needed = 1;
			break;

		case MD_JOURNAL_WAIT_BATCH:
			needed = waiting_req->batch->count;
			break;

		default:
			assert(false);
			return work;
		}

		if (jr->stopping || jr->failed || jr->paused) {
			TAILQ_REMOVE(&jr->wait_queue, waiting_req, link);
			if (waiting_req->type == MD_JOURNAL_WAIT_SINGLE) {
				md_journal_terminate_waiting_single(waiting_req);
			} else {
				md_journal_terminate_batch(waiting_req->batch);
			}
			free(waiting_req);
			work = true;
			continue;
		}

		if (jr->seq_resetting) {
			return false;
		}

		/*
		 * Strict FIFO.
		 *
		 * Do not allow anything behind this request to consume
		 * elements reserved implicitly for the head request.
		 */
		if (jr->free_count < needed) {
			/*
			 * We need journal elements back as quickly as
			 * possible.
			 */
			jr->force_home_drain = true;
			break;
		}

		TAILQ_REMOVE(&jr->wait_queue, waiting_req, link);

		if (waiting_req->type == MD_JOURNAL_WAIT_SINGLE) {
			md_journal_submit_waiting_single(waiting_req);
		} else {
			md_journal_submit_batch(waiting_req->batch);
		}

		free(waiting_req);
		work = true;
	}

	return work;
}

static void
md_journal_complete_home_waiters(struct spdk_bs_md_journal *jr, int rc)
{
	struct md_journal_home_waiter *waiter, *tmp;

	TAILQ_FOREACH_SAFE(waiter, &jr->home_wait_queue, link, tmp) {
		TAILQ_REMOVE(&jr->home_wait_queue, waiter, link);

		waiter->cb_fn(waiter->seq, waiter->cb_arg, rc);
		free(waiter);
	}
}

void
bs_md_journal_write(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, void *payload,
		    uint64_t lba, uint32_t lba_count,
		    spdk_bs_sequence_cpl cb_fn, void *cb_arg, enum md_journal_op_type type)
{
	struct md_journal_wait_req *req;
	struct md_journal_elem *elem;

	if (jr == NULL || cb_fn == NULL || seq == NULL) {
		if (cb_fn != NULL) {
			cb_fn(seq, cb_arg, -EINVAL);
		}
		return;
	}

	if (jr->paused && !jr->examine) {
    	cb_fn(seq, cb_arg, -EIO);
    	return;
	}

	if (jr->failed) {
		SPDK_ERRLOG("MD journal write rejected: journal is paused, rc=%d\n",
			    jr->failure_rc);

		cb_fn(seq, cb_arg, jr->failure_rc);
		return;
	}

	if (lba_count != jr->blocks_per_page) {
		cb_fn(seq, cb_arg, -EINVAL);
		return;
	}

	if (jr->next_seq >= BS_MD_JOURNAL_SEQ_RESET_THRESHOLD && !jr->seq_resetting) {
		SPDK_ERRLOG("MD journal sequence reached reset threshold: "
				"next_seq=%" PRIu64 "\n",
				jr->next_seq);
		jr->seq_resetting = true;
		/* stop accepting metadata until update/reset */
	}

	if (jr->examine) {
		elem = md_journal_hash_get(jr, lba);
		if (elem) {
			if (type == MD_JOURNAL_WRITE) {
				memcpy(elem->page, payload, BS_MD_JOURNAL_PAGE_SIZE);
			} else {
				memset(elem->page, 0, BS_MD_JOURNAL_PAGE_SIZE);
			}
		}

		req = calloc(1, sizeof(*req));
		if (req == NULL) {
			cb_fn(seq, cb_arg, -ENOMEM);
			return;
		}

		req->type = MD_JOURNAL_WAIT_SINGLE;
		req->entry.payload = payload;
		req->entry.lba = lba;
		req->entry.lba_count = lba_count;
		req->entry.type = type;
		req->seq = seq;
		req->cb_fn = cb_fn;
		req->cb_arg = cb_arg;
		req->journal = jr;

		if (type == MD_JOURNAL_WRITE) {
			bs_sequence_write_dev(seq, payload, lba, lba_count, md_journal_write_cpl_v2, req);
		} else {
			bs_sequence_write_zeroes_dev(seq, lba, lba_count, md_journal_write_cpl_v2, req);
		}
		
		return;
	}

	/*
	 * Do not allow a new write to bypass older queued writes.
	 */
	if (TAILQ_EMPTY(&jr->wait_queue) && !jr->seq_resetting) {
		elem = md_journal_get_free_elem(jr);
		if (elem != NULL) {
			md_journal_fill_elem(jr, elem, payload, lba, lba_count, type);

			elem->cb_fn = cb_fn;
			elem->cb_arg = cb_arg;
			elem->bs_seq = seq;

			md_journal_submit_elem(elem);
			return;
		}
	}

	/*
	 * No element is currently available, or older writes are
	 * already waiting.
	 *
	 * Keep only the payload pointer. Blobstore guarantees that
	 * payload remains valid until cb_fn is called.
	 */
	req = calloc(1, sizeof(*req));
	if (req == NULL) {
		cb_fn(seq, cb_arg, -ENOMEM);
		return;
	}

	req->type = MD_JOURNAL_WAIT_SINGLE;
	req->entry.payload = payload;
	req->entry.lba = lba;
	req->entry.lba_count = lba_count;
	req->entry.type = type;
	req->seq = seq;
	req->cb_fn = cb_fn;
	req->cb_arg = cb_arg;
	req->journal = jr;

	TAILQ_INSERT_TAIL(&jr->wait_queue, req, link);
}

struct md_journal_batch *
bs_md_journal_sequence_to_batch(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, uint16_t capacity,
				spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct md_journal_batch *batch;
	struct md_journal_op *entry;

	if (jr == NULL || seq == NULL || cb_fn == NULL || capacity == 0) {
		return NULL;
	}

	if (jr->paused && !jr->examine ) {
		return NULL;
	}

	if (capacity > BS_MD_JOURNAL_NUM_ELEMS) {
		return NULL;
	}

	batch = calloc(1, sizeof(*batch));
	if (batch == NULL) {
		return NULL;
	}

	entry = calloc(capacity, sizeof(*entry));
	if (entry == NULL) {
		free(batch);
		return NULL;
	}

	batch->capacity = capacity;
	batch->entry = entry;
	batch->count = 0;

	batch->journal = jr;
	batch->seq = seq;

	batch->cb_fn = cb_fn;
	batch->cb_arg = cb_arg;

	return batch;
}

void
bs_md_journal_batch_write(struct md_journal_batch *batch, void *payload, uint64_t lba, uint32_t lba_count, enum md_journal_op_type type)
{
	struct md_journal_elem *elmnt;
	if (batch == NULL) {
		return;
	}

	if (batch->rc != 0) {
		return;
	}

	if (batch->closed) {
		batch->rc = -EINVAL;
		return;
	}

	if (lba_count != batch->journal->blocks_per_page) {
		batch->rc = -EINVAL;
		return;
	}

	if (batch->count >= batch->capacity) {
		batch->rc = -ENOSPC;
		return;
	}

	if (batch->journal->examine) {
		elmnt = md_journal_hash_get(batch->journal, lba);
		if (elmnt) {
			if (type == MD_JOURNAL_WRITE) {
				memcpy(elmnt->page, payload, BS_MD_JOURNAL_PAGE_SIZE);
			} else {
				memset(elmnt->page, 0, BS_MD_JOURNAL_PAGE_SIZE);
			}
			
		}
	}

	/*
	 * Do NOT copy the 4 KiB page here.
	 *
	 * Blobstore sequence/batch owns the payload until our
	 * journal batch completion.
	 */
	batch->entry[batch->count].payload = payload;
	batch->entry[batch->count].lba = lba;
	batch->entry[batch->count].lba_count = lba_count;
	batch->entry[batch->count].type = type;

	batch->count++;

	return;
}

void
bs_md_journal_batch_close(struct md_journal_batch *batch)
{
	struct spdk_bs_md_journal *jr;
	struct md_journal_wait_req *req;

	assert(batch != NULL);
	assert(!batch->closed);

	batch->closed = true;

	jr = batch->journal;

	if (batch->rc != 0) {
		batch->cb_fn(batch->seq, batch->cb_arg, batch->rc);
		free(batch->entry);
		free(batch);
		return;
	}

	if (batch->count == 0) {
		batch->cb_fn(batch->seq, batch->cb_arg, 0);
		free(batch->entry);
		free(batch);
		return;
	}

	if (jr->paused && !jr->examine) {
    	batch->cb_fn(batch->seq, batch->cb_arg, -EIO);
    	free(batch->entry);
    	free(batch);
    	return;
	}

	if (jr->failed) {
		SPDK_ERRLOG("MD journal batch rejected: journal is paused, "
			    "count=%u rc=%d\n",
			    batch->count, jr->failure_rc);

		batch->cb_fn(batch->seq, batch->cb_arg, jr->failure_rc);
		free(batch->entry);
		free(batch);
		return;
	}

	if (jr->next_seq >= BS_MD_JOURNAL_SEQ_RESET_THRESHOLD && !jr->seq_resetting) {
		SPDK_ERRLOG("MD journal sequence reached reset threshold: "
				"next_seq=%" PRIu64 "\n",
				jr->next_seq);

		/* stop accepting metadata until update/reset */
		jr->seq_resetting = true;
	}

	if (jr->examine) {
		md_journal_submit_batch(batch);
		return;
	}

	/*
	 * Do not allow this batch to bypass an older waiting request.
	 */
	if (!TAILQ_EMPTY(&jr->wait_queue) || jr->free_count < batch->count || jr->seq_resetting) {
		req = calloc(1, sizeof(*req));
		if (req == NULL) {
			batch->cb_fn(batch->seq, batch->cb_arg, -ENOMEM);
			free(batch->entry);
			free(batch);
			return;
		}

		req->type = MD_JOURNAL_WAIT_BATCH;
		req->batch = batch;
		TAILQ_INSERT_TAIL(&jr->wait_queue, req, link);

		/*
		 * Head request cannot currently be satisfied.
		 * Ask the drain side to aggressively return slots.
		 */
		if (jr->free_count < batch->count) {
			jr->force_home_drain = true;
		}
		return;
	}

	md_journal_submit_batch(batch);
}

static void
md_journal_process_home_waiters(struct spdk_bs_md_journal *jr)
{
	struct md_journal_home_waiter *waiter, *tmp;

	TAILQ_FOREACH_SAFE(waiter, &jr->home_wait_queue, link, tmp) {

		if (waiter->target_seq > jr->home_durable_seq) {
			if (jr->failed) {
				TAILQ_REMOVE(&jr->home_wait_queue, waiter, link);
				waiter->cb_fn(waiter->seq, waiter->cb_arg, jr->failure_rc);
				free(waiter);
			} else if (jr->paused) {
				TAILQ_REMOVE(&jr->home_wait_queue, waiter, link);
				waiter->cb_fn(waiter->seq, waiter->cb_arg, -EIO);
				free(waiter);
			}

			continue;
		}

		TAILQ_REMOVE(&jr->home_wait_queue, waiter, link);

		waiter->cb_fn(waiter->seq, waiter->cb_arg, 0);

		free(waiter);
	}
}

static void
md_journal_fail(struct spdk_bs_md_journal *jr, int bserrno, const char *reason)
{
	struct md_journal_wait_req *req;
	int rc;

	assert(jr != NULL);

	rc = bserrno != 0 ? bserrno : -EIO;

	if (!jr->failed) {
		jr->failed = true;
		jr->failure_rc = rc;

		SPDK_ERRLOG("MD journal paused due to fatal %s error: rc=%d "
			    "journal_inflight=%u free=%u next_seq=%" PRIu64
			    " next_home_seq=%" PRIu64 "\n",
			    reason, rc, jr->journal_inflight, jr->free_count,
			    jr->next_seq, jr->next_home_seq);
	}

	while ((req = TAILQ_FIRST(&jr->wait_queue)) != NULL) {
		TAILQ_REMOVE(&jr->wait_queue, req, link);

		if (req->type == MD_JOURNAL_WAIT_SINGLE) {
			SPDK_ERRLOG("Failing waiting MD journal single request: rc=%d\n",
				    		jr->failure_rc);

			req->cb_fn(req->seq, req->cb_arg, jr->failure_rc);
		} else {
			SPDK_ERRLOG("Failing waiting MD journal batch: count=%u rc=%d\n",
				    req->batch->count, jr->failure_rc);
			req->batch->cb_fn(req->batch->seq, req->batch->cb_arg, jr->failure_rc);
			free(req->batch->entry);
			free(req->batch);
		}

		free(req);
	}

	md_journal_process_home_waiters(jr);
}

uint64_t
bs_md_journal_next_seq_num(struct spdk_bs_md_journal *jr) {
	return jr->next_seq;
}

static void
spdk_md_journal_batch_drain_cpl(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	struct md_journal_drain_batch *drain_batch = jr->drain_batch;
	struct md_journal_elem *elem;
	uint32_t i;

	jr->active_drain_batch = false;

	if (bserrno != 0) {
		SPDK_ERRLOG("MD journal HOME drain failed: rc=%d "
			    "elements=%u - pausing journal\n",
			    bserrno, drain_batch->elem_count);

		/*
		* Fatal HOME/ZERO IO error.
		*
		* This journal instance is dead. Do not retry or requeue these
		* elements. Persistent journal state will be reconstructed by
		* the next update/recovery.
		*/
		memset(drain_batch->items, 0, sizeof(drain_batch->items));
		drain_batch->elem_count = 0;
		drain_batch->rc = 0;

		md_journal_fail(jr, bserrno, "HOME");
		return;
	}

	if (TAILQ_EMPTY(&jr->home_queue)) {
		jr->home_durable_seq = jr->next_home_seq - 1;
	} else {
		jr->home_durable_seq = drain_batch->items[drain_batch->elem_count - 1]->seq;
	}

	md_journal_process_home_waiters(jr);

	/*
	 * All HOME writes in this blobstore batch are durable now.
	 *
	 * This includes the skipped elements logically: their newer
	 * same-LBA entry was written by this same batch.
	 */
	for (i = 0; i < drain_batch->elem_count; i++) {
		elem = drain_batch->items[i];

		elem->state = MD_JOURNAL_ELEM_ZERO_PENDING;
		elem->drain_gen = jr->next_drain_gen;
		TAILQ_INSERT_TAIL(&jr->zero_queue, elem, link);
	}
	jr->next_drain_gen++;

	drain_batch = jr->drain_batch;
	memset(drain_batch->items, 0, sizeof(drain_batch->items));
	drain_batch->elem_count = 0;
	drain_batch->rc = 0;
	// bs_sequence_finish(seq, 0);
}

static int
spdk_md_journal_write_batch_drain(struct spdk_bs_md_journal *jr)
{
	struct spdk_blob_store *bs = jr->bs;
	struct md_journal_drain_batch *drain_batch;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint32_t i;

	if (jr->drain_batch == NULL) {
		return -EINVAL;
	}

	drain_batch = jr->drain_batch;

	batch = bs_sequence_to_batch(jr->home_seq, 0, spdk_md_journal_batch_drain_cpl, jr);

	for (i = 0; i < drain_batch->elem_count; i++) {
		elem = drain_batch->items[i];
		elem->state = MD_JOURNAL_ELEM_HOME_INFLIGHT;
		if (elem->skip_home) {
			continue;
		}
		bs->w_io++;
		bs_batch_write_dev(batch, elem->page, elem->hdr->target_lba, elem->hdr->lba_count);
	}

	bs_batch_close(batch);

	return 0;
}

static void
md_journal_mark_latest(struct md_journal_drain_batch *batch)
{
	uint32_t i;
	struct md_journal_elem *elem;
	int rc = 0;

	md_journal_hash_reset(batch->journal);

	for (i = 0; i < batch->elem_count; i++) {
		elem = batch->items[i];

		elem->skip_home = false;

		rc = md_journal_hash_insert(batch->journal, elem);
		if (rc != 0) {
			/* Should never happen with 16K table / max 8192 elems. */
			assert(false);
			return;
		}
	}

	for (i = 0; i < batch->elem_count; i++) {
		elem = batch->items[i];

		if (md_journal_hash_get(batch->journal, elem->hdr->target_lba) != elem) {
			elem->skip_home = true;
		}
	}
}

static void
md_journal_start_drain_batch(struct spdk_bs_md_journal *jr, bool force)
{
	struct md_journal_drain_batch *batch;
	struct md_journal_elem *elem;

    if (jr->active_drain_batch || TAILQ_EMPTY(&jr->home_queue)) {
        return;
    }

	if (jr->paused) {
		md_journal_process_home_waiters(jr);
		return;
	}
	
	batch = jr->drain_batch;

	batch->journal = jr;

	uint32_t max_drain = force ?  BS_MD_JOURNAL_NUM_ELEMS : BS_MD_JOURNAL_DRAIN_BATCH_SIZE;
	/*
	 * Consume the next consecutive elements from the ordered
	 * HOME queue.
	 */
	while (batch->elem_count < max_drain) {
		elem = TAILQ_FIRST(&jr->home_queue);
		if (elem == NULL) {
			break;
		}

		TAILQ_REMOVE(&jr->home_queue, elem, link);

		assert(elem->state == MD_JOURNAL_ELEM_HOME_PENDING);

		batch->items[batch->elem_count] = elem;

		batch->elem_count++;
	}

	if (batch->elem_count == 0) {
		// free(batch);
		return;
	}

	/*
	 * Entries are already in increasing sequence order.
	 *
	 * If the same LBA occurs multiple times in this batch,
	 * only the newest entry must reach the home location.
	 */
	md_journal_mark_latest(batch);

	jr->active_drain_batch = true;

	/*
	 * Next step:
	 *
	 * md_journal_submit_drain_batch(batch);
	 *
	 * We will implement the actual home IO and completion in
	 * the next part.
	 */
	spdk_md_journal_write_batch_drain(jr);

	if (jr->force_home_drain) {
		jr->force_home_drain = false;
	}

}

static void
spdk_md_journal_homes_finished(void *cb_arg, int bserrno) {
	// struct spdk_bs_md_journal *jr = cb_arg;
}

static void
spdk_md_journal_zeroes_finished(void *cb_arg, int bserrno) {
	// struct spdk_bs_md_journal *jr = cb_arg;
}

static void
spdk_md_journal_submit_zeroes_v2_cpl(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct md_journal_drain_batch *zero_batch = cb_arg;
	struct spdk_bs_md_journal *jr = zero_batch->journal;
	struct md_journal_elem *elem;
	uint32_t i;

	jr->active_zero_batch = false;

	if (bserrno != 0) {
		SPDK_ERRLOG("MD journal ZERO batch failed: rc=%d elements=%u - pausing journal\n",
			    bserrno, zero_batch->elem_count);

		/*
		* Fatal HOME/ZERO IO error.
		*
		* This journal instance is dead. Do not retry or requeue these
		* elements. Persistent journal state will be reconstructed by
		* the next update/recovery.
		*/
		// for (i = zero_batch->elem_count; i > 0; i--) {
		// 	elem = zero_batch->items[i - 1];

		// 	assert(elem != NULL);
		// 	assert(elem->state == MD_JOURNAL_ELEM_ZERO_INFLIGHT);

		// 	elem->state = MD_JOURNAL_ELEM_ZERO_PENDING;
		// 	TAILQ_INSERT_HEAD(&jr->zero_queue, elem, link);
		// }

		memset(zero_batch->items, 0, sizeof(zero_batch->items));
		zero_batch->elem_count = 0;
		md_journal_fail(jr, bserrno, "ZERO");
		return;
	}

	for (i = 0; i < zero_batch->elem_count; i++) {
		elem = zero_batch->items[i];
		assert(elem != NULL);
		assert(elem->state == MD_JOURNAL_ELEM_ZERO_INFLIGHT);
		zero_batch->items[i] = NULL;

		md_journal_put_free_elem(jr, elem);
	}
	memset(zero_batch->items, 0, sizeof(zero_batch->items));
	zero_batch->elem_count = 0;
}

static void
spdk_md_journal_submit_zeroes_v1_cpl(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct md_journal_drain_batch *zero_batch = cb_arg;
	struct spdk_bs_md_journal *jr = zero_batch->journal;
	struct spdk_blob_store *bs = jr->bs;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint64_t journal_lba, lba_count;

	if (bserrno < 0) {
		spdk_md_journal_submit_zeroes_v2_cpl(seq, cb_arg, bserrno);
		return;
	}

	if (jr->paused) {
		/*
		* Leadership was lost between ZERO phase 1 and phase 2.
		*
		* This is not a journal IO failure.  Stop runtime ZERO processing.
		* The remaining persistent journal entries will be handled by the
		* next leader during recovery.
		*/
		SPDK_NOTICELOG("MD journal ZERO stopped after leadership loss\n");

		jr->active_zero_batch = false;

		// for (uint32_t i = 0; i < zero_batch->elem_count; i++) {
        // 	elem = zero_batch->items[i];
		// 	if (elem != NULL) {
		// 		zero_batch->items[i] = NULL;
		// 		md_journal_put_free_elem(jr, elem);
		// 	}
		// }
		
		memset(zero_batch->items, 0, sizeof(zero_batch->items));
		zero_batch->elem_count = 0;
		zero_batch->rc = 0;
		return;
	}

	batch = bs_sequence_to_batch(jr->zero_seq, 0, spdk_md_journal_submit_zeroes_v2_cpl, zero_batch);
	
	for (uint32_t i = 0; i < zero_batch->elem_count; i++) {
		elem = zero_batch->items[i];
		if (elem == NULL) {
			break;
		}

		if (elem->skip_home) {
			continue;
		}
		elem->state = MD_JOURNAL_ELEM_ZERO_INFLIGHT;
		journal_lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + ((uint64_t)elem->slot * jr->blocks_per_entry));
		lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);
		bs->w_io++;
		bs_batch_write_zeroes_dev(batch, journal_lba, lba_count);
	}
	bs_batch_close(batch);
}

static int
spdk_md_journal_submit_zeroes(struct spdk_bs_md_journal *jr)
{
	struct spdk_blob_store *bs = jr->bs;
	struct md_journal_drain_batch *zero_batch;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint64_t journal_lba, lba_count;

	if (jr->zero_batch == NULL || jr->paused) {
		return -EINVAL;
	}

	zero_batch = jr->zero_batch;

	/*
	 * A ZERO batch is already active.
	 */
	if (zero_batch->elem_count != 0) {
		return -EBUSY;
	}

	/*
	 * Nothing to zero.
	 */
	if (TAILQ_EMPTY(&jr->zero_queue)) {
		return 0;
	}

	batch = bs_sequence_to_batch(jr->zero_seq, 0, spdk_md_journal_submit_zeroes_v1_cpl, zero_batch);
	uint32_t gen = TAILQ_FIRST(&jr->zero_queue)->drain_gen;
	while (zero_batch->elem_count < BS_MD_JOURNAL_DRAIN_BATCH_SIZE) {
		elem = TAILQ_FIRST(&jr->zero_queue);
		if (elem == NULL || elem->drain_gen != gen) {
			break;
		}

		TAILQ_REMOVE(&jr->zero_queue, elem, link);

		if (elem->skip_home) {
			elem->state = MD_JOURNAL_ELEM_ZERO_INFLIGHT;
			journal_lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + ((uint64_t)elem->slot * jr->blocks_per_entry));
			lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);
			bs->w_io++;
			bs_batch_write_zeroes_dev(batch, journal_lba, lba_count);
		}

		zero_batch->items[zero_batch->elem_count++] = elem;
	}

	jr->active_zero_batch = true;

	bs_batch_close(batch);
	return 0;
}

static int
md_journal_discard_runtime_state(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;

	assert(jr != NULL);

	/*
	 * The journal instance is dead, but we must not destroy/reset
	 * element memory while an IO can still reference it.
	 *
	 * Wait until all already-submitted journal/HOME/ZERO IOs have
	 * completed.
	 */
	if (jr->journal_inflight != 0 ||
	    jr->active_drain_batch ||
	    jr->active_zero_batch) {
		SPDK_NOTICELOG("MD journal discard waiting for inflight IO: "
			       "journal_inflight=%u home_active=%d zero_active=%d\n",
			       jr->journal_inflight,
			       jr->active_drain_batch,
			       jr->active_zero_batch);
		return -EBUSY;
	}

	/*
	 * No IO is active anymore.
	 *
	 * The current journal instance is dead. Do not submit any more
	 * HOME/ZERO IO. Persistent journal state will be reconstructed
	 * by the next update/recovery.
	 */

	while ((elem = TAILQ_FIRST(&jr->reorder_queue)) != NULL) {
		TAILQ_REMOVE(&jr->reorder_queue, elem, link);
	}

	while ((elem = TAILQ_FIRST(&jr->home_queue)) != NULL) {
		TAILQ_REMOVE(&jr->home_queue, elem, link);
	}

	while ((elem = TAILQ_FIRST(&jr->zero_queue)) != NULL) {
		TAILQ_REMOVE(&jr->zero_queue, elem, link);
	}

	/*
	 * Failed HOME/ZERO batch bookkeeping should already have been
	 * cleared by its completion callback. Clear it again here so the
	 * journal is in a consistent state before destruction.
	 */
	if (jr->drain_batch != NULL) {
		memset(jr->drain_batch->items, 0, sizeof(jr->drain_batch->items));
		jr->drain_batch->elem_count = 0;
		jr->drain_batch->rc = 0;
	}

	if (jr->zero_batch != NULL) {
		memset(jr->zero_batch->items, 0, sizeof(jr->zero_batch->items));
		jr->zero_batch->elem_count = 0;
		jr->zero_batch->rc = 0;
	}

	SPDK_NOTICELOG("MD journal runtime state discarded after fatal IO error\n");

	return 0;
}

static bool
md_journal_can_reset_seq(struct spdk_bs_md_journal *jr)
{
	return jr->journal_inflight == 0 &&
	       !jr->active_drain_batch &&
	       !jr->active_zero_batch &&
	       TAILQ_EMPTY(&jr->reorder_queue) &&
	       TAILQ_EMPTY(&jr->home_queue) &&
	       TAILQ_EMPTY(&jr->zero_queue) &&
	       jr->free_count == BS_MD_JOURNAL_NUM_ELEMS;
}

static int
md_journal_reset_seq(struct spdk_bs_md_journal *jr)
{
	if (!md_journal_can_reset_seq(jr)) {
		SPDK_ERRLOG("Cannot reset MD journal sequence: journal is not empty "
			    "inflight=%u free=%u home_active=%d zero_active=%d\n",
			    jr->journal_inflight,
			    jr->free_count,
			    jr->active_drain_batch,
			    jr->active_zero_batch);
		return -EBUSY;
	}

	jr->next_seq = 1;
	jr->next_home_seq = 1;
	jr->home_durable_seq = 0;

	SPDK_NOTICELOG("MD journal sequence reset to 1\n");

	return 0;
}

static int
md_journal_drain_poller(void *arg)
{
	struct spdk_bs_md_journal *jr = arg;
	bool work = false;
	spdk_blob_op_complete destroy_cb_fn;
	struct spdk_blob_store *bs;

	if (jr->stopping) {
		/*
		* Reject all requests which have not yet obtained a
		* journal slot.
		*/
		md_journal_process_waiting(jr);

		/*
		* Journal writes already submitted must finish first.
		* Their completion may add elements to HOME.
		*/
		if (jr->journal_inflight != 0) {
			return SPDK_POLLER_BUSY;
		}

		if (jr->failed || !jr->bs->is_leader) {
			/*
			* Journal instance is dead.
			*
			* Do not HOME or ZERO anything else.
			* Persistent journal recovery owns all remaining work.
			*/
			if (md_journal_discard_runtime_state(jr) != 0) {
				return SPDK_POLLER_BUSY;
			}

			md_journal_complete_home_waiters(jr, -ESHUTDOWN);
			spdk_poller_unregister(&jr->drain_poller);
			destroy_cb_fn = jr->destroy_cb_fn;
			bs = jr->bs;
			md_journal_free(jr);
			destroy_cb_fn(bs, 0);
			return -1;
		}

		/*
		* Continue ZERO processing.  This can also overlap an
		* active HOME batch.
		*/
		if (!jr->active_zero_batch && !TAILQ_EMPTY(&jr->zero_queue)) {
			spdk_md_journal_submit_zeroes(jr);
		}

		/*
		* Continue HOME processing for successfully journaled
		* elements.
		*/
		if (!jr->active_drain_batch && !TAILQ_EMPTY(&jr->home_queue)) {
			md_journal_start_drain_batch(jr, true);
		}

		md_journal_complete_home_waiters(jr, -ESHUTDOWN);

		if (!md_journal_can_destroy(jr)) {
			return SPDK_POLLER_BUSY;
		}

		spdk_poller_unregister(&jr->drain_poller);
		destroy_cb_fn = jr->destroy_cb_fn;
		bs = jr->bs;
		md_journal_free(jr);
		destroy_cb_fn(bs, 0);
		return -1;
	}

	if (jr->failed) {
		/*
		 * Fatal HOME/ZERO failure.
		 *
		 * No new requests are admitted and no more HOME/ZERO work
		 * is submitted. Journal writes that were already submitted
		 * are allowed to finish their own callbacks.
		 */
		return SPDK_POLLER_IDLE;
	}

	if (jr->paused) {
		return SPDK_POLLER_IDLE;
	}

	if (jr->seq_resetting) {

		/*
		* Return journal slots as aggressively as possible.
		*/
		if (!jr->active_zero_batch && !TAILQ_EMPTY(&jr->zero_queue)) {
			spdk_md_journal_submit_zeroes(jr);
		}

		/*
		* Existing journal writes must complete before the current
		* generation can be closed.
		*/
		if (jr->journal_inflight != 0) {
			return SPDK_POLLER_BUSY;
		}

		if (!jr->active_drain_batch && !TAILQ_EMPTY(&jr->home_queue)) {
			md_journal_start_drain_batch(jr, true);
		}

		if (!md_journal_can_reset_seq(jr)) {
			return SPDK_POLLER_BUSY;
		}

		if (md_journal_reset_seq(jr) != 0) {
			return SPDK_POLLER_BUSY;
		}

		jr->seq_resetting = false;

		SPDK_NOTICELOG("MD journal sequence rollover completed\n");

		/*
		* Continue below so queued metadata can now be admitted
		* using the new sequence generation.
		*/
	}

	/*
	 * First process waiting requests.
	 *
	 * If the FIFO head cannot be admitted, this sets
	 * force_home_drain.
	 */
	if (md_journal_process_waiting(jr)) {
		work = true;
	}

	/*
	 * ZERO returns slots to FREE and can overlap HOME.
	 */
	if (!jr->active_zero_batch && !TAILQ_EMPTY(&jr->zero_queue)) {
		if (spdk_md_journal_submit_zeroes(jr) == 0) {
			work = true;
		}
	}

	/*
	 * Only one HOME batch at a time.
	 */
	if (!jr->active_drain_batch && !TAILQ_EMPTY(&jr->home_queue)) {
		md_journal_start_drain_batch(jr, jr->force_home_drain);
		work = true;
	}


	return work ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

int
bs_md_journal_start(struct spdk_bs_md_journal *jr)
{
	if (jr == NULL || jr->bs == NULL || jr->drain_poller != NULL) {
		return -EINVAL;
	}

	jr->drain_poller = SPDK_POLLER_REGISTER(md_journal_drain_poller, jr, 1000);
	if (jr->drain_poller == NULL) {
		return -ENOMEM;
	}

	return 0;
}

static int
md_journal_init_elements(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;
	uint32_t i;

	jr->elems = calloc(BS_MD_JOURNAL_NUM_ELEMS, sizeof(*jr->elems));
	if (jr->elems == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
		elem = &jr->elems[i];
		
		elem->journal = jr;
		elem->slot = i;

		elem->hdr = spdk_zmalloc(BS_MD_JOURNAL_PAGE_SIZE, BS_MD_JOURNAL_PAGE_SIZE,
            NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);

		if (elem->hdr == NULL) {
			goto error;
		}

		elem->page = spdk_zmalloc(BS_MD_JOURNAL_PAGE_SIZE, BS_MD_JOURNAL_PAGE_SIZE,
			NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);

		if (elem->page == NULL) {
			goto error;
		}

		elem->journal_iov[0].iov_base = elem->hdr;
		elem->journal_iov[0].iov_len = BS_MD_JOURNAL_PAGE_SIZE;

		elem->journal_iov[1].iov_base = elem->page;
		elem->journal_iov[1].iov_len = BS_MD_JOURNAL_PAGE_SIZE;

		md_journal_elem_reset(elem);

		TAILQ_INSERT_TAIL(&jr->free_queue, elem, link);
		jr->free_count++;
	}

	return 0;

error:
	for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
		elem = &jr->elems[i];

		if (elem->hdr != NULL) {
			spdk_free(elem->hdr);
			elem->hdr = NULL;
		}

		if (elem->page != NULL) {
			spdk_free(elem->page);
			elem->page = NULL;
		}
	}

	free(jr->elems);
	jr->elems = NULL;

	return -ENOMEM;
}

int
bs_md_journal_examine_complete(struct spdk_bs_md_journal *jr)
{
	int rc;

	if (jr == NULL) {
		return -EINVAL;
	}

	if (!jr->examine || !jr->recovering) {
		return -EINVAL;
	}

	/*
	 * Examine no longer needs the journal overlay.
	 * Return to the normal smaller hash table.
	 */
	rc = md_journal_hash_resize(jr, BS_MD_JOURNAL_HASH_SIZE);
	if (rc != 0) {
		return rc;
	}

	jr->drain_batch->elem_count = 0;
	jr->zero_batch->elem_count = 0;

	jr->examine = false;
	jr->recovering = false;
	jr->paused = false;

	return 0;
}

static void
spdk_md_journal_update_zero_finished(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	int rc;

	jr->recovering = false;
	jr->drain_batch->elem_count = 0;

	if (bserrno != 0) {
		SPDK_ERRLOG("MD journal failover ZERO failed: rc=%d\n", bserrno);
		jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
		return;
	}

	/*
	 * Persistent journal is now clean.
	 * It is safe to rebuild/reset the runtime journal state.
	 */
	rc = bs_md_journal_reset(jr);
	if (rc != 0) {
		SPDK_ERRLOG("MD journal failover reset failed: rc=%d\n", rc);
		jr->update_cb_fn(seq, jr->update_cb_arg, rc);
		return;
	}

	jr->paused = false;

	if (jr->examine) {

		jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
		return;
	}

	SPDK_NOTICELOG("MD journal failover recovery completed.\n");
	jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
}

/* Second ZERO phase of the recovery: the newest slot per LBA. */
static void
spdk_md_journal_update_zero_latest(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint64_t journal_lba;
	uint64_t lba_count;
	uint32_t i;

	if (bserrno != 0) {
		spdk_md_journal_update_zero_finished(seq, jr, bserrno);
		return;
	}

	batch = bs_sequence_to_batch(seq, 0, spdk_md_journal_update_zero_finished, jr);

	lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);

	for (i = 0; i < jr->drain_batch->elem_count; i++) {
		elem = jr->drain_batch->items[i];
		if (md_journal_hash_get(jr, elem->hdr->target_lba) != elem) {
			continue;	/* superseded: already zeroed in the first phase */
		}
		journal_lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + ((uint64_t)elem->slot * jr->blocks_per_entry));

		jr->bs->w_io++;

		bs_batch_write_zeroes_dev(batch, journal_lba, lba_count);
	}

	bs_batch_close(batch);
}

static void
spdk_md_journal_update_home_finished(spdk_bs_sequence_t *seq,
				     void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint64_t journal_lba;
	uint64_t lba_count;
	uint32_t i;

	if (bserrno != 0) {
		SPDK_ERRLOG("MD journal failover HOME failed: rc=%d\n",
			    bserrno);

		jr->recovering = false;
		jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
		return;
	}

	/*
	* HOME is durable.
	*
	* Zero all valid persistent journal slots discovered during
	* recovery. Invalid/torn/CRC-bad slots are left untouched.
	*
	* Superseded entries are zeroed first, followed by the newest
	* entry for each target LBA.
	*/
	batch = bs_sequence_to_batch(seq, 0, spdk_md_journal_update_zero_latest, jr);

	lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);

	for (i = 0; i < jr->drain_batch->elem_count; i++) {
		elem = jr->drain_batch->items[i];
		if (md_journal_hash_get(jr, elem->hdr->target_lba) == elem) {
			continue; /* write zero the old LBA first */
		}
		journal_lba = bs_page_to_lba(jr->bs, jr->md_journal_mask_start + ((uint64_t)elem->slot * jr->blocks_per_entry));

		jr->bs->w_io++;

		bs_batch_write_zeroes_dev(batch, journal_lba, lba_count);
	}

	bs_batch_close(batch);
}


static void
spdk_md_journal_update_read_finished(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno)
{
	struct spdk_bs_md_journal *jr = cb_arg;
	struct md_journal_elem *elem;
	spdk_bs_batch_t *batch;
	uint32_t expected_crc;
	uint32_t valid_count = 0;
	uint32_t i;
	int rc = 0;

	if (bserrno != 0) {
		SPDK_ERRLOG("MD journal failover read failed: rc=%d\n", bserrno);
		goto error;
	}

	if (jr->examine) {
		rc = md_journal_hash_resize(jr, BS_MD_JOURNAL_EXAMINE_HASH_SIZE);
		if (rc != 0) {
			bserrno = rc;
			goto error;
		}
	} else {
		md_journal_hash_reset(jr);
	}

	jr->zero_batch->elem_count = 0;
	jr->drain_batch->elem_count = 0;
	for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
		elem = &jr->elems[i];

		/*
		 * Empty, partially written or incompatible entries are
		 * ignored.
		 */
		if (elem->hdr->magic != BS_MD_JOURNAL_MAGIC ||
		    elem->hdr->version != BS_MD_JOURNAL_VERSION ||
		    elem->hdr->hdr_len != BS_MD_JOURNAL_PAGE_SIZE ||
			elem->hdr->seq == 0 ||
    		elem->hdr->lba_count != jr->blocks_per_page) {
			if (jr->examine) {
				jr->zero_batch->items[jr->zero_batch->elem_count++] = elem;
			}
			continue;
		}

		expected_crc = elem->hdr->crc;

		if (expected_crc != md_journal_entry_calc_crc(elem->hdr, elem->page)) {
			SPDK_ERRLOG("MD journal failover CRC mismatch: slot=%u seq=%" PRIu64 "\n", i, elem->hdr->seq);
			continue;
		}

		/*
		 * Runtime elem->seq is normally assigned during admission.
		 * During recovery reconstruct it from the persistent header.
		 */
		elem->seq = elem->hdr->seq;

		jr->drain_batch->items[jr->drain_batch->elem_count++] = elem;

		valid_count++;
		int rc = md_journal_hash_insert(jr, elem);
		if (rc != 0) {
			SPDK_ERRLOG("MD journal failover hash insert failed: slot=%u seq=%" PRIu64 "\n", i, elem->hdr->seq);
			bserrno = rc;
			goto error;
		}
	}

	if (jr->examine) {
		jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
		return;
	}

	SPDK_NOTICELOG("MD journal failover scan: valid=%u total=%u\n", valid_count, BS_MD_JOURNAL_NUM_ELEMS);

	/*
	 * No valid entries still requires ZERO of the complete journal.
	 * Use the HOME completion as the transition to ZERO.
	 */
	if (valid_count == 0) {
		spdk_md_journal_update_home_finished(seq, jr, 0);
		return;
	}

	batch = bs_sequence_to_batch(seq, 0, spdk_md_journal_update_home_finished, jr);

	for (i = 0; i < jr->hash_size; i++) {
		elem = jr->hash_table[i].elem;
		if (!elem) {
			continue;
		}

		jr->bs->w_io++;

		bs_batch_write_dev(batch, elem->page, elem->hdr->target_lba, elem->hdr->lba_count);
	}

	bs_batch_close(batch);
	return;

error:
	jr->recovering = false;

	jr->update_cb_fn(seq, jr->update_cb_arg, bserrno);
}

int
bs_md_journal_recovery_on_failover(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, spdk_bs_sequence_cpl cb_fn, void *cb_arg, bool examine_flag)
{
	spdk_bs_batch_t *batch;
	struct md_journal_elem *elem;
	uint64_t journal_lba;
	uint64_t lba_count;
	uint32_t i;

	if (jr == NULL || seq == NULL || cb_fn == NULL) {
		return -EINVAL;
	}

	if (jr->recovering) {
		return -EBUSY;
	}

	/*
	 * Failover recovery must run with no runtime journal IO active.
	 *
	 * The caller guarantees metadata admission has already stopped.
	 */
	if (jr->journal_inflight != 0 || jr->active_drain_batch ||
	    jr->active_zero_batch) {
		SPDK_ERRLOG("Cannot start MD journal failover recovery: "
			    "journal_inflight=%u home_active=%d zero_active=%d\n",
			    jr->journal_inflight, jr->active_drain_batch, jr->active_zero_batch);
		return -EBUSY;
	}

	jr->update_cb_fn = cb_fn;
	jr->update_cb_arg = cb_arg;

	jr->recovering = true;
	jr->paused = true;
	jr->examine = examine_flag;

	batch = bs_sequence_to_batch(seq, 0, spdk_md_journal_update_read_finished, jr);

	lba_count = bs_byte_to_lba(jr->bs, BS_MD_JOURNAL_ENTRY_SIZE);

	/*
	 * Read every persistent journal slot into its permanent
	 * elem->{hdr,page} buffers.
	 */
	for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
		elem = &jr->elems[i];

		journal_lba = bs_page_to_lba( jr->bs, jr->md_journal_mask_start + ((uint64_t)i * jr->blocks_per_entry));

		bs_batch_readv_dev(batch, elem->journal_iov, 2, journal_lba, lba_count);
	}

	bs_batch_close(batch);

	return 0;
}

int
md_journal_confirm_home_drain(struct spdk_bs_md_journal *jr, uint64_t target_seq,
			      spdk_bs_sequence_t *seq, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	struct md_journal_home_waiter *waiter;

	if (jr == NULL || cb_fn == NULL) {
		return -EINVAL;
	}

	if (jr->failed) {
		return jr->failure_rc != 0 ? jr->failure_rc : -EIO;
	}

	if (jr->stopping) {
		return -ESHUTDOWN;
	}

	if (jr->paused) {
    	return -EIO;
	}

	/*
	 * Already HOME durable.
	 *
	 * I would still avoid calling cb_fn synchronously from here.
	 * More on this below.
	 */
	if (target_seq <= jr->home_durable_seq) {
		return 1;
	}

	waiter = calloc(1, sizeof(*waiter));
	if (waiter == NULL) {
		return -ENOMEM;
	}

	waiter->target_seq = target_seq;
	waiter->cb_fn = cb_fn;
	waiter->seq = seq;
	waiter->cb_arg = cb_arg;

	TAILQ_INSERT_TAIL(&jr->home_wait_queue, waiter, link);

	/*
	 * We explicitly need HOME progress now.
	 */
	jr->force_home_drain = true;

	return 0;
}

int
bs_md_journal_reset(struct spdk_bs_md_journal *jr)
{
	struct md_journal_elem *elem;
	uint32_t i;

	if (jr == NULL) {
		return -EINVAL;
	}

	/*
	 * Reset is only valid after all journal/HOME/ZERO IO has stopped.
	 */
	if (jr->journal_inflight != 0 ||
	    jr->active_drain_batch ||
	    jr->active_zero_batch) {
		SPDK_ERRLOG("Cannot reset MD journal: IO still active "
			    "journal_inflight=%u home_active=%d zero_active=%d\n",
			    jr->journal_inflight,
			    jr->active_drain_batch,
			    jr->active_zero_batch);
		return -EBUSY;
	}



	/*
	 * Requests in wait_queue have no element and no seq yet; they were
	 * queued while the recovery ran and are admitted by the poller with
	 * the new generation.
	 */
	md_journal_complete_home_waiters(jr, 0);
	// /*
	//  * There must not be requests waiting for journal slots.
	//  * The caller must stop admission before performing the
	//  * update/failover scan and reset.
	//  */
	// if (!TAILQ_EMPTY(&jr->wait_queue)) {
	// 	SPDK_ERRLOG("Cannot reset MD journal: wait queue is not empty\n");
	// 	return -EBUSY;
	// }

	/*
	 * At this point recovery/update must already have processed
	 * all persistent journal entries.
	 *
	 * We intentionally rebuild all runtime queues from scratch.
	 */
	TAILQ_INIT(&jr->free_queue);
	TAILQ_INIT(&jr->reorder_queue);
	TAILQ_INIT(&jr->home_queue);
	TAILQ_INIT(&jr->zero_queue);

	jr->free_count = 0;

	for (i = 0; i < BS_MD_JOURNAL_NUM_ELEMS; i++) {
		elem = &jr->elems[i];

		md_journal_elem_reset(elem);

		TAILQ_INSERT_TAIL(&jr->free_queue, elem, link);
		jr->free_count++;
	}

	/*
	 * Reset reusable HOME/ZERO batch state.
	 */
	if (jr->drain_batch != NULL) {
		memset(jr->drain_batch->items, 0, sizeof(jr->drain_batch->items));
		jr->drain_batch->elem_count = 0;
		jr->drain_batch->rc = 0;
		jr->drain_batch->journal = jr;
	}

	if (jr->zero_batch != NULL) {
		memset(jr->zero_batch->items, 0, sizeof(jr->zero_batch->items));
		jr->zero_batch->elem_count = 0;
		jr->zero_batch->rc = 0;
		jr->zero_batch->journal = jr;
	}

	/*
	 * Start a completely new logical journal generation.
	 *
	 * This is safe only because all old persistent slots were
	 * checked/handled before this reset.
	 */
	jr->next_seq = 1;
	jr->next_home_seq = 1;
	jr->home_durable_seq = 0;
	jr->journal_inflight = 0;

	jr->active_drain_batch = false;
	jr->active_zero_batch = false;
	jr->force_home_drain = false;

	/*
	 * Clear the fatal HOME/ZERO error state so metadata journaling
	 * can start again.
	 */
	jr->failed = false;
	jr->failure_rc = 0;
	jr->seq_resetting = false;

	SPDK_NOTICELOG("MD journal reset complete: seq=1 free=%u\n",
		       jr->free_count);

	return 0;
}

struct spdk_bs_md_journal *
bs_md_journal_create(struct spdk_blob_store *bs, uint64_t md_journal_mask_start, uint64_t md_journal_mask_len)
{
	struct spdk_bs_md_journal *jr;
	struct md_journal_drain_batch *drain_batch, *zero_batch;
	int rc;

	if (bs == NULL) {
		return NULL;
	}

	if (bs->dev->blocklen == 0 || BS_MD_JOURNAL_PAGE_SIZE % bs->dev->blocklen != 0) {
		SPDK_ERRLOG("Invalid block size %u for md journal\n", bs->dev->blocklen);
		return NULL;
	}

	jr = calloc(1, sizeof(*jr));
	if (jr == NULL) {
		return NULL;
	}

	jr->bs = bs;
	jr->md_journal_mask_start = md_journal_mask_start;
	jr->journal_mask_len = md_journal_mask_len;
	jr->blocks_per_page = BS_MD_JOURNAL_PAGE_SIZE / bs->dev->blocklen;
	jr->blocks_per_entry = BS_MD_JOURNAL_ENTRY_SIZE / bs->dev->blocklen;

	jr->seq_resetting = false;

	TAILQ_INIT(&jr->free_queue);
	TAILQ_INIT(&jr->reorder_queue);
	TAILQ_INIT(&jr->home_queue);
	TAILQ_INIT(&jr->zero_queue);

	TAILQ_INIT(&jr->wait_queue);

	TAILQ_INIT(&jr->home_wait_queue);

	jr->force_home_drain = false;

	struct spdk_bs_cpl home_cpl;
	home_cpl.type = SPDK_BS_CPL_TYPE_BLOB_BASIC;
	home_cpl.u.blob_basic.cb_fn = spdk_md_journal_homes_finished;
	home_cpl.u.blob_basic.cb_arg = jr;

	jr->home_seq = bs_sequence_start_bs(bs->md_channel, &home_cpl);
	if (jr->home_seq == NULL) {
		md_journal_free(jr);
		return NULL;
	}

	struct spdk_bs_cpl zero_cpl;
	zero_cpl.type = SPDK_BS_CPL_TYPE_BLOB_BASIC;
	zero_cpl.u.blob_basic.cb_fn = spdk_md_journal_zeroes_finished;
	zero_cpl.u.blob_basic.cb_arg = jr;

	jr->zero_seq = bs_sequence_start_bs(bs->md_channel, &zero_cpl);
	if (jr->zero_seq == NULL) {
		md_journal_free(jr);
		return NULL;
	}
	/*
	 * For a fresh journal.
	 *
	 * Recovery will replace these with values reconstructed
	 * from persistent entries.
	 */
	jr->next_seq = 1;
	jr->next_home_seq = 1;
	jr->home_durable_seq = 0;
	jr->next_drain_gen = 0;
	jr->free_count = 0;
	jr->journal_inflight = 0;

	jr->active_drain_batch = false;
	jr->active_zero_batch = false;

	jr->recovering = false;
	jr->stopping = false;
	jr->paused = false;
	jr->examine = false;
	jr->failed = false;
	jr->failure_rc = 0;

	rc = md_journal_init_elements(jr);
	if (rc != 0) {
		md_journal_free(jr);
		return NULL;
	}

	drain_batch = calloc(1, sizeof(*drain_batch));
	if (drain_batch == NULL) {
		md_journal_free(jr);
		return NULL;
	}
	drain_batch->journal = jr;
	jr->drain_batch = drain_batch;

	zero_batch = calloc(1, sizeof(*zero_batch));
	if (zero_batch == NULL) {
		md_journal_free(jr);
		return NULL;
	}
	zero_batch->journal = jr;
	jr->zero_batch = zero_batch;


	jr->hash_size = BS_MD_JOURNAL_HASH_SIZE;

	jr->hash_table = calloc(jr->hash_size, sizeof(jr->hash_table[0]));
	if (jr->hash_table == NULL) {
		md_journal_free(jr);
		return NULL;
	}

	return jr;
}

static void
md_journal_pause_msg(void *arg)
{
	struct spdk_blob_store *bs = arg;
	struct spdk_bs_md_journal *jr = bs->md_journal;

	if (jr == NULL || jr->recovering) {
		return;
	}
	jr->paused = true;
	md_journal_complete_home_waiters(jr, -EIO);
}

static void
bs_md_journal_pause(struct spdk_bs_md_journal *jr)
{
	if (spdk_get_thread() == jr->bs->md_thread) {
		md_journal_pause_msg(jr->bs);
	} else {
		spdk_thread_send_msg(jr->bs->md_thread, md_journal_pause_msg, jr->bs);
	}
}

void
bs_md_journal_leadership_change(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, bool old_state,
			    bool new_state, spdk_bs_sequence_cpl cb_fn, void *cb_arg)
{
	int rc;

	if (jr == NULL) {
		return;
	}

	if (!new_state) {
		/* demotion: may come from IO threads, needs no seq */
		bs_md_journal_pause(jr);	/* sets paused on the md thread */
		return;
	}

	/*
	 * Non-leader -> leader.
	 *
	 * Do NOT complete cb_fn here. Recovery owns the sequence
	 * and completes cb_fn after READ -> HOME -> ZERO -> RESET.
	 */
	if (!old_state && new_state) {
		rc = bs_md_journal_recovery_on_failover(jr, seq, cb_fn, cb_arg, false);
		if (rc != 0) {
			SPDK_ERRLOG("MD journal failover recovery failed: rc=%d\n", rc);
			cb_fn(seq, cb_arg, rc);
		}

		return;
	}

	/*
	 * Leader -> leader, nothing to do.
	 */
	cb_fn(seq, cb_arg, 0);
}

void
bs_md_journal_destroy(struct spdk_bs_md_journal *jr, spdk_blob_op_complete cb_fn)
{
	if (jr == NULL) {
		return;
	}

	if (jr->drain_poller == NULL) {	/* never started, nothing in flight */
		struct spdk_blob_store *bs = jr->bs;
		/* process_waiting only terminates requests when stopping */
		jr->stopping = true;
		md_journal_process_waiting(jr);
		md_journal_complete_home_waiters(jr, -ESHUTDOWN);
		md_journal_free(jr);
		cb_fn(bs, 0);
		return;
	}

	jr->stopping = true;
	jr->destroy_cb_fn = cb_fn;
}