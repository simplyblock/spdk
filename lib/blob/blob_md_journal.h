/* blob_md_journal.h */

#ifndef SPDK_BLOB_MD_JOURNAL_H
#define SPDK_BLOB_MD_JOURNAL_H

#include "spdk/stdinc.h"
#include "spdk/blob.h"
#include "request.h"

#define BS_MD_JOURNAL_PAGE_SIZE           4096u
#define BS_MD_JOURNAL_ENTRY_SIZE          8192u
#define BS_MD_JOURNAL_NUM_ELEMS           8192u

/*
 * Maximum number of ordered journal elements handled by one home drain batch.
 *
 * Only one drain batch is active at a time.
 */
#define BS_MD_JOURNAL_DRAIN_BATCH_SIZE	1000u


#define BS_MD_JOURNAL_MAGIC               0x4D444A32u
#define BS_MD_JOURNAL_VERSION             1u
#define BS_MD_JOURNAL_SHUTDOWN_MAX_RETRIES 3

#define BS_MD_JOURNAL_SEQ_RESET_THRESHOLD  (UINT64_MAX - BS_MD_JOURNAL_NUM_ELEMS)

struct spdk_bs_md_journal;
struct md_journal_elem;
struct md_journal_batch;
struct md_journal_drain_batch;


#define BS_MD_JOURNAL_HASH_SIZE		(BS_MD_JOURNAL_NUM_ELEMS * 2)
#define BS_MD_JOURNAL_EXAMINE_HASH_SIZE	65536u

SPDK_STATIC_ASSERT(
	(BS_MD_JOURNAL_HASH_SIZE & (BS_MD_JOURNAL_HASH_SIZE - 1)) == 0,
	"MD journal hash size must be power of two");

SPDK_STATIC_ASSERT(
	(BS_MD_JOURNAL_EXAMINE_HASH_SIZE &
	 (BS_MD_JOURNAL_EXAMINE_HASH_SIZE - 1)) == 0,
	"MD journal examine hash size must be power of two");

struct md_journal_hash_entry {
	struct md_journal_elem *elem;
};

enum md_journal_op_type {
	MD_JOURNAL_WRITE = 0,
	MD_JOURNAL_WRITE_ZEROS,
};

/*
 * Persistent 4 KiB header.
 *
 * The second 4 KiB of the 8 KiB journal element contains the metadata page.
 */
struct md_journal_entry_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t hdr_len;

	uint8_t io_priority;
	uint8_t io_geometry;
	uint8_t io_special;
	uint8_t type;
	uint32_t crc;

	uint64_t seq;

	uint64_t target_lba;

	uint64_t lba_count;

	uint8_t reserved[BS_MD_JOURNAL_PAGE_SIZE - 41];
};

SPDK_STATIC_ASSERT(sizeof(struct md_journal_entry_hdr) == BS_MD_JOURNAL_PAGE_SIZE, "md journal header must be 4 KiB");


enum md_journal_elem_state {
	MD_JOURNAL_ELEM_FREE = 0,

	/* 8 KiB journal write has been submitted. */
	MD_JOURNAL_ELEM_JOURNAL_INFLIGHT,

	/*
	 * Journal write completed, but an earlier sequence is still
	 * outstanding. The element waits in the ordered/reorder queue.
	 */
	MD_JOURNAL_ELEM_JOURNAL_DONE,

	/* Element has reached sequence order and is waiting for drain. */
	MD_JOURNAL_ELEM_HOME_PENDING,

	/* Element belongs to the currently active home drain batch. */
	MD_JOURNAL_ELEM_HOME_INFLIGHT,

	/* Home batch completed; journal slot needs clearing. */
	MD_JOURNAL_ELEM_ZERO_PENDING,

	/* Journal slot zero IO is outstanding. */
	MD_JOURNAL_ELEM_ZERO_INFLIGHT,
	MD_JOURNAL_ELEM_JOURNAL_FAILED,
};


typedef void (*bs_md_journal_write_cb)(void *cb_arg, int bserrno);

typedef void (*bs_md_journal_batch_cb)(spdk_bs_sequence_t *seq, void *cb_arg, int bserrno);

struct md_journal_elem {

	struct spdk_bs_md_journal *journal;

	uint32_t slot;
	enum md_journal_elem_state state;

	/*
	 * Logical ordering number.
	 *
	 * Assigned when the element is admitted for journal write,
	 * not when the journal IO completes.
	 */
	uint64_t seq;
	spdk_bs_sequence_t *bs_seq;

	struct spdk_bs_io_opts io_opts;

	/*
	 * Permanent DMA buffers:
	 *
	 * journal_iov[0] -> 4 KiB header
	 * journal_iov[1] -> 4 KiB metadata page
	 */
	struct md_journal_entry_hdr *hdr;
	void *page;

	struct iovec journal_iov[2];

	/*
	 * Used by the journal/home/zero asynchronous operations.
	 */
	// struct spdk_bs_dev_cb_args journal_cb_args;
	// struct spdk_bs_dev_cb_args home_cb_args;
	// struct spdk_bs_dev_cb_args zero_cb_args;

	/*
	 * Single-write completion.
	 *
	 * For batch writes this is normally NULL; completion belongs
	 * to batch_ctx instead.
	 */
	spdk_bs_sequence_cpl cb_fn;
	void *cb_arg;

	/*
	 * Set by drain batching when a newer element for the same
	 * target LBA exists inside the same batch.
	 */
	bool skip_home;

    TAILQ_ENTRY(md_journal_elem) link;
};

struct md_journal_op {
	void *payload;
	uint64_t lba;
	uint64_t lba_count;
	enum md_journal_op_type type;
	struct md_journal_elem *elemt;
};

struct md_journal_batch {
	spdk_bs_sequence_t *seq;
	struct spdk_bs_md_journal *journal;
	struct md_journal_op *entry;
	uint32_t count;
	bool closed;
	uint32_t capacity;
	/*
	* Error recorded while building the batch.
	*/
	int rc;

	bs_md_journal_batch_cb cb_fn;
	void *cb_arg;
};

enum md_journal_wait_type {
	MD_JOURNAL_WAIT_SINGLE = 0,
	MD_JOURNAL_WAIT_BATCH,
};

struct md_journal_wait_req {
	enum md_journal_wait_type type;
	struct spdk_bs_md_journal *journal;
	struct md_journal_op entry;
	spdk_bs_sequence_t *seq;
	spdk_bs_sequence_cpl cb_fn;
	void *cb_arg;
	struct md_journal_batch *batch;
	TAILQ_ENTRY(md_journal_wait_req) link;
};

TAILQ_HEAD(md_journal_wait_queue, md_journal_wait_req);

struct md_journal_drain_batch {
	struct spdk_bs_md_journal *journal;

	struct md_journal_elem *items[BS_MD_JOURNAL_NUM_ELEMS];

	/*
	 * Number of journal elements consumed from home_queue.
	 *
	 * This includes elements that are skipped because a newer
	 * version of the same LBA exists in this batch.
	 */
	uint32_t elem_count;

	/*
	* Error recorded while building the batch.
	*/
	int rc;
};

TAILQ_HEAD(md_journal_elem_queue, md_journal_elem);

struct spdk_bs_md_journal {
	struct spdk_bs_dev *dev;
	struct spdk_blob_store *bs;
	struct spdk_io_channel *md_channel;
	spdk_bs_sequence_t *home_seq;
	spdk_bs_sequence_t *zero_seq;
	/*
	 * Physical location of the journal.
	 */
	uint64_t md_journal_mask_start;
	uint64_t journal_mask_len;
	uint32_t blocks_per_page;
	uint32_t blocks_per_entry;

	/*
	 * Sequence assigned to the next admitted metadata write.
	 */
	uint64_t next_seq;

	/*
	 * Next sequence that may enter home_queue.
	 */
	uint64_t next_home_seq;

	/*
	 * Permanent journal elements.
	 */
	struct md_journal_elem *elems;

	/* Temporary sortable references to those elements. */
	struct md_journal_hash_entry *hash_table;
	uint32_t hash_size;
	/*
	 * Journal slots available for new metadata writes.
	 */
	struct md_journal_elem_queue free_queue;

	/*
	* Completed journal writes, successful or failed,
	* waiting to be released in sequence order.
	*/
	struct md_journal_elem_queue reorder_queue;

	/*
	 * Journal elements in correct sequence order and ready for
	 * home draining.
	 */
	struct md_journal_elem_queue home_queue;

	/*
	 * Home-durable elements whose journal slots need zeroing.
	 */
	struct md_journal_elem_queue zero_queue;

	struct md_journal_wait_queue wait_queue;

	/*
	* Set when the head of wait_queue cannot be admitted because
	* there are not enough FREE journal elements.
	*/
	bool force_home_drain;

	uint32_t free_count;

	uint32_t journal_inflight;

	/*
	 * Exactly one home drain batch can exist at a time.
	 */
	bool active_drain_batch;
	bool active_zero_batch;

	struct md_journal_drain_batch  *drain_batch;
	struct md_journal_drain_batch  *zero_batch;

	struct spdk_poller *drain_poller;

	spdk_bs_sequence_cpl update_cb_fn;
	void *update_cb_arg;

	bool recovering;
	bool examine;
	bool stopping;
	/*
	 * Fatal HOME/ZERO IO failure.
	 *
	 * Once set, no new metadata writes are admitted and no further
	 * HOME/ZERO processing is performed.
	 */
	bool failed;
	int failure_rc;
	bool seq_resetting;

};

struct spdk_bs_md_journal * bs_md_journal_create(struct spdk_blob_store *bs,
					uint64_t md_journal_mask_start, uint64_t md_journal_mask_len);

int bs_md_journal_reset(struct spdk_bs_md_journal *jr);

int bs_md_journal_start(struct spdk_bs_md_journal *jr);

void bs_md_journal_destroy(struct spdk_bs_md_journal *jr);

void bs_md_journal_batch_close(struct md_journal_batch *batch);

void bs_md_journal_batch_write(struct md_journal_batch *batch, void *payload,
	 			uint64_t lba, uint32_t lba_count, enum md_journal_op_type type);

struct md_journal_batch * bs_md_journal_sequence_to_batch(struct spdk_bs_md_journal *jr,
	 		spdk_bs_sequence_t *seq, uint16_t capacity, spdk_bs_sequence_cpl cb_fn, void *cb_arg);

void bs_md_journal_write(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, void *payload,
		    uint64_t lba, uint32_t lba_count, spdk_bs_sequence_cpl cb_fn, void *cb_arg, enum md_journal_op_type type);

struct md_journal_batch * bs_md_journal_sequence_to_batch(struct spdk_bs_md_journal *jr,
			spdk_bs_sequence_t *seq, uint16_t capacity, spdk_bs_sequence_cpl cb_fn, void *cb_arg);

int bs_md_journal_examine_complete(struct spdk_bs_md_journal *jr);

int
bs_md_journal_recovery_on_failover(struct spdk_bs_md_journal *jr, spdk_bs_sequence_t *seq, spdk_bs_sequence_cpl cb_fn, void *cb_arg, bool examine_flag);

bool bs_md_journal_read_on_examine(struct spdk_bs_md_journal *jr, uint64_t target_lba, void *payload);


#endif /* SPDK_BLOB_MD_JOURNAL_H */