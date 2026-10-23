/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_INTERNAL_LVOLSTORE_H
#define SPDK_INTERNAL_LVOLSTORE_H

#include "spdk/blob.h"
#include "spdk/lvol.h"
#include "spdk/queue.h"
#include "spdk/tree.h"
#include "spdk/uuid.h"

/* Default size of blobstore cluster */
#define SPDK_LVS_OPTS_CLUSTER_SZ (4 * 1024 * 1024)

/* UUID + '_' + blobid (20 characters for uint64_t).
 * Null terminator is already included in SPDK_UUID_STRING_LEN. */
#define SPDK_LVOL_UNIQUE_ID_MAX (SPDK_UUID_STRING_LEN + 1 + 20)

struct spdk_lvs_req {
	spdk_lvs_op_complete    cb_fn;
	void                    *cb_arg;
	struct spdk_lvol_store		*lvol_store;
	struct spdk_poller *poller;
	int				lvserrno;
	bool			destroy;
	bool            lvs_state;
};

struct spdk_lvol_update_on_failover_req {
	// spdk_lvs_op_complete    cb_fn_lvs;
	// void                    *cb_arg_lvs;		
	spdk_lvol_op_complete   cb_fn;
	void                    *cb_arg;
	struct spdk_lvol_store		*lvol_store;
	struct spdk_lvol		*lvol;
	int				lvserrno;
};

struct spdk_lvs_grow_req {
	struct spdk_lvs_req	base;
	spdk_lvs_op_complete	cb_fn;
	void			*cb_arg;
	struct lvol_store_bdev	*lvs_bdev;
	int			lvol_cnt;
};

struct spdk_lvol_req {
	spdk_lvol_op_complete   cb_fn;
	void                    *cb_arg;
	struct spdk_lvol	*lvol;
	struct spdk_poller *poller;
	/* Only set while lvol is being deleted and has a clone. */
	struct spdk_lvol	*clone_lvol;
	size_t			sz;
	struct spdk_io_channel	*channel;
	bool			md_ro;
	char			name[SPDK_LVOL_NAME_MAX];
	int 	rc;
};

struct spdk_lvol_copy_req {
	spdk_lvol_op_complete	cb_fn;
	void			*cb_arg;
	struct spdk_lvol	*lvol;
	struct spdk_io_channel	*channel;
	struct spdk_bs_dev	*ext_dev;
};

struct spdk_lvs_with_handle_req {
	spdk_lvs_op_with_handle_complete cb_fn;
	void				*cb_arg;
	struct spdk_lvol_store		*lvol_store;
	struct spdk_bs_dev		*bs_dev;
	struct spdk_bdev		*base_bdev;
	int				lvserrno;
	bool 			examine;
};

struct spdk_lvs_destroy_req {
	spdk_lvs_op_complete    cb_fn;
	void                    *cb_arg;
	struct spdk_lvol_store	*lvs;
};

struct spdk_lvol_with_handle_req {
	spdk_lvol_op_with_handle_complete cb_fn;
	void				*cb_arg;
	FILE *fp;
	int lvol_priority_class;
	struct spdk_poller *poller;
	int force_failure;
	int frozen_refcnt;
	struct spdk_lvol		*lvol;
	struct spdk_lvol		*origlvol;
};

struct spdk_lvol_bs_dev_req {
	struct spdk_lvol	*lvol;
	struct spdk_bs_dev	*bs_dev;
	spdk_lvol_op_complete	cb_fn;
	void			*cb_arg;
};

struct spdk_lvs_degraded_lvol_set;

struct spdk_pending_iorsp {
	struct spdk_bdev_io *bdev_io;
	struct spdk_thread	*thread;
	TAILQ_ENTRY(spdk_pending_iorsp)	entry;
};

struct spdk_migrate_io {
	struct spdk_bdev_io *bdev_io;
	struct spdk_io_channel *ch;
	struct spdk_thread	*thread;
	spdk_lvol_op_migrate_complete cb_fn;
	TAILQ_ENTRY(spdk_migrate_io)	entry;
};

struct spdk_redirect_request {
	struct spdk_bdev_io *bdev_io;
	struct spdk_io_channel *ch;
	uint64_t io_count;
	TAILQ_ENTRY(spdk_redirect_request)	entry;
};

struct spdk_lvs_redirect {
	struct spdk_lvol *lvol[65535];
};

struct spdk_redirect_dev {
	struct spdk_bdev_desc	*desc;
	struct spdk_thread		*thread;
	struct spdk_poller *cleanup_poller;
	uint64_t redirected_io_count;
	enum hublvol_state	state;
	spdk_drain_op_submit_handle	submit_cb;
	bool dev_in_remove;
	bool drain_in_action;
};

enum xfer_status {
	XFER_NONE = 0,
	XFER_IN_PROGRESS,
	XFER_DONE,
	XFER_FAILED,
};

struct spdk_transfer_dev {
	struct spdk_bdev_desc	*desc;
	bool is_s3;
	char bdev_name[SPDK_LVOL_NAME_MAX];
	struct spdk_thread		*thread;
	struct spdk_poller *cleanup_poller;
	enum hublvol_state	state;
	uint64_t redirected_io_count;
	bool dev_in_remove;
	bool drain_in_action;
	int pg[20];
	struct spdk_hublvol_channels *current_channel;
	TAILQ_HEAD(, spdk_hublvol_channels)	redirect_channels;
	struct spdk_lvol_store	*lvs;
	TAILQ_ENTRY(spdk_transfer_dev)	entry;
};

struct remote_lvol_info {
	bool status; // true - connected, false - disconnected
	enum xfer_type   type;
	struct spdk_transfer_dev *tdev;
	struct spdk_bdev_desc	*desc;
	struct spdk_io_channel	*channel;
	struct spdk_io_channel	*md_channel;
	struct spdk_lvs_poll_group *group;
	struct spdk_poller *cleanup_poller;
	struct spdk_poller *abort_inflight_poller;
	struct spdk_lvs_xfer *xfer_task;
	/* Copied from the owning xfer at creation (not derived through xfer_task,
	 * whose lifetime ends before this entry's cleanup poller runs): requests
	 * of a freeze-critical FINAL transfer are dispatched before any other. */
	bool priority;
	uint64_t outstanding_io;
	struct spdk_ring *free_ring;     /* tasks available for this snapshot */
    struct spdk_ring *ready_ring;    /* tasks ready to send to remote lvol */
	TAILQ_ENTRY(remote_lvol_info)	entry;
};

struct lvolstore_info {
	struct spdk_lvol_store	*lvs;
	struct spdk_io_channel	*md_channel;
	bool status; // true - connected, false - disconnected
};

struct remote_dev_info {
	struct spdk_transfer_dev *tdev;
	struct spdk_io_channel	*tdev_channel;
	TAILQ_ENTRY(remote_dev_info)	entry;// channel and tdev
};

struct spdk_lvs_poll_group {
	TAILQ_HEAD(, remote_lvol_info)	rmt_lvols;
	struct lvolstore_info lvs_info[4];
	int lvs_cnt;
	// struct spdk_lvs_poll_group	*next;
	struct spdk_thread	*thread;
	// struct spdk_thread	*md_thread;
	// struct spdk_poller 	*xfer_poller;
	const char *thread_name;
	int id;
	TAILQ_ENTRY(spdk_lvs_poll_group) entry;
	TAILQ_HEAD(, remote_dev_info)	ch_tdev;	
};



/*
 * Transfer command: a special write of SPDK_LVOL_XFER_CMD_BLOCKS blocks at
 * offset 0 of the destination lvol, sent through the transfer hub (migration
 * and replication).
 *
 * The destination takes such a write as a command only when magic, name,
 * version, type and count are all valid; anything else is written as normal
 * data. One command fills exactly SPDK_LVOL_XFER_CMD_SIZE bytes.
 */
#define SPDK_LVOL_XFER_CMD_MAGIC	0x444D43584C4F564CULL	/* "LVOLXCMD" */
#define SPDK_LVOL_XFER_CMD_NAME		"xfer_cmd:alloc_clusters"
#define SPDK_LVOL_XFER_CMD_VERSION	1
#define SPDK_LVOL_XFER_CMD_BLOCK_SIZE	4096
#define SPDK_LVOL_XFER_CMD_BLOCKS	8
#define SPDK_LVOL_XFER_CMD_SIZE		(SPDK_LVOL_XFER_CMD_BLOCKS * SPDK_LVOL_XFER_CMD_BLOCK_SIZE)

enum spdk_lvol_xfer_cmd_type {
	/* Allocate the listed cluster indexes on the destination blob. */
	SPDK_LVOL_XFER_CMD_ALLOC_CLUSTERS = 1,
};

struct spdk_lvol_xfer_cmd_hdr {
	uint64_t	magic;		/* SPDK_LVOL_XFER_CMD_MAGIC */
	char		name[32];	/* SPDK_LVOL_XFER_CMD_NAME, NUL padded */
	uint16_t	version;	/* SPDK_LVOL_XFER_CMD_VERSION */
	uint16_t	type;		/* enum spdk_lvol_xfer_cmd_type */
	uint32_t	count;		/* entries that follow the header */
	uint32_t	reserved[4];
	uint32_t	entries[];	/* cluster indexes */
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_lvol_xfer_cmd_hdr) == 64, "Incorrect size");

/* (32 KiB - 64) / 4 = 8176 clusters per command */
#define SPDK_LVOL_XFER_CMD_MAX_ENTRIES \
	((SPDK_LVOL_XFER_CMD_SIZE - sizeof(struct spdk_lvol_xfer_cmd_hdr)) / sizeof(uint32_t))

struct spdk_lvs_xfer_req {
	enum xfer_req_status status;
	enum xfer_type   type;
	enum req_action action;
	uint64_t offset;
	uint64_t dst_offset;
	uint64_t len;
	void *payload;
	int fragments_outstanding;
	int aggregated_status;
	/* A dirty range of a cluster (partial transfer): every block of it is
	 * written, zeroes included -- the destination's merge takes every block
	 * NOT written from the base, so a skipped zero block would read the
	 * base's old data. */
	bool partial;
	struct remote_lvol_info *rmt_lvol;
	struct spdk_lvs_xfer *xfer;
	TAILQ_ENTRY(spdk_lvs_xfer_req)	entry;
};

struct spdk_lvs_xfer {
	struct spdk_lvs_xfer **list_task;
	bool waiting_for_sub_tasks;
	int num_sub_tasks;
	struct spdk_lvol		*lvol;
	struct spdk_lvs_xfer_req *reqs;
	void *pdus;
	struct spdk_ring *free_ring;     /* tasks available for this snapshot */
    struct spdk_ring *ready_ring;    /* tasks ready to send to remote lvol */
	enum xfer_type   type;
	int	cluster_batch;
	uint32_t outstanding_io;
	uint64_t current_offset;
	uint64_t timeout;
	uint64_t terminate_timeout;     /* the task will be terminated after this time*/
	struct spdk_poller 	*tmo_poller;
	// char bdev_name[SPDK_LVOL_NAME_MAX];
	char snapshot_name[SPDK_LVOL_NAME_MAX];
	int len;
	spdk_lvol_op_with_handle_complete	cb_fn;
	void *cb_arg;
	bool pg[20];
	bool final_step;
	bool signal_sent;
	/* Freeze-critical transfer (final migration step / final replication
	 * delta): dispatched with absolute priority; while one is active, the
	 * dispatcher pauses refilling every non-priority transfer window. */
	bool priority;
	bool priority_counted;
	/* IO priority class of the transfer's reads of the source blob, so the
	 * reads are scheduled apart from client IO that reaches the same blob
	 * (reads of a volume fall through to its snapshots). 0 keeps the blob's
	 * own class. */
	uint8_t priority_class;

	TAILQ_ENTRY(spdk_lvs_xfer)	entry;

	uint64_t page_size;
	uint64_t page_per_cluster;

	//related to s3 backup
	enum xfer_state   state;

	//: The transfer device (S3 bdev) this task is bound to. Used to reject a
	//: second backup/recovery/merge task against a lvstore's tdev while one is
	//: already in flight -- concurrent transfers sharing a tdev corrupt the
	//: shared channel/descriptor state.
	struct spdk_transfer_dev *tdev;

	struct spdk_lvol  **chain;
	uint32_t *chain_s3_ids;
	uint32_t chain_count;

	uint64_t *clusters;
	uint32_t num_clusters;

	uint64_t *old_clusters;
	uint32_t old_num_clusters;

	uint32_t num_extent_pages;
	uint32_t old_num_extent_pages;

	uint32_t s3_id;
	uint32_t old_s3_id;
	uint32_t success_cnt;

	uint32_t hold_idx;
	uint32_t idx;
	bool persist_swap;
	uint32_t timeout_cnt;

	/* XFER_STATE_ALLOC_CLUSTERS: next clusters[] index to put in a command,
	 * and the number of commands sent. */
	uint32_t alloc_next;
	uint32_t alloc_cmds;

	/* Partial (dirty-bitmap) replication, see xfer_setup_partial. dirty_gen
	 * is the snapshot's generation, pinned for the task's lifetime.
	 * partial[i] marks the clusters sent as dirty ranges; the destination
	 * pre-allocates them like any other and fills what was not sent from the
	 * base after the transfer (spdk_blob_merge_base). ranges[range_pos..num_ranges) of
	 * range_cluster are still to send, range_done blocks of the current one
	 * already sent, in requests of at most XFER_PARTIAL_MAX_BYTES. */
	bool allow_partial;
	struct blob_dirty_gen *dirty_gen;
	uint8_t *partial;
	struct blob_dirty_range *ranges;
	uint32_t max_ranges;
	uint32_t num_ranges;
	uint32_t range_pos;
	uint32_t range_done;
	uint64_t range_cluster;
	uint64_t partial_clusters;
	/* The destination may hold non-zero content in clusters this task did
	 * not just allocate (a resumed transfer skips the allocation step), so
	 * zero ranges must be written too. */
	bool no_zero_skip;
};

struct spdk_lvol_store {
	struct spdk_bs_dev		*bs_dev;
	struct spdk_blob_store		*blobstore;
	struct spdk_blob		*super_blob;
	spdk_blob_id			super_blob_id;
	struct spdk_uuid		uuid;
	int				lvol_count;
	uint8_t				id;
	int				lvols_opened;
	TAILQ_HEAD(, spdk_lvol)		lvols;
	TAILQ_HEAD(, spdk_lvol)		pending_lvols;
	TAILQ_HEAD(, spdk_lvol)		retry_open_lvols;
	TAILQ_HEAD(, spdk_lvol)		pending_update_lvols;
	TAILQ_HEAD(, spdk_pending_iorsp)   pending_iorsp;
	TAILQ_HEAD(, spdk_lvol)		pending_delete_requests;
	TAILQ_HEAD(, spdk_hublvol_channels)	hublvol_channels;
	TAILQ_HEAD(, spdk_transfer_dev)	transfer_devs;
	bool is_deletion_in_progress;
	bool				queue_failed_rsp;
	bool				on_failed_rsp;
	bool				load_esnaps;
	bool				on_list;
	TAILQ_ENTRY(spdk_lvol_store)	link;
	char				name[SPDK_LVS_NAME_MAX];
	char				new_name[SPDK_LVS_NAME_MAX];
	spdk_bs_esnap_dev_create	esnap_bs_dev_create;
	RB_HEAD(degraded_lvol_sets_tree, spdk_lvs_degraded_lvol_set)	degraded_lvol_sets_tree;
	struct spdk_thread		*thread;
	bool				leader;
	bool				update_in_progress;
	bool				failed_on_update;
	int  retry_on_update;
	uint64_t			groupid;
	uint64_t			leadership_timeout;
	uint64_t			timeout_trigger;
	bool 				trigger_leader_sent;
	bool				special_send_signal;
	/* Two-node arbitration (sbcli docs/design/two-node-arbitration.md):
	 * ha_held: client writes are held in the frozen-IO queue awaiting a verdict;
	 * ha_fenced: the LVS was fenced; its client port stays blocked (the hublvol port is
	 *            never blocked by the fence, so the returning peer can reconnect);
	 * ha_demoted: set when the control plane demotes the LVS (spdk_set_leader_all with
	 *            leader=false), cleared on promotion; consumed by spdk_lvs_ha_take_demoted;
	 * ha_fence_port: the client port this LVS's fence blocked and therefore owns (0: the
	 *            fence blocked nothing of its own, e.g. the port was already blocked by
	 *            someone else). spdk_lvs_ha_unfence lifts only this block. */
	bool				ha_held;
	bool				ha_fenced;
	bool				ha_demoted;
	int				ha_fence_port;
	/* ha_takeover_blocked: set by the fence; while set, IO on this LVS never starts a
	 *            leadership takeover (lvstore update on failover). Only an explicit
	 *            leadership set by the control plane (bdev_lvol_set_leader) clears it.
	 *            Until then such IO completes with an ANA-inaccessible path error. */
	bool				ha_takeover_blocked;
	/* ha_ana_restore_port: client port whose listeners' ANA state the fence set to
	 *            inaccessible and that waits for the control plane's leadership set
	 *            before it is restored (primary role only: a primary that does not lead
	 *            cannot redirect, so it must not look accessible before that). */
	int				ha_ana_restore_port;
	bool 				read_only;
	bool				skip_redirecting;
	node_role_t 		node_role;
	int 				subsystem_port;
	int 				hublvol_port;
	struct spdk_poller *redirect_poller;
	struct spdk_poller *hublvol_poller;
	uint64_t			total_io;
	uint64_t			current_io;
	uint64_t			current_io_t;
	struct spdk_lvs_redirect lvol_map;	
	struct spdk_redirect_dev hub_dev;
	char	remote_bdev[SPDK_LVOL_NAME_MAX];
};

struct spdk_lvol {
	struct spdk_lvol_store		*lvol_store;
	struct spdk_blob		*blob;
	struct spdk_blob		*tmp_blob;
	spdk_blob_id			blob_id;
	uint16_t		map_id;
	bool				leader;
	bool				update_in_progress;
	bool				hublvol;
	
	bool				failed_on_update;
	bool				deletion_failed;
	bool				migration_flag;
	int					failed_rc;
	uint8_t				deletion_status; // 0 - not started, 1 - started, 2 - completed
	char				unique_id[SPDK_LVOL_UNIQUE_ID_MAX];
	char				name[SPDK_LVOL_NAME_MAX];
	struct spdk_uuid		uuid;
	char				uuid_str[SPDK_UUID_STRING_LEN];
	int priority_class;
	struct spdk_bdev		*bdev;
	/* An NVMe-oF reservation state kept in the blob's xattr, as last read or
	 * written on the lvolstore's thread (vbdev_lvol.c) */
	void				*resv_cache;
	size_t				resv_cache_len;
	int				ref_count;
	bool				action_in_progress;
	enum blob_clear_method		clear_method;
	TAILQ_ENTRY(spdk_lvol)		link;
	TAILQ_ENTRY(spdk_lvol)		entry_to_update;
	TAILQ_ENTRY(spdk_lvol)		entry_to_delete;
	struct spdk_lvs_degraded_lvol_set *degraded_set;
	TAILQ_ENTRY(spdk_lvol)		degraded_link;
	// TAILQ_HEAD(, spdk_pending_iorsp)   redirected_io;
	TAILQ_HEAD(, spdk_migrate_io)   redirect_migrate_io;
	struct spdk_transfer_dev *tdev;
	uint16_t		redirect_map_id;
	bool			redirect_failed;
	bool			freezed;
	bool			redirect_io;

	enum xfer_status transfer_status;
	uint64_t last_offset;
	/* stats of the most recent transfer: how many requests went out as
	 * bitmap-driven partial ranges vs whole clusters (dirty-bitmap
	 * replication; reset when a transfer starts) */
	/* bdev_lvol_merge_base job (destination of a partial transfer): it
	 * takes longer than an RPC may, so the RPC starts it and
	 * bdev_lvol_merge_base_stat reports it. */
	enum spdk_lvol_merge_state {
		LVOL_MERGE_NONE = 0,
		LVOL_MERGE_RUNNING,
		LVOL_MERGE_DONE,
		LVOL_MERGE_FAILED,
	} merge_state;
	int merge_rc;
	struct spdk_blob_merge_stats merge_stats;
	uint64_t merge_start_ticks;
	uint64_t merge_ms;
	uint64_t xfer_partial_reqs;
	uint64_t xfer_full_clusters;
	uint64_t xfer_pages_sent;
	uint64_t current_offset;
};

struct lvol_store_bdev *vbdev_lvol_store_first(void);
struct lvol_store_bdev *vbdev_lvol_store_next(struct lvol_store_bdev *prev);
void spdk_change_redirect_state(struct spdk_lvol_store *lvs, bool disconnected);
void spdk_lvs_store_hublvol_channel(struct spdk_lvol_store *lvs, struct spdk_io_channel *ch);
void spdk_trigger_failover(struct spdk_lvol_store *lvs);
void spdk_lvol_resize(struct spdk_lvol *lvol, uint64_t sz, spdk_lvol_op_complete cb_fn,
		      void *cb_arg);
void spdk_lvol_resize_unfreeze(struct spdk_lvol *lvol, spdk_lvol_op_complete cb_fn, void *cb_arg);
void spdk_lvol_resize_register(struct spdk_lvol *lvol, uint64_t sz,
		 spdk_lvol_op_complete cb_fn, void *cb_arg);

int spdk_lvol_register_live(struct spdk_lvol_store *lvs, const char *name, const char *uuid_str, uint64_t blobid,
		 bool thin_provision, enum lvol_clear_method clear_method, spdk_lvol_op_with_handle_complete cb_fn,
		 void *cb_arg);

void spdk_lvol_set_read_only(struct spdk_lvol *lvol, spdk_lvol_op_complete cb_fn,
			     void *cb_arg);

int spdk_lvs_esnap_missing_add(struct spdk_lvol_store *lvs, struct spdk_lvol *lvol,
			       const void *esnap_id, uint32_t id_len);
void spdk_lvs_esnap_missing_remove(struct spdk_lvol *lvol);
bool spdk_lvs_notify_hotplug(const void *esnap_id, uint32_t id_len,
			     spdk_lvol_op_with_handle_complete cb_fn, void *cb_arg);

#define S3_INDEX_BITS     32
#define S3_MID_FLAG_BIT   32
#define S3_ID_BITS        30
#define S3_ID_SHIFT       33
#define S3_MSB_FLAG_BIT   63

#define S3_INDEX_MASK    ((1ULL << S3_INDEX_BITS) - 1ULL)
#define S3_ID_MASK        ((1ULL << S3_ID_BITS) - 1ULL)

static inline uint64_t
s3_pack_offset(uint32_t num_extent_pages,
               uint32_t s3_id,
               bool mid_flag,
               bool msb_flag)
{
    uint64_t v = 0;

    /* bits 0..31: num_extent_pages */
    v |= (uint64_t)(num_extent_pages & S3_INDEX_MASK);

    /* bit 32: mid flag */
    if (mid_flag) {
        v |= (1ULL << S3_MID_FLAG_BIT);
    }

    /* bits 33..62: s3_id (30 bits) */
    v |= ((uint64_t)(s3_id & S3_ID_MASK) << S3_ID_SHIFT);

    /* bit 63: MSB flag */
    if (msb_flag) {
        v |= (1ULL << S3_MSB_FLAG_BIT);
    }

    return v;
}

static inline uint32_t
s3_unpack_num_index(uint64_t v)
{
    return (uint32_t)(v & S3_INDEX_MASK);
}

// static inline bool
// s3_unpack_mid_flag(uint64_t v)
// {
//     return ((v >> S3_MID_FLAG_BIT) & 1ULL) != 0;
// }

static inline uint32_t
s3_unpack_s3_id(uint64_t v)
{
    return (uint32_t)((v >> S3_ID_SHIFT) & S3_ID_MASK);
}


static inline const char *
xfer_type_to_string(enum xfer_type type)
{
    switch (type) {
    case XFER_TYPE_NONE:
        return "none";
    case XFER_REPLICATE_SNAPSHOT:
        return "replicate_snapshot";
    case XFER_MIGRATE_SNAPSHOT:
        return "migrate_snapshot";
    case XFER_S3_BACKUP:
        return "s3_backup";
    case XFER_S3_RECOVER:
        return "s3_recover";
    case XFER_S3_MERGE:
        return "s3_merge";
    default:
        return "unknown";
    }
}


static inline const char *
xfer_result_type_to_string(enum xfer_status type)
{
    switch (type) {
    case XFER_NONE:
        return "None";
    case XFER_IN_PROGRESS:
        return "In progress";
    case XFER_DONE:
        return "Done";
    case XFER_FAILED:
        return "Failed";
    default:
        return "unknown";
    }
}

#endif /* SPDK_INTERNAL_LVOLSTORE_H */
