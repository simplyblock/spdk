
/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/rpc.h"
#include "spdk/bdev.h"
#include "spdk/util.h"
#include "vbdev_lvol.h"
#include "spdk/string.h"
#include "spdk/log.h"
#include "spdk/json.h"

SPDK_LOG_REGISTER_COMPONENT(lvol_rpc)
#define RPC_MAX_LVOL_VBDEV 255

struct rpc_shallow_copy_status {
	uint32_t				operation_id;
	/*
	 * 0 means ongoing or successfully completed operation
	 * a negative value is the -errno of an aborted operation
	 */
	int					result;
	uint64_t				copied_clusters;
	uint64_t				total_clusters;
	LIST_ENTRY(rpc_shallow_copy_status)	link;
};

static uint32_t g_shallow_copy_count = 0;
static LIST_HEAD(, rpc_shallow_copy_status) g_shallow_copy_status_list = LIST_HEAD_INITIALIZER(
			&g_shallow_copy_status_list);

struct rpc_bdev_lvol_create_lvstore {
	char *lvs_name;
	char *bdev_name;
	uint32_t cluster_sz;
	char *clear_method;
	uint32_t num_md_pages_per_cluster_ratio;
};

static int
vbdev_get_lvol_store_by_uuid_xor_name(const char *uuid, const char *lvs_name,
				      struct spdk_lvol_store **lvs)
{
	if ((uuid == NULL && lvs_name == NULL)) {
		SPDK_INFOLOG(lvol_rpc, "lvs UUID nor lvs name specified\n");
		return -EINVAL;
	} else if ((uuid && lvs_name)) {
		SPDK_INFOLOG(lvol_rpc, "both lvs UUID '%s' and lvs name '%s' specified\n", uuid,
			     lvs_name);
		return -EINVAL;
	} else if (uuid) {
		*lvs = vbdev_get_lvol_store_by_uuid(uuid);

		if (*lvs == NULL) {
			SPDK_INFOLOG(lvol_rpc, "blobstore with UUID '%s' not found\n", uuid);
			return -ENODEV;
		}
	} else if (lvs_name) {

		*lvs = vbdev_get_lvol_store_by_name(lvs_name);

		if (*lvs == NULL) {
			SPDK_INFOLOG(lvol_rpc, "blobstore with name '%s' not found\n", lvs_name);
			return -ENODEV;
		}
	}
	return 0;
}

static void
free_rpc_bdev_lvol_create_lvstore(struct rpc_bdev_lvol_create_lvstore *req)
{
	free(req->bdev_name);
	free(req->lvs_name);
	free(req->clear_method);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_create_lvstore_decoders[] = {
	{"bdev_name", offsetof(struct rpc_bdev_lvol_create_lvstore, bdev_name), spdk_json_decode_string},
	{"cluster_sz", offsetof(struct rpc_bdev_lvol_create_lvstore, cluster_sz), spdk_json_decode_uint32, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_create_lvstore, lvs_name), spdk_json_decode_string},
	{"clear_method", offsetof(struct rpc_bdev_lvol_create_lvstore, clear_method), spdk_json_decode_string, true},
	{"num_md_pages_per_cluster_ratio", offsetof(struct rpc_bdev_lvol_create_lvstore, num_md_pages_per_cluster_ratio), spdk_json_decode_uint32, true},
};

static void
rpc_lvol_store_construct_cb(void *cb_arg, struct spdk_lvol_store *lvol_store, int lvserrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvserrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_uuid(w, &lvol_store->uuid);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvserrno));
}

static void
rpc_bdev_lvol_create_lvstore(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_create_lvstore req = {};
	int rc = 0;
	enum lvs_clear_method clear_method;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_create_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_create_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	if (req.clear_method != NULL) {
		if (!strcasecmp(req.clear_method, "none")) {
			clear_method = LVS_CLEAR_WITH_NONE;
		} else if (!strcasecmp(req.clear_method, "unmap")) {
			clear_method = LVS_CLEAR_WITH_UNMAP;
		} else if (!strcasecmp(req.clear_method, "write_zeroes")) {
			clear_method = LVS_CLEAR_WITH_WRITE_ZEROES;
		} else {
			spdk_jsonrpc_send_error_response(request, -EINVAL, "Invalid clear_method parameter");
			goto cleanup;
		}
	} else {
		clear_method = LVS_CLEAR_WITH_UNMAP;
	}

	rc = vbdev_lvs_create(req.bdev_name, req.lvs_name, req.cluster_sz, clear_method,
			      req.num_md_pages_per_cluster_ratio, rpc_lvol_store_construct_cb, request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	free_rpc_bdev_lvol_create_lvstore(&req);

	return;

cleanup:
	free_rpc_bdev_lvol_create_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_create_lvstore", rpc_bdev_lvol_create_lvstore, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_rename_lvstore {
	char *old_name;
	char *new_name;
};

static void
free_rpc_bdev_lvol_rename_lvstore(struct rpc_bdev_lvol_rename_lvstore *req)
{
	free(req->old_name);
	free(req->new_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_rename_lvstore_decoders[] = {
	{"old_name", offsetof(struct rpc_bdev_lvol_rename_lvstore, old_name), spdk_json_decode_string},
	{"new_name", offsetof(struct rpc_bdev_lvol_rename_lvstore, new_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_rename_lvstore_cb(void *cb_arg, int lvserrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvserrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvserrno));
}

static void
rpc_bdev_lvol_rename_lvstore(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_rename_lvstore req = {};
	struct spdk_lvol_store *lvs;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_rename_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_rename_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	lvs = vbdev_get_lvol_store_by_name(req.old_name);
	if (lvs == NULL) {
		SPDK_INFOLOG(lvol_rpc, "no lvs existing for given name\n");
		spdk_jsonrpc_send_error_response_fmt(request, -ENOENT, "Lvol store %s not found", req.old_name);
		goto cleanup;
	}

	vbdev_lvs_rename(lvs, req.new_name, rpc_bdev_lvol_rename_lvstore_cb, request);

cleanup:
	free_rpc_bdev_lvol_rename_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_rename_lvstore", rpc_bdev_lvol_rename_lvstore, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_delete_lvstore {
	char *uuid;
	char *lvs_name;
};

static void
free_rpc_bdev_lvol_delete_lvstore(struct rpc_bdev_lvol_delete_lvstore *req)
{
	free(req->uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_delete_lvstore_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_delete_lvstore, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_delete_lvstore, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_lvol_store_destroy_cb(void *cb_arg, int lvserrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvserrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvserrno));
}

static void
rpc_bdev_lvol_delete_lvstore(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_delete_lvstore req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_delete_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_delete_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	vbdev_lvs_destruct(lvs, rpc_lvol_store_destroy_cb, request);

cleanup:
	free_rpc_bdev_lvol_delete_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_delete_lvstore", rpc_bdev_lvol_delete_lvstore, SPDK_RPC_RUNTIME)

static void
rpc_bdev_lvol_cleanup_lvstore(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_delete_lvstore req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_delete_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_delete_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_lvolsotre_cleanup(lvs, rpc_lvol_store_destroy_cb, request);

cleanup:
	free_rpc_bdev_lvol_delete_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_cleanup_lvstore", rpc_bdev_lvol_cleanup_lvstore, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_create {
	char *uuid;
	char *lvs_name;
	char *lvol_name;
	int32_t lvol_priority_class;
	uint8_t ndcs;
	uint8_t npcs;
	uint64_t size_in_mib;
	bool thin_provision;
	char *clear_method;
};

static void
free_rpc_bdev_lvol_create(struct rpc_bdev_lvol_create *req)
{
	free(req->uuid);
	free(req->lvs_name);
	free(req->lvol_name);
	free(req->clear_method);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_create_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_create, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_create, lvs_name), spdk_json_decode_string, true},
	{"lvol_name", offsetof(struct rpc_bdev_lvol_create, lvol_name), spdk_json_decode_string},
	{"lvol_priority_class", offsetof(struct rpc_bdev_lvol_create, lvol_priority_class), spdk_json_decode_int32, true},
	{"ndcs", offsetof(struct rpc_bdev_lvol_create, ndcs), spdk_json_decode_uint8, true},
	{"npcs", offsetof(struct rpc_bdev_lvol_create, npcs), spdk_json_decode_uint8, true},
	{"size_in_mib", offsetof(struct rpc_bdev_lvol_create, size_in_mib), spdk_json_decode_uint64},
	{"thin_provision", offsetof(struct rpc_bdev_lvol_create, thin_provision), spdk_json_decode_bool, true},
	{"clear_method", offsetof(struct rpc_bdev_lvol_create, clear_method), spdk_json_decode_string, true},
};

static void
rpc_bdev_lvol_create_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_create(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_create req = {};
	enum lvol_clear_method clear_method;
	int rc = 0;
	uint8_t geometry = 0;
	struct spdk_lvol_store *lvs = NULL;

	SPDK_INFOLOG(lvol_rpc, "Creating blob\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_create_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_create_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	if (req.clear_method != NULL) {
		if (!strcasecmp(req.clear_method, "none")) {
			clear_method = LVOL_CLEAR_WITH_NONE;
		} else if (!strcasecmp(req.clear_method, "unmap")) {
			clear_method = LVOL_CLEAR_WITH_UNMAP;
		} else if (!strcasecmp(req.clear_method, "write_zeroes")) {
			clear_method = LVOL_CLEAR_WITH_WRITE_ZEROES;
		} else {
			spdk_jsonrpc_send_error_response(request, -EINVAL, "Invalid clean_method option");
			goto cleanup;
		}
	} else {
		clear_method = LVOL_CLEAR_WITH_DEFAULT;
	}

	if (req.ndcs != 0 || req.npcs != 0) {
		SPDK_NOTICELOG("lvol geometry is [%d, %d]", req.ndcs, req.npcs);
		geometry = ((req.npcs + 1) << 2) | (req.ndcs - 1);
	}

	if (!(req.lvol_priority_class >= MIN_PRIORITY_CLASS && req.lvol_priority_class <= MAX_PRIORITY_CLASS)) {
		SPDK_ERRLOG("lvol priority class is not within the allowed range of [%d, %d]", MIN_PRIORITY_CLASS, MAX_PRIORITY_CLASS);
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	rc = vbdev_lvol_create(lvs, req.lvol_name, req.size_in_mib * 1024 * 1024,
			       req.thin_provision, clear_method, req.lvol_priority_class, geometry, rpc_bdev_lvol_create_cb, request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

cleanup:
	free_rpc_bdev_lvol_create(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_create", rpc_bdev_lvol_create, SPDK_RPC_RUNTIME)


struct rpc_bdev_hublvol {
	char *uuid;
	char *lvs_name;
};

static void
free_rpc_bdev_hublvol(struct rpc_bdev_hublvol *req)
{
	free(req->uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_hublvol_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_hublvol, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_hublvol, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_bdev_hublvol_create_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_create_hublvol(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_hublvol req = {};
	int rc = 0;
	struct spdk_lvol_store *lvs = NULL;

	SPDK_NOTICELOG("Creating Hub lvol.\n");

	if (spdk_json_decode_object(params, rpc_bdev_hublvol_decoders,
				    SPDK_COUNTOF(rpc_bdev_hublvol_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	rc = vbdev_lvol_create_hublvol(lvs, rpc_bdev_hublvol_create_cb, request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

cleanup:
	free_rpc_bdev_hublvol(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_create_hublvol", rpc_bdev_lvol_create_hublvol, SPDK_RPC_RUNTIME)

static void
rpc_bdev_hublvol_delete_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;
	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_delete_hublvol(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_hublvol req = {};
	int rc = 0;
	struct spdk_lvol_store *lvs = NULL;
	struct spdk_lvol *lvol = NULL;

	SPDK_NOTICELOG("Deleting Hub lvol.\n");

	if (spdk_json_decode_object(params, rpc_bdev_hublvol_decoders,
				    SPDK_COUNTOF(rpc_bdev_hublvol_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	lvol = spdk_lvol_get_by_names(lvs->name, "hublvol");
	if (!lvol) {
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_delete_hublvol(lvol, rpc_bdev_hublvol_delete_cb, request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

cleanup:
	free_rpc_bdev_hublvol(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_delete_hublvol", rpc_bdev_lvol_delete_hublvol, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_register {
	char *uuid;
	char *lvs_name;
	char *lvol_name;
	int32_t lvol_priority_class;
	char *registered_uuid;
	bool thin_provision;
	char *clear_method;
	int64_t blobid;
};

struct rpc_lvol_with_handle_req  {
	struct spdk_jsonrpc_request *request;
	struct rpc_bdev_lvol_register *req;
	struct spdk_lvol_store *lvs;
};

static void
free_rpc_bdev_lvol_register(struct rpc_bdev_lvol_register *req)
{
	free(req->uuid);
	free(req->lvs_name);
	free(req->lvol_name);
	free(req->clear_method);
	free(req->registered_uuid);
	free(req);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_register_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_register, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_register, lvs_name), spdk_json_decode_string, true},
	{"lvol_name", offsetof(struct rpc_bdev_lvol_register, lvol_name), spdk_json_decode_string},
	{"lvol_priority_class", offsetof(struct rpc_bdev_lvol_register, lvol_priority_class), spdk_json_decode_int32, true},
	{"registered_uuid", offsetof(struct rpc_bdev_lvol_register, registered_uuid), spdk_json_decode_string},
	{"thin_provision", offsetof(struct rpc_bdev_lvol_create, thin_provision), spdk_json_decode_bool},	
	{"clear_method", offsetof(struct rpc_bdev_lvol_register, clear_method), spdk_json_decode_string},
	{"blobid", offsetof(struct rpc_bdev_lvol_register, blobid), spdk_json_decode_uint64},
};

static void
rpc_bdev_lvol_register_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;
	
	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvs_update_cb(void *cb_arg, int lvolerrno) {
	struct rpc_lvol_with_handle_req *ctx = cb_arg;
	struct rpc_bdev_lvol_register *req = ctx->req;
	enum lvol_clear_method clear_method;
	int rc = 0;
	if (lvolerrno != 0) {
		spdk_jsonrpc_send_error_response(ctx->request, lvolerrno, spdk_strerror(-lvolerrno));
		goto cleanup;
	}

	if (req->clear_method != NULL) {
		if (!strcasecmp(req->clear_method, "none")) {
			clear_method = LVOL_CLEAR_WITH_NONE;
		} else if (!strcasecmp(req->clear_method, "unmap")) {
			clear_method = LVOL_CLEAR_WITH_UNMAP;
		} else if (!strcasecmp(req->clear_method, "write_zeroes")) {
			clear_method = LVOL_CLEAR_WITH_WRITE_ZEROES;
		} else {
			spdk_jsonrpc_send_error_response(ctx->request, -EINVAL, "Invalid clean_method option");
			goto cleanup;
		}
	} else {
		clear_method = LVOL_CLEAR_WITH_DEFAULT;
	}

	rc = vbdev_lvol_register(ctx->lvs, req->lvol_name, req->registered_uuid, req->blobid,
			       req->thin_provision, clear_method, req->lvol_priority_class, rpc_bdev_lvol_register_cb, ctx->request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(ctx->request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

cleanup:
	free_rpc_bdev_lvol_register(req);
	free(ctx);
}

static void
rpc_bdev_lvol_register(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_register *req;
	struct rpc_lvol_with_handle_req *ctx;
	int rc = 0;
	struct spdk_lvol_store *lvs = NULL;
	ctx = calloc(1, sizeof(struct rpc_lvol_with_handle_req));
	if (ctx == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		return;
	}
	req = calloc(1, sizeof(struct rpc_bdev_lvol_register));
	if (req == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		free(ctx);
		return;
	}
	SPDK_INFOLOG(lvol_rpc, "Register blob\n");
	SPDK_NOTICELOG("Register blob on secondary.\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_register_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_register_decoders),
				    req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req->uuid, req->lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	if (!(req->lvol_priority_class >= MIN_PRIORITY_CLASS && req->lvol_priority_class <= MAX_PRIORITY_CLASS)) {
		SPDK_ERRLOG("lvol priority class is not within the allowed range of [%d, %d]", MIN_PRIORITY_CLASS, MAX_PRIORITY_CLASS);
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}
	ctx->req = req;
	ctx->request = request;
	ctx->lvs = lvs;
	if (ctx->lvs->leader) {
		rpc_bdev_lvs_update_cb(ctx, 0);
	} else if (ctx->lvs->update_in_progress) {
		SPDK_ERRLOG("lvolstore update in progress in failover state.\n");
		spdk_jsonrpc_send_error_response(request, -EBUSY, spdk_strerror(EBUSY));
		goto cleanup;
	} else {
		spdk_lvs_update_live(lvs, req->blobid, rpc_bdev_lvs_update_cb, ctx);
	}
	return;

cleanup:
	free_rpc_bdev_lvol_register(req);
	free(ctx);
}

SPDK_RPC_REGISTER("bdev_lvol_register", rpc_bdev_lvol_register, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvs_dump {
	char *uuid;
	char *lvs_name;
	char *file;	
};

static const struct spdk_json_object_decoder rpc_bdev_lvs_dump_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvs_dump, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvs_dump, lvs_name), spdk_json_decode_string, true},
	{"file", offsetof(struct rpc_bdev_lvs_dump, file), spdk_json_decode_string},	
};

static void
free_rpc_bdev_lvs_dump(struct rpc_bdev_lvs_dump *req)
{
	free(req->uuid);
	free(req->lvs_name);
	free(req->file);	
}

static void
rpc_bdev_lvs_dump_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;	
	if (lvolerrno == 0) {
		w = spdk_jsonrpc_begin_result(request);
		spdk_json_write_string(w, "done");
		SPDK_NOTICELOG("Lvs dumping completed successfully, and the RPC response has been sent.\n");
		spdk_jsonrpc_end_result(request, w);
		return;
	}

	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}


static void
rpc_bdev_lvs_dump(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvs_dump req = {};
	int rc = 0;
	struct spdk_lvol_store *lvs = NULL;

	SPDK_INFOLOG(lvol_rpc, "Dumping blobstore\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvs_dump_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvs_dump_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}


	rc = vbdev_lvs_dump(lvs, req.file, rpc_bdev_lvs_dump_cb, request);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

cleanup:
	free_rpc_bdev_lvs_dump(&req);
}

SPDK_RPC_REGISTER("bdev_lvs_dump", rpc_bdev_lvs_dump, SPDK_RPC_RUNTIME)


struct rpc_bdev_lvol_snapshot {
	char *lvol_name;
	char *snapshot_name;
};

static void
free_rpc_bdev_lvol_snapshot(struct rpc_bdev_lvol_snapshot *req)
{
	free(req->lvol_name);
	free(req->snapshot_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_snapshot_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_snapshot, lvol_name), spdk_json_decode_string},
	{"snapshot_name", offsetof(struct rpc_bdev_lvol_snapshot, snapshot_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_snapshot_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_snapshot(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_snapshot req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Snapshotting blob\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_snapshot_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_snapshot_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_create_snapshot(lvol, req.snapshot_name, rpc_bdev_lvol_snapshot_cb, request);

cleanup:
	free_rpc_bdev_lvol_snapshot(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_snapshot", rpc_bdev_lvol_snapshot, SPDK_RPC_RUNTIME)

struct rpc_snapshot_register {
	char *lvol_name;
	char *snapshot_name;
	char *registered_uuid;
	int64_t blobid;
};

struct rpc_snapshot_with_handle_req  {
	struct spdk_jsonrpc_request *request;
	struct rpc_snapshot_register *req;
	struct spdk_lvol_store *lvs;
	struct spdk_lvol *lvol;
};

static void
free_rpc_bdev_lvol_snapshot_register(struct rpc_snapshot_register *req)
{
	free(req->lvol_name);
	free(req->snapshot_name);
	free(req->registered_uuid);
}

static const struct spdk_json_object_decoder rpc_snapshot_register_decoders[] = {
	{"lvol_name", offsetof(struct rpc_snapshot_register, lvol_name), spdk_json_decode_string},
	{"snapshot_name", offsetof(struct rpc_snapshot_register, snapshot_name), spdk_json_decode_string},
	{"registered_uuid", offsetof(struct rpc_snapshot_register, registered_uuid), spdk_json_decode_string},
	{"blobid", offsetof(struct rpc_snapshot_register, blobid), spdk_json_decode_uint64},
};

static void
rpc_bdev_lvol_snapshot_update_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_snapshot_lvol_register_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno) {
	struct rpc_snapshot_with_handle_req *ctx = cb_arg;
	struct rpc_snapshot_register *req = ctx->req;
	struct spdk_lvol *origlvol = ctx->lvol;
	if (lvolerrno != 0) {
		spdk_jsonrpc_send_error_response(ctx->request, lvolerrno, spdk_strerror(-lvolerrno));
		goto cleanup;
	}

	vbdev_lvol_update_snapshot_clone(lvol, origlvol, false, rpc_bdev_lvol_snapshot_update_cb, ctx->request);

cleanup:
	free_rpc_bdev_lvol_snapshot_register(req);
	free(ctx);
}

static void
rpc_snapshot_lvs_update_cb(void *cb_arg, int lvolerrno) {
	struct rpc_snapshot_with_handle_req *ctx = cb_arg;
	struct rpc_snapshot_register *req = ctx->req;
	struct spdk_lvol *lvol = ctx->lvol;
	enum lvol_clear_method clear_method;
	int rc = 0;
	if (lvolerrno != 0) {
		spdk_jsonrpc_send_error_response(ctx->request, lvolerrno, spdk_strerror(-lvolerrno));
		goto cleanup;
	}

	clear_method = (enum lvol_clear_method)lvol->clear_method;

	rc = vbdev_lvol_register(ctx->lvs, req->snapshot_name, req->registered_uuid, req->blobid,
			       true, clear_method, 0, rpc_snapshot_lvol_register_cb, ctx);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(ctx->request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	return;

cleanup:
	free_rpc_bdev_lvol_snapshot_register(req);
	free(ctx);
}

static void
rpc_bdev_lvol_snapshot_register(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct rpc_snapshot_register *req;
	struct rpc_snapshot_with_handle_req *ctx;
	ctx = calloc(1, sizeof(struct rpc_snapshot_with_handle_req));
	if (ctx == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		return;
	}
	req = calloc(1, sizeof(struct rpc_snapshot_register));
	if (req == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		free(ctx);
		return;
	}

	SPDK_INFOLOG(lvol_rpc, "Register snapshot blob.\n");

	if (spdk_json_decode_object(params, rpc_snapshot_register_decoders,
				    SPDK_COUNTOF(rpc_snapshot_register_decoders), req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req->lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req->lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);		
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	ctx->req = req;
	ctx->request = request;
	ctx->lvol = lvol;
	ctx->lvs = lvol->lvol_store;
	if (ctx->lvs->leader) {
		rpc_snapshot_lvs_update_cb(ctx, 0);
	} else if (ctx->lvs->update_in_progress) {
		SPDK_ERRLOG("lvolstore update in progress in failover state.\n");
		spdk_jsonrpc_send_error_response(request, -EBUSY, spdk_strerror(EBUSY));
		goto cleanup;
	} else {
		spdk_lvs_update_live(lvol->lvol_store, req->blobid, rpc_snapshot_lvs_update_cb, ctx);
	}
	return;
cleanup:
	free_rpc_bdev_lvol_snapshot_register(req);
	free(ctx);
}

SPDK_RPC_REGISTER("bdev_lvol_snapshot_register", rpc_bdev_lvol_snapshot_register, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_clone {
	char *snapshot_name;
	char *clone_name;
};

static void
free_rpc_bdev_lvol_clone(struct rpc_bdev_lvol_clone *req)
{
	free(req->snapshot_name);
	free(req->clone_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_clone_decoders[] = {
	{"snapshot_name", offsetof(struct rpc_bdev_lvol_clone, snapshot_name), spdk_json_decode_string},
	{"clone_name", offsetof(struct rpc_bdev_lvol_clone, clone_name), spdk_json_decode_string, true},
};

static void
rpc_bdev_lvol_clone_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_clone(struct spdk_jsonrpc_request *request,
		    const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Cloning blob\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.snapshot_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.snapshot_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_create_clone(lvol, req.clone_name, rpc_bdev_lvol_clone_cb, request);

cleanup:
	free_rpc_bdev_lvol_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_clone", rpc_bdev_lvol_clone, SPDK_RPC_RUNTIME)

struct rpc_clone_register {
	char *snapshot_name;
	char *clone_name;
	char *registered_uuid;
	int64_t blobid;
};

struct rpc_clone_with_handle_req  {
	struct spdk_jsonrpc_request *request;
	struct rpc_clone_register *req;
	struct spdk_lvol_store *lvs;
	struct spdk_lvol *lvol;
};

static void
free_rpc_bdev_lvol_clone_register(struct rpc_clone_register *req)
{
	free(req->clone_name);
	free(req->snapshot_name);
	free(req->registered_uuid);
}

static const struct spdk_json_object_decoder rpc_clone_register_decoders[] = {
	{"snapshot_name", offsetof(struct rpc_clone_register, snapshot_name), spdk_json_decode_string},
	{"clone_name", offsetof(struct rpc_clone_register, clone_name), spdk_json_decode_string},
	{"registered_uuid", offsetof(struct rpc_clone_register, registered_uuid), spdk_json_decode_string},
	{"blobid", offsetof(struct rpc_clone_register, blobid), spdk_json_decode_uint64},
};

static void
rpc_bdev_lvol_clone_update_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno)
{
	struct spdk_json_write_ctx *w;
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, lvol->unique_id);
	spdk_jsonrpc_end_result(request, w);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_clone_lvol_register_cb(void *cb_arg, struct spdk_lvol *lvol, int lvolerrno) {
	struct rpc_clone_with_handle_req *ctx = cb_arg;
	struct rpc_clone_register *req = ctx->req;
	struct spdk_lvol *origlvol = ctx->lvol;
	if (lvolerrno != 0) {
		spdk_jsonrpc_send_error_response(ctx->request, lvolerrno, spdk_strerror(-lvolerrno));
		goto cleanup;
	}

	vbdev_lvol_update_snapshot_clone(lvol, origlvol, true, rpc_bdev_lvol_clone_update_cb, ctx->request);

cleanup:
	free_rpc_bdev_lvol_clone_register(req);
	free(ctx);
}

static void
rpc_clone_lvs_update_cb(void *cb_arg, int lvolerrno) {
	struct rpc_clone_with_handle_req *ctx = cb_arg;
	struct rpc_clone_register *req = ctx->req;
	struct spdk_lvol *lvol = ctx->lvol;
	enum lvol_clear_method clear_method;
	int rc = 0;
	if (lvolerrno != 0) {
		spdk_jsonrpc_send_error_response(ctx->request, lvolerrno, spdk_strerror(-lvolerrno));
		goto cleanup;
	}

	clear_method = (enum lvol_clear_method)lvol->clear_method;

	rc = vbdev_lvol_register(ctx->lvs, req->clone_name, req->registered_uuid, req->blobid,
			       true, clear_method, 0, rpc_clone_lvol_register_cb, ctx);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(ctx->request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	return;

cleanup:
	free_rpc_bdev_lvol_clone_register(req);
	free(ctx);
}

static void
rpc_bdev_lvol_clone_register(struct spdk_jsonrpc_request *request,
		    const struct spdk_json_val *params)
{
	struct rpc_clone_register *req;
	struct rpc_clone_with_handle_req *ctx;
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	ctx = calloc(1, sizeof(struct rpc_snapshot_with_handle_req));
	if (ctx == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		return;
	}
	req = calloc(1, sizeof(struct rpc_clone_register));
	if (req == NULL) {
		SPDK_ERRLOG("Cannot allocate context for lvol register.'\n");
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		free(ctx);
		return;
	}

	SPDK_INFOLOG(lvol_rpc, "Register cloning blob.\n");

	if (spdk_json_decode_object(params, rpc_clone_register_decoders,
				    SPDK_COUNTOF(rpc_clone_register_decoders), req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req->snapshot_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req->snapshot_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	ctx->req = req;
	ctx->request = request;
	ctx->lvol = lvol;
	ctx->lvs = lvol->lvol_store;
	if (ctx->lvs->leader) {
		rpc_clone_lvs_update_cb(ctx, 0);
	} else if (ctx->lvs->update_in_progress) {
		SPDK_ERRLOG("lvolstore update in progress in failover state.\n");
		spdk_jsonrpc_send_error_response(request, -EBUSY, spdk_strerror(EBUSY));
		goto cleanup;
	} else {
		spdk_lvs_update_live(lvol->lvol_store, req->blobid, rpc_clone_lvs_update_cb, ctx);
	}
	return;
cleanup:
	free_rpc_bdev_lvol_clone_register(req);
	free(ctx);
}

SPDK_RPC_REGISTER("bdev_lvol_clone_register", rpc_bdev_lvol_clone_register, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_clone_bdev {
	/* name or UUID. Whichever is used, the UUID will be stored in the lvol's metadata. */
	char *bdev_name;
	char *lvs_name;
	char *clone_name;
};

static void
free_rpc_bdev_lvol_clone_bdev(struct rpc_bdev_lvol_clone_bdev *req)
{
	free(req->bdev_name);
	free(req->lvs_name);
	free(req->clone_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_clone_bdev_decoders[] = {
	{
		"bdev", offsetof(struct rpc_bdev_lvol_clone_bdev, bdev_name),
		spdk_json_decode_string, false
	},
	{
		"lvs_name", offsetof(struct rpc_bdev_lvol_clone_bdev, lvs_name),
		spdk_json_decode_string, false
	},
	{
		"clone_name", offsetof(struct rpc_bdev_lvol_clone_bdev, clone_name),
		spdk_json_decode_string, false
	},
};

static void
rpc_bdev_lvol_clone_bdev(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_clone_bdev req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol_store *lvs = NULL;
	struct spdk_lvol *lvol;
	int rc;

	SPDK_INFOLOG(lvol_rpc, "Cloning bdev\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_clone_bdev_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_clone_bdev_decoders), &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(NULL, req.lvs_name, &lvs);
	if (rc != 0) {
		SPDK_INFOLOG(lvol_rpc, "lvs_name '%s' not found\n", req.lvs_name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "lvs does not exist");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.bdev_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.bdev_name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "bdev does not exist");
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol != NULL && lvol->lvol_store == lvs) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' is an lvol in lvstore '%s\n", req.bdev_name,
			     req.lvs_name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "bdev is an lvol in same lvs as clone; "
						 "use bdev_lvol_clone instead");
		goto cleanup;
	}

	vbdev_lvol_create_bdev_clone(req.bdev_name, lvs, req.clone_name,
				     rpc_bdev_lvol_clone_cb, request);
cleanup:
	free_rpc_bdev_lvol_clone_bdev(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_clone_bdev", rpc_bdev_lvol_clone_bdev, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_rename {
	char *old_name;
	char *new_name;
};

static void
free_rpc_bdev_lvol_rename(struct rpc_bdev_lvol_rename *req)
{
	free(req->old_name);
	free(req->new_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_rename_decoders[] = {
	{"old_name", offsetof(struct rpc_bdev_lvol_rename, old_name), spdk_json_decode_string},
	{"new_name", offsetof(struct rpc_bdev_lvol_rename, new_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_rename_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_rename(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_rename req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Renaming lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_rename_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_rename_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.old_name);
	if (bdev == NULL) {
		SPDK_ERRLOG("bdev '%s' does not exist\n", req.old_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_rename(lvol, req.new_name, rpc_bdev_lvol_rename_cb, request);

cleanup:
	free_rpc_bdev_lvol_rename(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_rename", rpc_bdev_lvol_rename, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_inflate {
	char *name;
};

static void
free_rpc_bdev_lvol_inflate(struct rpc_bdev_lvol_inflate *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_inflate_decoders[] = {
	{"name", offsetof(struct rpc_bdev_lvol_inflate, name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_inflate_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_inflate(struct spdk_jsonrpc_request *request,
		      const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_inflate req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Inflating lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_inflate_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_inflate_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.name);
	if (bdev == NULL) {
		SPDK_ERRLOG("bdev '%s' does not exist\n", req.name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_inflate(lvol, rpc_bdev_lvol_inflate_cb, request);

cleanup:
	free_rpc_bdev_lvol_inflate(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_inflate", rpc_bdev_lvol_inflate, SPDK_RPC_RUNTIME)

static void
rpc_bdev_lvol_decouple_parent(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_inflate req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Decoupling parent of lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_inflate_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_inflate_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.name);
	if (bdev == NULL) {
		SPDK_ERRLOG("bdev '%s' does not exist\n", req.name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_decouple_parent(lvol, rpc_bdev_lvol_inflate_cb, request);

cleanup:
	free_rpc_bdev_lvol_inflate(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_decouple_parent", rpc_bdev_lvol_decouple_parent, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_resize {
	char *name;
	uint64_t size_in_mib;
};

static void
free_rpc_bdev_lvol_resize(struct rpc_bdev_lvol_resize *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_resize_decoders[] = {
	{"name", offsetof(struct rpc_bdev_lvol_resize, name), spdk_json_decode_string},
	{"size_in_mib", offsetof(struct rpc_bdev_lvol_resize, size_in_mib), spdk_json_decode_uint64},
};

static void
rpc_bdev_lvol_resize_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_resize(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_resize req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Resizing lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_resize_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_resize_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.name);
	if (bdev == NULL) {
		SPDK_ERRLOG("no bdev for provided name %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	if (lvol->lvol_store->leader) {
		SPDK_NOTICELOG("Resizing lvol on primary.\n");
		vbdev_lvol_resize(lvol, req.size_in_mib * 1024 * 1024, rpc_bdev_lvol_resize_cb, request);
	} else {
		SPDK_NOTICELOG("Resizing lvol on secondary.\n");
		vbdev_lvol_resize_register(lvol, req.size_in_mib * 1024 * 1024, rpc_bdev_lvol_resize_cb, request);
	}

cleanup:
	free_rpc_bdev_lvol_resize(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_resize", rpc_bdev_lvol_resize, SPDK_RPC_RUNTIME)

struct rpc_set_ro_lvol_bdev {
	char *name;
};

static void
free_rpc_set_ro_lvol_bdev(struct rpc_set_ro_lvol_bdev *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_set_ro_lvol_bdev_decoders[] = {
	{"name", offsetof(struct rpc_set_ro_lvol_bdev, name), spdk_json_decode_string},
};

static void
rpc_set_ro_lvol_bdev_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_set_read_only(struct spdk_jsonrpc_request *request,
			    const struct spdk_json_val *params)
{
	struct rpc_set_ro_lvol_bdev req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	SPDK_INFOLOG(lvol_rpc, "Setting lvol as read only\n");

	if (spdk_json_decode_object(params, rpc_set_ro_lvol_bdev_decoders,
				    SPDK_COUNTOF(rpc_set_ro_lvol_bdev_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	if (req.name == NULL) {
		SPDK_ERRLOG("missing name param\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, "Missing name parameter");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.name);
	if (bdev == NULL) {
		SPDK_ERRLOG("no bdev for provided name %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_set_read_only(lvol, rpc_set_ro_lvol_bdev_cb, request);

cleanup:
	free_rpc_set_ro_lvol_bdev(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_read_only", rpc_bdev_lvol_set_read_only, SPDK_RPC_RUNTIME)

struct rpc_set_ro_lvs_bdev {
	char *lvs_name;
	char *uuid;
	bool read_only;

};

static void
free_rpc_set_ro_lvs_bdev(struct rpc_set_ro_lvs_bdev *req)
{
	free(req->lvs_name);
	free(req->uuid);
}

static const struct spdk_json_object_decoder rpc_set_ro_lvs_bdev_decoders[] = {
	{"lvs_name", offsetof(struct rpc_set_ro_lvs_bdev, lvs_name), spdk_json_decode_string, true},
	{"uuid", offsetof(struct rpc_set_ro_lvs_bdev, uuid), spdk_json_decode_string, true},
	{"read_only", offsetof(struct rpc_set_ro_lvs_bdev, read_only), spdk_json_decode_bool},
};

static void
rpc_bdev_lvol_set_lvs_read_only(struct spdk_jsonrpc_request *request,
			    const struct spdk_json_val *params)
{
	struct rpc_set_ro_lvs_bdev req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	SPDK_INFOLOG(lvol_rpc, "Setting lvol as read only\n");

	if (spdk_json_decode_object(params, rpc_set_ro_lvs_bdev_decoders,
				    SPDK_COUNTOF(rpc_set_ro_lvs_bdev_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	
	spdk_lvs_set_read_only(lvs, req.read_only);
	spdk_jsonrpc_send_bool_response(request, true);
cleanup:
	free_rpc_set_ro_lvs_bdev(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_lvs_read_only", rpc_bdev_lvol_set_lvs_read_only, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_delete {
	char *name;
	bool sync;
};

static void
free_rpc_bdev_lvol_delete(struct rpc_bdev_lvol_delete *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_delete_decoders[] = {
	{"name", offsetof(struct rpc_bdev_lvol_delete, name), spdk_json_decode_string},
	{"sync", offsetof(struct rpc_bdev_lvol_delete, sync), spdk_json_decode_bool, true},
};

static void
rpc_bdev_lvol_delete_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;
	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	// spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
	// 				 spdk_strerror(-lvolerrno));
		spdk_jsonrpc_send_error_response(request, lvolerrno,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_delete(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_delete req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_uuid uuid;
	char *lvs_name, *lvol_name;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_delete_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_delete_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	/* lvol is not degraded, get lvol via bdev name or alias */
	bdev = spdk_bdev_get_by_name(req.name);
	if (bdev != NULL) {
		lvol = vbdev_lvol_get_from_bdev(bdev);
		if (lvol != NULL) {
			goto done;
		}
	}

	/* lvol is degraded, get lvol via UUID */
	if (spdk_uuid_parse(&uuid, req.name) == 0) {
		lvol = spdk_lvol_get_by_uuid(&uuid);
		if (lvol != NULL) {
			goto done;
		}
	}

	/* lvol is degraded, get lvol via lvs_name/lvol_name */
	lvol_name = strchr(req.name, '/');
	if (lvol_name != NULL) {
		*lvol_name = '\0';
		lvol_name++;
		lvs_name = req.name;
		lvol = spdk_lvol_get_by_names(lvs_name, lvol_name);
		if (lvol != NULL) {
			goto done;
		}
	}

	/* Could not find lvol, degraded or not. */
	spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
	goto cleanup;

done:
	if (!lvol->lvol_store->leader && !req.sync) {
		SPDK_ERRLOG("Deleting async lvol on non-leader lvs.\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "Deleting async lvol on non-leader lvs.");
		goto cleanup;
	}
	vbdev_lvol_destroy(lvol, rpc_bdev_lvol_delete_cb, request, req.sync);

cleanup:
	free_rpc_bdev_lvol_delete(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_delete", rpc_bdev_lvol_delete, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_get_lvstores {
	char *uuid;
	char *lvs_name;
};

static void
free_rpc_bdev_lvol_get_lvstores(struct rpc_bdev_lvol_get_lvstores *req)
{
	free(req->uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_get_lvstores_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_get_lvstores, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_get_lvstores, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_dump_lvol_store_info(struct spdk_json_write_ctx *w, struct lvol_store_bdev *lvs_bdev)
{
	struct spdk_blob_store *bs;
	uint64_t cluster_size;

	bs = lvs_bdev->lvs->blobstore;
	cluster_size = spdk_bs_get_cluster_size(bs);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_uuid(w, "uuid", &lvs_bdev->lvs->uuid);
	spdk_json_write_named_string(w, "name", lvs_bdev->lvs->name);
	spdk_json_write_named_bool(w, "lvs leadership", lvs_bdev->lvs->leader);
	spdk_json_write_named_bool(w, "lvs_read_only", lvs_bdev->lvs->read_only);
	if (lvs_bdev->lvs->secondary) {
		spdk_json_write_named_bool(w, "lvs_secondary", lvs_bdev->lvs->secondary);
		spdk_json_write_named_bool(w, "lvs_redirect", !lvs_bdev->lvs->skip_redirecting);
		spdk_json_write_named_string(w, "remote_bdev", lvs_bdev->lvs->remote_bdev);
		spdk_json_write_named_bool(w, "connect_state", lvs_bdev->lvs->hub_dev.state == HUBLVOL_CONNECTED);
	} else if (lvs_bdev->lvs->primary) {
		spdk_json_write_named_bool(w, "lvs_primary", lvs_bdev->lvs->primary);
	}
	spdk_json_write_named_string(w, "base_bdev", spdk_bdev_get_name(lvs_bdev->bdev));
	spdk_json_write_named_uint64(w, "total_data_clusters", spdk_bs_total_data_cluster_count(bs));
	spdk_json_write_named_uint64(w, "free_clusters", spdk_bs_free_cluster_count(bs));
	spdk_json_write_named_uint64(w, "block_size", spdk_bs_get_io_unit_size(bs));
	spdk_json_write_named_uint64(w, "cluster_size", cluster_size);

	spdk_json_write_object_end(w);
}

static void
rpc_bdev_lvol_get_lvstores(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_get_lvstores req = {};
	struct spdk_json_write_ctx *w;
	struct lvol_store_bdev *lvs_bdev = NULL;
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (params != NULL) {
		if (spdk_json_decode_object(params, rpc_bdev_lvol_get_lvstores_decoders,
					    SPDK_COUNTOF(rpc_bdev_lvol_get_lvstores_decoders),
					    &req)) {
			SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "spdk_json_decode_object failed");
			goto cleanup;
		}

		rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
		if (rc != 0) {
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto cleanup;
		}

		lvs_bdev = vbdev_get_lvs_bdev_by_lvs(lvs);
		if (lvs_bdev == NULL) {
			spdk_jsonrpc_send_error_response(request, ENODEV, spdk_strerror(-ENODEV));
			goto cleanup;
		}
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(w);

	if (lvs_bdev != NULL) {
		rpc_dump_lvol_store_info(w, lvs_bdev);
	} else {
		for (lvs_bdev = vbdev_lvol_store_first(); lvs_bdev != NULL;
		     lvs_bdev = vbdev_lvol_store_next(lvs_bdev)) {
			rpc_dump_lvol_store_info(w, lvs_bdev);
		}
	}
	spdk_json_write_array_end(w);

	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_lvol_get_lvstores(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_get_lvstores", rpc_bdev_lvol_get_lvstores, SPDK_RPC_RUNTIME)
SPDK_RPC_REGISTER_ALIAS_DEPRECATED(bdev_lvol_get_lvstores, get_lvol_stores)

struct rpc_bdev_lvol_set_lvs_opts {
	char *uuid;
	char *lvs_name;
	uint64_t groupid;
	uint64_t subsystem_port;
	bool primary;
	bool secondary;
};

static void
free_rpc_bdev_lvol_set_lvs_opts(struct rpc_bdev_lvol_set_lvs_opts *req)
{
	free(req->uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_set_lvs_opts_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_set_lvs_opts, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_set_lvs_opts, lvs_name), spdk_json_decode_string, true},
	{"groupid", offsetof(struct rpc_bdev_lvol_set_lvs_opts, groupid), spdk_json_decode_uint64},
	{"subsystem_port", offsetof(struct rpc_bdev_lvol_set_lvs_opts, subsystem_port), spdk_json_decode_uint64},
	{"primary", offsetof(struct rpc_bdev_lvol_set_lvs_opts, primary), spdk_json_decode_bool, true},
	{"secondary", offsetof(struct rpc_bdev_lvol_set_lvs_opts, secondary), spdk_json_decode_bool, true},
};

static void
rpc_bdev_lvol_set_lvs_opts(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_set_lvs_opts req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_set_lvs_opts_decoders,
					SPDK_COUNTOF(rpc_bdev_lvol_set_lvs_opts_decoders),
					&req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							"spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_lvs_set_opts(lvs, req.groupid, req.subsystem_port, req.primary, req.secondary);
	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_lvol_set_lvs_opts(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_lvs_opts", rpc_bdev_lvol_set_lvs_opts, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_create_poller_group_opts {
	char *cpu_mask;
};

static void
free_rpc_bdev_lvol_create_poller_group_opts(struct rpc_bdev_lvol_create_poller_group_opts *req)
{	
	free(req->cpu_mask);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_create_poller_group_decoders[] = {
	{"cpu_mask", offsetof(struct rpc_bdev_lvol_create_poller_group_opts, cpu_mask), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_create_poller_group(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_create_poller_group_opts req = {};
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_create_poller_group_decoders,
					SPDK_COUNTOF(rpc_bdev_lvol_create_poller_group_decoders),
					&req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							"spdk_json_decode_object failed");
		goto cleanup;
	}

	// rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (!req.cpu_mask) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	rc = spdk_lvs_poll_group_options(req.cpu_mask);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_lvol_create_poller_group_opts(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_create_poller_group", rpc_bdev_lvol_create_poller_group, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_create_poller_group_opts {
	char *cpu_mask;
};

static void
free_rpc_bdev_lvol_create_poller_group_opts(struct rpc_bdev_lvol_create_poller_group_opts *req)
{	
	free(req->cpu_mask);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_create_poller_group_decoders[] = {
	{"cpu_mask", offsetof(struct rpc_bdev_lvol_create_poller_group_opts, cpu_mask), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_create_poller_group(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_create_poller_group_opts req = {};
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_create_poller_group_decoders,
					SPDK_COUNTOF(rpc_bdev_lvol_create_poller_group_decoders),
					&req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							"spdk_json_decode_object failed");
		goto cleanup;
	}

	// rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (!req.cpu_mask) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	rc = spdk_lvs_poll_group_options(req.cpu_mask);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_lvol_create_poller_group_opts(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_create_poller_group", rpc_bdev_lvol_create_poller_group, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_connect_hublvol {
	char *uuid;
	char *lvs_name;
	char *remote_bdev;
};

static void
free_rpc_bdev_lvol_connect_hublvol(struct rpc_bdev_lvol_connect_hublvol *req)
{
	free(req->uuid);
	free(req->lvs_name);
	free(req->remote_bdev);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_connect_hublvol_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_connect_hublvol, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_connect_hublvol, lvs_name), spdk_json_decode_string, true},	
	{"remote_bdev", offsetof(struct rpc_bdev_lvol_connect_hublvol, remote_bdev), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_connect_hublvol(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_connect_hublvol req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_connect_hublvol_decoders,
					SPDK_COUNTOF(rpc_bdev_lvol_connect_hublvol_decoders),
					&req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							"spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	if (!lvs->secondary) {
		SPDK_ERRLOG("Try to connect hublvol from nonsecondary node.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, "nonsecondary node");
		goto cleanup;
	}

	spdk_lvs_connect_hublvol(lvs, req.remote_bdev);
	spdk_jsonrpc_send_bool_response(request, true);

cleanup:
	free_rpc_bdev_lvol_connect_hublvol(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_connect_hublvol", rpc_bdev_lvol_connect_hublvol, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_get_lvols {
	char *lvs_uuid;
	char *lvs_name;
};

static void
free_rpc_bdev_lvol_get_lvols(struct rpc_bdev_lvol_get_lvols *req)
{
	free(req->lvs_uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_get_lvols_decoders[] = {
	{"lvs_uuid", offsetof(struct rpc_bdev_lvol_get_lvols, lvs_uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_get_lvols, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_dump_lvol(struct spdk_json_write_ctx *w, struct spdk_lvol *lvol)
{
	struct spdk_lvol_store *lvs = lvol->lvol_store;

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string_fmt(w, "alias", "%s/%s", lvs->name, lvol->name);
	spdk_json_write_named_string(w, "uuid", lvol->uuid_str);
	spdk_json_write_named_string(w, "name", lvol->name);
	spdk_json_write_named_bool(w, "is_thin_provisioned", spdk_blob_is_thin_provisioned(lvol->blob));
	spdk_json_write_named_bool(w, "is_snapshot", spdk_blob_is_snapshot(lvol->blob));
	spdk_json_write_named_bool(w, "is_clone", spdk_blob_is_clone(lvol->blob));
	spdk_json_write_named_bool(w, "is_esnap_clone", spdk_blob_is_esnap_clone(lvol->blob));
	spdk_json_write_named_bool(w, "is_degraded", spdk_blob_is_degraded(lvol->blob));
	spdk_json_write_named_uint8(w, "lvol_priority_class", lvol->priority_class);

	spdk_json_write_named_uint64(w, "num_allocated_clusters",
				     spdk_blob_get_num_allocated_clusters(lvol->blob));
	spdk_json_write_named_uint64(w, "blobid", spdk_blob_get_id(lvol->blob));
	spdk_json_write_named_uint64(w, "map_id", lvol->map_id);
	spdk_json_write_named_uint8(w, "geometry", spdk_blob_get_geometry(lvol->blob));
	spdk_json_write_named_uint32(w, "open_ref", spdk_blob_get_open_ref(lvol->blob));
	spdk_json_write_named_object_begin(w, "lvs");
	spdk_json_write_named_string(w, "name", lvs->name);
	spdk_json_write_named_uuid(w, "uuid", &lvs->uuid);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static void
rpc_dump_lvols(struct spdk_json_write_ctx *w, struct lvol_store_bdev *lvs_bdev)
{
	struct spdk_lvol_store *lvs = lvs_bdev->lvs;
	struct spdk_lvol *lvol;

	TAILQ_FOREACH(lvol, &lvs->lvols, link) {
		if (lvol->ref_count == 0) {
			continue;
		}
		rpc_dump_lvol(w, lvol);
	}
}

static void
rpc_bdev_lvol_get_lvols(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_get_lvols req = {};
	struct spdk_json_write_ctx *w;
	struct lvol_store_bdev *lvs_bdev = NULL;
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (params != NULL) {
		if (spdk_json_decode_object(params, rpc_bdev_lvol_get_lvols_decoders,
					    SPDK_COUNTOF(rpc_bdev_lvol_get_lvols_decoders),
					    &req)) {
			SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "spdk_json_decode_object failed");
			goto cleanup;
		}

		rc = vbdev_get_lvol_store_by_uuid_xor_name(req.lvs_uuid, req.lvs_name, &lvs);
		if (rc != 0) {
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto cleanup;
		}

		lvs_bdev = vbdev_get_lvs_bdev_by_lvs(lvs);
		if (lvs_bdev == NULL) {
			spdk_jsonrpc_send_error_response(request, ENODEV, spdk_strerror(-ENODEV));
			goto cleanup;
		}
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(w);

	if (lvs_bdev != NULL) {
		rpc_dump_lvols(w, lvs_bdev);
	} else {
		for (lvs_bdev = vbdev_lvol_store_first(); lvs_bdev != NULL;
		     lvs_bdev = vbdev_lvol_store_next(lvs_bdev)) {
			rpc_dump_lvols(w, lvs_bdev);
		}
	}
	spdk_json_write_array_end(w);

	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_lvol_get_lvols(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_get_lvols", rpc_bdev_lvol_get_lvols, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_get_lvol_delete_status {
	char *name;
};

static void
free_rpc_bdev_lvol_get_lvol_delete_status(struct rpc_bdev_lvol_get_lvol_delete_status *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_get_lvol_delete_status_decoders[] = {
	{"name", offsetof(struct rpc_bdev_lvol_get_lvol_delete_status, name), spdk_json_decode_string, true},
};

static void
rpc_bdev_lvol_get_lvol_delete_status(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_get_lvol_delete_status req = {};
	struct spdk_lvol *lvol;
	char *lvs_name = NULL, *lvol_name = NULL;
	struct spdk_lvol_store *lvs = NULL;
	int rc;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_get_lvol_delete_status_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_get_lvol_delete_status_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	/* lvol is degraded, get lvol via lvs_name/lvol_name */
	lvol_name = strchr(req.name, '/');
	if (lvol_name != NULL) {
		*lvol_name = '\0';
		lvol_name++;
		lvs_name = req.name;
		lvol = spdk_lvol_get_by_names(lvs_name, lvol_name);
		if (lvol != NULL) {
			lvs = lvol->lvol_store;
			goto done;
		}
	}

	if (lvs_name == NULL) {
		SPDK_ERRLOG("lvolstore: %s not found.\n", req.name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	if (lvs_name) {
		rc = vbdev_get_lvol_store_by_uuid_xor_name(NULL, lvs_name, &lvs);
		if (rc != 0) {
			SPDK_ERRLOG("lvolstore: %s not found.\n", lvs_name);
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto cleanup;
		}
	}

	done:
	if(lvol == NULL) {
		SPDK_NOTICELOG("lvol: %s delete request completed successfully before.\n", req.name);
		w = spdk_jsonrpc_begin_result(request);
		spdk_json_write_int32(w, 0);
		spdk_jsonrpc_end_result(request, w);
	} else {
		w = spdk_jsonrpc_begin_result(request);
		if (lvol_delete_requests_contains(lvol)) {
			if (lvol->deletion_status == 1) {
				SPDK_NOTICELOG("lvol: %s the delete requests in progress.\n", req.name);
				spdk_json_write_int32(w, 1);
				spdk_jsonrpc_end_result(request, w);
			} else if (lvol->deletion_status == 0) {
				SPDK_NOTICELOG("lvol: %s the delete requests still waiting in queue.\n", req.name);
				spdk_json_write_int32(w, 1);
				spdk_jsonrpc_end_result(request, w);
			}
		} else if (lvol->deletion_status == 2 && lvs->leader) {
				SPDK_NOTICELOG("lvol: %s the async delete requests done.\n", req.name);
				spdk_json_write_int32(w, 2);
				spdk_jsonrpc_end_result(request, w);
		} else if (lvol->deletion_status == 2 && !lvs->leader) {
				SPDK_NOTICELOG("lvol: %s the async delete requests done.\n", req.name);
				spdk_json_write_int32(w, 3);
				spdk_jsonrpc_end_result(request, w);
 		} else if (lvol->deletion_failed) {
			SPDK_NOTICELOG("lvol: %s delete request failed due to error.\n", req.name);
			spdk_json_write_int32(w, lvol->failed_rc);
			spdk_jsonrpc_end_result(request, w);
		} else {
			SPDK_NOTICELOG("No delete action on lvol: %s.\n", req.name);
			spdk_json_write_int32(w, 4);
			spdk_jsonrpc_end_result(request, w);
		}
	}

cleanup:
	free_rpc_bdev_lvol_get_lvol_delete_status(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_get_lvol_delete_status", rpc_bdev_lvol_get_lvol_delete_status, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_grow_lvstore {
	char *uuid;
	char *lvs_name;
};

static void
free_rpc_bdev_lvol_grow_lvstore(struct rpc_bdev_lvol_grow_lvstore *req)
{
	free(req->uuid);
	free(req->lvs_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_grow_lvstore_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_grow_lvstore, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_grow_lvstore, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_bdev_lvol_grow_lvstore_cb(void *cb_arg, int lvserrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvserrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvserrno));
}

static void
rpc_bdev_lvol_grow_lvstore(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_grow_lvstore req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_grow_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_grow_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_bdev_update_bs_blockcnt(lvs->bs_dev);
	spdk_lvs_grow_live(lvs, rpc_bdev_lvol_grow_lvstore_cb, request);

cleanup:
	free_rpc_bdev_lvol_grow_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_grow_lvstore", rpc_bdev_lvol_grow_lvstore, SPDK_RPC_RUNTIME)

static void
rpc_bdev_lvol_update_lvstore(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_grow_lvstore req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_grow_lvstore_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_grow_lvstore_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}
	// spdk_bdev_update_bs_blockcnt(lvs->bs_dev);
	//TODO we should delete this part there is no need
	spdk_lvs_update_live(lvs, 0, rpc_bdev_lvol_grow_lvstore_cb, request);

cleanup:
	free_rpc_bdev_lvol_grow_lvstore(&req);
}
SPDK_RPC_REGISTER("bdev_lvol_update_lvstore", rpc_bdev_lvol_update_lvstore, SPDK_RPC_RUNTIME)


struct rpc_bdev_lvol_leadership {
	char *uuid;
	char *lvs_name;
	bool lvs_leadership;
	bool bs_nonleadership;
};

static const struct spdk_json_object_decoder rpc_bdev_lvol_leadership_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_grow_lvstore, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_grow_lvstore, lvs_name), spdk_json_decode_string, true},
	{"lvs_leadership", offsetof(struct rpc_bdev_lvol_leadership, lvs_leadership), spdk_json_decode_bool},
	{"bs_nonleadership", offsetof(struct rpc_bdev_lvol_leadership, bs_nonleadership), spdk_json_decode_bool},
};

static void
rpc_bdev_lvol_set_leader_all(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_leadership req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_leadership_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_leadership_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_set_leader_all(lvs, req.lvs_leadership, req.bs_nonleadership);
	spdk_jsonrpc_send_bool_response(request, true);
cleanup:
	free(req.uuid);
	free(req.lvs_name);
	return;
}

SPDK_RPC_REGISTER("bdev_lvol_set_leader_all", rpc_bdev_lvol_set_leader_all, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_blockport {
	char *uuid;
	char *lvs_name;
};

static const struct spdk_json_object_decoder rpc_bdev_lvol_blockport_decoders[] = {
	{"uuid", offsetof(struct rpc_bdev_lvol_blockport, uuid), spdk_json_decode_string, true},
	{"lvs_name", offsetof(struct rpc_bdev_lvol_blockport, lvs_name), spdk_json_decode_string, true},
};

static void
rpc_bdev_lvol_block_data_port(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_blockport req = {};
	struct spdk_lvol_store *lvs = NULL;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_blockport_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_blockport_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = vbdev_get_lvol_store_by_uuid_xor_name(req.uuid, req.lvs_name, &lvs);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	spdk_block_data_port(lvs);
	spdk_jsonrpc_send_bool_response(request, true);
cleanup:
	free(req.uuid);
	free(req.lvs_name);
	return;
}

SPDK_RPC_REGISTER("bdev_lvol_block_data_port", rpc_bdev_lvol_block_data_port, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_shallow_copy {
	char *src_lvol_name;
	char *dst_bdev_name;
};

struct rpc_bdev_lvol_shallow_copy_ctx {
	struct spdk_jsonrpc_request *request;
	struct rpc_shallow_copy_status *status;
};

static void
free_rpc_bdev_lvol_shallow_copy(struct rpc_bdev_lvol_shallow_copy *req)
{
	free(req->src_lvol_name);
	free(req->dst_bdev_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_shallow_copy_decoders[] = {
	{"src_lvol_name", offsetof(struct rpc_bdev_lvol_shallow_copy, src_lvol_name), spdk_json_decode_string},
	{"dst_bdev_name", offsetof(struct rpc_bdev_lvol_shallow_copy, dst_bdev_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_shallow_copy_cb(void *cb_arg, int lvolerrno)
{
	struct rpc_bdev_lvol_shallow_copy_ctx *ctx = cb_arg;

	ctx->status->result = lvolerrno;

	free(ctx);
}

static void
rpc_bdev_lvol_shallow_copy_status_cb(uint64_t copied_clusters, void *cb_arg)
{
	struct rpc_shallow_copy_status *status = cb_arg;

	status->copied_clusters = copied_clusters;
}

static void
rpc_bdev_lvol_start_shallow_copy(struct spdk_jsonrpc_request *request,
				 const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_shallow_copy req = {};
	struct rpc_bdev_lvol_shallow_copy_ctx *ctx;
	struct spdk_lvol *src_lvol;
	struct spdk_bdev *src_lvol_bdev;
	struct rpc_shallow_copy_status *status;
	struct spdk_json_write_ctx *w;
	int rc;

	SPDK_INFOLOG(lvol_rpc, "Shallow copying lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_shallow_copy_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_shallow_copy_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	src_lvol_bdev = spdk_bdev_get_by_name(req.src_lvol_name);
	if (src_lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.src_lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	src_lvol = vbdev_lvol_get_from_bdev(src_lvol_bdev);
	if (src_lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	status = calloc(1, sizeof(*status));
	if (status == NULL) {
		SPDK_ERRLOG("Cannot allocate status entry for shallow copy of '%s'\n", req.src_lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		goto cleanup;
	}

	status->operation_id = ++g_shallow_copy_count;
	status->total_clusters = spdk_blob_get_num_allocated_clusters(src_lvol->blob);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		SPDK_ERRLOG("Cannot allocate context for shallow copy of '%s'\n", req.src_lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		free(status);
		goto cleanup;
	}
	ctx->request = request;
	ctx->status = status;

	LIST_INSERT_HEAD(&g_shallow_copy_status_list, status, link);
	rc = vbdev_lvol_shallow_copy(src_lvol, req.dst_bdev_name,
				     rpc_bdev_lvol_shallow_copy_status_cb, status,
				     rpc_bdev_lvol_shallow_copy_cb, ctx);

	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		LIST_REMOVE(status, link);
		free(ctx);
		free(status);
	} else {
		w = spdk_jsonrpc_begin_result(request);

		spdk_json_write_object_begin(w);
		spdk_json_write_named_uint32(w, "operation_id", status->operation_id);
		spdk_json_write_object_end(w);

		spdk_jsonrpc_end_result(request, w);
	}

cleanup:
	free_rpc_bdev_lvol_shallow_copy(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_start_shallow_copy", rpc_bdev_lvol_start_shallow_copy,
		  SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_shallow_copy_status {
	char		*src_lvol_name;
	uint32_t	operation_id;
};

static void
free_rpc_bdev_lvol_shallow_copy_status(struct rpc_bdev_lvol_shallow_copy_status *req)
{
	free(req->src_lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_shallow_copy_status_decoders[] = {
	{"operation_id", offsetof(struct rpc_bdev_lvol_shallow_copy_status, operation_id), spdk_json_decode_uint32},
};

static void
rpc_bdev_lvol_check_shallow_copy(struct spdk_jsonrpc_request *request,
				 const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_shallow_copy_status req = {};
	struct rpc_shallow_copy_status *status;
	struct spdk_json_write_ctx *w;
	uint64_t copied_clusters, total_clusters;
	int result;

	SPDK_INFOLOG(lvol_rpc, "Shallow copy check\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_shallow_copy_status_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_shallow_copy_status_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	LIST_FOREACH(status, &g_shallow_copy_status_list, link) {
		if (status->operation_id == req.operation_id) {
			break;
		}
	}

	if (!status) {
		SPDK_ERRLOG("operation id '%d' does not exist\n", req.operation_id);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	copied_clusters = status->copied_clusters;
	total_clusters = status->total_clusters;
	result = status->result;

	w = spdk_jsonrpc_begin_result(request);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_uint64(w, "copied_clusters", copied_clusters);
	spdk_json_write_named_uint64(w, "total_clusters", total_clusters);
	if (copied_clusters < total_clusters && result == 0) {
		spdk_json_write_named_string(w, "state", "in progress");
	} else if (copied_clusters == total_clusters && result == 0) {
		spdk_json_write_named_string(w, "state", "complete");
		LIST_REMOVE(status, link);
		free(status);
	} else {
		spdk_json_write_named_string(w, "state", "error");
		spdk_json_write_named_string(w, "error", spdk_strerror(-result));
		LIST_REMOVE(status, link);
		free(status);
	}

	spdk_json_write_object_end(w);

	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_lvol_shallow_copy_status(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_check_shallow_copy", rpc_bdev_lvol_check_shallow_copy,
		  SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_set_parent {
	char *lvol_name;
	char *parent_name;
};

static void
free_rpc_bdev_lvol_set_parent(struct rpc_bdev_lvol_set_parent *req)
{
	free(req->lvol_name);
	free(req->parent_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_set_parent_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_set_parent, lvol_name), spdk_json_decode_string},
	{"parent_name", offsetof(struct rpc_bdev_lvol_set_parent, parent_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_set_parent_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_set_parent(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_set_parent req = {};
	struct spdk_lvol *lvol, *snapshot;
	struct spdk_bdev *lvol_bdev, *snapshot_bdev;

	SPDK_INFOLOG(lvol_rpc, "Set parent of lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_set_parent_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_set_parent_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	snapshot_bdev = spdk_bdev_get_by_name(req.parent_name);
	if (snapshot_bdev == NULL) {
		SPDK_ERRLOG("snapshot bdev '%s' does not exist\n", req.parent_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	snapshot = vbdev_lvol_get_from_bdev(snapshot_bdev);
	if (snapshot == NULL) {
		SPDK_ERRLOG("snapshot does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_set_parent(lvol, snapshot, rpc_bdev_lvol_set_parent_cb, request);

cleanup:
	free_rpc_bdev_lvol_set_parent(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_parent", rpc_bdev_lvol_set_parent, SPDK_RPC_RUNTIME)

static void
rpc_bdev_lvol_set_parent_bdev(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_set_parent req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;

	SPDK_INFOLOG(lvol_rpc, "Set external parent of lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_set_parent_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_set_parent_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	vbdev_lvol_set_external_parent(lvol, req.parent_name, rpc_bdev_lvol_set_parent_cb, request);

cleanup:
	free_rpc_bdev_lvol_set_parent(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_parent_bdev", rpc_bdev_lvol_set_parent_bdev,
		  SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_set_priority_class {
	char* lvol_name;
	int32_t lvol_priority_class;
};

static void 
free_rpc_bdev_lvol_set_priority_class(struct rpc_bdev_lvol_set_priority_class *req) {
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_set_priority_class_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_set_priority_class, lvol_name), spdk_json_decode_string},
	{"lvol_priority_class", offsetof(struct rpc_bdev_lvol_set_priority_class, lvol_priority_class), spdk_json_decode_int32}
};

static void
rpc_bdev_lvol_set_priority_class_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void 
rpc_bdev_lvol_set_priority_class(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_set_priority_class req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;

	SPDK_INFOLOG(lvol_rpc, "Set priority_class of lvol\n");

	if (spdk_json_decode_object(params, rpc_bdev_lvol_set_priority_class_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_set_priority_class_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	if (!(req.lvol_priority_class >= MIN_PRIORITY_CLASS && req.lvol_priority_class <= MAX_PRIORITY_CLASS)) {
		SPDK_ERRLOG("lvol priority class is not within the allowed range of [%d, %d]", MIN_PRIORITY_CLASS, MAX_PRIORITY_CLASS);
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol->priority_class = req.lvol_priority_class;
	vbdev_lvol_set_io_priority_class(lvol);
	rpc_bdev_lvol_set_priority_class_cb(request, 0);

cleanup:
	free_rpc_bdev_lvol_set_priority_class(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_priority_class", rpc_bdev_lvol_set_priority_class,
		  SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer {
	char *lvol_name;
	uint64_t offset;
	uint32_t cluster_batch;
	char *gateway;
	char *operation;
};

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)
	  

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void 
free_rpc_bdev_lvol_transfer(struct rpc_bdev_lvol_transfer *req) {
	free(req->lvol_name);
	free(req->gateway);
	free(req->operation);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer, lvol_name), spdk_json_decode_string},
	{"offset", offsetof(struct rpc_bdev_lvol_transfer, offset), spdk_json_decode_uint64},
	{"cluster_batch", offsetof(struct rpc_bdev_lvol_transfer, cluster_batch), spdk_json_decode_uint32, true},
	{"gateway", offsetof(struct rpc_bdev_lvol_transfer, gateway), spdk_json_decode_string},	
	{"operation", offsetof(struct rpc_bdev_lvol_transfer, operation), spdk_json_decode_string},
};

static void 
rpc_bdev_lvol_transfer(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params) 
{
	struct rpc_bdev_lvol_transfer req = {};
	struct spdk_lvol *lvol;
	struct spdk_bdev *lvol_bdev;
	struct spdk_transfer_dev *tdev;
	enum xfer_type type = XFER_TYPE_NONE;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}
	
	if (!req.lvol_name || !req.gateway) {
		SPDK_ERRLOG("lvol name and bdev name must be specified");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
		goto cleanup;
	}

	lvol_bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (lvol_bdev == NULL) {
		SPDK_ERRLOG("lvol bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(lvol_bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	tdev = spdk_open_rmt_bdev(req.gateway, lvol->lvol_store);
	if (tdev == NULL) {
		SPDK_ERRLOG("bdev '%s' open failed\n", req.gateway);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(-ENODEV));
		goto cleanup;
	}

	if (req.operation != NULL) {
		if (!strcasecmp(req.operation, "replicate")) {
			type = XFER_REPLICATE_SNAPSHOT;
		} else if (!strcasecmp(req.operation, "migrate")) {
			type = XFER_MIGRATIE_SNAPSHOT;
		} else {
			SPDK_ERRLOG("Invalid operation '%s' for transfer.\n", req.operation);
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
			goto cleanup;
		}
	} else {
		SPDK_ERRLOG("Operation mode for transfer is NULL.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(-EINVAL));
		goto cleanup;
	}
	SPDK_NOTICELOG("Transfering lvol %s in %s mode.\n", req.lvol_name, req.operation);

	rc = spdk_lvol_transfer(lvol, req.offset, req.cluster_batch, type, tdev);
	if (rc < 0) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto cleanup;
	}
	spdk_jsonrpc_send_bool_response(request, true);
	return;
cleanup:
	free_rpc_bdev_lvol_transfer(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer", rpc_bdev_lvol_transfer, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_transfer_stat {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_transfer_stat(struct rpc_bdev_lvol_transfer_stat *req)
{
	free(req->lvol_name);	
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_transfer_stat_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_transfer_stat, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_transfer_stat(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_transfer_stat req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_transfer_stat_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_transfer_stat_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	w = spdk_jsonrpc_begin_result(request);
	// spdk_json_write_array_begin(w);
	spdk_json_write_object_begin(w);
	if (lvol->transfer_status == XFER_DONE) {
		spdk_json_write_named_string(w, "transfer_state", "Done");
	} else if (lvol->transfer_status == XFER_FAILED) {
		spdk_json_write_named_string(w, "transfer_state", "Failed");
	} else if (lvol->transfer_status == XFER_IN_PROGRESS) {
		spdk_json_write_named_string(w, "transfer_state", "In progress");
	} else {
		spdk_json_write_named_string(w, "transfer_state", "No process");
	}
	spdk_json_write_named_uint64(w, "offset", lvol->last_offset);
	spdk_json_write_object_end(w);
	// spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
	
cleanup:
	free_rpc_bdev_lvol_transfer_stat(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_transfer_stat", rpc_bdev_lvol_transfer_stat, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_convert {
	char *lvol_name;
};

static void
free_rpc_bdev_lvol_convert(struct rpc_bdev_lvol_convert *req)
{
	free(req->lvol_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_convert_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_convert, lvol_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_convert_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_convert(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_convert req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_convert_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_convert_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	spdk_lvol_convert(lvol, rpc_bdev_lvol_convert_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_convert(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_convert", rpc_bdev_lvol_convert, SPDK_RPC_RUNTIME)

struct rpc_bdev_lvol_add_clone {
	char *lvol_name;
	char *child_name;
};

static void
free_rpc_bdev_lvol_add_clone(struct rpc_bdev_lvol_add_clone *req)
{
	free(req->lvol_name);
	free(req->child_name);
}

static const struct spdk_json_object_decoder rpc_bdev_lvol_add_clone_decoders[] = {
	{"lvol_name", offsetof(struct rpc_bdev_lvol_add_clone, lvol_name), spdk_json_decode_string},
	{"child_name", offsetof(struct rpc_bdev_lvol_add_clone, child_name), spdk_json_decode_string},
};

static void
rpc_bdev_lvol_add_clone_cb(void *cb_arg, int lvolerrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (lvolerrno != 0) {
		goto invalid;
	}

	spdk_jsonrpc_send_bool_response(request, true);
	return;

invalid:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
					 spdk_strerror(-lvolerrno));
}

static void
rpc_bdev_lvol_add_clone(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_lvol_add_clone req = {};
	struct spdk_bdev *bdev;
	struct spdk_lvol *lvol, *clone = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_lvol_add_clone_decoders,
				    SPDK_COUNTOF(rpc_bdev_lvol_add_clone_decoders),
				    &req)) {
		SPDK_INFOLOG(lvol_rpc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.lvol_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.lvol_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	lvol = vbdev_lvol_get_from_bdev(bdev);
	if (lvol == NULL) {
		SPDK_ERRLOG("lvol does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	bdev = spdk_bdev_get_by_name(req.child_name);
	if (bdev == NULL) {
		SPDK_INFOLOG(lvol_rpc, "bdev '%s' does not exist\n", req.child_name);
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}

	clone = vbdev_lvol_get_from_bdev(bdev);
	if (clone == NULL) {
		SPDK_ERRLOG("clone does not exist\n");
		spdk_jsonrpc_send_error_response(request, -ENODEV, spdk_strerror(ENODEV));
		goto cleanup;
	}
	
	spdk_lvol_chain(lvol, clone, rpc_bdev_lvol_add_clone_cb, request);
	
cleanup:
	free_rpc_bdev_lvol_add_clone(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_clone", rpc_bdev_lvol_add_clone, SPDK_RPC_RUNTIME)

static void
dummy_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *ctx)
{
}

struct rpc_vbdev_lvol_set_qos_limit {
	uint64_t	bdev_group_id;
	uint64_t	limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
};

static void
free_rpc_vbdev_lvol_set_qos_limit(struct rpc_vbdev_lvol_set_qos_limit *r)
{
}

static const struct spdk_json_object_decoder rpc_vbdev_lvol_set_qos_limit_decoders[] = {
	{"bdev_group_id", offsetof(struct rpc_vbdev_lvol_set_qos_limit, 
						bdev_group_id), 
		spdk_json_decode_uint64,true},
	{
		"rw_ios_per_sec", offsetof(struct rpc_vbdev_lvol_set_qos_limit,
					   limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"rw_mbytes_per_sec", offsetof(struct rpc_vbdev_lvol_set_qos_limit,
					      limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"r_mbytes_per_sec", offsetof(struct rpc_vbdev_lvol_set_qos_limit,
					     limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"w_mbytes_per_sec", offsetof(struct rpc_vbdev_lvol_set_qos_limit,
					     limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
};

static void
rpc_vbdev_lvol_set_qos_limit_complete(void *cb_arg, int status)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (status != 0) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}

static void
rpc_vbdev_lvol_set_qos_limit(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_vbdev_lvol_set_qos_limit req = {0, {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}};
	int i;

	if (spdk_json_decode_object(params, rpc_vbdev_lvol_set_qos_limit_decoders,
				    SPDK_COUNTOF(rpc_vbdev_lvol_set_qos_limit_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (req.limits[i] != UINT64_MAX) {
			break;
		}
	}

	if (i == SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES) {
		SPDK_ERRLOG("No rate limits specified\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, "No rate limits specified");
		goto cleanup;
	}

	// Group ID is compulsory for this RPC
	if(req.bdev_group_id == 0)
	{
		SPDK_ERRLOG("No group ID specified.\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, "No group ID specified");
		goto cleanup;
	}
	spdk_bdev_set_qos_rate_limits_to_group(req.bdev_group_id, req.limits, rpc_vbdev_lvol_set_qos_limit_complete, request);

cleanup:
	free_rpc_vbdev_lvol_set_qos_limit(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_set_qos_limit", rpc_vbdev_lvol_set_qos_limit, SPDK_RPC_RUNTIME)


struct rpc_vbdev_lvol_name_list {
	/* Number of lvol bdevs */
	size_t	num_lvols;
	/* List of lvol bdevs names */
	char	*names[RPC_MAX_LVOL_VBDEV];
};

struct rpc_vbdev_lvol_add_to_group {
	uint64_t	bdev_group_id;
	/* List of lvol bdevs names */
	struct rpc_vbdev_lvol_name_list  lvol_vbdev_list;
};

static void
free_rpc_vbdev_lvol_add_to_group(struct rpc_vbdev_lvol_add_to_group *req)
{
	for (size_t i = 0; i < req->lvol_vbdev_list.num_lvols; i++) {
		if(req->lvol_vbdev_list.names[i]) {
			free(req->lvol_vbdev_list.names[i]);
		}
	}
}
static int
decode_lvol_vbdev_names(const struct spdk_json_val *val, void *out)
{
	struct rpc_vbdev_lvol_name_list *lvols = out;
	return spdk_json_decode_array(val, spdk_json_decode_string, lvols->names,
				      RPC_MAX_LVOL_VBDEV, &lvols->num_lvols, sizeof(char *));
}

static const struct spdk_json_object_decoder rpc_vbdev_lvol_add_to_group_decoders[] = {
	{"bdev_group_id", offsetof(struct rpc_vbdev_lvol_add_to_group, bdev_group_id), spdk_json_decode_uint64,},
	{"lvol_vbdev_list", offsetof(struct rpc_vbdev_lvol_add_to_group, lvol_vbdev_list), decode_lvol_vbdev_names},
};


static void
rpc_vbdev_lvol_add_to_group_complete(void *cb_arg, int status)
{
	struct spdk_jsonrpc_request *request = cb_arg;
	if (status != 0) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}

static void
rpc_vbdev_lvol_add_to_group(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_vbdev_lvol_add_to_group req;
	struct spdk_bdev_desc *desc;
	size_t i = 0;
	int rc;
	char	*unique_bdev_name[RPC_MAX_LVOL_VBDEV];
	struct spdk_bdev * bdev = NULL;
	
	// Initilize the char array.
	for (i = 0; i < RPC_MAX_LVOL_VBDEV; i++) {
		req.lvol_vbdev_list.names[i] = NULL;
		unique_bdev_name[i] = NULL;
	}

	if (spdk_json_decode_object(params, rpc_vbdev_lvol_add_to_group_decoders,
				    SPDK_COUNTOF(rpc_vbdev_lvol_add_to_group_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	// Validate the list of lvols.
	for (i = 0; i < req.lvol_vbdev_list.num_lvols; i++) {
		rc = spdk_bdev_open_ext(req.lvol_vbdev_list.names[i], false, dummy_bdev_event_cb, NULL, &desc);
		if (rc != 0) {
			SPDK_ERRLOG("Failed to open bdev '%s': %d\n", req.lvol_vbdev_list.names[i], rc);
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto cleanup;
		}
		bdev = spdk_bdev_desc_get_bdev(desc);
		if(bdev->internal.qos != NULL) {
			SPDK_ERRLOG("Qos limits already set for lvol: '%s'. Please disable the limits before adding to the group.\n", req.lvol_vbdev_list.names[i]);
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Failed to add lvol to pool: Operation not permitted");
			spdk_bdev_close(desc);
			goto cleanup;
		}
		unique_bdev_name[i] = strdup(bdev->name);
		spdk_bdev_close(desc);
	}

	spdk_bdev_add_remove_bdev_to_pool(req.bdev_group_id, req.lvol_vbdev_list.num_lvols, unique_bdev_name, false,
					rpc_vbdev_lvol_add_to_group_complete,request);
cleanup:
	// Free the transient variable.
	for (i = 0; i < req.lvol_vbdev_list.num_lvols; i++) {
		if(unique_bdev_name[i]) {
			free(unique_bdev_name[i]);
		}
	}
	free_rpc_vbdev_lvol_add_to_group(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_add_to_group", rpc_vbdev_lvol_add_to_group, SPDK_RPC_RUNTIME)


/*******************/

struct rpc_vbdev_lvol_remove_from_group {
	uint64_t	bdev_group_id;
	/* List of lvol bdevs names */
	struct rpc_vbdev_lvol_name_list  lvol_vbdev_list;
};

static void
free_rpc_vbdev_lvol_remove_from_group(struct rpc_vbdev_lvol_remove_from_group *req)
{
	for (size_t i = 0; i < req->lvol_vbdev_list.num_lvols; i++) {
		if(req->lvol_vbdev_list.names[i]) {
			free(req->lvol_vbdev_list.names[i]);
		}
	}
}

static const struct spdk_json_object_decoder rpc_vbdev_lvol_remove_from_group_decoders[] = {
	{"bdev_group_id", offsetof(struct rpc_vbdev_lvol_remove_from_group, bdev_group_id), spdk_json_decode_uint64,},
	{"lvol_vbdev_list", offsetof(struct rpc_vbdev_lvol_remove_from_group, lvol_vbdev_list), decode_lvol_vbdev_names},
};


static void
rpc_vbdev_lvol_remove_from_group_complete(void *cb_arg, int status)
{
	struct spdk_jsonrpc_request *request = cb_arg;
	if (status != 0) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}

static void
rpc_vbdev_lvol_remove_from_group(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_vbdev_lvol_remove_from_group req;
	struct spdk_bdev_desc *desc;
	size_t i = 0;
	int rc;
	char	*unique_bdev_name[RPC_MAX_LVOL_VBDEV];
	
	// Initilize the char array.
	for (i = 0; i < RPC_MAX_LVOL_VBDEV; i++) {
		req.lvol_vbdev_list.names[i] = NULL;
		unique_bdev_name[i] = NULL;
	}

	if (spdk_json_decode_object(params, rpc_vbdev_lvol_remove_from_group_decoders,
				    SPDK_COUNTOF(rpc_vbdev_lvol_remove_from_group_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	// Validate the list of lvols.
	for (i = 0; i < req.lvol_vbdev_list.num_lvols; i++) {
		rc = spdk_bdev_open_ext(req.lvol_vbdev_list.names[i], false, dummy_bdev_event_cb, NULL, &desc);
		if (rc != 0) {
			SPDK_ERRLOG("Failed to open bdev '%s': %d\n", req.lvol_vbdev_list.names[i], rc);
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto cleanup;
		}

		unique_bdev_name[i] = strdup(spdk_bdev_desc_get_bdev(desc)->name);
		spdk_bdev_close(desc);
	}

	spdk_bdev_add_remove_bdev_to_pool(req.bdev_group_id, req.lvol_vbdev_list.num_lvols, unique_bdev_name, true,
					rpc_vbdev_lvol_remove_from_group_complete,request);
cleanup:
	// Free the transient variable.
	for (i = 0; i < req.lvol_vbdev_list.num_lvols; i++) {
		if(unique_bdev_name[i]) {
			free(unique_bdev_name[i]);
		}
	}
	free_rpc_vbdev_lvol_remove_from_group(&req);
}

SPDK_RPC_REGISTER("bdev_lvol_remove_from_group", rpc_vbdev_lvol_remove_from_group, SPDK_RPC_RUNTIME)