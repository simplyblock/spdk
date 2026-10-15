/*
 * NVMe-oF reservation state of lvol namespaces, kept in the lvol's blob metadata so
 * that every storage node serving the lvol sees the same reservations and a
 * replaced SPDK process gets them back. Other namespaces keep the default
 * operations, the JSON file named by ptpl_file.
 *
 * It lives in the nvmf event subsystem because it joins the NVMe-oF target and the
 * lvol bdev module, and neither library depends on the other: the operations are
 * installed before any namespace is added, and a namespace is reloaded whenever
 * the lvol module says its stored state may have changed under this node (it
 * became the leader, reread the metadata, or fetched the leader's state).
 *
 * Only the lvol's leader changes the state. A Register, Acquire, or Release that
 * arrives on another node is forwarded to the leader over the hub connection, the
 * leader executes it as the host that sent it, and the forwarding node applies the
 * state the leader then holds before the host hears the answer.
 */

#include "spdk/stdinc.h"
#include "spdk/nvmf.h"
#include "spdk/bdev.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/endian.h"

#include "event_nvmf.h"
#include "lvol/vbdev_lvol.h"

struct nvmf_lvol_resv_update {
	spdk_nvmf_ns_reservation_update_cb	cb_fn;
	void					*cb_arg;
};

static const struct spdk_nvmf_ns_reservation_ops *
nvmf_lvol_resv_default(void)
{
	return spdk_nvmf_get_default_ns_reservation_ops();
}

static struct spdk_bdev *
nvmf_lvol_resv_bdev(const struct spdk_nvmf_ns *ns)
{
	return spdk_nvmf_ns_get_bdev((struct spdk_nvmf_ns *)ns);
}

static bool
nvmf_lvol_resv_is_shared(const struct spdk_nvmf_ns *ns)
{
	return vbdev_lvol_is_lvol_bdev(nvmf_lvol_resv_bdev(ns));
}

static bool
nvmf_lvol_resv_is_ptpl_capable(const struct spdk_nvmf_ns *ns)
{
	/* The lvol's metadata persists, so Persist Through Power Loss is honored */
	return nvmf_lvol_resv_is_shared(ns) || nvmf_lvol_resv_default()->is_ptpl_capable(ns);
}

/* The stored state and its generation; an lvol that stores none has an empty state */
static int
nvmf_lvol_resv_read(struct spdk_bdev *bdev, struct spdk_nvmf_reservation_info *info,
		    uint64_t *generation)
{
	uint8_t buf[SPDK_NVMF_RESERVATION_INFO_ENCODED_MAX_LEN];
	size_t len = sizeof(buf);
	int rc;

	memset(info, 0, sizeof(*info));
	*generation = 0;
	rc = vbdev_lvol_resv_get(bdev, buf, &len);
	if (rc == -ENOENT) {
		return 0;
	}
	if (rc != 0) {
		return rc;
	}
	return spdk_nvmf_reservation_info_decode(buf, len, info, generation);
}

static int
nvmf_lvol_resv_load(const struct spdk_nvmf_ns *ns, struct spdk_nvmf_reservation_info *info)
{
	struct spdk_bdev *bdev = nvmf_lvol_resv_bdev(ns);
	uint64_t generation;

	if (!vbdev_lvol_is_lvol_bdev(bdev)) {
		return nvmf_lvol_resv_default()->load(ns, info);
	}
	return nvmf_lvol_resv_read(bdev, info, &generation);
}

static int
nvmf_lvol_resv_update(const struct spdk_nvmf_ns *ns, const struct spdk_nvmf_reservation_info *info)
{
	if (!nvmf_lvol_resv_is_shared(ns)) {
		return nvmf_lvol_resv_default()->update(ns, info);
	}
	/* An lvol's state is only ever written through update_async */
	return -ENOTSUP;
}

static void
nvmf_lvol_resv_update_done(void *cb_arg, int rc)
{
	struct nvmf_lvol_resv_update *ctx = cb_arg;

	if (rc != 0) {
		SPDK_ERRLOG("Storing reservation state in the lvol failed: %s\n", spdk_strerror(-rc));
	}
	ctx->cb_fn(ctx->cb_arg, rc);
	free(ctx);
}

static void
nvmf_lvol_resv_update_async(const struct spdk_nvmf_ns *ns,
			    const struct spdk_nvmf_reservation_info *info,
			    spdk_nvmf_ns_reservation_update_cb cb_fn, void *cb_arg)
{
	struct spdk_bdev *bdev = nvmf_lvol_resv_bdev(ns);
	struct spdk_nvmf_reservation_info current;
	struct nvmf_lvol_resv_update *ctx;
	uint8_t buf[SPDK_NVMF_RESERVATION_INFO_ENCODED_MAX_LEN];
	uint64_t generation;
	size_t len;
	int rc;

	if (!vbdev_lvol_is_lvol_bdev(bdev)) {
		cb_fn(cb_arg, nvmf_lvol_resv_default()->update(ns, info));
		return;
	}

	/*
	 * Each write carries the next generation, for nodes that compare what they hold.
	 * Stored state that cannot be read is kept: writing over it would discard it, and
	 * would restart at a generation every node holding a later one ignores.
	 */
	rc = nvmf_lvol_resv_read(bdev, &current, &generation);
	if (rc != 0) {
		SPDK_ERRLOG("The lvol's stored reservation state cannot be read, so it is not "
			    "replaced: %s\n", spdk_strerror(-rc));
		cb_fn(cb_arg, rc);
		return;
	}
	len = spdk_nvmf_reservation_info_encode(info, generation + 1, buf, sizeof(buf));
	if (len == 0) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		cb_fn(cb_arg, -ENOMEM);
		return;
	}
	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;
	vbdev_lvol_resv_put(bdev, buf, len, nvmf_lvol_resv_update_done, ctx);
}

struct nvmf_lvol_resv_forwarded {
	struct spdk_bdev			*bdev;
	spdk_nvmf_ns_reservation_forward_cb	cb_fn;
	void					*cb_arg;
};

static void
nvmf_lvol_resv_forwarded(void *cb_arg, int rc, uint8_t sct, uint8_t sc)
{
	struct nvmf_lvol_resv_forwarded *ctx = cb_arg;
	struct spdk_nvme_status status = { .sct = sct, .sc = sc };
	struct spdk_nvmf_reservation_info info;
	uint64_t generation;

	if (rc != 0) {
		/* The leader could not be reached; the host may retry */
		SPDK_ERRLOG("Forwarding a reservation command to the leader failed: %s\n",
			    spdk_strerror(-rc));
		status.sct = SPDK_NVME_SCT_GENERIC;
		status.sc = SPDK_NVME_SC_NAMESPACE_NOT_READY;
		ctx->cb_fn(ctx->cb_arg, &status, NULL);
	} else if (nvmf_lvol_resv_read(ctx->bdev, &info, &generation) == 0) {
		/* The state the leader holds now, which the forward installed */
		ctx->cb_fn(ctx->cb_arg, &status, &info);
	} else {
		/* The leader executed the command, but this node cannot apply the state it
		 * left: answering with the leader's status would report a reservation this
		 * node does not enforce. The host retries, and the retry finds the state. */
		SPDK_ERRLOG("The reservation state a forwarded command left cannot be read\n");
		status.sct = SPDK_NVME_SCT_GENERIC;
		status.sc = SPDK_NVME_SC_NAMESPACE_NOT_READY;
		ctx->cb_fn(ctx->cb_arg, &status, NULL);
	}
	free(ctx);
}

static int
nvmf_lvol_resv_forward(const struct spdk_nvmf_ns *ns, const struct spdk_uuid *hostid,
		       const char *hostnqn, const struct spdk_nvme_cmd *cmd,
		       const void *data, size_t data_len,
		       spdk_nvmf_ns_reservation_forward_cb cb_fn, void *cb_arg)
{
	struct spdk_bdev *bdev = nvmf_lvol_resv_bdev(ns);
	struct vbdev_lvol_resv_exec_msg msg = {};
	struct nvmf_lvol_resv_forwarded *ctx;

	/* The leader, and a namespace that is no lvol, execute the command here */
	if (!vbdev_lvol_is_lvol_bdev(bdev) || vbdev_lvol_resv_is_leader(bdev)) {
		return -EAGAIN;
	}
	if (data_len > sizeof(msg.data)) {
		return -EINVAL;
	}

	to_le32(&msg.magic, VBDEV_LVOL_RESV_EXEC_MAGIC);
	msg.version = VBDEV_LVOL_RESV_EXEC_VERSION;
	msg.opc = cmd->opc;
	msg.data_len = (uint16_t)data_len;
	msg.cdw10 = cmd->cdw10;
	msg.cdw11 = cmd->cdw11;
	memcpy(msg.hostid, hostid, sizeof(msg.hostid));
	if (data_len > 0) {
		memcpy(msg.data, data, data_len);
	}
	snprintf(msg.hostnqn, sizeof(msg.hostnqn), "%s", hostnqn ? hostnqn : "");

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}
	ctx->bdev = bdev;
	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;
	vbdev_lvol_resv_forward(bdev, &msg, nvmf_lvol_resv_forwarded, ctx);
	return 0;
}

static const struct spdk_nvmf_ns_reservation_ops g_nvmf_lvol_resv_ops = {
	.is_ptpl_capable = nvmf_lvol_resv_is_ptpl_capable,
	.update = nvmf_lvol_resv_update,
	.load = nvmf_lvol_resv_load,
	.update_async = nvmf_lvol_resv_update_async,
	.is_shared = nvmf_lvol_resv_is_shared,
	.forward = nvmf_lvol_resv_forward,
};

static void
nvmf_lvol_resv_reloaded(void *cb_arg, int rc)
{
	if (rc != 0 && rc != -ENOENT) {
		SPDK_ERRLOG("Reloading reservation state after an lvol refresh failed: %s\n",
			    spdk_strerror(-rc));
	}
}

/* The lvol module says the bdev's stored state may have changed under this node */
static void
nvmf_lvol_resv_changed(struct spdk_bdev *bdev, void *unused)
{
	struct spdk_nvmf_tgt *tgt;
	struct spdk_nvmf_subsystem *subsystem;
	struct spdk_nvmf_ns *ns;

	for (tgt = spdk_nvmf_get_first_tgt(); tgt; tgt = spdk_nvmf_get_next_tgt(tgt)) {
		for (subsystem = spdk_nvmf_subsystem_get_first(tgt); subsystem;
		     subsystem = spdk_nvmf_subsystem_get_next(subsystem)) {
			for (ns = spdk_nvmf_subsystem_get_first_ns(subsystem); ns;
			     ns = spdk_nvmf_subsystem_get_next_ns(subsystem, ns)) {
				if (spdk_nvmf_ns_get_bdev(ns) == bdev) {
					spdk_nvmf_ns_reload_reservation(subsystem, spdk_nvmf_ns_get_id(ns),
									nvmf_lvol_resv_reloaded, NULL);
				}
			}
		}
	}
}

/* The namespace that exposes the bdev, if any */
static struct spdk_nvmf_ns *
nvmf_lvol_resv_find_ns(struct spdk_bdev *bdev, struct spdk_nvmf_subsystem **subsystemp)
{
	struct spdk_nvmf_tgt *tgt;
	struct spdk_nvmf_subsystem *subsystem;
	struct spdk_nvmf_ns *ns;

	for (tgt = spdk_nvmf_get_first_tgt(); tgt; tgt = spdk_nvmf_get_next_tgt(tgt)) {
		for (subsystem = spdk_nvmf_subsystem_get_first(tgt); subsystem;
		     subsystem = spdk_nvmf_subsystem_get_next(subsystem)) {
			for (ns = spdk_nvmf_subsystem_get_first_ns(subsystem); ns;
			     ns = spdk_nvmf_subsystem_get_next_ns(subsystem, ns)) {
				if (spdk_nvmf_ns_get_bdev(ns) == bdev) {
					*subsystemp = subsystem;
					return ns;
				}
			}
		}
	}
	return NULL;
}

struct nvmf_lvol_resv_exec {
	vbdev_lvol_resv_exec_done	done;
	void				*done_arg;
};

static void
nvmf_lvol_resv_executed(void *cb_arg, const struct spdk_nvme_status *status)
{
	struct nvmf_lvol_resv_exec *ctx = cb_arg;

	ctx->done(ctx->done_arg, status->sct, status->sc);
	free(ctx);
}

/* On the leader: a command another node forwarded, executed as the host it names */
static void
nvmf_lvol_resv_exec(struct spdk_bdev *bdev, const struct vbdev_lvol_resv_exec_msg *msg,
		    vbdev_lvol_resv_exec_done done, void *done_arg, void *unused)
{
	struct spdk_nvmf_subsystem *subsystem = NULL;
	struct spdk_nvmf_ns *ns = nvmf_lvol_resv_find_ns(bdev, &subsystem);
	struct nvmf_lvol_resv_exec *ctx;
	struct spdk_nvme_cmd cmd = {};
	struct spdk_uuid hostid;
	int rc;

	if (ns == NULL) {
		done(done_arg, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
		return;
	}
	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		done(done_arg, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_INTERNAL_DEVICE_ERROR);
		return;
	}
	ctx->done = done;
	ctx->done_arg = done_arg;
	cmd.opc = msg->opc;
	cmd.cdw10 = msg->cdw10;
	cmd.cdw11 = msg->cdw11;
	memcpy(&hostid, msg->hostid, sizeof(hostid));
	rc = spdk_nvmf_ns_reservation_execute(subsystem, spdk_nvmf_ns_get_id(ns), &hostid,
					      msg->hostnqn, &cmd, msg->data, msg->data_len,
					      nvmf_lvol_resv_executed, ctx);
	if (rc != 0) {
		free(ctx);
		done(done_arg, SPDK_NVME_SCT_GENERIC,
		     rc == -ENOMEM ? SPDK_NVME_SC_INTERNAL_DEVICE_ERROR : SPDK_NVME_SC_INVALID_FIELD);
	}
}

void
nvmf_lvol_resv_init(void)
{
	spdk_nvmf_set_custom_ns_reservation_ops(&g_nvmf_lvol_resv_ops);
	vbdev_lvol_set_resv_changed_cb(nvmf_lvol_resv_changed, NULL);
	vbdev_lvol_set_resv_exec_cb(nvmf_lvol_resv_exec, NULL);
}

void
nvmf_lvol_resv_fini(void)
{
	vbdev_lvol_set_resv_changed_cb(NULL, NULL);
	vbdev_lvol_set_resv_exec_cb(NULL, NULL);
	spdk_nvmf_set_custom_ns_reservation_ops(spdk_nvmf_get_default_ns_reservation_ops());
}
