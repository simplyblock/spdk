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
 * became the leader, or reread the metadata).
 */

#include "spdk/stdinc.h"
#include "spdk/nvmf.h"
#include "spdk/bdev.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/thread.h"

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

static const struct spdk_nvmf_ns_reservation_ops g_nvmf_lvol_resv_ops = {
	.is_ptpl_capable = nvmf_lvol_resv_is_ptpl_capable,
	.update = nvmf_lvol_resv_update,
	.load = nvmf_lvol_resv_load,
	.update_async = nvmf_lvol_resv_update_async,
	.is_shared = nvmf_lvol_resv_is_shared,
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

void
nvmf_lvol_resv_init(void)
{
	spdk_nvmf_set_custom_ns_reservation_ops(&g_nvmf_lvol_resv_ops);
	vbdev_lvol_set_resv_changed_cb(nvmf_lvol_resv_changed, NULL);
}

void
nvmf_lvol_resv_fini(void)
{
	vbdev_lvol_set_resv_changed_cb(NULL, NULL);
	spdk_nvmf_set_custom_ns_reservation_ops(spdk_nvmf_get_default_ns_reservation_ops());
}
