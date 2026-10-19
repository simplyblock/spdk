/*
 * Unit tests of module/event/subsystems/nvmf/nvmf_lvol_resv.c, the glue that keeps an
 * lvol namespace's reservation state in the lvol. The lvol bdev module and lib/nvmf are
 * stubbed: what is under test is which state the glue stores, and with which
 * generation, given what the lvol already holds.
 */

#include "spdk/stdinc.h"

#include "spdk_internal/cunit.h"
#include "spdk_internal/mock.h"
#include "event/subsystems/nvmf/nvmf_lvol_resv.c"

static struct spdk_bdev g_bdev;

DEFINE_STUB(spdk_nvmf_get_default_ns_reservation_ops, const struct spdk_nvmf_ns_reservation_ops *,
	    (void), NULL);
DEFINE_STUB(spdk_nvmf_ns_get_bdev, struct spdk_bdev *, (struct spdk_nvmf_ns *ns), &g_bdev);
DEFINE_STUB(vbdev_lvol_is_lvol_bdev, bool, (struct spdk_bdev *bdev), true);
DEFINE_STUB(vbdev_lvol_resv_is_leader, bool, (struct spdk_bdev *bdev), true);
DEFINE_STUB_V(vbdev_lvol_resv_forward, (struct spdk_bdev *bdev,
					const struct vbdev_lvol_resv_exec_msg *msg,
					vbdev_lvol_resv_forward_cb cb_fn, void *cb_arg));
DEFINE_STUB_V(vbdev_lvol_set_resv_exec_cb, (vbdev_lvol_resv_exec_cb cb_fn, void *ctx));
DEFINE_STUB_V(vbdev_lvol_set_resv_changed_cb, (vbdev_lvol_resv_changed_cb cb_fn, void *ctx));
DEFINE_STUB_V(spdk_nvmf_set_custom_ns_reservation_ops,
	      (const struct spdk_nvmf_ns_reservation_ops *ops));
DEFINE_STUB(spdk_nvmf_get_first_tgt, struct spdk_nvmf_tgt *, (void), NULL);
DEFINE_STUB(spdk_nvmf_get_next_tgt, struct spdk_nvmf_tgt *, (struct spdk_nvmf_tgt *prev), NULL);
DEFINE_STUB(spdk_nvmf_subsystem_get_first, struct spdk_nvmf_subsystem *,
	    (struct spdk_nvmf_tgt *tgt), NULL);
DEFINE_STUB(spdk_nvmf_subsystem_get_next, struct spdk_nvmf_subsystem *,
	    (struct spdk_nvmf_subsystem *subsystem), NULL);
DEFINE_STUB(spdk_nvmf_subsystem_get_first_ns, struct spdk_nvmf_ns *,
	    (struct spdk_nvmf_subsystem *subsystem), NULL);
DEFINE_STUB(spdk_nvmf_subsystem_get_next_ns, struct spdk_nvmf_ns *,
	    (struct spdk_nvmf_subsystem *subsystem, struct spdk_nvmf_ns *prev_ns), NULL);
DEFINE_STUB(spdk_nvmf_ns_get_id, uint32_t, (const struct spdk_nvmf_ns *ns), 1);
DEFINE_STUB(spdk_nvmf_ns_reload_reservation, int, (struct spdk_nvmf_subsystem *subsystem,
		uint32_t nsid, spdk_nvmf_ns_reservation_reload_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_nvmf_ns_reservation_execute, int, (struct spdk_nvmf_subsystem *subsystem,
		uint32_t nsid, const struct spdk_uuid *hostid, const char *hostnqn,
		const struct spdk_nvme_cmd *cmd, const void *data, size_t data_len,
		spdk_nvmf_ns_reservation_execute_cb cb_fn, void *cb_arg), 0);

/* What the lvol holds: vbdev_lvol_resv_get() answers g_get_rc, or the stored bytes */
static int g_get_rc;
static uint8_t g_stored[64];
static size_t g_stored_len;

int
vbdev_lvol_resv_get(struct spdk_bdev *bdev, void *buf, size_t *len)
{
	if (g_get_rc != 0) {
		return g_get_rc;
	}
	SPDK_CU_ASSERT_FATAL(*len >= g_stored_len);
	memcpy(buf, g_stored, g_stored_len);
	*len = g_stored_len;
	return 0;
}

/* The codec: byte 0 is the generation, and g_decode_rc stands for a stored encoding
 * this build cannot read */
static int g_decode_rc;

int
spdk_nvmf_reservation_info_decode(const void *buf, size_t len,
				  struct spdk_nvmf_reservation_info *info, uint64_t *generation)
{
	if (g_decode_rc != 0) {
		return g_decode_rc;
	}
	memset(info, 0, sizeof(*info));
	*generation = ((const uint8_t *)buf)[0];
	return 0;
}

size_t
spdk_nvmf_reservation_info_encode(const struct spdk_nvmf_reservation_info *info,
				  uint64_t generation, void *buf, size_t buf_len)
{
	((uint8_t *)buf)[0] = (uint8_t)generation;
	return 1;
}

static int g_put_calls;
static uint64_t g_put_generation;

void
vbdev_lvol_resv_put(struct spdk_bdev *bdev, const void *buf, size_t len,
		    vbdev_lvol_resv_cb cb_fn, void *cb_arg)
{
	g_put_calls++;
	g_put_generation = ((const uint8_t *)buf)[0];
	cb_fn(cb_arg, 0);
}

static int g_update_rc;

static void
ut_update_done(void *cb_arg, int rc)
{
	g_update_rc = rc;
}

static void
ut_store(void)
{
	g_put_calls = 0;
	g_update_rc = 1;
	nvmf_lvol_resv_update_async((const struct spdk_nvmf_ns *)0x1,
				    &(struct spdk_nvmf_reservation_info) {}, ut_update_done, NULL);
}

static void
test_update_carries_the_next_generation(void)
{
	/* An lvol that stores no state yet gets the first generation */
	g_get_rc = -ENOENT;
	g_decode_rc = 0;
	ut_store();
	CU_ASSERT(g_update_rc == 0);
	CU_ASSERT(g_put_calls == 1);
	CU_ASSERT(g_put_generation == 1);

	/* Every later write carries the next one */
	g_get_rc = 0;
	g_stored[0] = 4;
	g_stored_len = 1;
	ut_store();
	CU_ASSERT(g_update_rc == 0);
	CU_ASSERT(g_put_calls == 1);
	CU_ASSERT(g_put_generation == 5);
}

static void
test_update_keeps_state_it_cannot_read(void)
{
	/* A stored encoding this build cannot decode is neither overwritten nor
	 * restarted at the first generation, which every node holding a later one
	 * would ignore */
	g_get_rc = 0;
	g_stored[0] = 9;
	g_stored_len = 1;
	g_decode_rc = -EPROTONOSUPPORT;
	ut_store();
	CU_ASSERT(g_update_rc == -EPROTONOSUPPORT);
	CU_ASSERT(g_put_calls == 0);

	/* Nor is state that could not be read at all */
	g_decode_rc = 0;
	g_get_rc = -EIO;
	ut_store();
	CU_ASSERT(g_update_rc == -EIO);
	CU_ASSERT(g_put_calls == 0);
}

static struct spdk_nvme_status g_fwd_status;
static bool g_fwd_had_info;
static int g_fwd_calls;

static void
ut_forward_done(void *cb_arg, const struct spdk_nvme_status *status,
		const struct spdk_nvmf_reservation_info *info)
{
	g_fwd_status = *status;
	g_fwd_had_info = info != NULL;
	g_fwd_calls++;
}

static void
ut_forwarded(int rc, uint8_t sct, uint8_t sc)
{
	struct nvmf_lvol_resv_forwarded *ctx = calloc(1, sizeof(*ctx));

	SPDK_CU_ASSERT_FATAL(ctx != NULL);
	ctx->bdev = &g_bdev;
	ctx->cb_fn = ut_forward_done;
	g_fwd_calls = 0;
	nvmf_lvol_resv_forwarded(ctx, rc, sct, sc);
	CU_ASSERT(g_fwd_calls == 1);
}

static void
test_forwarded_state_it_cannot_read(void)
{
	/* The leader's success comes back with the state it left */
	g_get_rc = 0;
	g_stored[0] = 3;
	g_stored_len = 1;
	g_decode_rc = 0;
	ut_forwarded(0, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_SUCCESS);
	CU_ASSERT(g_fwd_status.sc == SPDK_NVME_SC_SUCCESS);
	CU_ASSERT(g_fwd_had_info);

	/* A state this node cannot decode is not reported as the leader's success: the
	 * host would hold a reservation this node does not enforce. (Copilot review on
	 * #77, 4282821619.) */
	g_decode_rc = -EPROTONOSUPPORT;
	ut_forwarded(0, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_SUCCESS);
	CU_ASSERT(g_fwd_status.sct == SPDK_NVME_SCT_GENERIC);
	CU_ASSERT(g_fwd_status.sc == SPDK_NVME_SC_NAMESPACE_NOT_READY);
	CU_ASSERT(!g_fwd_had_info);
	g_decode_rc = 0;

	/* No state at all is an empty state, which applies */
	g_get_rc = -ENOENT;
	ut_forwarded(0, SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_SUCCESS);
	CU_ASSERT(g_fwd_status.sc == SPDK_NVME_SC_SUCCESS);
	CU_ASSERT(g_fwd_had_info);
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("nvmf_lvol_resv", NULL, NULL);

	CU_ADD_TEST(suite, test_update_carries_the_next_generation);
	CU_ADD_TEST(suite, test_update_keeps_state_it_cannot_read);
	CU_ADD_TEST(suite, test_forwarded_state_it_cannot_read);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();
	return num_failures;
}
