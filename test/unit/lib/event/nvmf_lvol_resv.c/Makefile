#  Unit tests of the nvmf event subsystem's lvol reservation glue, built with the lvol
#  bdev module's and lib/nvmf's functions stubbed.

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../../../..)

CFLAGS += -I$(SPDK_ROOT_DIR)/module/bdev -I$(SPDK_ROOT_DIR)/module

TEST_FILE = nvmf_lvol_resv_ut.c

include $(SPDK_ROOT_DIR)/mk/spdk.unittest.mk
