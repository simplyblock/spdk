#ifndef SPDK_TIERING_BITS_H
#define SPDK_TIERING_BITS_H

#include "spdk/priority_class.h"

#define TIERED_IO_MASK (1UL << 60)
#define FORCE_FETCH_MASK (1UL << 61) // force a fetch write even into already-fetched chunks in case of a client fetch
#define SYNC_FETCH_MASK FORCE_FETCH_MASK // in case of a regular client read, wait for all its pages to be fetched for any not in hot tier
#define FORCE_FLUSH_MASK FORCE_FETCH_MASK // force a flush of an untiered page in case of a client flush (if tiered, must not be completely non-dirty)
#define UNMAP_MODE_MASK FORCE_FETCH_MASK // tiered unmap mode 1 is full delete, tiered unmap mode 0 is client eviction
#define METADATA_PAGE_MASK (1UL << 62) // whether the pages accessed are metadata, always set by an lvol metadata channel
#define LBA_METADATA_BITS_MASK (TIERED_IO_MASK | FORCE_FETCH_MASK | METADATA_PAGE_MASK)


#define TIERED_BIT 1
#define FORCE_FETCH_BIT 2
#define SYNC_FETCH_BIT 4
#define FORCE_FLUSH_BIT 8
#define UNMAP_MODE_BIT 16
#define METADATA_PAGE_BIT 32

#endif