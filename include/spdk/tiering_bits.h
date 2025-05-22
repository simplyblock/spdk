#ifndef SPDK_TIERING_BITS_H
#define SPDK_TIERING_BITS_H

#include "spdk/priority_class.h"

#define TIERED_IO_MASK (1UL << (64 - NBITS_PRIORITY_CLASS - 3))
#define FORCE_FETCH_MASK (1UL << (64 - NBITS_PRIORITY_CLASS - 2)) // force a fetch write even into already-fetched chunks in case of a client fetch
#define SYNC_FETCH_MASK FORCE_FETCH_MASK // in case of a regular client read, wait for all its ranges on its pages to be fetched for any not in hot tier
#define FLUSH_MODE_MASK FORCE_FETCH_MASK // whether a tiered write should be pure flush (mode 1) or eviction (mode 0)
#define METADATA_PAGE_MASK (1UL << (64 - NBITS_PRIORITY_CLASS - 1)) // whether the pages accessed are metadata, always set by an lvol metadata channel

#define TOTAL_TIERING_MASK (TIERED_IO_MASK | FORCE_FETCH_MASK | METADATA_PAGE_MASK)
#define TIERING_BITS_POS (64 - NBITS_PRIORITY_CLASS - 3)
#define LBA_METADATA_BITS_MASK (PRIORITY_CLASS_MASK | TOTAL_TIERING_MASK)


#define TIERED_BIT 1
#define FORCE_FETCH_BIT 2
#define SYNC_FETCH_BIT 4
#define FLUSH_MODE_BIT 8
#define NOT_EVICT_BLOB_MD_BIT 16 // whether blob-specific metadata should in fact be unevictable (if lvolstore md is evictable)
#define DO_EVICT_BLOB_MD_BIT 32 // whether blob-specific metadata should in fact be evictable even if lvolstore md is unevictable
#define METADATA_PAGE_BIT 64

#endif