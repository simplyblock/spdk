# Snapshot Compaction & Deduplication — Technical Design Document

Status: **Draft for review**
Owner: (tbd)
Target branch: `dedup` (SPDK fork) + ultra `DISTR_v2`
Last updated: 2026-06-16

---

## 0. How to read this document

This design spans three codebases. The split was fixed up front and is load-bearing
for every section below:

| Concern | Codebase | Language |
|---|---|---|
| Extent-metadata on-disk format (type + offset), read/unmap resolution hook, **async compaction worker thread** | **SPDK** `lib/blob`, `lib/lvol` (this repo) | C |
| Hash pool, reference-extent cache + eviction, compaction-segment allocator + bitmaps, dedup decision logic, hash-pool persistence | **ultra** `DISTR_v2` | C++17 |
| Orchestration: take/delete internal snapshots, start compaction, poll status | **sbcli** | Python (RPC) |

Confirmed design constraints (from spec review):

- **Backward-compatible, opt-in per lvol.** Existing non-dedup volumes must load and run
  unchanged. Dedup is a per-lvol (per-blob) feature, gated by a new blob flag. Old SPDK
  binaries must still refuse new-format blobs cleanly (via the existing `invalid_flags`
  mechanism), never silently misread them.
- **Per-node / per-lvstore scope.** The hash pool, reference extents and compacted extents
  are local to a single SPDK data-plane node and its lvstore. The 64-bit address is unique
  within the node's lvstore by construction. There is **no** cross-node dedup, no shared
  hash pool, no distributed consistency protocol. However, its **important** that secondary 
  nodes are not short of any meta-data required to seamlessly continue operation on fail-over. 
  This also includes a relatively up-to-date version of the hash pool.   

Anything marked **[OPEN]** requires a future decision; each carries a proposed
default so implementation is not blocked, but the team should confirm.

---

## 1. Background & current state

SPDK logical volumes are blobs in a blobstore (`lib/blob/blobstore.c`,
`lib/lvol/lvol.c`). Relevant mechanics this design builds on (see also `doc/blob.md` and
`doc/dedup_blobstore_primer.md` if split out):

- A blob is a virtual volume divided into fixed-size **clusters** (extents); the lvstore
  default is configurable, we use **2 MiB** (`lvs_opts.cluster_sz`).
- `active.clusters[i]` maps logical cluster `i` → backing-device LBA, or `0` for a thin
  hole (`blobstore.h:41`).
- The current default cluster-map encoding is **EXTENT_TABLE + EXTENT_PAGE**
  (`SPDK_MD_DESCRIPTOR_TYPE_EXTENT_TABLE` / `_EXTENT_PAGE`, `blobstore.h:354`/`:367`).
  An EXTENT_PAGE is its own 4 KiB metadata page holding up to `SPDK_EXTENTS_PER_EP` (512)
  `uint32_t` cluster indices — i.e. today **one 32-bit cluster index per logical cluster**,
  no room for a type or an offset.
- **Snapshots** are read-only blobs. Taking a snapshot swaps the populated cluster map into
  a new read-only blob and leaves the live blob empty + thin, chained via `back_bs_dev`
  (`bs_snapshot_swap_cluster_maps`, `blobstore.c:8656`; `bs_create_blob_bs_dev`,
  `blob_bs_dev.c:287`). Reads fall through the chain cluster-by-cluster; writes trigger
  copy-on-write (`bs_allocate_and_copy_cluster`, `blobstore.c:3542`).
- The full data-plane stack (corrected after ultra exploration) is:

  ```
  NVMe-oF → lvol bdev → blobstore (lvstore) → raid0 → {distrib×N} → {alceml×M} → physical
  ```

  The **raid0-over-distribs** is the lvstore's backing bdev. A distrib manages its
  `ndcs+npcs` alceml devices *directly* (it does its own striping/parity; there is **no**
  raid0 between distrib and alceml — `bdev_distrib_impl.cpp`). alceml is page-based thin
  provisioning whose **page is 2 MiB — equal to the lvs extent and the distrib page** (§4.1);
  per-block allocation bitmap, free list, reads of unallocated regions return zeroes
  (`bdev_alceml_impl.cpp`).
- **Reference extents and compacted extents are regions of the lvstore's backing (raid0)
  address space** — i.e. ordinary blobstore clusters, just specially typed/used. A vLBA
  resolves to a raid0 LBA, which raid0 splits across distribs, which split across alceml.

> [!IMPORTANT]
> We compact **snapshots, not live data.** The live lvol is never rewritten in place.
> Compaction is thus run as an asynchronous background task. To ensure minimum compaction
> cadence of all data, regular auto-snapshots are used. 

---

## 2. Goals / Non-goals

### Goals
1. Reduce physical footprint of snapshot data by deduplicating 256 KiB segments that recur
   within a node's lvstore, and by relocating unique segments into densely-packed
   compacted extents. The main target for deduplication are VMs; hundreds or thousands of
   VMs may share significant amounts of data in their ephemeral on-disk images, leading to
   potential storage savings of 1:100 and more. While data of on-disk images may not be 
   perfectly aligned (can be shifted by single or multiple blocks), long contiguous ranges
   of blocks are usually identical. 
2. Keep dedup fully opt-in and backward compatible on disk.
3. Run compaction asynchronously in the background, with bounded chain depth (at most one
   live internal snapshot).
4. Survive node restart: recover extent metadata on examine, lazy-load reference extents,
   persist + reload the hash pool, reconcile bitmaps via GC.
5. No read amplification on the hot path **when the reference block is cached**.

### Non-goals
- Cross-node / cluster-global dedup.
- Deduplicating the live (writable) lvol data — only frozen snapshots/generations.
- Inline (write-path) dedup. Dedup happens during background compaction only.
- Changing the lvol bdev external contract (block size, etc.).
- Compression (orthogonal; the "compacted extent" name refers to dedup packing, not
  entropy compression).

---

## 3. Glossary

- **Extent / cluster** — a 2 MiB blob cluster.
- **Segment** — a 256 KiB contiguous range = 64 × 4 KiB blocks. Dedup granularity.
  8 segments per extent.
- **Block** — a 4 KiB unit. Hashing granularity.
- **Generation** — a compacted snapshot. Realized as an SPDK blob snapshot.
- **Internal snapshot** — a system-created snapshot used to enforce compaction cadence,
  invisible to the user. At most one *live* (not-yet-compacted) internal snapshot per chain.
- **Reference extent** — a special extent holding 64-byte **reference blocks**. One
  reference block describes one logical extent: 8 × 8-byte virtual LBAs, one per segment.
- **Compacted extent** — a regular-looking data extent that densely stores *unique*
  256 KiB segments copied during compaction. Referenced by virtual LBAs.
- **Virtual LBA (vLBA)** — a 64-bit, lvstore-unique address at 4 KiB-block granularity,
  decodable into (lvol/blob, extent, in-extent block offset). Stored as the hash-pool value
  and as the segment pointers inside reference blocks.

### 3.1 Two granularities — 4 KiB hashing vs 256 KiB dedup (load-bearing)

The hashing unit and the dedup unit are **deliberately different**, and the gap between them
is what makes the scheme effective. This distinction is fundamental, not an implementation
detail:

- **Hashing is per 4 KiB block.** Every 4 KiB block is fingerprinted independently
  (BLAKE3-128) and its location recorded in the hash pool as a vLBA. This fine granularity is
  precisely what lets us recognise two otherwise-identical ranges **even when one is shifted
  relative to the other** by one or several 4 KiB blocks. Matching reduces to "find 64
  consecutive vLBAs in the pool", so a duplicate run is found wherever it physically lives and
  at *whatever* block offset — not only when the two ranges happen to share the same 256 KiB
  alignment. A coarse 256 KiB fingerprint would miss every shifted duplicate (a single
  inserted/removed block would change the whole-segment hash).
- **Dedup — i.e. referencing and relocation — is per 256 KiB segment.** Although we *detect*
  duplication at 4 KiB, we only ever *reference* or *relocate* whole 256 KiB segments. This
  keeps reference blocks tiny (8 segment pointers per extent, §5.4), keeps compacted extents
  densely packed in 256 KiB slots (§5.5), and keeps reads chunk-aligned. In other words the
  coarse dedup unit **avoids the fragmentation** that a 4 KiB referencing granularity would
  cause — millions of tiny pointers and a shredded, RMW-heavy address space.

Consequently a segment qualifies for dedup only when *all 64* of its 4 KiB block fingerprints
are present in the pool **and** their stored vLBAs are **consecutive** — i.e. the matching
256 KiB exists contiguously at a single source location, possibly at a different block offset
than the segment being compacted (§9.2b). **Fine-grained detection, coarse-grained action.**

---

## 4. Address model (vLBA)  **[OPEN: bit layout]**

A single 64-bit address space, unique within an lvstore, is shared by:
- hash-pool values (hash → source data location), and
- reference-block segment pointers.

Granularity is **4 KiB block** (so that a 256 KiB segment is 64 consecutive vLBAs and
"contiguous range" reduces to "consecutive integers"). Proposed encoding:

```
 63                         40 39                  9 8            0
+-----------------------------+----------------------+-------------+
|   blob/lvol selector (24b)  |  cluster index (31b) | blk ofs (9b)|
+-----------------------------+----------------------+-------------+
```

- 9 bits block offset → 512 blocks per 2 MiB extent. ✓
- 31 bits cluster index → 2^31 × 2 MiB ≈ 4 EiB addressable per blob. Generous.
- 24 bits blob selector → 16 M blobs per lvstore.

The "blob selector" is **always a real blob page-id** (`bs_blobid_to_page`, `blobstore.h:627`)
— there are **no reserved selector values**. A node's lvstore will never hold more than 2²⁴
blobs, so 24 bits suffice with no truncation risk and no dense remapping table.

This is deliberate and load-bearing: **compacted extents are addressed by the real blob-id of
the (internal) blob that owns them**, not by a single reserved id. A reserved-id scheme would
confine *every* compacted extent in the lvstore to one blob's 31-bit cluster space — a hard
cap of 2³¹ clusters (≈ 4 PiB of compacted data per node), which is **not** acceptable. By
using real blob-ids, compacted extents may be spread across as many internal blobs as needed,
so the addressable compacted space is the full `2²⁴ blobs × 2³¹ clusters`. Compaction
allocates new internal blobs for compacted extents on demand, exactly like any other blob.

Consequently **every vLBA is uniform**: regular data, relocated/compacted segments — all are
`(blob, cluster, 4 KiB offset)` and all resolve through the owning blob's cluster map
(`bs_cluster_to_lba` over `active.clusters[]`). There is no separate "compacted address
space" and no second translation path (see §5.5 — this supersedes the earlier descriptor-table
idea). The only specially-managed pool with a compact index is the **reference-extent pool**,
which is *bounded* (hundreds of extents) and so is addressed by a small pool index in the
type-1 cluster entry rather than a full vLBA (§5.2, §5.4).

> The decode contract (`vLBA → backing LBA` via the owning blob's cluster map) lives in ultra
> and is the single source of truth; SPDK treats vLBAs as opaque 64-bit values it stores and
> hands back to the resolver hook (§7).

### 4.1 Relationship to the backing (raid0) address space

The vLBA addresses **logical blob content** (which blob, which cluster, which 4 KiB block).
The data physically lives at a **raid0 backing LBA** (what `clusters[i]` already holds today,
`blobstore.h:48`). These are different spaces:

- **vLBA** → identifies a piece of *dedup-tracked content* (hash-pool value, segment pointer).
- **backing LBA** → where blobstore reads/writes it on the raid0.

A **regular** (type `0`) cluster has a concrete backing LBA in `clusters[]`. A **reference**
(type `1`) cluster instead carries a pointer to a reference block (§5.2). Compacted extents
are never named directly by a snapshot's cluster map — they are reached only through the
vLBAs stored *inside* reference blocks, and are physically ordinary backing clusters owned by
the compaction machinery. A vLBA decodes (via the blob page-id, §4) to *the
blob+cluster+offset that owns that content*, and from there to the owning cluster's backing
LBA. So the resolver
(§7.1) ultimately returns **raid0 backing LBAs** to SPDK; everything below (raid0→distrib→
alceml placement) is unchanged and unaware of dedup.

**Granularity alignment.** The units already line up across the stack, so no special distrib
configuration is needed:

- distrib's **chunk** is the unit striped to one alceml device and is **4 KiB by default** —
  i.e. the same as the dedup *block* (hashing unit, §3.1), not the segment.
- a distrib **page is 2 MiB per extent**, which is **exactly the lvs extent size and the
  alceml page size**. So one 2 MiB blob cluster (dedup extent) = one distrib page = one alceml
  page — a clean 1:1:1 mapping with no cross-page split.

Within that 2 MiB page a 256 KiB dedup **segment** is a contiguous run of `256 KiB / 4 KiB =
64` chunks, and a 4 KiB block is one chunk. Because the segment and extent sizes are whole
multiples of the 4 KiB chunk, segment copies and reference reads are chunk-aligned **by
construction** — there is no read-modify-write amplification to design around, and nothing to
mandate at deployment time.

---

## 5. On-disk format changes (SPDK blobstore)

![Dedup extent types and how they map onto distrib pages](dedup_extent_types.png)

The figure above summarizes the on-disk model. A snapshot's basic structure (the sparse list
of allocated extents, chaining and fallback logic) is **unchanged**. When the dedup threshold
is **not** reached, an extent's allocation and mapping is also unchanged — a regular extent
still maps directly to a distrib page (2 MiB) via raid0. When the threshold **is** met, two
new extent types come into play — the **reference extent** and the **compacted extent**
("compaction extent" in the figure) — both of which map to underlying distrib pages exactly
like regular extents. A snapshot cluster entry pointing at a reference extent carries, in
addition to the extent's base address, an **offset** that selects one of the reference blocks
inside it (§5.2). A reference extent holds arrays of 64-bit addresses — `(blob-id, extent,
offset)` vLBAs (§4) — pointing at the start of each 256 KiB segment; **8 addresses per 2 MiB
extent**. A compacted extent stores the 256 KiB segments themselves, gathered from different
snapshot extents and possibly different snapshots, and those segments are reachable **only**
via the vLBAs stored in reference extents.

### 5.1 Requirement

Only **two** extent types are ever named directly by a snapshot's cluster map:

- **regular** (type `0`) — as today: a direct backing-LBA cluster index (widened).
- **reference** (type `1`) — points at one 64-byte reference block inside a reference extent.
  A bare 32-bit cluster index is **not** sufficient here: a reference extent packs up to
  **32768** reference blocks (§5.4), so the entry must also carry a **block offset** that
  selects one of them. The reference pointer is therefore `(reference-extent id, block
  offset ∈ [0, 32768))` — i.e. a ~32-bit extent id plus a 15-bit in-extent offset.

**Compacted extents are not a snapshot-referenceable type.** They are reached *only* through
the vLBAs stored inside reference blocks; physically each compacted extent is an ordinary
backing cluster of an **internal compaction blob** (shared across snapshots, §5.5), never
pointed at by a user/snapshot cluster-map entry. So each logical cluster needs, beyond
today's 32-bit index,
only a **1-bit type** and — for type `1` — the reference pointer above.

### 5.2 New descriptor: `EXTENT_PAGE_V2`  (backward compatible)

We do **not** mutate the existing `EXTENT_PAGE` layout (old binaries parse it). Instead add
a new descriptor type and a new blob feature flag:

```c
/* blobstore.h */
#define SPDK_MD_DESCRIPTOR_TYPE_EXTENT_PAGE_V2 7   /* new */
#define SPDK_BLOB_DEDUP            (1ULL << 4)      /* new invalid_flag bit */
```

`SPDK_BLOB_DEDUP` is added to `SPDK_BLOB_INVALID_FLAGS_MASK`. Effect: a blobstore binary
that does not understand dedup will see an unknown invalid_flag and **refuse to open** the
blob (existing safety behavior, `blobstore.h:377-382`), rather than misreading it. Volumes
without the flag are 100 % unaffected.

Per-cluster entry in `EXTENT_PAGE_V2` (8 bytes instead of 4):

```c
struct spdk_blob_extent_v2 {
    uint64_t type   : 1;   /* 0 = regular, 1 = reference */
    uint64_t value  : 63;  /* type 0: cluster index → backing LBA (as today, widened)
                              type 1: ref_extent_id : 32, ref_block_ofs : 15
                                      (selects 1 of up to 32768 reference blocks) */
};
```

- **Decided: 256 entries/page.** 8 B × 256 = 4096 B → one entry array per page, half the
  density of v1 (512 × 4 B). We accept more extent pages per blob in exchange for a far
  simpler parse than packing type bits into a side bitmap.
- The EXTENT_TABLE descriptor (`blobstore.h:354`) is reused unchanged; it already just
  points at extent pages. Only the page *contents* version changes.

### 5.2.1 How compatibility with the 512-entry v1 page is preserved

The concern is real: changing entries-per-page would break v1 pages **if** it changed the
shared offset math. It doesn't, because v1 and v2 are kept on strictly separate code paths
and **no v1 constant or call site is mutated**. Two facts from the current code make this work
(`lib/blob/blobstore.c`, `lib/blob/blobstore.h`):

1. **Entry *count* on parse is already self-describing — not hardcoded to 512.** The parser
   derives the number of entries from the descriptor's own `length` field divided by the entry
   stride:
   ```c
   /* blob_parse_page, blobstore.c:1041,1049 */
   cluster_idx_length = desc_extent->length - sizeof(desc_extent->start_cluster_idx);
   for (i = 0; i < cluster_idx_length / sizeof(desc_extent->cluster_idx[0]); i++) { ... }
   ```
   So a page may legally hold *fewer* entries than the max; `start_cluster_idx`
   (`blobstore.c:1074,1092`) anchors each page's first cluster. A v2 page simply declares its
   own `length`.

2. **Entry *stride* is fixed by the descriptor *struct*, which is selected by descriptor
   *type*.** v1's `spdk_blob_md_descriptor_extent_page.cluster_idx[0]` is a `uint32_t`
   (`blobstore.h:367-375`), so `sizeof(cluster_idx[0]) == 4`. v2 is a **new descriptor type
   (7) with its own struct** whose entry is the 8-byte `spdk_blob_extent_v2`. The existing
   `desc->type == SPDK_MD_DESCRIPTOR_TYPE_EXTENT_PAGE` parse branch (`blobstore.c:1028`) is
   touched **not at all**; a new `== ..._EXTENT_PAGE_V2` branch parses 8-byte entries. An old
   page (type 6) is therefore always read with the 4-byte stride, a v2 page (type 7) always
   with 8 — they cannot be confused.

The genuine hazard the question points at is the **cluster → extent-page divisor**, the
compile-time constant `SPDK_EXTENTS_PER_EP` (= 512, `blobstore.h:447-449`). It is *not*
self-describing and is baked into many sites that compute "which page holds cluster N" and
"how many pages does a blob of N clusters need":

| Site | Code |
|---|---|
| cluster → extent-page index | `bs_cluster_to_extent_table_id`, `blobstore.h:593-595` (`cluster_num / SPDK_EXTENTS_PER_EP`) |
| serialize: page's first cluster + fill cap | `blob_serialize_extent_page`, `blobstore.c:1488,1500` |
| resize: number of extent pages | `blobstore.c:2897-2898,2981-2982` (`spdk_divide_round_up(sz, SPDK_EXTENTS_PER_EP)`) |
| `remaining_clusters_in_et` bookkeeping | `blobstore.c:1986-1995` |
| sync / cluster-insert iteration | `blobstore.c:3176,11212,12844-12845` |

**Fix: do not change the global constant — make the divisor per-blob.** A blob is entirely v1
*or* entirely v2 (gated by `SPDK_BLOB_DEDUP`), so within one blob the divisor is constant and
the two formats never mix. Introduce `SPDK_EXTENTS_PER_EP_V2 = 256` and an accessor

```c
static inline uint64_t bs_extents_per_ep(const struct spdk_blob *blob) {
    return blob_is_dedup(blob) ? SPDK_EXTENTS_PER_EP_V2 : SPDK_EXTENTS_PER_EP;
}
```

then replace the bare `SPDK_EXTENTS_PER_EP` at the sites above with `bs_extents_per_ep(blob)`.
The only signature change of note: `bs_cluster_to_extent_table_id()` currently takes just
`cluster_num` (`blobstore.h:593`) and must also take the blob to pick the divisor.

Net effect: a v1 blob runs the identical 512 / 4-byte arithmetic and the unchanged type-6
parse branch (byte-for-byte the old behavior); a v2 blob runs 256 / 8-byte throughout; an old
binary refuses a v2 blob outright via `invalid_flags` (§5.2). No on-disk v1 page is ever
reinterpreted.

### 5.3 In-memory representation

`spdk_blob_mut_data` (`blobstore.h:41`) gains a parallel array so the existing
`clusters[]` fast paths keep working for regular extents:

```c
uint8_t  *cluster_types;     /* per logical cluster: 0 = regular, 1 = reference */
uint64_t *cluster_ref;       /* per logical cluster: (ref_extent_id, ref_block_ofs) for
                                type 1; unused for type 0 (clusters[] holds the LBA) */
```

For type `0` (regular), `clusters[i]` keeps its meaning (backing LBA) and all current
hot-path inlines (`bs_blob_io_unit_to_lba`, `bs_io_unit_is_allocated`,
`blobstore.h:648`/`:720`) work untouched. Only type `1` (reference) clusters take the new
resolution path (§7).

### 5.4 Reference extent layout (on backing dev, managed by ultra)

A **reference extent** is a 2 MiB pool extent carved into **32768 fixed-size 64-byte
reference blocks** (2 MiB / 64 B = 32768). One reference block fully describes the dedup
layout of **one logical 2 MiB extent** of a snapshot: it holds the 8 segment pointers (one
per 256 KiB segment), each a vLBA naming where that segment's data actually lives.

```c
/* ultra: one reference block — describes a single 2 MiB logical extent. */
#define DEDUP_SEGMENTS_PER_EXTENT  8      /* 2 MiB / 256 KiB                       */
#define DEDUP_REFBLK_SIZE          64     /* bytes; == 8 × sizeof(uint64_t)        */
#define DEDUP_REFBLKS_PER_EXTENT   32768  /* 2 MiB / 64 B                          */

struct dedup_ref_block {                  /* exactly 64 bytes, no padding */
    uint64_t segment_vlba[DEDUP_SEGMENTS_PER_EXTENT];
    /* segment_vlba[s] = start vLBA of the 256 KiB segment s.
     * 256 KiB = 64 consecutive 4 KiB blocks, so the segment occupies vLBAs [v, v+64).
     * A zero vLBA means "thin / unallocated segment" (no backing data).            */
};
```

A snapshot's **type-1 (reference)** cluster entry does *not* point at data — it points at one
of these reference blocks, via the `(ref_extent_id, ref_block_ofs)` pair from §5.2:

- `ref_extent_id` selects a reference extent in the pool (its descriptor → backing LBA, below);
- `ref_block_ofs ∈ [0, 32768)` selects the 64-byte reference block within that extent.

The pool itself is a flat table of extent descriptors, persisted alongside the hash pool
(§8/§10) and rebuilt on load:

```c
/* ultra: the reference-extent pool. Each extent is a (shared) cluster of an internal blob,
 * just like compacted extents (§5.5); base_backing_lba is that cluster's LBA, cached once at
 * load from the owning blob's clusters[] — not re-read per I/O. */
struct dedup_ref_extent_desc {
    uint64_t base_backing_lba;   /* raid0 LBA of this 2 MiB extent, in 4 KiB-block units */
    uint16_t shard;              /* which shard owns it (§8.4)                           */
    /* the 32768-bit ref-block allocation bitmap AND the per-ref-block refcounts (§7.4a)
     * live in the shard, not here (a ref block is exactly 64 B on disk with no room for a
     * refcount). The refcount counts how many live snapshots/generations point at the
     * block; the bitmap is just `refcount > 0`. */
};
struct dedup_ref_extent_desc ref_pool[N_REF_EXTENTS];   /* default N_REF_EXTENTS = 200 */
```

Resolving a reference cluster to the 4 KiB device block that holds its reference block (the
first hop of the read path, §7.1) is pure arithmetic — **no metadata page is read**:

```c
/* 64 reference blocks per 4 KiB device block (4096 / 64 = 64). */
uint64_t ref_block_device_lba(uint32_t ref_extent_id, uint32_t ref_block_ofs) {
    uint64_t base = ref_pool[ref_extent_id].base_backing_lba;   /* 4 KiB units */
    return base + (ref_block_ofs >> 6);          /* (ref_block_ofs * 64) / 4096 */
}
/* byte offset of the 64-byte block inside that 4 KiB device block: */
//   (ref_block_ofs & 63) * 64
```

ultra reads that 4 KiB block (or finds it in the reference-block cache, §8.2), slices out the
64-byte `dedup_ref_block`, then resolves each segment vLBA it needs (§5.5).

- One reference extent → layouts for up to **32768** logical extents.
- Pool of **200** reference extents (≈ 400 MiB), pseudo-randomly sharded by extent address
  to avoid hot-spotting (§8.4). Shards grow by allocating additional reference extents on
  demand when full.
- Addressing capacity sanity check: 200 × 32768 × 2 MiB ≈ **12.8 TiB** of *referenced
  logical* data per pool. **[OPEN]** the spec states "≈0.11 PB"; the arithmetic gives
  ~0.012 PB. Likely the intended pool/extent size is larger, or 0.11 PB is a typo. Flag to
  spec owner; the pool size is a tunable, not a correctness issue.

### 5.5 Compacted extent layout, and vLBA → backing-LBA translation

A **compacted extent** is an ordinary 2 MiB cluster of an **internal compaction blob** that
ultra fills with *unique* 256 KiB segments during compaction, sliced into **8 × 256 KiB
slots**. Because it is a real blob cluster it is named by a real `(blob, cluster)` and
addressed by an **ordinary vLBA** — no reserved selector, no separate compacted address space
(§4).

**Translation is the ordinary blob path — there is no second mechanism.** A compacted-segment
vLBA `(blob, cluster, blk_ofs)` resolves exactly like regular data, through the owning
internal blob's cluster map:

```c
uint64_t backing_lba(uint64_t vlba) {              /* identical for regular AND compacted */
    struct spdk_blob *b = blob_lookup(SELECTOR(vlba));            /* by blob page-id      */
    uint64_t cluster_lba = b->active.clusters[CLUSTER_IDX(vlba)]; /* in-memory array      */
    return cluster_lba + BLK_OFS(vlba);            /* 4 KiB units; blk_ofs ∈ [0, 512)     */
}
```

So the earlier worry — *"compacted extents have no metadata pages, how do we translate?"* —
dissolves: a compacted extent **is** a blob cluster and therefore **does** have the normal
`EXTENT_PAGE(_V2)` metadata, recovered into `active.clusters[]` on load. The hot path never
reads a metadata *page*; it reads the in-memory `clusters[]` array, exactly as every regular
read does today. The on-disk page only backs that array and is touched at load/sync. This is
also what removes the **2³¹-cluster cap** that a single reserved blob-id would impose:
compaction allocates **as many internal blobs as needed**, each contributing a fresh 31-bit
cluster space (§4).

**What ultra still tracks (and why it is *not* a translation table).** The compaction
machinery keeps a slot allocator + occupancy bitmap to pack unique segments and drive
unmap/GC — this is *allocation* metadata, not *address translation*:

```c
#define DEDUP_SLOTS_PER_CEXT  8            /* 2 MiB / 256 KiB */

struct dedup_compacted_extent {            /* one per 2 MiB compacted cluster */
    spdk_blob_id blob;                     /* internal compaction blob that owns it */
    uint32_t     cluster_idx;              /* its cluster within that blob          */
    uint8_t      slot_occupancy;           /* 1 bit per 256 KiB slot; drives §9/§10  */
    /* per-segment refcount lives in the hash pool's HashEntry */
};
```

A segment's backing location is *derived* from `(blob, cluster_idx)` + `slot×64` via the
formula above; `slot_occupancy` only answers "which slots are free / still referenced". The
authoritative occupancy is rebuilt by the GC metadata scan (§10.1).

**Ownership vs sharing — these extents are NOT exclusive to one snapshot.** A compacted slot
(and likewise a reference block, §5.4) is routinely pointed at by **many snapshots /
generations at once** — that is the whole point of dedup. So the internal compaction blob is
purely a **physical container**: it is *not* part of any user snapshot's chain, has no
`back_bs_dev` parent, and is never subject to per-snapshot COW or to snapshot-delete chain
merging. "Which snapshot owns this extent" is the wrong question; the extent is owned by the
compaction machinery and **shared by reference**:

- Sharing is expressed by vLBA — every sharer's reference block stores the *same* segment vLBA
  `(internal_blob, cluster, blk_ofs)`. There is no per-snapshot copy. This is exactly why the
  vLBA names the **internal** blob directly (§4) and resolution is independent of which
  snapshot is reading: any reader decodes the same absolute address.
- Lifetime is governed by **refcounts, not the snapshot chain.** The hash-pool `HashEntry`
  refcount (per relocated segment) and reference-block occupancy track how many live
  generations point in. Deleting one snapshot only *decrements* refs; a slot/reference block
  is freed (and its internal-blob cluster eventually reclaimed) only when its refcount hits
  zero, reconciled by the GC scan (§10.1). A shared extent therefore outlives any single
  snapshot that references it.

**Allocation & write concurrency.** Internal compaction blobs are grown **on demand and
filled sequentially**: a blob is filled extent-by-extent (slot-by-slot within each extent),
and once all of its clusters are allocated the next compaction blob is opened. The number of
internal blobs is therefore not fixed — it grows with the compacted footprint.

What *is* bounded is the **working set of concurrently-open compacted extents**: ultra keeps
roughly **200 open extents at any time** to write into, and spreads parallel segment writes
across them rather than funnelling every compaction worker at one extent. This matters because
a compacted extent is **shared across snapshots** — multiple workers (compacting different
snapshot blobs) may target the same extent at once. So reserving the slots to write into is
done under a **brief per-extent lock**:

1. lock the target extent, claim a free slot range (flip `slot_occupancy` bits + advance the
   allocator cursor), unlock — the lock is held only for the reservation, *not* for the copy;
2. copy the 256 KiB segment data into the reserved slot(s) outside the lock;
3. record each segment's vLBA `(internal_blob, cluster, slot×64)` in the reference block.

The ~200-wide open set keeps the chance of two workers colliding on one extent low; sharding
the open set by snapshot / extent address (as the reference pool does, §8.4) reduces it
further. The exact width (≈200) is a tunable, not a correctness property.

Reference extents are managed the same way (shared clusters of internal blob(s), ~200 open,
brief-lock slot reservation); the only difference is that the *bounded* reference pool is named
from a snapshot entry by a compact pool index (§5.2/§5.4) rather than a full vLBA, since there
are few reference extents.

### 5.6 Worked example — one extent, end to end

Take logical extent **E = cluster 5 of snapshot blob `0x20`**, a 2 MiB extent with 8 × 256 KiB
segments `seg0..seg7`. During compaction (§9) ultra found:

- `seg0,seg1` — a **duplicate** of an existing 512 KiB run already in the pool. Crucially the
  match was found at a **shifted offset**: the source is blob `0x41`, cluster 9, starting at
  block offset **64** (not 0) — exactly the case the 4 KiB hashing granularity (§3.1) buys us.
- `seg2..seg7` — **unique** → copied into free slots of a compacted extent that lives at
  **cluster 7 of internal compaction blob `0x1000`** (shared, see §5.5).

The new generation's metadata entry for cluster 5 becomes **type 1**, pointing at reference
block 17 of reference extent 3:

```
EXTENT_PAGE_V2 entry for (blob 0x20, cluster 5):
    type  = 1                       # reference
    value = ref_extent_id=3, ref_block_ofs=17
```

That reference block (read via §5.4 arithmetic: `ref_pool[3].base + (17>>6)`, byte
`(17&63)*64 = 1088` within the 4 KiB block) contains 8 segment vLBAs. Visualized:

```
snapshot blob 0x20, EXTENT_PAGE_V2[cluster 5]
        │  type=1  →  (ref_extent_id=3, ref_block_ofs=17)
        ▼
ref_pool[3].base_backing_lba ──► reference extent #3 (2 MiB = 32768 × 64 B)
                                 ┌───────────────── ref block 17 (64 B) ─────────────────┐
                                 │ seg_vlba[0] = {sel=0x41,   clu=9, blk=64 }            │  ┐ duplicate run,
                                 │ seg_vlba[1] = {sel=0x41,   clu=9, blk=128}            │  ┘ found SHIFTED (+64)
                                 │ seg_vlba[2] = {sel=0x1000, clu=7, blk=0  }            │  ┐
                                 │ seg_vlba[3] = {sel=0x1000, clu=7, blk=64 }            │  │
                                 │ seg_vlba[4] = {sel=0x1000, clu=7, blk=128}            │  │ unique segments,
                                 │ seg_vlba[5] = {sel=0x1000, clu=7, blk=192}            │  │ packed into cext
                                 │ seg_vlba[6] = {sel=0x1000, clu=7, blk=256}            │  │ blob 0x1000 / clu 7
                                 │ seg_vlba[7] = {sel=0x1000, clu=7, blk=320}            │  ┘
                                 └───────────────────────────────────────────────────────┘
        resolve each seg_vlba → backing LBA (ONE uniform path, §5.5):
        seg0,seg1  → bs_cluster_to_lba(blob 0x41,   clu 9) + blk     (data blob's cluster map)
        seg2..seg7 → bs_cluster_to_lba(blob 0x1000, clu 7) + blk     (internal blob's cluster map)

compacted extent = internal blob 0x1000, cluster 7 (2 MiB = 8 × 256 KiB slots), occ=1111_1100b
        ┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┐
        │ slot0 │ slot1 │ slot2 │ slot3 │ slot4 │ slot5 │ free  │ free  │   ← slots are shared:
        │ seg2  │ seg3  │ seg4  │ seg5  │ seg6  │ seg7  │       │       │     other snapshots'
        └───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┘     ref blocks may also
          blk0    blk64   blk128  blk192  blk256  blk320                       point at slot0..5
```

A read of extent E therefore costs: 1 reference-block lookup (cache hit ⇒ no device I/O,
§7.1) + the normal backing reads for the touched segments — all resolved through the **same**
`bs_cluster_to_lba` path, whether the owning blob is a data blob (`0x41`) or an internal
compaction blob (`0x1000`). No special compacted-extent metadata or descriptor table is
consulted.

---

## 6. Snapshot / generation model

### 6.1 Chain shape

```
live lvol --> [internal_snap_new] --> userN --> ... --> user1
```

Dedup operates only on snapshots. The spec's worked example is the contract:

```
start:  lvol -> us5 -> us4 -> us3 -> us2 -> internal -> us1     (all already compacted)
deadline reached, take new internal snapshot at head:
        lvol -> internal_new -> us5 -> us4 -> us3 -> us2 -> internal -> us1
merge (delete) the OLD internal snapshot into its parent (us2 side):
        lvol -> internal_new -> us5 -> us4 -> us3 -> us2 -> us1
now compact internal_new into a new generation.
```

Invariant: **at most one live (uncompacted) internal snapshot per chain.** Before creating a
new one, the previous internal snapshot must be merged away via the existing snapshot-delete
/ merge machinery (`delete_snapshot_*`, `blobstore.c:10961`+, which already merges a
snapshot's clusters into its single clone and re-links `back_bs_dev`).

### 6.2 Who does what
- **sbcli**: decides cadence, issues "create internal snapshot", "delete (merge) internal
  snapshot", "start compaction on lvol X", "get compaction status".
- **SPDK**: executes snapshot create/delete (existing RPCs), runs the compaction worker.
- **ultra**: performs the dedup decisions and data movement the worker calls into.

### 6.3 Crash fallback
During compaction the chain transiently holds both the source snapshot and the new
generation: `lvol -> new_snapshot -> old_snapshot`. **Neither old nor new is deleted until
the target generation is fully written and durable.** A crash mid-compaction leaves a valid,
readable chain; the partially-built generation is discarded and compaction restarts (§9.3).

---

## 7. I/O path

### 7.1 Resolver hook (the SPDK↔ultra contract)  **[OPEN: confirm shape]**

Because reference/compacted resolution needs the reference-block cache (ultra-owned), the
blobstore read path delegates non-regular clusters through a registered callback. Proposed
interface, registered per-lvstore at load:

```c
/* SPDK calls this for any reference (type 1) cluster */
struct spdk_dedup_resolve_req {
    spdk_blob_id   blob;
    uint64_t       io_unit;       /* offset within blob */
    uint32_t       length;        /* io units */
    uint64_t       cluster_ref;   /* ref pointer: (ref_extent_id, ref_block_ofs) */
    /* filled by ultra: list of (backing_lba, len) extents to read, in order */
};
typedef void (*spdk_dedup_resolver)(struct spdk_dedup_resolve_req *req,
                                    spdk_dedup_resolve_cb cb, void *cb_arg);
```

ultra's resolver:
1. Locate the 64-byte reference block named by `cluster_ref` (cache hit → in-memory; miss →
   lazy read from the reference extent on backing dev, insert into cache w/ eviction).
2. Read the 8 segment vLBAs; for the requested in-extent range, map each touched segment's
   vLBA → backing LBA (the vLBA decodes to a regular or compacted extent location).
3. Return the ordered (lba,len) scatter list. SPDK issues the backing reads and assembles.

Hot path with reference block cached = one extra in-memory lookup, **no extra device I/O**
(matches the spec's "no read amplification" goal). Cache miss = one 4 KiB-ish reference read
amplification, amortized by the cache.

**[OPEN]** Alternative considered: encode the reference indirection as a special
`back_bs_dev` so the existing fallback-chain read machinery handles it with no new hook. This
keeps blobstore unaware of dedup but forces reference-block caching to live behind a bs_dev,
which is awkward for eviction/persistence. Recommendation: **the explicit resolver hook**;
revisit if the bs_dev approach proves cleaner during prototyping.

### 7.2 Read

blobstore already splits an I/O at cluster boundaries (`blob_request_submit_op_split`), so the
new logic is per-cluster. A **regular** cluster takes the unchanged fast path; a **reference**
cluster is delegated to ultra, which returns a backing scatter list:

```c
/* SPDK: per-cluster read dispatch */
static void
dedup_read_cluster(struct spdk_blob *blob, uint64_t cluster_num,
                   uint32_t blk_in_cluster, uint32_t nblk, struct iovec *iov, read_ctx *ctx)
{
    if (blob->active.cluster_types[cluster_num] == CLUSTER_REGULAR) {
        uint64_t lba = bs_blob_io_unit_to_lba(blob, cluster_num * io_units_per_cluster
                                                    + blk_in_cluster);
        bs_batch_read_dev(ctx->batch, iov, lba, nblk);          /* unchanged fast path */
        return;
    }
    /* CLUSTER_REFERENCE → resolve through ultra (§7.1) */
    struct spdk_dedup_resolve_req req = {
        .blob        = blob->id,
        .cluster_ref = blob->active.cluster_ref[cluster_num],   /* (ref_ext_id, ref_blk_ofs) */
        .io_unit     = blk_in_cluster,
        .length      = nblk,
    };
    dedup_resolver(&req, dedup_read_resolved_cb, ctx);          /* async; cb issues reads */
}
```

ultra turns the reference cluster + touched range into ordered backing extents:

```c
/* ultra: resolve a reference-cluster read into backing (lba,len) extents */
int dedup_resolve(resolve_req *r, scatter_list *out) {
    ref_block_t *rb = refcache_get(REF_EXT(r->cluster_ref), REF_OFS(r->cluster_ref)); /* §8.2 */
    uint32_t seg_lo =  r->io_unit                    / BLKS_PER_SEG;   /* 64 blk / segment */
    uint32_t seg_hi = (r->io_unit + r->length - 1)   / BLKS_PER_SEG;

    for (uint32_t s = seg_lo; s <= seg_hi; s++) {
        uint64_t seg_vlba = rb->segment_vlba[s];
        /* clip the request to this segment */
        uint32_t blk0 = MAX(r->io_unit, s * BLKS_PER_SEG) - s * BLKS_PER_SEG;
        uint32_t cnt  = MIN(r->io_unit + r->length, (s + 1) * BLKS_PER_SEG)
                        - (s * BLKS_PER_SEG + blk0);
        if (seg_vlba == 0) {                       /* thin / unallocated segment */
            scatter_emit_zeroes(out, cnt);
            continue;
        }
        uint64_t lba = backing_lba(seg_vlba + blk0);   /* §5.5 — uniform bs_cluster_to_lba path */
        scatter_emit(out, lba, cnt);
    }
    scatter_coalesce(out);     /* merge adjacent (lba,len) — contiguous post-compaction runs */
    return 0;
}
```

- The reference-block lookup is the only added step; on a **cache hit it is a pure in-memory
  lookup, no device I/O** → meets the "no read amplification when cached" goal (§2). A miss
  costs one 4 KiB reference read, amortized by the cache (§8.2).
- Segments whose `vLBA == 0` read as zeroes (thin). Adjacent segments that resolve to
  consecutive backing LBAs (the common case once compaction packs a run) coalesce into one
  backing read.
- **Snapshot fallback chain unchanged** (`blob_bs_dev.c`): a hole in the live lvol falls
  through `back_bs_dev` to the snapshot; if that snapshot cluster is type `1` it resolves via
  the same path there.

### 7.3 Write

Writes only ever hit the **live** lvol, which is never dedup'd (only frozen snapshots are
compacted, §9). So no write creates or mutates a reference/compacted extent — the write path's
only new responsibility is **COW from a backing snapshot cluster that is itself dedup'd**.
Cases for a write to live-lvol cluster `c`:

| Case | live cluster `c` | backing snapshot cluster | action |
|------|------------------|--------------------------|--------|
| **W1** | already allocated (private regular) | — | write in place — **unchanged** |
| **W2** | thin hole, **full**-cluster write | any (overwritten whole) | allocate fresh regular cluster, write — **unchanged**; no copy-up |
| **W3** | thin hole, **partial** write, backing type `0` | regular | standard COW copy-up + overlay — **unchanged** (`bs_allocate_and_copy_cluster`, `blobstore.c:3542`) |
| **W4** | thin hole, **partial** write, backing type `1` | reference (dedup'd) | COW whose **read-half goes through the resolver** (§7.1), then overlay the written range |

W4 is the only new path:

```c
/* SPDK: COW copy-up when the backing cluster is a dedup reference (type 1) */
static void
dedup_cow_copyup_w4(struct spdk_blob *blob, uint64_t cluster_num, write_ctx *ctx)
{
    uint64_t new_lba = bs_allocate_cluster(blob, cluster_num);   /* fresh REGULAR cluster */

    /* read-half: pull the whole backing cluster through the resolver into a bounce buffer */
    struct spdk_dedup_resolve_req req = {
        .blob        = blob->id,
        .cluster_ref = backing_cluster_ref(blob, cluster_num),  /* the snapshot's type-1 ptr */
        .io_unit     = 0,
        .length      = io_units_per_cluster,
    };
    dedup_resolver(&req, /* on assembled bounce: */ dedup_cow_overlay_and_write, ctx);
}

static void
dedup_cow_overlay_and_write(read_ctx *rc, write_ctx *ctx) {
    memcpy_overlay(ctx->bounce, ctx->write_iov, ctx->offset, ctx->len);  /* apply the write */
    bs_write(ctx->blob, ctx->new_lba, ctx->bounce, io_units_per_cluster, ctx->cb);
    ctx->blob->active.cluster_types[ctx->cluster_num] = CLUSTER_REGULAR; /* now private */
}
```

Invariants that make this safe:

- The result is always a **private, regular (type 0)** cluster. Writing to a dedup'd region
  transparently **un-shares** it; the shared compacted segment is untouched and still
  referenced by the snapshots that point at it.
- **No refcount change on write.** The live lvol never *owned* the shared segment — it only
  read through `back_bs_dev`. Refcounts move only on compaction (+1), snapshot delete (−1),
  and unmap (−1) (§7.4, §9). This is why a write can never strand or double-free shared data.
- A **full-cluster** overwrite over a dedup backing (W2) skips the read-half entirely — there
  is nothing to preserve — so dedup adds zero cost there.

### 7.4 Unmap

Unmap first de-allocates from the underlying virtualized storage (already journaled by ultra
to backing storage — the durability anchor for GC reconciliation, §10.1). The dedup-specific
work is **decrementing the shared refcounts** and freeing slots / reference blocks / extents
only when they reach zero. Cases for an unmap of live-lvol or snapshot cluster `c`:

#### 7.4a Reference-count invariant (spec remark — load-bearing)

> Both shared object kinds carry a reference count of how many live snapshots/generations
> point into them:
> - a **compacted segment** (256 KiB slot) — counted by `HashEntry.refcount` (§8.1);
> - a **reference block** (and, transitively, the **reference extent** that contains it) —
>   counted by the per-ref-block refcount kept in the shard (§5.4).
>
> An object **must not be removed merely because the snapshot that directly references it is
> deleted, or because that snapshot unmaps the extent.** Either event only *decrements* the
> count. The slot / reference block / extent is reclaimed **only when its refcount reaches
> zero** — i.e. when no live snapshot references it any longer — because active references
> from other snapshots may still exist. This is precisely what makes a shared extent outlive
> any single snapshot that references it (§5.5), and why deletion is reference-counted rather
> than chain-driven. The same multi-referrer sharing applies to **reference blocks**: an
> unmodified extent carried forward by pointer into a new generation (§9.2a) leaves *two*
> generations pointing at the *same* reference block, so the block's refcount is ≥ 2 and a
> delete/unmap of either one alone must not free it.

| Case | cluster `c` | action |
|------|-------------|--------|
| **U1** | regular, whole cluster | free the cluster, return to allocator — **unchanged** |
| **U2** | regular, partial | punch hole within the cluster — **unchanged** |
| **U3a** | reference (type 1), **whole cluster** | drop this snapshot's reference to the block: `ref_block_unref()` (§7.4a), which decrements the block's refcount and, only on its last referrer, cascades `seg_unref()` per segment |
| **U3b** | reference (type 1), **partial** | only the fully-covered 256 KiB segments are affected; partially-covered segments are left intact. If the block is **shared** (refcount ≥ 2) it must first be **COW-cloned** for this snapshot (fresh reference block, decrement the shared one) before zeroing the covered segments' vLBAs and `seg_unref()`-ing them — never mutate a block another generation still points at |

`seg_unref` is where a **segment's** shared lifetime is resolved — freeing cascades only when
the last referrer drops; the reference *block's* lifetime is resolved one level up by its own
refcount (§7.4a):

```c
/* ultra: drop one reference to a relocated segment; cascade frees on last ref */
void seg_unref(uint64_t seg_vlba) {
    HashEntry *e = hashpool_find_by_vlba(seg_vlba);   /* §8.1; may be evicted → metadata scan */
    if (e && --e->refcount > 0)
        return;                                        /* still shared by other snapshots */

    /* last referrer gone → free the 256 KiB slot in its compacted extent */
    compacted_extent *ce = cext_of(seg_vlba);          /* (blob, cluster) from §5.5 */
    uint32_t slot = SLOT_OF(seg_vlba);                 /* (blk_ofs / 64) within the 2 MiB */
    ce->slot_occupancy &= ~(1u << slot);               /* §3a: free slot → refillable */
    if (e) hashpool_remove(e);

    if (ce->slot_occupancy == 0)                       /* §3b: all 8 slots free */
        compacted_extent_release(ce);                  /* return the 2 MiB cluster */
}
```

And the reference block itself is reclaimed only when the **last snapshot** referencing it
goes away — driven by its refcount, not by scanning its segment pointers (a shared block still
describes live segments for the *other* generations that point at it, §7.4a):

```c
/* called once per snapshot cluster entry that stops pointing at this block —
 * i.e. on unmap of a type-1 cluster (§7.4 U3a) or on snapshot delete (§9). */
void ref_block_unref(uint32_t ref_ext_id, uint32_t ref_blk_ofs) {
    if (ref_block_dec_refcount(ref_ext_id, ref_blk_ofs) > 0)
        return;                                        /* other generations still point here */

    /* last referrer gone → drop the segment refs this block held, then free the block */
    ref_block_t *rb = refcache_get(ref_ext_id, ref_blk_ofs);
    for (int s = 0; s < SEGMENTS_PER_EXTENT; s++)
        if (rb->segment_vlba[s])
            seg_unref(rb->segment_vlba[s]);            /* cascades to slot/extent free above */
    ref_extent_free_block(ref_ext_id, ref_blk_ofs);    /* 64-byte block returns to the shard;
                                                          a reference extent whose blocks are
                                                          all free is released like a cext */
}
```

Note the ordering: a reference block drops its segment references (`seg_unref`, which in turn
honors each segment's own refcount) **only on its own last referrer**, so a compacted segment
is never freed while any live reference block — for any snapshot — still names it.

- **Anti-fragmentation (spec §3a):** a freed slot is immediately re-fillable by future
  compaction; the extent's `slot_occupancy` is the free list.
- **Extent release (spec §3b):** an all-free compacted extent's 2 MiB cluster goes back to the
  blobstore allocator.
- Refcounts live in the hash-pool `HashEntry.refcount` (§8.1); slot/reference occupancy lives
  in the ultra bitmaps (§5.5, §5.4). Decrements are driven by unmap (here) and by snapshot
  delete (§9). Because occupancy is best-effort in memory, the authoritative state is rebuilt
  by the GC metadata scan after a crash (§10.1).

---

## 8. ultra data structures (C++)

### 8.1 Hashing & the hash pool

**Fingerprint.** Each 4 KiB block is fingerprinted with **BLAKE3-128** (the 128-bit prefix of
a BLAKE3 digest): fast (SIMD, multi-GB/s/core), strong collision resistance, and a compact
16-byte key. Hashing runs *only* during compaction, over modified segments (§9) — never on the
read/write hot path.

```cpp
struct Hash128 { uint64_t hi, lo; };

static inline Hash128 fingerprint(const void *blk4k) {
    uint8_t d[16];
    blake3_hash(blk4k, 4096, d, sizeof d);
    return { load_le64(d), load_le64(d + 8) };
}
```

**What the pool is — and isn't.** The hash pool is an **index for finding duplicate source
data during compaction**: `fingerprint(4 KiB block) → a vLBA where an identical block already
lives`. It is fundamentally a **cache** — evicting an entry only forgoes a *future* dedup
opportunity, never correctness. The **authoritative** lifetime of a compacted segment is the
set of reference blocks across all live generations, reconciled by GC (§10.1); the per-entry
`refcount` is a denormalized accelerator for the resident case (so inline unmap, §7.4, can
free immediately when the entry is present, and defer to GC when it isn't). Because it is only
needed to *find* duplicates during compaction, the hash pool is **maintained solely on the
active node**; standbys carry none and materialize one from the checkpoint only on promotion
(§10.2.2).

```cpp
struct HashEntry {
    Hash128  key;          // fingerprint (kept for open-addressed probing + rehash)
    uint64_t vlba;         // location of this block's data, 4 KiB granularity (§4)
    uint32_t refcount;     // accelerator: # live generations referencing the segment this heads
    uint32_t generation;   // creating generation (aging / tie-break)
    uint16_t flags;        // CLOCK ref-bit, S3-FIFO queue id, checksum-present
    uint32_t weak_csum;    // optional cheap verify before trusting a match (§11)
};
```

**Sharded, open-addressed.** Each shard is an independent map + lock + eviction state, so
shards scale across cores and a compaction worker only contends on the shard it probes:

```cpp
struct HashShard {
    HashEntry      *table;      // open-addressed (Robin Hood / linear probe)
    size_t          cap, used;
    s3fifo_clock_t  evict;      // §8.2.1 — shared eviction discipline
    critsec_t       lock;       // ultra critsec_t (§8.5)
};
static inline uint32_t shard_of(Hash128 h) { return (h.hi >> K) & (n_shards - 1); }
```

**Contiguity match — the dedup test, in code.** A 256 KiB segment is a dedup candidate iff
*all 64* of its block fingerprints are present **and** their stored vLBAs are **consecutive**
(one contiguous 256 KiB source, possibly at a shifted offset, §3.1):

```cpp
/* returns the source start-vLBA if the 64-block segment is a contiguous duplicate, else 0 */
uint64_t segment_dup_match(const Hash128 fp[64]) {
    HashEntry *h0 = shard_lookup(fp[0]);
    if (!h0) return 0;
    uint64_t base = h0->vlba;                       /* candidate source start */
    for (uint32_t i = 1; i < 64; i++) {
        HashEntry *h = shard_lookup(fp[i]);
        if (!h || h->vlba != base + i) return 0;    /* missing or non-consecutive → no match */
    }
    return base;                                    /* 64 consecutive blocks ⇒ contiguous 256 KiB */
}
```

`shard_lookup` also ticks the CLOCK ref-bit and S3-FIFO promotion (§8.2.1). On a confirmed
unique segment, compaction inserts its 64 fingerprints pointing at the freshly written slot
(refcount=1) so later runs can dedup against it:

```cpp
void hashpool_insert_segment(const Hash128 fp[64], uint64_t slot_start_vlba, uint32_t gen) {
    for (uint32_t i = 0; i < 64; i++)
        shard_insert(fp[i], slot_start_vlba + i, gen);   /* admission via S3-FIFO (§8.2.1) */
}
```

**[OPEN]** `shard_count` default = next pow2 ≥ 4×cores; `weak_csum` verify on/off (§11).

### 8.2 Reference-block cache

Caches the 64-byte reference blocks read by the resolver (§7.1). Residency is **per reference
extent** (simpler, and matches "keep as many reference extents resident as possible") with a
**per-block dirty bitmap** so a single modified reference block can be written back without
rewriting the 2 MiB extent:

```cpp
struct RefExtentCacheLine {
    uint32_t        ref_ext_id;
    void           *page;        // the resident 2 MiB extent (or a sub-page window)
    uint64_t        dirty[512];  // 1 bit per 64-byte ref block (32768 blocks / 64)
    s3fifo_clock_t  evict_state; // §8.2.1
};
```

```cpp
/* lookup used by the resolver and by ref_block_unref (§7.4) */
ref_block_t *refcache_get(uint32_t ref_ext_id, uint32_t ref_blk_ofs) {
    RefExtentCacheLine *l = cache_find(ref_ext_id);
    if (!l) {                                            /* miss */
        l = cache_admit(ref_ext_id);                     /* may evict a victim (writeback if dirty) */
        uint64_t lba = ref_pool[ref_ext_id].base_backing_lba;   /* §5.4 */
        backing_read(lba, l->page, REF_EXTENT_BYTES);    /* one lazy device read */
    }
    clock_touch(&l->evict_state);                        /* §8.2.1 */
    return (ref_block_t *)((char *)l->page + ref_blk_ofs * DEDUP_REFBLK_SIZE);
}

void refcache_mark_dirty(RefExtentCacheLine *l, uint32_t ref_blk_ofs) {
    l->dirty[ref_blk_ofs >> 6] |= 1ull << (ref_blk_ofs & 63);
}
```

On eviction a dirty line writes back only the dirty 64-byte blocks (gathered from the bitmap)
before its buffer is reclaimed; a clean line is dropped. This bounds the steady-state read
amplification to compulsory misses (§7.1).

### 8.2.1 Shared eviction discipline — S3-FIFO + CLOCK

Both the hash pool and the reference-block cache use the **same** eviction module (one
implementation, two instantiations). S3-FIFO handles *admission* (keep scan-resistant, drop
one-hit-wonders cheaply); CLOCK handles *resident* eviction:

```cpp
struct s3fifo_clock_t {
    fifo_t  small;     // new keys land here (≈10% capacity)
    fifo_t  main;      // promoted (twice-seen) keys; CLOCK ref-bit per entry
    ghost_t ghost;     // keys only, no value (≈90% by key count) — recently evicted
    uint32_t hand;     // CLOCK hand into `main`
};
```

- **Admit:** a fingerprint/extent first enters `small`. If it is hit again before aging out, it
  is **promoted to `main`**; otherwise it is evicted from `small` cheaply (its key drops to
  `ghost`). Most unique 4 KiB blocks are never seen twice, so this keeps them from polluting
  the resident set — exactly the dedup access pattern.
- **Rehit from ghost** → admit straight to `main` (it was wrongly evicted once).
- **CLOCK evict (on pressure in `main`):** sweep from `hand`, clearing each ref-bit; evict the
  first entry whose ref-bit is already 0. `clock_touch()`/`shard_lookup` set the ref-bit, so
  hot entries survive a sweep.
- The hash pool just discards a victim (it is a pure index). The reference-block cache writes
  back dirty 64-byte blocks (§8.2) before discarding.

**[OPEN]** Exact `small:main:ghost` ratios are tunables; defaults small = 10 %, ghost = 90 %
of capacity by key count. Build on the existing ultra primitives (`cppringbuf1_t`,
`t_spdk_bitpool` for ref-bits) — only the small/main/ghost coordinator is new (§8.5).

### 8.3 Compaction-segment allocator

- A **working set of ~200 concurrently-open compacted extents**, each with an 8-slot
  occupancy bitmap. Internal compaction blobs are filled sequentially (extent-by-extent) and a
  new blob is opened when the current one is full (§5.5).
- Allocates the next free 256 KiB slot for a unique segment under a **brief per-extent lock**
  (reserve range → unlock → copy outside the lock), spreading writes across the open set to
  avoid contention on a shared extent (§5.5). Opens another extent when the open ones fill;
  releases an extent when its bitmap is all-zero (§7.4).

### 8.4 Reference-extent sharding (anti-congestion)

`ref_shard = mix(extent_address) % n_ref_shards` where `mix` is a cheap bijective hash, so
sequential extents scatter across reference extents instead of piling onto one. Within a
shard, reserve the next free 64-byte reference block; grow the shard (new reference extent)
when full.

### 8.5 Reuse inventory — build on existing ultra primitives, don't reinvent

ultra exploration found solid building blocks. The dedup caches are **assembled** from these,
not written from scratch. Eviction policy (S3-FIFO + CLOCK) is the only genuinely new logic.

| Need | Reuse | Location | Notes |
|---|---|---|---|
| Per-shard hash map (hash pool, dedup index) | `hashx` / `hashx2` (open-addressing, O(1), resizable) | `src_code_3p/bmdx/vecm_hashx.h` | No eviction built in — we wrap it. |
| S3-FIFO small/main/ghost queues | `cppringbuf1_t` (lock-free ring) | `src_code_3p/bmdx/bmdx_cpiomt.h` | O(1) push/pop, concurrent. |
| Cache-entry / reference-block allocation | `util_hf_objpool_t`, `wrapper_mempool_spdk`, `wrapper_mempool_custom` (ref-counted, DMA-aware) | `utils/util_hf_mempool_spdk.hpp` | Derive entries from `util_hf_elem_base_t` for auto-free. |
| CLOCK reference bits; compacted-extent slot bitmaps | `t_spdk_bitpool`, `t_spdk_bit_array_wrapper` | `utils/util_spdk_bit_array_wrapper.h` | `nbits_set()` gives occupancy counts. |
| Per-shard locking; lock-free counters | `critsec_t`; `atomrdal64` / `atomadd64` | `src_code_3p/bmdx/bmdx_cpiomt.h` | Recursive, timeout-able locks. |
| Range bookkeeping (optional) | `map_range_int_t`, `sliding_sum_t` | `utils/util_range_map.h`, `utils/util_sliding_sum.hpp` | For stats/aging windows. |

**New code to write**: the S3-FIFO admission + CLOCK eviction wrapper around `hashx`, the
sharding coordinator (`shard[N]` of `{hashx + critsec_t}`), and the dedup decision logic.

**Cryptographic hash is NOT vendored.** No BLAKE3 / SHA / xxHash exists; alceml's only
checksum is a weak 8-byte XOR per 4 KiB block (`ultra-checksum-validation`
`bdev_alceml_impl.cpp::calculate_checksum`), usable at most as a cheap secondary check, not
as the dedup fingerprint. **BLAKE3-128 must be vendored** into ultra `3rdparty/` (Phase 0).
`bmdx`'s `hashx` hashing is for container bucketing only — not a content fingerprint.

### 8.6 Threading & integration with ultra

- The **compaction worker is SPDK-side** (lvs thread, §9.1). It calls into ultra for dedup
  decisions and data movement. ultra already has the precedent for background work:
  `spdk_thread_create` + `SPDK_POLLER_REGISTER` + `spdk_thread_send_msg`, per-channel
  `cppringbuf1_t` input queues and a `vnnqueue_t` cross-thread command queue
  (`bdev_distrib_impl.cpp` worker thread + poller). The dedup subsystem in ultra runs its
  hash/cache work on its own thread(s) and exchanges requests with the SPDK worker via that
  message/queue pattern.
- **RPCs** follow the established `SPDK_RPC_REGISTER` + JSON-decoder + async-completion
  pattern (`bdev_distrib_impl.cpp` `bdev_distrib_create`; simpler sync example
  `bdev_ptnonexcl_rpc.c`). Snapshot + compaction-control RPCs live in SPDK `lib/lvol`
  (driven by sbcli, §12); any hash-pool/cache tuning RPCs live in ultra.

---

## 9. Compaction algorithm (SPDK worker thread + ultra calls)

### 9.1 Worker thread

Runs on the lvstore thread (`lvs->thread`) / `g_lvs_md_thread` (`lvol.c:37,102`), as a
registered poller (`spdk_poller_register`, cf. the existing snapshot poller `lvol.c:1681`),
or a dedicated thread per lvstore. Metadata mutations are funneled to the md thread exactly
like today's `blob_insert_cluster_on_md_thread` (`blobstore.c:12781`). Compaction is fully
async and yields between extents to avoid starving I/O.

**[OPEN]** dedicated thread vs poller-on-lvs-thread. Proposed default: **poller on the lvs
thread** with a small per-tick extent budget, reusing existing threading invariants
(`assert(lvs->thread == spdk_get_thread())`, `lvol.c:2964`+).

### 9.2 Per-volume compaction run

Precondition: a previous compacted generation exists, and (per §6) the chain has the
new internal snapshot at the head with at most one live internal snapshot.

1. **Freeze**: the new internal snapshot already froze current data into `new_snapshot`.
2. **Iterate extents of `new_snapshot`:**

   **a. Unmodified extent** (identical to the previous generation): include by **pointer**
   into the new generation — no hashing, no data movement. (Detected via the snapshot-delta /
   extent map; an extent untouched since last generation needs no work.) Two sub-cases:
      - **was regular (type 0)** → copy the type-0 entry forward unchanged.
      - **was reference (type 1)** → copy the `(ref_extent_id, ref_block_ofs)` entry forward
        and **increment that reference block's refcount** (§7.4a): the new generation now
        shares the *same* reference block (and through it the same compacted segments) with the
        prior generation. No segment data is re-hashed, re-copied, or re-pointed. This is the
        step that makes a reference block refcount ≥ 2, and exactly why a later delete/unmap of
        one generation must only decrement, never free (§7.4a).

   **b. Modified, was regular** → candidate for dedup:
      1. Hash all 512 blocks (8 segments × 64 blocks).
      2. For each of the 8 segments, it is a **dedup candidate** iff *all 64* block hashes are
         found in the hash pool **and** their vLBAs are **consecutive** (segment is
         contiguous at a single source location). (Spec remark: 256 KiB must reside on one
         contiguous range.)
      3. **Extent-level threshold** to dedup the extent at all: **≥ 3 of 8 dedup candidate
         segments.** **[OPEN]** the spec says both ">25 % of the segment can be deduplicated"
         and "at least 3 dedup candidates per extent" (3/8 = 37.5 %). These disagree. Proposed
         resolution: use **≥3 candidate segments per extent** as the trigger (the concrete,
         testable rule), and treat "25 %" as the looser informal motivation. Confirm with
         spec owner.
      4. If threshold met:
         - Pick a reference shard by pseudo-randomized extent address (§8.4); reserve the next
           64-byte reference block (allocate a new reference extent in that shard if full).
         - For each of the 8 segments:
           - **dedup candidate** → set its reference vLBA = source start vLBA (point at the
             existing contiguous source; increment that source's refcount).
           - **unique** → copy (rewrite) its 256 KiB from the source extent into the next free
             slot of a compacted extent (§8.3); set its vLBA to that slot; insert the segment's
             64 block hashes into the hash pool (refcount=1) so future runs can dedup against
             it.
         - Set the new-generation extent metadata entry to **type 1 (reference)** pointing at
           (ref_extent_id, ref_block_ofs).
      5. If threshold not met: include the **original regular extent by pointer** (no data
         movement) into the new generation.
   3. Fresh hashes not found in the pool are added (eviction if full, §8.1).

3. **Finalize**: once every extent is processed and all reference/compacted writes +
   metadata syncs are durable, the new generation is complete. Only **then** delete the
   superseded old generation / merge the now-dead internal snapshot (§6.1).

### 9.3 Idempotency / restart
Each run writes a new generation and never mutates the source snapshot in place, so a
crash simply discards the half-built generation. A run is resumable at extent granularity
if the partial generation's metadata is persisted incrementally; **[OPEN]** resume-vs-restart
— proposed default: **restart the run from scratch** (simpler; compaction is background and
idempotent), optimize to resumable later.

---

## 10. Crash consistency, recovery & multi-node failover

| State | Persistence | Recovery |
|---|---|---|
| Extent metadata (types, ref pointers) | In blob metadata pages (synced via `spdk_blob_sync_md`) | Recovered on examine/load — authoritative |
| Reference extents | On backing dev | Lazy read on first use (§7.1) |
| Compacted extent data | On backing dev | Persistent; addressed by vLBA |
| **Hash pool** | **Not derivable** → periodic snapshot to disk (§11) | Reload newest persisted image; rebuild deltas lazily |
| Slot/reference occupancy bitmaps | Best-effort in memory; **not journaled per update** | Reconciled by GC against journaled unmaps (below) |

### 10.1 Bitmap reconciliation / GC (spec §3)

We cannot journal every in-memory slot/reference bitmap flip. Two durability anchors below us
already exist and we reconcile against them on restart:

1. **alceml persists allocation durably by itself.** alceml writes modified per-block
   allocation bitmap blocks and stamps a page header (`"ALCEML_PAGE"` / `"_UNMAPPED_"`) on
   full-page unmap, and **rebuilds its free list by scanning page headers on open**
   (`bdev_alceml_impl.cpp`). Unallocated/unmapped reads return zeroes. So "the underlying
   space was actually freed" is durable without our help.
2. **The JM journals distrib placement** (`alg_journal.cpp`, record types incl.
   `jrt_single_unmap`, `jrt_single_unset_latest`; replayed via `alg_remapped_ranges`).

   ⚠️ **Finding:** per-chunk unmap is **not** systematically journaled today — only full-vuid
   unmap (`jfi_r_unmap_vuid`). So we cannot rely on the JM alone to replay individual
   compacted-slot frees.

On restart, a GC pass reconciles our (lost) in-memory bitmaps **and refcounts** (§7.4a) by
**scanning the extent metadata of all live generations** (authoritative, recovered on examine).
Because every refcount is exactly "how many live snapshots point in", it is fully
reconstructible from that scan:
- Rebuild each **reference block's refcount** = the number of live type-`1` cluster entries
  (across all generations) that name it. A block with refcount 0 is free; a reference extent
  whose blocks are all free is released.
- Rebuild each **compacted-segment slot's refcount** = the number of live reference blocks
  whose segment vLBAs resolve into that slot; mark occupied slots used, unreferenced slots
  free, and release an all-free compacted extent.
- A cluster entry that resolves to no live physical data is freed (virtual space only).

Counting referrers (not just presence) is what lets GC correctly preserve an extent that
multiple snapshots share and free one only when its last referrer is gone (§7.4a).

This makes the in-memory bitmaps a **reconstructible cache of authoritative metadata**, not a
source of truth — which sidesteps the "can't journal every bit" problem. Transient
over-counting after a crash only wastes space until GC runs; it never corrupts data.

**[OPEN]** Whether to *also* add a dedicated journaled record (via the JM, reusing the
`jrt_single_unmap` machinery) for compacted-slot/reference frees, to make GC incremental
instead of a full metadata scan. Proposed default: **metadata-scan GC first** (simpler,
correct); add journaled slot-frees later if scan cost is too high on large clusters.

### 10.2 Multi-node HA & failover (NVMe-oF multipathing)  **[load-bearing]**

**Context.** lvols are exported over NVMe-oF with **secondary and tertiary nodes attached via
multipathing (ANA)** that continue serving I/O seamlessly on fail-over. Today a standby keeps a
warm copy of the lvstore and, on promotion, **reloads up-to-date blob metadata (the cluster /
extent-page metadata) from disk**; in steady state, material blob changes (create / resize /
delete) are mirrored to the standbys **via RPC**. Dedup adds substantial in-memory state — the
hash pool, typed extents + `cluster_ref[]`, the reference-extent pool descriptors + occupancy
bitmaps + refcounts (§7.4a), and the reference-block cache — **all of which must fit this
fail-over model.** This section is the contract for that.

**Guiding principle — same as §10.** *Every* dedup in-memory structure is either **(a)
authoritative on disk** or **(b) reconstructible from authoritative on-disk metadata.** Nothing
in-memory has to be *replicated between nodes* for correctness. **Fail-over is just crash
recovery (§10/§10.1) performed on an already-warm peer** — the recovery machinery is reused
verbatim; the only additions are steady-state RPC propagation and a freed-slot-reuse ordering
rule (both below).

#### 10.2.1 Single-writer invariant

Only the **active** node runs compaction and mutates the dedup metadata: hash pool, slot
allocators, occupancy bitmaps, refcounts, and reference/compacted-extent allocation. Secondary
and tertiary nodes are **read-only resolvers** — they resolve type-1 reference clusters to
serve reads (§7), but never compact, never reserve/free a slot or reference block, and never
mutate the hash pool. There is therefore a **single writer** to the on-backing-dev dedup
structures across the whole multipath group, exactly as there is a single writer to ordinary
blob metadata today. (sbcli, which already chooses the active node, also gates which node is
allowed to start compaction, §12.)

#### 10.2.2 What each role needs in memory

| State | Role that needs it | Source on a fresh/promoted node |
|---|---|---|
| `cluster_types[]` / `cluster_ref[]` / `clusters[]` (typed extents) | **read path — all nodes** | **(a)** on-disk `EXTENT_PAGE_V2`, reloaded on examine/promotion (§5.3) |
| `ref_pool[]` descriptor base LBAs (§5.4) | **read path — all nodes** | **(b)** derived from the owning internal blob's cluster map (on disk) |
| reference-block cache (§8.2) | read path — all nodes | cold; lazy-loaded from disk via the resolver (§7.1) |
| compacted-segment → backing LBA (§5.5) | read path — all nodes | **(a)** internal blob's on-disk cluster map |
| slot/reference **occupancy + refcounts** (§7.4a) | **compaction — active only** | **(b)** rebuilt by the GC metadata scan (§10.1) |
| hash pool (§8.1) | **compaction — active only** | checkpoint on disk (§11), or cold |

The key consequence: a standby can **resolve every read correctly using only on-disk +
reconstructible state** — it needs *no* hash pool at all, because the hash pool exists solely to
*find* duplicates during compaction, which only the active node performs. A standby therefore
carries **no live hash pool**; it materializes one only on promotion, and even then lazily
(§10.2.4).

#### 10.2.3 Steady-state propagation to standbys

The existing "material blob change → RPC to secondaries" path is **extended to the new
dedup-driven blob-lifecycle events**, so a standby's in-memory blob table stays current without
polling disk:

- create an **internal compaction blob** (§5.5);
- create / resize a **reference-extent blob** (§5.4);
- create a **new generation** (compacted snapshot) and, after finalize, **delete the superseded
  old generation / merge the dead internal snapshot** (§6.1, §9.2 finalize);
- set / clear `SPDK_BLOB_DEDUP` on a blob (§5.2).

These are all ordinary blob create/resize/delete events on internal + snapshot blobs — they
reuse the same registration mechanism, just with more blobs in play. Applying them keeps a
standby able to reach newly created reference/compacted extents **immediately** (not only after
a disk reload), so a read arriving on a non-optimized path right after a new generation lands
still resolves. On-disk metadata stays the source of truth at promotion regardless.

#### 10.2.4 Fail-over / promotion sequence (node becoming active)

1. **Reload blob metadata from disk** (existing behavior), now parsing `EXTENT_PAGE_V2` →
   up-to-date `cluster_types[]` / `cluster_ref[]` / `clusters[]` for *all* blobs, including
   internal compaction and reference-extent blobs.
2. **Rebuild the reconstructible dedup state via the GC metadata scan (§10.1):** `ref_pool`
   base LBAs, reference-block occupancy + refcounts, compacted-slot occupancy + refcounts.
   Authoritative, no cross-node replication.
3. **Load the latest valid hash-pool checkpoint (§11)**, dropping entries for generations that
   no longer exist — or start cold. The hash pool is a **cache**; a stale/empty one only lowers
   the *future* dedup ratio, never correctness (§8.1).
4. The **reference-block cache starts cold** and warms lazily through the resolver (§7.1) —
   cold-cache read amplification only, bounded by S3-FIFO admission (§8.2.1).
5. **Discard any half-built generation** left by compaction interrupted on the failed node
   (§6.3, §9.3); finalize-then-delete ordering guarantees the chain it reads is valid. Resume /
   restart compaction as the new active.

The node can **serve reads as soon as step 1 (and lazy reference reads) are available**; steps
2–5 only gate *compaction*, which a freshly-promoted node need not start immediately.

#### 10.2.5 Freed-slot / reference-block reuse ordering  **[load-bearing]**

Because a standby may read the same backing store the active is mutating, a freed reference
block or compacted slot must not be **reused** until every metadata entry that referenced it is
both **(a) durably synced** and **(b) propagated to standbys**. The active therefore orders:

```
drop last reference (refcount → 0, §7.4a)
  → sync the metadata that stopped referencing it (generation delete / unmap)
  → propagate that change by RPC (§10.2.3)
  → only THEN return the slot / reference block to the allocator for reuse
```

This is the same ordering crash-safety already demands (finalize-then-delete, §6.3/§9.2;
GC reconciliation, §10.1) — the multi-node case only adds the *propagation* step. As a result a
standby can **never** resolve a stale `cluster_ref` into a *reused* slot: it either still sees
the old generation (whose data is still live and not yet freed), or it has already been told the
generation is gone (and dropped the `cluster_ref`). Reuse strictly trails both fences.

**[OPEN]** (a) Keep the standby reference-block cache warm by snooping the active's writebacks
(faster promotion) vs. cold-load on promotion. Proposed default: **cold-load** (simpler; warms
fast under S3-FIFO). (b) Force a hash-pool checkpoint just before a *planned* failover so the
promoted node starts warmer. Proposed default: **rely on the periodic checkpoint cadence**
(§11); correctness is unaffected either way.

---

## 11. Hash-pool persistence (spec §4)

- Periodic checkpoint of each shard to a reserved on-backing-dev region (or a dedicated
  blob). Format: shard header + packed `(Hash128, HashEntry)` records. Checkpoint cadence is
  a tunable (time- and/or mutation-count-based).
- Crash-consistency of the checkpoint itself: **double-buffer** (write to inactive slot, then
  flip a validated superblock pointer with CRC) so a torn checkpoint never destroys the prior
  good one. **Reuse the JM's proven pattern**: `t_header_block_jm` (signature + monotonic
  `igeneration` + `check_validity()`) with the `t_history_cache` staging/committed double
  buffer (`dbuf_hdrjm` / `dbuf_hdrjm2`), `bdev_jm_impl.hpp` — rather than inventing a new
  superblock format.
- On restart: load newest valid checkpoint. Entries whose generation no longer exists are
  dropped during load. A stale hash pool only costs missed dedup opportunities (correctness
  is preserved because dedup always verifies contiguity from authoritative metadata, and
  optionally a checksum, before trusting a match) — never wrong data.
- **[OPEN]** verify-before-dedup: store and check a weak per-block checksum (or re-read +
  compare) before accepting a hash match, to defend against BLAKE3-128 collisions and stale
  entries. Proposed default: **store an additional cheap checksum in `HashEntry.flags`/field
  and verify**; full re-read+compare optional under a paranoia flag.

---

## 12. Control plane (sbcli)

Minimal RPC surface (new RPCs in `lib/lvol` + module wiring):
- `bdev_lvol_create_internal_snapshot <lvol>` — take internal snapshot (head of chain).
- `bdev_lvol_delete_internal_snapshot <snap>` — merge/delete (reuses existing delete path).
- `bdev_lvol_start_compaction <lvol>` — kick the worker for one generation.
- `bdev_lvol_compaction_status <lvol>` — progress, current chain, last generation, errors.
- `bdev_lvol_set_dedup <lvol> <on|off>` — set the per-blob `SPDK_BLOB_DEDUP` opt-in flag.

sbcli owns cadence policy and calls these; it holds no dedup data structures. It also already
selects the **active** node of a multipath group — so it additionally **gates compaction to the
active node only** (the single-writer invariant, §10.2.1) and is the natural driver of the
fail-over promotion sequence (§10.2.4). The dedup-driven blob-lifecycle events that must reach
secondary/tertiary nodes (new generation, deleted generation, new internal compaction /
reference-extent blobs, `SPDK_BLOB_DEDUP` toggles) ride the **existing** "material blob change →
RPC to secondaries" path (§10.2.3); no new standby-replication protocol is introduced.

---

## 13. Open questions (consolidated)

1. **vLBA bit layout & blob selector** (§4) — dense per-lvstore index vs raw blob id.
2. **EXTENT_PAGE_V2 packing** (§5.2) — 256 entries/page vs side-bitmap to keep 512.
3. **Resolver hook vs special back_bs_dev** (§7.1).
4. **Dedup threshold** (§9.2b.3) — reconcile "25 %" vs "≥3 of 8 segments".
5. **Reference-cache granularity** (§8.2) — per-block vs per-extent.
6. **Worker thread model** (§9.1) — poller-on-lvs-thread vs dedicated thread.
7. **Resume vs restart** of an interrupted run (§9.3).
8. **Verify-before-dedup** strength (§11).
9. **Reference-extent capacity** spec arithmetic (§5.4) — 0.11 PB vs ~0.012 PB.
10. **Checksum/size/flags** fields actually needed in `HashEntry`.
11. **Granularity** (§4.1) — confirm the 1:1:1 sizing (2 MiB lvs extent = distrib page =
    alceml page, with a 4 KiB distrib chunk). No special distrib config is required; this is a
    confirmation, not a constraint to negotiate.
12. **Journaled slot-frees** (§10.1) — metadata-scan GC only, or add a JM-journaled
    compacted-slot/reference free record for incremental GC?
13. **Standby cache warmth** (§10.2.5) — snoop the active's reference-block writebacks to keep
    a standby cache warm (faster promotion), or cold-load on promotion (simpler)?
14. **Pre-failover hash-pool checkpoint** (§10.2.5) — force a checkpoint before a *planned*
    failover, or rely on the periodic cadence (§11)? Correctness-neutral either way.

Each has a proposed default so implementation can proceed without blocking.

---

## 14. Phased implementation plan

Phases are ordered by dependency. Each lands behind the `SPDK_BLOB_DEDUP` opt-in so trunk
stays shippable. Every phase ships with tests.

### Phase 0 — Spec lock & scaffolding (no behavior change)
- Resolve **[OPEN]** items 1–4, 9, 11 with the team (the format- and deployment-affecting
  ones). Confirm the **2 MiB extent = distrib page = alceml page, 4 KiB chunk** sizing (§4.1).
- Reserve on-disk identifiers: `SPDK_MD_DESCRIPTOR_TYPE_EXTENT_PAGE_V2`, `SPDK_BLOB_DEDUP`.
- **Vendor BLAKE3** into ultra `3rdparty/` and wire it into the build (`CMakeLists.txt`,
  modular `.cmake` includes). No crypto hash exists today (§8.5).
- ultra: create a `dedup/` subsystem skeleton under `DISTR_v2/src_code_app_spdk/subsys/`
  (headers, no logic), reusing the existing subsys structure.
- **Tests**: BLAKE3 known-answer vectors; CI builds both trees.
- **Exit**: format constants merged; BLAKE3 available; ambiguities closed.

### Phase 1 — Backward-compatible extent format v2 (SPDK)
- Add `EXTENT_PAGE_V2` serialize/parse (`blob_serialize_extent_page`/`blob_parse_page`,
  `blobstore.c:1482`/`:865`), `cluster_types[]` / `cluster_ref[]` in `spdk_blob_mut_data`,
  and `SPDK_BLOB_DEDUP` flag plumbing.
- All clusters are type `0` for now → byte-for-byte equivalent behavior, just wider entries.
- **Tests**: round-trip serialize/parse; load old-format blob with new binary (unaffected);
  new binary writes v2, old binary refuses (flag). blobstore UT + `test/blob`.
- **Exit**: a dedup-flagged blob persists/loads with v2 pages and behaves identically.

### Phase 2 — Resolver hook + read path for reference (type 1) clusters (SPDK + ultra stub)
- Add the resolver registration + read delegation (§7.1, §7.2).
- ultra provides a **trivial** resolver (identity: a type-1 reference with a single-segment
  passthrough) to exercise the path end to end without real dedup.
- **Tests**: craft a blob with a hand-built reference block; verify reads assemble correctly;
  COW copy-up from a type-1 backing cluster (§7.3).
- **Exit**: reads through a reference indirection return correct data.

### Phase 3 — Hash pool (ultra, standalone)
- `Hash128`, sharded map, BLAKE3-128 fingerprinting, S3-FIFO+CLOCK eviction (§8.1).
- Build on reuse inventory (§8.5): `hashx` per shard, `cppringbuf1_t` for S3-FIFO queues,
  `util_hf_objpool_t` for entries, `t_spdk_bitpool` for CLOCK bits, `critsec_t` per shard.
  Only the eviction wrapper + sharding coordinator are new.
- Pure unit-testable component, no SPDK dependency.
- **Tests**: insert/lookup/refcount; eviction behavior under skew; contiguity-match helper;
  benchmark hit-rate on synthetic workloads. (ultra `src_code_tests`.)
- **Exit**: hash pool passes correctness + eviction tests.

### Phase 4 — Reference & compacted extent management (ultra)
- Reference-extent pool + sharding (§8.4), reference-block reserve/free.
- Reference-extent cache w/ eviction (§8.2), reusing the Phase-3 eviction wrapper.
- Compacted-extent slot allocator + occupancy bitmaps (§8.3) — model on alceml's free-list +
  per-page bitmap pattern (`ipgar_free`, `t_page_area_info::bitmap`, `bdev_alceml_impl.cpp`),
  partitioned into reference vs compacted pools.
- Wire the real resolver (replaces Phase 2 stub).
- **Tests**: reserve/free reference blocks across shard growth; slot alloc/free + extent
  release; cache hit/miss + eviction with lazy reload.
- **Exit**: full read resolution against real reference/compacted extents.

### Phase 5 — Compaction worker (SPDK) + dedup decision (ultra)
- Worker poller on the lvs thread; per-extent iteration with delta detection (§9).
- ultra dedup decision: hash segments, contiguity test, threshold, reserve reference block,
  copy unique segments, emit type-1 (reference) metadata; pointer-include otherwise.
- New-generation build with the §6.3 crash-safe chain; finalize-then-delete ordering.
- **Tests**: end-to-end on a synthetic lvol with known-duplicate segments → verify physical
  savings, correct reads post-compaction, and that old/new generations both remain readable
  until finalize.
- **Exit**: a volume compacts into a new generation with measurable dedup, data intact.

### Phase 6 — Unmap, bitmaps & GC (SPDK + ultra)
- Unmap on compacted extents (slot clear/release), reference-block free, refcount decrements
  (§7.4).
- Restart GC reconciliation against journaled unmaps (§10.1).
- **Tests**: unmap frees slots; full-extent release; crash-inject (drop bitmap, keep unmap
  journal) → GC reconciles; no data loss / no leaked space after GC.
- **Exit**: space is reclaimed correctly and survives crash + GC.

### Phase 7 — Hash-pool persistence (ultra)
- Double-buffered checkpoint + reload; drop-stale-on-load; verify-before-dedup (§11).
- Reuse the JM superblock/double-buffer pattern (`t_header_block_jm` + `t_history_cache`,
  `bdev_jm_impl.hpp`) rather than a new format.
- Restart GC for slot/reference bitmaps via metadata scan (§10.1).
- **Tests**: checkpoint/reload round-trip; torn-write injection keeps prior good image;
  post-reload dedup still correct; collision/stale entry rejected by verify.
- **Exit**: node restart preserves dedup effectiveness without correctness risk.

### Phase 8 — sbcli control plane + cadence
- New RPCs (§12); sbcli cadence policy: create internal snapshot, merge previous, start
  compaction, poll status, toggle dedup.
- **Tests**: orchestration integration test exercising the §6.1 chain transitions end to end.
- **Exit**: cadence-driven compaction runs unattended; chain depth stays bounded.

### Phase 9 — Multi-node fail-over (§10.2) + hardening
- **Fail-over**: wire dedup blob-lifecycle events into the existing standby RPC propagation
  (§10.2.3); enforce the single-writer/compaction-gating invariant (§10.2.1); implement the
  promotion sequence (reload metadata → GC scan → load checkpoint → cold caches, §10.2.4) and
  the freed-slot reuse ordering fence (§10.2.5).
- **Tests**: read on a standby resolves type-1 clusters correctly with cold caches; promote a
  standby mid-compaction → reads stay correct, half-built generation discarded, compaction
  resumes; inject a freed-then-reused slot race → standby never reads stale data; measure
  promotion time (GC scan + cache warm-up).
- Fault injection across phases (node restart mid-compaction, eviction storms, full pools),
  perf benchmarking (read amp with cold/warm reference cache), tunable sweep, soak.
- **Exit**: meets perf goals (no read amp when cached); seamless fail-over with correct reads;
  stable under soak + fault injection.

### Dependency graph
```
P0 ─► P1 ─► P2 ─► P4 ─► P5 ─► P6 ─► P9
          └► P3 ─┘        ▲          ▲
                          P7 ────────┘
P5 ─► P8 ─────────────────────────► P9
```

---

## 15. Risks

- **On-disk format churn** — mitigated by additive, flag-gated v2 (no migration of existing
  data; old binaries fail safe).
- **Read amplification on reference-cache miss** — mitigated by per-extent residency +
  S3-FIFO admission; quantify in P9.
- **Hash collisions / stale pool entries** — mitigated by verify-before-dedup (P7) and
  authoritative contiguity check from metadata.
- **Space accounting drift after crash** — bounded and self-healing via journaled-unmap GC;
  never corrupts data.
- **Cross-layer complexity (SPDK↔ultra resolver)** — contained behind one narrow hook;
  prototype in P2 before committing to it.
- **New crypto-hash dependency (BLAKE3)** — not currently vendored; adds a build dependency
  and per-block hashing CPU cost during compaction. Mitigated by hashing only modified
  snapshot extents in the background (never on the write hot path) and by SIMD BLAKE3.
- **Per-chunk unmap not journaled today (§10.1)** — relying on metadata-scan GC; if scan cost
  is prohibitive on large clusters, falls back to adding a journaled slot-free record (open
  item 12). Mitigated because in-memory bitmaps are reconstructible, never authoritative.
- **Multi-node fail-over of the larger dedup state (§10.2)** — hash pool, typed extents,
  reference-extent descriptors/bitmaps and the reference-block cache all change the standby's
  in-memory footprint. Mitigated structurally: every structure is on-disk-authoritative or
  reconstructible, only the active node writes (single-writer invariant), and freed-slot reuse
  trails both the metadata sync and its RPC propagation — so a standby never reads a reused slot
  through a stale pointer. Promotion cost (GC scan + cold caches) is bounded and quantified in
  P9; correctness never depends on cross-node replication.
