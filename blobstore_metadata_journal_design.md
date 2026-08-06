# LVS metadata (page) journaling with torn-write protection — design

Status: rev 3 — aligned precisely to the specification
"LVS meta-data (page) journaling with torn-write protection" (2026-07-29).
Scope: simplyblock SPDK fork, branch `md-journal`, `lib/blob`.

## 1. Problem

The lvstore reports a **4K logical block** and runs the blobstore on a **4K page**. Blobstore
crash-consistency assumes a single 4K metadata-page write is **atomic**. The backing store
guarantees atomicity only at the **512-byte sector**, so a 4K metadata write can **tear** on power
loss. Only blobstore **metadata** must be made torn-safe.

Consequences today (confirmed by source mapping):
- Torn **root/extent page** → page CRC fails → `bs_load_iter` aborts the **entire lvstore load**.
- Torn **`used_blobids` mask page** → no CRC, seeds dirty-recovery replay → **silent loss of a
  blob**.

## 2. What is journaled

Per the spec: **all md updates** — super block, bitmap (mask) pages, blobstore md pages, per-blob
md pages. Concretely every 4K write whose target falls inside the blobstore metadata region:

| Structure | Journaled |
|---|---|
| Super block (page 0) | yes |
| `used_pages` / `used_clusters` / `used_blobids` mask pages | yes |
| Blob root pages, COW chain pages, extent pages (the md-page region) | yes |
| Data cluster writes | no (pass through) |

## 3. Journal placement and format

- Per LVS, a **64 MB region at the highest offset of the virtual underlying space**:
  `journal_start = dev_size_bytes − 64 MB`, where `dev_size_bytes` is taken from the **actual
  device size at runtime** (`blockcnt × blocklen`), never a hard-coded 2 PB.
- The region is a **ring buffer** of fixed-size entries.
- **Entry = 2 blocks (8 KB total)**:
  - **block 0 — page header**: `{ u32 checksum (CRC32C of the md page), u64 target_lba }`,
    rest of the block zero. The checksum comes **with the write from the caller** (the caller
    hands us the finished md block[s] including checksum[s]).
  - **block 1 — the 4K md page**, byte-exact home content.
- A zeroed or checksum-mismatching entry is **empty** by definition (torn journal writes are
  self-detecting; they were never acknowledged, so discarding them is always correct).
- 64 MB / 8 KB = 8192 entries. One entry slot is kept as a **guard** (ring is "full" at 8191
  used) so a completely-valid full ring cannot become ambiguous on recovery.

## 4. In-memory state (read-amplification avoidance)

To avoid read amplification, journaled pages are **never read back from the journal in normal
operation**:

- After a journal write completes, the md page is **copied into an in-memory buffer** (so it
  survives release of the caller's write buffer on IO completion).
- An **in-memory dictionary maps target LBA → offset of the newest copy in that buffer/SGL**.
- **Journal head and tail pointers are kept in memory as two pairs**: one pair for the in-memory
  buffer, one pair mirroring the on-disk ring state. Nothing is persisted; recovery rebuilds both
  pairs from the ring content (§7).
- The dictionary (and buffer slot reuse) is protected by a **spinlock**, because md reads race
  with the LVS drain thread.

## 5. Write path

On every md-page write (per 4K page, in issue order):

1. Build the header block (checksum from caller, target LBA) and write
   `[header][md page]` to the ring slot at the in-memory head; advance head.
2. On journal-write completion: copy the page into the in-memory buffer, point
   `dict[target_lba]` at it (newest wins), advance the on-disk head mirror, and
   **complete the IO back to the caller**. The home write has not happened yet and the caller
   must not care.
3. **Journal full** (head would run into tail's guard slot): the write **waits** until the LVS
   drain thread frees a slot, then proceeds. No error, no bypass.

Multi-page md writes (mask flushes, chain batches) are appended page-by-page FIFO and completed
when all their entries are durable.

## 6. Drain (LVS asynchronous thread)

A background poller on the blobstore md thread loops comparing head and tail. While they differ,
for the entry at tail:

1. Take the target LBA from the entry (first block) and write the md page (second block —
   served from the in-memory copy, not a journal read) to its home LBA.
2. On home-write completion, **unmap (zero) both journal blocks** of the entry.
3. Advance tail (both pairs); drop `dict[target_lba]` **iff** it still points at this entry's
   buffer slot (a newer copy may exist further up the ring), then release the buffer slot.

Ordering invariant: a slot is only reused after its home write is durable **and** its journal
blocks are zeroed — this is what keeps "non-empty ⇒ not yet applied" true for recovery, and the
zeroing is what makes the valid region of the ring contiguous.

## 7. Read path

On every md read: **first look up the dictionary** (under the spinlock). For each 4K page of the
read range that hits, serve it from the in-memory copy (validate its checksum); pages that miss
are read from home. Implementation: **snapshot the dictionary hits (page copies) at read issue
time**, issue the home read, and overlay the snapshots on completion. The snapshot at issue is
load-bearing: the drain can complete a home write, zero the entry and drop the dictionary entry
*while the home read is in flight*, and the concurrent home read may still return the pre-drain
page — a completion-time lookup would then miss and serve that stale data (found as a blob-md
CRC mismatch in single-node integration testing).

## 8. Sudden power-off and fail-over (recovery)

Run by whichever node next loads the LVS (secondary/tertiary on failover, same node after
power-off), **before any other md read**:

1. **Read the whole 64 MB journal** using up to **32 parallel 64 KB IOs**.
2. Validate every entry: an entry is valid iff it is not all-zero and the header checksum
   matches the payload page. **Zeroed and corrupted entries are both treated as empty** (torn
   writes inside the journal itself are expected and harmless — they were never acknowledged).
3. The valid entries form one contiguous run in ring order (guaranteed by §6's zero-on-drain and
   the §3 guard slot): its ends are the recovered **tail and head**; set both in-memory pairs
   accordingly.
4. Fill the **in-memory buffer and dictionary** from the valid entries in ring (FIFO) order —
   for duplicate LBAs the later entry wins.
5. Continue normal load: md reads are already correct via §7, and the **LVS drain thread works
   the backlog off in the background** — no upfront redo pass, no load stall.
6. Recovery completion arms read/write interception for the **whole device range** immediately:
   the super block is read before the metadata layout is known, and after a crash its newest
   version may still sit in the ring (home copy stale or torn by the power loss mid-drain).
   Overlaying is correct for any LBA (a dictionary miss passes through untouched); the range is
   tightened to the metadata region once the super block is parsed.

### 8.1 Promotion of an already-loaded peer (rescan)

The product does **not** load the LVS at failover. The secondary/tertiary loaded it when the
LVS was created or activated, and takeover is `bdev_lvol_update_lvstore` +
`bdev_lvol_set_leader_all` (`storage_node_ops` leaderless recovery / failover), plus the
IO-driven reactive promotion (`spdk_bs_update_on_failover`). Neither loads the blobstore, so
§8 recovery would never run on the node that becomes the new leader.

That is not survivable: the ring is shared state on the shared device, the buffer/dictionary
that overlays reads from it is **per process**. A peer's ring view is a snapshot as of its own
load; every entry the leader appended (and acknowledged) afterwards is invisible to it. A peer
promoted without a rescan therefore

- serves the **home** page for every page the dead leader acknowledged but did not drain — the
  acknowledged md is lost, which is exactly what the journal exists to prevent; and
- appends at **its own stale head**, overwriting those undrained entries and breaking the single
  contiguous run that §8 step 3 relies on, so even a later crash-recovery cannot get them back.

`spdk_bs_update_live()` therefore re-runs recovery (`bs_md_journal_rescan()`) before it re-reads
the super block whenever the whole store is reloaded (`id == 0`), which covers the explicit
promotion RPC and the reactive failover path. The rescan waits for the append/drain pipeline to
quiesce, drops the dictionary and both pointer pairs, re-reads the ring exactly as §8 does, and
re-arms the drain poller, so the new leader inherits the dead leader's backlog and drains it.
The per-blob variant of the same call (`bdev_lvol_register`, `id != 0`) does not rescan: it runs
per lvol create in a live cluster and the cost would land on the create path.

Measured on the two-instance failover rig (ultra `mdj_failover_tests.py`, phase 3): without the
rescan a promotion logged no recovery at all; with it, promotion logs
`md journal rescan: re-reading the ring on takeover` followed by the normal
`md journal recovery: N entries` line.

## 9. Why this is correct (invariants)

- **I1 — ack after journal durability**: the caller sees completion only once the entry is on
  disk. Hence any torn/invalid entry found by recovery was never acknowledged → safe to drop.
- **I2 — reuse after home durability + zeroing**: a slot is recycled only after its page is home
  and the entry is zeroed → every acknowledged-but-not-yet-home page is present and valid in the
  ring; recovery cannot miss one.
- **I3 — FIFO order end to end**: append order = issue order; drain and recovery process in ring
  order; duplicates resolve newest-wins. The blobstore's own prefix-consistent write ordering is
  therefore preserved; no transactions or multi-page atomicity are needed.
- The journal never relies on any write being atomic — only on **torn-write detection** (the
  per-entry checksum).

## 10. Integration points (fork)

- New module `lib/blob/blob_md_journal.[ch]`: ring + buffer + dictionary + drain poller +
  recovery; owned by `struct spdk_blob_store`.
- The journal claims the top 64 MB by presenting the blobstore a **shrunk device**
  (`blockcnt − 64 MB worth`), so data clusters can never collide with the ring; the journal
  itself addresses the base device raw.
- **Write interposition** at the md write-issue points / md LBA range; data-path writes are
  untouched.
- **Read interposition** as §7 overlay.
- `spdk_bs_init`: zero the journal region when formatting.
- `spdk_bs_load`: run §8 recovery first.
- Feature/format flag in the super block: journaling active only for stores formatted with the
  reserved region (legacy stores load unchanged).

## 11. Risks / validate first

1. **Completion ⇒ durability** on the backing dev (distr/JC committed) — required for I1/I2;
   today's md writes already assume this.
2. **Single-writer fencing** — one appender at a time; re-drain is idempotent, concurrent append
   is not.

   **How the product actually fences: fail-stop.** Leadership moves only when the old leader is
   gone — its SPDK process died (abort, segfault, container kill, host reboot) or, on a network
   outage, the node aborts itself from inside. There is no scenario in the intended design where
   a healthy old leader keeps serving while a peer is promoted, and the journal inherits that
   guarantee rather than adding one.

   **What phase-3 test F3 establishes (2026-08-05).** The journal contributes *no* fence of its
   own, so the assumption above carries all the weight. Freezing a leader with SIGSTOP, promoting
   the peer and thawing the old leader — deliberately breaking fail-stop — it accepted every
   metadata operation: `bdev_lvol_get_lvstores` still reported `"lvs leadership": true`, three
   creates and a sync delete were acknowledged, its ring head advanced 2673 → 2688 (15 entries)
   while the new leader was at head 23, and its drain poller wrote those pages to their home LBAs
   on the shared device. Nothing logged a leadership rejection. The blob layer's `is_leader`
   checks cover only async delete and cleanup (`bs_delete_blob_non_leader`,
   `blob_clear_clusters_async`, `bs_cleanup_*`); the lvol layer gates on `lvs->leader`, which a
   stale node still has set. Nothing consults the device: with no epoch in the super block or the
   entry header, a second appender is indistinguishable from the first.

   **Why this matters even under fail-stop: the journal widens the blast radius.** Before the
   journal a stale writer wrote stale md pages to their home LBAs — damaging but page-local.
   Now it also mutates *shared ring structure* with pointers that have diverged from the new
   leader's (2673 vs 23 above): it appends into slots the new leader believes are free, and its
   drain zeroes slots and writes home pages the new leader's recovery depends on, so I2 (a slot
   is recycled only after its page is home) and I3 (FIFO, one contiguous run) can both break and
   recovery can mis-derive tail/head. Any window where fail-stop is soft is therefore more
   expensive than it used to be — and such windows are real, not hypothetical: the self-abort on
   a network outage is a timed reaction and **a promotion elsewhere can precede it** (confirmed
   with the product owner, 2026-08-05), and a reactor stalled by host swap thrash that later
   resumes (MCD incident 2026-07-13) looks exactly like the SIGSTOP above. The exposure is
   bounded by how long the old leader can still reach the shared device after the peer is
   promoted.

   **Not implemented, and deliberately so:** closing this needs a fence the device can see — a
   monotonically increasing leadership epoch in the super block, carried in every entry header,
   with appends refused once the on-disk epoch has moved on. That is a change beyond the journal
   (the epoch has to be owned by whoever grants leadership) and is out of scope here; it is
   recorded so the trade-off is a decision rather than an oversight.
3. **Journal-full behavior** under md-heavy bursts (mass create/delete): writers stall until the
   drain frees slots — benchmark; drain batches multiple entries per poll.
4. **Unmap-vs-zero**: if the device's unmap does not guarantee deterministic zero-read, use
   explicit write-zeroes for the two entry blocks.
5. **Migration**: legacy stores without the reserved region keep the old (unprotected) path
   until reformatted/migrated.
