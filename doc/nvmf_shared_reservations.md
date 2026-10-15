# Shared NVMe-oF reservations across an lvol's storage nodes {#nvmf_shared_reservations}

An lvol is served by its primary storage node and by one or two secondaries. Each
node runs its own NVMe-oF target, and before this work each target kept its own
reservation state: a Linux host sends a reservation command down one path only
(`nvme_find_path()`), so the state existed on one node, a secondary's
`non_optimized` listener accepted I/O with no reservation, and the state was lost
when an SPDK pod was replaced or the primary changed.

## What is implemented

**Step 1, the nvmf library.** `struct spdk_nvmf_ns_reservation_ops` gains two
optional members:

- `update_async` stores a namespace's new state and calls back when it is durable.
  The reservation command completes, and the poll groups see the new state, only
  after a successful callback. On failure the namespace's state is rolled back to
  the snapshot taken before the command, the poll groups are not updated, and the
  command fails with Internal Device Error. Upstream's per-namespace serialization
  of reservation commands (`ns->reservations`) keeps commands from interleaving
  with an outstanding write.
- `is_shared` marks a namespace whose state other targets share: every state change
  is stored, not only those Persist Through Power Loss covers, and the state loaded
  at namespace add is applied whether or not PTPL was activated.

`spdk_nvmf_ns_reload_reservation()` (and the RPC `nvmf_ns_reload_reservation`)
replaces a live namespace's state with what `load` returns and updates the poll
groups. A reload waits until the namespace's queued reservation commands have
completed, so it never lands between a command and the write of its result.

`spdk_nvmf_reservation_info_encode()` and `_decode()` give a compact, versioned,
little-endian encoding with a generation counter, at most 2080 bytes for 64
registrants.

**Step 2, the lvol module and its glue.** `vbdev_lvol` keeps the encoded state in
the lvol blob's `nvmf_resv` xattr. Only the lvol's leader writes it
(`spdk_blob_set_xattr` and `spdk_blob_sync_md` on the lvolstore's thread); any other
node gets `-EPERM`. Every node keeps a copy that is read on the lvolstore's thread
when the lvol bdev is created and whenever lib/lvol reports that the metadata may
have changed under the node (`spdk_lvs_set_refresh_cb()`): the node became leader
of an lvol (`spdk_lvol_set_leader`, which the failover path ends in), became leader
of the lvolstore (`spdk_set_leader_all`), or, as a non-leader, reread the metadata
(`spdk_lvs_update_live`). After a refresh, the nvmf event subsystem
(`nvmf_lvol_resv.c`) reloads every namespace on that bdev. Other bdevs keep the
default JSON file. Each write carries the generation after the stored one. Stored
state that cannot be read, in an encoding this build does not decode or after a
read error, is not written over: the write fails, and with it the command.

**Step 3, the same state on every node.** A node that is not an lvolstore's
leader already reaches the leader over the hub connection: its I/O to an lvol goes
to the leader's hublvol, an NVMe-oF namespace on the leader, with the lvol's map id
packed into the offset (`vbdev_redirect_request_to_hublvol`,
`vbdev_hublvol_submit_request`). Reservation state uses that connection too, as
three vendor-specific NVMe I/O commands on the hublvol (`vbdev_lvol.h`). CDW10
bits 15:0 name the lvol by its map id; 0 and 0xffff name none. The hublvol advertises NVMe I/O, and the
target passes vendor opcodes through to it as for any bdev that does:

| Command | Opcode | Data | Answer |
|---------|--------|------|--------|
| `RESV_EPOCH` | `0xC4` | none | completion dword 0 is the leader's reservation epoch for the lvolstore |
| `RESV_EXEC` | `0xC5` | host to controller: `struct vbdev_lvol_resv_exec_msg` | the status of the command the leader executed |
| `RESV_FETCH` | `0xC6` | controller to host: the lvol's stored state | completion dword 0 is its length, 0 when none is stored |

A node that is not the leader answers each of them with Namespace Not Ready.

The leader's nvmf target hands an I/O passthru command to the bdev layer through
`spdk_bdev_nvme_iov_passthru_md`, which checks for `NVME_IO` support but submits
the I/O as `NVME_IOV_MD`, with the data in its iovs. The lvol bdev takes both
types as a reservation command of another node; any other type goes to the
hublvol's data path. bdev_nvme does not retry a vendor-specific I/O passthru
command (opcodes 80h to FFh) that failed: the lvol module decides what a failure
means, and a forwarded Acquire must not run twice.

- **Commands on a non-leader are executed by the leader.**
  `spdk_nvmf_ns_reservation_ops` gains an optional `forward` member. For a shared
  namespace, the nvmf library offers it each Register, Acquire, and Release when
  the command reaches the head of the namespace's reservation queue. On the leader,
  and for a namespace that is not an lvol, it returns `-EAGAIN` and the command
  runs locally. Otherwise the event subsystem's glue (`nvmf_lvol_resv.c`) sends a
  `RESV_EXEC` carrying the command, its data, and the host identifier and NQN of
  the controller it arrived on. The leader runs it through
  `spdk_nvmf_ns_reservation_execute()`, which executes a command as a host with no
  controller there: same queue, same durable write, same poll-group update, and
  never forwarded again. The forwarding node then fetches the state the leader
  holds, installs it, applies it to the namespace and its poll groups, and only
  then completes the command with the leader's status. A fetch that fails, or
  whose state cannot be installed, is asked again, up to
  `VBDEV_LVOL_RESV_FWD_FETCHES` (3) fetches in all. The reservation functions
  take a host identifier rather than a controller for this.
- **Every other node follows by polling.** A non-leader asks `RESV_EPOCH` every
  200 ms per lvolstore (`VBDEV_LVOL_RESV_SYNC_PERIOD_US`). When the epoch differs
  from the one it last fetched for, or a fetch failed, it fetches every lvol's
  state, installs what is newer, and the glue reloads the namespaces. The leader's
  epoch changes with every stored change. A round that fails is asked again on the
  next poll, and each further failure in a row doubles the polls skipped, up to
  `VBDEV_LVOL_RESV_SYNC_MAX_SKIP` (50 polls, 10 s); the first round that succeeds
  asks every poll again. The start and the end of a failing streak are logged once
  each.
- **Older state never wins.** State is installed only when the generation of its
  encoding is newer than what the node holds, and a metadata reread keeps a newer
  state it already has. A deposed leader cannot store, a node asks only the hub it
  is connected to, and nothing older than what a node holds is installed. The
  epoch's high half is an incarnation drawn from `getrandom()` whenever a node
  becomes leader, one of 32768 values. A restarted or new leader repeats an epoch
  another node remembers only when both the incarnation and the counter match, and
  that node then skips one fetch until the next stored change.

### What a command waits for

A command executed on the leader completes once its state is durable and the
leader's own poll groups have it, the semantics every lvol metadata change already
has: the leader writes, and the other nodes catch up. A command forwarded from a
non-leader additionally waits for that node to install the state. Every other
non-leader enforces the previous state until its next poll, at most 200 ms plus a
fetch later. During that window a host that was just preempted can still write
through a third node's path.

### Failure cases

- **The leader is unreachable from a non-leader.** A forwarded command fails with
  Namespace Not Ready and the host may retry, typically on another path. Polling
  stops while the hub is down, and the node enforces the last state it installed.
- **The state a forwarded command left cannot be fetched.** After the last fetch
  the command fails with Namespace Not Ready, although the leader may have
  executed it, and the node enforces the last state it installed until a poll
  succeeds. The host's retry runs on the leader's current state.
- **The leader answers, but with an error.** The non-leader backs off as described
  above and enforces the last state it installed until a round succeeds, so the
  window of a stale state grows to the backoff, at most 10 s plus a fetch.
- **The leader changes.** The new leader rereads the metadata (step 2) and starts a
  new epoch incarnation; non-leaders see an epoch they have not fetched for and
  fetch everything.
- **The leader crashes after the durable write.** The host's command never
  completed and is retried. The new leader loads the written state, so the retry
  runs on current state; Acquire of a held reservation and a Preempt of an
  already-removed key are idempotent. A Register with the same key is counted
  again, so the host's next release leaves it registered with a count of one.
- **Preempt and Abort.** The leader waits only for the preempted host's commands
  that it executes itself. Commands in flight on another node are not waited for.

### Tests that need a cluster

The unit tests cover each node's half against a fake hub (`vbdev_lvol_ut`) and a
fake owner (`subsystem_ut`). What only a cluster proves: that the leader's target
passes the vendor commands to the hublvol and `bdev_nvme` carries them over the
hub, that a forwarded command and a polled change arrive in the order described,
and the end-to-end behavior. On a three-node cluster with one lvol exported on all
three: register hosts through the primary and through a secondary, preempt one from
another host, and check that the preempted host's writes through every path fail
with Reservation Conflict within 200 ms; then kill the primary, let a secondary take
over, and check that registrants and holder survived and are enforced on every
path.
