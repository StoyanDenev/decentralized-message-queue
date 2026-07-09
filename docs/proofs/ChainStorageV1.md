# Chain-Storage-v1 — the O(1) append-only block store (register B1)

**Status:** SHIPPED 2026-07-09 (pre-launch register B1; commit-local, staged
migration). Gated by `determ test-chain-store` (16 assertions, FAST) + the
live `test_weak_3node` cluster + FAST 203/0 both platforms. Relates to
[PRE-LAUNCH-DECISIONS.md](../../PRE-LAUNCH-DECISIONS.md) B1 and the
[SnapshotDeterminismComposition.md](SnapshotDeterminismComposition.md)
fast-restore path.

## 1. What changed and why

The save worker used to rewrite the whole `chain.json` on every save tick —
O(N) serialize+write under the state `shared_lock`, the register's
global-mutex/throughput offender on long chains. Now
[`Chain::save_incremental`](../../src/chain/chain.cpp) writes only the blocks
appended since the last incremental save:

```
<chain_path>.blocks/<i>.json      one block per file, atomic tmp+rename,
                                  NEVER rewritten once persisted
<chain_path>.manifest.json        tiny {format:"chain-blocks-v1", height,
                                  head_hash}, atomic, written LAST
```

`head_hash` carries the same S-021 tamper gate as the legacy wrapped
`chain.json`: [`Chain::load`](../../src/chain/chain.cpp) replays the store's
blocks and rejects if the recomputed head digest mismatches. Because the
manifest is written last, a crash mid-save leaves the previous consistent
(manifest, blocks) pair; stranded block files beyond the manifest height are
ignored by load and atomically overwritten by the next save.

## 2. Load preference + the no-rewind invariants

- **Manifest present → the store wins.** It is written every save tick while
  the legacy file is written only at graceful `stop()`, so after a crash the
  store is strictly newer, never older.
- **Present-but-broken store → HARD error** (missing block file, bad format,
  head mismatch). Never a silent fallback to a possibly-stale `chain.json` —
  that could rewind the chain below already-gossiped state. Operator
  recovery: delete `<chain_path>.manifest.json` to force a legacy load, or
  resync from peers/snapshot.
- **Legacy `Chain::save()` deletes the sibling manifest.** Any legacy-only
  writer (CLI fixtures, the snapshot-restore bootstrap, external tools)
  automatically supersedes the store; a stale manifest can never win over a
  fresher legacy file. Writers that maintain the store (the Node) call
  `save_incremental` immediately after `save()` to re-manifest —
  the `stop()` order is `save(); save_incremental();`.

## 3. The staged-migration boundary (found by the live gate)

~19 test/operator scripts plus `determ-light verify-chain-file` parse
`chain.json` content — some MID-RUN, some after a hard kill (no graceful
stop). A store-only hot path broke `test_weak_3node` on its first run. The
shipped rule ([node.hpp](../../include/determ/node/node.hpp)
`kLegacyFullSaveMaxHeight = 4096`):

- **height ≤ 4096:** the save worker dual-writes — legacy file stays
  per-tick fresh (every existing consumer byte-compatible; O(N) is trivial
  at this scale), then the store.
- **height > 4096:** store-only — the true O(1) hot path, exactly the scale
  where the O(N) rewrite hurt. Live reads there use RPC; the legacy file is
  refreshed at graceful stop.

This is a *documented migration boundary*, not a compromise of the win: the
consumers are ours and migrate to the store/RPC before the boundary matters
in production; the constant is node-local (no genesis pinning).

## 4. Composition + hooks

- **Pruning:** store files are individually deletable once a snapshot covers
  them (the snapshot subsystem is the state seed; a pruned store can no
  longer full-replay, so prune only behind a snapshot). Not automated in
  this increment.
- **Reorg hook (A4/S-048):** the store is append-only because sync is
  append-only today. The authorized bounded head-reorg increment must
  rewrite the tail file + manifest and reset the chain's persisted counter —
  called out in [`chain.hpp`](../../include/determ/chain/chain.hpp) at the
  API declaration.
- **`state.json` (the register's second half):** deliberately NOT built —
  the snapshot subsystem already provides the fast state restore an
  incremental state file would duplicate; adding a second state-persistence
  mechanism would grow the audit surface for no new capability. Recorded as
  a conscious deviation from the register's letter, serving its intent
  (O(1) save, prunability, no protocol change).

## 5. What pins it

`determ test-chain-store` ([tools/test_chain_store.sh](../../tools/test_chain_store.sh)):
store/legacy round-trip parity (height, head_hash, state_root, balances);
APPEND-ONLY (a sentinel written into a persisted block file survives the
next incremental save); manifest head_hash tamper → reject; missing block
file → fail-closed reject even with a legacy file present; plain legacy
load + first-incremental-writes-all after it; legacy-save manifest
invalidation (load takes the newer legacy file — no rewind); the stop-order
pair loads to the identical chain through both views.
