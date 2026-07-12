# Bounded Head-Reorg Design — wiring `resolve_fork` to close S-048 (A4)

**Status: A4.1–A4.5 ALL SHIPPED — S-048 CLOSED end to end.** The depth-1 head
reorg is wired into the live accept path (A4.2), reachable over both the gossip
and the CHAIN_RESPONSE sync path (A4.4 rejoiner), and its on-disk persistence is
crash-consistent (A4.5). A node that applied a minority same-height block now
reorgs to `resolve_fork`'s deterministic winner (commit `e22d857`). Direct evidence: the
5-node `test-fa-liveness-virtual` cluster is 10/10 with `[node] S-048 REORG …
replaced head` firing and zero "cannot reorg" markers; `test-node-reorg-s048`
is the deterministic WINNER/REPLAY/LOSER/INVALID repro. Byte-neutral for normal
operation (FAST 216/0 both platforms — the reorg is a strict no-op on the
gossip-duplicate stream). Original design-review context follows.

**Status (original): DESIGN-REVIEW; increment 1 (chain depth-1 revert primitive) implemented next.**
This is the design-review-first step the [KqueueReactorDesign.md](KqueueReactorDesign.md)
/ [DeterministicSchedulerDesign.md](DeterministicSchedulerDesign.md) discipline
mandates for a change to shipped consensus orchestration. The owner authorized the
approach in the pre-launch register (A4, 2026-07-09): *wire `resolve_fork` + a
bounded ONE-block head-reorg (state rollback + replacement) into the sync/gossip
path; the deterministic S-048 repro harness gates it.* The byte-reproducible FA4
substrate this leans on is now complete — the virtual scheduler, `VirtualClock`,
`VirtualTransport` + fault model, and the RNG seam
([DeterministicSchedulerDesign.md](DeterministicSchedulerDesign.md) §3.8 + §4).

Reference convention: bare `§` are this doc; `S-047`/`S-048` are `docs/SECURITY.md`.

## 0. Scope — the one behavior that must change, and the invariant that must not

**Must change:** a node that has applied the *minority* block at the head height
must be able to switch to the deterministically-preferred *majority* block at that
same height (`resolve_fork`'s winner), so a same-height fork converges instead of
stranding the node forever.

**Must NOT change (the hard invariant):** the reorg is **depth-1** — it may rewrite
ONLY the current head (index `H = height()-1`); it may never touch any block at
`H-1` or below. `H-1` is the de-facto finality floor (there is no explicit
checkpoint concept today — [SECURITY.md](../SECURITY.md) "no separate finalized-height").
This is safe because the S-047 abort-vs-finalize race diverges only at a single
head height, never deeper (SECURITY.md S-048: *"depth-1, frozen, deterministic
winner specified"*).

Non-goals: depth>1 reorg, an explicit finality/checkpoint layer, changing
`resolve_fork`'s ranking (heaviest sig set → fewer aborts → smallest block hash,
[chain.cpp](../../src/chain/chain.cpp) `resolve_fork`) — all out of scope.

## 1. Why S-048 can't reorg today (two composing gaps)

1. **Unwired fork choice.** `Chain::resolve_fork` is defined but called only from
   `main.cpp` tests — **zero live callers**. A same-height competitor arrives with
   `b.index == height()-1 < height()`, so `Node::apply_block_locked`
   ([node.cpp](../../src/node/node.cpp), the `b.index < chain_.height()` branch)
   drops it (after optional BFT equivocation logging) before any comparison.
2. **No rollback primitive.** Chain state is a single mutable structure (the
   `StateSnapshot` set in [chain.hpp](../../include/determ/chain/chain.hpp)). The
   only snapshot/restore is captured per-apply and **discarded on commit**
   (`apply_transactions` restores only if that same apply throws), so a *prior*
   committed head cannot be undone. Persistence is append-only too (the
   `save_incremental` reorg-hook TODO in chain.hpp).

Together: the node can neither recognize the majority block as a candidate (dropped
as `< height()`) nor undo its own head to switch. Append-only sync can't help — it
pulls forward from own height and rejects a wrong-`prev_hash` tail forever.

## 2. Approach — one-deep snapshot + wired fork choice

**Rollback mechanism: one-deep snapshot-before-head (chosen).** Given the depth-1
bound, the cheapest correct option is to retain the `H-1` state alongside the head:
before applying a head block, capture `create_state_snapshot()`; keep exactly that
one snapshot. A revert is then O(1): `restore_state_snapshot(H-1)` +
`blocks_.pop_back()` + republish the lock-free `committed_state_view_`. Rejected
alternatives: replay-from-genesis (expensive, needs a state-root source v1 lacks);
a general per-block undo-log (heavier, only justified for depth>1, which is out of
scope). This reuses the EXISTING `create_state_snapshot`/`restore_state_snapshot`
machinery verbatim — no new state-manipulation code, which is the whole safety
argument.

**Wired fork choice.** In the same-height branch of `apply_block_locked`, when an
incoming block collides with the current head at height `H`: (a) validate the
incoming block against `H-1` state (the reverted state — it must independently pass
`validator_.validate`), (b) call `resolve_fork(current_head, incoming)`, (c) if the
incoming block wins, perform the depth-1 revert then `append` it; otherwise drop it
(current head stays). Every peer runs the same deterministic `resolve_fork`, so all
converge on the same winner.

## 3. Increment plan (smallest safe first, each with its gate)

| # | Increment | Gate |
|---|---|---|
| A4.1 ✅ | **Chain depth-1 revert primitive** — `prev_head_snapshot_` (the A9 rollback snapshot) retained on apply-success; `revert_head()` = restore + `pop_back()` + republish view; fail-closed on genesis + double-revert. **SHIPPED `d661d05`.** | `test-chain-revert-head` (11 assertions): exact restore incl. `compute_state_root()` + the lazy-`stakes_` path, depth-1 refuse-second, genesis floor, re-apply, `has_revertible_head()`, + the A4.2 persistence case. FAST 216/0 both platforms; review GO. |
| A4.2 ✅ | **Node wiring** — `Node::maybe_reorg_to_locked` calls `resolve_fork` in the same-height branch + revert→validate-against-H-1→append the winner (or restore the old head on invalid), depth-1 guarded; `post_append_bookkeeping_locked` factored verbatim (byte-neutral normal path); reverted txs → mempool; `revert_head` clamps `persisted_count_` (review finding 8). **SHIPPED `e22d857`.** | live 5-node `test-fa-liveness-virtual` 10/10 with `S-048 REORG` firing + zero stuck markers; FAST 216/0 both platforms (byte-neutral no-op on duplicates); adversarial review GO. |
| A4.3 ✅ | **Deterministic S-048 repro** — a non-producing follower is fed a producer block + a same-height competitor over real gossip and must reorg to the winner; WINNER/REPLAY/LOSER/INVALID via `SeededRng` (§3.8 seam). **SHIPPED `e22d857`.** | `test-node-reorg-s048` — RED without A4.2, GREEN after; replay-twice-identical; both platforms. |
| A4.4 ✅ | **Sync-path rejoiner** — `request_next_chunk` fetches from `height()-1` and `on_chain_response` routes a block at `height()-1` into the reorg, so a restarted node holding a minority tail adopts the winner over the sync path (was `prev_hash mismatch` forever). A `progressed` guard (head advanced OR head-hash changed) stops a Byzantine peer spinning the loop. Pre-revert gate 3b (finding 4): reject a size-mismatched competitor before the revert (sound — the validator enforces the same size invariant). **SHIPPED `dcb49be`.** Residuals (documented, non-blocking, consistent with the depth-1 bound): (a) a Byzantine peer can pack ≤chunk-size same-parent competitors with garbage-but-count-matched sigs, forcing bounded fail-closed revert+restore cycles before validation rejects them; (b) a same-height minority rejoiner within the sync TOLERANCE (5) relies on the network advancing >5 blocks OR a gossip re-offer (the A4.2 path) to trigger convergence — a lone minority node cannot self-extend past its tail (no K committee sigs), so it stays recoverable at the depth-1 floor. | `test-node-reorg-s048` scenario 5 (winner via CHAIN_RESPONSE); the REJOIN phase of `test-fa-liveness-virtual` 10/10 ("restarted node caught up … real sync path"), zero KNOWN-OPEN markers; FAST 216/0 both platforms; adversarial review GO. |
| A4.5 ✅ | **Reorg-during-save crash-consistency** — a reorg clamps `persisted_count_` below the on-disk manifest height, so the next `save_incremental` REWRITES the tail block file in place (no longer append-only); a crash between that rewrite and the manifest update would leave `manifest{N, head=OLD}` beside `<N-1>.json=WINNER`, which `load()` rejects as a head_hash mismatch = a fail-closed brick. Fix: track `persisted_manifest_height_` (NOT clamped by `revert_head`); when it exceeds `persisted_count_`, `save_incremental` writes a SHRINK manifest to `persisted_count_` FIRST — after which every block file the manifest names is unchanged on disk (index `persisted_count_-1` = the H-1 finality floor, never reverted), so every subsequent crash window reloads a consistent shorter chain and re-syncs. Byte-neutral (the shrink fires only post-reorg; a test-only `write_file_atomic` crash seam, default-disarmed, adds one relaxed atomic load). **SHIPPED `<this commit>`.** Adversarial review GO (zero findings; closed-window enumeration independently re-derived). Residuals (documented, non-blocking): process-crash model, not power-loss/`fsync` — the SAME assumption the pre-existing manifest-last scheme already made; and a benign short-chain legacy transient (a crash mid-reorg-save can reload H-1 while the sibling `chain.json` holds N — still consistent + self-re-syncing, never a brick). | `test-chain-reorg-save-crash` (6 assertions): a DANGER PROOF reproducing the pre-fix brick + a FIX PROOF driving the real `save_incremental` through the crash seam at every atomic file boundary (crash before/after shrink, after tail rewrite, full completion, recovery-on-retry). FAST 217/0 both platforms; soundness [BoundedReorgSoundness.md](BoundedReorgSoundness.md) REORG-6. |

The recurring gate is the one every consensus increment uses: **goldens
byte-identical + FAST + live cluster**, strengthened here by the **deterministic
S-048 repro** (A4.3) that is the entire point of the work, and an **adversarial
review** of each consensus-touching increment before commit.

## 4. Invariants the implementation must preserve

- **Depth-1 hard bound.** `revert_head()` reverts exactly one block and refuses to
  revert twice in a row without an intervening apply; the node never evaluates a
  reorg that would rewrite `H-1` or below.
- **Validate-before-switch.** The replacement head must pass `validator_.validate`
  against `H-1` state BEFORE the revert commits — never revert on an unvalidated
  competitor (a Byzantine peer could otherwise force a revert to nothing).
- **Deterministic winner.** The switch criterion is `resolve_fork` VERBATIM, so all
  honest peers converge identically; no local tie-break, no timing dependence.
- **Atomic view publication.** The revert republishes `committed_state_view_` in one
  step so lock-free RPC readers never observe a torn head.
- **Supply / S-049 safety.** The revert restores a prior snapshot (no arithmetic),
  so the checked-add supply guards are untouched; the re-applied winner runs the
  same validated apply path as any block.

## 5. Risks / open questions

- **Snapshot cost on the hot path.** One `create_state_snapshot()` per head apply is
  an O(state) copy. The existing snapshot is lazy-capture; measure and, if needed,
  restrict the retained snapshot to the mutable subset actually diverging. Not a
  correctness risk — a throughput note.
- **Reorg storms.** Two peers oscillating is prevented by `resolve_fork` being a
  total order (every node picks the SAME winner), so after one exchange all agree;
  document that the winner is a pure function of the two blocks, not of arrival
  order.
- **Interaction with in-flight rounds.** A reorg mid-round must reset the round
  state (A4.2 bookkeeping) so the node re-derives its committee/proposer from the
  new head; the deterministic harness (A4.3) is what proves this converges.
