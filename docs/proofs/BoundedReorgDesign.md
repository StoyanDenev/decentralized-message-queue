# Bounded Head-Reorg Design — wiring `resolve_fork` to close S-048 (A4)

**Status: DESIGN-REVIEW; increment 1 (chain depth-1 revert primitive) implemented next.**
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
| A4.1 | **Chain depth-1 revert primitive** — `snapshot_prev_head_` captured before each head apply; `revert_head()` = restore + `pop_back()` + republish view; a hard guard that it only ever reverts the single head. Pure chain-layer, no node wiring yet. | a unit test asserts: apply H, capture root; apply H+1; `revert_head()` restores byte-identical H state (accounts/stakes/registry/roots) + `height()` drops by 1 + a second `revert_head()` is refused (depth-1 guard). FAST both platforms. |
| A4.2 | **Node wiring** — `resolve_fork` in the same-height branch + revert→append the winner, depth-1 guarded; post-reorg bookkeeping (reverted txs → mempool, registry rebuild, round/timer reset, equivocation + inbound-receipt redo, subscriber fan-out). | live 2-node cluster: force a same-height fork, assert both nodes converge on `resolve_fork`'s winner; FAST; goldens byte-identical (no change on the no-fork path). |
| A4.3 | **Deterministic S-048 repro harness** — a byte-deterministic in-process scenario (SeededRng + virtual scheduler): two nodes partition, each finalizes a different head, heal, assert the minority node reorgs to the winner and both tips are byte-identical; replay-twice-identical. | the repro is RED before A4.2, GREEN after; replay-twice-identical; both platforms. |
| A4.4 | **Sync-path rejoiner** — a node restarted holding a minority tail fetches + accepts the one-block replacement (today it hits `prev_hash mismatch` forever). | the REJOIN phase of `test-fa-liveness-virtual` converges instead of printing the KNOWN-OPEN S-048 marker; live cluster kill-recover loop. |
| A4.5 | **Persistence on reorg** — `save_incremental` rewrites the tail block file + manifest and resets `persisted_count_` (the in-code TODO); crash-consistency ordering (manifest-last). | a save→reorg→reload test: the reloaded chain has the winner tail, not the reverted block. |

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
