# BoundedReorgSoundness — the A4 depth-1 head reorg closes S-048 without weakening any settled state: bounded, exact, convergent, fail-closed, byte-neutral, restart-consistent, supply-safe

This is the soundness argument for the A4 bounded head-reorg (design
`docs/proofs/BoundedReorgDesign.md`; commits `d661d05` A4.1 revert primitive,
`e22d857` A4.2+A4.3 node wiring + deterministic repro) that closed **S-048**
(`docs/SECURITY.md:1345-1353`) at the node level. It proves the §4 invariants of
the design doc against the shipped source. The implementation surface is:
`Chain::revert_head` + `Chain::publish_committed_view` + the retained
`prev_head_snapshot_` (`src/chain/chain.cpp:1737-1797`,
`include/determ/chain/chain.hpp:95-110`, `:840-856`),
`Node::maybe_reorg_to_locked` + `Node::post_append_bookkeeping_locked`
(`src/node/node.cpp:2043-2243`), and the same-height call site in
`Node::apply_block_locked` (`src/node/node.cpp:2020-2026`). Pinning tests:
`test-chain-revert-head` (`src/main.cpp:33004-33189`, 11 assertions,
`tools/test_chain_revert_head.sh`) and `test-node-reorg-s048`
(`src/main.cpp:27004-27201`, 7 assertions over 4 scenarios,
`tools/test_node_reorg_s048.sh`), both in the FAST set (216/0 both platforms);
live witness = the 5-node `test-fa-liveness-virtual` cluster 10/10 with
`S-048 REORG` firing and zero stuck markers (`docs/SECURITY.md:1351`).

**PROVEN-in-code** = enforced by shipped source at the cited `file:line` and
witnessed by a named green assertion. No new crypto is introduced anywhere in
A4; every argument below is structural.

---

## REORG-1 — DEPTH-1 BOUND: no execution can rewrite a block at H-1 or below

**Claim.** Let H = `height()-1` be the head index. Every reorg path rewrites at
most the block at H; no reachable execution modifies, removes, or replaces any
block at index ≤ H-1.

**Argument.** Four independent mechanisms compose, each sufficient on its own
path:

1. **Caller gate.** The only live caller is the same-height branch of
   `apply_block_locked`: `maybe_reorg_to_locked` is invoked iff
   `chain_.height() >= 2 && b.index == chain_.height() - 1`
   (`src/node/node.cpp:2024-2025`). A block at any lower index stays in the
   pre-A4 duplicate/stale drop (with optional BFT equivocation logging,
   `:1952-2019`) and returns without touching the chain (`:2026`).
2. **Same-parent structural gate.** The reorg proceeds only when
   `incoming.prev_hash == cur.prev_hash` (`src/node/node.cpp:2170`) — the
   replacement extends the *same* H-1 parent, so by construction the block at
   H-1 and everything below is byte-identical before and after the swap.
3. **Genesis floor + snapshot consumption.** `revert_head` throws on
   `blocks_.size() < 2` (`src/chain/chain.cpp:1773-1775`) and on a missing
   snapshot (`:1776-1779`); the snapshot is move-consumed and reset on use
   (`:1780-1783`), so a second revert without an intervening apply is refused
   — reverting can never recurse below one block. Exactly one snapshot ever
   exists: the commit path *overwrites* the prior one (`:1741-1743`), and the
   node declines (rather than throws) when none exists, via
   `has_revertible_head()` (`include/determ/chain/chain.hpp:108-110`,
   `src/node/node.cpp:2186-2190`).
4. **Stale-snapshot exclusion.** Any non-incremental `blocks_` rewind
   (`atomic_scope` rollback) resets `prev_head_snapshot_`
   (`src/chain/chain.cpp:569-575`, `:578-584`), so a snapshot that no longer
   corresponds to the current head can never drive a revert. A *failed* apply
   changes neither `blocks_` (append pushes only after apply returns,
   `src/chain/chain.cpp:50-55`) nor the retained snapshot, preserving the
   invariant "Some(S) iff S is the state before `blocks_.back()`"
   (`include/determ/chain/chain.hpp:840-851`).

**Excluded failure.** A crafted block stream (or a repeated competitor volley)
rewinding the chain two or more blocks, or reverting genesis — the classic
long-range/deep-reorg surface. The S-047 abort-vs-finalize race that produces
these forks diverges only at a single head height (`docs/SECURITY.md:1347`;
BoundedReorgDesign §0), so depth-1 capability is complete for the defect.

**Witness.** `test-chain-revert-head`: "a second revert_head with NO intervening
apply is refused" (`src/main.cpp:33071-33076`) and "revert_head at height 1
refuses (genesis is the depth-1 finality floor)" (`:33086-33095`);
`has_revertible_head()` tracking across apply/revert (`:33133-33145`).

## REORG-2 — RESTORE FIDELITY: revert_head restores exactly the pre-head state

**Claim.** After `revert_head()`, every block-mutable state field equals its
value immediately before the head block was applied.

**Argument.** The retained snapshot is the **A9 faithful-rollback image**, not a
new mechanism: `apply_transactions` captures `__snapshot` at entry
(`src/chain/chain.cpp:696`) and, on commit, moves that exact object into
`prev_head_snapshot_` (`:1737-1743`) — so the revert reuses verbatim the same
restore machinery every failed apply has always used (`:641-681`). Coverage of
the block-mutable field set (`include/determ/chain/chain.hpp:801-836`):

- **Eager:** `accounts_` (mutated on every block) and `pending_param_changes_`
  (mutated by `activate_pending_params` at apply entry, `:738`), plus all 16
  mutable scalars (`genesis_total_`, the six `accumulated_*` counters,
  `min_stake_`, `suspension_slash_`, `unstake_delay_`, the three merge
  thresholds, `block_subsidy_`, `subsidy_pool_initial_`, `subsidy_mode_`,
  `lottery_jackpot_multiplier_`) — captured unconditionally
  (`src/chain/chain.cpp:607-631`), restored unconditionally (`:664-680`).
- **Lazy (9 containers):** `stakes_`, `registrants_`, `abort_records_`,
  `merge_state_`, `applied_inbound_receipts_`, `dapp_registry_`,
  `shielded_pool_`, `audit_keys_`, `audit_log_count_` — each guarded by an
  ensure-lambda (`:697-732`) that copies the container into the snapshot
  **before its first mutation** in the apply body (the AL-5 discipline,
  `AuditLayerSoundness.md`). The case split is exhaustive: if the container was
  touched, the optional holds the exact pre-apply value (capture preceded the
  first write), and move-restore is exact (`:646-663`); if untouched, the
  optional is nullopt and the live container *already equals* its pre-apply
  value, so skipping the restore is exact.
- **Deliberately outside the snapshot, each handled explicitly:** `blocks_`
  (handled by `pop_back()`, `:1784`), `persisted_count_` (handled by the clamp,
  REORG-6), `committed_state_view_` (rebuilt from the restored maps by
  `publish_committed_view()`, `:1796`, the verbatim factoring of the commit
  path `:1752-1767` — so lock-free readers never observe a torn or stale head),
  genesis-pinned routing fields (cannot change during apply,
  `include/determ/chain/chain.hpp:816-819`), and `param_changed_hook_` (not
  block-derived state, `src/chain/chain.cpp:633-640`).

**Excluded failure.** State leakage across the revert — a balance, nonce, stake,
staged param, or shielded/audit entry from the reverted head surviving into the
H-1 state, which would fork the state root against peers that never applied the
loser.

**Witness.** `test-chain-revert-head`: the exact-restore assertion compares
height, `head_hash`, **`compute_state_root()` over all state namespaces**,
balances, nonce, and stake against values captured before the head applied
(`src/main.cpp:33039-33069`); the lazy-path case mutates `stakes_` via a STAKE
head and asserts stake + balance + full root return exactly (`:33097-33131`).

## REORG-3 — CONVERGENCE / NO OSCILLATION: one deterministic winner, adopted once

**Claim.** All honest peers that observe both same-height candidates adopt the
same block, regardless of arrival order, and a once-adopted winner is never
flipped back by re-receipt of the loser.

**Argument.** `Chain::resolve_fork` (`src/chain/chain.cpp:1811-1832`) is a
**pure, order-independent total order** over distinct-content blocks: it reads
only the two blocks (count of non-zero `creator_block_sigs`, then
`abort_events.size()`, then lexicographic `compute_hash()`), uses no local
state, clock, or randomness, and every comparison is symmetric in its
arguments; the ultimate hash tie-break is total because gate (2) of the caller
has already excluded identical content (`src/node/node.cpp:2172-2174`). The
node applies this order verbatim — "no local tie-break, no timing dependence"
(design §4): a peer holding the loser sees
`resolve_fork(cur, incoming) == incoming` and reorgs; a peer holding the winner
sees the winner and returns with **zero mutation** (`:2179-2180`). So after one
exchange (guaranteed re-offers: the S-047 round-state retry plus the post-reorg
role broadcasts at `:2140-2156` — "announcing the winner helps stuck peers
converge", `:2236-2241`) both peers hold the winner. Re-receipt of the loser then hits gate
(3) forever; re-receipt of the winner hits gate (2). Oscillation would require
`resolve_fork(winner, loser) == loser`, contradicting order-independence.
Post-swap, the round machinery re-derives from the new head:
`post_append_bookkeeping_locked` clears aborts, cancels both phase timers,
resets the round, and re-runs `check_if_selected` (`:2062-2065`, `:2159`) — the
design §5 in-flight-round concern.

**Excluded failure.** Reorg storms (two peers flapping A→B→A on alternating
gossip) and permanent head divergence between honest peers that both saw the
fork — the residual liveness hole S-048 named.

**Witness.** `test-node-reorg-s048` scenario 1 WINNER (follower reorgs to the
resolve_fork winner over the real gossip path, `src/main.cpp:27149-27162`) +
scenario 3 LOSER (competitor preferred-against is dropped, head unchanged,
`:27177-27184`) + scenario 2 REPLAY (the entire fork+reorg replays
byte-identically on the same `SeededRng` seed — determinism witnessed
end-to-end, `:27164-27175`). Live: `test-fa-liveness-virtual` 10/10 with
`S-048 REORG` markers and zero "cannot reorg" markers (`docs/SECURITY.md:1351`).

## REORG-4 — FAIL-CLOSED: an invalid structural winner never displaces a valid head

**Claim.** A competitor that wins `resolve_fork` on its *claimed* signature set
but fails validation is rejected after the revert, and the old head is restored
verbatim; the chain is never left at H-1 by the reorg's designed paths.

**Argument.** The tie-break input is unauthenticated at gate time (non-zero sig
*slots* are counted, not verified — `src/chain/chain.cpp:1812-1818`), which is
exactly why the design mandates validate-before-switch (§4). The sequence
(`src/node/node.cpp:2192-2216`): copy the head (`old_head`, `:2195` — the
reference dies on `pop_back`), `revert_head()` (`:2196`), then
`validator_.validate(incoming, chain_, reg)` against the **restored H-1 state**
with the registry rebuilt at `incoming.index` (`:2202-2203` — REGISTER/
DEREGISTER effects of the reverted head are correctly absent). On `!res.ok`,
`chain_.append(old_head)` (`:2209`): apply is a deterministic function of
(state, block), the restored state is exactly the pre-head state (REORG-2), and
`old_head` validated and applied successfully once from that state — so the
re-append reproduces the original post-state and cannot fail; net effect is no
change, and the re-apply re-retains a fresh `prev_head_snapshot_`
(`src/chain/chain.cpp:1743`), so a later legitimate reorg remains possible. On
`res.ok`, `chain_.append(incoming)` installs the winner (`:2216`); either
branch ends with an appended head at H. Reverted-head transactions absent from
the winner return to the mempool with a stale-nonce guard (`:2223-2231`) so no
once-admitted honest tx is silently lost.

**Excluded failure.** A Byzantine peer forcing an honest node onto a garbage
block (or onto *nothing*) by stuffing sig slots — "never revert on an
unvalidated competitor" (design §4).

**Witness.** `test-node-reorg-s048` scenario 4 INVALID: a competitor that wins
the structural tie-break but carries a corrupted Phase-1 commit sig is rejected
after the revert and the old head is restored verbatim
(`src/main.cpp:27186-27194`); `test-chain-revert-head` "after revert, a
DIFFERENT block applies cleanly at the head height" pins the
apply-after-revert half (`:33078-33083`).

## REORG-5 — BYTE-NEUTRALITY: normal operation is a strict no-op

**Claim.** On the ordinary gossip stream — byte-identical duplicates and
competitors that lose to the current head — the A4 code performs no state
mutation, and the normal accept path is byte-identical to pre-A4.

**Argument.** All four gates in `maybe_reorg_to_locked` precede any mutation
(the block comment says so and the code obeys it,
`src/node/node.cpp:2166-2190`): wrong parent returns at `:2170`; a
byte-identical duplicate returns at `:2172-2174` (the M-creators gossip
fan-out case that dominates traffic); a losing competitor returns at
`:2179-2180`; a non-revertible head declines at `:2186-2190`. Blocks below the
head height never reach the function at all (`:2024`). The only mutation on
the normal accept path is the factoring of `post_append_bookkeeping_locked`,
extracted **verbatim, same order** from `apply_block_locked` (`:2040-2043`
comment; normal path = `chain_.append(b)` + the call, `:2036-2037`), and
`Chain`'s commit path change is the pure factoring of `publish_committed_view`
(`src/chain/chain.cpp:1723`, `:1749-1752` "so that path is byte-identical")
plus a snapshot *move* that replaced a destruction (`:1743`).

**Excluded failure.** A consensus-visible behavior change on chains that never
fork — the regression class the golden corpus exists to catch.

**Witness.** FAST 216/0 on both platforms with A4 compiled in — every
pre-existing golden state root and consensus vector unchanged
(`docs/SECURITY.md:1349`: "byte-neutral … strict no-op on the constant
gossip-duplicate stream"); `test-node-reorg-s048` scenario 3 LOSER pins the
no-mutation drop explicitly (`src/main.cpp:27177-27184`).

## REORG-6 — PERSISTENCE CONSISTENCY: a reorg-then-restart reloads the winner

**Claim.** After a reorg followed by a save and a restart, the node loads the
winner tail, not the reverted block.

**Argument.** The block store is append-only with an O(new) writer:
`save_incremental` writes exactly `blocks_[persisted_count_, size)` then the
manifest last (`src/chain/chain.cpp:2365-2388`; loop `:2373`, manifest
`:2377-2386`, `persisted_count_ = blocks_.size()` `:2387`). Without
intervention, a revert leaves `persisted_count_ > blocks_.size()`: the next
save writes **nothing** while the manifest names the new head, and `load()` —
which reads exactly `manifest.height` block files and replays them
(`:2424-2433`) — would replay the stale reverted block and throw the S-021
`head_hash`-mismatch gate (`:2440-2447`). `revert_head` therefore clamps
`persisted_count_` to `blocks_.size()` (`:1785-1795`, adversarial-review
finding 8), which forces the next `save_incremental` to **rewrite the tail
file** for whatever block next occupies that index — the reorg winner.
Thread-safety of the clamp: `persisted_count_` is save-thread-confined
(`include/determ/chain/chain.hpp:671-677`), and the revert runs under the
node's unique `state_mutex_`, mutually exclusive with the save worker's
shared_lock (`src/chain/chain.cpp:1792-1793`).

**Excluded failure.** A node that reorgs, saves, restarts — and either boots on
the loser (silent divergence) or refuses to boot at all (head-hash mismatch),
i.e. a reorg that "works until the first restart".

**Witness.** `test-chain-revert-head` persistence case: save through the
to-be-reverted head → `revert_head` → apply a distinct winner → save → `load()`
yields height 3 with the **winner** head hash, not the reverted one
(`src/main.cpp:33147-33183`).

## REORG-7 — SUPPLY SAFETY (S-049 interaction): no arithmetic on revert, checked arithmetic on re-apply

**Claim.** The reorg cannot mint, burn, or overflow value: the revert performs
no arithmetic, and every block applied by the reorg runs the normal
S-049-hardened apply path.

**Argument.** `restore_state_snapshot` is pure move/assignment — whole-map
moves and scalar copies of the captured values (`src/chain/chain.cpp:641-681`);
no `+`/`-` touches any balance, stake, or `accumulated_*` counter, so the
revert can introduce neither an overflow nor a divergence from the H-1 values
(REORG-2 gives exactness; this claim adds that the *mechanism* is
arithmetic-free, so the mod-2^64 blindness of the A1 identity —
`determ-a1-supply-invariant-mod2^64-blind` — has no new surface here). The
re-applied block (winner at `src/node/node.cpp:2216`, or the restored old head
at `:2209`) goes through `Chain::append` → `apply_transactions`
(`src/chain/chain.cpp:50-55`) — the same path as any block, including the
S-049 `checked_add_u64` debit guards at every `cost = amount + fee` site
(`:39`, `:821`, `:863`, `:1105`, `:1458`) and the post-apply invariant checks.
The mempool return of reverted txs (`src/node/node.cpp:2223-2231`) writes only
the two mempool maps — no balance is credited outside apply.

**Excluded failure.** A CVE-2010-5139-class value event smuggled through the
reorg path — e.g. a revert that "restores" by re-crediting, or a winner block
applied through a side door that skips the checked debits.

**Witness.** `test-chain-revert-head`'s exact-restore assertion pins the
supply-bearing state (balances, stake, and the full state root) byte-identical
after revert (`src/main.cpp:33060-33069`), and its re-apply assertion runs the
winner through the ordinary checked apply (`:33078-33083`); the S-049
regression assertions and the A1 supply-identity tests in FAST remain green
with A4 compiled in (FAST 216/0).

---

## LIMITS — what this argument does NOT cover

- **A4.4 — the sync-path rejoiner is still open.** This document proves the
  *running-node* fork closed. A node **restarted while holding a persisted
  minority tail** still cannot recover: append-only sync pulls forward from its
  own height and rejects the majority chain's next block with `prev_hash
  mismatch` forever (`docs/SECURITY.md:1353`; BoundedReorgDesign §3 A4.4). The
  REJOIN phase of `test-fa-liveness-virtual` converging is the gate for that
  increment, not this one.
- **Byzantine revert-amplification is bounded and fail-closed, not free**
  (adversarial-review finding 4). Because `resolve_fork` counts *claimed* sig
  slots (`src/chain/chain.cpp:1812-1818`), a Byzantine peer can repeatedly
  offer structural winners with garbage signatures, each costing the victim one
  revert + validate + re-append cycle (REORG-4: no net state change, depth-1
  work per offer). The planned hardening is a cheap pre-revert structural
  sig-slot sanity check (`docs/SECURITY.md:1353`); until then this is a bounded
  CPU-griefing surface, not a safety break.
- **Depth>1 forks are out of scope by mechanism, not by proof.** The S-047
  abort-vs-finalize race diverges at a single head height
  (`docs/SECURITY.md:1347`; design §0 "depth-1, frozen"), and REORG-1 shows the
  primitive *refuses* anything deeper — but no claim is made that a depth>1
  fork could be resolved if some other mechanism produced one. There is no
  explicit finality/checkpoint layer; H-1 is the de-facto floor.
- **BFT-mode nuance.** In the same-height branch, BFT equivocation-evidence
  assembly (`src/node/node.cpp:1960-2019`) runs *before* the reorg call, so
  adopting a winner does not suppress evidence against an equivocating
  proposer; slashing is orthogonal to fork choice. The `resolve_fork` ranking
  itself is the S-029 rule and is unchanged by A4.
- **Validator/apply divergence class.** REORG-4's "never left at H-1" covers
  the designed reject path (`validate` returns `!ok`). A hypothetical *throw*
  from inside the winner's apply after a successful validate (a
  validator-vs-apply divergence bug, the S-049/AL-3 class) would propagate and
  leave the node at H-1 until the S-047 retry re-offers a block — the same
  exposure class as the normal accept path, not one the reorg adds.
- **Observable, by design:** streaming subscribers see height H fan out twice
  on a reorg — once per head content (`src/node/node.cpp:2236-2242`). Inherent
  to any reorg; consumers must key on block hash, not height.
- **A4.5 — crash-during-save around a reorg.** REORG-6 covers the quiescent
  save→restart ordering; the crash-consistency ordering for a live daemon
  reorg racing an in-flight incremental save (manifest-last hardening) is the
  remaining A4.5 increment (design §3).

---

## Cross-references

- `BoundedReorgDesign.md` — the design + increment plan; §4 is the invariant
  register this document discharges (depth-1 hard bound → REORG-1;
  validate-before-switch → REORG-4; deterministic winner → REORG-3; atomic
  view publication → REORG-2; supply/S-049 safety → REORG-7).
- `docs/SECURITY.md:1345-1353` — S-048 CLOSED entry: mechanism, fix, validation
  anchors, remaining follow-ons (A4.4/A4.5).
- `RoundStateRetrySoundness.md` — S-047: the retry that re-offers blocks/round
  state (the delivery mechanism REORG-3's convergence leans on) and whose §4
  explicitly deferred minority-fork recovery to this work.
- `AuditLayerSoundness.md` AL-5 — the A9 snapshot/ensure-lambda rollback
  machinery REORG-2 reuses verbatim.
- Memory: `determ-a1-supply-invariant-mod2^64-blind` — why REORG-7 rests on
  checked_add + snapshot restore, not on the A1 identity.
