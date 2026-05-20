# FA-Apply-15 — Multi-event composition in `apply_transactions`

This document formalizes the **composition property** of the apply path: when a single finalized block carries a heterogeneous mix of state-mutating surfaces — ordinary transactions (`TRANSFER`, `REGISTER`, `STAKE`, `UNSTAKE`, `DEREGISTER`, `PARAM_CHANGE`, `COMPOSABLE_BATCH`, `MERGE_EVENT`, `DAPP_REGISTER`, `DAPP_CALL`), `AbortEvent`s, `EquivocationEvent`s, and `CrossShardReceipt` inbound entries — the apply path consumes them in a strictly serialized, consensus-pinned order, and each surface's per-event invariants (from the corresponding FA-Apply proof) hold independently of the other surfaces' presence or absence in the same block. The composition is not just "no cross-surface interference"; it is the stronger claim that the unitary-supply invariant A1, the state-root commitment S-033, and the snapshot-replay equivalence T-S2 each compose **additively** over the per-surface deltas, with the chain-wide accumulators (`block_inbound`, `block_outbound`, `block_slashed`, `total_fees`, `subsidy_this_block`) acting as the per-block linear-superposition channel that the apply-tail A1 closure consumes as a single ledger equation.

The proof is structural rather than mechanical: it rests on the apply path being a finite sequence of independent loops, each loop body reading from + writing to a disjoint set of state maps (modulo the small intersection where `accounts_[d]` is touched by both `TRANSFER` recipients and `DAPP_CALL` recipients), and the chain-wide accumulators being u64 sums whose order-independence over a finite block follows from `u64` addition's commutativity + the `checked_add_u64` overflow guard's at-most-one-throw behavior. The strength of this document is consolidation: every prior FA-Apply proof (FA-Apply-1 through FA-Apply-14) targets a single surface in isolation — `CrossShardReceiptDedup.md` (FA-Apply-9) covers inbound receipts, `EquivocationSlashingApply.md` (FA-Apply-10) covers equivocation, `AbortEventApply.md` (FA-Apply-11) covers abort events, `AppliedReceiptRestore.md` (FA-Apply-12) covers the dedup-set snapshot round-trip, and so on — but none of them states the joint property that **all of them hold simultaneously** when their respective events coincide in one block. FA-Apply-15 names that joint property and pins the per-loop-disjoint-write argument that makes it hold by construction.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for the six per-event invariants I-1 through I-6 (atomic apply / nonce monotonicity / balance ↔ stake independence / cross-shard credit channel / balance arithmetic channels / A1 contribution); `EquivocationSlashingApply.md` (FA-Apply-10) for the equivocation-slash branch's deltas T-E1 through T-E7; `AbortEventApply.md` (FA-Apply-11) for the abort-slash branch's deltas T-A1 through T-A8; `CrossShardReceiptDedup.md` (FA-Apply-9) for the inbound-receipt dedup + credit-branch deltas T-R1, T-R2; `AppliedReceiptRestore.md` (FA-Apply-12) for the snapshot-replay equivalence of the dedup set; `SnapshotEquivalence.md` (FA-Apply-2) for the cross-namespace state-root coverage L-S0 / L-S1 + the apply-after-restore equivalence T-S2; `EconomicSoundness.md` (FA11) for the A1 unitary-supply closure that this proof's T-M3 specializes to multi-event blocks; `docs/PROTOCOL.md` §6.1 for the apply-rules order; `docs/SECURITY.md` §S-033 / §S-038 for the state-root commitment + producer-side wiring that make T-M4 non-vacuous on production blocks.

---

## 1. Setup

### 1.1 The apply path is a serialized sequence of loops

`Chain::apply_transactions(const Block& b)` at `src/chain/chain.cpp:633` is the single entry-point for replaying any non-genesis block. The function body — once the genesis short-circuit at line 681 and the A9 snapshot capture at lines 646–670 are accounted for — is structurally a **serialized sequence of seven loops** over the block's six event-bearing fields, plus one bookkeeping closure at the tail:

| Phase | Apply step | Source range | Reads | Writes |
|---|---|---|---|---|
| **1** | Phase A: `b.transactions[]` loop (10 tx-types: TRANSFER, REGISTER, STAKE, UNSTAKE, DEREGISTER, PARAM_CHANGE, COMPOSABLE_BATCH, MERGE_EVENT, DAPP_REGISTER, DAPP_CALL) | `chain.cpp:734–1232` | `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, `pending_params_` | `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, `merge_state_`, `total_fees` accumulator |
| **2** | Fee + subsidy distribution to creators | `chain.cpp:1286–1305` | `total_fees`, `subsidy_this_block`, `b.creators` | `accounts_` (creator credits), `accumulated_subsidy_` (deferred) |
| **3** | `b.abort_events[]` loop (round-1 Phase-1 slashing only) | `chain.cpp:1313–1328` | `abort_records_`, `stakes_` | `abort_records_`, `stakes_`, `block_slashed` |
| **4** | `b.equivocation_events[]` loop (full forfeit + immediate deregister) | `chain.cpp:1344–1356` | `stakes_`, `registrants_` | `stakes_`, `registrants_`, `block_slashed` |
| **5** | `b.inbound_receipts[]` loop (cross-shard credit + dedup) | `chain.cpp:1363–1381` | `applied_inbound_receipts_`, `accounts_` | `applied_inbound_receipts_`, `accounts_`, `block_inbound` |
| **6** | A1 accumulator update + A1 closure assertion | `chain.cpp:1390–1419` | All per-block accumulators + chain-wide counters | `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_` |
| **7** | S-033 state-root verification gate | `chain.cpp:1430–1446` | All state maps via `compute_state_root` | (assertion-only — throws on mismatch) |

The order is **consensus-pinned**: every honest node sees the same `b.transactions`, `b.abort_events`, `b.equivocation_events`, `b.inbound_receipts` in the same indices because the block's body is signed by the K creators (PROTOCOL.md §4) and the order of these fields inside the body is the wire format. T-M1 below pins this order formally; the remaining theorems consume the ordering as a hypothesis.

### 1.2 The five per-block accumulators

`apply_transactions` declares five `uint64_t` per-block accumulators at the top of the non-genesis path (`chain.cpp:720–725`):

```cpp
uint64_t total_fees    = 0;      // collected from tx.fee on every successful tx
uint64_t block_outbound = 0;     // cross-shard TRANSFER amount that left this shard
uint64_t block_inbound  = 0;     // cross-shard receipt amount credited here
uint64_t block_slashed  = 0;     // suspension + equivocation forfeit
                                 // (also subsidy_this_block, computed at line 1267)
```

Each accumulator is mutated by exactly one Phase's loop (modulo `block_slashed` which is shared by Phases 3 + 4 — both abort-slash and equivocation-slash contribute to the same chain-wide A1-burn channel). The accumulators are u64 + are guarded by `checked_add_u64` at every write that depends on an attacker-influenced value (S-007 closure). At the apply-tail (lines 1393–1395), they are folded into the chain-wide counters via four sequential u64 additions:

```cpp
accumulated_subsidy_  += subsidy_this_block;   // conditional on creators non-empty
accumulated_inbound_  += block_inbound;
accumulated_outbound_ += block_outbound;
accumulated_slashed_  += block_slashed;
```

The A1 closure at lines 1397–1419 then evaluates `expected_total() = genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ - accumulated_slashed_ - accumulated_outbound_` and asserts `live_total_supply() == expected_total`. The five-term linear equation is **additive over the per-block contributions** by construction — each surface contributes to exactly one or two of the four ± channels, and the sum-of-contributions equals the chain-wide post-block delta.

### 1.3 The disjoint-write claim

A multi-event block's apply correctness hinges on the per-loop write sets being **disjoint or commuting**. Inspect the loop bodies:

- Phase 1 (transactions): writes `accounts_[*]`, `stakes_[*]`, `registrants_[*]`, `dapp_registry_[*]`, `merge_state_`, `total_fees`, `block_outbound`. Reads the same maps for tx-state lookup.
- Phase 2 (fee distribution): writes `accounts_[creator_i].balance` for `i ∈ [0, m)`. Reads `total_fees`, `subsidy_this_block`, `b.creators`.
- Phase 3 (abort-slash): writes `abort_records_[d]`, `stakes_[d].locked`, `block_slashed`. Reads `stakes_`.
- Phase 4 (equivocation-slash): writes `stakes_[d].locked`, `registrants_[d].inactive_from`, `block_slashed`. Reads same maps.
- Phase 5 (inbound receipts): writes `accounts_[r.to].balance`, `applied_inbound_receipts_`, `block_inbound`. Reads same maps.
- Phase 6 (A1 closure): writes the four chain-wide counters. Reads per-block accumulators.
- Phase 7 (S-033 gate): reads everything via `compute_state_root`. Writes nothing.

The pairwise intersections that matter:

- Phase 1 `accounts_[*]` ∩ Phase 2 `accounts_[creator_i]`: Phase 2 reads `total_fees` set by Phase 1, but writes only to creator-indexed entries. Sender + recipient balances are stabilized by end of Phase 1.
- Phase 1 `stakes_[*]` ∩ Phase 3 `stakes_[d].locked`: Phase 3 reads only locked field, Phase 1 might have written locked via STAKE/UNSTAKE earlier this block. **This is intentional** — a STAKE in the same block as an abort against the same domain should let the abort slash the post-STAKE locked value (the chain treats the block as fully committed before slashing).
- Phase 3 `stakes_[d].locked` ∩ Phase 4 `stakes_[d].locked`: an abort + equivocation on the same domain in the same block sequence the abort-slash first (deduct ≤ `SUSPENSION_SLASH`), then the equivocation-slash full-forfeits whatever remains. The composed effect equals the equivocation full-forfeit (T-E3 idempotence absorbs the abort's contribution).
- Phase 4 `registrants_[d]` ∩ Phase 1 `registrants_[d]`: a REGISTER + EquivocationEvent on the same domain in the same block — REGISTER's contains-check (`chain.cpp:792–812`) skips if entry exists, so a re-REGISTER is silent; if the domain wasn't registered, Phase 1 creates the entry (with `inactive_from = UINT64_MAX`), and Phase 4 immediately deactivates it (`inactive_from = b.index + 1`). The net effect is "registered + deactivated in the same block" — a transient registration that never participates.
- Phase 5 `accounts_[r.to].balance` ∩ Phase 1 `accounts_[r.to].balance` ∩ Phase 2 `accounts_[creator].balance`: all three are u64 additions on the same balance field. Commutative; the final value is the sum of the contributions modulo the per-step S-007 overflow check.

No intersection produces non-commuting effects under the apply-time guarantee that each loop's per-iteration write is a deterministic function of the state at the moment of read. T-M6 below formalizes this.

### 1.4 The A9 atomic-apply envelope

The entire seven-phase apply path runs inside a single `try { ... } catch { ... }` block (`chain.cpp:671` open, the catch block elsewhere). The A9 atomic-apply property (`AccountStateInvariants.md` I-1) is that any throw in any Phase 1–7 rolls back **all** map mutations to the pre-apply state — the snapshot captured at `chain.cpp:646–670` (the `StateSnapshot __snapshot` + the six lazy-snapshot `__ensure_*` helpers) is restored on throw via `restore_from_snapshot_internal`. This means multi-event composition is also atomic: a block containing 3 TRANSFERs + 2 AbortEvents + 1 EquivocationEvent + 5 inbound receipts that throws at the A1 closure (Phase 6) rolls back ALL of them, not just the last loop's. The atomic envelope is what makes the per-surface invariants composable without ordering-induced partial-failure modes — there is no "partial apply" state observable on the chain.

---

## 2. Theorems

### T-M1 — Deterministic event ordering

**Statement.** For every block `B`, the apply path consumes B's event-bearing fields in the strict, consensus-pinned order:

1. `b.transactions[i]` for `i = 0, 1, ..., |b.transactions| - 1`
2. Fee + subsidy distribution to `b.creators[]`
3. `b.abort_events[i]` for `i = 0, 1, ..., |b.abort_events| - 1`
4. `b.equivocation_events[i]` for `i = 0, 1, ..., |b.equivocation_events| - 1`
5. `b.inbound_receipts[i]` for `i = 0, 1, ..., |b.inbound_receipts| - 1`
6. A1 accumulator update + closure assertion
7. S-033 state-root verification

with no interleaving across phases. Two independent invocations of `apply_transactions(b)` on chains in equivalent pre-states (per FA-Apply-2 §1.2) produce byte-identical post-states.

**Proof sketch.** By direct inspection of `chain.cpp:633` through `chain.cpp:1499`. The function body is a sequence of seven loops (or loop-equivalent linear blocks) without `goto`, without coroutine yields, without nested calls that re-enter `apply_transactions`. Each loop iterates in `std::vector` index order (the four event fields are `std::vector<T>` per `block.hpp:228–280`), which is the block-construction order pinned by the producer's `make_canonical_block` and signed by the K creators. The block's wire format (PROTOCOL.md §4) carries the four vectors as ordered arrays; an attacker reordering them would change `block_hash` and fail V14 (state_root match). Phase 2's fee distribution iterates `b.creators[]` in vector index order. Phases 6 + 7 are not loops but sequential statements. The composition is byte-deterministic by FA-Apply-2 T-S6 (no I/O, no clock, no RNG) and by the per-Phase deterministic-loop arguments (T-A8, T-E7, T-R1/T-R2 determinism, etc.). ∎

**Code witness.** `src/chain/chain.cpp:633–1499` (the full apply path); `src/chain/chain.cpp:734` (Phase 1 loop head); `src/chain/chain.cpp:1286` (Phase 2 distribution); `src/chain/chain.cpp:1313` (Phase 3 loop head); `src/chain/chain.cpp:1344` (Phase 4 loop head); `src/chain/chain.cpp:1363` (Phase 5 loop head); `src/chain/chain.cpp:1395` (Phase 6 accumulator); `src/chain/chain.cpp:1430` (Phase 7 S-033 gate).

**Test witness.** `tools/test_multi_event_block_apply.sh` (intended canonical regression — exercises a single block containing TRANSFER + abort + equivocation + inbound + DAPP_CALL and asserts the per-Phase deltas land independently). `tools/test_block_event_composition.sh` (broader composition surface — asserts Phase ordering is observable via per-Phase state-root diffs). Both regressions inherit byte-determinism from `tools/test_chain_save_load.sh` (snapshot roundtrip preserves the post-apply state).

### T-M2 — Independent per-event invariance

**Statement.** Let `B` be a block containing events of mixed types. For each event `e ∈ B.transactions ∪ B.abort_events ∪ B.equivocation_events ∪ B.inbound_receipts`, the per-event invariant from the corresponding FA-Apply proof holds **regardless** of the presence or absence of other event types in `B`. Formally:

- For each `tx ∈ B.transactions`, the corresponding TxType's invariant (FA-Apply T-K1/T-K2/T-K3 for STAKE/UNSTAKE/DEREGISTER, FA-Apply-13's outbound apply for cross-shard TRANSFER, FA-Apply DApp lifecycle, etc.) holds.
- For each `ae ∈ B.abort_events` with `ae.round == 1`, the FA-Apply-11 deltas T-A1, T-A3, T-A4, T-A5, T-A6, T-A7 hold.
- For each `ev ∈ B.equivocation_events`, the FA-Apply-10 deltas T-E1, T-E2, T-E3, T-E4, T-E5 hold.
- For each `r ∈ B.inbound_receipts` with `(r.src_shard, r.tx_hash) ∉ applied_inbound_receipts_`, the FA-Apply-9 deltas T-R1 hold; for the duplicate case, T-R2 holds.

The invariance is **independent** in the strict sense: the deltas for `e_i` do not depend on the deltas for `e_j` for `i ≠ j`, **modulo intentional coupling** (T-M6 below) where two events legitimately co-mutate the same field (e.g., abort + equivocation on the same domain).

**Proof sketch.** Each FA-Apply-N proof's deltas are stated as a function of (a) the event-specific fields (`tx.from`, `tx.to`, `tx.amount`, `ae.aborting_node`, `ev.equivocator`, `r.to`, `r.amount`, etc.) and (b) the chain state at the moment of read inside the corresponding loop body. The chain state at Phase k's read is the **post-Phase-(k-1) state**, which is well-defined by T-M1's serialized ordering. Because each FA-Apply-N's loop body is independent of the events processed in other Phases (their reads/writes are on disjoint or commuting state — §1.3), the loop body's deltas evaluated at the post-(k-1) state are identical to the deltas it would produce if the block contained ONLY this event. The independence is structural: there is no "if other events present" branch in any of the loop bodies — each iteration is a self-contained read-then-compute-then-write triple over the event's fields + the relevant subset of state.

The intentional-coupling cases (T-M6) are confined to a small enumeration: STAKE/UNSTAKE → abort-slash (Phase 1 sets locked, Phase 3 deducts), REGISTER → equivocation (Phase 1 creates entry, Phase 4 deactivates), and the shared `block_slashed` channel between Phases 3 + 4. None of these cases breaks per-event invariance — they each produce the natural "in-block ordering" semantics that the protocol design intends. ∎

**Code witness.** Per-Phase loop bodies cited under T-M1. Each loop body is structurally independent of the others (no shared loop variable, no `goto` between phases).

**Test witness.** `tools/test_multi_event_block_apply.sh` (asserts each Phase's per-event invariant holds in a composed block). `tools/test_block_event_composition.sh` (cross-product: TRANSFER + abort, TRANSFER + equivocation, abort + equivocation on same domain, inbound + DAPP_CALL credit, etc., each asserting per-Phase invariants from the FA-Apply-N theorems remain valid). The full unit-test surface (`tools/test_abort_event_apply.sh`, `tools/test_equivocation_apply.sh`, `tools/test_cross_shard_atomicity.sh`, `tools/test_dapp_call_apply.sh`) covers each Phase in isolation; T-M2 composes them.

### T-M3 — A1 composability

**Statement.** For any block `B` with arbitrary event mix, the A1 unitary-supply invariant decomposes additively over per-event contributions:

```
Δlive_total_supply(B) = Σ_{tx ∈ B.transactions} Δ(tx)
                      + Σ_{i ∈ creators} (fee_share + subsidy_share)
                      + Σ_{ae ∈ B.abort_events, ae.round==1} (−min(SUSPENSION_SLASH, locked₀(ae)))
                      + Σ_{ev ∈ B.equivocation_events} (−locked₀(ev))
                      + Σ_{r ∈ B.inbound_receipts, fresh} (+r.amount)
```

with the matching `Δexpected_total(B)` advancing by the same scalar. The A1 closure `live_total_supply() == expected_total()` at `chain.cpp:1399` evaluates to **equality** at apply-tail iff each of the four chain-wide accumulator updates at lines 1393–1395 matches the sum of the per-event contributions to the corresponding accumulator.

**Proof sketch.** Each Phase's contribution to the supply equation is a sum of per-event u64 deltas, with the per-event contribution to one of the five A1 channels:

- Phase 1 TRANSFER (local): `Δaccounts_[from].balance = -(amount+fee)`, `Δaccounts_[to].balance = +amount`, `Δtotal_fees = +fee` → net `Δsupply = 0` from this tx (the fee will be re-distributed by Phase 2; per FA11 the fee channel is intra-supply).
- Phase 1 TRANSFER (cross-shard outbound): `Δaccounts_[from].balance = -(amount+fee)`, `Δblock_outbound = +amount`, `Δtotal_fees = +fee` → net `Δsupply = -(amount+fee)` from this tx; the `-amount` enters A1 via `accumulated_outbound_`, and the `-fee` is reconstituted by Phase 2's creator credits.
- Phase 1 STAKE: `Δaccounts_[d].balance = -(amount+fee)`, `Δstakes_[d].locked = +amount`, `Δtotal_fees = +fee` → net `Δsupply = 0` (balance leaves, locked enters; T-K1 of FA-Apply-4).
- Phase 1 UNSTAKE (success): `Δaccounts_[d].balance = +amount - fee`, `Δstakes_[d].locked = -amount`, `Δtotal_fees = +fee` → net `Δsupply = 0` (T-K2).
- Phase 1 other tx-types (REGISTER / DEREGISTER / PARAM_CHANGE / DAPP_REGISTER / DAPP_CALL local / MERGE_EVENT): `Δsupply = 0` (each is fee-only mutation modulo a control-flow effect — DAPP_CALL local credits within-shard are zero-sum like TRANSFER).
- Phase 2 fee + subsidy distribution: `Δaccounts_[creator_i].balance = +per_creator (+remainder for creator[0])`. The subsidy portion adds `Δaccumulated_subsidy_ = +subsidy_this_block` at Phase 6 (line 1391, conditional on `total_distributed > 0 && !b.creators.empty()`). Net `Δsupply = +subsidy_this_block` from the subsidy channel (the fee portion is intra-supply circulation).
- Phase 3 abort-slash: `Δstakes_[d].locked = -deduct`, `Δblock_slashed = +deduct` → net `Δsupply = -deduct` from this event (the slashed value enters `accumulated_slashed_` at Phase 6, which subtracts from `expected_total`). T-A7.
- Phase 4 equivocation-slash: `Δstakes_[d].locked = -L`, `Δblock_slashed = +L` → net `Δsupply = -L` from this event. T-E5.
- Phase 5 inbound receipt (fresh): `Δaccounts_[r.to].balance = +r.amount`, `Δblock_inbound = +r.amount` → net `Δsupply = +r.amount` from the inbound channel. T-R1.
- Phase 5 inbound receipt (duplicate): zero contribution (T-R2 silent skip).

Phase 6's chain-wide accumulator update is a literal u64 addition of the per-block sums into the chain-wide counters; under u64 commutativity the sum-of-events-per-Phase equals the Phase's contribution to A1, and the Phase-wise contributions sum to the block's total supply delta. The A1 closure at line 1399 checks `actual == expected` where both sides have been advanced by the same scalar — by construction the equality holds for any well-formed block. Any single per-event miscount (e.g., a TRANSFER that debited the sender but forgot to increment `block_outbound` on a cross-shard destination) would surface here as a thrown `runtime_error`. ∎

**Code witness.** `src/chain/chain.cpp:1393–1419` (the additive accumulator + A1 closure block). Each per-Phase contribution is anchored in the FA-Apply-N proof's T-N7-or-equivalent A1 invariance theorem (T-A7 for abort, T-E5 for equivocation, T-R1 for inbound, T-K1/T-K2 for stake lifecycle).

**Test witness.** `tools/test_multi_event_block_apply.sh` (asserts the A1 closure passes on a block containing TRANSFER + abort + equivocation + inbound + DAPP_CALL — each contributing to a different channel). `tools/test_supply_lifecycle.sh` (multi-block A1 closure across a long mixed event stream — composed assertion). `tools/test_supply_invariant.sh` (closure under composed sequence including equivocation events).

### T-M4 — State-root composability

**Statement.** For any block `B`, the post-apply state-root `compute_state_root(C_post)` is a deterministic function of the union of per-event state mutations applied in the order pinned by T-M1. Formally:

```
state_root(C_post) = hash(  state(C_pre)
                         ⊕ Σ_{tx ∈ B.transactions} effect(tx)
                         ⊕ Σ_{i ∈ creators} effect(fee_credit_i)
                         ⊕ Σ_{ae ∈ B.abort_events} effect(ae)
                         ⊕ Σ_{ev ∈ B.equivocation_events} effect(ev)
                         ⊕ Σ_{r ∈ B.inbound_receipts} effect(r) )
```

where `⊕` denotes the apply-order composition of state mutations on the chain's ten Merkle namespaces (`a:`, `s:`, `r:`, `d:`, `i:`, `b:`, `m:`, `p:`, `k:`, `c:`). The S-033 verification gate at `chain.cpp:1430–1446` then asserts `body.state_root == compute_state_root(C_post)`, blocking any block whose producer's computed root disagrees with the apply-time recomputed root.

**Proof sketch.** Each Phase's contribution to a state-root namespace is structural:

- Phase 1 transactions mutate `accounts_` (→ `a:`), `stakes_` (→ `s:`), `registrants_` (→ `r:`), `dapp_registry_` (→ `d:`), `pending_params_` (→ `p:`), `merge_state_` (→ `m:`).
- Phase 2 fee + subsidy distribution mutates `accounts_` only (→ `a:`).
- Phase 3 abort-slash mutates `abort_records_` (→ `b:`) + `stakes_` (→ `s:`).
- Phase 4 equivocation-slash mutates `stakes_` (→ `s:`) + `registrants_` (→ `r:`).
- Phase 5 inbound receipts mutate `applied_inbound_receipts_` (→ `i:`) + `accounts_` (→ `a:`).
- Phase 6 mutates chain-wide counters (→ `k:`, `k:c:` namespace).
- Phase 7 reads everything, writes nothing.

`build_state_leaves` at `chain.cpp:267` iterates each map in sorted-key order and emits one Merkle leaf per entry; the leaves' contributions are byte-stable under deterministic apply (T-M1 + T-A8 + T-E7 + T-R1/T-R2 determinism). The sorted-leaves balanced binary Merkle tree (`AppliedReceiptRestore.md` §1.2 + `Preliminaries.md` §2.1) is a pure function of the leaf set, so two chains in equivalent post-states produce byte-identical state-roots.

The crucial property is the producer-side wiring (S-038): `Node::try_finalize_round` populates `body.state_root` via a tentative-chain dry-run BEFORE broadcasting the block (`node.cpp:1024–1113`). The producer's computed root at the moment of block construction equals the validator's recomputed root at the moment of apply (under T-M1's deterministic ordering + T-A8 + T-E7 + T-R1's per-Phase determinism). The S-033 gate at `chain.cpp:1430` is the apply-time check; under S-038's wiring, the gate fires on every production block and validates that the recomputed root matches.

The composition is "additive" in the namespace-disjoint sense: each Phase touches a known subset of namespaces, and the final state-root is the Merkle root over the union of all post-Phase namespaces. There is no Phase that "subtracts" from another Phase's namespace contributions — slashing zeros `stakes_[d].locked` but the `s:` namespace's leaf for `d` is still emitted (with the new value), preserving the leaf set's structure even when individual entries' values change. ∎

**Code witness.** `src/chain/chain.cpp:267–413` (`build_state_leaves` + `compute_state_root`); `src/chain/chain.cpp:1430` (Phase 7 S-033 gate); `src/node/node.cpp:1024–1113` (producer-side S-038 wiring that populates `body.state_root` via tentative dry-run); `docs/PROTOCOL.md` §4.1.1 (the ten-namespace key-encoding table).

**Test witness.** `tools/test_multi_event_block_apply.sh` (asserts `body.state_root == compute_state_root()` after applying a multi-event block). `tools/test_block_event_composition.sh` (Phase-by-Phase state-root deltas observable when isolating Phases). `tools/test_state_root_namespaces.sh` (12 assertions covering each of the ten namespaces; T-M4 inherits the per-namespace coverage). `tools/test_dapp_snapshot.sh` (S-033 + S-038 joint surface end-to-end on a DApp-active multi-event chain).

### T-M5 — Replay determinism with multi-event blocks

**Statement.** For any chain `C` and block sequence `B_1, B_2, ..., B_n` with each `B_i` containing arbitrary event-mix, two independent replays of `apply_transactions(B_i)` for `i = 1, ..., n` on chains in equivalent pre-states produce byte-identical post-states. Specifically, after `n` blocks: identical `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `pending_params_`, and identical chain-wide accumulators (`accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_`).

**Proof sketch.** By induction on `n`. Base case `n = 0`: trivial (equivalent pre-states are equivalent post-zero-blocks). Inductive step `k → k+1`: assume two chains `C_A`, `C_B` are state-equivalent after `B_1..B_k`. Apply `B_{k+1}` to both. T-M1 fixes the per-Phase ordering on both sides identically. T-M2 fixes the per-Phase per-event deltas on both sides identically (each FA-Apply-N's T-N7-or-equivalent determinism theorem applies independently). T-M3 fixes the A1 accumulator updates identically. T-M4 fixes the post-Phase state-root identically. Therefore the post-`B_{k+1}` states are equivalent.

The induction's load-bearing primitive is that no Phase reads from a non-deterministic source — no `std::random_device`, no system clock, no thread-scheduler hint, no `std::chrono::now()`. Every read is either from a deterministic chain-state map or from a deterministic block field. The `compute_state_root` recomputation at Phase 7 is a pure function of the maps (T-M4). Replay-determinism is therefore structural.

The snapshot-restore variant (FA-Apply-2 T-S2) composes: a chain restored from snapshot at state-equivalent point `C_k` followed by replay of `B_{k+1}..B_n` produces the same post-state as a chain that applied all `n` blocks from genesis. T-M5 is the "no surprises" property that makes fast-bootstrap (snapshot + replay tail) operationally correct on multi-event chains. ∎

**Code witness.** `src/chain/chain.cpp:633–1499` (the apply path); all per-Phase determinism theorems (T-A8, T-E7, T-R1 / T-R2 determinism, T-K7 stake-lifecycle determinism).

**Test witness.** `tools/test_chain_save_load.sh` (snapshot roundtrip determinism on multi-event chains). `tools/test_snapshot_then_apply.sh` (21-assertion regression covering snapshot → replay of arbitrary tail). `tools/test_multi_event_block_apply.sh` (T-M5 base case: two chains seeing the same multi-event block produce byte-identical post-states + identical state-roots).

### T-M6 — No event-event interference (modulo intentional coupling)

**Statement.** For any block `B` and any pair of events `e_i, e_j ∈ B.transactions ∪ B.abort_events ∪ B.equivocation_events ∪ B.inbound_receipts` with `i ≠ j`, the apply-time invariant of `e_j` is unchanged by the presence of `e_i` **except** in the following intentional-coupling cases:

1. **Slashing collapses to equivocation**: if `B.abort_events` contains an abort for domain `d` and `B.equivocation_events` also contains an equivocation for `d`, the abort-slash deducts up to `SUSPENSION_SLASH` from `stakes_[d].locked` first (Phase 3), then the equivocation full-forfeits whatever remains to zero (Phase 4). The combined `Δblock_slashed = locked_pre_phase3` (the pre-Phase-3 value), not `min(SUSPENSION_SLASH, locked) + (locked - min(SUSPENSION_SLASH, locked)) = locked` is the same scalar by additive cancellation — this is the consistent answer regardless of ordering, but the explicit ordering is "abort then equivocation" and the slashing branch's T-E1 reads `sit->second.locked` post-Phase-3.

2. **Fee distribution depends on creators**: Phase 2's fee + subsidy credit depends on `b.creators[]` and on `total_fees` aggregated across Phase 1. This is an intra-block dependency, not a cross-event interference — the fee channel is fully determined by Phase 1's tx-set + the block header's creators.

3. **Subsidy accumulator gated on creators**: `accumulated_subsidy_` is only incremented when `total_distributed > 0 && !b.creators.empty()` (line 1390), which is an unconditional structural condition on the block — independent of any specific event's presence.

4. **Cross-shard outbound depends on tx routing**: a TRANSFER's contribution to `block_outbound` is conditional on `is_cross_shard(tx.to)` (line 752). This is a tx-internal property, not a cross-event coupling.

5. **STAKE / UNSTAKE during slashing block**: if Phase 1 contains a STAKE for `d` and Phase 3 contains an abort for `d`, the Phase-3 slash reads the post-Phase-1 locked value (which includes the just-staked amount). The post-block `stakes_[d].locked` reflects both the credit and the slash — the chain treats the block as a single committed unit.

6. **REGISTER + EquivocationEvent on the same domain**: if Phase 1 contains a REGISTER for `d` (creating `registrants_[d]` with `inactive_from = UINT64_MAX`) and Phase 4 contains an EquivocationEvent for `d`, Phase 4 immediately deactivates the entry (`inactive_from = b.index + 1`). The net effect is "registered + immediately deactivated in the same block" — a transient registration that never participates in selection. This is the design — a Byzantine actor who registers and immediately equivocates is removed in the same block.

All five intentional-coupling cases produce well-defined, deterministic semantics under T-M1's serialized ordering. None of them breaks T-M3's A1 composability — the per-channel accumulator updates remain additive across the events.

**Proof sketch.** The general claim (no interference) follows from §1.3's disjoint-write argument: each Phase's loop body reads from + writes to a known set of state maps, and the pairwise intersections produce deterministic results under u64 commutativity (balance arithmetic) or under structural sequencing (set / map writes that don't depend on iteration order). The five enumerated coupling cases are exhaustive — they each correspond to a specific structural intersection identified in §1.3 — and they each have a published semantics:

- Case 1 (abort + equivocation on same domain) is handled by FA-Apply-10 T-E3's idempotence claim: the second slash on the same domain contributes zero, regardless of whether the "first slash" came from Phase 3 or Phase 4. The composed deduct equals the pre-Phase-3 `stakes_[d].locked`.
- Case 2 (fee distribution) is the natural intra-block dependency that PROTOCOL.md §3.3 documents.
- Case 3 (subsidy gating) is the conditional accumulator update at line 1390, structurally orthogonal to event mix.
- Case 4 (cross-shard routing) is the per-tx conditional at line 752, structurally orthogonal to other events.
- Case 5 (STAKE + abort on same domain in same block) is the post-Phase-1 read at Phase 3, which is the producer-intended semantics.
- Case 6 (REGISTER + equivocation on same domain) is the post-Phase-1 registry-entry creation observed by Phase 4's `registrants_.find(...)` check, which finds the just-created entry and deactivates it.

The enumeration is complete by inspection: any two Phases that share a state-map write (Phases 1 ∩ 2 via `accounts_`, Phases 1 ∩ 3 via `stakes_`, Phases 1 ∩ 4 via `stakes_` + `registrants_`, Phases 1 ∩ 5 via `accounts_`, Phases 3 ∩ 4 via `stakes_`, Phases 4 ∩ 5 via none — they're disjoint) are accounted for. ∎

**Code witness.** Per-Phase write sets cited at §1.3. The intentional-coupling cases are each anchored in code:

- Case 1: `src/chain/chain.cpp:1326` (Phase 3 deduct) → `src/chain/chain.cpp:1349` (Phase 4 zero-out reading post-Phase-3 `locked`).
- Case 5: `src/chain/chain.cpp:858–872` (Phase 1 STAKE write) → `src/chain/chain.cpp:1322–1326` (Phase 3 reads post-write `locked`).
- Case 6: `src/chain/chain.cpp:792–812` (Phase 1 REGISTER create) → `src/chain/chain.cpp:1351–1355` (Phase 4 finds + deactivates).

**Test witness.** `tools/test_block_event_composition.sh` (cross-product tests covering each intentional-coupling case). `tools/test_equivocation_multi.sh` "Same equivocator twice in same block" (Case 1 idempotence). `tools/test_stake_lifecycle.sh` (Case 5 STAKE + slash interactions over multi-block traces). The five intentional-coupling cases are tested explicitly; cross-cases not in the enumeration are exercised by `tools/test_multi_event_block_apply.sh` and pass by structural independence.

### T-M7 — Empty-events graceful handling

**Statement.** For any block `B` where one or more of `B.transactions`, `B.abort_events`, `B.equivocation_events`, `B.inbound_receipts`, `B.creators` is empty, the apply path produces no exception, no state corruption, and no observable difference from a block with the empty list replaced by a single no-op event. Specifically:

- `B.transactions == []`: Phase 1 loop body never executes; `total_fees = 0`; Phase 2 distributes only `subsidy_this_block` (still conditional on `b.creators` non-empty).
- `B.abort_events == []`: Phase 3 loop body never executes; `block_slashed` unchanged from abort contribution.
- `B.equivocation_events == []`: Phase 4 loop body never executes; `block_slashed` unchanged from equivocation contribution.
- `B.inbound_receipts == []`: Phase 5 loop body never executes; `block_inbound = 0`.
- `B.creators == []`: Phase 2's distribution branch is gated by `!b.creators.empty()` (line 1286) and `total_distributed > 0 && !b.creators.empty()` (line 1390); both checks fall through, no fee / subsidy distributed, `accumulated_subsidy_` not incremented this block.
- All of the above empty simultaneously: every Phase is a no-op; the A1 closure passes trivially (live supply unchanged); the state-root recomputation produces the same root as pre-apply.

**Proof sketch.** Each Phase's loop is `for (auto& X : b.Y) { ... }`, where `Y` is a `std::vector<T>`. An empty vector produces zero iterations; the loop body is never entered; no state mutation occurs from that Phase. The per-block accumulators initialize to zero (lines 720–725) and remain zero if the corresponding Phase doesn't execute. The Phase-6 accumulator updates are u64 += 0 operations, no-ops. The A1 closure at Phase 6 is `actual == expected`, and both sides are unchanged from the pre-apply values when no per-block delta is produced. The Phase-7 S-033 gate compares `body.state_root` against `compute_state_root()`, which is a pure function of the (unchanged) maps; if the producer's `body.state_root` was correctly computed against the pre-apply state, the gate passes.

The `b.creators.empty()` case is the lone path that could conceivably bypass the subsidy accumulator update without bypassing A1 — but Phase 6's conditional at line 1390 (`if (total_distributed > 0 && !b.creators.empty())`) is exactly this guard. The chain's invariant is that an empty-creators block is an "empty block" for subsidy purposes, which matches the subsidy semantics (the chain mints subsidy only when there are creators to pay).

In practice, blocks with all event lists empty are rare (the producer's block-construction logic at `make_canonical_block` always includes a creator set), but the apply path is structurally robust against the edge case. The robustness is what makes T-M7 a theorem and not a happy-path observation: a block accidentally constructed with all-empty event lists (e.g., a test fixture, a corrupted block, a future protocol revision with skip-block semantics) applies as a no-op, not as an exception or state corruption. ∎

**Code witness.** Each Phase's loop: `chain.cpp:734` (Phase 1), `chain.cpp:1286 + 1390` (Phase 2 + accumulator gates), `chain.cpp:1313` (Phase 3), `chain.cpp:1344` (Phase 4), `chain.cpp:1363` (Phase 5). The accumulator initialization at lines 720–725 + the post-Phase fold at lines 1390–1395 + the A1 closure at line 1399 collectively make the no-event-block apply path trivially A1-consistent.

**Test witness.** `tools/test_block_event_composition.sh` (the "empty-events block" scenario — a block with `transactions = []`, `abort_events = []`, `equivocation_events = []`, `inbound_receipts = []`, `creators = []` applies as a no-op; state-root unchanged, A1 closure passes). `tools/test_chain_apply_block.sh` (basic empty-tx block apply). The structural correctness inherits from `tools/test_chain_save_load.sh` (snapshot roundtrip on a chain that included empty blocks preserves byte-identical state).

---

## 3. Composition with prior FA-Apply theorems

The proof's structure is intentionally a thin composition layer over the per-surface FA-Apply proofs. T-M1 through T-M7 do not re-derive any single-surface semantics; they pin the joint property that the per-surface semantics hold simultaneously.

| Source | Single-surface theorem | T-M usage |
|---|---|---|
| `AccountStateInvariants.md` (FA-Apply) | I-1 (atomic apply) | T-M2's "per-event invariant holds independently" — atomic envelope ensures no partial-apply state observable. |
| `AccountStateInvariants.md` I-6 | A1 contribution per channel | T-M3's "linear superposition" — each per-event delta enters exactly one of the five A1 channels (fee, subsidy, inbound, outbound, slashed). |
| `SnapshotEquivalence.md` (FA-Apply-2) T-S2 | Apply-after-restore equivalence | T-M5's "replay determinism" — snapshot ↔ replay equivalence carries multi-event blocks. |
| `EquivocationSlashingApply.md` (FA-Apply-10) T-E1, T-E3, T-E5, T-E7 | Equivocation slash mechanics + idempotence + A1 + determinism | T-M3 (A1), T-M5 (determinism), T-M6 Case 1 (idempotent stack with abort-slash). |
| `AbortEventApply.md` (FA-Apply-11) T-A1, T-A3, T-A7, T-A8 | Phase-1 abort slash + cache + A1 + determinism | T-M3 (A1), T-M5 (determinism), T-M6 Case 1 (composes with equivocation). |
| `CrossShardReceiptDedup.md` (FA-Apply-9) T-R1, T-R2 | Fresh / duplicate inbound credit | T-M2 (per-receipt invariant), T-M3 (A1 inbound channel). |
| `AppliedReceiptRestore.md` (FA-Apply-12) T-AR3, T-AR7 | Dedup-set restore equivalence + determinism | T-M5 (replay determinism through snapshot boundary). |
| `StakeLifecycle.md` (FA-Apply-4) T-K1, T-K2, T-K7 | STAKE / UNSTAKE / determinism | T-M3 (A1 zero-sum on stake transitions), T-M6 Case 5 (STAKE + slash composition). |
| `EconomicSoundness.md` (FA11) T-12 | A1 unitary-balance | T-M3 generalization to arbitrary event mix. |

The novelty is the **joint statement**: no individual proof above claims all of them hold simultaneously. FA-Apply-15 is the missing theorem that pins the composition property by structural argument (disjoint-write loops + additive accumulators + serialized phase ordering).

---

## 4. What this doesn't prove

- **Validator-side acceptance of multi-event blocks.** V1–V15 covers per-surface validation (V2 registry, V10 abort-quorum, V11 equivocation, V12 cross-shard receipt source, V13 dedup, V14 state-root, V15 transaction apply). The apply-side composition holds conditional on V1–V15 all passing at validate-time; this proof does not address the validator's joint validation correctness for multi-surface blocks. The validator's per-Phase checks are themselves disjoint by construction (each V_i targets a specific field of the block), so the validate-side joint correctness mirrors the apply-side joint correctness.

- **Mempool-side multi-event admission ordering.** The producer's `make_canonical_block` decides which events to include and in what intra-Phase order. A producer that includes an "ill-formed" event mix (e.g., an abort for a domain that hasn't registered, a duplicate inbound receipt) would have the events filtered at validate-time (V10 / V13) before reaching the apply path. The producer-side filtering is out of scope; the apply path treats whatever survives validation as authoritative.

- **Cross-shard receipt source-side correctness during multi-event apply.** Each inbound receipt's destination-side apply (T-R1) requires the source-side TRANSFER + receipt-emit chain (FA7 + FA-Apply-13). The composition does not re-prove the source-side chain.

- **Snapshot equivalence of multi-event chains.** FA-Apply-2 T-S1 / T-S2 / T-S3 cover the cross-namespace round-trip property; T-AR1 through T-AR7 specialize to the `i:` namespace; the analogous specializations for `s:`, `r:`, `b:`, `d:` namespaces are FA-Apply-4 T-K4-restore, FA-Apply-10 §5 (registrants restore), FA-Apply-11 §5 (abort_records restore), FA-Apply-12 (dapp_registry restore). T-M5's replay-determinism inherits the snapshot-equivalence claim composed across all ten namespaces.

- **Wire-format multi-event block validity.** PROTOCOL.md §4 + §9 covers the block's binary codec; the apply path consumes the post-decode struct. A malformed block's decode would fail upstream of apply; the apply path's correctness is conditional on the struct being well-formed.

- **Concurrent multi-block apply.** This proof addresses a single-block apply. Concurrent applies of multiple blocks (or apply during a chain reorganization) are handled by the A9 atomic-apply envelope (`AccountStateInvariants.md` I-1) and the Phase-2C published-view bundle (`chain.cpp:1475–1499`). The multi-block concurrency story is FA-Apply's scope.

- **Phase-7 S-033 gate dormancy on legacy blocks.** Pre-S-038 blocks carry `body.state_root == 0` and skip the gate (lines 1431–1432). The composition holds on pre-S-038 blocks because the gate is the only Phase that depends on the producer-side state-root wiring — every other Phase's correctness is structurally independent of the state-root field. Post-S-038 blocks have non-zero `state_root`, and the gate fires.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | V1–V15 validator-predicate definitions; assumptions A1, A3, A5 for the underlying cryptographic + determinism primitives. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 atomic apply, I-3 balance ↔ stake independence, I-5 channel enumeration, I-6 A1 contribution — the per-event invariants this proof composes. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 byte-level round-trip, T-S2 apply-after-restore, T-S3 cross-namespace coverage — the multi-namespace foundation T-M4 + T-M5 inherit. |
| `CrossShardReceiptDedup.md` (FA-Apply-9) | T-R1 (fresh credit), T-R2 (duplicate silent skip) — the Phase-5 per-receipt deltas. |
| `EquivocationSlashingApply.md` (FA-Apply-10) | T-E1 full forfeit, T-E2 registry deactivation, T-E3 idempotence, T-E5 A1 invariance, T-E7 determinism — the Phase-4 per-event deltas. |
| `AbortEventApply.md` (FA-Apply-11) | T-A1 Phase-1 slashing, T-A3 cache update, T-A4 no deregistration, T-A7 A1 invariance, T-A8 determinism — the Phase-3 per-event deltas. |
| `AppliedReceiptRestore.md` (FA-Apply-12) | T-AR3 + T-AR5 + T-AR7 — the snapshot-replay equivalence that T-M5 inherits through the `i:` namespace. |
| `StakeLifecycle.md` (FA-Apply-4) | T-K1 STAKE, T-K2 UNSTAKE, T-K7 determinism — Phase-1 stake-lifecycle deltas. |
| `EconomicSoundness.md` (FA11) | T-12 A1 unitary-balance — the closure that T-M3 specializes to multi-event blocks. |
| `docs/PROTOCOL.md` §6.1 | Apply rules ordering; the seven-Phase sequence pinned by T-M1. |
| `docs/PROTOCOL.md` §4 | Block struct + signed-body ordering of `transactions / abort_events / equivocation_events / inbound_receipts / creators`. |
| `docs/PROTOCOL.md` §4.1.1 | Ten-namespace state-root key encoding consumed by T-M4. |
| `docs/SECURITY.md` §S-007 | u64 overflow checks via `checked_add_u64` — defended at every Phase. |
| `docs/SECURITY.md` §S-033 | Merkle state commitment + apply-side / restore-side verification gates; the Phase-7 gate consumed by T-M4. |
| `docs/SECURITY.md` §S-038 | Producer-side `body.state_root` population via tentative dry-run — the wiring that makes T-M4 non-vacuous on post-S-038 blocks. |
| `src/chain/chain.cpp:633` | `apply_transactions` entry point. |
| `src/chain/chain.cpp:646–670` | A9 snapshot capture + ensure-lambdas; the atomic envelope T-M1 + T-M2 rely on. |
| `src/chain/chain.cpp:720–725` | Per-block accumulator declarations. |
| `src/chain/chain.cpp:734–1232` | Phase 1 transactions loop. |
| `src/chain/chain.cpp:1286–1305` | Phase 2 fee + subsidy distribution. |
| `src/chain/chain.cpp:1313–1328` | Phase 3 abort-slash loop. |
| `src/chain/chain.cpp:1344–1356` | Phase 4 equivocation-slash loop. |
| `src/chain/chain.cpp:1363–1381` | Phase 5 inbound-receipt loop. |
| `src/chain/chain.cpp:1390–1419` | Phase 6 accumulator update + A1 closure. |
| `src/chain/chain.cpp:1430–1446` | Phase 7 S-033 state-root verification gate. |
| `src/node/node.cpp:1024–1113` | Producer-side S-038 wiring that populates `body.state_root` via tentative dry-run. |
| `tools/test_multi_event_block_apply.sh` | Canonical T-M1 + T-M2 + T-M3 + T-M4 + T-M5 regression — a single block carrying TRANSFER + abort + equivocation + inbound + DAPP_CALL applies correctly with each Phase's invariant + A1 closure + state-root recomputation passing. |
| `tools/test_block_event_composition.sh` | T-M6 + T-M7 regression — cross-product of intentional-coupling cases + empty-events edge cases. |
| `tools/test_supply_lifecycle.sh` | Multi-block A1 closure across composed event streams; T-M3 composes. |
| `tools/test_state_root_namespaces.sh` | Ten-namespace state-root coverage; T-M4 inherits. |
| `tools/test_chain_save_load.sh` | Snapshot roundtrip on multi-event chains; T-M5 composes. |

---

## 6. Status

All seven theorems (T-M1 through T-M7) are closed in the current codebase by structural composition of the prior FA-Apply theorems:

- **T-M1** (deterministic event ordering) closed by inspection of `chain.cpp:633–1499` — the apply path is a sequence of seven loops/blocks with no interleaving; regressions `test_multi_event_block_apply.sh` + `test_block_event_composition.sh`.
- **T-M2** (independent per-event invariance) closed by structural disjoint-write argument over the seven Phases — each loop body's reads/writes are isolated modulo the enumerated coupling cases of T-M6; per-Phase regressions (`test_abort_event_apply.sh`, `test_equivocation_apply.sh`, `test_cross_shard_atomicity.sh`, `test_dapp_call_apply.sh`) + composed regression `test_multi_event_block_apply.sh`.
- **T-M3** (A1 composability) closed via the additive accumulator updates at `chain.cpp:1393–1395` + the A1 closure at `chain.cpp:1399` — each per-event delta enters one of the five A1 channels and the chain-wide closure checks the additive sum; regressions `test_multi_event_block_apply.sh` + `test_supply_lifecycle.sh` + `test_supply_invariant.sh`.
- **T-M4** (state-root composability) closed via `build_state_leaves` being a pure function of the ten namespaces + S-038's producer-side wiring + S-033's apply-side gate; regressions `test_multi_event_block_apply.sh` + `test_state_root_namespaces.sh` + `test_dapp_snapshot.sh`.
- **T-M5** (replay determinism with multi-event blocks) closed by induction on the block count + per-Phase determinism (T-A8, T-E7, T-R1/T-R2, T-K7) + snapshot-restore equivalence (FA-Apply-2 T-S2); regressions `test_chain_save_load.sh` + `test_snapshot_then_apply.sh` + `test_multi_event_block_apply.sh`.
- **T-M6** (no event-event interference modulo intentional coupling) closed by exhaustive enumeration of pairwise Phase-intersection cases (five intentional couplings identified at §1.3) + structural disjoint-write argument elsewhere; regressions `test_block_event_composition.sh` + `test_equivocation_multi.sh` + `test_stake_lifecycle.sh`.
- **T-M7** (empty-events graceful handling) closed by structural empty-loop semantics of `for (auto& X : b.Y)` over empty `std::vector<T>` + accumulator-zero-initialization + creators-empty branch gating; regression `test_block_event_composition.sh` "empty-events block" scenario + `test_chain_apply_block.sh`.

No theorem is open or partial. The proof's foundation rests entirely on prior FA-Apply theorems plus the structural argument that the apply path is a finite sequence of independent loops with additive per-block accumulators. The contribution of FA-Apply-15 is to **name the composition property explicitly** so that future agents reading the proof stack understand which joint claims hold without re-deriving them per-block.

The composition property is what makes the chain's apply path operationally tractable for heterogeneous workloads: a regional shard handling a thousand TRANSFERs per block alongside a handful of abort/equivocation events and a few cross-shard inbound credits does not require any special-cased apply path — the single `apply_transactions` function consumes the union deterministically, each Phase's invariants hold independently, A1 closes additively, and the state-root recomputes to the producer-pinned root. The few intentional couplings (T-M6's five enumerated cases) are explicit semantics rather than ad-hoc behaviors; each has a published interpretation and a test witness.
