# FA-Apply — Equivocation slashing apply-side mechanics

This document formalizes the apply-layer mechanics of equivocation slashing — the moment the chain consumes an `EquivocationEvent` baked into a finalized block, forfeits the equivocator's entire staked balance, and deactivates the equivocator's registry entry effective on the next block. The mechanism is two paired writes inside a single loop at `src/chain/chain.cpp:1344–1356`: a `stakes_[ev.equivocator].locked := 0` write whose pre-write value is added to the per-block `block_slashed` accumulator (line 1348), and a `registrants_[ev.equivocator].inactive_from := b.index + 1` write that pulls the equivocator out of the eligible-creator pool the very next block (line 1354). The two writes are independent — either map may be absent, and the loop body guards both with a `find(...) != end()` check — so the apply path is robust against ghost equivocators (events naming a domain that never registered) and against same-block double-events (a second event for the same domain re-runs the loop body with `locked == 0` already, contributing nothing).

The proof is mechanical: the apply branch is 13 lines, the per-block `block_slashed` accumulator folds into chain-wide `accumulated_slashed_` at apply-tail (`chain.cpp:1395`), and the A1 unitary-supply invariant at `chain.cpp:1399` consumes `accumulated_slashed_` as one of the five terms in `expected_total`. The strength is consolidation: FA6 (`EquivocationSlashing.md`) proves slashing **soundness** (an honest validator is never named as the equivocator in a finalized event, under EUF-CMA); FA-Apply-10 drills into the apply-side **mechanics** that fire conditional on FA6's soundness guarantee. FA6's argument depends on the slash being applied correctly when it does fire; the present proof closes that dependency.

**Companion documents:** `Preliminaries.md` (F0) for notation, the V11 equivocation-proof validator predicate, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6, especially I-3 (balance ↔ stake independence: slashing consumes `stakes_[d].locked` without crossing into `accounts_[d].balance`) and I-6 (A1 closure); `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot ↔ replay equivalence that carries the post-slash `stakes_[d]` (locked = 0) + `registrants_[d]` (inactive_from = h+1) + `accumulated_slashed_` triple across snapshot boundaries; `StakeLifecycle.md` (FA-Apply-4) for the three-state stake machine — equivocation-slash is the `staked-active → unstaked` (and `staked-pending-unlock → unstaked`) transition from §1.2 — and for the slashing-window claim (§4) that the deferred-unlock window is the slashing-evidence window; `CrossShardReceiptDedup.md` (FA-Apply-9) for the structural template of an apply-side primitive whose semantics survive snapshot bootstrap; `EquivocationSlashing.md` (FA6) for slashing **soundness** — the present proof's mechanics fire only when FA6's V11 + EUF-CMA chain has authorized the slash.

---

## 1. Setup

### 1.1 The `EquivocationEvent` struct

Per `include/determ/chain/block.hpp:256–279`:

```cpp
struct EquivocationEvent {
    std::string equivocator;          // domain whose key signed both digests
    uint64_t    block_index{0};       // height at which equivocation occurred
    Hash        digest_a{};
    Signature   sig_a{};
    Hash        digest_b{};
    Signature   sig_b{};
    uint32_t    shard_id{0};
    uint64_t    beacon_anchor_height{0};
    // ...
};
```

The `equivocator` field names the offending domain. V11 (Preliminaries §5) requires `digest_a ≠ digest_b` and that both signatures verify under the equivocator's registered Ed25519 public key. The cross-chain fields (`shard_id`, `beacon_anchor_height`) are forensic — they route the slash through the beacon in cross-shard mode (FA6 Corollary T-6.1) but do not affect the apply-side mechanics, which key on `ev.equivocator` only.

### 1.2 The apply branch

Per `src/chain/chain.cpp:1344–1356`:

```cpp
for (auto& ev : b.equivocation_events) {
    auto sit = stakes_.find(ev.equivocator);
    if (sit != stakes_.end()) {
        __ensure_stakes();
        block_slashed     += sit->second.locked;  // A1: full forfeit
        sit->second.locked = 0;
    }
    auto rit = registrants_.find(ev.equivocator);
    if (rit != registrants_.end()) {
        __ensure_registrants();
        rit->second.inactive_from = b.index + 1;
    }
}
```

Three structural properties of the branch:

1. **Dual mechanism.** A single equivocation triggers TWO writes: stake forfeiture (lines 1346–1350) AND registry deactivation (lines 1351–1355). Either may be a no-op if the corresponding map entry is absent. The dual mechanism unifies STAKE_INCLUSION mode (where the stake-zeroing is the primary disincentive) and DOMAIN_INCLUSION mode (where stake is already 0 and the registry deactivation is what actually removes the offender from selection).
2. **Independent guards.** The `sit != stakes_.end()` and `rit != registrants_.end()` checks are independent. A domain that has unstaked but is still registered will have its registry deactivated without a stake write (the stake-guard fails). A domain that staked but never registered (an impossible state on an honest chain — STAKE requires REGISTER per `chain.cpp:807–811` — but defensively handled) would have its stake forfeited without a registry write. The all-paths-defensive design is what makes T-E4 (ghost-equivocator robustness) hold without source-side changes.
3. **`block_slashed` accumulation.** The line-1348 `block_slashed += sit->second.locked` reads the pre-write value of the locked stake, so a subsequent event for the same domain (now with `locked == 0`) contributes zero. This is what makes T-E3 (idempotent re-apply within a block) hold by construction.

### 1.3 The `block_slashed` → `accumulated_slashed_` accumulator

Per `chain.cpp:725`:

```cpp
uint64_t block_slashed  = 0;   // suspension + equivocation forfeit
```

`block_slashed` is a per-block u64 accumulator declared at the top of `apply_transactions`. It captures both suspension-slash deductions (lines 1313–1328, FA6 not directly; covered by `StakeLifecycle.md` §4.1) and equivocation forfeitures (lines 1344–1356, this proof). At apply-tail per `chain.cpp:1395`:

```cpp
accumulated_slashed_  += block_slashed;
```

the per-block accumulator folds into the chain-wide `accumulated_slashed_` counter. The A1 closure at `chain.cpp:1397–1419` then consumes `accumulated_slashed_` as one of the five terms in `expected_total = genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ - accumulated_slashed_ - accumulated_outbound_` and asserts `live_total_supply() == expected_total`. Any equivocation-slash that produced an off-by-one accumulator update would surface here as a thrown `runtime_error` with the per-field delta diagnostic.

---

## 2. Theorems

### T-E1 — Full stake forfeiture

**Statement.** For every block `B` at height `b.index` containing an `EquivocationEvent ev` with `ev.equivocator == d` and a chain state where `stakes_[d]` exists with `stakes_[d].locked == L` for some `L ≥ 0`, the apply produces exactly the deltas (from the equivocation branch alone):

```
Δstakes_[d].locked        = −L                (locked → 0)
Δblock_slashed            = +L
→ Δaccumulated_slashed_   = +L                (after apply-tail fold)
```

with no mutation to `stakes_[d].unlock_height`, `accounts_[d].balance`, or any other field outside the registry-deactivation path covered by T-E2. The forfeit is **entire**: regardless of `L`'s value (including `L == 0`), the post-apply state has `stakes_[d].locked == 0`.

*Proof sketch.* By inspection of `chain.cpp:1344–1350`. The loop iteration on `ev` enters the body. `stakes_.find(ev.equivocator)` returns a valid iterator under hypothesis. `block_slashed += sit->second.locked` reads `L` and adds it to the accumulator; this single read-then-write is atomic because the iterator `sit` is not invalidated between the two operations (no `stakes_` mutation occurs between line 1348 and line 1349 inside the loop body). `sit->second.locked = 0` writes the zero, completing the forfeiture. No other field on `stakes_[d]` (specifically `unlock_height`) is touched — the staked-pending-unlock window's scheduled return is voided by the zero-locked rather than by an explicit unlock-height reset (FA-Apply-4 T-K6's structural mechanism continues to fire: any subsequent UNSTAKE on `d` sees `locked < amount` for any `amount > 0` and falls into the T-K4 refund branch, never re-crediting the forfeited stake). The apply-tail fold at line 1395 then advances `accumulated_slashed_` by `block_slashed`, including the `+L` contribution from this event. ∎

**Code witness.** `src/chain/chain.cpp:1344–1350` (the forfeit half of the dual-mechanism loop body); `src/chain/chain.cpp:725` (`block_slashed` declaration); `src/chain/chain.cpp:1395` (apply-tail fold into `accumulated_slashed_`); `include/determ/chain/chain.hpp:23–30` (`StakeEntry` struct).

**Test witness.** `tools/test_equivocation_apply.sh` (`determ test-equivocation-apply`) — the "Full stake forfeiture" block asserts `stake → 0` after the equivocation event applies. The companion `tools/test_equivocation_slashing.sh` exercises the end-to-end gossip + V11 + apply path through a 3-node cluster; this in-process test pins the apply semantics in <1s.

### T-E2 — Registry deactivation

**Statement.** For every block `B` at height `b.index` containing an `EquivocationEvent ev` with `ev.equivocator == d` and a chain state where `registrants_[d]` exists with any prior `inactive_from` value (sentinel `UINT64_MAX` or a finite value from a prior DEREGISTER), the apply produces exactly:

```
Δregistrants_[d].inactive_from = (b.index + 1) − prior_inactive_from
```

i.e., `inactive_from` is unconditionally set to `b.index + 1`, irrespective of its prior value. No other field on `registrants_[d]` is touched (`ed_pub`, `registered_at`, `active_from`, `region` all preserved).

*Proof sketch.* By inspection of `chain.cpp:1351–1355`. The `registrants_.find(ev.equivocator)` lookup returns a valid iterator under hypothesis. Line 1354 writes `rit->second.inactive_from = b.index + 1` unconditionally — there is no read-modify-write guard against the prior value. The post-apply value is the literal `b.index + 1`, which makes the equivocator ineligible for committee selection at every height `h' ≥ b.index + 1` (V2 of F0 + `eligible_in_region` filter at `registry.cpp::build_from_chain`'s eligibility predicate `active_from <= at_index < inactive_from`).

The "irrespective of prior value" property is intentional: if the equivocator had previously DEREGISTERed and the prior `inactive_from` is some `b.index + δ_reg > b.index + 1`, the equivocation override advances the deactivation to the immediate next block, closing the registration-grace window during which the offender might otherwise have continued participating. If a future-effective DEREGISTER had set `inactive_from = b.index + δ_reg` with `δ_reg ≤ REGISTRATION_DELAY_WINDOW` (~10 blocks), the equivocation override at line 1354 brings it forward by `δ_reg − 1` blocks. The override is one-way: the equivocator cannot re-activate by re-REGISTERing the same domain (REGISTER's apply branch at `chain.cpp:792–812` checks `registrants_.contains(d)` and skips on hit; the existing-but-deactivated entry is what blocks re-entry). The offender must register a fresh domain to participate again. ∎

**Code witness.** `src/chain/chain.cpp:1351–1355` (the registry-deactivation half); `include/determ/chain/chain.hpp:32–43` (`RegistryEntry` struct); `src/chain/chain.cpp:792–812` (REGISTER's contains-check that prevents re-activation of the deactivated entry); `src/node/registry.cpp::build_from_chain` (eligibility predicate).

**Test witness.** `tools/test_equivocation_apply.sh` "Registry deactivation" block — 2 assertions: baseline `inactive_from == UINT64_MAX` (sentinel pre-equivocation), post-apply `inactive_from == b.index + 1`. `tools/test_equivocation_multi.sh` "Pre-deactivated equivocator" scenario asserts the override: a domain whose prior `inactive_from` was a finite future value gets its `inactive_from` reset to `b.index + 1`.

### T-E3 — Idempotent re-apply

**Statement.** For any block `B` containing two `EquivocationEvent`s `ev_1, ev_2 ∈ B.equivocation_events` with `ev_1.equivocator == ev_2.equivocator == d`, OR for two sequential blocks `B_1, B_2` each containing an `EquivocationEvent` for `d`, the cumulative chain-wide `accumulated_slashed_` advances by exactly `stakes_[d].locked` evaluated at the moment of the **first** event's apply iteration. A second event for the same domain — whether intra-block or cross-block — contributes zero to `accumulated_slashed_`. The post-apply state after the second event is byte-identical to the post-apply state after the first event (modulo any other concurrent mutations on `accounts_` / `stakes_` / `registrants_` for other domains).

*Proof sketch.* Intra-block case: the loop at `chain.cpp:1344` iterates over `b.equivocation_events` in serialized order. The first iteration on `ev_1` enters the stake-forfeit branch (T-E1) and writes `sit->second.locked = 0` — the post-iteration value. The second iteration on `ev_2` re-runs `stakes_.find(ev.equivocator)`, which returns the same iterator (the map entry was not erased), so `sit != stakes_.end()` holds. Line 1348 reads `sit->second.locked == 0` (set by the first iteration) and adds zero to `block_slashed`. Line 1349 writes zero to the locked field (a no-op idempotent write). The registry half (lines 1351–1355) writes `inactive_from = b.index + 1` on both iterations — a deterministic idempotent write to the same value. The net `block_slashed` contribution from the pair is `L + 0 == L`, not `2L`. The apply-tail fold at line 1395 advances `accumulated_slashed_` by exactly `L`.

Cross-block case: after `B_1` applies, the chain has `stakes_[d].locked == 0` and `accumulated_slashed_ += L_1` (where `L_1` was the pre-`B_1` locked value). When `B_2` applies, the loop iteration on `ev_2` finds `stakes_[d].locked == 0` and contributes zero to `B_2`'s `block_slashed`. The chain-wide `accumulated_slashed_` advances by zero from this event. The registry's `inactive_from = b.index + 1` write at `B_2` overrides any prior finite value, but since `B_1` already set it to `b.index_1 + 1 < b.index_2 + 1`, the override moves the deactivation forward (a strictly increasing sequence under monotone block-index ordering — see Discussion §4 for the inactive_from monotonicity claim).

The construction is robust against legitimate evidence reaching the chain in different blocks (an attacker who equivocated at height H may be denounced at H+5 in one shard and H+50 in another; the apply path treats the second denunciation as a no-op on stake, with the registry deactivation harmlessly re-asserted). ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (the loop body whose read-then-write pattern on `locked` makes the second iteration contribute zero); `src/chain/chain.cpp:725` (`block_slashed` accumulator); the absence of any side-channel that re-credits the forfeited stake (no UNSTAKE post-slash can re-credit because T-K4's refund-branch fires on `locked < amount`).

**Test witness.** `tools/test_equivocation_multi.sh` "Same equivocator twice in same block" scenario — 2 assertions: first equivocation forfeits the full stake (`accumulated_slashed += L`), second equivocation no-op (`accumulated_slashed` unchanged). The "Pre-deactivated equivocator" scenario covers the cross-block analogue.

### T-E4 — Ghost-equivocator robustness

**Statement.** For every block `B` containing an `EquivocationEvent ev` with `ev.equivocator == d` and a chain state where `stakes_[d]` does NOT exist AND/OR `registrants_[d]` does NOT exist, the apply iteration on `ev` produces zero state mutation on the absent side(s) and proceeds without throwing. Specifically:

- If `stakes_[d]` is absent: the `sit != stakes_.end()` guard fails at line 1346, the stake-half body is skipped, `block_slashed` is unchanged.
- If `registrants_[d]` is absent: the `rit != registrants_.end()` guard fails at line 1352, the registry-half body is skipped, no new registry entry is created.
- If both are absent: the event is a complete no-op on the equivocator's state, but the apply continues normally (no exception, no rollback).

The chain-wide A1 invariant is preserved (a no-op forfeiture contributes zero to `accumulated_slashed_`, so `expected_total` is unchanged from this event).

*Proof sketch.* By inspection of `chain.cpp:1344–1356`. The two guards at lines 1346 and 1352 are independent `if`s, not an `else if` chain. Each `find(...)` is a pure read on its respective map and does not implicitly create an entry (unlike `operator[]`'s default-construction semantics, which the apply path explicitly avoids for both maps — the `__ensure_stakes()` / `__ensure_registrants()` calls happen inside the guard-passed branch, not before the find). Under the hypothesis "stakes_[d] absent," the find returns `stakes_.end()`, the guard at line 1346 evaluates false, lines 1347–1349 are skipped. The registry half is structurally identical at lines 1352–1355.

The robustness matters in practice for two scenarios: (a) **DOMAIN_INCLUSION mode** where validators register without staking (`min_stake_ == 0`), so `registrants_[d]` exists but `stakes_[d]` may not — the apply path deactivates the registry without a stake write, consistent with the dual mechanism's design. (b) **Post-UNSTAKE equivocation** where an offender unstaked all their value before evidence surfaced, leaving `stakes_[d].locked == 0` (or `stakes_` not containing `d` if the UNSTAKE drained the entry — though in practice `stakes_[d]` is kept around with `locked == 0` because the UNSTAKE branch at `chain.cpp:889–893` debits `locked` without erasing the map entry). Either way, the slash contributes zero to A1 but the registry deactivation still fires, preserving the FA6 H2-soundness guarantee that an equivocator cannot re-participate.

The third case — a forensically-constructed event naming a domain that **never existed on the chain** — is also handled: both find()s return end(), both halves of the loop body skip, the event is a complete no-op. V11 (`check_equivocation_events` at `validator.cpp`) is responsible for rejecting such events at validate-time (the equivocator's registered Ed25519 key must be looked up to verify the two signatures; a non-existent domain would fail this lookup). The apply-side robustness is the belt-and-suspenders defense against any path that slips past the validator. ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (the dual independent guards); `src/node/validator.cpp::check_equivocation_events` (V11 upstream gate that should reject ghost-equivocators by pubkey-lookup failure).

**Test witness.** `tools/test_equivocation_apply.sh` "Robustness on ghost equivocator" block — 2 assertions: apply succeeds without crashing on an event for a never-registered domain; other domains' state is unaffected. `tools/test_equivocation_multi.sh` "Equivocator with NO stake" scenario covers the DOMAIN_INCLUSION variant (registry deactivated, no stake to forfeit) — the no-stake case is the "absent stake / present registry" half of the ghost-equivocator robustness claim.

### T-E5 — A1 invariance under slashing

**Statement.** Across any finite sequence of blocks `B_1, B_2, ..., B_n` applied to a Chain `C`, including blocks containing zero or more `EquivocationEvent`s, the A1 unitary-supply invariant `live_total_supply() == expected_total()` holds at every apply-tail (`chain.cpp:1399`). Specifically, for an equivocation event with pre-event `stakes_[d].locked == L`:

```
Δlive_total_supply       = −L         (locked stake leaves Σ stakes_)
Δexpected_total          = −L         (accumulated_slashed advances by L,
                                       which enters expected as a subtraction)
```

so the two sides advance by the same delta; the equality is preserved. Total supply moves by exactly `−L` (the forfeited stake is removed from the live circulating + staked total — it is not redistributed to anyone, not even creators, not even the chain itself; it is **burned** into `accumulated_slashed_`).

*Proof sketch.* The `live_total_supply()` helper (`chain.cpp:1797` approximate location) sums `accounts_[d].balance + stakes_[d].locked` across all `d`. Pre-event, `d`'s stake contributes `+L` to this sum. Post-event (T-E1), `d`'s stake contributes `+0`, so `live_total_supply` decreased by `L`. The companion side: `expected_total()` is `genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ - accumulated_slashed_ - accumulated_outbound_`. The event contributes `+L` to `block_slashed` (T-E1), which folds into `accumulated_slashed_` at apply-tail (line 1395). Since `accumulated_slashed_` enters `expected_total` as a subtraction, `Δexpected_total = −L`. Both sides advance by `−L`, equality preserved.

The "burned" character is critical: there is no `accounts_[creators[i]].balance += L` write anywhere in the equivocation branch, and the suspension-slash + equivocation-slash combined `block_slashed` is NOT included in the per-block creator-fee distribution (`chain.cpp:1286–1305` distributes `total_fees + subsidy_this_block`, not slashed). The forfeit is unrecoverable. This is the design — equivocation is a Byzantine offense whose disincentive must be the actual destruction of stake value, not a redistribution that another colluding party could capture.

The A1 closure at `chain.cpp:1399` catches any apply-path bug that would break the invariance — e.g., a hypothetical regression that forfeited stake without incrementing `block_slashed`, or one that incremented `accumulated_slashed_` without zeroing `locked`. Both would surface as a `runtime_error` with the per-field delta diagnostic at lines 1405–1418, blocking the block at apply-time and rolling back to the pre-apply state via the A9 atomic-apply machinery. ∎

**Code witness.** `src/chain/chain.cpp:1348–1349` (the paired `block_slashed += L` / `locked = 0` writes that preserve the A1 ledger arithmetic); `src/chain/chain.cpp:1395` (apply-tail fold); `src/chain/chain.cpp:1397–1419` (A1 closure assertion + rollback diagnostic); `src/chain/chain.cpp:1286–1305` (creator distribution — verified to NOT include `block_slashed`).

**Test witness.** `tools/test_equivocation_apply.sh` "A1 supply invariant" block — 3 assertions: `accumulated_slashed` bumped by exactly the full stake amount; `live_total_supply` decreases by exactly the forfeit; `expected_total == live_total_supply` after the forfeit (the A1 closure passes). `tools/test_supply_invariant.sh` cross-checks the A1 closure across composed block sequences including equivocation events.

### T-E6 — Cross-block accumulation

**Statement.** Across any finite sequence of blocks `B_1, B_2, ..., B_n` applied to a Chain `C`, with each block `B_i` containing zero or more `EquivocationEvent`s, the chain-wide `accumulated_slashed_` advances by exactly:

```
Σ {pre_event_locked(d, B_i) : i ∈ {1, ..., n},
                              ev ∈ B_i.equivocation_events,
                              d = ev.equivocator,
                              stakes_[d].locked > 0 at the moment ev applies}
```

i.e., the total of FIRST-time forfeitures across the sequence. Each domain's stake contributes at most once across the entire sequence (the first equivocation against it zeros the stake; all subsequent equivocations against the same domain contribute zero per T-E3). Multiple distinct equivocators each contribute their own forfeit independently (T-E7's independence claim).

*Proof sketch.* By induction on the block index. Base case: at genesis, `accumulated_slashed_ == 0` (per `chain.cpp:713`) and no equivocation events have applied; the equality holds vacuously. Inductive step: assume the equality after `B_1..B_k` (the chain-wide counter equals the sum of first-time forfeitures across `B_1..B_k`). Apply `B_{k+1}`. The equivocation loop at `chain.cpp:1344–1356` iterates over `B_{k+1}.equivocation_events`. For each event `ev`:

- If `stakes_[ev.equivocator].locked > 0` at iteration start (first-time forfeiture for this domain in the cumulative sequence): T-E1 fires, adding `L` to `block_slashed`.
- If `stakes_[ev.equivocator].locked == 0` at iteration start (either no stake to begin with — T-E4 — or a prior forfeiture already zeroed it — T-E3): the iteration adds zero to `block_slashed`.
- If `stakes_[ev.equivocator]` is absent: T-E4 — zero contribution.

The per-block `block_slashed` is then folded into `accumulated_slashed_` at apply-tail (line 1395). The induction hypothesis combined with this step gives the equality for `B_1..B_{k+1}`.

The independence claim — multiple distinct equivocators in the same block each contribute independently — follows from T-E7. Each event's stake-forfeit and registry-write are keyed by `ev.equivocator`; distinct equivocators access distinct `stakes_[d_1]`, `stakes_[d_2]` entries with no cross-key interference (the `std::map::find` + `std::map::operator->second` semantics are per-key isolated; same argument as FA-Apply-4 T-K7). ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (per-event accumulation logic); `src/chain/chain.cpp:1395` (block-tail fold); `src/chain/chain.cpp:713` (genesis-initialization `accumulated_slashed_ = 0`).

**Test witness.** `tools/test_equivocation_multi.sh` "Two distinct equivocators in same block" scenario — assertions confirm both forfeitures land independently in `accumulated_slashed_` (the chain-wide counter advances by `L_1 + L_2`). The "Determinism" scenario at the tail of `test_equivocation_multi.sh` exercises the same property across two chains seeing the same multi-equivocation sequence. `tools/test_equivocation_slashing.sh` exercises the multi-block accumulation across a network-level scenario.

### T-E7 — Deterministic apply

**Statement.** For any two Chain instances `C₁` and `C₂` with `C₁ ≡_S C₂` (per FA-Apply-2 §1.2 state-equivalence), and any block `B` containing equivocation events, the apply results satisfy `apply_transactions(C₁, B) ≡_S apply_transactions(C₂, B)`. In particular: the final `stakes_[d].locked` values coincide for every `d` named in `B.equivocation_events`, the final `registrants_[d].inactive_from` values coincide, the final `accumulated_slashed_` counters coincide, and the final `compute_state_root` values coincide byte-identically.

*Proof sketch.* This is the apply-after-restore equivalence (FA-Apply-2 T-S2) specialized to the equivocation-slash branch. The argument has three components:

- **Per-event determinism.** Each loop iteration reads only `stakes_[ev.equivocator]` and `registrants_[ev.equivocator]`, and writes only `stakes_[ev.equivocator].locked` and `registrants_[ev.equivocator].inactive_from`. Under hypothesis `C₁ ≡_S C₂`, both reads return the same values on both sides, so both writes produce the same post-state.
- **Event-order determinism.** The loop iterates over `b.equivocation_events` in serialized order, which is consensus-pinned (the block's `equivocation_events` vector is part of the block's signed body — see PROTOCOL.md §4 + V11). Identical serialized order → identical iteration sequence → identical cumulative writes on both sides.
- **Map iteration determinism.** The `stakes_` and `registrants_` maps are `std::map` (red-black tree, sorted-key invariant); subsequent iteration for state-root construction (`build_state_leaves` at `chain.cpp:331–341` for the `s:` and `r:` namespaces) is deterministic across implementations because the tree's structural invariant pins the iteration order to the key's `<` ordering.

The composition of these three components: equivocation-slash apply is a pure function of `(C, B)`, with no system-clock, no RNG, no thread-scheduling dependency. Two chains in equivalent states applying the same block produce equivalent post-states. The state-root equivalence then follows from `compute_state_root` being a deterministic function of the maps. ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (deterministic loop body); `src/chain/chain.cpp:331–341` (`s:` + `r:` namespace state-root contribution that surfaces any non-determinism as a state-root divergence).

**Test witness.** `tools/test_equivocation_apply.sh` "Determinism" assertion — two chains seeing the same equivocation event produce the same `state_root`. `tools/test_equivocation_multi.sh` "Determinism" assertion across the multi-equivocation surface. `tools/test_state_root_namespaces.sh` cross-checks the `s:` and `r:` namespaces as part of the 10-namespace state-root composition.

---

## 3. Slashing vs DEREGISTER

Equivocation slashing and DEREGISTER are the two paths that deactivate a registered validator. They share the registry-mutation surface — both write `registrants_[d].inactive_from` to a finite value — but differ structurally on three dimensions:

| Dimension | Equivocation slash (this proof) | DEREGISTER (FA-Apply-4 T-K3) |
|---|---|---|
| **Stake disposition** | Immediate full forfeit: `stakes_[d].locked := 0`, value burned into `accumulated_slashed_`. | Preserved: `stakes_[d].locked` unchanged, value remains locked until UNSTAKE post-unlock_height. |
| **Deactivation timing** | Immediate: `inactive_from := b.index + 1` (effective next block, irrespective of prior `inactive_from`). | Deferred: `inactive_from := b.index + derive_delay(b.cumulative_rand, tx.hash)` for `δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]` (~10 blocks). |
| **Re-activation path** | Closed: the deactivated entry blocks REGISTER from re-creating the same domain (registrants_.contains check at `chain.cpp:792–812`); offender must register a fresh domain. | Open: after `UNSTAKE_DELAY` blocks (~1000), the offender may REGISTER the same domain anew (REGISTER's contains check is satisfied if the old entry has been removed, though in current code the entry persists indefinitely — see Discussion §4). |
| **A1 impact** | Negative: total supply decreases by the forfeited stake (T-E5). | Neutral: total supply unchanged at DEREGISTER (only `tx.fee` enters `total_fees`, which is intra-supply per FA11). |
| **Validator initiates** | No — equivocation evidence is gossipped + V11-validated by peers, the offender has no control. | Yes — DEREGISTER is a tx the validator signs and broadcasts themselves. |
| **Trigger event** | Cryptographic: V11 verifies two distinct signatures over distinct digests under the same registered key (FA6 soundness — `≤ 2⁻¹²⁸` false-positive bound per attempt). | Voluntary: the validator submits a DEREGISTER tx with their own signature. |
| **Slashing window** | N/A — the slash IS the punishment. | The `[inactive_from, unlock_height)` tail (~1000 blocks) is the slashing-evidence window: an equivocation from before DEREGISTER, surfacing during this window, still slashes the pending-unlock locked stake (StakeLifecycle.md §4). |

The asymmetric stake disposition is the central economic distinction. DEREGISTER is the orderly-exit path — the validator gives notice, the chain holds their stake hostage for `UNSTAKE_DELAY` blocks during which evidence of prior bad behavior can still surface and consume the stake, and then the stake returns to balance via UNSTAKE. Equivocation is the disorderly-exit path — the chain has detected a deliberate Byzantine offense and immediately destroys the stake without ceremony. The two paths share the registry mutation only because both produce "no longer in the eligible pool"; they diverge sharply on what happens to value.

**Interaction.** A validator who DEREGISTERs at height `h` enters the `staked-pending-unlock` state (StakeLifecycle.md §1.2). During the `[h+1, h+δ_reg+UNSTAKE_DELAY)` window, an `EquivocationEvent` for the same domain (perhaps for evidence of earlier misbehavior) consumes the pending-unlock stake via T-E1, producing `stakes_[d].locked = 0` and overriding `inactive_from` from the DEREGISTER's scheduled value to `b.index + 1` per T-E2. The override is one-way: post-slash, the operator's stake is gone and the registry is permanently closed. A subsequent UNSTAKE during this window falls into the T-K4 refund branch (locked is now 0, fails the `locked >= amount` check) — the operator pays the UNSTAKE fee and gets it refunded but recovers no stake. The fee-refund convention (StakeLifecycle.md §3) protects the honest user who didn't know the equivocation evidence was about to surface; an attacker who slashed-then-spammed UNSTAKE retries gains nothing because each attempt only consumes a nonce slot.

**Validator-mode independence.** Both paths function in both STAKE_INCLUSION and DOMAIN_INCLUSION modes. In DOMAIN_INCLUSION (`min_stake_ == 0`), the stake-forfeit branch is a no-op on the `accumulated_slashed_` counter (no stake to forfeit), but the registry-deactivation branch still removes the offender from the eligible pool. This is the design point that makes the dual mechanism unifying: regardless of which inclusion mode the chain runs, equivocation produces a permanent removal, and DEREGISTER produces a deferred orderly exit.

---

## 4. Discussion

### 4.1 `inactive_from` monotonicity claim

Across the lifetime of a registered domain `d`, the sequence of writes to `registrants_[d].inactive_from` follows the discipline:

1. **Initial state** at REGISTER: `inactive_from := UINT64_MAX` (sentinel, per `chain.cpp:792–812`).
2. **DEREGISTER write**: `inactive_from := b.index + δ_reg` for `δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]` — strictly less than UINT64_MAX.
3. **Equivocation-slash write**: `inactive_from := b.index + 1` — strictly less than the DEREGISTER-scheduled value (because `b.index + 1 ≤ b.index + δ_reg` and the slash usually occurs at a later block than the DEREGISTER, but even at the same block the slash's `b.index + 1` is `≤` the DEREGISTER's `b.index + δ_reg` for `δ_reg ≥ 1`).

The intuitive ordering is that `inactive_from` only ever moves **forward in deactivation time** (closer to "now"), never backward to a later height. T-E2's "irrespective of prior value" claim is the formal expression: the equivocation override is unconditional, so even if a buggy DEREGISTER were to set `inactive_from` to a value smaller than `b.index + 1`, the equivocation write would overwrite it to `b.index + 1` — which might appear to "rewind" the deactivation, but in practice the only way `inactive_from < b.index + 1` could occur is via a DEREGISTER at the same block, which sets `δ_reg ≥ 1` and produces `b.index + δ_reg ≥ b.index + 1`. So the inequality `inactive_from_post_slash ≤ inactive_from_pre_slash` always holds on a well-formed chain. The override is therefore equivalent to "advance the deactivation to immediate" in all reachable states.

### 4.2 Why the forfeit is "burned" and not redistributed

The design choice to send the forfeited stake to `accumulated_slashed_` (a counter that enters A1's `expected_total` as a subtraction) rather than to the creator-fee distribution pool has three justifications:

1. **No incentive to manufacture equivocation evidence.** If forfeited stake were redistributed to the creators of the block carrying the `EquivocationEvent`, those creators would have an incentive to fabricate evidence (forge a second signature, plant manipulation traces) to capture the stake. Burning the stake removes the incentive — the creators get nothing beyond the standard per-block fee + subsidy. Combined with V11's EUF-CMA-bound on signature forgery (`≤ 2⁻¹²⁸`), the system is incentive-aligned: creators are paid to include legitimate evidence, but cannot profit from fabricating it.

2. **Preserves the unitary-supply ceiling.** Total supply is bounded above by `genesis_total + Σ_h subsidy_h + Σ_h inbound_h`. Equivocation forfeiture is the only mechanism (alongside outbound cross-shard transfers) that can REDUCE supply. Without this, slashing would be a redistribution and the chain's total supply would be monotonically non-decreasing, which is a weaker property than the "supply bounded above and slashable downward" guarantee that A1 establishes.

3. **Aligns with Ethereum-class slashing semantics.** Ethereum's beacon-chain slashing similarly burns the slashed ETH (after a "whistleblower reward" component, which Determ deliberately omits to close the manufacturing-incentive surface in (1)). The "burn, not redistribute" pattern is the established mutually-distrustful approach.

### 4.3 Apply-side vs validator-side division of labor

The apply-side mechanics in this proof fire **conditional on V11 having authorized the slash upstream**. V11 (`check_equivocation_events` at `validator.cpp`) is responsible for:

- Verifying `digest_a ≠ digest_b` (the two-distinct-signatures requirement).
- Verifying `Verify(pk_equivocator, digest_a, sig_a) == 1` and `Verify(pk_equivocator, digest_b, sig_b) == 1` against the equivocator's REGISTER-bound pubkey.
- For cross-shard events (`shard_id != 0`), verifying the beacon-anchor-height context (FA6 Corollary T-6.1).

If V11 rejects the block at validate-time, the apply path never runs and the equivocation branch above does not execute. The apply-side mechanics are therefore "trusted" in the operational sense — they assume the equivocation evidence is genuine. FA6 closes the cryptographic gap: an honest validator's signatures cannot be forged, so an honest validator is never falsely accused, so the apply-side mechanics never wrongly destroy honest stake.

The apply-side robustness (T-E4 ghost-equivocator handling) is the belt-and-suspenders defense against any path that slips past V11 — e.g., a snapshot replay of a pre-V11 block, a buggy peer producing a block that bypassed its own validator, or a malicious supplier injecting a forged snapshot whose `equivocation_events[]` references a domain that doesn't exist on the receiver's chain. The defensive guards at lines 1346 and 1352 ensure the apply path is **safe** in all these edge cases (no crash, no state corruption), even where it cannot be **soundly punitive** (a forged event against a non-existent domain produces no slash). The combination of V11 cryptographic soundness + apply-side defensive robustness produces the desired property: slashing fires exactly when it should, and no other time.

---

## 5. What this doesn't prove

The theorems above target the apply-layer mechanics of equivocation slashing in isolation. They do not extend to:

- **Slashing soundness — the "honest never slashed" property.** This is the scope of `EquivocationSlashing.md` (FA6) Theorem T-6. FA6's argument is cryptographic (EUF-CMA + H2 honest-validator behavior), and the apply-side mechanics fire only when FA6's V11 + EUF-CMA chain authorizes the slash. The present proof's T-E1 through T-E7 are conditional on FA6's soundness: "given that the slash IS authorized, here's what happens."

- **Slashing completeness — "every equivocator gets caught."** A separate theorem would prove that every actual equivocation eventually surfaces as a finalized `EquivocationEvent`. This is a liveness property (FA4-adjacent) for the gossip + evidence-pool pipeline; not proven here. In practice the gossip layer's `EQUIVOCATION_EVIDENCE` propagation + the pending-evidence-pool dedup makes most actual equivocations land in some honest committee's block, but the formal completeness claim is out of scope.

- **Suspension slashing (round-1 aborts).** The suspension-slash branch at `chain.cpp:1313–1328` shares the `block_slashed` accumulator with the equivocation branch but operates on a different trigger (abort events instead of equivocation events). Suspension slashing is bounded-magnitude (`SUSPENSION_SLASH = 10` per event, vs. full forfeit for equivocation) and is the "economic, not cryptographic" deterrent for round-1 absence. The suspension-slash analytic is covered by `StakeLifecycle.md` §4 (slashing-intersection note) and is informally addressed in `docs/SECURITY.md` S-008.

- **EquivocationEvent wire format / V11 validator check.** The struct's serialization, V11's verify-against-pubkey logic, and the consensus-time rejection are PROTOCOL.md §4 / FA6 / validator-side scope. The present proof references `ev.equivocator` as the key for the apply-side mechanics but does not verify the event's authenticity — that is V11's job.

- **Snapshot restore preserves the post-slash state.** The post-slash `stakes_[d].locked = 0`, `registrants_[d].inactive_from = h+1`, and `accumulated_slashed_ += L` triple is carried across snapshot boundaries via the `s:`, `r:`, and `c:` namespaces respectively (FA-Apply-2 T-S3 cross-namespace coverage). The restore equivalence is FA-Apply-2's scope; the present proof's deltas compose through snapshot restore by T-S2 without re-derivation. A regression introducing a path where a post-slash chain failed snapshot serialize/restore for any of the three would manifest as a state-root divergence (G2 gate failure at `chain.cpp:1893–1911`).

- **Cross-shard equivocation propagation.** FA6 Corollary T-6.1 covers cross-shard slashing soundness; the present proof references the `ev.shard_id` and `ev.beacon_anchor_height` fields only as forensic context. The cross-shard apply mechanics are identical to the single-chain branch — the shard fields do not gate the apply-side writes, only the V11 routing. The single-chain proof here is the apply-side claim for both modes.

- **Re-registration after equivocation.** The present proof claims (Discussion §4 + T-E2 commentary) that the equivocated entry blocks REGISTER from re-creating the same domain. The actual REGISTER apply path at `chain.cpp:792–812` does check `registrants_.contains(d)` and skips on hit, but the lifecycle of the deactivated entry across very long horizons (does the chain ever GC inactive registry entries?) is not formally addressed here. In current code the entry persists indefinitely, which is the design point that makes the re-registration block permanent. A future GC policy would need to interact carefully with this property.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V11 (equivocation-proof verification) + assumption A1 (Ed25519 EUF-CMA) backing FA6's soundness. |
| `EquivocationSlashing.md` (FA6) | Slashing soundness theorem T-6 + cross-shard corollary T-6.1; the present proof's mechanics fire only when FA6's V11 + EUF-CMA chain authorizes the slash. |
| `AccountStateInvariants.md` (FA-Apply) | I-3 (balance ↔ stake independence: slashing consumes `stakes_[d].locked` without crossing into `accounts_[d].balance`); I-5 (channel enumeration — equivocation-slash is the `locked → ∅` debit channel); I-6 (A1 closure consuming `accumulated_slashed_`). |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S2 + T-S3 — the post-slash state triple (stakes/registrants/accumulated_slashed) is carried across snapshot boundaries via the `s:`, `r:`, and `c:` namespaces respectively. |
| `StakeLifecycle.md` (FA-Apply-4) | T-K3 (DEREGISTER deferred-unlock) — the alternative deactivation path compared in §3; §4 (slashing intersection — equivocation can fire during the staked-pending-unlock window). |
| `CrossShardReceiptDedup.md` (FA-Apply-9) | Structural template — both are apply-side state-machine proofs over a chain-instance container whose semantics survive snapshot bootstrap. |
| `EconomicSoundness.md` (FA11) | A1 unitary-balance invariant (T-12); the `accumulated_slashed_` term enters `expected_total` as a subtraction (the "burn, not redistribute" property of §4.2). |
| `docs/PROTOCOL.md` §4 | Block.equivocation_events wire format + V11 validator predicate. |
| `docs/PROTOCOL.md` §6.1 | Equivocation detection paths (BlockSigMsg-level + ContribMsg same-generation, S-006 closure). |
| `docs/SECURITY.md` §S-006 | ContribMsg same-generation equivocation closure (the second detection path that produces EquivocationEvent). |
| `docs/SECURITY.md` §S-033 / §S-038 | State-root commitment over `s:`, `r:`, `c:` namespaces that makes T-E7 + T-R4-analogue (snapshot-restore preserves post-slash state) non-vacuous. |
| `include/determ/chain/block.hpp:256–279` | `EquivocationEvent` struct. |
| `include/determ/chain/chain.hpp:23–30` | `StakeEntry` struct (`locked`, `unlock_height`). |
| `include/determ/chain/chain.hpp:32–43` | `RegistryEntry` struct (`inactive_from` field). |
| `src/chain/chain.cpp:725` | `block_slashed` per-block accumulator declaration. |
| `src/chain/chain.cpp:1313–1328` | Suspension-slash branch (companion mechanism; out of scope per §5). |
| `src/chain/chain.cpp:1344–1356` | Equivocation-slash apply branch (the central dual-mechanism loop). |
| `src/chain/chain.cpp:1395` | Block-tail fold of `block_slashed` into `accumulated_slashed_`. |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion + rollback diagnostic. |
| `src/chain/chain.cpp:792–812` | REGISTER's `registrants_.contains` check that blocks re-activation of the deactivated entry. |
| `src/chain/chain.cpp:331–341` | `s:` + `r:` namespace state-root contribution (T-E7's determinism backstop). |
| `src/node/validator.cpp::check_equivocation_events` | V11 upstream gate (FA6 scope). |
| `tools/test_equivocation_apply.sh` | T-E1 + T-E2 + T-E4 + T-E5 + T-E7 (~10 assertions across five blocks — full forfeit, registry deactivation, ghost-equivocator robustness, A1 supply invariant, determinism; see `determ test-equivocation-apply`). |
| `tools/test_equivocation_multi.sh` | T-E3 + T-E6 + T-E4 DOMAIN_INCLUSION variant + T-E7 multi-event determinism (~14 assertions across five scenarios — two distinct equivocators in same block, same equivocator twice in same block, equivocator with NO stake, pre-deactivated equivocator override, determinism; see `determ test-equivocation-multi`). |
| `tools/test_equivocation_slashing.sh` | End-to-end network-level scenario (3-node cluster, gossip + V11 + apply). |
| `tools/test_supply_invariant.sh` | A1 closure across composed block sequences including equivocation events. |

---

## 7. Status

All seven theorems (T-E1 through T-E7) are closed in the current codebase:

- **T-E1** (full stake forfeiture) closed via the `block_slashed += sit->second.locked; sit->second.locked = 0;` paired writes at `chain.cpp:1348–1349` + apply-tail fold at `chain.cpp:1395`; regression `test_equivocation_apply.sh` "Full stake forfeiture" assertion.
- **T-E2** (registry deactivation) closed via the unconditional `rit->second.inactive_from = b.index + 1;` write at `chain.cpp:1354`; regression `test_equivocation_apply.sh` "Registry deactivation" (2 assertions) + `test_equivocation_multi.sh` "Pre-deactivated equivocator" override case.
- **T-E3** (idempotent re-apply) closed via the read-then-write pattern at `chain.cpp:1348–1349` that makes the second iteration on the same domain read `locked == 0` and contribute zero; regression `test_equivocation_multi.sh` "Same equivocator twice in same block" scenario.
- **T-E4** (ghost-equivocator robustness) closed via the independent `find(...) != end()` guards at `chain.cpp:1346` and `chain.cpp:1352`; regression `test_equivocation_apply.sh` "Robustness on ghost equivocator" (2 assertions) + `test_equivocation_multi.sh` "Equivocator with NO stake" DOMAIN_INCLUSION variant.
- **T-E5** (A1 invariance under slashing) closed via the paired `block_slashed += L` / `locked = 0` writes preserving the A1 ledger arithmetic + apply-tail fold + A1 closure at `chain.cpp:1397–1419`; regression `test_equivocation_apply.sh` "A1 supply invariant" (3 assertions).
- **T-E6** (cross-block accumulation) closed via the apply-tail fold at `chain.cpp:1395` + the read-then-write idempotence of T-E3 across blocks; regression `test_equivocation_multi.sh` "Two distinct equivocators in same block" + "Determinism" scenarios.
- **T-E7** (deterministic apply) closed via the apply branch's reliance on only the chain's deterministic state + the block's consensus-pinned `equivocation_events[]` order + `std::map` per-key isolation; regression `test_equivocation_apply.sh` "Determinism" assertion + `test_equivocation_multi.sh` "Determinism" multi-event variant.

No theorem is open or partial. The proof rests on a small set of primitives: the dual-mechanism `(stake-forfeit, registry-deactivate)` paired writes guarded by independent `find` checks, the `block_slashed` per-block accumulator that folds into the chain-wide `accumulated_slashed_` at apply-tail, the A1 closure that catches any off-by-one in the accumulator update, and the `std::map` per-key isolation that makes multi-equivocator independence structural. The breadth of consequences — seven theorems plus the slashing-vs-DEREGISTER comparison plus the `inactive_from` monotonicity claim plus the "burn, not redistribute" rationale — is testimony to how few primitives the chain needs to express the slashing mechanism without compromising A1 conservation, replay determinism, or DOMAIN_INCLUSION-mode compatibility.

The proof's foundation rests on FA6's cryptographic soundness (no honest validator is ever named as the equivocator in a finalized event, under EUF-CMA) and FA-Apply's invariants (I-3 balance/stake independence + I-6 A1 closure). FA-Apply-10's contribution is the apply-side mechanism that, conditional on FA6's soundness, executes the slashing transition correctly: full forfeit, registry deactivation, A1 closure, idempotence, ghost-equivocator robustness, cross-block accumulation, and determinism.
