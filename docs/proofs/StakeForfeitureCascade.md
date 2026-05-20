# FA-Apply-16 — Stake forfeiture cascade (slashing × deferred-unstake interaction)

This document formalizes the **cascade composition** between two stake-mutating channels that can fire on the same domain within overlapping time windows: equivocation slashing (FA-Apply-10) and the deferred-unlock phase of voluntary deregistration (FA-Apply-4 T-K3). The interesting case is a validator `D` that signed STAKE → DEREGISTER (entering `staked-pending-unlock` per `StakeLifecycle.md` §1.2) and then has equivocation evidence surface BEFORE `b.index ≥ stakes_[D].unlock_height`. The chain has two state-mutating mechanisms aimed at the same `stakes_[D].locked` field; their composition must produce a single deterministic answer regardless of the apply-time ordering, must preserve the A1 unitary-supply invariant under every reachable interleaving, and must leave the honest-misclock UX guarantee from T-K4 intact for post-slash UNSTAKE attempts.

The composition is decided structurally by the **Phase ordering** of `apply_transactions` (FA-Apply-15 T-M1): Phase 1 consumes ordinary transactions including UNSTAKE; Phase 4 consumes `EquivocationEvent`s. Within a single block, the apply path runs Phase 1 first and Phase 4 fourth, so a same-block UNSTAKE-then-equivocate sequence applies UNSTAKE on the pre-slash `locked`, then slashes whatever remains. Across blocks, the same logic applies per-block. The cascade reduces to one of six well-defined sequences whose joint semantics this proof pins.

**Companion documents:** `Preliminaries.md` (F0) for notation, V11 + V15 + the deferred-unlock window; `AccountStateInvariants.md` (FA-Apply) for I-3 (balance ↔ stake independence), I-5 (channel enumeration), I-6 (A1 closure); `EquivocationSlashingApply.md` (FA-Apply-10) for T-E1 (full forfeit), T-E2 (registry deactivation), T-E3 (idempotence), T-E4 (ghost-equivocator robustness); `StakeLifecycle.md` (FA-Apply-4) for T-K1 (STAKE), T-K3 (DEREGISTER deferred-unlock), T-K4 (UNSTAKE pre-unlock fee refund), T-K5 (UNSTAKE post-unlock success), T-K6 (pre-DEREGISTER UNSTAKE silent skip); `MultiEventComposition.md` (FA-Apply-15) for T-M1 (deterministic event ordering across the seven Phases), T-M3 (A1 composability), T-M6 (intentional coupling cases — Case 1 is abort + equivocation on same domain, Case 5 is STAKE + slash, Case 6 is REGISTER + slash; the present proof addresses the analogous UNSTAKE × slash case); `docs/SECURITY.md` §S-017 for the producer/validator/chain alignment of the unlock-height check.

---

## 1. Setup

### 1.1 The two mechanisms on `stakes_[D].locked`

Two apply-time branches mutate `stakes_[D].locked` for a single domain `D`:

1. **UNSTAKE success path** (Phase 1, `chain.cpp:889–893`): debits `amount` from `locked`, credits the matching amount to `accounts_[D].balance`. The branch is gated on `stakes_[D].locked >= amount` AND `b.index >= stakes_[D].unlock_height`. The success branch is reachable only after a prior DEREGISTER set `unlock_height` to a finite value (T-K3) and the chain has advanced past it.
2. **Equivocation forfeit path** (Phase 4, `chain.cpp:1344–1356`): zeroes `stakes_[D].locked` unconditionally on `stakes_.contains(D)`, accumulates the pre-write value into `block_slashed` (which folds into chain-wide `accumulated_slashed_` at the apply-tail per T-E5). The branch reads no other field on `stakes_[D]` — specifically not `unlock_height`. The slash is **insensitive to deferred-unlock state**: a `staked-active` domain and a `staked-pending-unlock` domain both have their `locked` field zeroed identically.

The asymmetry is intentional: the deferred-unlock window IS the slashing-evidence window (`StakeLifecycle.md` §4). A domain that has signaled DEREGISTER but not yet completed UNSTAKE is still slashable until `unlock_height`. This is what makes the cascade non-trivial — the chain deliberately keeps Byzantine-evidence-eligible stake locked across the deregistration tail, so the operator's stake remains forfeitable for misbehavior in or before the window.

### 1.2 Six cascade sequences

Let `H_d := b.index of DEREGISTER block`, `H_u := stakes_[D].unlock_height = H_d + δ_reg + unstake_delay_`, `H_e := b.index of block carrying EquivocationEvent`, `H_unstake := b.index of block carrying UNSTAKE attempt`. The reachable scenarios fall into six classes:

| Class | Sequence | T-C theorem | Outcome |
|---|---|---|---|
| (i) | DEREGISTER → equivocate (H_e ∈ [H_d+1, H_u−1]) | T-C1 | Full forfeit; pending UNSTAKE rendered moot |
| (ii) | DEREGISTER → equivocate → UNSTAKE attempt (H_unstake > H_e) | T-C2 | UNSTAKE skipped: `locked == 0 < amount` → T-K4 refund branch |
| (iii) | DEREGISTER → UNSTAKE attempt at H_unstake < H_u (too-early) → equivocate | T-C3 | UNSTAKE refunds fee + bumps nonce; subsequent slash forfeits remaining `locked` |
| (iv) | DEREGISTER → UNSTAKE success at H_unstake ≥ H_u → equivocate | T-C4 | Slash applies to zero `locked`; no forfeiture; registry deactivation still fires |
| (v) | Same-block: UNSTAKE + EquivocationEvent in B at height H ≥ H_u | T-C5 | Phase 1 UNSTAKE succeeds; Phase 4 slashes residual `locked` |
| (vi) | Same-block: UNSTAKE (pre-unlock) + EquivocationEvent in B at height H < H_u | T-C5 alt | Phase 1 UNSTAKE refunds; Phase 4 zeroes full `locked` |

Each class is a deterministic apply-time outcome; T-C7 below pins replay-equivalence across classes.

### 1.3 The fee-refund × full-forfeit interaction

A subtle coupling: Phase 1's UNSTAKE refund branch (T-K4, lines 884–885) restores `tx.fee` to `accounts_[D].balance` and removes it from `total_fees`. This restoration is **independent** of the equivocation forfeiture in Phase 4 because the two branches read/write disjoint accumulators (Phase 1 touches `total_fees` + `accounts_[D].balance`; Phase 4 touches `block_slashed` + `stakes_[D].locked` + `registrants_[D].inactive_from`). A1 closure remains additive (T-M3): the UNSTAKE refund nets to zero on supply, the slash subtracts `locked` from supply. Both contributions are correctly captured in the apply-tail closure.

---

## 2. Theorems

### T-C1 — Equivocation during deferred-unlock window: full stake forfeiture

**Statement.** Let `D` be a domain in the `staked-pending-unlock` state at the start of block `B_e` (`stakes_[D].locked == L > 0`, `stakes_[D].unlock_height == H_u`, `registrants_[D].inactive_from == H_d + δ_reg < H_u`). Assume `B_e` contains an `EquivocationEvent ev` with `ev.equivocator == D` and `b.index == H_e ∈ [H_d + 1, H_u − 1]` (strictly inside the deferred-unlock window, **before** unlock). Then apply produces:

```
Δstakes_[D].locked          = −L                  (locked → 0)
Δstakes_[D].unlock_height   = 0                   (unchanged; sentinel-or-finite preserved)
Δregistrants_[D].inactive_from = (H_e + 1) − (H_d + δ_reg)   (advanced forward)
Δblock_slashed              = +L
→ Δaccumulated_slashed_     = +L
Δaccounts_[D].balance       = 0                   (no balance crossing)
```

with no other state mutation outside the per-Phase 4 loop body. Total supply decreases by exactly `L` (T-E5 specialization).

**Proof sketch.** T-K3 (DEREGISTER) established the pre-`B_e` state: `stakes_[D].locked == L`, `stakes_[D].unlock_height == H_u = H_d + δ_reg + unstake_delay_`, `registrants_[D].inactive_from == H_d + δ_reg`. By T-M1 (Phase ordering), `B_e`'s Phase 4 loop iterates over `b.equivocation_events`; the iteration on `ev` finds `stakes_[D]` (hypothesis `L > 0`) and enters the forfeit branch. Per T-E1: `block_slashed += L`, `sit->second.locked := 0`. The `unlock_height` field is NOT touched (T-E1 explicitly excludes it from the write set — see EquivocationSlashingApply.md §2.1 commentary on "unlock_height untouched"). Per T-E2: `rit->second.inactive_from := H_e + 1`. Since `H_e + 1 ≤ H_d + δ_reg` is FALSE for any honest DEREGISTER (the slash happens later in time than the DEREGISTER, so `H_e ≥ H_d + 1` and `H_e + 1 ≤ H_d + δ_reg` requires `δ_reg ≥ 2`; in practice `δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]` so the override may or may not advance the deactivation — but in either case it is unconditionally written, T-E2 "irrespective of prior value"). The deltas are exactly the per-Phase-4 write set; A1 invariance follows from T-E5. ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (Phase 4 forfeit loop); `src/chain/chain.cpp:851` (T-K3's `unlock_height` write that established the pre-`B_e` state — preserved across `B_e` because Phase 4 never reads or writes it); `src/chain/chain.cpp:1395` (apply-tail fold).

**Test witness.** `tools/test_equivocation_multi.sh` "Pre-deactivated equivocator" scenario establishes the `inactive_from` override for a domain whose prior `inactive_from` is finite (exactly the DEREGISTER-then-slash setup). `tools/test_unstake_deregister_apply.sh` exercises the deferred-unlock setup that precedes the cascade.

### T-C2 — Subsequent UNSTAKE attempt: refunded, no stake credit

**Statement.** Let `D` be a domain that has been slashed for equivocation (post-T-C1 state: `stakes_[D].locked == 0`, `registrants_[D].inactive_from == H_e + 1`, `stakes_[D].unlock_height == H_u` unchanged). Assume a later block `B_unstake` at height `H_unstake > H_e` contains an UNSTAKE transaction `tx` with `tx.from == D`, `tx.nonce == accounts_[D].next_nonce`, payload encoding `amount > 0`, `accounts_[D].balance ≥ tx.fee`. Then apply produces:

```
Δaccounts_[D].balance       = 0                   (fee charged then refunded; net zero)
Δaccounts_[D].next_nonce    = +1                  (slot consumed)
Δstakes_[D].locked          = 0                   (no credit; refund branch)
Δstakes_[D].unlock_height   = 0                   (unchanged)
Δtotal_fees                 = 0                   (fee added then removed; net zero)
```

The operator does not recover their forfeited stake via UNSTAKE retry. The honest-misclock UX guarantee (T-K4) covers this case as well: no fee penalty, only a consumed nonce slot.

**Proof sketch.** Phase 1's UNSTAKE branch at `chain.cpp:873–894` enters via the nonce gate (hypothesis match). Payload decode succeeds. `charge_fee` debits `tx.fee` (succeeds by balance hypothesis). The unlock-failure condition at lines 880–881 evaluates `stakes_[D].locked < amount` — under T-C1's post-state `stakes_[D].locked == 0` and the hypothesis `amount > 0`, so the disjunct is TRUE, and the refund branch at lines 882–887 fires. Lines 884–885 refund the fee. Line 886 bumps the nonce. The `unlock_height` check at line 881 is the third disjunct; whether `H_unstake ≥ H_u` or not is irrelevant — the `locked < amount` disjunct already enters the refund. The post-apply state has `stakes_[D].locked == 0` (unchanged from T-C1) and `unlock_height == H_u` (also unchanged); subsequent UNSTAKE retries fall into the same refund branch indefinitely. The operator pays no further fees but also recovers no stake; T-K4's structural pattern is preserved. ∎

**Code witness.** `src/chain/chain.cpp:880–887` (the refund branch reached when `locked == 0 < amount`); `src/chain/chain.cpp:884–885` (the load-bearing fee refund).

**Test witness.** `tools/test_unstake_deregister_apply.sh` "UNSTAKE insufficient locked" scenario covers the `locked < amount` case independent of `unlock_height`. The post-equivocation `locked == 0` is the extreme of this case (the slashed domain has zero stake to recover).

### T-C3 — UNSTAKE pre-unlock with intervening slash: nonce bumped, fee refunded, no stake credit

**Statement.** Consider the sequence on domain `D`:

1. Block `B_d` at `H_d`: DEREGISTER (per T-K3, sets `unlock_height = H_u = H_d + δ_reg + unstake_delay_`).
2. Block `B_pre` at `H_pre ∈ [H_d + 1, H_u − 1]`: UNSTAKE attempt with `tx.from == D`, `amount = a ≤ L`. Per T-K4 (pre-unlock fee refund), apply produces zero net delta on balance, stake, and `total_fees`; only `next_nonce` is bumped.
3. Block `B_e` at `H_e ∈ [H_pre + 1, H_u − 1]`: EquivocationEvent for `D`. Per T-C1, apply produces `Δstakes_[D].locked = −L`, `Δblock_slashed = +L`, `Δregistrants_[D].inactive_from = H_e + 1 − (H_d + δ_reg)`.

The composed final state has `stakes_[D].locked == 0`, `accounts_[D].balance` unchanged from before `B_pre` (modulo unrelated transactions), `accumulated_slashed_` advanced by `L`, and `accounts_[D].next_nonce` bumped by 1 (from the failed UNSTAKE attempt). The slash and the UNSTAKE-refund commute on supply (both contribute zero to balance crossing); the slash zeroes the stake regardless of the prior pre-unlock UNSTAKE attempt because T-K4's refund branch did not mutate `locked`.

**Proof sketch.** T-K4 directly: at `B_pre`, the conditional at `chain.cpp:881` evaluates `H_pre < stakes_[D].unlock_height == H_u`, which is TRUE under hypothesis `H_pre ∈ [H_d + 1, H_u − 1]`. The refund branch fires. Crucially, `locked` is NOT mutated by T-K4 — see `chain.cpp:884–887`, which only touches `balance`, `total_fees`, and `next_nonce`. The post-`B_pre` `stakes_[D].locked == L` (unchanged). Then T-C1 fires at `B_e` against `locked == L > 0`; the full `L` is forfeited. A1 invariance holds in each block independently (T-M3), and across the two-block composition by induction. The net deltas across `B_pre + B_e` on supply: 0 (T-K4) + (−L) (T-C1) = −L. The chain's `live_total_supply()` decreases by exactly `L`, matching `accumulated_slashed_ += L`. ∎

**Code witness.** `src/chain/chain.cpp:884–887` (T-K4 refund — does NOT touch `locked`); `src/chain/chain.cpp:1344–1356` (T-C1 slash reads post-T-K4 `locked == L`); `src/chain/chain.cpp:1395` (apply-tail fold consistent across both blocks).

**Test witness.** `tools/test_unstake_deregister_apply.sh` "UNSTAKE too-early" scenario covers `B_pre`'s refund branch (stake unchanged, balance unchanged, nonce bumped). `tools/test_equivocation_multi.sh` covers `B_e`'s slash. The two scenarios are composed structurally by T-M5's replay determinism — no single test exercises the exact sequence, but the per-block invariants compose by T-M5 + T-M3.

### T-C4 — Slash AFTER UNSTAKE complete: no stake to forfeit (registry deactivation only)

**Statement.** Consider the sequence on domain `D`:

1. Block `B_d` at `H_d`: DEREGISTER (T-K3).
2. Block `B_us` at `H_us ≥ H_u`: UNSTAKE with `amount == L` (full unstake). Per T-K5: `Δstakes_[D].locked = −L`, `Δaccounts_[D].balance = +L − tx.fee`, `Δtotal_fees = +tx.fee`. Post-state: `stakes_[D].locked == 0`, `accounts_[D].balance == B_d_initial + L − tx.fee` (modulo unrelated tx activity).
3. Block `B_e` at `H_e > H_us`: EquivocationEvent for `D` (e.g., evidence surfaces from misbehavior earlier in `D`'s active history). Apply produces:

```
Δstakes_[D].locked          = 0                   (already zero; T-E1 reads 0)
Δregistrants_[D].inactive_from = (H_e + 1) − (H_d + δ_reg)   (override; T-E2)
Δblock_slashed              = 0                   (no stake left to forfeit)
Δaccumulated_slashed_       = 0
```

The equivocation event records in the block but produces **zero stake forfeiture**. The registry deactivation still fires (T-E2 is unconditional on stake state). The operator's `accounts_[D].balance` (which now holds the unstaked value) is **unaffected** — the slash branch never crosses into the balance map (FA-Apply I-3 balance ↔ stake independence; FA-Apply-10 T-E4 ghost-equivocator robustness composes here since `stakes_[D]` exists with `locked == 0`).

**Proof sketch.** Phase 4 iteration on `ev` enters with `stakes_[D].locked == 0` (post-T-K5). T-E1 fires symbolically — line 1348 reads `sit->second.locked == 0`, adds zero to `block_slashed`, line 1349 writes zero (idempotent no-op). T-E2 fires unconditionally: line 1354 writes `inactive_from := H_e + 1` regardless of prior value. The post-apply state has registry permanently closed (Discussion §4 of FA-Apply-10 on the "deactivation blocks re-registration" property — the offender cannot re-register `D` even though they recovered their stake). T-E5's A1 contribution is zero: `Δlive_total_supply = 0` (no stake forfeited from a zero balance), `Δaccumulated_slashed_ = 0`. The balance the operator recovered via UNSTAKE is permanent — the chain has no apply-time mechanism to retroactively claw back UNSTAKEd value via post-UNSTAKE equivocation evidence. This is intentional: the `unstake_delay_` window is the chain's commitment to the evidence horizon. Evidence surfacing post-`H_u` no longer threatens the stake. ∎

**Code witness.** `src/chain/chain.cpp:1346` (the `sit != stakes_.end()` guard passes since `stakes_[D]` persists with `locked == 0` post-UNSTAKE — UNSTAKE debits `locked` but does NOT erase the map entry); `src/chain/chain.cpp:1348` (the read-then-write reads zero); `src/chain/chain.cpp:1352–1354` (registry deactivation unconditional).

**Test witness.** `tools/test_equivocation_multi.sh` "Equivocator with NO stake" scenario covers the `locked == 0 OR stakes_[D] absent` case — the slash is a no-op on the supply channel, the registry deactivation fires. The post-UNSTAKE setup is the structural analogue (locked is zero by UNSTAKE rather than by prior slash, but the apply-path behavior is identical from Phase 4's perspective).

### T-C5 — Order matters: same-block UNSTAKE + equivocation

**Statement.** Within a single block `B` at height `H` containing both an UNSTAKE transaction for `D` (in `B.transactions`) AND an `EquivocationEvent ev` for `D` (in `B.equivocation_events`), the apply path's Phase ordering (T-M1) sequences UNSTAKE first (Phase 1) and equivocation second (Phase 4). Two sub-cases:

**T-C5a (UNSTAKE post-unlock, H ≥ H_u, amount ≤ L):**
- Phase 1 UNSTAKE per T-K5: `locked := L − amount`, `balance += amount`, fee debited.
- Phase 4 equivocation per T-E1: `locked := 0` (zeroing the residual `L − amount`), `block_slashed += L − amount`.
- Net: total supply decreases by `L − amount`; operator's balance retains the UNSTAKEd `amount`.

**T-C5b (UNSTAKE pre-unlock, H < H_u):**
- Phase 1 UNSTAKE per T-K4: refund branch fires; `locked` unchanged.
- Phase 4 equivocation per T-E1: `locked := 0`, `block_slashed += L`.
- Net: total supply decreases by `L`; operator's balance unchanged.

Compare against the inverted hypothetical `STAKE → DEREGISTER → equivocation → UNSTAKE` sequence (T-C2 + T-C3): the equivocation-before-UNSTAKE-attempt case slashes the full `L` and the UNSTAKE refund-branches on `locked == 0 < amount`. The inverted `STAKE → DEREGISTER → UNSTAKE → equivocation` (T-C4) UNSTAKEs the full `L` first, then the equivocation no-ops on the supply channel. The two sequences produce DIFFERENT supply outcomes (`Δsupply = −L` vs `Δsupply = 0`) because order matters: only stake locked AT THE MOMENT of the Phase 4 iteration can be forfeited.

**Proof sketch.** By T-M1, Phase 1 runs first. The UNSTAKE branch executes against `stakes_[D].locked == L` (pre-block value). In T-C5a, the unlock-height check at line 881 passes (`H ≥ H_u`), the success branch runs, `locked := L − amount` post-Phase-1. In T-C5b, the check fails (`H < H_u`), the refund branch runs, `locked` unchanged.

Phase 4 then runs. The iteration on `ev` reads `stakes_[D].locked` at the post-Phase-1 value. In T-C5a, that value is `L − amount`; T-E1 forfeits exactly that amount. In T-C5b, that value is `L`; T-E1 forfeits the full `L`. A1 closure (T-M3) sums the Phase 1 contribution (`Δsupply = 0` in T-C5a from intra-domain locked→balance, `Δsupply = 0` in T-C5b from full refund) plus the Phase 4 contribution (`Δsupply = −(L−amount)` in T-C5a, `Δsupply = −L` in T-C5b).

The order-dependence argument is exhaustive: there is no possible apply path where Phase 4 reads `locked` before Phase 1's write, because the seven-Phase ordering is structurally sequential. The composition is well-defined for every (UNSTAKE intent, equivocation evidence) pair within a single block, and the answer is "operator keeps whatever they unstaked before slashing began; chain forfeits the residual." ∎

**Code witness.** `src/chain/chain.cpp:889–893` (Phase 1 UNSTAKE writes `locked` first); `src/chain/chain.cpp:1344–1356` (Phase 4 reads post-Phase-1 `locked`); FA-Apply-15 T-M1 ordering proof.

**Test witness.** `tools/test_block_event_composition.sh` (intended canonical regression for T-M6's intentional-coupling cases — UNSTAKE + equivocation on same domain in same block is the analogue of Case 5 STAKE + abort; the composition is structurally verified by Phase ordering). `tools/test_multi_event_block_apply.sh` (broader composition surface — T-C5 inherits from T-M5's replay determinism).

### T-C6 — A1 invariance under cascade

**Statement.** Across any reachable cascade sequence on domain `D` (any of classes (i)–(vi) of §1.2, or any concatenation thereof across multiple blocks), the A1 unitary-supply invariant holds at every apply-tail. Specifically, for any pre-cascade chain state `C_0` and any sequence of blocks `B_1, ..., B_n` instantiating the cascade:

```
live_total_supply(C_n) == genesis_total_
                        + accumulated_subsidy_(C_n)
                        + accumulated_inbound_(C_n)
                        - accumulated_outbound_(C_n)
                        - accumulated_slashed_(C_n)
```

regardless of the specific interleaving of UNSTAKE, DEREGISTER, EquivocationEvent, and AbortEvent on `D` and on any other domain. The accumulated values reflect exactly the slashed magnitude across the cascade: `Δaccumulated_slashed_(C_0 → C_n)` equals the sum of `stakes_[D].locked` AT THE MOMENT of each Phase 4 iteration that finds non-zero locked. No double-counting (T-E3 idempotence) and no under-counting (T-E1 full forfeit) on the slashing channel; the UNSTAKE channel contributes zero to `accumulated_slashed_` regardless of pre- or post-unlock timing.

**Proof sketch.** By induction on the block sequence. Base case: `C_0` satisfies A1 (chain invariant from FA-Apply I-6 + EconomicSoundness FA11 T-12). Inductive step: assume A1 at `C_k`; apply `B_{k+1}`. Per T-M3 (A1 composability over the seven Phases), each Phase's contribution to the A1 ledger is additive across events. Phase 1 UNSTAKE contributes 0 to `Δsupply` regardless of success/refund (T-K4 net zero on supply, T-K5 intra-domain transfer). Phase 4 equivocation contributes `−L_event` where `L_event` is the pre-event-iteration `locked` (T-E1, T-E5). The chain-wide `accumulated_slashed_` advances by exactly `Σ_{ev ∈ B_{k+1}} L_event`, and `live_total_supply` advances by `−Σ L_event`. Both sides of A1 advance by the same scalar; equality preserved.

The cross-event coupling within a single block (T-M6 Case 1 + Case 5 analogue): a same-block UNSTAKE + equivocation produces Phase 1 mutating `locked` first, then Phase 4 reading the post-Phase-1 `locked`. The accumulator update at Phase 6 captures both contributions correctly because each Phase writes to its own per-block accumulator (`total_fees` for Phase 1, `block_slashed` for Phase 4), and the apply-tail fold sums all four channels into the chain-wide counters. The A1 closure at `chain.cpp:1399` checks `live_total_supply == expected_total` after the fold; any cascade-induced miscounting would throw at this gate with the per-field diagnostic at lines 1405–1418. ∎

**Code witness.** `src/chain/chain.cpp:1393–1395` (the four accumulator updates); `src/chain/chain.cpp:1397–1419` (A1 closure + rollback diagnostic); composition of FA-Apply-10 T-E5, FA-Apply-4 T-K1/T-K5/T-K4, FA-Apply-15 T-M3.

**Test witness.** `tools/test_supply_invariant.sh` (A1 closure across composed sequences including equivocation events); `tools/test_supply_lifecycle.sh` (multi-block A1 closure across mixed event streams). `tools/test_equivocation_apply.sh` "A1 supply invariant" assertions specialize to the slash-only side. The cascade-specific composition inherits the A1 guarantee from T-M3 without requiring a dedicated regression — every per-block A1 check passes by induction.

### T-C7 — Determinism: identical event sequence produces identical state

**Statement.** For any two Chain instances `C_1`, `C_2` satisfying `C_1 ≡_S C_2` (state-equivalence per FA-Apply-2 §1.2) and any finite block sequence `B_1, ..., B_n` instantiating a cascade scenario on domain `D`, two independent replays of `apply_transactions(B_i)` for `i = 1, ..., n` on `C_1` and `C_2` produce byte-identical post-states. Specifically: identical `accounts_[D]`, `stakes_[D]`, `registrants_[D]`, `accumulated_slashed_`, and identical `compute_state_root(C_n)`.

**Proof sketch.** Composition of FA-Apply-10 T-E7 (Phase 4 determinism), FA-Apply-4 T-K7 (Phase 1 stake-branch determinism per `tx.from` keying), and FA-Apply-15 T-M5 (replay determinism with multi-event blocks). Each cascade block's apply is a pure function of `(C_prev, B)` with no nondeterministic input (no system clock, no RNG, no thread-scheduling). The cascade's intentional couplings (T-C5 ordering) are structurally pinned by T-M1's Phase ordering, which is invariant across `C_1` and `C_2`. The state-root recomputation at Phase 7 is a pure function of the ten namespaces (FA-Apply-15 T-M4); equivalent maps produce byte-identical roots; the S-033 gate either passes on both sides or throws on both sides. The determinism is structural. ∎

**Code witness.** Same as T-C6 plus FA-Apply-10's `chain.cpp:1344–1356` deterministic loop and FA-Apply-4's `chain.cpp:858–894` per-`tx.from` keying. The state-root recomputation at `chain.cpp:267–413` is the determinism backstop.

**Test witness.** `tools/test_equivocation_multi.sh` "Determinism" assertion (two chains seeing the same multi-equivocation sequence produce identical state-roots); `tools/test_chain_save_load.sh` (snapshot roundtrip on a chain that exercised DEREGISTER + slash sequences preserves the cascade-induced state byte-identically); `tools/test_multi_event_block_apply.sh` (replay determinism on multi-event blocks composes T-C7 trivially).

---

## 3. Why "order matters" is a feature, not a bug

The asymmetry between T-C1 (slash-then-UNSTAKE: full forfeit, no recovery) and T-C4 (UNSTAKE-then-slash: full recovery, no forfeit) is intentional design. The `unstake_delay_` parameter is the chain's commitment to a **finite evidence horizon**: post-unlock, the chain treats the operator's stake as safely recovered. Pre-unlock, the stake remains slashable.

**Two reasons this asymmetry is correct:**

1. **No retroactive clawback.** A chain that could slash post-UNSTAKE value via post-UNSTAKE-discovered evidence would have an unbounded horizon — every dollar of recovered stake remains forever at risk. This breaks operator economics: a validator cannot model the actual cost of exit because they cannot bound the post-exit liability. The `unstake_delay_` window is the chain's negotiated horizon (typically ~1000 blocks ≈ 8 minutes at 0.5s round time, longer at production-realistic parameters); slashing-eligible evidence must surface within that window or it does not threaten the stake. This is symmetric with the SECURITY.md §S-017 closure (validator-side reject of too-early UNSTAKE) — both sides of the unlock gate are deliberately discrete.

2. **Evidence freshness.** Equivocation evidence is gossiped by the network within seconds of the offense (the EQUIVOCATION_EVIDENCE message type at `protocol.hpp` does not have multi-block latency budget). The 1000-block unlock window is dramatically longer than the propagation horizon for honest evidence. A slash that surfaces post-`H_u` is either (a) stale evidence the network ignored (already-slashed offense), (b) cross-shard evidence with beacon-anchor delay (FA6 Corollary T-6.1 — but cross-shard slashes still respect the destination shard's unlock window), or (c) maliciously-fabricated forensic data (V11's EUF-CMA guard catches this). In none of these cases is post-`H_u` slashing necessary for soundness; T-E4 (ghost-equivocator robustness) ensures the registry deactivation still fires for the offender's domain so they cannot rejoin.

The cascade's order-dependence is therefore a **bounded-horizon guarantee**, not an exploitable race. The chain's economic model commits to "we will slash within this window; outside it, we record the offense but do not retroactively claw back." Operator confidence in exit timing is exactly the property a permissioned-consortium deployment needs.

**Why not retroactive?** A naive alternative would extend the slashable window beyond `unstake_delay_` by checkpointing the operator's pre-DEREGISTER balance + tracking it in a separate "slashable-tail" map. This would (a) bloat the chain state by `O(deregistration_history)`, (b) require a new state-root namespace and a corresponding S-033 commitment, (c) introduce a gameable interaction with subsequent TRANSFER/STAKE activity on `accounts_[D].balance` (the slashable-tail value must be tracked separately from current balance), and (d) extend the chain's economic complexity without addressing any actual attack surface (FA6 + V11 guarantee no honest validator is ever slashed; an offender who waited `unstake_delay_` blocks before re-misbehaving is already filtered out of the eligible-creator pool by T-E2's registry deactivation — they cannot misbehave again on `D`). The cascade as-implemented is the minimal mechanism that preserves the FA6 + V11 + S-017 invariants without unnecessary state bloat.

---

## 4. What this doesn't prove

- **Cryptographic soundness of the equivocation event.** FA6's T-6 EUF-CMA chain is the soundness backstop; the present proof's cascade fires conditional on FA6's authorization. A forged EquivocationEvent (impossible under EUF-CMA + V11) would naturally take the same apply-time path as a legitimate one.
- **Cross-shard cascade.** The cascade analysis above assumes a single chain. Cross-shard equivocation propagation (FA6 Corollary T-6.1) routes evidence through the beacon anchor; the cascade on the destination shard fires by the same Phase 4 mechanics described in T-C1. Cross-shard nuances (beacon-anchor-height ordering, source-shard / destination-shard `unlock_height` alignment) are FA6 scope.
- **Under-quorum merge interaction.** R7 merges (`UnderQuorumMerge.md` FA9) transfer `stakes_[D]` from one shard to another. A cascade in progress across a merge boundary preserves `locked` + `unlock_height` + `inactive_from` (the `s:` and `r:` namespaces are part of the merge state transfer per S-033). The cascade composes through the merge by FA9's state-restore equivalence; not re-derived here.
- **DOMAIN_INCLUSION-mode cascade.** When `min_stake_ == 0`, the stake-forfeiture side of the cascade is a no-op (no stake to forfeit), but the registry-deactivation side still fires. T-C4's "balance preserved" property is trivially true (no stake → balance crossing exists). The cascade reduces to "registry-only" deactivation; T-C7's determinism applies unchanged.
- **Nonce coordination across the cascade.** Each transaction (DEREGISTER, UNSTAKE) consumes one nonce slot via FA-Apply-3's strict-equality gate. The cascade respects the nonce sequence; an operator with concurrent endpoints must coordinate nonces (FA-Apply-3 T-N1). Not specific to the cascade.
- **Wallet-side UX for the cascade.** The chain's apply-time mechanics preserve `balance` across slash (T-C1) and refund `tx.fee` on failed UNSTAKE (T-K4 / T-C2). The wallet's job is to communicate "your stake has been slashed; subsequent UNSTAKE will not recover it" to the operator. The wallet-side display logic is out of scope; the chain's invariants are well-defined regardless.
- **AbortEvent × UNSTAKE composition.** AbortEvent (Phase 3) deducts at most `SUSPENSION_SLASH` from `locked` per round-1 abort. The composition with same-block UNSTAKE is structurally identical to T-C5 with Phase 3 substituted for Phase 4 and a bounded deduction substituted for the full forfeit. The analysis is symmetric; covered by `MultiEventComposition.md` T-M6 Case 1 + Case 5 directly without specialization in the present proof.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | V11 (equivocation-proof validator) + V15 (transaction apply) + S-017 closure on deferred-unlock alignment. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 atomic apply, I-3 balance ↔ stake independence (T-C4's "balance unaffected by slash"), I-5 channel enumeration, I-6 A1 closure. |
| `EquivocationSlashingApply.md` (FA-Apply-10) | T-E1 (full forfeit), T-E2 (registry deactivation), T-E3 (idempotence), T-E4 (ghost-equivocator robustness), T-E5 (A1 invariance), T-E7 (determinism) — the slash-side primitives. |
| `StakeLifecycle.md` (FA-Apply-4) | T-K1 (STAKE), T-K3 (DEREGISTER deferred-unlock), T-K4 (UNSTAKE pre-unlock fee refund — load-bearing for T-C2/T-C3), T-K5 (UNSTAKE post-unlock success), T-K6 (pre-DEREGISTER UNSTAKE silent skip), T-K7 (independent stakes). |
| `MultiEventComposition.md` (FA-Apply-15) | T-M1 (Phase ordering — load-bearing for T-C5), T-M3 (A1 composability — load-bearing for T-C6), T-M5 (replay determinism — load-bearing for T-C7), T-M6 (intentional coupling cases — the cascade's UNSTAKE × slash interaction is the natural Phase 1 × Phase 4 specialization). |
| `EconomicSoundness.md` (FA11) | T-12 A1 unitary-balance closure that T-C6 inherits. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S2 apply-after-restore equivalence carries the post-cascade state (`s:`, `r:`, `c:` namespaces) across snapshot boundaries. |
| `docs/SECURITY.md` §S-017 | Producer/validator/chain alignment on the unlock-height check — the validator-side reject prevents most too-early UNSTAKE attempts from reaching apply, leaving T-K4's refund as the apply-time belt-and-suspenders that T-C3 + T-C5b inherit. |
| `docs/PROTOCOL.md` §3.3 + §6.1 | Apply rules for STAKE / DEREGISTER / UNSTAKE + the seven-Phase ordering. |
| `src/chain/chain.cpp:858–894` | Phase 1 STAKE / UNSTAKE / DEREGISTER branches. |
| `src/chain/chain.cpp:839–856` | DEREGISTER apply branch (T-K3 establishes pre-cascade `unlock_height`). |
| `src/chain/chain.cpp:880–887` | UNSTAKE refund branch (T-K4 — invoked by T-C2 + T-C3 + T-C5b). |
| `src/chain/chain.cpp:889–893` | UNSTAKE success branch (T-K5 — invoked by T-C4 + T-C5a). |
| `src/chain/chain.cpp:1344–1356` | Phase 4 equivocation forfeit branch (T-E1, T-E2 — invoked by T-C1 + T-C3 tail + T-C4 + T-C5). |
| `src/chain/chain.cpp:1393–1395` | Apply-tail accumulator fold (T-C6 A1 invariance backstop). |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion + per-field rollback diagnostic. |
| `tools/test_equivocation_multi.sh` | "Pre-deactivated equivocator" + "Equivocator with NO stake" + "Determinism" scenarios — T-C1's registry override + T-C4's locked-zero behavior + T-C7's determinism. |
| `tools/test_unstake_deregister_apply.sh` | "UNSTAKE too-early" + "UNSTAKE insufficient locked" + "UNSTAKE success after unlock" + "DEREGISTER scenario" — T-K3 setup + T-K4 refund (the building blocks of T-C2 / T-C3 / T-C5b). |
| `tools/test_supply_invariant.sh` | A1 closure across composed sequences including equivocation events — T-C6's invariance witness. |
| `tools/test_multi_event_block_apply.sh` | Multi-event-block composition; T-C5 inherits via T-M1 + T-M5. |

---

## 6. Status

All seven theorems (T-C1 through T-C7) are closed in the current codebase by structural composition of FA-Apply-10 (slash mechanics), FA-Apply-4 (UNSTAKE / DEREGISTER mechanics), and FA-Apply-15 (multi-event composition):

- **T-C1** (equivocation during deferred-unlock: full forfeit) closed via T-E1 + T-E2 firing on a `staked-pending-unlock` domain; the slash branch at `chain.cpp:1344–1356` reads `locked > 0` and zeroes it, irrespective of `unlock_height` (which the branch never touches). Regressions: `test_equivocation_multi.sh` "Pre-deactivated equivocator" + `test_unstake_deregister_apply.sh` DEREGISTER setup.
- **T-C2** (post-slash UNSTAKE refunded) closed via T-K4's refund branch firing on `locked == 0 < amount`; the disjunct at `chain.cpp:881` is satisfied unconditionally once stake is forfeited. Regression: `test_unstake_deregister_apply.sh` "UNSTAKE insufficient locked".
- **T-C3** (pre-unlock UNSTAKE + intervening slash) closed via composition of T-K4 (no mutation to `locked`) + T-C1 (slash reads post-T-K4 `locked == L`). No dedicated regression; composes from T-K4 + T-E1 via T-M5 replay determinism.
- **T-C4** (post-UNSTAKE slash: no forfeiture) closed via T-E1's no-op behavior on `locked == 0` + T-E2's unconditional registry deactivation. Regression: `test_equivocation_multi.sh` "Equivocator with NO stake".
- **T-C5** (same-block ordering) closed via T-M1's Phase ordering — Phase 1 (UNSTAKE) before Phase 4 (equivocation); the post-Phase-1 `locked` is what Phase 4 reads. T-C5a inherits from T-K5 + T-E1; T-C5b inherits from T-K4 + T-E1. Regression: `test_block_event_composition.sh` (cross-product of intentional couplings).
- **T-C6** (A1 invariance under cascade) closed via T-M3's A1 composability + the per-Phase additive accumulator updates at `chain.cpp:1393–1395` + the A1 closure at `chain.cpp:1399`. Regressions: `test_supply_invariant.sh` + `test_supply_lifecycle.sh` + `test_equivocation_apply.sh` A1 assertions.
- **T-C7** (determinism) closed via composition of T-E7 + T-K7 + T-M5 — every cascade primitive is a deterministic per-key map mutation, and replay determinism inherits structurally. Regressions: `test_equivocation_multi.sh` "Determinism" + `test_chain_save_load.sh` (snapshot roundtrip preserves cascade-induced state).

No theorem is open or partial. The proof's foundation rests entirely on prior FA-Apply theorems — FA-Apply-16 is a composition layer that names the joint property "equivocation slashing × deferred-unstake interaction is well-defined under every reachable interleaving." The contribution is to **make the order-dependence explicit** so that operator economics (the `unstake_delay_` exit horizon), wallet UX (the post-slash UNSTAKE refund), and FA6 soundness (no honest validator ever forfeits) all rest on a single named composition theorem rather than on implicit reasoning across three separate proofs.

The cascade as-implemented preserves the chain's economic model: stake is slashable while locked, recoverable post-unlock, and the slashing window cannot retroactively extend. The honest validator's exit path is therefore deterministic and bounded — a property that matters as much to permissioned-consortium operators planning rotation as to permissionless validators planning retirement. The few intentional couplings (T-C5's same-block ordering) are structurally pinned by Phase ordering, not by ad-hoc per-case logic; the chain has one apply path, not six.
