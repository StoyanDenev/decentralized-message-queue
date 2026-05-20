# FA-Apply-11 — AbortEvent apply mechanics (suspension slashing + S-032 cache)

This document formalizes the apply-layer mechanics for the `AbortEvent` baked into a finalized block. Each Phase-1 abort baked into block `B` triggers the **proportional suspension-slash** code path at `src/chain/chain.cpp:1313–1328`: it deducts a fixed `suspension_slash_` (= 10 by genesis default; see `include/determ/chain/params.hpp:65`) from the aborting domain's `stakes_[d].locked` field (floored at zero — no negative balances), increments the S-032 `abort_records_` cache (count + last_block) for `build_from_chain` to consume on snapshot replay or fresh-node bootstrap, and contributes the deducted amount to the per-block `block_slashed` accumulator that feeds the A1 unitary-supply closure at `chain.cpp:1395 / 1399`. The slashing is **deliberately proportional, not full forfeit** — Determ distinguishes "validator unavailable on Phase-1" (economic-livelihood penalty, bounded at `SUSPENSION_SLASH` per event) from "validator equivocated" (full stake confiscation + immediate deregistration, FA6 territory). This asymmetry is the design's core economic safety claim.

The proof is mechanical: each AbortEvent in `b.abort_events` is consumed by one loop body (`chain.cpp:1313–1328`) gated by `ae.round != 1` (Phase-2 skip), and the slashing arithmetic is a single `std::min(suspension_slash_, locked)` deduction. The present proof's contribution is to enumerate the eight legitimate consequences of Phase-1 abort apply, prove each preserves I-3 (balance ↔ stake independence) and I-6 (A1 contribution) from FA-Apply, document the Phase-1-only gating rationale (round=2 timing-skew aborts on healthy creators are NOT punished), and pin the test surface against regression.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6, especially I-3 (balance ↔ stake independence — abort-slashing channel: `Δlocked < 0, Δbalance == 0`); `StakeLifecycle.md` (FA-Apply-4) for the three-state stake machine and the explicit slashing-transitions enumeration in §1.2 (the `staked-active --suspension-slash--> staked-active (locked -= SUSPENSION_SLASH, bounded)` transition formalized here); `EquivocationSlashing.md` (FA6) for the contrasting **full-forfeit + deregister** apply path (the "guilt vs. unavailability" asymmetry); `SelectiveAbort.md` (FA3) for the abort-defense randomness story this slashing complements; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot ↔ replay equivalence that carries `abort_records_` via the `b:` state-root namespace; `EconomicSoundness.md` (FA11) for the A1 closure that this slashing contributes to via `accumulated_slashed_`; `docs/SECURITY.md` §S-032 for the cache contract (`build_from_chain` reads `abort_records_` instead of walking chain history).

---

## 1. Setup

### 1.1 The `AbortEvent` struct

Per `include/determ/chain/block.hpp:228–241`:

```cpp
struct AbortEvent {
    uint8_t     round{0};            // 1 (Phase-1, commit) or 2 (Phase-2, reveal)
    std::string aborting_node;       // = missing_creator from the M-1 quorum claims
    int64_t     timestamp{0};        // first quorum claim's timestamp
    Hash        event_hash{};        // SHA256(round || aborting_node || timestamp || prev_random_state)
    nlohmann::json claims_json;      // inline array of M-1 signed AbortClaimMsgs that quorumed
};
```

`b.abort_events` is `std::vector<AbortEvent>`. Each entry is the chain's deterministic record that committee member `aborting_node` failed to contribute at the specified round. The M-1 claims in `claims_json` are the validator-verified evidence of the abort — V10 of F0 binds the apply path to events that already cleared the validator's quorum check, so the apply branch can assume `aborting_node` is honestly identified.

### 1.2 The S-032 `abort_records_` cache

Per `include/determ/chain/chain.hpp:227–233 + 587`:

```cpp
struct AbortRecord {
    uint64_t count{0};
    uint64_t last_block{0};
};
std::map<std::string, AbortRecord>  abort_records_;
```

The cache exists because `build_from_chain` (the fresh-node bootstrap path that constructs `Chain` state by replaying every block) would otherwise need to walk every block's `abort_events` list per registered domain to compute the suspension-escalation trigger. The S-032 closure replaces that O(blocks · domains) walk with an O(1) map lookup at the cost of one map write per applied AbortEvent. The cache is consulted by `tools/operator_chain_health.sh` and by the producer's selection-eligibility gate (a domain with `abort_records_[d].count ≥ escalation_threshold` is candidate for governance-level intervention; the mechanics are out of scope here).

### 1.3 The Phase-1-only slashing gate

Per `chain.cpp:1313–1314`:

```cpp
for (auto& ae : b.abort_events) {
    if (ae.round != 1) continue;
    ...
}
```

The gate is the design's economic-fairness primitive. Phase-1 aborts represent a committee member who failed to publish their `ContribMsg` commitment — they were either offline, network-isolated, or deliberately withholding. Either way, the chain's progress required the remaining M-1 members to quorum the abort claim, costing real round-time. The slash recovers some of that cost.

Phase-2 aborts, by contrast, represent a committee member whose Phase-1 commit was gathered but whose Phase-2 reveal did not arrive in the BFT escalation window. This can be caused by **healthy creator timing skew** (NTP drift, packet loss at the reveal-broadcast moment, brief CPU stall) and is not economically punished — the chain still made progress via BFT, and slashing here would create false-positive risk for legitimate operators with marginal connectivity. The Phase-1 / Phase-2 distinction is also mirrored at the abort-event channel itself (`registry.cpp`'s suspension policy uses the same round-1-only filter for downstream escalation).

### 1.4 The proportional-penalty design

`suspension_slash_` is an instance-state field (`chain.hpp:589`) with a build-time default of 10 (`params.hpp:65`). It can be mutated via the A5 PARAM_CHANGE multisig (the `SUSPENSION_SLASH` key is on the whitelist; see `Governance.md` FA10). The genesis default of 10 is calibrated against `MIN_STAKE = 1000` (10 × 100 = 1000): a minimally-staked validator is exited from selection eligibility after exactly 100 Phase-1 aborts. The arithmetic is intentional — the chain's "stake-vs-suspension" relationship is fully observable at any point in time as `count` from the S-032 cache, and a validator can compute their own remaining headroom without RPC roundtrips.

The asymmetry vs. equivocation full-forfeit is the key economic-soundness claim: aborts are forgivable (slow recovery via fresh STAKE, no registry deactivation), equivocations are not (full forfeit + immediate deregistration). The motivating intuition: a validator with bad WAN connectivity should be able to recover from a bad day; a validator who double-signs is a Byzantine actor whose pool-eligibility termination is the safety property FA1 + FA6 prove out.

---

## 2. Theorems

### T-A1 — Phase-1 abort slashing

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` with `ae.round == 1`, let `d := ae.aborting_node`. If `stakes_` contains `d` with `state.stakes_[d].locked > 0`, then apply produces the deltas:

```
Δstakes_[d].locked          = −min(suspension_slash_, locked₀)
Δaccumulated_slashed_       = +min(suspension_slash_, locked₀)
Δabort_records_[d].count    = +1
Δabort_records_[d].last_block = (b.index − abort_records_[d].last_block₀)  // overwrite, not increment
```

with no other state mutation. Specifically: `accounts_[d].balance` is **unchanged** (the slashed value moves to the per-block `block_slashed` sink, not to the equivocator's spendable balance — that channel is what `accumulated_slashed_` exists to track in the A1 invariant).

*Proof sketch.* By inspection of `chain.cpp:1313–1328`. The gate at line 1314 admits the round-1 case. Line 1317 ensures the abort_records snapshot is captured (A9 atomic-apply pattern; rollback-safety). Lines 1318–1320 increment the cache: `ar.count++`, `ar.last_block = b.index`. Line 1322 looks up the stake entry; line 1323 takes the `stakes_.end()` defensive `continue` for absent stake (handled by T-A5). Line 1324 computes `deduct = std::min(suspension_slash_, locked)` — this is the floor-at-zero arithmetic without branching: when `locked < suspension_slash_`, `min` returns `locked` (full deduction); when `locked ≥ suspension_slash_`, `min` returns `suspension_slash_`. Line 1325 ensures the stakes snapshot is captured. Line 1326 debits: `sit->second.locked -= deduct`. Line 1327 accumulates: `block_slashed += deduct`, which later feeds `accumulated_slashed_ += block_slashed` at line 1395. The A1 closure at `chain.cpp:1399` confirms the slash arithmetic is supply-conserving: the slashed amount becomes unspendable (no balance credit, no fee redistribution) and the bookkeeping accumulator captures the loss. ∎

**Code witness.** `src/chain/chain.cpp:1313–1328` (the AbortEvent slash branch); `src/chain/chain.cpp:1395 / 1399` (A1 closure path); `include/determ/chain/params.hpp:65` (`SUSPENSION_SLASH` build-time default); `include/determ/chain/chain.hpp:589` (`suspension_slash_` instance state).

**Test witness.** `tools/test_abort_event_apply.sh` (`determ test-abort-event-apply`) — assertion `Phase-1 abort: alice stake 500 - SUSPENSION_SLASH(10) = 490` at `src/main.cpp:15544` exercises T-A1 directly; assertions `A1: accumulated_slashed bumped by SUSPENSION_SLASH=10` + `A1: live supply decreased by exactly the slash` + `A1 invariant: expected == live after slash` at lines 15671–15676 exercise the A1 closure.

### T-A2 — Phase-2 abort no-slash

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` with `ae.round == 2`, apply produces NO state mutation for `ae` — no stake debit, no abort_records cache update, no accumulated_slashed contribution. `Δstakes_[d].locked = 0`, `Δabort_records_[d].count = 0`, `Δaccumulated_slashed_ = 0` from this event.

*Proof sketch.* By inspection of `chain.cpp:1314`: `if (ae.round != 1) continue;`. Under the hypothesis `ae.round == 2`, the `continue` is taken before any state mutation. Lines 1315–1327 (cache update, stake lookup, deduct arithmetic, accumulator) are unreached for this event. The next iteration of the loop processes the next `ae` independently. The rationale: Phase-2 timing-skew on healthy creators (NTP drift, brief network blip at the reveal-broadcast moment) is not a slashable offense — the chain still finalized via the BFT escalation path, and economically punishing here would create false-positive risk for honest operators with marginal connectivity. ∎

**Code witness.** `src/chain/chain.cpp:1314` (the round-1-only filter, the design's "guilt vs. timing-skew" primitive).

**Test witness.** `tools/test_abort_event_apply.sh` — assertions `Phase-2 abort: stake unchanged (timing-skew not slashed)` + `Phase-2 abort: abort_records NOT incremented` at `src/main.cpp:15590–15593` exercise T-A2 directly.

### T-A3 — S-032 abort_records cache update

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` with `ae.round == 1`, let `d := ae.aborting_node`. Apply increments `abort_records_[d].count` by exactly 1 and sets `abort_records_[d].last_block = b.index` (overwrite, not max — see Discussion §4). The increment is unconditional on the stake lookup at line 1322; the cache is updated even when `d` is not present in `stakes_` (the DOMAIN_INCLUSION mode path, covered by T-A5).

*Proof sketch.* By inspection of `chain.cpp:1315–1320`. The cache write is sequenced BEFORE the stake lookup at line 1322. Line 1317 captures the abort_records snapshot for atomic-apply rollback. Line 1318 accesses `abort_records_[d]` (note: `std::map::operator[]` creates the entry with default-constructed `AbortRecord{count:0, last_block:0}` if not present). Line 1319 increments `count`. Line 1320 writes `last_block = b.index`. The two writes are sequential and atomic per the surrounding `try { ... }` block (A9 atomic-apply guarantees rollback on any subsequent throw). The cache update is the load-bearing S-032 mechanism: `build_from_chain` reads `abort_records_` on bootstrap rather than re-walking every block's `abort_events` vector. The "set, not max" overwrite of `last_block` is deliberate — `last_block` is the most-recent-block sentinel, not a high-water mark; blocks apply in monotonic index order so the overwrite is equivalent to a max in practice, but the simpler write is what the code uses. ∎

**Code witness.** `src/chain/chain.cpp:1315–1320` (the cache update); `include/determ/chain/chain.hpp:227–233` (`AbortRecord` struct definition + getter); `include/determ/chain/chain.hpp:587` (`abort_records_` field); `include/determ/chain/chain.hpp:286` (the `b:` state-root namespace key encoding — `"b:" + domain`).

**Test witness.** `tools/test_abort_event_apply.sh` — assertions `abort_records: alice count incremented to 1` + `abort_records: alice last_block == 1` at `src/main.cpp:15564–15569` exercise T-A3 directly.

### T-A4 — No registry deactivation

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` (round=1 or round=2), let `d := ae.aborting_node`. Apply does NOT modify `registrants_[d]`. Specifically: `Δregistrants_[d].inactive_from = 0`, `Δregistrants_[d].active_from = 0`. The aborting node remains in the selection-eligibility pool exactly as before the apply. Future blocks may still select `d` as a committee member.

*Proof sketch.* By inspection of `chain.cpp:1313–1328`. The AbortEvent loop body's write set comprises (a) `abort_records_[d]` (lines 1318–1320), (b) `stakes_[d].locked` (line 1326), (c) `block_slashed` (line 1327, a per-block accumulator), and (d) the snapshot-capture lambdas (`__ensure_abort_records`, `__ensure_stakes`, no `__ensure_registrants` call). `registrants_` is never accessed inside the AbortEvent branch — neither read nor write. This is in stark contrast to the EquivocationEvent branch at `chain.cpp:1351–1355` which DOES set `registrants_[d].inactive_from = b.index + 1` (the full FA6 deregistration). The asymmetry is the design's "guilt vs. unavailability" primitive: an aborting validator is presumed available-but-late (their stake is the price of late delivery), not Byzantine (which is what the equivocation deregistration handles). The aborting validator's recovery path is straightforward: continue running, gather their next-round committee selection, and contribute normally — no fresh REGISTER needed. ∎

**Code witness.** `src/chain/chain.cpp:1313–1328` (the AbortEvent branch with no `registrants_` write); compare with `src/chain/chain.cpp:1351–1355` (the EquivocationEvent branch that DOES deregister).

**Test witness.** Not directly tested as a negative assertion in `test_abort_event_apply`, but structurally guaranteed by the absence of any `registrants_` write in the loop body. The complementary EquivocationEvent test at `tools/test_equivocation_apply.sh` covers the inverse property (equivocation DOES deregister, with the inactive_from = b.index + 1 invariant).

### T-A5 — Aborts on zero-stake nodes (DOMAIN_INCLUSION)

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` with `ae.round == 1` and `d := ae.aborting_node` such that either (a) `stakes_` does not contain `d`, or (b) `stakes_[d].locked == 0`, apply produces the deltas:

```
Δstakes_[d].locked          = 0     (no stake to deduct, or already zero)
Δaccumulated_slashed_       = 0     (deduct returned zero from std::min)
Δabort_records_[d].count    = +1    (cache still tracks the abort)
Δabort_records_[d].last_block = b.index  (overwrite)
```

with no other state mutation. The cache update is decoupled from the stake deduction — DOMAIN_INCLUSION mode chains (where `min_stake_ == 0` and validators carry no stake) still produce auditable abort traces, enabling escalation logic to fire even without economic punishment via the stake channel.

*Proof sketch.* By inspection of `chain.cpp:1315–1327`. Lines 1315–1320 unconditionally update `abort_records_[d]` (the cache update runs before the stake lookup). At line 1322 the stake lookup `auto sit = stakes_.find(d)` returns `stakes_.end()` for case (a), triggering the `continue` at line 1323 — exit the iteration with no stake mutation. For case (b) where the entry exists but `locked == 0`, line 1324 computes `deduct = std::min(suspension_slash_, 0) = 0`; line 1326 writes `locked -= 0` (no-op); line 1327 writes `block_slashed += 0` (no-op). In both subcases the cache write at lines 1318–1320 persists, the stake deduction is zero, and the A1 contribution from this event is zero. The decoupling is intentional: the cache exists to track validator behavior independent of the economic channel, which is what makes DOMAIN_INCLUSION mode coherent for permissioned-consortium deployments. ∎

**Code witness.** `src/chain/chain.cpp:1322–1323` (defensive `stakes_.end()` check); `src/chain/chain.cpp:1324` (the `std::min` floor at 0 via the locked operand); `src/chain/chain.cpp:1315–1320` (the cache write that survives the stake-lookup skip).

**Test witness.** `tools/test_abort_event_apply.sh` — assertions `no-stake abort: no stake change (sender has none)` + `no-stake abort: records incremented (S-032 cache contract)` at `src/main.cpp:15616–15619` exercise T-A5 directly with `aborting_node="bogus_no_stake"`.

### T-A6 — Stake exhaustion

**Statement.** For every domain `d` and every sequence of `n ≥ 1` Phase-1 AbortEvents at consecutive blocks targeting `d`, if `n ≥ ⌈stake₀ / suspension_slash_⌉` (where `stake₀` is `d`'s `locked` value before the first abort), then after applying all `n` events: `stakes_[d].locked == 0`, `accumulated_slashed_` has been incremented by exactly `stake₀` (the initial locked balance is fully drained), and `abort_records_[d].count == n` (the cache keeps tracking past the exhaustion boundary). Subsequent Phase-1 aborts on `d` produce zero stake deduction (covered by T-A5) but continue to increment `abort_records_[d].count`.

*Proof sketch.* By induction on `i = 1, 2, …, n`. Base case `i = 1`: by T-A1, `stakes_[d].locked` decreases by `min(suspension_slash_, stake₀) = suspension_slash_` (since by hypothesis `stake₀ ≥ suspension_slash_` for the typical case; the edge case where `stake₀ < suspension_slash_` collapses to a single-event full-drain by `std::min` flooring). Inductive step `i → i+1`: assume after `i` aborts the locked balance is `stake_i = stake₀ − i · suspension_slash_` (clamped at zero). Apply the `(i+1)`-th abort: if `stake_i ≥ suspension_slash_`, the deduct is `suspension_slash_` and `stake_{i+1} = stake_i − suspension_slash_`; if `stake_i < suspension_slash_` (including zero), the deduct is `stake_i` (by `std::min`) and `stake_{i+1} = 0`. After exactly `n = ⌈stake₀ / suspension_slash_⌉` iterations the cumulative deduction reaches `stake₀` (the final iteration may be a partial deduct, but the sum is exact). Beyond this point, additional aborts continue to update the cache (T-A3) but produce zero stake deduction (T-A5 case (b)). The `accumulated_slashed_` contribution after exhaustion is `stake₀` (exactly the initial locked balance, no more, no less), confirming the A1 supply closure: nothing was minted or burned beyond the initial-stake budget. ∎

**Code witness.** `src/chain/chain.cpp:1324` (the `std::min(suspension_slash_, locked)` flooring); `src/chain/chain.cpp:1326–1327` (the deduct + accumulator).

**Test witness.** `tools/test_abort_event_apply.sh` — the "Stake exhaustion (no negative)" scenario at `src/main.cpp:15627–15650` runs 51 Phase-1 aborts on stake=500 / suspension_slash=10 (51 × 10 = 510 > 500). Assertions `exhausted stake: 51 aborts drains stake to 0 (no negative)` + `exhausted stake: abort_records.count == 51 (cache still tracks)` confirm both the flooring (locked ≥ 0) and the cache-keeps-tracking property (count = 51 after exhaustion).

### T-A7 — A1 invariance per Phase-1 abort

**Statement.** For every block `B` containing an AbortEvent `ae ∈ B.abort_events` with `ae.round == 1` and `d := ae.aborting_node`, the per-block `block_slashed` accumulator increases by exactly the deducted amount: `Δblock_slashed = min(suspension_slash_, stakes_[d].locked₀)`. The block-tail A1 closure at `chain.cpp:1395 / 1399` then composes this into `accumulated_slashed_ += block_slashed`, and the unitary-supply invariant `actual_total == expected_total` (where the expression at lines 1413–1417 deducts `accumulated_slashed_` from `genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ − accumulated_outbound_`) continues to hold.

*Proof sketch.* By inspection of `chain.cpp:1327`: `block_slashed += deduct;`. The deduct value comes from line 1324: `deduct = std::min(suspension_slash_, sit->second.locked)`. The accumulator at lines 1393–1395 then composes per-event slashes into the per-block sum, and lines 1395 + 1399 propagate to the chain-wide accumulator: `accumulated_slashed_ += block_slashed`. The A1 closure at line 1399 evaluates `expected = expected_total()` and `actual = live_total_supply()` — the live supply counts balances + stakes (every value not yet slashed), and the expected total subtracts `accumulated_slashed_` from the supply ceiling. If the slash arithmetic at line 1326 (which debits `stakes_[d].locked`) matches the accumulator at line 1327, the difference between expected and actual is exactly zero. Any mismatch would throw at line 1418 (the `unitary-balance invariant violated` runtime_error with the diagnostic breakdown). The per-event A1 contribution is thus the slash-deduct amount: `accumulated_slashed_ += min(suspension_slash_, locked₀)` per Phase-1 event, with the boundary case `locked₀ < suspension_slash_` correctly contributing `locked₀` (not `suspension_slash_`) — the `std::min` is the per-event A1-correctness primitive. ∎

**Code witness.** `src/chain/chain.cpp:1324` (deduct computation); `src/chain/chain.cpp:1326–1327` (the stake debit + accumulator); `src/chain/chain.cpp:1395` (`accumulated_slashed_ += block_slashed`); `src/chain/chain.cpp:1399` (the A1 closure assertion).

**Test witness.** `tools/test_abort_event_apply.sh` — the "A1 invariant holds across slashing" scenario at `src/main.cpp:15655–15677` exercises T-A7 with three assertions: `accumulated_slashed bumped by SUSPENSION_SLASH=10`, `live supply decreased by exactly the slash`, `expected == live after slash`. Composed with `tools/test_supply_lifecycle.sh` which runs the full A1 invariant across a multi-channel apply sequence.

### T-A8 — Determinism

**Statement.** For every chain state `state` and every block `B` with identical `abort_events` ordering, two independent invocations of `apply_transactions(B)` from `state` produce identical post-apply state — identical `stakes_[d].locked` for every `d`, identical `abort_records_[d]` for every `d`, identical `accumulated_slashed_`. The ordering is fully determined by the producer's block construction at `make_canonical_block`; the apply path consumes the vector in iteration order.

*Proof sketch.* By inspection of `chain.cpp:1313–1328`. The loop body is a deterministic function of (a) the AbortEvent fields (`round`, `aborting_node`), (b) the current `stakes_[d]` value, (c) the current `abort_records_[d]` value, and (d) the chain instance state (`suspension_slash_`). No I/O, no randomness, no system-clock reads, no map iteration that depends on iteration order beyond what the vector's index provides. The std::map writes (`abort_records_[d]`, `stakes_[d]`) are deterministic in C++ for the same key sequence and value writes. The `std::min(suspension_slash_, locked)` arithmetic is pure (integer comparison). The accumulator increment at line 1327 is sequential. Re-running the same loop on identical input produces byte-identical post-state — this is what makes snapshot replay (T-S2 of FA-Apply-2) work for abort_records, and what makes cross-shard apply equivalence work in EXTENDED mode (the `b:` namespace contributes to the state_root, so any non-determinism would surface as a state_root mismatch on snapshot restore). ∎

**Code witness.** `src/chain/chain.cpp:1313–1328` (the deterministic loop body); `include/determ/chain/chain.hpp:286` (the `b:` state-root namespace, which makes abort_records part of the S-033 commitment — any non-determinism would be caught by the state_root gate).

**Test witness.** Determinism is exercised structurally by `tools/test_chain_save_load.sh` (snapshot roundtrip determinism — abort_records survive the serialize-restore cycle byte-identically) and by `tools/test_chain_apply_block.sh` (per-apply determinism — re-applying the same block sequence produces identical state). The S-033 state_root gate is the runtime mechanism that would surface a determinism violation: a non-deterministic abort apply would produce a different state_root on the second apply, and the validator's V14 (state_root match) would reject the block.

---

## 3. Abort vs equivocation slashing

The chain has two on-chain "slashing" channels with deliberately asymmetric semantics. Pinning the asymmetry explicitly is the core economic-soundness primitive:

| Dimension | Phase-1 abort (this proof) | Equivocation (FA6) |
|---|---|---|
| Penalty | Proportional: `suspension_slash_ = 10` per event | Full forfeit: `locked := 0` |
| Registry effect | None — node stays in pool | `inactive_from = b.index + 1` (immediate deregister) |
| Future selection | Eligible (subject to remaining stake ≥ `min_stake_`) | Ineligible until fresh REGISTER on a new domain |
| Recovery path | Fresh STAKE tx; no re-REGISTER needed | Must register a brand-new domain (the offending one is permanently inactive) |
| S-032 cache | Updated (`count++`, `last_block = b.index`) | Not touched |
| Apply branch | `chain.cpp:1313–1328` | `chain.cpp:1344–1356` |
| Underlying evidence | M-1 signed AbortClaimMsgs (V10 quorum) | Two distinct sigs over distinct digests (V11 cryptographic) |
| False-positive risk | Possible (network blip on a healthy creator) — bounded at `suspension_slash_` | None (FA6 §1 theorem: ≤ 2⁻¹²⁸ per fabrication attempt) |
| Cumulative cap | Bounded by initial stake (`⌈stake₀ / suspension_slash_⌉` events drains to zero) | Unbounded slashing impossible (one-shot full forfeit) |
| Slash semantics | Economic livelihood penalty | Cryptographic guilt finding |

**Why the asymmetry matters for the protocol's safety story.** FA1 (BFT safety) depends on `f < N/3` Byzantine validators. The equivocation slash is what enforces this bound — a Byzantine validator who double-signs is **permanently removed** from the pool, so their stake-weighted vote is gone and the `f < N/3` boundary is restored. The abort slash, by contrast, does NOT remove the validator from the pool — a slow validator still counts toward `N`, and their stake is still part of the security budget (just diminished). This is the right design because abort behavior alone is not Byzantine — a validator who is slow but honest should be able to recover; permanently removing them on a single timeout would create a partition-attack surface (an attacker who can briefly DoS K-1 validators could force their permanent removal via abort cascades, fundamentally damaging the chain's liveness).

The proportional penalty also has a sanity-check economic property: at `suspension_slash_ = 10` and `min_stake_ = 1000`, a validator can absorb up to 100 Phase-1 aborts before their stake drops below the eligibility threshold. This gives an operator with marginal connectivity a multi-hour buffer to fix their NTP / firewall / peer list before being pushed out of selection. Equivocation has no such buffer because there is no honest interpretation — a validator who signs two conflicting digests has provably violated H2 (Preliminaries §4), and the design's job is to remove them immediately.

**Where the two channels interact.** A validator can be both equivocation-slashed AND abort-slashed in the same block (the two loops at `chain.cpp:1313–1328` and `chain.cpp:1344–1356` run sequentially within one apply). The interaction is benign: the abort slash runs first (deduct `suspension_slash_`), then the equivocation slash runs (zero whatever remains + deregister). The A1 accumulator captures both contributions cleanly. In practice this co-occurrence is rare (a validator equivocating on the same block they aborted is structurally an edge case — abort means they failed to commit at all, equivocation means they signed two conflicting things, so the two events on the same block require very specific timing). The apply path handles it correctly without special-casing.

---

## 4. What this doesn't prove

The theorems above target the AbortEvent apply branch in isolation. They do not extend to:

- **The validator's V10 abort-quorum check itself.** T-A1 presumes `ae` was admitted by V10 (the M-1 signed AbortClaimMsgs cleared the validator's quorum-evidence check at block-validation time). The cryptographic soundness of V10 (i.e., that the M-1 claims couldn't have been forged by the producer to slash an honest validator) is the scope of the producer/validator integration tests (`tools/test_abort_event_apply` covers apply; `tools/test_abort_quorum.sh` and the network-level multi-node abort-injection scripts cover the V10 evidence path).
- **The producer's abort-detection logic.** Whether a producer correctly identifies "aborting_node" as the missing creator at a given round is `src/node/producer.cpp`'s scope. A producer that misidentifies the abort target would produce an AbortEvent that the validator's V10 would still pass (the claims are signed and quorumed), so the slash would land on the wrong domain. This is a "garbage-in / garbage-out" scenario — the chain's apply correctly slashes whoever the AbortEvent names, but the naming is upstream of this proof.
- **The escalation policy that consumes the S-032 cache.** Future blocks may consult `abort_records_[d].count` to decide whether `d` should be force-deregistered, force-rebooted, or governance-flagged. The mechanics of that escalation policy are in `registry.cpp` and the producer's selection-eligibility gate; the present proof only pins that the cache is populated correctly.
- **Cross-shard abort propagation.** A validator on shard `S_X` who aborts is slashed on shard `S_X` by the local AbortEvent apply. Whether that slash propagates to shard `S_Y` (e.g., if the validator was beacon-anchored on both shards) is the scope of FA8 (regional sharding) and the cross-shard receipt apply (FA-Apply-2's namespace coverage includes the `i:` applied_inbound_receipts namespace, separate from the `b:` abort_records namespace). The present proof assumes single-shard or local-shard-only context.
- **Apply-failure rollback semantics for abort_records and stakes.** The A9 atomic-apply property at `chain.cpp:671–1499` (`AccountStateInvariants.md` §1.2) ensures that any throw inside the apply path (S-007 overflow, A1 violation, S-033 mismatch) rolls back `abort_records_` and `stakes_` along with the other maps. The `__ensure_abort_records()` and `__ensure_stakes()` calls at lines 1317 + 1325 capture the snapshots before the per-event writes. The present proof's deltas are stated for **successful applies only**; rollback semantics are inherited from FA-Apply's §1.2 framing.
- **Snapshot restore preserves abort_records.** The `abort_records_[d]` (count, last_block) tuple is included in the `b:` namespace of the S-033 state-root commitment (`AccountStateInvariants.md` I-3 + `SnapshotEquivalence.md` L-S0). Restore equivalence (T-S1, T-S2 of FA-Apply-2) carries abort_records across snapshot boundaries. The present proof's cache-state deltas compose through snapshot restore by T-S2; no re-derivation here.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V10 (abort-quorum evidence check); V14 (state_root match after apply) — both gate the apply path. |
| `AccountStateInvariants.md` (FA-Apply) | I-3 (balance ↔ stake independence — abort slashing is `Δlocked < 0, Δbalance == 0`); I-6 (A1 contribution via `accumulated_slashed_`). |
| `StakeLifecycle.md` (FA-Apply-4) | §1.2 state machine — the `staked-active --suspension-slash--> staked-active (locked -= SUSPENSION_SLASH, bounded)` transition formalized here. |
| `EquivocationSlashing.md` (FA6) | The contrasting full-forfeit + deregister channel. T-A4 + §3 explicitly contrast with FA6's apply path. |
| `SelectiveAbort.md` (FA3) | The abort-defense randomness story this slashing complements — selective aborts are economically costly per T-A1, removing the predictive-bias incentive that FA3 covers cryptographically. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1, T-S2 — `abort_records_` is in the `b:` state-root namespace; snapshot replay equivalence carries the cache across restore boundaries. |
| `EconomicSoundness.md` (FA11) | T-12 A1 unitary-balance closure; abort slashing contributes to `accumulated_slashed_` per T-A7. |
| `Governance.md` (FA10) | A5 PARAM_CHANGE whitelist — `SUSPENSION_SLASH` is on the whitelist, mutable via N-of-N multisig. |
| `docs/SECURITY.md` §S-032 | The abort_records cache contract (`build_from_chain` reads `abort_records_` instead of walking history); the present proof's T-A3 is the apply-side counterpart of S-032's load-side correctness. |
| `docs/SECURITY.md` §S-035 | The unit-test-edge-cases note that this proof's `test_abort_event_apply` regression is part of. |
| `docs/PROTOCOL.md` §6.1 | Apply rules for abort_events; the round-1-only filter and the proportional-penalty design. |
| `docs/WHITEPAPER-v1.x.md` §3.4 | The economic-disincentive narrative for abort vs. equivocation; the proportional/full-forfeit asymmetry. |
| `tools/test_abort_event_apply.sh` | T-A1 + T-A2 + T-A3 + T-A5 + T-A6 + T-A7 (~12 assertions across six scenarios — Phase-1 slashing, Phase-2 no-slash, S-032 cache, no-stake DOMAIN_INCLUSION mode, stake exhaustion, A1 closure; see `determ test-abort-event-apply`). |
| `tools/test_equivocation_apply.sh` | The contrasting FA6 apply path; T-A4's "no deregistration" property is the inverse of the equivocation test's deregistration assertion. |
| `tools/test_supply_lifecycle.sh` | Composed A1 conservation across the abort-slash channel + other channels (subsidy, fees, inbound receipts). |
| `tools/test_chain_save_load.sh` | T-A8 determinism witness (snapshot roundtrip preserves abort_records byte-identically). |
| `include/determ/chain/block.hpp:228–241` | `AbortEvent` struct. |
| `include/determ/chain/chain.hpp:227–233` | `AbortRecord` struct + `abort_records()` getter. |
| `include/determ/chain/chain.hpp:286` | `b:` state-root namespace key encoding. |
| `include/determ/chain/chain.hpp:587` | `abort_records_` field. |
| `include/determ/chain/chain.hpp:589` | `suspension_slash_` instance state (A5 PARAM_CHANGE mutable). |
| `include/determ/chain/params.hpp:65` | `SUSPENSION_SLASH` build-time default (= 10). |
| `src/chain/chain.cpp:1313–1328` | The AbortEvent apply branch (T-A1 through T-A8). |
| `src/chain/chain.cpp:1344–1356` | The EquivocationEvent apply branch (contrasting FA6 channel; §3 comparison). |
| `src/chain/chain.cpp:1395` | `accumulated_slashed_ += block_slashed` per-block composition. |
| `src/chain/chain.cpp:1399` | A1 unitary-balance closure assertion. |

---

## 6. Status

All eight theorems (T-A1 through T-A8) are closed in the current codebase:

- **T-A1** (Phase-1 abort slashing) closed via the `std::min(suspension_slash_, locked)` deduct + `block_slashed += deduct` accumulator at `chain.cpp:1324–1327`; regression `test_abort_event_apply.sh` "Phase-1 slashing" scenario.
- **T-A2** (Phase-2 abort no-slash) closed via the `if (ae.round != 1) continue;` gate at `chain.cpp:1314`; regression `test_abort_event_apply.sh` "Phase-2 no-slashing" scenario.
- **T-A3** (S-032 abort_records cache update) closed via the `ar.count++; ar.last_block = b.index;` writes at `chain.cpp:1318–1320`; regression `test_abort_event_apply.sh` "S-032 abort_records cache" scenario.
- **T-A4** (no registry deactivation) closed by structural absence of `registrants_` writes in the AbortEvent loop body; complementary equivocation test at `test_equivocation_apply.sh` covers the inverse property.
- **T-A5** (aborts on zero-stake DOMAIN_INCLUSION mode) closed via the `stakes_.find / continue` defense + the cache-write-before-stake-lookup sequencing at `chain.cpp:1315–1323`; regression `test_abort_event_apply.sh` "Aborted-without-stake" scenario.
- **T-A6** (stake exhaustion) closed via the `std::min` flooring at `chain.cpp:1324` + the cache-keeps-tracking property at lines 1318–1320; regression `test_abort_event_apply.sh` "Stake exhaustion" scenario (51 aborts on stake=500, slash=10).
- **T-A7** (A1 invariance per Phase-1 abort) closed via the `block_slashed += deduct` per-event composition + the chain-tail `accumulated_slashed_ += block_slashed` + the A1 closure at `chain.cpp:1395 / 1399`; regression `test_abort_event_apply.sh` "A1 invariant" scenario.
- **T-A8** (determinism) closed structurally by the pure-function nature of the loop body (no I/O, no randomness, no clock reads) + the `b:` namespace's contribution to the S-033 state_root commitment; regression `test_chain_save_load.sh` snapshot roundtrip determinism.

No theorem is open or partial. The S-032 cache contract (closed via the apply-side cache write per T-A3) and the snapshot-restore equivalence (T-S2 of FA-Apply-2 carrying abort_records across boundaries via the `b:` namespace) compose cleanly with the proof's deltas — a snapshot taken after a Phase-1 abort and restored on a fresh node produces byte-identical `abort_records_[d]` state, byte-identical `stakes_[d].locked` state, and a byte-identical `accumulated_slashed_` accumulator. This composition is the load-bearing operational property for fresh-node bootstrap and snapshot-based recovery; the present proof's apply-side correctness is the precondition.

The proof's foundation rests on a small set of code primitives: the round-1 gate at `chain.cpp:1314`, the `std::min(suspension_slash_, locked)` flooring at line 1324, the cache-write-before-stake-lookup sequencing at lines 1315–1322, and the per-block `block_slashed` accumulator that feeds the chain-wide A1 invariant. The breadth of consequences — eight theorems, a documented asymmetry vs. equivocation full-forfeit, an explicit DOMAIN_INCLUSION mode story, and a regression scenario covering each — is testimony to how few primitives the chain needs to express the proportional-penalty design.
