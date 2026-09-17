# FA-Apply-10 — The equivocation-evidence apply path (state-neutral since D4)

> **RESTATED 2026-09-17 (sequence step 3c; owner decision D4, DECISION-LOG 2026-09-16 — landed as O-1 step 3a).**
> **This document's subject no longer exists.** The forfeiture + deregistration loop was removed from
> `Chain::apply_transactions`; an `EquivocationEvent` moves NO L1 state. The shipped apply-side
> theorem is **T-E0 (§2.0)** — state neutrality — and it is the only theorem of this document that
> describes HEAD. **T-E1 through T-E7 (§2.1) are retained as the HISTORICAL record of the removed
> mechanism** and are clearly marked as such; they must not be cited as current, and no other proof
> in this corpus may consume them. The D13 companion applies to §1.3 only: the `block_slashed`
> accumulator also lost its other producer (the Phase-1 abort deduction), so it is frozen at 0.

This document formalizes the apply-layer treatment of an `EquivocationEvent` baked into a finalized block. **At HEAD that treatment is: nothing happens.** `Chain::apply_transactions` contains no loop over `b.equivocation_events` at all — only a comment block recording the decision. No stake is forfeited, no registry entry is deactivated, no counter advances, no abort record is touched. The event is validated upstream by V11 (`src/node/validator.cpp::check_equivocation_events`) and is committed inside the block body and the block hash; that commitment IS its entire effect, and it exists because the record is the declared input to the L2 bond policy (D22).

The proof is therefore a **neutrality** proof rather than a mechanics proof, and it is one paragraph long (§2.0) backed by a falsify-on-mutant gate. What remains load-bearing is the division of labour with FA6 (`EquivocationSlashing.md`), restated: FA6 proves an accepted event names only the guilty (no false accusation, under EUF-CMA and its H3 boundary); FA-Apply-10 proves the chain does nothing with that fact. The two together are the whole of L1's equivocation handling.

**Companion documents:** `Preliminaries.md` (F0) §9 for what an equivocation event is and does since D4, and for V11; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6 — note the equivocation channel now touches none of them; `EquivocationSlashing.md` (FA6) for the no-false-accusation bound the record carries; `StakeLifecycle.md` (FA-Apply-4) for the stake machine, from which the equivocation transition has been REMOVED; `StakeForfeitureCascade.md` (FA-Apply-16) for the cascade that is now vacuous on one of its two channels.

---

## 0. HISTORICAL — ⚠ Soundness correction (2026-07-28): registry deactivation is NOT permanent; re-REGISTER re-activates

> **MOOT since 2026-09-16 (D4).** Equivocation no longer deactivates anything, so there is nothing for a re-REGISTER to undo. This section is retained as the record of a defect in the removed mechanism and of the owner escalation it produced — which D4 answers: no L1 exclusion, ever.

A round-3 adversarial proof-claim audit (`wf_97a30e14`, independently verified) found that the "re-activation closed / the offender must register a fresh domain" claim (T-E2, §3 asymmetry table, §5, §7) is **false**. The REGISTER apply branch (`src/chain/chain.cpp:1231-1296`) has **no `registrants_.contains(d)` skip**: it computes `first_time_register` only to gate the Negative-Entry-Fee pool drain (`:1282`), then **unconditionally** builds a fresh `RegistryEntry` with `inactive_from = UINT64_MAX` + fresh `active_from` and does `registrants_[tx.from] = e` (`:1260-1264`), overwriting the equivocation-deactivated entry (the inline comment `:1249-1253` confirms re-registration is a supported overwrite path for key-rotation/region-update). The validator REGISTER case (`validator.cpp:709-710`) is a bare `break`.

**Consequence.** A slashed equivocator submits REGISTER for the **same** domain → `inactive_from` resets to `UINT64_MAX` → eligible again after `derive_registration_delay`. In **DOMAIN_INCLUSION mode** (`min_stake_ == 0`, which §3/T-E4 treat as supported and where registry deactivation is the *entire* penalty) this re-activates at **zero lasting cost** — a repeatable Byzantine equivocation with no permanent removal, defeating the FA6 deterrent this proof exists to back. (In STAKE_INCLUSION mode the T-E1 stake burn still stands, but the "permanent removal / fresh domain required" claim is still false and the same domain identity is reused.) The §3 asymmetry (DEREGISTER re-activation "Open" vs equivocation "Closed") is impossible — both are indistinguishable `registrants_` entries hitting the same overwriting REGISTER path. **Status: OWNER-ESCALATED** (a slash-lockout / cooldown policy that distinguishes slash-deactivation from voluntary DEREGISTER is a consensus/state-format decision → owner-gated). The T-E1 stake-forfeiture and T-E3 ghost-record results are unaffected; it is the registry-permanence claim that fails.

## 1. Setup

### 1.1 The `EquivocationEvent` struct

Per `include/determ/chain/block.hpp:256–279`:

```cpp
struct EquivocationEvent {                   // EQV-height-bind form, 2026-08-12
    std::string equivocator;          // domain whose key signed both digests
    uint64_t    block_index{0};       // height at which equivocation occurred
    uint8_t     kind{0};              // 0 = BLOCK_DIGEST, 1 = CONTRIB_COMMIT; > 1 rejected
    uint64_t    index_a{0};           // side-a opening: signed height
    Hash        body_root_a{};        // side-a opening: digest body root
    Signature   sig_a{};
    uint64_t    index_b{0};
    Hash        body_root_b{};
    Signature   sig_b{};
    uint32_t    shard_id{0};
    uint64_t    beacon_anchor_height{0};
};
```

The `equivocator` field names the offending domain. V11 (Preliminaries §5) requires `kind ≤ 1`, `index_a = index_b = block_index` (the height assert), `body_root_a ≠ body_root_b`, `sig_a ≠ sig_b`, and that both signatures verify against digests the validator DERIVES as `SHA256(TAG(kind) ‖ index u64 BE ‖ body_root)` — the digests are no longer carried (`digest_a`/`digest_b` were deleted 2026-08-12). **Nothing in this proof reads those fields**, so every theorem below is unaffected; the struct is reproduced here only so the apply-side reader sees the current shape. The cross-chain fields (`shard_id`, `beacon_anchor_height`) are forensic — they route the slash through the beacon in cross-shard mode (FA6 Corollary T-6.1) but do not affect the apply-side mechanics, which key on `ev.equivocator` only.

### 1.2 The apply branch

**At HEAD there is none.** `Chain::apply_transactions` iterates `b.abort_events` (the S-032 record; D13) and `b.inbound_receipts`, and between them carries only a comment stating that an `EquivocationEvent` is an evidence record with no L1 consequence and naming D4 as the authority. `grep -n equivocation_events src/chain/chain.cpp` returns that comment and nothing else.

**HISTORICAL — the removed branch**, as it stood until 2026-09-16, retained here so the removal can be read against something:

```cpp
// REMOVED 2026-09-16 (D4, O-1 step 3a) — retained as the historical record.
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

Three structural properties **of the removed branch** (historical):

1. **Dual mechanism.** A single equivocation triggers TWO writes: stake forfeiture (lines 1346–1350) AND registry deactivation (lines 1351–1355). Either may be a no-op if the corresponding map entry is absent. The dual mechanism unifies STAKE_INCLUSION mode (where the stake-zeroing is the primary disincentive) and DOMAIN_INCLUSION mode (where stake is already 0 and the registry deactivation is what actually removes the offender from selection).
2. **Independent guards.** The `sit != stakes_.end()` and `rit != registrants_.end()` checks are independent. A domain that has unstaked but is still registered will have its registry deactivated without a stake write (the stake-guard fails). A domain that staked but never registered (an impossible state on an honest chain — STAKE requires REGISTER per `chain.cpp:807–811` — but defensively handled) would have its stake forfeited without a registry write. The all-paths-defensive design is what makes T-E4 (ghost-equivocator robustness) hold without source-side changes.
3. **`block_slashed` accumulation.** The line-1348 `block_slashed += sit->second.locked` reads the pre-write value of the locked stake, so a subsequent event for the same domain (now with `locked == 0`) contributes zero. This is what makes T-E3 (idempotent re-apply within a block) hold by construction.

### 1.3 The `block_slashed` → `accumulated_slashed_` accumulator — now frozen at 0

The declaration survives in `Chain::apply_transactions` and its comment states the fact:

```cpp
uint64_t block_slashed  = 0;   // frozen at 0: no apply path credits it since D13 (abort
                               // deduction retired) and D4 (equivocation forfeiture removed)
```

`block_slashed` is a per-block u64 accumulator declared at the top of `apply_transactions`. It used to capture the Phase-1 abort deduction (retired by D13, 2026-09-16) and the equivocation forfeiture (removed by D4, 2026-09-16). **Both producers are gone, so it is never incremented and `accumulated_slashed_` never grows.** The variable, the `c:accumulated_slashed` state-root leaf, both snapshot containers and the A1 term are deliberately retained with their shapes unchanged: removing them is a state-format change and there are no migrations. At apply-tail:

```cpp
accumulated_slashed_  += block_slashed;
```

the per-block accumulator folds into the chain-wide `accumulated_slashed_` counter. The A1 closure at `chain.cpp:1397–1419` then consumes `accumulated_slashed_` as one of the six terms in `expected_total = genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ - accumulated_slashed_ - accumulated_outbound_ - accumulated_shielded_` and asserts `live_total_supply() == expected_total`. Any equivocation-slash that produced an off-by-one accumulator update would surface here as a thrown `runtime_error` with the per-field delta diagnostic.

---

## 2. Theorems

### 2.0 T-E0 — Apply is state-neutral on `b.equivocation_events` (THE SHIPPED THEOREM)

**Statement.** Let `S` be the chain state before applying block `B`, and let `B′` be `B` with
`B′.equivocation_events = []` and every other field unchanged. Then `apply_transactions(S, B)` and
`apply_transactions(S, B′)` produce **byte-identical state**: every account balance and nonce, every
`stakes_` entry (`locked` and `unlock_height`), every `registrants_` entry (`active_from` and
`inactive_from`), every `abort_records_` entry, and all six A1 counters are equal, and the two runs
reach the same `compute_state_root()`. Blocks `B` and `B′` differ in their own hash (the events are
inside `signing_bytes` and inside the digest's reconciled eq-root), so the *record* is committed —
but no state leaf moves.

**Proof.** By inspection: `Chain::apply_transactions` contains no read of any field of
`b.equivocation_events`. The identifier appears exactly once in `src/chain/chain.cpp`, in the comment
that records D4. Since the function's output is a deterministic function of `(S, B)` and the only
part of `B` that differs is a field the function never reads, the outputs coincide. ∎

**Gate (falsify-on-mutant, at the layer where the rule lives).** `determ test-equivocation-apply`:
the neutrality assertion above against an event-free twin, the A1 unitary-supply assertion, and a
positive control showing the event really is in the applied block (so the test is not vacuous).
Mutants M1–M8 each restore some consequence (full forfeit; forfeit without the A1 credit; a partial
deduction; a deregistration only; a stake-gated variant; …) and each is RED. Recorded in the
DECISION-LOG entry "O-1 step 3a LANDED" (2026-09-16).

**Corollaries that follow trivially and replace T-E3 / T-E4 / T-E5 / T-E6 / T-E7.**

- *Replay* (was T-E3): re-applying the same event, within a block or across blocks, changes nothing,
  because one application changes nothing. The pre-D4 argument ("the second apply reads
  `locked == 0`") is no longer needed. **The residual is not state, it is bytes:** deregistration was
  the record's only natural limiter, so an event is re-includable at 2 Ed25519 verifies per copy.
  Bounding that is sequence step 3b (per-block cap + in-block duplicate rejection) and is **OPEN**.
- *Ghost equivocator* (was T-E4): an event naming an unregistered or unstaked domain is handled
  because nothing is looked up at all.
- *A1 invariance* (was T-E5): `Δlive_total_supply = 0 = Δexpected_total`; the identity is preserved
  on both sides by the absence of any transfer.
- *Cross-block accumulation* (was T-E6): `accumulated_slashed_` has no producer (§1.3); the
  accumulation is the empty sum.
- *Determinism* (was T-E7): two chains applying the same block reach the same root, a fortiori.

**What T-E0 deliberately does NOT claim.** It says nothing about whether the record is *complete*
(S-090: gossip is one-hop with no relay or re-request — OPEN), whether two honest observers derive the
same event hash on a SHARD chain (S-089 — OPEN), or whether the record is *bounded* (step 3b — OPEN).
Under D4 those three are correctness requirements of the L2 design, not merely DoS or hygiene items,
because the record is D22's input.

---

### 2.1 HISTORICAL — T-E1 through T-E7, the mechanics of the REMOVED branch

> **Everything from here to the end of §2 describes code deleted on 2026-09-16 (D4, O-1 step 3a).**
> It is retained as the record of what was removed and why the removal is safe to reason about — not
> as a description of HEAD. Do not cite T-E1..T-E7. The shipped statements are T-E0 and its
> corollaries above.

### T-E1 — Full stake forfeiture (HISTORICAL)

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

### T-E2 — Registry deactivation (HISTORICAL)

**Statement.** For every block `B` at height `b.index` containing an `EquivocationEvent ev` with `ev.equivocator == d` and a chain state where `registrants_[d]` exists with any prior `inactive_from` value (sentinel `UINT64_MAX` or a finite value from a prior DEREGISTER), the apply produces exactly:

```
Δregistrants_[d].inactive_from = (b.index + 1) − prior_inactive_from
```

i.e., `inactive_from` is unconditionally set to `b.index + 1`, irrespective of its prior value. No other field on `registrants_[d]` is touched (`ed_pub`, `registered_at`, `active_from`, `region` all preserved).

*Proof sketch.* By inspection of `chain.cpp:1351–1355`. The `registrants_.find(ev.equivocator)` lookup returns a valid iterator under hypothesis. Line 1354 writes `rit->second.inactive_from = b.index + 1` unconditionally — there is no read-modify-write guard against the prior value. The post-apply value is the literal `b.index + 1`, which makes the equivocator ineligible for committee selection at every height `h' ≥ b.index + 1` (V2 of F0 + `eligible_in_region` filter at `registry.cpp::build_from_chain`'s eligibility predicate `active_from <= at_index < inactive_from`).

The "irrespective of prior value" property is intentional: if the equivocator had previously DEREGISTERed and the prior `inactive_from` is some `b.index + δ_reg > b.index + 1`, the equivocation override advances the deactivation to the immediate next block, closing the registration-grace window during which the offender might otherwise have continued participating. If a future-effective DEREGISTER had set `inactive_from = b.index + δ_reg` with `δ_reg ≤ REGISTRATION_DELAY_WINDOW` (~10 blocks), the equivocation override at line 1354 brings it forward by `δ_reg − 1` blocks. ∎

> **⚠ Corrected (see §0).** An earlier version of this proof sketch appended a false corollary: that the equivocation deactivation is *one-way* — "the equivocator cannot re-activate by re-REGISTERing the same domain" because "REGISTER's apply branch checks `registrants_.contains(d)` and skips on hit," so "the offender must register a fresh domain to participate again." **No such contains-skip exists.** The REGISTER apply branch (`chain.cpp:1231-1296`) computes `first_time_register` only to gate the Negative-Entry-Fee drain (`:1282`), then **unconditionally** rebuilds the entry with `inactive_from = UINT64_MAX` + a fresh `active_from` and does `registrants_[tx.from] = e` (`:1260-1264`), overwriting the equivocation-set `inactive_from`. A slashed equivocator who re-REGISTERs the **same** domain therefore re-activates after `derive_registration_delay`. In DOMAIN_INCLUSION mode (`min_stake_ == 0`) this is a zero-lasting-cost bypass of the FA6 deterrent. **The theorem *statement* above — the deactivation write `inactive_from := b.index + 1` — is real and holds; only its re-activation-permanence corollary fails.** Status: OWNER-ESCALATED.

**Code witness.** `src/chain/chain.cpp:1351–1355` (the registry-deactivation half); `include/determ/chain/chain.hpp:32–43` (`RegistryEntry` struct); `src/chain/chain.cpp:1231–1296` (REGISTER apply branch — note it has **no** contains-skip and re-activates a slashed entry by overwriting `inactive_from`; see §0 correction); `src/node/registry.cpp::build_from_chain` (eligibility predicate).

**Test witness.** `tools/test_equivocation_apply.sh` "Registry deactivation" block — 2 assertions: baseline `inactive_from == UINT64_MAX` (sentinel pre-equivocation), post-apply `inactive_from == b.index + 1`. `tools/test_equivocation_multi.sh` "Pre-deactivated equivocator" scenario asserts the override: a domain whose prior `inactive_from` was a finite future value gets its `inactive_from` reset to `b.index + 1`.

### T-E3 — Idempotent re-apply (HISTORICAL — superseded by T-E0 *Replay*)

**Statement.** For any block `B` containing two `EquivocationEvent`s `ev_1, ev_2 ∈ B.equivocation_events` with `ev_1.equivocator == ev_2.equivocator == d`, OR for two sequential blocks `B_1, B_2` each containing an `EquivocationEvent` for `d`, the cumulative chain-wide `accumulated_slashed_` advances by exactly `stakes_[d].locked` evaluated at the moment of the **first** event's apply iteration. A second event for the same domain — whether intra-block or cross-block — contributes zero to `accumulated_slashed_`. The post-apply state after the second event is byte-identical to the post-apply state after the first event (modulo any other concurrent mutations on `accounts_` / `stakes_` / `registrants_` for other domains).

*Proof sketch.* Intra-block case: the loop at `chain.cpp:1344` iterates over `b.equivocation_events` in serialized order. The first iteration on `ev_1` enters the stake-forfeit branch (T-E1) and writes `sit->second.locked = 0` — the post-iteration value. The second iteration on `ev_2` re-runs `stakes_.find(ev.equivocator)`, which returns the same iterator (the map entry was not erased), so `sit != stakes_.end()` holds. Line 1348 reads `sit->second.locked == 0` (set by the first iteration) and adds zero to `block_slashed`. Line 1349 writes zero to the locked field (a no-op idempotent write). The registry half (lines 1351–1355) writes `inactive_from = b.index + 1` on both iterations — a deterministic idempotent write to the same value. The net `block_slashed` contribution from the pair is `L + 0 == L`, not `2L`. The apply-tail fold at line 1395 advances `accumulated_slashed_` by exactly `L`.

Cross-block case: after `B_1` applies, the chain has `stakes_[d].locked == 0` and `accumulated_slashed_ += L_1` (where `L_1` was the pre-`B_1` locked value). When `B_2` applies, the loop iteration on `ev_2` finds `stakes_[d].locked == 0` and contributes zero to `B_2`'s `block_slashed`. The chain-wide `accumulated_slashed_` advances by zero from this event. The registry's `inactive_from = b.index + 1` write at `B_2` overrides any prior finite value, but since `B_1` already set it to `b.index_1 + 1 < b.index_2 + 1`, the override moves the deactivation forward (a strictly increasing sequence under monotone block-index ordering — see Discussion §4 for the inactive_from monotonicity claim).

The construction is robust against legitimate evidence reaching the chain in different blocks (an attacker who equivocated at height H may be denounced at H+5 in one shard and H+50 in another; the apply path treats the second denunciation as a no-op on stake, with the registry deactivation harmlessly re-asserted). ∎

**Code witness (HISTORICAL — the loop was removed by D4; see §1.2).** The loop body whose read-then-write pattern on `locked` made the second iteration contribute zero; the `block_slashed` accumulator; the absence of any side-channel that re-credits the forfeited stake (no UNSTAKE post-slash can re-credit because T-K4's refund-branch fires on `locked < amount`).

**Test witness (the gate was INVERTED at step 3a).** `tools/test_equivocation_multi.sh` "Same equivocator twice in same block" now asserts that BOTH events move nothing and `accumulated_slashed` stays 0. *(HISTORICAL: it asserted that the first equivocation forfeits the full stake (`accumulated_slashed += L`) and the second is a no-op.)* The "Pre-deactivated equivocator" scenario covers the cross-block analogue.

### T-E4 — Ghost-equivocator robustness (HISTORICAL — superseded by T-E0 *Ghost equivocator*)

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

### T-E5 — A1 invariance under slashing (HISTORICAL — superseded by T-E0 *A1 invariance*)

**Statement.** Across any finite sequence of blocks `B_1, B_2, ..., B_n` applied to a Chain `C`, including blocks containing zero or more `EquivocationEvent`s, the A1 unitary-supply invariant `live_total_supply() == expected_total()` holds at every apply-tail (`chain.cpp:1399`). Specifically, for an equivocation event with pre-event `stakes_[d].locked == L`:

```
Δlive_total_supply       = −L         (locked stake leaves Σ stakes_)
Δexpected_total          = −L         (accumulated_slashed advances by L,
                                       which enters expected as a subtraction)
```

so the two sides advance by the same delta; the equality is preserved. Total supply moves by exactly `−L` (the forfeited stake is removed from the live circulating + staked total — it is not redistributed to anyone, not even creators, not even the chain itself; it is **burned** into `accumulated_slashed_`).

*Proof sketch.* The `live_total_supply()` helper (`chain.cpp:1797` approximate location) sums `accounts_[d].balance + stakes_[d].locked` across all `d`. Pre-event, `d`'s stake contributes `+L` to this sum. Post-event (T-E1), `d`'s stake contributes `+0`, so `live_total_supply` decreased by `L`. The companion side: `expected_total()` is `genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ - accumulated_slashed_ - accumulated_outbound_ - accumulated_shielded_` (the sixth term §3.22, unchanged by a slash). The event contributes `+L` to `block_slashed` (T-E1), which folds into `accumulated_slashed_` at apply-tail (line 1395). Since `accumulated_slashed_` enters `expected_total` as a subtraction, `Δexpected_total = −L`. Both sides advance by `−L`, equality preserved.

The "burned" character is critical: there is no `accounts_[creators[i]].balance += L` write anywhere in the equivocation branch, and the suspension-slash + equivocation-slash combined `block_slashed` is NOT included in the per-block creator-fee distribution (`chain.cpp:1286–1305` distributes `total_fees + subsidy_this_block`, not slashed). The forfeit is unrecoverable. This is the design — equivocation is a Byzantine offense whose disincentive must be the actual destruction of stake value, not a redistribution that another colluding party could capture.

The A1 closure at `chain.cpp:1399` catches any apply-path bug that would break the invariance — e.g., a hypothetical regression that forfeited stake without incrementing `block_slashed`, or one that incremented `accumulated_slashed_` without zeroing `locked`. Both would surface as a `runtime_error` with the per-field delta diagnostic at lines 1405–1418, blocking the block at apply-time and rolling back to the pre-apply state via the A9 atomic-apply machinery. ∎

**Code witness.** `src/chain/chain.cpp:1348–1349` (the paired `block_slashed += L` / `locked = 0` writes that preserve the A1 ledger arithmetic); `src/chain/chain.cpp:1395` (apply-tail fold); `src/chain/chain.cpp:1397–1419` (A1 closure assertion + rollback diagnostic); `src/chain/chain.cpp:1286–1305` (creator distribution — verified to NOT include `block_slashed`).

**Test witness.** `tools/test_equivocation_apply.sh` "A1 supply invariant" block — 3 assertions: `accumulated_slashed` bumped by exactly the full stake amount; `live_total_supply` decreases by exactly the forfeit; `expected_total == live_total_supply` after the forfeit (the A1 closure passes). `tools/test_supply_invariant.sh` cross-checks the A1 closure across composed block sequences including equivocation events.

### T-E6 — Cross-block accumulation (HISTORICAL — superseded by T-E0 *Cross-block accumulation*)

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

### T-E7 — Deterministic apply (HISTORICAL — superseded by T-E0 *Determinism*)

**Statement.** For any two Chain instances `C₁` and `C₂` with `C₁ ≡_S C₂` (per FA-Apply-2 §1.2 state-equivalence), and any block `B` containing equivocation events, the apply results satisfy `apply_transactions(C₁, B) ≡_S apply_transactions(C₂, B)`. In particular: the final `stakes_[d].locked` values coincide for every `d` named in `B.equivocation_events`, the final `registrants_[d].inactive_from` values coincide, the final `accumulated_slashed_` counters coincide, and the final `compute_state_root` values coincide byte-identically.

*Proof sketch.* This is the apply-after-restore equivalence (FA-Apply-2 T-S2) specialized to the equivocation-slash branch. The argument has three components:

- **Per-event determinism.** Each loop iteration reads only `stakes_[ev.equivocator]` and `registrants_[ev.equivocator]`, and writes only `stakes_[ev.equivocator].locked` and `registrants_[ev.equivocator].inactive_from`. Under hypothesis `C₁ ≡_S C₂`, both reads return the same values on both sides, so both writes produce the same post-state.
- **Event-order determinism.** The loop iterates over `b.equivocation_events` in serialized order, which is consensus-pinned (the block's `equivocation_events` vector is part of the block's signed body — see PROTOCOL.md §4 + V11). Identical serialized order → identical iteration sequence → identical cumulative writes on both sides.
- **Map iteration determinism.** The `stakes_` and `registrants_` maps are `std::map` (red-black tree, sorted-key invariant); subsequent iteration for state-root construction (`build_state_leaves` at `chain.cpp:331–341` for the `s:` and `r:` namespaces) is deterministic across implementations because the tree's structural invariant pins the iteration order to the key's `<` ordering.

The composition of these three components: equivocation-slash apply is a pure function of `(C, B)`, with no system-clock, no RNG, no thread-scheduling dependency. Two chains in equivalent states applying the same block produce equivalent post-states. The state-root equivalence then follows from `compute_state_root` being a deterministic function of the maps. ∎

**Code witness.** `src/chain/chain.cpp:1344–1356` (deterministic loop body); `src/chain/chain.cpp:331–341` (`s:` + `r:` namespace state-root contribution that surfaces any non-determinism as a state-root divergence).

**Test witness.** `tools/test_equivocation_apply.sh` "Determinism" assertion — two chains seeing the same equivocation event produce the same `state_root`. `tools/test_equivocation_multi.sh` "Determinism" assertion across the multi-equivocation surface. `tools/test_state_root_namespaces.sh` cross-checks the `s:` and `r:` namespaces as part of the 10-namespace state-root composition.

---

## 3. HISTORICAL — Slashing vs DEREGISTER

Equivocation slashing and DEREGISTER are the two paths that deactivate a registered validator. They share the registry-mutation surface — both write `registrants_[d].inactive_from` to a finite value — but differ structurally on three dimensions:

| Dimension | Equivocation slash (this proof) | DEREGISTER (FA-Apply-4 T-K3) |
|---|---|---|
| **Stake disposition** | Immediate full forfeit: `stakes_[d].locked := 0`, value burned into `accumulated_slashed_`. | Preserved: `stakes_[d].locked` unchanged, value remains locked until UNSTAKE post-unlock_height. |
| **Deactivation timing** | Immediate: `inactive_from := b.index + 1` (effective next block, irrespective of prior `inactive_from`). | Deferred: `inactive_from := b.index + derive_delay(b.cumulative_rand, tx.hash)` for `δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]` (~10 blocks). |
| **Re-activation path** | **OPEN — owner-escalated (see §0).** No re-entry block exists: the REGISTER apply branch (`chain.cpp:1231-1296`) unconditionally overwrites `registrants_[d]` with `inactive_from = UINT64_MAX`, so a slashed equivocator who re-REGISTERs the same domain re-activates. In DOMAIN_INCLUSION mode this is a zero-lasting-cost bypass. | Open: the **same** overwriting REGISTER path lets a voluntarily-DEREGISTERed domain re-REGISTER and re-activate (`inactive_from` reset to `UINT64_MAX`). ⚠ The original "Closed vs Open" asymmetry claimed here was **not real** — both cells resolve to one indistinguishable `registrants_` entry hitting one overwriting REGISTER branch. |
| **A1 impact** | Negative: total supply decreases by the forfeited stake (T-E5). | Neutral: total supply unchanged at DEREGISTER (only `tx.fee` enters `total_fees`, which is intra-supply per FA11). |
| **Validator initiates** | No — equivocation evidence is gossipped + V11-validated by peers, the offender has no control. | Yes — DEREGISTER is a tx the validator signs and broadcasts themselves. |
| **Trigger event** | Cryptographic: V11 verifies two distinct signatures over distinct digests under the same registered key (FA6 soundness — `≤ 2⁻¹²⁸` false-positive bound per attempt). | Voluntary: the validator submits a DEREGISTER tx with their own signature. |
| **Slashing window** | N/A — the slash IS the punishment. | The `[inactive_from, unlock_height)` tail (~1000 blocks) is the slashing-evidence window: an equivocation from before DEREGISTER, surfacing during this window, still slashes the pending-unlock locked stake (StakeLifecycle.md §4). |

The asymmetric stake disposition is the central economic distinction. DEREGISTER is the orderly-exit path — the validator gives notice, the chain holds their stake hostage for `UNSTAKE_DELAY` blocks during which evidence of prior bad behavior can still surface and consume the stake, and then the stake returns to balance via UNSTAKE. Equivocation is the disorderly-exit path — the chain has detected a deliberate Byzantine offense and immediately destroys the stake without ceremony. The two paths share the registry mutation only because both produce "no longer in the eligible pool"; they diverge sharply on what happens to value.

**Interaction.** A validator who DEREGISTERs at height `h` enters the `staked-pending-unlock` state (StakeLifecycle.md §1.2). During the `[h+1, h+δ_reg+UNSTAKE_DELAY)` window, an `EquivocationEvent` for the same domain (perhaps for evidence of earlier misbehavior) consumes the pending-unlock stake via T-E1, producing `stakes_[d].locked = 0` and overriding `inactive_from` from the DEREGISTER's scheduled value to `b.index + 1` per T-E2. Post-slash, the operator's stake is gone and the registry entry is deactivated effective the next block — but (per §0) that registry closure is **not permanent**: a re-REGISTER of the same domain currently overwrites `inactive_from` back to `UINT64_MAX` and re-activates. The stake forfeiture (T-E1) is permanent; the registry closure is owner-escalated. A subsequent UNSTAKE during this window falls into the T-K4 refund branch (locked is now 0, fails the `locked >= amount` check) — the operator pays the UNSTAKE fee and gets it refunded but recovers no stake. The fee-refund convention (StakeLifecycle.md §3) protects the honest user who didn't know the equivocation evidence was about to surface; an attacker who slashed-then-spammed UNSTAKE retries gains nothing because each attempt only consumes a nonce slot.

**Validator-mode independence.** Both paths function in both STAKE_INCLUSION and DOMAIN_INCLUSION modes. In DOMAIN_INCLUSION (`min_stake_ == 0`), the stake-forfeit branch is a no-op on the `accumulated_slashed_` counter (no stake to forfeit), but the registry-deactivation branch still removes the offender from the eligible pool. This is the design point that makes the dual mechanism unifying: regardless of which inclusion mode the chain runs, equivocation removes the offender from the eligible pool effective the next block, and DEREGISTER produces a deferred orderly exit. ⚠ Per §0, that removal is **not permanent** — a re-REGISTER of the same domain currently re-activates it (owner-escalated); in DOMAIN_INCLUSION mode, where the registry deactivation is the *entire* penalty, this leaves no lasting cost.

---

## 4. HISTORICAL — Discussion of the removed mechanism

### 4.1 `inactive_from` monotonicity claim

Across the lifetime of a registered domain `d`, the sequence of writes to `registrants_[d].inactive_from` follows the discipline:

1. **Initial state** at REGISTER: `inactive_from := UINT64_MAX` (sentinel, per `chain.cpp:1231–1296`).
2. **DEREGISTER write**: `inactive_from := b.index + δ_reg` for `δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]` — strictly less than UINT64_MAX.
3. **Equivocation-slash write**: `inactive_from := b.index + 1` — strictly less than the DEREGISTER-scheduled value (because `b.index + 1 ≤ b.index + δ_reg` and the slash usually occurs at a later block than the DEREGISTER, but even at the same block the slash's `b.index + 1` is `≤` the DEREGISTER's `b.index + δ_reg` for `δ_reg ≥ 1`).

The intuitive ordering is that `inactive_from` only ever moves **forward in deactivation time** (closer to "now"), never backward to a later height. T-E2's "irrespective of prior value" claim is the formal expression: the equivocation override is unconditional, so even if a buggy DEREGISTER were to set `inactive_from` to a value smaller than `b.index + 1`, the equivocation write would overwrite it to `b.index + 1` — which might appear to "rewind" the deactivation, but in practice the only way `inactive_from < b.index + 1` could occur is via a DEREGISTER at the same block, which sets `δ_reg ≥ 1` and produces `b.index + δ_reg ≥ b.index + 1`. So the inequality `inactive_from_post_slash ≤ inactive_from_pre_slash` always holds on a well-formed chain. The override is therefore equivalent to "advance the deactivation to immediate" in all reachable states.

> **⚠ Corrected (see §0).** This monotonicity discipline holds only *within* the slash/DEREGISTER writes. It is **broken by the REGISTER apply branch**: a re-REGISTER of an already-slashed domain overwrites `inactive_from` back to the `UINT64_MAX` sentinel (step 1), i.e. moves the deactivation *backward* to "never." So `inactive_from` is **not** globally monotone across a domain's lifetime — a slashed domain can be re-activated by re-REGISTERing it. This is the owner-escalated gap; the monotonicity claim above should be read as scoped to the equivocation-vs-DEREGISTER comparison, not as a whole-lifecycle invariant.

### 4.2 Why the forfeit is "burned" and not redistributed

The design choice to send the forfeited stake to `accumulated_slashed_` (a counter that enters A1's `expected_total` as a subtraction) rather than to the creator-fee distribution pool has three justifications:

1. **No incentive to manufacture equivocation evidence.** If forfeited stake were redistributed to the creators of the block carrying the `EquivocationEvent`, those creators would have an incentive to fabricate evidence (forge a second signature, plant manipulation traces) to capture the stake. Burning the stake removes the incentive — the creators get nothing beyond the standard per-block fee + subsidy. Combined with V11's EUF-CMA-bound on signature forgery (`≤ 2⁻¹²⁸`), the system is incentive-aligned: creators are paid to include legitimate evidence, but cannot profit from fabricating it.

2. **Preserves the unitary-supply ceiling.** Total supply is bounded above by `genesis_total + Σ_h subsidy_h + Σ_h inbound_h`. Equivocation forfeiture is the only mechanism (alongside outbound cross-shard transfers) that can REDUCE supply. Without this, slashing would be a redistribution and the chain's total supply would be monotonically non-decreasing, which is a weaker property than the "supply bounded above and slashable downward" guarantee that A1 establishes.

3. **Aligns with Ethereum-class slashing semantics.** Ethereum's beacon-chain slashing similarly burns the slashed ETH (after a "whistleblower reward" component, which Determ deliberately omits to close the manufacturing-incentive surface in (1)). The "burn, not redistribute" pattern is the established mutually-distrustful approach.

### 4.3 Apply-side vs validator-side division of labor (RESTATED 2026-09-17)

**At HEAD the division of labour is total: the validator does all of it.** V11 accepts or rejects the event; apply does nothing either way. There is therefore no longer any path by which a false accusation destroys honest stake — the FA6 §2 Case (c) residual (an honest validator that ran two round instances at one height can be validly accused) costs the accused NOTHING on L1, and lands instead on the L2 policy (D22) as an input-quality obligation. That is the whole of the change to this section; the historical text follows.

**HISTORICAL.**

The apply-side mechanics in this proof fire **conditional on V11 having authorized the slash upstream**. V11 (`check_equivocation_events` at `validator.cpp`) is responsible for:

- Rejecting `kind > 1`, and asserting `index_a = index_b = ev.block_index` (the height assert — what makes the accused height signature-bound).
- Verifying `body_root_a ≠ body_root_b` (the two-distinct-commitments requirement).
- Verifying both signatures against the DERIVED digests `D(kind, index_x, body_root_x)` under the equivocator's REGISTER-bound pubkey.
- For cross-shard events (`shard_id != 0`), verifying the beacon-anchor-height context (FA6 Corollary T-6.1).

If V11 rejects the block at validate-time, the apply path never runs and the equivocation branch above does not execute. The apply-side mechanics are therefore "trusted" in the operational sense — they assume the equivocation evidence is genuine. FA6 closes the cryptographic gap: an honest validator's signatures cannot be forged and cannot be re-opened at another height, so an honest validator is never falsely accused, so the apply-side mechanics never wrongly destroy honest stake. **Read FA6's boundary with it:** that conclusion holds under the H3 single-round hypothesis — a validator that signed in two rounds at ONE height can still be validly accused (`EquivocationSlashing.md` §2 Case (c), OPEN). Since this proof's mechanics are unconditional on the evidence's genuineness, that residual lands here as destroyed honest stake, which is why it is recorded as an open owner item rather than absorbed.

The apply-side robustness (T-E4 ghost-equivocator handling) is the belt-and-suspenders defense against any path that slips past V11 — e.g., a snapshot replay of a pre-V11 block, a buggy peer producing a block that bypassed its own validator, or a malicious supplier injecting a forged snapshot whose `equivocation_events[]` references a domain that doesn't exist on the receiver's chain. The defensive guards at lines 1346 and 1352 ensure the apply path is **safe** in all these edge cases (no crash, no state corruption), even where it cannot be **soundly punitive** (a forged event against a non-existent domain produces no slash). The combination of V11 cryptographic soundness + apply-side defensive robustness produces the desired property: slashing fires exactly when it should, and no other time.

---

## 5. What this doesn't prove (restated 2026-09-17: T-E0 replaces the T-E1..T-E7 references below)

The theorems above target the apply-layer mechanics of equivocation slashing in isolation. They do not extend to:

- **No-false-accusation — the "honest never named" property.** This is the scope of `EquivocationSlashing.md` (FA6) Theorem T-6, which is cryptographic (EUF-CMA) and bounded by the H3 hypothesis. T-E0 is *unconditional* on it: apply is neutral whether the event is genuine or fabricated, so this document no longer inherits FA6's boundary as a risk. (The historical T-E1..T-E7 did.)

- **Slashing completeness — "every equivocator gets caught."** A separate theorem would prove that every actual equivocation eventually surfaces as a finalized `EquivocationEvent`. This is a liveness property (FA4-adjacent) for the gossip + evidence-pool pipeline; not proven here. In practice the gossip layer's `EQUIVOCATION_EVIDENCE` propagation + the pending-evidence-pool dedup makes most actual equivocations land in some honest committee's block, but the formal completeness claim is out of scope.

- **The Phase-1 abort channel.** The abort loop in `apply_transactions` used to share the `block_slashed` accumulator with the equivocation branch. Since D13 (2026-09-16) it deducts nothing either: it increments the S-032 `abort_records_` entry, which arms the exponential suspension window, and moves no stake. `SUSPENSION_SLASH` remains a genesis-hash-covered but INERT parameter. Covered by `AbortEventApply.md` (restated) and `EligibilityFloorDesign.md`.

- **EquivocationEvent wire format / V11 validator check.** The struct's serialization, V11's verify-against-pubkey logic, and the consensus-time rejection are PROTOCOL.md §4 / FA6 / validator-side scope. The present proof references `ev.equivocator` as the key for the apply-side mechanics but does not verify the event's authenticity — that is V11's job.

- **Snapshot restore.** There is no post-slash state to preserve any more: T-E0 produces no delta in `s:`, `r:` or `c:`. The three namespaces and the `c:accumulated_slashed` leaf keep their shapes unchanged (no migrations), so every existing snapshot round-trip gate stays green and stays non-vacuous on its other channels; FA-Apply-2 T-S2/T-S3 are unaffected.

- **Cross-shard equivocation propagation.** FA6 Corollary T-6.1 covers cross-shard slashing soundness; the present proof references the `ev.shard_id` and `ev.beacon_anchor_height` fields only as forensic context. The cross-shard apply mechanics are identical to the single-chain branch — the shard fields do not gate the apply-side writes, only the V11 routing. The single-chain proof here is the apply-side claim for both modes.

- **Re-registration after equivocation — MOOT since D4 (2026-09-17 note).** There is no deactivation to undo: `apply_transactions` never sets `inactive_from` for an equivocator, so "can a slashed domain re-register?" has no referent. The §0 correction and the text below are HISTORICAL. The policy question it escalated (should an equivocator be excluded, and how) was answered by D4: not at L1, ever — exclusion at `|eligible pool| == K` is a self-sustaining halt, and no predicate over two signed openings is sound and complete. Exclusion policy, if any, is the L2 bond design (D22).

  **HISTORICAL.** ⚠ **Corrected (see §0) — this was the OWNER-ESCALATED gap.** An earlier version of this proof claimed (Discussion §4 + T-E2 commentary) that the equivocated entry blocks REGISTER from re-creating the same domain, via a "`registrants_.contains(d)` check that skips on hit." **No such check exists** — the REGISTER apply branch (`chain.cpp:1231-1296`) unconditionally overwrites `registrants_[d]`, re-activating a slashed domain after `derive_registration_delay`. Whether a slashed domain should be permanently locked out — vs. the current overwrite semantics that legitimately support key-rotation / region-update re-registration — is a consensus/state-format policy decision. It is OWNER-ESCALATED (the fix must distinguish slash-deactivation from voluntary DEREGISTER, and once decided should be gated falsify-on-mutant: slash-then-re-REGISTER the same domain and assert `inactive_from` stays `== slash_height + 1`). A future GC policy for inactive entries would interact with whatever lockout rule is chosen.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V11 (equivocation-proof verification) + assumption A1 (Ed25519 EUF-CMA) backing FA6's soundness. |
| `EquivocationSlashing.md` (FA6) | No-false-accusation theorem T-6 + cross-shard corollary T-6.1. T-E0 does not depend on it (apply is neutral on genuine and fabricated events alike). |
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
| `Chain::apply_transactions` (`src/chain/chain.cpp`) | The `block_slashed` declaration (frozen at 0), the `b.abort_events` record loop (D13), and the `b.equivocation_events` comment block that IS the D4 apply path. |
| `tools/test_equivocation_apply.sh` (`determ test-equivocation-apply`) | **The T-E0 gate**: neutrality against an event-free twin, A1, positive control; mutants M1–M8 RED. |
| `src/chain/chain.cpp:1395` | Block-tail fold of `block_slashed` into `accumulated_slashed_`. |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion + rollback diagnostic. |
| `src/chain/chain.cpp:1231–1296` | REGISTER apply branch — **unconditionally overwrites** `registrants_[d]` (no contains-skip); re-activates a slashed domain by resetting `inactive_from` to `UINT64_MAX` (see §0 correction, OWNER-ESCALATED). |
| `src/chain/chain.cpp:331–341` | `s:` + `r:` namespace state-root contribution (T-E7's determinism backstop). |
| `src/node/validator.cpp::check_equivocation_events` | V11 upstream gate (FA6 scope). |
| `tools/test_equivocation_multi.sh` (`determ test-equivocation-multi`) | The multi-event composition arms, inverted to neutrality: two distinct equivocators in one block, the same equivocator twice, an equivocator with no stake, a pre-deactivated equivocator, determinism — every one now asserting that nothing moves. |
| `tools/test_equivocation_slashing.sh` | End-to-end network-level scenario (3-node cluster, gossip + V11 + apply). |
| `tools/test_supply_invariant.sh` | A1 closure across composed block sequences including equivocation events. |

---

## 7. Status (rewritten 2026-09-17, step 3c)

**Shipped: T-E0 only.** `Chain::apply_transactions` is state-neutral on `b.equivocation_events`; gate `determ test-equivocation-apply` (neutrality against an event-free twin, A1, positive control), mutants M1–M8 RED (DECISION-LOG 2026-09-16 "O-1 step 3a LANDED"). The T-E0 corollaries (replay, ghost equivocator, A1 invariance, cross-block accumulation, determinism) follow from neutrality and replace T-E3 through T-E7 in every citation.

**Open, and owed elsewhere — not by this document:**

- **Evidence bound (step 3b, OPEN).** Deregistration was the record's only limiter; a per-block cap + in-block duplicate rejection on `equivocation_events` is the next increment of the O-1 chain. Until it lands, one valid proof is re-includable at 2 Ed25519 verifies per copy.
- **Evidence completeness (S-090, OPEN).** `on_equivocation_evidence` adopts without rebroadcasting; gossip has no relay and no re-request, so the record can be incomplete.
- **Evidence identity on shards (S-089, OPEN).** `beacon_anchor_height` / `shard_id` are hashed but compared by nothing.
- **The consumer (D22, v1.1 DApp scope, NOT DESIGNED).** The L2 bond/arbitration policy that is supposed to act on the record does not exist. Until it does, equivocation has no consequence anywhere.

**HISTORICAL — the T-E1..T-E7 status record of the removed mechanism follows.** The re-activation-permanence corollary asserted in T-E2 / §3 / §4.1 / §5 was OPEN and OWNER-ESCALATED (see §0) and is now MOOT.

- **T-E1** (full stake forfeiture) closed via the `block_slashed += sit->second.locked; sit->second.locked = 0;` paired writes at `chain.cpp:1348–1349` + apply-tail fold at `chain.cpp:1395`; regression `test_equivocation_apply.sh` "Full stake forfeiture" assertion.
- **T-E2** (registry deactivation) — the deactivation *write* is closed via the unconditional `rit->second.inactive_from = b.index + 1;` write at `chain.cpp:1354`; regression `test_equivocation_apply.sh` "Registry deactivation" (2 assertions) + `test_equivocation_multi.sh` "Pre-deactivated equivocator" override case. **⚠ Its re-activation-permanence corollary is OPEN and OWNER-ESCALATED (see §0): the REGISTER apply branch (`chain.cpp:1231-1296`) has no contains-skip, so a re-REGISTER of the same domain resets `inactive_from` to `UINT64_MAX` and re-activates a slashed equivocator.**
- **T-E3** (idempotent re-apply) closed via the read-then-write pattern at `chain.cpp:1348–1349` that makes the second iteration on the same domain read `locked == 0` and contribute zero; regression `test_equivocation_multi.sh` "Same equivocator twice in same block" scenario.
- **T-E4** (ghost-equivocator robustness) closed via the independent `find(...) != end()` guards at `chain.cpp:1346` and `chain.cpp:1352`; regression `test_equivocation_apply.sh` "Robustness on ghost equivocator" (2 assertions) + `test_equivocation_multi.sh` "Equivocator with NO stake" DOMAIN_INCLUSION variant.
- **T-E5** (A1 invariance under slashing) closed via the paired `block_slashed += L` / `locked = 0` writes preserving the A1 ledger arithmetic + apply-tail fold + A1 closure at `chain.cpp:1397–1419`; regression `test_equivocation_apply.sh` "A1 supply invariant" (3 assertions).
- **T-E6** (cross-block accumulation) closed via the apply-tail fold at `chain.cpp:1395` + the read-then-write idempotence of T-E3 across blocks; regression `test_equivocation_multi.sh` "Two distinct equivocators in same block" + "Determinism" scenarios.
- **T-E7** (deterministic apply) closed via the apply branch's reliance on only the chain's deterministic state + the block's consensus-pinned `equivocation_events[]` order + `std::map` per-key isolation; regression `test_equivocation_apply.sh` "Determinism" assertion + `test_equivocation_multi.sh` "Determinism" multi-event variant.

**HISTORICAL summary of the removed mechanism.** The seven theorem statements held against the pre-D4 code, but the **T-E2 / §3 / §4.1 / §5 re-activation-permanence corollary was OPEN and OWNER-ESCALATED (see §0)** — the REGISTER apply path unconditionally overwrites the registry entry, so equivocation removal was *not* permanent; in DOMAIN_INCLUSION mode a re-REGISTER re-activated the slashed domain at zero lasting cost. That proof rested on a small set of primitives: the dual-mechanism `(stake-forfeit, registry-deactivate)` paired writes guarded by independent `find` checks, the `block_slashed` per-block accumulator that folds into the chain-wide `accumulated_slashed_` at apply-tail, the A1 closure that catches any off-by-one in the accumulator update, and the `std::map` per-key isolation that makes multi-equivocator independence structural. The breadth of consequences — seven theorems plus the slashing-vs-DEREGISTER comparison plus the `inactive_from` monotonicity claim plus the "burn, not redistribute" rationale — is testimony to how few primitives the chain needs to express the slashing mechanism without compromising A1 conservation, replay determinism, or DOMAIN_INCLUSION-mode compatibility.

That proof's foundation rested on FA6's cryptographic soundness and FA-Apply's invariants (I-3 balance/stake independence + I-6 A1 closure). **FA-Apply-10's contribution at HEAD is the opposite and is one line: conditional on nothing at all, the apply path executes no transition.**
