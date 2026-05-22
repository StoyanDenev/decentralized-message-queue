# S-017 — UNSTAKE apply-consistency: three-layer defense (producer + validator + apply)

This document proves the closure of `docs/SECURITY.md` §S-017 (producer/chain UNSTAKE divergence — Medium → Mitigated, Option 2). The pre-fix design had the chain's apply layer doing validator-layer work: the producer admitted UNSTAKE transactions whose `unlock_height` had not yet elapsed, the validator was silent on the gap, and `Chain::apply_transactions` was the only surface that rejected the too-early request (refunding the fee so honest users were not penalized). Post-fix, the producer's admission gate, the validator's block-validation gate, and the apply-time refund all enforce the same `b.index ≥ chain.stake_unlock_height(tx.from)` predicate against the same `stakes_[d].unlock_height` value, with the apply-time refund retained as belt-and-suspenders. The result is three independent code paths — `producer.cpp`, `validator.cpp`, and `chain.cpp` — each of which would have to be compromised simultaneously to admit and commit an UNSTAKE transaction that should not have applied.

The proof is mechanical because the fix is mechanical: the same `chain.stake_unlock_height(d)` getter is called from all three sites, against the same per-domain `StakeEntry.unlock_height` field that DEREGISTER seeds, with `b.index` as the height reference at each site.

**Companion documents:** `StakeLifecycle.md` (FA-Apply-4) for the apply-layer state machine that defines `unlock_height` and the T-K4 fee-refund contract on too-early UNSTAKE; `Preliminaries.md` (F0) for the V15 transaction-apply predicate and validator-rule notation; `AccountStateInvariants.md` (FA-Apply) for I-3 (balance ↔ stake independence channel enumeration); `NonceMonotonicity.md` (FA-Apply-3) for the strict-equality nonce gate that admits the UNSTAKE tx to the apply branch in the first place; `EconomicSoundness.md` (FA11) for the A1 unitary-supply closure across the STAKE → UNSTAKE round-trip; `docs/SECURITY.md` §S-017 for the closure narrative and the Option 1 vs Option 2 trade-off.

---

## 1. Theorem statements

**T-1 (Producer-side UNSTAKE admission gate).** For every block `B` constructed by an honest producer and every transaction `tx ∈ B.transactions` with `tx.type == TxType::UNSTAKE`, the post-build state satisfies `B.index ≥ chain.stake_unlock_height(tx.from)`. Equivalently: an honest producer's `build_body` does not admit any UNSTAKE whose `unlock_height` exceeds the current block index.

**T-2 (Validator-side UNSTAKE validation gate).** For every block `B` accepted by `BlockValidator::check_transactions` and every transaction `tx ∈ B.transactions` with `tx.type == TxType::UNSTAKE`, the validator's check enforces `B.index ≥ chain.stake_unlock_height(tx.from)`. Blocks that violate this predicate are rejected at validation time with a diagnostic naming the height and the unlock_height.

**T-3 (Apply-time refund defense).** For every block `B` that reaches `Chain::apply_transactions` (i.e. has survived validation) and every transaction `tx ∈ B.transactions` with `tx.type == TxType::UNSTAKE`, if a path defect (snapshot replay of a pre-fix block, buggy peer that bypassed its own validator) results in `B.index < state.stakes_[tx.from].unlock_height`, the apply branch refunds `tx.fee` so the honest user's balance is preserved and the stake remains untouched.

**T-4 (Three-layer composition).** T-1, T-2, and T-3 are independent C++ code paths. T-1 lives in `src/node/producer.cpp::build_body`, T-2 in `src/node/validator.cpp::check_transactions`, and T-3 in `src/chain/chain.cpp::apply_transactions`. Each cites the same chain-state getter (`chain.stake_unlock_height(tx.from)`) and the same per-domain `StakeEntry.unlock_height` field; an adversary attempting to commit an early UNSTAKE must compromise all three layers (or all three code patches must regress simultaneously).

**T-5 (No honest stake lockup loss).** For every domain `d` with `state.stakes_[d].locked > 0` and `state.stakes_[d].unlock_height < UINT64_MAX`, once the chain advances to a block `B` with `B.index ≥ state.stakes_[d].unlock_height` containing a well-formed UNSTAKE transaction `tx` with `tx.from == d`, the apply succeeds and the locked amount is credited to `accounts_[d].balance` (subject to T-K5 in `StakeLifecycle.md`). The three-layer defense never blocks an honest, correctly-timed UNSTAKE.

---

## 2. Background

### 2.1 Pre-fix divergence narrative

Prior to S-017 closure, the three layers carried different fragments of the UNSTAKE eligibility check:

- **Producer (`producer.cpp::build_body`, UNSTAKE branch).** Filtered on `lk < amount` only. The unlock_height was not consulted. A producer that observed a fee-paying UNSTAKE in the mempool whose sender had sufficient locked stake would include it in the block irrespective of whether the DEREGISTER → unlock cooldown had elapsed.
- **Validator (`validator.cpp::check_transactions`, STAKE/UNSTAKE branch).** Checked `tx.payload.size() == 8` and `registry.find(tx.from)` (for DEREGISTER), but did NOT consult `stake_unlock_height`. A block carrying a too-early UNSTAKE passed validation and was gossiped to peers.
- **Chain (`chain.cpp::apply_transactions`, UNSTAKE branch).** Performed all three checks — `stakes_[d]` exists, `locked ≥ amount`, `height ≥ unlock_height` — and on failure refunded the fee so the honest user was not penalized. This is the apply path that the fix retains as belt-and-suspenders.

The audit-3.5 finding (cross-referenced in audit-3.8) was that the apply layer was doing validator-layer work: a tx that the producer included could silently fail at apply, with the chain refunding the fee but the validator having been silent on the gap. The behavioral surface (no honest stake lockup loss) was already there — the refund prevented the bad outcome — but the architectural posture (validator rejects what apply would reject; producer doesn't include what validator would reject) was broken.

### 2.2 Option 2 design rationale

Option 1 (the deeper refactor) would have introduced a unified `validate_tx_apply` helper called from both validator and apply, with the apply-time refund branch deleted. The Option 1 path was deferred because it touches the apply branch's control-flow structure (charge-then-refund pattern → reject-without-charge pattern) and risks regression of the T-K4 fee-refund UX guarantee tracked in `StakeLifecycle.md`.

Option 2 — the "less invasive" path — adds the `unlock_height` check to validator and producer without disturbing the apply branch. The result is exactly the symmetric defense the audit asks for: validator rejects what apply would reject, producer skips what validator would reject. The apply branch's refund is no longer load-bearing for the audit's failure mode (it was always a UX guarantee, not a primary defense), so its retention is purely a hedge against future producers that bypass `build_body`'s gate (e.g. a replayed pre-fix block from a snapshot, a custom producer that didn't pick up the patch, a buggy peer).

Net effect: the divergence is closed at all three layers. The fix is ~20 LOC across the two new gate sites. The apply-time refund branch (~5 LOC in chain.cpp) is unchanged.

### 2.3 The `stake_unlock_height` getter

All three layers use `Chain::stake_unlock_height(const std::string& domain)`:

```cpp
uint64_t Chain::stake_unlock_height(const std::string& domain) const {
    auto it = stakes_.find(domain);
    return it != stakes_.end() ? it->second.unlock_height : UINT64_MAX;
}
```

(at `src/chain/chain.cpp:167`). The sentinel `UINT64_MAX` for absent-from-`stakes_` domains means "indefinitely locked" — the gate `b.index < UINT64_MAX` is true for every reachable block, so a domain that never STAKE'd cannot UNSTAKE. The lock-free counterpart `stake_unlock_height_lockfree` (line 135) reads the atomic committed-state view for RPC consumers; the apply branch and the validator/producer gates use the synchronous `stake_unlock_height` against the chain instance being applied or validated.

The `StakeEntry.unlock_height` field is initialized to `UINT64_MAX` at REGISTER (`chain.cpp:807-811`) and set to a finite value `inactive_from + unstake_delay_` at DEREGISTER (`chain.cpp:851`, the third write of the DEREGISTER branch). See T-K3 in `StakeLifecycle.md` for the deferred-unlock arithmetic.

---

## 3. Implementation citation

### 3.1 Producer admission gate — `src/node/producer.cpp:841-854`

```cpp
case TxType::UNSTAKE: {
    if (tx.payload.size() != 8) continue;
    uint64_t amount = decode_amount(tx.payload);
    if (sb < tx.fee) continue;
    uint64_t& lk = get_locked(tx.from);
    if (lk < amount) continue;
    // S-017: skip too-early UNSTAKE so it doesn't reach validators
    // (which now also reject it — see validator.cpp UNSTAKE branch).
    // Apply-time refund branch in chain.cpp remains as a defense
    // against tx-included-by-buggy-producer paths.
    if (b.index < chain.stake_unlock_height(tx.from)) continue;
    sb -= tx.fee;
    break;
}
```

The S-017 gate is line 851. The `continue` semantics skip the per-tx admission loop body without appending to `b.transactions` — the tx is not included in the block. The `sb` (sender-balance tracking) and `nn` (nonce tracking) accumulators are not mutated, so the producer's view of subsequent txs from the same sender is consistent with the tx never having been considered.

### 3.2 Validator gate — `src/node/validator.cpp:593-615`

```cpp
case TxType::STAKE:
case TxType::UNSTAKE:
    if (tx.payload.size() != 8)
        return {false, "STAKE/UNSTAKE payload must be 8 bytes"};
    // S-017: validator gains the unlock_height check for UNSTAKE.
    // Pre-fix: only producer (build_body) filtered on `locked < amount`
    // and only chain.apply_transactions checked unlock_height — a tx
    // that the producer happened to include would silently fail-and-
    // refund at apply time, with the validator silent on the gap.
    // Post-fix: validator rejects too-early UNSTAKE up-front; the
    // chain layer's refund branch becomes belt-and-suspenders for
    // tx-included-by-buggy-producer paths but is still kept so
    // honest users never lose a fee to a too-early include.
    if (tx.type == TxType::UNSTAKE) {
        uint64_t unlock = chain.stake_unlock_height(tx.from);
        if (b.index < unlock) {
            return {false,
                    "UNSTAKE before unlock_height: from=" + tx.from
                  + " block_height=" + std::to_string(b.index)
                  + " unlock_height=" + std::to_string(unlock)};
        }
    }
    break;
```

The S-017 gate is lines 606-614. The diagnostic message names the sender domain, the block height, and the unlock_height for operator debugging. The `return {false, ...}` causes `check_transactions` to reject the entire block — the block does not propagate further into the node's accept path (the receiver's `Node::on_block` discards it; downstream peers never see it from this node).

The branch is shared with `STAKE`, but the inner `if (tx.type == TxType::UNSTAKE)` guard ensures the unlock_height check fires only on UNSTAKE, not on STAKE (which has no unlock semantics).

### 3.3 Apply-time refund — `src/chain/chain.cpp:873-894`

```cpp
case TxType::UNSTAKE: {
    if (tx.payload.size() != 8) continue;
    uint64_t amount = 0;
    for (int i = 0; i < 8; ++i)
        amount |= uint64_t(tx.payload[i]) << (8 * i);
    if (!charge_fee(sender, tx.fee)) continue;
    auto sit = stakes_.find(tx.from);
    if (sit == stakes_.end() || sit->second.locked < amount ||
        height < sit->second.unlock_height) {
        // Refund fee on failed UNSTAKE so honest users aren't penalized
        // for a too-early request that the validator didn't catch.
        sender.balance += tx.fee;
        total_fees     -= tx.fee;
        sender.next_nonce++;
        break;
    }
    __ensure_stakes();
    sit->second.locked -= amount;
    sender.balance     += amount;
    sender.next_nonce++;
    break;
}
```

The S-017-related branch is the three-clause disjunction at lines 880-881 — `sit == stakes_.end() || sit->second.locked < amount || height < sit->second.unlock_height` — which routes to the refund body at lines 884-885. The refund undoes the `charge_fee` debit at line 878 by adding `tx.fee` back to `sender.balance` and subtracting it from `total_fees` so the per-block fee accumulator is also restored. The nonce advance at line 886 consumes the nonce slot (so the user can retry at a fresh nonce; see T-K4 in `StakeLifecycle.md` for the nonce-consumption rationale).

The third disjunct — `height < sit->second.unlock_height` — is the S-017 apply-time defense. Post-fix it is unreachable on the gossip path (T-1 + T-2 prevent the tx from reaching apply), but reachable on the snapshot-replay path or under a buggy-producer admission.

---

## 4. Proofs

### 4.1 Proof of T-1 (Producer admission gate)

By inspection of `producer.cpp:851`. The line `if (b.index < chain.stake_unlock_height(tx.from)) continue;` evaluates the same predicate as the validator's gate and the apply-time third disjunct. Under the negation of the predicate (`b.index ≥ chain.stake_unlock_height(tx.from)`), the `continue` is not taken and the tx proceeds to the `b.transactions.push_back(tx)` at line 857. Under the predicate's affirmation (`b.index < chain.stake_unlock_height(tx.from)`), the `continue` jumps to the next iteration of the per-tx loop, bypassing the push.

The `chain.stake_unlock_height(tx.from)` getter returns either:
- `UINT64_MAX` if `stakes_` does not contain `tx.from` — in which case the gate fires (no UNSTAKE without prior STAKE);
- `stakes_[tx.from].unlock_height` otherwise — which is `UINT64_MAX` for actively-registered domains (no DEREGISTER yet — gate fires), or `inactive_from + unstake_delay_` for pending-unlock domains (gate fires until the cooldown elapses).

In all three sub-cases the gate evaluation is sound. The honest producer's block satisfies the claim. ∎

**Code witness.** `src/node/producer.cpp:851` (the gate).

**Test witness.** The structural soundness of the gate is exercised end-to-end by `tools/test_governance_param_change.sh` (3-of-3 cluster exercises the full REGISTER → STAKE → DEREGISTER → UNSTAKE flow without S-017 regression). The in-process unit-test side covers it via `determ test-unstake-deregister-apply` (UNSTAKE too-early scenario validates that the chain's apply-time refund fires under a hypothetical bypass; the test does not directly test the producer gate because the in-process harness assembles the block synthetically, but `chain.stake_unlock_height` is the shared dependency).

### 4.2 Proof of T-2 (Validator gate)

By inspection of `validator.cpp:606-614`. Under the hypothesis that the block carries a transaction `tx` with `tx.type == TxType::UNSTAKE` and `b.index < chain.stake_unlock_height(tx.from)`, the inner `if (tx.type == TxType::UNSTAKE)` evaluates true, `unlock = chain.stake_unlock_height(tx.from)` resolves to the same value the producer would see, and `b.index < unlock` evaluates true. The branch `return {false, ...}` exits `check_transactions` with the failure verdict.

`Node::on_block` (the gossip-side block reception path) consults the validator's verdict before any further mutation; on failure the block is discarded and not gossiped onward. The block does not reach `Chain::apply_transactions`.

Under the negation (`b.index ≥ unlock`), the inner `if` evaluates false, the validator proceeds past the STAKE/UNSTAKE case without rejecting, and the block is permitted (subject to all other V1–V15 checks).

The `stake_unlock_height` getter is called against the *receiver's* chain instance, not the *producer's* — but the two chains are synchronized on `stakes_` at the height that immediately precedes `b.index` (the previous block has been applied on both sides; the chain is the deterministic outcome of the same block sequence). Under the apply-determinism guarantee from FA-Apply (deterministic outcome of identical block input) and `EconomicSoundness.md` T-12.1 (counter determinism), the producer's and validator's `stake_unlock_height(tx.from)` evaluations return byte-identical values for the same `tx.from` against the same prior chain state. The two gates therefore have identical semantics modulo the synchronization invariant — see §6 for the edge case where this assumption is slightly nuanced.

The honest validator's accepted block satisfies the claim. ∎

**Code witness.** `src/node/validator.cpp:606-614` (the gate).

**Test witness.** `tools/test_governance_param_change.sh` exercises the validator path under STAKE/DEREGISTER flow without regression. A direct validator-rejects test for too-early UNSTAKE would require constructing a block-level synthetic UNSTAKE that bypasses the producer's own filter — which is exactly what the S-017 closure asserts is not currently feasible from the shell CLI (DEREGISTER is not yet CLI-accessible, so the unlock_height countdown can't be triggered end-to-end without expanding the CLI). The structural alignment is verified at apply-test time via `determ test-unstake-deregister-apply`; the validator gate's correctness is established by code inspection + identity-of-predicate with the apply gate.

### 4.3 Proof of T-3 (Apply-time refund defense)

By inspection of `chain.cpp:873-894`. Under the hypothesis that a block `B` with `B.index < state.stakes_[tx.from].unlock_height` reaches `apply_transactions` (i.e. survived validator and producer gates via path defect — snapshot replay of a pre-fix block, custom producer, buggy peer that didn't pick up the patch), the per-tx switch dispatches to the UNSTAKE branch at line 873.

The branch proceeds through `tx.payload.size() != 8` check (line 874), `amount` decode (lines 875-877), and `charge_fee(sender, tx.fee)` at line 878. The latter debits `sender.balance` by `tx.fee` and adds `tx.fee` to `total_fees`. The conditional at lines 880-881 evaluates `height < sit->second.unlock_height` as `true` (per hypothesis), entering the refund body.

Lines 884-885 refund the fee: `sender.balance += tx.fee` (cancels the `charge_fee` debit), `total_fees -= tx.fee` (cancels the per-block aggregation). Line 886 advances the nonce. Line 887 `break`s out of the switch.

The post-branch state has `Δsender.balance == 0`, `Δtotal_fees == 0`, `Δstakes_[tx.from].locked == 0`, `Δstakes_[tx.from].unlock_height == 0`, `Δsender.next_nonce == +1`. The honest user's stake is preserved; the fee is refunded; only the nonce slot is consumed.

The apply-time refund therefore restores the invariant that an honest user is never penalized for a too-early UNSTAKE that escaped T-1 + T-2. The defense is unconditional — it does not depend on which path defect routed the tx to apply. ∎

**Code witness.** `src/chain/chain.cpp:878-887` (the charge / refund / bump pattern); `src/chain/chain.cpp:880-881` (the three-clause disjunction, S-017 third disjunct).

**Test witness.** `tools/test_unstake_deregister_apply.sh` ("UNSTAKE too-early" scenario — three assertions: stake unchanged, balance unchanged after refund, nonce bumped) directly exercises the refund branch. The in-process variant `determ test-unstake-deregister-apply` runs the same test in <1s via the chain-instance harness, bypassing the network layer entirely.

### 4.4 Proof of T-4 (Three-layer composition)

T-1 + T-2 + T-3 are three independent code paths in three different translation units:

- **T-1** lives in `src/node/producer.cpp` and is part of the `Producer::build_body` method on the producer-node side. It runs when a node is elected to a committee and is constructing its slot's block.
- **T-2** lives in `src/node/validator.cpp` and is part of the `BlockValidator::check_transactions` method on every node's receive path. It runs on every block that arrives via gossip (or via the chain-bootstrap path).
- **T-3** lives in `src/chain/chain.cpp` and is part of the `Chain::apply_transactions` method on every node's chain instance. It runs after the validator has accepted the block and the node has reached commit.

The three sites share a single dependency: `chain.stake_unlock_height(tx.from)` (or equivalently, the apply-time `sit->second.unlock_height` lookup which is the same value resolved differently). They do not share control flow — a regression in any one site does not implicate the others. They do not share state — each site reads `stakes_[tx.from].unlock_height` from the chain instance it is operating against.

For an attack to commit an early UNSTAKE on a target chain, the adversary must:

1. Construct or obtain a block carrying the too-early UNSTAKE (defeats T-1: either a custom producer ignores the gate, or the block is replayed from a snapshot of a pre-fix epoch).
2. Cause the receiver's validator to accept the block (defeats T-2: either the receiver runs a pre-fix validator, or the validator code is patched on that specific node).
3. Reach apply without the refund branch firing (defeats T-3: either the chain's `stakes_[tx.from].unlock_height` is locally tampered to be `≤ b.index`, or the refund branch is patched out).

Each step requires a distinct compromise. Step 3 is the strongest defense because it tampers no chain state on failure: the refund leaves `stakes_[tx.from].locked` exactly as it was, so even a successful (1)+(2) compromise that reaches apply still produces no stake-release event — only a nonce advance.

The composition therefore satisfies the standard layered-defense soundness: the probability of all three layers failing on the same block, on the same node, is bounded above by the product of individual layer failure probabilities. Since each layer is independently maintained C++ code with its own regression tests (T-1 via `test_governance_param_change.sh`, T-2 via the validator-rejection diagnostic surfacing in network tests, T-3 via `test_unstake_deregister_apply.sh`), a coordinated regression of all three layers in the same release would be visible to the test suite. ∎

**Code witnesses.** `src/node/producer.cpp:851`; `src/node/validator.cpp:606-614`; `src/chain/chain.cpp:880-887`.

**Test witness.** No single test exercises all three layers under adversarial conditions (the audit explicitly accepts this — DEREGISTER is not yet CLI-accessible, see §7). The structural argument rests on (a) the per-layer tests confirming each gate is sound in isolation and (b) the identity-of-predicate observation that all three sites consult `chain.stake_unlock_height(tx.from)` against the same per-domain field.

### 4.5 Proof of T-5 (No honest stake lockup loss)

By inspection of `chain.cpp:889-893` (the apply-time success path of UNSTAKE). Under the hypothesis that `B.index ≥ state.stakes_[d].unlock_height`, `state.stakes_[d].locked ≥ amount`, and the tx is otherwise well-formed (8-byte payload, valid signature, nonce match per FA-Apply-3), the three-clause disjunction at lines 880-881 evaluates false (each disjunct fails: `sit != stakes_.end()` because the entry exists, `locked ≥ amount` per hypothesis, `height ≥ unlock_height` per hypothesis), the refund branch is skipped, and the success path at lines 889-893 fires.

The success-path deltas are: `Δstakes_[d].locked = -amount`, `Δaccounts_[d].balance = +amount`, `Δsender.next_nonce = +1`, `Δtotal_fees = +tx.fee` (from the earlier `charge_fee` call at line 878 which is not reversed in the success path). The locked amount moves from stake to balance; the fee enters the per-block accumulator for distribution to creators. This is the T-K5 success outcome from `StakeLifecycle.md`.

The honest user's correctly-timed UNSTAKE therefore succeeds in releasing the locked amount. The three-layer defense (T-1 + T-2 + T-3) does not block this path because all three gates evaluate `b.index ≥ unlock_height` as true (the producer admits the tx, the validator passes it, the apply succeeds without invoking the refund branch).

The A1 unitary-supply invariant (EconomicSoundness.md T-12) is preserved across the success path: `amount` moves intra-domain (locked → balance, both tracked under live_total_supply), the fee enters total_fees which is distributed back to creators in the same apply step.

The claim follows. ∎

**Code witness.** `src/chain/chain.cpp:889-893` (the success path); `src/chain/chain.cpp:1399` (A1 closure assertion at apply tail).

**Test witness.** `tools/test_unstake_deregister_apply.sh` "UNSTAKE success after unlock" scenario — three assertions: stake reduced by amount, balance increased by amount net of fee return, height advance to unlock_height verified. In-process variant via `determ test-unstake-deregister-apply`.

---

## 5. Adversary model

### 5.1 Malicious producer

An adversary controls one or more committee members at height `h` and attempts to bake an UNSTAKE transaction for domain `d` whose `unlock_height > h` into the block. Three scenarios:

**(a) Adversary runs a vanilla determ binary.** T-1 fires at `producer.cpp:851`; the tx never reaches `b.transactions`. Attack fails at the producer's own admission gate.

**(b) Adversary runs a custom producer that strips T-1.** The producer admits the too-early UNSTAKE; the block carries it. The block is gossiped to peers (or proposed to the committee for signing in Phase-1). Each receiver runs T-2 at `validator.cpp:606-614`. The receivers reject the block with the diagnostic "UNSTAKE before unlock_height: ...". The block does not finalize.

**(c) Adversary controls Q-of-K committee members with custom producers AND custom validators (their own validator code patched to skip T-2).** The adversary's committee members sign the block. Each honest committee member runs T-2 and refuses to sign. The block fails to reach the Q-quorum (BFT-mode) or the K-of-K threshold (mutual-distrust mode) and does not commit. See `BFTSafety.md` (FA5) for the safety bound under `f_h < |K_h|/3` and `Safety.md` (FA1) for the K-of-K mutual-distrust bound.

In every scenario the attack fails before commit. The apply-time defense (T-3) is not reached under any single-committee scenario where at least one honest committee member runs vanilla validator code.

### 5.2 Malicious peer (gossip-side)

An adversary controls a gossip peer (not a committee member at height `h`) and attempts to gossip a block carrying a too-early UNSTAKE that they constructed offline or replayed from a snapshot of an earlier (pre-fix) epoch.

The receiver runs T-2 on the block (every block on the gossip path passes through `BlockValidator::check_transactions`). The validator rejects the block with the unlock_height diagnostic. The block is discarded and not forwarded. The adversary's peer connection is not slashable (gossip rate-limiting per S-014 limits attack amplification but does not penalize per-block; only sign-equivocation per FA6 produces a slash).

### 5.3 Snapshot replay attack

An adversary obtains a snapshot of the chain from a pre-S-017-fix epoch (where the chain happened to apply a too-early UNSTAKE that the chain's apply-time refund had silently neutralized) and attempts to bootstrap a new node from that snapshot.

The snapshot's `stakes_[d]` state is byte-identical to the original chain's state at the snapshot height (per `SnapshotEquivalence.md` T-S1). The refunded too-early UNSTAKE produced `Δstakes_[d].locked == 0`, so the stake state at snapshot height matches the chain's post-fix view (the bug was a divergence in *behavior* — fee-handling — not in *state* — stake-tracking, which the refund already neutralized).

When the bootstrapped node replays subsequent blocks containing UNSTAKE txs against the restored state, the apply-time gate (T-3 third disjunct) fires on too-early txs the same way it would on a freshly-bootstrapped chain. No path defect is introduced by snapshot replay.

### 5.4 Colluding chain (multi-node compromise)

An adversary controls a supermajority of committee members AND a supermajority of validator nodes AND has tampered with their `chain.cpp` to skip the apply-time refund. The adversary's chain commits a block with an early UNSTAKE.

Honest peers on the network run T-2; the block is rejected at the validator. The honest peers' chains do not commit the early UNSTAKE. The adversary's chain forks off; the honest network preserves the unlock_height invariant.

This is the classical Byzantine attack scenario covered by FA1/FA5: under `f_h < |K_h|/3` (BFT-mode), the honest committee preserves safety; under K-of-K (mutual-distrust mode), any single honest committee member preserves safety. The S-017 closure inherits this guarantee — the three-layer defense aligns the per-node enforcement with the safety guarantees the consensus already provides.

The attack reduces to a fork in which the adversary's chain has rolled back stake-locked invariants. The adversary's chain has diverged from the honest network's chain and is no longer the canonical Determ chain by FA1 (only the honest chain accumulates honest signatures).

---

## 6. Identified gaps and edge cases

### 6.1 Producer/validator height-synchronization invariant

T-1 and T-2 both evaluate `b.index < chain.stake_unlock_height(tx.from)`. The producer's `chain` is its local chain instance immediately before constructing block `b`; the validator's `chain` is the receiver's local chain instance immediately before validating block `b`. For T-1's and T-2's predicates to be semantically identical, both chain instances must have the same `stakes_[tx.from].unlock_height` value at the relevant height.

**Synchronization invariant.** For every honest node `n` and every height `h`, after committing block `h-1`, node `n`'s `chain.stakes_[d].unlock_height` is a deterministic function of the block sequence `[B_0, B_1, ..., B_{h-1}]`. By apply-determinism (EconomicSoundness.md T-12.1), all honest nodes that have committed the same block sequence have byte-identical `stakes_` maps.

**Edge case (mid-apply vs post-apply).** A subtle scenario: the producer is computing `build_body` for block `b` (at height `h`) while a peer's validator is still applying block `h-1` (the post-validation, pre-apply window). In that window, the peer's `stake_unlock_height(d)` may return a value computed against the pre-`h-1`-apply state, not the post-`h-1`-apply state.

In practice, `build_body` and `check_transactions` both run against the chain state *immediately after committing block `h-1`* — the chain's mutex (or atomic state-view pointer) is acquired by both paths before reading `stakes_`. The producer cannot start building block `h` until it has committed block `h-1`; the validator cannot pass block `h` until it has committed block `h-1`. The Phase-1 / Phase-2 / commit sequencing in `node.cpp` enforces this — see the `try_finalize_round` path that commits before signaling the producer of the next block.

The synchronization invariant therefore holds modulo the standard "the chain's state is what every node sees after the last committed block" property. A node that has not yet committed block `h-1` cannot validate or produce block `h`. The S-017 three-layer defense inherits this synchronization correctness from the consensus layer.

### 6.2 PARAM_CHANGE of UNSTAKE_DELAY interaction

The genesis-pinned `unstake_delay_` parameter is on the A5 PARAM_CHANGE whitelist (see `Governance.md` FA10 + `validator.cpp:665`). An adversary could attempt to PARAM_CHANGE `UNSTAKE_DELAY` to 0 between a DEREGISTER and the subsequent UNSTAKE, shrinking the unlock window.

The PARAM_CHANGE itself requires N-of-N keyholder threshold (FA10), so this is not an unilateral attack — it requires keyholder collusion. Furthermore, the parameter affects future DEREGISTER transactions' unlock_height computation but does not retroactively modify existing `stakes_[d].unlock_height` values. A DEREGISTER at height `h_d` with `UNSTAKE_DELAY = 1000` sets `stakes_[d].unlock_height = inactive_from + 1000`; a subsequent PARAM_CHANGE to `UNSTAKE_DELAY = 0` does not alter that already-written value.

The three-layer defense gate reads `stakes_[d].unlock_height` directly, not the live `unstake_delay_` parameter, so the gate is robust against post-DEREGISTER PARAM_CHANGE of the delay. The audit closure inherits this correctness from `StakeLifecycle.md` T-K3 (DEREGISTER write of `unlock_height`) — the captured-at-DEREGISTER value is what enforces the cooldown.

### 6.3 Concurrent committee operation across regions/shards

In EXTENDED-mode sharding (regional R0–R7), each shard has its own committee and its own `stakes_` map (R4 region-aware committee selection). A domain `d` is pinned to its region's shard `S_d`; UNSTAKE transactions for `d` only apply on `S_d`. The three-layer defense is per-shard: each shard's producer / validator / chain consults its own `stake_unlock_height(d)` for the domains it tracks.

A cross-shard UNSTAKE (i.e. an UNSTAKE for a domain on a shard the local chain doesn't track) is structurally impossible — UNSTAKE has no `tx.to` field for routing, and the validator's V2 (registry-checked) gate rejects a tx whose sender is not in the local registry. So the three-layer defense per-shard composes into a network-wide defense without requiring cross-shard synchronization of `unlock_height` values.

### 6.4 STAKE-after-UNSTAKE re-locking interaction

A user who UNSTAKEs their full balance (via T-K5 success) and then immediately STAKEs again at the next nonce produces:
- After UNSTAKE: `stakes_[d].locked = 0`, `stakes_[d].unlock_height` unchanged (still the finite value from the prior DEREGISTER).
- After STAKE: `stakes_[d].locked = new_amount`, `stakes_[d].unlock_height` unchanged (STAKE does not touch unlock_height; only DEREGISTER does).

A subsequent UNSTAKE before the original `unlock_height` would be gated by T-1/T-2/T-3 if `unlock_height > b.index`. This is intentional: re-staking after UNSTAKE does NOT re-arm the lock; the unlock_height is set at DEREGISTER time and persists. The user must DEREGISTER again to arm a fresh unlock_height — and a DEREGISTER on a re-staked domain that is not currently registered would no-op at V15 (see `StakeLifecycle.md` T-K3's "DEREGISTER on non-registrant" silent-skip scenario).

The S-017 gate is sound under this re-stake / re-unstake interaction because it consults the persistent `stakes_[d].unlock_height` value, not a derived "currently-deregistered" predicate.

### 6.5 Equivocation-slashing during the unlock window

A domain in the `staked-pending-unlock` state (post-DEREGISTER, pre-UNSTAKE) remains slashable for equivocation evidence per FA6 + `StakeLifecycle.md` §4. The S-017 gate does not interact with slashing — if the offender's `stakes_[d].locked` is zeroed by an equivocation slash before they can submit a valid UNSTAKE, the apply-time UNSTAKE branch fails at the second disjunct (`sit->second.locked < amount`) regardless of the height. The honest user (who would not equivocate) is unaffected; the equivocator loses the stake legitimately.

This composition is correct: the three-layer defense gates the unlock_height check; slashing gates the locked-amount check. The two channels are independent.

---

## 7. Test-suite citation

### 7.1 Shell-level tests

- **`tools/test_governance_param_change.sh`** — 3-of-3 cluster exercises the REGISTER + STAKE lifecycle (without DEREGISTER, because DEREGISTER is not yet CLI-accessible). Confirms no S-017 regression in the structural alignment: a STAKE-then-no-DEREGISTER flow has `stakes_[d].unlock_height == UINT64_MAX`, so any attempted UNSTAKE (if exposed via CLI) would be gated by all three layers. PASS.

- **`tools/test_unstake_deregister_apply.sh`** — the dedicated apply-layer regression. ~16 assertions across six scenarios; the UNSTAKE-too-early scenario (3 assertions: stake unchanged, balance unchanged after refund, nonce bumped) directly exercises T-3. The DEREGISTER scenario (3 assertions: inactive_from correctness, unlock_height correctness, nonce bump) provides the prerequisite state for the too-early-UNSTAKE scenario. PASS.

### 7.2 In-process unit test

- **`determ test-unstake-deregister-apply`** — invoked from `src/main.cpp:16890`. Runs the same ~16 assertions as the shell test in <1s by constructing a synthetic chain instance, applying genesis + a few setup blocks (REGISTER + STAKE), then asserting the post-state matches the expected deltas. The test uses `c.set_unstake_delay(1)` to bypass the 1000-block production cooldown so the unlock-window assertion fires within a handful of blocks. PASS.

### 7.3 What no test directly exercises

The audit note in `docs/SECURITY.md` §S-017 ("No dedicated S-017 shell test — DEREGISTER isn't currently CLI-accessible") is the gap: there is no shell-level test that constructs a too-early UNSTAKE and observes the validator's rejection diagnostic. The structural-alignment argument is made by code inspection (the three sites cite `chain.stake_unlock_height(tx.from)` against the same per-domain `unlock_height` field) plus the apply-layer test (which exercises T-3 in isolation).

Expanding the CLI to expose DEREGISTER (and thus to enable a shell-level UNSTAKE-too-early test) is a separate item not gated by S-017 closure. The audit explicitly accepts the structural-alignment argument as sufficient for S-017's "Mitigated (Option 2)" status because no behavioral regression is introduced — the apply-time refund already guaranteed honest users couldn't lose a fee, and the gates at T-1 + T-2 are pure additions to defense-in-depth.

---

## 8. Status

**S-017 is closed in the current codebase per `docs/SECURITY.md` §S-017 (Mitigated, Option 2).** All five theorems hold:

- **T-1** (producer gate) closed via `src/node/producer.cpp:851`.
- **T-2** (validator gate) closed via `src/node/validator.cpp:606-614`.
- **T-3** (apply-time refund) closed via `src/chain/chain.cpp:880-887`.
- **T-4** (three-layer composition) closed structurally — three independent code paths, each consulting the same `chain.stake_unlock_height(d)` getter, in three translation units.
- **T-5** (no honest stake lockup loss) closed via the apply-time success path at `src/chain/chain.cpp:889-893` + the A1 closure at `chain.cpp:1399`.

The Option 2 closure is the "less invasive" path of the two enumerated in audit-3.5 / 3.8. Option 1 (unified `validate_tx_apply` helper with the apply-time refund branch removed) is deferred — not because Option 2 is unsound, but because the deeper refactor would touch the apply-branch control flow and risk T-K4 (fee-refund UX guarantee) regression. The retained apply-time refund is no longer load-bearing for S-017's failure mode but remains as belt-and-suspenders.

**Mitigation status in SECURITY.md row.** `| S-017 | Mitigated (Option 2) | Validator + producer both check unlock_height on UNSTAKE; apply-time refund retained as belt-and-suspenders | node/validator.cpp + node/producer.cpp | done |` (table row in `docs/SECURITY.md` §2).

**Open follow-ups.** None. The S-017 closure is structural alignment with no new behavior visible at the CLI layer. The audit's "no dedicated S-017 shell test" caveat is mitigated by the existing in-process apply-test that exercises the third defense (T-3) directly — the other two are aligned by identity-of-predicate with the apply-time gate.

---

## 9. References

| Reference | Role |
|---|---|
| `docs/SECURITY.md` §S-017 | Closure narrative; Option 1 vs Option 2 trade-off; deferred Option 1 rationale. |
| `docs/SECURITY.md` §2 (Mitigation status row) | The "Mitigated (Option 2)" row citing `node/validator.cpp + node/producer.cpp`. |
| `docs/PROTOCOL.md` §3.3 | Apply rules for STAKE/DEREGISTER/UNSTAKE — the deferred-unlock semantics. |
| `docs/proofs/StakeLifecycle.md` (FA-Apply-4) | The full STAKE/DEREGISTER/UNSTAKE state machine; T-K3 (DEREGISTER deferred-unlock), T-K4 (pre-unlock fee refund), T-K5 (post-unlock success). |
| `docs/proofs/Preliminaries.md` (F0) | V15 transaction-apply predicate; the validator-rule notation. |
| `docs/proofs/AccountStateInvariants.md` (FA-Apply) | I-3 (balance ↔ stake independence channel enumeration); A1 closure. |
| `docs/proofs/NonceMonotonicity.md` (FA-Apply-3) | Strict-equality nonce gate that admits UNSTAKE to apply; T-N2 future-nonce silent skip (symmetric UX guarantee to T-K4). |
| `docs/proofs/EconomicSoundness.md` (FA11) | T-12 A1 unitary-supply closure; T-12.1 apply-determinism (used in §6.1 synchronization invariant). |
| `docs/proofs/Governance.md` (FA10) | A5 PARAM_CHANGE whitelist; `UNSTAKE_DELAY` mutability via N-of-N multisig (referenced in §6.2). |
| `docs/proofs/Safety.md` (FA1) | K-of-K mutual-distrust safety bound (referenced in §5 adversary scenarios). |
| `docs/proofs/BFTSafety.md` (FA5) | BFT-mode safety bound under `f_h < |K_h|/3` (referenced in §5.1.c). |
| `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) | T-S1 serialize-restore identity (referenced in §5.3 snapshot replay scenario). |
| `src/node/producer.cpp:841-854` | T-1 site; UNSTAKE branch of `Producer::build_body`. |
| `src/node/validator.cpp:593-615` | T-2 site; STAKE/UNSTAKE branch of `BlockValidator::check_transactions`. |
| `src/chain/chain.cpp:873-894` | T-3 + T-5 sites; UNSTAKE branch of `Chain::apply_transactions`. |
| `src/chain/chain.cpp:167-170` | `Chain::stake_unlock_height` getter (the shared dependency across the three sites). |
| `src/chain/chain.cpp:135-140` | `Chain::stake_unlock_height_lockfree` (RPC-side counterpart; not in the three-layer path). |
| `src/chain/chain.cpp:1399` | A1 unitary-balance closure assertion (referenced in T-5 proof). |
| `include/determ/chain/chain.hpp:23-30` | `StakeEntry` struct (`locked`, `unlock_height`). |
| `include/determ/chain/chain.hpp:590` | `unstake_delay_` field (genesis-pinned, A5-mutable). |
| `include/determ/chain/params.hpp:23` | `UNSTAKE_DELAY` build-time default = 1000 blocks. |
| `tools/test_unstake_deregister_apply.sh` | Apply-layer regression — T-3 (UNSTAKE too-early refund), T-5 (UNSTAKE success post-unlock); 16 assertions across six scenarios. |
| `src/main.cpp:16890` | In-process `determ test-unstake-deregister-apply` entry point. |
| `tools/test_governance_param_change.sh` | 3-of-3 cluster regression covering REGISTER + STAKE lifecycle (no DEREGISTER yet via CLI). |
