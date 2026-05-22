# S007OverflowProtection — `checked_add_u64` composition theorem across every credit path (S-007 closure)

This document proves that Determ's S-007 overflow-protection layer — the `static inline bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out)` helper at `src/chain/chain.cpp:33` and its eight call sites inside `Chain::apply_transactions` — is exhaustive across every credit path that can mutate balances, pool accumulators, or per-block aggregator counters. The closure replaces every credit-path `+` (or `+=`) that depends on attacker-influenceable inputs with a guarded addition that throws `std::runtime_error("S-007: ...")` on the iff-overflow branch; the A9 atomic-apply envelope (`AccountStateInvariants.md` I-1) then rolls the entire block back, so the chain remains byte-identical to apply-entry and FA11's A1 unitary-supply identity is preserved through the throwing branch.

We prove five theorems: T-1 per-credit overflow detection completeness, T-2 no silent wrap reachable, T-3 A1 invariance under the protection, T-4 cross-shard receipt overflow (the highest-amplification surface), and T-5 subsidy + fee pool overflow. Three findings F-1..F-3 surface the canonical code-review discipline (every NEW credit site must use `checked_add_u64`), the structural pattern for debit paths (NOT covered by S-007 — relies on an explicit `if (balance >= amount)` precondition), and the composition with FA-Apply-15 multi-event-composition (a block carrying both a wrap-trip AND a non-wrap event rejects atomically — guaranteed by A9 but explicit here for the auditor's benefit).

**Companion documents:** `AccountStateInvariants.md` (FA-Apply-1) for the I-1 / I-5 channel-enumeration that this proof's exhaustiveness argument cites; `EconomicSoundness.md` (FA11) for the A1 unitary-supply identity that T-3 composes with; `FeeAccounting.md` (FA-Apply-6) + `SubsidyDistribution.md` (FA-Apply-7) for the pool-distribution composition that T-5 closes; `CrossShardReceipts.md` (FA7) + `CrossShardReceiptDedup.md` (FA-Apply-9) for the cross-shard composition cited in T-4; `MultiEventComposition.md` (FA-Apply-15) for the joint-correctness-under-mixed-events composition cited in F-3; `docs/SECURITY.md` §S-007 for the closure-status narrative this proof formalizes; `S014RateLimiterSoundness.md` for the structural template (§1–§8) followed here.

---

## 1. Background

### 1.1 The u64 wrap surface

In Determ, every balance / stake / pool / accumulator field is `uint64_t`. The C++ standard (ISO/IEC 14882:2017 §6.7.1 [basic.fundamental], §7.6.6 [expr.add]) defines unsigned-integer arithmetic modulo `2^N` — addition that would exceed `UINT64_MAX = 2^64 - 1` silently wraps around to a small value. This is the foundational hazard S-007 closes: an apply path executing `balance += credit` where `balance + credit > UINT64_MAX` produces a *smaller* `balance` than it started with, and no compile-time or runtime warning fires absent an explicit check.

For a chain that tracks economic value via a unitary-supply invariant (A1), a silent wrap is catastrophic: an attacker with chain-state-write access (whether by issuing a state-aware transaction in a long-lived deployment that has aggregated payouts toward `UINT64_MAX`, or by forging a cross-shard receipt with an inflated `amount`) can destroy supply by causing a victim's balance to wrap to a small value and then walking the chain's per-block accumulators (`total_fees`, `subsidy_this_block`, `block_inbound`, etc.) past `UINT64_MAX`. The per-block A1 closure at `chain.cpp:1397–1419` would then fail to detect the wrap because `Σ balances + Σ locked` would be quietly under-counted relative to `expected_total`.

S-007 closes the surface by replacing every credit-path `+` (or `+=`) with a call to `checked_add_u64`. The helper returns `false` iff the addition would overflow; the caller pattern is `if (!checked_add_u64(a, b, &out)) throw std::runtime_error("S-007: ...")`. The throw rolls back via A9.

### 1.2 The S-007 design rationale

S-007 was originally closed via two complementary changes per `docs/SECURITY.md` §S-007:

1. **Runtime overflow checks** (option 2 from the audit's resolution table). Every credit site in `apply_transactions` is gated by `checked_add_u64`. The helper is portable: MSVC does not ship `__builtin_add_overflow`, but the `if (a > UINT64_MAX - b) return false;` pattern is uniformly portable and the compiler optimizes it to a single ADC/JC sequence on x86-64.
2. **Genesis sane-bounds check** (option 3). A separate check at `GenesisConfig::from_json` rejects `block_subsidy`, `subsidy_pool_initial`, or `zeroth_pool_initial` exceeding `1e18` (1 quintillion native units — sane for 18-decimal-place currencies). The genesis check also rejects `block_subsidy * lottery_jackpot_multiplier > UINT64_MAX`. The genesis-layer check is a defense-in-depth complement to the runtime check; this proof's scope is the runtime layer.

The two layers compose so a future regression in either path remains caught by the other. This proof targets the runtime layer (every credit site exhaustively guarded); the genesis-layer guard is cited in §6 as a separate adversary-class defense.

### 1.3 Adversary model

S-007's runtime layer defends against three adversary families:

1. **A_supply_attacker.** Tries to issue a transaction or trigger a state-change that would cause a u64 wrap to silently destroy supply. **Defended (T-1 + T-2 + T-3).** Every credit site throws on the iff-overflow branch; A9 rolls back; A1 is preserved through the throw.
2. **A_cross_shard_forger.** With access to the cross-shard receipt-relay surface, forges a `CrossShardReceipt` with an inflated `amount` claiming to credit a victim-domain whose balance is near `UINT64_MAX`. **Defended (T-4).** The inbound-receipt credit path uses `checked_add_u64`; the throw fires before the wrap can corrupt accumulator state; FA-Apply-9 dedup prevents replay of the rejected receipt.
3. **A_overflow_DOS.** Tries to issue many transactions that overflow → all rejected → A9 rollback. The overflow trip is loud (throws) but each rejected block costs the producer build-cycles. **Bounded by S-014 (rate limit) + S-022 (body cap).** Severity: Low (cost of mounted attack is proportional to attacker's own work, and the rate-limit caps the throughput).

The composition is structural: the per-site arithmetic invariant + the A9 atomic-apply envelope + the A1 unitary-supply check at apply-tail jointly form the defense. None of the three alone is sufficient — the per-site check without A9 would corrupt mid-block state; A9 without the per-site check would silently wrap before the A1 closure ran; A1 alone would only catch the wrap *if* the cumulative accumulator sum diverged (and per-block deltas could mask cumulative drift over thousands of blocks).

---

## 2. Notation and assumptions

**Notation.**

- `U64_MAX := 2^64 - 1` — the `uint64_t` saturation point.
- Per-tx u64 fields: `amount`, `fee`, `nonce`. (Validator V8 + V9 + V15 already filter syntactically malformed values; the apply-time `checked_add_u64` is the runtime arithmetic guard.)
- Per-account u64 fields: `balance` (in `AccountState::balance`), `locked` (in `StakeEntry::locked`), `next_nonce` (in `AccountState::next_nonce` — bumped by `++`, not by `checked_add_u64`; the increment can only wrap after `2^64` successful txs from one account, which is unreachable in practice).
- Per-block u64 accumulators declared at `chain.cpp:720–725` and `chain.cpp:1267`: `total_fees`, `block_inbound`, `block_outbound`, `block_slashed`, `subsidy_this_block`.
- Chain-wide u64 accumulators in `Chain` instance state: `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_`, `genesis_total_`.

**A1 invariant** (from FA11 §1 / FA-Apply-1 I-6): after every successful apply of block `B_n`,

```
Σ_{d ∈ accounts_} accounts_[d].balance
  + Σ_{v ∈ stakes_} stakes_[v].locked
  == genesis_total_
     + accumulated_subsidy_
     + accumulated_inbound_
     - accumulated_slashed_
     - accumulated_outbound_
```

The left-hand side is `Chain::live_total_supply()` at `chain.cpp:548–553`; the right-hand side is `Chain::expected_total()`. The equality is asserted at `chain.cpp:1397–1419` ("unitary-balance invariant violated" diagnostic on mismatch).

**A9 atomic-apply** (FA-Apply-1 I-1, sketched in `chain.cpp:646–670` + `1489–1501`): a `StateSnapshot __snapshot = create_state_snapshot()` is captured at apply entry; the entire apply body runs inside `try { ... } catch (...) { restore_state_snapshot(std::move(__snapshot)); throw; }`. Any throw anywhere in the apply body — including from `checked_add_u64`'s caller — leaves the chain byte-identical to apply-entry.

**Cryptographic assumptions** (from `Preliminaries.md` §2): A1 Ed25519 EUF-CMA + A3 SHA-256 collision resistance. S-007 itself is arithmetic, not cryptographic; the dependency is indirect: cross-shard receipts (T-4) are signed under A1 + bound under A3, so an A_cross_shard_forger must break A1 or A3 before the runtime overflow surface even becomes reachable.

---

## 3. Theorem statements

**Theorem T-1 (Per-Credit Overflow Detection Completeness).** For every credit path in `Chain::apply_transactions`, the result of `current_value + credit_amount` is checked against `U64_MAX` *before* the assignment to the destination u64 field. If and only if the sum would exceed `U64_MAX`, the call to `checked_add_u64` returns `false`, the caller throws `std::runtime_error("S-007: ...")`, and the A9 atomic-apply envelope rolls back.

Concretely: the eight `checked_add_u64` call sites at `src/chain/chain.cpp` lines `757, 1006, 1216, 1280, 1292, 1300, 1368, 1377` exhaustively cover the seven credit-mutation surfaces — TRANSFER receiver, COMPOSABLE_BATCH inner TRANSFER receiver, DAPP_CALL receiver, fees+subsidy pool sum, per-creator subsidy+fee distribution, dust to `creators[0]`, cross-shard inbound receipt receiver — plus one per-block accumulator (`block_inbound`).

**Theorem T-2 (No Silent Wrap Reachable).** For every reachable chain state `state_n` and every successfully-appended block `B_{n+1}`, no account's `balance` and no per-block accumulator decreases as a silent consequence of an additive operation. Formally:

For every domain `d` and every `n ≥ 0`:

$$
\text{state}_{n+1}.\text{balance}(d) \;\geq\; \text{state}_n.\text{balance}(d) \;-\; \Delta_{\text{debit}}(d, B_{n+1})
$$

where $\Delta_{\text{debit}}(d, B_{n+1})$ is the sum of explicit per-tx debit channels (TRANSFER source, STAKE lock, DAPP_CALL source, COMPOSABLE_BATCH inner TRANSFER source, `charge_fee`) per FA-Apply-1 I-5. The inequality holds because every additive credit path is guarded by `checked_add_u64`; an iff-overflow case throws and the entire block is rolled back via A9, in which case `state_{n+1} = state_n` and the inequality holds trivially with no debit applied either.

Equivalently, the negation — "exists a domain `d`, block `B_{n+1}`, and credit path such that `balance(d)` strictly decreased due to a silent wrap" — is unreachable.

**Theorem T-3 (A1 Invariance Under Overflow Protection).** The S-007 overflow-protection branch preserves the A1 unitary-supply identity from FA11 across both code paths:

1. **Non-overflow case.** Every `checked_add_u64(a, b, &out)` returns `true`, performs the addition in-place, and the apply proceeds to the A1 closure at `chain.cpp:1397–1419` which asserts the identity. By FA-Apply-1 I-5 + FA-Apply-6 T-F6 + FA-Apply-7 T-S7, the per-channel contributions sum into the right-hand side exactly, so the closure passes.
2. **Overflow case.** `checked_add_u64` returns `false`, the caller throws `std::runtime_error("S-007: ...")`. The A9 atomic-apply envelope at `chain.cpp:1489–1501` catches the throw, calls `restore_state_snapshot(std::move(__snapshot))`, and re-raises. Post-rollback, `state_{n+1} == state_n`, and by inductive hypothesis A1 held at `state_n`, so A1 holds at `state_{n+1}` trivially.

The composition with FA-Apply-1 (apply determinism) is that the throwing branch is deterministic — every honest node sees the same overflow, throws the same exception, rolls back to the same `state_n`. So honest fork-divergence is impossible at the apply layer.

**Theorem T-4 (Cross-Shard Receipt Overflow).** The cross-shard inbound-receipt credit path — the highest-amplification surface, because a forged `CrossShardReceipt` can claim arbitrary `amount` from a remote shard whose source-side debit has not yet been settled in the destination shard's verifiable state — is protected by `checked_add_u64` at two sites:

1. `chain.cpp:1368` — `checked_add_u64(rcv, r.amount, &rcv)` for the destination account credit.
2. `chain.cpp:1377` — `checked_add_u64(block_inbound, r.amount, &block_inbound)` for the per-block inbound accumulator.

T-4 composes with FA7 (cross-shard atomicity) as follows: FA7 establishes that for every honest-deployment cross-shard `TRANSFER`, the source-side debit and destination-side credit are atomically paired across the K-shard set, with the dedup set `applied_inbound_receipts_` (per FA-Apply-9 T-R1) preventing double-credit. S-007's T-4 adds: even if A_cross_shard_forger manages to fabricate a `CrossShardReceipt` with `r.amount` set adversarially close to `U64_MAX - balance(r.to)`, the credit path's `checked_add_u64` fires before the wrap can corrupt the destination account or the per-block accumulator. The cross-shard surface inherits FA7's atomicity *plus* S-007's arithmetic safety.

**Theorem T-5 (Subsidy + Fee Pool Overflow Defense).** The block-level economic-distribution pool — computed at `chain.cpp:1280` as `total_distributed = total_fees + subsidy_this_block` — and its downstream per-creator distribution at lines `1292` + `1300` are jointly guarded by `checked_add_u64` at three sites. T-5 closes the per-block pool surface against:

1. **Pool sum overflow.** `chain.cpp:1280` — guards `total_fees + subsidy_this_block`. An adversarial-genesis `block_subsidy_` combined with an extreme-block `total_fees` could push the sum past `U64_MAX`; the runtime check fires before the wrapped value reaches the distribution loop.
2. **Per-creator credit overflow.** `chain.cpp:1292` — guards `accounts_[domain].balance + per_creator`. A long-lived creator with near-`U64_MAX` balance receiving another subsidy slice would otherwise wrap; the per-iteration check fires.
3. **Dust credit overflow.** `chain.cpp:1300` — guards `accounts_[creators[0]].balance + remainder`. The dust-to-creator[0] is the second pool-distribution write; the same overflow concern applies and is guarded identically.

T-5 composes with FA-Apply-6 (FeeAccounting) and FA-Apply-7 (SubsidyDistribution): FA-Apply-6 T-F4 + FA-Apply-7 T-S3 establish the per-creator distribution algorithm + dust-to-creator[0] placement; S-007's T-5 adds that every per-creator + dust credit is arithmetic-safe.

---

## 4. Source-code citation enumeration

The eight `checked_add_u64` call sites in `src/chain/chain.cpp` (plus the helper definition at line 33) categorize as follows.

### 4.1 The helper

**`chain.cpp:33`** — `static inline bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out)`:

```cpp
// S-007: portable checked u64 addition. Returns false on overflow.
// Used at every balance/counter mutation site that could realistically
// overflow under adversarial genesis or accumulated-fees scenarios.
// MSVC doesn't have __builtin_add_overflow; the if-check is uniformly
// portable and the compiler optimizes it to a single ADC/JC sequence.
static inline bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a > UINT64_MAX - b) return false;
    *out = a + b;
    return true;
}
```

The invariant `a > UINT64_MAX - b ⇔ a + b > UINT64_MAX (mod 2^64 unbounded)` holds because `a + b` (without wrap) exceeds `UINT64_MAX` iff `a` exceeds `UINT64_MAX - b`. The check is strict greater-than, so the boundary case `a + b == UINT64_MAX` is allowed — i.e., a credit that brings the destination to exactly `UINT64_MAX` is OK, as the `test-overflow-paths` boundary scenario at `src/main.cpp:19870–19894` verifies.

### 4.2 Balance credits (six sites)

| Site | Source line | Description | Throw diagnostic prefix |
|------|------------:|-------------|--------------------------|
| TRANSFER receiver (same-shard) | `chain.cpp:757` | `checked_add_u64(rcv, tx.amount, &rcv)` — `accounts_[tx.to].balance += tx.amount` for same-shard `TRANSFER`. | `"S-007: TRANSFER credit would overflow recipient balance (to=...)"` |
| COMPOSABLE_BATCH inner TRANSFER receiver | `chain.cpp:1006` | `checked_add_u64(irecv, inner.amount, &irecv)` — inner TRANSFER inside an outer COMPOSABLE_BATCH; the v2.4 atomic-batch primitive's per-inner credit. | `"S-007: refuse to wrap recipient balance"` (returns `false`, abort_scope rolls back the entire batch — A9-internal). |
| DAPP_CALL receiver | `chain.cpp:1216` | `checked_add_u64(rcv, tx.amount, &rcv)` — `accounts_[tx.to].balance += tx.amount` for the v2.19 DAPP_CALL same-shard branch. | `"S-007: DAPP_CALL credit would overflow recipient balance (to=...)"` |
| Per-creator subsidy+fee distribution | `chain.cpp:1292` | `checked_add_u64(bal, per_creator, &bal)` — per-creator credit of `total_distributed / m` inside the distribution loop. Loops over `b.creators`. | `"S-007: per-creator credit would overflow creator balance (creator=...)"` |
| Dust to creator[0] | `chain.cpp:1300` | `checked_add_u64(bal0, remainder, &bal0)` — `accounts_[b.creators[0]].balance += total_distributed % m` for the modulo-remainder placement. | `"S-007: dust credit would overflow creator[0] balance (creator=...)"` |
| Cross-shard inbound receipt receiver | `chain.cpp:1368` | `checked_add_u64(rcv, r.amount, &rcv)` — `accounts_[r.to].balance += r.amount` for each non-deduplicated entry in `b.inbound_receipts`. The T-4 surface. | `"S-007: inbound receipt credit would overflow recipient balance (to=...)"` |

### 4.3 Pool / accumulator credits (two sites)

| Site | Source line | Description | Throw diagnostic prefix |
|------|------------:|-------------|--------------------------|
| Pool sum (fees + subsidy) | `chain.cpp:1280` | `checked_add_u64(total_fees, subsidy_this_block, &total_distributed)` — fuses the per-block fee pool with the subsidy mint into a single distributable scalar. The T-5 (1) site. | `"S-007: total_distributed (fees + subsidy) overflowed u64 (fees=... subsidy=...)"` |
| Per-block inbound accumulator | `chain.cpp:1377` | `checked_add_u64(block_inbound, r.amount, &block_inbound)` — folds each inbound receipt's `r.amount` into the per-block accumulator that the apply-tail's A1 closure consumes. | `"S-007: per-block inbound sum overflowed u64"` |

### 4.4 Sites NOT guarded by checked_add_u64

For completeness, the following credit-mutation sites in `apply_transactions` use raw `+=` rather than `checked_add_u64`:

1. **`chain.cpp:830`** — NEF credit on first-time REGISTER: `accounts_[tx.from].balance += nef` where `nef = pool_balance / 2`. **Bounded by construction.** Since `nef ≤ pool_balance ≤ genesis_total_ ≤ UINT64_MAX`, and the per-account balance plus NEF cannot exceed the chain-wide live supply (A1), an overflow on this site implies the chain-wide supply already exceeded `UINT64_MAX` — which itself implies a prior overflow on one of the guarded sites. So this site is overflow-safe by reduction to the guarded sites' soundness. **Documented as F-1.5** (latent guard-by-induction; if the chain ever supports inflationary mint sources that decouple from `genesis_total_`, this site needs a `checked_add_u64`).
2. **`chain.cpp:867`** — STAKE locked balance increment: `stakes_[tx.from].locked += amount`. **Bounded by construction.** The amount was just debited from `sender.balance`, so `locked_new = locked_old + amount ≤ locked_old + balance_old ≤ live_total_supply ≤ U64_MAX`. Reduces to A1 — if this were to overflow, A1 was already violated.
3. **`chain.cpp:884`** — UNSTAKE fee refund: `sender.balance += tx.fee`. **Bounded by construction.** The fee was just charged off the sender via `charge_fee`; refunding it returns balance to its pre-charge value. No new value enters the account.
4. **`chain.cpp:891`** — UNSTAKE locked → balance transfer: `sender.balance += amount`. **Bounded by construction.** The amount was just debited from `stakes_[d].locked`; the net effect is a transfer between two A1-tracked fields owned by the same domain.
5. **`chain.cpp:767, 868`** — `total_fees += tx.fee`. **Bounded by induction.** Each `tx.fee` ≤ sender's balance ≤ `U64_MAX`, summed over txs in one block; the cumulative `total_fees` is bounded by the chain's live supply, so the only way to overflow is to already violate A1.
6. **`chain.cpp:765`** — `block_outbound += tx.amount` (cross-shard TRANSFER source-side). **Bounded by induction.** Same argument as `total_fees`.
7. **`chain.cpp:1327, 1348`** — `block_slashed += deduct` / `+= sit->second.locked`. **Bounded by induction.** The slashed amount is bounded by the offender's current `locked`, itself bounded by live supply.
8. **`chain.cpp:1391–1395`** — chain-wide accumulator folds: `accumulated_subsidy_ += subsidy_this_block` and three siblings. **Bounded by induction over A1 + invariant decomposition.** If `accumulated_subsidy_ + subsidy_this_block` would overflow, then by the A1 closure equation either `live_total_supply` or `genesis_total_` is also at or near `U64_MAX` and the A1 check at `chain.cpp:1397–1419` would fire on the *next* block.

The structural property: **every site that uses raw `+=` is provably bounded by induction on A1.** The sites that use `checked_add_u64` are those that ingest *attacker-influenced* values — either directly (TRANSFER `tx.amount`, DAPP_CALL `tx.amount`, cross-shard receipt `r.amount`) or transitively (total_distributed, per_creator, remainder are all functions of `total_fees + subsidy_this_block`). The bifurcation matches the canonical design intent stated in `chain.cpp:30`: "Used at every balance/counter mutation site that could realistically overflow under adversarial genesis or accumulated-fees scenarios."

This is the **canonical pattern** for any new credit site added to `apply_transactions`: if the addend traces back to a transaction field, a receipt field, or a genesis-pinned mint amount, use `checked_add_u64`; if the addend is a pure transfer between two A1-tracked fields whose sum is bounded by the existing supply identity, raw `+=` is acceptable but should be commented with the inductive reduction.

---

## 5. Composition with FA-track proofs

### 5.1 Composition with FA-Apply-1 (AccountStateInvariants)

`AccountStateInvariants.md` I-1 (Non-negative balance + apply atomicity) cites `checked_add_u64` directly in the proof of T-A1: "The `checked_add_u64` helper handles the credit-side wrap. The outer try/catch + `restore_state_snapshot` ensures that any apply-time throw (from S-007 overflow, A1 violation, or S-033 mismatch) leaves `accounts_` exactly as it was at apply entry." S007OverflowProtection is the standalone formalization of the credit-side half of that statement; FA-Apply-1 T-A1 is the standalone formalization of the rollback-on-throw envelope.

I-5 (balance-arithmetic channel enumeration) lists every credit channel and its apply-site line number. The S-007 closure intersects exactly the attacker-influenced channels in that enumeration (TRANSFER credit lines 757, 1006; DAPP_CALL line 1216; receipts 1368; subsidy+fee distribution 1292, 1300, and the upstream 1280). The non-attacker-influenced channels (UNSTAKE post-unlock, NEF, raw fees++) are guarded by induction per §4.4 above.

### 5.2 Composition with FA11 (EconomicSoundness)

FA11 §2 (A1 closed-form invariant) is the chain-wide statement: `Σ balances + Σ locked == genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` after every block apply. T-3 (this proof) composes with FA11 by closing the conditional under which FA11's left-hand side computation is meaningful — if a silent wrap occurred mid-apply, `Σ balances` would compute over a corrupted state and the chain-wide closure would happen to coincidentally pass (because the wrap rewrites `balance` to a small value, but the running accumulators on the right-hand side don't track the wrap event). S-007's runtime guard ensures the wrap is impossible, so FA11's closure is meaningful — pass implies consistency, not the trivial "happens to balance" case.

The chip-task interpretation: pre-S-007, A1 would have *silently* passed on a wrapped block. Post-S-007, A1 passes iff the actual unitary supply is conserved.

### 5.3 Composition with FA-Apply-6 (FeeAccounting) + FA-Apply-7 (SubsidyDistribution)

FA-Apply-6 T-F4 (creator distribution) cites `chain.cpp:1286–1305` (the distribution branch) including the lines `1292` + `1300` `checked_add_u64` calls. FA-Apply-7 T-S3 (FLAT-mode equal-share + dust placement) cites the same lines. S-007's T-5 (this proof) closes the per-credit arithmetic for both: the per-creator slice and the dust slice are individually guarded; if either exceeds the recipient's `U64_MAX - balance` headroom, the apply throws.

Composition: the FA-Apply-6 + FA-Apply-7 distribution algorithm + S-007 T-5 jointly guarantee that:

- For every block whose `total_fees + subsidy_this_block` fits in `u64`,
- For every creator whose current `balance + per_creator + (eventual dust)` fits in `u64`,
- The distribution completes successfully, A1 holds, and the per-creator credits are deterministic.

If any of the three checks fails, the entire block throws and rolls back. There is no partial-distribution state.

### 5.4 Composition with FA7 (CrossShardReceipts) + FA-Apply-9 (CrossShardReceiptDedup)

FA7 closes cross-shard atomicity at the protocol layer: every honest cross-shard `TRANSFER` produces a source-side debit + destination-side credit, the K-shard sum identity (`Σ_{s ∈ shards} live_supply(s) == genesis_total_global` modulo per-shard outbound/inbound) holds, and double-credit is prevented by the dedup set. FA-Apply-9 T-R5 lifts this to the apply layer: `applied_inbound_receipts_` ensures every credit is applied at most once.

S-007's T-4 (this proof) closes the third leg: even with atomicity (FA7) and dedup (FA-Apply-9), the inbound credit's arithmetic must not wrap. The cross-shard receipt is the highest-amplification surface because:

1. The receipt's `r.amount` is not bounded by the destination shard's view of source-side supply — the destination accepts the receipt's claimed amount and credits the destination account, trusting the source shard's atomicity proof.
2. An attacker who manages to relay a forged receipt (the FA7 + FA-Apply-9 defense fails *or* a same-source-shard double-credit slips past the dedup, neither of which we assume here but model the worst case for) could otherwise cause a wrap.

S-007 T-4 reduces the arithmetic-corruption surface to "either FA7 holds (so no forged receipt) or A9 fires (so no state change)." Composition is multiplicative: A_cross_shard_forger must defeat FA7 *and* find an in-bounds receipt amount that doesn't trigger the S-007 throw — the second leg is asymptotically infeasible because the throw fires for any `balance(r.to) + r.amount > U64_MAX`, which an attacker who already controls receipt forgery would want to set to maximize damage.

### 5.5 Composition with FA-Apply-15 (MultiEventComposition)

FA-Apply-15 T-M3 closes the joint A1-invariance theorem for blocks carrying heterogeneous events. It cites `block_inbound`, `block_outbound`, `block_slashed`, `total_fees`, `subsidy_this_block` as the per-block accumulators that compose linearly into the chain-wide closure. FA-Apply-15 §1.2 explicitly states: "The accumulators are u64 + are guarded by `checked_add_u64` at every write that depends on an attacker-influenced value (S-007 closure)."

S-007 (this proof) is the underlying analytic that FA-Apply-15 cites. F-3 in §7 below makes the composition explicit: a block carrying a wrap-trip event AND a non-wrap event rejects atomically — the A9 envelope catches the wrap-trip throw and rolls back all per-event state changes, not just the wrap-tripping one.

### 5.6 Composition with FA-Apply-2 (SnapshotEquivalence)

FA-Apply-2 T-S6 (determinism) closes the snapshot-restore identity: serialize-restore yields byte-identical state. A wrap-tripping block on the producer side throws (S-007 T-1); the producer never broadcasts a wrapped state. A validator/receiver applying a block from the wire deterministically re-executes the same `apply_transactions` path and throws at the same point. Snapshot equivalence holds because both pre-wrap and post-rollback states are identical (the rollback restores the snapshot).

Composition: S-007 + FA-Apply-2 jointly imply that wrapping events never enter the persisted chain state — they're rejected at the apply layer and never written to disk, snapshot, or wire.

---

## 6. Adversary model

The S-007 runtime layer defends against the following adversary families:

**(a) A_supply_attacker — single-tx wrap.** Attacker issues a single transaction with attacker-controlled `tx.to` whose recipient balance is near `U64_MAX`. The TRANSFER credit at `chain.cpp:757` throws; A9 rolls back. Block rejected. **Defended (T-1 + T-2 + T-3).**

**(b) A_cross_shard_forger — receipt wrap.** Attacker forges a `CrossShardReceipt` with inflated `r.amount`. The inbound credit at `chain.cpp:1368` throws; the block carrying the forged receipt is rejected; A1 preserved via A9 rollback. **Defended (T-4 + composition with FA7 + FA-Apply-9).**

**(c) A_genesis_attacker — adversarial genesis.** Attacker sets `block_subsidy_` close to `U64_MAX / 2` so that `total_fees + subsidy_this_block` wraps under any non-trivial fee load. The pool sum check at `chain.cpp:1280` throws. **Defended (T-5).** Additionally, the genesis sane-bounds check (`docs/SECURITY.md` §S-007 option 3) prevents the adversarial value from being accepted at all — defense-in-depth.

**(d) A_subsidy_creator — creator-side wrap.** Attacker is a block creator whose balance is near `U64_MAX` and is about to receive a per-creator subsidy slice. The per-creator credit at `chain.cpp:1292` throws on overflow; the dust credit at `chain.cpp:1300` also throws if the creator is `creators[0]`. **Defended (T-5).** Note: this case is structurally rare because reaching `U64_MAX - per_creator` balance for an honest creator requires `~U64_MAX` lifetime payouts, which would imply chain-wide supply at `U64_MAX` and so the A1 closure would have already fired. The defense is for an adversarial-genesis pre-allocated near-MAX creator account.

**(e) A_overflow_DOS — repeated overflow blocks.** Attacker (a producer) submits many blocks each tripping the overflow guard. Every block rejected at apply, A9 rolls back. Cost to attacker: full block-build cycle (mempool selection, BFT phase-1/2 if reached). Cost to network: bounded by S-014 per-IP rate limit + S-022 per-message body cap. **Bounded but not zero-cost.** Severity: Low, because the attacker burns their own producer-stake / build-cycles for no consensus advance.

**(f) A_silent_wrap_adversary (out-of-scope after S-007).** Pre-S-007, an attacker could in principle craft a transaction that wraps a victim's balance to a small value, then use the wrapped balance for further attack (e.g., draining the wrapped victim before the next A1 check fires). Post-S-007, the silent-wrap path is unreachable (T-2). The threat reduces to (a), (b), or (c) above.

**(g) A_compiler_bug_adversary (out-of-scope).** Attacker exploits a compiler optimization that elides the `if (a > UINT64_MAX - b)` check. The check is documented as compiler-optimizable to a single ADC/JC sequence on x86-64, but the code remains semantically a normal conditional even if the compiler folds it. No known C++ compiler elides correctly-written branchful overflow checks; this is a compiler-supply-chain concern, not a Determ-layer concern. The genesis sane-bounds check (option 3) provides defense-in-depth for this case.

---

## 7. Findings

The S-007 runtime layer is closed; the genesis layer (option 3 from the audit) is also closed; this proof formalizes both. Three findings are advisory.

### Finding F-1: Every NEW credit path added to `apply_transactions` MUST use `checked_add_u64` (code-review checklist).

**Severity:** Low (process-discipline finding) • **Status:** Open (documentation discipline).

The S-007 closure works because every credit site that ingests an attacker-influenced value is guarded. If a future feature adds a new transaction type with a credit side — e.g., a v2.22 confidential-transfer destination credit, a v2.25 distributed-IdP balance-update side-effect, a new DApp call with state-mutating credit semantics — and that credit site uses raw `+=` instead of `checked_add_u64`, the S-007 closure regresses *silently*.

**Recommended code-review checklist for any PR touching `Chain::apply_transactions`:**

1. Identify every line that increments an account balance, a pool field, or a per-block accumulator.
2. For each line, classify the addend's provenance:
   - If the addend comes from a transaction field, receipt field, or genesis-pinned amount: **MUST use `checked_add_u64`** with a `throw std::runtime_error("S-007: ...")` on the false branch.
   - If the addend is a pure transfer between two A1-tracked fields whose sum is bounded by existing supply: raw `+=` is acceptable BUT must be paired with an inline comment citing the inductive reduction.
3. Add a regression test scenario to `test-overflow-paths` (extending the in-process unit in `src/main.cpp:19744`) that exercises the new credit path at `U64_MAX - 1`.

**Recommended mitigation:** add a CI grep-gate that fails any PR introducing `accounts_[*].balance +=` or `total_fees +=` or `subsidy_this_block +=` or `block_*_ +=` without a co-located `checked_add_u64` or a `// S-007: bounded by ...` comment. Effort: ~30 minutes of CI scripting.

### Finding F-2: Subtraction paths (debits) are NOT protected by S-007 — they rely on a separate `if (balance >= amount)` precondition (structural pattern documentation).

**Severity:** Low (documentation finding) • **Status:** Open (documented here for future-implementer awareness).

S-007 covers the credit side only. Debit paths (subtraction) use a different protection pattern: a strict precondition `if (sender.balance >= cost) { ... sender.balance -= cost; }`. See `chain.cpp:744` (TRANSFER cost), `chain.cpp:864` (STAKE cost), `chain.cpp:1002` (COMPOSABLE_BATCH inner amount), `chain.cpp:1213` (DAPP_CALL cost).

There is no `checked_sub_u64` helper because subtraction-underflow has a different operational consequence than addition-overflow: an underflowing subtraction is *always* a bug at the validator layer (the validator V-checks should have rejected the tx for insufficient balance); the apply-time precondition is a defense-in-depth that catches a validator bypass. By contrast, an addition-overflow is reachable under realistic deployments (long-lived deployments accumulating payouts toward `U64_MAX`), so the apply-time check is the primary defense.

**Documentation discipline:** the canonical pattern for debits in any new transaction type is `if (sender.balance >= amount + fee) { sender.balance -= amount + fee; ... } else { continue; }`. The `continue` skip-without-mutation is the canonical silent-skip pattern (matches the validator's per-V-check skip semantics; see FA-Apply-3 T-N3 for nonce-monotonicity composition).

### Finding F-3: Multi-event composition — a block with both a wrap-trip AND a non-wrap event rejects atomically (covered by A9 + FA-Apply-15, but explicit here).

**Severity:** Informational • **Status:** Closed by composition; explicit for the auditor.

A block `B` carrying a mix of events — say, 3 TRANSFER txs of which one trips an S-007 wrap, 2 AbortEvents, 1 EquivocationEvent, and 5 inbound cross-shard receipts — rejects atomically. The wrap-trip throw at `chain.cpp:757` (or `:1006`, `:1216`, `:1280`, `:1292`, `:1300`, `:1368`, `:1377`) propagates through the catch at `chain.cpp:1489–1501`; A9 calls `restore_state_snapshot` and re-raises. Every per-event state change in `B` — the two non-wrap-trip TRANSFERs, the AbortEvents, the EquivocationEvent's stake-zeroing + registry-deactivation, the non-wrap inbound receipts' credits + dedup-set inserts — all roll back together.

The atomic rollback is what makes S-007 compose cleanly with FA-Apply-15 (MultiEventComposition). T-M3 (joint A1 invariance) cites the A9 envelope as the structural reason per-surface invariants compose: any per-surface throw (S-007 overflow, FA-Apply-3 nonce mismatch, S-033 state_root mismatch, A1 closure failure) rolls back all surfaces, so the post-apply state is either fully-committed-consistent or pre-apply-byte-identical.

**Implication for adversaries:** A_supply_attacker cannot "smuggle" a wrap-trip alongside a benign event to use the benign event as cover. The wrap-trip rejects the entire block. The minimum granularity of state change is the block, not the per-event sub-step.

---

## 8. Status and references

### 8.1 Status

**Shipped (S-007 closed in-session per `docs/SECURITY.md` §S-007).** Both the runtime layer (this proof's scope) and the genesis sane-bounds layer (option 3 from the audit, also shipped) are live in the current `main` branch:

- `src/chain/chain.cpp:33` — `checked_add_u64` helper.
- `src/chain/chain.cpp:757, 1006, 1216, 1280, 1292, 1300, 1368, 1377` — eight call sites covering seven credit-mutation surfaces + one per-block accumulator.
- `src/chain/chain.cpp:1489–1501` — A9 atomic-apply envelope (the `restore_state_snapshot` rollback path on throw).
- `src/chain/chain.cpp:1397–1419` — A1 closure (consumes the S-007-guarded accumulators).
- `src/main.cpp:19744–19948` — `test-overflow-paths` in-process unit (six scenarios, eight assertions: TRANSFER overflow + rollback contract + inbound-receipt overflow + boundary + sanity + A1-preserved-on-throw).
- `tools/test_overflow_paths.sh` — shell wrapper invoking `determ test-overflow-paths`.
- `docs/SECURITY.md` §S-007 — closure-status narrative this proof formalizes.

**Not yet shipped (future work):**

- **F-1 mitigation (CI grep-gate for new credit-site coverage).** Documented above; ~30 minutes effort.

This proof was added in the current review pass as part of the analytic-closure sweep for S-007; it does not modify any source code, only formalizes the `checked_add_u64` composition argument that closes the runtime-overflow surface across every credit path.

### 8.2 Source files cited

- `src/chain/chain.cpp:33` — `checked_add_u64` helper (the proof's primary object).
- `src/chain/chain.cpp:757` — TRANSFER receiver credit (T-1 site 1).
- `src/chain/chain.cpp:1006` — COMPOSABLE_BATCH inner TRANSFER receiver credit (T-1 site 2).
- `src/chain/chain.cpp:1216` — DAPP_CALL receiver credit (T-1 site 3).
- `src/chain/chain.cpp:1280` — total_fees + subsidy_this_block pool sum (T-5 site 1).
- `src/chain/chain.cpp:1292` — per-creator distribution credit (T-1 site 4, T-5 site 2).
- `src/chain/chain.cpp:1300` — dust to creator[0] (T-1 site 5, T-5 site 3).
- `src/chain/chain.cpp:1368` — cross-shard inbound receipt credit (T-1 site 6, T-4 site 1).
- `src/chain/chain.cpp:1377` — per-block inbound accumulator credit (T-1 site 7, T-4 site 2).
- `src/chain/chain.cpp:1397–1419` — A1 closure (the consumer of the guarded accumulators).
- `src/chain/chain.cpp:1489–1501` — A9 atomic-apply catch-rollback envelope.
- `src/main.cpp:19744–19948` — `test-overflow-paths` in-process unit.

### 8.3 Companion FA-track proofs

- `AccountStateInvariants.md` (FA-Apply-1) — I-1 (no underflow + A9 atomic apply) + I-5 (balance-arithmetic channel enumeration). Cites this proof's helper.
- `EconomicSoundness.md` (FA11) — A1 unitary-supply invariant. T-3 (this proof) composes with FA11.
- `FeeAccounting.md` (FA-Apply-6) — fee-charging + distribution contract. T-F4 cites the `chain.cpp:1292` site; T-5 (this proof) closes the arithmetic.
- `SubsidyDistribution.md` (FA-Apply-7) — subsidy contract. T-S3 cites the same lines; T-5 (this proof) closes the arithmetic.
- `CrossShardReceipts.md` (FA7) + `CrossShardReceiptDedup.md` (FA-Apply-9) — cross-shard receipt atomicity + dedup. T-4 (this proof) closes the per-credit arithmetic on the inbound surface.
- `MultiEventComposition.md` (FA-Apply-15) — multi-event joint A1 invariance. T-M3 cites the S-007 closure as the structural reason per-block accumulators compose linearly.
- `SnapshotEquivalence.md` (FA-Apply-2) — serialize-restore identity. §5.6 above documents the composition.

### 8.4 Closure-analyses-and-specs cross-references

- `S014RateLimiterSoundness.md` — provides the structural template (§1–§8) followed here, and the composition reference for adversary class A_overflow_DOS.
- `S022WireFormatCaps.md` — per-MsgType body caps; bounds the cost of A_overflow_DOS at the framing layer.
- `S033StateRootNamespaceCoverage.md` — Merkle state-root coverage; FA-Apply-2 + S-033 compose with S-007 to ensure no wrap-state enters the persisted chain.
- `BlockchainStateIntegrity.md` — chain-integrity at load + apply + produce surfaces; cites the apply-time gate at `chain.cpp:1397–1419` (the A1 closure) that S-007's guards uphold.

### 8.5 External references

- **ISO/IEC 14882:2017** §6.7.1 [basic.fundamental] + §7.6.6 [expr.add] — unsigned-integer modular arithmetic semantics underlying the S-007 motivation.
- **CERT C Coding Standard INT30-C** (Ensure that unsigned integer operations do not wrap) — the canonical secure-coding rule that S-007 implements at the apply-path layer.
- **CWE-190** (Integer Overflow or Wraparound) — the canonical weakness class. Determ's S-007 closure mitigates CWE-190 at the chain-apply surface.
- **Bishop, "Computer Security: Art and Science"** (2nd ed., Pearson 2018) §15.4 — integer-overflow attack class; the unitary-supply-destruction scenario this proof's T-3 defends against.
