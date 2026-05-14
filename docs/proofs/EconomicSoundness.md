# FA11 — Economic soundness (A1 unitary balance + E1/E3/E4)

This document proves that Determ's economic primitives — A1 (unitary supply invariant), E1 (Negative Entry Fee from Zeroth pool), E3 (lottery subsidy mode), E4 (finite subsidy fund) — collectively preserve a closed-form supply ledger across every block apply. The bound is sharp: total live value across all accounts and stakes exactly matches `genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` after every block.

Three properties matter:

1. **A1 closed-form invariant.** After every `apply_transactions`, the live sum across accounts.balance + stakes.locked equals the expected total derived from the running counters.
2. **E1 supply neutrality.** Negative-Entry-Fee distribution from the Zeroth pool is a balance transfer, not a mint — it consumes pool balance and credits the registrant, leaving total supply unchanged.
3. **E3 + E4 expected-value preservation.** Lottery mode preserves the same total issuance schedule as FLAT under the finite-pool cap.

The proof is mechanical because the apply path explicitly tracks per-block deltas for every counter and asserts the invariant at the end.

**Companion documents:** `Preliminaries.md` (F0); `CrossShardReceipts.md` (FA7) for the cross-shard `inbound`/`outbound` semantics.

---

## 1. Mechanism summary

### A1 counters (Chain instance state)

```cpp
uint64_t genesis_total_;          // sum at index-0 apply: balances + stakes
uint64_t accumulated_subsidy_;    // monotone increase
uint64_t accumulated_slashed_;    // monotone increase
uint64_t accumulated_inbound_;    // monotone increase (cross-shard credits in)
uint64_t accumulated_outbound_;   // monotone increase (cross-shard debits out)
```

### Invariant

After every block apply:

```
Σ accounts[a].balance + Σ stakes[v].locked
    == genesis_total + accumulated_subsidy + accumulated_inbound
       − accumulated_slashed − accumulated_outbound
```

Enforced via direct C++ assertion at `apply_transactions` tail; mismatch throws with a diagnostic (chain.cpp ~ line 530).

### E1 NEF flow

On first-time REGISTER apply (the registrant was not previously in `registrants_`), if `accounts[ZEROTH_ADDRESS].balance > 0`:

```cpp
nef = accounts[ZEROTH_ADDRESS].balance / 2;
accounts[ZEROTH_ADDRESS].balance       -= nef;
accounts[tx.from].balance              += nef;
```

The Zeroth pool address is the canonical `0x00…0` and has no usable private key (validator rejects any tx with `from == ZEROTH_ADDRESS`). Pool seeding happens at genesis via `zeroth_pool_initial`, which is included in `genesis_total_` at index-0 apply.

### E3 lottery + E4 finite pool

Per-block subsidy computation:

```cpp
base_subsidy = block_subsidy_                              // FLAT default
if subsidy_mode_ == 1 (LOTTERY):
    lottery_seed = first 8 bytes of cumulative_rand
    if lottery_seed % lottery_jackpot_multiplier_ == 0:
        base_subsidy = block_subsidy_ * multiplier         // jackpot
    else:
        base_subsidy = 0                                   // miss

if subsidy_pool_initial_ > 0:                              // E4 cap
    remaining = subsidy_pool_initial_ − accumulated_subsidy_
    subsidy_this_block = min(base_subsidy, remaining)

distribute subsidy_this_block + fees across creators
accumulated_subsidy_ += subsidy_this_block (only when distributed)
```

---

## 2. Theorem statements

**Theorem T-12 (A1 closed-form supply invariant).** For every finalized block `b` accepted by `apply_transactions`, the post-apply chain state satisfies:

```
live_total_supply() == expected_total()
```

where:
- `live_total_supply()` = `Σ accounts[a].balance + Σ stakes[v].locked` (O(N) walk over both maps).
- `expected_total()` = `genesis_total_ + accumulated_subsidy_ + accumulated_inbound_ − accumulated_slashed_ − accumulated_outbound_`.

Holds unconditionally — no cryptographic assumption required; the property is structural.

**Theorem T-13 (E1 supply neutrality).** Every NEF distribution event preserves T-12 trivially: the pre-event sum and post-event sum across `Σ accounts[a].balance` are equal (balance moves from `ZEROTH_ADDRESS` to the registrant; `accumulated_subsidy_` and other counters are unchanged).

**Theorem T-14 (E3+E4 expected-value preservation + hard cap).** Under T-12:

1. **(Hard cap.)** When `subsidy_pool_initial_ > 0`, `accumulated_subsidy_ ≤ subsidy_pool_initial_` for every finalized block. The pool exhausts monotonically; subsequent blocks pay 0 subsidy.
2. **(Expected value under LOTTERY.)** Under SubsidyMode = LOTTERY with multiplier M and uniform `cumulative_rand`, the expected per-block payout is `block_subsidy_` (same as FLAT). Concretely, `E[payout] = (1/M) · (block_subsidy_ · M) + ((M−1)/M) · 0 = block_subsidy_`.

**Corollary T-12.1 (Determinism).** Two honest nodes applying the same block sequence reach byte-identical A1 counters after each apply. Snapshots taken at the same block index are byte-identical with respect to all counters.

---

## 3. Proof of T-12

By induction on block index.

**Base case (block 0).** The genesis apply path (`if (b.index == 0)` branch) computes:

```cpp
gtotal = 0;
for a in initial_state:
    accounts[a.domain].balance = a.balance;  gtotal += a.balance;
    if a.stake > 0:
        stakes[a.domain].locked = a.stake;   gtotal += a.stake;
genesis_total_       = gtotal;
accumulated_subsidy_ = 0;  ...  accumulated_outbound_ = 0;
```

Live sum at index-0 exit equals `gtotal = genesis_total_`, with all counters zero. ⇒ `live = expected`. ✓

**Inductive step.** Suppose `live == expected` before applying block `h`. The apply path's per-block delta tracking:

- TRANSFER (same-shard): sender.balance −= amount + fee; receiver.balance += amount; fees aggregated. Net change in `Σ balances`: −fee (fee credited to creators; tracked below).
- TRANSFER (cross-shard): sender.balance −= amount + fee; `block_outbound += amount`. Net change in `Σ balances`: −(amount + fee). The `amount` is captured by `accumulated_outbound_`; the fee is credited to creators.
- REGISTER: sender pays fee (-= fee, → creators). E1 NEF: pool → registrant transfer, sum-preserving. Net change in `Σ balances`: −fee, modulo NEF transfer which is sum-preserving.
- STAKE: balance → locked (sum preserving).
- UNSTAKE (eligible): locked → balance (sum preserving). Fee deducted: −fee.
- DEREGISTER: −fee.
- PARAM_CHANGE, MERGE_EVENT: −fee.

Fee aggregation: `total_fees` summed across all txs is credited to creators alongside subsidy. Net effect on `Σ balances + Σ locked`:

```
Δ live = −(Σ fees) − (block_outbound) + (block_inbound) + total_distributed − block_slashed
```

where `total_distributed = total_fees + subsidy_this_block`. Substituting:

```
Δ live = −(Σ fees) + total_fees + subsidy_this_block − block_outbound + block_inbound − block_slashed
       = +subsidy_this_block + block_inbound − block_outbound − block_slashed
```

(The `−(Σ fees) + total_fees = 0` cancellation is exact: every fee deducted from a sender is added to `total_fees`.)

Counter updates at apply tail:

```
accumulated_subsidy_  += subsidy_this_block  (when distributed > 0 and creators non-empty)
accumulated_inbound_  += block_inbound
accumulated_outbound_ += block_outbound
accumulated_slashed_  += block_slashed
```

⇒ `Δ expected = +subsidy_this_block + block_inbound − block_outbound − block_slashed = Δ live`.

The post-apply assertion `live == expected` is `pre-live + Δ live == pre-expected + Δ expected = (pre-expected) + Δ live` by IH. ⇒ live == expected. ✓ ∎

---

## 4. Proof of T-13 (E1 NEF neutrality)

The NEF branch is structurally a balance-only transfer within `Σ accounts.balance`:

```cpp
nef = accounts[ZEROTH_ADDRESS].balance / 2;
if nef > 0:
    accounts[ZEROTH_ADDRESS].balance -= nef;
    accounts[tx.from].balance        += nef;
```

Δ(Σ balances) = −nef + nef = 0. No counter is touched by the NEF branch. T-12's invariant is preserved trivially.

The Zeroth pool's initial balance is counted in `genesis_total_` at index-0 apply (line 212 of chain.cpp seeds it via `initial_state[]` like any other genesis account). Subsequent NEF distributions move balance within the accounts map without altering `genesis_total_` or any other counter. ∎

---

## 5. Proof of T-14

### 5.1 Hard cap

`subsidy_this_block = min(base_subsidy, remaining)` where `remaining = subsidy_pool_initial_ − accumulated_subsidy_`. Two cases:

- If `base_subsidy ≤ remaining`: `subsidy_this_block = base_subsidy`; `accumulated_subsidy_ += base_subsidy ≤ accumulated_subsidy_ + remaining = subsidy_pool_initial_`. ✓
- If `base_subsidy > remaining`: `subsidy_this_block = remaining`; `accumulated_subsidy_ + remaining = subsidy_pool_initial_`. ✓

Either way, `accumulated_subsidy_ ≤ subsidy_pool_initial_` post-apply. Once `accumulated_subsidy_ = subsidy_pool_initial_`, `remaining = 0` and all subsequent blocks pay 0 subsidy.

The pool counter is monotone-non-decreasing by construction (only `+=`); the cap is a fixed constant from genesis. ⇒ A1 holds across pool exhaustion (the transition is just `subsidy_this_block = 0` for that block and all subsequent). ∎

### 5.2 Expected-value preservation under LOTTERY

Under the random-oracle assumption that `cumulative_rand` is uniform in `{0, 1}^256` (FA3's commit-reveal hiding establishes this — the adversary cannot control the modular bias), the first 8 bytes read as `uint64_t` are uniform in `{0, …, 2^64 − 1}`. For modulus M, the residue is uniform (modulo the modular bias of `2^64 / M` ≈ 0 for any M ≥ 2).

```
P(lottery_seed % M == 0)        = 1/M
P(lottery_seed % M ≠ 0)        = (M − 1)/M

E[base_subsidy] = (1/M) · (block_subsidy · M) + ((M−1)/M) · 0
                = block_subsidy
```

Identical to FLAT's per-block `block_subsidy`. Total issuance schedule is preserved in expectation. Variance is increased (jackpot magnitude × hit rate), and the operator chooses M to trade off variance for incentive concentration.

Combined with E4: jackpot payouts that exceed `remaining` are capped, which biases late-life lottery payouts downward slightly (variance reduces as the pool approaches exhaustion). The total issuance bound `accumulated_subsidy_ ≤ subsidy_pool_initial_` still holds. ∎

---

## 6. Proof of T-12.1 (determinism)

Every counter mutation is a deterministic function of the block's contents:

- `subsidy_this_block`: function of `block_subsidy_`, `subsidy_mode_`, `lottery_jackpot_multiplier_`, `cumulative_rand[0..7]`, `accumulated_subsidy_`, `subsidy_pool_initial_`. All inputs are deterministic given the block.
- `block_outbound`, `block_inbound`, `block_slashed`: sums over tx subsets / receipt subsets / event subsets, all in canonical block order.
- `total_fees`: deterministic sum.

No randomness, no external state, no time-dependence. Two honest nodes applying the same block reach byte-identical counters and accounts/stakes maps. Snapshot serialization includes all counters explicitly (lines 657–661 of chain.cpp), so snapshot-bootstrapped nodes resume with identical state. ∎

---

## 7. What this proof does NOT cover

- **Fairness of lottery distribution among creators.** When a jackpot fires, the payout is distributed across `b.creators` (the K committee members). Dust (remainder of division by K) goes to `b.creators[0]`. The proof covers issuance schedule, not per-creator distribution equity. A creator's expected fair share is `(block_subsidy / K)` per block on average (same as FLAT).
- **Inflation/deflation policy.** E4's perpetual-subsidy mode (`subsidy_pool_initial_ == 0`) is inflationary by design; E4 with a finite pool is deflationary post-exhaustion. The proof guarantees neither — they're operator-policy choices encoded at genesis.
- **NEF formula choice.** The current implementation halves the pool on first-time REGISTER. The plan documents an alternative `nef = pool × 2 / (n × (n+1))` formula — the proof would hold under either since both are sum-preserving.
- **Genesis-time accounting errors.** If genesis's `initial_balances` + `initial_stakes` + `zeroth_pool_initial` sum to a different value than what the operator intends, the chain enforces whatever `genesis_total_` evaluates to. This is operator responsibility (genesis hash includes all these fields; node refuses to start against a mismatched pinned hash).
- **Floating-point / overflow at extreme values.** Counters are `uint64_t`. The invariant assertion subtracts `slashed + outbound` from `(genesis + subsidy + inbound)`. If `slashed + outbound` exceeds the positive sum, the underflow wraps — but this scenario requires breaking H1 (validators slashed for more than genesis ever held), which the apply path's per-tx guards (`min(SUSPENSION_SLASH, locked)`) prevent.

---

## 8. Implementation cross-reference

| Component | Source |
|---|---|
| A1 counters declaration | `include/determ/chain/chain.hpp` (`genesis_total_` ... `accumulated_outbound_`) |
| Genesis-time `genesis_total_` initialization | `src/chain/chain.cpp::apply_transactions` `b.index == 0` branch |
| Per-block delta tracking | `src/chain/chain.cpp::apply_transactions` (per-tx delta accumulation) |
| Apply-tail assertion | `src/chain/chain.cpp::apply_transactions` (A1 invariant assertion at tail) |
| E1 NEF distribution | REGISTER branch in `apply_transactions` |
| Zeroth address validator guard | `src/node/validator.cpp::check_transactions` (rejects `from == ZEROTH_ADDRESS`) |
| E3 lottery branch | subsidy distribution in `apply_transactions` |
| E4 cap enforcement | same; `min(base_subsidy, remaining)` |
| Snapshot serialization of all counters | `src/chain/chain.cpp::serialize_state` |

A reviewer can confirm soundness by:

1. Running any of the 18 regression tests — the apply-tail assertion throws loudly on any A1 mismatch, so a passing test is a per-block invariant verification.
2. Grepping for `+=` / `-=` on `accumulated_*` and `genesis_total_`: every mutation site should be inside `apply_transactions` and paired with the corresponding state mutation.
3. Confirming the snapshot path round-trips all five counters; restore_from_snapshot's `value()` defaults are conservative (zero, equivalent to a fresh chain) so old snapshots load with degraded-but-consistent state.

---

## 9. Conclusion

T-12 establishes Determ's closed-form supply invariant unconditionally — no cryptographic assumption is required; the apply path's mechanical counter updates make it structurally true. T-13 + T-14 establish that all three economic primitives (E1 NEF, E3 lottery, E4 finite pool) preserve the invariant.

The proof is mechanical because the design is mechanical: every state mutation is paired with the corresponding counter delta, and the post-apply assertion catches any divergence before the block commits. Combined with FA1's safety guarantee (no forks finalize), this means an operator can compute the chain's total supply *as of any height* from genesis parameters + the chain's counter values — and that number is exact, not approximate, even under cross-shard transit and slashing.

This completes the FA-track coverage of all v1.x mechanisms: consensus + sharding + slashing + governance + economics.
