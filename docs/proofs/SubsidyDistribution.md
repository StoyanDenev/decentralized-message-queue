# FA-Apply — Block subsidy distribution (E1 / E3 / E4)

This document formalizes the apply-layer state machine governing Determ's block subsidy: the per-block mint into `accumulated_subsidy_`, the FLAT and LOTTERY distribution modes (E3) over the K-of-K committee, the optional finite-pool cap (E4), the empty-creators gate that turns a genesis-like block into a structural no-op, and the separate Negative-Entry-Fee (E1) channel that drains the Zeroth pool on first-time REGISTER apply. Together these four mechanisms define the chain's only legitimate mint surfaces, and their correctness is what makes the A1 unitary-supply invariant of `EconomicSoundness.md` (FA11) closed under arbitrary block sequences.

The proof is mechanical: the entire subsidy computation lives in `Chain::apply_transactions` at `src/chain/chain.cpp:1234–1305`, with the A1-bookkeeping update at `chain.cpp:1390–1392`, the E4 cap derivation at `chain.cpp:1267–1272`, the E3 LOTTERY draw at `chain.cpp:1250–1266`, and the FLAT default falling through unconditionally at `chain.cpp:1250`. The E1 NEF mechanism is a separately-scoped per-REGISTER drain at `chain.cpp:823–833`; it is not part of the per-block mint and is documented here only to demarcate the boundary. The companion proof for fee distribution lives in `FeeAccounting.md` (FA-Apply-6); the credit channel is structurally identical to subsidy (same flat-with-dust-to-`creators[0]` algorithm, same A1 closure pattern), but fees originate as an intra-supply transfer from senders, whereas subsidy is minted into existence. This split is the load-bearing distinction that motivates the separation of FA-Apply-6 and FA-Apply-7: they share an algorithm but not a supply contract.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validity predicates V1–V15, and the assumptions A1–A2 (Ed25519 EUF-CMA + SHA-256 collision resistance) that bound the LOTTERY draw's adversarial bias; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6 — especially I-5 (the per-creator subsidy + fee distribution channel is one of the eight enumerated credit channels) and I-6 (the A1 closure that subsidy mints feed via `accumulated_subsidy_`); `StakeLifecycle.md` (FA-Apply-4) for the structural template — both are state-machine proofs that close A1 over a deterministic counter update; `DAppRegistryLifecycle.md` (FA-Apply-5) for the analogous fee-only-debit channel framing (DAPP_REGISTER does not touch NEF, mirroring the subsidy-vs-NEF separation here); `FeeAccounting.md` (FA-Apply-6) for the fee-distribution counterpart (same algorithm, different supply contract); `EconomicSoundness.md` (FA11) for the chain-wide closed-form supply invariant (T-12) plus the E1 supply-neutrality argument (T-13) and E3+E4 expected-value bounds (T-14); `SelectiveAbort.md` (FA3) for the random-oracle assumption that makes the LOTTERY seed unpredictable to a single-committee adversary.

---

## 1. Setup

### 1.1 The subsidy state

Per `include/determ/chain/chain.hpp:571–584`, the per-Chain subsidy state is five values:

```cpp
uint64_t block_subsidy_{0};                  // genesis-pinned per-block mint amount
uint64_t subsidy_pool_initial_{0};           // E4 cap: 0 = unlimited, non-zero = hard cap
uint8_t  subsidy_mode_{0};                   // E3: 0 = FLAT, 1 = LOTTERY
uint32_t lottery_jackpot_multiplier_{0};     // E3 LOTTERY: M, must be >= 2
uint64_t accumulated_subsidy_{0};            // A1 monotone counter (chain.hpp:612)
```

The four front fields are genesis-pinned (loaded from `GenesisConfig` at chain bootstrap, see `chain.cpp:1999–2007`) and are immutable once set (no PARAM_CHANGE entry maps to `block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, or `lottery_jackpot_multiplier` in the A5 whitelist per `Governance.md` FA10). The fifth field `accumulated_subsidy_` is the running A1 counter mutated by every successful subsidy-distribution event. Together they form the complete subsidy substrate; no other chain field participates.

The companion `ZEROTH_ADDRESS` constant (`include/determ/chain/params.hpp:31`) is the canonical anon-style address `0x0000…0000`, encoding an all-zero pubkey (a low-order curve25519 point) with no usable Ed25519 private key. The genesis `zeroth_pool_initial` field (`include/determ/chain/genesis.hpp:137`) seeds `accounts_[ZEROTH_ADDRESS].balance` at index-0 apply; that balance is then drained per first-time REGISTER per E1.

### 1.2 The per-block mint pipeline

For every non-genesis block `b`, the subsidy computation at `chain.cpp:1234–1305` proceeds in five stages:

1. **Base subsidy** (line 1250): `base_subsidy = block_subsidy_`. The FLAT default — every block carries the chain's pinned subsidy amount.

2. **LOTTERY override** (lines 1251–1266): if `subsidy_mode_ == 1` AND `lottery_jackpot_multiplier_ >= 2`, read the first 8 bytes of `b.cumulative_rand` as a big-endian u64 `lottery`. If `lottery % lottery_jackpot_multiplier_ == 0`, `base_subsidy := block_subsidy_ * lottery_jackpot_multiplier_` (jackpot); otherwise `base_subsidy := 0` (miss). The jackpot probability is `1/M`, the miss probability is `(M-1)/M`, and the expected payout is `block_subsidy_` (per FA11 T-14).

3. **E4 cap** (lines 1267–1272): if `subsidy_pool_initial_ != 0`, compute `remaining = subsidy_pool_initial_ - accumulated_subsidy_` (saturating at 0) and `subsidy_this_block = min(base_subsidy, remaining)`. If `subsidy_pool_initial_ == 0`, `subsidy_this_block = base_subsidy` (perpetual subsidy, the historical default).

4. **Fee + subsidy aggregation** (lines 1273–1285): `total_distributed = total_fees + subsidy_this_block` with S-007 overflow-checked addition; on overflow the apply throws and rolls back via the outer try/catch.

5. **Creator distribution** (lines 1286–1305): if `total_distributed > 0` AND `!b.creators.empty()`, distribute `per_creator = total_distributed / m` to each of the `m` creators, plus dust `remainder = total_distributed mod m` to `b.creators[0]`. If either gate fails, the distribution branch is skipped entirely and no `accounts_` mutation occurs.

The A1 mint into `accumulated_subsidy_` at line 1391 is conditional on the same `total_distributed > 0 && !b.creators.empty()` gate as the distribution. **Mint and distribute are joined**: there is no path in which `accumulated_subsidy_` advances without a corresponding per-creator credit, and there is no path in which creators are credited without `accumulated_subsidy_` advancing. The gate is the structural mechanism that makes the empty-creators / zero-distribution case an A1-neutral no-op (T-S2 below).

### 1.3 The empty-creators gate

The `b.creators.empty()` check at lines 1286 and 1390 is load-bearing for two reasons. First, **genesis is the only legitimate empty-creators block** — the genesis apply branch at `chain.cpp:712` initializes `accumulated_subsidy_ = 0` and is short-circuited before reaching the subsidy pipeline, so the gate is mostly a defensive belt-and-suspenders for any future block whose `creators[]` arrives empty (e.g., a malformed snapshot replay, a buggy validator). Second, **division by zero would crash** without the gate: `per_creator = total_distributed / m` at line 1288 would divide by zero if `m = 0`. The empty-creators check is therefore both a semantic gate (genesis-like blocks don't mint) AND a runtime safety gate (no divide-by-zero).

The same gate appears in `FeeAccounting.md` (FA-Apply-6) T-F5 — fees and subsidy share the empty-creators contract because they share the distribution algorithm. The subsidy half of the joint contract is what this proof formalizes.

### 1.4 NEF (E1) is a separate channel

The Negative-Entry-Fee mechanism at `chain.cpp:823–833` is a per-REGISTER drain, not a per-block mint. It fires inside the REGISTER apply branch (line 770–836) when `first_time_register == true` (the sender is not yet in `registrants_`, per line 795–796), draining `pool/2` from `accounts_[ZEROTH_ADDRESS].balance` and crediting `accounts_[tx.from].balance` by the same amount. The mechanism is **supply-neutral** (per FA11 T-13) — it is a balance transfer, not a mint, so `accumulated_subsidy_` is not touched and the A1 invariant is preserved trivially.

The separation is structural: the per-block mint pipeline in §1.2 and the NEF drain at `chain.cpp:823–833` share no code path, no chain field (except `accounts_` which both write to), and no triggering event. The per-block mint fires on every block with `total_distributed > 0 && !b.creators.empty()`; NEF fires on every successful first-time REGISTER apply, regardless of subsidy mode. The two are independent in both the math and the code.

---

## 2. Theorems

### T-S1 — Per-block subsidy mint

**Statement.** For every non-genesis block `b` (i.e., `b.index >= 1`) with `b.creators.size() = m >= 1` accepted by `apply_transactions`, the subsidy computation produces a deterministic `subsidy_this_block ∈ {0, 1, …, base_subsidy}` (bounded by E4 cap if applicable), and the joint distribution gate fires iff `total_distributed = total_fees + subsidy_this_block > 0`. When the gate fires, the deltas are:

```
Δaccounts_[b.creators[i]].balance = total_distributed / m   for each i ∈ {0, …, m−1}
Δaccounts_[b.creators[0]].balance += total_distributed mod m   (dust)
Δaccumulated_subsidy_             = +subsidy_this_block       (mint)
```

The per-block mint feeds into A1's `+ accumulated_subsidy_` term (FA11 T-12), preserving the unitary-supply invariant: every unit minted into `accumulated_subsidy_` is matched by an equal unit credited across `accounts_[creators[*]].balance`, so `live_total_supply` and `expected_total` advance by the same amount.

*Proof sketch.* By inspection of `chain.cpp:1250–1305` and `chain.cpp:1390–1392`. The base subsidy is set deterministically at line 1250 (FLAT default) or lines 1251–1266 (LOTTERY override, deterministic given `b.cumulative_rand`). The E4 cap at lines 1267–1272 is a `std::min` over `base_subsidy` and `remaining`, deterministic. `total_distributed` at line 1279 is the S-007-checked sum of `total_fees` (deterministically accumulated over `b.transactions`) and `subsidy_this_block`. The distribution loop at lines 1290–1297 walks `b.creators` in vector order, crediting each by `per_creator` via `checked_add_u64`. The dust at lines 1298–1304 credits `b.creators[0]` by `remainder`. The A1 mint at lines 1390–1392 advances `accumulated_subsidy_` by exactly `subsidy_this_block`. The A1 closure at `chain.cpp:1397–1419` confirms the equality `live_total_supply == expected_total` post-mutation; any divergence throws and triggers rollback via the outer try/catch (FA-Apply §1.2 atomic-apply guarantee). ∎

**Code witness.** `src/chain/chain.cpp:1250` (FLAT default); `src/chain/chain.cpp:1286–1305` (distribution); `src/chain/chain.cpp:1390–1392` (A1 mint); `include/determ/chain/chain.hpp:571` (`block_subsidy_` field).

**Test witness.** `tools/test_subsidy_distribution.sh` (`determ test-subsidy-distribution`) exercises the FLAT mode mint over multiple committee sizes, asserting `Σ per-creator credits == subsidy_this_block + total_fees` and `accumulated_subsidy_` advances by exactly `subsidy_this_block` per block. `tools/test_supply_lifecycle.sh` exercises the FLAT mode mint composed with fees, STAKE / UNSTAKE, REGISTER (including NEF), and cross-shard transfers, asserting A1 closure block-by-block.

### T-S2 — Empty-creators gate (A1-safety on genesis-like blocks)

**Statement.** For every block `b` with `b.creators.empty()`, the subsidy distribution branch at `chain.cpp:1286` is skipped, AND the A1 mint at `chain.cpp:1390` is skipped. The deltas are:

```
Δaccounts_[*].balance        = 0     (no creator credit)
Δaccumulated_subsidy_        = 0     (no mint)
Δtotal_fees                  = unchanged (still distributed-free)
```

Equivalently: a block with no creators contributes zero to `accumulated_subsidy_`, zero to per-creator credits, and the A1 invariant holds trivially because no chain field is touched by the subsidy pipeline.

*Proof sketch.* By inspection of the two guards at `chain.cpp:1286` and `chain.cpp:1390`, both of the form `if (total_distributed > 0 && !b.creators.empty()) { ... }`. Under the hypothesis `b.creators.empty() == true`, both predicates are false, so both branch bodies are skipped. No `accounts_[*]` write reaches; no `accumulated_subsidy_ += ...` reaches. The A1 closure at line 1397–1399 still fires, but with zero subsidy-side delta: `expected_total` advances by `+block_inbound − block_outbound − block_slashed` (the other three counters), and `live_total_supply` advances by the same (no creator credit). The invariant holds because the subsidy contribution to both sides is exactly zero. ∎

The gate is the **A1-safety contract on genesis-like blocks**: any block whose `creators[]` is empty is treated by the apply layer as a structural no-op for the subsidy pipeline. Genesis itself (block 0) is short-circuited far earlier (at `chain.cpp:684` the index-0 branch returns before reaching the subsidy code), so the gate is a defensive secondary check rather than a primary mechanism — but it makes the apply layer robust against any future code path that might construct a block with empty creators (snapshot replay, validator regression, malformed network input).

**Code witness.** `src/chain/chain.cpp:1286` (distribution gate); `src/chain/chain.cpp:1390` (A1 mint gate).

**Test witness.** `tools/test_empty_block_apply.sh` exercises the empty-block apply path, asserting no `accumulated_subsidy_` advance and no creator credit. The test constructs a block with `b.creators = {}` (defensively bypassing the validator) and confirms apply leaves `accumulated_subsidy_` unchanged and `accounts_` unmutated. The A1 closure assertion at line 1399 fires successfully (no mismatch), demonstrating the gate's structural correctness.

### T-S3 — FLAT mode distribution (deterministic per-creator credit)

**Statement.** Under `subsidy_mode_ == 0` (FLAT, the genesis default), for every block `b` with `b.creators.size() = m >= 1` and `total_distributed > 0`, the distribution is:

```
per-creator credit  = total_distributed / m       (integer division, every creator)
dust credit         = total_distributed mod m     (only to b.creators[0])
sum of credits      = total_distributed           (exact, by construction)
```

The per-creator credit is identical across all `m` creators except `b.creators[0]` who receives `per_creator + remainder`. The total minted exactly equals `total_distributed`; no value is lost to rounding or to a phantom address.

*Proof sketch.* By inspection of `chain.cpp:1287–1304`. Line 1287 computes `m = b.creators.size()`. Lines 1288–1289 compute `per_creator = total_distributed / m` and `remainder = total_distributed % m` via integer arithmetic. The loop at lines 1290–1297 walks `b.creators` and credits each creator by `per_creator` via `checked_add_u64` (overflow-guarded). Line 1298–1304 credits `b.creators[0]` by `remainder`. The sum `m × per_creator + remainder = total_distributed` is exact by the integer-division identity. Determinism follows from `b.creators` being a canonical block-field (deterministic across replays per V1–V15) and `total_distributed` being deterministic over `total_fees` (deterministic block-tx-order accumulation) plus `subsidy_this_block` (deterministic given the block's `cumulative_rand`). ∎

**Code witness.** `src/chain/chain.cpp:1287–1304` (the flat-with-dust distribution algorithm).

**Test witness.** `tools/test_subsidy_distribution.sh` covers the FLAT distribution explicitly across multiple committee sizes (M=3, M=5, M=7) and asserts the per-creator credit + dust-to-`creators[0]` semantics by reading post-apply `accounts_[*].balance` values. `tools/test_fee_distribution_edge.sh` (companion to FA-Apply-6) exercises the same algorithm on the fee side; the implementation is shared (single distribution loop covers both fees and subsidy via `total_distributed`).

### T-S4 — LOTTERY mode distribution (jackpot scaling + miss-is-zero-mint)

**Statement.** Under `subsidy_mode_ == 1` (LOTTERY) with multiplier `M = lottery_jackpot_multiplier_ >= 2`, for every block `b`, the LOTTERY draw computes `lottery = decode_be_u64(b.cumulative_rand[0..7])` and branches:

- **Jackpot** (probability `1/M` under ROM): `lottery % M == 0` ⇒ `base_subsidy = block_subsidy_ * M`. The distribution proceeds normally with the jackpot-scaled amount; if `m = |creators|`, each creator receives `(block_subsidy_ * M + total_fees) / m` plus dust to `creators[0]`.
- **Miss** (probability `(M-1)/M`): `lottery % M != 0` ⇒ `base_subsidy = 0`. If `total_fees > 0`, fees still distribute (the T-S3 flat algorithm runs); if `total_fees = 0`, the distribution gate at line 1286 fails and **zero mint, zero credit**.

The "miss" outcome is **explicit zero**, not a no-op-on-the-mint-side-only: `subsidy_this_block` is bound to `0` at line 1264, `total_distributed` becomes `total_fees + 0 = total_fees`, and `accumulated_subsidy_` advances by exactly `0` at line 1391. Two replays of the same block produce byte-identical LOTTERY outcomes.

*Proof sketch.* By inspection of `chain.cpp:1251–1266`. The guard at line 1251 admits the LOTTERY branch (hypothesis `subsidy_mode_ == 1 && M >= 2`). Lines 1257–1260 decode the lottery seed as a big-endian u64 from the first 8 bytes of `b.cumulative_rand`. The branch at lines 1261–1265 sets `base_subsidy` to `block_subsidy_ * M` on jackpot or `0` on miss. The E4 cap at lines 1267–1272 may further cap the jackpot if `subsidy_pool_initial_ != 0` (handled by T-S5). The distribution at lines 1286–1305 runs with the resulting `base_subsidy` (under E4 cap) merged into `total_distributed`. Under jackpot, `total_distributed = block_subsidy_ * M + total_fees`; under miss, `total_distributed = total_fees`. The A1 mint at line 1391 advances `accumulated_subsidy_` by `subsidy_this_block` (the post-cap jackpot amount on jackpot, exactly `0` on miss). Determinism follows from `b.cumulative_rand` being a canonical block-field; the LOTTERY draw is purely a deterministic function of it. The probability bounds rely on the random-oracle assumption A3 over SHA-256 + the FA3 commit-reveal selective-abort resistance — see `EconomicSoundness.md` T-14 for the full ROM treatment. ∎

**Code witness.** `src/chain/chain.cpp:1251–1266` (the LOTTERY branch); `include/determ/chain/chain.hpp:583–584` (`subsidy_mode_`, `lottery_jackpot_multiplier_` fields).

**Test witness.** `tools/test_lottery_subsidy.sh` (`determ test-lottery-subsidy`) constructs a LOTTERY-mode chain with `M = 4`, applies many blocks, asserts that jackpot blocks credit `block_subsidy_ * M` total (split across creators) and miss blocks credit only fees, and confirms `accumulated_subsidy_` advances by the jackpot amount on jackpot blocks and by zero on miss blocks. The test also verifies determinism by replaying the block sequence and asserting byte-identical post-apply state.

### T-S5 — FINITE_POOL drain (E4 cap with pool exhaustion)

**Statement.** Under `subsidy_pool_initial_ != 0` (FINITE_POOL mode, optional E4 cap), for every block `b`, the chain enforces:

```
remaining = max(0, subsidy_pool_initial_ - accumulated_subsidy_)
subsidy_this_block = min(base_subsidy, remaining)
```

Two structural consequences:

1. **Cap.** `accumulated_subsidy_ <= subsidy_pool_initial_` holds after every successful apply. The post-mint counter cannot exceed the genesis-pinned cap.
2. **Exhaustion.** Once `accumulated_subsidy_ == subsidy_pool_initial_`, `remaining = 0` and `subsidy_this_block = 0` for every subsequent block, **regardless of FLAT vs LOTTERY**. The chain remains live (fees still distribute), but no new subsidy is minted. The exhaustion is permanent (monotone counter, no decrement path).

The pool is **genesis-pinned** via `GenesisConfig.subsidy_pool_initial`, loaded at chain bootstrap (`chain.cpp:1999–2007`), and immutable post-genesis (not on the A5 PARAM_CHANGE whitelist).

*Proof sketch.* By inspection of `chain.cpp:1267–1272`. The guard at line 1268 admits the cap branch (hypothesis `subsidy_pool_initial_ != 0`). Line 1269–1270 computes `remaining` with saturating subtraction: `remaining = subsidy_pool_initial_ > accumulated_subsidy_ ? subsidy_pool_initial_ - accumulated_subsidy_ : 0`. Line 1271 sets `subsidy_this_block = std::min(base_subsidy, remaining)`. The A1 mint at line 1391 advances `accumulated_subsidy_` by exactly `subsidy_this_block`. By induction: if `accumulated_subsidy_ <= subsidy_pool_initial_` pre-apply (base case: 0 at genesis), then `subsidy_this_block <= remaining = subsidy_pool_initial_ - accumulated_subsidy_`, so `accumulated_subsidy_ + subsidy_this_block <= subsidy_pool_initial_` post-apply. The exhaustion case is the boundary `accumulated_subsidy_ = subsidy_pool_initial_` ⇒ `remaining = 0` ⇒ `subsidy_this_block = 0`, and the boundary is sticky because `accumulated_subsidy_` is monotone non-decreasing. The genesis-pinned property follows from the loader at lines 1999+ writing the field once and the absence of the field from the A5 whitelist (per `Governance.md` FA10). ∎

**Code witness.** `src/chain/chain.cpp:1267–1272` (the E4 cap derivation); `src/chain/chain.cpp:1390–1392` (the gated A1 mint); `include/determ/chain/chain.hpp:577` (`subsidy_pool_initial_` field); `include/determ/chain/chain.hpp:194–198` (`subsidy_pool_remaining()` accessor — read-only convenience).

**Test witness.** `tools/test_finite_subsidy.sh` (`determ test-finite-subsidy`) constructs a FINITE_POOL chain with a small pool (e.g., 3× `block_subsidy_`), applies enough blocks to exhaust the pool, and asserts that subsequent blocks distribute only fees with `accumulated_subsidy_` pinned at `subsidy_pool_initial_`. The test covers both FLAT-with-cap (deterministic exhaustion at block N) and LOTTERY-with-cap (variance-reduced exhaustion as jackpots get clipped) cases.

### T-S6 — E1 NEF first-time-only drain

**Statement.** For every block `b` containing a successful REGISTER transaction `tx` with `tx.from == d` and `first_time_register == (registrants_.find(d) == registrants_.end())`, the NEF drain at `chain.cpp:823–833` fires iff:

1. `first_time_register == true` (per `chain.cpp:795–796`), AND
2. `accounts_[ZEROTH_ADDRESS].balance > 0`, AND
3. `tx.from != ZEROTH_ADDRESS`.

When all three hold, the deltas are:

```
nef = accounts_[ZEROTH_ADDRESS].balance / 2
Δaccounts_[ZEROTH_ADDRESS].balance = −nef
Δaccounts_[d].balance              = +nef
Δaccumulated_subsidy_              = 0    (NEF is NOT a mint)
```

Subsequent REGISTERs for the same domain `d` are **not first-time** (line 795 detects the existing `registrants_[d]` entry and sets `first_time_register := false`), so the NEF branch is skipped: a re-REGISTER (key rotation, region update) does not drain again. The pool drains **geometrically** — each first-time REGISTER halves the remaining pool balance — and **asymptotes** to zero without ever fully exhausting (integer-division floor on `pool/2` becomes 0 when `pool == 1`, and the `nef > 0` check at line 828 skips the no-op transfer). NEF is **supply-neutral** (per FA11 T-13): the channel transfers `nef` units from one account to another within `accounts_`, leaving `Σ balance` unchanged.

*Proof sketch.* By inspection of `chain.cpp:790–833`. Line 795–796 computes `first_time_register = (registrants_.find(tx.from) == registrants_.end())` **before** the registry mutation at line 805 (which would change the find result and break the invariant). Line 823 guards on `first_time_register`. Line 824–826 guards on `pool_it != end() && pool_balance > 0 && tx.from != ZEROTH_ADDRESS`. Line 827 computes `nef = pool_balance / 2`. The `if (nef > 0)` check at line 828 prevents the no-op transfer at the asymptotic tail (when pool balance is 1 and `nef = 0`). Lines 829–830 perform the atomic balance transfer. The mechanism does NOT touch `accumulated_subsidy_`, `total_fees`, or any of the other A1 counters; it is purely a balance-preserving channel within `accounts_`. The geometric decay follows from the halving rule: after N first-time REGISTERs against a pool of initial balance `Z`, the pool is `Z / 2^N` (integer division, asymptoting to 0). ∎

**Code witness.** `src/chain/chain.cpp:823–833` (the NEF branch); `src/chain/chain.cpp:795–796` (the first-time detection); `include/determ/chain/params.hpp:31` (`ZEROTH_ADDRESS` constant); `include/determ/chain/genesis.hpp:137` (`zeroth_pool_initial` genesis field).

**Test witness.** `tools/test_nef_pool_drain.sh` (`determ test-nef-pool-drain`) exercises the NEF mechanism across multiple first-time REGISTERs, asserting (a) the pool halves on each first-time REGISTER, (b) re-REGISTERs do NOT drain, (c) the supply invariant (FA11 A1) holds across NEF events, (d) `accumulated_subsidy_` is NOT advanced by NEF (the channel is supply-neutral, not a mint), and (e) DAPP_REGISTER does NOT drain the pool (cross-reference `DAppRegistryLifecycle.md` §4).

### T-S7 — A1 invariance (chain-wide closed-form supply)

**Statement.** For every successful apply of a block `b` (genesis or non-genesis), the chain-wide A1 unitary-supply invariant holds:

```
live_total_supply  ==  genesis_total
                       + accumulated_subsidy
                       + accumulated_inbound
                       − accumulated_slashed
                       − accumulated_outbound
```

where `live_total_supply = Σ_{a ∈ accounts_} accounts_[a].balance + Σ_{d ∈ stakes_} stakes_[d].locked`. The `accumulated_subsidy_` counter tracks **exactly the total minted across all blocks** — every unit minted into existence by the subsidy pipeline contributes to this counter, and every unit credited to a creator's balance is matched 1:1 by the counter's advancement.

*Proof sketch.* This is the FA11 T-12 invariant (per `EconomicSoundness.md` §3 by induction on block height). The present proof's contribution is to verify that the subsidy pipeline preserves the inductive step. By T-S1, every successful per-block subsidy event satisfies the joint update:

```
Δ(Σ accounts_[creators[*]].balance) = +subsidy_this_block + total_fees
Δaccumulated_subsidy_               = +subsidy_this_block
Δtotal_fees-into-creators           = +total_fees     (intra-supply, cancels with the per-tx fee debit)
```

The fee component is intra-supply (FA-Apply-6 T-F4 — the per-tx fee debit cancels with the creator credit). The subsidy component is the only **mint** — it advances `live_total_supply` by `+subsidy_this_block` on the LHS and advances `accumulated_subsidy_` by `+subsidy_this_block` on the RHS, preserving the equality. By T-S2, the empty-creators case is a structural no-op (both sides advance by zero, equality preserved). By T-S5, the E4-capped case still respects the equality (the cap binds `subsidy_this_block` but the LHS/RHS advancement remains 1:1). By T-S6, the NEF channel is supply-neutral (LHS unchanged across NEF, RHS unchanged because no counter is touched). By T-S4, the LOTTERY miss outcome contributes zero to both sides explicitly. The composition with `block_inbound`, `block_outbound`, and `block_slashed` is handled by `CrossShardReceipts.md` (FA7) and `EquivocationSlashing.md` (FA6); subsidy's role is the lone mint channel. The apply-tail assertion at `chain.cpp:1399` confirms the closure block-by-block; any divergence throws and rolls back. ∎

**Code witness.** `src/chain/chain.cpp:1390–1392` (the gated A1 mint); `src/chain/chain.cpp:1397–1419` (the A1 closure assertion); `include/determ/chain/chain.hpp:611–615` (the five A1 counters); `src/chain/chain.cpp:543–548` (`Chain::live_total_supply()` and `expected_total()` helpers).

**Test witness.** `tools/test_supply_lifecycle.sh` (the canonical A1 lifecycle integration test) walks the chain through TRANSFER / STAKE / UNSTAKE / REGISTER (with NEF) / DEREGISTER / equivocation slash / suspension slash / FLAT subsidy / LOTTERY subsidy / FINITE_POOL exhaustion / cross-shard inbound + outbound, asserting the A1 closing equality after every block. `tools/test_supply_invariant.sh` exercises the A1 assertion directly with synthetic per-counter deltas. `tools/operator_supply_check.sh` is the operator-facing offline audit tool that re-runs the A1 check from snapshot data.

### T-S8 — Subsidy determinism

**Statement.** For two replays of the same block sequence starting from the same genesis state, the per-creator subsidy credit is **byte-identical** across the replays. Equivalently: `subsidy_this_block`, the per-creator credit, the dust-to-`creators[0]` amount, and the post-apply `accumulated_subsidy_` value are deterministic functions of the chain state plus the block's `b.cumulative_rand` plus the block's `b.transactions` plus the genesis-pinned `block_subsidy_`, `subsidy_mode_`, `lottery_jackpot_multiplier_`, and `subsidy_pool_initial_` fields.

*Proof sketch.* By the determinism of every intermediate computation:

- **FLAT default** (line 1250): `base_subsidy = block_subsidy_` — `block_subsidy_` is genesis-pinned, so identical across replays.
- **LOTTERY override** (lines 1251–1266): the lottery seed is `decode_be_u64(b.cumulative_rand[0..7])`, a deterministic byte-decode of a canonical block field. `lottery % M` is deterministic integer arithmetic. The jackpot vs miss branch is deterministic. The jackpot amount `block_subsidy_ * M` is deterministic.
- **E4 cap** (lines 1267–1272): `remaining` is a deterministic function of `subsidy_pool_initial_` (genesis-pinned) and `accumulated_subsidy_` (deterministic by induction on prior blocks). `std::min` is deterministic.
- **Fee aggregation** (lines 1273–1285): `total_fees` is the sum over canonical-ordered `b.transactions`. `total_distributed = total_fees + subsidy_this_block` is deterministic integer arithmetic.
- **Distribution loop** (lines 1287–1305): `b.creators` is a canonical block-field (deterministic per V1–V15). The per-creator credit and dust are deterministic integer arithmetic.
- **A1 mint** (lines 1390–1392): the gate is deterministic. The counter advance is deterministic.

No source of non-determinism (no system time, no `rand()`, no OS clock, no thread-scheduling-dependent iteration) appears in the subsidy pipeline. Two honest nodes applying the same block sequence land on byte-identical post-apply state with respect to subsidy. The determinism is what makes `compute_state_root()` (S-033) emit identical values across honest replays — `accumulated_subsidy_` is included in the `k:c:` namespace (per `include/determ/chain/chain.hpp:250–254`) and would surface any non-determinism as a state-root divergence. ∎

**Code witness.** `src/chain/chain.cpp:1250–1305` (the deterministic pipeline); `src/chain/chain.cpp:382–410` (the `k:c:` namespace leaf encoding that surfaces `accumulated_subsidy_` to the state-root); `include/determ/chain/chain.hpp:250–254` (the state-root namespace table including counters).

**Test witness.** `tools/test_supply_lifecycle.sh` and `tools/test_lottery_subsidy.sh` both replay their block sequences twice and assert byte-identical post-apply state (including identical `accumulated_subsidy_` and identical per-creator balance deltas). The state-root assertion in `tools/test_subsidy_distribution.sh` catches any non-determinism that would manifest as a state-root divergence.

---

## 3. Subsidy vs fees

Subsidy distribution and fee distribution use **the same flat-with-dust-to-`creators[0]` algorithm** — the single distribution loop at `chain.cpp:1286–1305` covers both. The shared input is `total_distributed = total_fees + subsidy_this_block`, and the loop walks `b.creators` crediting each by `per_creator` plus dust to slot 0. The credit channel is structurally identical in both cases.

The **supply contract** is what separates them:

| Property | Fees (FA-Apply-6) | Subsidy (this proof) |
|---|---|---|
| **Origin** | Sender-balance debit (intra-supply transfer) | Minted (creates new supply) |
| **A1 counter** | None advances | `accumulated_subsidy_ += subsidy_this_block` |
| **Closure mechanism** | Per-tx debit + creator credit cancel exactly | Mint matched by counter advance on RHS |
| **Channel name in I-5** | "TRANSFER / STAKE / DAPP_CALL fee" rows | "Subsidy + fee distribution to creator" row |
| **Sensitivity to E1/E3/E4** | None | All three are subsidy-side mechanisms |
| **Sensitivity to empty creators** | Skipped (same gate as subsidy) | Skipped + mint also gated |

Both contributions land in `total_distributed`, both flow through the same distribution loop, and both gate on `!b.creators.empty()`. The structural overlap is intentional — it minimizes code duplication and makes the apply path easier to audit. The separation in the proofs (FA-Apply-6 vs FA-Apply-7) is the boundary between intra-supply transfer (fees) and minting (subsidy); the two cannot be merged into a single theorem because their A1 contributions are categorically different.

The split also explains why FA-Apply-6 T-F4 + T-F5 (fee distribution + empty-creators gate) and FA-Apply-7 T-S1 + T-S2 (subsidy mint + empty-creators gate) are paired: they share the algorithm but each carries its own supply-side reasoning. A reviewer working through the apply path can read both proofs in tandem to confirm the full creator-incoming credit channel is exhaustively characterized.

---

## 4. NEF (E1) rationale

The Negative Entry Fee mechanism exists to **bootstrap value for new entrants without bootstrapping inflation**. Three forces motivate the design:

1. **Bootstrap incentive.** A new chain has zero validators registered at genesis (or a small bootstrap set). New operators considering joining face a "cold start" cost: pay the REGISTER fee, pay the STAKE deposit, lose value to network latency and operational overhead before earning any subsidy. Without an entry-side incentive, the network has no signal to early adopters that participation is rewarded. NEF gives them a one-time payout sourced from a pre-funded pool, dampening the cold-start cost.

2. **No new supply.** The naive way to fund this would be a per-REGISTER mint — but that would couple bootstrap funding to inflation, making the chain's supply schedule unpredictable. NEF avoids this by drawing from a **genesis-funded pool** seeded by `zeroth_pool_initial`. The pool's initial balance is part of `genesis_total_` (FA11 T-13), so the chain's total supply at any height is exactly `genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound`. NEF events are intra-supply transfers; they do not advance any A1 counter.

3. **Geometric drain.** The pool halves per first-time REGISTER. After 64 first-time REGISTERs, the pool is `Z / 2^64` ≈ 0 (integer underflow to 0 when `Z < 2^64`). This is **not a perpetual inflation source** — the pool exhausts asymptotically. Operators registering early get more; operators registering after the pool exhausts get nothing. The drain rate matches the network's growth: early adopters get the highest incentive because they are the highest risk, late adopters get the lowest because the network is already established and the cold-start cost is lower.

The mechanism's relationship to the per-block subsidy is **complementary, not overlapping**. Per-block subsidy rewards ongoing participation (block production), NEF rewards entry. Per-block subsidy is potentially perpetual (under `subsidy_pool_initial_ == 0`), NEF is necessarily exhausting. Per-block subsidy is minted (advances `accumulated_subsidy_`), NEF is transferred (no counter advance). The two are independent in the math, in the code, and in the economic model.

The chain's economic invariant after both mechanisms have fired across N first-time REGISTERs and B blocks is:

```
genesis_total = Σ initial_balances + zeroth_pool_initial + Σ initial_stakes  (constant)
post_state = genesis_total + accumulated_subsidy + accumulated_inbound
              − accumulated_slashed − accumulated_outbound
```

NEF events do not appear explicitly because they are intra-supply transfers; only their initial pool funding is captured in `genesis_total`. Per-block subsidy events appear via `accumulated_subsidy`. Both mechanisms are A1-consistent.

---

## 5. What this doesn't prove

The theorems above target the subsidy pipeline + NEF channel in isolation. They do not extend to:

- **Apply-side fee distribution mechanics.** Fee aggregation across `b.transactions`, the per-tx-type fee debit, and the post-distribution `total_fees` consumption are covered by `FeeAccounting.md` (FA-Apply-6). The present proof's T-S3 references the shared distribution loop but does not formalize the fee-side input; T-F4 + T-F5 of FA-Apply-6 are the complement. Together FA-Apply-6 + FA-Apply-7 cover the full creator-incoming credit channel.

- **Slashing effects on supply.** T-S7's A1 invariance references `accumulated_slashed` but does not derive the slash mechanism's supply contribution; that derivation is in `EquivocationSlashing.md` (FA6) for equivocation slashing and in the suspension-slash branch at `chain.cpp:1313–1328` (covered by FA-Apply I-3 channel enumeration). The present proof treats `accumulated_slashed` as a given counter that other apply paths populate; its preservation under T-S7 follows from FA11 T-12's induction step.

- **Cross-shard subsidy composition.** The proof targets single-shard supply. Multi-shard chains run independent subsidy pipelines on each shard; cross-shard composition is handled by `CrossShardReceipts.md` (FA7) for the value-transfer side. Each shard's `accumulated_subsidy_` advances independently; chain-wide total subsidy across shards is the sum of per-shard counters, with no cross-shard coupling. Regional sharding (`RegionalSharding.md` FA8) and under-quorum merge (`UnderQuorumMerge.md` FA9) preserve the per-shard subsidy contract through region pinning and merge-event apply.

- **Genesis-time subsidy field validation.** The chain accepts whatever `block_subsidy_`, `subsidy_pool_initial_`, `subsidy_mode_`, and `lottery_jackpot_multiplier_` the genesis loader provides. Operator responsibility includes verifying these are sound (e.g., `subsidy_mode == 1` implies `lottery_jackpot_multiplier >= 2`, which the genesis loader does check at `chain.cpp:1999–2007`). Misconfigured genesis fields would produce A1-consistent but economically nonsensical chains (e.g., `block_subsidy_ = UINT64_MAX/2` would overflow `total_distributed` and trigger an S-007 throw). The present proof's correctness assumes a sane genesis.

- **PQ randomness assumptions for LOTTERY.** T-S4's probability bounds rely on the ROM treatment in FA11 T-14 over `b.cumulative_rand`. Under Grover (quantum adversary), the ROM bound degrades by a square-root factor — the adversary's ability to bias the LOTTERY outcome remains negligible at the chain's security parameters but tightens under PQ. The full PQ analysis is in FA3 + FA11; this proof inherits its bounds.

- **Snapshot ↔ replay equivalence of subsidy state.** The `accumulated_subsidy_` counter is in the S-033 state-root via the `k:c:` namespace, and is preserved across snapshot serialize/restore (`SnapshotEquivalence.md` FA-Apply-2 T-S1). The full equivalence proof is in FA-Apply-2; the present proof depends on it transitively (T-S1 through T-S8 hold post-snapshot-restore because the counter and per-account balances are byte-identical across the boundary) but does not re-derive it.

- **Wallet-side subsidy visibility.** RPC queries (`rpc_chain_status`, `rpc_balance`) return current subsidy state without further verification; light clients use state proofs (S-033) to verify. Wallet-side display of subsidy progress is a UX concern, not an apply-layer invariant.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V1–V15 + assumptions A1–A5 that bound the LOTTERY draw's adversarial bias. |
| `AccountStateInvariants.md` (FA-Apply) | I-5 (subsidy + fee distribution credit channel), I-6 (A1 closure). |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 + T-S2 — `accumulated_subsidy_` and per-account credits survive snapshot bootstrap. |
| `NonceMonotonicity.md` (FA-Apply-3) | Per-tx nonce-gating that precedes every fee-emitting branch; the fee inputs to subsidy distribution are nonce-gated. |
| `StakeLifecycle.md` (FA-Apply-4) | Structural template (state-machine proof over a deterministic counter); STAKE / UNSTAKE fee inputs feed `total_fees`. |
| `DAppRegistryLifecycle.md` (FA-Apply-5) | DAPP_REGISTER is a fee-only-debit channel; its fees feed `total_fees`. DAPP_REGISTER does NOT drain NEF (T-D1 + §4 of FA-Apply-5). |
| `FeeAccounting.md` (FA-Apply-6) | Fee distribution counterpart — same algorithm, different supply contract. T-F4 + T-F5 are the fee-side analogs of T-S1 + T-S2. |
| `EconomicSoundness.md` (FA11) | T-12 (A1 invariant), T-13 (NEF supply neutrality), T-14 (E3+E4 expected-value preservation under ROM). |
| `SelectiveAbort.md` (FA3) | The commit-reveal hiding that makes `b.cumulative_rand` unpredictable, bounding LOTTERY-side selective-abort attacks. |
| `EquivocationSlashing.md` (FA6) | The slash channel that advances `accumulated_slashed`; composes with subsidy via FA11 T-12. |
| `CrossShardReceipts.md` (FA7) | The cross-shard channels that advance `accumulated_inbound` and `accumulated_outbound`; per-shard subsidy is independent. |
| `Governance.md` (FA10) | The A5 PARAM_CHANGE whitelist — `block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, `lottery_jackpot_multiplier` are NOT on the whitelist (genesis-pinned). |
| `docs/PROTOCOL.md` §3.3 | Apply rules for the subsidy distribution. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table including the `k:` (constants) and `k:c:` (counters) namespaces that bind subsidy state. |
| `tools/test_subsidy_distribution.sh` | T-S1 + T-S3 (FLAT mode mint + per-creator credit + dust). |
| `tools/test_empty_block_apply.sh` | T-S2 (empty-creators gate). |
| `tools/test_lottery_subsidy.sh` | T-S4 (LOTTERY jackpot + miss outcomes, replay determinism). |
| `tools/test_finite_subsidy.sh` | T-S5 (FINITE_POOL cap + exhaustion). |
| `tools/test_nef_pool_drain.sh` | T-S6 (NEF first-time-only drain, geometric decay, supply neutrality). |
| `tools/test_supply_lifecycle.sh` | T-S7 (A1 invariance across the full apply surface). |
| `tools/test_supply_invariant.sh` | T-S7 (direct A1 assertion). |
| `tools/operator_supply_check.sh` | Operator-facing offline A1 audit tool. |
| `include/determ/chain/chain.hpp:571` | `block_subsidy_` field declaration. |
| `include/determ/chain/chain.hpp:577` | `subsidy_pool_initial_` field declaration (E4 cap). |
| `include/determ/chain/chain.hpp:583–584` | `subsidy_mode_` + `lottery_jackpot_multiplier_` fields (E3). |
| `include/determ/chain/chain.hpp:611–615` | The five A1 counters (`genesis_total_`, `accumulated_subsidy_`, `accumulated_slashed_`, `accumulated_inbound_`, `accumulated_outbound_`). |
| `include/determ/chain/genesis.hpp:105` | `GenesisConfig.block_subsidy`. |
| `include/determ/chain/genesis.hpp:114` | `GenesisConfig.subsidy_pool_initial`. |
| `include/determ/chain/genesis.hpp:125–126` | `GenesisConfig.subsidy_mode`, `lottery_jackpot_multiplier`. |
| `include/determ/chain/genesis.hpp:137` | `GenesisConfig.zeroth_pool_initial` (E1 pool seed). |
| `include/determ/chain/params.hpp:31` | `ZEROTH_ADDRESS` constant. |
| `src/chain/chain.cpp:712` | Genesis-time `accumulated_subsidy_ = 0` initialization. |
| `src/chain/chain.cpp:790–833` | REGISTER apply branch + E1 NEF drain (T-S6). |
| `src/chain/chain.cpp:1234–1305` | Subsidy distribution pipeline (T-S1, T-S2, T-S3, T-S4, T-S5). |
| `src/chain/chain.cpp:1250` | FLAT default `base_subsidy = block_subsidy_`. |
| `src/chain/chain.cpp:1251–1266` | LOTTERY override (T-S4). |
| `src/chain/chain.cpp:1267–1272` | E4 cap derivation (T-S5). |
| `src/chain/chain.cpp:1286–1305` | Distribution loop with dust-to-`creators[0]` (T-S3). |
| `src/chain/chain.cpp:1390–1392` | A1-counter mint with joint empty-creators / zero-distribution gate. |
| `src/chain/chain.cpp:1397–1419` | A1 unitary-balance closure assertion (T-S7). |
| `src/chain/chain.cpp:1999–2007` | Genesis loader (writes the four pinned subsidy fields once). |

---

## 7. Status

All eight theorems (T-S1 through T-S8) are closed in the current codebase:

- **T-S1** (per-block subsidy mint) closed via the deterministic subsidy pipeline at `chain.cpp:1250–1305` + the gated A1 mint at lines 1390–1392; regression `test_subsidy_distribution.sh` + `test_supply_lifecycle.sh`.
- **T-S2** (empty-creators gate) closed via the joint `total_distributed > 0 && !b.creators.empty()` predicate at lines 1286 and 1390; regression `test_empty_block_apply.sh`.
- **T-S3** (FLAT mode distribution) closed via the integer-arithmetic per-creator credit + dust-to-`creators[0]` at lines 1287–1304; regression `test_subsidy_distribution.sh`.
- **T-S4** (LOTTERY mode distribution) closed via the deterministic seed decode + branch at lines 1251–1266; regression `test_lottery_subsidy.sh`.
- **T-S5** (FINITE_POOL drain) closed via the E4 cap derivation at lines 1267–1272 + the monotone `accumulated_subsidy_` counter at line 1391; regression `test_finite_subsidy.sh`.
- **T-S6** (E1 NEF first-time-only drain) closed via the `first_time_register` check at `chain.cpp:795–796` + the guarded transfer at lines 823–833; regression `test_nef_pool_drain.sh`.
- **T-S7** (A1 invariance) closed via the apply-tail closure at `chain.cpp:1397–1419` + the joint mint-with-distribution gate; regression `test_supply_lifecycle.sh` + `test_supply_invariant.sh`.
- **T-S8** (subsidy determinism) closed via the determinism of every intermediate computation (no system-time, no `rand()`, no thread-scheduling-dependent iteration) + the state-root binding of `accumulated_subsidy_` via the `k:c:` namespace; regression `test_supply_lifecycle.sh` + `test_lottery_subsidy.sh` (both perform replay-determinism assertions).

No theorem is open or partial. The combination of T-S2's empty-creators gate + T-S5's E4 cap + T-S6's NEF first-time-only constraint forms the **three structural safety properties** of the subsidy substrate: a block with no creators cannot mint (genesis-safety), the cap binds the total ever minted (finite-supply chains), and NEF drains the pool deterministically without ever overdrawing. Combined with FA11 T-12's chain-wide invariant, the chain's total supply at any height is exactly computable from the genesis parameters plus the five A1 counters — and that number is exact, not approximate, even under arbitrary block sequences combining all four mechanisms (FLAT, LOTTERY, FINITE_POOL, NEF).

The proof's foundation rests on a small set of code primitives: the `subsidy_this_block` derivation, the `total_distributed = total_fees + subsidy_this_block` aggregation, the joint `total_distributed > 0 && !b.creators.empty()` gate on both distribution and mint, the `checked_add_u64` S-007 overflow guard on every credit, and the `first_time_register` check that bounds NEF to a one-shot per Determ identity. The breadth of consequences — eight theorems covering four economic mechanisms (E1 / E3 / E4 / FLAT-default) under one A1 invariant — is testimony to how few primitives the chain needs to express the full subsidy contract without coupling it to inflation, slashing, or cross-shard composition.
