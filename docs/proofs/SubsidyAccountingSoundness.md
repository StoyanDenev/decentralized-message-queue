# FA-Apply-18 — Subsidy + fee accounting soundness (SB-1..SB-3: determinism + A1 preservation)

This document is the **accounting-soundness capstone** for Determ's block-reward pipeline. Where `SubsidyDistribution.md` (FA-Apply-7) formalizes the subsidy state machine and `FeeAccounting.md` (FA-Apply-6) formalizes the per-tx fee flow, this proof composes their results into three end-to-end soundness theorems that an auditor needs to answer one question: *given only the genesis-pinned reward parameters and the chain's block sequence, is the per-block credit to the K-of-K committee a deterministic, supply-conserving function — identical on every honest node, with no path that mints, burns, or mis-routes value?*

The three theorems are:

1. **SB-1 (subsidy determinism).** Given the genesis-pinned `block_subsidy_`, `subsidy_mode_` (FLAT vs LOTTERY), `subsidy_pool_initial_` (E4 finite-pool cap), and `lottery_jackpot_multiplier_`, the per-block subsidy credit `subsidy_this_block` is a deterministic function of the chain state (`accumulated_subsidy_`) plus the block (`b.cumulative_rand`, `b.creators`) — byte-identical on every node.
2. **SB-2 (fee-routing determinism + dust).** Transaction fees collected into the per-block `total_fees` accumulator route to `b.creators[]` via the same flat-split-with-dust-to-`creators[0]` algorithm as subsidy, deterministically and exhaustively (every collected unit lands on exactly one creator; no residue).
3. **SB-3 (A1 preservation).** The subsidy mint and the fee redistribution jointly preserve the **A1 unitary-supply identity** of `EconomicSoundness.md` (FA11) via the `accumulated_subsidy_` counter, with the `checked_add_u64` S-007 guard (`S007OverflowProtection.md`) bounding every credit path so the identity holds even on the throwing branch.

The proof is mechanical and **derivative by design**: it re-cites the same apply-path lines as its companions rather than introducing new mechanism, and its contribution is the *composition* — pinning the determinism source of LOTTERY precisely, joining the fee and subsidy credit channels under one `total_distributed`, and stating the A1 closure as the single soundness contract that all four reward mechanisms (FLAT-default, LOTTERY, E4 finite pool, fee redistribution) satisfy simultaneously. The entire reward pipeline lives in `Chain::apply_transactions` at `src/chain/chain.cpp:1234–1305` (derivation + distribution) and `chain.cpp:1383–1419` (A1 mint-gate + closure assertion); the fee accumulator is the `total_fees` local at `chain.cpp:720` mutated by the `charge_fee` lambda at `chain.cpp:727–732`.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the **canonical assumption labels** (§2.0) — note that the *"A1 unitary-supply invariant"* of this proof is the apply-layer **accounting invariant** `live_total_supply == expected_total`, which Preliminaries §2.0 explicitly distinguishes from cryptographic assumption A1 (Ed25519 EUF-CMA); the LOTTERY unpredictability bound (SB-1 §3.2) rests on assumption A3 (SHA-256 preimage / CSPRNG uniformity) via FA3, not on accounting-A1; `SubsidyDistribution.md` (FA-Apply-7) for the subsidy state machine (T-S1 mint, T-S3 FLAT, T-S4 LOTTERY, T-S5 E4 cap, T-S8 determinism) that SB-1 composes; `FeeAccounting.md` (FA-Apply-6) for the fee flow (T-F1 per-tx debit, T-F3 block accumulation, T-F4 distribution + dust, T-F7 fee determinism) that SB-2 composes; `NefPoolDrain.md` (FA-Apply-14) for the E1 NEF channel, which SB-3 includes only to demarcate the boundary (NEF is an intra-supply transfer, not a mint — `EconomicSoundness.md` T-13); `S007OverflowProtection.md` (S-007) for the `checked_add_u64` exhaustiveness (T-1..T-5) that SB-3 cites as the credit-path bound; `AccountStateInvariants.md` (FA-Apply-1) for the per-account channel enumeration I-5 + the A1 closure bridge I-6; `EconomicSoundness.md` (FA11) for the chain-wide closed-form identity (T-12) + the E3/E4 expected-value bounds (T-14); `CrossShardSupplyConservation.md` (FA-Apply-17) for the K-shard aggregate identity that the per-shard subsidy contract composes into.

---

## 1. Setup

### 1.1 The reward substrate

Per `include/determ/chain/chain.hpp:571–584`, the per-Chain reward state is five values:

```cpp
uint64_t block_subsidy_{0};                  // genesis-pinned per-block mint amount   (chain.hpp:571)
uint64_t subsidy_pool_initial_{0};           // E4 cap: 0 = unlimited, non-zero = cap   (chain.hpp:577)
uint8_t  subsidy_mode_{0};                   // E3: 0 = FLAT, 1 = LOTTERY               (chain.hpp:583)
uint32_t lottery_jackpot_multiplier_{0};     // E3 LOTTERY: M, must be >= 2             (chain.hpp:584)
uint64_t accumulated_subsidy_{0};            // A1 monotone counter (chain.hpp, A1 block)
```

The four front fields are **genesis-pinned**: they enter the `GenesisConfig` via the loader at `src/chain/genesis.cpp:118–122`, are validated there (§1.4), and are installed on the `Chain` via the setters at `include/determ/chain/chain.hpp:186–203` (`set_block_subsidy`, `set_subsidy_pool_initial`, `set_subsidy_mode`, `set_lottery_jackpot_multiplier`) at bootstrap. None of the four is on the A5 PARAM_CHANGE whitelist (`Governance.md` FA10), so they are immutable post-genesis. The fifth field `accumulated_subsidy_` is the running A1 counter, mutated only by the gated mint at `chain.cpp:1391`.

The per-block **fee accumulator** is a function-local, not chain state:

```cpp
uint64_t total_fees = 0;                     // src/chain/chain.cpp:720
```

declared at `apply_transactions` entry, mutated by the `charge_fee` lambda (`chain.cpp:727–732`) and the bundled `total_fees += tx.fee` writes (TRANSFER `chain.cpp:767`, STAKE `chain.cpp:868`, DAPP_CALL `chain.cpp:1221`), decremented only by the UNSTAKE refund (`chain.cpp:885`), and consumed once at the block-tail join (`chain.cpp:1280`). It goes out of scope at function return.

### 1.2 The unified credit pipeline

For every non-genesis block `b`, the reward computation at `chain.cpp:1234–1305` joins fees and subsidy into a single distributed quantity and splits it over the committee:

```
base_subsidy        = block_subsidy_                                  // FLAT default          (1250)
   [LOTTERY override if subsidy_mode_==1 && M>=2]                     // jackpot or 0           (1251–1266)
subsidy_this_block  = base_subsidy
   [E4 cap if subsidy_pool_initial_!=0: min(base_subsidy, remaining)] //                        (1267–1272)
total_distributed   = checked_add_u64(total_fees, subsidy_this_block) // S-007; throw on wrap   (1279–1285)
if total_distributed > 0 && !b.creators.empty():                      // joint gate             (1286)
    per_creator = total_distributed / m;  remainder = total_distributed % m
    for d in b.creators: accounts_[d].balance += per_creator          // checked_add_u64        (1290–1297)
    accounts_[b.creators[0]].balance += remainder                     // dust, checked_add_u64  (1299–1304)
```

and at block tail books the mint under the **same** gate, then asserts the identity:

```
if total_distributed > 0 && !b.creators.empty():
    accumulated_subsidy_ += subsidy_this_block                        //                        (1390–1392)
... (inbound / outbound / slashed counters)                           //                        (1393–1395)
assert live_total_supply() == expected_total()  else throw           //                        (1397–1419)
```

The single load-bearing structural fact, established by FA-Apply-6 T-F5 and FA-Apply-7 T-S2 and reused throughout this proof: **the distribution branch and the mint counter share byte-identical gate predicates** (`total_distributed > 0 && !b.creators.empty()` at both `chain.cpp:1286` and `chain.cpp:1390`). Mint and pay-out are joined: no path advances `accumulated_subsidy_` without an equal credit to creators, and none credits creators without advancing the counter.

### 1.3 The A1 accounting identity

`live_total_supply()` (`chain.cpp:548–553`) walks both maps:

```cpp
uint64_t Chain::live_total_supply() const {
    uint64_t s = 0;
    for (auto& [_, a] : accounts_) s += a.balance;
    for (auto& [_, st] : stakes_)  s += st.locked;
    return s;
}
```

`expected_total()` (`include/determ/chain/chain.hpp:443`) is the closed form:

```
expected_total = genesis_total_ + accumulated_subsidy_ + accumulated_inbound_
                 − accumulated_slashed_ − accumulated_outbound_
```

The apply-tail assertion at `chain.cpp:1397–1419` enforces `live == expected` after every block; a mismatch throws a `"unitary-balance invariant violated"` diagnostic carrying the per-counter breakdown, which the outer A9 try/catch rolls back via `restore_state_snapshot` (`AccountStateInvariants.md` §1.2). This identity is the **soundness contract** that SB-3 establishes the reward pipeline satisfies.

> **Note on the SI-1 reference.** This proof was scoped against a `SupplyInvariantComposition` companion (theorem "SI-1"); no such document exists in `docs/proofs/` at the time of writing. The supply-composition role is instead filled by the **shipped** proofs `EconomicSoundness.md` (FA11 T-12, the chain-wide closed-form identity) and `CrossShardSupplyConservation.md` (FA-Apply-17, the K-shard aggregate), and SB-3 cites those directly. If an `SI-1` document is later added, SB-3's composition target should be re-pointed at it; the present proof is correct against the code regardless.

### 1.4 Genesis validation gates determinism inputs

SB-1's determinism rests on the four reward fields being well-formed before any block applies. The genesis loader (`src/chain/genesis.cpp:118–171`) enforces:

- `subsidy_mode ∈ {0, 1}` — any other value throws (`genesis.cpp:132–136`), so the LOTTERY-branch guard `subsidy_mode_ == 1` is exhaustive.
- `subsidy_mode == 1 ⇒ lottery_jackpot_multiplier ≥ 2` — throws otherwise (`genesis.cpp:126–131`); this is why the apply-path guard is `subsidy_mode_ == 1 && lottery_jackpot_multiplier_ >= 2` (M=1 degenerates to FLAT, M=0 would divide by zero in the residue test).
- Sane-bounds cap `block_subsidy ≤ 1e18`, `subsidy_pool_initial ≤ 1e18`, `zeroth_pool_initial ≤ 1e18` (`genesis.cpp:146–162`).
- Jackpot-overflow pre-check: `block_subsidy * lottery_jackpot_multiplier ≤ 1e18` (`genesis.cpp:164–171`), so the LOTTERY jackpot multiply at `chain.cpp:1262` cannot wrap u64 for a validly-loaded genesis.

These gates mean a chain that loads at all has reward parameters that the apply path treats deterministically; a misconfigured genesis is rejected before block 0, not silently mis-applied.

---

## 2. Theorems

### SB-1 — Subsidy determinism

**Statement.** For any two honest nodes (or any two replays on one node) applying the same block `b` from the same pre-apply chain state, the computed `subsidy_this_block` is byte-identical. Concretely, `subsidy_this_block` is a pure function

```
subsidy_this_block = f( block_subsidy_, subsidy_mode_, lottery_jackpot_multiplier_,
                        subsidy_pool_initial_, accumulated_subsidy_, b.cumulative_rand )
```

with no dependence on wall-clock time, thread scheduling, map iteration order, `rand()`, or any node-local state, where:

- **FLAT** (`subsidy_mode_ == 0`): `subsidy_this_block = min(block_subsidy_, remaining)` if E4-capped, else `block_subsidy_`.
- **LOTTERY** (`subsidy_mode_ == 1`, `M = lottery_jackpot_multiplier_ ≥ 2`): let `lottery = Σ_{i=0}^{7} b.cumulative_rand[i] << (8·(7−i))` be the big-endian decode of the first 8 bytes; then `base_subsidy = block_subsidy_ · M` if `lottery % M == 0` (jackpot), else `0` (miss); `subsidy_this_block = min(base_subsidy, remaining)` if E4-capped.

The E4 `remaining = subsidy_pool_initial_ > accumulated_subsidy_ ? subsidy_pool_initial_ − accumulated_subsidy_ : 0` when `subsidy_pool_initial_ != 0`; otherwise the cap is bypassed.

*Proof.* By inspection of `chain.cpp:1250–1272` and the determinism of every input.

1. **FLAT default** (`chain.cpp:1250`): `base_subsidy = block_subsidy_`, a genesis-pinned constant (§1.1) identical across nodes.
2. **LOTTERY decode** (`chain.cpp:1257–1260`): the loop `for (int i=0;i<8;++i) lottery = (lottery<<8) | b.cumulative_rand[i];` is a fixed big-endian read of a canonical block field. `b.cumulative_rand` is part of the block's wire image, so every node deserializes the same 32 bytes and the same first 8. The residue test `lottery % lottery_jackpot_multiplier_ == 0` (`chain.cpp:1261`) and the jackpot multiply `block_subsidy_ * lottery_jackpot_multiplier_` (`chain.cpp:1262`) are deterministic u64 arithmetic; the multiply cannot overflow for a validly-loaded genesis (§1.4, `genesis.cpp:164–171`).
3. **E4 cap** (`chain.cpp:1268–1271`): `remaining` is a saturating subtraction of two deterministic u64s (`subsidy_pool_initial_` genesis-pinned, `accumulated_subsidy_` deterministic by induction over prior blocks — SB-3); `std::min` is deterministic.

No system time, no `rand()`, no thread-id, no `std::map` traversal feeds the derivation (the only map access in the pipeline is the per-creator credit, which iterates the `b.creators` *vector*, not a map). Therefore `subsidy_this_block` is byte-identical across nodes. This is the foundation of the S-033 state-root agreement: `accumulated_subsidy_` is bound into the state root via the `k:` constants namespace with key prefix `c:` (`chain.cpp:405`, leaf `k:c:accumulated_subsidy`), and the four pinned fields via the same `k:` namespace (`chain.cpp:385–388`), so any divergence in the derivation would surface as a state-root mismatch at the S-033 gate (`chain.cpp:1430`). ∎

**Code witness.** `src/chain/chain.cpp:1250` (FLAT default); `src/chain/chain.cpp:1251–1266` (LOTTERY branch incl. the big-endian decode loop at 1257–1260); `src/chain/chain.cpp:1267–1272` (E4 cap); `include/determ/chain/chain.hpp:571,577,583,584` (the four fields); `src/chain/genesis.cpp:118–171` (genesis validation of the determinism inputs); `src/chain/chain.cpp:385–388,405` (state-root binding via `k:` / `k:c:`).

**Composition.** SB-1 is the determinism specialization of FA-Apply-7 T-S8 (subsidy determinism) joined with T-S3 (FLAT), T-S4 (LOTTERY), and T-S5 (E4 cap); FA11 T-14 supplies the LOTTERY expected-value bound `E[base_subsidy] = block_subsidy_` under the A3 random-oracle treatment of `b.cumulative_rand`. This proof's contribution is the precise determinism *source* statement (the byte-exact big-endian decode at `chain.cpp:1257–1260`) and the explicit dependency on the genesis-validation gates (§1.4).

**Test witness.** `tools/test_subsidy_distribution.sh` (FLAT mint across committee sizes); `tools/test_lottery_subsidy.sh` (LOTTERY jackpot/miss + a replay-determinism assertion that reapplies the block sequence and checks byte-identical post-apply state); `tools/test_finite_subsidy.sh` (E4 cap + pool exhaustion under both FLAT and LOTTERY).

### SB-2 — Fee-routing determinism + dust handling

**Statement.** For every successfully-applied block `b` with `b.creators.size() = m ≥ 1` and `total_distributed = total_fees + subsidy_this_block > 0`, the collected transaction fees route to the committee deterministically and exhaustively. With `per_creator = total_distributed / m` and `remainder = total_distributed % m`:

```
Δaccounts_[b.creators[i]].balance += per_creator      for each i ∈ {0, …, m−1}
Δaccounts_[b.creators[0]].balance += remainder        (dust)
Σ over all credits                = total_distributed (exact; no residue)
```

The **dust** (`remainder`, the integer-division leftover) is credited entirely to `b.creators[0]` — a fixed slot in the block's wire image — via a single separate `checked_add_u64` write after the per-creator loop. The routing is byte-identical across nodes: same `total_fees`, same `per_creator`, same `remainder`, same dust recipient.

*Proof.* By inspection of `chain.cpp:1286–1305` and the determinism of `total_fees`.

1. **`total_fees` determinism (the fee input).** `total_fees` is accumulated by iterating `b.transactions` — a `std::vector` fixed by the block's wire image — in declaration order; each fee-paying tx contributes via `charge_fee` (`chain.cpp:730`) or the bundled `total_fees += tx.fee` (`chain.cpp:767,868,1221`), and the lone subtraction is the UNSTAKE pre-unlock refund (`chain.cpp:885`, which also reverses its own immediately-prior charge so the net is zero). Silently-skipped txs (nonce-mismatch, insufficient balance) never reach a `total_fees` write. Every node thus accumulates the identical `total_fees` (FA-Apply-6 T-F3 + T-F7).
2. **Flat split** (`chain.cpp:1287–1289`): `m = b.creators.size()`, `per_creator = total_distributed / m`, `remainder = total_distributed % m` — deterministic u64 division.
3. **Per-creator loop** (`chain.cpp:1290–1297`): iterates the `b.creators` vector in declaration order (canonical per V1–V15), crediting each `per_creator` via `checked_add_u64` (S-007 guard; throw-and-rollback on overflow).
4. **Dust placement** (`chain.cpp:1299–1304`): the remainder is credited to `accounts_[b.creators[0]].balance` in a single separate write. The two-pass structure (loop, then dust) makes dust placement independent of any iteration-order subtlety: it always lands on index 0. `b.creators[0]` is alphabetically determined in genesis fixtures (the committee vector is sorted by domain), removing producer discretion over the dust recipient (FA-Apply-6 §4).
5. **Exhaustiveness.** The integer-division identity `m · (total_distributed / m) + (total_distributed % m) = total_distributed` guarantees the sum of all `m` per-creator credits plus the dust equals exactly `total_distributed` — no unit is lost to rounding, none is double-counted.

Therefore fee routing is deterministic and exhaustive. Any nondeterminism would surface in the `a:` namespace of the state root (per-creator balances) and trip the S-033 gate at `chain.cpp:1430`. ∎

**Code witness.** `src/chain/chain.cpp:720` (`total_fees` decl); `src/chain/chain.cpp:727–732` (`charge_fee`); `src/chain/chain.cpp:767,868,1221` (bundled fee adds); `src/chain/chain.cpp:885` (UNSTAKE refund cancellation); `src/chain/chain.cpp:1279–1285` (`total_distributed` join with S-007 check); `src/chain/chain.cpp:1286–1305` (flat split + per-creator loop + dust to `creators[0]`); `src/chain/chain.cpp:33` (`checked_add_u64`).

**Composition.** SB-2 is the routing-determinism specialization of FA-Apply-6 T-F4 (distribution + dust) joined with T-F3 (block-level accumulation) and T-F7 (fee determinism). Fees and subsidy share the single distribution loop via `total_distributed`; the supply contract differs (fees are an intra-supply transfer, subsidy is a mint — see SB-3 and FA-Apply-7 §3), but the routing arithmetic is identical, which is exactly why one loop serves both.

**Test witness.** `tools/test_fee_distribution_edge.sh` (12 assertions across seven scenarios: "many creators with prime dust" — 100/3 ⇒ per_creator=33, remainder=1 to creator[0]; "zero-fee tx with non-zero subsidy"; "exact-divide subsidy (no dust)"; plus a determinism assertion); `tools/test_chain_apply_block.sh` (per-tx fee debit + skip semantics); `tools/test_fee_edge_cases.sh` (fee + subsidy combine boundaries).

### SB-3 — A1 preservation (unitary-supply identity under mint + redistribution)

**Statement.** For every successfully-applied block `b`, the subsidy mint and the fee redistribution jointly preserve the A1 unitary-supply identity (`live_total_supply == expected_total`), and the per-block change to live supply decomposes as

```
live_total_supply(state_{n+1}) − live_total_supply(state_n)
    = subsidy_this_block + accumulated_inbound delta
      − accumulated_slashed delta − accumulated_outbound delta
```

with **fees contributing zero net** (the per-tx debit `−fee` cancels exactly against the per-creator distribution credit `+per_creator + dust`, which sum to `+total_fees`), and **subsidy contributing exactly `+subsidy_this_block`** matched 1:1 by the `accumulated_subsidy_ += subsidy_this_block` advance at `chain.cpp:1391`. Three corollaries:

1. **(Mint = pay-out, always.)** Because the distribution gate (`chain.cpp:1286`) and the mint gate (`chain.cpp:1390`) are byte-identical (`total_distributed > 0 && !b.creators.empty()`), `accumulated_subsidy_` advances by exactly the amount credited to creators, never more, never less. The empty-creators / zero-distribution case is an A1-neutral no-op on both sides.
2. **(E4 cap is A1-consistent.)** The counter tracks the *actually-paid* `subsidy_this_block` (post-cap), not the `block_subsidy_` literal (`chain.cpp:1384–1389` comment). Once the pool drains (`accumulated_subsidy_ == subsidy_pool_initial_`), `subsidy_this_block = 0` and no further mint occurs; `accumulated_subsidy_ ≤ subsidy_pool_initial_` holds for all blocks (FA-Apply-7 T-S5).
3. **(No silent wrap.)** Every credit on the reward path is guarded by `checked_add_u64` (the join at `chain.cpp:1280`, each per-creator credit at `chain.cpp:1292`, the dust at `chain.cpp:1300`); on overflow the apply throws an `"S-007"` diagnostic and the A9 envelope rolls back, leaving `accounts_` and all counters byte-identical to apply entry. The identity therefore holds on the throwing branch as well (no partial mint survives).

*Proof.* This is the FA11 T-12 inductive step specialized to the reward pipeline, with the S-007 bound from `S007OverflowProtection.md` T-3 + T-5.

By the A1 closure assertion at `chain.cpp:1397–1419`, it suffices to show the reward pipeline's contribution to `live_total_supply` equals its contribution to `expected_total`.

- **Fee channel (net zero).** Each fee-paying tx debits `−fee` from the sender (via `charge_fee` at `chain.cpp:729`, or the bundled `−(amount+fee)` at the TRANSFER/STAKE/DAPP_CALL debit) and adds `+fee` to `total_fees`. At block-tail, `total_fees` enters `total_distributed` and is split across creators; by SB-2's exhaustiveness, the sum of creator credits attributable to fees is exactly `+total_fees`. Net change to `Σ balances` from fees: `−total_fees + total_fees = 0`. UNSTAKE refunds cancel internally (`chain.cpp:885` reverses both the balance debit and the `total_fees` increment). No A1 counter is touched by the fee channel — consistent with `expected_total` having no fee term.
- **Subsidy channel (mint).** The distribution credits `+subsidy_this_block` (the subsidy portion of `total_distributed`) across creators, and the mint gate advances `accumulated_subsidy_` by the same `+subsidy_this_block` (`chain.cpp:1391`). LHS advances by `+subsidy_this_block`; RHS advances by `+subsidy_this_block`. Equality preserved.
- **Joint gate (no leak).** Corollary 1: the shared predicate guarantees the credit and the counter advance fire together or not at all. Were they unequal, `live` and `expected` would diverge and the assertion at `chain.cpp:1399` would throw — but they are syntactically the same predicate, so divergence is structurally impossible.
- **Overflow branch (no partial state).** Corollary 3: if any `checked_add_u64` on the reward path returns false, the function throws before reaching the mint gate (the join throw at `chain.cpp:1281`) or before completing the closure (the per-creator/dust throws at `chain.cpp:1293,1301`); the outer A9 try/catch restores the pre-apply snapshot. Neither the credit nor the counter advance commits, so the identity holds (both sides unchanged from `state_n`).

The remaining `expected_total` terms — `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_` — are populated by the cross-shard and slashing channels (`CrossShardReceipts.md` FA7, `EquivocationSlashing.md` FA6), independent of the reward pipeline; the NEF channel (`chain.cpp:823–833`) is an intra-supply transfer touching no counter (`EconomicSoundness.md` T-13, `NefPoolDrain.md` T-N5). Summing all channels yields exactly the decomposition in the statement, and the apply-tail assertion confirms it block-by-block. ∎

**Code witness.** `src/chain/chain.cpp:1286,1390` (the matched distribution + mint gates); `src/chain/chain.cpp:1391` (the gated mint); `src/chain/chain.cpp:1393–1395` (inbound/outbound/slashed counter advances); `src/chain/chain.cpp:1397–1419` (A1 closure assertion + rollback throw); `src/chain/chain.cpp:1280,1292,1300` (the three S-007 credit guards on the reward path); `src/chain/chain.cpp:548–553` (`live_total_supply`); `include/determ/chain/chain.hpp:443` (`expected_total`).

**Composition.** SB-3 composes FA11 T-12 (chain-wide A1 identity), FA-Apply-6 T-F6 (A1 invariance under fees), FA-Apply-7 T-S7 (A1 invariance under subsidy), and `S007OverflowProtection.md` T-3 + T-5 (overflow guard on the subsidy/fee pool credit paths). The K-shard aggregate generalization is `CrossShardSupplyConservation.md` (FA-Apply-17): per-shard `accumulated_subsidy_` counters advance independently, and the chain-wide subsidy total is their sum with no cross-shard coupling. (See §1.3 note re the absent `SI-1` document — the supply-composition role is filled by FA11 + FA-Apply-17.)

**Test witness.** `tools/test_supply_invariant.sh` (direct A1 assertion on synthetic per-counter deltas); `tools/test_supply_lifecycle.sh` (A1 closure after every block across TRANSFER / STAKE / UNSTAKE / REGISTER+NEF / DEREGISTER / equivocation + suspension slash / FLAT + LOTTERY subsidy / E4 exhaustion / cross-shard inbound+outbound); `tools/test_fee_distribution_edge.sh` ("A1 invariant across all distribution scenarios"); `tools/test_cross_shard_supply_invariant.sh` (the FA-Apply-17 aggregate); `tools/operator_supply_check.sh` (operator-facing offline A1 audit from snapshot data).

---

## 3. Determinism source, stated precisely

SB-1's determinism claim hinges on the **exact** randomness source of LOTTERY mode, which this section pins so an external reimplementation produces identical payouts.

### 3.1 The seed is the block's `cumulative_rand`, big-endian, first 8 bytes

The lottery seed is **not** a fresh draw, a wall-clock value, or a hash computed at apply time. It is a fixed big-endian decode of the first 8 bytes of the block's `cumulative_rand` field (`chain.cpp:1257–1260`):

```cpp
uint64_t lottery = 0;
for (int i = 0; i < 8; ++i) {
    lottery = (lottery << 8) | b.cumulative_rand[i];
}
```

`b.cumulative_rand` is the block's committee-aggregated randomness, already part of the signed block image and already consumed by `derive_delay` (`chain.cpp:42–43`) for REGISTER/DEREGISTER activation timing. Because it is a block field, every node that deserializes the block reads the identical 32 bytes; the decode is pure. The jackpot/miss decision `lottery % M == 0` is therefore a deterministic function of the block alone, given the genesis-pinned `M`.

### 3.2 Why the LOTTERY draw is unpredictable, not merely deterministic

Determinism (every node agrees) and unpredictability (no committee member can steer the outcome before committing) are separate properties. The latter rests on assumption **A3** (SHA-256 preimage / second-preimage resistance) plus FA3's commit-reveal hiding: the comment at `chain.cpp:1252–1256` records that no committee member can predict `cumulative_rand` at Phase-1 decision time, so selective-abort against a jackpot block is defeated for the same information-theoretic reason as a regular reveal `R`. The expected-value bound `E[base_subsidy] = (1/M)·(block_subsidy_·M) + ((M−1)/M)·0 = block_subsidy_` (FA11 T-14) holds under the random-oracle treatment of `cumulative_rand`. SB-1 itself only needs determinism (A3 is not required for two honest nodes to agree); A3 is required only for the economic claim that the LOTTERY schedule cannot be gamed. Per Preliminaries §2.0, this A3 dependency is unrelated to the *accounting* "A1 invariant" of SB-3.

### 3.3 The FLAT and E4 paths are parameter-only

FLAT mode reads no per-block randomness at all (`base_subsidy = block_subsidy_`), so it is trivially deterministic. The E4 cap reads only `subsidy_pool_initial_` (genesis-pinned) and `accumulated_subsidy_` (deterministic by SB-3 induction). Neither path can diverge across nodes.

---

## 4. What this proof does NOT cover

- **The subsidy/fee *mechanism* in isolation.** SB-1..SB-3 are a composition layer. The per-stage mechanism proofs are `SubsidyDistribution.md` (FA-Apply-7, T-S1..T-S8) for subsidy and `FeeAccounting.md` (FA-Apply-6, T-F1..T-F7) for fees; this proof cites them rather than re-deriving the per-stage arithmetic. A reader wanting the full per-tx-type fee-charge/refund matrix or the empty-creators divide-by-zero analysis should read those documents.
- **NEF (E1) drain mechanics.** SB-3 includes NEF only to demarcate the supply boundary (it is an intra-supply transfer, not a mint). The geometric-drain + first-time-only + supply-neutrality analysis is `NefPoolDrain.md` (FA-Apply-14, T-N1..T-N7) and `EconomicSoundness.md` T-13.
- **Slashing and cross-shard supply contributions.** SB-3's decomposition references `accumulated_slashed_`, `accumulated_inbound_`, `accumulated_outbound_` as given counters; their derivations are `EquivocationSlashing.md` (FA6), `AccountStateInvariants.md` I-3 (suspension slash), and `CrossShardReceipts.md` (FA7) / `CrossShardSupplyConservation.md` (FA-Apply-17).
- **Snapshot ↔ replay equivalence of reward state.** `accumulated_subsidy_` and the four pinned fields are serialized/restored (`chain.cpp:573,583–586` serialize; `chain.cpp:617,627–630` restore) and bound into the S-033 state root; the round-trip equivalence is `SnapshotEquivalence.md` (FA-Apply-2). SB-1..SB-3 hold post-restore because the counter and per-account balances are byte-identical across the boundary, but this proof depends on FA-Apply-2 transitively rather than re-deriving it.
- **A non-existent `SupplyInvariantComposition` / `SI-1` document.** This proof was scoped to compose an `SI-1` theorem; no such document exists (§1.3 note). The supply-composition role is filled by the shipped `EconomicSoundness.md` (FA11 T-12) and `CrossShardSupplyConservation.md` (FA-Apply-17), which SB-3 cites directly. This is an honest gap in the original scope, not in the code: the A1 identity is fully proved by FA11 + FA-Apply-17.
- **Producer-side reward economics.** Which txs a producer includes, fee-market dynamics, MEV-style reordering, and operator choice of `block_subsidy`/`subsidy_mode` at genesis are out of apply-layer scope (genesis validation in §1.4 rejects only structurally-bogus values, not economically-unwise ones).
- **PQ-degraded LOTTERY bounds.** The A3 random-oracle bound on LOTTERY unpredictability (§3.2) degrades by a square-root factor under a Grover adversary; the full PQ analysis lives in FA3 + FA11. SB-1 (determinism) is unaffected — agreement among honest nodes needs no cryptographic assumption.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) §2.0 | Canonical assumption labels; the accounting "A1 invariant" vs cryptographic A1 (Ed25519) disambiguation; A3 (SHA-256 preimage) underlies LOTTERY unpredictability. |
| `SubsidyDistribution.md` (FA-Apply-7) | Subsidy state machine — T-S1 (mint), T-S3 (FLAT), T-S4 (LOTTERY), T-S5 (E4 cap), T-S8 (determinism). SB-1 composes these. |
| `FeeAccounting.md` (FA-Apply-6) | Fee flow — T-F1 (per-tx debit), T-F3 (block accumulation), T-F4 (distribution + dust), T-F6 (A1 under fees), T-F7 (fee determinism). SB-2 composes these. |
| `NefPoolDrain.md` (FA-Apply-14) | E1 NEF channel — intra-supply transfer, not a mint; SB-3 boundary demarcation. |
| `S007OverflowProtection.md` (S-007) | `checked_add_u64` exhaustiveness — T-3 (A1 under protection), T-5 (subsidy + fee pool overflow). SB-3 corollary 3. |
| `AccountStateInvariants.md` (FA-Apply-1) | I-5 (per-account credit/debit channel enumeration), I-6 (A1 closure bridge). |
| `EconomicSoundness.md` (FA11) | T-12 (chain-wide closed-form A1 identity), T-13 (NEF supply neutrality), T-14 (E3/E4 expected-value bounds). SB-3's chain-wide composition target. |
| `CrossShardSupplyConservation.md` (FA-Apply-17) | K-shard aggregate supply identity; per-shard subsidy independence. SB-3 multi-shard generalization. |
| `SnapshotEquivalence.md` (FA-Apply-2) | `accumulated_subsidy_` + pinned fields survive snapshot bootstrap byte-identically. |
| `SelectiveAbort.md` (FA3) | Commit-reveal hiding that makes `cumulative_rand` unpredictable (SB-1 §3.2). |
| `docs/PROTOCOL.md` §3.3 | Apply rules for subsidy distribution. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table — the `k:` constants + `k:c:` counters that bind reward state, and the `a:` account namespace that binds per-creator credits. |
| `tools/test_subsidy_distribution.sh` | SB-1 (FLAT mint across committee sizes). |
| `tools/test_lottery_subsidy.sh` | SB-1 (LOTTERY jackpot/miss + replay determinism). |
| `tools/test_finite_subsidy.sh` | SB-1 (E4 cap + exhaustion). |
| `tools/test_fee_distribution_edge.sh` | SB-2 (flat split + dust + determinism + A1). |
| `tools/test_fee_edge_cases.sh` | SB-2 (fee + subsidy combine boundaries). |
| `tools/test_chain_apply_block.sh` | SB-2 (per-tx fee debit + skip semantics). |
| `tools/test_supply_invariant.sh` | SB-3 (direct A1 assertion). |
| `tools/test_supply_lifecycle.sh` | SB-3 (A1 closure across the full apply surface). |
| `tools/test_cross_shard_supply_invariant.sh` | SB-3 (K-shard aggregate). |
| `tools/operator_supply_check.sh` | SB-3 (operator-facing offline A1 audit). |
| `include/determ/chain/chain.hpp:186–203` | The four genesis-pinned reward-field setters. |
| `include/determ/chain/chain.hpp:443` | `expected_total()` closed form. |
| `include/determ/chain/chain.hpp:571,577,583,584` | `block_subsidy_`, `subsidy_pool_initial_`, `subsidy_mode_`, `lottery_jackpot_multiplier_`. |
| `include/determ/chain/genesis.hpp:105,114,125,126,137` | `GenesisConfig` reward fields + `zeroth_pool_initial`. |
| `src/chain/genesis.cpp:118–171` | Genesis loader + validation of reward params (SB-1 §1.4). |
| `src/chain/chain.cpp:33` | `checked_add_u64` (S-007). |
| `src/chain/chain.cpp:385–388,405` | State-root binding of the four pinned fields (`k:`) + `accumulated_subsidy_` (`k:c:`). |
| `src/chain/chain.cpp:548–553` | `live_total_supply()`. |
| `src/chain/chain.cpp:720` | `total_fees` per-apply accumulator. |
| `src/chain/chain.cpp:727–732` | `charge_fee` lambda. |
| `src/chain/chain.cpp:823–833` | NEF drain (boundary; intra-supply transfer). |
| `src/chain/chain.cpp:1234–1305` | The unified reward pipeline (derivation + distribution). |
| `src/chain/chain.cpp:1250` | FLAT default. |
| `src/chain/chain.cpp:1251–1266` | LOTTERY override (decode loop 1257–1260). |
| `src/chain/chain.cpp:1267–1272` | E4 cap. |
| `src/chain/chain.cpp:1279–1285` | `total_distributed = total_fees + subsidy_this_block` (S-007 join). |
| `src/chain/chain.cpp:1286–1305` | Distribution loop + dust to `creators[0]`. |
| `src/chain/chain.cpp:1390–1392` | Gated A1 mint (`accumulated_subsidy_ += subsidy_this_block`). |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion + rollback throw. |

---

## 6. Status

All three theorems are closed in the current codebase (commit `35c779e`):

- **SB-1** (subsidy determinism) closed via the parameter-only FLAT path, the byte-exact big-endian LOTTERY decode at `chain.cpp:1257–1260`, the deterministic E4 cap, and the genesis-validation gates at `genesis.cpp:118–171`; regression `test_subsidy_distribution.sh` + `test_lottery_subsidy.sh` + `test_finite_subsidy.sh`. Composes FA-Apply-7 T-S3/T-S4/T-S5/T-S8.
- **SB-2** (fee-routing determinism + dust) closed via the deterministic `total_fees` accumulation, the flat split, and the dust-to-`creators[0]` write at `chain.cpp:1286–1305`; regression `test_fee_distribution_edge.sh` + `test_fee_edge_cases.sh` + `test_chain_apply_block.sh`. Composes FA-Apply-6 T-F3/T-F4/T-F7.
- **SB-3** (A1 preservation) closed via the matched distribution/mint gates at `chain.cpp:1286/1390`, the gated mint at `chain.cpp:1391`, the S-007 credit guards at `chain.cpp:1280/1292/1300`, and the apply-tail closure assertion at `chain.cpp:1397–1419`; regression `test_supply_invariant.sh` + `test_supply_lifecycle.sh` + `test_cross_shard_supply_invariant.sh`. Composes FA11 T-12, FA-Apply-6 T-F6, FA-Apply-7 T-S7, S-007 T-3/T-5, and FA-Apply-17.

No theorem is open or partial against the code. **One scope gap is flagged honestly** (§1.3, §4): the originally-referenced `SupplyInvariantComposition` / `SI-1` companion does not exist in `docs/proofs/`; SB-3's supply-composition role is filled instead by the shipped `EconomicSoundness.md` (FA11 T-12) and `CrossShardSupplyConservation.md` (FA-Apply-17). The A1 identity is fully established by those documents; should an `SI-1` proof be added later, SB-3's composition citation should be re-pointed at it.

The reward pipeline's soundness rests on a small primitive set: the genesis-pinned reward fields (immutable, validated up-front), the byte-exact LOTTERY decode (the lone randomness consumer, sourced from the signed block's `cumulative_rand`), the `total_distributed = total_fees + subsidy_this_block` join, the byte-identical distribution/mint gate pair, the `checked_add_u64` guard on every credit, and the apply-tail A1 closure that catches any divergence before commit. Together SB-1..SB-3 establish that the per-block committee reward is deterministic (SB-1 + SB-2), exhaustively routed (SB-2), and supply-conserving (SB-3) — so the chain's total supply at any height is exactly computable from the genesis parameters plus the five A1 counters, even under arbitrary mixtures of FLAT, LOTTERY, E4-capped, and fee-bearing blocks.
