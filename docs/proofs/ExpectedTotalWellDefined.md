# ExpectedTotalWellDefined — totality of the unsigned `expected_total()` ledger (ET-1..ET-4: no-underflow of the A1 RHS)

> **STATUS 2026-09-16 — D13 landed: a Phase-1 AbortEvent records the abort (S-032) and deducts NOTHING; T-A1 and every statement below that rests on the deduction are historical and are re-derived in step 3c (DECISION-LOG 2026-09-16 "D13 landed").**

> **STATUS 2026-09-16 — equivocation carries NO L1 consequence (owner decision D4, DECISION-LOG 2026-09-16; landed as O-1 step 3a).** The full-stake forfeiture and registry deactivation that this document treats as shipped apply-path behaviour were removed from `Chain::apply_transactions`; an `EquivocationEvent` is now an on-chain evidence record only (gate `determ test-equivocation-apply`). Every statement below that rests on that consequence is pending re-derivation in step 3c of the recorded sequence and must not be cited as current; until then the DECISION-LOG entry is the authority.

This document proves a property the existing A1 proofs **assert but never establish**: that the right-hand side of the unitary-supply identity — the function `expected_total()` at `include/determ/chain/chain.hpp:590-597` — is **well-defined as a `uint64_t` computation at every reachable chain state**. `expected_total()` performs three *unsigned* subtractions:

```cpp
uint64_t Chain::expected_total() const {
    return genesis_total_
         + accumulated_subsidy_
         + accumulated_inbound_
         - accumulated_slashed_       // unsigned subtraction
         - accumulated_outbound_      // unsigned subtraction
         - accumulated_shielded_;     // unsigned subtraction (§3.22)
}
```

The sixth term `accumulated_shielded_` (§3.22, `chain.hpp:898`) is the value moved from the transparent live sum into the confidential pool by SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER; it is subtractive because that value left `live_total_supply()` but is not burned (real supply = `live + accumulated_shielded_`, `chain.hpp:585-589`), and it is `0` on any shield-free chain — which recovers the classical five-term / two-subtraction RHS this proof originally analyzed.

On `uint64_t`, `x - y` with `y > x` does **not** signal an error: it wraps to `x - y + 2^64`, a value near `2^64`. If any of the three subtractions could underflow, the A1 apply-tail gate at `chain.cpp:1866-1892` (`if (actual != expected) throw ...`) would compare the live supply against a near-`2^64` garbage RHS — either spuriously throwing on an honest block (a liveness break — the chain refuses to extend) or, worse, masking a real divergence whose magnitude happens to coincide with the wrap. Every A1 proof in the corpus (`EconomicSoundness.md` FA11, `AccountStateInvariants.md` I-6, `SupplyInvariantComposition.md` SI-1..SI-4) takes `expected_total()` as the *trusted reference value* the live sum is checked against; that trust is only justified if the RHS arithmetic is itself total. This proof discharges that obligation.

The dual already exists. `S007OverflowProtection.md` proves the **additive** half — every credit-path `+` is guarded by `checked_add_u64` so no balance/accumulator wraps *upward* past `UINT64_MAX`. The present proof is the **subtractive** half: the three `-` operations in `expected_total()` never wrap *downward* past `0`, because at every reachable state the burn/outflow/shielded terms are dominated by the mint/inflow terms. The two halves together pin the RHS to its true integer value on `[0, 2^64)` with no modular wraparound in either direction. `SupplyInvariantComposition.md` §5 lim. 4 names this underflow edge explicitly as an *unproven limitation* ("the underflow edge of the aggregate … requires breaking the per-tx slash bound … which the apply path prevents structurally"); ET-1..ET-4 convert that one-line aside into the structural theorem.

We prove four theorems: **ET-1** (the per-state structural domination bound `accumulated_slashed_ + accumulated_outbound_ + accumulated_shielded_ ≤ genesis_total_ + accumulated_subsidy_ + accumulated_inbound_`), **ET-2** (no upward wrap inside the additive prefix `genesis_total_ + accumulated_subsidy_ + accumulated_inbound_`), **ET-3** (totality: ET-1 + ET-2 ⇒ all three unsigned subtractions are exact, so `expected_total()` equals its real-integer value), and **ET-4** (the A1 gate consequence: a total RHS means the apply-tail check `actual != expected` is a true supply comparison, not a comparison against a wrapped sentinel). Two findings F-1 (the bound is an *emergent* invariant, not an explicit runtime assertion — there is no `assert(slashed + outbound + shielded <= ...)` in the code; it holds because every accumulator increment is itself dominated) and F-2 (the additive prefix's upward-wrap freedom rests on the same S-007 genesis sane-bounds defense-in-depth, cross-linked rather than re-proved).

**Companion documents:** `Preliminaries.md` (F0) §2.0 for the A1-accounting / A1-crypto namespace split (this proof concerns the *accounting* identity; it invokes **no** cryptographic assumption — it is a pure `uint64_t`-arithmetic totality argument); `EconomicSoundness.md` (FA11) for the A1 closed-form identity T-12 whose RHS is the object of this proof, and the monotone-accumulator description (§1, "monotone increase") ET-1's induction rests on; `AccountStateInvariants.md` (FA-Apply-1) for I-1 (no underflow on the per-account debit channels — the building block ET-1 lifts to the accumulator level) and I-6 (the A1 closure ET-4 protects); `SupplyInvariantComposition.md` (SI-1..SI-4) for the apply-preservation case analysis ET-1 reuses and the §5 lim. 4 underflow aside this proof closes; `S007OverflowProtection.md` (S-007) for the additive-overflow dual ET-2 cross-links (the `checked_add_u64` guards + the genesis `1e18` sane-bounds check); `FeeAccounting.md` (FA-Apply-6) for the fee-is-intra-supply property (fees never enter the accumulators, so they are absent from both sides of ET-1); `SubsidyDistribution.md` (FA-Apply-7) + `NefPoolDrain.md` (FA-Apply-14) for the subsidy-mint and NEF-drain channels ET-1 enumerates on the `+subsidy` side; `StakeForfeitureCascade.md` (FA-Apply-16) + `EquivocationSlashingApply.md` (FA-Apply-10) for the slash-deduct bound `min(suspension_slash_, locked)` / full-forfeit-of-`locked` that bounds the `−slashed` term; `CrossShardSupplyConservation.md` (FA-Apply-17) for the `+inbound` / `−outbound` in-flight semantics; `docs/SECURITY.md` §S-007 for the closure narrative.

---

## 1. Setup

### 1.1 The object: `expected_total()` as an unsigned expression tree

The function under analysis (`include/determ/chain/chain.hpp:590-597`):

```cpp
uint64_t expected_total() const {
    return genesis_total_
         + accumulated_subsidy_
         + accumulated_inbound_
         - accumulated_slashed_
         - accumulated_outbound_
         - accumulated_shielded_;    // §3.22
}
```

Evaluated left-to-right under C++ operator associativity, this is the expression

```
(((((genesis_total_ + accumulated_subsidy_) + accumulated_inbound_) − accumulated_slashed_) − accumulated_outbound_) − accumulated_shielded_)
```

with all six operands `uint64_t` (`chain.hpp:889-898`) and all five operators `uint64_t` arithmetic modulo `2^64` (ISO/IEC 14882:2017 §6.7.1, §7.6.6). Write the six accumulators as the integers

```
G := genesis_total_      S := accumulated_subsidy_   I := accumulated_inbound_
L := accumulated_slashed_   O := accumulated_outbound_   Sh := accumulated_shielded_
```

The **real-integer** intended value is `T := G + S + I − L − O − Sh` (computed in ℤ). The **machine** value is `expected_total() = (((((G + S) mod 2^64) + I mod 2^64) − L mod 2^64) − O mod 2^64) − Sh mod 2^64`. The two coincide iff (a) no intermediate sum exceeds `2^64 − 1` (no upward wrap, ET-2) and (b) no intermediate difference goes below `0` (no downward wrap, ET-1, now across all three subtractions). The proof establishes both, hence `expected_total() == T` as integers (ET-3). `Sh` is the one non-monotone accumulator — SHIELD raises it, UNSHIELD/CONFIDENTIAL_TRANSFER lower it — but it is non-negative at every reachable state (each SHIELD `+= A` credits value that a checked debit removed from live; each UNSHIELD/CT `−=` is bounded by the Pedersen-binding argument of `ShieldedPoolSoundness.md` SP-7/SP-12, so it never wraps below 0), which is all ET-1..ET-3 require of it.

### 1.2 Reachable states

A *reachable* chain state is a `Chain` obtained by replaying genesis (`chain.cpp:905-944`) followed by zero or more successful `apply_transactions` calls ("successful" = does not throw, per the A9 atomic-apply envelope `AccountStateInvariants.md` §1.2), and possibly one or more `serialize_state → restore_from_snapshot` round trips. The accumulators evolve **only** at three sites:

1. **Genesis** (`chain.cpp:905-944`): `G := Σ initial_balance + Σ initial_stake` (`:934`), and `S = L = I = O = Sh = 0` (the five accumulators zeroed at `:935-939`, `accumulated_shielded_` at `:939`).
2. **Apply tail** (`chain.cpp:1859-1864`): `S += subsidy_this_block` (gated, `:1859-1861`), `I += block_inbound`, `O += block_outbound`, `L += block_slashed`. `G` is **never** re-mutated on the apply path (written once at `:934`; the only other writer is the snapshot legacy back-solve at `chain.cpp:2634-2655`, which reproduces the same value — `SupplyInvariantComposition.md` SI-2).
3. **§3.22 shield apply arms** (`chain.cpp:1037`/`1081`/`1172`): `Sh += A` on SHIELD, `Sh −= A` on UNSHIELD, `Sh −= fee` on CONFIDENTIAL_TRANSFER — mutated *in-line* in the tx arms, not at the tail. `Sh` is therefore the one **two-directional** accumulator; the other four are monotone-non-decreasing.

No other code path mutates the six accumulators. So the reachable-state set is generated by the genesis base case plus the four monotone increments at the apply tail plus the two-directional `Sh` mutations in the shield arms.

### 1.3 The A1 identity as the load-bearing structural fact

The proof's engine is the A1 identity itself, taken as a *hypothesis* discharged by the companion proofs (FA11 T-12 / FA-Apply-1 I-6 / SI-1):

```
A1(C):   live_total_supply(C) == expected_total(C)            (in ℤ, once ET-3 makes the RHS total)
         i.e.  Σ balance + Σ locked  ==  G + S + I − L − O − Sh
```

where `live_total_supply()` (`chain.cpp:699-704`) is a sum of `uint64_t` balances and locked stakes, hence a **non-negative** integer. This non-negativity of the LHS is what forces the RHS to be non-negative *as a real integer* — which is exactly the domination bound ET-1. The argument is therefore not circular: FA11 proves `live == expected` holds at each block (the additive/subtractive deltas match); the present proof observes that since `live ≥ 0` always, the real-integer RHS `T = live ≥ 0`, and combined with the upper bound `T ≤ G + S + I` (slashed/outbound/shielded are all subtractive, non-negative) this pins `T ∈ [0, G + S + I]`, the interval on which all three unsigned subtractions are exact.

---

## 2. Theorems

### ET-1 — Structural domination bound: burns + outflows never exceed mints + inflows

**Statement.** At every reachable chain state `C`,

```
accumulated_slashed_(C) + accumulated_outbound_(C) + accumulated_shielded_(C)
        ≤  genesis_total_(C) + accumulated_subsidy_(C) + accumulated_inbound_(C)
```

i.e. `L + O + Sh ≤ G + S + I` (in ℤ). Equivalently, the real-integer ledger value `T = G + S + I − L − O − Sh ≥ 0`.

**Proof.** Two routes; we give the direct A1-consequence route first (shortest) and the standalone inductive route second (self-contained, not requiring A1 as input).

*Route A (via A1, shortest).* By FA11 T-12 / FA-Apply-1 I-6, every reachable `C` satisfies `live_total_supply(C) = G + S + I − L − O − Sh` as real integers (the per-block delta-matching argument of FA11 §3 / SI-1's net-zero table is in ℤ, independent of machine wraparound, because each individual accumulator step is bounded by S-007 / I-1 / the §3.22 Pedersen binding and so equals its real-integer value). The LHS `live_total_supply(C) = Σ_{d} balance[d] + Σ_{v} locked[v]` is a finite sum of non-negative `uint64_t` values, hence `live_total_supply(C) ≥ 0`. Therefore `G + S + I − L − O − Sh ≥ 0`, i.e. `L + O + Sh ≤ G + S + I`. Route A is insensitive to `Sh`'s non-monotonicity: it uses only `live ≥ 0` and the six-term identity, both of which hold at *every* reachable state regardless of how `Sh` rose and fell to get there. ∎

*Route B (standalone induction on block height, no A1 input).* By induction over the reachable-state generators of §1.2.

- **Base (genesis).** After `chain.cpp:935-939`, `L = O = Sh = 0` and `S = I = 0`, so `L + O + Sh = 0 ≤ G = G + S + I`. Holds (with `G ≥ 0` trivially).
- **Inductive step (one apply).** Assume `L + O + Sh ≤ G + S + I` at pre-apply state `C`. The apply tail adds `ΔL = block_slashed`, `ΔO = block_outbound`, `ΔS = subsidy_this_block` (gated), `ΔI = block_inbound`, and `ΔG = 0`; the §3.22 shield arms add `ΔSh` (net of SHIELD `+A` / UNSHIELD `−A` / CONFIDENTIAL_TRANSFER `−fee`). It suffices to show `ΔL + ΔO + ΔSh ≤ ΔS + ΔI`… **which is false in general** (a block can slash or shield without minting). Route B therefore cannot bound the *increments* against each other; instead it bounds the burns/outflows/shieldings against the **live supply they consume**, then uses live ≥ 0. Concretely:
  - `block_outbound = Σ tx.amount` over the cross-shard-TRANSFER branch (`chain.cpp:765`). Each such `tx.amount` was debited from `sender.balance` (the `cost = tx.amount + tx.fee`, `sender.balance ≥ cost` pre-check at `chain.cpp:744`-region, `AccountStateInvariants.md` I-1). So every unit added to `O` was simultaneously removed from `live_total_supply` — `O` accounts coin that *left* the live sum.
  - `block_slashed` aggregates `min(suspension_slash_, locked)` per Phase-1 abort and full `locked` per equivocation. Both deduct exactly that amount from `stakes_[d].locked`, again removing it from `live_total_supply`. So every unit added to `L` was simultaneously removed from the live sum.
  - The positive part of `ΔSh` is SHIELD (`chain.cpp:1037`, `Sh += A`), and each such `A` was debited from `sender.balance` by the S-049-checked `cost = A + fee`, `sender.balance ≥ cost` pre-check (`chain.cpp:1025-1032`) — so every unit added to `Sh` was simultaneously removed from `live_total_supply`, exactly like `O`. The negative part of `ΔSh` (UNSHIELD `Sh −= A` returning value to live, CONFIDENTIAL_TRANSFER `Sh −= fee`) only *decreases* the LHS, so it can never violate the bound; it is bounded below by `0` by the Pedersen binding (`ShieldedPoolSoundness.md` SP-7/SP-12: `Sh ≥ A` resp. `Sh ≥ fee` at each decrement, so `Sh` never wraps negative).
  - Therefore `ΔL + ΔO + max(ΔSh, 0) = (amount removed from live by slash) + (by outbound) + (by shield) ≤ live_total_supply(C) + ΔS + ΔI` — the inflows `ΔS` (minted in) and `ΔI` (credited in) are the only things that can be slashed/sent/shielded in the *same* block beyond the pre-existing live sum. Folding the inductive hypothesis, `live ≥ 0`, and (for the negative-`ΔSh` case) monotonic relaxation of the LHS gives `L' + O' + Sh' = (L + ΔL) + (O + ΔO) + (Sh + ΔSh) ≤ (G + S + I) + (ΔS + ΔI) = G + S' + I'`. ∎

Route B reduces, as expected, to the same fact Route A states directly: burns, outflows, and shieldings can only remove value that is *present* in the live sum (non-negative) or *entering* it (subsidy/inbound), never value that was never there. The bound is the accumulator-level lift of FA-Apply-1 I-1 ("no per-account underflow") to the chain-wide counters.

**Code witness.** The bounded increments: `chain.cpp:765` (`block_outbound += tx.amount`, gated by the `cost`-check at 744-region), the suspension-slash `deduct = min(suspension_slash_, locked); locked -= deduct; block_slashed += deduct` and equivocation full forfeit `block_slashed += locked; locked = 0`, the §3.22 `accumulated_shielded_ += A` gated by the SHIELD `cost` pre-check (`chain.cpp:1025-1037`), and the apply-tail fold at `chain.cpp:1859-1864`. The genesis base case at `chain.cpp:905-944` (counters zeroed at `:935-939`).

**Test witness.** `tools/test_supply_invariant.sh` + `tools/test_supply_lifecycle.sh` (A1 closure after slash + outbound channels — every passing assertion is an empirical instance of `live ≥ 0` with `live == G + S + I − L − O − Sh`, i.e. of ET-1); `determ test-supply-invariant-fuzz` (R41 H1, the randomized A1-delta driver — exercises slash + outbound + subsidy + inbound mixes and asserts the closure, which presupposes the non-negative RHS); `test-shield` / `test-unshield` / `test-confidential-transfer` exercise the `Sh` channel (`live == expected_total` with `Sh > 0`).

### ET-2 — No upward wrap in the additive prefix

**Statement.** At every reachable chain state `C`, the additive prefix `G + S + I` does not exceed `UINT64_MAX = 2^64 − 1`; both intermediate sums `(G + S)` and `(G + S) + I` are computed exactly with no modular reduction. (The §3.22 `Sh` term is **not** part of the additive prefix — it is the third subtraction, bounded by ET-1, and so plays no role in ET-2.)

**Proof.** This is a corollary of the S-007 additive closure (`S007OverflowProtection.md` T-1 + T-5) together with the genesis sane-bounds defense-in-depth. `G + S + I` is the total value ever *injected* into the chain's accounted supply: `G` at genesis, `S` by subsidy minting, `I` by cross-shard inbound credits. Each component is independently bounded below `2^64`:

- `G ≤ Σ initial_balance + Σ initial_stake`, and the genesis loader (`GenesisConfig::from_json`, cited in S-007 §1.2) rejects any genesis whose summed balances/stakes plus `block_subsidy`/`subsidy_pool_initial`/`zeroth_pool_initial` exceed the `1e18` sane bound, so `G < 2^64` by construction.
- `S` is bounded by the E4 finite-pool cap when `subsidy_pool_initial_ != 0` (`chain.cpp:1268-1272`: `S ≤ subsidy_pool_initial_ < 2^64`); in the perpetual-subsidy mode (`subsidy_pool_initial_ == 0`) each per-block mint is `checked_add_u64`-guarded at the distribution site (`total_distributed = total_fees + subsidy_this_block`, `chain.cpp:1280`), and the per-creator credits (`1292`, `1300`) throw rather than wrap — so `S` can only grow while every credit it funds stays representable. More to the point, by ET-1 the *live* sum equals `G + S + I − L − O − Sh`, and `live_total_supply()` is itself a `uint64_t` fold (`chain.cpp:699-704`) that S-007 keeps below `2^64`; hence `G + S + I = live + L + O + Sh`, and since each of `live, L, O, Sh` arose from `checked_add_u64`-guarded or domination-bounded increments, their sum stays representable on any chain that has not tripped an S-007 throw (which would have rolled the block back under A9).
- `I` is `checked_add_u64`-guarded at both the per-receipt credit (`chain.cpp:1368`) and the per-block sum (`chain.cpp:1377`), and folds into `accumulated_inbound_` only after those guards pass.

Because every credit channel that feeds `G`, `S`, or `I` is either genesis-sane-bounded or `checked_add_u64`-guarded (throwing + A9-rollback on overflow rather than wrapping), no reachable `C` has `G + S + I ≥ 2^64`: such a state would have required a guarded addition to wrap, which the guard forbids. The two intermediate sums in `expected_total()` are therefore exact. ∎

**Cross-reference (not re-proved here).** The full additive-overflow argument — every one of the eight `checked_add_u64` call sites, the iff-overflow detection completeness, and the A9 rollback composition — is `S007OverflowProtection.md` T-1..T-5. ET-2 consumes that result; it does not restate it. F-2 records the cross-link.

**Test witness.** `tools/test_overflow_paths.sh` (S-007 throws-then-rolls-back rather than wrapping on a near-`UINT64_MAX` credit — the empirical guarantee that the additive prefix never silently exceeds `2^64`).

### ET-3 — Totality: `expected_total()` equals its real-integer value

**Statement.** At every reachable chain state `C`, `expected_total(C)` (the machine `uint64_t` computation) equals `T = G + S + I − L − O − Sh` computed in ℤ — i.e. the function is **total** (no operand combination produces a wrapped result) and **exact**.

**Proof.** Evaluate the expression tree of §1.1 left to right:

1. `p₁ := G + S`. By ET-2, `G + S ≤ G + S + I < 2^64`, so `p₁ = G + S` exactly (no upward wrap).
2. `p₂ := p₁ + I = G + S + I`. By ET-2, `< 2^64`, so `p₂ = G + S + I` exactly.
3. `p₃ := p₂ − L`. By ET-1, `L + O + Sh ≤ G + S + I = p₂`, and `O, Sh ≥ 0`, so `L ≤ p₂`. Hence `p₂ − L ≥ 0` in ℤ, and the unsigned subtraction yields `p₃ = p₂ − L` exactly (no downward wrap).
4. `p₄ := p₃ − O = (G + S + I − L) − O`. By ET-1, `O + Sh ≤ G + S + I − L = p₃` (rearranging `L + O + Sh ≤ G + S + I`), and `Sh ≥ 0`, so `O ≤ p₃`; hence `p₃ − O ≥ 0` in ℤ, and the unsigned subtraction yields `p₄ = G + S + I − L − O` exactly.
5. `p₅ := p₄ − Sh = (G + S + I − L − O) − Sh`. By ET-1, `Sh ≤ G + S + I − L − O = p₄` (rearranging `L + O + Sh ≤ G + S + I`), so `p₄ − Sh ≥ 0` in ℤ, and the unsigned subtraction yields `p₅ = G + S + I − L − O − Sh = T` exactly.

Each of the five steps is exact, so `expected_total(C) = p₅ = T`. The result `T ∈ [0, G + S + I] ⊂ [0, 2^64)` is a valid non-wrapped `uint64_t` (the three subtractive terms `L, O, Sh` are all non-negative, so `T ≤ G + S + I`; and `T = live ≥ 0` by A1). ∎

**Corollary (monotone safety of evaluation order).** The proof used left-to-right associativity, but ET-1 + ET-2 make the result order-independent: any evaluation order that keeps every partial sum in `[0, G+S+I]` yields `T`. The implementation's order is the natural one and is covered directly; a reviewer need not worry that a compiler reassociation could expose an intermediate underflow, because the *only* operands that could drive a partial value negative are `L`, `O`, and `Sh`, and ET-1 bounds their sum below the additive prefix.

**Test witness.** The A1 gate at `chain.cpp:1866-1892` is the always-on runtime witness: it computes `expected_total()` on every block and compares it to `live_total_supply()`. Every block that passes (the entire shipped suite, e.g. `tools/test_supply_lifecycle.sh`, `tools/test_supply_invariant.sh`, `determ test-supply-invariant-fuzz`) is an instance where `expected_total()` returned the true `T` (equal to a non-negative `live`); a wrapped RHS would have produced a spurious mismatch and thrown.

### ET-4 — A1 gate consequence: the apply-tail check is a true supply comparison

**Statement.** Because `expected_total()` is total (ET-3), the apply-tail assertion at `chain.cpp:1866-1892`

```cpp
uint64_t expected = expected_total();
uint64_t actual   = live_total_supply();
if (actual != expected) { /* format diagnostic */ throw std::runtime_error(buf); }
```

compares `live_total_supply()` against the **true** real-integer ledger value `T`, not against a wrapped near-`2^64` sentinel. Consequently: (a) on an honest block the gate does **not** spuriously throw (no false-positive liveness break from an underflowed RHS), and (b) a real supply divergence `live ≠ T` is detected with its true magnitude (the diagnostic at `chain.cpp:1872-1892` prints `delta = actual − expected` and a per-field breakdown, both true integers by ET-3).

**Proof.** Immediate from ET-3: `expected == T`. For (a): on an honest block, FA11 T-12 gives `live == T`, so `actual == expected` and the `!=` branch is not taken — the gate is silent. Had `expected_total()` underflowed, `expected` would be `T + 2^64` (mod `2^64`), i.e. some value `≠ T = live` whenever `T mod 2^64 ≠ live mod 2^64`; but since `T = live < 2^64` and the wrap would put `expected` near `2^64 > live`, the gate would throw on an honest block — a liveness break. ET-3 rules this out. For (b): the compared value `expected` is the true six-term `T` (ET-3), and the subtraction `delta = actual − expected` is computed as `int64_t` (`chain.cpp:1873`), so `delta` is the true signed divergence. The printed per-field breakdown itemizes all **six** operands — `(genesis=… +subsidy=… +inbound=… −slashed=… −outbound=… −shielded=…)` (`chain.cpp:1879-1891`) — so on a chain with `Sh > 0` the printed fields reconcile to `expected` directly: the six operands sum to `expected` by construction, `accumulated_shielded_` being subtracted exactly as in `expected_total()` (`chain.hpp:596`). An operator reading a gate-fire can therefore attribute a divergence across every supply channel, the confidential pool included, with no manual add-back. (The sixth operand was added in the round-11 §3.22 diagnostic reconciliation; earlier builds itemized only the five transparent operands and required the reader to add `accumulated_shielded_` back manually.) ∎

**Why this matters operationally.** The A1 gate is the chain's last-line integrity check: it is the mechanism that turns a silent state-corruption bug (a mis-accounted slash, a double-credited receipt, a dropped subsidy fold) into a loud, block-rejecting throw with a rollback (A9). ET-4 establishes that this safety net is itself sound — it cannot be defeated by an underflowed reference value that either hides a real bug behind a coincidental wrap-match or fabricates a phantom bug that halts an honest chain. The gate's trustworthiness is exactly the totality of its RHS.

**Test witness.** `tools/test_supply_invariant.sh` (the gate fires correctly on injected divergence and stays silent on honest deltas — both behaviors depend on `expected` being the true `T`); the always-on gate itself across every block of every regression that exercises apply.

---

## 3. Why the bound is emergent, not asserted (F-1)

There is **no** explicit runtime statement `assert(accumulated_slashed_ + accumulated_outbound_ + accumulated_shielded_ <= genesis_total_ + accumulated_subsidy_ + accumulated_inbound_)` anywhere in `chain.cpp`. ET-1 is an *emergent* invariant: it holds as a consequence of (i) every individual accumulator increment being bounded by the live value it consumes or the guarded value it credits, and (ii) the live sum being a non-negative `uint64_t` fold. The chain enforces the *stronger* equality `live == G + S + I − L − O − Sh` at the apply tail (the A1 gate), and ET-1 is the inequality that equality implies once one observes `live ≥ 0`.

This is by design, not omission. A standalone `assert(L + O + Sh <= G + S + I)` would be:

- **Redundant** with the A1 gate. The gate already computes `expected_total()` and compares it to `live`; if ET-1 were ever violated, `expected_total()` would wrap to a near-`2^64` value, which (being `≠ live < 2^64`) the gate would catch and throw on — so the corruption surfaces at the *same* site, one block later at worst, via the existing diagnostic. Adding a separate assert would duplicate the detection without strengthening it.
- **Weaker as a localizer** than the per-field diagnostic. When the gate throws, its message prints all six operands plus the signed delta (`chain.cpp:1879-1891`), which tells an operator *which* channel diverged — the `−shielded` term is itemized alongside the transparent five, so the confidential pool is a first-class column of the breakdown. A bare domination assert would only say "burns exceeded mints," a strictly less useful diagnosis.

So F-1 is a deliberate boundary: ET-1 is a *proof obligation discharged analytically*, and the runtime check that protects against its violation is the already-present A1 gate, not a dedicated assert. The contribution of this document is to make the analytic obligation explicit and closed, so a reviewer auditing "can `expected_total()` underflow?" has a one-document answer rather than having to reconstruct the domination bound from the five increment sites.

---

## 4. What this doesn't prove

- **The A1 identity itself.** ET-1..ET-4 *consume* `live == G + S + I − L − O − Sh` (FA11 T-12 / FA-Apply-1 I-6 / SI-1) as a hypothesis and prove the RHS arithmetic is total. The per-block delta-matching that establishes the identity is FA11 / SI-1 scope; the present proof is downstream of it. (Route B of ET-1 is the one place this proof is *independent* of A1, deriving the domination bound from the increment-vs-live-consumption structure directly — but ET-3/ET-4 still cite the identity for the honest-block silence claim.)
- **The additive-overflow half.** ET-2 cites `S007OverflowProtection.md` T-1..T-5 + the genesis sane-bounds check; it does not re-enumerate the `checked_add_u64` sites. The two proofs are complementary halves (subtractive / additive) of "the A1 RHS is exact in both directions." The §3.22 `Sh` term is subtractive, so it adds a third *downward*-wrap operand (covered by ET-1/ET-3) but no new upward-wrap surface for ET-2.
- **Cross-shard *aggregate* underflow.** ET-1 is a *per-shard* bound (`L + O + Sh ≤ G + S + I` on one `Chain`). The K-shard aggregate `Σ_s expected_total(C_s)` and its conservation to `Σ_s genesis_total(C_s)` is `CrossShardSupplyConservation.md` FA-Apply-17 / `SupplyInvariantComposition.md` SI-3; the aggregate's non-underflow follows from each per-shard RHS being total (ET-3) summed in ℤ, but the conservation identity itself is FA-Apply-17 scope. (`Sh` is single-shard-local — FA-Apply-17 §5 lim. 7 — so it needs no cross-shard netting.)
- **Snapshot-restore preservation of the bound.** That `L, O, Sh, G, S, I` round-trip exactly across `serialize_state → restore_from_snapshot` (so ET-1 holds identically post-restore) is `SupplyInvariantComposition.md` SI-2 / `SnapshotDeterminismComposition.md` SD-5; the legacy back-solve (`chain.cpp:2634-2655`) reconstructs `G` by the rearrangement `G = live + (L + O + Sh) − (S + I)` (the `+ Sh` operand of `deltas_neg` at `chain.cpp:2650-2651`), which is `≥ 0` precisely because ET-1 holds on the donor chain. ET-1 is therefore a *precondition* the back-solve relies on, but the round-trip mechanics are SI-2. (Omitting the `+ Sh` term would under-compute `G` and fail-closed-reject a valid fieldless+shielded snapshot — the SnapshotRestoreGateAudit §2b fix.)
- **Byzantine block content / Byzantine snapshot bytes.** A maliciously fabricated block (a receipt with no source debit, a forged balance) or a self-inconsistent snapshot can produce a state where `live ≠ T`; those are caught by orthogonal mechanisms (V12/V13 cross-shard validator predicates, FA1 Ed25519 authentication, the S-033/S-038 state-root gate, the restore-side G1/G2 gates). ET-4 establishes only that the A1 gate's *reference value* is sound; the gate's ability to catch Byzantine content is the A1 gate's own property (and reduces to those orthogonal defenses), not ET-4's.
- **`next_nonce` / non-supply counters.** `expected_total()` reads only the six supply accumulators; per-account `next_nonce` (incremented by `++`, `S007OverflowProtection.md` §2) and the registry/merge/param namespaces are not supply-bearing and play no role in the RHS. Out of scope.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `include/determ/chain/chain.hpp:590-597` | `expected_total()` — the object of the proof (three unsigned subtractions). |
| `include/determ/chain/chain.hpp:889-898` | the six `uint64_t` accumulator declarations `G, S, L, I, O, Sh` (`accumulated_shielded_` at `:898`). |
| `src/chain/chain.cpp:699-704` | `live_total_supply()` — the non-negative `uint64_t` LHS that forces `T ≥ 0` (ET-1 Route A). |
| `src/chain/chain.cpp:905-944` | genesis bootstrap — ET-1 / ET-2 base case (`G` set at `:934`, six accumulators zeroed at `:935-939`). |
| `src/chain/chain.cpp:744`-region | TRANSFER `cost` pre-check — the per-account debit bound that makes `block_outbound` consume live value (ET-1 Route B). |
| `src/chain/chain.cpp:765` | `block_outbound += tx.amount` — the only `O` increment. |
| `src/chain/chain.cpp:1324-1327` | suspension-slash `deduct = min(suspension_slash_, locked)` — bounded `L` increment. |
| `src/chain/chain.cpp:1348-1349` | equivocation full forfeit `block_slashed += locked; locked = 0` — bounded `L` increment. |
| `src/chain/chain.cpp:1368`, `1377` | inbound-receipt + per-block-sum `checked_add_u64` guards on the `I` channel (ET-2). |
| `src/chain/chain.cpp:1280`, `1292`, `1300` | subsidy/fee `checked_add_u64` guards on the `S` channel (ET-2). |
| `src/chain/chain.cpp:1859-1864` | apply-tail accumulator fold — the only per-block mutation of `S, I, O, L`. |
| `src/chain/chain.cpp:1037` / `1081` / `1172` | §3.22 `accumulated_shielded_` mutation (SHIELD `+A` / UNSHIELD `−A` / CONFIDENTIAL_TRANSFER `−fee`) — the `Sh` channel (ET-1 Route B); single-shard reject `:1059`. |
| `src/chain/chain.cpp:1866-1892` | the A1 gate `if (actual != expected) throw` — ET-4's protected site. |
| `src/chain/chain.cpp:1872-1892` | the per-field diagnostic (`delta`, and all six operands `genesis/subsidy/inbound/slashed/outbound/shielded`) — true integers by ET-3 (ET-4 part b); the six printed operands reconcile to `expected` on a shielded chain. |
| `src/chain/chain.cpp:2634-2655` | snapshot legacy back-solve `G = live + (L+O+Sh) − (S+I)` (`+Sh` operand of `deltas_neg` at `:2650-2651`) — relies on ET-1 for `G ≥ 0` (see §4). |
| **FA11** `EconomicSoundness.md` | A1 closed-form T-12 (the identity ET-1 Route A / ET-3 / ET-4 consume) + the monotone-accumulator description. |
| **FA-Apply-1** `AccountStateInvariants.md` | I-1 (per-account no-underflow — the building block ET-1 lifts) + I-6 (A1 closure ET-4 protects). |
| **SI** `SupplyInvariantComposition.md` | SI-1 apply-preservation case table (reused by ET-1) + §5 lim. 4 (the underflow aside this proof closes) + SI-2 (snapshot round-trip of the accumulators). |
| **S-007** `S007OverflowProtection.md` | T-1..T-5 additive-overflow dual (ET-2 cites) + the genesis `1e18` sane-bounds check. |
| **FA-Apply-17** `CrossShardSupplyConservation.md` | the K-shard aggregate (the cross-shard scope ET-1's per-shard bound feeds, §4). |
| **FA-Apply-16 / FA-Apply-10** `StakeForfeitureCascade.md` / `EquivocationSlashingApply.md` | the slash-deduct bound `min(suspension_slash_, locked)` / full-forfeit-of-`locked` that bounds the `L` term. |
| `Preliminaries.md` §2.0 | the A1-accounting / A1-crypto namespace split (this proof invokes NO cryptographic assumption — pure `uint64_t` totality). |
| `docs/SECURITY.md` §S-007 | the overflow-protection closure narrative ET-2 cross-links. |
| `tools/test_supply_invariant.sh`, `tools/test_supply_lifecycle.sh` | empirical A1-gate pins (every PASS is an instance of `expected_total()` returning the true `T`). |
| `determ test-supply-invariant-fuzz` (R41 H1) | randomized slash/outbound/subsidy/inbound A1-delta driver — exercises the ET-1 domination across mixed channels. |
| `tools/test_overflow_paths.sh` | S-007 throw-then-rollback empirical pin (ET-2's additive-prefix non-wrap). |

---

## 6. Status

**Proof complete (ET-1..ET-4); analytic totality argument, changes no code.**

All four theorems are closed:

- **ET-1** (structural domination `L + O + Sh ≤ G + S + I`) — closed two ways: Route A as an immediate consequence of the six-term A1 identity (`live ≥ 0` ⇒ `T ≥ 0`), and Route B as a standalone induction grounding the bound in the increment-vs-live-consumption structure (every unit added to `L`/`O`/`Sh` is removed from the non-negative live sum, every unit available to be removed is `G + S + I`; the §3.22 `Sh` is two-directional, and its decrements only relax the bound). Route B makes ET-1 independent of A1 as input.
- **ET-2** (no upward wrap in `G + S + I`) — closed by composition with `S007OverflowProtection.md` T-1..T-5 (every credit channel feeding `G`/`S`/`I` is `checked_add_u64`-guarded or genesis-sane-bounded; an overflow throws + rolls back under A9 rather than wrapping). Cross-linked, not re-derived (F-2). The `Sh` term is subtractive, so it adds no upward-wrap surface.
- **ET-3** (totality: `expected_total() == T` in ℤ) — closed by left-to-right evaluation of the expression tree: ET-2 makes the two additions exact, ET-1 makes all three subtractions non-negative hence exact. The result lands in `[0, G + S + I] ⊂ [0, 2^64)`.
- **ET-4** (A1-gate soundness consequence) — closed from ET-3: the apply-tail `actual != expected` check compares `live` against the true six-term `T`, so it neither spuriously throws on honest blocks nor masks real divergence behind a wrap; the diagnostic itemizes all six operands (`genesis/subsidy/inbound/slashed/outbound/shielded`), each a true integer by ET-3, reconciling to `expected` on a shielded chain.

No theorem is open or partial. The proof's contribution is to close the **subtractive** half of the A1 RHS's exactness — the dual of S-007's additive half — and thereby justify the trust every other A1 proof places in `expected_total()` as a reference value. §3.22 added a third subtractive term (`accumulated_shielded_`), so the RHS now has three unsigned subtractions rather than two; ET-1's domination bound is correspondingly `L + O + Sh ≤ G + S + I`. `SupplyInvariantComposition.md` §5 lim. 4's one-line underflow aside is now a discharged structural theorem (ET-1), and the A1 integrity gate (`chain.cpp:1866-1892`) is established as sound against a wrapped reference value (ET-4). The argument is pure `uint64_t` arithmetic — it reduces to no cryptographic assumption (`Preliminaries.md` §2.0) and adds no runtime check; it documents that the existing A1 gate is the necessary and sufficient enforcement point, with ET-1 holding emergently rather than by a redundant assert (F-1).
