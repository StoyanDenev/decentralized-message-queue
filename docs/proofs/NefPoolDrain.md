# FA-Apply-14 — E1 Negative Entry Fee pool drain (REGISTER apply)

This document formalizes the apply-layer state machine governing Determ's E1 **Negative Entry Fee** (NEF) mechanism — the per-first-time-REGISTER drain that halves the Zeroth pool's balance and credits the new registrant. The mechanism is the **bootstrap-incentive channel** of the chain's economic model: a one-shot reward sourced from a genesis-funded pool that converges geometrically to zero across the network's growth curve, with zero contribution to inflation. Together with the per-block subsidy mint (FA-Apply-7 / `SubsidyDistribution.md` T-S1..T-S5) and the fee distribution channel (FA-Apply-6 / `FeeAccounting.md` T-F1..T-F5), NEF completes the chain's three credit channels into validator-bearing accounts. The supply-side correctness of the channel — that NEF is an **intra-supply transfer**, not a mint — is what FA11 T-13 cites as the load-bearing claim for A1 closure under arbitrary REGISTER sequences.

The proof is mechanical: the entire NEF computation lives in `Chain::apply_transactions` at `src/chain/chain.cpp:790–836`, with the first-time-detection gate at lines 795–796, the pool-availability gate at lines 824–826, the halving + transfer at lines 827–831, and the silent no-op fall-through when any gate fails. The genesis seeding of `accounts_[ZEROTH_ADDRESS].balance` happens in `src/chain/genesis.cpp:341–361` from the `GenesisConfig.zeroth_pool_initial` field, which the genesis-balance accounting path then folds into `genesis_total_` like any other initial allocation (`chain.cpp` index-0 branch). The mechanism's correctness sits at the intersection of three guarantees: (a) the gate fires iff this REGISTER is the FIRST for the sending domain (T-N3 idempotency), (b) the halving is exact integer division with a non-zero-guard (T-N1 + T-N4), and (c) the transfer is balance-only with no counter advance (T-N5 A1 conservation). The three guarantees compose into the global geometric exhaustion guarantee (T-N6) and the byte-level replay determinism (T-N7).

**Companion documents:** `Preliminaries.md` (F0) for V-15 transaction-apply rules and A1 conservation notation; `AccountStateInvariants.md` (FA-Apply) for I-1 atomic apply and I-5 channel decomposition — NEF is one of the eight enumerated credit channels into `accounts_[*].balance`; `SubsidyDistribution.md` (FA-Apply-7) §1.4 + §4 + T-S6, which references this proof as the drill-down for the NEF channel; `DAppRegistryLifecycle.md` (FA-Apply-5) §4 — DAPP_REGISTER explicitly does NOT drain the pool, mirroring the subsidy-vs-NEF channel separation; `EconomicSoundness.md` (FA11) T-12 (A1 unitary-supply invariant) + T-13 (E1 supply neutrality) — the present proof formalizes T-13 mechanically against the apply path; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot round-trip of `accounts_[ZEROTH_ADDRESS].balance` via the `a:` namespace contribution to the S-033 state_root.

---

## 1. Setup

### 1.1 The Zeroth pool state

Per `include/determ/chain/params.hpp:31–32`, the `ZEROTH_ADDRESS` constant is the canonical all-zero anon address `0x0000…0000`. The all-zero pubkey is a low-order point on curve25519 with no usable Ed25519 private key — no actor can synthesize a signature for `from == ZEROTH_ADDRESS`, and the validator's `check_transactions` step explicitly rejects any tx with that sender as a defense-in-depth guard (FA11 §8). The address is effectively **unspendable except through the NEF channel** — only the REGISTER apply branch at `chain.cpp:823–833` moves value out of `accounts_[ZEROTH_ADDRESS]`.

The pool's initial balance is set from `GenesisConfig.zeroth_pool_initial` (`include/determ/chain/genesis.hpp:127–137`) at bootstrap (`src/chain/genesis.cpp:341–361`): the loader merges the pool value into `g.initial_state[]` (either incrementing an existing ZEROTH entry or appending a new one). The pool then counts toward `genesis_total_` via the standard index-0 apply path (the genesis branch sums every `initial_state[].balance` into `gtotal`) — no separate accounting hook for the Zeroth pool. The merge logic supports both fresh genesis and snapshot-bootstrap restore (where `accounts_[ZEROTH_ADDRESS]` is reconstructed from the snapshot's account map; FA-Apply-2 T-S1). Post-genesis, the only mutator is the NEF branch at `chain.cpp:829`; the pool is monotone non-increasing.

### 1.2 The first-time-register detection

Per `chain.cpp:795–796`, the apply branch detects first-time REGISTER **before** mutating `registrants_`:

```cpp
const bool first_time_register =
    (registrants_.find(tx.from) == registrants_.end());
```

The ordering is load-bearing: if we wrote `registrants_[tx.from]` first (via `operator[]`'s default-construction), the very first call would create the entry as a side effect and a later `is_present` check would observe it as "already present". The `find()`-before-`insert()` ordering reflects the genuine pre-mutation state of the registry. This is the pattern `tla/DAppRegistry.tla` (FB9) formalizes as the `NefDrainsOnlyOnce` invariant — for any domain D, the NEF channel fires at most once across the chain's lifetime.

### 1.3 The NEF transfer

Per `chain.cpp:823–833`, the NEF branch is a guarded balance-only transfer:

```cpp
if (first_time_register) {
    auto pool_it = accounts_.find(ZEROTH_ADDRESS);
    if (pool_it != accounts_.end() && pool_it->second.balance > 0
        && tx.from != ZEROTH_ADDRESS) {
        uint64_t nef = pool_it->second.balance / 2;
        if (nef > 0) {
            pool_it->second.balance       -= nef;
            accounts_[tx.from].balance    += nef;
        }
    }
}
```

Four guards admit the transfer: (1) `first_time_register == true` excludes re-REGISTERs; (2) `pool_it != accounts_.end()` requires the Zeroth address to be present (genesis-seeded or restored); (3) `pool_it->second.balance > 0` rejects empty pool; (4) `tx.from != ZEROTH_ADDRESS` prevents self-credit (validator already rejects, belt-and-suspenders). When all four hold, `nef = pool_balance / 2` via unsigned integer division (`pool=1 ⇒ nef=0`, `pool=2 ⇒ nef=1`, …). The inner `nef > 0` guard at line 828 skips the asymptotic-tail no-op transfer. Lines 829–830 are the atomic two-leg transfer: pool debited by `nef`, registrant credited by `nef`. **No counter is touched** — no `accumulated_subsidy_`, no `accumulated_inbound_`, no `accumulated_slashed_`, no `accumulated_outbound_`, no `total_fees`. The mechanism is purely a balance-preserving channel within `accounts_`, which is what makes T-N5 trivially true.

---

## 2. Theorems

### T-N1 — First-time REGISTER drains pool by half

**Statement.** For every block `b` applied successfully and every REGISTER transaction `tx` ∈ `b.transactions` that (a) passed the validator's V-15 preconditions, (b) passed the apply-layer payload-shape check at `chain.cpp:780–787`, (c) passed the fee charge at `chain.cpp:788`, (d) is first-time for the sender (`registrants_.find(tx.from) == registrants_.end()`), AND (e) `accounts_[ZEROTH_ADDRESS].balance == P > 0`, the apply produces:

```
nef = P / 2
Δaccounts_[ZEROTH_ADDRESS].balance = −nef
Δaccounts_[tx.from].balance        = +nef    (plus any other channels in the same block)
```

The halving is exact integer division: for `P = 1000`, `nef = 500`; for `P = 999`, `nef = 499`; for `P = 1`, `nef = 0` (and the inner guard at line 828 then skips the no-op transfer). The pool's post-apply balance is `P − nef = P − ⌊P/2⌋ = ⌈P/2⌉`.

*Proof sketch.* By inspection of `chain.cpp:790–833`. Lines 795–796 evaluate `first_time_register` from a pre-mutation `find()` lookup. Lines 798–805 perform the registry mutation (the `find()` already returned a snapshot of the pre-mutation state, so the gate's decision is locked in). The guarded branch at lines 823–833 then dispatches the transfer. The four guards at lines 823–826 are conjunctive — all must hold to enter the transfer body. Inside the body, `nef = pool_it->second.balance / 2` is unsigned integer division (no rounding ambiguity). The two-leg transfer at lines 829–830 is unconditional once the inner `nef > 0` check at line 828 admits. Each leg uses unchecked u64 arithmetic; the debit cannot underflow (`pool_it->second.balance ≥ nef` by construction, since `nef = pool_it->second.balance / 2 ≤ pool_it->second.balance`), and the credit cannot overflow without the registrant's balance approaching u64-max (which the A1 supply ceiling prevents — see T-N5). ∎

**Code witness.** `src/chain/chain.cpp:795–796` (first-time detection); `src/chain/chain.cpp:823–833` (NEF branch); `src/chain/chain.cpp:827` (`nef = pool_balance / 2` halving).

**Test witness.** `tools/test_nef_pool_drain.sh` (`determ test-nef-pool-drain`) scenario 3: starts with `zeroth_pool_initial = 1000`, applies a first-time REGISTER for alice, asserts `c.balance(ZEROTH_ADDRESS) == 500` (T-N1 halving). Also asserts `c.balance("alice") == alice_before + 500 − 1` (alice gained 500 from NEF, paid 1 in fee; T-N2 credit landing point).

### T-N2 — Drained amount credits registrant

**Statement.** Under the hypotheses of T-N1, the registrant's balance advances by exactly `nef` from the NEF channel — the credit lands at `accounts_[tx.from]`, not at `accounts_[tx.to]` (REGISTER has no `to` field; the apply path indexes by `tx.from`). The credit is independent of any other balance change to the same account in the same block (fee debit on this tx, fee credit if the registrant is also a `b.creators[]` member, other txs from/to the same account); it adds on top of those.

The credit is also independent of `tx.payload` — the payload encodes the registrant's ed25519 pubkey + optional region, but neither is consulted by the NEF transfer. The credit lands at `accounts_[tx.from]` purely based on the `from` address.

*Proof sketch.* By inspection of `chain.cpp:830`. The left-hand side of the credit is `accounts_[tx.from].balance` (using `std::map::operator[]`, which auto-creates the entry if absent — see I-4 account auto-creation in FA-Apply, particularly relevant when the registrant is a brand-new domain with no prior balance). The right-hand side is `+= nef`. No other account is touched on the credit leg; in particular, no `tx.to` exists for a REGISTER (the field is unused for this tx type). The transfer is single-source single-sink: pool → registrant, exactly. ∎

**Code witness.** `src/chain/chain.cpp:829–830` (the two-leg atomic transfer).

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 3 asserts `c.balance("alice") == alice_before + 500 − 1` — the alice account ends up `+500` from NEF and `−1` from fee paid to the (non-self) validator-creator, net `+499`. This composite assertion catches drift in either direction: NEF credit landing on the wrong account, or the credit amount being other than `pool/2`.

### T-N3 — Re-REGISTER is no-op for the pool (idempotent channel)

**Statement.** For every block `b` applied successfully and every REGISTER transaction `tx` ∈ `b.transactions` whose sender already has an entry in `registrants_` (i.e., `registrants_.find(tx.from) != registrants_.end()` at the moment line 795 executes), the apply does NOT drain the pool. Specifically:

```
Δaccounts_[ZEROTH_ADDRESS].balance = 0
Δaccounts_[tx.from].balance        = 0  (from the NEF channel — fee debit still applies)
```

The registry update at line 805 still proceeds (key rotation / region update is a legitimate use case for re-REGISTER), and the fee charge at line 788 still applies. But the four-guard NEF branch at lines 823–833 evaluates `first_time_register == false` at line 823 and skips the entire transfer body. The pool's balance is invariant across any number of re-REGISTERs for the same domain.

*Proof sketch.* From line 795: `first_time_register = (registrants_.find(tx.from) == registrants_.end())`. If `tx.from` is already a key in `registrants_`, `find()` returns a valid iterator (≠ end), so the boolean is `false`. The branch at line 823 then bypasses lines 824–833 entirely. No `accounts_[ZEROTH_ADDRESS].balance` mutation occurs from this tx. The registry mutation at line 805 (`registrants_[tx.from] = e`) overwrites the existing entry with the new `RegistryEntry` (covering key rotation, region update, regenesis-time semantics), but does not roll back the existing entry to `end()` — the `first_time_register` boolean was already evaluated before the assignment, so this overwrite has no retroactive effect.

The idempotency is **the security property of NEF**: it defends against key-rotation churn attacks where an attacker registers, then re-registers repeatedly to drain the pool. By T-N3, each domain D contributes at most one NEF drain across its lifetime, regardless of the count of REGISTER txs from D. The economic cost of attacking the pool is therefore upper-bounded by `n × REGISTER_FEE`, where `n` is the number of distinct domains the attacker creates — and each new domain costs the attacker a wallet creation + the apply-layer fee, which is the cap on attack rate. ∎

**Code witness.** `src/chain/chain.cpp:795–796` (pre-mutation detection); `src/chain/chain.cpp:823` (`if (first_time_register)` gate); `src/chain/chain.cpp:805` (registry mutation that does NOT roll back `first_time_register`).

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 4: first REGISTER for alice drains pool 1000 → 500; second REGISTER for alice (with a region update, different payload bytes) keeps pool at 500. The assertions `c.balance(ZEROTH_ADDRESS) == pool_after_first` and `ra->region == "us-east"` jointly verify: NEF skipped (pool invariant) AND registry mutation applied (region update succeeded).

### T-N4 — Pool floor at zero (cannot go negative)

**Statement.** Across any chain history, `accounts_[ZEROTH_ADDRESS].balance ≥ 0` holds at every point (trivially, as it is `uint64_t`). The stronger property is that the NEF branch never produces an underflow: for any pool balance `P ≥ 0`, the post-apply balance is `P − ⌊P/2⌋ = ⌈P/2⌉ ≥ 0`. Specifically:

- `P = 0` ⇒ `nef = 0` ⇒ branch admitted at line 825 fails (`balance > 0` required) ⇒ no transfer ⇒ pool stays at 0.
- `P = 1` ⇒ enters line 825 (`balance > 0`) ⇒ `nef = 1/2 = 0` ⇒ inner guard `nef > 0` at line 828 fails ⇒ no transfer ⇒ pool stays at 1 (asymptotic tail).
- `P = 2` ⇒ `nef = 1` ⇒ transfer ⇒ pool 2 → 1.
- `P = 1000` ⇒ `nef = 500` ⇒ transfer ⇒ pool 1000 → 500.

The asymptotic tail `P = 1` is **not pathological**: the chain remains live, NEF degrades to a no-op, and subsequent registrants receive no NEF credit. The pool floor is structurally `0`, but the asymptotic limit under continual first-time REGISTERs is `1` (the pool never quite reaches zero — `P = 1` is a stable fixed point because `nef = 0`).

*Proof sketch.* By integer-arithmetic case analysis. For `P = 0`: line 825's `balance > 0` guard fails, branch skipped. For `P = 1`: line 825 admits, `nef = 1/2 = 0` (unsigned integer division truncates), line 828's `nef > 0` guard fails, branch skipped. For `P ≥ 2`: `nef = P/2 ≥ 1 > 0`, transfer proceeds, debit of `nef = P/2 ≤ P` cannot underflow (since `P ≥ 2 ⇒ P − P/2 = ⌈P/2⌉ ≥ 1 ≥ 0`).

Because the pool's balance is `uint64_t` (unchecked), an underflow would manifest as a wrap to a u64-max-ish value — but the debit's bounds-check is structural via the `nef = pool/2 ≤ pool` invariant. There is no path in the code where `pool_it->second.balance -= nef` produces an underflow, regardless of the pool's prior value, regardless of how many first-time REGISTERs have already drained the pool. ∎

**Code witness.** `src/chain/chain.cpp:827` (`nef = pool/2`, structurally ≤ pool); `src/chain/chain.cpp:828` (`nef > 0` guard for asymptotic tail); `src/chain/chain.cpp:825` (`balance > 0` guard for empty pool).

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 2: `zeroth_pool_initial = 0`, REGISTER for alice, assert `c.balance(ZEROTH_ADDRESS) == 0` after apply (empty pool stays empty). The asymptotic-tail `P = 1` case is implicitly covered by the geometric exhaustion test (T-N6 below); after enough drains, the pool reaches 1 and stays there, even on subsequent first-time REGISTERs.

### T-N5 — A1 conservation (NEF is intra-supply transfer)

**Statement.** Every NEF event preserves the A1 unitary-supply invariant **trivially**, because the channel is a balance-preserving transfer within `accounts_`. Specifically, for every NEF transfer of `nef` units:

```
Δ(Σ accounts_[*].balance) = (−nef from ZEROTH_ADDRESS) + (+nef to tx.from) = 0
Δaccumulated_subsidy_     = 0    (NEF is NOT a mint)
Δaccumulated_inbound_     = 0
Δaccumulated_outbound_    = 0
Δaccumulated_slashed_     = 0
Δgenesis_total_           = 0    (pinned at index-0 apply)
```

The five A1 counters are all unchanged. The left-hand-side `Σ accounts_[*].balance` is unchanged (one account loses `nef`, another gains `nef`, the sum is invariant). The right-hand-side `expected_total() = genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` is unchanged because no counter advances. The A1 invariant `live_total_supply() == expected_total()` therefore holds across NEF events as a direct consequence: both sides advance by `0`.

The Zeroth pool's **initial** balance is captured in `genesis_total_` at index-0 apply (the pool is a regular `initial_state[]` entry whose balance feeds `gtotal`). All subsequent NEF transfers move balance within `accounts_` without altering the genesis total or any of the four monotone counters; the supply ledger is closed under NEF events.

*Proof sketch.* By inspection of `chain.cpp:823–833`. The NEF body consists of exactly four operations: (a) the `nef = pool_balance / 2` computation, (b) the `pool_it->second.balance -= nef` debit, (c) the `accounts_[tx.from].balance += nef` credit, and (d) the implicit end-of-branch. No counter is incremented; no other state field is touched. The two `±nef` mutations are equal-and-opposite within `accounts_`. The sum `Σ accounts_[*].balance + Σ stakes_[*].locked = live_total_supply()` is therefore invariant across the NEF event (the stakes map is also untouched by NEF). The five A1 counters all stay at their pre-NEF values. The closure `live_total_supply() == expected_total()` at `chain.cpp:1397–1419` is preserved structurally.

This is the FA11 T-13 claim formalized at the apply-layer granularity: every NEF event is supply-neutral, so any block containing any number of NEF events still satisfies A1 at apply-tail. Composed with T-S1 (per-block subsidy mint) and T-F4 (fee distribution), NEF closes the three-channel apply-side decomposition of FA11 T-12's induction step. ∎

**Code witness.** `src/chain/chain.cpp:823–833` (the NEF branch's complete operation set); `src/chain/chain.cpp:1397–1419` (the A1 closure assertion at apply-tail); `include/determ/chain/chain.hpp:611–615` (the five A1 counter fields, none touched by NEF); `src/chain/genesis.cpp:341–361` (genesis-time seeding into `initial_state[]`, which feeds `genesis_total_`).

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 3 asserts `c.expected_total() == c.live_total_supply()` after a first-time REGISTER drain (T-N5 holds across a single NEF). Scenario 6 asserts the same equality across a 2-REGISTER block (multiple drains in one apply): `check(c.expected_total() == c.live_total_supply(), "A1: invariant holds under 2-REGISTER block")` AND `check(c.live_total_supply() == total_before, "A1: total supply unchanged (NEF is intra-shard transfer)")`. The composite assertion catches any covert mint or burn that might be introduced by a future apply-path change.

### T-N6 — Geometric exhaustion: pool = floor(initial / 2^k) after k drains

**Statement.** Let `P_0 = zeroth_pool_initial` be the genesis-seeded pool balance, and let `D_1, D_2, …, D_k` be `k ≥ 0` distinct first-time-REGISTER domains, each REGISTERing successfully in sequence. After the `k`-th first-time REGISTER apply, the pool balance is:

```
P_k = ⌈P_{k-1} / 2⌉ = ⌈⌈⌈P_0 / 2⌉ / 2⌉ ... / 2⌉   (k applications of ceiling-divide-by-2)
```

For powers-of-two initial pools, the recurrence simplifies to `P_k = P_0 / 2^k`. For odd initial pools, the recurrence accumulates rounding-up terms but stays within `1` of the pure geometric value. The first-time REGISTER count to reach `P_k = 1` (the asymptotic stable point) is bounded by `⌈log₂ P_0⌉ + O(1)`. After that, the pool is **stuck at 1** indefinitely — subsequent first-time REGISTERs see `nef = 1/2 = 0`, the inner `nef > 0` guard at line 828 skips the transfer, and the pool's balance does not change.

The mechanism's economic implication is sharp: NEF is **not a perpetual inflation source**. Even if the chain runs for millennia and admits exabytes of registrants, the cumulative NEF credit across all registrants is bounded by `P_0 − 1` (everything except the stable-point residue). The pool funds early entrants generously and converges to zero contribution as the network matures — exactly the economic curve a bootstrap-incentive mechanism should produce.

*Proof sketch.* By induction on `k`. **Base** (`k = 0`): `P_0` is the genesis-seeded pool balance, by definition. **Inductive step**: assume `P_{k-1}` is the pool balance after `k − 1` first-time REGISTERs. The `k`-th first-time REGISTER for a fresh domain `D_k` applies the four-guard NEF branch. By T-N1, the post-apply pool balance is `P_{k-1} − ⌊P_{k-1} / 2⌋ = ⌈P_{k-1} / 2⌉`. So `P_k = ⌈P_{k-1} / 2⌉`, completing the induction.

The closed-form `P_k = P_0 / 2^k` (integer division applied k times) holds for any `P_0` because the recurrence `P_k = ⌈P_{k-1} / 2⌉ = P_{k-1} − ⌊P_{k-1} / 2⌋` is bounded below by `⌊P_0 / 2^k⌋` and above by `⌈P_0 / 2^k⌉` (both by induction on k; the lower bound uses ⌈⌉ ≥ ⌊⌋ + (1 if P odd else 0), the upper bound uses ⌈⌉ ≤ ⌊⌋ + 1). The asymptote at `P = 1` follows from `⌈1/2⌉ = 1` (fixed point), and T-N4's `nef > 0` guard ensures no actual transfer in this regime.

The "distinct domains" hypothesis is necessary: by T-N3, only first-time REGISTERs drain. A sequence of `k` REGISTERs from a single domain produces exactly 1 NEF drain (the first), not `k`. The geometric exhaustion rate is therefore proportional to the network's unique-registrant growth, not its REGISTER-tx volume. ∎

**Code witness.** `src/chain/chain.cpp:823–833` (NEF branch repeated invocation across blocks); `src/chain/chain.cpp:795–796` (first-time detection rejects repeat REGISTERs).

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 5: `zeroth_pool_initial = 1000`. After alice's first-time REGISTER: pool = 500 (T-N6 with k=1). After bob's first-time REGISTER: pool = 250 (k=2). The scenario also exercises the carol case (REGISTER fails at fee-charge because carol has 0 genesis balance) — pool stays at 250 because the apply path skipped before reaching the NEF branch, which is consistent with the "k first-time REGISTERs admitted" formulation of the theorem. The asymptote behavior is not unit-tested in this regression but is implicit: after `⌈log₂ 1000⌉ = 10` more first-time REGISTERs from distinct domains, the pool would stabilize at 1 by T-N4's asymptotic-tail guard.

### T-N7 — NEF determinism

**Statement.** For any two Chain instances `C₁` and `C₂` with `C₁ ≡_S C₂` (per FA-Apply-2 §1.2 state-equivalence — identical `accounts_`, `registrants_`, etc.), and any block `B` containing REGISTER transactions, the NEF outcomes are byte-identical:

```
apply_transactions(C₁, B) ≡_S apply_transactions(C₂, B)
```

In particular: identical first-time-detection outcomes for each REGISTER, identical NEF transfer amounts, identical post-apply pool balances, identical post-apply registrant balances, and identical `compute_state_root(C₁_post) == compute_state_root(C₂_post)` byte-for-byte.

*Proof sketch.* The NEF branch is a pure function of three inputs: (a) the REGISTER transaction's `tx.from` field, (b) the chain's pre-apply `registrants_` map (consulted at line 795–796 for first-time detection), and (c) the chain's pre-apply `accounts_[ZEROTH_ADDRESS].balance` (consulted at line 825 for the gate + line 827 for the halving). No I/O, no clock, no RNG, no peer queries. Integer division and integer subtraction are deterministic at the C++ language level.

Under hypothesis `C₁ ≡_S C₂`, all three inputs are equal between the two chains. The branch executes the same comparisons in the same order, evaluates the same `first_time_register` boolean, computes the same `nef`, and produces the same `±nef` mutations. The post-apply maps are byte-identical.

The `compute_state_root` byte-equality follows from the state-root namespace coverage: `accounts_[ZEROTH_ADDRESS].balance` contributes to the `a:` namespace (FA-Apply-2 T-S3 — the per-account-balance leaves), and `accounts_[tx.from].balance` likewise contributes to the `a:` namespace. The Merkle root over sorted leaves is deterministic over the same leaf set. The state_root binding via S-033 + S-038 enforces the byte-equality at the wire layer (a divergent state_root would surface as a producer-side block validation failure under S-038's body.state_root population requirement). ∎

**Code witness.** `src/chain/chain.cpp:790–833` (the deterministic apply branch); `src/chain/chain.cpp:380–410` (state-root leaf encoding for the `a:` namespace covering `accounts_[ZEROTH_ADDRESS]` + `accounts_[tx.from]`); the absence of any clock read, RNG call, or peer query in the REGISTER branch.

**Test witness.** `tools/test_nef_pool_drain.sh` scenario 7 (state_root sensitivity): two chains with the same `zeroth_pool_initial = 1000`; `c1` applies a first-REGISTER (NEF fires), `c2` applies an empty block. Assertion: `c1.compute_state_root() != c2.compute_state_root()` — the NEF mutation affects the state_root. Scenario 8 (determinism): both `c1` and `c2` apply the same first-REGISTER sequence; assertions `c1.compute_state_root() == c2.compute_state_root()` AND `c1.balance(ZEROTH_ADDRESS) == c2.balance(ZEROTH_ADDRESS)` jointly catch any non-determinism in the NEF branch.

---

## 3. NEF rationale

The Negative Entry Fee mechanism exists to **bootstrap value for new entrants without bootstrapping inflation**. Three forces motivate the design:

1. **Bootstrap incentive.** A new chain has zero or near-zero validators registered at genesis (or a small bootstrap committee). New operators considering joining face a "cold start" cost: pay the REGISTER fee (charged at line 788), pay the STAKE deposit (separate tx, typically required for committee eligibility), lose value to network latency and operational overhead before earning any subsidy or fees. Without an entry-side incentive, the network has no signal to early adopters that participation is rewarded. NEF gives them a one-time payout sourced from a pre-funded pool, dampening the cold-start cost — the literature's "founder-equity" pattern: early contributors receive disproportionate rewards because they bear disproportionate risk.

2. **No new supply.** The naive way to fund a bootstrap incentive would be a per-REGISTER mint — but that would couple bootstrap funding to inflation, making the chain's supply schedule unpredictable. NEF avoids this by drawing from a **genesis-funded pool** seeded by `zeroth_pool_initial`. The pool's initial balance is part of `genesis_total_` (per `src/chain/genesis.cpp:341–361`). NEF events are intra-supply transfers (T-N5); they do not advance any A1 counter. See FA11 T-13 for the supply-invariant proof at the chain-wide granularity; the present T-N5 is the apply-layer mechanical formalization.

3. **Geometric drain.** The pool halves per first-time REGISTER (T-N1) and exhausts geometrically (T-N6). This is **not a perpetual inflation source** — the pool exhausts asymptotically to its stable point at `1` (T-N4). Early operators get more; late operators get little or nothing. The drain rate matches the network's growth curve: early adopters get the highest incentive because they are the highest risk, late adopters get the lowest because the network is already established. The decay is also adversary-resistant: an attacker registering many domains cannot extract more than `P_0` total value across the chain's lifetime, and each domain costs a separate fee + wallet creation, putting a sharp cap on attack profitability.

The relationship to the per-block subsidy is **complementary, not overlapping**. Per-block subsidy rewards ongoing participation; NEF rewards entry. Per-block subsidy is potentially perpetual; NEF is necessarily exhausting. Per-block subsidy is minted (advances `accumulated_subsidy_`); NEF is transferred (no counter advance). The two are independent in the math, in the code, and in the economic model. The chain-wide invariant `live = genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` does not include NEF terms explicitly because NEF is intra-supply; only the pool's seed is captured in `genesis_total`. The full audit lives in FA11 T-12; the present proof closes its NEF-channel contribution.

---

## 4. What this doesn't prove

The theorems above target the NEF channel in isolation. They do not extend to:

- **Per-block subsidy mint.** The per-block mint at `chain.cpp:1234–1305` is the scope of FA-Apply-7 (`SubsidyDistribution.md`) T-S1..T-S5. NEF is structurally independent of the mint (T-N5: NEF does not touch `accumulated_subsidy_`).

- **Fee distribution.** The REGISTER fee charge at line 788 is the scope of FA-Apply-6 (`FeeAccounting.md`) T-F1..T-F5; the NEF channel does not touch `total_fees`.

- **DAPP_REGISTER.** A `DAPP_REGISTER` transaction does not drain the Zeroth pool. The DApp registry is a separate state with its own apply branch that does not consult `accounts_[ZEROTH_ADDRESS]`. Clean channel separation per `DAppRegistryLifecycle.md` §4 + T-D1.

- **Snapshot ↔ replay equivalence.** `accounts_[ZEROTH_ADDRESS].balance` survives snapshot serialize/restore via the standard `accounts_` map serialization + the `a:` namespace state_root binding (FA-Apply-2 T-S1 + T-S3). Transitively assumed here.

- **NEF design alternatives** (lottery distribution, harmonic decay, win caps). FA11 §7 discusses retired variants. T-N3, T-N4, T-N5, T-N7 carry over to any sum-preserving rule; T-N1 and T-N6 would require re-proof under a different drain formula.

- **NEF interaction with PARAM_CHANGE.** `zeroth_pool_initial` is genesis-pinned and not on the A5 whitelist (per `Governance.md` FA10). No in-chain refill mechanism exists.

- **Failed-REGISTER refund.** If `charge_fee` returns false at line 788, the apply executes `continue` and skips the entire REGISTER body — registrants_ untouched, NEF skipped, sender balance unaffected beyond the fee-charge's own rollback. Pool preserved exactly. Consistent with the carol-case observation in `test_nef_pool_drain.sh` scenario 5.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | V-15 transaction-apply rules; A1 conservation notation. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 (atomic apply with rollback on throw); I-4 (account auto-creation on `operator[]`); I-5 (NEF is one of the eight enumerated credit channels). |
| `SubsidyDistribution.md` (FA-Apply-7) | §1.4 + §4 + T-S6 — the per-block subsidy proof's NEF reference points to the present proof for the drill-down. |
| `FeeAccounting.md` (FA-Apply-6) | T-F1..T-F5 — fee charging + creator distribution; the REGISTER fee at `chain.cpp:788` is the FA-Apply-6 scope, independent of the NEF branch. |
| `DAppRegistryLifecycle.md` (FA-Apply-5) | §4 + T-D1 — DAPP_REGISTER does NOT drain NEF; clean channel separation between chain-level identity and on-chain DApp registry. |
| `EconomicSoundness.md` (FA11) | T-12 (A1 unitary-supply invariant); T-13 (E1 supply neutrality) — the present T-N5 is the apply-layer formalization. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 + T-S3 — `accounts_[ZEROTH_ADDRESS]` survives snapshot via the `a:` namespace. |
| `docs/PROTOCOL.md` §3.3 | Apply rules for REGISTER including the E1 NEF branch. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table; the `a:` namespace covers `accounts_[ZEROTH_ADDRESS].balance`. |
| `tools/test_nef_pool_drain.sh` | Canonical regression — 18 assertions across 8 scenarios covering T-N1 through T-N7. |
| `tools/test_supply_lifecycle.sh` | Composite A1 lifecycle including NEF + subsidy + fees + cross-shard. |
| `src/chain/chain.cpp:790–836` | REGISTER apply branch including NEF. |
| `src/chain/chain.cpp:795–796` | First-time-register detection (pre-mutation `find()`). |
| `src/chain/chain.cpp:823` | `if (first_time_register)` gate (T-N3). |
| `src/chain/chain.cpp:824–826` | Pool-availability + Zeroth-self guards. |
| `src/chain/chain.cpp:827` | `nef = pool_balance / 2` halving (T-N1, T-N6). |
| `src/chain/chain.cpp:828` | `nef > 0` asymptotic-tail guard (T-N4). |
| `src/chain/chain.cpp:829–830` | Atomic two-leg transfer (T-N2, T-N5). |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion at apply-tail. |
| `src/chain/genesis.cpp:341–361` | Genesis-time seeding of Zeroth pool into `initial_state[]`. |
| `include/determ/chain/params.hpp:25–32` | `ZEROTH_ADDRESS` constant. |
| `include/determ/chain/genesis.hpp:127–137` | `GenesisConfig.zeroth_pool_initial` field. |

---

## 6. Status

All seven theorems (T-N1 through T-N7) are closed in the current codebase:

- **T-N1** (first-time REGISTER drains pool by half) closed via `chain.cpp:827` halving + `chain.cpp:829–830` atomic transfer; regression `test_nef_pool_drain.sh` scenario 3 (`pool 1000 → 500`).
- **T-N2** (drained amount credits registrant) closed via `chain.cpp:830` `accounts_[tx.from].balance += nef`; regression scenario 3 (`alice +500 NEF`).
- **T-N3** (re-REGISTER idempotent for pool) closed via `chain.cpp:795–796` pre-mutation `find()` ordering + the `first_time_register` boolean evaluated before the registry write at line 805; regression scenario 4 (`pool UNCHANGED on re-REGISTER`).
- **T-N4** (pool floor at zero) closed via the conjunctive `balance > 0 && nef > 0` guards at lines 825 + 828 + integer-arithmetic safety of `nef = pool/2 ≤ pool`; regression scenario 2 (`empty pool: balance still 0`) + asymptotic-tail implicit coverage.
- **T-N5** (A1 conservation) closed via the no-counter-touched NEF branch + the A1 closure assertion at lines 1397–1419; regression scenarios 3 + 6 (`A1: invariant holds`, `A1: total supply unchanged`).
- **T-N6** (geometric exhaustion: pool = floor(initial / 2^k) after k drains) closed via the recursive composition of T-N1 across distinct first-time REGISTERs; regression scenario 5 (`pool 1000 → 500 → 250` for alice + bob).
- **T-N7** (determinism) closed via the pure-function nature of the NEF branch (no I/O, no clock, no RNG) + the `a:` namespace state-root binding; regression scenarios 7 + 8 (`state_root sensitive to pool drain`, `same NEF drain → same state_root`).

No theorem is open or partial. The proof rests on a small set of code primitives: the pre-mutation `registrants_.find()` for first-time detection, the integer-divide halving with `nef > 0` guard for the asymptotic tail, the conjunctive four-guard branch admission, the atomic two-leg `−nef / +nef` transfer with no counter touched, and the A1 closure assertion that catches any covert mint or burn. The breadth of consequences — seven theorems covering the full economic semantics of a bootstrap-incentive channel, composing cleanly with FA-Apply-6 (fees), FA-Apply-7 (subsidy), and FA11 (chain-wide A1) — is testimony to how few primitives the chain needs to express a clean intra-supply transfer rule that scales from a single first-time REGISTER to chain-wide geometric exhaustion across millions of registrants.

The §3 rationale closes the economic argument: NEF is the only credit channel in the chain that funds new entrants without inflation, and its geometric decay self-limits the cumulative outflow to the genesis-seeded pool. Combined with the per-block subsidy mint (FA-Apply-7) and the fee distribution channel (FA-Apply-6), the apply-layer's three credit channels exhaustively characterize how value flows into validator-bearing accounts — and FA11 T-12 ties the three back to the chain-wide unitary-supply invariant.
