# S-010 + S-011 — Sybil economics under operator stake-pricing

This document formalizes the joint closure of two High-severity audit findings — S-010 (Sybil via under-priced `min_stake`) and S-011 (abort-claim cartel via M-1 quorum) — through a single economic argument: the operator-facing stake-pricing formula in `docs/SECURITY.md` §S-010 prices a Sybil majority of `N_pool` at `⌈(N_pool / 2) + 1⌉ × min_stake`, and the FA6 + FA-Apply-10 equivocation-slashing composition bounds the cartel attack against an honest committee member to "per-attempt cost ≥ `(M-1) × min_stake`, full-stake forfeiture on follow-through." For any reasonable choice of `min_stake` relative to the chain's exogenous value-at-risk, the attack costs more than its payoff.

The proof is structural and arithmetic. It does not introduce new code paths — the closure is operator policy plus the registry-eligibility predicate at `src/node/registry.cpp:63` (the `chain.stake(domain) < threshold ⇒ ineligible` gate) plus the equivocation forfeit at `src/chain/chain.cpp:1344-1356`. The threat-model output is a concrete dollar-cost-of-attack function operators can plug into deployment planning.

**Companion documents:** `Preliminaries.md` (F0) for `N`, `K`, `V`, committee-selection notation; `EquivocationSlashing.md` (FA6) for the no-false-accusation bound (T-6) and its H3 boundary; `EquivocationSlashingApply.md` (FA-Apply-10) for the apply-side statement that holds at HEAD (T-E0, state neutrality — the full-forfeiture mechanics are historical); `EconomicSoundness.md` (FA11) for the A1 supply invariant under stake-and-slash transitions; `Censorship.md` (FA2) for the K-conjunction censorship bound that survives even a successful cartel; `SECURITY.md` §S-010 and §S-011 for the audit-side closure records and the operator calculator.

---

## 1. Theorem statements

**Setup.** Determ admits validators to the consensus pool via one of two `InclusionModel` values (`include/determ/chain/genesis.hpp:36-39`):

- `STAKE_INCLUSION` (default, `min_stake = 1000` default): a domain enters the eligible pool only when `stakes_[domain].locked ≥ min_stake` (gate at `src/node/registry.cpp:57-63`). Misbehavior was disincentivized by stake forfeit (the Phase-1 abort deduction + full-stake forfeit on equivocation); **both were retired on 2026-09-16 (D13 and D4)** and the only surviving on-chain response to misbehaviour is the S-032 suspension WINDOW, which moves no stake. See §6.7.
- `DOMAIN_INCLUSION` (`min_stake = 0`): the stake gate is skipped; admission is by registering with a domain name (e.g., a DNS-anchored identity, with the genesis-level multisig acting as the trust root over the initial `initial_creators` list). Misbehavior is disincentivized by registry deregistration (equivocator's `inactive_from` is set to the next block per `chain.cpp:1351-1355`; re-entry requires a fresh registration under whatever off-chain Sybil-resistance the operator chose).

Under `STAKE_INCLUSION`, committee selection is uniform-random over the eligible pool: `select_m_creators(random_state, N_pool, K)` in `src/crypto/random.cpp:70-100` returns a uniformly-distributed K-subset of `[0, N_pool)` under the random-oracle assumption on the seed (proven in `Liveness.md` L4 and `Censorship.md` T-2.1). The selection rule is **not** stake-weighted — each eligible domain has identical per-round selection probability `K / N_pool`.

Let `min_stake ∈ ℤ≥0` denote the genesis-pinned (governance-mutable per A5) eligibility threshold. Let `N_pool` denote the steady-state count of registered, active, non-suspended, sufficiently-staked domains — i.e., the cardinality of the eligible pool that `NodeRegistry::build_from_chain` constructs at any height `h`. Let `K` denote the committee size (`k_block_sigs` in `GenesisConfig`). Let `M` denote the per-round Phase-1 quorum size for abort claims (`M-1` matching signatures advance the claim, per the S-011 audit-side description).

For an adversary `Adv`, let `N_attacker ⊂ N_pool` denote the validator subset under `Adv`'s control (i.e., domains whose Ed25519 secret keys `Adv` holds and whose `min_stake` was furnished by `Adv`).

**Theorem T-1 (Stake-floor Sybil resistance, S-010 closure).** Under `STAKE_INCLUSION` with uniform-random committee selection (Preliminaries §6, `Liveness.md` L4, `Censorship.md` T-2.1), for `Adv` to obtain `Pr[majority of K-committee under Adv's control] > 1/2` averaged over committee rotations requires `|N_attacker| ≥ ⌈(N_pool / 2) + 1⌉`. The upfront capital lockup `Adv` must commit is exactly:

$$
\mathrm{sybil\_cost}(N_{pool}, \mathrm{min\_stake}) := \left\lceil \frac{N_{pool}}{2} + 1 \right\rceil \cdot \mathrm{min\_stake}
$$

The value is denominated in chain tokens; under an exogenous market price `p_{token}` (in USD-per-token), the dollar-cost-of-attack is `sybil_cost × p_token`. No additional operational cost (compute, bandwidth, custody overhead) materially raises this floor.

**Theorem T-2 (Per-operator stake cost) — CORRECTED 2026-09-17: it is RECOVERABLE.** Each validator pays `min_stake` to lock into `stakes_[v].locked` via the `STAKE` tx (`Chain::apply_transactions`, the STAKE arm). The lock-up source is the validator's account balance, which itself derives from either (a) `GenesisAllocation.balance` at genesis or (b) subsidy + fee credits earned by being on prior committees. **There is now exactly ONE exit: UNSTAKE plus `unstake_delay`.** The second exit this theorem was named for — "(ii) equivocation slash, full forfeit" — was removed on 2026-09-16 (D4), and the third — the Phase-1 abort deduction — was retired the same day (D13). No apply path reduces `stakes_[v].locked` below its staked value.

The theorem's title claim ("unrecoverable on attack") is therefore **FALSE at HEAD** and is withdrawn: an attacker that has finished attacking unstakes and walks away whole after `unstake_delay`. What survives is the *timing* half — capital is illiquid for `unstake_delay` blocks — which is a real but much weaker cost and is what T-1 and T-3 should be read as pricing. The consequence for the S-010 formula is in §6.1 and §6.7.

**Theorem T-3 (Sybil-cost-vs-token-value relation).** The Sybil-cost is denominated in tokens. For a chain with exogenous market value, the attack-economics reduce to capital lockup:

$$
\mathrm{dollar\_cost\_of\_attack} = \mathrm{sybil\_cost} \cdot p_{token} = \left\lceil \frac{N_{pool}}{2} + 1 \right\rceil \cdot \mathrm{min\_stake} \cdot p_{token}
$$

`Adv`'s expected gain is bounded above by the chain's value-at-risk `VaR` (total recoverable value across all accounts, plus the subsidy stream `Adv` could siphon during a successful capture, plus any off-chain leverage like loan-collateralized positions). The operator-chosen `safety_margin` (per §3 of `SECURITY.md` §S-010, typically `10×`) is the ratio:

$$
\mathrm{safety\_margin} := \frac{\mathrm{dollar\_cost\_of\_attack}}{\mathrm{VaR}}
$$

A `safety_margin ≥ 1` makes the attack non-profitable in expectation; `≥ 10` is the operator default to absorb modeling slack (estimation error on `VaR`, attacker risk-tolerance, opportunity-cost of the locked capital).

> **RE-DERIVED 2026-09-17 (sequence step 3c; owner decisions D4 + D13, DECISION-LOG 2026-09-16).**
> **T-4 as originally stated is FALSE and is replaced by T-4-R below.** Its three outcomes rested on
> two L1 costs that no longer exist: the equivocation forfeiture (removed 2026-09-16, D4 — apply reads
> nothing from `b.equivocation_events`) and the Phase-1 abort stake deduction (retired 2026-09-16,
> D13 — an abort records the S-032 suspension and moves no stake). **T-1, T-2, T-3, T-5 and T-6 are
> re-checked and stand** except for the one clause of T-2 identified below; T-1's Sybil floor is a
> *capital* bound and consumes no penalty term.
> The honest residual replacing T-4 is §6.7. The drafted residual this re-derivation supersedes was
> itself wrong in three named places (DECISION-LOG 2026-08-13); each is addressed in §6.7.

**Theorem T-4-R (What an M−1 cartel costs and earns, post-D4/post-D13 — S-011 restated).** Let `Adv`
control `M−1` committee members at height `h` under `STAKE_INCLUSION`. Over one round, the protocol
imposes on `Adv`:

| Channel | Pre-2026-09-16 | At HEAD |
|---|---|---|
| Fabricated abort claim against the honest member | claimants pay nothing; the ACCUSED loses `min(SUSPENSION_SLASH, locked)` | claimants pay nothing; the accused loses nothing (D13). An `AbortClaim` is a gossip message, not a transaction — **no fee, no nonce, no on-chain cost at all** |
| Equivocation by a cartel member | entire locked stake forfeited + deregistered | **nothing** (D4). The event is recorded and applied as a no-op (`EquivocationSlashingApply.md` T-E0) |
| Capital | `(M−1) · min_stake` locked, **destroyed** on either of the above | `(M−1) · min_stake` locked, **recoverable** — UNSTAKE + `unstake_delay` is the only exit and no path zeroes `locked` any more |

so the cartel's **marginal per-round cost is the opportunity cost of held capital plus bandwidth**:

```
cost_per_round  =  (M−1) · min_stake · r      (r = per-block risk-free rate; no principal is at risk)
```

Against it, the cartel's **per-round revenue** is the creator payout it collects for being the
committee. `Chain::apply_transactions` splits `total_distributed = total_fees + subsidy_this_block`
evenly across `b.creators`, so:

```
revenue_per_round  =  (|cartel ∩ committee| / K) · (block_subsidy + fees)
```

(`Chain::apply_transactions` computes `per_creator = total_distributed / m` over `b.creators`, so the
share is by seat count, not by stake. The extreme case is `N_pool == K`: with the lone honest member
suspended the committee is the cartel and the share is 1. For a larger pool the share is the cartel's
expected seat fraction, which is what T-1 prices — but it is positive in every case.)

**Corollary (the claim that fails).** `SECURITY.md` §S-011 concluded "the per-round attack cost
exceeds the chain's per-round subsidy throughput — economic infeasibility". At HEAD,
`cost_per_round → 0` while `revenue_per_round > 0` for any chain with a non-zero subsidy or fee
flow. **The inequality is reversed: the sustained cartel is not merely affordable, it is paid.**
The "economic infeasibility" claim of the S-011 closure does not hold — in any configuration with
a positive block subsidy, not only in the weak ones. What remains is T-1's one-time capital barrier
to *acquiring* `M−1` seats, which is a barrier to entry and not a per-round cost, and is fully
recoverable on exit.

---

**HISTORICAL — T-4 as it stood before 2026-09-16.** Retained because §4.4 proves it and because the
three-outcome decomposition is still the right frame; only the costs attached to the outcomes were
real. Do not cite.

**Theorem T-4 (Cartel defense via slashing, S-011 closure) — HISTORICAL, FALSE AT HEAD.** Even if `Adv` obtains `M-1` committee members via Sybil (the S-011 attack form), one of three outcomes follows:

- **(O1) `Adv` does not equivocate.** The cartel can suspend the lone honest member via fabricated abort claims, but only for a finite suspension window (exponential backoff per `BASE_SUSPENSION_BLOCKS × 2^k` at `registry.cpp:47-50`). The honest member rejoins after the window completes. Per-round cost: opportunity cost of locked stake and the abort-claim broadcast bandwidth; no slashing fires. Damage: bounded to "honest member off-committee for `O(2^k × BASE_SUSPENSION_BLOCKS)` blocks, where `k` is the count of consecutive abort hits."
- **(O2) `Adv` equivocates.** Signing two distinct `compute_block_digest` (or two distinct `make_contrib_commitment`) under the same registered Ed25519 key, at the same height, satisfies V11 (Preliminaries §5 and `EquivocationSlashing.md` T-6). The next block carrying the resulting `EquivocationEvent` triggers `apply_transactions`'s equivocation branch: every cartel member's `stakes_[v].locked` is zeroed (full forfeit, FA-Apply-10 T-E1) and `registrants_[v].inactive_from = h + 1` (deregistered, T-E2). Total realized loss: `(M-1) × min_stake`. The cartel cannot recover this stake.
- **(O3) `Adv` continues the cartel attack across many rounds without equivocating.** Per-round attack cost: opportunity cost of `(M-1) × min_stake` locked stake. Per-round chain-side defense: the K-conjunction censorship bound (`Censorship.md` T-2.1) still holds — Phase-1 union tx-root means a single honest validator outside the cartel forces inclusion of any tx the cartel tries to censor. Sustained M-1 control over many committee rotations requires majority capture of `N_pool` (rotation is uniform-random per Preliminaries §6), which is the S-010 Sybil-cost regime. Net cost ≥ T-1 floor + the opportunity cost compounding over the attack duration.

Outcome (O2) is the natural "next step" for a cartel that has paid the S-010 floor and seeks to extract value (equivocation is the lever that gives `Adv` chain control, e.g., to fork the chain or double-spend). Outcomes (O1) and (O3) are the "cartel-without-equivocation" cases; both reduce to "honest committee member is annoyed for a bounded time at a per-round cost exceeding the chain's subsidy throughput at any operator-recommended `min_stake`."

**Theorem T-5 (DOMAIN_INCLUSION alternative).** For deployments where stake-pricing economics are weak (e.g., the token has no exogenous market price, or the operator chooses a permissioned topology), `InclusionModel::DOMAIN_INCLUSION` (`genesis.hpp:38`) pins `min_stake = 0` and routes Sybil resistance through an off-chain registration cost. The two structural facts:

1. **Stake-gate skip:** at `registry.cpp:53-57`, when `threshold = chain.min_stake() = 0`, the `chain.stake(domain) < threshold` filter is unreachable (no value satisfies `< 0` under `uint64_t`). Every registered+active+non-suspended domain is eligible. Sybil resistance comes from whatever Sybil-resistance the off-chain registration mechanism provides (DNS TLD economics, multisig-attested operator list, KYC-gated registrar, etc.).
2. **Slashing redirection:** the equivocation forfeit path at `chain.cpp:1344-1356` still fires, but `stakes_[v].locked` is structurally `0` for DOMAIN_INCLUSION validators (no stake was ever locked), so the stake-forfeit half is a no-op. The deregistration half (`inactive_from = h + 1`) still triggers; the equivocator must register a fresh domain (incurring the off-chain registration cost again) to participate.

Under DOMAIN_INCLUSION, the Sybil-cost is denominated in the off-chain registration unit (USD, DNS-registrar fees, multisig-attestation overhead) rather than chain tokens. The T-1 formula does not apply directly; T-4 reduces to "cartel attack costs `(M-1) × registration_cost` per attempt, with deregistration of every equivocator."

**Theorem T-6 (Worked-example bounds).** For four representative deployment scenarios at `N_pool = 50` (majority = 26 sybils), `K = 5`:

| Scenario | `min_stake` | `sybil_cost` (tokens) | `p_token` | Dollar-cost-of-attack | Safety verdict |
|---|---|---|---|---|---|
| Testnet | 1,000 | 26,000 | n/a | n/a (no exogenous price) | Trivial — testnet purposes only |
| Community chain | 10,000 | 260,000 | n/a | n/a | Sufficient for low-value chains |
| Small token-traded | 100,000 | 2,600,000 | $0.10 | $260,000 | Adequate for low-value-at-risk |
| Token-traded chain | 1,000,000 | 26,000,000 | $1.00 | $26,000,000 | Production-grade |
| Enterprise (DOMAIN_INCLUSION) | 0 | n/a (off-chain) | n/a | Off-chain registration cost | Permissioned topology |

At `N_pool = 1000` (large token-traded deployment), `sybil_cost = 501,000 × min_stake`. For `min_stake = 1,000,000` and `p_token = $1`, the dollar-cost-of-attack exceeds $500M — well above any realistic `VaR` for a chain in this size class. The economic floor is "infeasible for any single adversary without nation-state resources."

Conversely, at `N_pool = 10` (testnet) with `min_stake = 1000` and no exogenous token price, `sybil_cost = 6 × 1000 = 6000` tokens — trivially attainable. This is the explicit "testnet only" calibration noted in `SECURITY.md` §S-010 "Comparison to existing default."

---

## 2. Background

### 2.1 S-010 narrative

The pre-closure S-010 audit observation was that `min_stake = 1000` (the `GenesisConfig::min_stake` default at `genesis.hpp:155`) is calibrated for testnets and demos. If a chain operator deploys to production without raising `min_stake`, an attacker could partition wealth across thousands of registered domains and dominate `N_pool` committee selection. The closure shipped as (Option 1) operator-facing guidance encoding the Sybil-cost formula in `SECURITY.md` §S-010 + (Option 3) `DOMAIN_INCLUSION` as a flag-flip alternative for chains without stake-pricing economics. No code change was required for Option 1; Option 3 was already shipped as part of rev.8.

The Sybil-cost formula derives from two structural protocol facts that the S-010 closure makes explicit:

1. Committee selection is uniform-random over the eligible pool (Preliminaries §6; `select_m_creators` at `random.cpp:70`). Each eligible domain has identical per-round selection probability `K / N_pool` regardless of stake amount; locking `100 × min_stake` does not buy `100 ×` selection rate.
2. Therefore controlling a majority of `N_pool` is equivalent to controlling a majority of committee positions averaged over rotations. The cheapest way to control a majority of `N_pool` is to be `⌈(N_pool/2)+1⌉` distinct registered domains, each meeting the `min_stake` threshold and no more.

### 2.2 S-011 narrative

The pre-closure S-011 audit observation was that abort claims advance via `M-1` matching signatures (the M-of-M Phase-1 quorum minus one — the silent member, by audit's framing). An adversary controlling `M-1` committee members could fabricate abort claims against the lone honest member, suspending them via the exponential-suspension path at `registry.cpp:47-50`. The closure shipped (Option 1) as a bounded-damage analysis composing three protocol-side bounds — Sybil-cost lower bound from S-010, equivocation slashing from FA6 + FA-Apply-10, and per-round subsidy comparison — all of which were already implemented. No code change was required.

The composition argument:

- The S-010 stake-pricing formula prices `Adv`'s upfront cost to control `M-1` committee positions at `(M-1) × min_stake`.
- **HISTORICAL (removed 2026-09-16, D4 — apply reads nothing from `b.equivocation_events`):** the equivocation-slashing branch and the V11 validator predicate at `validator.cpp` ensured that if `Adv` followed through with conflicting signatures, the full stake is forfeit per FA-Apply-10 T-E1.
- The censorship bound `Censorship.md` T-2.1 ensures the cartel cannot suppress transactions even with `M-1` control — the K-conjunction guarantee requires `K` consecutive all-attacker committees, which is the same Sybil-cost regime.

### 2.3 STAKE_INCLUSION vs DOMAIN_INCLUSION

The `InclusionModel` enum at `genesis.hpp:36-39` is single-byte, single-field, immutable post-genesis. The two modes share the entire consensus pipeline (K-of-K Phase-1, BFT escalation, equivocation detection); they differ only in `NodeRegistry::build_from_chain`'s eligibility filter:

```cpp
// src/node/registry.cpp:53-63
uint64_t threshold = chain.min_stake();    // 1000 STAKE / 0 DOMAIN

for (auto& [domain, r] : chain.registrants()) {
    if (r.active_from > at_index)            continue;
    if (at_index >= r.inactive_from)         continue;
    if (threshold > 0 && chain.stake(domain) < threshold) continue;   // S-010 floor
    if (is_suspended(domain))                continue;
    // ... add to NodeRegistry
}
```

When `threshold = 0`, the third filter is unreachable. Sybil resistance comes from the off-chain registration model — the genesis-builder's choice of `initial_creators` and any post-genesis REGISTER policy (`REGISTER` txs are sender-signed; an operator can run a custom validator that only admits REGISTERs co-signed by an external attestation, though this is currently a deployment-policy mechanism rather than a protocol-enforced gate).

### 2.4 Fisher-Yates committee selection

The K-committee at each round is computed by `select_m_creators(random_state, N_pool, K)` at `random.cpp:70-100`. The function uses a hybrid: rejection sampling when `2K ≤ N_pool` (preserves rev.9 output for `K/N ≤ 0.5`), partial Fisher-Yates shuffle when `2K > N_pool` (O(N) cost flat across the entire range up to `K = N`). Both branches consume the same SHA-256-derived randomness and produce a uniformly-distributed K-subset under the random-oracle model on the seed (`Liveness.md` L4; `Censorship.md` T-2.1 and §6).

The salient property for S-010 is **uniformity**: the per-domain selection probability is identical across all eligible domains, regardless of stake amount. This is by design: pure stake-weighted selection has a "rich-get-richer" failure mode the audit-side discussion in `SECURITY.md` §S-010 "Deferred Option 2" elaborates. The chosen design pushes Sybil-resistance into the registry-eligibility predicate (stake floor) rather than the selection step.

---

## 3. Implementation citations

### 3.1 The eligibility gate

```cpp
// src/node/registry.cpp:53-63 (excerpt)
uint64_t threshold = chain.min_stake();

NodeRegistry reg;
for (auto& [domain, r] : chain.registrants()) {
    if (r.active_from > at_index)            continue;
    if (at_index >= r.inactive_from)         continue;
    if (threshold > 0 && chain.stake(domain) < threshold) continue;
    if (is_suspended(domain))                continue;
    // ... append e to reg.nodes_ in sorted-by-domain order
}
```

Five structural properties:

1. `chain.min_stake()` returns the chain's current `min_stake_` value (genesis-pinned default; A5 governance-mutable via `PARAM_CHANGE` of the `MIN_STAKE` parameter, with N-of-N keyholder authorization).
2. The stake-gate filter is skipped when `threshold == 0` (DOMAIN_INCLUSION). For STAKE_INCLUSION with `threshold > 0`, a domain whose `stakes_[domain].locked < threshold` is filtered out before reaching the `reg.nodes_` insertion.
3. The `active_from > at_index` filter excludes domains in the post-REGISTER delay window (`derive_delay` at `chain.cpp:801` — a small commit-reveal-randomized delay before a new registrant is eligible, preventing flash-Sybil attacks where `Adv` registers thousands of domains in a single block to bypass per-block rate limits).
4. The `at_index >= r.inactive_from` filter excludes deregistered domains (DEREGISTER tx at `chain.cpp:844-846` sets `inactive_from = height + derive_delay(...)`).
5. `is_suspended(domain)` filters domains under exponential-backoff suspension from prior aborts (`registry.cpp:43-51`).

### 3.2 The stake locking and forfeit paths — HISTORICAL from the forfeit half onward

> **2026-09-17.** The STAKE / UNSTAKE listings below are current. **The forfeit listings are not**: the
> equivocation branch was deleted (D4) and the Phase-1 abort deduction retired (D13) on 2026-09-16, so
> `stakes_[v].locked` has exactly one exit — UNSTAKE after `unstake_delay`. The code blocks are retained
> to show what was removed.

```cpp
// src/chain/chain.cpp:858-871 (STAKE apply branch)
case TxType::STAKE: {
    if (tx.payload.size() != 8) continue;
    uint64_t amount = 0;
    for (int i = 0; i < 8; ++i)
        amount |= uint64_t(tx.payload[i]) << (8 * i);
    uint64_t cost = amount + tx.fee;
    if (sender.balance < cost) continue;
    sender.balance -= cost;
    __ensure_stakes();
    stakes_[tx.from].locked += amount;
    total_fees += tx.fee;
    sender.next_nonce++;
    break;
}

// src/chain/chain.cpp:1344-1356 (equivocation forfeit branch)
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

The STAKE branch debits the sender's balance and credits `stakes_[tx.from].locked`. The forfeit branch zeroes the entire locked amount (`block_slashed += sit->second.locked; sit->second.locked = 0`) — there is no partial-slash, no slash-amount field on `EquivocationEvent`. This was the full-stake-forfeiture property FA-Apply-10 T-E1 formalizes; the S-011 cartel-defense composition leans on it.

### 3.3 Committee selection (uniform-random under ROM)

```cpp
// src/crypto/random.cpp:70-100 (excerpt)
std::vector<size_t> select_m_creators(const Hash& random_state, size_t node_count, size_t m) {
    if (node_count < m)
        throw std::runtime_error("Not enough registered nodes for M creators");
    if (m * 2 <= node_count) {
        // Rejection sampling
        std::vector<size_t> result;
        Hash h = random_state;
        uint64_t counter = 0;
        while (result.size() < m) {
            h = SHA256Builder{}.append(h).append(counter++).finalize();
            size_t idx = hash_mod(h, node_count);
            if (std::find(result.begin(), result.end(), idx) == result.end())
                result.push_back(idx);
        }
        return result;
    }
    // Partial Fisher-Yates shuffle
    std::vector<size_t> indices(node_count);
    for (size_t i = 0; i < node_count; ++i) indices[i] = i;
    Hash h = random_state;
    uint64_t counter = 0;
    for (size_t i = 0; i < m; ++i) {
        h = SHA256Builder{}.append(h).append(counter++).finalize();
        size_t j = i + hash_mod(h, node_count - i);
        std::swap(indices[i], indices[j]);
    }
    indices.resize(m);
    return indices;
}
```

Uniformity over `K`-subsets of `[0, N_pool)` holds under the random-oracle assumption on `random_state` (which derives from `cumulative_rand`, itself a function of every committee member's reveal — see `Liveness.md` L4 and `Censorship.md` §6). Per-domain selection probability is `K / N_pool`; no domain has higher weight than another.

---

## 4. Proofs

### 4.1 Proof of T-1 (stake-floor Sybil resistance)

Let `N_attacker = |Adv's controlled domains|`. By uniformity of `select_m_creators`'s output (§3.3 above, under ROM on the seed), each eligible domain has per-round selection probability `K / N_pool`. The expected count of `Adv`-controlled committee members per round is `K × (N_attacker / N_pool)`.

For `Adv` to obtain `Pr[majority of K under Adv's control] > 1/2` averaged over rotations, we need

$$
\mathbb{E}[\text{Adv-count per round}] = K \cdot \frac{N_{attacker}}{N_{pool}} > \frac{K}{2}
$$

which simplifies to `N_attacker > N_pool / 2`, equivalently `N_attacker ≥ ⌈(N_pool / 2) + 1⌉` for integer `N_attacker`. (The "averaged over rotations" framing is the relevant attack model: `Adv` is patient and attacks across many committee rotations; the per-round committee composition is uniformly random, so the expected majority condition is the asymptotic capture condition.)

Each of `Adv`'s `N_attacker` domains must:

- Pass the registry-eligibility filter at `registry.cpp:53-63`, which (under STAKE_INCLUSION) requires `stakes_[domain].locked ≥ min_stake`.
- Have been admitted at some prior height via REGISTER, with stake locked via STAKE.

The minimum capital lockup per controlled domain is `min_stake`. (Locking more does not buy more selection probability per §3.3.) So `Adv`'s minimum total lockup is `N_attacker × min_stake = ⌈(N_pool/2) + 1⌉ × min_stake`. ∎

### 4.2 Proof of T-2 (per-operator stake cost unrecoverable on attack) — HISTORICAL; see the corrected T-2 in §1

Each `Adv`-controlled domain `v` has `stakes_[v].locked ≥ min_stake` (T-1). The locked stake exits via one of three paths — **at HEAD, only path (i) exists**; (ii) was removed by D4 and (iii) retired by D13, both on 2026-09-16:

- **Path (i): UNSTAKE.** Apply branch at `chain.cpp:873-894`. The branch refuses to decrement `locked` if `height < sit->second.unlock_height` (the `unstake_delay` window, default 1000 blocks per `GenesisConfig::unstake_delay`). Successful UNSTAKE returns the locked amount to the sender's account balance.
- **Path (ii): Equivocation forfeit — REMOVED 2026-09-16 (D4).** Was: `block_slashed += sit->second.locked; sit->second.locked = 0;` — full forfeit, no refund. Apply now reads nothing from `b.equivocation_events`.
- **Path (iii): Suspension slash — RETIRED 2026-09-16 (D13).** Was: a claimed-and-quorum'd Phase-1 abort triggered a `SUSPENSION_SLASH`-sized debit on the ACCUSED (default 10 tokens — enough to push a floor-staked validator under `min_stake` at its first abort, which is why it was retired; ledger S-087). The abort now records the S-032 suspension window and moves no stake.

Under attack-and-equivocate, path (ii) fires. The forfeit is full: `min_stake` for each domain that signed the equivocation. Under attack-without-equivocate (S-011 outcomes (O1)/(O3)), path (i) is the recovery route, but it cannot complete instantaneously — the `unstake_delay` window plus the validator-enforced refusal in `chain.cpp:881` impose a multi-block lag, during which any equivocation detected against `Adv` triggers path (ii) on what was still-locked stake. Thus `Adv`'s `N_attacker × min_stake` is unrecoverable whenever `Adv` follows through on the natural next step of using cartel control (equivocate to fork the chain or double-spend). ∎

### 4.3 Proof of T-3 (Sybil-cost-vs-token-value relation)

The Sybil-cost is denominated in chain tokens (T-1). Under an exogenous market price `p_token` (USD-per-token), the dollar-cost-of-attack is `sybil_cost × p_token = ⌈(N_pool/2)+1⌉ × min_stake × p_token`. The proof is arithmetic — units of (tokens) × (USD/tokens) = USD.

`Adv`'s expected gain is bounded above by `VaR`, the chain's total value-at-risk (sum of all account balances, plus subsidy stream over the attack duration, plus any off-chain leverage). For the attack to be unprofitable in expectation:

$$
\mathbb{E}[\text{Adv gain}] \leq \mathrm{VaR} < \mathrm{dollar\_cost\_of\_attack} = \mathrm{sybil\_cost} \cdot p_{token}
$$

The operator-chosen `safety_margin` is the ratio of the two; `safety_margin = 1` is the break-even point; `safety_margin = 10` is the operator default (per `SECURITY.md` §S-010, which justifies it as absorbing modeling slack: `VaR` is estimated, `Adv` may be risk-tolerant, opportunity-cost of locked capital varies). ∎

### 4.4 Proof of T-4 (cartel defense via slashing) — HISTORICAL

> The proof below is sound against the PRE-2026-09-16 apply path and is retained as the record. Every
> cost it computes is zero at HEAD; see T-4-R in §1 and the residual in §6.7.

Fix `Adv` controlling exactly `M-1` committee members at some height `h` (the S-011 worst case). The cartel's options:

**Outcome (O1):** `Adv` does not equivocate. The cartel fabricates an abort claim against the honest member `v_h`. Per `AbortEventApply.md` FA-Apply, the abort claim advances on `M-1` matching signatures and triggers a suspension slash + exponential-backoff `is_suspended` window for `v_h`. The window length is bounded by `MAX_SUSPENSION_BLOCKS` (a constant cap at `registry.cpp:48-50`); `v_h` rejoins the eligible pool after the window.

During the window, the cartel still does not control more than `M-1` of the K-committee at every round — committee rotation is uniform-random over the **remaining** eligible pool (which has dropped from `N_pool` to `N_pool - 1` while `v_h` is suspended). The expected per-round cartel count is now `K × (M-1) / (N_pool - 1)` < `K/2` for any reasonable `N_pool` and `M-1 < N_pool/2`. Sustained M-1 control requires re-suspending the next honest member every time the window expires, at a per-attempt cost of broadcasting fabricated abort claims (bandwidth + protocol-level abort-claim fees) and the risk that an honest peer detects fabricated content. Damage: bounded; no slashing of cartel members fires.

**Outcome (O2):** `Adv` equivocates. By hypothesis, at least one cartel member produces two distinct signatures over conflicting committed-block digests (or two conflicting `make_contrib_commitment` hashes per S-006) at height `h`. Per `EquivocationSlashing.md` T-6, the resulting `EquivocationEvent` is structurally well-formed (two valid signatures, two distinct digests, both verifying under the equivocator's registered key). Per V11 (Preliminaries §5), the validator accepts it. Per FA-Apply-10 T-E1, the apply branch at `chain.cpp:1344-1356` zeroes the equivocator's `stakes_[v].locked`. Total cartel loss for one round of equivocation: `min_stake` per equivocator (typically all `M-1` cartel members, since they coordinate signatures and trigger their joint slashing simultaneously).

The cartel cannot continue the attack — every member is deregistered (`inactive_from = h + 1`, FA-Apply-10 T-E2) and their stake is `0`. To resume the attack, `Adv` must register `M-1` fresh domains and lock `M-1 × min_stake` of fresh capital. The cost compounds.

**Outcome (O3):** `Adv` continues without equivocating. The cartel runs O1 across many rounds. Per `Censorship.md` T-2.1, the K-conjunction censorship probability is `(f/N)^K`; with `f = M-1` and `N = N_pool`, the bound is `((M-1)/N_pool)^K`, which goes to zero as `K` grows. So even sustained cartel control cannot censor transactions — the union-tx-root rule (`Censorship.md` L-2.1 + Phase-1 union, `Censorship.md` §2-§3) ensures honest committee members from the non-cartel pool fragment force inclusion. Sustained M-1 control over many rotations is equivalent to capturing a majority of `N_pool` — the S-010 floor `⌈(N_pool/2)+1⌉ × min_stake` re-applies.

Composing the three outcomes: any S-011-style attack reduces to either O1 (bounded damage, suspended-honest-member windows but no chain fork or value extraction) or O2 (full stake forfeiture, `M-1 × min_stake` cost per attempt) or O3 (Sybil-cost floor applies). For operator-chosen `min_stake` per the T-3 safety-margin formula, all three outcomes are economically infeasible. ∎

### 4.5 Proof of T-5 (DOMAIN_INCLUSION alternative)

Under DOMAIN_INCLUSION, `chain.min_stake() = 0` and the stake-gate filter at `registry.cpp:57` is unreachable. Sybil resistance does not derive from on-chain capital lockup — it derives from off-chain registration costs, which the protocol does not introspect.

The equivocation forfeit branch at `chain.cpp:1344-1356` still fires per V11 and FA-Apply-10. The stake-half is a no-op (locked stake is `0`); the deregistration-half (`inactive_from = b.index + 1`) takes effect. The equivocator must re-register a fresh domain to participate — incurring the off-chain registration cost again, plus the protocol-level REGISTER fee.

The T-1 formula does not apply. The operator's deployment-policy chooses the registration mechanism (DNS-anchored identity, multisig-attested operator list, KYC-gated registrar, etc.) and the Sybil-cost lives at that layer. ∎

### 4.6 Proof of T-6 (worked-example bounds)

Direct arithmetic from T-1 with `N_pool = 50, K = 5`:

| Scenario | `min_stake` | `sybil_cost = 26 × min_stake` | `p_token` | Dollar-cost-of-attack |
|---|---|---|---|---|
| Testnet | 1,000 | 26,000 | n/a | n/a |
| Community chain | 10,000 | 260,000 | n/a | n/a |
| Small token-traded | 100,000 | 2,600,000 | $0.10 | $260,000 |
| Token-traded chain | 1,000,000 | 26,000,000 | $1.00 | $26,000,000 |
| Enterprise (DOMAIN_INCLUSION) | 0 | n/a | n/a | off-chain |

Scaling to `N_pool = 1000` (large deployment): `sybil_cost = 501 × min_stake`. For `min_stake = 1,000,000` and `p_token = $1`, dollar-cost is `$501M` — exceeding `VaR` for almost any chain in this size class. For `N_pool = 10` and `min_stake = 1000`, dollar-cost is `6,000` tokens — trivially attainable, hence the "testnet only" explicit warning in `SECURITY.md` §S-010 "Comparison to existing default."

The four worked-example tiers (`SECURITY.md` §S-010 "Worked examples") map operator deployment scale to `min_stake_floor` via the inverse formula:

$$
\mathrm{min\_stake\_floor} = \frac{\mathrm{VaR} \cdot \mathrm{safety\_margin}}{\lceil (N_{pool}/2) + 1 \rceil}
$$

derived by setting `dollar_cost_of_attack ≥ VaR × safety_margin` and solving for `min_stake`. ∎

---

## 5. Adversary model

The closure covers four canonical adversary profiles:

**Well-funded attacker.** Owns substantial off-chain capital, willing to lock `⌈(N_pool/2)+1⌉ × min_stake × p_token` USD to take majority control. Defeated by T-1 + T-3 when operator-chosen `min_stake` yields a dollar-cost-of-attack above the chain's `VaR × safety_margin`. The classic example is a well-funded cryptocurrency exchange or whale; the model assumes they pursue rational profit-maximizing strategies, not deterrence-resistant ideological attacks.

**Coordinated cartel.** Multiple distinct entities cooperating to acquire `M-1` committee positions and run S-011 abort-claim attacks. **NOT defeated** — the historical T-4 answer (O1 bounded suspension damage, O2 full stake forfeiture on equivocation follow-through, O3 Sybil-cost floor for sustained control) lost both of its cost terms on 2026-09-16; see T-4-R (§1) and the residual (§6.7). What still holds against this adversary is the S-010 entry barrier plus the censorship and MD-safety bounds, neither of which is economic. Each member's stake is independently slashable; the cartel cannot externalize its capital lockup. Coordination cost (off-chain communication, trust between cartel members not to defect by reporting equivocations) further raises the effective attack barrier.

**Sybil farm.** Single attacker creating thousands of pseudonymously-distinct registered domains. Distinguished from the well-funded attacker only by the lack of overt coordination — the protocol cannot distinguish "one attacker with thousand domains" from "thousand independent operators." T-1 makes them equivalent: the attacker pays `N_attacker × min_stake` to register each domain. The S-010 closure is therefore robust against this profile: Sybil-resistance comes from the per-domain capital lockup, not from any identity-verification step.

**Insider-mint attacker.** Holder of a `GenesisAllocation.balance` that funds substantial post-genesis stake. The genesis allocation list is operator-set (`GenesisConfig::initial_balances`) and is **not** S-010 territory — the operator's genesis policy is the trust root. If `Adv` is a genesis insider, the relevant defense is the operator's choice of `initial_balances` distribution, not the `min_stake` formula. Documented here only to make the model boundary explicit: the S-010 closure presupposes a healthy genesis allocation; pathological genesis (one wallet holds `> 99%` of all tokens) is out of scope.

**Out-of-band coercion attacker.** Compels existing validators to surrender their signing keys via legal process, social engineering, or physical coercion. Out of scope for S-010 / S-011 closure; orthogonal to economic Sybil-resistance. Documented in `SECURITY.md` §6 as an operational risk requiring deployment-policy defenses (HSMs, multi-sig key custody, geographic key distribution).

---

## 6. Identified gaps and economic boundary conditions

### 6.1 Under-priced `min_stake` at genesis

If the operator sets `min_stake = 1000` (the default) for a production-grade token-traded chain, the dollar-cost-of-attack is far below `VaR × safety_margin` and the chain is exposed. This is **operator misconfiguration**, not a protocol flaw. The closure makes this explicit:

- `SECURITY.md` §S-010 "Comparison to existing default" warns: "the genesis default `min_stake = 1000` with `block_subsidy = 10` is suitable ONLY for testnets and demonstrations."
- A future tooling improvement (genesis-builder warning) is sketched in `SECURITY.md` §S-010 "Validation at genesis" — surface a startup warning if `min_stake × ⌈N_pool/2 + 1⌉ < block_subsidy × 100`. This is operator-facing tooling, not a protocol gate (the right floor depends on exogenous economics the protocol cannot observe).

The boundary condition: operators of token-traded production chains MUST set `min_stake` per the T-3 inverse formula. No protocol mechanism currently enforces this.

### 6.2 Token price crash mid-attack

If `Adv` locks `N_attacker × min_stake` tokens when `p_token = $1` (dollar-cost-of-attack = `$1 × N_attacker × min_stake`), and then mid-attack the token price crashes to `$0.10`, the dollar-cost-of-attack falls 10×. `Adv`'s realized cost (in fiat) is lower than the planning-time estimate; the safety margin shrinks.

Two structural facts mitigate this:

- The locked stake remains denominated in tokens, not USD. `Adv` cannot "extract value at a higher exchange rate during the attack" because the tokens-as-stake are not liquid for `Adv` during the attack (they're locked under `unstake_delay` + risk of equivocation slashing). If the price recovers post-attack, `Adv`'s realized fiat cost mirrors the planning-time estimate.
- `Adv`'s expected gain is also token-denominated (chain-VaR is in tokens, even if accounting in USD is convenient). A token-price crash deflates `VaR` by the same factor as the dollar-cost-of-attack. The ratio (safety_margin) is preserved.

Net: token price volatility does not create asymmetric risk for the chain. It introduces noise into operator planning (planning-time `VaR` estimates may be miscalibrated), which the `safety_margin = 10×` default is intended to absorb.

### 6.3 `N_pool` shrinkage during attack

If `Adv` registers `⌈(N_pool/2)+1⌉` domains, the act of registration changes `N_pool` itself. Specifically, post-registration `N_pool' = N_pool + N_attacker`, and the majority condition becomes:

$$
N_{attacker} > \frac{N_{pool} + N_{attacker}}{2} \implies N_{attacker} > N_{pool}
$$

This means an attacker entering a chain with steady-state `N_pool = 50` honest registrants needs to register `> 50` Sybils, not `26`. The S-010 formula in `SECURITY.md` is written for the post-Sybil steady state (the `N_pool` an attack consultant would compute *after* the attacker's domains have joined); the operator-planning quantity is the pre-attack honest pool size.

The boundary condition: operator's `safety_margin` choice should reflect this — if planning for `VaR × safety_margin = sybil_cost` against a pre-attack `N_pool^honest = 50`, the actual Sybil-cost is `(N_pool^honest + 1) × min_stake` (the smallest integer majority of `2 × N_pool^honest + 1`), not `26 × min_stake`. The 10× safety_margin default absorbs this factor of ~2 distortion.

### 6.4 Subsidy reflux

A successful cartel earns subsidy + fees on every block they produce (the standard creator-payout path at `chain.cpp` block-apply). If `Adv` holds majority of the committee, they earn ~50% of the per-block subsidy. Over a long attack, this subsidy reflux could in principle offset the locked-stake opportunity cost.

The boundary condition: `min_stake_floor = (VaR × safety_margin) / ⌈N_pool/2 + 1⌉` should include the cumulative subsidy stream over the attack duration in `VaR`, not just the spot account balances. The `SECURITY.md` §S-010 "Target threshold" table includes "Total subsidy budget = `block_subsidy × expected_chain_lifetime_blocks`" as a `VaR` choice for chains without a token market — this is the explicit accounting for subsidy reflux.

### 6.5 Equivocation false negatives (FA6 dependency)

**MOOT since D4 (2026-09-17 note): O2 has no closure to depend on — see §6.7.** Historically, T-4's O2 closure depended on FA6 T-6 — the no-false-accusation property — which itself depends on Ed25519 EUF-CMA (cryptographic, holds under standard assumptions) AND H2 (honest validator at most one signature per (height, round) and per (height, aborts_gen)). The contribution of S-006 (`S006ContribMsgEquivocation.md` T-1) is the Phase-1 detection layer; the rev.8 BlockSigMsg detection is the Phase-2 layer. Both must fire for the cartel's full attack surface to be covered.

The boundary condition: if a future protocol change introduces a third signing surface (e.g., a new gossip-control message type signed under the validator key), the equivocation detection coverage must be extended to that surface, or the T-4 O2 argument develops a gap. Currently the two layers (BlockSigMsg + ContribMsg) cover the surfaces V11 needs.

### 6.6 DOMAIN_INCLUSION trust-root fragility

T-5's DOMAIN_INCLUSION argument is only as strong as the off-chain Sybil-resistance the operator's registration mechanism provides. If the off-chain mechanism is gameable (e.g., the operator's "multisig of trusted registrars" is itself a 1-of-1 single key, or the DNS TLD is operated by a registrar that admits Sybils without identity verification), the T-5 cost-floor disappears.

The boundary condition: `DOMAIN_INCLUSION` chains MUST publish their off-chain Sybil-resistance assumptions in their deployment documentation. The protocol does not introspect these.

### 6.7 The honest S-011 residual (written 2026-09-17, sequence step 3c)

This section replaces the historical T-4 closure and is the citable statement of where S-011 stands.
It is written against the shipped mechanism after D4 (no equivocation consequence) and D13 (no abort
deduction), and it addresses, one by one, the three errors the DECISION-LOG (2026-08-13) recorded in
the previously drafted residual.

**(0) The bound that fails.** Per T-4-R (§1): the cartel's marginal per-round protocol cost is the
opportunity cost of recoverable locked capital (`(M−1)·min_stake·r`) plus bandwidth; abort claims are
unfee'd gossip messages, equivocation costs nothing, and no path reduces `locked`. Its per-round
revenue is its share of `block_subsidy + fees`, up to the whole of it once the honest member is
suspended. At the genesis defaults (`min_stake = 1000`, `block_subsidy = 10`) the twenty-six-sybil
figure of §S-010 pays for itself in 2,600 blocks of subsidy *even if the capital were destroyed*; it
is not destroyed. **"Per-round cost > chain subsidy" is false at every parameterization with a
positive subsidy.** S-011's recorded mitigation therefore rests on the S-010 stake floor alone — a
one-time, refundable barrier to entry.

**(1) Error one: "at K == M structurally unreachable" — FALSE. BFT escalation seats a zero-honest
committee at `|pool| == K`.** The mechanism, from the shipped code: `Node::check_if_selected` builds
`avail_domains` as the registry-eligible pool MINUS every domain named in the node's in-flight
`current_aborts_`. That local exclusion is applied *after* the S-051 Option-B eligibility floor
(`include/determ/chain/eligibility_floor.hpp`, consumed by `NodeRegistry::build_from_chain`), so the
floor cannot lift it — the floor only re-admits domains suspended by CHAIN-BAKED abort records.
Then the escalation gate fires when `avail_domains.size() < k_target && bft_enabled &&
total_aborts >= bft_escalation_threshold && avail_domains.size() >= bft_committee_size(K)`. With
`N_pool == K == 3`, `bft_escalation_threshold` defaulting to **1** (`include/determ/node/node.hpp`,
`Config::bft_escalation_threshold{1}`, S-045) and `bft_committee_size(3) == 2`: **one** fabricated
abort against the single honest member leaves `avail = 2`, which is `< 3` and `>= 2`, so the round
escalates to a BFT committee of two drawn from the two cartel members. `f_h = 2` against
`|K_h| = 2`, i.e. `f_h ≥ |K_h|/3` — `BFTSafety.md` assumption B1 is violated wholesale, and since
T-5.1 was withdrawn (`BFTSafety.md` §4, T-5.1-R) there is no recovery. The escalation root is ledger
row **S-086** (OPEN) and the pool bound is owner decision **D5a / R-4** (cap at REGISTER +
assertion at selection, genesis check `2K > |initial creators|`) with its joint design gate
**AUTHORIZED but NOT LANDED**. Until D5a lands, a chain whose eligible pool equals K has no
structural defence here.

**(2) Error two: "abort-driven stake drain below `min_stake` is permanent and S-051 does not lift
it" — TRUE WHEN RECORDED, and GONE SINCE D13.** That leg was real: `min(SUSPENSION_SLASH, locked)`
per Phase-1 abort against a floor-staked validator dropped it to 990 at the FIRST abort, the
eligibility floor excludes on `stake_of < min_stake`, and S-051's Option-B lift re-admits *suspended*
domains, never floor-breached ones — so one abort ejected a validator permanently (ledger S-087,
High). **D13 retired the deduction on 2026-09-16 and S-087 is closed**; the leg no longer exists and
must not be restated. Its replacement, which is weaker but not nothing, is the **suspension window**:
the S-032 record arms an exclusion of
`min(BASE_SUSPENSION_BLOCKS · 2^min(count−1, MAX_ABORT_EXPONENT), MAX_SUSPENSION_BLOCKS)` blocks
(10, doubling, capped at 10,000). Since the cartel pays nothing per claim, it renews that window
every time it lapses, and the exponent makes each renewal longer — after ~10 hits the honest member
is excluded in 10,000-block stretches at zero marginal cost. So the historical T-4 (O1) sentence
"the cartel cannot permanently remove them without continuing to expend stake" is false in its
premise: continuing costs no stake. The honest member's *stake* is now safe; its *seat* is not.
The one real brake is the Option-B floor: when the fully-eligible pool would fall below `k`, the
floor lifts suspensions in ascending `(count, last_block, domain)` order, so a chronically aborted
honest member IS re-admitted once the cartel has thinned the pool below K — which is exactly the
configuration that error (1) turns into a zero-honest BFT committee instead. The two failure modes
are complementary, not redundant.

**(3) Error three: "leg 1 holds unchanged" ignores DOMAIN_INCLUSION, where BOTH legs are zero.**
Under `InclusionModel::DOMAIN_INCLUSION` the genesis pins `min_stake = 0`, so `domain_eligible`'s
stake predicate is skipped entirely and T-1's `sybil_cost = ⌈(N_pool/2)+1⌉ × min_stake` is **0**.
Pre-D4 the deregistration half of the equivocation consequence still bit in that mode — it was, as
`EquivocationSlashingApply.md` §3 put it, "the *entire* penalty" there — and D4 removed it. So under
DOMAIN_INCLUSION **both** legs of the historical S-011 closure are now identically zero: no capital
barrier and no consequence. Everything rests on the operator's off-chain registration cost (§6.6),
which the protocol does not introspect and cannot bound. A `DOMAIN_INCLUSION` deployment must treat
S-011 as **not mitigated by this document at all**.

**(4) What actually still bounds an S-011 cartel.** Three things, all mechanism, none economic:

- **Censorship resistance is unaffected.** `Censorship.md` T-2.1's K-conjunction bound and the
  Phase-1 union tx-root are signature/counting arguments; a single honest committee member forces
  inclusion. Nothing in D4/D13 touches them. A cartel that holds M−1 seats cannot censor.
- **MD-mode safety is unaffected.** `Safety.md` T-1 clause 1 needs one honest member in `K_h` and
  consumes no economic term. The cartel cannot fork an MD-mode height. (It CAN, per (1), arrange for
  there to be no honest member in `K_h` at all — that is a liveness/escalation defect, not a failure
  of T-1.)
- **The suspension window is bounded per hit** by `MAX_SUSPENSION_BLOCKS`, and the Option-B floor
  re-admits when the pool would starve. Damage per round is bounded; damage *summed over rounds* is
  not, because renewal is free.

**(5) What is owed, and by whom.** Nothing here is closable by this document.

| Owed | Owner | Status |
|---|---|---|
| A per-round cost for a cartel — i.e. the economic layer the closure assumed | **D22**, the L2 bond / arbitration policy | v1.1 DApp scope, NOT DESIGNED. This is the only candidate replacement for the removed L1 penalty, and it is explicitly not a launch blocker for L1. |
| The `2K > N(h)` pool bound over the ELIGIBLE pool, which removes the `|pool| == K` regime of (1) | **D5a / R-4**, joint design gate with F-c and R-15 | AUTHORIZED, NOT LANDED |
| The escalation trigger reading a stale/instantaneous abort count | ledger **S-086** | OPEN |
| A Sybil bound for `DOMAIN_INCLUSION` | operator deployment policy (§6.6) | Outside the protocol by construction |

**(6) Ledger consequence.** S-011 stays **✅ Mitigated** — but on a strictly narrower mitigation than
recorded: *the S-010 stake floor prices ACQUIRING `M−1` seats under `STAKE_INCLUSION`, and the
censorship/safety bounds cap what those seats are worth.* The "economic infeasibility via
per-round cost > subsidy" half is struck. Under `DOMAIN_INCLUSION` the row's mitigation does not
apply at all. The ⚠ marker is retired in favour of this explicit statement, because "under
re-derivation" is no longer true — the derivation is here, and its answer is partly negative.

---

## 7. Test-suite citation

The S-010 + S-011 closure is operator-policy + existing-code; the relevant regression coverage:

- **`tools/test_anon_address.sh`** — exercises the stake-mechanic on the producer side: REGISTER, STAKE, UNSTAKE, balance accounting through the stake-locked transitions. Indirectly validates that the stake-floor at `registry.cpp:57-63` correctly admits/excludes domains based on `chain.stake(domain) >= min_stake`. Locks the apply-path consistency of stake bookkeeping that T-1 depends on.

- **`tools/test_equivocation_slashing.sh`** — exercises the end-to-end evidence path. **Inverted since D4:** it now confirms the accused node's stake is exactly its pre-submission value and its registry entry is untouched. It locks the detection → gossip → bake → apply composition with the S-006 / FA6 layers; there is no forfeit branch left for T-4 O2 to rely on.

- **`tools/test_equivocation_multi.sh`** — multi-validator equivocation scenarios; since D4 it confirms that multiple cartel members jointly producing conflicting signatures lose NOTHING, which is the empirical form of the T-4-R cost table.

- **`tools/test_equivocation_apply.sh`** — focused FA-Apply-10 **T-E0**: state neutrality against an event-free twin, A1 preservation, and a positive control that the event is in the applied block; mutants M1–M8 RED.

The four tests together cover the apply-path foundations of both T-2 (per-operator cost unrecoverable on attack) and T-4 (cartel-defense composition). No new regression test is required for the S-010 / S-011 closure; the existing tests + the operator-policy guidance in `SECURITY.md` §S-010 + §S-011 are the full closure.

A speculative future test — a "Sybil-cost worked-example calculator" tool — would surface the dollar-cost-of-attack at startup based on the running chain's `N_pool, min_stake, block_subsidy, expected_chain_lifetime_blocks`. This is operator tooling, not a protocol-level test, and is deferred per `SECURITY.md` §S-010 "Validation at genesis."

---

## 8. Status

Both S-010 and S-011 are closed in `SECURITY.md`:

- **S-010** — ✅ Mitigated (Options 1 + 3) per `SECURITY.md` §S-010, §3 status row. Severity reclassified from High (parameter-tuning risk) to Mitigated. Closure mechanism: operator stake-pricing formula + `DOMAIN_INCLUSION` availability.
- **S-011** — ✅ Mitigated, on the NARROWED closure re-derived 2026-09-17 (§6.7): the S-010 stake floor prices acquiring `M−1` seats under `STAKE_INCLUSION`, and `Censorship.md` T-2.1 plus `Safety.md` T-1 clause 1 cap what those seats are worth. The "FA6 + FA-Apply-10 equivocation slashing" term is struck (D4) and the per-round-cost-exceeds-subsidy claim with it. Under `DOMAIN_INCLUSION` the mitigation does not apply.

Both findings appear in `SECURITY.md` §1's "Mitigated in-session — High" row.

This proof formalizes the closure argument that the audit-side narrative carries. The closure does not require code change; the protocol mechanisms (registry-eligibility predicate, uniform-random committee selection — and, until 2026-09-16, equivocation forfeit) were already in place. The contribution is the explicit Sybil-cost function and the composition argument that prices the S-011 cartel attack at "per-attempt cost ≥ `(M-1) × min_stake`, full forfeiture on follow-through."

Production-readiness implications:

- For permissioned / consortium deployments: T-5 DOMAIN_INCLUSION path applies; closure is via operator-chosen off-chain trust root.
- For token-traded permissionless deployments: T-1 + T-3 + T-4 apply; closure is via operator-chosen `min_stake` per the T-3 inverse formula at `safety_margin = 10×` against the chain's projected `VaR`.
- For testnets / demonstrations: the genesis default `min_stake = 1000` is acceptable; the closure is "the chain has no production value-at-risk; the Sybil-cost is irrelevant."

---

## 9. References

### Audit-side documents

- `docs/SECURITY.md` §S-010 — Sybil via under-priced MIN_STAKE — closure narrative + Sybil-cost calculator + worked examples
- `docs/SECURITY.md` §S-011 — Abort claim cartel via M-1 quorum — closure narrative + three-property composition argument
- `docs/SECURITY.md` §1 — status row classification (Mitigated in-session — High)

### Companion proofs

- `docs/proofs/Preliminaries.md` — F0 notation (`V`, `N`, `K`, `N_pool`, committee selection at §6, H2 honest validator behavior at §4)
- `docs/proofs/EquivocationSlashing.md` — FA6 T-6 (soundness of equivocation slashing: honest validators never falsely slashed under EUF-CMA + H2)
- `docs/proofs/EquivocationSlashingApply.md` — FA-Apply-10 T-E1 through T-E7 (apply-side full-forfeiture mechanics, idempotence, A1 preservation under slash)
- `docs/proofs/S006ContribMsgEquivocation.md` — Phase-1 ContribMsg equivocation detection layer; composition with FA6 for full equivocation-detection coverage
- `docs/proofs/Censorship.md` — FA2 T-2.1 (K-conjunction censorship probability bound `(f/N)^K` — relied on by T-4 O3 for sustained-cartel censorship analysis)
- `docs/proofs/EconomicSoundness.md` — FA11 A1 closed-form supply invariant under stake-and-slash transitions (background; supports T-2 unrecoverable-cost claim via the A1 stake-bookkeeping argument)
- `docs/proofs/Liveness.md` — L4 uniform-random committee selection under ROM (background; supports T-1 uniformity claim)

### Implementation citations

- `include/determ/chain/genesis.hpp:36-39` — `InclusionModel { STAKE_INCLUSION, DOMAIN_INCLUSION }` enum
- `include/determ/chain/genesis.hpp:151` — `GenesisConfig::inclusion_model` field
- `include/determ/chain/genesis.hpp:155` — `GenesisConfig::min_stake` field (default `1000`)
- `include/determ/chain/genesis.hpp:145` — `GenesisConfig::bft_escalation_threshold` field
- `include/determ/chain/genesis.hpp:250` — `GenesisConfig::initial_creators` field
- `src/node/registry.cpp:53-63` — eligibility filter (the stake-floor gate)
- `src/chain/chain.cpp:858-871` — STAKE apply branch (stake lock-up)
- `src/chain/chain.cpp:873-894` — UNSTAKE apply branch (with `unlock_height` enforcement)
- `src/chain/chain.cpp:1344-1356` — equivocation forfeit branch (full stake forfeit + registry deactivation)
- `src/crypto/random.cpp:70-100` — `select_m_creators` (hybrid rejection-sampling / partial Fisher-Yates committee selection)

### Regression tests

- `tools/test_anon_address.sh` — stake mechanic (REGISTER + STAKE + UNSTAKE)
- `tools/test_equivocation_slashing.sh` — slashing composition (FA-Apply-10 end-to-end)
- `tools/test_equivocation_multi.sh` — multi-validator cartel-equivocation case
- `tools/test_equivocation_apply.sh` — FA-Apply-10 mechanics (idempotence, A1 preservation)
