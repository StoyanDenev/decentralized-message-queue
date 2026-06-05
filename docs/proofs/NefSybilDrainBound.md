# NefSybilDrainBound — economic self-limitation of the E1 NEF bootstrap-drain under a mass-registration adversary (NS-1..NS-6)

This document is the **adversarial-economics** companion to `NefPoolDrain.md` (FA-Apply-14). Where FA-Apply-14 proves the apply-layer *mechanics* of the E1 Negative-Entry-Fee channel — exact halving, first-time-only idempotency, A1 supply-neutrality, geometric exhaustion — it states the attack bound only as an aside (its T-N3 remark "the economic cost of attacking the pool is upper-bounded by `n × REGISTER_FEE`"). That remark is **asserted, not proven**, and it is also *not the sharp bound*: it ignores that the NEF reward *itself* decays geometrically while the per-registration cost does not. This proof closes that gap. It formalizes the mass-registration ("Sybil-drain") adversary against the Zeroth pool and proves that the geometric halving makes the channel **economically self-limiting**: the marginal NEF reward to the `(k+1)`-th first-time REGISTER is `P_0 / 2^{k+1}`, which falls below any fixed per-registration cost after a logarithmic number of registrations, so a rational adversary extracts a bounded, front-loaded prize and then stops. The total value any coalition can ever extract is bounded by `P_0 − 1` regardless of registration count, and the *profitable* prefix is bounded by `O(log P_0)` registrations.

The proof is **economic and arithmetic**, not mechanical: it introduces no code path. It rests entirely on the FA-Apply-14 mechanics (the halving recurrence, the first-time-only gate) plus the Determ fee model (the per-REGISTER fee is charged from the registrant's own balance and redistributed to the block's creators — `chain.cpp:788` + the distribution loop at `chain.cpp:1286–1305`). Its contribution is a closed-form attacker net-profit function and four bounds (NS-2..NS-5) that an operator sizing `zeroth_pool_initial` needs in order to answer a single question: *can someone farm the bootstrap pool for profit, and if so, how much, and for how long?*

**Distinction from neighbours.** This is **not** `NefPoolDrain.md` (FA-Apply-14) — that is the apply-correctness proof (T-N1..T-N7) and contains no attacker net-profit analysis. It is **not** `S010S011SybilEconomics.md` (S-010/S-011) — that prices a Sybil *majority of the K-committee* under `STAKE_INCLUSION` (`⌈(N_pool/2)+1⌉ × min_stake`) and the abort-claim cartel; it concerns *consensus capture*, an entirely different state surface from the *bootstrap reward pool*. It is **not** `EconomicSoundness.md` (FA11) T-13 — that proves NEF is supply-*neutral* (no mint), a conservation statement, whereas this proof is about *who captures the redistributed value and at what cost*. The NEF channel can be supply-neutral (FA11 T-13) yet still be either a fair bootstrap incentive or a farmable subsidy; which one it is depends on the economics this document settles.

**Companion documents.** `Preliminaries.md` (F0) §2.0 for the canonical assumption labels — this proof reduces to **assumption A1** (Ed25519 EUF-CMA, §2.2) only, and only to pin that the Zeroth address is unspendable except through the REGISTER hook (no actor can forge a `from == ZEROTH_ADDRESS` signature, so the pool cannot be drained by a direct TRANSFER); note the **"A1 unitary-supply invariant"** named in the FA-Apply series is the unrelated *accounting* identity (§2.0 disclaimer), which this proof invokes only via FA11 T-13 to fix that NEF moves value rather than minting it; `NefPoolDrain.md` (FA-Apply-14) for the halving recurrence (T-N1), first-time-only idempotency (T-N3), A1-neutrality (T-N5), and geometric exhaustion (T-N6) that NS-1 takes as given; `EconomicSoundness.md` (FA11) for T-13 (E1 supply-neutrality); `FeeAccounting.md` (FA-Apply-6) for the per-REGISTER fee debit (T-F1) and the creator-redistribution algorithm (T-F4) that NS-3's cost accounting rests on; `S010S011SybilEconomics.md` (S-010/S-011) for the *consensus-capture* Sybil model this proof is explicitly orthogonal to (§5 boundary); `docs/SECURITY.md` §S-010 for the operator stake-pricing context.

---

## 1. Setup

### 1.1 The pool, the halving, and the fee model (from source)

Per `include/determ/chain/genesis.hpp:137`, the Zeroth pool is seeded once at genesis from `GenesisConfig.zeroth_pool_initial` into `accounts_[ZEROTH_ADDRESS].balance`; write its genesis value `P_0 ≥ 0`. Per `src/chain/chain.cpp:823–833` (the FA-Apply-14 mechanism), on the FIRST successful REGISTER of a domain `D`, if the pool balance `P > 0` and `D ≠ ZEROTH_ADDRESS`, the channel transfers

```
nef = P / 2          (unsigned integer division; chain.cpp:827)
P  := P − nef        (chain.cpp:829)
balance[D] += nef    (chain.cpp:830)
```

guarded by `if (nef > 0)` so a pool of `P = 1` is a no-op. Re-REGISTERs of an already-registered domain skip the entire branch (first-time gate at `chain.cpp:795–796`; FA-Apply-14 T-N3).

The **fee model is the load-bearing economic fact**. The per-REGISTER fee `f := tx.fee` is (a) charged from the *registrant's own account balance* (`charge_fee` at `chain.cpp:788`, debiting `accounts_[D].balance`), and (b) accumulated into the block's `total_fees` and redistributed to *that block's creators* `b.creators[]` via the flat-split-with-dust loop at `chain.cpp:1286–1305` (FA-Apply-6 T-F4). There is **no minimum-fee floor** on REGISTER (an audit of `src/node/validator.cpp` REGISTER branch at `:494–533` shows shape/region/pubkey checks but no `fee >=` gate; the only fee constraint anywhere is the COMPOSABLE_BATCH inner-`fee == 0` rule at `validator.cpp:1015`, irrelevant here). The fee is therefore **not burned** — it is a transfer to the committee that finalized the registration.

### 1.2 Notation

Let the adversary `Adv` control a coalition of pseudonymously-distinct fresh domains `D_1, D_2, …` (a "Sybil farm" in the sense of `S010S011SybilEconomics.md` §5 — the protocol cannot distinguish one attacker with many domains from many independent operators). `Adv` registers them in some order; index the **first-time** REGISTERs that pass all gates (and find `P > 0`) by `k = 0, 1, 2, …`, where the `k`-th such REGISTER observes pool balance `P_k`. Let:

- `P_k` = pool balance immediately before the `(k+1)`-th admitted first-time REGISTER, with `P_0` the genesis value;
- `r_k` = the NEF reward paid to that registrant `= P_k / 2` (integer division);
- `f` = the per-REGISTER fee `Adv` pays (under `Adv`'s control; `f ≥ 0`);
- `c` = `Adv`'s exogenous per-registration cost floor — the irreducible non-fee cost of bringing one fresh domain on-chain (wallet keypair generation + the on-chain footprint + whatever Sybil-resistance the operator's inclusion policy imposes). `c ≥ 0` is an environment parameter, not a protocol constant.

`Adv` is **rational and profit-maximizing**: it registers a fresh domain iff doing so is expected-value-positive given the *then-current* pool. It is *not* an ideological/griefing adversary (those are covered by §5).

---

## 2. The reward recurrence (NS-1)

**Lemma NS-1 (geometric reward decay).** The NEF reward to the `(k+1)`-th admitted first-time registrant is

$$
r_k \;=\; \left\lfloor \frac{P_k}{2} \right\rfloor, \qquad P_{k+1} \;=\; P_k - r_k \;=\; \left\lceil \frac{P_k}{2} \right\rceil .
$$

Consequently `P_k = \lceil P_0 / 2^k \rceil` for all `k ≥ 0`, and the reward satisfies the two-sided bound

$$
\frac{P_0}{2^{k+1}} - 1 \;\le\; r_k \;\le\; \frac{P_0}{2^{k+1}} .
$$

*Proof.* The recurrence `P_{k+1} = P_k − ⌊P_k/2⌋ = ⌈P_k/2⌉` is exactly FA-Apply-14 T-N1 (the integer-halving step), read forward over the sequence of admitted first-time REGISTERs (FA-Apply-14 T-N6 establishes the same sequence drains the pool, but states the closed form only as the `⌈log₂ P_0⌉` exhaustion count; NS-1 sharpens it to the per-step reward). By induction, `P_k = ⌈P_0 / 2^k⌉`: the base `k = 0` is immediate, and `P_{k+1} = ⌈P_k / 2⌉ = ⌈⌈P_0/2^k⌉ / 2⌉ = ⌈P_0/2^{k+1}⌉` by the standard nested-ceiling identity `⌈⌈x/a⌉/b⌉ = ⌈x/(ab)⌉` for positive integers `a, b`. Then `r_k = ⌊P_k/2⌋ = ⌊⌈P_0/2^k⌉/2⌋`. Since `⌈P_0/2^k⌉ ∈ {P_0/2^k, P_0/2^k + (fractional correction < 1)}`, we have `P_0/2^{k+1} − 1 ≤ ⌊P_k/2⌋ ≤ P_0/2^{k+1}`, which is the stated two-sided bound. ∎

**Remark.** The decay is exact-geometric in `P_0`: each successive registrant collects half of what the previous one could, minus integer-rounding slack bounded by `1`. This is the entire economic content of the channel — it is the discrete analogue of a halving emission schedule, but front-loaded into the *first* `⌈log₂ P_0⌉` registrations rather than spread over block height.

---

## 3. The adversary net-profit function (NS-2)

**Definition (coalition net profit).** Suppose `Adv` performs `n` admitted first-time REGISTERs. Its gross extraction is `Σ_{k=0}^{n-1} r_k`. Its cost is `n · (f + c)` minus the fraction of its own fees it recaptures by being on the finalizing committee. Let `α ∈ [0, 1]` be the *fee-recapture fraction* — the expected share of each fee `f` that returns to `Adv` because an `Adv`-controlled domain sat on `b.creators[]` for the block that included the REGISTER (`α = 0` for an adversary with no committee presence; `α → 1` only for an adversary that already controls the committee, which is the *consensus-capture* regime of `S010S011SybilEconomics.md`, not the bootstrap-farm regime here). The net profit is

$$
\Pi(n) \;=\; \underbrace{\sum_{k=0}^{n-1} r_k}_{\text{NEF extracted}} \;-\; \underbrace{n\,(1-\alpha)\,f}_{\text{net fee paid}} \;-\; \underbrace{n\,c}_{\text{exogenous cost}} .
$$

**Theorem NS-2 (closed-form profit bound).** For every `n ≥ 1`,

$$
\Pi(n) \;\le\; \Big(P_0 - \big\lceil P_0/2^{n}\big\rceil\Big) \;-\; n\,(1-\alpha)\,f \;-\; n\,c \;\le\; P_0 \;-\; n\big((1-\alpha)f + c\big).
$$

*Proof.* The gross extraction telescopes: `Σ_{k=0}^{n-1} r_k = Σ_{k=0}^{n-1}(P_k − P_{k+1}) = P_0 − P_n = P_0 − ⌈P_0/2^n⌉` by NS-1. Substituting into `Π(n)` gives the first inequality with equality; dropping the non-negative term `⌈P_0/2^n⌉ ≥ 0` gives the second. ∎

**Corollary NS-2.1 (lifetime extraction cap).** Independent of `n`, `α`, `f`, `c`,

$$
\sum_{k\ge 0} r_k \;=\; P_0 - \lim_{n\to\infty}\big\lceil P_0/2^{n}\big\rceil \;=\; P_0 - 1 \quad (\text{for } P_0 \ge 1),
$$

so no coalition — of any size, registering any number of domains — extracts more than `P_0 − 1` total from the NEF channel. This recovers FA-Apply-14 T-N6's exhaustion bound as the `n → ∞` limit of NS-2's gross term, and pins it as a *hard ceiling on attacker revenue*, not merely a description of honest drain. ∎

---

## 4. Self-limitation: the profitable prefix is logarithmic (NS-3)

The decisive economic property is that **marginal** profit goes negative after a small number of registrations, so a rational `Adv` stops voluntarily.

**Theorem NS-3 (marginal stopping rule).** Let `g := (1−α)f + c` be `Adv`'s effective marginal cost per registration (`g ≥ 0`; and `g > 0` whenever `c > 0` *or* `f > 0` and `α < 1` — i.e. whenever registration is not entirely free to the adversary). The marginal net profit of the `(k+1)`-th registration is

$$
\Delta\Pi_k \;=\; r_k - g \;=\; \left\lfloor \frac{P_k}{2}\right\rfloor - g .
$$

For `g > 0`, `Δ\Pi_k < 0` for all `k ≥ k^\*` where

$$
k^\* \;=\; \left\lceil \log_2\!\frac{P_0}{g} \right\rceil ,
$$

i.e. the rational adversary stops after at most `k^\*` registrations, and `k^\* = O(\log P_0)`.

*Proof.* By NS-1, `r_k ≤ P_0 / 2^{k+1}`. Thus `r_k < g` whenever `P_0 / 2^{k+1} < g`, i.e. `2^{k+1} > P_0 / g`, i.e. `k + 1 > log₂(P_0/g)`, i.e. `k ≥ ⌈log₂(P_0/g)⌉ = k^\*`. Since `r_k` is non-increasing in `k` (NS-1: `P_k` is non-increasing, so `⌊P_k/2⌋` is non-increasing), once `Δ\Pi_k < 0` it stays `< 0`; a rational `Adv` registers only while `Δ\Pi_k ≥ 0`, hence performs at most `k^\*` registrations. ∎

**Corollary NS-3.1 (profitable-extraction cap).** A rational `Adv` extracts gross NEF at most

$$
\sum_{k=0}^{k^\*-1} r_k \;=\; P_0 - \big\lceil P_0 / 2^{k^\*}\big\rceil \;\le\; P_0 - \big\lceil g \big\rceil
$$

and incurs cost `≥ k^\* g`, so its **realizable** net profit is at most `P_0 − ⌈g⌉ − 0 = P_0 − ⌈g⌉` (taking the loosest cost lower bound), and more tightly, `Π` is maximized at `n = k^\*` with `Π(k^\*) ≤ P_0 − k^\* g`. The bootstrap pool is **not a perpetual subsidy faucet**: its farmable value is front-loaded into `O(log P_0)` registrations and capped by `P_0`. ∎

**Remark (the sharpening over FA-Apply-14 T-N3).** FA-Apply-14 T-N3's aside bounds attack cost by `n × REGISTER_FEE` but leaves `n` unbounded and ignores reward decay and fee-recapture. NS-3 supplies the missing two facts: (i) the reward the attacker is paying that cost to obtain *halves each step* while the cost does not, so (ii) `n` is not a free parameter — a profit-maximizing attacker self-caps at `k^\* = O(log P_0)`. The two results compose: T-N3 says "each domain costs a fee"; NS-3 says "after `O(log P_0)` domains the fee buys nothing worth having."

---

## 5. The free-registration boundary and the operator lever (NS-4)

NS-3 assumed `g > 0`. The boundary case `g = 0` (registration is *entirely* free to the adversary: `c = 0` AND either `f = 0` or full fee-recapture `α = 1`) is where the bound degrades, and it is the case an operator must rule out by policy.

**Theorem NS-4 (degenerate free-registration regime).** If `g = 0`, then `Δ\Pi_k = r_k ≥ 0` for every `k` with `P_k ≥ 2`, so a rational `Adv` registers until the pool reaches its stable point `P = 1` (FA-Apply-14 T-N4), extracting the full `P_0 − 1`. The number of registrations is still bounded — `⌈log₂ P_0⌉` by NS-1 / FA-Apply-14 T-N6 — but **all** of `P_0 − 1` is captured by the adversary rather than distributed across honest early adopters.

*Proof.* With `g = 0`, `Δ\Pi_k = r_k`, which is `≥ 1` while `P_k ≥ 2` and `0` once `P_k = 1` (`nef > 0` guard, FA-Apply-14 T-N4). The adversary's marginal profit is non-negative throughout, so it continues to the stable point; gross extraction is `P_0 − 1` by NS-2.1. ∎

**Corollary NS-4.1 (operator levers).** NS-4 isolates the two parameters that bound the *distributional* harm (NEF captured by an adversary vs. by honest early adopters) without affecting supply soundness (FA11 T-13 holds regardless):

1. **`zeroth_pool_initial = P_0`** is the *hard cap on total farmable value* (NS-2.1). Setting `P_0` proportional to the intended honest early-adopter cohort — rather than to a large round number — directly bounds the worst-case farm at `P_0 − 1`. An operator who wants the bootstrap incentive to fund (say) the first ~50 honest validators sizes `P_0` so that `P_0 / 2^{50} < 1`, i.e. the geometric series is exhausted by the intended cohort; any Sybil farm then competes with honest registrants for the *same fixed prize*, it does not enlarge it.
2. **A non-zero effective `g`** — via the inclusion policy. Under `STAKE_INCLUSION` (default `min_stake = 1000`, `genesis.hpp:155`), each domain `Adv` wants to keep eligible must also lock `min_stake`; even though staking is a separate tx from REGISTER (NEF fires on REGISTER alone), an adversary pursuing *committee* presence to raise `α` pays the `S010S011SybilEconomics.md` floor, and a pure NEF-farm adversary with `α = 0` pays at least the exogenous `c`. Under `DOMAIN_INCLUSION` (`min_stake = 0`) the operator's off-chain registry curation is the `c`-floor. Either way the operator, not the protocol, sets `g`; NS-3 then bounds the profitable prefix at `O(log(P_0/g))`. ∎

**Note (no protocol change implied).** NS-4 is a *parameterization* result, not a vulnerability: the NEF channel is supply-neutral (FA11 T-13) and exhaustion-bounded (FA-Apply-14 T-N6) in every regime. The worst case `g = 0` merely lets an adversary front-run honest adopters for a *bounded, genesis-pinned* prize; it never inflates supply, never exceeds `P_0 − 1`, and never persists beyond `⌈log₂ P_0⌉` registrations. The operator lever (`P_0` sizing + inclusion policy) is the documented mitigation, mirroring how `S010S011SybilEconomics.md` makes `min_stake` the operator lever for consensus-capture.

---

## 6. The pool is unspendable except through REGISTER (NS-5)

The bounds above assume the *only* way value leaves the Zeroth pool is the NEF REGISTER hook. This is what makes `P_0 − 1` the true ceiling — an attacker cannot bypass the geometric halving via a direct transfer.

**Theorem NS-5 (no direct-drain path).** Under **assumption A1** (Ed25519 EUF-CMA, `Preliminaries.md` §2.2), no adversary can move value out of `accounts_[ZEROTH_ADDRESS]` other than through the first-time-REGISTER NEF branch.

*Proof.* `ZEROTH_ADDRESS` is the canonical all-zero anon address (`params.hpp:31`), encoding an all-zero Ed25519 public key — a low-order curve point with no corresponding secret key. Every value-moving tx with `from == D` requires a valid Ed25519 signature over the tx's `signing_bytes` under `D`'s key (validity predicate V1, `Preliminaries.md`; verified in `validator.cpp` before apply). Forging a signature for `from == ZEROTH_ADDRESS` is exactly an EUF-CMA forgery against the all-zero key, which contradicts assumption A1 except with negligible probability. As defense-in-depth the validator additionally rejects any tx with `from == ZEROTH_ADDRESS` outright (FA-Apply-14 §1.1), and the NEF branch's own fourth guard `tx.from != ZEROTH_ADDRESS` (`chain.cpp:825`) prevents self-credit. Therefore the pool is debited only by the `chain.cpp:829` NEF leg, whose magnitude is the NS-1 halving — no path circumvents it. ∎

**Corollary NS-5.1.** The lifetime-extraction cap NS-2.1 (`P_0 − 1`) and the logarithmic profitable-prefix NS-3 are *tight* against all PPT adversaries, not merely against the modeled mass-registration strategy: any strategy that extracts pool value must do so via REGISTER (NS-5) and is therefore subject to NS-1's per-step halving. ∎

---

## 7. Composition and scope (NS-6)

**Theorem NS-6 (composition with the supply and consensus layers).** The NEF Sybil-drain bounds compose cleanly with — and do not weaken — the chain's supply-soundness and consensus-Sybil guarantees:

1. **Supply (FA11 T-13 / `EconomicSoundness.md`).** Every NEF transfer, adversarial or honest, is balance-conserving (`−nef` from pool, `+nef` to registrant, no counter touched; FA-Apply-14 T-N5). The A1 *accounting* identity `live_total_supply = expected_total` is preserved across any adversarial registration sequence. NS-1..NS-5 concern *who holds* the redistributed value, never *how much exists*.
2. **Consensus-Sybil (S-010/S-011).** NEF farming yields `≤ P_0 − 1` in *liquid balance*, not committee eligibility. To convert that balance into consensus influence the adversary must additionally lock `min_stake` per committee seat and survive selection — paying the `S010S011SybilEconomics.md` T-1 floor `⌈(N_pool/2)+1⌉ × min_stake`. The NEF prize is a *partial subsidy toward* that floor, bounded by `P_0 − 1`; an operator sizing `P_0 < ⌈(N_pool/2)+1⌉ × min_stake` ensures the bootstrap pool cannot by itself fund a consensus-capture attack.
3. **Fee redistribution (FA-Apply-6 T-F4).** The fees `Adv` pays are not destroyed; they fund the honest committee that finalized the registrations (when `α < 1`). The adversary's `(1−α)f` net fee outflow is honest validators' income — the farm is partially *self-taxing* in favour of the network it attacks.

*Proof.* (1) is FA-Apply-14 T-N5 applied per registration and summed; (2) is the observation that NEF credits `accounts_[D].balance`, which the `STAKE_INCLUSION` eligibility gate (`registry.cpp:57–63`) does not read — only `stakes_[D].locked` gates eligibility — composed with `S010S011SybilEconomics.md` T-1; (3) is FA-Apply-6 T-F4 (fees route to `b.creators[]`). ∎

### 7.1 Adversary model summary

| Profile | Captured by | Bound |
|---|---|---|
| **Rational NEF farmer** (`g > 0`, `α = 0`) | NS-3 | profitable prefix `≤ ⌈log₂(P_0/g)⌉` registrations; net profit `≤ P_0 − k^\* g` |
| **Free-registration farmer** (`g = 0`) | NS-4 | captures full `P_0 − 1`; bounded by `P_0` sizing (NS-4.1) |
| **Direct-drain attacker** (tries to TRANSFER from pool) | NS-5 | infeasible under assumption A1 |
| **Consensus-capture attacker** (farms NEF to fund stake) | NS-6(2) | NEF subsidy `≤ P_0 − 1` toward the `S010S011` `⌈(N_pool/2)+1⌉ × min_stake` floor |
| **Griefing / ideological adversary** (pool denial, not profit) | out of scope | the worst outcome is honest exhaustion of a genesis-pinned pool that was always going to drain (FA-Apply-14 T-N6); no supply effect (FA11 T-13) |

The **griefing** profile is explicitly out of scope, mirroring `S010S011SybilEconomics.md` §5: a non-economic adversary willing to burn `Σ(f + c)` purely to drain the pool faster than honest adopters extracts nothing it could not also extract honestly, achieves no supply effect, and merely accelerates a drain that FA-Apply-14 T-N6 already proves terminates. There is no liveness or safety consequence — the pool is a bootstrap incentive, not a consensus input.

### 7.2 Out of scope

- **Exogenous cost estimation.** `c` and `α` are environment parameters; this proof bounds profit *as a function of* them but does not estimate them for a given deployment. An operator must plug in their own `c` (registration friction) and `α` (adversary committee presence) — the latter is itself bounded by `S010S011SybilEconomics.md`.
- **Cross-shard NEF.** Each shard seeds and drains its own Zeroth pool independently (FA-Apply-14 has no cross-shard NEF coupling); the bounds apply per shard with per-shard `P_0`. The K-shard aggregate is `Σ_shards (P_0^{(shard)} − 1)`, which `CrossShardSupplyConservation.md` (FA-Apply-17) confirms involves no cross-shard value flow.
- **Time-value / discounting.** `Π(n)` is undiscounted. Front-loading (NS-1) only strengthens the result under any positive discount rate — early rewards are larger *and* sooner.

---

## 8. Conclusion

The E1 NEF bootstrap channel is **economically self-limiting** against a mass-registration adversary. Three facts pin it: (NS-1) the per-registrant reward halves geometrically, (NS-2.1) total extraction over any sequence is hard-capped at `P_0 − 1`, and (NS-3) for any non-zero effective registration cost `g` the *profitable* prefix is `O(log(P_0/g))` registrations — after which the halved reward no longer covers the un-halved cost and a rational adversary stops. The single residual lever is the genesis sizing of `P_0` together with the inclusion policy that sets `g` (NS-4.1), exactly the operator-policy posture `S010S011SybilEconomics.md` takes for consensus Sybil-resistance. NS-5 shows the pool is unspendable except through the halving (under assumption A1), making `P_0 − 1` a tight ceiling against all PPT adversaries, and NS-6 confirms the bounds compose with the supply (FA11 T-13) and consensus-Sybil (S-010/S-011) layers without weakening either. The bootstrap pool funds early entrants generously, converges geometrically, and cannot be farmed for unbounded or perpetual profit.

No theorem is open or partial. The proof rests on a small set of facts: the integer-halving recurrence (FA-Apply-14 T-N1), the first-time-only gate (FA-Apply-14 T-N3), the fee-redistribution model (FA-Apply-6 T-F4, no fee floor), and the unspendable-pool property (assumption A1 + the validator guard). Its breadth — a closed-form attacker net-profit function plus a logarithmic stopping bound — is what an operator needs to size `zeroth_pool_initial` against a Sybil farm rather than against an honest growth curve.
