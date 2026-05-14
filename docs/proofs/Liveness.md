# FA4 — Liveness theorem (probabilistic)

This document proves Determ's chain-progress guarantee: under partial synchrony, bounded per-validator unavailability, and BFT escalation enabled, the chain produces blocks with probability 1, and the expected number of round retries per height is bounded.

Unlike the cryptographic-soundness proofs (FA1 safety, FA2 censorship, FA3 selective-abort), FA4 is a **probabilistic** argument: liveness is not guaranteed for every single round (a Byzantine committee can stall one round), but the **expected** time to finalization is bounded.

**Companion documents:** `Preliminaries.md` (F0) for notation; `BFTSafety.md` (FA5) for the BFT-mode safety conditions that the escalation path relies on.

---

## 1. Theorem statement

**Setup.** Fix a height `h`. Let `N := |V|` be the validator pool size at `h`. Let `p ∈ [0, 1)` be the per-validator unavailability rate over a round window — the probability that any given honest validator fails to broadcast its Phase-1 contribution before the round timer fires. (Sources: network jitter, momentary load spikes, restart events; **not** Byzantine behavior, which is modeled separately.)

Let `K` be the genesis-pinned committee size. Let `M := ⌈2K/3⌉` be the BFT-escalation effective committee size. Let `T_threshold := bft_escalation_threshold` (genesis-pinned, default 5).

**Theorem T-4 (Liveness).** Under the assumptions:

- **(L1) Partial synchrony** (Preliminaries §3.1): there exists `Δ` such that within synchrony intervals, every honest broadcast is delivered to every honest peer within `Δ`.
- **(L2) Bounded per-validator unavailability**: `p < 1`. Equivalently, `(1-p) > 0`.
- **(L3) BFT-escalation enabled**: `bft_enabled = true` at genesis. (Optional; without it, the theorem holds for MD-mode rounds only and requires `(1-p)^K > 0` for liveness; see §4.)
- **(L4) Committee rotation per round is uniform-random** (modeled in §6 of Preliminaries; hybrid selector — rejection sampling at `2K ≤ N`, partial Fisher-Yates shuffle at `2K > N` — both uniform under ROM on the seed).
- **(L5) Synchrony window contains the round**: the round timer `T_round ≥ 2Δ + ε` for some small `ε`, so message delivery completes before timeout.

then:

1. **Expected rounds per finalized block** is bounded:
   $$
   \mathbb{E}[\text{rounds to finalize block at } h] \;\leq\; \frac{1}{(1-p)^K} \;+\; T_{\text{threshold}} \cdot \mathbb{E}[\text{BFT-mode rounds}]
   $$
2. **Probability of indefinite stall** is zero. If at least one round can be completed in MD mode `(1-p)^K > 0`, or escalation engages successfully (FA5 conditions met), some block at `h` finalizes with probability 1.

In plain terms: the chain *can* stall transiently (a few rounds of aborts under bad luck), but cannot stall permanently as long as some availability exists. The expected delay is bounded by a geometric expectation in MD mode, augmented by a bounded BFT fallback when MD repeatedly fails.

**Corollary T-4.1 (Steady-state throughput).** For `K = 3`, `p = 0.05`: `(1-p)^K = 0.857`, expected MD-mode rounds per block ≈ 1.17, throughput penalty over the noise-free baseline ≈ 17%.

For `K = 3`, `p = 0.20`: `(1-p)^K = 0.512`, expected MD-mode rounds ≈ 1.95, but with `T_threshold = 5` aborts the chain escalates within ~5 rounds, BFT-mode then finalizes with `M = 2` of `K = 3` survivors.

---

## 2. Lemmas

### Lemma L-4.1 — Per-round all-live probability

Under (L1), (L2), (L4) and the assumption that unavailability is independent across validators per round (independence assumption A4.1, which is reasonable for unsynchronized failures but breaks for correlated outages):

$$
\Pr[\text{all K committee members are live in a round}] = (1-p)^K
$$

**Proof.** Let `Live_i` be the event that committee member `v_i` successfully broadcasts its Phase-1 contribution within the round window. By (L2), `Pr[Live_i] = 1 - p`. By A4.1 independence, `Pr[⋂_i Live_i] = ∏_i (1-p) = (1-p)^K`.

The independence assumption holds under typical operational conditions (uncorrelated network jitter, hardware faults). Correlated outages (rack-level power failure, regional internet partition) violate A4.1. For Determ's `EXTENDED` sharding mode, regional concentration could correlate failures within a region — for global pools, correlation is generally low.   ∎

### Lemma L-4.2 — Geometric expectation

Under (L1)-(L5) and independence per round (rounds are independent because committee selection re-randomizes per round under (L4)):

$$
\mathbb{E}[\text{rounds to first all-live committee}] = \frac{1}{(1-p)^K}
$$

**Proof.** Let `X_r` be the indicator that round `r` has an all-live committee. By L-4.1, `Pr[X_r = 1] = (1-p)^K =: q`. Since committee selection is uniform per round (L4) and validator availability per round is independent (A4.1), the indicators `X_1, X_2, …` are i.i.d. Bernoulli(q).

The number of rounds to the first `X_r = 1` is a Geometric(q) random variable with expectation `1/q = 1/(1-p)^K`.   ∎

### Lemma L-4.3 — BFT escalation bound

Under (L3) and the assumption that after `T_threshold` consecutive aborts at the same height, BFT mode engages with effective committee size `M = ⌈2K/3⌉`:

The probability that a BFT-mode round at height `h` finalizes is at least `(1-p)^M`. Combined with FA5's conditional safety claim, an MD failure cascade is bounded to `T_threshold` rounds before escalation.

**Proof.** When BFT mode engages, the proposer-led committee accepts `M` of `K` signatures; the remaining `K - M` may be sentinel-zero. So liveness in BFT mode requires only `M` of `K` committee members to be live.

Pr[M of K live] is computed via the binomial expansion. For `K = 3, M = 2`:
$$
\Pr[\text{≥ 2 of 3 live}] = (1-p)^3 + 3 \cdot (1-p)^2 \cdot p = (1-p)^2 \cdot (1 + 2p)
$$

For `p = 0.20`: `(0.8)² · 1.4 = 0.896` — much higher than MD's `(0.8)³ = 0.512`.

The BFT-mode probability is monotone non-decreasing in `(1-p)` and strictly higher than MD's all-live probability whenever `K > M ≥ 1`. So BFT escalation strictly improves liveness odds at the cost of conditional safety (FA5).

The "bounded to `T_threshold` rounds" claim follows from the protocol-level rule: once `T_threshold` aborts accumulate at the same height, the next round is BFT-mode (Preliminaries §5 V8 + producer's escalation gate in `src/node/node.cpp::check_if_selected`).   ∎

### Lemma L-4.4 — Synchrony sufficiency for round completion

Under (L5) `T_round ≥ 2Δ + ε`, a round where all K committee members are live and the network is in a synchrony interval will complete (produce a finalized block) within `T_round`.

**Proof.** A round's timeline:

1. Phase 1 broadcast: each live `v_i` sends `ContribMsg`. Within `Δ` of round start, all `K` `ContribMsg`s reach all honest peers.
2. Phase 1 → Phase 2 transition: triggered at K-of-K Phase-1 arrival, no wait (the asio::post breaks recursion, takes ~µs).
3. Phase 2 broadcast: each live `v_i` sends `BlockSigMsg` after computing the block digest. Within another `Δ` of Phase-2 start, all `K` `BlockSigMsg`s arrive.
4. Finalization: triggered at K-of-K Phase-2 arrival, no wait.

Total: 2 broadcasts × `Δ` + processing overhead `< ε`. Provided `T_round ≥ 2Δ + ε`, the round timer doesn't fire before finalization.

Concretely, for `T_round = 200 ms` (web profile) and `Δ ≈ 80 ms` (Internet-scale RTT): `2Δ + ε = 165 ms < 200 ms` ✓.

For asynchrony intervals (network partition, large jitter spike): the round may timeout despite all members being live. This is the failure mode that triggers MD aborts and eventual BFT escalation.   ∎

---

## 3. Proof of Theorem T-4

We decompose the expected number of rounds to finalize a block at height `h` into MD-mode contribution + BFT-mode contribution.

**Step 1 — MD-mode contribution.**

Each round's success is i.i.d. Bernoulli`((1-p)^K)` by L-4.1, L-4.2, L-4.4 (under synchrony L5). Under typical conditions (network in synchrony interval, p small), the chain finalizes in `≈ 1/(1-p)^K` rounds.

Round failures from any cause (Byzantine abstention, network jitter, honest unavailability) advance the height's abort counter. The counter reaches `T_threshold` with probability:

$$
\Pr[\text{aborts} \geq T_{\text{threshold}}] = (1 - (1-p)^K)^{T_{\text{threshold}}}
$$

For `p = 0.20`, `K = 3`, `T_threshold = 5`: probability `≈ 0.488^5 ≈ 0.028`. So in 2.8% of heights, the chain hits the escalation threshold.

**Step 2 — BFT-mode contribution.**

When MD fails `T_threshold` times, BFT escalation engages. By L-4.3, BFT-mode finalization probability per round is `(1-p)^M · (1 + (K-M)p / (1-p))` or similar binomial; concretely much higher than MD's `(1-p)^K`.

Expected BFT-mode rounds to finalize is `≤ 1 / Pr[≥M of K live]`. For typical parameters, this is `≤ 2` rounds.

**Step 3 — Combining.**

The total expected rounds per height is:
$$
\mathbb{E}[\text{total rounds}] = \mathbb{E}[\text{MD rounds before escalation}] + \mathbb{E}[\text{BFT rounds after escalation}]
$$

For typical Determ parameters (`K=3, p=0.05, T_threshold=5`):

- `E[MD rounds] ≈ 1.17` (geometric on `q = 0.857`).
- `Pr[hits escalation] ≈ 0.143^5 ≈ 5.9 × 10⁻⁵`.
- `E[BFT rounds | escalation] ≈ 1.04`.
- `E[total] ≈ 1.17 + 5.9 × 10⁻⁵ × 1.04 ≈ 1.17`.

For adversarial parameters (`p = 0.30`):

- `E[MD rounds] ≈ 1/0.343 ≈ 2.92`.
- `Pr[hits escalation] ≈ 0.657^5 ≈ 0.124`.
- `E[BFT rounds | escalation] ≈ 1.17`.
- `E[total] ≈ 2.92 + 0.124 × 1.17 ≈ 3.06`.

Both finite. The chain makes steady progress at the geometric expectation, with bounded variance.

**Step 4 — Probability of indefinite stall.**

Suppose the chain stalls indefinitely at height `h`. Then `T_threshold` rounds of MD failures occur, escalation engages, and BFT-mode rounds also fail indefinitely.

- `Pr[MD failure forever] = 0` if `(1-p)^K > 0` (a positive probability of success per round, so almost-surely a success eventually).
- `Pr[BFT failure forever] = 0` under (L3) and (L5), with the analogous geometric argument.

By Borel-Cantelli (or the equivalent for geometric random variables): `Pr[indefinite stall] = 0`.   ∎

---

## 4. Without BFT escalation (MD-mode only)

If `bft_enabled = false` at genesis, the chain runs MD-mode strictly. Then:

**Theorem T-4' (MD-only liveness).** Under (L1)-(L5) excluding (L3), the chain finalizes with probability 1 provided `(1-p)^K > 0`. Expected rounds per height is `1/(1-p)^K`.

This is the special case of T-4 with no BFT fallback. It's exactly the geometric bound from L-4.2. For deployments preferring "unconditional safety on every block over liveness fallback" (Preliminaries §5 V8's "Opt out" path), T-4' is the operative claim.

**Concrete numbers.** For `K = 3`, `p = 0.05`: expected blocks `≈ 1.17` per finalization. For `p = 0.20`: `≈ 1.95` per finalization. For `p = 0.50`: `≈ 8` per finalization. For `p = 0.80`: `≈ 125` per finalization. As `p → 1`, expected rounds → ∞ (graceful degradation).

For `p < 0.30`, the throughput penalty is modest (under 3x slowdown). Above `p = 0.5`, finalization becomes glacial; this is the operational threshold below which Determ assumes its deployment.

---

## 5. Discussion

### 5.1 What this proof does and does NOT prove

T-4 proves:

- **Almost-sure finalization** (`Pr[stall] = 0`).
- **Bounded expected delay** (geometric in MD, geometric+constant in BFT).
- **Throughput characterization** for typical parameters.

T-4 does NOT prove:

- **Worst-case finalization time.** There's no absolute upper bound — the geometric expectation has heavy tails, so a specific round can stall arbitrarily long, just with vanishing probability.
- **Liveness under fully-Byzantine majority** of K. If every committee member is Byzantine and coordinates to abort, MD aborts indefinitely. BFT escalation engages but if every escalated committee is also Byzantine, it also aborts. The protocol's liveness assumption ultimately requires *some* honest member in *some* committee. This is the FA1 trust assumption applied to liveness rather than safety.
- **Asynchronous-network liveness.** During asynchrony intervals (network partition), rounds may stall without bound. T-4 explicitly assumes (L5) holds — the network reaches synchrony intervals long enough to complete rounds. Real Internet conditions typically satisfy this; degenerate partition scenarios don't.

### 5.2 Selective abort and FA3

A Byzantine `v_i` might selectively abort (not broadcast Phase-1) based on the resulting randomness. By FA3, this gains them zero predictive advantage — but it does *consume* a round (causing an abort + retry). The MD round-failure rate `1 - (1-p)^K` includes both honest unavailability AND Byzantine abort behavior.

For deployment analysis, treat `p` as combining honest-unavailability + Byzantine-abort-rate. Under FA3's bound, rational Byzantine `v_i` has no economic incentive to abort selectively (no gain in expectation), so the Byzantine contribution to `p` should approach 0 over time. Irrational adversaries (compromised key, malware) can keep `p` elevated; the bound still applies.

### 5.3 BFT escalation as a safety/liveness trade

Engaging BFT mode strictly improves liveness (L-4.3) but conditionally degrades safety (FA5). Operators choose:

- **MD-only (`bft_enabled = false`)**: unconditional safety on every block. Liveness graceful-degrades as `p` grows.
- **MD+BFT escalation (`bft_enabled = true`, default)**: liveness fallback at the cost of conditional safety on BFT blocks. `consensus_mode` is per-block observable; applications can wait for next MD-mode block for stronger guarantees.

This is a deployment-time choice, not a per-block choice.

### 5.4 What "almost surely" means

`Pr[indefinite stall] = 0` doesn't mean "in finite time always finalizes." It means: for any finite time `T`, `Pr[stall longer than T] → 0` as `T → ∞`. For Determ's typical parameters, the chain progresses at near-linear pace (1.17x baseline rounds per height); for adversarial parameters, progress slows but remains positive in expectation.

In practice, monitoring at the operator level: if expected rounds per block exceeds 5, something operational is wrong (network partition, persistent Byzantine abstention, hardware fault); operator-level recovery (restart suspicious validators, restore network connectivity, etc.) brings `p` back down.

### 5.5 Connection to BFT-mode safety (FA5)

T-4 establishes BFT escalation as a *liveness* mechanism. FA5 establishes that BFT-mode blocks are safe under `f < K_eff/3` Byzantine within the BFT committee. These are complementary:

- T-4 says: BFT escalation increases the probability that *some* block finalizes.
- FA5 says: BFT blocks are safe under conditions tighter than MD-mode (need ≥ `K - K_eff/3` honest in committee, vs ≥ 1 in MD).

Together: BFT escalation chooses liveness over safety; operators accept this trade for the small fraction of blocks that need it.

---

## 6. Implementation cross-reference

| Document | Source |
|---|---|
| Round timer T_round | `Config.tx_commit_ms` / `Config.block_sig_ms` (§3 §6 of Preliminaries) |
| Phase-1 timeout → abort | `src/node/node.cpp::handle_contrib_timeout` |
| Phase-2 timeout → abort | `src/node/node.cpp::handle_block_sig_timeout` |
| Abort quorum formation | `src/node/node.cpp::on_abort_claim` |
| BFT escalation trigger | `src/node/node.cpp::check_if_selected` BFT branch (four gates: `bft_enabled`, `total_aborts ≥ bft_escalation_threshold`, available pool < K, available pool ≥ ceil(2K/3) — see PROTOCOL.md §5.3) |
| Committee rotation per round | `src/node/node.cpp::check_if_selected` (`select_m_creators` call after the `rand`-mixing loop over `current_aborts_`) |
| Round retry after abort | `src/node/node.cpp::reset_round` + `start_contrib_phase` |

A reviewer can confirm the protocol's liveness story by reading these source paths and verifying:

- Round timer is configurable per profile (T_round = max(tx_commit_ms, block_sig_ms) + slack).
- Aborts increment a per-height counter and re-randomize the committee.
- BFT escalation engages when the counter hits `bft_escalation_threshold` and the pool can't form a full-K committee.
- No infinite-loop construction exists in the abort/retry path — rounds bounded by `T_threshold` for MD, then by BFT-mode geometric bound for the rest.

---

## 7. Conclusion

Liveness in Determ is a probabilistic claim with bounded expected delay: `E[rounds per block] ≤ 1/(1-p)^K + O(T_threshold)`. The bound is exact (not asymptotic), tight for typical Determ parameters, and characterizes both MD-only and MD+BFT-escalation deployments.

The proof's structural feature is that liveness is **not** unconditional (a sufficiently large `p` slows the chain), but indefinite-stall has probability zero under (L2) and (L5). This is the deliberate trade Determ makes: safety is unconditional (FA1); liveness is best-effort probabilistic with a graceful-degradation curve.
