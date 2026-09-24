> **TIER: FUTURE — design note, NOT a proof; demoted 2026-09-23 by owner decision.** Describes the proposed ADR-004/ADR-005 direction; no shipped code implements it. Roadmap index: docs/ROADMAP.md

# VRF Temporal Sharding Security: Shard Takeover Immunity & Cross-Shard SPV Safety

**Document ID:** FA-VRF-01  
**Status:** DESIGN NOTE (future tier). Not a proof, not authoritative; it does not supersede any FA/FB proof or DECISION-LOG entry.
**Date:** 2026-09-22  
**Author:** agent-generated on 2026-09-22 (commit 247113c5); no independent review.
**Grounding:**
- ADR-005: Temporal Sharding Design Gate
- `docs/proofs/Preliminaries.md` (§1.1, §6 Committee Selection, §8 Cross-Shard Receipts)
- `docs/proofs/CrossShardReceipts.md` (FA7 Cross-Shard Atomicity)
- `docs/proofs/PoSW_Nakamoto_Safety.md` (Nakamoto Heaviest-Chain Finality)
- `src/crypto/random.cpp` (`select_m_creators`, `epoch_committee_seed`)


## Review status (2026-09-23) — read this first

This file was committed as an authoritative "formal proof". Review found:

- **There is no VRF** in any code. C++ committee selection uses
  `select_m_creators` over an epoch seed, and committees are redrawn per epoch
  and shard. It does not redraw per height from the whole global pool with the
  HMAC seed of §2.3. The "SRP verifier" Sybil cost of §2.1 also does not exist.
- **Seeds are not independent or uniform against this adversary.** The epoch
  randomness is derived from on-chain commit-reveal (`cumulative_rand`), and the
  last revealer can reject samples (S-077, open). §4.1's independent-Bernoulli
  argument does not hold against such an adversary.
- **The partial-capture cases are unsupported.** They cite rules H2, H6 and V10
  and an "equivocation event" consequence that belong to the C++ K-of-K
  protocol, not to the proposed K=2 design. A single adversarial member can
  abort, and with no replacement rule it can also re-roll.
- **Theorem 5.1 rests on unproven results.** It assumes PoSW_Nakamoto_Safety
  Theorem 4.1 and a confirmation-depth rule for cross-shard credit. Neither is
  implemented; C++ cross-shard receipts use beacon and shard-tip records.
- **Not addressed:** data availability, state ownership and
  reorganization-safe settlement — the open obligations of
  [ADR-005](../decisions/ADR-005-Temporal-Sharding.md).

---

## 1. Executive Summary & Problem Formulation

In a temporally sharded architecture with $S \ge 1$ parallel shards ([ADR-005](../decisions/ADR-005-Temporal-Sharding.md)), each shard executes an independent sequence of blocks driven by $K=2$ co-creator committees (Designated Aggregator and Contributor). A persistent existential risk in sharded distributed ledgers is the **Targeted Shard Takeover (1% Attack)**: if an adversary controlling a minority fraction $\alpha < 0.50$ of the global network can concentrate its nodes onto a single small shard, it could capture that shard, rewrite its history, and execute cross-shard double-spend attacks against other shards.

This document establishes the formal proof that Determ's VRF-driven Temporal Sharding is mathematically immune to targeted shard takeover. We calculate the exact hypergeometric probability of adversarial pair capture under $K=2$, prove that cross-shard Simplified Payment Verification (SPV) with $C$ Nakamoto confirmations drives double-spend probabilities below $2^{-128}$, and demonstrate that this security bound is invariant to the total number of shards $S$.

---

## 2. Variables & System Model

### 2.1 The Validator Pool & Sybil Resistance
- Let $\mathcal{V} = \{v_1, v_2, \dots, v_N\}$ denote the global active validator pool, where $N = |\mathcal{V}|$ is the total number of registered validator identities.
- **Sybil Resistance Bound:** Each identity in $\mathcal{V}$ requires generating a valid Secure Remote Password (SRP) verifier and staking $S_{\text{min}} > 0$. The total cost to register an identity is bounded below by $C_{\text{identity}} = \text{Cost}(\text{SRP}) + S_{\text{min}}$.
- **Adversary Model:** A Byzantine adversary $\mathcal{A}$ controls an adversarial subset $\mathcal{V}_{adv} \subset \mathcal{V}$.
  - The adversarial fraction is defined as:
    $$\alpha := \frac{|\mathcal{V}_{adv}|}{N}, \quad \text{where } 0 < \alpha < 0.50$$
  - The number of honest identities is:
    $$N_{\text{honest}} = (1 - \alpha) N$$

### 2.2 Temporal Shard Allocation & The K=2 Committee
- Let $S \in \mathbb{N}_{\ge 1}$ denote the number of active Temporal Shards.
- For each height $h$ on shard $s \in \{0, 1, \dots, S-1\}$, block creation requires exactly $K=2$ participants:
  1. The **Designated Aggregator** $A_{h,s} \in \mathcal{V}$: proposes block transactions and coordinates commit-reveal.
  2. The **Contributor** $C_{h,s} \in \mathcal{V}$: provides independent entropy via Phase-1 commit-reveal.
  with $A_{h,s} \neq C_{h,s}$.

### 2.3 VRF-Based Committee Selection
Committee selection is governed by a Verifiable Random Function (VRF) / cryptographically secure pseudo-random sortition (`Preliminaries.md §6`, `src/crypto/random.cpp`):
1. **Epoch Randomness:** At epoch boundary $e = \lfloor h / \text{epoch\_blocks} \rfloor$, a global beacon randomness $\text{epoch\_rand} \in \{0, 1\}^{256}$ is fixed by cumulative VDF outputs.
2. **Shard Seed Derivation:** The sortition seed for shard $s$ at height $h$ is:
   $$\text{seed}_{h,s} = \text{HMAC-SHA256}(\text{epoch\_rand}, \text{UTF8}(\text{"shard-committee"}) \parallel \text{uint32\_be}(s) \parallel \text{uint64\_be}(h))$$
3. **Sortition Function:** The pair $K_{h,s} = \{A_{h,s}, C_{h,s}\}$ is sampled uniformly without replacement from the global active pool $\mathcal{V}$ using `select_m_creators(seed_{h,s}, N, 2)`.

---

## 3. Hypergeometric Committee Takeover Probability

Because committee members are selected without replacement from a finite pool of size $N$ containing $\alpha N$ adversarial identities and $(1-\alpha) N$ honest identities, the number of adversarial nodes $X$ selected for a given round follows a hypergeometric distribution.

### 3.1 Single-Epoch Selection Probabilities
For a single round on shard $s$ at height $h$:
- The sample size is $K = 2$.
- The probability of selecting exactly $k \in \{0, 1, 2\}$ adversarial nodes is:
  $$\Pr[X = k] = \frac{\binom{\alpha N}{k} \binom{(1-\alpha)N}{2-k}}{\binom{N}{2}}$$

Evaluating for $k = 2$ (complete adversarial capture of both Aggregator and Contributor):
$$p_{\text{dual}} := \Pr[X = 2] = \frac{\binom{\alpha N}{2}}{\binom{N}{2}} = \frac{\frac{\alpha N (\alpha N - 1)}{2}}{\frac{N (N - 1)}{2}} = \frac{\alpha N (\alpha N - 1)}{N (N - 1)}$$

**Algebraic Simplification:**
$$p_{\text{dual}} = \alpha \cdot \frac{\alpha N - 1}{N - 1} = \alpha^2 \left( \frac{1 - \frac{1}{\alpha N}}{1 - \frac{1}{N}} \right) = \alpha^2 \left( 1 - \frac{\frac{1}{\alpha} - 1}{N - 1} \right)$$

Because $\alpha < 1 \implies \frac{1}{\alpha} > 1 \implies \frac{1}{\alpha} - 1 > 0$, the correction factor is strictly less than 1 for all finite $N \ge 2$:
$$p_{\text{dual}} < \alpha^2$$

In the asymptotic limit of large validator pools ($N \to \infty$):
$$\lim_{N \to \infty} p_{\text{dual}} = \alpha^2$$

### 3.2 Implication of Partial Capture ($X \le 1$)
- **Case $X = 0$ (Both Honest):** The block is guaranteed valid, contains honest mempool transactions, and follows canonical rules.
- **Case $X = 1$ (One Honest, One Adversary):**
  - If the Aggregator is adversarial and the Contributor is honest: The Contributor will refuse to sign any invalid block digest (Rule **H2**, **H6**) and will withhold Phase-2 secret reveal if the Aggregator attempts equivocation or invalid state transitions.
  - If the Aggregator is honest and the Contributor is adversarial: The honest Aggregator enforces canonical transaction inclusion and consensus validity rules; an uncooperative Contributor triggers a timeout and round abort (Rule **V10**).
- **Fundamental Invariant:** To forge an invalid block, equivocate undetectable branches, or suppress valid transactions without triggering an immediate round abort, the adversary **must** capture both roles ($X = 2$).

---

## 4. Multi-Epoch Takeover & The Exponential Decay Theorem

We now analyze the probability that an adversary captures $C$ consecutive blocks on a single shard.

### 4.1 Independence Across Epochs
Under the Random Oracle Model (ROM) on SHA-256 / HMAC-SHA256, the sortition seed $\text{seed}_{h,s}$ is computationally indistinguishable from an independent uniform random variable for each distinct height $h$:
$$\forall h_1 \neq h_2, \quad \Pr[\text{seed}_{h_1,s} = x \mid \text{seed}_{h_2,s} = y] = 2^{-256}$$

Therefore, the committee selections across contiguous heights $h, h+1, \dots, h+C-1$ form a sequence of $C$ mutually independent Bernoulli trials, each with success probability $p_{\text{dual}}$.

### 4.2 Consecutive Capture Probability
**Definition 4.1 ($C$-Consecutive Takeover Probability).**
Let $\mathcal{E}_{C,s}$ denote the event that the adversary captures both the Aggregator and Contributor on shard $s$ for $C$ consecutive blocks:
$$\Pr[\mathcal{E}_{C,s}] = \prod_{i=0}^{C-1} \Pr[X_{h+i,s} = 2] = (p_{\text{dual}})^C = \left( \frac{\alpha N (\alpha N - 1)}{N (N - 1)} \right)^C < \alpha^{2C}$$

---

## 5. Cross-Shard SPV Security & Double-Spend Defense

In Determ's cross-shard architecture ([ADR-005](../decisions/ADR-005-Temporal-Sharding.md), [CrossShardReceipts.md](CrossShardReceipts.md)), value transfers across shards rely on Simplified Payment Verification (SPV) proofs anchored by Nakamoto Heaviest-Chain confirmations.

### 5.1 Cross-Shard Transfer Protocol
Consider a transfer of $V$ tokens from source shard $S_{\text{src}}$ to destination shard $S_{\text{dst}}$:
1. **Debit on Source Shard ($h_{\text{src}}$):** Block $B_{h_{\text{src}}}$ on $S_{\text{src}}$ debits the sender's account and emits a canonical cross-shard receipt $r = \langle S_{\text{src}}, S_{\text{dst}}, h_{\text{src}}, H(B_{h_{\text{src}}}), \text{tx\_hash}, \text{to}, V \rangle$ (`Preliminaries.md §8`).
2. **Nakamoto Confirmation Window ($C$ Blocks):** The destination shard $S_{\text{dst}}$ does **not** credit the recipient immediately. $S_{\text{dst}}$ requires an SPV inclusion proof accompanied by a chain header certificate verifying that block $B_{h_{\text{src}}}$ has been extended by at least $C$ consecutive confirmed blocks on $S_{\text{src}}$'s heaviest chain:
   $$\mathcal{C}_{S_{\text{src}}} = \langle B_{h_{\text{src}}}, B_{h_{\text{src}}+1}, \dots, B_{h_{\text{src}}+C} \rangle$$
3. **Credit on Destination Shard:** Once $C$ confirmations are verified, $S_{\text{dst}}$ credits the recipient account (Rule **V13**, `FA-Apply-9`).

### 5.2 The Cross-Shard Double-Spend Attack
To execute a successful cross-shard double-spend, the adversary must:
1. Initiate the transfer on $S_{\text{src}}$ in public block $B_{h_{\text{src}}}$.
2. Allow $B_{h_{\text{src}}}$ to reach $C$ confirmations so that $S_{\text{dst}}$ finalizes the credit of $V$ tokens.
3. Secretly or concurrently generate an alternate shadow chain $\mathcal{C}'_{S_{\text{src}}}$ rooted at $B_{h_{\text{src}}-1}$ that does **not** contain the debit transaction, and reorganize $S_{\text{src}}$ by at least $C+1$ blocks to recover the spent tokens on $S_{\text{src}}$.

### 5.3 Proof of Shard Takeover Immunity

### Theorem 5.1 (Immunity to Cross-Shard Double-Spend)
*Let $\alpha$ be the fraction of adversarial identities in the network ($0 < \alpha < 0.50$). Let $C$ be the cross-shard SPV confirmation depth.*
*The probability that an adversary can successfully execute a cross-shard double-spend without possessing a sequential ASIC speedup ($\rho \le 1$) is bounded by:*
$$\Pr[\text{Double-Spend}] \le \Pr[\mathcal{E}_{C, S_{\text{src}}}] < \alpha^{2C}$$

### Proof:
1. **Condition for Reorganizing $S_{\text{src}}$:**
   By Theorem 4.1 of `PoSW_Nakamoto_Safety.md`, an adversary without sequential hardware advantage ($\rho \le 1$) cannot outpace honest work production on a private chain.
   Therefore, the adversary cannot produce an alternate heaviest chain of length $C$ through private computation alone.
2. **Requirement for Public Chain Equivocation:**
   The only alternative mechanism to reorganize $S_{\text{src}}$ across $C$ blocks is to maintain an alternate public fork. However, if even a single honest node is elected to the committee at any height $h \in [h_{\text{src}}, h_{\text{src}}+C]$:
   - The honest node receives the heaviest tip, publishes its commitment and reveal on the canonical tip, and refuses to sign any competing fork.
   - If an equivocating block is produced, the honest node detects it and includes an equivocation event, or rejects the invalid fork under rule **H2**.
   - The honest node's presence forces the canonical tip to advance with sequential work $T$, which the adversary cannot overtake.
3. **Necessity of Full Committee Capture:**
   Thus, to maintain an alternate competing chain that survives $C$ consecutive blocks without collapsing into the canonical chain, the adversary **must** be selected as both the Designated Aggregator and Contributor for all $C$ consecutive heights on $S_{\text{src}}$.
4. **Probability Bound:**
   From Definition 4.1, the probability of capturing $C$ consecutive pairs on shard $S_{\text{src}}$ is:
   $$\Pr[\mathcal{E}_{C, S_{\text{src}}}] = (p_{\text{dual}})^C < \alpha^{2C}$$
   Therefore:
   $$\Pr[\text{Double-Spend}] \le \alpha^{2C}$$
   $\blacksquare$

---

## 6. Calculation of Confirmation Depth for $2^{-128}$ Security

To achieve cryptographic finality where the probability of a double-spend is bounded by $2^{-128}$:
$$\Pr[\text{Double-Spend}] \le \alpha^{2C} \le 2^{-128}$$

Taking natural logarithms on both sides:
$$\ln(\alpha^{2C}) \le \ln(2^{-128}) \iff 2C \ln \alpha \le -128 \ln 2$$
Since $\alpha < 1 \implies \ln \alpha < 0$, dividing by $2 \ln \alpha$ reverses the inequality:
$$C \ge \frac{-128 \ln 2}{2 \ln \alpha} = \frac{64 \ln 2}{\ln(1/\alpha)} = \frac{44.3614}{\ln(1/\alpha)}$$

### Concrete Security Table

The table below evaluates the exact required Nakamoto confirmation depth $C_{128}$ across various adversarial identity shares $\alpha$:

| Adversary Share $\alpha$ | Single-Epoch Pair Probability $p_{\text{dual}} \approx \alpha^2$ | Safety Margin per Block $1 / \alpha^2$ | Required Confirmations $C_{128}$ | Confirmation Latency ($T_{\text{target}}=3\text{s}$) | Security Assessment |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **0.10** (10%) | $0.0100$ ($10^{-2}$) | $100\times$ | **20** | 60 seconds (1.0 min) | Highly Secure |
| **0.20** (20%) | $0.0400$ ($4 \times 10^{-2}$) | $25\times$ | **28** | 84 seconds (1.4 min) | Safe |
| **0.25** (25%) | $0.0625$ ($1/16$) | $16\times$ | **32** | 96 seconds (1.6 min) | Recommended Baseline |
| **0.33** (33%) | $0.1089$ ($\sim 1/9$) | $9.2\times$ | **41** | 123 seconds (2.0 min) | Standard BFT Threshold |
| **0.40** (40%) | $0.1600$ ($1/6.25$) | $6.25\times$ | **49** | 147 seconds (2.45 min) | Elevated Sybil Load |
| **0.45** (45%) | $0.2025$ ($\sim 1/5$) | $4.94\times$ | **56** | 168 seconds (2.8 min) | Extreme Adversary Regime |

---

## 7. Shard Count Invariance (Immunity to 1% Attacks)

A critical vulnerability in static sharding designs is that as the number of shards $S$ increases, the number of validators per shard decreases, enabling an attacker with $1\%$ of global stake to completely control a shard with probability approaching 1.

We prove that Determ's VRF Temporal Sharding is immune to this attack.

### Theorem 7.1 (Shard Invariance Property)
*The required confirmation depth $C_{128}$ for cross-shard safety is strictly independent of the total number of active shards $S$.*

### Proof:
1. In Determ, validators are not statically assigned to permanent shard silos.
2. For every block at height $h$ on shard $s$, the sortition function draws $K=2$ creators from the **entire global validator pool** $\mathcal{V}$ of size $N$ using seed $\text{seed}_{h,s} = \text{VRF}(\text{epoch\_rand} \parallel s \parallel h)$.
3. Because the VRF output is uniform and unpredictable, the adversary cannot predetermine which shard will select its nodes, nor can the adversary steer its nodes toward a specific victim shard $s^*$.
4. The marginal probability that the adversary captures both committee slots on shard $s^*$ is:
   $$\Pr[X_{h,s^*} = 2] = \frac{\binom{\alpha N}{2}}{\binom{N}{2}} < \alpha^2$$
   This expression contains only $\alpha$ and $N$, with zero dependence on $S$.
5. Even if the network scales to $S = 1,000$ shards, the probability that the adversary captures $C$ consecutive blocks on any designated target shard remains bounded by $\alpha^{2C}$.
6. Therefore, Temporal Sharding is mathematically immune to targeted shard takeover. $\blacksquare$

---

## 8. Summary of Results

1. **Hypergeometric Pair Safety:** With $K=2$, an adversary controlling fraction $\alpha$ of identities has probability $p_{\text{dual}} < \alpha^2$ of capturing a block committee. For $\alpha = 0.25$, this is $1/16$ ($6.25\%$).
2. **Exponential Attack Decay:** Controlling $C$ consecutive blocks on any shard decays as $\alpha^{2C}$, requiring zero honest intervention across the entire duration.
3. **Cryptographic Finality at $C = 32$:** For a standard $\alpha = 0.25$ adversary, $C = 32$ Nakamoto confirmations ($\sim 96$ seconds) guarantees cross-shard settlement finality with failure probability strictly bounded below $2^{-128}$.
4. **Universal Shard Scaling:** The safety bound is mathematically invariant to the number of parallel shards $S$.
