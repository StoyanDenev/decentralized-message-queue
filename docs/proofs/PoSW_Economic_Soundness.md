> **TIER: FORMAL PROOF.** Authoritative consensus and security specification. Roadmap index: docs/ROADMAP.md

# PoSW Economic Soundness: VDF Cost-to-Forge & The Irrationality of 1-Bit Bias

**Document ID:** FA-PoSW-02  
**Status:** ACTIVE FORMAL PROOF (supersedes legacy Zero-Bit Bias / Time-Lock Claims per Decision Log 2026-09-22)  
**Date:** 2026-09-22  
**Author:** Principal Cryptography Researcher & Formal Verification Architect  
**Grounding:**
- Decision Log 2026-09-22: Formal Retraction of "Zero-Bit Bias" Claims
- `docs/proofs/K2_VDF_Soundness.md` (§2 R1, R2, R3 refutations)
- `docs/decisions/ADR-004-Fault-Model.md` (PoSW Cumulative Work Model)
- `docs/proofs/PoSW_Nakamoto_Safety.md` (Sequential Speed Ratio $\rho$)
- `docs/proofs/Preliminaries.md` (Base Cryptographic Assumptions A1-A4)

---

## 1. Context & Retraction of Prior Zero-Bit Bias Claims

In earlier revisions of the Determ architecture, protocol documents asserted that a local VDF time-lock puzzle guaranteed mathematical "Zero-Bit Bias" during committee commit-reveal phases. As formally documented in `docs/proofs/K2_VDF_Soundness.md` (§2, Refutation R1) and recorded in the Decision Log of 2026-09-22:

> *"The claim that a K=2 commit-reveal protocol with a local VDF delivers strict 0-bit bias under an adversarial majority (colluding Aggregator and Contributor) is mathematically FALSE in the information-theoretic sense. When an adversary controls all secret shares in a round, it possesses the information necessary to compute candidate randomness outcomes before publication."*

This document provides the rigorous replacement: **Economic Soundness under Proof of Sequential Work (PoSW)**. We prove that although an adversary controlling both the Designated Aggregator and Contributor can evaluate multiple candidate branches in private (a 1-bit bias attempt), any delay in broadcasting immediately causes the honest network to advance the canonical Heaviest-Chain, orphaning the adversary's precomputed block. Unless the adversary possesses an impossible sequential hardware speedup ($\rho \gg 1$), attempting to bias the randomness is strictly negative-EV and economically irrational.

---

## 2. Pre-Computation & Branch Grinding Attack Model

### 2.1 The K=2 Committee Structure
At height $h$, the protocol elects a committee $K_h = \{A, C\}$ comprising:
- The Designated Aggregator $A$, responsible for assembling transactions and proposing block candidates.
- The Contributor $C$, providing independent entropy via secret reveal $s_C$.

Let the round evaluation require $T$ sequential VDF steps:
$$y = f^{(T)}(\chi)$$
where the VDF seed $\chi$ is bound to the commitments of both parties:
$$\chi = H(B_{h-1}.\text{hash} \parallel c_A \parallel c_C \parallel \text{tx\_root})$$

### 2.2 The Adversary's Pre-Computation Strategy
Suppose a Byzantine adversary $\mathcal{A}$ corrupts both $A$ and $C$ at height $h$ (or $C$ is colluding with $A$).
1. Because $\mathcal{A}$ controls both secrets $s_A$ and $s_C$, $\mathcal{A}$ can construct $M \ge 2$ distinct candidate pairs $(s_A^{(j)}, s_C^{(j)})$ or transaction sets $\text{tx\_root}^{(j)}$ for $j \in \{1, 2, \dots, M\}$.
2. Each candidate $j$ yields a distinct challenge $\chi^{(j)}$.
3. The adversary seeks a specific target predicate $\mathcal{P}: \mathcal{Y} \to \{0, 1\}$ on the output randomness $R(B) = H(y^{(j)})$ (for example, biasing the parity bit $\mathcal{P}(R) = R \pmod 2 = 1$ to favor validator selection in epoch $h+1$, or manipulating MEV ordering).
4. $\mathcal{A}$ delays the public broadcast of block $B_h$ while concurrently or sequentially evaluating the VDF on the candidate branches.

---

## 3. The Race Against Canonical Chain Growth

Let $t_0 = 0$ denote the start of round $h$.

### 3.1 Parallel vs. Sequential Evaluation
Let the adversary deploy $M$ independent ASIC evaluation cores.
- By **Axiom 1 (Sequentiality)**, parallel cores cannot accelerate a single evaluation of $f^{(T)}(\chi^{(j)})$.
- Each core evaluates one candidate branch $j \in \{1, \dots, M\}$ serially.
- The minimum wall-clock time required for $\mathcal{A}$ to evaluate any single candidate $j$ is:
  $$\tau_{\text{eval}} = \frac{T}{V_{adv}} = \frac{T}{\rho V_{honest}}$$
  where $\rho = V_{adv} / V_{honest}$ is the hardware advantage ratio defined in `PoSW_Nakamoto_Safety.md`.

### 3.2 Honest Network Progression Under Withholding
Under the Determ consensus protocol, the honest network does not wait indefinitely for a silent or withholding producer pair:
1. **Reveal Window Timeout ($W_{\text{reveal}}$):** If valid reveal signatures and the completed block $B_h$ are not broadcasted across the gossip network within the window:
   $$t_{\text{timeout}} = W_{\text{reveal}} + \Delta$$
   where $\Delta$ is the network synchrony bound, honest nodes trigger the fallback protocol or initiate a round abort (Rule **V10**).
2. **Canonical Tip Extension:**
   - If honest validators transition to fallback / re-round, they elect the fallback pair or advance round counter $r \to r+1$.
   - Honest validators append the honest fallback block $B_h^{\text{honest}}$ with weight $W(B_h^{\text{honest}}) = W(B_{h-1}) + T_{\text{fallback}}$.
   - Immediately thereafter, the network proceeds to height $h+1$, evaluating sequential iterations $T_{h+1}$.
3. **Canonical Chain Work at Adversary Completion Time:**
   Suppose the adversary completes evaluating its $M$ candidates at wall-clock time $t = \tau_{\text{eval}} + \delta_{\text{grind}}$, selects the winning candidate $j^* \in \{1, \dots, M\}$ satisfying $\mathcal{P}(y^{(j^*)}) = 1$, and broadcasts $B_h^{(j^*)}$.
   
   If $t > t_{\text{timeout}}$, the honest network has already advanced to height $h+k$ ($k \ge 1$).
   The cumulative sequential work on the honest canonical chain is:
   $$W_{\text{honest}}(t) = W(B_{h-1}) + \sum_{i=0}^{k-1} T_{h+i} \ge W(B_{h-1}) + (1 + k) T$$
   
   However, on candidate branch $j^*$, the adversary has only computed a single block's sequential work:
   $$W(B_h^{(j^*)}) = W(B_{h-1}) + T_h = W(B_{h-1}) + T$$

---

## 4. Catch-Up Impossibility & The Orphan Proof

### Theorem 4.1 (Catch-Up Impossibility Without $\rho \gg 1$)
*Let $\mathcal{A}$ delay broadcasting block $B_h$ by elapsed duration $\Delta t_{\text{delay}} > 0$ to pre-compute and select among $M \ge 2$ branches. Under the Heaviest-Chain fork choice rule, candidate block $B_h^{(j^*)}$ will be rejected and orphaned by every honest node unless $\mathcal{A}$ possesses a sequential hardware speedup satisfying:*
$$\rho > 1 + \frac{\Delta t_{\text{delay}}}{\tau_{\text{honest}}}$$

### Proof:
1. **Weight Comparison at Gossip Delivery:**
   When the adversary's chosen block $B_h^{(j^*)}$ arrives at an honest node $v_i$, node $v_i$ evaluates the fork choice rule (`Preliminaries.md §2.2`, `ADR-004`):
   $$\mathcal{C}^* = \arg\max_{\mathcal{C}} W(\mathcal{C})$$
2. **Case 1: Adversary broadcasts before timeout ($\Delta t_{\text{delay}} \le W_{\text{reveal}}$).**
   - The adversary must complete the VDF evaluation before the honest network's reveal deadline:
     $$\tau_{\text{eval}} \le W_{\text{reveal}}$$
   - In Determ, the protocol parameters are strictly configured such that $T$ iterations at commodity speed requires wall-clock time:
     $$\tau_{\text{honest}} = \frac{T}{V_{honest}} = T_{\text{target}} \gg W_{\text{reveal}}$$
     (Nominal configuration: $T_{\text{target}} = 3000\text{ ms}$, while $W_{\text{reveal}} = 200\text{ ms}$).
   - For the adversary to finish $T$ iterations within the narrow reveal window $W_{\text{reveal}}$, the adversary's hardware speed must satisfy:
     $$\tau_{\text{eval}} = \frac{T}{V_{adv}} \le W_{\text{reveal}} \implies V_{adv} \ge \frac{T}{W_{\text{reveal}}} = V_{honest} \cdot \frac{T_{\text{target}}}{W_{\text{reveal}}}$$
     $$\rho = \frac{V_{adv}}{V_{honest}} \ge \frac{3000\text{ ms}}{200\text{ ms}} = 15.0$$
   - By **Lemma 2.1** of `PoSW_Nakamoto_Safety.md`, physical memory latency floors constrain ASIC acceleration to $\rho < 1.45$. An advantage of $\rho \ge 15.0$ is physically impossible in silicon CMOS.
3. **Case 2: Adversary broadcasts after timeout ($\Delta t_{\text{delay}} > W_{\text{reveal}}$).**
   - Because $\tau_{\text{eval}} > W_{\text{reveal}}$, the honest network times out and extends the fallback branch or round $r+1$.
   - When $B_h^{(j^*)}$ is broadcasted, honest nodes already hold a canonical chain tip with cumulative work:
     $$W_{\text{honest}} \ge W(B_{h-1}) + T_{\text{fallback}} + T_{h+1}$$
   - The adversary's candidate carries cumulative work:
     $$W_{\text{adv}} = W(B_{h-1}) + T_h$$
   - Since $T_{\text{fallback}} + T_{h+1} > T_h$:
     $$W_{\text{honest}} > W_{\text{adv}}$$
   - By the Heaviest-Chain rule, honest nodes reject $B_h^{(j^*)}$ and do not reorganize.
   - For $\mathcal{A}$ to overtake the honest chain, $\mathcal{A}$ must compute block $h$ AND block $h+1$ privately:
     $$\text{Time}_{\mathcal{A}}(2 \text{ blocks}) = \frac{2T}{V_{adv}} = \frac{2T}{\rho V_{honest}}$$
     In that same wall-clock time, the honest network generates $2 \rho$ blocks of work. Since $\rho < 1.45$, the adversary remains behind.
   - Hence, $B_h^{(j^*)}$ is permanently orphaned. $\blacksquare$

---

## 5. Economic Game-Theoretic Analysis

We now formalize the economic game between honest block publication and branch pre-computation.

### 5.1 Payoff Matrix Parameters
Let:
- $R_{\text{block}}$: The block subsidy minted to block co-creators (FA-Apply-7).
- $F_{\text{tx}}$: The aggregate transaction fees collected in block $B_h$ (FA-Apply-6).
- $C_{\text{vdf}}$: The capital, operational, and energy cost of running 1 full VDF sequential evaluation of length $T$.
- $V_{\text{bias}}$: The economic utility gained by the adversary if the 1-bit bias succeeds (e.g. MEV extraction or lottery manipulation).
- $P_{\text{orphan}}(\Delta t)$: The probability that block $B_h$ is orphaned when delayed by $\Delta t$.

### 5.2 Expected Utility of Honest Participation
An honest validator pair produces 1 block candidate, evaluates 1 VDF sequence, and broadcasts immediately upon completion ($\Delta t = 0$):
$$P_{\text{orphan}}(0) \le \epsilon_{\text{net}} \approx 0.001$$
$$\mathbb{E}[\mathcal{U}_{\text{honest}}] = (1 - \epsilon_{\text{net}})(R_{\text{block}} + F_{\text{tx}}) - C_{\text{vdf}} \approx R_{\text{block}} + F_{\text{tx}} - C_{\text{vdf}} > 0$$

### 5.3 Expected Utility of Pre-Computation Attack
To pre-compute $M$ candidate branches, the adversary must:
1. Incur computational cost for $M$ parallel VDF runs: $M \cdot C_{\text{vdf}}$.
2. Delay broadcast by $\Delta t_{\text{delay}} \ge \tau_{\text{eval}} - W_{\text{reveal}}$.
3. From Theorem 4.1, for any realistic hardware ($\rho < 1.45$), the delay exceeds the acceptance threshold, forcing:
   $$P_{\text{orphan}}(\Delta t_{\text{delay}}) \to 1.0$$

The expected utility of the pre-computation attack is:
$$\mathbb{E}[\mathcal{U}_{\text{precompute}}] = (1 - P_{\text{orphan}}(\Delta t_{\text{delay}})) \cdot \left( R_{\text{block}} + F_{\text{tx}} + V_{\text{bias}} \right) - M \cdot C_{\text{vdf}}$$

Substituting $P_{\text{orphan}} \approx 1.0$:
$$\mathbb{E}[\mathcal{U}_{\text{precompute}}] \approx - M \cdot C_{\text{vdf}} - (R_{\text{block}} + F_{\text{tx}})$$

### 5.4 Net Deficit & Irrationality Condition

**Theorem 5.1 (Economic Irrationality of 1-Bit Bias).**
*An adversary will strictly prefer honest publication over branch pre-computation iff:*
$$\mathbb{E}[\mathcal{U}_{\text{honest}}] - \mathbb{E}[\mathcal{U}_{\text{precompute}}] > 0$$
*which reduces to:*
$$(R_{\text{block}} + F_{\text{tx}}) + (M - 1) C_{\text{vdf}} > (1 - P_{\text{orphan}}) V_{\text{bias}}$$

Because $P_{\text{orphan}} \to 1$ under the Heaviest-Chain fork choice rule, the right-hand side vanishes:
$$(1 - P_{\text{orphan}}) V_{\text{bias}} \approx 0$$
While the left-hand side is strictly bounded below by the entire block reward and transaction fees:
$$(R_{\text{block}} + F_{\text{tx}}) > 0$$

### Conclusion
Even if the adversary can evaluate $M = 1000$ branches in parallel, and even if a successful 1-bit bias yields significant MEV $V_{\text{bias}}$, the precomputed block cannot overtake the broadcasted canonical chain. The adversary inevitably forfeits $100\%$ of the block reward $R_{\text{block}} + F_{\text{tx}}$ and burns $M \cdot C_{\text{vdf}}$ in wasted electricity. 

Therefore, pre-computation mathematically results in orphaned blocks, rendering the 1-bit bias economically irrational.

---

## 6. Synthesis: From Cryptographic Impossibility to Economic Impossibility

| Metric | Legacy "Zero-Bit Bias" Claim | Restated PoSW Economic Soundness |
|---|---|---|
| **Underlying Premise** | Information-theoretic hiding via VDF time-lock | Sequential work accumulation & Heaviest-Chain fork choice |
| **Adversary Model** | Majority/Colluding Pair ($A$ and $C$) | Same: $\mathcal{A}$ controls both $A$ and $C$ |
| **Attack Feasibility** | Claimed impossible ($\Delta t_{\text{vdf}} > \text{timeout}$) | Feasible to compute in private, but broadcast is delayed |
| **Chain Consequence** | Zero bias claimed | Delayed block is strictly orphaned by canonical tip |
| **Economic Outcome** | Unspecified | Adversary loses block subsidy + fees + burns $M \times$ energy |
| **Security Foundation** | Refuted by C99 experiment (`K2_VDF_Soundness.md`) | Provably sound under Game-Theoretic Rationality & PoSW |
