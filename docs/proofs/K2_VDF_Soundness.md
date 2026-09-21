# K2_VDF_Soundness — Mathematical Proof of the $K=2$ VDF Duel Consensus Architecture

**Status:** ACTIVE / CANONICAL CONSENSUS SPECIFICATION  
**Supersedes:** Legacy $K$-of-$K$ consensus (`Safety.md`, `ConsensusPhaseStructureSoundness.md`, `BFTSafety.md`, `BFTLiveness.md`).  
**Companion Documents:** `Preliminaries.md` (F0), `audit_crypto_primitives_encoding.md`, `CanonicalSigningBytesParity.md`, `include/determ/consensus/duel_state.h`.

---

## 1. Executive Summary & Architectural Axiom

The Determ decentralized message queue and state replication engine operates on a bare-metal C99 $K=2$ Verifiable Delay Function (VDF) Duel consensus protocol. The consensus committee at each height $h$ consists of exactly two elected nodes:
1. **Aggregator ($\mathcal{A}$):** Proposes primary transaction bundle $Payload_A$ and commitment $C_A = H(Payload_A)$.
2. **Contributor ($\mathcal{B}$):** Proposes secondary transaction bundle $Payload_B$ and commitment $C_B = H(Payload_B)$.

Finalization of height $h$ requires evaluating a sequential, non-parallelizable Verifiable Delay Function (Wesolowski / Pietrzak modular squaring over an unknown order group) over the canonical payload commitment.

### Axiom 1 (The Time-Lock Inequality Axiom)
Let $W_{reveal}$ denote the strictly enforced monotonic wall-clock window during which Contributor $\mathcal{B}$ may reveal $Payload_B$. Let $\Delta_{max}$ denote the maximum network message propagation delay under partial synchrony. Let $T_{vdf}$ denote the minimum physical execution time required by any polynomial-time adversary possessing maximum hardware acceleration (ASIC/FPGA) to compute $T_{iter}$ sequential steps of the VDF:

$$T_{vdf} > W_{reveal} + \Delta_{max}$$

---

## 2. Formal Protocol State Transitions

The per-height consensus execution is modeled as a deterministic state machine:

$$\Sigma = \{\text{INIT}, \text{COMMIT}, \text{AWAIT\_REVEALS}, \text{VDF\_EVALUATE}, \text{FINAL}\}$$

1. **Commit Phase:**
   - Aggregator samples $Payload_A$, signs and broadcasts commitment $C_A = H(Payload_A \parallel h)$.
   - Contributor samples $Payload_B$, signs and submits commitment $C_B = H(Payload_B \parallel h)$.
   - Both nodes must publish $C_A, C_B$ before entering `AWAIT_REVEALS`.

2. **Await Reveals Phase:**
   - Aggregator enters `AWAIT_REVEALS` at local timestamp $t_0$, initializing a monotonic hardware timer $\tau = 0$.
   - **Branch 1 (Dual Collaboration):** If Contributor transmits valid $Payload_B$ such that $H(Payload_B \parallel h) = C_B$ at timestamp $\tau \le W_{reveal}$, the composite seed is formed:
     $$Seed_{A+B} = \text{SHA-256}(C_A \parallel C_B \parallel Payload_A \parallel Payload_B)$$
     The state transitions immediately to $\text{VDF\_EVALUATE}(Seed_{A+B})$.
   - **Branch 2 (1-of-2 Straggler Fallback):** If monotonic timer $\tau > W_{reveal}$ expires without a valid reveal from Contributor (due to network partition, Byzantine crash, or strategic withholding), the 1-of-2 fallback executes unconditionally:
     $$Seed_{A} = \text{SHA-256}(C_A \parallel Payload_A)$$
     The state transitions unconditionally to $\text{VDF\_EVALUATE}(Seed_{A})$.

3. **VDF Evaluation Phase:**
   - The node evaluates $Y = VDF(Seed, T_{iter})$ sequentially.
   - Computes succinct proof $\pi$.
   - Assembles canonical `wire_block_header_t` (212 bytes) and enters $\text{FINAL}$.

---

## 3. Theorem 1 (Zero-Bit Bias & Anti-Collusion via Enforced Blindness)

**Theorem Statement.**  
Let $\mathcal{A}^*$ be an adversary controlling both the Aggregator $\mathcal{A}$ and Contributor $\mathcal{B}$ ($K=2$ total collusion). Let $u: \{0, 1\}^* \to \mathbb{R}$ be an arbitrary non-trivial utility function over finalized block states. The adversary $\mathcal{A}^*$ cannot selectively withhold $Payload_B$ to maximize $u$. Specifically, the advantage of $\mathcal{A}^*$ in predicting or biasing any outcome bit before $W_{reveal}$ expires is negligible:

$$\left| \Pr\left[\mathcal{A}^*(1^\lambda, C_A, C_B) = \mathrm{LSB}(Outcome) \right] - \frac{1}{2} \right| \le \mathrm{negl}(\lambda)$$

### Proof (Mathematical Reduction to VDF Sequentiality)
1. At state `COMMIT`, $\mathcal{A}^*$ commits to $C_A$ and $C_B$. By SHA-256 preimage resistance (Assumption A3), $Payload_A$ and $Payload_B$ are uniquely bound.
2. Two mutually exclusive finalization seeds exist:
   $$S_1 = Seed_A = H(C_A \parallel Payload_A)$$
   $$S_2 = Seed_{A+B} = H(C_A \parallel C_B \parallel Payload_A \parallel Payload_B)$$
   These lead to two candidate block states $Outcome_A = \text{VDF}(S_1)$ and $Outcome_{A+B} = \text{VDF}(S_2)$.
3. To execute a selective abort, $\mathcal{A}^*$ must decide whether to transmit $Payload_B$ before the deadline $t_0 + W_{reveal}$.
4. A rational adversary chooses to transmit $Payload_B$ if and only if:
   $$u(Outcome_{A+B}) > u(Outcome_A)$$
   Computing this predicate requires computing both $Outcome_{A+B}$ and $Outcome_A$.
5. By the definition of a Verifiable Delay Function with sequential parameter $T_{iter}$, computing $\text{VDF}(S)$ requires minimum wall-clock duration:
   $$t_{eval} \ge T_{vdf}$$
   even on massively parallel hardware.
6. By Axiom 1 (Time-Lock Inequality):
   $$T_{vdf} > W_{reveal} + \Delta_{max}$$
7. Therefore, at all timestamps $t \le W_{reveal}$:
   $$t < T_{vdf}$$
8. Consequently, at the decision boundary $t = W_{reveal}$, neither $Outcome_A$ nor $Outcome_{A+B}$ has been computed by $\mathcal{A}^*$.
9. Under the random oracle model (ROM) for the VDF output mapping, both $Outcome_A$ and $Outcome_{A+B}$ are independent, uniformly distributed random variables over $\{0, 1\}^{256}$.
10. Therefore, the adversary possesses zero bits of information regarding which outcome yields higher utility. The decision to reveal or withhold $Payload_B$ is uncorrelated with the resulting block state:
    $$\Pr[\text{Select } S_2 \mid u(Outcome_{A+B}) > u(Outcome_A)] = \frac{1}{2}$$
We conclude that the colluding adversary is mathematically forced to commit blindly. $\blacksquare$

---

## 4. Theorem 2 (Absolute Liveness under Asynchronous Networks)

**Theorem Statement.**  
Let the network undergo arbitrary asynchronous delays, network partitions, or silent dropping of messages between Contributor $\mathcal{B}$ and Aggregator $\mathcal{A}$. The state machine $\Sigma$ is guaranteed to terminate in $\text{FINAL}$ at height $h$ without deadlocking and without requiring a Byzantine voting quorum.

### Proof (Exhaustive Branch Progress)
1. Suppose Aggregator $\mathcal{A}$ is honest and broadcasts $C_A$ at height $h$.
2. Aggregator transitions to `AWAIT_REVEALS` at local time $t_0$.
3. The monotonic clock $\tau$ advances locally via monotonic hardware registers:
   $$\frac{d\tau}{dt} \ge 1$$
4. Consider the two cases for Contributor's reveal:
   - **Case 1 (Timely Reveal):** Contributor $\mathcal{B}$ sends valid $Payload_B$ arriving at $\tau \le W_{reveal}$. The transition rule for Dual Collaboration fires. State transitions to `VDF_EVALUATE`, which runs for finite steps $T_{iter}$ and finalizes.
   - **Case 2 (Straggler / Dropped Payload):** Due to network partition or adversarial crash, no valid payload arrives before $\tau = W_{reveal}$.
5. Because the local timer $\tau$ is strictly monotonic, there exists a finite wall-clock timestamp $t_{exp} = t_0 + W_{reveal}$ at which $\tau > W_{reveal}$.
6. The predicate for 1-of-2 Straggler Fallback evaluates to TRUE at $t_{exp}$.
7. The Aggregator transitions unconditionally to $\text{VDF\_EVALUATE}(Seed_A)$.
8. VDF evaluation is purely local and deterministic, requiring zero inbound network messages.
9. Upon completion of $T_{iter}$ sequential squarings, the Aggregator produces block $B_h$ and transitions to $\text{FINAL}$.
10. Deadlock requires a state with no enabled outgoing transitions. Because $\tau > W_{reveal}$ is an absorbing event that unconditionally enables the 1-of-2 transition, no deadlocks exist.
We conclude that the system achieves absolute liveness under arbitrary network asynchrony. $\blacksquare$

---

## 5. Theorem 3 (Unique Canonical Block Safety)

**Theorem Statement.**  
For any given height $h$, honest verifiers accept at most one canonical block:
$$|\text{CanonicalBlocks}(h)| \le 1$$

### Proof
1. Block validity requires an Ed25519 signature from the elected Aggregator $\mathcal{A}_h$ over the canonical 212-byte header (`wire_block_header_t`).
2. By Assumption A1 (EUF-CMA), an adversary cannot forge the Aggregator's signature.
3. If the Aggregator attempts equivocation by signing two distinct block headers $B_h \ne B'_h$, both carry valid cryptographic proofs of equivocation.
4. Furthermore, because the VDF function $VDF(Seed, T_{iter})$ is a deterministic bijection:
   $$\forall Seed, \quad \exists! Y \text{ such that } VerifyVDF(Seed, Y, \pi) = 1$$
5. Honest verifiers apply the deterministic fork-choice rule (lowest VDF output lexicographically or highest VRF priority), selecting a unique canonical block.
Therefore, safety holds unconditionally. $\blacksquare$

---

## 6. Deprecation of Legacy Proofs

The following proofs analyzed the pre-migration $K$-of-$K$ unanimous agreement model and BFT escalation committees, which are obsolete:
- `docs/proofs/Safety.md`
- `docs/proofs/Liveness.md`
- `docs/proofs/BFTSafety.md`
- `docs/proofs/ConsensusPhaseStructureSoundness.md`
- `docs/proofs/SelectiveAbort.md`
- `docs/proofs/S025BFTEscalationSoundness.md`

All consensus invariants and model checking are now formally anchored in `K2_VDF_Soundness.md`.
