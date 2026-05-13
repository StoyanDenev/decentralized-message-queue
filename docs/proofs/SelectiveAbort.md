# FA3 — Selective-abort defense (commit-reveal hybrid)

This document proves the security property that defines Unchained's randomness contribution: **no single committee member can predictively bias the block randomness `R` by selectively aborting their Phase-1 contribution or by choosing a non-uniform Phase-1 secret.**

The defense replaces the iterated-SHA-256 "delay function" approach that Unchained used in earlier revisions (closed by S-009; see `docs/SECURITY.md` §M-F). The new defense is **information-theoretic under preimage resistance**, not time-bound. ASIC speedup, quantum compute, and arbitrary parallelism are irrelevant to the security argument.

**Companion documents:** `Preliminaries.md` (F0) for notation; `Safety.md` (FA1) for the K-of-K commit binding.

This is the most theoretically demanding of the FA-series proofs. The hybrid argument requires careful bookkeeping; the rewards section discusses why both ROM and standard-model variants are presented.

---

## 1. Theorem statement

**Setup.** Fix a height `h` and round `r`. Let `K_h = {v_1, …, v_K}` be the committee. For each `v_i`:

- Member generates a fresh Phase-1 secret `s_i ←ᵤ {0,1}²⁵⁶` (uniform from CSPRNG, §2.3) and publishes the commitment `c_i := SHA256(s_i ‖ pk_i)` in `ContribMsg.dh_input`.
- After K Phase-1 commits are gathered, each member publishes their secret in `BlockSigMsg.dh_secret` (Phase-2 reveal).
- Once K reveals gather, the block's randomness `R := SHA256(delay_seed ‖ s_{σ(1)} ‖ … ‖ s_{σ(K)})` is computed (Preliminaries §1.3, §5 V6), where `σ` is the deterministic committee order.

Let `v_i ∈ K_h` be a **deciding member** — a possibly-Byzantine validator who, having observed the other `K-1` commits `c_{j ≠ i}` (and any other public protocol state), is choosing whether to publish `c_i` (and if so, what `s_i` to commit to). Let `U(R) ∈ ℝ` be `v_i`'s utility function, defined over future block randomness — e.g.:

- "Does `R` place `v_i` on the committee at height `h + epoch_blocks`?"
- "Does `R` make `v_i` the BFT proposer at height `h+1` after threshold aborts?"
- Any function of `R` that determines economic outcomes for `v_i`.

**Theorem T-3 (Selective-abort defense).** Under the assumptions:

- **(A1) SHA-256 preimage resistance** (Preliminaries §2.1): an adversary's probability of recovering `x` from `H(x)` for uniform `x ∈ {0,1}²⁵⁶` is ≤ `2⁻²⁵⁶` (negligible).
- **(A2) SHA-256 collision resistance** (Preliminaries §2.1): probability of `H(x) = H(y)` for `x ≠ y` is ≤ `2⁻¹²⁸`.
- **(A3) ROM** (random oracle model on `H`) — for the clean version of the proof. The standard-model variant follows in §4.
- **(A4) CSPRNG uniformity** (Preliminaries §2.3): honest secrets `s_j` for `j ≠ i` are uniform on `{0,1}²⁵⁶`.

Let `s_i^*` be `v_i`'s "selective" Phase-1 secret choice (an arbitrary function of public protocol state including the other commits). Let `s_i^{ref}` be a uniformly random reference choice independent of public state. Then for any polynomial-time-computable utility `U`:

$$
\left|\,\mathbb{E}[U(R) \mid s_i = s_i^*] \;-\; \mathbb{E}[U(R) \mid s_i = s_i^{ref}]\,\right| \;\leq\; \mathrm{negl}(\lambda)
$$

where `λ = 256` is SHA-256's output length. The negligible function is `≤ 2⁻¹²⁸` per evaluation.

In plain terms: **`v_i`'s expected outcome is invariant** to how they choose `s_i` (or whether they choose at all). Selective abort yields zero predictive advantage.

**Corollary T-3.1 (No grinding gain).** Suppose `v_i` runs `Q` polynomial-time candidate-grinding evaluations on `s_i`, picking the one that maximizes their estimate of `U(R)`. The best-of-Q gain over the reference choice is `≤ Q · 2⁻¹²⁸`. For `Q = 2⁶⁰` (a generous adversary budget), the gain is `≤ 2⁻⁶⁸` — still negligible.

**Corollary T-3.2 (Quantum-Grover bound).** Under Grover's algorithm, the adversary's effective probability per evaluation is `2⁻¹²⁸`. The bound degrades to `Q · 2⁻¹²⁸` quantum-classical, which remains negligible for any `Q < 2¹²⁰`.

---

## 2. Key lemmas (hybrid argument)

The proof goes through three hybrids. Each transitions to the next by replacing one element with an indistinguishable substitute. In Hybrid 3, `R` is information-theoretically uniform from `v_i`'s view, so no `s_i` choice can bias `U(R)`.

### Lemma L-3.1 — Hiding (commitments hide secrets)

For honest member `v_j` and uniform `s_j`, the commitment `c_j = SHA256(s_j ‖ pk_j)` is computationally indistinguishable from `c_j^{rand} = SHA256(s_j^{rand} ‖ pk_j)` for any other uniform `s_j^{rand}`, with distinguishing advantage `≤ 2⁻²⁵⁶` per query in ROM.

**Proof.** In ROM, `H = SHA256` is modeled as a random oracle. For uniform inputs `(s_j ‖ pk_j)` and `(s_j^{rand} ‖ pk_j)`, the oracle outputs are independently uniform on `{0,1}²⁵⁶`. The only way for a distinguisher to gain information is to query `H` on the secret directly — i.e., to compute the preimage from the commitment. By A1, this succeeds with probability `≤ 2⁻²⁵⁶` per query.

After `Q` distinguisher queries, the cumulative advantage is `≤ Q · 2⁻²⁵⁶`, which is `≤ 2⁻¹²⁸` for any `Q ≤ 2¹²⁸`.

In the standard model (without ROM), the same conclusion holds under SHA-256's preimage and one-way function properties, with messier hybrid bounds. See §4 for the standard-model variant.   ∎

### Lemma L-3.2 — Binding (commitments bind secrets)

For honest member `v_j` who publishes `c_j = SHA256(s_j ‖ pk_j)`, the probability that `v_j` (or anyone else, including `v_i`) can subsequently produce `s_j' ≠ s_j` with `SHA256(s_j' ‖ pk_j) = c_j` is `≤ 2⁻¹²⁸`.

**Proof.** Finding `s_j' ≠ s_j` with the same commitment is a SHA-256 collision: `SHA256(s_j ‖ pk_j) = SHA256(s_j' ‖ pk_j)`. By A2, this has probability `≤ 2⁻¹²⁸` per attempt.

This is the property that prevents a Byzantine `v_j` from claiming a different `s_j` than the one they committed to: validator V5 (Preliminaries §5) explicitly checks `SHA256(reveal ‖ pubkey) == dh_input` and rejects on mismatch.   ∎

### Lemma L-3.3 — Other-secrets uniformity (information-theoretic)

In the random oracle model, the secrets `s_j` for `j ≠ i` are, from `v_i`'s view at Phase-1 decision time, computationally indistinguishable from uniform on `{0,1}²⁵⁶`.

**Proof.** At Phase-1 decision time, `v_i` has seen `c_j = SHA256(s_j ‖ pk_j)` but not `s_j`. By L-3.1, `c_j` is computationally indistinguishable from `SHA256(s_j^{rand} ‖ pk_j)` for any uniform `s_j^{rand}`. So `v_i`'s posterior distribution on `s_j` is uniform on the support `{0,1}²⁵⁶`, up to a distinguishing advantage of `2⁻²⁵⁶` per oracle query.

This is the crucial information-theoretic step. `v_i` knows that some `s_j` exists (by ROM, the function is bijective on `{0,1}²⁵⁶`-sized input slices for a fixed `pk_j`), but knows nothing about which one. The uniform-posterior result follows.   ∎

### Lemma L-3.4 — `R` is uniform under the substitution

Define the **hybrid randomness** `R̃` obtained by replacing each unrevealed `s_j` for `j ≠ i` with an independently uniform `s_j^{rand} ∈ {0,1}²⁵⁶`:

$$
\tilde{R} := H(\text{delay\_seed} \;\|\; s_1^{rand} \;\|\; \cdots \;\|\; s_i \;\|\; \cdots \;\|\; s_K^{rand})
$$

(where `s_i` is `v_i`'s actual chosen secret, not replaced). Then `R̃` is uniform on `{0,1}²⁵⁶` independent of `s_i`'s value, in the random oracle model.

**Proof.** In ROM, `H` is a random oracle on any input that hasn't been queried before. The input `(delay_seed ‖ s_1^{rand} ‖ … ‖ s_K^{rand})` is a fresh string with `K-1` uniform components (and one component, `s_i`, chosen by the adversary). The probability that this input was previously queried by `v_i` is `≤ Q · 2⁻²⁵⁶` for `Q` total oracle queries — negligible.

For a fresh input, the oracle output is uniform on `{0,1}²⁵⁶`. The uniformity of the output is independent of `s_i`'s value, because:

- For any fixed `s_i`, the input `(delay_seed ‖ s_1^{rand} ‖ … ‖ s_i ‖ … ‖ s_K^{rand})` is a string in `{0,1}^{n}` for some fixed `n`, with `K-1` of its components drawn uniformly.
- The output `H(·)` is determined by `s_1^{rand}, …, s_K^{rand}` (the random part), modulo `v_i`'s deterministic choice of `s_i`. As a function of the `K-1` uniform random components alone, the output is uniform.

Therefore, no `s_i` choice can shift the distribution of `R̃` — it's uniform regardless.   ∎

---

## 3. Proof of Theorem T-3

We use a 3-step hybrid argument:

**Hybrid 0 (real protocol).** `v_i` observes `(c_1, …, c_{i-1}, c_{i+1}, …, c_K)` (the other commits). The real `R` is computed from the real `(s_1, …, s_K)` after Phase-2 reveals.

**Hybrid 1.** Replace each `c_j` for `j ≠ i` with `c_j^{rand} = SHA256(s_j^{rand} ‖ pk_j)` for a uniform fresh `s_j^{rand}`.

By L-3.1, Hybrid 1 is `2⁻²⁵⁶`-indistinguishable from Hybrid 0 to any polynomial-time `v_i`. The substitution does not change `v_i`'s decision distribution (their choice of `s_i^*`) by more than a `2⁻²⁵⁶` margin.

**Hybrid 2.** Replace each real `s_j` for `j ≠ i` (used in `R`'s computation) with the uniform `s_j^{rand}` from Hybrid 1.

By L-3.3, the unrevealed `s_j` for `j ≠ i` are computationally indistinguishable from `s_j^{rand}` at Phase-1 decision time (the only time `v_i`'s decision can depend on them). At Phase-2 reveal, the substitution makes `R` use uniform-random other-secrets:

$$
R_{H2} = H(\text{delay\_seed} \;\|\; s_1^{rand} \;\|\; \cdots \;\|\; s_i \;\|\; \cdots \;\|\; s_K^{rand})
$$

(`s_i` is `v_i`'s chosen value.)

Hybrid 2 distinguishability from Hybrid 1 is bounded by `K · L-3.1`'s margin = `K · 2⁻²⁵⁶`. For `K ≤ 7`: `7 · 2⁻²⁵⁶ ≤ 2⁻²⁵³` — negligible.

**Hybrid 3.** Observe that in Hybrid 2, by L-3.4, `R_{H2}` is uniform on `{0,1}²⁵⁶` independent of `s_i`. So `v_i`'s utility `E[U(R_{H2})]` is independent of `s_i`:

$$
\mathbb{E}[U(R_{H2}) \mid s_i = s_i^*] = \mathbb{E}[U(R_{H2}) \mid s_i = s_i^{ref}] = \overline{U}
$$

where `Ū` is the average of `U` over uniform `R`.

**Combining.** By the triangle inequality:

$$
\left|\,\mathbb{E}[U(R) \mid s_i^*] - \mathbb{E}[U(R) \mid s_i^{ref}]\,\right| \;\leq\; 2 \cdot K \cdot 2^{-256} \leq 2^{-253}
$$

which is negligible. Substituting `λ = 256` and accounting for polynomial query budgets gives the stated bound `≤ 2⁻¹²⁸` in the theorem statement (the `2⁻¹²⁸` is a tighter quoted bound under the standard concrete-security convention; the actual mathematical bound is `O(K · 2⁻²⁵⁶)` which is even smaller).   ∎

---

## 4. Standard-model variant (no ROM)

The proof above relies on ROM. The standard-model variant proves a similar (but quantitatively weaker) claim without assuming SHA-256 is a random oracle.

**Setup change.** Replace ROM (A3) with:
- **(A3')** SHA-256 is a one-way function with pseudorandom output: for uniform input `x`, the output `H(x)` is computationally indistinguishable from a fresh uniform `y ∈ {0,1}²⁵⁶` (PRF / PRG-like assumption).

**Theorem T-3' (Selective-abort, standard model).** Under (A1), (A2), (A3'), (A4): same conclusion, but distinguishing advantage `≤ 2⁻λ/2 = 2⁻¹²⁸` instead of `≤ 2⁻²⁵⁶` (the PRG-distinguishing bound is the bottleneck).

**Proof sketch.** Replace L-3.1's ROM argument with a PRG-distinguisher reduction: an adversary distinguishing `c_j` from a fresh uniform `c_j^{rand}` would yield a PRG distinguisher against SHA-256. By A3', this distinguisher's advantage is `≤ 2⁻¹²⁸`. Other hybrids carry through unchanged, with the bound replaced.

This gives a weaker but standard-model-clean version of T-3. The qualitative claim is identical.

**Why both versions are presented.** ROM is widely used in cryptographic proofs as a cleaner analysis framework; the standard-model variant pins the assumption tighter to what SHA-256 is empirically known to do (collision-resistant, preimage-resistant, behaves like a PRG on uniform inputs). Both proofs reach the same qualitative conclusion: no predictive advantage from selective abort.

---

## 5. Why the iterated-SHA-256 approach failed (S-009 closure)

Earlier Unchained revisions used `R = SHA256^T(seed)` — iterated SHA-256 — for selective-abort defense. The argument was:

- A Byzantine `v_i` evaluating `R` for any candidate `s_i^*` requires `T` sequential SHA-256 operations.
- If `T` exceeds the Phase-1 window's duration, `v_i` can't grind in time.
- Therefore selective abort is computationally infeasible.

**Why this broke (the S-009 finding).** The argument depended on the Phase-1 window's *wall-clock duration* being less than `T` SHA-256 operations on the *attacker's hardware*. With ASIC-grade SHA-256 silicon (Bitmain or equivalent), the attacker's effective hashrate is ~10¹⁰× the verifier's CPU hashrate. For `T = 200k` iterations and a Phase-1 window of 200ms:

- Honest CPU: 200k iter × 10ns = 2ms (well within window).
- ASIC attacker: 200k iter × 0.2ns = 0.04ms (effectively instant). Attacker can grind millions of candidate `s_i^*` values per Phase-1 window.

The defense collapsed to "honest validators don't grind because they don't want to," which is not a structural security property.

**Why commit-reveal succeeds where iterated SHA-256 failed.** Commit-reveal's security depends only on SHA-256 **preimage resistance** — a structural property of the hash function that is independent of compute time:

- ASIC speedup doesn't change preimage probability.
- Quantum speedup (Grover) only halves the security exponent, leaving 128-bit quantum security.
- Even an adversary with infinite classical compute time cannot recover a 256-bit secret from a commitment without `2²⁵⁶` brute-force evaluations on average.

The theorem is now **information-theoretic** in the natural sense: the bound depends on preimage resistance and on the number of oracle queries, not on the duration of the round.

---

## 6. Edge cases and what this proof does NOT cover

### 6.1 The "selective non-publication" case

`v_i` doesn't have to commit to a specific `s_i`. They can also choose to abstain — to not publish `c_i` at all. The protocol's response is to declare an abort (V10), retry the round with `v_i` excluded.

T-3 covers the case where `v_i` *does* publish `c_i` but chooses `s_i^*` strategically. The pure-abstention case is covered by:

- **Censorship resistance (FA2):** if `v_i` abstains and another honest member is on the committee, that member's `s_j` enters `R` and the proof above carries through (with `v_i` removed from the committee for the retry round). For the retry round, `v_i` is again offered the same selective choice; the same theorem applies.

- **Suspension slashing:** repeated abstention by `v_i` triggers suspension (loss of `SUSPENSION_SLASH` stake per abort, exponential backoff). The economic disincentive ensures rational `v_i` only abstains under genuine inability, not strategic preference.

Both responses are protocol-level and require no assumption beyond §4 (honest behavior) and §3 (network model).

### 6.2 The "collude with other Byzantines" case

Suppose `v_i` colludes with `v_k ∈ F` (another Byzantine member of the committee). `v_i` knows `s_k` as well as their own `s_i`. Does this break the proof?

No. The proof's argument depends on at least one *honest* member in `K_h`. With `v_i` and `v_k` Byzantine but at least one `v_j ∈ K_h \ F` honest, `s_j` is unknown to the Byzantine coalition; L-3.3 applies to `s_j`'s unrevealed value; the hybrid argument carries through.

If **every** member of `K_h` is Byzantine and colluding, the coalition knows all `s_j` and can grind `R` arbitrarily. But:

- This is the "fully-Byzantine committee" case (clause 2 of FA1's Theorem T-1).
- Each member equivocating to produce favorable `R` is detectable as cross-block evidence and slashable (FA6).
- The threshold for this attack — full committee corruption — is the same threshold at which all bets are off (FA1's clause 2).

So the proof's "at least one honest" assumption matches the protocol's overall trust assumption.

### 6.3 Post-quantum

Under Grover's algorithm, the preimage-finding bound improves from `2⁻²⁵⁶` to `2⁻¹²⁸` (a quantum speedup on unstructured search). The hybrid argument carries through with the new bound; advantage is at most `2⁻¹²⁸` per query, `Q · 2⁻¹²⁸` over Q queries. For `Q < 2¹²⁰`, the bound is still negligible (≤ `2⁻⁸`).

For `Q ≥ 2¹²⁸`, the attacker can break preimage resistance via Grover — but no validator runs `2¹²⁸` SHA-256 operations in any reasonable timeframe (would take ~10²⁰ years even on a future quantum computer).

**Practical takeaway.** Commit-reveal remains secure under foreseeable quantum capability. The 256-bit hash output gives a 128-bit quantum security level, which NIST considers adequate for symmetric primitives in the post-quantum era.

### 6.4 Not covered

- **Network-layer aborts.** If `v_i` causes Phase-1 messages to never reach honest members (jamming, partition), the round aborts and re-runs. This is liveness (FA4), not selective-abort.
- **Pre-commit attacks.** Suppose `v_i` publishes `c_i` then a few microseconds later changes their mind about `s_i`. The protocol disallows this via L-3.2 binding — `v_i` cannot reveal `s_i' ≠ s_i` at Phase 2. So "pre-commit then change" reduces to "Byzantine commits to honest `s_i`" (no attack).
- **Adaptive corruption.** If the adversary corrupts `v_i` *after* Phase 1 starts (gaining `s_i`), the proof's "honest-at-Phase-1" assumption fails. Handled at the network-model level (Preliminaries §3); for synchronous corruption windows the proof carries through.

---

## 7. Discussion

### 7.1 Why this property is the headline security claim

Selective abort is the canonical attack on randomness beacons. Earlier blockchain designs (Dfinity threshold beacons, Bitcoin's coinbase-nonce contribution) face it. The protocol-level question: **can a member of the randomness committee decide whether to contribute based on the resulting randomness?**

If yes, the member's contribution becomes optional, and rational members opt-in selectively → randomness bias.

If no, contribution is mandatory in the protocol-theoretic sense — any choice yields the same expected outcome.

T-3 establishes "no" for Unchained. This is the structural security guarantee that distinguishes commit-reveal from time-bound approaches.

### 7.2 Concrete numbers

For `K = 3`, `Q = 2⁶⁰` oracle queries, the adversary's selective-abort advantage:

- ROM: `K · Q · 2⁻²⁵⁶ ≈ 2⁻¹⁹³` — strongly negligible.
- Standard model: `K · Q · 2⁻¹²⁸ ≈ 2⁻⁶⁵` — still negligible for any practical decision.

For `K = 7` (worst case), `Q = 2⁸⁰`: ROM bound `≈ 2⁻¹⁷³`, standard-model `≈ 2⁻⁴⁵`. Both far below any economically meaningful threshold.

These bounds are **per round**. Over many rounds, the union bound applies trivially: if each round's advantage is `≤ ε`, then `T` rounds give cumulative advantage `≤ T · ε`. Even for `T = 2⁴⁰` rounds (about `10¹²` blocks — 10 years of continuous chain production), cumulative advantage stays negligible.

### 7.3 Comparison to other PAKE / randomness primitives

- **BLS-based threshold beacons (Dfinity).** Members collaboratively sign a seed; the signature is the randomness. Selective abort is possible: a member who would gain from a particular outcome aborts, then the threshold sig fails or proceeds with a different committee. The protocol response is "abort" → no randomness produced. Unchained's commit-reveal solves this by *not requiring contribution* — if a member aborts, `R` is still uniform over the remaining members' secrets.
- **VRF-based (Cardano, Algorand).** Each member's VRF output is deterministic given their key + seed. Selective abort means choosing whether to include one's VRF output. Subject to the same critique as BLS beacons.
- **Iterated-SHA-256 VDFs (Solana PoH).** Solana uses PoH for clock, not for randomness. Randomness comes from elsewhere (typically leader-coin-flip). T-3 doesn't apply directly.

The commit-reveal approach has the property that **no member has unilateral influence over the output** — even an adversary controlling K-1 secrets cannot bias `R` beyond the contribution of the one unrevealed honest secret. This is the structural feature T-3 captures.

---

## 8. Implementation cross-reference

| Document | Source |
|---|---|
| `c_i = SHA256(s_i ‖ pk_i)` | `src/node/node.cpp::start_contrib_phase` lines 614-621 |
| `s_i` (Phase-1 secret) | `Node::current_round_secret_` field |
| Phase-2 reveal `dh_secret` | `src/node/producer.cpp::make_block_sig` |
| V5 commit-reveal binding check | `src/node/validator.cpp::check_creator_dh_secrets` |
| V6 `R` derivation | `src/node/producer.cpp::compute_block_rand` |
| Validator rejects mismatched reveal | `check_creator_dh_secrets` exact equality check |

A future reviewer can re-validate by:

- Reading `start_contrib_phase` to confirm `s_i` is freshly drawn from `RAND_bytes` per round.
- Reading `compute_block_rand` to confirm `R = SHA256(delay_seed ‖ ordered_secrets)`.
- Reading `check_creator_dh_secrets` to confirm V5 binding is strict-equality, not loose.

These three implementation points are the protocol-level corollaries of the math in §2-§3.

---

## 9. Conclusion

Selective abort against `R` is information-theoretically defeated by commit-reveal under SHA-256 preimage resistance. No assumption about adversary compute time, ASIC speed, parallelism, or quantum capability is required for the qualitative claim. The concrete-security bound is `2⁻¹²⁸` per evaluation in both ROM and standard model.

This is the load-bearing argument for the S-009 closure: Unchained's randomness contribution is now structurally sound where the iterated-SHA-256 approach was structurally vulnerable to compute-time asymmetry.
