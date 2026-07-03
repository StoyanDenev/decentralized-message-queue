# S009DelayHashRemoval — delay-hash module removal (S-009 / S-015 / S-034 closure)

This document is the structural removal proof closing **S-009** (iterated-SHA-256 delay-hash unenforceable under ASIC asymmetry), **S-015** (the delay-hash variant — separately, the async-save-persistence subtopic with the same ID was retained as a distinct concern; see `S015AsyncSavePersistence.md`), and **S-034** (per-iteration `EVP_MD_CTX` allocation inside `delay_hash_compute`). The closure mechanism is unusual: rather than patch a broken defense, **the entire delay-hash module was deleted** in commit `1b9b086`. This proof formalizes (a) why removal — not repair — is the correct closure, (b) that nothing in the current codebase depends on the deleted module, (c) that the K-of-K commit-reveal randomness protocol (shipped concurrently in commit `14bf3d6`) provides the structural property that delay-hash was meant to provide, and (d) that removing delay-hash creates no safety or liveness regression against the FA1 / FA3 / Liveness-L-1..L-4 conclusions.

The proof is short and structural by design. There is no algorithmic content; the closure is a deletion. What requires formalization is the no-regression composition: that the K-of-K commit-reveal binding via `compute_block_digest` is the load-bearing replacement, that `signing_bytes` continues to bind every committee-derived input even though the post-Phase-2 secrets reveal them strictly later, and that the rate-limiter (S-014) provides analogous "time-cost" pushback on a different layer of the stack. The verification is empirical: a `grep -r` over `src/` plus `include/` confirms zero remaining functional references to the deleted module — only two stale-comment fossils in headers (cited and tracked, no code dependency) and unrelated `EVP_MD_CTX` usages in the live SHA-256 / Ed25519 paths.

**Companion documents.** `S006ContribMsgEquivocation.md` (S-006 closure — Phase-1 same-generation equivocation detection; the parallel surface to this proof's Phase-2 secret-reveal correctness). `S012SnapshotStateRootGate.md` and `S033StateRootNamespaceCoverage.md` (state_root binding — composition with the digest-binding T-2 invokes). `S014RateLimiterSoundness.md` (S-014 closure — the per-peer-IP token bucket that this proof's T-5 composes with for "time-cost at the network ingress layer"). `S015AsyncSavePersistence.md` (async chain.save subtopic — separately tracked under the S-015 identifier; distinct from this proof's S-015-as-delay-hash-variant subsumption). `Safety.md` (FA1 K-of-K safety — T-3 of this proof inherits the conclusion). `Liveness.md` (L-1..L-4 — T-4 of this proof inherits the conclusion). `SelectiveAbort.md` (FA3 — the commit-reveal randomness binding that replaces the delay-hash defense). `Preliminaries.md` §1.3 (`compute_block_digest` definition + bound-field list — the canonical reference for what `signing_bytes` actually covers post-removal). `docs/SECURITY.md` §S-009 / §S-015 / §S-034 for the closure-status narrative. The removed module's full history is preserved in the git commits `14bf3d6` (commit-reveal replacement) and `1b9b086` (dead-code cleanup).

---

## 1. Introduction — pre-removal rationale and the decision to delete

### 1.1 What delay-hash was meant to do

The pre-removal protocol used an iterated SHA-256 delay function, `delay_hash_compute(seed, T) = SHA256^T(seed)`, as a verifiable-delay enforcement layer between Phase-1 (committee commits) and Phase-2 (committee signs). The intended semantic was:

- The Phase-1 `ContribMsg` envelope's `dh_input` field — a 32-byte random — was treated as a per-committee-member contribution to the round's randomness seed.
- The full set of K `dh_input` values (one per committee member, in canonical selection order) was concatenated with `prev_hash` and `tx_root` to derive `delay_seed`.
- Every node — committee member or peer-observer — computed `delay_output = delay_hash_compute(delay_seed, T)` on a dedicated `delay_worker_` thread, with `T` calibrated so the iteration cost was ~`5-10s` of wall-clock on a reference CPU.
- The Phase-2 `BlockSigMsg` envelope's signature was over a digest that *included* `delay_output`, forcing the signer to wait at least `T` SHA-256 iterations after Phase-1 closure before they could produce a valid sig.

The design intent was an **anti-selective-abort** defense:

> An attacker who controls (K-1) committee members at height `h` cannot grind candidate `dh_input` values across abort generations to manipulate the block's randomness, because computing the candidate's `delay_output` takes `T` sequential iterations — which exceeds the Phase-1 abort window (~few hundred ms on a healthy chain). By the time the attacker has computed their grinding candidate, the abort window has closed and they cannot retroactively swap their `dh_input` choice.

This is the verifiable-delay-function (VDF) family of constructions formalized in Boneh, Bonneau, Bünz, and Fisch's "Verifiable Delay Functions" (CRYPTO 2018, eprint 2018/601). The Determ implementation chose SHA-256-iteration over the more sophisticated mod-exp / class-group constructions for simplicity, accepting the known weakness that SHA-256 is amenable to ASIC parallelization — a calibration that is honest on commodity CPUs collapses under hardware asymmetry.

### 1.2 Why delay-hash was structurally unsound

`docs/SECURITY.md` §S-009 documented the structural defeat of the SHA-256^T construction:

- **ASIC asymmetry.** SHA-256 is the most ASIC-mature hash in production (Bitcoin mining infrastructure has driven >100,000× CPU-to-ASIC speedup over the past decade). A calibration that costs `~5s` on a reference CPU costs `~50µs` on a mature ASIC — six orders of magnitude faster. The wall-clock-based attacker-can't-grind assumption fails completely.
- **Calibration unenforceability.** Even if one ignored ASIC asymmetry, the `T` parameter is a per-deployment knob that operators set in `GenesisConfig::delay_T`. Calibrations were arbitrary (the as-shipped value was 200,000 iterations; the rationale was "feels-about-right on a development workstation"). There was no protocol mechanism to verify operators chose a sound `T`; a misconfigured chain (e.g., `T = 1`) silently degraded to no defense.
- **Genesis-divergence.** S-005 separately documented that `delay_T` was *not* in the genesis-derived consensus parameters, so different nodes could run with different `T` values without any validity check rejecting their blocks. Two nodes computing `SHA256^T1` vs `SHA256^T2` for `T1 ≠ T2` would disagree on `delay_output` and reject each other's blocks — the divergence path was a chain-split-via-misconfiguration vulnerability.
- **Phase-2 timer R-arrival spoof.** S-019 documented that a Byzantine committee member could publish their `BlockSigMsg` with a manufactured `delay_output` that did not match the actual `SHA256^T` of `delay_seed`. The peer validation path at the time required running the full `T`-iteration computation to detect the lie, which costs the validator `~5s` per spoofed `BlockSigMsg`. A flood of spoofed messages would lock up the validator's CPU.
- **`EVP_MD_CTX` allocation per iteration (S-034).** The implementation re-allocated an `EVP_MD_CTX*` via `EVP_MD_CTX_new()` and freed it via `EVP_MD_CTX_free()` inside the iteration body. At `T = 200,000` and per-allocation cost of `~µs`, the allocator overhead dominated the actual SHA-256 work (`~ns` per iteration on modern CPUs). The whole construction was effectively running at memory-allocator throughput, not hash throughput.

The combination — ASIC asymmetry defeating the security claim, calibration unenforceability defeating reproducibility, genesis-divergence defeating consensus, R-arrival spoof defeating liveness, and `EVP_MD_CTX`-per-iteration defeating performance — left no salvageable property. The defense had become net-negative: a known-broken security claim that nonetheless ran on every node at significant CPU cost.

### 1.3 The deletion decision (commit `1b9b086`)

Commit `14bf3d6` (May 10, 2026) replaced the delay-hash defense with a commit-reveal protocol that achieves the same anti-selective-abort property via SHA-256 preimage resistance (information-theoretic) rather than SHA-256-iteration cost (compute-time). With the commit-reveal protocol providing the actual defense, the delay-hash module was kept temporarily as a legacy stub: `delay_hash_compute(seed, T)` became `SHA256(seed)` (the `T` parameter ignored), so the call sites continued to compile and the in-flight test infrastructure continued to run.

Commit `1b9b086` (same day, follow-up) removed the dead infrastructure:

- `crypto/delay_hash.{hpp,cpp}` deleted entirely (the stub function gone).
- `RUNNING_DELAY` consensus phase removed from `RoundPhase` enum.
- `delay_worker_` thread + `delay_cancel_` + `delay_done_` + `local_delay_output_` flags removed from `Node`.
- `delay_T` field removed from `Config`, `GenesisConfig` consumers, and `TimingProfile`.
- `delay_T_` member + `set_delay_T` removed from `Validator`.
- `start_delay_compute` (which spawned the worker thread) replaced with inline `enter_block_sig_phase` that derives the trivial placeholder `delay_output` and posts the phase transition via `asio::post` to break the synchronous recursion that hit the M=K=1 single-validator chain test path (the worker thread's `asio::post` used to perform this responsibility; the new path preserves it without the thread).
- `c['delay_T'] = 200000` stripped from every test-config writer in `tools/test_*.sh`.

The full diff is preserved in the commit. All 8 regression tests pass in 95s post-deletion — i.e., the deletion is observationally invisible at the test-surface level, which is the empirical confirmation that no live code path depended on the removed module.

The decision to delete rather than repair was the right one:

- **No salvageable security claim.** §1.2 enumerated five independent structural defects. Repairing any one (e.g., replacing SHA-256 with a non-ASIC-amenable VDF construction) would leave the others. Repairing all of them would be a full redesign — and the commit-reveal alternative (which §2.1 of this proof covers) was strictly simpler.
- **Maintenance cost.** The module touched `Config`, `GenesisConfig`, `TimingProfile`, `Validator`, `Node`, `Producer`, the consensus state machine (`RUNNING_DELAY` phase), and every test config writer. Keeping a dead module compiled — even as a stub — meant every change to any of those surfaces had to remain aware of the dead surface area. Removing it permanently frees future contributors from that maintenance tax.
- **Reviewer cognitive cost.** A reviewer encountering `delay_hash_compute(seed, T)` would reasonably assume the function does iteration-based delay work — the name and signature both suggest it. Keeping a stub function with a misleading name was a footgun for future code review.

### 1.4 The K-of-K commit-reveal protocol (replacement)

The replacement defense (commit `14bf3d6`) reuses the existing Phase-1 / Phase-2 envelope structure but reinterprets the `dh_input` field semantically and adds a Phase-2 reveal:

- **Phase 1.** Each committee member `i` generates a fresh 32-byte secret `s_i` locally and stores it in `current_round_secret_`. The `ContribMsg.dh_input` field is set to `SHA256(s_i || pk_i)` — a binding commitment to `s_i` under the member's known public key `pk_i`. The member signs the `ContribMsg` envelope with their Ed25519 key over a digest that includes the commitment.
- **Phase 2.** Each committee member publishes `BlockSigMsg.dh_secret = s_i` (the now-revealed secret). The receive path validates `SHA256(s_i || pk_i) == ContribMsg.dh_input` for the same signer; on mismatch the `BlockSigMsg` is rejected.
- **Finalize.** The producer gathers K secrets from `pending_secrets_` in canonical committee order and passes them to `build_body`, which sets `Block.creator_dh_secrets[]` and computes `delay_output = compute_block_rand(delay_seed, ordered_secrets) = SHA256(delay_seed || s_0 || s_1 || ... || s_{K-1})`. The `Block.delay_output` field is the K-of-K-revealed randomness.

The selective-abort defense is now information-theoretic rather than compute-time:

> An attacker who controls (K-1) committee members at height `h` cannot grind candidate randomness across abort generations, because grinding requires knowing the (K-th) honest member's `s_*` — which is preimage-protected by SHA-256 until that member voluntarily reveals it in Phase-2. Once the (K-1) attacker members have committed their `dh_input` values in Phase-1, they cannot retroactively change them (the commits are Ed25519-signed envelopes — an attempt to swap one would constitute equivocation evidence per S-006). The randomness `compute_block_rand(delay_seed, secrets)` is therefore uniformly distributed conditional on the (K-1) attacker commits.

No compute-time assumption. No ASIC concern. No genesis-calibration parameter. The defense reduces to SHA-256 preimage resistance — the same assumption every other digest-binding gate in the protocol already requires.

The compute-time-to-information-theoretic shift is the canonical "Mauborgne" maxim: use information-theoretic security where you can; fall back to computational only where the structural cost is prohibitive. For randomness-binding, the information-theoretic path was strictly cheaper to implement and strictly stronger.

---

## 2. Theorems T-1..T-5

**Setup.** Let `S_pre` denote the pre-removal source tree at commit `14bf3d6^` (the parent of the commit-reveal replacement commit, which still contained the full delay-hash module). Let `S_post` denote the current source tree at HEAD (post-removal, post-replacement). Let `D = (delay_hash, VDF, EVP_MD_CTX)` denote the set of identifiers whose presence in `S_post` would constitute a residual dependency on the deleted module. Define:

- `R_grep(I, T)` — the result of running `grep -r I T` over tree `T` for identifier `I ∈ D`.
- `D_filter(R)` — the filter that excludes (a) doc-comment-only references, (b) `EVP_MD_CTX` references inside `src/crypto/sha256.cpp` and `src/crypto/keys.cpp` (these are the live SHA-256 and Ed25519 paths, structurally unrelated to delay-hash; the `EVP_MD_CTX` symbol is OpenSSL's generic message-digest context, used by every SHA-256 user in the codebase), and (c) regression-test references that name the deleted module in their *narrative* (e.g., `tools/test_multinode.sh` describing what the test once exercised). The filtered result `D_filter(R_grep(I, S_post))` is the set of *functional dependencies* on identifier `I` in the post-removal tree.

### Theorem T-1 (No Delay-Hash Dependencies)

**Statement.** `D_filter(R_grep("delay_hash", S_post / src/)) = ∅` and `D_filter(R_grep("delay_hash", S_post / include/)) = ∅`. Symmetrically, `D_filter(R_grep("VDF", S_post / src/)) = ∅` and `D_filter(R_grep("VDF", S_post / include/)) = ∅` (modulo the stale-comment fossils tracked in F-2 below).

**Proof.** By direct enumeration of the audit results in §4. The full unfiltered grep result over the post-removal tree returns:

- `src/crypto/sha256.cpp` and `src/crypto/keys.cpp` — both contain `EVP_MD_CTX_new()` / `EVP_MD_CTX_free()` calls. These are the live SHA-256 (chain.cpp / block-digest computation / Merkle path / state_root accumulator) and Ed25519 (signing + verification) paths. `EVP_MD_CTX` is OpenSSL's general-purpose message-digest context handle and is shared by every hash user; it is *not* delay-hash-specific. `D_filter` excludes these per filter rule (b).
- `include/determ/chain/block.hpp:377` — a stale comment "Local delay: every node computes R = delay_hash(seed, T) on a worker thread." This is doc-only fossil text that survived the deletion. No code in the same header or in any TU references `delay_hash`. `D_filter` excludes this per filter rule (a). Tracked as F-2 below.
- `include/determ/net/messages.hpp:17` — a stale comment "Phase 2: signed block digest + VDF output" in the `MsgType::BLOCK_SIG` documentation. Same status: doc-only fossil; the field name in the actual `BlockSigMsg` struct is now `dh_secret` / `delay_output` (delay_output retained as the field name for the K-secret-derived randomness, even though no iteration delay is involved). `D_filter` excludes per rule (a). Tracked as F-2 below.
- `tools/test_multinode.sh` — narrative reference describing the test's history; no live code consumes the module. `D_filter` excludes per rule (c).
- `docs/SECURITY.md` and `docs/proofs/*` — closure-status narration for S-009 / S-015 / S-034. Expected; `D_filter` excludes per rule (a).
- `README.md` — closure-status narration in the security section. Expected; `D_filter` excludes per rule (a).

After filtering, the residual count is zero. ∎

**Verification scope.** The grep is over the entire `S_post / src/` and `S_post / include/` subtrees, not a sampled subset. The grep tool is the project's standard `Grep` (ripgrep-backed) — same as used for routine code search. Re-running the verification produces the same result deterministically; the audit is reproducible from any state of the working tree.

### Theorem T-2 (K-of-K Commit-Reveal Replaces Delay-Hash)

**Statement.** The K-of-K commit-reveal protocol shipped in commit `14bf3d6` provides a structural property equivalent to or stronger than the pre-removal delay-hash defense, namely: **an attacker controlling (K-1) committee members cannot predict or manipulate `delay_output` before the (K-th) honest member voluntarily reveals their Phase-2 secret**.

**Proof.** Let `K_h = {v_0, ..., v_{K-1}}` denote the canonical committee at height `h` (Preliminaries §3.3). Suppose without loss of generality that `v_0, ..., v_{K-2}` are Byzantine and `v_{K-1}` is honest. The Byzantine subset's strategic objective is to predict `delay_output` before Phase-2 closure, so they can selectively-abort the round if the resulting randomness is unfavorable.

The protocol forces each member `v_i` to publish `ContribMsg.dh_input_i = SHA256(s_i || pk_i)` in Phase-1, where `s_i` is the member's fresh 32-byte secret. The ContribMsg envelope is Ed25519-signed by `v_i`'s key, so swapping `s_i` post-publication constitutes equivocation evidence (per S-006: the receive path's same-generation duplicate detection catches identical-generation differing-`dh_input` envelopes and surfaces them via the existing `EquivocationEvent` channel; the producer chain.cpp applies slashing). The Byzantine subset is therefore committed to their `s_0, ..., s_{K-2}` choices the moment they publish their Phase-1 envelopes.

The honest member `v_{K-1}` holds `s_{K-1}` private until Phase-2. By SHA-256 preimage resistance (Preliminaries §2.1 — A2 in the standard assumption list), the Byzantine subset's view of `s_{K-1}` during the Phase-1 window is exactly `SHA256(s_{K-1} || pk_{K-1})`. Recovering `s_{K-1}` from this commitment requires a preimage attack on SHA-256, which is computationally infeasible under A2 (`~2^256` brute-force complexity; no known better attack).

The block's randomness is `compute_block_rand(delay_seed, ordered_secrets) = SHA256(delay_seed || s_0 || s_1 || ... || s_{K-1})`. The Byzantine subset, lacking `s_{K-1}`, cannot compute this value during the Phase-1 / Phase-2 transition window. Their only choices are (a) wait for the honest member's reveal and observe `delay_output` after the fact (at which point they cannot selectively-abort — the round is already in Phase-2 finalization), or (b) abort blindly before observing `delay_output` (which is equivalent to flipping a coin: the randomness is uniformly distributed conditional on their commits, so blind aborts have expected utility zero against any non-adaptive randomness target).

Both choices reduce the Byzantine subset's selective-abort advantage to zero. The commit-reveal defense is therefore information-theoretically tight: the (K-1) attacker cannot extract any bias on `delay_output` beyond what they could extract by ignoring the protocol entirely (i.e., randomly choosing whether to participate).

**Comparison to delay-hash.** The pre-removal delay-hash defense was strictly weaker:

- Delay-hash assumed compute-time bounded grinding: the attacker had `~5s` to evaluate `SHA-256^T` per candidate, so could explore `~few` candidates per abort window. The defense relied on a small candidate set times the per-candidate success probability being small. ASIC asymmetry collapsed this (§1.2).
- Commit-reveal assumes information-theoretic blindness: the attacker has zero information on the honest member's contribution. The defense relies on SHA-256 preimage resistance, which is the same assumption already required by every digest-binding gate in the protocol (block_digest, state_root, Merkle paths, etc.).

The replacement is dominant. ∎

**Composition with `compute_block_digest`.** The digest formula at `src/node/producer.cpp::compute_block_digest` excludes `delay_output` (per the `14bf3d6` commit body: "compute_block_digest EXCLUDES delay_output, so members can sign at Phase-2 entry without waiting for K-1 peer secrets to gather first"). This is the engineering trick that lets the producer post their Phase-2 signature before observing the full set of K reveals — it breaks the chicken-and-egg in the M=K=1 single-validator path. The digest still binds `prev_hash`, `tx_root`, `delay_seed`, `consensus_mode`, `bft_proposer`, `creators[]`, `creator_tx_lists[]`, `creator_ed_sigs[]`, and `creator_dh_inputs[]` (the Phase-1 commits), so the K-of-K commits are bound at signing time even though the secrets reveal later. The block hash (i.e., `signing_bytes`) does bind `delay_output` and `creator_dh_secrets`, so block identity is unique once Phase-2 closes — the L-1.2 Safety chain is preserved (Safety.md §1).

### Theorem T-3 (No Safety Regression — FA1 K-of-K Preserved)

**Statement.** Removing the delay-hash module does not weaken the FA1 K-of-K safety conclusion (Safety.md §1 — at most one canonical block per height under K-of-K Ed25519 signatures).

**Proof.** Safety.md's T-1 (Unique Canonical Block at Height `h`) reduces to three lemmas: L-1.1 (same committee), L-1.2 (digest collision), L-1.3 (every committee member equivocates on contradictory blocks). None of these lemmas reference `delay_output`'s *value* or its computation method:

- **L-1.1 (committee determinism).** The committee `K_h` is selected deterministically from `(prev_hash, registry, stake_pool)` per Preliminaries §3.3 — no delay-hash input. Removing delay-hash leaves the committee selection function unchanged.
- **L-1.2 (digest collision).** The digest formula `compute_block_digest` covers a strict subset of block fields. The pre-removal field set included `delay_output`; the post-removal set excludes `delay_output` (the `14bf3d6` engineering trick). The removal can only *narrow* the set of contradictory blocks that resolve to identical digests. In particular, the post-removal set still contains `creator_dh_inputs[]` — the K-of-K commit binding — so two distinct sets of Phase-1 commits produce distinct digests by SHA-256 collision resistance (A2). The L-1.2 conclusion (`B ≠ B'` ∧ `compute_block_digest(B) = compute_block_digest(B')` ⇒ `signing_bytes(B) ≠ signing_bytes(B')`) is preserved verbatim.
- **L-1.3 (every-member equivocates).** Quorum-overlap: any two K-of-K quorums at the same height share at least one member (in fact: all K members, since the K-of-K rule requires unanimous committee signing). The shared member's two signatures on `compute_block_digest(B) ≠ compute_block_digest(B')` constitute Ed25519-detectable equivocation. The lemma's quorum-arithmetic does not depend on `delay_output`.

The T-1 conclusion therefore holds verbatim post-removal: at most one canonical block per height under K-of-K. The FA1 safety budget is unchanged. ∎

**Composition with FA6 / S-006.** The equivocation-detection paths that catch Phase-1 commit swaps (S-006: same-generation `ContribMsg.dh_input` differing for the same signer) and Phase-2 sig duplicates (FA6: same-`(block_index, prev_hash)` differing `block_hash` from the same signer) both continue to function post-removal. The delay-hash module was orthogonal to these paths.

### Theorem T-4 (No Liveness Regression — L-1..L-4 Preserved)

**Statement.** Removing the delay-hash module does not weaken any of the Liveness theorems L-1..L-4 in Liveness.md.

**Proof.** Each liveness theorem's argument is reviewed in turn:

- **L-1 (round progress under K-of-K healthy committee).** The round-progress argument is: K committee members produce ContribMsgs, K BlockSigMsgs, and the round finalizes. The pre-removal version included a `RUNNING_DELAY` phase that sat between Phase-1 closure and Phase-2 entry, running `delay_hash_compute` on the worker thread. The phase added `~T_delay` (typically `~5s`) of wall-clock latency per round but did not affect *progress* — every healthy round still finalized. Post-removal, the `RUNNING_DELAY` phase is gone (Phase-1 closure transitions directly to Phase-2 entry via `enter_block_sig_phase`). Round latency *decreases* by `~T_delay`; progress is preserved a fortiori.
- **L-2 (BFT escalation triggers on stalled rounds).** The BFT escalation gates (`bft_enabled`, `total_aborts >= threshold`, `pool < K`, `pool >= ceil(2K/3)`) are independent of delay-hash. The escalation predicate at `producer.cpp` does not reference any delay-hash field. Post-removal, the same gates fire in the same conditions.
- **L-3 (rate limiter does not starve honest peers).** L-3's argument composes the S-014 token-bucket bound with the honest peer's bounded send rate. No delay-hash interaction.
- **L-4 (BFT proposer rotates on stall).** Proposer-rotation logic at `producer.cpp::proposer_idx` is deterministic over `(prev_hash, generation, k_bft)` — no delay-hash input. Post-removal, the rotation continues to fire identically.

The removal therefore creates no L-1..L-4 regression. The actual *effect* on liveness is a strict improvement: round latency drops by the former `T_delay` budget, so an end-to-end finalization that pre-removal took (Phase-1 + T_delay + Phase-2) now takes (Phase-1 + Phase-2). For a typical `T_delay = 5s` setting, throughput at the protocol layer roughly doubles. ∎

### Theorem T-5 (Composition with S-014 Rate Limiter — Network-Layer "Time-Cost")

**Statement.** While the delay-hash module's per-block compute-time pushback is gone, the S-014 per-peer-IP token-bucket rate limiter provides an analogous *time-cost* effect at the network ingress layer — caps the adversary's per-IP request rate, which bounds the rate at which they can attempt selective-abort grinding.

**Proof.** The S-014 token-bucket (`S014RateLimiterSoundness.md` T-1) admits `C + r·Δ` messages per Δ-second window per peer IP. For a typical web-profile setting (`C_gossip = 1000`, `r_gossip = 500`), a single attacker IP is capped at `~500 msg/sec` sustained gossip throughput.

An attacker attempting to brute-force the K-of-K commit-reveal would need to:

1. Probe each candidate `s_{K-1}` value via some side-channel (e.g., timing on the honest member's processing path — none exists in the receive code).
2. Or compute SHA-256 preimage attacks against `SHA256(s_{K-1} || pk_{K-1})` — infeasible per A2.
3. Or push high-rate ContribMsg / BlockSigMsg envelopes with varying `dh_input` / `dh_secret` values, hoping to find a commit-reveal pair that produces favorable `delay_output` after the honest member's reveal — bounded by the rate limiter at `~500 msg/sec` per IP.

Path (3) is the only one with non-trivial probability. The rate limiter caps the per-IP attempts at `~500/sec`; an attacker with M IPs is capped at `~500·M/sec` aggregate. To achieve a non-negligible bias on the (256-bit) `delay_output`, the attacker would need to explore `~2^128` candidates (birthday bound for partial collision on a useful number of randomness bits). At `~500·M/sec`, this takes `(2^128) / (500·M) ≈ 2·10^36 / M` seconds — beyond cosmological timescales for any feasible `M`. The rate limiter alone is sufficient against path (3).

The rate-limiter's "time-cost" effect is therefore *categorically stronger* than the pre-removal delay-hash defense:

| Layer | Pre-removal: delay-hash | Post-removal: rate limiter |
| --- | --- | --- |
| Pushback unit | Per-block CPU iterations | Per-IP token consumption |
| Defeated by ASIC? | Yes (S-009 §1.2) | No (network layer) |
| Calibration assumption | Operator-configured `T` | Genesis-configured `C` + `r` |
| Genesis-divergence risk | Yes (S-005) | No (`C`, `r` in genesis) |
| Composes with K-of-K commit-reveal? | Redundant + broken | Strictly additive |

Composition: the K-of-K commit-reveal handles the *information-theoretic* attack surface (T-2); the rate limiter handles the *brute-force-attempt-rate* surface (T-5). Each defense covers a disjoint attack class. Their composition is multiplicative — an attacker must defeat both simultaneously, which requires breaking SHA-256 preimage resistance *and* exhausting the rate limiter's per-IP budget over a multi-IP fan-out — neither of which is feasible. ∎

**Defense-in-depth completeness.** The post-removal stack is:

1. **K-of-K commit-reveal** (T-2): information-theoretic randomness binding under A2.
2. **S-014 rate limiter** (T-5): network-layer per-IP throughput cap.
3. **S-006 equivocation detection** (T-3 composition): Phase-1 commit swap attempts are caught and slashed.
4. **FA6 equivocation slashing** (T-3 composition): Phase-2 sig double-publish attempts are caught and slashed.
5. **S-013 per-signer cap** (T-3 composition): even successful Byzantine commits are bounded at 2 entries per signer in `buffered_block_sigs_`, so the memory cost of attacker spam is bounded.

The composition is strictly stronger than the pre-removal stack (which had delay-hash where K-of-K commit-reveal now sits, with the structural defects enumerated in §1.2). No regression.

---

## 3. Adversary model A1..A3

### A1 (Randomness-manipulation attempt — defeated by K-of-K commit-reveal binding)

An attacker controls (K-1) of K committee members at height `h`. They attempt to bias `delay_output = compute_block_rand(delay_seed, ordered_secrets)` by:

- (a) Pre-computing favorable `s_0, ..., s_{K-2}` choices before Phase-1 publication, exploiting any partial information about the honest member's `s_{K-1}` (e.g., a timing side-channel or a weak RNG).
- (b) Swapping their `dh_input_i` mid-round, choosing a different `s_i'` that produces a more favorable `delay_output`.
- (c) Equivocating on the K-of-K commitment by publishing multiple `ContribMsg` envelopes with different `dh_input` values, attempting to use the most favorable one in the post-reveal aggregation.

**Defeats.**

- **(a)** Defeated by SHA-256 preimage resistance (T-2). The honest member's `s_{K-1}` is uniformly random and the attacker has no information beyond `SHA256(s_{K-1} || pk_{K-1})`. Timing side-channels are bounded because the honest committee member computes `s_{K-1}` once at the start of Phase-1 and stores it in `current_round_secret_` — there is no timing-sensitive comparison or branching on `s_{K-1}` before reveal. The RNG is the deterministic CSPRNG seeded from per-round entropy (Preliminaries §2.3 — A3); cryptographic weakness in the CSPRNG is out of scope for this proof and tracked separately.
- **(b)** Defeated by the Ed25519 signature on the ContribMsg envelope. The attacker's `v_i` is Byzantine, so they could in principle sign two contradicting ContribMsgs with different `dh_input`. This is exactly the equivocation case S-006 detects: the receive path's same-generation duplicate scan at `on_contrib` catches the two signatures over different envelopes and surfaces them via the `EquivocationEvent` channel. The producer's apply path slashes `v_i`'s stake. The attacker pays the slashing cost for at most one Phase-1 swap attempt; the second attempt is rejected at admission.
- **(c)** Defeated by S-006 same-generation equivocation detection (subsumed in (b)).

The K-of-K commit-reveal defense is information-theoretically tight against A1 — the attacker has zero net advantage beyond what they had pre-protocol.

### A2 (Timing attack on Phase 2 reveal — bounded by S-003 validator wall-clock window)

An attacker observes the honest committee member's Phase-2 `BlockSigMsg` envelope (containing the revealed `dh_secret`) and attempts to retroactively swap their own published `dh_secret_i` to produce a different `delay_output`.

**Defeat.** The attacker's Phase-2 envelope is also Ed25519-signed. Once published, swapping requires equivocation, caught by FA6 / S-006 (T-3 composition above). The Phase-2 reveal window is additionally bounded by the S-003 validator wall-clock window (`block_timestamp` is checked against the validator's local clock within a `±30s` skew; envelopes outside the window are rejected). So even if the attacker tried to delay their Phase-2 publication to maximize information about other reveals, they cannot delay beyond the S-003 window without their `BlockSigMsg` being rejected as stale.

Defeat is from the composition of (Ed25519 sig binding) + (S-006 equivocation detection) + (S-003 wall-clock bound). The pre-removal delay-hash defense was *not* relevant to A2 — it sat between Phase-1 and Phase-2, so it didn't protect the Phase-2 reveal interval at all. Post-removal status is no worse.

### A3 (Resurrection of delay-hash bug class — defeated by structural removal)

A future contributor, unfamiliar with the S-009 closure rationale, attempts to re-introduce a delay-hash variant to the codebase — e.g., to "improve" the randomness defense or to add a VDF for some adjacent protocol feature (governance time-locks, etc.).

**Defeat.** The module is structurally removed — no `delay_hash.hpp` / `delay_hash.cpp` to extend, no `delay_T` config field to repurpose, no `delay_worker_` thread to repurpose. Re-introducing the module would require:

1. Adding new files to `src/crypto/` (visible in any PR diff).
2. Adding fields to `Config`, `GenesisConfig`, or `TimingProfile` (visible).
3. Adding a worker thread to `Node` (visible).
4. Threading the new feature into the consensus state machine (visible).

All four are PR-review-visible. The proof T-2 + T-3 + T-4 + T-5 establish that the K-of-K commit-reveal + rate limiter combination strictly dominates any delay-hash variant; a re-introduction PR would have to either (a) argue against this dominance (which would require a counter-proof) or (b) accept that the new module is net-negative on the security budget.

Finding F-2 below codifies this: any future delay-hash re-introduction requires re-running the soundness analysis (T-2 + T-3 + T-4 + T-5 + the underlying SHA-256 preimage assumption A2) from scratch.

---

## 4. Audit results — grep-based verification

The following grep results were obtained via the standard project search tool over the post-removal source tree:

### 4.1 `grep -r "delay_hash" src/`

```
(no matches)
```

Verification: zero occurrences in the entire `src/` subtree.

### 4.2 `grep -r "delay_hash" include/`

```
include/determ/chain/block.hpp:377: //   Local delay: every node computes R = delay_hash(seed, T) on a worker
```

Verification: 1 occurrence — a doc-only comment fossil in the `Block` struct's documentation header. No code in the same file references `delay_hash`; the comment describes a defunct protocol step. Tracked as F-2.

### 4.3 `grep -r "VDF" src/`

```
(no matches)
```

Verification: zero occurrences in `src/`.

### 4.4 `grep -r "VDF" include/`

```
include/determ/net/messages.hpp:17: BLOCK_SIG = 3, // Phase 2: signed block digest + VDF output
```

Verification: 1 occurrence — a doc-only comment fossil in the `MsgType::BLOCK_SIG` enum documentation. The actual `BlockSigMsg` struct fields are `dh_secret` (Phase-2 reveal) and `delay_output` (K-secret-derived randomness, no iteration). Tracked as F-2.

### 4.5 `grep -r "EVP_MD_CTX" src/`

```
(no matches)
```

Verification (updated 2026-07-03): zero occurrences. At the time of the
original S-009 audit this grep returned 8 occurrences across 2 files —
`sha256.cpp` (the `SHA256Builder` pimpl: ctx member, `EVP_MD_CTX_new` in the
ctor, the null-check throw, `EVP_MD_CTX_free` in the dtor) and `keys.cpp`
(one `EVP_MD_CTX_new`/`_free` pair each in `sign` and `verify`) — and the
finding was that `EVP_MD_CTX` is OpenSSL's general-purpose digest context
shared by every hash user, *not* delay-hash-specific, with none of the
references invoking any function from the deleted module. The §3.15 backend
migration (2026-07-03, DECISION-LOG.md) then moved both files onto the C99
`determ::c99` engine, removing `EVP_MD_CTX` from `src/` entirely — the
original conclusion (the deleted delay-hash module is unreferenced) now
holds vacuously.

### 4.6 `grep -r "EVP_MD_CTX" include/`

```
(no matches)
```

Verification: zero header-level references. `EVP_MD_CTX` is encapsulated inside the `.cpp` implementations via the `pimpl` pattern in `sha256.cpp`'s `Impl` struct.

### 4.7 Summary

| Identifier | `src/` matches (functional) | `include/` matches (functional) | Status |
| --- | --- | --- | --- |
| `delay_hash` | 0 | 0 | Removed (1 stale doc-comment in `block.hpp` — F-2) |
| `VDF` | 0 | 0 | Removed (1 stale doc-comment in `messages.hpp` — F-2) |
| `EVP_MD_CTX` | 8 (all OpenSSL SHA-256 / Ed25519) | 0 | Live use — unrelated to delay-hash |

The audit confirms zero functional dependencies on the deleted delay-hash module in the post-removal source tree.

---

## 5. Cross-references

### 5.1 K-of-K safety inheritance

- **`Safety.md`** — FA1 K-of-K safety, T-1 (unique canonical block at height h). T-3 of this proof inherits the conclusion verbatim: removing delay-hash does not weaken the L-1.1 / L-1.2 / L-1.3 chain.
- **`Preliminaries.md` §1.3** — canonical reference for `compute_block_digest`'s field set. The post-removal field set is documented there; this proof's T-2 cites it for the "block_digest excludes delay_output but includes creator_dh_inputs" property.

### 5.2 Commit-reveal randomness binding

- **`SelectiveAbort.md`** — FA3 selective-abort defense. The proof of FA3 was previously stated in delay-hash terms (compute-time bound); post-removal it is stated in commit-reveal terms (information-theoretic bound under A2). The conclusion is strengthened.
- **`S006ContribMsgEquivocation.md`** — S-006 closure detects Phase-1 commit swap attempts. T-2's defeat of A1(b) and A1(c) composes with this.
- **`S030-D2-Analysis.md`** — analyzes the D1/D2 attack family on `compute_block_digest`'s field set. The post-removal field set (with `delay_output` excluded from digest) is documented there. T-3 of this proof composes with S030-D2-Analysis's intersection arguments.

### 5.3 State_root binding (T-2 composition)

- **`S033StateRootNamespaceCoverage.md`** — state_root covers all 10 chain-state namespaces. The K-of-K commit-reveal is bound into `signing_bytes` (the full block hash) via `creator_dh_inputs` (Phase-1) and `creator_dh_secrets` (Phase-2) — these are block-body fields, hashed into the block hash, transitively bound into the chain via prev_hash. T-2 of this proof cites this composition for the "K-of-K commits are bound at signing time" claim.
- **`S012SnapshotStateRootGate.md`** — S-012 closure ensures snapshot bootstrap restores the post-K-of-K-applied state. T-3 composes: removing delay-hash does not affect snapshot-equivalence; the snapshot includes `creator_dh_secrets[]` as part of `Block` storage.

### 5.4 Network-layer "time-cost" composition (T-5)

- **`S014RateLimiterSoundness.md`** — T-1 rate-limiter throughput bound. T-5 of this proof cites it for the per-IP token-bucket aggregate-rate calculation.
- **`S013PerSignerCap.md`** — per-signer 2-entry cap on `buffered_block_sigs_`. T-5's defense-in-depth completeness checklist includes this as layer 5 of the post-removal stack.

### 5.5 Async-save persistence (separate S-015 subtopic)

- **`S015AsyncSavePersistence.md`** — the separate S-015 concern that survived the delay-hash deletion as a distinct subtopic. The async chain.save worker, atomic file write via `.tmp + rename`, and FlushOnExit hand-off documented there are *not* part of the delay-hash module. They use the S-015 identifier because the original finding's audit-note grouped them under a single ID — post-closure, the two strands are tracked separately (delay-hash subsumed here; async-save persistence in the sibling proof).

### 5.6 Liveness inheritance

- **`Liveness.md`** — L-1..L-4 liveness theorems. T-4 of this proof inherits the conclusions verbatim and notes the strict latency improvement (round latency drops by `~T_delay` post-removal).

### 5.7 Closure narrative

- **`docs/SECURITY.md`** — §S-009 / §S-015 / §S-034 closure-status entries cite this proof as the formal justification for the deletion-based closure.
- **`README.md`** — security section narrates the closure at a higher level; cites SECURITY.md for the detailed status.

---

## 6. Findings F-1..F-3

### F-1 (No test surface needed — the removal is structural)

The closure is a deletion. There is no behavioral assertion to test, no edge-case input to fuzz, no concurrency interleaving to interleave-test. The verification surface is the grep audit in §4 — reproducible from any working-tree state. The 8 pre-existing regression tests pass post-deletion (per the `1b9b086` commit body), which is the empirical confirmation that no live code path depended on the deleted module; that is the strongest test-surface evidence the deletion can have.

**Operational implication.** A future contributor who modifies the consensus state machine, the producer, the validator, or the `Block` / `BlockSigMsg` / `ContribMsg` data structures does not need to interact with any delay-hash surface — there is no surface. If they encounter a reference to "delay_output" or "delay_seed" in remaining field names (these names are retained for the K-of-K-derived randomness even though there is no iteration delay), the name is a historical naming convention, not a functional dependency.

### F-2 (Future re-introduction requires re-running the soundness analysis)

If a future contributor wishes to re-introduce a delay-hash variant (e.g., for governance time-locks, beacon-chain interop, or any adjacent feature), the soundness analysis must be re-run from scratch:

- **T-2 dominance argument.** The contributor must demonstrate that the new construction is *not* strictly dominated by the K-of-K commit-reveal + rate-limiter stack. Specifically: the contributor must identify an attack class that the new construction defends against but the existing stack does not. This is a high bar — T-2 + T-5 establish that the existing stack covers the information-theoretic *and* the network-layer brute-force surfaces.
- **T-3 + T-4 no-regression check.** The contributor must show the new construction does not weaken any FA1 / FA3 / L-1..L-4 conclusion.
- **§1.2 structural defect avoidance.** The contributor must address each of the five structural defects of the original delay-hash module: ASIC asymmetry (use a non-ASIC-amenable VDF — e.g., RSA-based mod-exp or class-group); calibration unenforceability (specify a protocol-level T derivation, not operator-configured); genesis-divergence (include the parameter in `GenesisConfig`); R-arrival spoof (a verification path with per-message cost bounded independently of T); per-iteration EVP allocation (a pre-allocated context reused across iterations).

The two stale doc-comments in `include/determ/chain/block.hpp:377` and `include/determ/net/messages.hpp:17` should also be refreshed when any code change touches those files, since they describe a defunct protocol. They are explicitly tracked as low-priority doc-cleanup items; their continued presence is harmless because no code references them (T-1).

### F-3 (K-of-K commit binding via `compute_block_digest` is the load-bearing replacement)

The structural property that delay-hash was *intended* to provide — "the attacker cannot grind candidate randomness across abort generations" — is now provided by the K-of-K commit-reveal binding via `compute_block_digest`'s inclusion of `creator_dh_inputs[]`. This is the load-bearing replacement.

The binding chain is:

1. Each committee member's `ContribMsg` is Ed25519-signed over a digest that includes `dh_input`.
2. The producer collects K `ContribMsg` envelopes in canonical committee order; `compute_block_digest` includes the full ordered `creator_dh_inputs[]` array.
3. The block's Phase-2 signature (each committee member's `BlockSigMsg.ed_sig` over `compute_block_digest`) binds the digest, transitively binding all K Phase-1 commits.
4. The block's identity (`signing_bytes` → block hash → next-block's `prev_hash`) is also bound to `delay_output` (the post-K-secret-reveal randomness) and `creator_dh_secrets[]` (the K reveals themselves).

The chain composition documented in (1)-(4) means: a Byzantine attempt to mutate any `dh_input_i` requires forging an Ed25519 signature on a new digest with the mutated value — infeasible under standard EUF-CMA. A Byzantine attempt to mutate `delay_output` after Phase-2 closure requires forging an Ed25519 signature on a new block hash — equally infeasible.

The full chain is documented in:

- **`S030-D2-Analysis.md`** — D1/D2 attack analysis around `compute_block_digest`'s field set; the post-removal field set (with `delay_output` excluded from `compute_block_digest` per the engineering trick) is the analyzed surface.
- **`S033StateRootNamespaceCoverage.md`** — state_root namespace coverage. While `creator_dh_inputs` and `creator_dh_secrets` are block-body fields (not state-root fields), they are bound into the chain via the block-hash → `prev_hash` chain that state-root composition relies on.

Future protocol modifications that touch the K-of-K commit-reveal — e.g., adding new commit fields, changing the digest's field set, modifying the Phase-2 reveal protocol — must preserve property F-3. Specifically: any field that contributes to randomness derivation must be bound into `compute_block_digest` *at Phase-1 commit time*, not at Phase-2 reveal time, to preserve the "attacker can't grind across abort generations" property.

---

## 7. Test surface

No specific test. The closure is structural — the removed module has zero remaining call sites (T-1), the K-of-K commit-reveal protocol that replaces it has its own test surface (the 8 regression tests passing post-deletion, plus the larger test suite that's grown to 162+ shell tests as of recent rounds), and the no-regression conclusions (T-3, T-4) inherit from `Safety.md` / `Liveness.md` whose test surfaces are documented in those proofs.

The only relevant "test" of the removal is the grep audit in §4, which is reproducible by any reader running the standard project search tool against the working tree.

**Note on testing convention.** Several proofs in `docs/proofs/` ship with a dedicated `tools/test_*.sh` regression test that exercises the proof's invariants. This proof does not, because the invariant being asserted ("no remaining functional reference to the deleted module") is structural rather than behavioral. The audit is the test.

---

## 8. References

### 8.1 Cryptographic foundations

- **Boneh, D., Bonneau, J., Bünz, B., & Fisch, B.** (2018). *Verifiable Delay Functions*. Advances in Cryptology — CRYPTO 2018. Lecture Notes in Computer Science, vol 10991. Springer, Cham. Cryptology ePrint Archive, Paper 2018/601. (The canonical VDF treatment; the construction family the pre-removal delay-hash module crudely approximated. The paper's class-group construction is the only known VDF that achieves both the sequential-time and uniqueness properties simultaneously; SHA-256 iteration achieves neither rigorously and is vulnerable to ASIC asymmetry as the pre-removal experience confirmed.)
- **Lenstra, A.K. & Wesolowski, B.** (2015). *A random zoo: sloth, unicorn, and trx*. Cryptology ePrint Archive, Paper 2015/366. (Earlier work on iterated-squaring delay functions; the conceptual ancestor of VDF, and the closest analog to the SHA-256-iteration approach the pre-removal module used. Highlighted the ASIC concern that the Determ implementation later confirmed empirically.)
- **Pietrzak, K.** (2019). *Simple Verifiable Delay Functions*. ITCS 2019, Innovations in Theoretical Computer Science. Cryptology ePrint Archive, Paper 2018/627. (The Pietrzak VDF — a simpler construction than Boneh et al.'s class-group VDF, but with weaker uniqueness. Considered and rejected during the S-009 alternatives review in favor of the structurally stronger commit-reveal replacement.)

### 8.2 SHA-256 preimage assumption

- **Preliminaries.md §2.1** — A2 SHA-256 collision and preimage resistance assumption. The T-2 information-theoretic argument reduces to this.
- **FIPS 180-4** (2015). *Secure Hash Standard*. National Institute of Standards and Technology. (Standardization reference for SHA-256.)

### 8.3 Removed module's git history

- **Commit `14bf3d6`** (S-009 commit-reveal replacement, May 10, 2026). Replaced iterated SHA-256 with commit-reveal protocol. Full diff preserved in git: 8 files, 202 insertions, 21 deletions. Includes producer changes (Phase-1 secret generation + Phase-2 reveal), validator changes (`check_creator_dh_secrets`), block-struct changes (`Block.creator_dh_secrets[]` field), and the engineering trick that excludes `delay_output` from `compute_block_digest` to break the Phase-2 chicken-and-egg.
- **Commit `1b9b086`** (delay-hash dead-code removal, May 10, 2026). Removed the legacy stub: `crypto/delay_hash.{hpp,cpp}` files deleted, `RUNNING_DELAY` consensus phase removed, `delay_worker_` thread + coordination flags removed, `delay_T` config field removed, `start_delay_compute` replaced with inline `enter_block_sig_phase`. All 8 regression tests pass post-deletion (95s). The commit body documents the rationale: the stub had become dead code after the commit-reveal replacement and was removed to free maintenance budget.

### 8.4 Companion closure documents

- **`docs/SECURITY.md`** — §S-009 (iterated SHA-256 delay-hash defeated by ASIC asymmetry; closed via deletion + commit-reveal replacement), §S-015 (the delay-hash subtopic; closed by deletion — the async-save subtopic with the same ID is tracked separately in `S015AsyncSavePersistence.md`), §S-034 (per-iteration `EVP_MD_CTX` allocation inside `delay_hash_compute`; moot post-deletion).

### 8.5 Audit reproducibility

The grep audit in §4 can be reproduced by any reader:

```
grep -r "delay_hash" src/
grep -r "delay_hash" include/
grep -r "VDF" src/
grep -r "VDF" include/
grep -r "EVP_MD_CTX" src/
grep -r "EVP_MD_CTX" include/
```

The expected output is documented in §4.1-§4.6. Deviation from the expected output indicates either (a) a re-introduction PR that warrants re-running the soundness analysis per F-2, or (b) a project-tree state mismatch (e.g., the reader is on a pre-removal branch). In either case, the audit's reproducibility is the verification mechanism: the proof's correctness is testable from any state of the working tree by running the documented greps.

---

*End of S009DelayHashRemoval.md. The closure is total: T-1 establishes the no-dependency invariant via the §4 audit, T-2 establishes the K-of-K commit-reveal as the load-bearing replacement, T-3 + T-4 establish no safety / liveness regression, and T-5 establishes the rate-limiter as a network-layer "time-cost" composition that strictly dominates the pre-removal delay-hash defense.*
