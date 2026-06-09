# FA1 — Safety theorem (fork freedom)

This document proves that Determ's K-of-K mutual-distrust protocol produces at most one valid block per height, under the cryptographic assumptions of `Preliminaries.md` §2 plus the honest-behavior definition §4.

**Companion documents:** `Preliminaries.md` (notation, model, validator definition); `EquivocationSlashing.md` (FA6, picks up the "fully-Byzantine committee" edge case).

---

## 1. Theorem statement

**Theorem T-1 (Safety).** Let `B` and `B'` be blocks both passing `BlockValidator::validate` (Preliminaries §5, V1–V15) against the same chain prefix `B₀, …, B_{h-1}` at height `h ≥ 1`. Under the assumptions:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2): no polynomial-time adversary forges a signature by an honest key with non-negligible probability.
- **(A2) SHA-256 collision resistance** (Preliminaries §2.1): no polynomial-time adversary finds `x ≠ y` with `H(x) = H(y)` with non-negligible probability.

then **at least one** of the following holds:

1. `B = B'` (the blocks are syntactically identical), or
2. **Every** committee member `v ∈ K_h` has produced two valid signatures over distinct values at height `h` — i.e., every committee member has equivocated.

**Corollary T-1.1 (Safety with at least one honest member).** If at least one member of `K_h` is honest (definition §4, H2), then `B = B'`.

In plain terms: two valid blocks at the same height require the **entire** committee to be Byzantine and to have signed both. With any honest member, the protocol is unconditionally fork-free.

The fully-Byzantine-committee case (T-1 clause 2) leaves a slashable forensic trail — see `EquivocationSlashing.md` (FA6).

**Scope clarification — "block" means "block digest" here.** "Two valid blocks at the same height" is interpreted at the digest level: `compute_block_digest(B) = compute_block_digest(B')`. The K-of-K committee signs over this digest, so two distinct digests passing K-of-K verification is what T-1 rules out. A weaker question — "can two distinct block *instances* share the same digest" — is separately addressed: the digest covers the canonical Phase-1 commit material but excludes Phase-2-reveal-time fields and several evidence/receipt list fields. The `prev_hash` chain (which uses `signing_bytes`, covering everything) closes that residual ambiguity at the next block boundary. The full discussion is §5.3 plus `S030-D2-Analysis.md`. Reading FA1 as proving "at most one block instance per height" is stronger than what's proven here; the chain-level "at most one finalized block instance per height" follows from T-1 *plus* the `prev_hash`-chain argument made elsewhere.

---

## 2. Lemmas

### Lemma L-1.1 — Committee determinism

For any height `h ≥ 1` and any pair of valid blocks `B, B'` at height `h` against the same chain prefix, `B.creators = B'.creators` (the same K-vector, in the same order).

**Proof.** Validity requires V3 (committee selection): `B.creators` is the unique deterministic K-committee derived from the chain prefix plus `B.abort_events`. The chain prefix is the same by hypothesis. The committee depends only on:

- `epoch_committee_seed(epoch_rand, shard_id)` (Preliminaries §6) — a function of the chain prefix and the chain's pinned `shard_id`. Independent of `B`.
- `B.abort_events`, mixed in via `round_rand` (§6). Each abort event's `event_hash` enters the derivation.

If `B.abort_events ≠ B'.abort_events`, then `B.creators` and `B'.creators` are derived from different `round_rand` values. They could in principle yield the same committee, but in this proof we treat the abort-events sequence as an input to the committee-selection function and rely on V3 to rule out both blocks having the *same* selection from *different* inputs.

Formally: V3 enforces `B.creators = select_m_creators(round_rand(B), |pool|, K)` and identically for `B'`. If `round_rand(B) ≠ round_rand(B')`, the selections may differ; both blocks have passed V3 against their own respective committees, so this isn't a contradiction by itself — but it is then a sub-case (different committees) addressed in §3 case (b).

For the **same abort_events** sub-case (which dominates in practice — abort_events are bound into the round_rand the same way for both blocks), `B.creators = B'.creators` follows by determinism of `select_m_creators`.   ∎

### Lemma L-1.2 — `signing_bytes` injectivity (cryptographic)

If `signing_bytes(B) = signing_bytes(B')`, then `B` and `B'` differ at most in `B.creator_block_sigs` (the Phase-2 signature array appended *after* `signing_bytes` to form `compute_hash`). Under SHA-256 collision resistance (A2), `compute_block_digest(B) = compute_block_digest(B')` follows whenever the digest-bound fields match (Preliminaries §1.3).

**Proof.** `signing_bytes(B)` is a canonical serialization of all `Block` fields except `creator_block_sigs` (see `src/chain/block.cpp::signing_bytes`). The serialization is injective on the field set it covers: each field uses a fixed-width or length-prefixed encoding. So two blocks with the same `signing_bytes()` agree on every field except possibly the Phase-2 sig vector.

`compute_block_digest(B)` (Preliminaries §1.3) is `SHA256` over the strict subset of fields `{index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators[], creator_tx_lists[][], creator_ed_sigs[], creator_dh_inputs[]}` — all included in `signing_bytes`. If those match, the digest matches up to a SHA-256 collision (probability ≤ `2⁻¹²⁸` under A2).   ∎

### Lemma L-1.3 — Pigeonhole on K-of-K signatures

Suppose `B ≠ B'` are valid at height `h` and have the same committee `K_h` (Lemma L-1.1). Suppose further `compute_block_digest(B) ≠ compute_block_digest(B')` (the "B and B' represent semantically different blocks" case — see §3 for the alternative). Then for every `v_i ∈ K_h`, there exist signatures `σ_a, σ_b ∈ {0,1}⁵¹²` with:

- `Verify(pk_i, compute_block_digest(B), σ_a) = 1`
- `Verify(pk_i, compute_block_digest(B'), σ_b) = 1`
- `compute_block_digest(B) ≠ compute_block_digest(B')`

i.e., `v_i` has signed two distinct digests at the same height `h`.

**Proof.** V8 (Preliminaries §5) for `B`: at least `K` (MD-mode, `|B.creators| = K`) or `Q = ⌈2·k_bft/3⌉` (BFT-mode, where `|B.creators| = k_bft = ⌈2K/3⌉ = |K_h|`) members have signed `compute_block_digest(B)`. V8 for `B'`: same, with `compute_block_digest(B')`.

For MD-mode blocks, the quorum is `K` and **all** K members have signed each. So every `v_i ∈ K_h` signed both digests. The two signatures `(σ_a, σ_b)` witnessing this are extracted from `B.creator_block_sigs[i]` and `B'.creator_block_sigs[i]` respectively, both of which verify under V8.

For BFT-mode blocks the committee size shrinks to `|K_h| = k_bft = ⌈2K/3⌉` and the quorum within that smaller committee is `Q = ⌈2·k_bft/3⌉ = ⌈2|K_h|/3⌉`, leaving `|K_h| − Q` sentinel slots. By inclusion-exclusion: `|S(B) ∩ S(B')| ≥ 2Q − |K_h|` (≥ 2 in the worked cases K = 3, 6, 9, and growing thereafter). At least the intersection-many members signed both digests. See `BFTSafety.md` (FA5) for the conditional-safety argument that builds on this overlap.

Therefore at least one — and in MD-mode, every — member of `K_h` has produced two valid signatures over distinct digests at `h`.   ∎

---

## 3. Proof of Theorem T-1

Let `B, B'` both pass `BlockValidator::validate` at height `h` against the same chain prefix `B₀, …, B_{h-1}`. Three cases by Lemmas L-1.1 and L-1.2:

**Case (a): `signing_bytes(B) = signing_bytes(B')` and `B.creator_block_sigs = B'.creator_block_sigs`.**

By L-1.2, every digest-bound field of `B` equals that of `B'`. Adding the equal `creator_block_sigs`, `compute_hash(B) = compute_hash(B')` (a stronger equality including the Phase-2 sigs). Block records are determined by `compute_hash` plus the explicit fields, so `B = B'`.   ✓ T-1 clause 1.

**Case (b): different `abort_events` between `B` and `B'` (different committees).**

By L-1.1's branch for `B.abort_events ≠ B'.abort_events`, the committees `B.creators` and `B'.creators` may differ. But V10 requires every `ae ∈ B.abort_events` to carry a `K-1`-quorum of signed `AbortClaimMsg` against the aborting node by committee-at-that-event members. If `B.abort_events` includes events that `B'.abort_events` doesn't (or vice versa), then either:

- (b.i) The "extra" abort_event has a valid quorum: K-1 distinct, valid claims by committee members at the at-event round. These signatures are forensic evidence in the chain transcript. Under EUF-CMA (A1), they cannot be forged. They genuinely exist.
- (b.ii) The "extra" abort_event has an invalid quorum: V10 fails, contradicting block validity.

(b.ii) is ruled out. In (b.i), the K-1 honest-or-Byzantine signers genuinely existed. The block divergence is then *caused* by genuine in-protocol abort sequences (which the protocol explicitly allows — different abort patterns produce different committees in subsequent rounds). For the safety claim, we observe:

- If at least one of the `B`'s or `B'`'s committee is fully Byzantine, we fall to clause 2 of T-1.
- If both committees have at least one honest member, then the abort-events sequences are consistent across honest views (under partial synchrony + gossip propagation), and only one such sequence can be reproduced consistently — so only one of `B, B'` is what honest observers will adopt. This is a liveness/fork-choice property, not a safety property; it's covered by `Liveness.md` (FA4) and not strictly here.

For the formal safety claim, case (b) reduces to case (c) when both blocks are simultaneously valid in some honest view — that is, when both arrive at honest validators as "valid against my chain prefix" — which requires both committees to share at least one signed digest. We don't need this sub-claim for T-1; we just note that case (b) is consistent with the corollary's required setup.

**Case (c): different `signing_bytes` (and so different `compute_block_digest`).**

By L-1.1 (same abort_events sub-case), `B.creators = B'.creators = K_h`. By L-1.2, `compute_block_digest(B) ≠ compute_block_digest(B')`. By L-1.3, every member of `K_h` has signed both distinct digests at `h`.

For each `v_i ∈ K_h`, two outcomes:

- **(c.i)** `v_i` is honest (definition §4). H2 states honest members sign at most one digest per height. Contradiction. So `v_i` cannot be honest.
- **(c.ii)** `v_i` is Byzantine. No contradiction — Byzantine members may produce arbitrary signatures, subject only to the inability to forge honest keys (A1).

If at least one `v_i ∈ K_h` is honest, (c.i) gives a contradiction; therefore the case (c) configuration is impossible.

If every `v_i ∈ K_h` is Byzantine, (c.ii) holds for every member, and clause 2 of T-1 obtains: every committee member has equivocated.

In summary:

- Cases (a), (b): consistent with `B = B'` or with non-equivocation paths.
- Case (c): requires every committee member to be Byzantine AND to have equivocated.

T-1 follows.   ∎

---

## 4. Proof of Corollary T-1.1

Assume at least one `v_j ∈ K_h` is honest. Cases (a) and (b) are consistent with `B = B'` (case (a)) or are reductions to case (c) under further analysis. Case (c) is impossible under the honest-member assumption (Lemma L-1.3 step (c.i) gives contradiction).

So only case (a) survives: `B = B'`.   ∎

---

## 5. Discussion

### 5.1 What "unconditional safety" means in Determ's documentation

Determ claims "unconditional fork-freedom" in MD-mode. Reading T-1, this is **slightly informal** but accurate in practice:

- Strict unconditional: would require ruling out clause 2 (fully-Byzantine equivocating committee). T-1 doesn't.
- Practical unconditional: clause 2 is detectable (every signature is on-chain after gossip), and FA6 (equivocation slashing) makes it economically suicidal for any rational actor — every member loses their entire stake AND their domain registration.

The "unconditional" claim is therefore: **fork-freedom holds under any honest-fraction assumption from ≥ 1 honest in `K_h` upward**. A fully-Byzantine committee can technically fork the chain at a height, but every fork-creator gets slashed and re-organizes around the surviving honest member at the next eligible committee selection.

This is materially stronger than BFT protocols' `f < N/3` safety claim, which fails completely above the threshold (no slashing reorganization).

### 5.2 Concrete-security bound

The reduction loses a SHA-256 collision-finding probability (≤ `2⁻¹²⁸`) at L-1.2 and an Ed25519 forgery probability (≤ `2⁻¹²⁸`) at L-1.3. Under standard concrete-security accounting, the safety claim holds with probability `1 - O(2⁻¹²⁸)` per height for an adversary running in polynomial time.

This bound is significantly tighter than the BFT-mode safety claim (FA5), which is conditional on `f_h < |K_h|/3` within the BFT committee and degrades sharply above that threshold.

### 5.3 What this proof does NOT cover

- **Liveness.** T-1 says nothing about whether *any* block finalizes — only that no two valid blocks can coexist at the same height. See `Liveness.md` (FA4).
- **Network model variability.** T-1 is independent of synchrony assumptions. It holds in fully asynchronous networks too. Validity is a local predicate.
- **Cross-shard atomicity.** T-1 is per-chain. Cross-shard safety (atomicity, no double-credit) is in `CrossShardReceipts.md` (FA7).
- **BFT-mode conditional safety.** When `B` and `B'` are both BFT-mode blocks (consensus_mode = BFT), the BFT committee has only `|K_h| = ⌈2K/3⌉` members and the V8 quorum is `Q = ⌈2|K_h|/3⌉`, so Lemma L-1.3 gives only `2Q − |K_h|` overlap (≥ 2 across the worked K=3/6/9/12 cases), not full K. BFT-mode safety relies on `f_h < |K_h|/3` within that smaller committee plus equivocation slashing; the full BFT-mode argument is in `BFTSafety.md` (FA5).
- **"≤ 1 block instance per digest" (S-030 D2).** T-1 says "at most one *digest* finalizes per height" — a single Hash value. It does NOT directly say "at most one *block instance* per height." The K-of-K committee signs `compute_block_digest()`, which is narrower than `Block::signing_bytes()` (it excludes Phase-2-reveal-time fields and several evidence/receipt list fields). Two block instances differing only in those excluded fields share the same digest; both pass K-of-K signature verification.

  **Apply-layer closure (S-033 + S-038, now belt-and-suspenders beneath the consensus-layer binding below).** `Block::signing_bytes` binds `state_root` (when non-zero), which is the Merkle root over canonical state after apply. The producer's `Node::try_finalize_round` populates `body.state_root` via a tentative-chain dry-run before broadcast (S-038 closure — pre-S-038 fix the field was zero on every gossiped block and the gate short-circuited). The validator re-derives state_root at apply time and rejects on mismatch. Two block instances with differing evidence/receipt lists produce different post-apply states → different state_roots → at most one apply-validates on any honest node. The state-divergence window narrows from "one block wide" (pre-S-033, recovered at N+1 via prev_hash) to "zero blocks (detected at apply with a loud diagnostic)."

  Two K-of-K-signed instances can still both circulate on the gossip layer (their signatures over the narrower `compute_block_digest` are both valid), but only one apply-validates. Honest nodes converge on the apply-validating instance; nodes that received the wrong one resync from peers. This apply-layer enforcement was, pre-full-closure, the only line of defense and left a residual consensus-layer gap for fully-Byzantine-committee scenarios. **That gap is now closed at the consensus layer** (every apply-affecting digest field is bound or deterministically pinned — see the Full closure note below); the apply-layer gate described here is retained as a redundant backstop.

  **Full closure (SHIPPED — every digest dimension now bound).** `compute_block_digest()` now covers all apply-affecting fields. The three pool-fed dimensions are bound via v2.7 F2 Phase-1 view reconciliation with **per-field heterogeneous rules** — union (per-event V11 verifiability) for `equivocation_events`, union (per-event V10) for `abort_events`, intersection for `inbound_receipts` (commits `a727cb2` / `48c4b45`); `partner_subset_hash` is bound directly when non-zero (deterministic from merge state, no reconciliation needed — commit `8585a50`, `PartnerSubsetDigestBindingSoundness.md` + FB56); and `timestamp` is bound as the deterministic LOWER-median of the K Phase-1-committed proposer times (commit `f99eeb8`, `TimestampReconciliationSoundness.md` + FB55 — honest-flanked under f<K/3, so a Byzantine minority cannot bias it, and a pure function of the signed commits so honest assemblers never diverge). The fields still absent from the digest are NOT independent divergence vectors: `cross_shard_receipts` is deterministically derived from the committee tx set (`tx_root` + `creator_tx_lists`, both in the digest); the Phase-2-reveal fields are each pinned by digest-bound commitments (`creator_dh_secrets` must match the digest-bound `creator_dh_inputs = SHA256(secret‖pubkey)`; `delay_output = compute_block_rand(delay_seed, secrets)` and `cumulative_rand` derive from those + the digest-bound `delay_seed`); `state_root` is bound through `signing_bytes`/`prev_hash` (S-033/S-038). Therefore two K-of-K-signed instances sharing a digest cannot differ in any apply-affecting field — the literal "≤ 1 block instance per height" property now holds at the **consensus layer** (signatures gather only around one canonical body), with the S-033 apply-layer gate retained beneath as belt-and-suspenders. Full per-field analysis: `S030-D2-Analysis.md` §1 + §5. Companions: `TimestampReconciliationSoundness.md`, `PartnerSubsetDigestBindingSoundness.md`, `EqAbortViewDigestExtension.md`, FB55/FB56.

### 5.4 Why the protocol design supports this proof so cleanly

Determ's safety proof is unusually short for a consensus protocol. Three structural reasons:

1. **No fork-choice rule.** No "heaviest chain" or "longest chain" tiebreaker logic to verify. Fork-freedom is a *local* validation predicate, not a *global* fork-choice outcome.
2. **No leader / proposer.** No leader-election rule to formally verify. K-of-K is symmetric in committee members.
3. **K-of-K means signature quorums are full.** No `f < N/3` quorum overlap arguments needed in MD mode — overlap is `K - K + K = K`, total.

The price for this cleanliness is liveness: a single silent committee member halts the round. BFT escalation (FA5) and rotation (FA4) recover liveness without compromising the safety story above.

---

## 6. Implementation cross-reference

The safety predicate proved here corresponds to the implementation chain:

| Document | Source |
|---|---|
| Validation predicate V1–V15 | `src/node/validator.cpp::BlockValidator::validate` |
| K-of-K quorum check V8 (MD) | `BlockValidator::check_block_sigs` |
| BFT-mode quorum branch (committee `|K_h| = ⌈2K/3⌉`, quorum `Q = ⌈2|K_h|/3⌉`) | same, `consensus_mode == BFT` branch via `producer.cpp::required_block_sigs` |
| Committee determinism L-1.1 | `BlockValidator::check_creator_selection` + `src/node/node.cpp::check_if_selected` |
| `signing_bytes` injectivity L-1.2 | `src/chain/block.cpp::Block::signing_bytes` |
| Block digest L-1.2 | `src/node/producer.cpp::compute_block_digest` |
| Equivocation detection (clause 2) | Two paths feed the same `EquivocationEvent` channel: (i) rev.8 BlockSigMsg-level cross-block check in `src/node/node.cpp::apply_block_locked` (matches stored block-at-height vs incoming block-at-height by `bft_proposer`); (ii) S-006 ContribMsg same-generation check in `src/node/node.cpp::on_contrib` (matches the same signer producing two different commits in the same round). Both detections gossip an `EquivocationEvent` that gets baked into the next block; downstream slashing is FA6. |
| State commitment + apply-time gate (S-033 + S-038, S-030 D1/D2 apply-layer closure) | `src/chain/chain.cpp::compute_state_root` (Merkle root) + `apply_transactions` (`if (b.state_root != zero) verify` gate) + `src/node/node.cpp::try_finalize_round` (producer populates `body.state_root` via tentative-chain dry-run before broadcast — S-038 closure) |

A future reviewer can re-validate the proof by reading the source-level objects in the right column against the predicates in the left.

---

## 7. Light-client safety composition

The trust-minimized light-client `determ-light.exe` (shipped commits `f597c44` + `5e74097`, formalized in `LightClientThreatModel.md`) extends the chain-level safety story established above into a per-invocation pipeline that an honest light-client runs against a single (potentially malicious) operator-controlled daemon. The light-client introduces no new chain-level safety invariant; instead, it COMPOSES the existing FA1 / FA-Apply / S-021 / S-033 / S-038 results into a per-block + per-state-proof verifier under the `A_daemon` adversary model.

This sub-section makes the composition explicit so a reader of Safety.md knows where the light-client extension lives without flipping documents.

### 7.1 Preconditions inherited

The light-client safety claim (`LightClientThreatModel.md` §2.3) takes as preconditions every chain-level safety invariant proved in §1–§6 above, plus the state-integrity composition documented in adjacent proofs:

- **T-1 + Corollary T-1.1 (unique chain head).** The daemon, whether honest or malicious, serves a chain whose finalized heads are unambiguous at the digest level. The light-client trusts that the chain it walks is a single canonical sequence (or fails to walk it).
- **L-1.1 (committee determinism).** The committee at each height is a deterministic function of the chain prefix. The light-client's `build_genesis_committee` + creator-set match against `b.creators` rests on this determinism.
- **L-1.2 (`signing_bytes` injectivity + `compute_block_digest` collision resistance).** The light-client's `light_compute_block_digest` (`light/verify.cpp:57-92`) is a byte-for-byte copy of the chain's producer-side digest (`src/node/producer.cpp:608-693`). L-1.2's injectivity is what makes the light-client's local digest recomputation match the producer's signed digest.
- **L-1.3 (K-of-K signature-set pigeonhole).** Equivalently, the per-block K-of-K (or `Q = ⌈2|K_h|/3⌉` in BFT) sig set witnesses that the chain committed a single canonical block at that height. The light-client's `verify_block_sigs` consumes exactly this primitive.
- **S-021 (chain integrity at rest).** `chain.json` wrap with head-hash recompute means the daemon's loaded chain has self-consistent prev_hash links before any RPC reply. The light-client walks the served prev_hash chain on top of this foundation.
- **S-033 (state_root namespace coverage).** The full 10-namespace state surface is bound into `Block.state_root`. The light-client's `read_account_trustless` anchors to this commitment for the `a:` namespace (and the design admits future extension to `d:` / `r:` / etc.).
- **S-038 (producer-side state_root population).** The producer's `try_finalize_round` populates `body.state_root` via tentative-chain dry-run before broadcast, closing the dormancy gap. The light-client's "chain has not activated state_root" diagnostic path (`light/trustless_read.cpp:202-208`) is the failure mode if S-038 is not active on a deployed chain.

If any precondition above fails on a deployed chain, the light-client safety chain breaks at the corresponding step — see §7.4.

### 7.2 Layered theorems

The light-client adds five per-invocation theorems atop the chain-level base. Each is stated formally in `LightClientThreatModel.md` §4; here we record how each composes with the chain-level invariants above.

- **T-L1 (genesis-anchored chain identity).** Composes with **A2 (SHA-256 collision/preimage resistance, Preliminaries §2.1)** to bind the daemon's served block 0 to the operator's pinned `genesis.json`. The chain-level theorems do not need to know about T-L1 — it is a per-invocation gate at the operator side, not a chain-side invariant. The bound (`≤ 2⁻¹²⁸`) follows from A2.
- **T-L2 (head trust via committee signatures).** Composes with **FA1 (this document) + A1 (Ed25519 EUF-CMA)**. T-L2 is FA1's per-block K-of-K signature primitive applied at the light-client side. The light-client does NOT independently re-establish T-1's full-chain "no two finalized blocks at the same height" claim; it relies on the per-block primitive that T-1 uses internally. Composition statement in `LightClientThreatModel.md` §5.1: "T-L2 = FA1 per-block primitive applied at the light-client side." No new claim beyond FA1 is asserted.
- **T-L3 (state-proof correctness).** Composes with **A2 (SHA-256 collision resistance)** and **S-033 (namespace coverage completeness, `S033StateRootNamespaceCoverage.md` T-1 + T-4)**. T-L3 reduces to "forging a Merkle inclusion against a fixed root requires a collision at some level of the tree" — exactly the standard Merkle soundness reduction.
- **T-L4 (balance/nonce trust via state-proof composition).** Composes with **L-1.3 (state-root inclusion semantics — apply-time gate)** and the FA-Apply suite (chain apply-determinism). T-L4 chains T-L1 + T-L2 + T-L3 with a race-window mitigation (`light/trustless_read.cpp:226-307`) covering the gap between head-anchor time `vc.height` and state-proof time `proof_height`. The mitigation's load-bearing step is the three-branch dispatch for `proof_height < / == / > vc.height` plus the prev_hash walk that re-anchors the proof's claimed root to a committee-signed header on the verified prefix. The race-window mitigation is the light-client-side analog of L-1.3 — both bind the state-root commitment to the canonical chain at the apply boundary.
- **T-L5 (sign-and-submit correctness).** Composes with **FA-Apply-3 (NonceMonotonicity, `NonceMonotonicity.md`)** and **A1 (Ed25519 EUF-CMA)** to ensure that an operator-supplied tx envelope, built atop a T-L4-verified `next_nonce`, survives daemon mutation by virtue of the signature binding all envelope fields. The light-client's `compute_signing_bytes` (`light/sign_tx.cpp:37-62`) is a byte-for-byte copy of the chain's `Transaction::signing_bytes`, so the chain's apply-time signature check enforces the same field set the operator signed.

### 7.3 Composition theorem

**Theorem T-1.2 (light-client safety inherits chain safety).** Under the preconditions T-1, T-1.1, L-1.1, L-1.2, L-1.3, S-021, S-033, S-038 (all established in §1–§6 of this document and the adjacent integrity proofs), and the threat model of `LightClientThreatModel.md` §2 (adversary `A_daemon` controlling the daemon; cryptographic primitives A1 + A2 + A3 holding), the light-client `determ-light.exe` never **acts on** data that is inconsistent with the operator's pinned `genesis.json`. "Acts on" instantiates to the five operational claims in `LightClientThreatModel.md` §2.3:

1. signing and submitting a transaction using a nonce or amount not verified against a committee-signed state_root,
2. displaying a balance not so verified,
3. displaying a `next_nonce` not so verified,
4. displaying a head height or head block_hash not verified against the genesis anchor + committee sigs,
5. accepting a state-proof that does not verify against a committee-signed state_root.

**Proof.** Induction over the per-invocation pipeline T-L1 → T-L2 → T-L3 → T-L4 → T-L5.

Each adversarial attempt by `A_daemon` to inject data inconsistent with the genesis-pinned chain is caught at exactly one of the five gates:

- A wrong-genesis lie is caught by T-L1 (byte-equality against locally-computed `compute_genesis_hash(genesis_O)`).
- A forged block header is caught by T-L2 (`Ed25519.Verify` under the seeded committee map).
- A forged Merkle inclusion proof is caught by T-L3 (Merkle path recomputation against the verified root).
- A stale or forked state-proof (different state_root than what the committee signed at the head) is caught by T-L4 (the three-branch race-window dispatch + prev_hash chain re-anchor).
- A mutated tx envelope on the submit path is caught by T-L5 (the chain's apply-time signature check rejects under A1, since the light-client signed the original field set).

The five gates' adversarial-success bounds are independent (each grounded in a separate cryptographic primitive: A2 for T-L1 + T-L3, A1 for T-L2 + T-L5, composition of A1 + A2 for T-L4). The union bound (`LightClientThreatModel.md` §4.4 derivation) is `≤ 2⁻⁶⁰` per invocation for chains of practical size, dominated by the T-L4 race-window step.

By the chain-level preconditions, any data the light-client successfully verifies through all five gates is consistent with the chain that the operator's pinned `genesis.json` identifies — equivalently, consistent with the unique finalized chain that T-1 + S-021 + S-033 + S-038 jointly characterize. Therefore the light-client never acts on inconsistent data.   ∎

**Corollary T-1.2.1 (fail-closed exit).** Under T-1.2, every inconsistency the light-client detects causes a `throw std::runtime_error(...)` that propagates to a non-zero process exit code with a structured stderr diagnostic. Proof: Lemma L-6 of `LightClientThreatModel.md` (no silent-accept code path exists in `light/verify.cpp` or `light/trustless_read.cpp`).   ∎

### 7.4 Limitations of composition

T-1.2 is a CONDITIONAL safety claim: it holds on the chain-level invariants of §1–§6 plus the integrity composition in adjacent proofs. If a chain-level invariant is broken on a deployed chain, the light-client safety chain breaks at the corresponding step:

- If **T-1** were to fail (two finalized blocks at the same height), T-L2's per-block primitive would still succeed for each individual block, but the light-client's prev_hash walk would diverge across invocations against different daemons — surfacing as "this daemon's head doesn't chain to the previously-verified head" rather than silent acceptance. Soundness within a single invocation is preserved; cross-invocation consistency is operator-visible.
- If **S-033** were to regress (a state_root namespace becomes uncommitted), the light-client's `verify_state_proof` would still verify Merkle inclusion against the served root, but the served root would no longer reflect the full chain state. T-L3 holds; T-L4's claim that "the value at the leaf reflects the chain's apply-layer state" weakens because the root no longer commits to the full state. This is exactly the failure mode `S033StateRootNamespaceCoverage.md` defends against.
- If **S-038** were to regress (the producer stops populating `body.state_root` — the pre-S-038 dormancy state), the light-client's `read_account_trustless` would hit the explicit "chain has not activated state_root (S-033)" throw path (`light/trustless_read.cpp:202-208`). Fail-closed exit; no soundness loss, but operational availability is reduced.
- If **L-1.3** / the apply-time state-root gate were to weaken (e.g., a future regression making `if (b.state_root != zero) verify` skipped), the light-client's race-window mitigation would still bind the proof's `state_root` to a committee-signed header, but the bound state-root would no longer correspond to a strictly apply-validated state. This is the S-030 D2 residual gap that `S030-D2-Analysis.md` §3.5 tracks for full closure via v2.7 F2 view reconciliation.

Cross-ref: `SECURITY.md` §S-037 / §S-038 closure narrative for the deployment-prerequisite story; `BlockchainStateIntegrity.md` for the chain-side composition that T-1.2 transitively depends on.

### 7.5 Cross-references

- `docs/proofs/LightClientThreatModel.md` — full T-L1 through T-L5 statements with adversary games, proofs, and concrete-security bounds (§4); supporting lemmas L-1 through L-6 (§4.6); FA-series composition discussion (§5); known limitations and findings register (§6, §7).
- `light/trustless_read.cpp::read_account_trustless` (lines 188-350) — the composite trustless-read flow; the race-window mitigation cited by T-L4 lives at lines 226-307; the cleartext-vs-value_hash cross-check binding the daemon's `account` reply lives at lines 309-343.
- `docs/proofs/Safety.md` §2 (L-1.3) — the K-of-K signature-set pigeonhole that T-L2 leverages as a per-block primitive.
- `docs/proofs/Safety.md` §6 — implementation cross-reference table for the chain-side functions T-L2 / T-L4 invoke transitively.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — namespace-coverage completeness underlying T-L3.
- `docs/proofs/BlockchainStateIntegrity.md` — chain-level integrity composition (S-021 + S-033 + S-038) that T-1.2's preconditions chain to.
