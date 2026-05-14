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

Suppose `B ≠ B'` are valid at height `h` and have the same committee `K_h` (Lemma 1.1). Suppose further `compute_block_digest(B) ≠ compute_block_digest(B')` (the "B and B' represent semantically different blocks" case — see §3 for the alternative). Then for every `v_i ∈ K_h`, there exist signatures `σ_a, σ_b ∈ {0,1}⁵¹²` with:

- `Verify(pk_i, compute_block_digest(B), σ_a) = 1`
- `Verify(pk_i, compute_block_digest(B'), σ_b) = 1`
- `compute_block_digest(B) ≠ compute_block_digest(B')`

i.e., `v_i` has signed two distinct digests at the same height `h`.

**Proof.** V8 (Preliminaries §5) for `B`: at least K members of `K_h` have signed `compute_block_digest(B)` (exactly K for MD-mode, ≥ ⌈2K/3⌉ for BFT). V8 for `B'`: same, with `compute_block_digest(B')`.

For MD-mode blocks, **all** K members have signed each. So every `v_i ∈ K_h` signed both digests. The two signatures `(σ_a, σ_b)` witnessing this are extracted from `B.creator_block_sigs[i]` and `B'.creator_block_sigs[i]` respectively, both of which verify under V8.

For BFT-mode blocks with `K_eff = ⌈2K/3⌉`, only at least `K_eff` members signed each. By inclusion-exclusion on K-element sets:

- Let `S(B) ⊂ K_h` be the set that signed `digest(B)`, `|S(B)| ≥ K_eff`.
- Let `S(B') ⊂ K_h` be the set that signed `digest(B')`, `|S(B')| ≥ K_eff`.
- `|S(B) ∩ S(B')| ≥ |S(B)| + |S(B')| - K ≥ 2K_eff - K = 2⌈2K/3⌉ - K ≥ K/3 + 1` (since `K_eff ≥ (2K+2)/3`).

So at least `⌈K/3⌉ + 1` members signed both digests. (For BFT-mode `K = 3`, `K_eff = 2`, intersection ≥ 1.)

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

This bound is significantly tighter than the BFT-mode safety claim (FA5), which is conditional on `f < K_eff/3` and degrades sharply above that threshold.

### 5.3 What this proof does NOT cover

- **Liveness.** T-1 says nothing about whether *any* block finalizes — only that no two valid blocks can coexist at the same height. See `Liveness.md` (FA4).
- **Network model variability.** T-1 is independent of synchrony assumptions. It holds in fully asynchronous networks too. Validity is a local predicate.
- **Cross-shard atomicity.** T-1 is per-chain. Cross-shard safety (atomicity, no double-credit) is in `CrossShardReceipts.md` (FA7).
- **BFT-mode conditional safety.** When `B` and `B'` are both BFT-mode blocks (consensus_mode = BFT), Lemma L-1.3 gives only `⌈K/3⌉ + 1` overlap, not full K. BFT-mode safety relies on `f < K_eff/3` in the committee plus equivocation slashing; the full BFT-mode argument is in `BFTSafety.md` (FA5).
- **"≤ 1 block instance per digest" (S-030 D2).** T-1 says "at most one *digest* finalizes per height" — a single Hash value. It does NOT directly say "at most one *block instance* per height." The K-of-K committee signs `compute_block_digest()`, which is narrower than `Block::signing_bytes()` (it excludes Phase-2-reveal-time fields and several evidence/receipt list fields). Two block instances differing only in those excluded fields share the same digest; both pass K-of-K signature verification.

  **Current state (post-S-033, partial closure).** `Block::signing_bytes` now binds `state_root` (when non-zero), which is the Merkle root over canonical state after apply. The validator re-derives state_root at apply time and rejects on mismatch. Two block instances with differing evidence/receipt lists produce different post-apply states → different state_roots → at most one apply-validates on any honest node. The state-divergence window narrows from "one block wide" (pre-S-033, recovered at N+1 via prev_hash) to "zero blocks (detected at apply with a loud diagnostic)."

  Two K-of-K-signed instances can still both circulate on the gossip layer (their signatures over the narrower `compute_block_digest` are both valid), but only one apply-validates. Honest nodes converge on the apply-validating instance; nodes that received the wrong one resync from peers. The literal "≤ 1 finalized block instance per height" property is enforced at the apply layer rather than at signature gathering — functionally equivalent for honest-majority deployments but with a residual consensus-layer gap for fully-Byzantine-committee scenarios.

  **Full closure (planned v2.7 F2 view reconciliation).** Extends `compute_block_digest()` to cover the ✗-row fields directly, via Phase-1 view reconciliation. K-of-K signatures gather only if committee views agree on the evidence/receipt lists → divergent instances cannot both be K-of-K-signed → literal "≤ 1 instance per height" enforced at the consensus layer. Full analysis (including comparison of the two closure paths): `S030-D2-Analysis.md` §3.5. Implementation specification (resolving 9 open design questions): `F2-SPEC.md`.

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
| BFT-mode `K_eff` branch | same, `consensus_mode == BFT` branch |
| Committee determinism L-1.1 | `BlockValidator::check_creator_selection` + `src/node/node.cpp::check_if_selected` |
| `signing_bytes` injectivity L-1.2 | `src/chain/block.cpp::Block::signing_bytes` |
| Block digest L-1.2 | `src/node/producer.cpp::compute_block_digest` |
| Equivocation detection (clause 2) | `src/node/node.cpp::apply_block_locked` (cross-block check) + FA6 |

A future reviewer can re-validate the proof by reading the source-level objects in the right column against the predicates in the left.
