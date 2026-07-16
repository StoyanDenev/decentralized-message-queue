# NOTICE — FROST is a Claude-introduced design deviation, not part of Stoyan Denev's original Determ design

**Status:** PROVENANCE RECORD. Load-bearing for any future proposal to re-introduce FROST or threshold-signature primitives into Determ's chain-consensus path.

**Date issued:** 2026-06-07
**Author of record:** Stoyan Denev (project owner)
**Document author:** Claude Opus (the AI system that introduced the deviation, recording it for the record at Stoyan's direction)

---

## 1. Statement of provenance

FROST (Flexible Round-Optimized Schnorr Threshold signatures), the entire FROST-Ed25519 stack (DKG via Feldman VSS, threshold signing, partial+aggregate split, Proactive Secret Sharing refresh) under `src/crypto/frost/` + the `v2.10-DKG-SPEC.md` + the `V210ImplementationRoadmap.md` + the `FrostThresholdSoundness.md` proof construction + all FROST-related commits in the project history (commit range approximately `92a85b5` through `8241587`, plus PSS commits `090735f` and `ab381be`) **is not part of Stoyan Denev's original Determ design.**

FROST was introduced into the project's design conversations by Claude (an Anthropic AI system, model Claude Opus) during AI-assisted design sessions. It was proposed as a way to achieve threshold randomness for block generation and as the underlying primitive for what eventually became the DSSO (Distributed Single Sign-On) plan in `V1.1-PLAN.md` Bundle A.

The proposal was accepted at the time and propagated through specs, planning documents, and implementation work (the C99 FROST implementation under `src/crypto/frost/` did ship — that code is real and audited). On re-examination 2026-06-07 under the v1.1-launch + no-migrations + formal-verifiability frame, FROST was found to be **not load-bearing**:

- Block randomness: already provided by v1.x commit-reveal protocol (`R = SHA256(delay_seed ‖ ordered_secrets)`; unbiasable under SHA-256 preimage resistance; selective abort cryptographically defeated)
- Block authentication: already provided by K individual Ed25519 signatures
- DSSO: implementable using DLT-native primitives already shipped (X25519 threshold DH for the T-OPRF leg + block-anchored DAPP_CALL with K-of-K block signature for the assertion-binding leg — see `DECISION-LOG.md 2026-06-07` "Option C + DLT-A")

FROST was therefore **removed from the v1.1 launch scope** by Stoyan's direction at 2026-06-07. The implementation code under `src/crypto/frost/` is retained for historical reasons (audit completeness) but is not part of the v1.1 consensus path, is not part of the formal-verification target surface, and **must not be re-introduced** without explicit re-justification against the criteria below.

## 2. Why this matters

The project's no-migrations constraint is load-bearing for formal verifiability (per `DECISION-LOG.md 2026-06-06 (afternoon)` and memory `dlt-no-migrations-constraint`). Every primitive in the v1.1-locked surface must be:

1. **Traceable to an intentional design decision** by the project owner — not extrapolated by an AI system that does not bear the consequences of the chain's permanence.
2. **Load-bearing for a v1.1 property commitment** (god protocol, DSSO, PFS, or chain consensus correctness) — not added "for forward optionality" or "because it's the standard threshold scheme."
3. **Justified against simpler DLT-native alternatives** — Determ's character is K-of-K + commit-reveal + Ed25519 + X25519. Additions that introduce new crypto families (DKG, threshold signing, PSS, pairing primitives, BLS) increase the formal-verification surface and the audit burden for the chain's entire lifetime.

FROST failed all three on re-examination:
1. It was AI-introduced, not Stoyan-designed.
2. The v1.1 properties (god protocol, DSSO, PFS) are all achievable without it.
3. DLT-native alternatives (X25519 threshold DH + commit-reveal aggregation + K individual Ed25519 sigs + block-anchored DAPP_CALL) deliver the same functional outcomes with zero new crypto surface.

## 3. How to use this NOTICE

**Before proposing any threshold-signature primitive for the chain consensus path** (FROST, BLS, MuSig2, Schnorr aggregation, or any other), the proposer must:

1. **Justify against this NOTICE.** Explain why the v1.x commit-reveal + K Ed25519 sig model is insufficient for the proposed use case.
2. **Trace to a Stoyan-designed requirement.** Identify the original design property that requires the new primitive, with reference to project documents authored or signed off by Stoyan, not AI-generated documents.
3. **Quantify the formal-verification cost.** The proposed primitive will become part of the immutable v1.1+ surface. Estimate the proof-track expansion (new soundness theorems needed, new audit families, new failure modes to characterize).
4. **Estimate the no-migrations cost.** Under `dlt-no-migrations-constraint`, the primitive is locked forever once shipped. Articulate the cost of "wrong choice locked forever."

If the proposer cannot meet all four bars, the default answer is **no** — Determ's character is K-of-K + commit-reveal + Ed25519 + X25519, and additions are foreclosed by formal-verifiability + no-migrations.

## 4. Generalization — for any AI-introduced design element

This NOTICE establishes a precedent for the project: **AI-introduced design elements that become load-bearing in long-lived artifacts must be flagged as such**, so that future re-examination can scrutinize them against the originator's intent.

The fundamental asymmetry: an AI system that proposes a design element does not bear the consequences of that element's permanence. A human designer (here, Stoyan) does. When the consequence is "this primitive is in the chain's immutable surface forever, and the formal-verification track must cover it for the chain's lifetime," the provenance of that primitive matters.

This is not a criticism of AI-assisted design — AI suggestions surfaced valid primitives that needed evaluation. It is a discipline: AI proposals must be reviewed against the project owner's original intent before they are accepted into the immutable surface. The discipline failed for FROST (the proposal propagated through specs + implementation + audit before re-examination caught it). This NOTICE records the failure mode so future sessions can apply the discipline preemptively.

**Operational rule for future sessions:** Before any AI-introduced primitive lands in `IMPLEMENTATION-SEQUENCING.md` substrate bundles, `V1.1-PLAN.md` application bundles, or `Improvements.md §7` schema commitments, the AI must:
- Identify it as AI-suggested in the proposal
- Cite the original design property it addresses
- Compare against DLT-native alternatives explicitly
- Defer to Stoyan for accept/reject before recording in any immutable document

## 5. Files affected by FROST removal (cascade applied 2026-06-07)

The FROST removal applied 2026-06-07 affects (changes recorded in `DECISION-LOG.md 2026-06-07`):

- `V1.1-PLAN.md` Bundle A — DSSO mechanism switched from FROST-based T-OPAQUE to DLT-A composition (T1 X25519 threshold DH OPRF + B3 block-anchored DAPP_CALL assertion)
- `V1.1-PLAN.md` Bundle 1 — v2.10 FROST chain-wiring removed from substrate scope
- `IMPLEMENTATION-SEQUENCING.md` Bundle 1 — v2.10 substrate work removed from critical path
- `Beaconless-v2-SPEC.md §4.6` — cross-shard randomness switched from FROST-Ed25519 threshold signature to commit-reveal aggregation across shards
- `V210ImplementationRoadmap.md` — marked HISTORICAL; FROST chain-integration path closed
- `ECONOMICS_CONFIG_GUIDANCE.md §2.2` — K-of-K FROST forward-compat note removed (no longer applicable; 1/K split is unambiguous under K individual Ed25519 sigs)
- `Improvements.md §7.1` — BLS aggregation rationale updated (no FROST-Ed25519 fallback path needed); `signature_form` discriminator decision flagged for re-evaluation
- `CRYPTO-C99-SPEC.md` — FROST sections (§3.8+) marked NOT IN v1.1 CONSENSUS PATH; implementation retained for historical reference + audit completeness
- Memory `dlt-no-migrations-constraint` — DSSO mechanism updated to DLT-A; FROST_DEVIATION_NOTICE referenced

## 6. What remains of FROST in the repo — **FROZEN** (amended 2026-07-03)

The FROST C99 implementation under `src/crypto/frost/` (including DKG, threshold signing, PSS refresh, all audit findings remediated per `C99CryptoStackAudit.md`) is **retained FROZEN** for two reasons:

1. The code shipped and was audited; deleting it would erase audit history.
2. Removing the implementation would invalidate test infrastructure (`test-frost-c99`, the RFC 9591 E.1 vector gate in both §3.13 halves, the frost timing-probe targets) which exercises useful negative paths for the broader C99 crypto stack.

**Amendment (2026-07-03, authority: Stoyan Denev):** the original §6 cited a third retention reason — prospective DApp-layer usefulness ("future post-launch DApps may choose to use FROST as a DApp-layer primitive"). On review under §4 of this NOTICE, that claim was itself AI-introduced optionality with no existing consumer, and it is **withdrawn as a retention justification**. DApp-layer use remains *permitted* as a matter of scope (DApp-level code is outside the no-migrations constraint; this NOTICE constrains only the chain consensus path), but a hypothetical future consumer is not a reason to keep — or grow — the module; such a consumer could equally vendor an external implementation.

**FROZEN means:** the existing tests, vector gates, probe targets, and coherence guards stay green (retention reasons 1-2 require a verified artifact, not a rotting one), and **no further feature, validation, vector, probe, or documentation investment** goes into the module. Specifically NOT planned: the RFC-mode binding-factor transcript (byte-exact RFC 9591 R/sig-share interop), the zcash/frost-ed25519 cross-check, RFC 9591 Appendix C vector expansion, and DKG ceremony orchestration. Un-freezing requires Stoyan Denev's explicit re-scoping; a DApp-layer consumer materializing does not by itself un-freeze it.

**The clear separation:** FROST is available as a *library* under `src/crypto/frost/`. It is NOT part of the chain consensus path, NOT part of the v1.1-locked formal-verification surface, NOT part of any v1.1 substrate bundle. Any DApp post-launch wanting to use it as a library does so under DApp-layer authority, not chain authority.

## 7. Authority

This NOTICE is authoritative for the project. Any document in `docs/proofs/`, `docs/`, `README.md`, or memory that contradicts this NOTICE is superseded by this NOTICE. Re-introduction of FROST into the chain consensus path requires Stoyan Denev's explicit sign-off in writing, satisfying §3 above, and corresponding DECISION-LOG entry.

---

*End of NOTICE. Append-only beyond this point — corrections only, no retroactive modification of the provenance statement above.*

## 8. Amendment 2026-07-09 — module DELETED from the tree (pre-launch register B2)

**Authority: Stoyan Denev, pre-launch decision register item B2 (jointly A7), 2026-07-09 — `PRE-LAUNCH-DECISIONS.md`.** The frozen module is now **DELETED from the tree entirely**: `src/crypto/frost/`, the C++ bridge (`frost.cpp` / `frost.hpp` headers), together with the RingCT/LSAG/CLSAG ring-signature library (`src/crypto/ringsig/` + headers) and their test surfaces (`test-frost-c99`, `test-frost-types`, `test-lsag-c99`, `test-clsag-c99`, `test-ringct-spend-c99`, wrappers, vectors, and python oracles). Git history preserves the code; the audit and soundness documents remain in `docs/proofs/` as the retained design record. This supersedes §6's FROZEN-retention: audit history now lives in git plus the retained docs, and the test-infrastructure retention reason lapsed with the tests' removal. **Re-adding FROST (or the ring-signature library) is a normal reviewed feature; the deviation discipline in §3–§4 stays in force.**

## 9. Amendment 2026-07-09 — doc-consolidation increment 1: the v2.10 document set DELETED; absorbed claims

**Authority: Stoyan Denev, standing doc-consolidation directive (2026-07-09).** The v2.10 / FROST document set is deleted from `docs/proofs/` — git history is the archive: `FrostVerifyDelegation.md` (248 lines), `FrostThresholdSoundness.md` (328), `V210ImplementationRoadmap.md` (468), `F2-V210-IMPLEMENTATION-PLAN.md` (194), `V210-PhaseD-RandomnessWiring.md` (383), `v2.10-DKG-SPEC.md` (370), `tla/FrostVerify.tla` (640; FB23, spec-only, never model-checked) — 7 files, 2,631 lines. This supersedes §8's phrasing that the soundness documents "remain in `docs/proofs/`": the retained design record is now git history + this NOTICE + the surviving `C99CryptoStackAudit.md`. This NOTICE itself stays — it is the governing deviation discipline.

### Absorbed from the deleted v2.10 document set (consolidation increment 1)

The only claims with forward value, each re-verified against the current tree before recording:

- **Block-beacon decision rationale** (was `V210-PhaseD-RandomnessWiring.md` §1/§9; surviving-doc pointers to that §9 now resolve here). A FROST/Schnorr aggregate is randomized and non-unique — `R` depends on the signer subset and its fresh per-session nonces — so FROST-as-block-beacon is NOT a bias-resistance upgrade over the retained v1 MPDH commit-reveal beacon (`compute_block_rand`, `src/node/producer.cpp`): grinding is already closed information-theoretically by the hiding commit (FA3, `SelectiveAbort.md`), and abort is handled by re-roll + suspension slashing. Round-2-withholding robustness (a fixed round-1 commitment set determines one `(R, z)` for every aggregator) is neither subset-invariance nor beacon-grade unbiasability. The only unbiasable-*by-construction* beacon is a unique-signature scheme (threshold BLS, as in drand/DFINITY) — which would add a pairing curve, a primitive family Determ deliberately excludes (pairing work is offloaded to the external zk-VM layer per the God Stack pattern). The genuine forks are therefore: keep MPDH (chosen), or go threshold-BLS if unbiasable-by-construction ever becomes a hard requirement. FROST is a middle option that costs nearly as much as BLS without delivering its defining property.
- **MPDH statelessness is an architectural asset** (was `V210-PhaseD-RandomnessWiring.md` §9.1). A fresh per-block secret with no long-lived key material means committee membership changes need zero key-management ceremony (any threshold beacon instead requires DKG or PSS ceremonies on churn), and it is what lets `Beaconless-v2-SPEC.md` §Q6 use each shard's header-chain-authenticated `cumulative_rand` as its cross-shard contribution (decision recorded there; hard precondition: the genesis-pinned `randomness_aggregation_form` discriminator, under no-migrations).

Everything else in the deleted set is either superseded in surviving docs — the Ed25519 TweetNaCl-vs-`ref10` backend record lives in `CRYPTO-C99-SPEC.md` §3.2 note; the F2 (v2.7) half of the implementation plan is documented by `F2-SPEC.md` + `SECURITY.md` S-030; the DKG spec's crypto-substrate corrections live in `DECISION-LOG.md` 2026-07-07 — or is roadmap/proof content for the deleted module, preserved by git.

*Consolidation record: increment 1, 2026-07-09 — 7 files / 2,631 lines deleted; 2 claims absorbed above.*

## 10. Amendment 2026-07-15 — DSSO T-OPRF leg re-based to P-256 (DLT-B); the X25519-threshold-DH statements above are the 2026-06-07 historical record

**Authority: Stoyan Denev, 2026-07-15 (`DECISION-LOG.md` 2026-07-15; mechanism spec `v2.25-DSSO-DAPP-SPEC.md`).** §1, §2, and §5 above record the 2026-06-07 removal rationale verbatim, including "X25519 threshold DH for the T-OPRF leg." A 2026-07-15 coherence review found that instantiation unimplementable on the shipped clamped x-only X25519 API (no point addition, no unclamped scalar multiplication, no hash-to-curve) and without a published security proof (RFC 9497 restricts OPRF suites to prime-order group abstractions). The T-OPRF leg now runs **t-of-n on the shipped P-256 RFC 9497 VOPRF stack** (DLT-B, user-dealt Shamir shares — no DKG). Everything this NOTICE says about FROST is unchanged: DLT-B introduces **no threshold signing** — the assertion attestation remains the chain's K-of-K block signature (attesting inclusion, not authentication truth) — and §3's re-introduction bars stay fully in force. Read the X25519-T-OPRF mentions above as the historical record of the 2026-06-07 decision, superseded on this point by DLT-B.
