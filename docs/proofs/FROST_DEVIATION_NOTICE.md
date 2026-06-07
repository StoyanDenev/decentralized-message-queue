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

## 6. What remains of FROST in the repo

The FROST C99 implementation under `src/crypto/frost/` (including DKG, threshold signing, PSS refresh, all audit findings remediated per `C99CryptoStackAudit.md`) is **retained in the codebase** for three reasons:

1. The code shipped and was audited; deleting it would erase audit history.
2. Future post-launch DApps may choose to use FROST as a DApp-layer primitive (DApp-level use is outside the no-migrations constraint — DApps can use whatever crypto they want, including FROST as a library; this NOTICE only constrains the *chain consensus path*).
3. Removing the implementation would invalidate the test infrastructure (`test-frost-c99`) which exercises useful negative paths for the broader C99 crypto stack.

**The clear separation:** FROST is available as a *library* under `src/crypto/frost/`. It is NOT part of the chain consensus path, NOT part of the v1.1-locked formal-verification surface, NOT part of any v1.1 substrate bundle. Any DApp post-launch wanting to use it as a library does so under DApp-layer authority, not chain authority.

## 7. Authority

This NOTICE is authoritative for the project. Any document in `docs/proofs/`, `docs/`, `README.md`, or memory that contradicts this NOTICE is superseded by this NOTICE. Re-introduction of FROST into the chain consensus path requires Stoyan Denev's explicit sign-off in writing, satisfying §3 above, and corresponding DECISION-LOG entry.

---

*End of NOTICE. Append-only beyond this point — corrections only, no retroactive modification of the provenance statement above.*
