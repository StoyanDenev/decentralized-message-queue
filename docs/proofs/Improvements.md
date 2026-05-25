# Improvements — post-v1.0 enhancement queue

**Purpose.** Capture enhancements identified during pre-implementation review (May 2026) that are deliberately *out of v1.0 scope*. Preserves the rationale for deferral and the design context so future planning sessions can pick items up without rediscovering the analysis.

**Audience.** Future planning sessions; implementation threads asking "should we add X to v1.0?"; security reviewers asking "did you consider Y?"

**Coherence with other artifacts.**
- `IMPLEMENTATION-SEQUENCING.md` — current v1.0 execution plan. This file contains everything **not** in the sequencing plan.
- `DECISION-LOG.md` — backward-looking deliberation history for v1.0 decisions. This file is the forward-looking complement: what was considered but deferred.
- Memory `dlt-no-migrations-constraint` — practical no-migrations interpretation. Every entry here is classified against that constraint.

**Convention.** Each entry carries a classification:

| Classification | Meaning |
|---|---|
| **Additive** | Can ship post-v1.0 without breaking changes (new optional fields, new tx types validators ignore). Compatible with no-migrations constraint. |
| **Breaking** | Requires schema / wire / consensus change post-v1.0. Forbidden under no-migrations except as security-critical hard fork. Effectively requires an explicit "v2 protocol" if ever pursued. |
| **Research** | Primitive or technique doesn't exist in production-grade form yet; revisit when it matures. |
| **Process** | Not a code change — operational or governance change to existing process. |

---

## 1. v2.22 PRIVACY improvements

### 1.1 Forward-secure encryption (FSE / forward-secure HIBE) as PFS alternative

**Improvement.** Replace the OTPK-stream mechanism (PRIV-6) with a single long-term `fs_view_pk` published once at account creation; recipient evolves the master irreversibly each epoch. Eliminates publish-cadence leak entirely (one PUBLISH event ever, not periodic batches).

**Deferred reason.** No production-grade C99 implementation. Canonical Canetti-Halevi-Katz construction requires bilinear pairings (BLS12-381) → would add a third curve family, conflicting with CRYPTO-C99 two-curve discipline. Pairing-free lattice-based FSE constructions exist but are bleeding-edge with no production deployments.

**Classification.** Breaking (replaces OTPK-stream mechanism). **Could be downgraded to Additive** if v1.0 ships a `view_key_mechanism` discriminator + optional `fs_view_pk` field — see §7.5.

**Dependencies.** Production-grade C99 FSE implementation OR explicit acceptance of a third curve family.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary; §7.5 schema-freeze decision.

### 1.2 Puncturable encryption (Green-Miers / Bloom-filter)

**Improvement.** Per-tx PFS via single long-term keypair that punctures at specific tags after use. No publish events of any kind post-account-creation.

**Deferred reason.** Research-grade primitive; no production deployments; secret-key state grows with each puncture; false-positive risk in Bloom-filter variants requires careful parameterization.

**Classification.** Breaking. **Could be downgraded to Additive** via the same `view_key_mechanism` discriminator as §1.1 — see §7.5.

**Dependencies.** Production-grade C99 puncturable encryption + extensive cryptographic audit.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary; §7.5 schema-freeze decision.

### 1.3 Stealth addresses (Monero-style) for graph privacy

**Improvement.** Combine amount-PFS with recipient-graph-privacy. Sender derives a fresh stealth address per tx via DH against recipient's `spend_view_pk`; recipient scans chain to find their own.

**Deferred reason.** Architectural change vastly larger than v2.22's amount-PFS scope. Requires full chain scan per recipient per receive — light-client problem unsolved at scale; Monero hits this wall too. Conflicts with v2.24 audit model (stealth addresses designed to be unlinkable). Appropriate as v3+ work alongside broader graph-privacy.

**Classification.** Breaking + research (light-client scan optimization needed at scale).

**Dependencies.** Light-client scan optimization research OR acceptance of full-scan recipient cost; v3 audit-model redesign.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary.

### 1.4 OOB ephemeral exchange (established-pair PFS mode)

**Improvement.** For sender-recipient pairs with existing secure messaging channels (Signal, encrypted email), exchange ephemeral DH keys out-of-band. Zero on-chain metadata for the exchanged keys; per-tx PFS preserved.

**Deferred reason.** Useless as general-purpose mechanism — requires bidirectional OOB channel per sender-recipient pair; doesn't fit ad-hoc send. May ship as opt-in "established-pair PFS" mode for B2B counterparties with existing relationships.

**Classification.** Additive (new opt-in mode alongside PRIV-6 OTPK stream).

**Dependencies.** Specific B2B partner demand justifying the implementation cost; design for wallet-side OOB key import/export.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary.

### 1.5 Cohort batching for OTPK publish-cadence privacy

**Improvement.** Multiple recipients pool their OTPK publishes into shared batches; observer cannot attribute OTPKs to specific recipients within cohort.

**Deferred reason.** Requires recipient-coordination protocol; reduces to mixnet design. Out of v2.22 scope. PRIV-6.2 cadence padding chosen as simpler mitigation.

**Classification.** Additive (alongside PRIV-6.2 padding).

**Dependencies.** Mixnet design + recipient-coordination protocol + cross-account OTPK lookup mechanism.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6.2 alternatives rejected.

### 1.6 Decoy batches for OTPK cadence obfuscation

**Improvement.** Recipient publishes mix of real + decoy OTPK batches; observer cannot distinguish real receive-rate from decoy traffic.

**Deferred reason.** Decoys must be cryptographically unforgeable to defeat sophisticated analysis; marginal gain over straight padding which PRIV-6.2 already provides.

**Classification.** Additive (alongside PRIV-6.2).

**Dependencies.** Decoy-unforgeability mechanism (commitment scheme or similar); demonstrated need to defeat statistical inference beyond what padding provides.

### 1.7 ZK disclosure proofs for audit

**Improvement.** Replace key-disclosure-based audit with zero-knowledge proofs of specific amount properties (e.g., "sum of transactions ≤ $X" without revealing individual amounts).

**Deferred reason.** Requires production-grade ZK proof system; out of v2.22 scope; v3+ work.

**Classification.** Additive (new proof type alongside existing disclosure paths).

**Dependencies.** Production-grade ZK proof system (zk-SNARK or similar); v3+ audit design that integrates with v2.24 hooks.

### 1.8 Trusted-issuer audit model

**Improvement.** Designated trusted issuer holds escrow of audit master keys; provides standing audit access without per-account key disclosure.

**Deferred reason.** Centralization vector contrary to DH-consensus ethos. Rejected during v2.22 PRIV-4 deliberation.

**Classification.** Breaking (new chain role + escrow infrastructure). **Could be downgraded to Additive** if v1.0 ships an `Account.audit_model` enum + optional `trusted_issuer_pubkey` field — see §7.5.

**Dependencies.** Project-policy decision to introduce trusted-issuer pattern; deployment-driven demand.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-4 dual-mode audit (alternatives section); §7.5 schema-freeze decision.

---

## 2. CRYPTO-C99 improvements

### 2.1 Falcon as alternative PQ signature

**Improvement.** Falcon (FIPS 206 candidate) ships alongside Dilithium for PQ signatures. Smaller signature size (666–1280 B vs. Dilithium-3's ~3293 B).

**Deferred reason.** Falcon requires constant-time FFT over floating-point; implementation-risk-heavy. Reference impl is fragile to compiler optimisation. Revisit when FIPS 206 finalises + battle-tested constant-time impl exists.

**Classification.** Additive (alternative PQ signature; v2.8 initial release ships Dilithium only).

**Dependencies.** FIPS 206 finalization + constant-time C99 Falcon implementation.

**Related.** V2-DESIGN.md §v2.8.

### 2.2 Dilithium-FROST threshold scheme

**Improvement.** Threshold-Dilithium scheme composing with v2.10 randomness-aggregation path under PQ. Preserves threshold property under quantum adversary.

**Deferred reason.** No published Dilithium-FROST scheme as of 2026; estimated 2027-2028 production-ready.

**Classification.** Additive (composes with v2.10 path).

**Dependencies.** Published + audited Dilithium-FROST scheme.

**Related.** V2-DESIGN.md §v2.8 composition with v2.10.

---

## 3. Beaconless v2 improvements

### 3.1 Horizontal scale beyond ~500 shards

**Improvement.** Sharding-of-sharding architecture for deployments needing >500 shards. Lazy validation contains O(N²) cost up to ~200-500 shards; beyond that, additional architectural work needed.

**Deferred reason.** v3 concern per Beaconless-v2-SPEC.md §1 scope. No current deployment driving the need.

**Classification.** Breaking (significant architectural change).

**Dependencies.** Deployment-driven need for >500 shards.

**Related.** Beaconless-v2-SPEC.md §1.

### 3.2 VRF-based cross-shard randomness aggregation

**Improvement.** Replace threshold-signature accumulator (BL-6) with VRF-based per-shard randomness output.

**Deferred reason.** Threshold-sig accumulator with subset-recording already provides bias-resistance. VRF doesn't solve the withholding attack that's the remaining surface — same attack applies to both. Switch would add new crypto primitive (VRF over Ed25519 / P-256) and discard v2.10 DKG composition. Sideways move at meaningful cost.

**Classification.** Breaking (replaces randomness mechanism + new primitive). **Could be downgraded to Additive** if v1.0 manifest schema includes a `randomness_aggregation_form` discriminator — see §7.5.

**Dependencies.** Demonstrated attack on threshold-sig path that VRF would actually defeat.

**Related.** `DECISION-LOG.md` → Beaconless-v2 → BL-6 VRF pushback rationale; §7.5 schema-freeze decision.

### 3.3 Beaconless v2 manifest `merritt_k` operator-override

**Improvement.** Allow operator-override of the `merritt_k` hard invariant via signed governance act.

**Deferred reason.** Hard invariant is *precondition for the security property the spec claims*. Allowing override means deployment can claim properties it doesn't have. Operator who wants weaker tolerance can run a fork — that's the correct escape valve.

**Classification.** Breaking (consensus-rule change).

**Dependencies.** None — explicitly rejected on principle.

**Related.** `DECISION-LOG.md` → Beaconless-v2 → Q2.1 hard/soft validation split.

---

## 4. v2 deferred items (per V2-DESIGN.md)

### 4.1 v2.8 Post-quantum signature migration

**Deferred reason.** Dilithium-FROST not production-ready until 2027-2028.

**Classification.** Breaking (signature format change). **Could be downgraded to Additive** via the same `Block.signature_form` discriminator as §6.1 (one discriminator covers both PQ migration and BLS aggregation) — see §7.5.

**Dependencies.** Dilithium-FROST availability (see 2.2).

**Related.** V2-DESIGN.md §v2.8; §7.5 schema-freeze decision.

### 4.2 v2.9 Distributed VRF for committee selection

**Improvement.** Per-validator ECVRF on Ed25519 (Option A) for committee selection randomness. Composes with v2.10 threshold-sig aggregation.

**Deferred reason.** Post-v2.10; not on Phase A-D critical path. v2.10 alone closes the residual selective-abort attack.

**Classification.** Additive (flag-day activation; pre-v2.9 chain remains valid).

**Dependencies.** v2.10 in production for sufficient observation period to confirm v2.9 layering value.

**Related.** V2-DESIGN.md §v2.9.

### 4.3 v2.13 Fair-ordering primitive

**Deferred reason.** Open research area; not on v2 critical path.

**Classification.** Research.

**Dependencies.** Research breakthrough + DEX or fair-ordering-dependent use case.

**Related.** V2-DESIGN.md §v2.13.

### 4.4 v2.21+ DApp ecosystem items

**Deferred reason.** Per V2-DAPP-DESIGN.md scope; not v1.0 mainnet critical path.

**Classification.** Additive (DApp layer extensions on top of v2.18 + v2.19 substrate).

**Dependencies.** v2.18 + v2.19 + v2.20 streaming all shipped (per IMPLEMENTATION-SEQUENCING.md).

**Related.** V2-DAPP-DESIGN.md.

---

## 5. Process / governance improvements

### 5.1 Stability gate added to Phase D criterion

**Improvement.** Augment Phase D entry criterion (currently pure named-feature checklist) with a stability gate: blocking features must run cleanly in test network for N weeks before Phase D opens.

**Deferred reason.** User picked pure Option C for Phase D criterion; explicitly rejected the C+lightweight-B hybrid. Trade-off accepted: code-complete is the trigger; if a feature regresses after Phase D opens, Bundle 5 work doesn't unwind.

**Classification.** Process.

**Dependencies.** Operational experience suggesting current gate is insufficient.

**Related.** `DECISION-LOG.md` → IMPLEMENTATION-SEQUENCING → Phase D criterion.

### 5.2 External multi-firm security audit before mainnet

**Improvement.** Add external multi-firm security audit as gate to mainnet declaration. Standard for crypto-projects of comparable ambition.

**Deferred reason.** User chose internal-testing-only QA (closed-beta + DSF + thread review). Explicit risk acceptance — residual: bugs escaping beta into mainnet bind under no-migrations.

**Classification.** Process.

**Dependencies.** Project-policy decision to add audit phase; budget; firm-selection criteria.

**Related.** Memory `dlt-qa-strategy`; IMPLEMENTATION-SEQUENCING.md §4.4.

### 5.3 Public bug bounty pre-mainnet

**Improvement.** Invite-only or public bug bounty against a long-running internal test network. Community-quality bug-finding without public release.

**Deferred reason.** Outside current QA strategy (closed-beta-only). Acceptable as supplementary mitigation if added later; not currently planned.

**Classification.** Process (operational addition).

**Dependencies.** Project-policy decision; bounty budget; researcher recruitment.

**Related.** Memory `dlt-qa-strategy`.

### 5.4 Open-source pre-mainnet test network releases (Option C release cadence)

**Improvement.** Public v0.x testnet/devnet releases as bundles complete; supplements internal closed-beta with broader test exposure.

**Deferred reason.** User chose Option A big-bang v1.0 — no public releases before mainnet. Reduces release-management overhead at cost of community visibility + testnet adoption.

**Classification.** Process (release-cadence change).

**Dependencies.** Project-policy decision to add public testnet phase.

**Related.** `DECISION-LOG.md` → IMPLEMENTATION-SEQUENCING → Bundle release cadence; memory `dlt-no-migrations-constraint`.

---

## 6. Post-v2 architectural optimizations (from `docs/Improvements.md` C99 spec)

A separate design candidate document at `docs/Improvements.md` outlines four wire-format / consensus optimizations targeting a hypothetical post-v2 chain. Each is captured here individually with the standard classification + deferral rationale. The no-migrations constraint discussion that classifies "Breaking" improvements is in §7.1 below.

### 6.1 BLS signature aggregation (aggregate Phase-2 commit-sigs) — MODERN-profile only

**Improvement (per-profile dispatch, following the PRIV-3 / C99-11 "curve follows profile" pattern):**
- **MODERN profile**: replace the per-creator K-of-K Ed25519 signature array (K × 64 bytes = up to 1024 B at K=16) in the block header with a single constant-size BLS12-381 aggregate signature (96 bytes). Each validator signs the block digest via its BLS12-381 private key; the proposer aggregates the K (or 2F+1 if combined with §6.2) signatures into a single `aggregate_sig` field.
- **FIPS profile** (`tactical` + `cluster`): retain the existing K-of-K Ed25519 signature array (status quo; no aggregation). BLS12-381 is not in NIST's FIPS-validated curve list and BLS signatures have no FIPS standard; FIPS-profile deployments cannot adopt aggregation via BLS. The old K × 64-byte array IS the FIPS configuration variant.

The block-header schema gains a `signature_form` discriminator: `SIG_KK_ED25519` (FIPS path, identical to v1.0 wire format) or `SIG_BLS12_381_AGGREGATE` (MODERN path). Validators dispatch verification by `signature_form` per the deployment's crypto profile (matching the `crypto_profile_build` compile-time gate from C99-13).

**Deferred reason (MODERN variant).** BLS12-381 is a pairing-friendly curve outside CRYPTO-C99's current two-curve discipline (curve25519 + secp256k1). Adding pairing primitives requires a carefully audited C99 pairing implementation (currently no production-grade option in C99). Bandwidth savings (~1 KB per block at K=16) are real but secondary to the cryptographic-discipline cost. Project-policy decision required to expand crypto-curve roster.

**Deferred reason (FIPS variant).** None — FIPS variant is the current v1.0 K-of-K Ed25519 wire format. The "improvement" for FIPS is the absence of change. Documented here so future implementation threads understand the profile-dispatch contract.

**Classification.** Breaking for the MODERN profile (replaces block-header signature format + introduces new curve family + pairing primitives). Additive for the FIPS profile (status quo retained; no wire-format change). Under no-migrations, the MODERN profile change cannot ship post-v1.0 without v3 protocol opening; the FIPS profile is unaffected regardless.

**Dependencies (MODERN variant).** Production-grade C99 BLS12-381 implementation + audited pairing primitives + project-policy decision to expand crypto-curve roster + `signature_form` schema addition at v1.0 genesis (so post-v1.0 MODERN-profile chains can opt into BLS aggregation via the discriminator without breaking legacy validators that already expect the field).

**Related.** `docs/Improvements.md` §1; v2.10 (FROST-Ed25519 — already provides aggregation in the threshold-randomness path but on curve25519, not BLS12-381); PRIV-3 curve-follows-profile precedent in v2.22-PRIVACY-SPEC.md; CRYPTO-C99-SPEC.md C99-11 profile bundling.

**Note for v1.0 schema-shape decision.** If the project ever intends to adopt BLS aggregation in MODERN-profile deployments post-v1.0, the `signature_form` discriminator field must ship in the v1.0 block-header schema (default `SIG_KK_ED25519`). Without that field in v1.0 genesis, adding it later requires schema migration — forbidden under no-migrations. Decision is binary: either ship the discriminator pre-v1.0 (preserves future optionality) or close off BLS aggregation as a v3-only candidate (loses optionality but simpler v1.0 schema). Flag this choice for explicit decision before v1.0 schema freeze.

### 6.2 Quorum Liveness — 2F+1 BFT-threshold finalization (OPTIONAL deployment mode)

**Improvement.** Add a `bft_quorum_2f1` finalization mode alongside (NOT replacing) the existing K-of-K unanimous mode. Selected per-deployment at genesis (new `Config::finalization_mode` knob). The block header gains a `quorum_bitset` (16 bytes for K_max=128) indicating which committee members participated; finalization requires ≥ 2F+1 bits set. In `unanimous_k` mode (the default), `quorum_bitset` is fixed to all-1s and the BFT-threshold check short-circuits to the existing K-of-K equality check.

**Deferred reason.** v1.0 K-of-K unanimity is a deliberate design choice: it makes any abort-rate signal valuable evidence for FA6 equivocation slashing + FA5 selective-abort defense; weaker quorum thresholds dilute that signal. The 2F+1 mode is appropriate for permissioned deployments where mutual-distrust posture is relaxed (e.g., enterprise consortia with explicit BFT-style failure tolerance) but should not be the default. v1.0 already has the **BFT-escalation** path (4-gate trigger per S-025) which provides liveness recovery WITHOUT changing the steady-state finalization rule — that captures most of the practical benefit at zero spec cost. A first-class 2F+1 mode is a different posture choice, not a strict upgrade.

**Classification.** Additive-via-opt-in **as long as legacy K-of-K finalization remains the default codepath**. The wire format adds a new field (`quorum_bitset`) but `unanimous_k`-mode chains emit fixed all-1s and validators of `unanimous_k`-mode chains can ignore the field. **Marked OPTIONAL per project-policy decision** — new deployments may opt in at genesis; existing chains are unaffected.

**Dependencies.** `Config::finalization_mode` knob added to genesis schema + apply-time gate dispatching on the mode + BFT-quorum bitset validator. No new crypto primitives (compatible with both Ed25519 K-of-K and §7.1 BLS aggregation).

**Related.** `docs/Improvements.md` §2 (annotated as OPTIONAL); existing BFT-escalation per `docs/proofs/S025BFTEscalationSoundness.md` (R34A7) — the 4-gate escalation is a strictly *temporary* liveness mode triggered by abort threshold; §7.2 would make BFT-mode the steady-state default for opt-in deployments. The two are complementary: a deployment running in `unanimous_k` mode still escalates to BFT-mode under stress; a deployment running in `bft_quorum_2f1` mode operates at the BFT threshold continuously without escalation gates.

### 6.3 Data deduplication — `deduplicated_tx_root`

**Improvement.** Replace the per-creator `creator_tx_lists[][]` arrays (which can carry the same transaction across multiple creators' lists, redundantly) with a single `deduplicated_tx_root` Merkle root over the globally lex-sorted unique transaction set. The committee's contribution remains attested via the Phase-1 sketch (see §7.4) and the BLS aggregate sig (see §7.1) — the tx_root commits to the canonical post-dedup set without listing per-creator membership.

**Deferred reason.** Bandwidth saving is real (proportional to inter-creator overlap, which is high under healthy mempool propagation), but the per-creator-list redundancy is also the evidence base for FA2 censorship resistance (every creator's contributed-or-not status is observable from the per-creator lists). Removing per-creator lists removes that evidence; FA2's "k_bft-conjunction-of-creators-must-collude-to-censor" argument doesn't carry over without replacement. A replacement would be: per-creator commitment to a Bloom filter / IBLT over their proposed-tx set, recorded in the header for off-chain verification — adds complexity that erodes the bandwidth saving.

**Classification.** Breaking (block-header structural change; loses per-creator censorship-evidence surface; requires FA2 reformulation).

**Dependencies.** Replacement evidence-surface for FA2 censorship resistance (per-creator Bloom/IBLT commitment in the header, OR a separate audit-log mechanism); FA2 proof reformulation; production-grade IBLT/Minisketch impl in C99.

**Related.** `docs/Improvements.md` §3; FA2 censorship proof at `docs/proofs/Censorship.md`.

### 6.4 Bandwidth reduction — IBLT/Minisketch in Phase-1 contrib

**Improvement.** Replace the Phase-1 ContribMsg's full transaction-hash array with an IBLT (Invertible Bloom Lookup Table) or Minisketch payload. Peers reconcile their mempool views with the proposer's sketch via set-difference decode (O(δ) bandwidth where δ is the symmetric difference), allowing mempool sync at fixed bandwidth even as mempool grows.

**Deferred reason.** Bandwidth saving is largest at high mempool size + low inter-peer overlap (worst-case mempool churn). At the throughput Determ targets (~hundreds of tx/sec sustained), raw 32-byte tx-hash arrays in Phase-1 contribs are well under per-message body caps (S-022) — the bandwidth saving is real but not load-bearing. IBLT / Minisketch decode failure modes (over-capacity sketch → undecidable) require careful parameterization + fallback to raw-array contrib; the implementation complexity is meaningful, the operational risk is non-trivial.

**Classification.** Breaking (Phase-1 ContribMsg wire format change; new sketch primitive in net stack; new decode-failure fallback). **Could be downgraded to Additive** if v1.0 ships a `ContribMsg.contrib_msg_form` discriminator — see §7.5.

**Dependencies.** Production-grade IBLT / Minisketch C99 implementation + audit; mempool-size measurements demonstrating the saving is load-bearing for real deployments; spec for sketch-decode-failure fallback (when peers' mempool delta exceeds sketch capacity).

**Related.** `docs/Improvements.md` §4; v2.6 (gossip-out-of-lock — already addresses Phase-1 gossip latency, an adjacent concern); S-022 wire-format caps proof; §7.5 schema-freeze decision.

### 6.5 Composition notes

The four items above compose orthogonally; any subset can be adopted independently. §6.2 (Quorum Liveness OPTIONAL) is the most ship-ready of the four — it requires no new cryptographic primitive, the codepath is small, and the optionality preserves all existing FA-track safety proofs for `unanimous_k`-mode deployments. The other three (§6.1 BLS aggregation, §6.3 dedup, §6.4 IBLT) require new crypto primitives / proof reformulations and are appropriate v3 candidates.

If only one of the four ships, §6.2 is the natural pick — small, optional, well-understood interaction with the existing BFT-escalation gate (S-025), and immediate value for permissioned-deployment operators who want a first-class BFT-threshold finalization mode without going through the abort-rate escalation path.

---

## 7. Cross-cutting notes

### 7.1 Breaking improvements + no-migrations constraint

Any improvement classified **Breaking** cannot ship post-v1.0 mainnet without one of:

1. Absorption as security-critical hard fork (reserved for true security necessities, not feature delivery)
2. Explicit opening of a new protocol version (effectively v2.0; project-policy decision separate from current execution)
3. Operation of an alternate chain alongside v1.0

This means most items in §1.1, §1.2, §1.3, §1.8, §3.1, §3.2, §3.3, §4.1, §6.1 (MODERN variant), §6.3, §6.4 are *effectively v3 candidates* if pursued. Their planning horizon is years, not months. **Exceptions:**
- §6.2 (Quorum Liveness OPTIONAL) is classified Additive-via-opt-in because legacy K-of-K remains the default codepath — see its entry for the policy rationale.
- §6.1 (BLS aggregation) is split per profile: the MODERN-profile aggregation variant is Breaking (v3 candidate), but the FIPS-profile variant is Additive — FIPS deployments retain the v1.0 K-of-K Ed25519 array unchanged. The per-profile dispatch mirrors the PRIV-3 / C99-11 "curve follows profile" pattern. See §6.1 for the `signature_form` discriminator decision that must be made pre-v1.0 schema freeze to preserve MODERN-side optionality.

### 7.2 Additive improvements + opt-in defaults

Items classified **Additive** can ship post-v1.0 as long as they preserve legacy-validator behavior. The pattern: new optional fields validators can ignore, new tx types that legacy validators fail-closed on or skip without state mutation. These improvements have realistic post-v1.0 paths. **§6.2 (Quorum Liveness OPTIONAL)** is the canonical "Additive-via-opt-in" example — a new deployment-mode knob at genesis that older chains never read, gated such that the v1.0 K-of-K validator codepath is unaffected.

### 7.3 Research improvements + revisit triggers

Items classified **Research** are paused waiting for primitive maturation or deployment-driven demand. Revisit triggers (in approximate priority order):

- Production-grade C99 FSE implementation → revisit 1.1
- Production-grade C99 puncturable encryption → revisit 1.2
- Production-grade ZK proof system in C99 → revisit 1.7
- Dilithium-FROST publication + audit → revisit 2.2, 4.1
- FIPS 206 finalization + Falcon C99 impl → revisit 2.1
- Deployment driving >500 shards → revisit 3.1
- Fair-ordering research breakthrough → revisit 4.3
- Production-grade C99 BLS12-381 + pairing primitives + project-policy decision to expand crypto-curve roster → revisit 6.1
- Permissioned-deployment operator demand for first-class BFT-threshold finalization (rather than abort-rate escalation) → revisit 6.2
- FA2 censorship-resistance evidence-surface replacement design → revisit 6.3
- Production-grade IBLT / Minisketch C99 implementation + sketch-decode-failure fallback spec → revisit 6.4

### 7.4 Reopening process

When an item here becomes load-bearing (revisit trigger fires, or operator demand surfaces), the process is:

1. Move item from this file into a new spec doc (or amend existing spec)
2. Add a decision-log entry capturing why now + what changed
3. Classify against no-migrations constraint to determine if Additive (can ship) or Breaking (requires v3 protocol opening)
4. Update IMPLEMENTATION-SEQUENCING.md if it joins a current bundle plan

### 7.5 Pre-v1.0-schema-freeze optionality decisions — RESOLVED 2026-05-24

Under the no-migrations constraint, several improvements classified as Breaking *could be downgraded to Additive* if the v1.0 schema includes a cheap discriminator or optional field that lets future protocol-mode dispatch happen without a schema change. The cost per discriminator is small (typically 1 byte per applicable record, or one optional field per Account). The cost of NOT shipping a discriminator is permanent foreclosure of the improvement under no-migrations.

**All five discriminators resolved: SHIP in v1.0.** Maximum optionality preserved at minimal schema cost. Each is now a v1.0 implementation work item (not deferred).

| # | Discriminator / field | Location | v1.0 default | Unlocks | v1.0 schema cost | Decision |
|---|---|---|---|---|---|---|
| **7.5.1** | `Block.signature_form: enum` | Block header | `SIG_KK_ED25519` | §6.1 BLS aggregation (MODERN-profile), §4.1 v2.8 PQ migration (both profiles via `SIG_DILITHIUM_KK`) | 1 byte/block | ✅ SHIP |
| **7.5.2** | `Account.view_key_mechanism: enum` + optional `fs_view_pk` field | Account state | `OTPK_STREAM` | §1.1 FSE / forward-secure HIBE, §1.2 puncturable encryption | ~1 byte/Account + ~33 B if `fs_view_pk` populated (optional) | ✅ SHIP |
| **7.5.3** | `Account.audit_model: enum` + optional `trusted_issuer_pubkey` field | Account state | `KEY_DISCLOSURE` (PRIV-4 dual-mode default) | §1.8 trusted-issuer audit + other future audit-model variants | ~1 byte/Account + ~33 B if `trusted_issuer_pubkey` populated (optional) | ✅ SHIP (overrides §7.5 heuristic of "don't ship discriminators that invite principle-rejected paths"; user chose optionality over discipline-preservation, accepting that future revisit of the trusted-issuer principle remains structurally possible) |
| **7.5.4** | `manifest.randomness_aggregation_form: enum` | Beaconless v2 deployment manifest | `THRESHOLD_SIG_ACCUMULATOR` (BL-6) | §3.2 VRF-based aggregation | 1 byte/manifest | ✅ SHIP |
| **7.5.5** | `ContribMsg.contrib_msg_form: enum` | Phase-1 ContribMsg | `TX_HASH_ARRAY` | §6.4 IBLT/Minisketch contrib | 1 byte/ContribMsg | ✅ SHIP |
| **7.5.6** | `Transaction.sig_form: enum` | Every Transaction | `SIG_ED25519` | §4.1 PQ migration of tx-level sigs (Dilithium); future tx-level BLS use cases | 1 byte/tx | ✅ SHIP (added 2026-05-24 after gap analysis) |
| **7.5.7** | `pubkey_form: enum` + variable-length pubkey encoding throughout | Every pubkey-bearing field: RegistryEntry.ed_pub, Transaction.from, Transaction.to, Account, ROTATE_KEY new_pubkey, DAppEntry.service_pubkey, view_master_pk, audit_view_master_pk, OTPK entries, etc. | `PUBKEY_ED25519` (fixed 32B encoded as variable-length with leading discriminator) | §4.1 PQ migration of pubkeys (Dilithium 1952B); §6.1 BLS aggregation per-creator pubkeys (BLS12-381 96B) | 1 byte/pubkey + variable-length encoding overhead; ~3-5 days v1.0 schema lift | ✅ SHIP (added 2026-05-24 after gap analysis) |

**Effective reclassification.** The five Breaking entries above are now effectively Additive-via-discriminator-dispatch: their wire-format toggle ships in v1.0; the underlying mechanism can be added post-v1.0 without schema change as long as legacy validators handle unknown enum values gracefully (recommended: fail-closed on unknown discriminator values per profile-dispatch contract).

**Implementation impact on v1.0 bundles** (work items to add to IMPLEMENTATION-SEQUENCING.md):
- **Bundle 3 (v2.22)**: `view_key_mechanism` enum + optional `fs_view_pk` field on Account (7.5.2); `audit_model` enum + optional `trusted_issuer_pubkey` field on Account (7.5.3). ~1-2 days schema work; no validator logic for the unused enum values yet (fail-closed validators reject unknown enum values).
- **Bundle 5 (Beaconless v2)**: `randomness_aggregation_form` field on deployment manifest (7.5.4). ~0.5 days. Manifest-validation `validate_manifest()` rejects unknown values per Q2.1 hard-invariant pattern.
- **Foundation / v1.x stabilization**: `signature_form` enum on Block header (7.5.1) and `contrib_msg_form` enum on Phase-1 ContribMsg (7.5.5). ~1-2 days each. These touch block-level + gossip-level wire formats; should land before any of the review-week bundles to lock the genesis schema shape.

**Cross-coupling preserved.** 7.5.1 `signature_form` covers both §6.1 BLS aggregation and §4.1 PQ migration with a single discriminator (enum values `SIG_KK_ED25519`, `SIG_BLS12_381_AGGREGATE`, `SIG_DILITHIUM_KK`, etc.). One field; two future improvement paths preserved.

### 7.6 Discriminator-coherence resolutions

After §7.5 decisions landed, the five discriminators were verified against existing review-week decisions (v2.10 FROST, PRIV-4 audit, PRIV-6 confidential_policy, v2.6 gossip-out-of-lock). All five resolve cleanly. Specific clarifications follow.

#### 7.6.1 `signature_form` scope vs v2.10 FROST-Ed25519

**Concern.** v2.10 (resolved in review week) ships FROST threshold sigs for per-shard epoch randomness aggregation. Does `signature_form` discriminate v2.10 FROST sigs too, or only the per-creator block sigs?

**Resolution.** `signature_form` discriminates **only** the per-creator block-creator signature format (`Block.creator_sigs[]`). It does NOT discriminate v2.10's FROST epoch-randomness sig — that lives in a separate `Block.epoch_randomness_sig` field (optional, present at epoch boundary) with its own fixed format per v2.10 (FROST-Ed25519). The two are orthogonal: a block could simultaneously carry K-of-K per-creator Ed25519 sigs AND a FROST aggregate over epoch randomness, with different curve families.

**Enum values for v1.0 + future:**
- `SIG_KK_ED25519` (v1.0 default; status quo K-of-K per-creator Ed25519 array)
- `SIG_BLS12_381_AGGREGATE` (future MODERN-profile per §6.1; single 96-byte aggregate)
- `SIG_DILITHIUM_KK` (future both-profile per §4.1; K-of-K per-creator Dilithium array)
- Reserved: 0xFF for forward-compat

**Validator dispatch.** On block apply, read `signature_form` first; dispatch creator-sig verification by enum value. Reject unknown values (forward-incompat = fail-closed). FROST epoch-randomness sig verified independently per v2.10 spec, regardless of `signature_form`.

#### 7.6.2 `audit_model = KEY_DISCLOSURE` semantics vs PRIV-4 dual-mode

**Concern.** PRIV-4 specifies dual-mode disclosure (full `view_master_sk` OR per-epoch `vk_epoch_n`). The discriminator default `KEY_DISCLOSURE` — does it encompass dual-mode, or carve master vs per-epoch as separate values?

**Resolution.** `KEY_DISCLOSURE` encompasses PRIV-4 dual-mode in full. The master-vs-per-epoch choice is a sub-mode chosen by the discloser at audit time (off-chain), not a chain-level discriminator value. The discriminator distinguishes the *broader audit mechanism class* (key-disclosure vs trusted-issuer vs ZK-based vs none), not the granularity within key-disclosure.

**Enum values for v1.0 + future:**
- `KEY_DISCLOSURE` (v1.0 default; PRIV-4 dual-mode; account holder discloses `view_master_sk` or `vk_epoch_n` off-chain when audited)
- `TRUSTED_ISSUER` (future per §1.8; requires `trusted_issuer_pubkey` field populated; escrow infrastructure)
- Reserved: `ZK_BASED_AUDIT`, `NO_AUDIT` for future use
- Reserved: 0xFF for forward-compat

**Interaction with `confidential_policy`.** For `confidential_policy = AUDITABLE_ONLY` or `MIXED`, `audit_model` is load-bearing (selects audit mechanism for AMT_AUDITABLE txs). For `confidential_policy = PFS_ONLY`, `audit_model` is structurally moot (no audit possible regardless of value); validator allows any value but no audit RPC will succeed.

#### 7.6.3 `view_key_mechanism` orthogonality with `confidential_policy`

**Concern.** PRIV-6 added `Account.confidential_policy: {AUDITABLE_ONLY, PFS_ONLY, MIXED}`. Adding `view_key_mechanism: {OTPK_STREAM, FSE, PUNCTURABLE}` creates a 3×3 cross-product. Which combinations are valid?

**Resolution.** Orthogonal axes. Cross-product validity:

| `confidential_policy` × `view_key_mechanism` | Validity |
|---|---|
| `AUDITABLE_ONLY` × any | Valid; `view_key_mechanism` unused (no PFS path) — validator allows default value |
| `PFS_ONLY` × `OTPK_STREAM` | Valid; v1.0 mechanism |
| `PFS_ONLY` × `FSE` | Valid; future mechanism (post-§1.1 maturation) |
| `PFS_ONLY` × `PUNCTURABLE` | Valid; future mechanism (post-§1.2 maturation) |
| `MIXED` × any | Valid; `view_key_mechanism` applies to AMT_PFS subset of mixed account |

**Validator dispatch at v1.0:** since FSE and PUNCTURABLE aren't implemented yet, validator rejects any account-creation tx with `view_key_mechanism != OTPK_STREAM` (forward-compat fail-closed). For AUDITABLE_ONLY accounts, validator allows default value (OTPK_STREAM is fine even though unused).

**Semantic intent.** `confidential_policy` answers *which modes does this account accept* (audit posture). `view_key_mechanism` answers *what crypto realizes the PFS path when used*. Independent dimensions; both immutable at account creation.

#### 7.6.4 `contrib_msg_form` interaction with v2.6 gossip-out-of-lock

**Concern.** v2.6 (shipped) moved gossip broadcast out of the global lock. Does `contrib_msg_form` discriminator dispatch interact with v2.6's lock semantics?

**Resolution.** No interaction. v2.6 is broadcast-side (send path); `contrib_msg_form` is receive-side decode. Receiver reads the discriminator before any further processing — pure wire-format dispatch, no state mutation, no lock change. Compatible with all existing gossip code.

**Validator dispatch at v1.0:** read `contrib_msg_form` first; if `TX_HASH_ARRAY` (v1.0 default), decode as tx-hash array per existing path. If unknown value, fail-closed reject the message. IBLT/Minisketch decode path lands post-v1.0 if §6.4 is ever pursued.

#### 7.6.5 Asymmetric pinning (per-record vs manifest-pinned) — verified consistent

**Concern.** Four discriminators are per-record (block / Account / ContribMsg); `randomness_aggregation_form` is manifest-pinned (deployment-wide). Cross-checks needed?

**Resolution.** Asymmetry is correct and required by the underlying mechanisms:

| Discriminator | Pinning | Why this granularity |
|---|---|---|
| `signature_form` | per-block | Allows per-block flexibility (e.g., shard-by-shard migration if future-MODERN profile adopts BLS while FIPS retains Ed25519); per-creator sig forms must be in the block anyway |
| `view_key_mechanism` | per-Account | Each account independently picks PFS mechanism; account-creation-time immutable |
| `audit_model` | per-Account | Each account independently picks audit mechanism |
| `contrib_msg_form` | per-ContribMsg | Per-message decoding flexibility; aligns with v2.6 broadcast-side independence |
| `randomness_aggregation_form` | per-manifest | Cross-shard randomness MUST agree on aggregation; deployment-wide pinning enforces consistency at manifest-validation time (per Q2.1 hard-invariant pattern) |

**Required cross-check (currently absent; flagged for future Theme 9 review-completion).** No per-record discriminator currently needs to be cross-checked against `randomness_aggregation_form` (they're orthogonal subsystems). If a future improvement adds manifest-pinned discriminators that constrain per-record values, validator must enforce compatibility at apply time. Add this constraint to the manifest-validation discipline in `Beaconless-v2-SPEC.md §Q2.1` if/when such constraints emerge.

#### 7.6.6 `Transaction.sig_form` coherence (added 2026-05-24)

**Concern.** Tx-level sigs need their own discriminator to enable PQ migration; how does `Transaction.sig_form` interact with `Block.signature_form` (7.5.1)?

**Resolution.** Orthogonal. `Block.signature_form` discriminates per-creator BLOCK signatures (consensus-level). `Transaction.sig_form` discriminates per-tx signatures (user-level). A block could carry mixed-form txs (some Ed25519, some Dilithium during transition) under a single block-level sig form, or homogeneous (all-Ed25519, all-Dilithium) — both are valid.

**Enum values for v1.0 + future:**
- `SIG_ED25519` (v1.0 default; all current txs)
- `SIG_DILITHIUM` (future PQ migration)
- `SIG_BLS12_381` (future if tx-level BLS use cases emerge)
- Reserved: 0xFF for forward-compat

**Validator dispatch at v1.0:** read `Transaction.sig_form` first; if `SIG_ED25519` (only allowed value at v1.0), verify per existing path. Fail-closed reject unknown values.

**Embedded sigs in tx payloads** (e.g., v2.26 ROTATE_KEY's `old_key_sig`, F2 reveal sigs, multi-sig aux_sigs): these are payload-internal and follow tx-level `sig_form` (homogeneous within a tx). A `SIG_DILITHIUM` tx has its outer sig + all embedded sigs in Dilithium form. This avoids combinatorial form-mixing within a single tx and keeps validation simple.

#### 7.6.7 `pubkey_form` coherence + variable-length pubkey encoding (added 2026-05-24)

**Concern.** Variable-length pubkey encoding is a non-trivial schema lift; how does it compose with all existing pubkey-bearing fields?

**Resolution.** Single discriminator+encoding pattern applied uniformly to every pubkey-bearing field. Wire-format pattern:

```
PubKey = {
    pubkey_form: u8     // discriminator
    body_len:    u16    // length of body in bytes (0 for fixed-size known forms)
    body:        bytes  // pubkey bytes
}
```

For fixed-size known forms (Ed25519 32B, BLS12-381 96B, Dilithium 1952B), `body_len` is implicit from `pubkey_form` and can be elided in encoding (use form-dispatch-derived size). Including `body_len` explicitly costs 2 bytes per pubkey but adds forward-compat for arbitrary-size future pubkey forms.

**Enum values for v1.0 + future:**
- `PUBKEY_ED25519` (v1.0 default; 32-byte body)
- `PUBKEY_BLS12_381` (future; 96-byte compressed body)
- `PUBKEY_DILITHIUM` (future; 1952-byte body for Dilithium-3)
- Reserved: 0xFF for forward-compat

**Fields affected** (every existing PubKey32 usage):
- `RegistryEntry.ed_pub`
- `Transaction.from`, `Transaction.to`
- `Account` (various pubkey fields per PRIV-6, PRIV-6.1)
- `view_master_pk`, `audit_view_master_pk`, optional `trusted_issuer_pubkey`, optional `fs_view_pk`
- `OtpkEntry.otpk_pk`
- `DAppEntry.service_pubkey`
- v2.26 ROTATE_KEY `new_pubkey`, implicit `old_pubkey` (from registry)
- Multi-sig (v2.15) signer pubkeys when that ships

**Validator dispatch at v1.0:** all pubkey reads dispatch on `pubkey_form`. `PUBKEY_ED25519` is the only accepted value at v1.0. Fail-closed reject unknown forms. Variable-length decoding is uniform across all pubkey fields.

**Address derivation.** Determ addresses today derive from pubkeys (or domains). For Ed25519, derivation is `address = some_hash(pubkey_32B || ...)`. With pubkey_form discriminator, derivation becomes `address = some_hash(pubkey_form || pubkey_body || ...)` — the discriminator MUST be in the address-derivation preimage to prevent address collision across pubkey forms. This is a v1.0 design lock-in: getting it wrong now forecloses PQ pubkey migration even with the discriminator present.

**Interaction with v2.10 FROST-Ed25519.** FROST uses Ed25519 internally; per-shard threshold keys are Ed25519 pubkeys per v2.10 spec. With `pubkey_form` discriminator, FROST shares store Ed25519 pubkeys as `(PUBKEY_ED25519, 32B body)`. No interaction with FROST's internal math; just wire-format wrapping.

**Interaction with `Transaction.sig_form` (7.5.6).** The pubkey used to verify a `Transaction.sig_form = SIG_X` signature MUST have `pubkey_form = PUBKEY_X` (matching curve family). Validator enforces this consistency at sig-verification time. Mismatch (e.g., `SIG_ED25519` + `PUBKEY_DILITHIUM`) is a hard reject.

#### 7.6.8 Summary — all seven discriminators coherent

| # | Coherence concern | Resolution |
|---|---|---|
| 7.6.1 | `signature_form` vs v2.10 FROST | Scope limited to per-creator block sigs; FROST sig is a separate orthogonal field |
| 7.6.2 | `audit_model = KEY_DISCLOSURE` semantics | Encompasses PRIV-4 dual-mode; master-vs-per-epoch is off-chain sub-mode choice |
| 7.6.3 | `view_key_mechanism` × `confidential_policy` cross-product | Orthogonal; all 9 combinations meaningful; v1.0 validator enforces `view_key_mechanism = OTPK_STREAM` until future mechanisms implemented |
| 7.6.4 | `contrib_msg_form` vs v2.6 | No interaction; v2.6 is send-side, discriminator is receive-side decode |
| 7.6.5 | Per-record vs manifest-pinned asymmetry | Correct by design; each discriminator at appropriate granularity for its subsystem |
| 7.6.6 | `Transaction.sig_form` vs `Block.signature_form` | Orthogonal; embedded sigs within a tx are homogeneous (follow tx-level sig_form) |
| 7.6.7 | `pubkey_form` + variable-length encoding + address derivation | Uniform encoding across all pubkey-bearing fields; discriminator MUST be in address-derivation preimage to prevent collision; sig_form↔pubkey_form curve-family consistency enforced at verify time |

**Action items for v1.0 implementation threads.**
- All seven discriminators use the documented enum spaces above; reserve 0xFF for forward-compat in each.
- Validator dispatches on enum value with fail-closed unknown-value handling (forward-incompat = reject).
- `view_key_mechanism = OTPK_STREAM` enforced at v1.0 for account-creation accepting AMT_PFS or MIXED.
- `signature_form = SIG_KK_ED25519` enforced at v1.0 for all blocks.
- `audit_model = KEY_DISCLOSURE` enforced at v1.0 for all accounts (TRUSTED_ISSUER requires the field-pubkey infrastructure not in v1.0 scope).
- `randomness_aggregation_form = THRESHOLD_SIG_ACCUMULATOR` enforced at v1.0 in `validate_manifest()` (per Beaconless-v2-SPEC.md §Q2.1 hard-invariant pattern).
- `contrib_msg_form = TX_HASH_ARRAY` enforced at v1.0 for all Phase-1 ContribMsgs.
- `Transaction.sig_form = SIG_ED25519` enforced at v1.0 for all txs; embedded sigs within tx payloads follow tx-level sig_form.
- `pubkey_form = PUBKEY_ED25519` enforced at v1.0 for all pubkey-bearing fields; variable-length encoding applied uniformly; discriminator IS in address-derivation preimage; sig_form↔pubkey_form curve-family consistency enforced at sig verification.

**Aggregate cost of all seven discriminators in v1.0 (now committed).**
- Per block: ~1 byte (`signature_form`)
- Per Account: ~2 bytes (two enums; optional fields cost only when populated)
- Per manifest: 1 byte (one-time deployment-wide)
- Per ContribMsg: 1 byte
- Per tx: 1 byte (`sig_form`)
- Per pubkey: 1 byte discriminator + variable-length encoding overhead (Ed25519 stays 32B body; future Dilithium 1952B body; future BLS 96B body)
- **Per-record discriminators are trivial relative to existing record sizes. The variable-length pubkey encoding (7.5.7) is a substantive ~3-5 day v1.0 schema lift — touches every consumer of pubkey data (sig verification, address derivation, serialization). This is the only material v1.0 implementation cost in the §7.5 set; everything else is wire-format scaffolding.**

**Items that CANNOT be cheaply downgraded** (Breaking remains Breaking; no v1.0 schema addition would help):

- **§1.3 stealth addresses** — restructures tx-level recipient indication; the whole TRANSFER tx format would change, not just a discriminator dispatch. Future stealth-address adoption requires v3 protocol opening regardless of v1.0 schema choices.
- **§3.1 sharding-of-sharding** — fundamental restructuring of inter-shard architecture; not amenable to discriminator dispatch.
- **§3.3 merritt_k operator-override** — deliberately rejected on principle (operator who wants weaker tolerance can run a fork). No schema addition would change that disposition.
- **§6.3 dedup `deduplicated_tx_root`** — discriminator alone is insufficient because the FA2 censorship-evidence-surface loss requires a *proof reformulation*, not just wire-format dispatch. Even if a `tx_root_form` discriminator existed in v1.0, the FA2 proof would still need reworking before §6.3 could be enabled — making the optionality cost not load-bearing.

**Heuristic that was applied (preserved for future reference).**

The §7.5 review used the following heuristic:

- If the relevant improvement is classified **Research** and waiting for a primitive maturation that may take years (§1.1 FSE, §1.2 puncturable, §4.1 PQ): **ship the discriminator** — optionality is high-value because the primitive will mature eventually. *Applied: 7.5.2, 7.5.1.*
- If the relevant improvement is classified **Breaking** but has clear strategic motivation (§6.1 MODERN BLS aggregation, §3.2 VRF): **ship the discriminator** — strategic alternative paths should not be foreclosed by an oversight. *Applied: 7.5.1, 7.5.4.*
- If the improvement is rejected on principle (§1.8 trusted-issuer for centralization, §3.3 merritt_k override): **don't ship the discriminator** — adding it would invite the rejected path. *Override for 7.5.3: user chose to ship anyway, accepting that future revisit remains structurally possible.*
- If the improvement is in scope but cost-tier-marginal (§6.4 IBLT): **operator preference** — ship if the project anticipates mempool-sizing pressure; skip if not. *Applied: 7.5.5 shipped consistent with the broader "preserve all optionality" stance.*

**Outcome.** All five discriminators ship in v1.0. Reclassifies the five Breaking entries listed above to effectively-Additive-via-discriminator-dispatch. Trusted-issuer audit (§1.8) remains principle-rejected at the *implementation* level — the discriminator slot exists but the trusted-issuer enum value is not implemented in v1.0; a future revisit would add the value to the enum and implement the escrow infrastructure.

---

---

## 8. Post-v1.0 DApp roadmap (not chain-level work)

Items that V2-DESIGN.md originally framed as chain-level substrate but were reclassified as post-v1.0 chain-aware DApps. These ship on top of the v1.0 v2.18 + v2.19 + v2.26 substrate without requiring chain-level work.

### 8.1 v2.25 DSSO substrate — reclassified as DApp (2026-05-24)

**Improvement.** Distributed identity provider with K-of-K mutual-distrust posture, T-OPAQUE authentication, signed assertions for relying parties.

**Original V2-DESIGN.md framing.** Chain-level substrate; T-OPAQUE on K committee members; FROST-Ed25519 threshold-signed assertions verified against on-chain committee pubkey set.

**Reclassified as.** Chain-aware DApp registered via v2.18 DAPP_REGISTER. K DApp instances run BY committee members; T-OPAQUE coordination via DAPP_CALL; assertion signing via chain's FROST primitive (when applicable) or per-instance signing verified against DApp registry.

**Reclassification rationale.** ~80% of substrate's security properties recoverable at the DApp level; ~8-12 weeks of v1.0 critical-path work eliminated; DSSO iterates post-mainnet without no-migrations constraints; federation by design (multiple DSSO providers can coexist). See `DECISION-LOG.md` 2026-05-24 entry "DSSO architecture (v2.25): DApp, not substrate".

**Classification.** Post-v1.0 DApp (Theme 7 application). Not Breaking, not Additive at chain level — entirely DApp-level. Ships when DApp infrastructure for committee-instance hosting is built and v2.26 (chain-level key rotation precondition per V2-DESIGN.md §v2.25) is shipped.

**Dependencies (DApp-side, post-v1.0):**
- v2.18 DAPP_REGISTER (✅ shipped)
- v2.19 DAPP_CALL (✅ shipped)
- v2.26 on-chain key rotation (in Theme 9 review-track; v1.0 critical path)
- v2.10 FROST threshold sigs for assertion-signing path (✅ in review-week bundle 1)
- Committee-instance DApp-hosting infrastructure (post-v1.0; new DApp pattern not previously deployed)

**Related.** Memory `dlt-dsso-as-dapp`; V2-DESIGN.md §v2.25 (original substrate design — preserved for historical reference but supplanted by this reclassification); `DECISION-LOG.md` 2026-05-24 entry.

---

*End of improvements queue. Append new entries as future deliberations produce additional deferred items.*
