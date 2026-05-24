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

**Classification.** Breaking (replaces OTPK-stream mechanism).

**Dependencies.** Production-grade C99 FSE implementation OR explicit acceptance of a third curve family.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary.

### 1.2 Puncturable encryption (Green-Miers / Bloom-filter)

**Improvement.** Per-tx PFS via single long-term keypair that punctures at specific tags after use. No publish events of any kind post-account-creation.

**Deferred reason.** Research-grade primitive; no production deployments; secret-key state grows with each puncture; false-positive risk in Bloom-filter variants requires careful parameterization.

**Classification.** Breaking.

**Dependencies.** Production-grade C99 puncturable encryption + extensive cryptographic audit.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary.

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

**Classification.** Breaking (new chain role + escrow infrastructure).

**Dependencies.** Project-policy decision to introduce trusted-issuer pattern; deployment-driven demand.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-4 dual-mode audit (alternatives section).

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

**Classification.** Breaking (replaces randomness mechanism + new primitive).

**Dependencies.** Demonstrated attack on threshold-sig path that VRF would actually defeat.

**Related.** `DECISION-LOG.md` → Beaconless-v2 → BL-6 VRF pushback rationale.

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

**Classification.** Breaking (signature format change).

**Dependencies.** Dilithium-FROST availability (see 2.2).

**Related.** V2-DESIGN.md §v2.8.

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

### 6.1 BLS signature aggregation (aggregate Phase-2 commit-sigs)

**Improvement.** Replace the per-creator K-of-K Ed25519 signature array (K × 64 bytes = up to 1024 B at K=16) in the block header with a single constant-size BLS12-381 aggregate signature (96 bytes). Each validator signs the block digest via its BLS12-381 private key; the proposer aggregates the K (or 2F+1 if combined with §7.2) signatures into a single `aggregate_sig` field.

**Deferred reason.** BLS12-381 is a pairing-friendly curve outside CRYPTO-C99's current two-curve discipline (curve25519 + ristretto255 / secp256k1). Adding pairing primitives requires either a third curve family (conflict) OR a carefully audited C99 pairing implementation (currently no production-grade option). Bandwidth savings (~1 KB per block at K=16) are real but secondary to the cryptographic-discipline cost.

**Classification.** Breaking (replaces block-header signature format + introduces new curve family + pairing primitives).

**Dependencies.** Production-grade C99 BLS12-381 implementation + audited pairing primitives + project-policy decision to expand crypto-curve roster.

**Related.** `docs/Improvements.md` §1; v2.10 (FROST-Ed25519 — already provides aggregation in the threshold-randomness path but on curve25519, not BLS12-381).

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

**Classification.** Breaking (Phase-1 ContribMsg wire format change; new sketch primitive in net stack; new decode-failure fallback).

**Dependencies.** Production-grade IBLT / Minisketch C99 implementation + audit; mempool-size measurements demonstrating the saving is load-bearing for real deployments; spec for sketch-decode-failure fallback (when peers' mempool delta exceeds sketch capacity).

**Related.** `docs/Improvements.md` §4; v2.6 (gossip-out-of-lock — already addresses Phase-1 gossip latency, an adjacent concern); S-022 wire-format caps proof.

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

This means most items in §1.1, §1.2, §1.3, §1.8, §3.1, §3.2, §3.3, §4.1, §6.1, §6.3, §6.4 are *effectively v3 candidates* if pursued. Their planning horizon is years, not months. **Exception:** §6.2 (Quorum Liveness OPTIONAL) is classified Additive-via-opt-in because legacy K-of-K remains the default codepath — see its entry for the policy rationale.

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

---

*End of improvements queue. Append new entries as future deliberations produce additional deferred items.*
