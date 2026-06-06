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

### 1.3 Stealth addresses (Monero-style) for graph privacy — MOVED TO §11.1 (2026-06-03)

**Status:** reclassified from "v3 candidate" to "Out of scope" — not v3-motivating on its own. See §11.1 for full original analysis.

**Why moved:** Graph privacy is a significant feature, but requires Monero-class whole-chain rewrite. A whole-chain rebuild just to add graph privacy is overkill — graph-privacy users have Monero/Zcash.

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

### 3.1 Horizontal scale beyond ~500 shards — MOVED TO §11.2 (2026-06-03)

**Status:** reclassified from "v3 candidate" to "Out of scope" — speculative scaling for unforeseen need. See §11.2 for full original analysis.

**Why moved:** No deployment in any foreseeable horizon needs >500 shards.

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

### 5.7 Genesis-time validation for self-consistent economic configuration (added 2026-06-05)

**Improvement.** Manifest-validity check at genesis (extends Beaconless-v2 §Q2.1 hard-invariant pattern) that rejects bad combinations of `block_subsidy` + `subsidy_pool_initial` + per-tx fee policy + sponsor-declaration. Prevents operator misconfiguration from creating chains with broken long-term validator economics.

**The problem.** v1.x provides three economic primitives (block subsidy, subsidy pool cap, per-tx fees) configurable per deployment. Some combinations are self-consistent; others are not:

| Configuration | Self-consistent? |
|---|---|
| `block_subsidy = 0` + non-zero fees + sponsor-deployment declaration | ✅ Sponsor pays validators directly; fees are minor revenue |
| Permanent inflation (`block_subsidy > 0`, `subsidy_pool_initial = 0`) | ✅ Validators always paid via issuance |
| Bootstrap (`subsidy_pool_initial > 0` + non-zero fee rate) | ✅ Subsidy initially, then fee market |
| `block_subsidy = 0` + zero fees + no sponsor declaration | ❌ No one pays validators — chain dies |
| Bootstrap (`subsidy_pool_initial > 0`) + zero fees | ❌ Cliff at pool exhaustion; chain economics break |

Without genesis validation, operators can ship the broken combinations — and the failure mode surfaces post-launch when validators stop being compensated.

**Proposed validation rule (manifest hard-invariant).**

```
post_exhaustion_funded := (per_tx_fee_rate > 0) OR (sponsor_deployment_declared = true)
acceptable := (block_subsidy > 0 AND subsidy_pool_initial == 0)        // permanent inflation
              OR (post_exhaustion_funded)                                // fees and/or sponsor
              OR (block_subsidy == 0 AND post_exhaustion_funded)         // genesis-only inflation, then post-exhaustion funded
```

Manifest fails validation if `acceptable == false`. Operator must either (a) enable permanent inflation, (b) set non-zero fee rate, or (c) declare sponsor-deployment status (operator-attested; not chain-enforced beyond declaration).

**Sponsor-declaration field.** Add `manifest.sponsor_declaration: enum { NONE, SOVEREIGN_OPERATOR, FOUNDATION_RUN, OTHER }` — operator attestation of how validators are funded off-chain. Validator does not enforce truthfulness (sponsor-attestation is honor-system), but the field makes economic-model intent explicit and unlocks the "no fees + sponsor-funded" acceptable path.

**Classification.** Additive if shipped pre-v1.0 (genesis manifest schema addition); requires another §7.5-style discriminator (call it §7.5.12) preserved in v1.0 schema for forward compatibility.

**Effort.** ~1-2 days: manifest field + validation rule + sponsor_declaration enum + DECISION-LOG entry. Minimal v1.0 schema lift.

**Dependencies.** None — composes with existing Beaconless-v2 §Q2.1 manifest-validity framework.

**Related.** `WHITEPAPER-v1.x.md §8.2-8.4` v1.x economic primitives; Beaconless-v2-SPEC.md §Q2.1 manifest-validity pattern; §9.6 monetization framing.

### 5.6 S-010 stake-pricing review under AI-volume assumptions (added 2026-06-05)

**Improvement.** Review the S-010 stake-pricing formula (per `SECURITY.md §S-010`) under the assumption that AI orchestrators can spin up accounts at industrial rates rather than human-velocity rates. AI-traffic-dominance (2026 baseline: AI traffic > human traffic on broader internet) may change the Sybil-resistance assumptions S-010 relies on.

**Why this matters now.** S-010's "economic argument for security" assumes Sybil cost grows linearly with attacker effort. AI orchestration changes that to "linearly with attacker capital" — potentially much lower per-account cost. Whether the existing formula still provides adequate Sybil-resistance depends on AI-orchestration-cost vs stake-cost ratios that weren't analyzed in the original S-010 work.

**Deferred reason.** Not a chain-design change yet — it's an analytical review. May result in: (a) formula parameter tuning, (b) AI-orchestration cost modeling becoming a deployment-tier knob, (c) confirming current formula remains adequate.

**Classification.** Process (analytical review, potentially leading to operator-facing parameter guidance).

**Dependencies.** Empirical data on AI-orchestration cost economics; cryptographic-economist review; possibly DSF-based simulation of high-velocity Sybil scenarios.

**Related.** `SECURITY.md §S-010` stake-pricing formula; §9.2.1 AI-agent economy patterns; memory `dlt-no-migrations-constraint` (any parameter change post-v1.0 must fit Additive constraints).

### 5.5 Hardware wallet ecosystem support for ROTATE_KEY (v3 — deferred from v2.26 per KR-11)

**Improvement.** First-class hardware wallet (Ledger / Trezor / etc.) support for v2.26 ROTATE_KEY UX. Device firmware shows "Rotate operator key for domain X to new key Y" before signing; multi-sig co-flow UX; recovery-flow integration.

**Deferred reason.** V2-DESIGN.md §v2.26 originally included HW-wallet UX commitments. KR-11 reclassified to post-v1.0 ecosystem concern: the chain's wire format remains HW-wallet-compatible (standard Ed25519 sign over hashed envelope works with existing firmware), but explicit certification + UX commitments are wallet-ecosystem-facing work, not chain-design work.

**Classification.** Process (ecosystem partnership + certification).

**Dependencies.** Wallet-ecosystem partner engagement; device-firmware update cycles per vendor; multi-sig (v2.15) shipped first so HW wallet support covers both single-sig and multi-sig rotation flows.

**Related.** `DECISION-LOG.md` → v2.26 v2.26-ROTATION-SPEC.md → KR-11; `v2.26-ROTATION-SPEC.md §2 KR-11`.

### 5.8 EIP-1559-style base-fee + priority-tip mechanism (added 2026-06-06)

**Improvement.** Add a chain-level mechanism to split per-tx fees into (base fee + priority tip). Base fee is algorithmic per block, targeting a configurable utilization (e.g., 50% block capacity), with a microscopic floor. Priority tip is uncapped, user-set, awarded 100% to the active K-of-K committee split 1/K (uses existing FLAT distribution). Composes with `ECONOMICS_CONFIG_GUIDANCE.md` three-policy pattern for deployments wanting cheap base layer + market-bid priority lane.

**The problem this solves.** v1.x's per-tx `fee` field is a single value; sender sets, validator distributes. This works for simple economics but doesn't support:
- Microscopic base cost for telemetry/Web3-logging workloads (no algorithmic floor + adjustment)
- Market-bid priority lane that doesn't drag up the base for everyone else
- Spam-mitigation backpressure that activates only when blocks exceed target utilization
- Symmetric Phase-2 signing incentive across K committee members (single-fee model doesn't guarantee even split semantics)

EIP-1559 (Ethereum's 2021 fee market upgrade) solved these with base-fee + priority-tip semantics. Adapting to Determ's K-of-K consensus + sovereign-deployment context fits the project's character.

**Wire-format additions.**

| Field | Location | Purpose |
|---|---|---|
| `Transaction.priority_tip: u64` | Every Transaction (NEW optional field) | Sender-set bid for next-block inclusion; 0 for telemetry-class txs; uncapped for high-frequency actors |
| `Block.base_fee: u64` | Block header (NEW per-block field) | Algorithmic base-fee value for this block; computed by validators from previous block's utilization |
| `manifest.base_fee_floor: u64` | Beaconless-v2 deployment manifest (NEW genesis-pinned field) | Operator-set minimum base fee; deployment-wide |
| `manifest.base_fee_target_util: u16` | Beaconless-v2 deployment manifest (NEW genesis-pinned field) | Operator-set target utilization in basis points (5000 = 50%); deployment-wide |
| `manifest.base_fee_adjust_rate: u16` | Beaconless-v2 deployment manifest (NEW genesis-pinned field) | Adjustment rate per block in basis points (1250 = 1/8 per EIP-1559 default); deployment-wide |
| `manifest.base_fee_handling: enum` | Beaconless-v2 deployment manifest (NEW genesis-pinned field) | Operator policy: BURN / SUBSIDY_POOL / PRIORITY_POOL for base-fee disposition |

**Classification.** Additive if the new `Transaction.priority_tip` field is preserved via a pre-v1.0 schema discriminator (similar to §7.5 pattern). Otherwise Breaking. Recommended: ship the field in v1.0 with default `priority_tip = 0` for backward compatibility (legacy fee-only path); EIP-1559 algorithm activates when manifest fields are set non-zero.

**Apply path.**

1. Validator computes `base_fee_this_block = adjust(prev_block.base_fee, prev_utilization, manifest.base_fee_floor, target, rate)` per EIP-1559 algorithm
2. For each tx in block: `total_fee_paid = tx.fee + tx.priority_tip`; `base_fee_required = base_fee_this_block * tx_size_or_complexity_metric`; reject if `tx.fee < base_fee_required`
3. Distribute: `tx.priority_tip → FLAT split 1/K to active K committee (dust to creators[0])`; `(tx.fee - base_fee_required) → manifest.base_fee_handling policy (BURN | SUBSIDY_POOL | PRIORITY_POOL)`

**Dependencies.**
- Genesis-pinned manifest fields for base-fee parameters (~1 day spec)
- `Transaction.priority_tip` optional field (~1 day wire format)
- `Block.base_fee` per-block field (~1 day wire format)
- Validator base-fee algorithm + distribution logic (~3-5 days impl)
- Tests + docs (~2-3 days)
- **Total effort: ~1-2 weeks if shipped pre-v1.0 (Additive)**
- If shipped post-v1.0, requires `Transaction.fee_form` discriminator pre-v1.0 (would need §7.5.13 added to existing 9-discriminator sweep)

**Pre-v1.0-schema-freeze flag.** §5.8 needs either:
- Ship the new fields in v1.0 schema (Additive; ~1-2 weeks pre-bundle work) — recommended
- Ship a `Transaction.fee_form` discriminator + `manifest.fee_form` discriminator (~1-2 days pre-bundle) preserving optionality to add the algorithm post-v1.0
- Skip and accept that EIP-1559-style economics is v3-only

**Related.** `ECONOMICS_CONFIG_GUIDANCE.md` (operator-facing recommended-defaults pattern); `Improvements.md §5.7` (genesis-time economic-config validation; §5.7 + §5.8 together let operators ship the three-policy pattern with safety-checked configuration); `WHITEPAPER-v1.x.md §8.2-8.4` (v1.x economic primitives this extends).

**Pro/Con vs alternative approaches.**

| Pro | Con |
|---|---|
| Microscopic base cost for telemetry workloads | New chain-level mechanism (additional implementation work) |
| Market-bid priority lane isolated from base | New manifest parameters operators must understand |
| Spam-mitigation only when blocks > 50% full | EIP-1559 adjustment can oscillate under certain load patterns |
| 1/K priority-tip split aligns K-of-K signing incentives symmetrically | If shipped post-v1.0 without pre-v1.0 discriminator, becomes Breaking |
| Composable with §5.7 genesis-validation + §9.2 DApp-pricing | Adds complexity to the fee-accounting layer (validators must compute base_fee per block) |

**Compositional cleanliness.** The mechanism is Additive-via-default-zero: when `manifest.base_fee_floor = 0` AND `manifest.base_fee_target_util = 0` AND `Transaction.priority_tip = 0`, behavior reduces exactly to v1.x's existing single-fee model. Operators opt in to EIP-1559 by setting the manifest fields; default deployment behavior unchanged.

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

### 6.3 Data deduplication `deduplicated_tx_root` — MOVED TO §11.3 (2026-06-03)

**Status:** reclassified from "v3 candidate" to "Out of scope (ride-along only)" — not v3-motivating on its own. See §11.3 for full original analysis.

**Why moved:** Bandwidth saving is real but not load-bearing per the entry's own analysis; requires FA2 proof reformulation. Cost-benefit doesn't favor opening v3 just for this. Could ride along IF v3 opens for another reason (e.g., crypto migration).

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

This means most items in §1.1, §1.2, §1.8, §3.2, §3.3, §4.1, §6.1 (MODERN variant), §6.4 are *effectively v3 candidates* if pursued. Their planning horizon is years, not months. **Exceptions:**
- §6.2 (Quorum Liveness OPTIONAL) — fully Additive via §7.5.10 + §7.5.11 (per `DECISION-LOG.md` 2026-06-03); no longer a v3 candidate.
- §6.1 (BLS aggregation) is split per profile: the MODERN-profile aggregation variant is Breaking (v3 candidate), but the FIPS-profile variant is Additive — FIPS deployments retain the v1.0 K-of-K Ed25519 array unchanged. The per-profile dispatch mirrors the PRIV-3 / C99-11 "curve follows profile" pattern. See §6.1 for the `signature_form` discriminator decision that must be made pre-v1.0 schema freeze to preserve MODERN-side optionality.
- §1.3 stealth addresses, §3.1 sharding-of-sharding, §6.3 dedup, §9.1 tier-bond monetization — RECLASSIFIED 2026-06-03 to **§11 Out of scope** (not v3-motivating on their own). See §11 entries for reasoning.

### 7.2 Additive improvements + opt-in defaults

Items classified **Additive** can ship post-v1.0 as long as they preserve legacy-validator behavior. The pattern: new optional fields validators can ignore, new tx types that legacy validators fail-closed on or skip without state mutation. These improvements have realistic post-v1.0 paths. **§6.2 (Quorum Liveness OPTIONAL)** is the canonical "Additive-via-opt-in" example — a new deployment-mode knob at genesis that older chains never read, gated such that the v1.0 K-of-K validator codepath is unaffected.

### 7.3 Research improvements + revisit triggers

Items classified **Research** are paused waiting for primitive maturation or deployment-driven demand. Revisit triggers (in approximate priority order):

- Production-grade C99 FSE implementation → revisit 1.1
- Production-grade C99 puncturable encryption → revisit 1.2
- Production-grade ZK proof system in C99 → revisit 1.7
- Dilithium-FROST publication + audit → revisit 2.2, 4.1
- FIPS 206 finalization + Falcon C99 impl → revisit 2.1
- Fair-ordering research breakthrough → revisit 4.3
- Production-grade C99 BLS12-381 + pairing primitives + project-policy decision to expand crypto-curve roster → revisit 6.1
- Production-grade IBLT / Minisketch C99 implementation + sketch-decode-failure fallback spec → revisit 6.4
- (§3.1 >500 shards, §6.3 dedup moved to §11 Out of scope 2026-06-03; not in live revisit-trigger list)

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
| **7.5.8** | `RegistryEntry.deployment_tier: enum` (per-account monetization tier) | RegistryEntry | `UNSTAKED` | §9.1 Option A tier-bond monetization (forward-compat slot only; tier-bond logic NOT implemented at v1.1) | 1 byte/RegistryEntry | ✅ **SHIP REVISED 2026-06-06** — under v1.1-launch model the "Breaking-only post-v1.0" framing dissolves (no pre-v1.0 boundary); shipping the discriminator preserves forward-compat optionality at trivial schema cost. Value-decision against tier-bond monetization stays (validator enforces deployment_tier = UNSTAKED at v1.1 launch); POLICY_TIER_BONDS_ENABLED flag in §7.5.10 becomes implementable if Option A ever revisited post-v1.1 as Additive. |
| **7.5.10** | `manifest.policy_tier_flags: u32` bitset (per-deployment opt-in policy framework) | Beaconless-v2 deployment manifest | `0x00000000` (all flags off — conservative) | Operator-tier opt-in framework (§10.3) cascading to §1.8 trusted-issuer audit, §5.2 external audit, §5.5 HW wallet certification, §6.2 Quorum Liveness OPTIONAL | 4 bytes/manifest; validated via Beaconless-v2 §Q2.1 hard-invariant (unknown bits = reject) | ✅ **SHIP 2026-06-03** — single 4-byte field unlocks 4 deferred items as Additive |
| **7.5.11** | Per-block `quorum_bitset` field (variable-length per genesis K) | Block header | All-1s (matches unanimous_k mode; equivalent to current behavior) | §6.2 Quorum Liveness OPTIONAL — completes the unlock initiated by 7.5.10 (manifest flag + per-block bitset both required for full implementability) | 1-16 bytes/block depending on profile K (1B tactical K=8 → 16B global K=128); prunable under chain pruning | ✅ **SHIP 2026-06-03** — completes §6.2 unlock; coherent with 7.5.10 ship decision |
| **7.5.12** | `manifest.sponsor_declaration: enum` (off-chain validator funding attestation) | Beaconless-v2 deployment manifest | `NONE` (per-deployment operator attestation; chain does not enforce truthfulness) | §5.7 genesis-time economic-config validation rule — enables operator attestation that validators are funded off-chain (sovereign-deployment model); required by ECONOMICS_CONFIG_GUIDANCE three-policy recommended pattern | 1 byte/manifest (enum NONE / SOVEREIGN_OPERATOR / FOUNDATION_RUN / OTHER) | ✅ **SHIP v1.1 GENESIS 2026-06-06** — enables §5.7 validation + ECONOMICS_CONFIG_GUIDANCE recommended pattern; required when subsidy + base_fee floor are minimal |
| **5.8.S** | EIP-1559 fee mechanism fields: `Transaction.priority_tip: u64` + `Block.base_fee: u64` + 4 manifest fields (`base_fee_floor`, `base_fee_target_util`, `base_fee_adjust_rate`, `base_fee_handling`) | Transaction, Block header, manifest | All zero (reduces to v1.x single-fee model) | §5.8 EIP-1559-style three-policy fee mechanism (per `ECONOMICS_CONFIG_GUIDANCE.md`) | 8B/tx + 8B/block + ~16-32B/manifest | ✅ **SHIP v1.1 GENESIS 2026-06-06** — full mechanism (not just discriminator); enables ECONOMICS_CONFIG_GUIDANCE three-policy pattern from v1.1 launch day 1; Additive-via-default-zero (manifest fields zero = v1.x behavior preserved) |

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

#### 7.6.8 `manifest.policy_tier_flags` coherence (7.5.10, added 2026-06-03)

**Concern.** Per-deployment opt-in framework: how does the policy bitset interact with existing manifest fields and validation?

**Resolution.** Orthogonal to existing manifest fields (`epoch_snapshot_interval` per BL-3, `merritt_k` per BL-5, `epoch_boundary_cutoff_blocks` per BL-6, `randomness_aggregation_form` per 7.5.4). Each bit is an independent policy opt-in for a specific post-v1.0 feature; multiple bits can be set per deployment.

**Reserved bit allocation (v1.0):**
- `POLICY_TRUSTED_ISSUER_AUDIT` (1 << 0) — enables §1.8 trusted-issuer audit as opt-in tier
- `POLICY_EXTERNAL_AUDIT_REQUIRED` (1 << 1) — enables §5.2 external audit as deployment-policy opt-in
- `POLICY_HW_WALLET_CERTIFIED` (1 << 2) — enables §5.5 HW wallet ecosystem certification tier
- `POLICY_BFT_THRESHOLD_FINALIZATION` (1 << 4) — enables §6.2 Quorum Liveness OPTIONAL 2F+1 finalization
- Reserved: bit 3 (was tentatively `POLICY_TIER_BONDS_ENABLED`; now vestigial since 7.5.8 skipped — kept reserved to avoid bit-renumbering if Option A revisited later)
- Reserved: bits 5..31 for future policy opt-ins

**Validator dispatch at v1.0.** `validate_manifest()` rejects manifests with any bits set other than 0 (only `0x00000000` accepted). Future activations land per-flag as the corresponding feature implementations ship.

**Composition with §6.2 Quorum Liveness OPTIONAL.** The §6.2 entry originally noted that ship required a `Config::finalization_mode` knob + `quorum_bitset` block-header field. The `quorum_bitset` block-header field still needs to exist (it's per-block, not per-manifest); 7.5.10 only covers the manifest-level enablement flag. The block-header `quorum_bitset` field would need its own pre-v1.0 commitment — flagged as residual gap for §6.2 enablement (the manifest enables the mode but the per-block bitset must exist in the schema).

**Composition with Beaconless-v2 §Q2.1.** Hard-invariant validation rejects unknown flag bits. Per the §Q2.1 hard/soft tier split, this validation is HARD (consensus-enforced) — operators cannot ship manifests with unrecognized bits.

#### 7.6.9 7.5.8 skip cascade

**Concern.** Skipping 7.5.8 (deployment_tier) closes Option A monetization. What other v3 paths are affected?

**Resolution.** §9.1 Option A reclassified from "live candidate" to "Breaking-only post-v1.0" (would require v3 protocol opening to add). §7.5.10's `POLICY_TIER_BONDS_ENABLED` flag becomes vestigial (no per-account tier field to enforce against), but the bit position is reserved to avoid renumbering if Option A is ever revisited via v3 protocol opening. The reservation is documented but the flag has no current implementation path.

#### 7.6.10 Per-block `quorum_bitset` coherence (7.5.11, added 2026-06-03)

**Concern.** Per-block participation bitset is variable-length per genesis K; how does it interact with the existing block-header schema?

**Resolution.** Variable-length encoding follows the same pattern as §7.5.7 pubkey_form: `{length: u8 (K_bytes), body: bytes}`. For K=8 the body is 1 byte; for K=128 it's 16 bytes. The length field is implicit from genesis K (K is genesis-pinned per deployment), so no per-block length-byte overhead is strictly needed — the body alone suffices when K is known.

**Default at v1.0.** All-1s bitset (every committee member participated). Identical semantics to current unanimous_k mode. Validator's BFT-threshold check short-circuits to existing K-of-K equality check when bitset is all-1s.

**Future activation.** Requires BOTH `manifest.policy_tier_flags & POLICY_BFT_THRESHOLD_FINALIZATION` (per 7.5.10) AND `manifest.finalization_mode == BFT_THRESHOLD_2F1` (additional manifest field for finalization mode selection — not currently spec'd as a separate discriminator; could be part of POLICY_BFT_THRESHOLD_FINALIZATION semantics).

**Composition.**
- Orthogonal to §7.5.1 `signature_form` (signature scheme vs. participation tracking)
- Orthogonal to v2.10 FROST randomness sig (randomness layer vs. block finalization layer)
- Logically dependent on §7.5.10 (manifest enablement flag) — without §7.5.10 the bitset can exist but the BFT-mode is not opt-in-able

**Validator dispatch at v1.0.** Bitset validates as all-1s (mode=unanimous_k); fail-closed reject any other pattern. Post-v1.0, when POLICY_BFT_THRESHOLD_FINALIZATION is set, validator checks at least 2F+1 bits are set per the BFT threshold.

#### 7.6.11 Summary — nine discriminators coherent (8 ship, 1 skip)

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

**v1.1 plan reference.** Items in this section + §10 are operationalized in `V1.1-PLAN.md` (the post-v1.0 Additive release covering DSSO-DApp, zk-VM-DApp, sketch-v2.x formalization, and 5 reference killer-DApps). v1.1 ships ~4-7 months post-mainnet. See `V1.1-PLAN.md` Bundle A specifically for the DSSO-DApp implementation plan operationalizing §8.1 below.

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

---

## 9. Monetization model research (v3 candidates)

Captured 2026-06-03 after explicit rejection of a casino-fee proposal (per DECISION-LOG.md → "Casino-fee mechanism rejection (2026-06-03)"). The underlying goal — capture value from high-margin use cases without burdening general adoption — is legitimate. Five alternative models preserved as research candidates; none committed.

**Common principle.** All five avoid the rejected proposal's anti-pattern of pricing general-purpose cryptographic primitives (VRF, ZK proofs, escrow) that have legitimate non-casino uses. Instead, they price either (a) resource consumption, (b) deployment posture, or (c) DApp-layer revenue capture — none of which tax the cryptographic substrate itself.

### 9.1 Option A — Stake/bond requirements scaled by deployment tier — MOVED TO §11.4 (2026-06-03)

**Status:** reclassified from "v3 candidate (Breaking-only)" to "Out of scope" — deliberately rejected via 7.5.8 skip on 2026-06-03. See §11.4 for full original analysis.

**Why moved:** The 7.5.8 skip was a deliberate project decision (preserving chain-level character of "no per-account fee differentiation"). Classification as "v3 candidate" implied a backdoor where the project might revisit; that's misleading since the rejection was a value decision, not technical. §11.4 preserves the analysis without false signaling.

### 9.2 Option B — Application-layer pricing via DApp framework

**Mechanism.** DApps charge their users for premium features (VRF, ZK proofs, atomic escrow) and pay protocol fees from revenue. Protocol stays primitive-free; DApps own pricing/billing.

**Classification.** Additive (no chain-level change needed; DApps handle pricing in v2.18 + v2.19 substrate). No discriminator required.

**Dependencies.** DApp framework guidance / SDK for fee handling; reference DApp showing pricing pattern.

**Pro/Con.** Purest "everything else is a DApp" model; chain stays free; casinos naturally pay more via their DApp's pricing; no protocol-level revenue capture (foundation must monetize elsewhere). Matches V2-DESIGN.md §God-protocol philosophy.

**Related.** `DAPP_SDK_GUIDANCE.md` (could add fee-handling guidance); `Improvements.md §8.1` DSSO-as-DApp (same pattern); v2.18/v2.19 substrate (already shipped).

### 9.3 Option C — Resource-based pricing with feature multipliers (Ethereum-style gas) — REJECTED 2026-06-03

**Status.** Rejected. "No gas-style" decision per `DECISION-LOG.md` 2026-06-03 entry "Gas-style pricing rejected".

**Rationale for rejection.** Gas-style pricing changes Determ's "free for enterprise" framing fundamentally; adds substantial v3 infrastructure (gas accounting, mempool fee-priority, validator gas-metering, per-opcode cost schedule + governance for updates, gas-payment token model); shifts project's character from primitive-free public-interest infrastructure toward fee-market substrate. Explicit project-policy rejection.

**Preserved for record (original mechanism description):** VRF opcode costs N gas-equivalent; ZK proof verify costs M; escrow state-hold costs storage rent. Standard chain-economy model. Would have required §7.5.9 `Block.gas_pricing_form: enum` discriminator pre-v1.0 to remain Additive — that discriminator is now NOT being added to §7.5 (rejection cascades to closing the discriminator slot).

**Cascade.** This rejection also implicitly closes Option D (§9.4 validator revenue sharing) because Option D required the same gas-accounting infrastructure as Option C.

### 9.4 Option D — Validator revenue sharing on premium operations — REJECTED 2026-06-03 (cascade)

**Status.** Rejected. Cascade-rejection from §9.3: depended on the same gas-style accounting infrastructure that Option C was rejected for.

**Rationale for rejection.** Cascades from §9.3 gas-style rejection (same per-tx fee accounting + validator fee-receipt mechanism). Additionally suffers the same use-case-overlap problem as the originally-rejected casino-fee proposal — VRF/ZK/escrow have substantial non-casino legitimate users who would also pay, taxing the wrong feature set.

**Preserved for record (original mechanism description):** VRF/ZK/escrow opcodes pay validators directly (revenue share). Market-priced; self-balancing; validators capture their own value. But: requires gas-style infrastructure (rejected) AND taxes general-purpose primitives that have non-target legitimate users.

**If pursued later under different framing:** would need to be restructured around non-gas-style flat fees or subscription model rather than per-tx revenue share. Different design than originally captured here.

### 9.5 Option E — Foundation/SDK revenue model unrelated to protocol

**Mechanism.** Protocol stays free. Determ Foundation monetizes via: enterprise support contracts, regulatory-compliance certification, ecosystem partnerships, training/certification programs.

**Classification.** Process (no chain change; entirely off-protocol).

**Dependencies.** Foundation entity establishment; service offerings; staff for support/certification.

**Pro/Con.** Decouples protocol economics from use-case capture (cleanest mission alignment); validated model (Linux Foundation, CNCF, Apache Foundation, etc.). Con: no protocol-level revenue; slower revenue ramp than fee-based; requires building services org.

**Related.** Memory `dlt-no-migrations-constraint` (foundation services don't affect chain immutability); aligns with MOTIVATION.md "transparent public-interest infrastructure" framing.

### 9.6 Final monetization model (post-2026-06-05 sharpening)

**The live monetization model is §9.2 + §9.5. Nothing else.** §9.1, §9.3, §9.4 are preserved-rejection-rationale for record — NOT parallel candidates competing with §9.2/§9.5. The two live models are orthogonal (not competing) and together cover legitimate value-capture without protocol-level fee mechanics.

| Option | Status | Layer | What it funds |
|---|---|---|---|
| **9.2 DApp-layer pricing (B)** | ✅ **Live model** | Application | DApp businesses (each DApp captures value from its users — including AI-delegate principals per §9.2.1 below) |
| **9.5 Foundation services (E)** | ✅ **Live model** | Off-protocol | Foundation operations + reference deployments (support contracts, certification, ecosystem partnerships, training) — repositioned 2026-06-05 as "AI-agent economy infrastructure" provider |
| 9.1 Tier-bonds (A) | ⛔ Skipped (7.5.8 not shipped 2026-06-03) | Protocol | (Would have funded chain via stake economics; rejected — not in v1.0) |
| 9.3 Gas pricing (C) | ❌ Rejected 2026-06-03 | Protocol | (Would have funded chain via fee market; rejected on character grounds) |
| 9.4 Validator revenue share (D) | ❌ Rejected 2026-06-03 (cascade from C) | Protocol | (Would have funded validators; cascade-rejected with C) |

**Important framing correction (2026-06-05):** "Chain protocol stays free" earlier in this section was over-simplified. The chain protocol **already has** a per-tx fee mechanism + block subsidy mechanism in v1.x (per `WHITEPAPER-v1.x.md §8.2-8.4` and `PROTOCOL.md`). What's correct:

- **Chain protocol provides fee + subsidy mechanism**; per-deployment operator configures the rates (genesis-pinned `block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, plus per-tx `fee` field with operator-set rate). v1.x model is already complete for the chain-level economic primitive.
- **§9 monetization research addresses ADDITIONAL revenue capture** beyond v1.x's existing fee + subsidy. Specifically: chain-level mechanisms that would tax use-case-specific patterns (rejected — §9.3 gas-style, §9.4 validator revenue share) OR alternative non-fee value-capture layers (live — §9.2 DApp-layer, §9.5 Foundation services).
- **The rejected protocol-level proposals** (§9.1 tier-bonds, §9.3 gas-style, §9.4 validator revenue share) failed because they would have ADDED feature-discriminating or use-case-pricing mechanisms on top of the existing fee/subsidy primitive — the rejection wasn't "no fees ever" but "no use-case-specific fee discrimination."

**Why §9.2 + §9.5 are sufficient as ADDITIONAL revenue layers beyond v1.x fees/subsidy.**

- **Validators in sovereign-deployment model** are paid by the deployment's sponsor (banks, governments, enterprises run their own deployments for their own benefit). The v1.x fee + subsidy is bonus revenue offsetting sponsor's organizational cost; doesn't need additional layers.
- **Validators in public/permissionless deployment model** are paid by v1.x's fee + subsidy mechanism — operator chooses configuration (permanent inflation, bootstrap+fees, fees-only) per their economic model. See §5.7 for the operator-config validation that prevents bad combinations like "pool-cap subsidy + zero fees + no sponsor."
- **DApp ecosystem captures application value via §9.2** — orthogonal to chain-level fees; DApps price their applications (per-action, per-principal-subscription, per-delegation-credential per §9.2.1).
- **Foundation captures non-deployment value via §9.5** — orthogonal to both; services-org revenue funds chain maintenance, reference implementations, certification.

**Three independent layers:**
1. Chain-level fee + subsidy (v1.x; operator configures per-deployment)
2. DApp-layer application pricing (§9.2)
3. Foundation services off-protocol (§9.5)

Each layer captures legitimate value at its own granularity without interfering with the others.

**Why no other models are needed.** Protocol-level revenue capture (§9.1, §9.3, §9.4) was repeatedly rejected because (a) it requires identity-classification at protocol level which is structurally infeasible (blindness problem); (b) it changes Determ's character from primitive-free public-interest infrastructure toward fee-market substrate. The two-layer split (DApp + Foundation) preserves character while capturing legitimate value at the layers where it can be captured fairly.

**Pre-v1.0-schema-freeze status:** §7.5.8 SKIPPED 2026-06-03 (Option A monetization now Breaking-only — kept in §9.1 row for rejection-rationale only). §7.5.10 SHIPPED 2026-06-03 (unrelated; operator-tier opt-in framework for §1.8 / §5.2 / §5.5 / §6.2).

### 9.2.1 DApp-layer pricing patterns under AI-agent economy dominance (added 2026-06-05)

By 2026 AI traffic has surpassed human traffic on the broader internet. DApps building on Determ should structure pricing for AI-mediated usage, where principals delegate to AI agents that act at higher transaction velocity than the principal alone would.

**Recommended DApp pricing patterns:**

| Pattern | When appropriate |
|---|---|
| **Per-principal subscription** (principal pays one bill covering self + delegated AI agents' actions) | Default for principal-mediated use; predictable revenue; AI volume doesn't bankrupt principal |
| **Per-action with principal-aggregate cap** | Hybrid; per-action visibility + cap protection |
| **Delegation-credential issuance fee** (each DSSO-as-DApp delegate credential carries one-time issuance fee) | Captures AI proliferation directly; self-selecting (humans without delegates pay nothing) |
| **Volume-tier discounts that scale with AI orchestration** | High-volume principals pay less per-tx; recognizes AI orchestration as a legitimate use pattern |

The chain protocol stays free for AI agents and humans alike (per §9.6 — no protocol-level discrimination). DApps absorb the pricing-design problem and price-discriminate at the application layer where they have the visibility to do so legitimately.

**Authority for these patterns: DApp owners.** The chain provides primitives (DSSO-as-DApp delegation credentials, v2.22 PFS for principal-protection, v2.26 ROTATE_KEY for delegate revocation); DApps choose business models. `DAPP_SDK_GUIDANCE.md` will carry detailed pricing-pattern guidance for DApp developers.

### 9.5.1 Foundation-services repositioning — AI-agent economy infrastructure (added 2026-06-05)

Determ's design fits the AI-agent economy especially well — AI agents need K-of-K mutual-distrust, verifiable identity (DSSO), transaction confidentiality (PFS), and cryptographic accountability (ROTATE_KEY + audit hooks). The Foundation's §9.5 services can target this positioning explicitly:

| Service | AI-agent-economy framing |
|---|---|
| Enterprise support contracts | "Run AI-agent infrastructure on verifiable cryptographic substrate; we support your AI-delegate deployment" |
| Regulatory-compliance certification | "Certify your AI agents are operating under cryptographically auditable delegation per v2.26 + v2.22 PRIV-4" |
| Ecosystem partnerships | "Integrate with leading AI-agent platforms via DSSO-as-DApp delegation primitives" |
| Training/certification programs | "AI-agent-economy infrastructure operator certification" |

No technical change; sharper positioning for foundation-services pitch. Aligns with the project's design fitness for the AI-agent economy.

---

## 10. Near-term v3-blocker unblocks (captured 2026-06-03)

Three v3 items had blocker-alternative analysis indicating modest spec work could promote them from "blocked" to "spec-ready." Captured here for future activation; not currently scheduled.

### 10.1 §6.3 dedup — reformulation via per-creator Bloom/IBLT

**Improvement.** Replace the FA2 censorship-evidence-surface concern with a per-creator Bloom filter / IBLT commitment in the block header. Each creator commits to their proposed-tx set via a small commitment; FA2's "k-conjunction-of-creators-must-collude" argument carries through against the commitment witness rather than the raw per-creator list.

**Status change.** Per `Improvements.md §6.3` original entry, blocker was "FA2 reformulation needed (not just discriminator)." Reformulation via per-creator Bloom/IBLT was already noted as an alternative inside that entry. Promoting from "research-stuck" to "Breaking but spec-ready" requires ~1 week of focused FA2 proof + wire-format design.

**Classification.** Still Breaking (the dedup itself remains a block-header structural change) but no longer research-stuck.

**Dependencies.** ~1 week design work for FA2 proof reformulation + per-creator commitment wire format.

**Action.** Defer until §6.3 demand surfaces; spec-sketch then.

### 10.2 §1.6 stateless scheduled decoys

**Improvement.** Recipient publishes decoy OTPK batches on a fixed schedule, not based on actual usage. Observer sees uniform-but-not-cryptographically-unforgeable decoy pattern. ~80% of unforgeable-decoy benefit at trivial implementation cost.

**Status change.** Per `Improvements.md §1.6` original entry, blocker was "decoy-unforgeability mechanism (commitment scheme or similar)." Stateless scheduled decoys sidestep that requirement entirely — accept slightly weaker privacy in exchange for ~3-5 day spec-sketch instead of multi-month commitment-scheme research.

**Classification.** Additive (alongside PRIV-6.2 cadence padding); composes with existing OTPK stream.

**Dependencies.** ~3-5 days spec work; wallet-side scheduler.

**Action.** Could ship in v1.0 alongside PRIV-6.2 if wallet-team capacity permits — but classified Additive so post-v1.0 is also fine.

### 10.3 Operator-tier opt-in framework as a v3 design pattern — ENABLED 2026-06-03 via 7.5.10

**Improvement.** Generalize the §6.2 Quorum Liveness OPTIONAL pattern (operator-tier opt-in with default-conservative codepath) into a reusable v3 framework. Chain-level `manifest.policy_tier_flags` u32 bitset with per-flag opt-in lets multiple policy-blocked items ship as opt-in tiers without project-wide policy decisions.

**Status: 7.5.10 shipped in v1.0** (per `Improvements.md §7.5` 2026-06-03 decision). Framework is now ENABLED — `manifest.policy_tier_flags` field exists in v1.0 schema; specific flag bits activate as their corresponding feature implementations ship post-v1.0.

**Unblocked items (now Additive via opt-in flag):**
- §1.8 trusted-issuer audit — via `POLICY_TRUSTED_ISSUER_AUDIT` (bit 0)
- §5.2 external audit — via `POLICY_EXTERNAL_AUDIT_REQUIRED` (bit 1)
- §5.5 HW wallet certification — via `POLICY_HW_WALLET_CERTIFIED` (bit 2)
- §6.2 Quorum Liveness OPTIONAL — via `POLICY_BFT_THRESHOLD_FINALIZATION` (bit 4); see §6.2 residual gap below

**Items that did NOT get unblocked:**
- §9.1 tier-bond monetization — 7.5.8 was skipped, so even with this framework's `POLICY_TIER_BONDS_ENABLED` reservation (bit 3), there is no per-account tier field to enforce against. Reserved bit kept for renumbering safety if Option A is revisited via v3 protocol opening.

**§6.2 Quorum Liveness OPTIONAL — FULLY UNBLOCKED 2026-06-03.** Both the manifest enablement flag (7.5.10) AND the per-block `quorum_bitset` field (7.5.11) ship in v1.0. §6.2 is now Additive-via-opt-in end-to-end: deployments set the policy flag in manifest at creation; per-block bitset records participation; validator's BFT-threshold check activates when flag is set. Best-specified post-v2 architectural optimization (was 60% ready per earlier audit) becomes a real implementable Additive path.

**Implementation impact.**
- v1.0 chain: ~1-2 days to add `policy_tier_flags` field to manifest schema + validate_manifest() check rejecting unknown bits
- Per-flag enablement: each feature's implementation cost (separate from this framework) when activated

**Action items now closed.** Framework spec lands inside Beaconless-v2-SPEC manifest section + §Q2.1 hard-invariant validation. Per-flag-bit reservations documented here.

---

---

## 11. Out of v1.0 + Not motivating v3 (preserved-for-posterity)

**Purpose.** Items reclassified from "v3 candidate (Breaking)" to "Out of scope" on 2026-06-03. Each was an architectural change too large or marginal-benefit to *motivate* opening v3 protocol on its own. Captured here so future planning sessions don't re-propose them without reading the deferral reasoning — and so reviewers asking "why isn't this in the design?" find the answer.

**Convention difference vs §1–§10.** Entries here are NOT classified as Additive / Breaking / Research because they're not "future work" — they're "considered and explicitly out of scope." Three of the four could *ride along* if v3 ever opens for an unrelated reason (e.g., mandatory PQ migration) but none is a v3 driver.

**Pattern for future entries:** when triaging a v3-candidate Breaking item, ask "does this item *by itself* motivate opening v3?" If no, it belongs here, not in the live v3 queue.

### 11.1 Stealth addresses (Monero-style) for graph privacy

**Original improvement.** Combine amount-PFS with recipient-graph-privacy. Sender derives a fresh stealth address per tx via DH against recipient's `spend_view_pk`; recipient scans chain to find their own.

**Original deferred reason.** Architectural change vastly larger than v2.22's amount-PFS scope. Requires full chain scan per recipient per receive — light-client problem unsolved at scale; Monero hits this wall too. Conflicts with v2.24 audit model (stealth addresses designed to be unlinkable).

**Why out of scope.** Graph-privacy users have Monero/Zcash today; Determ rebuilding its whole tx-routing model just to compete in graph-privacy is overkill. Determ's value proposition is K-of-K mutual-distrust + Kerckhoffs's principle + amount-PFS, not graph-privacy. If graph-privacy becomes a project priority later, the rebuild is essentially "build a different chain" — would happen as a separate project, not as a Determ v3.

**Ride-along potential.** None — graph-privacy requires whole-chain architectural changes that can't be bundled with smaller protocol opens.

**Related.** `DECISION-LOG.md` → v2.22 PRIVACY → PRIV-6 alternative-mechanism rejection summary.

### 11.2 Sharding-of-sharding (horizontal scale beyond ~500 shards)

**Original improvement.** Sharding-of-sharding architecture for deployments needing >500 shards. Lazy validation contains O(N²) cost up to ~200-500 shards; beyond that, additional architectural work needed.

**Original deferred reason.** v3 concern per Beaconless-v2-SPEC.md §1 scope. No current deployment driving the need.

**Why out of scope.** Speculative scaling for a problem nobody has and nobody is forecast to have. 200-500 shards covers every realistic deployment topology including planet-scale. Beyond that, the right answer is probably "deploy a sibling Determ chain and bridge them" — which is v2.23 cross-chain bridge territory, not sharding-of-sharding.

**Ride-along potential.** None — fundamental shard architecture restructuring; can't bundle.

**Related.** `Beaconless-v2-SPEC.md §1` scope.

### 11.3 Data deduplication (`deduplicated_tx_root`)

**Original improvement.** Replace the per-creator `creator_tx_lists[][]` arrays with a single `deduplicated_tx_root` Merkle root over the globally lex-sorted unique transaction set.

**Original deferred reason.** Bandwidth saving is real (proportional to inter-creator overlap) but the per-creator-list redundancy is also the evidence base for FA2 censorship resistance. Removing per-creator lists removes that evidence; FA2's "k_bft-conjunction-of-creators-must-collude-to-censor" argument doesn't carry over without replacement.

**Why out of scope.** Per the entry's own analysis, the bandwidth savings aren't load-bearing at Determ's target throughput. Cost-benefit ratio doesn't favor opening v3 just for this. FA2 reformulation via per-creator Bloom/IBLT (per `§10.1`) was identified as a spec-ready path, but even with the reformulation done the savings don't motivate v3.

**Ride-along potential.** Yes — IF v3 opens for an unrelated reason (e.g., mandatory PQ signature migration requires breaking block-header schema), §11.3 dedup could ride along as a coincident cleanup. The §10.1 per-creator Bloom/IBLT reformulation should be spec-ready when v3 opens; that work converts dedup from "Breaking + research-stuck" to "Breaking + spec-ready, ride-along available."

**Related.** `Improvements.md §10.1` (per-creator Bloom/IBLT reformulation); `docs/proofs/Censorship.md` (FA2 proof).

### 11.4 Tier-bond monetization (Option A)

**Original improvement.** Operators register at a tier (`UNSTAKED`, `ENTERPRISE`, `REGULATED`, `HIGH_RISK`) and post bond proportional to tier. Casinos in `HIGH_RISK` post substantial slashable bond; non-casino enterprises pay zero or token bonds.

**Original deferred reason.** Required §7.5.8 `RegistryEntry.deployment_tier: enum` discriminator pre-v1.0 to remain Additive. §7.5.8 was explicitly skipped 2026-06-03.

**Why out of scope.** The 7.5.8 skip was a deliberate project decision preserving chain-level character of "no per-account fee differentiation." Calling §9.1 a "v3 candidate" after the skip implied a backdoor where the project might revisit — misleading because the rejection was a value decision (project philosophy: primitive-free public-interest infrastructure, not fee-market substrate), not a technical one.

**Ride-along potential.** Technically yes (could ship via v3 protocol opening), but the value rejection still applies regardless of v3 opening. If v3 opens for another reason, §11.4 stays out of scope.

**Live monetization candidates remain:** §9.2 DApp-layer pricing (Additive) and §9.5 Foundation services (off-protocol). Per `DECISION-LOG.md` 2026-06-03.

**Related.** `DECISION-LOG.md` → "Gas-style pricing rejected" + "§7.5 sweep extension: 7.5.8 SKIP + 7.5.10 SHIP".

---

*End of improvements queue. Append new entries as future deliberations produce additional deferred items. When triaging future v3-candidate Breaking items, apply the §11 test: does this motivate v3 by itself?*
