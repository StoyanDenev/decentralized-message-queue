# Implementation sequencing — bundled-release plan

**Status:** planning artifact. Resolves the execution sequence for the 41 design decisions + 4 spec amendments resolved during pre-implementation review week (May 2026). Approach C (bundled releases): each bundle ships as a discrete release; related decisions land together rather than incrementally.

**Companion documents:**
- `PRE-IMPLEMENTATION-REVIEW.md` — review-week checklist (decisions verbally resolved)
- `CRYPTO-C99-SPEC.md`, `DSF-SPEC.md`, `F2-SPEC.md`, `v2.10-DKG-SPEC.md`, `v2.22-PRIVACY-SPEC.md`, `Beaconless-v2-SPEC.md` — sibling spec docs that this plan executes against
- `DECISION-LOG.md` — backward-looking deliberation history for the decisions this plan executes
- `Improvements.md` — forward-looking enhancement queue (post-v1.0 items deferred from this plan; rejected alternatives; research items)
- `MAINNET_READINESS.md` — readiness-criteria tracking artifact gating mainnet declaration
- `PFS_DEPLOYMENT_GUIDANCE.md` — operator-facing PFS regulatory framework

---

## 1. Why bundled releases (Approach C)

Three reasons for bundling over alternatives:

- **Cleaner user-facing story.** Each release answers a single question ("v2.22 = confidential transactions") rather than dripping partial features across many releases.
- **Audit-friendly.** Security audits scope cleanly to a single bundle (e.g., "audit v2.22 release: all PRIV-1..6.2 together") rather than chasing partial implementations across versions.
- **Operator deployment discipline.** Operators upgrade once per bundle, run regression once per bundle. Lower operational overhead per shipped capability.

The cost is longer wall-clock between releases. Mitigated by parallel build within bundles (where dependency permits) and by clear bundle boundaries that prevent scope-creep mid-bundle.

---

## 2. Bundle map

Each bundle is a discrete release. Bundles ship in the order specified; bundles without arrows between them can be built in parallel given team capacity.

```
Foundation (mostly shipped)
    │
    ├──> Bundle 1: v2.10 DKG
    │       │
    │       └──> Bundle 3 ────┐
    │                         │
    ├──> Bundle 2: F2         │
    │                         │
    └──> Bundle 3: v2.22 ─────┤
                              │
        Bundle 4: DSF ────────┤
                              │
        Bundle 5: Beaconless v2 (after v2 + Theme 9 substantially shipped)
```

### Pre-bundle schema discriminators (RESOLVED 2026-05-24 via Improvements.md §7.5)

Seven v1.0 schema discriminators must land **before any review-week bundle** to lock the genesis schema shape and preserve post-v1.0 optionality under no-migrations. Per `Improvements.md §7.5` + §7.6 coherence resolutions:

| Discriminator | Location | v1.0 default | Effort | Notes |
|---|---|---|---|---|
| `Block.signature_form` | Block header | `SIG_KK_ED25519` | ~1-2 days | Unlocks future BLS aggregation (MODERN) + PQ migration of block sigs |
| `ContribMsg.contrib_msg_form` | Phase-1 ContribMsg | `TX_HASH_ARRAY` | ~1-2 days | Unlocks future IBLT/Minisketch contrib |
| `Transaction.sig_form` | Every Transaction | `SIG_ED25519` | ~1-2 days | Unlocks future PQ migration of tx sigs; tx-payload embedded sigs follow tx-level form (homogeneous) |
| `pubkey_form` + variable-length pubkey encoding | Every pubkey-bearing field (RegistryEntry.ed_pub, Transaction.from/to, Account fields, DAppEntry, OTPK, etc.) | `PUBKEY_ED25519` (32B body) | **~3-5 days** | Unlocks future PQ pubkey migration (Dilithium 1952B) + BLS pubkey adoption (96B). **MUST include discriminator in address-derivation preimage** to prevent address collision across pubkey forms. Substantive v1.0 schema lift — touches every consumer of pubkey data. |

Combined effort: **~6-10 days** (substantially larger than the original 5-discriminator estimate due to 7.5.7 variable-length pubkey encoding). Validator behavior: fail-closed on unknown enum values (forward-compat). No additional logic needed in v1.0 for the unused discriminator values — wire-format scaffolding only — but the pubkey-encoding lift is real implementation work touching sig verification, address derivation, serialization, deserialization throughout.

The remaining three discriminators (`Account.view_key_mechanism`, `Account.audit_model`, `manifest.randomness_aggregation_form`) land inside Bundle 3 and Bundle 5 respectively — see those bundles.

### Bundle 0: Foundation (mostly shipped pre-review-week)

| Item | Source | Status |
|---|---|---|
| `DETERM_CRYPTO` CMake option (modern/fips/universal) | C99-12 | ✅ Done (task #12) |
| `crypto_profile_build` C++ header | C99-13 | ✅ Done (task #13) |
| Genesis-vs-build compat assert | C99-14 | ✅ Done (task #14) |
| `src/crypto/{modern,fips,universal}/` subtree | C99-15 | ✅ Done (task #15) |
| Build matrix verification | C99-16 | ✅ Done (task #16) |
| C99-11 tactical/cluster civilian profiles | C99-11 revise | ✅ Done (task #18) |
| Doc sweep (README, PROTOCOL, specs) | C99-11 revise | ✅ Done (task #20) |
| g++ standalone compile verification | C99-11 revise | ✅ Done (task #21) |

**Status:** Foundation complete. All downstream bundles can proceed.

**One outstanding edit from PRIV-3 revise:** CRYPTO-C99-SPEC.md primitive list confirms P-256 ECDH in-scope (applied in task #27). Implementation of P-256 ECDH vendoring tracks under §3.8c of CRYPTO-C99-SPEC.md (~5 days; not yet implemented).

### Bundle 1: v2.10 DKG (FROST-Ed25519 threshold randomness)

| Decision | Effort | Notes |
|---|---|---|
| DKG-1..5 (all v2.10 decisions) | per v2.10-DKG-SPEC.md | curve25519 family; libsodium-vendored |
| **Bundle effort** | ~2-3 weeks | Confirm against spec total |

**Depends on:** Foundation
**Blocks:** Bundle 5 (Beaconless v2 Q6 uses FROST threshold sigs for cross-shard randomness)
**Can parallelize with:** Bundle 2 (F2), Bundle 3 (v2.22) — different curve families and code paths

### Bundle 2: F2

| Decision | Effort | Notes |
|---|---|---|
| F2-1..5 (all F2 decisions) | per F2-SPEC.md | v2.7 functionality |
| **Bundle effort** | ~per F2-SPEC.md | Confirm against spec total |

**Depends on:** Foundation
**Blocks:** (independent — does not gate other bundles)
**Can parallelize with:** Bundle 1, Bundle 3

### Bundle 3: v2.22 Confidential Transactions (largest bundle)

| Decision | Effort | Notes |
|---|---|---|
| PRIV-1: Per-epoch HKDF view-key derivation | 2 weeks | reuses libsecp256k1 |
| PRIV-2: Bulletproofs over secp256k1 | ~10 days | libsecp256k1-zkp vendor + integrate |
| PRIV-3: secp256k1 ECDH amount handshake | 1 week | curve-follows-profile principle |
| PRIV-4: Dual-mode audit disclosure | 2-3 weeks | composes with v2.24 |
| PRIV-5: Rotation tx types (PUBLISH_VIEW_KEY, ROTATE_VIEW_MASTER) | 1 week | ships for operational use; migration plumbing N/A pre-mainnet |
| PRIV-6: Per-tx PFS via OTPK stream | 3-4 weeks | new tx type + apply path + wallet integration |
| PRIV-6.1: Wallet-loss reconciliation | 1.5-2 weeks | no chain changes; wallet-side + spec docs |
| PRIV-6.2: Publish-cadence padding | 3-5 days | wallet feature + per-account immutable field |
| Pedersen commitment integration | 2-3 weeks | apply path + balance-conservation check |
| Audit-mode tooling + v2.24 integration | 2-3 weeks | reference auditor; LOG_AUDIT_ACCESS |
| Tests + docs | 2 weeks | end-to-end confidential transfer; audit-mode integration |
| **Bundle effort** | **~3-3.5 months** | per v2.22-PRIVACY-SPEC.md §5 |

**Depends on:** Foundation (C99-11 MODERN profile + secp256k1 vendoring)
**Blocks:** v2.24 audit hooks (out of review-week scope; downstream)
**Can parallelize with:** Bundle 1, Bundle 2 (different curve families: v2.22 uses secp256k1, v2.10 uses curve25519)
**Critical-path within bundle:** PRIV-2 (Bulletproofs vendoring) is the longest single item; should start first within bundle. PRIV-1, PRIV-3, PRIV-4, PRIV-5 can pipeline. PRIV-6 + 6.1 + 6.2 are wallet-heavy; ship together as the PFS sub-feature.

### Bundle 4: DSF (S-035 Option 2)

| Decision | Effort | Notes |
|---|---|---|
| DSF-1..6 (all DSF decisions) | per DSF-SPEC.md | deterministic-simulation framework |
| **Bundle effort** | ~3-4 weeks | per DSF-SPEC.md |

**Depends on:** Foundation
**Blocks:** Bundle 5 (hard prerequisite per BL-7)
**Can parallelize with:** Bundles 1-3 (DSF is testing infrastructure; doesn't share code paths)
**Sequencing note:** Should land before Bundle 5 starts, but can build in parallel with Bundles 1-3 throughout Phase B/C.

### Bundle 5: Beaconless v2 (largest bundle; Phase D)

| Decision | Effort | Notes |
|---|---|---|
| BL-1: Light-client mesh with lazy validation | 3-4 weeks | per Beaconless-v2-SPEC.md §4.1 |
| BL-2: Deployment manifest + K-of-K co-signing | 3-4 weeks | includes Q2.1 manifest validity (~1 week) |
| BL-3: Committee-rotation log + manifest-tunable snapshot interval | 1-2 weeks | |
| BL-4: Cross-shard receipts with Merkle proofs + u32 nonce | 2-3 weeks | |
| BL-5: Decentralized merge-detection + manifest-tunable merritt_k | 1-2 weeks | |
| BL-6: Cross-shard randomness aggregation + manifest-tunable cutoff | 1-2 weeks | uses FROST from Bundle 1 |
| BL-7: DSF prerequisite | (Bundle 4) | already landed before Bundle 5 starts |
| BL-8: Phase D sequencing | (this doc) | meta-decision |
| Q2.1: Manifest validity (hard + soft tiers) | 1 week | inside BL-2 work |
| AUTONOMOUS_SHARD chain_role + migration | 1-2 weeks | per §4.7 |
| Tests + docs | 2 weeks | DSF-driven Byzantine scenarios |
| **Bundle effort** | **~3-4 months** | per Beaconless-v2-SPEC.md §5 |

**Depends on:** Bundle 4 (DSF), Bundle 1 (v2.10 FROST for Q6 randomness), v2 + Theme 9 substantially shipped (per BL-8)
**Blocks:** v2.23 cross-chain bridge (out of review-week scope; uses Beaconless v2's light-client primitive)
**Cannot parallelize with:** v2 + Theme 9 (per BL-8 — rebase pain; spec-authority conflicts)
**Sequencing note:** Phase D start gated on TWO completion criteria: (a) DSF in place (Bundle 4 done), (b) v2 + Theme 9 substantially shipped (criterion TBD — see §4).

---

## 3. Phase map

| Phase | Bundles | Sequencing constraint |
|---|---|---|
| **Phase A** (foundation) | Bundle 0 (Foundation) | Substantially shipped pre-review-week |
| **Phase B/C** (current) | Bundles 1, 2, 3, 4 + v2 + Theme 9 | Parallel-buildable subject to team capacity; Bundle 4 (DSF) should land by end of Phase C |
| **Phase D** | Bundle 5 (Beaconless v2) | Starts only after Phase C wraps AND v2 + Theme 9 substantially ships AND DSF is in place |

---

## 4. Unknowns to resolve

These cannot be answered from the design specs alone; they require team-knowledge.

### 4.1 Team capacity — RESOLVED

**Team composition (2026-05-24):** 4 to 32 parallel development threads of Opus 4.7 (Claude code tab). **All threads share all qualities.** No discipline boundaries of any kind — every thread is equally capable across crypto, chain, wallet, infrastructure, spec writing, doc production, regulatory framework drafting, and review work. There is no "chain dev" vs "wallet dev" vs "compliance writer" — capacity is fully fungible.

**Implication for sequencing.** Capacity is no longer the binding constraint. Bundles 1, 2, 3, 4 fully parallelize during Phase B/C — wall-clock for Phase B/C completion is bounded by the *longest single bundle* (Bundle 3 v2.22, ~3-3.5 months), not the sum. The three near-term actions in §5 all start concurrently without contention.

**New binding constraint: coordination, not capacity.** AI-parallel development has different failure modes than human teams:

- **Merge conflicts at integration points.** Multiple threads touching shared files (e.g., `Transaction` struct, `Account` schema, `manifest_validity.hpp`) need clear interface contracts before parallel work starts, or rebases pile up.
- **Architectural drift between threads.** Two threads independently choosing different internal naming, error patterns, or validation strategies for adjacent code produces an inconsistent surface that integration cannot easily smooth over.
- **Cross-bundle interface contracts.** When Bundle 5 Q6 consumes Bundle 1 FROST sigs, the integration point must be specified upfront — not negotiated between threads working in isolation.
- **Test-discipline criticality.** Human review catches bugs intuitively; AI threads benefit from strict pre-merge test gating since they don't carry tacit knowledge of "the way we do things here."
- **Verification of generated work.** A thread's claim of "feature X done" needs independent validation — code review by another thread, integration test, etc.

**Recommended coordination practices** (to add to the Bundle workflow, not chain spec):

1. **Pre-bundle interface freeze**: before parallel threads start a bundle, capture the public interfaces (struct fields, function signatures, validator errors) in a short interface-contract doc. Threads work against the contract, not against each other.
2. **Single integration thread per bundle**: one thread owns the final merge + integration pass. Parallel threads produce work; integration thread serializes.
3. **Pre-merge test gating**: every PR must pass full test suite before merge. No `--no-verify` exceptions.
4. **Bundle-boundary verification**: at bundle completion, dedicated thread runs end-to-end integration test exercising every decision in the bundle (e.g., for Bundle 3: full confidential-amount transfer with both AMT_AUDITABLE and AMT_PFS paths, audit-mode disclosure, reconciliation, padding).
5. **Specs as canonical source**: when threads disagree on intent, the spec text wins. If the spec is ambiguous, freeze and resolve before resuming parallel work.

**Wall-clock with this capacity model.** Phase B/C completion ≈ max(Bundle 1, Bundle 2, Bundle 3, Bundle 4) ≈ Bundle 3 at ~3-3.5 months. Phase D = Bundle 5 at ~3-4 months. Total review-week implementation horizon: **~6-7.5 months** from start, gated on coordination quality rather than headcount.

### 4.2 "v2 + v2.26 substantially shipped" — completion criterion for Phase D

**REVISED 2026-05-24:** Theme 9 scope reduced. DSSO (v2.25) reclassified as a DApp (chain-aware DApp on top of v2.18 + v2.19 + v2.26 substrate; ships post-v1.0 as Theme 7 application). Theme 9 chain-level work reduces to v2.26 (on-chain key rotation) only. Phase D gate updated accordingly.

**Approach: named-feature checklist (Option C).** Phase D opens when an explicit list of must-have features from v2 + v2.26 has landed (merged + tests passing). No separate stability gate — code-complete on the blocking subset is the trigger. Non-blocking v2 work may continue in parallel with Phase D.

The checklist itself has two halves to be populated by team:

**v2 blocking features (must land before Phase D):**
- _to be filled by team_

**v2.26 (on-chain key rotation) blocking features (must land before Phase D):**
- _to be filled by team after v2.26 review-track deliberation completes_

**Explicitly non-blocking (may run in parallel with Phase D):**
- v2.25 DSSO substrate — reclassified as DApp (ships post-v1.0 as Theme 7 application, not chain-level work)
- _other items to be filled by team — list items that do NOT gate Phase D so it's clear what's deferrable_

**Decision authority for Phase D opening:** _to be filled by team_ (recommend: single technical decision-maker — eng lead or architect — to avoid committee deadlock).

**Why no stability gate.** Per Option C as picked: code-complete on the blocking subset is the trigger. Stability emerges from continued operation post-Phase-D-start; if a blocking feature regresses after Phase D opens, Bundle 5 work doesn't unwind — fixes land in parallel. The rejected stability-gate alternative is preserved in `Improvements.md §5.1` for future revisit.

### 4.4 QA strategy — Closed-beta partner program (Option A)

**Choice (2026-05-24).** Closed-beta partner program. Selected operators run private testnet pre-mainnet under NDA/partnership agreement. Provides real-world exposure (operator-UX bugs, integration issues, performance-at-scale, real adversary surface) without public release. Composes with Option A release cadence — beta partners are not "public releases" because deployment is under agreement.

**Why this matters more than internal DSF alone.** DSF excels at deterministic Byzantine scenarios but cannot surface: operator wallet UX bugs, real-network performance characteristics, cross-operator integration patterns, real adversary creativity, economic-incentive edge cases at scale. Closed-beta surfaces the categories that internal testing structurally misses.

**Why this fits the "no migrations at all" constraint.** Closed-beta runs the v1.0 code surface; bugs found in beta are fixed pre-mainnet; no post-mainnet migration ever needed. Beta is the bug-discovery window; mainnet is the immutable launch.

**Resolved design parameters (2026-05-24, revised same-day):**
- **Beta-to-mainnet handoff: clean break.** Beta runs as a separate test environment; state is discarded at mainnet. Mainnet starts from a fresh genesis. Partners re-create accounts/balances operationally at mainnet launch (operational migration only; no chain-level state translation — consistent with [[dlt-no-migrations-constraint]]).
- **Beta duration: open-ended.** No fixed end. Mainnet declared when decision authority is satisfied.
- **Pre-beta audit: none.** Internal testing only (DSF + review). No external multi-firm or single-firm audit before beta start.

**Model: "test then commit"** — beta is a genuine test environment; bugs found during beta can be freely fixed because beta state is discarded at mainnet. Mainnet launches with the matured code base after open-ended beta refines it.

**Still need team input:**
- Partner pool: how many partners, what use cases, recruitment criteria
- Bug-finding incentives: financial rewards, early-access, service-fee discounts
- Confidentiality structure: NDA scope, public-disclosure permissions (especially for security findings)
- Beta environment specifics: shared single-chain test network vs. per-partner sandboxes

**Mainnet-declaration authority (RESOLVED 2026-05-24):** the user (project lead) is the sole decision-maker for mainnet declaration. AI threads provide analysis and criteria-status reports as input; declaration itself is unilateral. No advisory veto, no committee, no partner-vote gate. Rationale: AI threads cannot meaningfully bear permanence-of-launch responsibility under the no-migrations constraint; the human-in-the-loop is the only entity with standing to commit.

**Mainnet-declaration criteria (RESOLVED 2026-05-24):** three internal-quality categories feed into the decision. Partner-activity threshold deliberately NOT included (closed beta is bug-finder, not legitimacy validator):
1. **DSF Byzantine coverage** — all Bundle 5 Byzantine scenarios pass deterministic-simulation cleanly
2. **Bug-finding trajectory** — new Sev-1 bug discovery rate at 0 for sustained window; zero open Sev-1 bugs for 60+ days
3. **Subsystem zero-bug windows** — load-bearing subsystems (consensus, crypto, wallet, manifest, confidential-tx apply path) show zero known bugs for defined window

Specific numeric thresholds populated pre-beta. Tracking artifact: `MAINNET_READINESS.md` (created 2026-05-24).

**Implications worth noting explicitly.**

| Property | Consequence |
|---|---|
| Clean break at mainnet | Partners must understand that beta state is operational/test, not permanent. Wallet addresses, account balances, transaction history all reset at mainnet. Partner agreements should make this explicit. |
| Open-ended duration | No external calendar anchor for mainnet date. Confidence threshold for declaring mainnet is internal-only. |
| No external audit | All QA confidence comes from internal team output (DSF + thread review + closed-beta partner findings). No independent validation event. This is a deliberate trade-off; documented as accepted. |
| Bug-fix freedom during beta | Beta state is discardable → bugs caught in beta can be fixed by any means including breaking changes. The "no migrations" constraint only kicks in at mainnet declaration. |

**Calendar implications.**
- Pre-beta development: ~6-7.5 months (bundle implementation; unchanged)
- Beta period: open-ended (no audit window inserted; partner ramp begins as soon as Bundle 5 feature-complete)
- Mainnet launch: declared when internal team + beta partners confident; no calendar prediction
- **Net horizon to beta start: ~6-7.5 months. Net horizon to mainnet: unbounded (driven by confidence rather than schedule).**

**Residual risk acknowledgment.** No-external-audit + closed-beta only (no public bug-bounty) concentrates QA confidence in the internal team's judgment + partner-observed behavior. If a bug escapes beta into mainnet, the no-migrations constraint binds — only security-critical hard fork available as remediation. This is accepted as a risk profile, not a gap to mitigate. Mitigation options not adopted are preserved in `Improvements.md §5.2` (external multi-firm audit), `§5.3` (public bug bounty pre-mainnet), `§5.4` (Option C public pre-mainnet releases) for future revisit if the risk posture changes.

---

### 4.3 Bundle release cadence — RESOLVED

**Hard project constraint (2026-05-24):** *No migrations at all*, interpreted as **no breaking changes post-v1.0** (practical reading). Specifically:

- ✅ **In-protocol mechanisms OK**: `ROTATE_VIEW_MASTER`, `ROTATE_AUDIT_KEY`, `MANIFEST_UPDATE`, `PUBLISH_OTPK_BATCH`, etc. — these are runtime operations governed by consensus rules shipped in v1.0. Not migrations.
- ✅ **Additive-only post-v1.0 changes OK**: new optional fields validators can ignore; new tx types that legacy validators can fail-closed on.
- ✅ **Security-critical hard forks reserved as last resort**: not zero, but rare and only for critical security; not routine evolution.
- ❌ **No schema migrations, wire-format breaks, or consensus-rule additions post-v1.0**: anything requiring coordinated operator upgrades or state translation is forbidden.

**Release cadence: Option A — big-bang v1.0.**

- No public pre-mainnet releases (no v0.x testnet/devnet artifacts).
- Internal development only until everything is ready.
- Single launch event: v1.0 mainnet ships all 5 bundles together.
- Total horizon: ~6-7.5 months from start (gated on Bundle 5 Beaconless v2, the longest sequential bundle in Phase D).

**Why Option A over C.** Trade-off accepted: forgo public delivery cadence + testnet adoption + incremental audit in exchange for one clean launch event. Reduces release-management overhead during the development window; defers community visibility to a single high-impact moment.

**Implications for prior decisions.** None invalidated. The "pre-mainnet, no migration" disposition holds for every review-week decision; the "no migrations at all" constraint is the *permanent* extension of that disposition forward through v1.0 launch.

**Implications for execution.** All 5 bundles must complete before mainnet. Bundle 4 (DSF) is still a Phase D prerequisite (BL-7); Bundle 5 (Beaconless v2) is still Phase D after v2 + Theme 9 substantially ships (BL-8). The new constraint doesn't reorder bundles — it just confirms that they all land in v1.0 genesis together.

**Future evolution discipline (for implementation threads).** Any thread proposing a feature that would change wire format, state schema, or consensus rules post-v1.0 must either: (a) push the feature into v1.0 scope (pre-mainnet), or (b) restructure as additive-only (new optional field with legacy-ignore semantics), or (c) escalate as a security-critical hard fork candidate. The default answer to "can we change X post-mainnet?" is **no**.

### 4.4 Pre-mainnet status sanity check — RESOLVED

**Confirmed pre-mainnet (2026-05-24).** The review-week assumption holds. All bundles ship into a chain that has not yet launched mainnet; PRIV-5 migration plumbing remains N/A; BL-8 Phase D sequencing does not need a migration window; all `confidential_policy` and `pfs_padding_cadence` defaults apply from account creation without legacy-account considerations.

This confirmation validates all 41 review-week decisions + 4 amendments as currently specified. No re-design required.

---

## 5. Recommended near-term actions

Independent of the unknowns in §4, three things can start immediately:

1. **CRYPTO-C99 P-256 ECDH vendoring** (§3.8c, ~5 days). Foundation completion; no downstream gate. Can start now.
2. **Bundle 4 (DSF)** scaffolding. DSF is a prerequisite for Bundle 5 and parallel-buildable with everything else. Earliest start = highest leverage.
3. **Bundle 3 (v2.22) critical-path item PRIV-2 (Bulletproofs vendoring)**. The longest sub-component of the largest bundle. Earliest start de-risks Phase C completion.

These three can run concurrently if capacity permits, and none of them block any other in-flight work.

---

## 6. Risks of this sequencing approach

**Risk: Bundle 3 (v2.22) blast radius at release.** v2.22 ships 8 PRIV decisions + audit integration in one release. A bug discovered post-release affects all of confidential-transaction infrastructure simultaneously.

*Mitigation.* Per v2.22-PRIVACY-SPEC.md §6 rollback plan: confidential-amount tx type can be disabled via flag-day reversal; existing confidential-amount commitments remain in chain history but become unrecoverable. Operators can opt in per account.

**Risk: Bundle 5 (Beaconless v2) Phase D gate slips.** If v2 + Theme 9 takes longer than estimated, Bundle 5 (~3-4 months) shifts right. v2.23 cross-chain bridge slips with it.

*Mitigation.* Make "substantially shipped" criterion concrete (§4.2 unknown). Track Theme 9 burn-down separately. Begin Bundle 4 (DSF) early so it's not on the Phase D critical path.

**Risk: Bundle 3 internal sequencing.** PRIV-6 + 6.1 + 6.2 are wallet-heavy; if wallet capacity is constrained, the bundle ships without PFS feature even though PRIV-1..5 are ready.

*Mitigation.* If wallet capacity is the constraint, ship Bundle 3 in two sub-bundles: 3a (PRIV-1..5; core confidential txs) and 3b (PRIV-6 + 6.1 + 6.2; PFS feature). Deviates slightly from Approach C but preserves bundle-discipline at sub-bundle granularity.

---

## 7. What this doc is NOT

- **Not a Gantt chart.** No dates. Effort estimates are from spec docs; calendar dates depend on team capacity and start dates that haven't been set.
- **Not a feature spec.** Features are defined in the per-bundle spec docs; this doc only orders their delivery.
- **Not immutable.** As bundles ship and unknowns resolve, this doc should be updated. Versioning via git history.

---

*End of sequencing plan.*
