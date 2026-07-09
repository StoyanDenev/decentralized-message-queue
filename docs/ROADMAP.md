# Determ — Roadmap & Future Directions (NON-AUTHORITATIVE)

> **This file is the single entry point for everything NOT in the Determ 1.0-authoritative
> doc set.** Specs linked here are design-stage: they do **not** describe shipped code and
> are **not** coherence-maintained against `src/`. The shipped system is documented in the
> 1.0-authoritative set — `README.md`, `PROTOCOL.md`, `SECURITY.md`, `WHITEPAPER-v1.x.md`,
> `CLI-REFERENCE.md`, `QUICKSTART.md`, and the `proofs/` that back shipped code.
>
> Tiering: the label-in-place plan (`DOC-TIERING-PLAN.md`, a proposal doc) was EXECUTED —
> this ROADMAP index + the per-file tier banners are the on-disk truth, guarded by
> `tools/test_doc_tier_check.sh`; physical relocation (its Phase 3) was not adopted. The
> proposal doc was deleted 2026-07-09 (doc-consolidation inc.2 — git history is the archive).
> Design deliberation trail: `proofs/DECISION-LOG.md` and `proofs/Improvements.md`.

---

## Near-term (1.0.x trajectory) — per-row status

| Item | Status | Docs |
|---|---|---|
| **v2.7 F2 view reconciliation** | **SHIPPED** (S-016 + S-030-D2 consensus closure; commits 850d2c3..48c4b45) | `proofs/F2-SPEC.md`, `proofs/F2ViewReconciliationAnalysis.md`, `proofs/S030-D2-Analysis.md`, `proofs/tla/F2ViewReconciliation.tla`, `proofs/tla/MakeContribCommitment.tla`, `proofs/tla/MakeBlockSigPrimitive.tla`, `proofs/tla/MergeEventAcceptGate.tla` |
| **C99 crypto stack** | **SHIPPED** through every non-gated section (§3.1-§3.6, §3.8, §3.8b/c, §3.9b, §3.10-§3.14 seeds; FROST module FROZEN 2026-07-03, then REMOVED from the tree 2026-07-09 — pre-launch register B2); §3.7/§3.9a secp256k1 **DE-SCOPED 2026-07-03** (DECISION-LOG); **§3.15 daemon+light migration SHIPPED 2026-07-03** (consensus path OpenSSL-free; determ-light links zero OpenSSL; goldens byte-invariant on MSVC+GCC) — remaining OpenSSL surface is wallet-envelope + §Q9-test-oracle only (the 1c follow-up) | `proofs/CRYPTO-C99-SPEC.md` (`tla/FrostVerify.tla` deleted 2026-07-09, doc-consolidation inc.1) |
| **RPC anti-replay window** | HMAC-auth extension (v2.16+) | `proofs/RpcAuthReplayWindowSoundness.md` |

---

## Post-1.0 design space — speculative, not in the 1.0 freeze

| Theme | Docs |
|---|---|
| **Scaling** — beaconless cross-shard architecture | `proofs/Beaconless-v2-SPEC.md` (cross-shard randomness now **MPDH commit-reveal**, §Q6, 2026-06-07) |
| **Privacy** — confidential transactions | `proofs/v2.22-PRIVACY-SPEC.md`, `proofs/PFS_DEPLOYMENT_GUIDANCE.md` — implementation **DE-SCOPED 2026-07-03** (design record only; DECISION-LOG) |
| **Identity** — distributed IdP / DSSO + key rotation | Theme 9 / v2.25 (in `V2-DESIGN.md`), `proofs/v2.26-ROTATION-SPEC.md` |
| **Threshold crypto** — DKG ceremony | **block-beacon DE-SCOPED**; FROST module **FROZEN 2026-07-03**, then **REMOVED from the tree 2026-07-09** (pre-launch register B2; FROST_DEVIATION_NOTICE §8). The v2.10 doc set (`v2.10-DKG-SPEC.md` et al.) was deleted 2026-07-09, doc-consolidation inc.1 — `proofs/FROST_DEVIATION_NOTICE.md` §9 + git history are the design record |
| **Post-quantum** — Dilithium/Falcon migration | v2.8 (in `V2-DESIGN.md`) |
| **Tooling** — deterministic-simulation framework | `proofs/DSF-SPEC.md` |
| **Portability** — C99 / MINIX reimplementation | `C99-MINIX-PORT.md` |
| **Launch** — v1.1 mainnet (address-derivation decision **DECIDED 2026-07-03**: formula frozen as-is — DECISION-LOG) | `proofs/V1.1-PLAN.md`, `proofs/AnonAddressDerivationMigration.md` |
| **Trustless reads** — supply-counter trustless read (deferred) | `proofs/SupplyProofSoundness.md` — command reverted R41; needs daemon-side height-pinned counter read (or raw-value `state_proof`); soundness SU-1..SU-4 stands as the spec |
| **Full design space** | `V2-DESIGN.md` (v2 themes; 10 of 25 shipped), `V2-DAPP-DESIGN.md` (DApp themes; v2.18/v2.19 substrate shipped) |

---

## Decommissioned / de-scoped

| Item | Outcome |
|---|---|
| **v2.10 FROST-as-block-beacon** | **De-scoped** — the v1 **MPDH commit-reveal** block beacon is retained (not a bias upgrade over FA3; lacks BLS-style uniqueness). The FROST C99 primitives were retained for a time as a frozen library, then removed from the tree 2026-07-09 (pre-launch register B2). See `proofs/FROST_DEVIATION_NOTICE.md` §9 (rationale absorbed there; the `V210-PhaseD-RandomnessWiring.md` / `V210ImplementationRoadmap.md` originals were deleted 2026-07-09, doc-consolidation inc.1) and `proofs/DECISION-LOG.md` 2026-06-07. |

---

## Rationale archive (process / meta — retained, not coherence-maintained)

`proofs/DECISION-LOG.md` · `proofs/Improvements.md` · `proofs/IMPLEMENTATION-SEQUENCING.md` ·
`proofs/DAPP_SDK_GUIDANCE.md` ·
`proofs/ECONOMICS_CONFIG_GUIDANCE.md` · `proofs/UnitTestCoverageMap.md` ·
`proofs/LightClientCompositionMap.md` · `proofs/tla/CHECK-RESULTS.md` · `UNIT-TESTS.md`

*(Deleted 2026-07-09, doc-consolidation inc.2 — git history is the archive: `MAINNET_READINESS.md`
— a never-populated tracking scaffold; the declaration authority + three readiness-criteria
categories remain recorded in `proofs/IMPLEMENTATION-SEQUENCING.md` §4.4 + `proofs/DECISION-LOG.md`
2026-05-24/2026-06-06, and the open-ended-beta model it tracked was superseded by the owner's
single-soak-at-feature-complete decision, pre-launch register D4, 2026-07-09.
`PRE-IMPLEMENTATION-REVIEW.md` — the review-week checklist; all 40+ decisions it queued are
resolved and recorded in `proofs/DECISION-LOG.md` 2026-05-24 review-week entries + the per-spec
docs, and its crypto direction was superseded 2026-07-07. `DOC-TIERING-PLAN.md` — executed, see
banner note above.)*

---

*Authority: Stoyan Denev. This index is maintained by hand; tier assignments are the
per-file tier banners (the executed `DOC-TIERING-PLAN.md` proposal — deleted 2026-07-09,
git history). Not co-authored by the AI assistant.*
