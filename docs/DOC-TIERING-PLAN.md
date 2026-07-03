# Determ 1.0 Documentation Tiering Plan — PROPOSAL (review before executing)

> **NOTICE.** This is a *proposal for review* — **no files have been moved, renamed, or
> deleted**. It is the "concrete inventory + ROADMAP outline" requested before any
> consolidation. Documentation/process authority is **Stoyan Denev**'s; this plan is
> recorded by the AI assistant and is **not co-authored**.

## Goal

Collapse the doc corpus to a single **1.0-authoritative tier** (what actually ships +
the proofs that back it) and isolate the **speculative future tier** into one indexed
place. This shrinks two costs at once: the *open-question surface* (most open questions
live in unbuilt specs) and the *coherence tax* (this session, one decision — adopt MPDH
— rippled across ~13 docs precisely because speculative specs sit in the coherence path).

## Method + result

A 14-agent classification read the header + `Status:` line of **all 202 doc files**
(151 `.md` + 51 `.tla`) and assigned each a tier. Result:

| Tier | Count | Meaning | Disposition |
|---|---:|---|---|
| **T1** 1.0-authoritative | **163** | describes shipped, tested code (protocol/security/CLI/whitepaper + every proof/TLA backing `src/`) | **stays** — the coherence-maintained set |
| **T2** near-term committed | **11** | decided + imminent on the 1.0.x path (mostly v2.7 F2) | keep in place + uniform "near-term, not-yet-shipped" banner |
| **T3** speculative future | **13** | unshipped v2+ design | index under one `ROADMAP.md`; stop threading decisions into them |
| **T4** process / rationale | **15** | deliberation + meta (decision log, guidance, indexes) | retain as archive; mark "not coherence-maintained" |

Only **39 of 202** files leave the coherence-critical tier. That 39-file set is the
entire source of the recurring "is this still consistent?" churn.

## Tier 2 — near-term committed (1.0.x trajectory) — keep, banner as in-flight

- `docs/proofs/F2-SPEC.md` — v2.7 F2 view reconciliation (the last readiness gate, ~3–4d)
- `docs/proofs/F2ViewReconciliationAnalysis.md` — F2 primitives + invariants
- `docs/proofs/S030-D2-Analysis.md` — block-digest field-coverage (F2 closes it)
- `docs/proofs/tla/F2ViewReconciliation.tla`, `tla/MakeContribCommitment.tla`,
  `tla/MakeBlockSigPrimitive.tla`, `tla/MergeEventAcceptGate.tla`, `tla/FrostVerify.tla`
- `docs/proofs/CRYPTO-C99-SPEC.md` — C99 stack (Phase 0 shipped; later phases near-term)
- `docs/proofs/RpcAuthReplayWindowSoundness.md` — HMAC anti-replay window (v2.16+ extension)
- `docs/proofs/SupplyProofSoundness.md` — **reconcile** (classified T2 "spec deferred", but
  its siblings `SupplyInvariantComposition` / `CrossShardSupplyConservation` are T1 — confirm
  whether it backs shipped supply code → likely T1)

## Tier 3 — speculative future → move to `ROADMAP.md` index

- `docs/V2-DESIGN.md` — full v2 design space (10 of 25 shipped; rest future)
- `docs/V2-DAPP-DESIGN.md` — DApp themes (v2.18/v2.19 substrate shipped; rest future)
- `docs/proofs/Beaconless-v2-SPEC.md` — beaconless cross-shard architecture
- `docs/proofs/v2.10-DKG-SPEC.md` — threshold-randomness DKG (block-beacon **de-scoped**; FROST module **FROZEN 2026-07-03**, NOTICE §6 amendment — design record only)
- `docs/proofs/V210-PhaseD-RandomnessWiring.md` — FROST block-beacon wiring (**de-scoped**, historical)
- `docs/proofs/V210ImplementationRoadmap.md` — v2.10 roadmap (block-beacon **de-scoped**)
- `docs/proofs/v2.22-PRIVACY-SPEC.md` — confidential transactions
- `docs/proofs/v2.26-ROTATION-SPEC.md` — on-chain key rotation
- `docs/proofs/PFS_DEPLOYMENT_GUIDANCE.md` — PFS regulatory framework (for v2.22)
- `docs/proofs/DSF-SPEC.md` — deterministic-simulation framework
- `docs/proofs/V1.1-PLAN.md` — v1.1 mainnet launch plan
- `docs/proofs/AnonAddressDerivationMigration.md` — v1.1 address-formula decision (OPEN)
- `docs/C99-MINIX-PORT.md` — C99 reimplementation planning (post-v3)

## Tier 4 — process / rationale archive → mark "not coherence-maintained", retain

- `docs/proofs/DECISION-LOG.md`, `docs/proofs/Improvements.md` (+ `docs/Improvements.md` dup),
  `docs/proofs/IMPLEMENTATION-SEQUENCING.md`, `docs/proofs/F2-V210-IMPLEMENTATION-PLAN.md`,
  `docs/proofs/MAINNET_READINESS.md`, `docs/proofs/PRE-IMPLEMENTATION-REVIEW.md`
- Guidance: `docs/proofs/DAPP_SDK_GUIDANCE.md`, `docs/proofs/ECONOMICS_CONFIG_GUIDANCE.md`
- Indexes / maps: `docs/README.md`, `docs/proofs/README.md`, `docs/UNIT-TESTS.md`,
  `docs/proofs/UnitTestCoverageMap.md`, `docs/proofs/LightClientCompositionMap.md`,
  `docs/proofs/tla/CHECK-RESULTS.md`
- (The DECISION-LOG + Improvements are the deliberation trail — **retain**, they prevent re-litigation.)

## Recommended execution — low-risk, no link breakage

The 163 T1 proofs are densely cross-linked; **physically relocating** T3/T4 would break
links *from* T1 docs *to* them — a large coherence cost that defeats the purpose. So:

- **Phase 1 (the lever):** create `docs/ROADMAP.md` — the single entry point for the
  future tier. One link target instead of speculative specs scattered through the index.
- **Phase 2:** add a one-line tier banner to each of the **39** non-T1 docs (most T3
  already carry de-scoped / spec-only banners — this just makes them uniform). T1 needs
  no banner (it is the default authoritative tier).
- **Phase 3 (optional, later):** physically relocate T3 → `docs/future/` with a link
  rewrite — deferred; only if you want directory-level separation, and worth its own pass.

This gets ~90% of the benefit (clear shipped-vs-speculative signal + one future index +
decisions stop leaking into T3) at near-zero merge/link risk.

## Proposed `ROADMAP.md` outline (for review — not yet written)

```
# Determ — Roadmap & Future Directions  (NON-AUTHORITATIVE)
> Single entry point for everything NOT in the 1.0-authoritative set. Specs here are
> design-stage: they do NOT describe shipped code and are NOT coherence-maintained
> against src/. The shipped system is README / PROTOCOL / SECURITY / WHITEPAPER + proofs/.

## Near-term (1.0.x trajectory)        [T2]
- v2.7 F2 view reconciliation — last readiness gate (~3–4d) → F2-SPEC, F2ViewReconciliationAnalysis, S030-D2-Analysis, tla/F2*
- C99 crypto stack — remaining phases → CRYPTO-C99-SPEC
- RPC anti-replay window → RpcAuthReplayWindowSoundness

## Post-1.0 design space               [T3]
- Scaling    → Beaconless-v2-SPEC (cross-shard randomness now MPDH, §Q6)
- Privacy    → v2.22-PRIVACY-SPEC, PFS_DEPLOYMENT_GUIDANCE
- Identity   → Theme 9 DSSO / v2.25, v2.26-ROTATION-SPEC
- Threshold  → v2.10-DKG-SPEC  (block-beacon DE-SCOPED; FROST FROZEN 2026-07-03 — design record only)
- Post-quantum → v2.8  (in V2-DESIGN)
- Tooling    → DSF-SPEC (deterministic simulation)
- Portability→ C99-MINIX-PORT
- Launch     → V1.1-PLAN, AnonAddressDerivationMigration
- Full space → V2-DESIGN, V2-DAPP-DESIGN

## Decommissioned / de-scoped
- v2.10 FROST-as-block-beacon → MPDH commit-reveal retained (DECISION-LOG 2026-06-07)

## Rationale archive                    [T4]
- DECISION-LOG, Improvements, IMPLEMENTATION-SEQUENCING, MAINNET_READINESS,
  PRE-IMPLEMENTATION-REVIEW, *_GUIDANCE
```

## Open decisions for you

1. **Label-in-place (Phases 1–2) or also physically relocate (Phase 3)?** Recommend
   label-in-place now; defer relocation.
2. **`ROADMAP.md` location/name** — top-level `docs/ROADMAP.md` proposed.
3. **T2 borderline reconciliation** — confirm `SupplyProofSoundness.md` (T1 vs T2) and
   whether the F2 TLA specs are "near-term" (T2) or already "shipped-primitive" (T1).
4. **Do-not-touch overlap** — several T4 items (DECISION-LOG, IMPLEMENTATION-SEQUENCING,
   MAINNET_READINESS, F2-V210-IMPLEMENTATION-PLAN, the GUIDANCE docs) are on the
   concurrent-session do-not-touch list; banner edits to those should be coordinated.

## Classifier notes (to reconcile during execution)

- A few items came back with absolute paths (`C:\sauromatae\...`) — same files as their
  relative entries (SupplyProofSoundness, V1.1-PLAN, V210-PhaseD, V210ImplementationRoadmap,
  UnitTestCoverageMap); de-duplicate on execution.
- `docs/Improvements.md` and `docs/proofs/Improvements.md` — **RESOLVED (not a duplicate)**:
  the former is a C99-architecture candidates doc (104 lines), the latter the enhancement
  queue (1028 lines). Both legitimate; no dedupe needed.
- `docs/proofs/SupplyProofSoundness.md` — **RESOLVED → T3 (future)**: the `supply-trustless`
  command was reverted (R41); the doc is the spec for a future v2.x height-pinned counter read.
  Reclassified T2→T3; moved to ROADMAP post-1.0.
