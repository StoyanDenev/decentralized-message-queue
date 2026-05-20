# Determ — Formal proofs index

This directory contains the per-property analytic proofs for Determ's consensus, sharding, and slashing mechanisms. Each proof is self-contained: a theorem statement, the cryptographic and behavioral assumptions it depends on, the proof itself, and an implementation cross-reference so a reviewer can match the math to the code.

The proofs target two audiences:

1. **Protocol reviewers** — to confirm the properties Determ claims are actually proved, not assumed.
2. **Implementers** — to confirm each invariant is enforced at the exact source location the proof cites.

The proofs are written in standard mathematical prose, not in a machine-checkable spec language. A future track (FB) will add TLA+ models for the consensus and sharding state machines; the FA-track documents here are the human-readable counterpart.

---

## Reading order

Start with **F0 Preliminaries**. Everything else cites its notation, assumptions, and validity predicates.

| # | File | Property | Status |
|---|---|---|---|
| F0 | [Preliminaries.md](Preliminaries.md) | Notation, assumptions, validity predicates | ✓ |
| FA1 | [Safety.md](Safety.md) | K-of-K mutual-distrust safety: ≤1 finalized digest per height | ✓ |
| FA2 | [Censorship.md](Censorship.md) | Censorship resistance: union-tx-root inclusion of any honest mempool tx | ✓ |
| FA3 | [SelectiveAbort.md](SelectiveAbort.md) | Selective-abort resistance: commit-reveal hides delay_output until phase-2 | ✓ |
| FA4 | [Liveness.md](Liveness.md) | Liveness: finalized block within geometric-bounded rounds | ✓ |
| FA5 | [BFTSafety.md](BFTSafety.md) | BFT-mode safety under `f_h < |K_h|/3` within the BFT committee (`|K_h| = ⌈2K/3⌉`); slashing recovery otherwise | ✓ |
| FA6 | [EquivocationSlashing.md](EquivocationSlashing.md) | Slashing soundness: honest never slashed for equivocation | ✓ |
| FA7 | [CrossShardReceipts.md](CrossShardReceipts.md) | Cross-shard atomicity: no double-credit, A1 invariant composes | ✓ |
| FA8 | [RegionalSharding.md](RegionalSharding.md) | Regional pinning preserves FA1/FA4/FA5/FA6/FA7 | ✓ |
| FA9 | [UnderQuorumMerge.md](UnderQuorumMerge.md) | R4 under-quorum merge preserves FA1/FA7 across BEGIN/END | ✓ |
| FA10 | [Governance.md](Governance.md) | A5 PARAM_CHANGE soundness: no unauthorized mutation, off-whitelist immunity | ✓ |
| FA11 | [EconomicSoundness.md](EconomicSoundness.md) | A1 unitary supply invariant + E1/E3/E4 preservation | ✓ |
| FA12 | [WalletRecovery.md](WalletRecovery.md) | A2 wallet recovery: Shamir ITS + AEAD + OPAQUE composition | ✓ |
| FA-Apply | [AccountStateInvariants.md](AccountStateInvariants.md) | AccountState invariants (I-1..I-6): non-negative balance, nonce monotonicity, balance/stake independence, account auto-creation paths, balance arithmetic channels, A1 contribution | ✓ |
| FA-Apply-2 | [SnapshotEquivalence.md](SnapshotEquivalence.md) | Snapshot ↔ replay equivalence (T-S1..T-S6): serialize-restore identity, apply-after-restore equivalence, cross-namespace coverage of the S-033 state_root, idempotent restore, version-gate soundness, determinism — depends critically on S-033 state_root binding + S-038 producer-side state_root population | ✓ |
| FA-Apply-3 | [NonceMonotonicity.md](NonceMonotonicity.md) | Nonce-gating contract (T-N1..T-N6): stale-nonce rejection, future-nonce rejection, per-account independence, replay defense via monotonic advance, monotonic accumulation across blocks, and genesis `next_nonce = 0` bootstrap — the chain.cpp apply-layer replay-defense invariant; cross-references `tools/test_tx_replay_protection` and `tools/test_chain_apply_block` regressions | ✓ |
| FA-Apply-4 | [StakeLifecycle.md](StakeLifecycle.md) | STAKE/DEREGISTER/UNSTAKE state-machine contract (T-K1..T-K7): STAKE locks balance into the stake bucket, insufficient-balance STAKE silently skips (validator + apply-layer cascade), DEREGISTER schedules deferred unlock at `current_height + UNSTAKE_DELAY`, pre-unlock UNSTAKE refunds fee + bumps nonce only, post-unlock UNSTAKE moves locked → balance, pre-DEREGISTER UNSTAKE silently skips with fee refund, and per-account independence across the lifecycle — the apply-layer staking-correctness invariant tracked against `chain.cpp` STAKE/DEREGISTER/UNSTAKE branches. Slashing-intersection clarification documents the FA6 boundary (evidence-driven slash predates UNSTAKE; locked decremented before the unlock-height refund path can fire). | ✓ |
| FA-Apply-5 | [DAppRegistryLifecycle.md](DAppRegistryLifecycle.md) | DApp registry state machine contract (T-D1..T-D8) for the v2.18 DAPP_REGISTER substrate: first-time REGISTER initializes registry entry (T-D1), update preserves owner + `registered_at` (T-D2), non-owner update silently rejected (T-D3), DAPP_DEREGISTER schedules deferred deactivation at `current_height + DAPP_GRACE_BLOCKS` (T-D4), non-owner DAPP_DEREGISTER silently rejected (T-D5), post-deactivation queries skip the entry (T-D6), per-domain independence across the lifecycle (T-D7), and A1 unitary-supply invariance across all registry transitions (T-D8). Cross-references `tools/test_dapp_register` and `tools/test_dapp_state_transition` regressions. | ✓ |
| FA-Apply-6 | [FeeAccounting.md](FeeAccounting.md) | Fee charging + distribution contract (T-F1..T-F7): per-tx debit (T-F1), skip-vs-charge contract per tx type (T-F2), block-level accumulation (T-F3), creator distribution + dust placement (T-F4), empty-creators safety gate preserving A1 (T-F5), A1 invariance — fees are intra-supply (T-F6), and determinism across replays (T-F7). The apply-layer fee-flow correctness invariant tracked against `chain.cpp` per-tx fee debit + block-finalization distribution branches. Cross-references `tools/test_chain_apply_block`, `tools/test_fee_distribution_edge`, `tools/test_empty_block_apply`, and `tools/test_supply_invariant` regressions. | ✓ |
| FA-Apply-7 | [SubsidyDistribution.md](SubsidyDistribution.md) | E1/E3/E4 block-subsidy contract (T-S1..T-S8): per-block mint amount per subsidy mode (T-S1), empty-creators gate preserves pool + zero-mint A1 invariance (T-S2), FLAT mode equal-share + dust placement (T-S3), LOTTERY mode single-winner selection (T-S4), FINITE_POOL mode pool-draining + cap-at-pool semantics (T-S5), NEF first-time-only domain-bound drain (T-S6), A1 invariance — subsidy is bounded + deterministic inflation (T-S7), and determinism across replays (T-S8). Companion to FA-Apply-6 (creator-distribution algorithm shared between fee + subsidy streams; the `chain.cpp:1286-1305` distribution loop fans both pools through the same dust-to-creators[0] rule). Cross-references `tools/test_subsidy_distribution`, `tools/test_supply_lifecycle`, `tools/test_nef_pool_drain`, and `tools/operator_subsidy_audit.sh`. | ✓ |

FB-track (TLA+ machine-checkable):

| # | File | Status |
|---|---|---|
| FB1 | [tla/Consensus.tla](tla/Consensus.tla) — K-of-K consensus state machine | ✓ spec, model-check pending TLC install |
| FB2 | [tla/Sharding.tla](tla/Sharding.tla) — multi-shard receipt flow | ✓ spec, model-check pending TLC install |
| FB3 | [tla/Receipts.tla](tla/Receipts.tla) — receipt dedup state machine | ✓ spec, model-check pending TLC install |
| FB4 | [tla/AccountState.tla](tla/AccountState.tla) — AccountState invariants (companion to FA-Apply) | ✓ spec, model-check pending TLC install |
| FB5 | [tla/Snapshot.tla](tla/Snapshot.tla) — snapshot + restore state machine (companion to FA-Apply-2; 5 invariants SerializeRestoreIdentity / ApplyAfterRestoreEquivalence / VersionGateSoundness / DeterministicSerialization / StateRootBindsApply + 2 temporal props EventualSnapshotConsistency / RestoreIsCorrect) | ✓ spec, model-check pending TLC install |
| FB7 | [tla/Nonce.tla](tla/Nonce.tla) — per-account nonce-gate state machine (companion to FA-Apply-3; 5 invariants StrictNonceGate / NonceMonotonic / ReplayImpossible / PerAccountIndependence / GenesisStart + 2 temporal props EventualNonceAdvance / NoStaleApplied) | ✓ spec, model-check pending TLC install |
| FB8 | [tla/StakeLifecycle.tla](tla/StakeLifecycle.tla) — STAKE/DEREGISTER/UNSTAKE state machine (companion to FA-Apply-4; 7 invariants TypeOK / StakeNonNegative / BalanceNonNegative / A1Conservation / UnlockMonotonic / DeregisterImpliesActiveOff / NoEarlyUnstake + 2 temporal props EventualUnstake / StakeOrUnstakeOnly) | ✓ spec, model-check pending TLC install |
| FB9 | [tla/DAppRegistry.tla](tla/DAppRegistry.tla) — DApp registry state machine (companion to FA-Apply-5; 7 invariants TypeOK / OwnerImmutable / RegisteredAtImmutable / DeactivationForward / NefDrainsOnlyOnce / RegisterIdempotent / NefPoolNonNegative + 2 temporal props EventualDeactivation / PostDeactivationInactive) | ✓ spec, model-check pending TLC install |
| FB10 | [tla/FeeAccounting.tla](tla/FeeAccounting.tla) — fee charging + distribution state machine (companion to FA-Apply-6; 7 invariants TypeOK / BalanceNonNegative / BlockTotalFeesNonNegative / A1Conservation / NoFeeOnSkip / EmptyCreatorsNoDistribute / FeeDistributionDeterministic + 2 temporal props EventualFeeDrain / SupplyConservation) | ✓ spec, model-check pending TLC install |
| FB11 | [tla/SubsidyDistribution.tla](tla/SubsidyDistribution.tla) — subsidy mint + distribution state machine (companion to FA-Apply-7; 7 invariants TypeOK / BalanceNonNegative / NefPoolNonNegative / AccumulatedSubsidyMonotonic / EmptyCreatorsNoMint / NefDrainsOnceperDomain / SubsidyConservation + 2 temporal props EventualSubsidy / RegistrationIdempotent) | ✓ spec, model-check pending TLC install |
| FB12 | [tla/CHECK-RESULTS.md](tla/CHECK-RESULTS.md) — model-check transcripts | ✓ template, transcripts pending |

**Closure analyses and specs** (companion documents — not core FA/FB theorems, but cited alongside them):

| File | Scope |
|---|---|
| [F2-SPEC.md](F2-SPEC.md) | Implementation specification for v2.7 F2 view reconciliation (the consensus-layer closure of S-030 D2). 9 open design questions resolved; PAKE-style architecture for per-field reconciliation rules. Cited by `docs/SECURITY.md` §S-030. |
| [v2.10-DKG-SPEC.md](v2.10-DKG-SPEC.md) | Implementation specification for v2.10 threshold-randomness DKG ceremony. 4 primary + 3 cascade design decisions resolved (Option C: epoch-boundary trustless DKG with PSS refresh on the curve25519 family via FROST-Ed25519 / RFC 9591). Preserves "two primitives" design value — no new pairing-friendly curve. Shared cryptographic foundation (same curve family) for v2.22 (Bulletproofs on curve25519) and v2.25 (T-OPAQUE OPRF on ristretto255). Revises v2.10 cost from ~1 week to ~3 weeks. |
| [v2.22-PRIVACY-SPEC.md](v2.22-PRIVACY-SPEC.md) | Implementation specification for v2.22 confidential transactions. 4 interlinked design decisions resolved (Option C: per-epoch HKDF view-key derivation + Bulletproofs over curve25519 (dalek-cryptography reference impl) + ephemeral-DH amount handshake on ristretto255 + dual-mode audit disclosure). Curve family cascades from v2.10 (same libsodium primitives). v2.24 audit scope reduced from 2-3 weeks to 1-2 weeks because v2.22 delivers the underlying view-key infrastructure. ~2.5-3 months to ship from spec-review acceptance. |
| [Beaconless-v2-SPEC.md](Beaconless-v2-SPEC.md) | Implementation specification for Beaconless v2 architecture (Phase D, after v2 + Theme 9). 6 interlinked foundational design decisions resolved (Option A: light-client mesh with lazy validation + replicated deployment manifest with K-of-K co-signing + per-shard committee-rotation log + Merkle-proof cross-shard receipts + decentralized merge-detection via Merritt's Mutually Verified Election + per-epoch threshold-signature accumulator for randomness using FROST-Ed25519). Removes beacon as special role; completes mutual-distrust posture; raises horizontal-scale ceiling from ~50 to ~200-500 shards. ~3 months to ship from spec-review acceptance (DSF prereq retired — DSF ships in Phase 0 ahead of Phase A). |
| [DSF-SPEC.md](DSF-SPEC.md) | Implementation specification for the Deterministic-Simulation Framework (S-035 Option 2, **promoted ahead of Phase A**). 7 design decisions resolved (virtual-clock + virtual-network dependency injection + C++ scenario DSL + property checker framework + random scenario generator + replay tooling + 30-scenario initial set). Subsumes A10 NH1 Stage 1 streams 1 + 2 (~3 months of work eliminated; A10 reduces to streams 3 + 4 fuzz + test vectors at ~6 weeks). Provides Byzantine-bug coverage for every Phase A through D item as it lands. ~3-4 weeks to ship from spec-review acceptance. |
| [S030-D2-Analysis.md](S030-D2-Analysis.md) | Analysis of S-030 D2 (block-body fields not in `block_digest`) + comparison of the two closure paths (apply-layer via S-033 state_root + S-038 producer wiring, consensus-layer via v2.7 F2). Section 3.5 documents which fields each path covers. |
| [S002-Mempool-Sig-Verify.md](S002-Mempool-Sig-Verify.md) | Analysis trail for S-002 closure (mempool accepts unverified sigs) including the paired `binary_codec::decode_tx_frame` fix that surfaced once mempool sig-verify gated the gossip path. |

---

## Cryptographic assumptions

All FA-track proofs reduce to one or more of:

- **(A1) Ed25519 EUF-CMA** — `Verify(pk, m, σ) = 1` implies the holder of `sk` signed `m`, except with probability `≤ 2⁻¹²⁸`. Used in FA1, FA5, FA6, FA7.
- **(A3) SHA-256 collision resistance** — finding `x ≠ y` with `SHA256(x) = SHA256(y)` is `≤ 2⁻¹²⁸`. Used in FA2 (tx_root commitment), FA7 (receipt binding).
- **(A4) SHA-256 preimage resistance** — finding `x` with `SHA256(x) = h` for adversary-chosen `h` is `≤ 2⁻²⁵⁶`. Used in FA3 (commit-reveal hiding).
- **(A5) SHA-256 as a random oracle** — used in FA3 (analytic) for the cleanest formulation; FA3 also gives a standard-model version with weaker constants.

The PQ degradation under Grover (square-root speedup) is discussed in each proof's "Concrete-security bound" section. Determ's design upgrades to post-quantum signatures (Dilithium / Falcon) would restore the classical bounds; this is a pre-planned migration path, not a current requirement.

---

## Behavioral assumptions

- **(H1)** Honest validators follow the protocol: produce phase-1 commits, reveal in phase-2, vote on valid blocks, gossip evidence.
- **(H2)** Honest validators sign at most one digest per `(height, round)` — the rule that makes equivocation detection trip on misbehavior, never on honest behavior.
- **(H3)** Honest validators do not censor: they include all mempool txs they observe in their phase-1 commit, subject to validation.
- **(H4)** Honest validators reveal `dh_secret` in phase-2 only after gathering K phase-1 commits.

These are not cryptographic assumptions; they define what "honest" *means* in the protocol. FA-track proofs target conditional properties: "given H1–H4 and A1/A3/A4/A5, the protocol satisfies property P with bound B."

---

## What the FA-track proofs do NOT cover

- **Pure economic incentives**: e.g., why a rational validator chooses honest behavior. The proofs assume `≥ 1` honest committee member (FA1 standard branch) or assume slashing makes equivocation economically irrational (FA6 motivation). A separate economic-security analysis is in `docs/SECURITY.md`.
- **Network-layer DoS resistance**: gossip flood control, peer reputation, eclipse attacks. These are operational concerns, not consensus-level invariants. `docs/SECURITY.md` covers them.
- **Implementation bugs**: the proofs cite source locations, but a reviewer must still confirm the code at those locations matches the proof's stated invariant. The TLA+ track (FB) will close the gap between proof and code by model-checking the abstract state machines that the C++ implementation tracks.
- **Cross-shard liveness under permanent regional silence**: FA7 covers safety; long-running silent shards strand value in `Pending`. Refund mechanism is a v2+ design item.

---

## Cross-references

Each per-property proof cites:

- F0 (Preliminaries) for notation and assumptions
- Other FA proofs where their results are used
- `src/` paths where the invariants are enforced
- `tools/test_*.sh` integration tests that exercise the invariant

A reviewer working bottom-up (code → proof) should be able to:

1. Read a `check_*` function in `src/node/validator.cpp`.
2. Identify which validity predicate (V1–V15 from F0) it enforces.
3. Trace which FA-track proof depends on that predicate.

A reviewer working top-down (theorem → code) should be able to:

1. Read a theorem statement in this directory.
2. Identify which validator check + apply-side state mutation upholds it.
3. Confirm in the cited source location.

If either direction fails — a check in code that no theorem references, or a theorem with no code-side enforcement — that's a gap worth raising.

---

## Concrete-security summary

Under standard assumptions (Ed25519 EUF-CMA, SHA-256 CR + preimage resistance, ROM where needed), every FA-track property holds with probability ≥ `1 - Q · 2⁻¹²⁸` over polynomial adversary budget `Q`. For `Q = 2⁶⁰`, the cumulative failure probability is `≤ 2⁻⁶⁸` — strongly negligible.

Per-property bounds:

| Property | Bound per attempt | Cumulative (Q = 2⁶⁰) |
|---|---|---|
| FA1 safety fork | 2⁻¹²⁸ | 2⁻⁶⁸ |
| FA2 censorship | 2⁻¹²⁸ (tx_root preimage) | 2⁻⁶⁸ |
| FA3 selective abort | 2⁻²⁵⁶ (commit preimage) | 2⁻¹⁹⁶ |
| FA5 BFT fork | 2⁻¹²⁸ · |K_h| (forge intersection within BFT committee) | 2⁻⁶² for |K_h| ≤ 64 |
| FA6 false-positive slash | 2⁻¹²⁸ | 2⁻⁶⁸ |
| FA7 receipt fabrication | K · 2⁻¹²⁸ | 2⁻⁶² for K ≤ 64 |
| FA10 unauthorized PARAM_CHANGE | 2⁻¹²⁸·(N−1) for N keyholders | 2⁻⁴⁵² for N = 5 |
| FA12 wallet recovery (real OPAQUE) | Q · 2⁻⁶⁰ + N · 2⁻¹²⁸ | 2⁻⁴⁴ with 60-bit pw, Q = 2¹⁶ |
| FA12 wallet recovery (stub adapter) | offline-grindable | NOT for production |

Under Grover (PQ), each `2⁻¹²⁸` degrades to `2⁻⁶⁴`. The protocol remains operationally secure but tighter PQ-signature migration is recommended.
