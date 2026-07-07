> **TIER: PROCESS / ARCHIVE.** Deliberation/meta; retained for rationale but NOT coherence-maintained as part of the 1.0 set. Roadmap index: docs/ROADMAP.md

# Pre-implementation review — six formal specifications

> **SUPERSEDED CRYPTO DIRECTION (2026-07-07) — read the checklist below as historical design deliberation.** This review predates the crypto-stack direction change. **secp256k1 was REJECTED (a Koblitz curve) and NEVER built** — there is no `src/crypto/secp256k1/`, `src/crypto/secp256k1_zkp/`, or `src/crypto/oprf/`, and `libsecp256k1`/`libsecp256k1-zkp` were never vendored (the secp256k1/Bulletproofs implementation track was DE-SCOPED 2026-07-03). **ristretto255 was never used** (libsodium was removed from the tree entirely). **FROST is FROZEN** (removed from the chain path 2026-07-03; `src/crypto/frost/` is retained for audit history + test coverage only, off the consensus path). The **actual, as-built direction:** all prime-order ZK — Bulletproofs / range proofs / Pedersen commitments / OPRF / confidential-tx — runs on the **profile-agnostic NIST P-256 shielded pool** (`src/crypto/p256/` §3.8c, `src/crypto/pedersen/` §3.19, OPRF = RFC 9497 P256-SHA256 §3.9b). **MODERN profile = Ed25519 (sign) + X25519 (KX/DH) + the P-256 stack** for everything prime-order (no MODERN-specific ZK backend, no big-prime Z_p* — the §3.20 finite-field stack was removed 2026-07-07). **DSSO = DLT-A** (X25519 threshold-OPRF + the chain's own K-of-K block signature as the threshold attestation), NOT FROST/BLS and NOT "T-OPAQUE over ristretto255." Wherever the checklist items below say *secp256k1*, *ristretto255*, *libsecp256k1(-zkp)*, or *FROST-Ed25519*, they describe the intended-but-abandoned plan. See DECISION-LOG 2026-07-07 (privacy-track direction; D3 MODERN-reuses-P-256) and 2026-07-03 (secp256k1/Bulletproofs track DE-SCOPED; FROST removed from chain path). Line C99-11 has already been reconciled to the P-256 reality; the other items have not.

**Purpose.** Consolidated review checklist for all six formal specifications resolved during the cascade-resolution sessions. Designed for a focused review week (~5 working days) clearing all decisions before Phase 0 engineering begins.

**Review format.** Each spec has 5-10 explicit decisions requiring sign-off. Reviewer reads the spec, runs the checklist, marks each item Accept / Reject / Revise. Rejected or Revised items return to design for revision; Accepted items unlock the spec for implementation.

**Sequencing.** The six specs have an internal dependency order — earlier specs constrain later ones. Recommended review order:

1. **CRYPTO-C99-SPEC.md** — cryptographic stack foundation; constrains every other spec's primitive choices
2. **DSF-SPEC.md** — testing infrastructure foundation; gates Phase A items
3. **F2-SPEC.md** — v2.7 view reconciliation; smaller change, isolated
4. **v2.10-DKG-SPEC.md** — threshold randomness; consumes CRYPTO-C99 substrate
5. **v2.22-PRIVACY-SPEC.md** — confidential transactions; consumes CRYPTO-C99 substrate
6. **Beaconless-v2-SPEC.md** — Phase D architecture; consumes v2.10 substrate

**Single Accept/Reject discipline.** Each decision is binary: accept the spec's choice (proceeds to implementation) or reject with rationale (returns to design). "Revise" is acceptable as "reject + propose alternative."

---

## Spec 1: CRYPTO-C99-SPEC.md (cryptographic stack foundation)

**Reference:** `docs/proofs/CRYPTO-C99-SPEC.md`
**Author summary:** Vendor every cryptographic primitive Determ uses as independent C99 source organized into modular sub-libraries. Eliminate libsodium dependency entirely. Dual-profile design: MODERN profile (Ed25519, X25519, secp256k1, Bulletproofs, XChaCha20-Poly1305, Argon2id) for `web`/`regional`/`global`; FIPS profile (Ed25519 FIPS 186-5, X25519, NIST P-256, AES-256-GCM, PBKDF2) for `cluster`/`tactical`. Crypto profile bundled into `TimingProfile`. ristretto255 eliminated entirely.
**Effort if accepted:** ~17-19 weeks senior cryptographic engineering, Phase 0 Track 2 parallel with DSF.

### Decision checklist (11 items)

- [ ] **C99-1: Two curve families accepted.** curve25519 family (Ed25519 + X25519) + secp256k1 family. Three curves total; two underlying mathematical families. Alternative: stay single-family with vendored libsodium ristretto255 — retains libsodium-derived code.
- [ ] **C99-2: ristretto255 elimination accepted.** v2.10 FROST → Ed25519 per RFC 9591; v2.22 DH → X25519; v2.22 Bulletproofs → secp256k1; v2.25 OPRF → secp256k1. Zero ristretto255 callers. Alternative: keep ristretto255 (vendor libsodium or implement from IETF draft independently).
- [ ] **C99-3: Per-primitive vendoring sources accepted.** NIST FIPS refs (SHA-256/SHA-512, AES-GCM), Bernstein ref10 (Ed25519), curve25519-donna (X25519), RFC 8439 (ChaCha20-Poly1305), P-H-C reference (Argon2id), libsecp256k1 + libsecp256k1-zkp (secp256k1 + Bulletproofs), RFC 9591 (FROST-Ed25519 implementation), voprf draft + RFC 9380 (OPRF on secp256k1). Each pinned to specific upstream version.
- [ ] **C99-4: Modular sub-library structure accepted.** `src/crypto/<primitive>/` per primitive family. Each compiles as standalone static library. Per-module test isolation. Modular benefits: per-primitive replacement straightforward at any future trigger.
- [ ] **C99-5: Unified C99 API + C++ wrapper accepted.** `include/determ/crypto.h` exposes C99 API; `include/determ/crypto.hpp` wraps for C++ ergonomics (RAII, span, type safety). Migration burden from libsodium API tolerable (~5 days per CRYPTO-C99-SPEC §3.15).
- [ ] **C99-6: Constant-time discipline approach accepted.** dudect statistical timing-leak verification + manual review per primitive. Each primitive documented as constant-time or variable-time. Alternative: add ctgrind alongside dudect.
- [ ] **C99-7: Test-vector validation approach accepted.** Per-primitive canonical test vectors from NIST CAVP, RFC references, P-H-C, libsecp256k1 test suite, RFC 9591 Appendix C, voprf draft. CI gate on vectors. Cross-validation against libsodium outputs during migration.
- [ ] **C99-8: Cross-platform targets accepted.** x86-64 + ARM64 + Linux + Windows + MINIX (NH1 secondary OS). Pure C99 baseline + optional SIMD-optimized variants gated by build flag.
- [ ] **C99-9: libsodium removal trigger accepted.** Defer-libsodium-removal until cross-validation has been clean for ~4 weeks of production exposure (per CRYPTO-C99-SPEC §5 risks).
- [ ] **C99-10: Total cost ~17-19 weeks accepted.** Phase 0 Track 2 parallel with DSF (Track 1, ~3-4 weeks). Phase 0 wall-clock = max(Track 1, Track 2) = ~17-19 weeks. If single engineer: Track 1 ships first; Track 2 defers to trigger event.
- [ ] **C99-11: Dual-profile bundling accepted.** `CryptoProfile { MODERN, FIPS }` bundled into `TimingProfile` rather than orthogonal genesis field. `cluster` + `tactical` bundle FIPS (AES-256-GCM, PBKDF2, NIST P-256 + P-256 Bulletproofs); `web` + `regional` + `global` bundle MODERN (XChaCha20-Poly1305, Argon2id, Ed25519/X25519; confidential-tx via the profile-agnostic P-256 shielded pool). Notes that FIPS-profile confidential-tx (the §3.22 P-256 shielded pool) is built on FIPS-approved primitives but its Bulletproofs construction is not itself a FIPS-validated algorithm (per-op-CMVP: out-of-module). Crypto is a posture, not a code switch. Alternative: orthogonal profile axis (5 timing × 2 crypto = 10 combinations).

**If accepted:** unlocks Phase 0 Track 2 engineering. Constrains the primitive substrate referenced by v2.10/v2.22/v2.25/Beaconless v2 specs.

---

## Spec 2: DSF-SPEC.md (deterministic-simulation framework)

**Reference:** `docs/proofs/DSF-SPEC.md`
**Author summary:** Virtual clock + virtual network + scriptable Byzantine actors + property checkers + 30-scenario initial set. Promoted ahead of Phase A. Subsumes A10 NH1 Stage 1 streams 1 + 2 (~3 months of work eliminated). Provides Byzantine-bug coverage for every Phase A through D item.
**Effort if accepted:** ~3-4 weeks senior distributed-systems engineering, Phase 0 Track 1 parallel with C99 crypto.

### Decision checklist (6 items)

- [ ] **DSF-1: Dependency-injection refactor accepted.** Thread `time::Clock&` and `net::Transport&` through ~30-50 call sites in Node/Validator/Producer/RPC/Gossip. Alternative: global mockable singletons (smaller refactor, weaker dependency hygiene).
- [ ] **DSF-2: C++ scenarios over embedded scripting accepted.** Scenarios are C++ classes with `setup() / run() / check()` lifecycle. Alternative: Lua or Python embedded (faster scenario authoring; trade-off is dependency + audit surface).
- [ ] **DSF-3: Four initial invariant checkers accepted.** FA1 single-block-per-height; A1 unitary supply; FA6 equivocation slashing; FA7 cross-shard atomicity. Acceptable for v2 coverage? Additional candidates: FA2 (collaborative inclusion), FA5 (BFT-mode safety), FA8 (committee selection bias).
- [ ] **DSF-4: Initial 30-scenario set balance accepted.** Categories: selective-abort (5), equivocation (4), network partition (4), cross-shard (5), DKG (4), F2 view reconciliation (4), BFT escalation (4). Right balance across categories? Should DKG / F2 scenarios get more weight given Phase A focus?
- [ ] **DSF-5: Pre-Phase-A scheduling accepted.** ~3-4 weeks before Phase A starts (delays Phase A by that much in exchange for DSF coverage during Phase A development).
- [ ] **DSF-6: A10 retirement of streams 1 + 2 accepted.** DSF subsumes bash integration test extension + property tests for invariants. A10 reduces to streams 3 + 4 (fuzz + test vectors) at ~6 weeks.

**If accepted:** unlocks Phase 0 Track 1 engineering. Enables DSF-tested behavior for every Phase A through D item.

---

## Spec 3: F2-SPEC.md (v2.7 view reconciliation)

**Reference:** `docs/proofs/F2-SPEC.md`
**Author summary:** Per-field heterogeneous reconciliation rules for v2.7 F2: union (with V11 verifiability) for `equivocation_events`; union (with V10) for `abort_events`; intersection for `inbound_receipts`; deterministic derivation for `cross_shard_receipts` and `partner_subset_hash`; assembler-proposes-members-bound-check for `timestamp`. Each member's ContribMsg carries per-field Merkle-root hashes + the actual lists.
**Effort if accepted:** ~3-4 days (small; spec is fully realized).

### Decision checklist (5 items)

- [ ] **F2-1: Per-field reconciliation rule assignments accepted.** Esp. `inbound_receipts` intersection (conservative, prevents double-credit) vs threshold rule alternative.
- [ ] **F2-2: Wire format choice accepted.** Per-field Merkle root (32 bytes) + full list per member in `ContribMsg`. Suggested cap 64 events per type per member. ~1-2 KB extra per member per round.
- [ ] **F2-3: Phase-2 signature semantics under union rule accepted.** Member signs over reconciled canonical list, including evidence/abort events the member didn't personally observe (but which individually pass V10/V11 verification).
- [ ] **F2-4: Timestamp inclusion in v2.7 scope accepted.** Assembler-proposes-members-bound-check pattern (±30s window). Avoids separate v2.7.5 scope.
- [ ] **F2-5: Flag-day migration approach accepted.** ContribMsg wire-version bump; pre-flag-day legacy commit; post-flag-day F2 enforcement. vs. hard fork with re-genesis.

**If accepted:** unlocks v2.7 implementation. Closes S-030 D2 at consensus layer. Position A.2 in Phase A.

---

## Spec 4: v2.10-DKG-SPEC.md (threshold randomness DKG)

**Reference:** `docs/proofs/v2.10-DKG-SPEC.md`
**Author summary:** Epoch-boundary trustless DKG with proactive secret sharing (PSS) refresh. FROST-Ed25519 protocol per RFC 9591 implemented as Determ-original C99 code in `src/crypto/frost/` over Bernstein's `ref10` Ed25519. No libsodium dependence per CRYPTO-C99-SPEC. Per-epoch threshold-key rotation; share refresh per epoch when committee membership unchanged.
**Effort if accepted:** ~3 weeks (includes Phase 0 Track 2 work for FROST implementation if not yet shipped).

### Decision checklist (5 items)

- [ ] **DKG-1: Epoch-boundary timing accepted.** Acceptable to consume R blocks per epoch for DKG (3-5% overhead at epoch_blocks=100)? R = 5 at tactical/cluster; R = 3 at web/regional/global.
- [ ] **DKG-2: Curve25519 family (Ed25519/ristretto255) via independent C99 accepted.** Preserves CRYPTO-C99 stack. Alternative: BLS12-381 + `blst` if pairing-capable future features become in-scope (currently deferred per God Stack pattern).
- [ ] **DKG-3: FROST-Ed25519 per RFC 9591 accepted.** Determ-original C99 implementation cross-validated against zcash/frost-ed25519 (Rust). Alternative: Pedersen DKG (older, less robust) or FROST-BLS (requires curve change to BLS12-381).
- [ ] **DKG-4: R-block timing per profile accepted.** R=5 at tactical/cluster, R=3 at web/regional/global. Acceptable wall-clock budget?
- [ ] **DKG-5: Flag-day migration approach accepted.** ContribMsg wire-format bump from `creator_dh_secrets` → `creator_partial_sigs`. Three new gossip-layer message types. Three new on-chain block fields. Pre-flag-day legacy; post-flag-day FROST.

**If accepted:** unlocks v2.10 implementation. Phase A.4 (largest single item). Theme-9 precondition; shared cryptographic infrastructure with v2.22 + v2.25.

---

## Spec 5: v2.22-PRIVACY-SPEC.md (confidential transactions)

**Reference:** `docs/proofs/v2.22-PRIVACY-SPEC.md`
**Author summary:** Per-epoch HKDF view-key derivation from long-term `view_master`. Bulletproofs over secp256k1 via libsecp256k1-zkp (Bitcoin Core's library). Ephemeral DH on X25519 for amount handshake. Two-curve protocol: X25519 for DH (curve25519 family) + secp256k1 for Pedersen commitment (matches Bulletproof curve). Dual-mode audit disclosure: master OR per-epoch keys.
**Effort if accepted:** ~2.5-3 months (Phase B.1).

### Decision checklist (5 items)

- [ ] **PRIV-1: Per-epoch HKDF view-key derivation accepted.** Master `view_master` derives `vk_epoch_n = HKDF(view_master, "VK" || chain_id || account_addr || epoch_n)`. Bounded exposure per epoch; zero on-chain rotation cost; maps to regulator audit cadence. Optional hierarchical extension (cold/hot master separation) documented as recommended for high-stakes deployments.
- [ ] **PRIV-2: Bulletproofs over secp256k1 via libsecp256k1-zkp accepted.** Most-production-tested C99 Bulletproof implementation (Liquid + Grin, ~5+ years). Bitcoin-grade audit pedigree. Adds secp256k1 as second curve family. Alternative: BLS12-381 port (~2-3 weeks additional cost) or libsodium-vendored ristretto255 (retains libsodium-derived code).
- [ ] **PRIV-3: X25519 ephemeral DH for amount handshake accepted.** Two-curve protocol: X25519 for DH + secp256k1 for commitment. DH curve choice independent of commitment curve. libsodium-independent via curve25519-donna.
- [ ] **PRIV-4: Dual-mode audit disclosure accepted.** Auditor receives either `view_master_sk` (full access; in-house compliance) or per-epoch `vk_epoch_n` keys (scoped access; external regulator with bounded audit window). Composes with v2.24 `audit_view_master_pk` field.
- [ ] **PRIV-5: Wire-format break + flag-day migration approach accepted.** New tx-type tag distinguishing clear-amount vs confidential-amount. New Account fields. New tx types: PUBLISH_VIEW_KEY, ROTATE_VIEW_MASTER. Flag-day genesis field controls when confidential-amount becomes required for accounts with `view_master_pk` set.

**If accepted:** unlocks v2.22 implementation. Phase B.1 (largest Theme-8 item). Reduces v2.24 audit hooks scope from 2-3 weeks to 1-2 weeks.

---

## Spec 6: Beaconless-v2-SPEC.md (Phase D architecture)

**Reference:** `docs/proofs/Beaconless-v2-SPEC.md`
**Author summary:** Light-client mesh with lazy validation (Option A). Each shard maintains light-client headers only for shards from which it receives receipts; per-source eviction with `LIGHT_CLIENT_RETENTION_BLOCKS` window. Replicated deployment manifest with K-of-K co-signing for mutations. Per-shard append-only committee-rotation log. Cross-shard receipts with Merkle inclusion proofs against source shard's state_root. Merritt's Mutually Verified Election for merge detection. Per-epoch threshold-signature accumulator for randomness using FROST-Ed25519.
**Effort if accepted:** ~3 months (Phase D; DSF prereq already satisfied via Phase 0).

### Decision checklist (8 items)

- [ ] **BL-1: Light-client mesh with lazy validation (Option A) accepted.** Each shard maintains light-client headers for shards from which it actually receives receipts. Per-source eviction with `LIGHT_CLIENT_RETENTION_BLOCKS = 10000` (default). Alternative: rotating ephemeral hub (Option B), pairwise gossip + accumulator (Option C), sample-and-attest (Option D).
- [ ] **BL-2: Deployment manifest with K-of-K co-signing accepted.** Replicated across all shards via gossip. Mutations require K-of-K signing from every shard's current committee. Cooldown-based default-accept after `MANIFEST_UPDATE_TIMEOUT_BLOCKS` prevents single-shard veto.
- [ ] **BL-3: Committee-rotation log compaction interval accepted.** EPOCH_SNAPSHOT_INTERVAL = 100 epochs. Log compacted to snapshot root every 100 epochs; light clients verify against snapshots for epochs older than the interval.
- [ ] **BL-4: Receipt-id format accepted.** `receipt_id = SHA256("DTM-RECEIPT" || source_shard || dest_shard || source_height || nonce_within_block)`. Globally unique by construction; no collision risk.
- [ ] **BL-5: Merritt-witness adversary tolerance accepted.** k=1 with `num_shards >= 3` for v2.0; k=2 (requiring `num_shards >= 7`) optional for high-stakes deployments. Heartbeat absence claims propagate through deterministic j-witnesses; merge fires only when claim collects k-affidavits.
- [ ] **BL-6: Late-shard randomness handling accepted.** Subset of shards contributing to deployment-rand recorded in block header (new `deployment_rand_subset` field) for deterministic verification.
- [ ] **BL-7: DSF as Beaconless v2 prerequisite already satisfied.** DSF shipped in Phase 0; Phase D D.0 entry retired. Phase D starts directly at D.1 (light-client mesh).
- [ ] **BL-8: Sequencing as Phase D (after Phase A/B/C) accepted.** Not parallel with v2 + Theme 9; sequential. Phase D = ~3 months after Phase A/B/C ship.

**If accepted:** unlocks Phase D implementation. Completes mutual-distrust at architectural layer; raises horizontal-scale ceiling from ~50 to ~200-500 shards.

---

## Total review surface

| Spec | Items | Spec doc size | Suggested review time |
|---|---|---|---|
| CRYPTO-C99-SPEC.md | 11 | ~560 lines | ~1 day |
| DSF-SPEC.md | 6 | ~365 lines | ~half day |
| F2-SPEC.md | 5 | ~270 lines | ~half day |
| v2.10-DKG-SPEC.md | 5 | ~360 lines | ~half day |
| v2.22-PRIVACY-SPEC.md | 5 | ~340 lines | ~half day |
| Beaconless-v2-SPEC.md | 8 | ~440 lines | ~1 day |
| **Total** | **40 items** | **~2335 lines** | **~4-5 days** |

**A single focused review week (5 working days) clears all six specs.**

---

## Review-week format suggestion

| Day | Spec | Output |
|---|---|---|
| Day 1 (morning) | CRYPTO-C99-SPEC.md | 11 decision Accept/Reject; constrains all downstream |
| Day 1 (afternoon) | DSF-SPEC.md | 6 decision Accept/Reject |
| Day 2 (morning) | F2-SPEC.md | 5 decision Accept/Reject |
| Day 2 (afternoon) | v2.10-DKG-SPEC.md | 5 decision Accept/Reject |
| Day 3 (morning) | v2.22-PRIVACY-SPEC.md | 5 decision Accept/Reject |
| Day 3 (afternoon) | Beaconless-v2-SPEC.md | 8 decision Accept/Reject |
| Day 4 | Reviewer drafts revisions for any rejected items | Per-spec revision summary |
| Day 5 | Decision document consolidation; sign-off | Approval recorded; specs unlocked for implementation |

After review-week completion:
- ✅ Accepted specs unlock immediately
- ⚠️ Rejected items return to design for revision (typically ~1-2 days per item)
- 🔄 Re-review of revised items happens in a follow-up half-day session

---

## What review-week completion enables

Once all 40 decisions are accepted (or revised + re-approved):

**Phase 0 begins.** Two parallel tracks (DSF + C99 crypto) launch immediately. ~17-19 weeks until Phase A start.

**No further design questions remain on the documented roadmap.** All cascading questions formally resolved. Engineering execution begins.

**Each spec has a self-contained implementation plan** with:
- Per-component work units (totaling per-spec effort estimate)
- Per-component test approach
- Per-component risks + rollback plan
- Per-component cross-references to other specs

**The roadmap is bounded** at ~12-15 months from review-week completion to v2 + Theme 9 + Beaconless v2 complete with libsodium-free C99 cryptographic stack.

---

## What review-week completion does NOT do

**Does not commit engineering resources.** Each spec accept-decision is a design-layer commitment; actual engineering still requires staffing decisions.

**Does not start implementation immediately.** After acceptance, Phase 0 implementation begins. If engineering resources aren't available, accepted specs sit ready until staffed.

**Does not preclude future revisions.** Specs can be revised post-acceptance if new evidence (audit findings, deployment data, research advances) warrants. Acceptance is "ready to implement," not "permanent forever."

**Does not address operational decisions.** Operator-side genesis parameters (NEF amounts, MIN_STAKE sizing, profile selection, region taxonomy) are per-deployment choices, not protocol design.

---

## Cross-spec dependencies — visual

```
CRYPTO-C99-SPEC.md (foundation — review first)
    │
    ├─ provides primitives to ─→ v2.10-DKG-SPEC.md
    ├─ provides primitives to ─→ v2.22-PRIVACY-SPEC.md
    ├─ provides primitives to ─→ Beaconless-v2-SPEC.md
    │
    └─ shares Phase 0 with    ─→ DSF-SPEC.md (independent track)

F2-SPEC.md (isolated; small change)

v2.10-DKG-SPEC.md
    │
    └─ provides threshold infrastructure to ─→ Beaconless-v2-SPEC.md (cross-shard randomness)
    └─ provides threshold infrastructure to ─→ v2.25 (Theme 9 DSSO)

v2.22-PRIVACY-SPEC.md
    │
    └─ provides view-key infrastructure to ─→ v2.24 (audit hooks)

Beaconless-v2-SPEC.md (depends on CRYPTO-C99 + v2.10 + DSF)
```

Acceptable to review in dependency order or all-in-parallel. Dependency order is cleaner because earlier acceptances inform later sections.

---

*End of consolidated review checklist.*
