# Beaconless v2 architecture — design specification

**Status:** specification only. No code. Resolves the 6 interlinked design questions for removing the beacon as a special role from Determ's regional-sharding architecture. Implementation should not begin until this document's design choices are reviewed and committed, and until v2 + Theme 9 has substantially shipped (Beaconless v2 is the natural next major architectural effort after v2 + Theme 9, not parallel with it).

**Companion documents:**
- `plan.md` "Future: Beaconless cross-shard architecture (v2)" — original problem statement and constraint discussion
- `V2-DESIGN.md` Themes 1-9 — the architecture Beaconless v2 inherits from
- `F2-SPEC.md`, `v2.10-DKG-SPEC.md`, `v2.22-PRIVACY-SPEC.md` — sibling spec docs in the cascade-resolution pattern
- `CrossShardReceipts.md` — FA7 cross-shard atomicity proof (gets updated under beaconless)
- `RegionalSharding.md` — current beacon-based sharding architecture (Beaconless v2 replaces the beacon role)

---

## 1. Scope

This spec covers ONLY the architectural removal of the beacon as a special role and the redistribution of beacon functions across shards. It does NOT cover:

- New consensus mechanism — Beaconless v2 reuses the existing K-of-K mutual-distrust consensus per shard. Only the cross-shard coordination layer changes.
- New cryptographic primitives — uses the v2.10 FROST-Ed25519 DKG infrastructure (curve25519 family via libsodium), v2.1 state Merkle root, v2.2 light-client proofs. All already-shipped or already-spec'd.
- Horizontal-scale beyond ~hundreds of shards — Beaconless v2 raises the practical ceiling from ~50 to ~200-500 shards via lazy validation; beyond that, additional sharding-of-sharding work is a v3 concern.
- Cross-deployment interop — Beaconless v2 is intra-deployment only. Cross-deployment bridges remain v2.23's scope (which also uses light-client mesh, so the infrastructures align).

The artifacts produced by Beaconless v2:
- **Deployment manifest** (replicated across all shards via gossip) — the new trust anchor replacing the beacon's authority
- **Per-shard light-client header chain** — every shard maintains light-client headers for shards it actually receives receipts from (lazy validation)
- **Append-only committee-rotation log** per shard with cross-signing by previous committee
- **Direct shard-to-shard cross-shard receipt gossip** with Merkle inclusion proofs against source shard's state_root
- **Per-shard SHARD_TIP observation** for decentralized merge-detection
- **Cross-shard randomness aggregation** via per-epoch accumulator over signed shard randomness
- **`AUTONOMOUS_SHARD` chain_role** for the new shard type, enabling migration from beacon-bound to beaconless deployments

---

## 2. Design decisions

### Q1: Cross-shard validation architecture (foundational)

**Decision: light-client mesh with lazy validation (Option A).**

Each shard maintains light-client headers for every other shard from which it actually receives cross-shard receipts. Headers are signature-chain validated against the source shard's committee-rotation log. Cross-shard receipts carry Merkle inclusion proofs against the source shard's state_root at receipt-emission height; the receiver validates the proof against its locally-maintained light-client header for the source shard.

**Lazy validation rule.** A shard maintains light-client headers for shard S iff it has received at least one receipt from S within the last `LIGHT_CLIENT_RETENTION_BLOCKS` (default 10000, ~7 hours at tactical). Beyond that, the headers are evicted; if a new receipt from S arrives, the receiver fetches headers from S's gossip peers to catch up. Eviction is per-source, not per-receiver — different shards may evict different sources independently.

**Rationale.**
- Strongest cryptographic guarantee — no privileged role; every shard is symmetric. Matches K-of-K mutual-distrust posture (no special "validator of validators").
- Reuses already-shipped v2.1 state Merkle root + v2.2 light-client proof infrastructure. No new cryptographic primitive family.
- Composes with v2.23 cross-chain bridge (same light-client primitive validates intra-deployment cross-shard receipts AND Determ-to-Determ bridge transfers).
- Lazy validation contains the O(N²) cost — effective N is the active-pair count, not the total shard count. For typical regional-cluster topologies, active pairs are far below N².

**Alternatives rejected:**
- *Rotating ephemeral hub (Option B):* Still has a hub; rotation doesn't solve the architectural-bottleneck problem.
- *Pairwise gossip + Merkle accumulator (Option C):* Accumulator scheme is itself a hard research-grade design question; premature.
- *Two-tier with sample-and-attest (Option D):* Re-introduces a privileged role; conceptually similar to beacon.

### Q2: Trust anchor — deployment manifest

**Decision: deployment manifest replicated across all shards via gossip; mutations require existing-committee co-signing.**

The deployment manifest contains:
- List of shard IDs in the deployment
- Each shard's genesis hash
- Each shard's initial committee (as of deployment creation)
- Cryptographic primitives in use (curve25519 family, FROST-Ed25519, etc.)
- Manifest version (incremented on mutation)
- Co-signing record (every mutation signed by the existing committee of every shard, K-of-K per shard)
- **Operator-tunable parameters** (per review-week BL-3, BL-5, BL-6):
  - `epoch_snapshot_interval: u64` — committee-log compaction cadence (default 100 epochs)
  - `merritt_k: u8` — Byzantine-shard tolerance for merge-detection; invariant `num_shards > k(k+1)` (default 1)
  - `epoch_boundary_cutoff_blocks: u64` — cutoff window for late-shard randomness contributions (default 10 blocks)

**Replication.** Manifest is replicated via gossip across all shard validators. Each shard's validator set independently verifies the manifest's co-signing chain back to the deployment-genesis manifest. Light clients fetch the manifest from any gossip peer and verify the same chain.

**Mutation.** Adding a shard, removing a shard, or rotating the cryptographic suite requires a new manifest version. Mutation is initiated by a `MANIFEST_UPDATE` tx submitted to any shard; the tx carries the proposed new manifest + collected K-of-K signatures from every shard's current committee. Once collected, the new manifest is gossiped; old manifest is retired at a flag-day height committed in the mutation.

**Rationale.**
- Replicated (not single-source) eliminates the beacon's single-point-of-failure / single-point-of-attack.
- Co-signing by every shard's K-of-K committee preserves mutual-distrust at the cross-shard level (no single committee can unilaterally mutate the manifest).
- Light clients verify manifest authenticity without trusting any single RPC.

**Alternatives rejected:**
- *Single-shard authoritative manifest:* Reintroduces beacon-like privileged shard.
- *On-chain manifest committed to each shard's genesis:* No mutation path; would require complete re-genesis for any shard add/remove.

#### Q2.1: Manifest validation (hard invariants + soft warnings)

**Problem.** BL-3/5/6 made `epoch_snapshot_interval`, `merritt_k`, and `epoch_boundary_cutoff_blocks` operator-tunable. Without explicit validation, an operator can ship a manifest whose claimed properties do not match actual deployment behavior. Most critically: `merritt_k` chosen without satisfying `num_shards > k(k+1)` silently degrades Byzantine tolerance — the deployment looks correct, runs correctly under benign conditions, and only reveals weakness under adversarial exploitation. No observable signal until attack.

**Two tiers of validation.**

**Hard invariants (consensus-enforced; `MANIFEST_UPDATE` apply path rejects):**

```
merritt_k >= 1
merritt_k <= 5                                  // Merritt construction unwieldy beyond
num_shards > merritt_k * (merritt_k + 1)        // Byzantine tolerance precondition
```

Rationale: these gate security properties. Putting them in consensus means every node validates and the chain cannot operate with the invariant violated. No operator override path.

**Soft warnings (manifest-construction tooling only; not consensus-enforced):**

```
epoch_snapshot_interval >= 10                                          // prevent pathological churn
epoch_snapshot_interval <= 10000                                       // prevent bootstrap pain
epoch_boundary_cutoff_blocks >= 2                                      // prevent tiny-subset bias in deployment rand
epoch_boundary_cutoff_blocks <= 1000                                   // prevent liveness loss
epoch_boundary_cutoff_blocks < epoch_snapshot_interval / 10            // cross-field sanity
```

Rationale: these are performance failure modes that operations teams catch and fix (slow nodes, stuck epochs, surge alerts). Consensus-enforcing them would freeze the operating envelope and prevent legitimate experimentation. Warning emitted at manifest construction with explicit acknowledgment of consequence required to override.

**Where validation runs.**
- **Manifest-construction tooling** (CLI / operator builder): runs BOTH hard and soft checks. Hard violations block manifest construction. Soft violations emit warnings that require `--acknowledge-soft-violations` flag to bypass.
- **`MANIFEST_UPDATE` apply path** (consensus-enforced on every validator): runs ONLY hard checks. Soft thresholds are not consensus-relevant. A manifest passing tooling-time hard checks always passes apply-path validation; a hand-crafted manifest violating hard invariants is rejected.

**Definition source.** All thresholds defined as compile-time constants in `manifest_validity.hpp`. One source of truth; spec text references the file; values not duplicated in spec body to prevent drift.

**Rationale.**
- **Decouples security guarantees from operator judgment.** The Merritt invariant is a precondition for the security property the spec claims; consensus-enforcement makes the precondition non-negotiable.
- **Preserves operator flexibility for performance tuning.** Soft thresholds reflect *recommended* operating envelope, not algorithmic requirements. Research labs, custom deployments, and future experiments retain the ability to step outside.
- **Failure-mode separation matches detection-mode.** Security failures (silent until exploited) → hard. Performance failures (operationally visible) → soft.

**Alternatives rejected.**
- *All-hard (consensus-enforce performance bounds too):* freezes operating envelope; prevents legitimate experimentation; couples consensus rules to performance heuristics that may evolve.
- *All-soft (only warn on Merritt invariant violation):* allows misconfigured deployments to ship; reproduces the failure mode this amendment exists to prevent.
- *External validation document only (no code-level enforcement):* relies on operators reading and following docs; provides no defense against accidental misconfiguration.
- *Per-deployment governance-vote override of Merritt invariant:* introduces complexity for a corner case (operator deliberately wants weaker tolerance — should be rare; if needed, operator can run a fork with adjusted constants).

**Effort.** ~1 week: spec text (~2-3h), `manifest_validity.hpp` + `validate_manifest()` (~3-5 days), apply-path integration + manifest-construction-tool integration (~1-2 days), tests covering each invariant violation case (~2 days). Composes with BL-2 (`MANIFEST_UPDATE` apply path already exists from the manifest mutation infrastructure).

### Q3: Committee continuity — append-only committee-rotation log per shard

**Decision: each shard maintains an append-only on-chain log of committee rotations, with each new committee co-signed by the previous committee (K-of-K).**

```
ShardCommitteeLog (per shard) {
    entries: [
        {
            epoch: 0,
            committee: [pubkey_0_0, pubkey_0_1, …, pubkey_0_K]
            // Initial committee — committed in shard genesis; no prev-committee sig.
        },
        {
            epoch: 1,
            committee: [pubkey_1_0, …, pubkey_1_K],
            prev_committee_sig: K-of-K signature by epoch-0 committee
                                over (epoch, committee)
        },
        {
            epoch: 2,
            committee: [pubkey_2_0, …, pubkey_2_K],
            prev_committee_sig: K-of-K signature by epoch-1 committee
                                over (epoch, committee)
        },
        …
    ]
}
```

The log is stored as a per-shard data structure committed in each block's state_root (via v2.1 Merkle commitment). Light clients fetch any historical committee by traversing the log from the deployment manifest's initial entry forward.

**Verification.** To verify committee at epoch N for shard S:
1. Fetch manifest, retrieve S's genesis-pinned initial committee (epoch 0).
2. Walk S's committee log from epoch 0 to epoch N, verifying each `prev_committee_sig` against the previous epoch's committee.
3. The terminal entry is the committee at epoch N.

**Compaction.** The log grows without bound. Snapshot mechanism: every `manifest.epoch_snapshot_interval` epochs (default 100), the log emits a snapshot root committing the entire log up to that epoch. Light clients verify against snapshots, not raw entries, for epochs older than the snapshot interval. Interval is operator-tunable per deployment via the manifest (BL-3 revise).

**Rationale.**
- Cryptographically auditable: any historical committee verifiable by anyone with the deployment manifest.
- Self-contained per shard: no cross-shard coordination needed for committee rotation.
- Composes with v2.10 epoch-boundary DKG (FROST-Ed25519) — committee rotation already happens at epoch boundary; the log just records what's already deterministically derived.

### Q4: Cross-shard receipts — Merkle inclusion proofs

**Decision: cross-shard receipts carry Merkle inclusion proofs against the source shard's state_root at receipt-emission height; receiver validates via locally-maintained light-client header for the source shard.**

```
CrossShardReceipt {
    source_shard:        ShardId
    dest_shard:          ShardId
    source_height:       u64        // height at which receipt was emitted on source
    receipt_payload:     bytes      // existing receipt content (account, amount, etc.)
    inclusion_proof:     MerkleProof // proof that receipt is in source_state_root @ source_height
    receipt_id:          Hash       // globally-unique ID for dedup
}
```

**Validation by receiver shard.** When CrossShardReceipt arrives:
1. Look up source shard's light-client header at `source_height` in the local light-client header chain.
2. If not present, fetch from source shard's gossip peers (lazy-load).
3. Verify `inclusion_proof` against the header's `state_root`.
4. Verify the source committee signature on the header against the source shard's committee log at `source_height`'s epoch.
5. If all verifications pass, dedup against `applied_inbound_receipts_` by `receipt_id`, then apply.

**Receipt-id format.** `receipt_id = SHA256("DTM-RECEIPT" || source_shard || dest_shard || source_height || nonce_within_block: u32)`. `nonce_within_block` pinned at u32 (BL-4 revise) — 4B receipts per shard per block, effectively unbounded for any realistic workload. Globally unique by construction; survives the beacon-relay-removal that breaks the v1.x receipt-ID assumption (which relied on beacon-assigned ordering).

**Rationale.**
- Receiver doesn't trust source's word — verifies cryptographically.
- Lazy fetching of source headers means dormant shard pairs incur no maintenance cost.
- Reuses v2.1 state Merkle root + v2.2 light-client proof infrastructure already in tree.

### Q5: Decentralized merge-detection — per-shard SHARD_TIP observation

**Decision: each shard observes neighboring shard's SHARD_TIP via light-client header sync; triggers MERGE_BEGIN locally when observation window shows partner below quorum.**

Each shard maintains a periodic SHARD_TIP heartbeat — emitted every block, carrying current eligible-validator count, height, and committee signature. Neighboring shards observe SHARD_TIPs via the same light-client header-sync infrastructure used for cross-shard receipts.

**Trigger logic** (per shard, observing partner shard S):
- If S has not emitted a valid SHARD_TIP within `merge_threshold_blocks` (default 100), OR
- If S's last SHARD_TIP shows `eligible_in_region(S) < 2K`,

then this shard locally emits `MERGE_BEGIN(target=S)` in its next block. The MERGE_BEGIN is K-of-K signed by this shard's current committee.

**Coordination.** Multiple shards may observe S's silence simultaneously and emit overlapping MERGE_BEGINs. Resolution rule: the modular-neighbor shard (`T = (S+1) mod num_shards`, per the established R4 modular-merge pattern) is the canonical merge target; other shards' MERGE_BEGINs are advisory and discarded. T's MERGE_BEGIN goes into effect at `effective_height = current + merge_grace_blocks`.

**Adversary tolerance.** Adopts Merritt's Mutually Verified Election ("Elections in the Presence of Faults," PODC 1984). Each shard `i` has deterministic j-witnesses `(i+1)..(i+k+j) mod num_shards` for j = 1..k. Heartbeat absence claims propagate through witnesses; merge fires only when claim collects k-affidavits. Tolerates `k = manifest.merritt_k` Byzantine shards given `num_shards > k(k+1)` (manifest-validation invariant, BL-5 revise). Reference points: k=1 needs `num_shards >= 3` (v1.x default); k=2 needs `num_shards >= 7`; k=3 needs `num_shards >= 13`. Operator picks k per deployment threat model.

**Rationale.**
- Removes beacon's role as merge coordinator.
- Reuses already-shipped R4 modular-merge mechanism (just replacing the trigger source from beacon to peer-shard observation).
- Merritt's witness construction gives provable Byzantine tolerance; no new research-grade primitive needed.

### Q6: Cross-shard randomness mixing — per-epoch accumulator

**Decision: cross-shard randomness aggregation via per-epoch accumulator over each shard's threshold-signature output.**

At each epoch boundary, every shard's K-of-K committee produces an epoch-end threshold signature (via v2.10 FROST-Ed25519 DKG) over `("DTM-EPOCH-RAND" || epoch || shard_id || shard_state_root)`. These per-shard threshold signatures are gossiped across the deployment.

The deployment-wide randomness for epoch N+1 is the accumulator:

```
deployment_rand_N+1 = SHA256(
    "DTM-MIX-V1"
    || sort_by_shard_id(threshold_sig_0_N, threshold_sig_1_N, …, threshold_sig_{S-1}_N)
)
```

Per-shard committee selection for epoch N+1 mixes `deployment_rand_N+1` with the shard's own commit-reveal output via XOR. Result: committee selection depends on BOTH this shard's current epoch AND every other shard's previous epoch — biasing committee selection requires controlling this shard AND every other shard in the deployment, simultaneously, before the epoch boundary.

**Late-shard handling.** If some shards haven't emitted their epoch-N threshold signature within `manifest.epoch_boundary_cutoff_blocks` of the epoch boundary, deployment_rand_N+1 is computed over the subset that did. Each shard records which subset was used in its block header (via a new `deployment_rand_subset` field), so light clients can verify the derivation deterministically. Cutoff window is operator-tunable per deployment via the manifest (BL-6 revise) — shorter window favors liveness, longer window favors complete-shard participation.

**Rationale.**
- Removes beacon as randomness aggregator.
- Reuses v2.10 threshold-signature infrastructure already in tree.
- Bias-resistance is structurally stronger than current beacon-mediated mixing (requires controlling more parties).
- Late-shard handling preserves liveness — randomness doesn't stall waiting for a slow shard.

---

## 3. Wire-format extensions

### 3.1 New on-chain block fields (per shard)

```
Block {
    ...existing fields...,
    shard_tip:                  ShardTipPayload          // periodic heartbeat (per-block)
    committee_log_entry:        Option<CommitteeRotation> // only at epoch boundaries
    deployment_rand_subset:     Vec<ShardId>             // shards contributing to epoch's rand
    merge_observations:         Vec<MergeObservation>    // observed-silence claims for peer shards
}
```

### 3.2 New gossip-layer message types

- `MANIFEST_UPDATE` — proposed new deployment manifest with co-signing collection state
- `MANIFEST_REPLICATE` — gossip-replicated current manifest for new joiners / restarted nodes
- `LIGHT_CLIENT_HEADER_REQUEST` / `LIGHT_CLIENT_HEADER_RESPONSE` — lazy-fetch of source shard's headers when receipt arrives from previously-dormant pair
- `SHARD_TIP_BROADCAST` — periodic heartbeat for merge-detection
- `CROSS_SHARD_RECEIPT` (existing, extended) — adds `inclusion_proof` + `receipt_id` fields
- `EPOCH_RAND_THRESHOLD_SIG` — per-shard epoch-end threshold signature for deployment rand
- `MERGE_OBSERVATION` — Merritt-witness affidavit for absent-heartbeat claim

### 3.3 New tx type

- `MANIFEST_UPDATE` — on-chain commitment of approved manifest mutation (after gossip-layer co-signing completes)

### 3.4 New chain_role

- `AUTONOMOUS_SHARD` — new chain_role distinguishing beaconless shards from beacon-bound ones. Existing `SHARD` role continues to interoperate with `BEACON` during migration; `AUTONOMOUS_SHARD` operates independently.

---

## 4. Implementation work units

### 4.1 Light-client mesh infrastructure (~3-4 weeks)

- Per-shard light-client header storage + lazy fetch on receipt arrival.
- `LIGHT_CLIENT_HEADER_REQUEST` / `_RESPONSE` gossip handlers.
- Eviction policy (per-source, `LIGHT_CLIENT_RETENTION_BLOCKS` window).
- Light-client header chain validation (signature-chain check against committee log).

### 4.2 Deployment manifest infrastructure (~3-4 weeks)

- Manifest data structure + serialization.
- Gossip-layer replication (`MANIFEST_REPLICATE`).
- Mutation path: `MANIFEST_UPDATE` tx, co-signing collection, flag-day activation.
- Manifest-verification logic (any node verifies against any peer).
- **Q2.1 manifest validity (~1 week):** `manifest_validity.hpp` compile-time thresholds; `validate_manifest()` function with hard (consensus-enforced) and soft (warning-only) tiers; `MANIFEST_UPDATE` apply-path integration; manifest-construction-tool integration with `--acknowledge-soft-violations` override flag; unit tests covering each invariant violation case.

### 4.3 Committee-rotation log (~1-2 weeks)

- Per-shard log data structure + state_root commitment.
- Per-epoch entry creation (at v2.10 DKG ceremony completion).
- Light-client traversal logic.
- Snapshot compaction (every EPOCH_SNAPSHOT_INTERVAL epochs).

### 4.4 Cross-shard receipt with Merkle proofs (~2-3 weeks)

- Receipt format extension (`inclusion_proof` + `receipt_id`).
- Source-side proof generation at receipt-emission time.
- Receiver-side proof verification via light-client header.
- Migration path: existing beacon-relay receipts continue to validate during transition.

### 4.5 Decentralized merge-detection (~1-2 weeks)

- SHARD_TIP heartbeat broadcast (per block).
- Per-shard observation logic with Merritt-witness affidavit collection.
- Local MERGE_BEGIN trigger when threshold met.
- Coordination rule (modular-neighbor target is canonical).

### 4.6 Cross-shard randomness aggregation (~1-2 weeks)

- Per-shard epoch-end threshold signature emission (uses v2.10 FROST-Ed25519).
- Gossip replication of per-shard signatures.
- Accumulator computation at epoch boundary.
- Late-shard handling (subset recording in block header).

### 4.7 `AUTONOMOUS_SHARD` chain_role + interop (~1 week) — REVISED 2026-06-05

**Originally (~1-2 weeks):** chain_role enum + interop logic + flag-day migration tooling (beacon-bound → beaconless conversion) + per-deployment operator migration runbook.

**Revised under no-migrations:** the flag-day conversion path is structurally forbidden per memory `dlt-no-migrations-constraint`. Operators who deploy beacon-bound at v1.0 launch cannot later migrate to beaconless via chain mechanism; their options are stay beacon-bound forever OR operationally redeploy as a new beaconless chain (application-level account transfer; not chain-level). What remains:

- New `chain_role` enum value (`AUTONOMOUS_SHARD`) (~1-2 days) — needed for v1.0 launch where both deployment types coexist
- Interop logic between existing `SHARD` / `BEACON` roles and `AUTONOMOUS_SHARD` at v1.0 launch (~3-5 days) — cross-deployment operation; each shard knows its own role from genesis

**Removed:** flag-day conversion tooling (~3-5 days dead), per-deployment migration runbook (~1-2 days dead).

**Operational guidance** (replacing the removed migration runbook): operators choose deployment type (beacon-bound or beaconless) at genesis. Choice is permanent for that chain's lifetime under no-migrations. To switch to the other model, operator stands up a new chain and migrates via application-level account-balance transfer — documented in operator-facing materials, not in chain-level migration tooling.

**Net effort reduction:** ~5-7 days deleted from Bundle 5 critical path.

### 4.8 Tests + docs (~2 weeks)

- Per-component unit tests via deterministic-simulation framework (S-035 Option 2 — recommended as Beaconless v2 prerequisite).
- Integration tests for full beaconless deployment (boot 3-5 autonomous shards, verify cross-shard flow without beacon).
- Migration test (beacon-bound → beaconless flag-day).
- Documentation refresh: PROTOCOL.md, README §sharding, V2-DESIGN.md cross-references.

---

## 5. Total estimated cost

| Sub-component | Effort |
|---|---|
| Light-client mesh infrastructure | 3-4 weeks |
| Deployment manifest infrastructure (incl. Q2.1 validity ~1w) | 3-4 weeks |
| Committee-rotation log | 1-2 weeks |
| Cross-shard receipt with Merkle proofs | 2-3 weeks |
| Decentralized merge-detection | 1-2 weeks |
| Cross-shard randomness aggregation | 1-2 weeks |
| `AUTONOMOUS_SHARD` chain_role + migration | 1-2 weeks |
| Tests + docs | 2 weeks |
| **Total** | **~3-4 months** |

This is genuinely a multi-month architectural effort — significantly larger than any single v2 + Theme 9 item. Justified by the structural improvements (mutual-distrust completion, horizontal-scale beyond ~50 shards, beacon-operator-burden removal) and by the cascade benefit (composes with v2.23 cross-chain bridge using the same light-client primitive).

**Recommended sequencing.** After v2 + Theme 9 substantially ships. DSF (S-035 Option 2, ~3-4 weeks) should precede Beaconless v2 implementation — the much-larger beaconless surface needs deterministic-simulation testing to catch Byzantine bugs that integration tests can't drive.

---

## 6. Risks and rollback plan

**Risk: Lazy validation eviction creates re-fetch storms.** A shard that suddenly receives receipts from many previously-dormant sources may need to re-fetch many light-client header chains simultaneously, exhausting bandwidth.

*Mitigation.* Eviction-resistant cache for high-traffic pairs. Operational alerting on `light_client_refetch_rate`. Rate-limit re-fetch requests per peer.

**Risk: Manifest update co-signing requires K-of-K from every shard.** A single shard refusing to co-sign blocks the manifest update. Could be used as a deployment-wide veto by a captured shard.

*Mitigation.* Cooldown-based default-accept: if a shard fails to co-sign within `MANIFEST_UPDATE_TIMEOUT_BLOCKS` (default 10000, ~7 hours at tactical), its co-signature requirement is bypassed by deployment-wide governance vote (threshold of K-of-K committees from other shards). Documented as soft-default, operator-tunable.

**Risk: Cross-shard randomness aggregation has subtle bias if late-shard subset is adversarially chosen.** An attacker controlling network timing could selectively delay certain shards' threshold signatures, biasing which subset contributes to deployment_rand.

*Mitigation.* Subset selection is deterministic given the gossip-observed arrival order at epoch boundary — every honest node sees roughly the same arrival order. Subset is recorded in block header for verification. Selective bias requires controlling gossip timing for K-of-K committee of multiple shards simultaneously — same threshold as Byzantine takeover.

**Risk: Migration from beacon-bound to beaconless creates split-brain.** During migration, some shards are still beacon-bound while others are autonomous. Cross-shard receipts may not route correctly.

*Mitigation.* Migration is per-deployment, not per-shard — entire deployment migrates simultaneously at a flag-day epoch boundary. Operator runs migration tooling that coordinates the cut-over. Documented as operator-led process, not gradual rollout.

**Risk: Spec disagreement during review.** Q1 (Option A vs alternatives) is the highest-impact choice. If review prefers Option B (rotating hub) or Option D (sample-and-attest), substantial revision required.

*Mitigation.* Pre-implementation review per §8 below.

**Risk: Operator ships manifest with `merritt_k` violating `num_shards > k(k+1)`.** Deployment silently runs with weaker Byzantine tolerance than claimed (e.g., k=2 with num_shards=4 actually tolerates only k=1). No observable signal until adversarial exploitation; security audit decouples from operational reality.

*Mitigation.* Q2.1 manifest validity: hard invariants consensus-enforced at `MANIFEST_UPDATE` apply path; rejected at validator-level. Manifest-construction tooling also enforces — invalid manifests cannot be built without errors. No operator override path for hard invariants. Soft performance thresholds emit construction-time warnings with `--acknowledge-soft-violations` flag for legitimate experimentation.

**Rollback plan.** If Beaconless v2 ships with a bug discovered after deployment-wide migration:
1. Governance pause across all shards.
2. Revert flag-day; re-deploy beacon for the deployment.
3. Re-attempt Beaconless v2 after bug fix; new flag-day height.
4. Cost: chain re-genesis or large state-replay (operator-coordinated).

---

## 7. What this enables downstream

Beaconless v2 with Option A unlocks:

- **Horizontal scale beyond ~50 shards.** Lazy validation contains O(N²) cost; effective scale ceiling rises from ~50 (beacon-bound) to ~200-500 (light-client mesh with lazy validation).
- **Mutual-distrust completeness.** The beacon is the one remaining single-role component; removing it means Determ's mutual-distrust posture extends to every architectural layer.
- **Reduced operator burden.** Each beaconless deployment doesn't need to run a permanent beacon process. Smaller operational footprint; cheaper to deploy.
- **Composes with v2.23 cross-chain bridge.** Same light-client primitive validates intra-deployment cross-shard receipts AND Determ-to-Determ bridge transfers. Single infrastructure investment, dual use.
- **Compatible with future v2.x DApp routing** (cross-shard DApp message delivery, currently deferred per v2.21+).

---

## 8. Decision review

This spec is recommended to be reviewed before implementation. Reviewers should confirm:

1. **Q1 light-client mesh (Option A)** vs alternatives (rotating hub, accumulator-based, sample-and-attest). Highest-impact choice.
2. **Q2 manifest replication + K-of-K co-signing** for mutations. Accepts the "any single shard can veto" failure mode (mitigated by cooldown-based default-accept).
3. **Q3 committee-rotation log compaction.** EPOCH_SNAPSHOT_INTERVAL = 100 acceptable.
4. **Q4 receipt-id format** (`SHA256("DTM-RECEIPT" || …)`). Globally unique by construction; no collision risk.
5. **Q5 Merritt-witness adversary tolerance.** k=1 with num_shards>=3 acceptable for v2.0; k=2 (requiring num_shards>=7) for high-stakes deployments.
6. **Q6 late-shard randomness handling.** Subset-recording in block header acceptable.
7. **DSF as Beaconless-v2 prerequisite.** Agree that S-035 Option 2 should ship before Beaconless v2 implementation begins.
8. **Sequencing.** Beaconless v2 promotes to **Phase D** (after v2 + Theme 9 ships), not parallel.

Once these are confirmed, implementation can proceed against §4 work units. Estimated 3-4 months from spec-review acceptance, assuming DSF is in place.

---

*End of specification.*
