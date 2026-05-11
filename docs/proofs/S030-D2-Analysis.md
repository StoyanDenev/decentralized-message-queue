# S-030 D2: Block-digest field-coverage analysis

This document is a focused supplementary analysis to FA1 (`Safety.md`). It explains why a naive extension of `compute_block_digest()` is the wrong fix for the D2 dimension of S-030 — even though it looks like a one-line patch — and what the correct fix requires.

The honest version: an in-tree implementation attempt landed, broke the equivocation-slashing regression test, and was reverted. This doc records the reasoning so the next attempt doesn't repeat it.

---

## 1. The D2 gap restated

`Block::signing_bytes()` (used by `Block::compute_hash()` which feeds `prev_hash`) covers every canonical block field. The chain's `prev_hash` chain therefore binds the full block content at block N+1 — anyone applying block N+1 implicitly authenticates block N's full content via its hash.

`compute_block_digest()` (what the K-of-K committee signs in Phase 2) covers a narrower subset:

| Field | In `signing_bytes` | In `compute_block_digest` (today) |
|---|---|---|
| `index`, `prev_hash`, `tx_root`, `delay_seed` | ✓ | ✓ |
| `consensus_mode`, `bft_proposer` | ✓ | ✓ |
| `creators`, `creator_tx_lists` | ✓ | ✓ |
| `creator_ed_sigs`, `creator_dh_inputs` | ✓ | ✓ |
| `creator_dh_secrets` (Phase 2 reveals) | ✓ | ✗ (revealed after digest is signed) |
| `delay_output` (Phase 2 derived) | ✓ | ✗ (derived after digest is signed) |
| `cumulative_rand` (Phase 2 derived) | ✓ | ✗ (derived after digest is signed) |
| `timestamp` | ✓ | ✗ |
| `abort_events` | ✓ | ✗ |
| `equivocation_events` | ✓ | ✗ |
| `cross_shard_receipts` | ✓ | ✗ |
| `inbound_receipts` | ✓ | ✗ |
| `partner_subset_hash` | ✓ | ✗ |
| `initial_state` (genesis only) | ✓ | ✗ (genesis is not committee-signed) |

The "✗" rows below the Phase-2 reveal block are the D2 gap. They're part of the canonical block, they affect deterministic apply, but the K signatures don't authenticate them.

Why this matters: two distinct block instances with identical `block_digest` but different `abort_events` (or any other ✗-row field) would both pass K-of-K signature verification. Honest nodes receiving the two instances apply them, diverge in state, and only re-converge one block later when `prev_hash` mismatch surfaces.

Window: one block. Impact: a node stalls until it fetches the canonical version. Not a fork (FA1's "≤ 1 finalized digest per height" still holds — both instances share the same digest), but a state-split with deterministic prev_hash-mediated recovery. Liveness/sync issue dressed in safety-looking clothes.

---

## 2. The naive fix and why it breaks

The obvious patch: extend `compute_block_digest()` to also hash in `abort_events`, `equivocation_events`, `cross_shard_receipts`, `inbound_receipts`, `partner_subset_hash`. Mirror `signing_bytes()`'s serialization exactly. Now K signatures cover everything.

This was implemented and reverted. Failure mode:

**The gossip-async assumption.** Under the current implementation, each committee member assembles a *tentative block body* at Phase 1 → Phase 2 transition. The body includes:

- The union of K Phase-1 `tx_hashes` lists (deterministic from K signed commits → identical across members).
- Plus per-member-locally-chosen contents of pools:
  - `pending_equivocation_evidence_` → `equivocation_events`
  - `pending_inbound_receipts_` → `inbound_receipts`
  - Aggregated `AbortEvents` from local observation → `abort_events`

The pools are gossip-fed. Two committee members may at any instant have different views of these pools — node A has received `ev1` but not `ev2`, node B has both. Their tentative block bodies differ in `equivocation_events`.

Under the **current (✗-row excluded) digest**, this is harmless: both members compute the same `block_digest` (which excludes the differing fields), both sign it, K signatures gather, the block finalizes. Which evidence list actually ends up in the canonical block depends on whoever propagates the body — the implementation has a designated assembler whose body is canonical.

Under the **naive F2-extended digest**, this is fatal: members A and B compute *different* digests because their tentative bodies' evidence lists differ. K signatures fail to gather. The round aborts. BFT escalation eventually fires; if the gossip race recurs, the chain stalls under any nontrivial gossip-induced view drift.

The equivocation-slashing regression test demonstrated this experimentally: under naive F2, the test passed evidence to node1, gossip propagated to nodes 2 and 3, but the round-1 commit window closed before all three had identical pool views. Tentative bodies diverged; signatures didn't gather; no block in [28..60] contained the evidence. Test failed.

---

## 3. The correct F2 design

The fix is structural and requires the same kind of view-reconciliation step Determ already uses for `tx_root`:

### 3.1 What Determ already does for tx_root

- Each member's `ContribMsg` (Phase 1) contains `tx_hashes` — that member's *view* of the mempool.
- Each member signs over `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` — their own view, authenticated.
- At Phase 1 → Phase 2 transition, the K signed commits are gathered. `tx_root` is computed deterministically as the union/sort of the K signed lists. Every honest member computes the same `tx_root`.
- `compute_block_digest()` includes `tx_root` (and `creator_tx_lists` — the K signed lists). K Phase-2 signatures bind the agreed canonical `tx_root`.

This is the gossip-async-safe pattern: members commit to *their views* in Phase 1; canonical reconciliation happens at the boundary; Phase 2 signs the reconciled result.

### 3.2 Extending the pattern to evidence and receipts

For each ✗-row field that has a per-member pool source:

1. **Phase 1**: each member's `ContribMsg` includes a hash (or sorted set of hashes) of their pool view at commit time.
2. **Phase 1 signature**: covers the view-hash (so a member can't equivocate on their view).
3. **Phase 1 → Phase 2 reconciliation**: canonical rule. Options:
   - **Intersection**: only events that ALL K members report end up in the block. Conservative; biased against inclusion under gossip lag.
   - **Union**: all events any member reports end up. Aggressive; biased toward inclusion; may include events some members haven't verified yet.
   - **Threshold**: events reported by ≥ M of K members end up. Tunable middle ground.
4. **Phase 2 signature**: covers the reconciled canonical list (via the extended `compute_block_digest`).
5. **Validator**: reconstructs the canonical list from the K Phase-1 commits and verifies against the block's actual `equivocation_events` etc.

For `partner_subset_hash` (R4 merge), the reconciliation is simpler — it's a single hash value that all committee members at a merged height should compute identically from the merge state. No per-member pool involved.

For `cross_shard_receipts` (emitted by the producing shard) and `inbound_receipts` (consumed by the destination shard), the pool source is also gossip-fed. Same reconciliation pattern applies.

### 3.3 Estimated implementation scope

- **`ContribMsg` extension**: ~40 LOC. Add view-hash fields; update signing-bytes; update verification.
- **Producer-side assembly**: ~80 LOC. Implement the reconciliation rule; compute canonical lists from K Phase-1 commits.
- **Validator-side re-derivation**: ~60 LOC. Mirror the producer's reconciliation to verify the block's lists.
- **`compute_block_digest` extension**: ~30 LOC. Add the reconciled fields.
- **Tests**: 2-3 new regression suites covering the divergent-view convergence scenarios.

Total: ~1-2 days focused implementation. Plus design-decision time for the reconciliation rule (union vs intersection vs threshold).

### 3.4 Why this is properly a v2 scope item

- Wire-format change to `ContribMsg` — bumps the wire version.
- Behavior change for evidence inclusion under gossip lag — changes the practical inclusion latency for evidence and receipts.
- Adds 2-3 new failure modes around view divergence that need their own monitoring.
- The reconciliation-rule choice has economic implications (intersection biases against slashing inclusion, union biases for; both have different attack surfaces).

This is the kind of change that should ride alongside other v2 protocol-evolution items (A9 atomic block apply, F2 binding, post-quantum signatures, light-client headers), not slip into v1.x as a point fix.

---

## 4. Until v2: what holds today

The current `compute_block_digest()` leaves D2 open. The mitigations actually in place:

1. **`prev_hash` chain closes the window at N+1.** The window is one block wide. A node receiving a non-canonical N must re-sync from the canonical chain once N+1 arrives with the mismatched `prev_hash`.

2. **FA1's "≤ 1 finalized digest" still holds.** Both block instances share the same digest. The protocol's stated safety claim is preserved as written; only the implicit "and therefore one block instance" extension is gappy.

3. **D2 requires committee collusion or implementation-level race.** A K-of-K honest committee with synchronous gossip produces a single tentative body per round (the assembler's). The attack requires either (a) committee capture sufficient to mint two distinct K-of-K-signed bodies, or (b) an implementation race where two assemblers each propagate to disjoint subsets. Neither is the threat model FA1 was written against; both are deployment-scope concerns.

4. **The validate path's separate field checks (V10–V13) constrain which `equivocation_events` etc. are *valid*** — even if D2 lets two instances pass, both must satisfy V10–V13. The attacker can't substitute arbitrary fake evidence; they can only choose among valid evidence options.

5. **Equivocation slashing (FA6) catches a committee that does mint two K-of-K-signed blocks at the same height with different digests.** D2's specific case (same digest, different body fields) is harder to detect via slashing because there's only one digest, but the slashing pipeline catches the broader committee-malicious case.

For permissioned / consortium deployments, the residual risk is small. For permissionless deployments wanting to honor the "any single honest validator suffices" claim literally, v2 should ship the structural fix.

---

## 5. The non-fix: timestamp inclusion

A separate question: should `timestamp` be included in `compute_block_digest()`?

Today it isn't. Honest members' local clocks differ within `±5s` (the validator's window). If `timestamp` were in the digest, two members with clocks differing by 200ms would sign different digests. Spurious rounds aborts.

The way to include `timestamp` is to have the assembler propose a specific value at the Phase 1→2 transition and other members verify it's within their `±5s` window before signing. This is doable but interacts with the same view-reconciliation problem above — best handled together.

---

## 6. Why this analysis matters

Recording this carefully because:

1. The naive fix is genuinely tempting — it looks like a 30-line change.
2. The failure mode under naive fix is subtle (gossip-async view divergence) and might not surface in single-host test environments with low-latency gossip.
3. The correct fix is structurally bigger and needs design decisions (reconciliation rule choice) that warrant explicit deliberation, not "let's just patch the digest."
4. Marking S-030 D2 as "Open, fix scoped" rather than "Open, unscoped" is more useful — the next engineer knows what to do.

---

## 7. Cross-references

- `docs/proofs/Safety.md` (FA1) — the FA1 theorem this analysis qualifies.
- `docs/SECURITY.md` S-030 — the original audit finding.
- `docs/WHITEPAPER-v1.x.md` §3 — protocol description, including the commit-reveal that constrains which fields can be in the pre-reveal digest.
- `src/node/producer.cpp::compute_block_digest` — the current implementation with the D2 gap.
- `src/chain/block.cpp::Block::signing_bytes` — the full-coverage hash that `compute_hash` (and hence `prev_hash`) uses.
