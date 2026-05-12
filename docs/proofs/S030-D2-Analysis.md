# S-030 D2: Block-digest field-coverage analysis

This document is a focused supplementary analysis to FA1 (`Safety.md`). It explains why a naive extension of `compute_block_digest()` is the wrong fix for the D2 dimension of S-030 — even though it looks like a one-line patch — and what the correct fix requires.

The honest version: an in-tree implementation attempt landed, broke the equivocation-slashing regression test, and was reverted. This doc records the reasoning so the next attempt doesn't repeat it.

**Status note.** D2 is currently PARTIALLY closed via S-033's state_root binding (Option 4 in `SECURITY.md` S-030 resolution table). See §3.5 below for the comparison between the two closure paths. v2.7 F2 view reconciliation remains the planned full closure (Option 5). This doc was originally written before S-033 shipped; sections below have been updated to reflect the current state.

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
| `partner_subset_hash` | ✓ (conditional: non-zero only) | ✗ |
| `state_root` (S-033) | ✓ (conditional: non-zero only) | ✗ |
| `initial_state` (genesis only) | ✓ | ✗ (genesis is not committee-signed) |

The "✗" rows below the Phase-2 reveal block are the D2 gap. They're part of the canonical block, they affect deterministic apply, but the K signatures don't authenticate them.

**Conditional binding note.** `partner_subset_hash` and `state_root` are bound into `signing_bytes` only when their value is non-zero — a backward-compat shim that preserves byte-identical hashes for pre-feature blocks. On a freshly-deployed chain pre-S-033 (zero state_root on every block), the conditional binding contributes nothing; D2 is fully open. On a post-S-033 chain where the producer auto-populates state_root, the binding is active on every block, and S-033's indirect closure (§3.5) is in effect.

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

### 3.5 The other closure path: S-033 state_root binding (already shipped, partial)

After this analysis was written, S-033 shipped (Merkle root over canonical state, bound into `signing_bytes` conditionally). It closes D2 by a different mechanism: not by extending `compute_block_digest` to cover the ✗-row fields, but by adding a NEW field (`state_root`) whose value depends transitively on every apply-affecting field.

**Mechanism.** At apply time, the validator computes `state_root = MerkleRoot(canonical_state)` over the post-apply state and rejects if the block's claimed `state_root` doesn't match. Because the apply path is deterministic, only one canonical state_root exists per (starting state, applied block) pair. Two block instances with differing ✗-row fields produce different post-apply states, hence different canonical state_roots — at most one matches the validator's computation.

**Effect.**
- Two K-of-K-signed block instances can both exist on the wire (signatures cover `compute_block_digest`, which still doesn't bind the ✗-row fields).
- Both pass committee-signature verification.
- One fails apply-time state_root check; the other passes. Honest nodes converge on the passing one.
- A node that received the wrong instance loud-fails at apply (loud diagnostic with byte-precision state_root mismatch); the operator resyncs the canonical block from peers.

**Closure scope.**

| Property | Pre-S-033 | Post-S-033 | After v2.7 F2 |
|---|---|---|---|
| Two divergent K-of-K-signed instances can be minted | ✓ | ✓ | ✗ |
| Both instances pass signature verification | ✓ | ✓ | ✗ |
| Both instances pass apply | ✓ | ✗ (one rejects) | n/a (only one is signed) |
| State divergence between honest nodes | up to 1 block | 0 blocks (apply-time detection) | 0 blocks |
| Recovery window | next block's prev_hash | apply-time loud-fail + resync | n/a |

**Why this is "partial" closure.** S-033 ensures divergent state cannot apply on an honest node. It does NOT prevent two committee-signed instances from circulating on the gossip layer — they merely fail apply-time verification on whichever instance is non-canonical. The structural claim "≤ 1 finalized block instance per height" (Safety.md §5.3) is preserved at the apply layer; the literal "≤ 1 valid K-of-K signature gathering per height" requires v2.7's consensus-layer fix.

**Threat model implications.**
- **Honest majority committee:** S-033 is functionally complete. The honest assembler produces one canonical body; gossip distributes it; apply succeeds. No two-instance scenario arises.
- **Single-instance malicious assembler:** Manipulates ✗-row fields, produces a single block instance. K-of-K signatures gather. Apply fails at honest nodes because the manipulated fields yield non-canonical post-apply state, hence wrong state_root. Block rejected; assembler's effort wasted.
- **Two-instance fully-Byzantine committee:** Mints two distinct instances with different ✗-row fields, both K-of-K-signed. Both circulate. Apply picks one. State convergence happens via apply-time selection rather than at signature gathering. This is the residual gap v2.7 closes.

**Comparison with v2.7 F2:** F2 closes at the consensus layer (signatures can only gather around one view via Phase-1 reconciliation). S-033 closes at the apply layer (whichever signed body the network agrees on, only one apply-validates). For permissionless deployments wanting the literal property that "no two K-of-K-signed bodies can ever exist for the same height," v2.7 is the structural fix. For permissioned/consortium deployments where the threat model excludes "two-instance fully-Byzantine committees," S-033 is functionally equivalent.

### 3.4 Why this is properly a v2 scope item

- Wire-format change to `ContribMsg` — bumps the wire version.
- Behavior change for evidence inclusion under gossip lag — changes the practical inclusion latency for evidence and receipts.
- Adds 2-3 new failure modes around view divergence that need their own monitoring.
- The reconciliation-rule choice has economic implications (intersection biases against slashing inclusion, union biases for; both have different attack surfaces).

This is the kind of change that should ride alongside other v2 protocol-evolution items (A9 atomic block apply, F2 binding, post-quantum signatures, light-client headers), not slip into v1.x as a point fix.

---

## 4. Until v2.7 F2: what holds today

The current `compute_block_digest()` still doesn't cover the ✗-row fields — the consensus-layer D2 gap is structurally open. But the chain has acquired several apply-layer and protocol-layer mitigations that close most of the practical attack surface.

1. **S-033 state_root binding (strongest current mitigation, partial closure).** The validator's apply-time `compute_state_root() != b.state_root` check enforces that ✗-row fields produce a canonical post-apply state. Divergent block instances cannot both apply on honest nodes — at most one matches the validator's computed root; the other rejects loudly. State divergence between honest nodes narrows from "one block wide" to "zero blocks (detected at apply)." See §3.5 for the full comparison.

2. **`prev_hash` chain closes the window at N+1 (pre-S-033 mitigation, now redundant).** Before S-033, the window was one block wide: a node receiving a non-canonical N would re-sync once N+1 arrives with a mismatched `prev_hash`. Post-S-033, the apply-time check fires immediately at N; this mechanism is no longer load-bearing but remains as a belt-and-suspenders backup if state_root is somehow zero (pre-S-033 blocks or feature-toggled off).

3. **FA1's "≤ 1 finalized digest" still holds.** Both block instances share the same digest. The protocol's stated safety claim is preserved as written; only the implicit "and therefore one block instance" extension carries the documented footnote (Safety.md §5.3 — and S-033 narrows the residual gap to "two instances can exist but only one apply-validates").

4. **D2 requires committee collusion or implementation-level race.** A K-of-K honest committee with synchronous gossip produces a single tentative body per round (the assembler's). The attack requires either (a) committee capture sufficient to mint two distinct K-of-K-signed bodies, or (b) an implementation race where two assemblers each propagate to disjoint subsets. Neither is the threat model FA1 was written against; both are deployment-scope concerns.

5. **The validate path's separate field checks (V10–V13) constrain which `equivocation_events` etc. are *valid*** — even if D2 lets two instances pass committee signatures, both must satisfy V10–V13. The attacker can't substitute arbitrary fake evidence; they can only choose among valid evidence options.

6. **Equivocation slashing (FA6) catches a committee that does mint two K-of-K-signed blocks at the same height with different digests.** D2's specific case (same digest, different body fields) is harder to detect via slashing because there's only one digest, but the slashing pipeline catches the broader committee-malicious case.

For permissioned / consortium deployments, S-033's partial closure is the practical solution. For permissionless deployments wanting to honor the "any single honest validator suffices" claim literally (and to prevent two-instance gossip-layer attacks even when both fail apply on honest nodes), v2.7 F2 view reconciliation ships the consensus-layer structural fix.

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
3. The correct fix (v2.7 F2) is structurally bigger and needs design decisions (reconciliation rule choice, per-field semantics, view-hash format) that warrant explicit deliberation, not "let's just patch the digest." See `F2-SPEC.md` for the design-decision specification that should precede any v2.7 implementation attempt.
4. S-033's state_root binding closed most of the practical D2 surface via a different mechanism (apply-layer rather than consensus-layer). Understanding this dual-path closure is essential when triaging future S-030-class findings: the question "is the digest closed?" is distinct from "is two-instance divergence prevented?", and the answer depends on which mechanism you're asking about.
5. Marking S-030 D2 as "Partially mitigated (S-033) + v2.7 F2 planned for full closure" is more useful than the previous "Open, fix scoped" framing — current and planned status are both pinned.

---

## 7. Cross-references

- `docs/proofs/Safety.md` (FA1) — the FA1 theorem this analysis qualifies.
- `docs/SECURITY.md` S-030 — the original audit finding.
- `docs/WHITEPAPER-v1.x.md` §3 — protocol description, including the commit-reveal that constrains which fields can be in the pre-reveal digest.
- `src/node/producer.cpp::compute_block_digest` — the current implementation with the D2 gap.
- `src/chain/block.cpp::Block::signing_bytes` — the full-coverage hash that `compute_hash` (and hence `prev_hash`) uses.
