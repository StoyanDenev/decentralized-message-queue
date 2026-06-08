> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# S-030 D2: Block-digest field-coverage analysis

This document is a focused supplementary analysis to FA1 (`Safety.md`). It explains why a naive extension of `compute_block_digest()` is the wrong fix for the D2 dimension of S-030 — even though it looks like a one-line patch — and what the correct fix requires.

The honest version: an in-tree implementation attempt landed, broke the equivocation-slashing regression test, and was reverted. This doc records the reasoning so the next attempt doesn't repeat it.

**Status note (updated — D2 now FULLY closed at the digest layer).** D2 is now closed at the consensus layer: `compute_block_digest` binds every apply-affecting field — the three pool-fed dimensions via v2.7 F2 view reconciliation (commits `a727cb2` / `48c4b45`, §1 items 7+8), `partner_subset_hash` directly (commit `8585a50`, item 9), and `timestamp` via deterministic median reconciliation (commit `f99eeb8`, item 10 + §5). The fields still absent from the digest are not independent divergence vectors (`cross_shard_receipts` derived from `tx_root`; the Phase-2-reveal fields pinned by the digest-bound `creator_dh_inputs`/`delay_seed`; `state_root` bound via `signing_bytes`). S-033's apply-layer state_root gate (Option 4; producer-side wiring via S-038) is retained beneath as belt-and-suspenders — see §3.5 for the apply-layer-vs-consensus-layer comparison; the "After v2.7 F2" column there is now the shipped reality. This doc was originally written before S-033 shipped and before the F2 / partner / timestamp digest bindings landed; sections below reflect the current fully-closed state.

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
| `timestamp` | ✓ | ✓ (conditional: bound when the block carries `creator_proposer_times`, i.e. went through median reconciliation — commit `f99eeb8`, §5) |
| `abort_events` | ✓ | ✓ (conditional: bound when the block carries a non-zero abort view root — v2.7 F2, commit `48c4b45`, see note) |
| `equivocation_events` | ✓ | ✓ (conditional: bound when the block carries a non-zero eq view root — v2.7 F2, commit `48c4b45`, see note) |
| `cross_shard_receipts` | ✓ | ✗ (deterministically derived from the committee tx set, which `tx_root` + `creator_tx_lists` already bind) |
| `inbound_receipts` | ✓ | ✓ (conditional: bound when non-empty — commit `a727cb2`, see note) |
| `partner_subset_hash` | ✓ (conditional: non-zero only) | ✓ (conditional: bound when non-zero — deterministic from merge state per §3.2; commit `8585a50`, see note) |
| `state_root` (S-033) | ✓ (conditional: non-zero only) | ✗ |
| `initial_state` (genesis only) | ✓ | ✗ (genesis is not committee-signed) |

The "✗" rows below the Phase-2 reveal block are the D2 gap. They're part of the canonical block, they affect deterministic apply, but the K signatures don't authenticate them.

> **Note (`inbound_receipts` now bound — commit `a727cb2`).** The v2.7 F2 inbound
> dimension closed this row directly: `compute_block_digest` appends a root over the
> sorted `hash_cross_shard_receipt` keys of `inbound_receipts` when the block carries
> any (skipped when empty, preserving the v1 byte-identical digest for non-cross-shard
> blocks). This is the safe specialization of the "naive extension" warned against in
> §2 — it does NOT reintroduce the gossip-async divergence, because by the time the
> producer assembles `inbound_receipts` the set is already the deterministic committee-
> wide intersection (F2 sites 1+3, `reconcile_intersection` over the committee's
> Phase-1-committed views), so all honest assemblers digest the identical set.
>
> **Note (`equivocation_events` / `abort_events` now bound — commit `48c4b45`).** The
> v2.7 F2 eq/abort dimension closed these two rows the same way, with the **UNION**
> rule (F2-SPEC §Q1) instead of intersection: each member commits its eq/abort pool
> view in Phase-1, `build_body` bakes the assembler's pool restricted to the
> committee-wide `reconcile_union`, and `compute_block_digest` binds the reconciled
> sets (gated on a non-zero per-creator view root — the JSON-stable signal that the
> block went through F2 reconciliation; non-F2 blocks keep the v1 digest). The
> validator (`check_eqabort_reconciliation`) enforces block-evidence ⊆ union. UNION is
> safe to digest-bind for the same reason intersection is: `reconcile_union` is a pure
> function of the K signed Phase-1 commits, computed before digesting. Membership is
> SUBSET (not exact-cardinality) because the event hashes include observer-dependent
> forensic fields; see `EqAbortViewDigestExtension.md`. `cross_shard_receipts` is
> deterministically derived from the committee tx set (already bound via `tx_root`);
> `partner_subset_hash` is now bound (note below) and `timestamp` is now bound
> via median reconciliation (§5, commit `f99eeb8`), so NO ✗ rows remain.
>
> **Note (`partner_subset_hash` now bound — commit `8585a50`).** The R4/R7
> merged-signing partner-subset commitment is now appended to `compute_block_digest`
> when non-zero, mirroring the `signing_bytes` conditional binding (block.cpp:323).
> Unlike the three pool-fed rows above, this needed no view-reconciliation: per §3.2,
> `partner_subset_hash` is DETERMINISTIC — every committee member at a merged height
> computes the identical value from the merge state, so binding it raw cannot
> reintroduce the gossip-async digest divergence §2 warns against. The conditional
> gate keeps every non-merged block byte-identical to the v1 digest. The light client
> mirrors the same append (`light/verify.cpp`); the field survives the `rpc_headers`
> strip (kept alongside `state_root`), so header-only sync stays sound for merged-but-
> non-F2 blocks. `timestamp` is now bound too via median reconciliation (§5), so
> no S-030-D2 digest ✗ rows remain.

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

### 3.5 The other closure path: S-033 state_root binding (shipped, partial)

After this analysis was written, S-033 shipped (Merkle root over canonical state, bound into `signing_bytes` conditionally). It closes D2 by a different mechanism: not by extending `compute_block_digest` to cover the ✗-row fields, but by adding a NEW field (`state_root`) whose value depends transitively on every apply-affecting field. **S-038 (later same session)** wired the producer's `Node::try_finalize_round` to populate `body.state_root` via a tentative-chain dry-run before broadcast — pre-S-038 the gate at `chain.cpp::apply_transactions` short-circuited because every gossiped block carried `state_root = 0` (the backward-compat shim). Post-S-038, the gate actually fires on production blocks; the S-033 closure is genuine end-to-end rather than dormant infrastructure.

**Mechanism.** At apply time, the validator computes `state_root = MerkleRoot(canonical_state)` over the post-apply state and rejects if the block's claimed `state_root` doesn't match. Because the apply path is deterministic, only one canonical state_root exists per (starting state, applied block) pair. Two block instances with differing ✗-row fields produce different post-apply states, hence different canonical state_roots — at most one matches the validator's computation.

**Effect.**
- Two K-of-K-signed block instances can both exist on the wire (signatures cover `compute_block_digest`, which still doesn't bind the ✗-row fields).
- Both pass committee-signature verification.
- One fails apply-time state_root check; the other passes. Honest nodes converge on the passing one.
- A node that received the wrong instance loud-fails at apply (loud diagnostic with byte-precision state_root mismatch); the operator resyncs the canonical block from peers.

**Closure scope.**

| Property | Pre-S-033 | Post-S-033 (data layer, S-038 pending) | Post-S-033 + S-038 (apply gate firing) | After v2.7 F2 |
|---|---|---|---|---|
| Two divergent K-of-K-signed instances can be minted | ✓ | ✓ | ✓ | ✗ |
| Both instances pass signature verification | ✓ | ✓ | ✓ | ✗ |
| Both instances pass apply | ✓ | ✓ (gate skipped — state_root=0) | ✗ (one rejects) | n/a (only one is signed) |
| State divergence between honest nodes | up to 1 block | up to 1 block (gate dormant) | 0 blocks (apply-time detection) | 0 blocks |
| Recovery window | next block's prev_hash | next block's prev_hash | apply-time loud-fail + resync | n/a |

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

7. **The inbound dimension's consensus-layer fix is now SHIPPED (commit `a727cb2`).** For `inbound_receipts` specifically, the structural F2 closure is no longer pending: the admitted set is the deterministic committee-wide intersection (F2 sites 1+3), and `compute_block_digest` now binds that set directly (the conditional ✓ row in §1). So even the two-instance gossip-layer attack is closed for inbound — two distinct admitted inbound sets cannot both collect K-of-K signatures, because they yield different digests. The remaining dimensions (`equivocation_events` / `abort_events` / `cross_shard_receipts` / `partner_subset_hash`) still rely on the apply-layer S-033 closure pending the same treatment.

8. **The equivocation/abort dimensions' consensus-layer fix is now SHIPPED (commit `48c4b45`).** Same structural closure as inbound (item 7) but with the UNION rule: `equivocation_events` + `abort_events` are bound into `compute_block_digest` as the committee-wide `reconcile_union` of the members' committed Phase-1 views, and the validator enforces block-evidence ⊆ union. So the two-instance gossip-layer attack is closed for all three pool-fed dimensions (inbound + eq + abort). The remaining ✗ rows are `cross_shard_receipts` (deterministically derived from the bound tx set) and `timestamp` (the §5 non-fix) — neither an independently-gossiped committee-view pool; `partner_subset_hash` is now bound too (item 9).

9. **The `partner_subset_hash` dimension is now SHIPPED (commit `8585a50`).** Distinct from items 7+8: this one needed NO view-reconciliation. `partner_subset_hash` is the R4/R7 merged-signing partner-subset commitment, and it is DETERMINISTIC — every committee member at a merged height computes the identical value from the merge state (§3.2) — so `compute_block_digest` binds it raw (conditional on non-zero, mirroring `signing_bytes` at block.cpp:323) with no gossip-async divergence risk. A relayer that strips/alters it after the K-of-K Phase-2 signature now breaks digest verification. The light client mirrors the append (`light/verify.cpp`); the field survives the `rpc_headers` strip, so header-only sync stays sound for merged-but-non-F2 blocks.

10. **The `timestamp` dimension is now SHIPPED (commit `f99eeb8`).** The last ✗ row, closed via the median reconciliation in §5 (Phase-1 `proposer_time` commit → deterministic lower-median at `build_body` → digest binding → validator re-derivation). With this, **every S-030-D2 digest dimension is closed**: the three pool-fed views via v2.7 F2 (items 7+8), `partner_subset_hash` directly (item 9), and `timestamp` via median reconciliation (this item). `cross_shard_receipts` is the only ✗ that stays ✗ — but it is deterministically derived from the committee tx set (already bound via `tx_root` + `creator_tx_lists`), not an independent divergence vector. The consensus-layer D2 closure is therefore complete: no two distinct block instances can both collect K-of-K signatures.

For permissioned / consortium deployments, S-033's partial closure is the practical solution. For permissionless deployments wanting to honor the "any single honest validator suffices" claim literally (and to prevent two-instance gossip-layer attacks even when both fail apply on honest nodes), v2.7 F2 view reconciliation ships the consensus-layer structural fix — now live for all three pool-fed dimensions (inbound + equivocation + abort) per items 7 + 8.

---

## 5. Timestamp inclusion — the "non-fix" that became the fix (SHIPPED, commit `f99eeb8`)

A separate question: should `timestamp` be included in `compute_block_digest()`?

**The original obstacle (why a RAW append is wrong).** Honest members' local clocks differ within `±30s` (the validator's window). If the raw `timestamp` were in the digest, two members with clocks differing by 200ms would sign different digests → spurious round aborts. So `timestamp` cannot be hashed in the way `tx_root` is.

**The fix (shipped).** The same Phase-1-commit-then-reconcile pattern that closes the pool-fed dimensions (§3) applies — just with a numeric median instead of a set union/intersection:

1. **Phase-1 commit.** Each member's `ContribMsg` carries `proposer_time` = its local `now_unix()`, bound into `make_contrib_commitment` (behind the `DTM-TS-v1` domain separator, only when non-zero — so legacy/test contribs keep the byte-identical v1 commitment). The Phase-1 Ed25519 signature authenticates the committed time, so a member cannot equivocate on the time it contributes to the median.
2. **Reconcile at the Phase 1→2 boundary.** `build_body` sets the canonical `b.timestamp = reconcile_median_time(creator_proposer_times)` — the deterministic **lower-median** `sorted[(K-1)/2]` of the K committed times. This is a pure function of the K signed Phase-1 commits, so every honest assembler computes the identical value (no gossip-async divergence). Under `f < K/3` the lower-median is honest-flanked (the order statistic at index `(K-1)/2` lies within the honest-clock spread), so a Byzantine minority cannot bias it — the standard BFT-time median.
3. **Digest binding.** `compute_block_digest` appends `b.timestamp` when `creator_proposer_times` is non-empty (the activation signal — a legacy block keeps the v1 digest). Field order: inbound, eq, abort, `partner_subset_hash`, `timestamp`.
4. **Validator.** `check_creator_commits` recomputes each creator's Phase-1 commit WITH its `proposer_time` (so the per-creator time is sig-authenticated). `check_timestamp` re-derives the median from `creator_proposer_times` and rejects on `size != creators`, any zero entry, or `timestamp != median`; the existing `±30s` wall-clock bound is retained as a liveness sanity (the median is ~`now`, so it stays in-window).
5. **Light client.** `light_compute_block_digest` mirrors the append. `creator_proposer_times` survives the `rpc_headers` strip (kept like `state_root` / `partner_subset_hash`), so header-only sync stays sound — a daemon that tampers `b.timestamp` post-signing fails the light sig check.

Backward-compat: when any committed `proposer_time` is zero (pre-activation / test), `build_body` drops `creator_proposer_times` and falls back to the assembler wall-clock, so the block keeps its byte-identical v1 shape and `timestamp` is NOT digest-bound. Regression: `determ test-timestamp-reconciliation` (16 assertions) + FAST=1 (every non-reconciled block byte-identical). With this, **all S-030-D2 digest ✗ rows are closed** (`cross_shard_receipts` remains derived-not-independent via `tx_root`).

---

## 6. Why this analysis matters

Recording this carefully because:

1. The naive fix is genuinely tempting — it looks like a 30-line change.
2. The failure mode under naive fix is subtle (gossip-async view divergence) and might not surface in single-host test environments with low-latency gossip.
3. The correct fix (v2.7 F2) is structurally bigger and needs design decisions (reconciliation rule choice, per-field semantics, view-hash format) that warrant explicit deliberation, not "let's just patch the digest." See `F2-SPEC.md` for the formal resolution of all 9 historical open design questions (per-field union/intersection rules with V10/V11 verifiability constraints, Merkle-root wire format, Phase-2 signature semantics over reconciled canonical lists, flag-day migration plan). Implementation should proceed against F2-SPEC.md's §3 work units after the pre-implementation review of §6.
4. S-033's state_root binding closed most of the practical D2 surface via a different mechanism (apply-layer rather than consensus-layer). Understanding this dual-path closure is essential when triaging future S-030-class findings: the question "is the digest closed?" is distinct from "is two-instance divergence prevented?", and the answer depends on which mechanism you're asking about.
5. S-030 D2 is now markable as "**Closed at the consensus layer**" — `compute_block_digest` binds every apply-affecting field (pool-fed dims via v2.7 F2, `partner_subset_hash` directly, `timestamp` via median reconciliation), the remaining digest-excluded fields are deterministically pinned by digest-bound commitments, and the S-033 apply-layer gate is retained beneath as belt-and-suspenders. (The earlier "Partially mitigated (S-033 apply-layer) + F2 implementation pending" framing is superseded; current state, design state, and implementation state are all shipped.)

---

## 7. Cross-references

- `docs/proofs/Safety.md` (FA1) — the FA1 theorem this analysis qualifies.
- `docs/SECURITY.md` S-030 — the original audit finding.
- `docs/WHITEPAPER-v1.x.md` §3 — protocol description, including the commit-reveal that constrains which fields can be in the pre-reveal digest.
- `src/node/producer.cpp::compute_block_digest` — the current implementation with the D2 gap.
- `src/chain/block.cpp::Block::signing_bytes` — the full-coverage hash that `compute_hash` (and hence `prev_hash`) uses.
