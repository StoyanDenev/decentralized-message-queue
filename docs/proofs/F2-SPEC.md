# F2 view reconciliation — design specification

**Status:** specification only. No code. Resolves the 9 open design questions identified in the post-mortem of the prior naive F2 attempt. Implementation should not begin until this document's design choices are reviewed and committed.

**Companion documents:**
- `S030-D2-Analysis.md` — analysis of D2 + why naive F2 broke + S-033 partial closure
- `V2-DESIGN.md` v2.7 — v2 design space entry
- `Safety.md` §5.3 — current safety claim with D2 footnote
- `SECURITY.md` S-030 — the underlying audit finding

---

## 1. Scope

This spec covers ONLY F2 view reconciliation for `compute_block_digest`. It does NOT cover:
- S-033 state_root (already shipped; complementary apply-layer closure — gate actually fires now post-S-038 producer wiring)
- Block-format changes beyond `ContribMsg` extension
- Wallet / RPC changes (none required)
- Cross-shard receipt reconciliation across shards (intra-shard only; cross-shard is a v2.X follow-on)

The fields F2 reconciles over (the ✗-row fields in S030-D2-Analysis.md §1, excluding Phase-2-reveal fields):

| Field | Type | Pool source |
|---|---|---|
| `abort_events` | `vector<AbortEvent>` | Local observation aggregated across consensus rounds |
| `equivocation_events` | `vector<EquivocationEvent>` | Gossip-fed pool (`pending_equivocation_evidence_`) |
| `inbound_receipts` | `vector<CrossShardReceipt>` | Gossip-fed pool (`pending_inbound_receipts_`) |
| `cross_shard_receipts` | `vector<CrossShardReceipt>` | Computed deterministically from accepted txs (NOT gossip-fed) |
| `partner_subset_hash` | `Hash` | Deterministic from merge state |
| `timestamp` | `int64_t` | Local clock at assembler time |

`creator_dh_secrets`, `delay_output`, `cumulative_rand` are Phase-2-reveal fields and remain excluded from `compute_block_digest` for reasons unrelated to D2 (they're not yet known at Phase-2 digest signing). They're covered by `signing_bytes` (which is signed at gossip time, not at consensus time). Outside F2's scope.

---

## 2. Design decisions (the 9 open questions)

### Q1: Per-field reconciliation rule

**Decision: per-field heterogeneous rules, not a single global rule.** Different fields have different incentive structures and operational characteristics.

| Field | Rule | Rationale |
|---|---|---|
| `equivocation_events` | **Union** | Slashing-bearing. Censorship-resistance principle ("any single honest member suffices") applies — one member observing equivocation should be enough to land slashing. Each event already passes validator's V11 check (sigs/digests cryptographically verifiable), so union doesn't expand attack surface. |
| `abort_events` | **Union** | Same reasoning as equivocation. Aborts are individually verifiable (V10); any single observer suffices. |
| `inbound_receipts` | **Intersection** | Credit-bearing. Conservative: only credit when ALL K members have independently observed the receipt bundle. Reduces risk of double-credit if cross-shard relay is partially corrupted (one bad relayer can't unilaterally cause credit). |
| `cross_shard_receipts` | **Deterministic from txs** | These are *emitted* from in-block TRANSFER txs on this shard. Once `tx_root` is reconciled (already F2-safe via existing tx_root mechanism), the receipts derive deterministically. No separate reconciliation needed — the receipts list is a pure function of the accepted txs. Validator re-derives and checks. |
| `partner_subset_hash` | **Deterministic from merge state** | Computed identically on every honest node from the chain's `merge_state` at this height. No view divergence possible; no reconciliation rule needed. Validator re-derives. |
| `timestamp` | **Assembler-proposes, members-bound-check** | Assembler proposes a value at Phase 1→2 boundary. Other members verify it's within their `±30s` window before signing Phase-2 digest. If out of window, member doesn't sign; round aborts and re-runs. Same pattern as the validate-window in `check_timestamp`. |

**Effect:** the three pool-fed fields (equivocation, abort, inbound_receipts) have nontrivial reconciliation; the others are deterministic or proposer-bound.

### Q2: Pool snapshot timing semantics

**Decision: each member snapshots at their own Phase-1 commit instant ("whenever the local timer fires").**

No coordinated snapshot instant is enforced. Members commit when their `tx_commit_ms` timer expires; they hash the pool contents at that moment and include the hash in their `ContribMsg`. This is the same semantics as the existing `tx_hashes` field — members commit their views as of their own commit time.

**Rationale.** Coordinated snapshotting requires a coordination round (extra latency) and is fragile under gossip-async (the very thing F2 is trying to address). "Each member commits their own view" is the gossip-async-safe baseline; reconciliation across views is F2's job (Q1).

**Consequence.** Under union rule for equivocation_events, late-arriving evidence ends up in the canonical list IF AT LEAST one member observed it before their commit. Early-arriving evidence (seen by all K members before commit) is included by both intersection and union. Late evidence (seen by 0 members before any commit) doesn't make this round; rolls into the next round's pool.

### Q3: Wire format for view hashes

**Decision: Merkle root over sorted set, one 32-byte hash per field per member.**

Each `ContribMsg` gains 3 new 32-byte fields:
- `view_eq_root: Hash` — Merkle root over sorted equivocation_events pool
- `view_abort_root: Hash` — Merkle root over sorted local abort observations
- `view_inbound_root: Hash` — Merkle root over sorted inbound_receipts pool

Each member also includes their **actual list** in the ContribMsg (not just the hash). Bandwidth cost: bounded by max pool sizes × K members. Validator re-derives the canonical list from the K committed lists via the rule (Q1), checks the canonical list matches `block.<field>`, and (separately) checks each member's committed Merkle root matches their committed list. Two-stage verification: (1) commit binds member to view, (2) reconciliation produces canonical list.

**Bandwidth.** ContribMsg today is ~few KB. Adding 3 × 32 bytes for hashes + the actual lists. Worst case: large equivocation pool. Suggested cap: 64 events per type per member's ContribMsg.

**Rationale.** Two-stage decouples binding from canonicalization. Members can't equivocate on their view (binding via Merkle root in the signed commit) AND validators can re-derive without trusting any single member (canonicalization is deterministic).

### Q4: Phase-1 commit binding scope

**Decision: extend `make_contrib_commitment` to include all three view roots.**

```cpp
Hash make_contrib_commitment(
    uint64_t            block_index,
    const Hash&         prev_hash,
    const vector<Hash>& tx_hashes,
    const Hash&         dh_input,
    const Hash&         view_eq_root,         // F2 new
    const Hash&         view_abort_root,      // F2 new
    const Hash&         view_inbound_root);   // F2 new
```

Single Ed25519 sig over the extended commitment binds member to all three views at once. Replay-defense via existing `(block_index, prev_hash)` binding — a commit can't be replayed across heights or chain branches.

**Rationale.** Single sig is cheaper than three. Combined hash structure with separate fields preserves per-field auditability (you can verify each member's view of equivocation_events independently). No additional commit-message structure complexity.

### Q5: Phase-2 signature semantics under union rule

**Decision: Phase-2 signs over the reconciled canonical lists, not over any member's individual view.**

Specifically, the extended `compute_block_digest` includes:
- `canonical_eq_events[]` = union of K members' `equivocation_events` (sorted canonically)
- `canonical_abort_events[]` = union of K members' `abort_events` (sorted canonically)
- `canonical_inbound_receipts[]` = intersection of K members' `inbound_receipts` (sorted canonically)
- `canonical_cross_shard_receipts[]` = deterministic from accepted txs
- `canonical_partner_subset_hash` = deterministic from merge state
- `canonical_timestamp` = assembler-proposed (validated by each member's `±30s` window before Phase-2 sign)

Each member at Phase-2 sign-time:
1. Receives all K Phase-1 commits (already gathered for current digest computation)
2. Re-derives the canonical lists from those commits using the agreed rules
3. Verifies the proposed block body (assembler's claim) matches the re-derived canonical lists
4. If match, signs the extended digest

**The "binding evidence Phase-1 didn't see" concern (raised in Q5 of the prior analysis).** Member B's commit included evidence list `[ev1, ev2]`. The union-derived canonical list is `[ev1, ev2, ev3]` (ev3 contributed by member A). When B signs the Phase-2 digest, B is signing over `ev3` which B never observed in their pool.

This is **acceptable under the union rule** for the following reasons:
- ev3 must individually pass validator's V11 check (cryptographically verifiable from event data alone — sig and counter-sig over different digests). B can run V11 on ev3 before signing; if it passes, ev3 is genuinely evidence.
- Member A is bound to ev3 via their commit (their `view_eq_root` covers ev3).
- B is NOT bound to "I observed ev3"; B is bound to "the union of K committed views includes ev3, and ev3 passes V11."
- Equivocation slashing (FA6) catches any member who signs a Phase-2 digest with an evidence list that doesn't match their Phase-1 commit AS RECONCILED with the others' commits — but since the reconciliation is deterministic, no equivocation occurs as long as B follows the rule.

**The validator's job at gossip-time** (when receiving the block, after K signatures gather): re-derive the canonical lists from `b.creator_<view>_roots` (need to add these to Block for validator access; ContribMsg's view-roots are embedded in block via `b.creator_tx_lists`-analogous fields) and verify they match `b.<field>`.

### Q6: Timestamp inclusion scope

**Decision: include in v2.7 scope.**

Adding the assembler-proposes-value pattern for timestamp (Q1) is small relative to the rest of F2 work, and the validator-side ±30s window already exists. Adding it now avoids a separate `v2.7.5` scope.

Wire-format change: `compute_block_digest` extended with `timestamp` (already in `signing_bytes`, just not in digest today).

### Q7: Validator-side reconciliation caching

**Decision: no caching in v2.7 initial ship; re-derive per block.**

The reconciliation is K × pool-size work per block. At suggested caps (K ≤ ~30, pool size ≤ 64 events per type), this is bounded constant work per validate. Caching adds state-tracking complexity (cache invalidation, cross-block consistency) that's not worth it for the bounded work amount.

If profiling later shows this is a hot spot, add a per-block memoization (block_hash → reconciled_lists) at the Node layer. Defer.

### Q8: Monitoring metrics

**Decision: add 4 counters/gauges for operational observability.**

| Metric | Type | Purpose |
|---|---|---|
| `f2_view_divergence_count` | counter, per-round | Number of fields where the K members' committed view roots differed in current round. 0 = all members agreed. |
| `f2_round_aborts_attributed_to_view_drift` | counter | Phase-1 rounds that aborted because reconciliation could not converge (rare; only if intersection rule on inbound_receipts yields empty when ≥1 member has receipts). |
| `f2_canonical_list_size_per_field` | gauge | Size of each canonical list per block. Detects pool inflation. |
| `f2_evidence_inclusion_latency_blocks` | histogram | Blocks between evidence first observed (in any member's pool) and inclusion in a finalized block. Detects gossip-lag issues. |

Exposed via existing RPC `status` extensions or a new `rpc_metrics` (separate v2 ticket). Not strictly required for v2.7 closure but operationally important.

### Q9: FA1 proof update

**Decision: minor textual update, no structural changes to the proof.**

After F2 ships:
- `Safety.md` §5.3 D2 footnote is removed (or marked "✓ closed in v2.7").
- The "Implementation cross-reference" table at the bottom of Safety.md gets an entry pointing at `F2-SPEC.md`.
- The "two block instances can share a digest" caveat in L-1.2 (Lemma 1.2 — "signing_bytes injectivity") needs a parenthetical: post-v2.7, `compute_block_digest` covers all fields in `signing_bytes` except Phase-2-reveal fields, so the two-instance gap is closed.

The actual cryptographic content of FA1 doesn't change — it just gets a stronger conclusion ("≤ 1 block instance per height" replaces "≤ 1 digest per height + footnote").

---

## 3. Implementation work units

Given the design decisions above, the implementation breaks into focused units:

### 3.1 `ContribMsg` wire-format extension (~60 LOC)

- Add 3 fields: `view_eq_root`, `view_abort_root`, `view_inbound_root` (each `Hash`).
- Add 3 fields: `equivocation_events`, `abort_events_observed`, `inbound_receipts` (each `vector<...>`).
- `make_contrib_commitment` extended (Q4).
- `ContribMsg::to_json` / `from_json` updated.
- Binary codec updated.

### 3.2 Producer-side view assembly (~50 LOC)

In `start_contrib_phase`:
- Snapshot the three pools at commit time.
- Compute the 3 view roots (Merkle root over sorted lists).
- Include in the ContribMsg.

### 3.3 Producer-side reconciliation (~80 LOC)

In `build_body` / `start_block_sig_phase`:
- Receive K ContribMsgs.
- Apply the per-field reconciliation rules (Q1).
- Produce canonical `equivocation_events`, `abort_events`, `inbound_receipts`, etc.
- Include them in the block (replacing the assembler's locally-chosen lists).

### 3.4 Validator-side re-derivation (~60 LOC)

In `check_block_sigs` (or new `check_view_reconciliation`):
- For each member's commit, verify the embedded view root matches the embedded list.
- Apply the reconciliation rule to the K verified lists.
- Verify the resulting canonical lists equal `b.<field>`.
- Reject block on mismatch.

### 3.5 `compute_block_digest` extension (~20 LOC)

Add the reconciled fields (plus `timestamp` per Q6) to the digest computation.

### 3.6 Regression tests (~200 LOC)

- Existing test: equivocation-slashing under 3-of-3 (must continue to pass — the prior naive attempt broke this).
- New test: gossip-async divergent equivocation pools, F2 union should include all evidence.
- New test: inbound_receipts divergence under intersection rule.
- New test: timestamp out-of-window rejection.
- New test: F2 with 1 silent member (round aborts gracefully, escalates to BFT).

### 3.7 Migration / wire-version bump

- Bump `ContribMsg` wire version.
- Flag-day height in genesis config.
- Pre-flag-day: old ContribMsg accepted, no F2 enforcement.
- Post-flag-day: F2 enforcement active; pre-flag-day blocks remain valid.

---

## 4. Total estimated cost

- Specification: this document (already done; revise as needed).
- Implementation: 1-2 days focused work given specification.
- Testing: 0.5-1 day for the 5 regression test cases.
- Migration tooling + genesis update: 0.5 day.
- Documentation refresh (Safety.md §5.3, S030-D2-Analysis.md, V2-DESIGN.md v2.7): 0.5 day.

**Total: ~3-4 days** for v2.7 full ship, contingent on this spec being reviewed and the design decisions accepted as-is.

---

## 5. Risks and rollback plan

**Risk: gossip-async pool divergence under unusual conditions.** A real-world deployment with high gossip latency could see persistent view divergence across K members. Under union rule, this is benign (inflated canonical list). Under intersection rule for inbound_receipts, it could starve inclusion. Mitigation: monitor `f2_canonical_list_size_per_field`; if intersection-rule starvation is observed, consider switching that field to threshold rule.

**Risk: validator re-derivation has a bug.** Worst case: blocks rejected that should be accepted; chain halts at the flag-day height. Mitigation: dry-run validator side for 100 blocks pre-flag-day (log mismatches without rejecting), then flip the switch.

**Risk: spec disagreement during review.** Q1's per-field rules are the most consequential choice. If review surfaces a different preference (e.g., union for everything, or threshold for evidence), revise this doc and re-cost. Implementation hasn't started; revision is cheap.

**Rollback plan.** If F2 ships with a bug, freeze new block production via the governance pause mechanism (v2 governance feature, not yet shipped — flag-day governance fork is the v1.x version). Revert via re-flag-day to pre-F2 behavior. Cost: 1 block of stale state acceptance; recoverable via state_root mechanism (S-033) which doesn't change.

---

## 6. Decision review

This spec is recommended to be reviewed before implementation. Reviewers should confirm:

1. Q1's per-field rule assignments (esp. inbound_receipts intersection vs threshold).
2. Q3's wire format choice (full lists in ContribMsg, ~1-2 KB extra per member per round).
3. Q5's Phase-2 sig semantics under union rule (member signs over evidence they didn't observe but which is verifiable).
4. Q6's bundling of timestamp into v2.7 scope.
5. The flag-day migration approach (vs. hard fork).

Once these are confirmed, implementation can proceed against the work units in §3.

---

*End of specification.*
