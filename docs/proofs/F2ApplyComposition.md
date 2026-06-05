# F2ApplyComposition — v2.7 F2 view reconciliation + FA-Apply-1..16 composition + state_root binding

> **⚠ Implementation status (corrected 2026-06-05).** The S-033 `state_root`
> apply gate + S-038 producer wiring this proof composes against ARE shipped
> (verified: `src/chain/chain.cpp` populates and checks `body.state_root`, and
> the gate fires on production blocks). But the F2 **consensus-layer** premise —
> that each committee member binds view roots for `equivocation_events` /
> `abort_events` / `inbound_receipts` into the K-of-K signature surface — is NOT
> yet live: `Node::start_contrib_phase` never populates the view lists and
> `compute_block_digest` binds none of the view roots (see the status banner in
> `F2ViewReconciliationAnalysis.md`). The end-to-end composition theorem below is
> therefore a **specification** of the behavior once v2.7 F2 / S-016 is wired,
> not a description of current behavior. Today S-030 D2 is closed only at the
> apply layer (S-033 + S-038); the consensus-layer view-binding is open work.
> This banner is removed when the F2 wiring (sites 1–4) lands.

This document formalizes the **composition seam** between the v2.7 F2 view-reconciliation layer (consensus-side, per `F2ViewReconciliationAnalysis.md` + FB22) and the FA-Apply-1..16 apply-determinism sequence (apply-side, per `AccountStateInvariants.md`, `MultiEventComposition.md`, and the per-surface FA-Apply-N siblings). The two halves close S-030 D2 from opposite directions — F2 ensures every honest committee member commits, before any state mutation, to a canonical view of the three pool-fed input fields (`equivocation_events`, `abort_events`, `inbound_receipts`); FA-Apply-1..16 ensures the apply path consumes those inputs in a strictly serialized, byte-deterministic order producing a single post-apply state. The present document pins the joint claim: **the F2-committed view roots, once bound into the K-of-K Phase-2 signature surface, are sound inputs to the FA-Apply-1..16 sequence, in the sense that every honest receiver running the apply path against the F2-canonical inputs produces a byte-identical post-apply state and a byte-identical S-033 `state_root`**. The S-033 gate at `chain.cpp:1432–1444` is the apply-time observable that fires on any cross-node divergence, and (post-S-038) it fires on every production block.

The proof is structural rather than cryptographic. The cryptographic content (Ed25519 EUF-CMA + SHA-256 collision-resistance underwriting the F2 commit-binding step and the S-033 Merkle binding) is folded in from the sibling proofs and invoked at named cite-points. The novel content here is the composition argument: F2's pre-apply commitment + FA-Apply-1..16's per-Phase determinism + S-033's apply-time gate compose into a single end-to-end soundness theorem ("F2-committed view roots ⇒ byte-identical post-apply state ⇒ byte-identical state_root ⇒ K-of-K signature surface stays self-consistent"). The composition is what makes S-030 D2 actually closed in operational terms: pre-F2 + pre-S-033, the K-of-K signature surface covered fewer fields than the apply path consumed, so two honest nodes could legitimately apply the same K-signed block to divergent states. F2 + S-033 + S-038 jointly close that gap. This proof names the closure as a composed theorem so future agents reading the proof stack do not have to reconstruct it from the per-layer sibling proofs.

**Companion documents:** `Preliminaries.md` (F0) for notation, assumption A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance), and the validator-predicate scaffold V1..V15 + V21..V26; `F2ViewReconciliationAnalysis.md` for the consensus-layer half (T-1..T-6 algebraic invariants of `compute_view_root` / `reconcile_union` / `reconcile_intersection`); `MakeContribCommitmentBackwardCompat.md` for the Phase-1 commit-binding step (T-1 v1 byte-identity + T-2 DTM-F2-v1 replay-defense); `F2-SPEC.md` (§Q1–§Q9) for the per-field reconciliation-rule decisions this proof consumes; `AccountStateInvariants.md` (FA-Apply-1) for the per-account invariants the apply path preserves; `MultiEventComposition.md` (FA-Apply-15) for the multi-event-block joint-apply theorem T-M1..T-M7; `S033StateRootNamespaceCoverage.md` for the 10-namespace coverage completeness (T-1..T-5); `S012SnapshotStateRootGate.md` for the snapshot-pathway sibling; `BlockchainStateIntegrity.md` for the four-surface S-021 + S-033 + S-038 composition; `S030-D2-Analysis.md` for the underlying audit-finding closure narrative; `CrossShardReceiptDedup.md` (FA-Apply-9) + `EquivocationSlashingApply.md` (FA-Apply-10) + `AbortEventApply.md` (FA-Apply-11) + `AppliedReceiptRestore.md` (FA-Apply-12) for the per-surface apply-path proofs this composition glues together; `tla/F2ViewReconciliation.tla` (FB22) + `tla/MakeContribCommitment.tla` (FB24) + `tla/BlockchainStateIntegrity.tla` (FB26) for the machine-checkable TLA+ companions.

---

## 1. Introduction

### 1.1 The S-030 D2 closure has two halves

`SECURITY.md` §S-030 identifies two divergence vectors in the pre-F2 + pre-S-033 architecture:

- **D1 (validate-vs-apply divergence).** The validator's V-pass checks and the apply path's mutation checks ran against different field subsets. A block could pass V-checks but apply to a state the validator didn't model. Closed by S-033 (state_root binds the post-apply state as a header field) + S-038 (producer-side wiring populates the field via tentative-chain dry-run before broadcast).

- **D2 (gossip-async-vs-canonical-view divergence).** The K-of-K Phase-2 signature surface (`compute_block_digest`) covered a subset of the fields the apply path consumed. Pool-fed fields — `equivocation_events`, `abort_events`, `inbound_receipts` — were included in `signing_bytes` but not in `compute_block_digest`, so two distinct block instances could share the same digest (and therefore the same K signatures) but differ in these fields. Honest nodes applying the two instances would diverge in state for one block. Closed by F2 (consensus-layer): each committee member commits to their view of the three pool-fed fields at Phase-1 commit time via `make_contrib_commitment`'s three view-root parameters; the assembler reconciles the K views via `derive_canonical_view_lists`; the validator re-derives the same canonical lists from the K signed contribs and checks the block body's lists match (V25 + V26). Plus apply-layer: the same state_root + producer wiring that closes D1.

The two halves are necessary in concert: F2 alone closes the consensus-layer gap (the K-of-K signature now binds the canonical input set) but does not by itself guarantee that every honest node mutates state identically when consuming those inputs; FA-Apply-1..16 alone closes the apply-layer gap (the apply path is byte-deterministic given the same inputs) but does not by itself guarantee that two honest nodes see the same K-signed inputs to feed in. **The present document pins the composed claim**: F2's pre-apply commitment, fed through the FA-Apply-1..16 sequence, produces a byte-identical post-apply state, and the S-033 gate detects any cross-node divergence within the same apply path.

### 1.2 Scope

This proof:

- States the composition theorem T-1: the F2-committed view roots in `B.contrib_commitments[]` map deterministically (via the apply path) to the post-apply state `S'`, with state-form equivalence: two blocks with identical view roots + identical txs + identical events apply to identical `S'`.
- Decomposes the composition across the three F2 view-root channels (T-2 for inbound receipts via `view_inbound_root`, T-3 for equivocation evidence via `view_eq_root`, T-4 for abort events via `view_abort_root`).
- States the state-root binding closure T-5: post-apply `state_root` is a deterministic function of (pre-apply state, F2 view roots, txs, header fields); the S-033 gate enforces it; the composition is sound under FB22 + FB26 jointly.
- States the K-of-K composition closure T-6: even under Byzantine producer, K-of-K signatures bind the F2-canonical inputs; honest nodes following F2-spec apply rules reach the same state.

This proof does NOT:

- Re-derive any single FA-Apply-N's per-surface determinism (those are in the sibling proofs cited in §5).
- Re-derive the algebraic invariants of F2's reconciliation primitives (those are in `F2ViewReconciliationAnalysis.md` T-1..T-6).
- Address the v2.10 threshold-randomness aggregation roadmap (`V2-DESIGN.md` v2.10) which is a separate composition surface against the same K-of-K signing layer.
- Cover the wire-format / RPC / mempool admission surfaces (out of scope per the F2-SPEC.md §1 boundary).

---

## 2. Theorems

**Setup.** Let `B` be a block produced under v2.7 F2 by an honest producer `N_p` (per `Node::try_finalize_round` at `src/node/node.cpp:1024–1117`). Let `B.contrib_commitments[]` denote the K-of-K Phase-1 ContribMsg signatures bound to `B`, each carrying `view_eq_root`, `view_abort_root`, `view_inbound_root`, and the matching `view_eq_list`, `view_abort_list`, `view_inbound_list` per `include/determ/node/producer.hpp:134–139`. Let `B.view_eq_root` / `B.view_abort_root` / `B.view_inbound_root` denote the canonical view roots derived by `derive_canonical_view_lists` at `src/node/producer.cpp:438–456`. Let `B.equivocation_events[]`, `B.abort_events[]`, `B.inbound_receipts[]` denote the per-field canonical lists in the block body, as reconciled per F2-SPEC §Q1 (union for eq + abort, intersection for inbound). Let `S` denote the chain state before `apply_transactions(B)`; `S'` denote the chain state after; `state_root(S)` denote `Chain::compute_state_root()` over the ten-namespace canonical Merkle leaves at `src/chain/chain.cpp:267–411`.

### T-1 — F2 Commitment → Apply Determinism

**Statement.** For every honestly produced block `B` and every pair of independent honest receivers `N_a`, `N_b` whose pre-state `S` is byte-equivalent across the relevant chain namespaces, the apply path produces byte-identical post-states `S'_a = S'_b`. More precisely, the post-apply state is a deterministic function of:

1. The pre-apply state `S`.
2. The F2-committed view roots `(B.view_eq_root, B.view_abort_root, B.view_inbound_root)`.
3. The canonical event lists `(B.equivocation_events, B.abort_events, B.inbound_receipts)` (each list verified at validation-time to equal `reconcile_union` / `reconcile_intersection` over the K committed contrib views — V25 + V26).
4. The transactions `B.transactions[]` and the header fields (`b.index`, `b.prev_hash`, `b.creators[]`, etc.).

State-form equivalence:

```
apply(S, B) = apply(S, B')   iff   B.view_eq_root      == B'.view_eq_root
                                AND B.view_abort_root   == B'.view_abort_root
                                AND B.view_inbound_root == B'.view_inbound_root
                                AND B.equivocation_events == B'.equivocation_events
                                AND B.abort_events        == B'.abort_events
                                AND B.inbound_receipts    == B'.inbound_receipts
                                AND B.transactions        == B'.transactions
                                AND header_fields(B)      == header_fields(B')
```

(modulo A2 collision-resistance on the view roots' Merkle binding).

**Proof sketch.** The forward direction (identical inputs ⇒ identical post-state) decomposes across the seven Phases of `apply_transactions` per `MultiEventComposition.md` T-M1: Phase 1 (transactions), Phase 2 (fee + subsidy), Phase 3 (abort_events), Phase 4 (equivocation_events), Phase 5 (inbound_receipts), Phase 6 (A1 accumulator), Phase 7 (S-033 state_root). Each Phase is a deterministic loop over a wire-pinned `std::vector<T>` with per-iteration writes that are pure functions of the read state at that iteration's entry. By induction over the seven Phases, identical (S, B) inputs produce identical post-states.

The reverse direction (the *only* way two blocks apply to the same state is for their view roots + canonical lists + txs + header fields to match) is the cryptographic claim. The S-033 gate at `chain.cpp:1432–1444` rejects any block whose declared `state_root` does not match the receiver's recomputed `state_root` over the post-apply state — so producer-claimed `state_root` is bound to the post-apply state. Two blocks producing identical post-states therefore produce identical `state_root` values; conversely, two blocks with identical `state_root` either had identical inputs (modulo A2 collision on the Merkle root, ≤ 2⁻¹²⁸ per query) or the gate rejects one of them.

The F2-committed view roots enter the state through the canonical event lists (V25 + V26 enforce that `B.equivocation_events == reconcile_union(K contribs' view_eq_lists)` etc.); the canonical event lists enter the state through Phases 3, 4, 5 of `apply_transactions`. Therefore the view roots fully determine the contribution of the three pool-fed channels to the post-apply state (modulo A2 on the Merkle root binding from member view-list to view-root).

Composing: identical view roots ⇒ identical canonical event lists (V25 + V26 are deterministic functions of the K contribs' bound view-lists, per `F2ViewReconciliationAnalysis.md` T-3 + T-5 + T-6) ⇒ identical Phase 3/4/5 mutations ⇒ identical post-state (via the per-Phase determinism arguments of FA-Apply-9 / FA-Apply-10 / FA-Apply-11). ∎

**Implementation citations.** `src/node/producer.cpp:438–456` (canonical view-list derivation); `src/node/producer.cpp:458–496` (V25 + V26 enforcement at validate-time); `src/chain/chain.cpp:633–1502` (apply path); `src/chain/chain.cpp:1432–1444` (S-033 gate); `MultiEventComposition.md` T-M1 (Phase ordering); `F2ViewReconciliationAnalysis.md` T-3 (order-independence) + T-5 (union censorship-resistance) + T-6 (intersection conservative).

### T-2 — F2 View Root → Inbound Receipt Set Equivalence

**Statement.** For every honestly produced block `B` and every honest receiver, the `view_inbound_root` field in `B.contrib_commitments[]` cryptographically commits each contributor to a specific finite set of `CrossShardReceipt` hashes; the V26 check at the receiver enforces that `B.inbound_receipts` equals the intersection (per F2-SPEC §Q1) of the K contributors' committed view-lists; and the apply-layer Phase 5 loop at `src/chain/chain.cpp:1363–1381` consumes exactly this set — no extras, no missing. Formally:

```
For all r ∈ CrossShardReceipt(B):
    r ∈ B.inbound_receipts
        ⟺ ∀ k ∈ {1, …, K} : hash_cross_shard_receipt(r) ∈ contribs[k].view_inbound_list
        ⟹ Phase 5 of apply(S, B) applies exactly r once
            (modulo dedup against applied_inbound_receipts_ via FA-Apply-9 T-R1 / T-R2)
```

**Proof sketch.** The first biconditional is `F2ViewReconciliationAnalysis.md` T-6 (IntersectionConservative): a hash appears in `reconcile_intersection` iff it appears in every member's list. The first implication (membership ⇒ Phase 5 application) is the apply-path loop body at `chain.cpp:1363–1381`:

```cpp
for (auto& r : b.inbound_receipts) {
    auto key = std::make_pair(r.src_shard, r.tx_hash);
    if (applied_inbound_receipts_.count(key)) continue;   // FA-Apply-9 T-R2
    // ... crediting + dedup-insert ...
    applied_inbound_receipts_.insert(key);
    block_inbound += r.amount;
}
```

Every receipt in `B.inbound_receipts` is iterated; fresh receipts are applied; duplicate receipts are silently skipped per FA-Apply-9 T-R2. The Phase 5 loop produces no extra applications (it only iterates the wire-pinned vector) and no missing applications (every iteration is processed). The dedup-set's restore equivalence (FA-Apply-12 T-AR3) preserves the predicate across snapshot ↔ apply boundaries.

The cryptographic content (a contributor cannot equivocate on `view_inbound_list` between Phase-1 commit and Phase-2 reveal) is `MakeContribCommitmentBackwardCompat.md` T-2 + Corollary T-2.1: the Phase-1 Ed25519 signature binds the contributor to a specific `view_inbound_root`, which binds the contributor to a specific `set(view_inbound_list)` per `compute_view_root`'s collision-resistance (A2) per `F2ViewReconciliationAnalysis.md` §3.1. ∎

**Operational consequence.** A Byzantine producer who attempts to insert an "extra" inbound receipt into `B.inbound_receipts` (not witnessed by all K contributors) fails V26 at every honest receiver, blocking the block. A Byzantine producer who attempts to omit a legitimately-witnessed receipt (witnessed by all K contributors) also fails V26 (the receiver's `reconcile_intersection` produces the receipt; `B.inbound_receipts` lacks it; vector comparison fails). The F2 intersection rule gives the **conservative-credit** posture per F2-SPEC §Q1: a single corrupt cross-shard relayer cannot unilaterally cause a credit, because intersection requires unanimous witness.

**Implementation citations.** `F2ViewReconciliationAnalysis.md` T-6; `MakeContribCommitmentBackwardCompat.md` T-2 + T-2.1; `src/chain/chain.cpp:1363–1381` (Phase 5 loop); `CrossShardReceiptDedup.md` (FA-Apply-9) T-R1 + T-R2; `AppliedReceiptRestore.md` (FA-Apply-12) T-AR1..T-AR7.

### T-3 — F2 Eq Root → Equivocation Evidence Set Equivalence

**Statement.** For every honestly produced block `B`, the `view_eq_root` field in `B.contrib_commitments[]` commits each contributor to a specific finite set of `EquivocationEvent` hashes; the V25 check enforces that `B.equivocation_events` equals the union (per F2-SPEC §Q1) of the K contributors' committed view-lists; the apply-layer Phase 4 loop at `src/chain/chain.cpp:1344–1356` consumes exactly this set; and the cascade-interaction with FA-Apply-16 (post-slash zero-stake replay-safety) is preserved across the F2-canonical apply order:

```
For all ev ∈ EquivocationEvent(B):
    ev ∈ B.equivocation_events
        ⟺ ∃ k ∈ {1, …, K} : hash_equivocation_event(ev) ∈ contribs[k].view_eq_list
        ⟹ Phase 4 of apply(S, B) applies ev's slashing + deactivation
            (modulo FA-Apply-10 T-E3 idempotence on already-zeroed stake;
             FA-Apply-16 T-C1 cascade)
```

**Proof sketch.** The biconditional in the first line is `F2ViewReconciliationAnalysis.md` T-5 (UnionCensorshipResistant): a hash appears in `reconcile_union` iff it appears in at least one member's list. The implication to Phase 4 application is the apply-path loop body at `chain.cpp:1344–1356`:

```cpp
for (auto& ev : b.equivocation_events) {
    auto sit = stakes_.find(ev.equivocator);
    if (sit != stakes_.end()) {
        block_slashed += sit->second.locked;
        sit->second.locked = 0;             // FA-Apply-10 T-E1 full forfeit
    }
    auto rit = registrants_.find(ev.equivocator);
    if (rit != registrants_.end()) {
        rit->second.inactive_from = b.index + 1;  // FA-Apply-10 T-E2 deactivation
    }
}
```

Every equivocation event in `B.equivocation_events` is iterated; first-event-against-domain produces full forfeit + deactivation (FA-Apply-10 T-E1 + T-E2); subsequent events against the same domain produce zero contribution (FA-Apply-10 T-E3 idempotence; FA-Apply-16 T-C1 cascade-safety on zeroed stake). The post-Phase-4 state is uniquely determined by the multi-set of distinct equivocator domains in `B.equivocation_events`, regardless of duplicate evidence per equivocator (because each duplicate after the first is a no-op).

The F2 union rule gives the **censorship-resistance** posture per F2-SPEC §Q1: a single honest committee member's observation is sufficient to land slashing evidence. This is FA2's gossip-layer censorship guarantee lifted to the consensus view (`F2ViewReconciliationAnalysis.md` T-5 + §4.5 "FA2 connection"). The composition with FA-Apply-10's apply-side semantics is structural — the Phase 4 loop body is invariant under the order of equivocators in `B.equivocation_events` (per `MultiEventComposition.md` T-M2 + T-M6 Case 1) because each iteration's read+write is on `stakes_[ev.equivocator]` + `registrants_[ev.equivocator]` (per-equivocator-disjoint state). ∎

**Operational consequence.** A Byzantine producer who attempts to omit an equivocation event (witnessed by at least one honest contributor) fails V25 at every honest receiver. A Byzantine producer who attempts to include a *spurious* equivocation event (not witnessed by any contributor) also fails V25 — the receiver's `reconcile_union` will not include the spurious entry. Even if a Byzantine producer could insert a spurious entry past V25 (impossible under A2 + V22 + V25), the per-event V11 check at the validator (cryptographic verification of the two conflicting signed messages — see `EquivocationSlashing.md` T-6) would reject it before apply. Composed defense.

**Implementation citations.** `F2ViewReconciliationAnalysis.md` T-5; `src/chain/chain.cpp:1344–1356` (Phase 4 loop); `EquivocationSlashingApply.md` (FA-Apply-10) T-E1, T-E2, T-E3, T-E7; `StakeForfeitureCascade.md` (FA-Apply-16) T-C1, T-C2; `EquivocationSlashing.md` (FA6) T-6 (V11 cryptographic check, prerequisite to F2 reconciliation).

### T-4 — F2 Abort Root → AbortEvent Set Equivalence

**Statement.** For every honestly produced block `B`, the `view_abort_root` field in `B.contrib_commitments[]` commits each contributor to a specific finite set of `AbortEvent` hashes; the V25 check enforces that `B.abort_events` equals the union of the K contributors' committed view-lists; and the apply-layer Phase 3 loop at `src/chain/chain.cpp:1313–1328` consumes exactly this set:

```
For all ae ∈ AbortEvent(B):
    ae ∈ B.abort_events
        ⟺ ∃ k ∈ {1, …, K} : hash_abort_event(ae) ∈ contribs[k].view_abort_list
        ⟹ Phase 3 of apply(S, B) applies ae's slashing (Round-1 only)
             OR informational propagation (Round-2)
            (modulo FA-Apply-11 T-A1 Round-1 / T-A2 Round-2 split)
```

**Proof sketch.** Same structural argument as T-3, specialized to abort events. The union rule (T-5 UnionCensorshipResistant) means one honest observer's observation suffices for inclusion. The Phase 3 loop body at `chain.cpp:1313–1328` iterates every entry, applies Round-1 proportional slash (FA-Apply-11 T-A1) or treats Round-2 as informational (FA-Apply-11 T-A2), and bookkeeps `block_slashed` for the A1 closure (FA-Apply-11 T-A7).

The cascade-interaction with Phase 4 (equivocation slash on the same domain) is handled by `MultiEventComposition.md` T-M6 Case 1: Phase 3 deducts up to `SUSPENSION_SLASH` first, Phase 4 zeros whatever remains; the composed effect equals the equivocation full-forfeit (the abort contribution is absorbed). The composition holds because Phase 4 reads the post-Phase-3 `stakes_[d].locked` value.

The validator-side V10 check (cryptographic well-formedness of the abort evidence — see `Censorship.md` §3) is a prerequisite to F2's union admission: V10 fires before V25, so any abort event that survives V10 is a candidate for V25 reconciliation. F2 does not weaken V10; it lifts V10-checked evidence into the consensus view via the union rule. ∎

**Operational consequence.** Symmetric to T-3. A Byzantine producer cannot omit an abort event observed by any honest contributor (V25 fires); a Byzantine producer cannot insert a spurious entry (V25 fires; even if past V25, V10 would have rejected before apply). The union rule is the censorship-resistance posture for Phase-1 round disruption evidence.

**Implementation citations.** `F2ViewReconciliationAnalysis.md` T-5; `src/chain/chain.cpp:1313–1328` (Phase 3 loop); `AbortEventApply.md` (FA-Apply-11) T-A1, T-A2, T-A3, T-A7, T-A8; `Censorship.md` V10 (Phase-1 abort cryptographic well-formedness, prerequisite to F2 reconciliation); `MultiEventComposition.md` T-M6 Case 1 (Phase 3 + Phase 4 cascade interaction).

### T-5 — State Root Binding

**Statement.** The post-apply `state_root` field on `B` (populated by the producer via S-038's tentative-chain dry-run at `Node::try_finalize_round`, gated by S-033 at the apply-time check) is a deterministic function of:

```
state_root(C_post) = compute_state_root(
                         apply(S_pre,
                               B.transactions,
                               B.creators,
                               B.equivocation_events,    ← F2 view_eq_root provenance
                               B.abort_events,            ← F2 view_abort_root provenance
                               B.inbound_receipts,       ← F2 view_inbound_root provenance
                               B.header_fields))
```

The S-033 gate at `chain.cpp:1432–1444` enforces that the producer-declared `B.state_root` byte-equals the receiver's recomputed `compute_state_root(S_post)` over the post-apply state. The composition closes the apply-time observable: any cross-node state divergence under the same F2-canonical inputs produces a different `state_root` at the receiver, fails the S-033 gate, and the block is rejected.

**Proof sketch.** The state-root binding is `S033StateRootNamespaceCoverage.md` T-1 (Namespace Coverage Completeness: every mutable state field is committed to exactly one of the ten namespaces) + T-2 (Disjointness) + T-3 (Deterministic Leaf Ordering) + T-4 (Producer/Receiver Symmetry). The F2-canonical inputs flow into the state-root through the canonical apply path:

- `B.equivocation_events` enters via Phase 4's mutations to `stakes_` (→ `s:` namespace) + `registrants_` (→ `r:` namespace) + `block_slashed` → `accumulated_slashed_` (→ `k:c:` namespace).
- `B.abort_events` enters via Phase 3's mutations to `abort_records_` (→ `b:` namespace) + `stakes_` (→ `s:`) + `block_slashed` → `accumulated_slashed_` (→ `k:c:`).
- `B.inbound_receipts` enters via Phase 5's mutations to `applied_inbound_receipts_` (→ `i:` namespace) + `accounts_` (→ `a:`) + `block_inbound` → `accumulated_inbound_` (→ `k:c:`).
- `B.transactions` enters via Phase 1's mutations to `accounts_` / `stakes_` / `registrants_` / `dapp_registry_` / `pending_param_changes_` / `merge_state_` (six namespaces touched).
- `B.creators` enters via Phase 2's mutations to `accounts_` (creator credits).

By `S033StateRootNamespaceCoverage.md` T-1, every mutated field is covered by a namespace; by T-3, the leaf ordering is deterministic; by T-4, the producer's `compute_state_root` (called inside the tentative-chain dry-run at S-038) and the receiver's `compute_state_root` (called at the S-033 gate) execute the identical primitive on byte-identical post-apply states (by T-1 above on this proof's claim). Therefore the producer-declared and receiver-computed `state_root` values are byte-equal for any honest producer + honest receiver pair.

The composition of FB22 (F2 commit-binding) + FB26 (BlockchainStateIntegrity: at-rest + produce + receive surfaces) gives the joint state-machine model: F2 ensures the K signatures cover the F2-canonical inputs; FB26's BlockchainStateIntegrity ensures the at-rest chain.json + produce-time `body.state_root` + receive-time S-033 gate all bind the same post-apply state. The joint model has been TLC-checked at the bounded configurations described in FB22 §recommended-config + FB26 §recommended-config. ∎

**Operational consequence.** Any state divergence — whether caused by a node-local bug, a corrupted at-rest chain.json (S-021 detects), a Byzantine producer who lies about `state_root` (S-033 gate detects), or a Byzantine producer who omits a legitimately-witnessed event (V25 / V26 detects) — surfaces at the S-033 gate or at an earlier V-pass check. There is no silent divergence channel left open under the F2 + S-033 + S-038 composition.

**Implementation citations.** `S033StateRootNamespaceCoverage.md` T-1 + T-2 + T-3 + T-4; `S012SnapshotStateRootGate.md` (snapshot pathway); `BlockchainStateIntegrity.md` (four-surface composition); `src/chain/chain.cpp:413–415` (`compute_state_root`); `src/chain/chain.cpp:1432–1444` (S-033 gate); `src/node/node.cpp:1024–1117` (S-038 producer wiring); FB22 + FB24 + FB26 (TLA+ companions).

### T-6 — Composition with FA1 K-of-K Safety

**Statement.** Under a Byzantine producer scenario where a single committee member (out of K) is adversarial, the K-of-K Phase-2 signature surface binds the F2-canonical inputs — `view_eq_root`, `view_abort_root`, `view_inbound_root`, derived canonical lists — into the block digest. Honest receivers running V21..V26 + the apply path reach the same post-state, and the K-1 honest signers cannot be socially-engineered into producing K signatures over divergent inputs. Formally:

```
For any block B with K committee members C_1, …, C_K, of which f < ⌈K/3⌉ are Byzantine:
    If B reaches finality (collects ≥ Q signatures per BFTSafety),
    Then for every pair of honest receivers (N_a, N_b) with state-equivalent pre-states,
         apply(S_pre, B) at N_a == apply(S_pre, B) at N_b
         (byte-equality of post-state and post-state_root)
```

**Proof sketch.** F2's commitment-binding step (`MakeContribCommitmentBackwardCompat.md` T-2 + Corollary T-2.1) ensures that each honest committee member's Phase-1 commit signature binds them to a specific view of the three pool-fed fields. The Byzantine member can produce a "false" view (containing entries not in the actual gossip pool, or omitting entries that are) — but the canonical-reconciliation rules absorb this:

- Union for `equivocation_events` + `abort_events` (T-5 lift): any honest member's true observation lands in the canonical list regardless of what the Byzantine member commits. The Byzantine member's extra entries either pass V25 (the canonical list grows to include them — but each entry is cryptographically verified at V10 / V11, blocking spurious slashing evidence) or get caught at the apply layer (`EquivocationSlashing.md` T-6 V11 check).
- Intersection for `inbound_receipts` (T-6 conservative): the canonical list excludes any receipt the Byzantine member omits — but **this is intentional under F2-SPEC §Q1's conservative-credit posture**: a credit-bearing entry only lands if every member witnesses it, so one bad relayer cannot unilaterally cause inclusion. The cost is that a Byzantine member who selectively-omits a receipt blocks that receipt's inclusion in *this* round; the receipt is re-proposed in the next round when committee composition changes (or by an honest member of the same committee whose pool view changes).

The K-of-K Phase-2 signature surface is computed over the reconciled canonical lists (per F2-SPEC §Q5). Honest signers refuse to sign over any non-canonical lists (the V25 + V26 checks fire on every signer before they sign Phase-2). The Byzantine member can sign over false inputs, but that single signature is insufficient under the BFT quorum (Q signatures needed; Byzantine = 1 < Q ≤ K).

The composition with FA1 (`Safety.md` §5) is structural: FA1's safety theorem proves that under f < ⌈K/3⌉ Byzantine, no two conflicting blocks at the same height collect Q signatures each. F2 strengthens this by ensuring that the K signatures bind the F2-canonical inputs (not just `compute_block_digest` over a partial field set, as in pre-F2). The apply-time state divergence under same digest (the D2 attack) is closed because the digest now binds the inputs.

Therefore: any block reaching finality has K signatures over the F2-canonical inputs; honest receivers running the F2-spec validation + the FA-Apply-1..16 apply path reach the same post-state by T-1 above. ∎

**Operational consequence.** S-030 D2 is fully closed under this composition. The pre-F2 attack vector — Byzantine producer engineers two distinct blocks (same digest, different pool-fed fields) and gets K signatures on the digest, then ships one to N_a and another to N_b leading to silent state divergence — is no longer possible because the K signatures now cover the pool-fed field set (F2's contribution) and any cross-node divergence in apply produces different `state_root` values (S-033's contribution).

**Implementation citations.** `MakeContribCommitmentBackwardCompat.md` T-2 + T-2.1; `Safety.md` (FA1) §5; `BFTSafety.md` (BFT-mode safety under f < |K_h|/3); `F2-SPEC.md` §Q5 (Phase-2 signature semantics over reconciled canonical lists); `S030-D2-Analysis.md` (audit-finding analysis).

---

## 3. Adversary model

The composition theorem T-1..T-6 closes the S-030 D2 surface under the following adversary models. Each model is defeated by the named defensive layer; the proof works only because all four layers compose without gaps.

### A1 — Byzantine producer commits valid view roots, applies different state

**Capability.** Producer is one of the K committee members; produces a block `B` with view roots and canonical lists that pass V21..V26 (so honest receivers accept the block at validation-time); but the producer's at-rest chain.json shows a different post-apply state than the inputs would deterministically produce (e.g., producer wrote `accounts_["alice"].balance` to 1000 even though the transactions would yield 100).

**Defeat.** Defeated by **S-033 + S-038 jointly**. The producer must populate `body.state_root` before broadcasting (S-038's `Node::try_finalize_round` runs a tentative-chain dry-run and reads `compute_state_root()` over the deterministically-applied post-state — `node.cpp:1024–1117`). If the producer's broadcast block has a `state_root` that doesn't match what the deterministic apply produces, the receiver's S-033 gate at `chain.cpp:1432–1444` recomputes its own `state_root` over the deterministic apply, finds a mismatch, and throws. The producer cannot "lie" about state because the receiver re-derives it; the producer cannot bypass S-038 because every honest receiver expects a non-zero `state_root` post-activation (the zero-skip shim only fires for pre-S-038 historical blocks).

**Cite-points.** `BlockchainStateIntegrity.md` T-1..T-5 (four-surface composition); `S033StateRootNamespaceCoverage.md` T-4 (Producer/Receiver Symmetry); `S012SnapshotStateRootGate.md` (snapshot pathway sibling).

### A2 — Byzantine producer commits valid view roots, but excludes valid evidence from apply

**Capability.** Producer assembles `B` with a valid `view_eq_root` (matching their own Phase-1 commitment) but the `B.equivocation_events` body field contains fewer entries than the canonical `reconcile_union` would produce. (Symmetric attacks on `view_abort_root` / `B.abort_events` and `view_inbound_root` / `B.inbound_receipts`.)

**Defeat.** Defeated by **the validator-side V25 + V26 completeness check**. Every honest receiver, before accepting `B`, runs `derive_canonical_view_lists` over the K Phase-1 contribs (whose commitments are visible in `B.contrib_commitments[]`) and verifies that `B.equivocation_events == reconcile_union(...)` byte-for-byte (V25), and `B.inbound_receipts == reconcile_intersection(...)` (V26). Any divergence — fewer entries (Byzantine producer omitted) or extra entries (Byzantine producer inserted) — fails the vector-equality comparison at `src/node/producer.cpp:483–494`. The block is rejected.

This is the **load-bearing gate** for F2's binding (per §6 F-2). Without V25 + V26, the F2 commit roots would be advisory metadata; with them, they are binding (any divergence is caught). The Phase-1 contributors' commitments are bound by their Ed25519 signatures (A1 EUF-CMA), and the V25 + V26 reconciliation is over the bound view-lists, not over advisory metadata.

**Cite-points.** `F2ViewReconciliationAnalysis.md` §5.2 (validator-pass composition); `F2-SPEC.md` §Q5 (Phase-2 signature over canonical lists); `MakeContribCommitmentBackwardCompat.md` T-2 (commitment is binding).

### A3 — Apply-path race between two valid blocks at same height

**Capability.** Two distinct blocks `B_1`, `B_2` at the same `index` propagate over the gossip network simultaneously; both pass V21..V26 (e.g., committee sets differ slightly across honest receivers' partial gossip views, leading to two distinct canonical reconciliations). Two honest receivers `N_a` and `N_b` apply `B_1` and `B_2` respectively, producing divergent state.

**Defeat.** Defeated by **FA1 K-of-K + F2's commitment binding**. FA1 (`Safety.md` §5) proves that under f < ⌈K/3⌉ Byzantine, no two conflicting blocks at the same height collect Q signatures each. F2's contribution is to ensure the K signatures bind the F2-canonical inputs (not just `compute_block_digest`). If two distinct blocks `B_1`, `B_2` at the same height both have K signatures, they differ in fewer or different signers, and the fork-choice rule (`S029ForkChoiceSoundness.md`) picks the deterministic winner. The losing branch is reverted via `Chain::revert_to_height` at the receiver — there is no silent state divergence because the losing branch's `state_root` doesn't match the winning branch's, and the receiver replays the canonical history from the chosen branch.

The pre-F2 attack (D2 silent divergence) is **not** about competing-branch fork-choice — it's about two distinct *bodies* under the *same digest* sharing the K signatures and applying to divergent state. F2 closes this exact gap: the digest now binds the pool-fed fields, so two distinct bodies necessarily have two distinct digests, and the standard FA1 + fork-choice machinery handles the rest.

**Cite-points.** `Safety.md` (FA1); `S029ForkChoiceSoundness.md` (deterministic fork-choice); `F2ViewReconciliationAnalysis.md` T-3 (deterministic reconciliation across honest receivers seeing the same K commitments).

### A4 — Cross-shard receipt replay across F2-committed roots

**Capability.** Adversary submits the same `CrossShardReceipt r` to multiple consecutive blocks, attempting to double-credit the destination. Each block's `view_inbound_root` may include `r` (because the receipt sits in `pending_inbound_receipts_` until applied).

**Defeat.** Defeated by **FA7 cross-shard atomicity + FA-Apply-12 dedup-set restore equivalence**. The apply-layer Phase 5 loop at `chain.cpp:1363–1381` consults `applied_inbound_receipts_` before crediting; if the receipt's `(src_shard, tx_hash)` key is already present, the iteration silently skips (FA-Apply-9 T-R2). The dedup-set persists across `serialize_state` ↔ `restore_from_snapshot` (FA-Apply-12 T-AR1..T-AR3) and across at-rest chain.json reload (S-021).

The F2 layer does NOT need to dedup the receipt across blocks — its scope is "within a single block, intersect across K contributors' view-lists" (F2-SPEC §Q1). Cross-block dedup is the apply layer's responsibility (FA-Apply-9 + FA-Apply-12). The composition: F2 ensures the intra-block consensus view is correct; FA7 + FA-Apply-9 + FA-Apply-12 ensure cross-block replay is impossible. Either layer alone would leave a gap; together they close it.

A more subtle case: the receipt appears in two consecutive blocks' `view_inbound_root` because the assembler's pool snapshot includes both an unapplied receipt + the same receipt that was just applied at the previous block (race between gossip pool clean-up and the next assembler's view-snapshot). The apply-layer Phase 5 silently skips the duplicate per FA-Apply-9 T-R2; A1 (unitary supply) is preserved because no credit is issued; the V14 (state_root match) gate still passes because the receiver runs the same dedup logic.

**Cite-points.** `CrossShardReceipts.md` (FA7); `CrossShardReceiptDedup.md` (FA-Apply-9) T-R1 + T-R2; `AppliedReceiptRestore.md` (FA-Apply-12) T-AR1..T-AR7; `BlockchainStateIntegrity.md` (at-rest dedup-set persistence under S-021).

---

## 4. Lemmas

### L-1 — Pre-image disjointness (DTM-F2-v1 separator)

**Statement.** Per `MakeContribCommitmentBackwardCompat.md` L-3: the pre-image of any v1-shape `make_contrib_commitment` invocation (104 bytes) is disjoint from the pre-image of any F2-shape invocation with at least one non-zero view root (209 bytes). The 9-byte `"DTM-F2-v1"` ASCII literal at the head of the F2 extension ensures structural disjointness even without the length-distinguishing argument.

**Consequence for this composition.** The Phase-1 commit-binding step (A1 EUF-CMA on Ed25519) cannot be replayed across the v1 ↔ F2 boundary, so a v1 sig on an empty-view commit cannot be repurposed as an F2 sig on a non-empty-view commit (and vice versa). Pre-F2-activation contribs gossiped into an F2-aware peer continue to verify (T-1.1 backward compat), while post-F2-activation contribs cannot be replayed across the activation height.

### L-2 — View-root determinism

**Statement.** Per `F2ViewReconciliationAnalysis.md` §3.1: `compute_view_root(L)` is a deterministic function of `set(L)` (the underlying set after canonical-sort-and-dedup via `std::set<Hash>` coercion). Two member lists with the same underlying set produce the same root.

**Consequence for this composition.** A contributor cannot equivocate on their view between Phase-1 commit (which binds the root) and Phase-2 reveal (which reveals the list). If they attempt to reveal a list with a different `set(L)`, the validator's V22/V23/V24 check (`validate_contrib_view_roots`) fails. Therefore the F2-committed view roots in `B.contrib_commitments[]` are reliable inputs to the canonical-reconciliation rules.

### L-3 — Apply-loop deterministic order

**Statement.** Per `MultiEventComposition.md` T-M1: the apply path's seven Phases iterate the block's event-bearing `std::vector<T>` fields in wire-pinned index order. No `goto`, no coroutine yield, no concurrent iteration; each iteration's read+write is a deterministic function of the state at iteration entry.

**Consequence for this composition.** Two honest receivers `N_a`, `N_b` running the apply path on the same `(S_pre, B)` traverse the Phases in the same order, iterate the same events in the same order, and produce byte-identical post-states. Combined with L-2 (canonical reconciliation is deterministic across honest derivations), the entire F2 → apply pipeline is deterministic.

### L-4 — Reconciliation-rule purity

**Statement.** Per `F2ViewReconciliationAnalysis.md` T-1 + T-2 + T-3 + T-4: `reconcile_union` and `reconcile_intersection` are pure-function set operations (monotone in their inputs, anti-monotone in the intersection case, order-independent, idempotent). They are deterministic across any honest re-derivation given byte-identical K contribs.

**Consequence for this composition.** The validator's V25 + V26 re-derivation produces byte-identical canonical lists across all honest receivers, regardless of which committee member assembled the block. There is no validator-side ambiguity in deciding what `B.equivocation_events` etc. should contain.

### L-5 — State-root namespace coverage completeness

**Statement.** Per `S033StateRootNamespaceCoverage.md` T-1: every mutable state field consumed by `Chain::apply_transactions` is committed to exactly one of the ten Merkle namespaces (`a:`, `s:`, `r:`, `d:`, `i:`, `b:`, `m:`, `p:`, `k:`, `k:c:`).

**Consequence for this composition.** The three F2 input channels (eq, abort, inbound) write to the namespaces `s:` / `r:` / `b:` / `k:c:` / `i:` / `a:` per the per-Phase write-set table. None of these namespaces is "outside" the state-root; every mutation participates in the S-033 gate's comparison. There is no silent-mutation channel that bypasses the gate.

### L-6 — A1 unitary-supply additive composition

**Statement.** Per `MultiEventComposition.md` T-M3: the A1 closure (`live_total_supply == expected_total`) decomposes additively over per-event contributions across the four chain-wide accumulators (`accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_`).

**Consequence for this composition.** The three F2 input channels each feed exactly one or two of the four accumulators. Equivocation slash → `accumulated_slashed_`. Abort slash → `accumulated_slashed_`. Inbound receipt → `accumulated_inbound_`. The composition preserves A1 because the per-channel sums are additive u64 (S-007 overflow-checked at every += site). A divergence in F2-canonical inputs would surface as an A1 closure violation at the apply-tail; the chain-wide `live_total_supply()` recompute throws at `chain.cpp:1399`.

### L-7 — Producer/Receiver symmetry composes via state_root

**Statement.** Per `S033StateRootNamespaceCoverage.md` T-4: producer-side `compute_state_root` (in the S-038 tentative-chain dry-run) and receiver-side `compute_state_root` (in the S-033 apply-time gate) execute the identical primitive over byte-equivalent post-apply states. Asymmetry between producer and receiver is impossible under L-3 + L-5 + apply-determinism.

**Consequence for this composition.** Any divergence between producer's claimed `body.state_root` and receiver's recomputed `state_root` is caught at the S-033 gate. There is no silent divergence; the gate's byte-equality comparison at `chain.cpp:1434` is the cross-node observability point. Combined with T-1 (F2-canonical inputs ⇒ byte-identical post-state), no honest producer can ship a block that fails the gate at any honest receiver under A1..A4.

---

## 5. Cross-references

### Sibling proofs (consensus-layer F2)

| Reference | Role in this composition |
|---|---|
| `F2ViewReconciliationAnalysis.md` (T-1..T-6) | Algebraic invariants of `compute_view_root` / `reconcile_union` / `reconcile_intersection`; consumed by T-2 (intersection-conservative), T-3 + T-4 (union-censorship-resistant), L-2, L-4. |
| `MakeContribCommitmentBackwardCompat.md` (T-1 + T-2) | Phase-1 commit-binding step; consumed by L-1 (DTM-F2-v1 disjointness), A2 (binding ⇒ validator-side re-derivation is sound). |
| `F2-SPEC.md` (§Q1, §Q3, §Q4, §Q5) | Design decisions: per-field reconciliation rules, wire format, commit-binding scope, Phase-2 signature semantics. |
| `S030-D2-Analysis.md` | The underlying audit-finding analysis + comparison of closure paths. |
| `Censorship.md` (FA2) | T-5's "FA2 lift" — gossip-layer censorship-resistance lifted to consensus view. |
| `EquivocationSlashing.md` (FA6) | V11 cryptographic check on equivocation evidence; prerequisite to T-3's F2 union admission. |

### Sibling proofs (apply-layer FA-Apply)

| Reference | Role in this composition |
|---|---|
| `AccountStateInvariants.md` (FA-Apply-1) | I-1 atomic apply, I-2 nonce monotonicity, I-3 balance/stake independence, I-6 A1 contribution; consumed by T-1's per-Phase determinism + T-3's Phase 4 mutation analysis. |
| `MultiEventComposition.md` (FA-Apply-15) T-M1..T-M7 | Joint apply theorem; consumed by T-1's per-Phase serialized ordering + L-3 + L-6. |
| `CrossShardReceiptDedup.md` (FA-Apply-9) T-R1 + T-R2 | Per-receipt fresh/duplicate semantics; consumed by T-2's Phase 5 application analysis. |
| `EquivocationSlashingApply.md` (FA-Apply-10) T-E1..T-E7 | Per-equivocator forfeit + deactivation + idempotence; consumed by T-3's Phase 4 mutation analysis. |
| `AbortEventApply.md` (FA-Apply-11) T-A1..T-A8 | Per-abort Round-1 slash + Round-2 informational; consumed by T-4's Phase 3 mutation analysis. |
| `AppliedReceiptRestore.md` (FA-Apply-12) T-AR1..T-AR7 | Dedup-set restore equivalence; consumed by T-2 + A4 (cross-block replay defense). |
| `StakeForfeitureCascade.md` (FA-Apply-16) T-C1..T-C7 | Cascading slash safety on zeroed stake; consumed by T-3 (cascade Phase 3 + Phase 4 + future-block) + L-6. |

### Sibling proofs (state-integrity)

| Reference | Role in this composition |
|---|---|
| `S033StateRootNamespaceCoverage.md` T-1..T-5 | 10-namespace coverage completeness + disjointness + deterministic ordering + producer/receiver symmetry + snapshot round-trip; consumed by T-5 + L-5 + L-7 + A1. |
| `S012SnapshotStateRootGate.md` | Snapshot-pathway sibling for the apply-time gate; T-5's snapshot ↔ apply equivalence reference. |
| `BlockchainStateIntegrity.md` T-1..T-5 | Four-surface composition (at-rest + produce + receive + snapshot); T-5 + A1's "no silent divergence channel" reference. |
| `NonceMonotonicity.md` (FA-Apply-3) T-N1..T-N6 | Replay-defense at per-account nonce gate; complementary to T-2's cross-shard dedup. |

### TLA+ companions (FB-track)

| Reference | Role in this composition |
|---|---|
| `tla/F2ViewReconciliation.tla` (FB22) | Machine-checkable companion to F2ViewReconciliationAnalysis.md; pins T-1..T-6 + V21..V26 at the state-machine layer. |
| `tla/MakeContribCommitment.tla` (FB24) | Machine-checkable companion to MakeContribCommitmentBackwardCompat.md; pins T-1 v1-byte-identity + T-2 DTM-F2-v1 replay-defense. |
| `tla/BlockchainStateIntegrity.tla` (FB26) | Machine-checkable companion to BlockchainStateIntegrity.md; 3-node chain across load + apply + produce surfaces; consumed by T-5 + A1. |
| `tla/AppliedReceiptRestore.tla` (FB17) | Companion to AppliedReceiptRestore.md; cross-shard dedup-set restore state machine; consumed by T-2 + A4. |
| `tla/MultiEventComposition.tla` (FB20) | Companion to MultiEventComposition.md; full per-block apply-loop with four event classes in canonical order; consumed by T-1 + L-3 + L-6. |
| `tla/EquivocationApply.tla` (FB15) | Companion to EquivocationSlashingApply.md; equivocation slash state machine; consumed by T-3. |
| `tla/AbortApply.tla` (FB16) | Companion to AbortEventApply.md; abort slash state machine; consumed by T-4. |
| `tla/CrossShardReceiptDedup.tla` (FB14) | Companion to CrossShardReceiptDedup.md; cross-shard receipt dedup state machine; consumed by T-2. |

---

## 6. Findings

### F-1 — Pre-S-038 backward-compat: state_root=0 blocks bypass the S-033 gate

**Observation.** The S-033 gate at `chain.cpp:1432–1444` is wrapped in `if (b.state_root != zero) { … }`. Pre-S-038 blocks (legacy chains predating the producer-side wiring) carry `state_root == Hash{}` and skip the gate entirely. This is intentional under `WireFormatBackwardCompat.md` C-2 (zero-skip shim) — preserving byte-stability across the activation height — but it means the gate is dormant on legacy blocks even when the producer is honest.

**Composition impact.** T-5 (state_root binding) and L-7 (producer/receiver symmetry via state_root) hold *vacuously* on pre-S-038 blocks. T-1's "byte-identical post-apply state across receivers" still holds (the apply-determinism argument is independent of the gate firing), but the **observable** check at the apply layer is absent. A pre-S-038 block that legitimately diverges (e.g., one receiver's chain.json was tampered with at-rest, S-021 missed it) would not be caught until the next gossiped post-S-038 block arrived — the prev_hash chain would mismatch.

**Documented in.** `S012SnapshotStateRootGate.md` §7 F-1 (gate-position discipline); `BlockchainStateIntegrity.md` §6.2 (out-of-namespace gap mitigation); `WireFormatBackwardCompat.md` C-2 (zero-skip shim). No code change recommended; the backward-compat constraint is operationally necessary for chains activated before S-038.

### F-2 — Validator-side V25 + V26 completeness check is the load-bearing gate

**Observation.** F2's commitment binding (`MakeContribCommitmentBackwardCompat.md` T-2) is cryptographically sound — Phase-1 commit signatures bind each member to a specific view via the Merkle root. But the *commitment alone* is advisory metadata at the apply layer; the validator must actively re-derive `reconcile_union` / `reconcile_intersection` over the K committed contribs and compare against the block body's canonical lists (V25 + V26 at `src/node/producer.cpp:483–494`). Without this re-derivation step, a Byzantine producer could ship a block with valid view roots but a body whose `equivocation_events` / `abort_events` / `inbound_receipts` arrays did not match the F2 reconciliation — and the K signatures over the canonical-lists-in-the-body would still be valid (the signers signed over whatever the assembler proposed).

**Composition impact.** This is the gate that makes F2 binding rather than advisory. A2 in §3 hinges on it: without V25 + V26, A2's attack succeeds. The check is on the apply path's critical path; CI-gated by `tools/test_view_root.sh` per `F2ViewReconciliationAnalysis.md` §6.

**Recommended discipline.** Any future refactoring of the validator-side V-pass surface must preserve V25 + V26 as a single atomic check per block (not split across multiple passes, not deferred until apply). Same maintenance contract as the S-033 gate's "post-restore" placement (per `S012SnapshotStateRootGate.md` §1.3).

### F-3 — Replay during partition is bounded by FA7 + FA-Apply-12 cross-block dedup

**Observation.** F2 reconciles the inbound-receipt set *within* a single block. Cross-block replay defense — preventing the same receipt from being credited twice across consecutive blocks — is the apply layer's responsibility (FA-Apply-9 T-R2 silent-skip + FA-Apply-12 T-AR3 dedup-set restore equivalence). During a network partition where the cross-shard relayer's pool view is out of sync with the destination shard's `applied_inbound_receipts_`, a receipt may appear in multiple consecutive blocks' `view_inbound_root` (intersected across K relayers who haven't yet seen the destination-side apply).

**Composition impact.** A4 in §3 hinges on the apply-layer dedup. The composition is sound: the F2 layer admits the receipt into the canonical list as many times as it appears across blocks (intersection rule); the apply layer silently skips after the first credit. A1 (unitary supply) is preserved across the cascade because each duplicate contributes zero to `block_inbound`. The system tolerates partition-induced relay duplication without double-crediting.

**Operational consequence.** A long partition (lasting many blocks) may produce many "phantom" entries in `view_inbound_root` for the same receipt; this is a benign efficiency cost (bandwidth + apply-loop iteration count), not a correctness issue. Once the partition heals and the relayer's pool sees the receipt as applied, the phantom entries stop appearing.

---

## 7. Test surface

The composition theorem T-1..T-6 is exercised by the union of regression tests covering F2's consensus layer + FA-Apply-1..16's apply layer. Direct end-to-end tests that simultaneously exercise both halves:

| Test | T-N(s) exercised | What it asserts |
|---|---|---|
| `tools/test_state_root.sh` (13 assertions) | T-5 + L-5 + L-7 | `compute_state_root()` determinism + namespace sensitivity + invertibility; S-033 gate's primary correctness regression. |
| `tools/test_state_root_namespaces.sh` (12 assertions) | T-5 + L-5 | Exhaustive 10-namespace coverage (a:/s:/r:/d:/i:/b:/m:/p:/k:/c:); pre-S-033 a producer mutating a missed namespace would not surface; post-S-033 every mutation is gated. |
| `tools/test_chain_apply_block.sh` | T-1 + T-5 + L-3 + L-7 | Per-block apply determinism + state_root binding; matching state_root → apply succeeds; mismatching → apply throws. |
| `tools/test_multi_event_block_apply.sh` | T-1 + T-3 + T-4 + L-3 + L-6 | A single block carrying TRANSFER + abort + equivocation + inbound + DAPP_CALL applies correctly with each Phase's per-event invariant + A1 closure + state-root recomputation passing. |
| `tools/test_block_event_composition.sh` | T-3 + T-4 + L-3 | Cross-product of intentional-coupling cases (abort + equivocation on same domain, REGISTER + equivocation, etc.); each per-Phase invariant remains valid. |
| `tools/test_view_root.sh` | T-1 + T-2 + T-3 + T-4 + L-2 + L-4 | F2 helper assertion block — `compute_view_root` / `reconcile_union` / `reconcile_intersection` / V21..V26 — exercises the consensus-layer half of the composition. |
| `tools/test_cross_shard_atomicity.sh` | T-2 + A4 | End-to-end source-side debit + destination-side credit + dedup; FA7 + FA-Apply-9 + FA-Apply-12 composed. |
| `tools/test_equivocation_slashing.sh` | T-3 + L-6 | FA-Apply-10 + A1 invariance under equivocation forfeit; composed with F2 admission. |
| `tools/test_equivocation_multi.sh` | T-3 + T-6 (cascade) | Multiple equivocation events; FA-Apply-16 cascade-safety on zeroed stake. |
| `tools/test_abort_event_apply.sh` | T-4 + L-6 | FA-Apply-11 + A1 invariance under Phase-1 abort slash; composed with F2 admission. |
| `tools/test_applied_receipt_restore.sh` | T-2 + A4 + L-5 | FA-Apply-12 dedup-set restore equivalence; `i:` namespace round-trip. |
| `tools/test_dapp_snapshot.sh` | T-5 + L-5 | S-033 + S-038 joint surface end-to-end on a DApp-active multi-event chain; receiver's recomputed state-root strictly matches snapshot tail head's stored state-root. |
| `tools/test_supply_invariant.sh` | L-6 | A1 unitary-supply closure across composed event streams. |
| `tools/test_supply_lifecycle.sh` | L-6 + T-1 | Multi-block A1 closure across mixed event streams; T-1's "deterministic across blocks" composes. |
| `tools/test_chain_save_load.sh` | T-5 + A1 + L-7 | Snapshot roundtrip + load preserves state_root; BlockchainStateIntegrity at-rest surface. |
| `tools/test_snapshot_bootstrap.sh` | T-5 + L-5 + L-7 | Snapshot consumption + S-012 gate (recompute-and-throw on mismatch). |

The full regression suite (`bash tools/run_all.sh`) covers the apply-determinism foundation under heterogeneous event mix; F2's consensus-layer coverage is in `test_view_root.sh`; the joint surface T-1..T-6 is exercised by the multi-event + state-root + cross-shard + slashing tests above. CI gates on the full suite passing.

---

## 8. References

### Internal cites (sibling proofs + code + design specs)

- `src/node/producer.cpp:219–260` — `make_contrib_commitment` (Phase-1 commit-binding primitive; primary cite for L-1 + L-2).
- `src/node/producer.cpp:335–340` — `compute_view_root` (Merkle root over sorted-deduped view list; primary cite for L-2).
- `src/node/producer.cpp:345–351` — `reconcile_union` (per F2-SPEC §Q1 for eq + abort; primary cite for T-3 + T-4).
- `src/node/producer.cpp:357–372` — `reconcile_intersection` (per F2-SPEC §Q1 for inbound; primary cite for T-2).
- `src/node/producer.cpp:391–436` — `validate_contrib_view_roots` (V21..V24 per-contrib well-formedness; primary cite for A2 defeat).
- `src/node/producer.cpp:438–456` — `derive_canonical_view_lists` (assembler-side canonical reconciliation).
- `src/node/producer.cpp:458–496` — `validate_view_reconciliation` (V25 + V26 cross-contrib composite check; primary cite for F-2).
- `src/node/node.cpp:1024–1117` — `Node::try_finalize_round` (S-038 producer-side state_root wiring; primary cite for A1 defeat).
- `src/chain/chain.cpp:267–411` — `Chain::build_state_leaves` (10-namespace canonical leaf set; primary cite for T-5 + L-5).
- `src/chain/chain.cpp:413–415` — `Chain::compute_state_root` (SHA-256 Merkle root over sorted leaves; primary cite for T-5).
- `src/chain/chain.cpp:633–1502` — `Chain::apply_transactions` (seven-Phase apply path; primary cite for T-1 + L-3).
- `src/chain/chain.cpp:1313–1328` — Phase 3 abort-slash loop (cite for T-4).
- `src/chain/chain.cpp:1344–1356` — Phase 4 equivocation-slash loop (cite for T-3).
- `src/chain/chain.cpp:1363–1381` — Phase 5 inbound-receipt loop (cite for T-2).
- `src/chain/chain.cpp:1397–1419` — A1 closure (cite for L-6).
- `src/chain/chain.cpp:1432–1444` — S-033 state_root gate (primary cite for T-5 + L-7).
- `include/determ/node/producer.hpp:117–139` — `make_contrib_commitment` declaration with default-zero F2 args.
- `include/determ/node/producer.hpp:212` — `F2_VIEW_LIST_CAP = 64` (bandwidth cap per F2-SPEC §Q3).
- `include/determ/node/producer.hpp:214–266` — V21..V26 validator-side helper declarations + docstring.
- `include/determ/chain/chain.hpp:540` — `accounts_` declaration (the per-account state mutated by Phase 1 + Phase 2 + Phase 5).
- `docs/PROTOCOL.md` §4.1.1 — Ten-namespace state-root key-encoding table.
- `docs/PROTOCOL.md` §5.3 — BFT escalation gates + F2 + S-033 integration.
- `docs/PROTOCOL.md` §6.1 — Apply rules ordering (seven-Phase serialization).
- `docs/SECURITY.md` §S-030 — Audit-finding D1 + D2; closure narrative.
- `docs/SECURITY.md` §S-033 — Merkle state-root commitment + apply-time gate.
- `docs/SECURITY.md` §S-037 — Dapp_registry snapshot gap (closed; ten-namespace coverage maintenance contract).
- `docs/SECURITY.md` §S-038 — Producer-side state_root population via tentative dry-run.
- `docs/proofs/Preliminaries.md` §2.1 — SHA-256 collision-resistance (A2).
- `docs/proofs/Preliminaries.md` §2.2 — Ed25519 EUF-CMA (A1).
- `docs/proofs/Preliminaries.md` §4 — Honest-node behavior (H1–H6).
- `docs/proofs/Preliminaries.md` §5 — Validator predicates V1–V15.
- `docs/proofs/F2-SPEC.md` §Q1 — Per-field heterogeneous reconciliation rules.
- `docs/proofs/F2-SPEC.md` §Q3 — Wire format + `F2_VIEW_LIST_CAP`.
- `docs/proofs/F2-SPEC.md` §Q4 — Phase-1 commit-binding scope.
- `docs/proofs/F2-SPEC.md` §Q5 — Phase-2 signature semantics over canonical lists.

### Cited sibling proofs (already enumerated in §5)

- `F2ViewReconciliationAnalysis.md` — T-1..T-6 + V21..V26.
- `MakeContribCommitmentBackwardCompat.md` — T-1 + T-2.
- `S030-D2-Analysis.md` — Audit-finding analysis.
- `AccountStateInvariants.md` (FA-Apply-1) — I-1..I-6.
- `MultiEventComposition.md` (FA-Apply-15) — T-M1..T-M7.
- `S033StateRootNamespaceCoverage.md` — T-1..T-5.
- `S012SnapshotStateRootGate.md` — Snapshot pathway.
- `BlockchainStateIntegrity.md` — Four-surface composition.
- `CrossShardReceiptDedup.md` (FA-Apply-9), `EquivocationSlashingApply.md` (FA-Apply-10), `AbortEventApply.md` (FA-Apply-11), `AppliedReceiptRestore.md` (FA-Apply-12), `StakeForfeitureCascade.md` (FA-Apply-16).
- `Safety.md` (FA1), `BFTSafety.md`, `Censorship.md` (FA2), `EquivocationSlashing.md` (FA6).
- TLA+ FB22 + FB24 + FB26 + FB14..FB17 + FB20.

### External references

- Lamport, Leslie. *Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers*. Addison-Wesley, 2002. Chapter 8 ("Composing Specifications") covers the I/O automata composition pattern this proof's T-1 + T-6 abstractly mirror — the consensus-layer F2 spec composes with the apply-layer FA-Apply spec under the shared variable `body.state_root` + the validator-pass V25/V26 enforcement boundary. The compositional reasoning here (state-machine + per-Phase determinism + cross-layer shared invariants) follows Lamport's prescription that a composed system's safety follows from each component's safety + the well-formedness of their composition seam.
- Lynch, Nancy. *Distributed Algorithms*. Morgan Kaufmann, 1996. Chapter 8 ("Distributed Consensus with Process Failures") + Chapter 23 ("I/O Automata") provide the formal foundation for compositional reasoning across the consensus-layer (F2) and the apply-layer (FA-Apply): each is modeled as an I/O automaton, and the composition's joint properties hold when the components' input/output traces synchronize at the shared interface (here: the F2-canonical event lists as the apply layer's input). The replicated-state-machine pattern (Chapter 14) underlies the byte-identical-post-state claim in T-1 — every honest receiver runs the same deterministic state machine on the same input, producing the same output.
- Castro, Miguel and Liskov, Barbara. *Practical Byzantine Fault Tolerance*. OSDI 1999. The K-of-K Phase-2 signature surface this proof composes against is a BFT-style quorum signature; the composition with F2's view reconciliation extends PBFT's three-phase protocol by binding the committee members' input views into the commit phase, closing the silent-divergence channel that pre-F2 left open in the analogous gap between the PBFT prepare and commit phases.
- IETF RFC 9591. *The Flexible Round-Optimized Schnorr Threshold (FROST) Signing Protocol*. §4.5 covers the signing-round message-binding via commitment vectors — F2's `view_eq_root` / `view_abort_root` / `view_inbound_root` parallel FROST's pre-commitment values, and F2's Phase-2 reconciliation parallels FROST's signature-share aggregation step.
- ISO/IEC 14882:2020 [C++20]: `[array.syn]` (lexicographic compare on `std::array`), `[associative.reqmts]` (sorted iteration on `std::set`), `[set.modifiers]` (insertion is no-op on duplicates), `[set.intersection]` (set intersection algorithm), `[vector.syn]` (element-wise `operator==`). The deterministic-set-coercion + canonical-iteration patterns underwriting L-2 + L-4 + the per-Phase determinism arguments.
- NIST FIPS 180-4. *Secure Hash Standard (SHS)*. SHA-256 reference for the Merkle commitments at all F2 + S-033 layers.
- RFC 8032. *Edwards-Curve Digital Signature Algorithm (EdDSA)*. Ed25519 reference for the Phase-1 commit signatures binding each contributor to their view (A1 EUF-CMA).
