# FA9 — Under-quorum merge safety

This document proves that R4's under-quorum merge mechanism preserves the safety properties of FA1 (per-shard K-of-K safety) and FA7 (cross-shard receipt atomicity) across BEGIN/END transitions. The mechanism: when a shard's regional pool drops below 2K, validators of shard S temporarily participate in shard T = (S+1) mod num_shards via an eligibility stress branch.

The argument is short because the design carefully preserves the structural invariants of FA1/FA7 — merge does not modify them, it extends the eligible pool. Soundness follows from the extension being deterministic and validator-mirrored.

**Companion documents:** `Preliminaries.md` (F0); `Safety.md` (FA1); `CrossShardReceipts.md` (FA7); `RegionalSharding.md` (FA8).

---

## 1. Mechanism summary

### MERGE_EVENT lifecycle

A `MERGE_EVENT` (TxType = 7) is included in a beacon block carrying canonical payload:

```
[event_type: u8]   // 0 = BEGIN, 1 = END
[shard_id: u32 LE]
[partner_id: u32 LE]
[effective_height: u64 LE]
[evidence_window_start: u64 LE]
[merging_shard_region_len: u8]
[merging_shard_region: utf8 bytes]
```

On apply (chain.cpp):

- **BEGIN**: insert `(shard_id → {partner_id, refugee_region})` into `Chain::merge_state_` iff `partner_id == (shard_id + 1) mod shard_count_`.
- **END**: erase the matching entry.

The map is persisted in snapshots so a snapshot-bootstrapped node observes identical state.

### Eligibility stress branch

When this shard absorbs refugees (i.e., `Chain::shards_absorbed_by(my_shard)` returns non-empty), the committee eligibility pool extends with validators from each refugee region:

- `Node::check_if_selected` (producer side)
- `BlockValidator::check_creator_selection` (validator side)
- `BlockValidator::check_abort_certs` (abort-cert reconstruction)

All three apply the same extension logic; producers and validators see identical pools.

### Validator gates

- `sharding_mode == EXTENDED` required.
- Canonical 26+region_len byte payload.
- `event_type ∈ {0, 1}` and `partner_id ≠ shard_id`.
- Region charset `[a-z0-9-_]`, `≤ 32` bytes.
- `effective_height ≥ block.index + merge_grace_blocks` (R4 Phase 6 bound).
- BEGIN: `evidence_window_start + merge_threshold_blocks ≤ block.index` (R4 Phase 6 bound).

---

## 2. Theorem statements

**Theorem T-9 (Per-shard safety preserved under merge).** Under the assumptions of FA1 (T-1, T-1.1) and FA8 (T-8), if shard T absorbs refugee shard S via a finalized MERGE_BEGIN, then every finalized block on shard T's chain — produced by the merged committee — still satisfies FA1's "≤1 finalized digest per height" property, with bound `≤ 2⁻¹²⁸ · K` per attempted fork.

**Theorem T-9a (Receipt atomicity preserved across BEGIN/END boundaries).** Under FA7's assumptions, every cross-shard transfer emitted on shard X with destination Y has its credit applied exactly once on Y, regardless of whether either shard transitions through a BEGIN/END boundary between emit and credit.

**Corollary T-9.1 (No-flapping under hysteresis).** When `revert_threshold_blocks ≥ 2 · merge_threshold_blocks`, the merge cannot oscillate between BEGIN/END/BEGIN over a stable observed pool size — a one-shot violation of the trigger condition cannot fire repeated merges.

---

## 3. Proof sketch — why merge does not break FA1/FA7

### 3.1 T-9 (Safety): the stress branch widens the pool, not the protocol

FA1 / FA5 / FA8 share a structural argument: at most one digest finalizes per height because:

- The committee at height `h` is deterministically derived from `(eligible_pool, seed)`.
- K-of-K committee signatures (MD) require every member to sign at most one digest per `(h, round)` by H2.
- Forging the absent signature is `≤ 2⁻¹²⁸` under EUF-CMA.

When shard T absorbs refugees, the eligible pool grows from `Pool_T` to `Pool_T ∪ Pool_S_refugees`. The structural argument is unchanged:

- **Determinism (L-1.1 analog)**: `Chain::shards_absorbed_by(T)` is a pure function of the chain's `merge_state_`, which is itself a deterministic function of the apply order of MERGE_EVENT txs. The extended pool at height `h` is identical for every honest node that has applied the same blocks. ∎
- **Pigeonhole (L-1.3 analog)**: A committee of K members drawn from `Pool_T ∪ Pool_S_refugees` still requires K distinct Ed25519 signatures over the same `block_digest`. By H1+H2 applied to *every* validator in the extended pool (refugees still obey the honest-behavior assumptions), forging any sig is `≤ 2⁻¹²⁸`.
- **No double-signing across S and T**: A refugee validator `v_S` signing T's merged block at height `h_T` is bound by H2 to its own (h_T, round) on shard T. `v_S`'s signing on shard S at any height is independent (different chain identity, different `block_digest`) — H2 binds per-shard-per-height-per-round, not per-validator-globally.

The validator side of the stress branch mirrors the producer side exactly (same `chain.shards_absorbed_by` call, same `registry.eligible_in_region` lookups), so any block the producer proposes is accepted iff the validator agrees on the extended pool. There is no validator-producer divergence surface. ∎

### 3.2 T-9a (Receipt atomicity): unaffected by who signs

FA7's safety arguments depend on:

- V12: source-side receipt-tx binding by field-equality + size match.
- V13: destination-side dedup against `applied_inbound_receipts_`.
- K-of-K committee verification on receipt ratification at the destination.

None of these depend on *which* validators signed the source block — only that the K-of-K signatures verify under the source-shard committee at the receipt's `src_block_index`. A merged committee absorbing refugees signs source blocks identically: K Ed25519 sigs over the canonical `block_digest`. The destination's receipt-bundle verifier already reconstructs the source committee from beacon-anchored pool view + `shard_committee_regions_[src]` (R2), now extended via `shards_absorbed_by(src)` to include refugees. Verifications pass under exactly the same EUF-CMA assumption as in FA7.

In-flight receipts during BEGIN/END transitions:

- An emitted receipt at height `h_s` on source S, with destination D, is K-of-K signed by S's committee at `h_s`. Whether S is merged at `h_s` affects who signed (refugees + natives, or just natives), but not the structural binding (V12 fields, source block hash).
- The destination D's apply path looks up `applied_inbound_receipts_` keyed by `(src_shard, tx_hash)`. The src_shard is S regardless of merge state; the receipt's identity is stable across transitions.
- L-7.2 (dedup monotonicity) holds because `applied_inbound_receipts_` insertions are monotone-increasing and persist across snapshots.

A receipt emitted before BEGIN and credited after END (or vice-versa) is delivered exactly once. ∎

### 3.3 T-9.1 (Hysteresis prevents flapping)

The merge fires after observing the trigger condition for `merge_threshold_blocks` consecutive blocks. It reverts after `revert_threshold_blocks` consecutive blocks of non-trigger. By the default constants (`merge_threshold_blocks=100`, `revert_threshold_blocks=200`), even a noisy pool-size observation that crosses the 2K boundary every other block cannot fire a revert (which would need 200 consecutive observations above the threshold). The asymmetric 2:1 hysteresis is the protocol-level guarantee against flap.

Bonus: the apply-time idempotency guard (duplicate BEGIN with same (shard, partner) is a no-op via `merge_state_.insert` which fails on key collision) means even a misordered or duplicated BEGIN/END pair cannot corrupt the chain. ∎

---

## 4. What the proof does NOT cover

- **S-036 captured-beacon attack.** A fully-compromised beacon committee could fabricate the MERGE_BEGIN payload's `evidence_window_start` field, claiming a trigger condition that never actually held. R4 Phase 6 ships partial mitigation (bounds checks: window must lie in past, effective_height must respect grace), but full historical validation against on-chain SHARD_TIP records remains a v1.1 work item (currently SHARD_TIP is gossip-only — no on-chain commitment to its absence).
- **Cascading merges.** If shard T (currently absorbing S) also drops below 2K and tries to merge with U, the protocol does not chain S→T→U. v1.x first-trigger-wins; v1.1 work item per the design doc.
- **Auto-detection trigger.** The beacon-side observation logic that emits MERGE_BEGIN automatically based on `eligible_in_region < 2K` over the window is v1.1. Operator-driven MERGE_EVENT via `unchained submit-merge-event` is the v1.x path.
- **Slashing during merge.** Refugees misbehaving on T's merged block are slashed on S (their home chain). Per the R4 design, eligibility clears via the stress-branch predicate the next time S's pool is queried. The cross-chain slashing mechanic (B5 EquivocationEvent relay) already supports this — no special-case logic required.

---

## 5. Implementation cross-reference

| Component | Source |
|---|---|
| `MergeEvent` struct + canonical codec | `include/unchained/chain/block.hpp::MergeEvent`; `src/chain/block.cpp` |
| Validator MERGE_EVENT case (gate + bounds) | `src/node/validator.cpp::check_transactions` MERGE_EVENT branch |
| `Chain::merge_state_` + insert/erase apply | `src/chain/chain.cpp::apply_transactions` |
| `Chain::shards_absorbed_by(partner)` inverse lookup | `include/unchained/chain/chain.hpp` |
| Producer-side stress branch | `src/node/node.cpp::check_if_selected` |
| Validator-side stress branch | `src/node/validator.cpp::check_creator_selection`, `check_abort_certs` |
| `Block::partner_subset_hash` field | `include/unchained/chain/block.hpp::Block` |
| `unchained submit-merge-event` CLI | `src/main.cpp::cmd_submit_merge_event` |
| Integration test | `tools/test_under_quorum_merge.sh` |

A reviewer can confirm safety preservation by:

1. Reading the stress-branch extension at both producer and validator sites; confirm both call the same helper (`chain.shards_absorbed_by`) and same registry filter (`registry.eligible_in_region(refugee_region)`).
2. Confirming `merge_state_` mutations happen only inside `apply_transactions` and only on canonical MERGE_EVENT input.
3. Tracing that the snapshot path round-trips `merge_state` with `refugee_region` so a snapshot-bootstrapped node resumes mid-merge correctly.
4. Confirming the Phase 6 bounds in `check_transactions` reject obviously-forged windows.

---

## 6. Conclusion

T-9 + T-9a establish that R4's under-quorum merge mechanism preserves the safety properties of FA1 and FA7 without modifying their cryptographic reductions — the stress branch extends the eligible pool but does not relax any structural check. The validator mirrors the producer's pool extension, eliminating the divergence surface that would otherwise be a forking risk.

The Phase 6 bounds (effective_height grace, BEGIN evidence window past-bound) constrain the captured-beacon attack surface but do not fully close S-036. Full closure requires on-chain SHARD_TIP records — a v1.1 work item that does not block v1.x acceptance.

Unchained's v1.x merge mechanism is operator-driven (submit-merge-event CLI), audit-trace-friendly (every event is a canonical 26+region_len byte payload in a finalized block), and provably-safety-preserving under standard cryptographic assumptions.
