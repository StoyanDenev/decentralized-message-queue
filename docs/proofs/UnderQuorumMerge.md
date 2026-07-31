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

### Validator gates (`src/node/validator.cpp::check_transactions`, MERGE_EVENT branch)

- `chain_role == BEACON` required (`validator.cpp:862-866`). A shard's `t:` ring is always empty (only a BEACON producer under EXTENDED populates `b.shard_tip_records`), so only a BEACON chain can verify the historical distress witness below; accepting a shard-submitted MERGE_BEGIN would admit a fabricated-distress committee dilution unchecked (the reachable S-036 exploit).
- `sharding_mode == EXTENDED` required.
- Canonical 26+region_len byte payload.
- `event_type ∈ {0, 1}` and `partner_id ≠ shard_id`.
- Region charset `[a-z0-9-_]`, `≤ 32` bytes.
- `effective_height ≥ block.index + merge_grace_blocks` (R4 Phase 6 bound).
- BEGIN: the **historical-witness admission gate** (`validator.cpp:898-945`, S-036 closure, v2.11). Iterate every source-shard height `h ∈ [evidence_window_start, evidence_window_start + merge_threshold_blocks)` and require a committed `t:` shard-tip distress record (`chain.shard_tip_records().find({shard_id, h})`) attesting sub-2K eligibility at each; **fail-closed** on any absent record (`A_beacon_omit`, or the window predates the retained ring) or any record attesting healthy (`eligible_count ≥ 2K`). Guarded by `merge_threshold_blocks != 0` and a u64-overflow check on `evidence_window_start + threshold` (`validator.cpp:915-926`, the overflow guard at `922-926`). **This SUPERSEDES the old `evidence_window_start + merge_threshold_blocks ≤ block.index` arithmetic bound** (`validator.cpp:910-914`): that compared the source-height window against the BEACON containing-block height and — since shards outrun the beacon — false-rejected legitimate windows; `block.index` is no longer used in the BEGIN check.

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

- **S-036 captured-beacon attack — CLOSED (v2.11).** A fully-compromised beacon committee could once fabricate the MERGE_BEGIN payload's `evidence_window_start` field, claiming a trigger condition that never actually held. This is now closed: the BEGIN historical-witness admission gate (`validator.cpp:898-945`) validates the claimed window against the on-chain `t:` SHARD_TIP distress records — every source-shard height in `[evidence_window_start, +merge_threshold_blocks)` must carry a committed sub-2K record, fail-closed on any absent record or any record attesting health. The `t:` ring is **state-root-bound** (folded into `compute_state_root` at `chain.cpp:402-414`) and snapshot-inherited, so archive and snapshot-bootstrapped BEACON nodes verify against the same committed set, and a beacon that tried to forge a distress claim would have to rewrite the committed `t:` leaves — breaking `state_root` and tripping the S-033 gate. The gate is BEACON-only (`validator.cpp:862-866`), since a shard's `t:` ring is empty and cannot verify. Residual (not a safety hole): the gate verifies the *committed presence* of distress records but cannot manufacture them — activating the end-to-end merge flow (beacon emitter + beacon→shard propagation) is an owner-gated Layer-2 item, so the merge feature is dormant until that ships.
- **Cascading merges.** If shard T (currently absorbing S) also drops below 2K and tries to merge with U, the protocol does not chain S→T→U. v1.x first-trigger-wins; v1.1 work item per the design doc.
- **Auto-detection trigger.** The beacon-side observation logic that emits MERGE_BEGIN automatically based on `eligible_in_region < 2K` over the window is v1.1. Operator-driven MERGE_EVENT via `determ submit-merge-event` is the v1.x path.
- **Slashing during merge.** Refugees misbehaving on T's merged block are slashed on S (their home chain). Per the R4 design, eligibility clears via the stress-branch predicate the next time S's pool is queried. The cross-chain slashing mechanic (B5 EquivocationEvent relay) already supports this — no special-case logic required.

---

## 5. Implementation cross-reference

| Component | Source |
|---|---|
| `MergeEvent` struct + canonical codec | `include/determ/chain/block.hpp::MergeEvent`; `src/chain/block.cpp` |
| Validator MERGE_EVENT case (gate + bounds) | `src/node/validator.cpp:862-949` (MERGE_EVENT branch: BEACON-role gate `862-866`, shape/charset/grace bounds, BEGIN witness gate) |
| BEGIN historical-witness admission gate (S-036 closure, v2.11) | `src/node/validator.cpp:898-945` (iterate `[evidence_window_start, +merge_threshold_blocks)` over `chain.shard_tip_records()`, fail-closed on absent/healthy; overflow guard `922-926`) |
| `t:` SHARD_TIP distress-record ring, state-root-bound | `src/chain/chain.cpp:402-414` (`build_state_leaves`, folds `shard_tip_records_` into `state_root`) |
| `Chain::merge_state_` + insert/erase apply | `src/chain/chain.cpp::apply_transactions` (MERGE_EVENT branch ~1482) |
| `Chain::shards_absorbed_by(partner)` inverse lookup | `include/determ/chain/chain.hpp` |
| Producer-side stress branch | `src/node/node.cpp::check_if_selected` |
| Validator-side stress branch | `src/node/validator.cpp::check_creator_selection`, `check_abort_certs` |
| `Block::partner_subset_hash` field | `include/determ/chain/block.hpp::Block` |
| `determ submit-merge-event` CLI | `src/main.cpp::cmd_submit_merge_event` |
| Integration test | `tools/test_under_quorum_merge.sh` |

A reviewer can confirm safety preservation by:

1. Reading the stress-branch extension at both producer and validator sites; confirm both call the same helper (`chain.shards_absorbed_by`) and same registry filter (`registry.eligible_in_region(refugee_region)`).
2. Confirming `merge_state_` mutations happen only inside `apply_transactions` and only on canonical MERGE_EVENT input.
3. Tracing that the snapshot path round-trips `merge_state` with `refugee_region` so a snapshot-bootstrapped node resumes mid-merge correctly.
4. Confirming the BEGIN historical-witness gate (`validator.cpp:898-945`) rejects a MERGE_BEGIN whose `[evidence_window_start, +merge_threshold_blocks)` window lacks a committed sub-2K `t:` record at any source height (fail-closed on absent/healthy), that the gate is BEACON-only (`862-866`), and that the `t:` ring folds into `state_root` (`chain.cpp:402-414`) so the verified records are snapshot-inherited and tamper-evident.

---

## 6. Conclusion

T-9 + T-9a establish that R4's under-quorum merge mechanism preserves the safety properties of FA1 and FA7 without modifying their cryptographic reductions — the stress branch extends the eligible pool but does not relax any structural check. The validator mirrors the producer's pool extension, eliminating the divergence surface that would otherwise be a forking risk.

The Phase 6 effective_height-grace bound plus the BEGIN **historical-witness admission gate** (`validator.cpp:898-945`) **close S-036** (v2.11): the gate validates the claimed distress window against the state-root-bound on-chain `t:` SHARD_TIP records, requiring a committed sub-2K record at every in-window source height and failing closed on any absent-or-healthy record. On-chain SHARD_TIP records — once a v1.1 work item — are now shipped and folded into `state_root` (`chain.cpp:402-414`), so a captured beacon can no longer admit a fabricated-distress merge without breaking `state_root`. The gate is BEACON-only (`validator.cpp:862-866`); end-to-end activation of the merge flow (beacon emitter + beacon→shard propagation) remains an owner-gated Layer-2 item, so the mechanism is dormant-but-safe.

Determ's v1.x merge mechanism is operator-driven (submit-merge-event CLI), audit-trace-friendly (every event is a canonical 26+region_len byte payload in a finalized block), and provably-safety-preserving under standard cryptographic assumptions.
