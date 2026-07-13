# S036UnderQuorumMerge — R7 under-quorum-merge mechanism soundness composition

This document is the analytic composition theorem covering Determ's R7 under-quorum-merge mechanism (the runtime layer that absorbs a stressed shard's committee into a healthy partner's via `MERGE_BEGIN` / `MERGE_END` `MergeEvent` transactions and `Chain::merge_state_` chain state). The proof composes the EXTENDED-mode wire-format gate (`validator.cpp` MERGE_EVENT branch), the apply-time state machine (`chain.cpp` MERGE_EVENT case + `is_shard_merged` + `shards_absorbed_by` accessors), and the leading `evidence_window_start <= b.index` past-bound (the S-036 partial closure) against three adversary families — `A_beacon_forge`, `A_merge_replay`, and `A_self_merge` — and then carries the S-036 closure path into v2.11 (the deterministic beacon-side FSM + `validate_merge_event_historical` historical replay). The proof exists because the FA9 `UnderQuorumMerge.md` proof covers safety preservation (FA1 K-of-K + FA7 cross-shard atomicity stay sound across BEGIN/END transitions) but does NOT formalize the MERGE_BEGIN admission soundness, the MERGE_END idempotence, the bounded-time liveness preservation, the safety preservation under merge cascade, or the v2.11 closure-path composition; this proof fills those gaps as a single companion document so that an external auditor can confirm S-036's current partial-closure status and v2.11's full-closure trajectory without re-walking the source.

The S-036 finding itself was originally a generic "evidence-inclusion-window forgery" concern (an adversary fabricating `evidence_window_start` to make a MERGE_BEGIN look justified when the source shard's committee was actually healthy). The in-session partial closure tightened the EXTENDED-mode validator branch with a leading `evidence_window_start <= b.index` past-bound at `src/node/validator.cpp:772-776` — defeating the integer-overflow bypass that could otherwise wrap `evidence_window_start + threshold` below `b.index`. The full closure waits on v2.11 (V2-DESIGN.md §v2.11), which deterministically replays the beacon's MergeMonitor FSM against the historical chain segment in `[evidence_window_start, effective_height)` and rejects MERGE_BEGIN whose triggering predicate would not have fired under honest observation. v2.11 closes the operator-trust-singleton problem documented in V2-DESIGN.md §v2.11; this proof formalizes the composition.

**Companion documents.** `UnderQuorumMerge.md` (FA9 — the FA-track parent proof for safety preservation under merge); `RegionalSharding.md` (FA8 — regional-sharding committee soundness, the parent FA-track theorem); `Preliminaries.md` (F0) §2.1 for SHA-256 collision resistance (A2) and §3 for the committee-selection determinism that L-2 invokes; `Safety.md` (FA1) for the K-of-K per-shard safety bound that T-4 preserves under merge; `CrossShardReceipts.md` (FA7) for the cross-shard atomicity that T-4 invokes; `MultiEventComposition.md` (FA-Apply-15) for the per-block joint multi-event apply that T-2 + T-4 invoke; `S033StateRootNamespaceCoverage.md` for the `m:` namespace coverage that anchors `merge_state_` into the state_root commitment; `docs/SECURITY.md` §S-036 for the closure-status narrative this proof formalizes; `docs/V2-DESIGN.md` §v2.11 for the deterministic beacon-side FSM that closes S-036 fully; `docs/PROTOCOL.md` §6.4 (R4 substrate) for the wire-level contract.

---

## 1. Background

### 1.1 The R7 under-quorum-merge motivation

A Determ regional-sharded deployment (FA8 / R2) partitions validator stake by region: each shard's committee is selected via `Node::check_if_selected` / `BlockValidator::check_creator_selection` from the shard's `eligible_in_region(region)` pool. A shard whose pool drops below `2K` (the safety floor for FA1's K-of-K committee selection) is in a degraded-quorum state — the protocol still satisfies its safety conditions (committee selection picks from the smaller pool; per-shard safety holds), but liveness slack thins. A single additional validator drop tips into `< K`, and the shard stalls indefinitely until either (a) a previously-departed validator re-registers (random per-deployment latency), or (b) the operator notices and intervenes.

R7 introduces the under-quorum-merge mechanism: when shard `s`'s committee pool drops below the trigger threshold for `merge_threshold_blocks` consecutive blocks, a `MERGE_BEGIN` event admits `s` into a partner shard `(s+1) mod shard_count` so that the partner's committee absorbs `s`'s refugee validators via the eligibility-stress branch (`Chain::shards_absorbed_by` + `registry.eligible_in_region(refugee_region)` extension; see `Node::check_if_selected` + `BlockValidator::check_creator_selection`). When `s`'s pool recovers above the revert threshold for `revert_threshold_blocks` consecutive blocks, a `MERGE_END` event clears the absorbed state and shard `s` resumes independent operation.

The mechanism preserves FA1 (K-of-K safety) and FA7 (cross-shard receipt atomicity) per the FA9 / `UnderQuorumMerge.md` proof. This proof (S036UnderQuorumMerge) extends FA9's coverage to the *origination* side: how MERGE_BEGIN is admitted, why it cannot be forged by `A_beacon_forge` (the EXTENDED-mode adversary that could otherwise issue a baseless MERGE_BEGIN), how MERGE_END's idempotence prevents replay attacks, and how the v2.11 closure path makes the historical-witness check cryptographically meaningful.

### 1.2 The S-036 finding

S-036's pre-mitigation description: in EXTENDED mode, the validator gates on `MergeEvent.event_type ∈ {0, 1}` + region charset + `partner_id ≠ shard_id` + canonical decode + `effective_height ≥ b.index + grace` + (BEGIN only) `evidence_window_start + threshold ≤ b.index`. The historical-witness assertion underneath `evidence_window_start` is informational only — the validator cannot deterministically replay the source shard's MergeMonitor FSM against the historical chain in v1.0 because the chain does not carry on-chain SHARD_TIP records (the BEACON observes them but never persists them as transactions). A captured beacon committee that emits a MERGE_BEGIN against a healthy shard fails no chain-side check; the K-committee co-signs (under the H1 honest-validator assumption the committee follows the protocol; under the captured-beacon adversary the committee *is* the captured set), and the merge applies.

The in-session partial closure ships at `src/node/validator.cpp:772-776`:

```cpp
// S-036 tighten: check `evidence_window_start <= b.index`
// up-front so the threshold-arithmetic check that follows
// cannot be bypassed by integer overflow (an attacker setting
// evidence_window_start near UINT64_MAX could make the sum wrap
// below b.index and falsely pass the original check; this
// leading bound rejects that case before the addition).
if (ev->evidence_window_start > b.index) {
    return {false, "MERGE_EVENT BEGIN evidence_window_start "
                 + std::to_string(ev->evidence_window_start)
                 + " is in the future (block height "
                 + std::to_string(b.index) + ")"};
}
```

This past-bound rejects the integer-overflow bypass that could otherwise wrap the `evidence_window_start + threshold > b.index` check below `b.index`. The semantic remaining gap — fabricated-but-overflow-safe `evidence_window_start` values — is bounded to a single under-quorum-window-sized attack per merge and is closed fully by v2.11.

### 1.3 The R7 mechanism summary

Per the R4 design (`UnderQuorumMerge.md` §1):

**Wire format.** `MergeEvent` (`include/determ/chain/block.hpp:321-337`) carries `(event_type, shard_id, partner_id, effective_height, evidence_window_start, merging_shard_region)`. Canonical encoding via `MergeEvent::encode` + `MergeEvent::decode` with `event_type ∈ {0, 1}` + region charset `[a-z0-9-_]` + region length cap 32 bytes + partner ≠ shard.

**Chain state.** `Chain::merge_state_` (`include/determ/chain/chain.hpp:328-332`) is a `std::map<ShardId, MergePartnerInfo>` keyed by the refugee shard id. Each entry stores `{partner_id, refugee_region}` (refugee_region is empty for global-pool refugees, non-empty for region-scoped refugees). Absence from the map = NOT MERGED. Mutates only inside `Chain::apply_transactions` MERGE_EVENT case (`src/chain/chain.cpp:1017-1039`). Snapshot-serialized via `serialize_state` (chain.cpp:1637-1645) and snapshot-restored via `restore_from_snapshot` (chain.cpp:1790-1793).

**Apply state machine.**

- **BEGIN.** `MergeEvent::decode(tx.payload)` succeeds + `shard_count_ > 1` + `partner_id == (shard_id + 1) mod shard_count_` ⇒ insert `{shard_id → {partner_id, refugee_region}}` into `merge_state_`. Idempotent: `std::map::insert` on a pre-existing key is a no-op.
- **END.** Find `merge_state_[shard_id]` AND `merge_state_[shard_id].partner_id == event.partner_id` ⇒ erase. Idempotent: missing entry ⇒ no-op; mismatched partner ⇒ no-op.

**Eligibility stress branch.** Partners absorbing refugees extend their committee pool via `Chain::shards_absorbed_by(partner)` (returns the list of `(shard_id, refugee_region)` pairs whose merge partner is `partner`). Each `(shard_id, refugee_region)` extends the eligible pool with `registry.eligible_in_region(refugee_region)`. Producer-side (`Node::check_if_selected`) and validator-side (`BlockValidator::check_creator_selection` + `check_abort_certs`) all call the same extension logic; no producer-validator divergence.

**State-root binding.** `merge_state_` contributes to the `m:` namespace of the S-033 state_root commitment via `Chain::build_state_leaves` (`src/chain/chain.cpp:350-360`). Each MERGE_BEGIN / MERGE_END that mutates `merge_state_` produces a state_root delta that the apply-time gate at `chain.cpp:1421-1446` enforces cross-node post-apply.

### 1.4 The v2.11 closure path

> **⚠ SUPERSEDED — the as-built D3 SHARD_TIP arc (D3.1–D3.7) does NOT use a MergeMonitor FSM.** The
> shipped S-036 mitigation reads the committed `t:` shard-tip distress records over the SOURCE-shard
> window `[evidence_window_start, evidence_window_start + merge_threshold_blocks)` and admits a
> `MERGE_BEGIN` only on contiguous sub-2K coverage (uniform fail-closed on any absent record) — there
> is NO FSM, NO `{NORMAL, STRESS_CANDIDATE, …}` state machine, and NO `[evidence_window_start,
> effective_height)` replay. And the reachable exploit is closed by FAIL-CLOSING `MERGE_EVENT` on
> every non-BEACON+EXTENDED chain (D3.6, `1fda852`), not by the FSM below. S-036 is **STRONGLY
> MITIGATED, not CLOSED** — trustless closure is the owner-gated Layer 2 (D3.5e). The T-5 language
> below (an FSM replay reaching `MERGE_PENDING`) describes the RETIRED design; the operative spec is
> `ShardTipMergeDesign.md` §3.4/§9, the shipped soundness is `ShardTipMergeSoundness.md`, and the
> posture is `docs/SECURITY.md` S-036. Retained here for provenance.

V2-DESIGN.md §v2.11 specifies the deterministic beacon-side MergeMonitor FSM that closes S-036 fully:

1. Each beacon-tracked shard has a `MergeMonitor[s]` with states `{NORMAL, STRESS_CANDIDATE, STRESS_CONFIRMED, MERGE_PENDING, MERGED, RECOVERY_CANDIDATE, RECOVERY_CONFIRMED}`.
2. The FSM observes already-public chain state (`registrants_`, `SHARD_TIP_*` arrivals, per-shard tx-flow) and transitions deterministically based on `consecutive_stress_blocks`, `consecutive_recovery_blocks`, and `stress_confirm_blocks` + `merge_threshold_blocks` + `recovery_hysteresis` + `recovery_confirm_blocks` thresholds.
3. The partner-resolution algorithm (V2-DESIGN.md §v2.11 "Partner-resolution algorithm") picks the merge partner deterministically from public chain state.
4. The validator-side `BlockValidator::validate_merge_event_historical` replays the MergeMonitor FSM over `[evidence_window_start, effective_height)` and accepts a `MERGE_EVENT` iff the FSM trajectory reaches `MERGE_PENDING` (for BEGIN) or `RECOVERY_CONFIRMED` (for END) under the deterministic algorithm.

Per V2-DESIGN.md §v2.11: "A captured-beacon adversary that submits a `MERGE_BEGIN` against an actually-healthy shard fails this check at validator time on every honest node; the K-committee will not co-sign a block whose `MERGE_EVENT` tx fails validate." The historical replay is `O(merge_threshold_blocks)` per `MERGE_EVENT` — at default 100 blocks this is negligible compared to per-block apply cost.

This proof's T-5 formalizes the v2.11 closure as a composition step on top of T-1 through T-4.

---

## 2. Notation and assumptions

### 2.1 Cryptographic and behavioral assumptions

- **(A1) Ed25519 EUF-CMA** — `Verify(pk, m, σ) = 1` implies the holder of `sk` signed `m`, except with probability `≤ 2⁻¹²⁸`. Per `Preliminaries.md` §2.1. Used in T-3 + T-4 (the K-committee signature requirement that backs MERGE_EVENT inclusion).
- **(A2) SHA-256 collision resistance** — finding `x ≠ y` with `SHA256(x) = SHA256(y)` is `≤ 2⁻¹²⁸`. Per `Preliminaries.md` §2.1. Used in T-2 (MERGE_END idempotence under canonical encoding) + T-4 (state_root binding of `merge_state_` via the `m:` namespace) + T-5 (v2.11 historical replay's hash-based monitor-state continuity).
- **(H1)** Honest validators follow the protocol. Used throughout — the captured-beacon adversary is the H1-violating case that S-036 addresses.
- **(H2)** Honest validators sign at most one digest per `(height, round)`. Used in T-4 (no double-signing across S and T under merge).

### 2.2 Wire and apply primitives

**`MergeEvent` struct** (`include/determ/chain/block.hpp:321-337`):

```
struct MergeEvent {
    enum Type : uint8_t { BEGIN = 0, END = 1 };
    uint8_t      event_type{BEGIN};
    uint32_t     shard_id{0};
    uint32_t     partner_id{0};
    uint64_t     effective_height{0};
    uint64_t     evidence_window_start{0};   // BEGIN only; 0 for END
    std::string  merging_shard_region{};     // refugee shard's region
};
```

Canonical encoding via `MergeEvent::encode` produces a fixed 26+region_len byte payload (1 byte event_type + 4 bytes shard_id LE + 4 bytes partner_id LE + 8 bytes effective_height LE + 8 bytes evidence_window_start LE + 1 byte region_len + region_bytes). `MergeEvent::decode` returns `std::nullopt` on size mismatch, invalid event_type, or region_len > 32.

**Validator gate** (`src/node/validator.cpp:713-788`):

1. `sharding_mode_ == ShardingMode::EXTENDED` (line 728).
2. `MergeEvent::decode(tx.payload)` succeeds (line 732-735).
3. `partner_id ≠ shard_id` (line 737-738).
4. Region charset `[a-z0-9-_]`, ≤ 32 bytes (line 741-748).
5. `effective_height ≥ b.index + grace` where `grace := chain.merge_grace_blocks()` (line 753-757).
6. BEGIN only: `evidence_window_start ≤ b.index` (the S-036 partial closure at line 772-776).
7. BEGIN only: `threshold > 0 ⇒ evidence_window_start + threshold ≤ b.index` where `threshold := chain.merge_threshold_blocks()` (line 778-783).
8. Modular arithmetic check `partner_id == (shard_id + 1) mod shard_count_` deferred to apply (line 785-787; apply at chain.cpp:1021 enforces).

**Apply state machine** (`src/chain/chain.cpp:1017-1039`):

```cpp
case TxType::MERGE_EVENT: {
    if (!charge_fee(sender, tx.fee)) continue;
    auto ev = MergeEvent::decode(tx.payload);
    if (ev && shard_count_ > 1
        && ev->partner_id == ((ev->shard_id + 1) % shard_count_)) {
        if (ev->event_type == MergeEvent::BEGIN) {
            MergePartnerInfo info;
            info.partner_id     = ev->partner_id;
            info.refugee_region = ev->merging_shard_region;
            __ensure_merge_state();
            merge_state_.insert({ev->shard_id, std::move(info)});
        } else {  // END
            auto it = merge_state_.find(ev->shard_id);
            if (it != merge_state_.end()
                && it->second.partner_id == ev->partner_id) {
                __ensure_merge_state();
                merge_state_.erase(it);
            }
        }
    }
    sender.next_nonce++;
    break;
}
```

`std::map::insert` is idempotent on a pre-existing key (returns `{existing_iterator, false}` and does not mutate). `std::map::erase` on an iterator to a present element removes; the surrounding `find()` + present-and-partner-match gate handles the missing-key and mismatched-partner cases as no-ops.

### 2.3 Adversary models

Three adversary families are the proof's targets:

**`A_beacon_forge` (EXTENDED-mode beacon adversary).** The beacon committee is compromised (H1 violated for the beacon's K-committee). The adversary fabricates a MERGE_BEGIN against shard `s` claiming `evidence_window_start` (a historical window the adversary asserts contained under-quorum observations). The adversary's goal: force shard `s` into the MERGED state when `s`'s committee was actually healthy, so that the partner shard absorbs `s`'s refugees and the adversary controls more refugee capacity. Defense: §3 T-1 (current partial closure via past-bound) + §3 T-5 (full closure via v2.11 historical replay).

**`A_merge_replay` (event-replay adversary).** The adversary captures a finalized MERGE_BEGIN or MERGE_END event and replays it (or its byte-identical copy under a new tx envelope) to cause repeated merge / un-merge cascades. The adversary's goal: oscillate `merge_state_` to perturb committee selection, force repeated state_root recompute cost, or confuse light clients. Defense: §3 T-2 (idempotence) + nonce monotonicity (FA-Apply-3) + the canonical encoding's signing_bytes binding (events ride on signed transactions; replaying with a stale nonce fails apply).

**`A_self_merge` (malformed-payload adversary).** The adversary crafts a MERGE_EVENT with `partner_id == shard_id` (or other malformed shape). The adversary's goal: pollute `merge_state_` with self-referential entries that would break the eligibility-stress branch's pool extension logic or create a wedge for invariant violations. Defense: validator gate at validator.cpp:737-738 (`partner_id ≠ shard_id` rejection) + apply gate at chain.cpp:1021 (modular arithmetic check rejects non-canonical partner pairings).

---

## 3. Theorem set

**Theorem T-1 (MERGE_BEGIN Soundness — current partial closure).** Under EXTENDED mode + H1 for the gossip-receiver path, a MERGE_BEGIN can only be admitted to `Chain::apply_transactions`'s MERGE_EVENT case iff ALL of the following hold:

1. `sharding_mode_ == ShardingMode::EXTENDED`.
2. The canonical-encoding decode succeeds with `event_type == 0`.
3. `partner_id ≠ shard_id`.
4. Region charset `[a-z0-9-_]`, ≤ 32 bytes.
5. `effective_height ≥ b.index + chain.merge_grace_blocks()`.
6. `evidence_window_start ≤ b.index` (the S-036 partial closure).
7. `chain.merge_threshold_blocks() > 0 ⇒ evidence_window_start + chain.merge_threshold_blocks() ≤ b.index`.
8. `partner_id == (shard_id + 1) mod shard_count_` (apply-time check).

Adversary `A_beacon_forge` is currently defeated against (6) — the integer-overflow bypass that pre-S-036 could wrap `evidence_window_start + threshold` below `b.index` is now rejected at the leading past-bound. Residual gap: an `A_beacon_forge` adversary can still claim an `evidence_window_start` value that is past-bounded but historically false (the validator cannot deterministically replay the historical chain in v1.0 / R7 without on-chain SHARD_TIP records). Residual gap is bounded to a single under-quorum-window-sized attack per merge until v2.11 ships (see T-5).

**Theorem T-2 (MERGE_END Idempotence).** Apply of a MERGE_END for `(shard_id, partner_id)` produces one of three outcomes:

1. **First MERGE_END after a matching BEGIN.** `merge_state_.find(shard_id)` returns a valid iterator with `partner_id` matching; the entry is erased. Subsequent state-root recompute reflects the erasure via the `m:` namespace (`build_state_leaves` chain.cpp:350-360 no longer emits the leaf for `shard_id`).
2. **Subsequent MERGE_ENDs with the same `(shard_id, partner_id)`.** `merge_state_.find(shard_id)` returns `end()` (the entry was already erased); the case-bottom no-op fires. No state change, no exception.
3. **MERGE_END with mismatched `partner_id`.** `merge_state_.find(shard_id)` returns a valid iterator but `it->second.partner_id ≠ ev->partner_id`; the gate at chain.cpp:1030-1031 short-circuits. No state change.

Therefore: replaying a MERGE_END after the first apply is a no-op; mismatched-partner MERGE_ENDs are no-ops; pre-BEGIN MERGE_ENDs are no-ops. The apply path is idempotent over MERGE_END events. Defends against `A_merge_replay`.

**Theorem T-3 (Liveness Preservation).** Under FA9's standard liveness assumptions (committee selection deterministic from `(eligible_pool, seed)`; under-quorum trigger condition observable to honest validators), when:

1. Shard `s`'s committee pool drops below `2K` for `chain.merge_threshold_blocks()` consecutive blocks (the trigger condition), AND
2. A valid MERGE_BEGIN with `evidence_window_start = h_s_trigger_entry` and `effective_height ≥ b.index + grace` is observed,

then the merge applies within bounded time `Δ_merge ≤ chain.merge_grace_blocks() + 1` blocks past the MERGE_EVENT's inclusion. The bound holds because:

- After validator gate-pass, the MERGE_EVENT tx is includable in any block at height `H_effective = effective_height`.
- The apply at chain.cpp:1027 inserts into `merge_state_` synchronously within `apply_transactions`.
- The next block's committee selection (at height `H_effective + 1`) sees the updated `merge_state_` via `Chain::shards_absorbed_by(partner)` (Phase 4 stress branch).
- The partner's committee at `H_effective + 1` is extended with refugees from shard `s`, restoring liveness.

The bound `Δ_merge ≤ chain.merge_grace_blocks() + 1` is tight: the lower bound (`grace`) ensures committees observe the transition before it fires (no validator-producer divergence); the upper bound (+1) is the single block needed to apply the MERGE_EVENT itself.

**Theorem T-4 (Safety Under Merge — FA1 + FA7 preservation).** A merged committee (partner absorbing refugees) preserves both FA1 (K-of-K per-shard safety, ≤ 1 finalized digest per height with bound `≤ 2⁻¹²⁸ · K`) and FA7 (cross-shard receipt atomicity, every emitted receipt is credited exactly once at the destination). The argument is mostly an invocation of FA9 / `UnderQuorumMerge.md` T-9 + T-9a:

- **T-9 (FA1 preservation).** The eligible pool grows from `Pool_T` to `Pool_T ∪ Pool_S_refugees`. K-of-K committee signatures require K distinct Ed25519 signatures over the same `block_digest` regardless of pool composition; refugees obey H1+H2 on T's chain at height `h_T`; A1's EUF-CMA bound applies per-validator. No double-signing across S and T because H2 binds per-`(shard, height, round)`, not per-validator-globally.
- **T-9a (FA7 preservation).** Cross-shard receipts depend only on the source committee's K-of-K signature over `block_digest` at the receipt's `src_block_index`. The destination's `applied_inbound_receipts_` is keyed by `(src_shard, tx_hash)` — invariant across merge transitions. A receipt emitted before BEGIN and credited after END (or vice versa) is delivered exactly once via L-7.2 (dedup monotonicity, FA7).

Additionally, the merge does not alter the target shard's per-block apply rules: the target's `apply_transactions` continues to require K-of-K signatures from the (extended) committee at its own height. Pending refugee transactions are absorbed into the target's mempool via the standard mempool admission path (the producer-side stress branch in `Node::check_if_selected` exposes the extended pool for committee selection; the per-tx admission gates are unchanged). T-4 holds.

**Theorem T-5 (S-036 Closure Path — v2.11 composition).** The v2.11 deterministic-FSM trigger composes with T-1 through T-4 to close S-036 fully:

1. **Origination side.** Each honest beacon node tracks a `MergeMonitor[s]` per shard `s`, transitioning the FSM deterministically over public chain state per V2-DESIGN.md §v2.11. MERGE_BEGIN is emitted only when the FSM reaches `MERGE_PENDING`.
2. **Validation side.** `BlockValidator::validate_merge_event_historical` replays the MergeMonitor FSM over `[evidence_window_start, effective_height)` against the chain's historical state at each height. The replay accepts a MERGE_BEGIN iff the FSM trajectory reaches `MERGE_PENDING` at or before `effective_height` AND `consecutive_stress_blocks ≥ merge_threshold_blocks` at `effective_height`.
3. **Composition.** T-1's validator gate (steps 1-8) AND T-5's historical replay AND T-2 + T-3 + T-4 jointly bound `A_beacon_forge` to zero on every honest node post-v2.11. The captured-beacon adversary fabricating an `evidence_window_start` for a healthy shard fails the historical replay; the K-committee will not co-sign the block (per H1 on the receiver path); the chain doesn't advance with a baseless MERGE_BEGIN.

T-5 reduces the S-036 closure status from "EXTENDED-mode partial" to "fully closed for the v2.11 trigger path." The original S-036 broad scope (evidence inclusion windows for evidence/abort txs) is closed separately via the in-session `evidence_window_start ≤ b.index` past-bound shipped on the validator-side MERGE_EVENT branch.

---

## 4. Composition with FA-track

### 4.1 FA8 (RegionalSharding.md) — regional-sharding committee soundness

R7 under-quorum-merge sits underneath FA8's regional-sharding theorem. FA8 establishes:

- Committee selection is deterministic from `(eligible_pool, seed)` (FA8 T-8 determinism).
- Each shard's committee is selected from `registry.eligible_in_region(region)` — the regional-isolation property that bounds Sybil cost (S-010 / S-011 composition).
- Cross-shard committee membership is region-bounded (a validator registered in region `R_A` cannot serve shard `B`'s committee unless `B`'s region is `R_A` or empty / global).

R7 extends FA8's committee-selection rule with the eligibility stress branch: when partner shard `T` absorbs refugees from `S`, `T`'s committee is selected from `eligible_in_region(T_region) ∪ eligible_in_region(S_region)` via `Chain::shards_absorbed_by(T)` (chain.hpp:346-353). The composition is sound because:

- `shards_absorbed_by` is a pure function of `merge_state_`, which is itself a pure function of the chain's MERGE_EVENT apply order (by T-1 + T-2). Determinism holds across all honest observers.
- The producer-side path (`Node::check_if_selected`) and validator-side path (`BlockValidator::check_creator_selection` + `check_abort_certs`) both call the same `shards_absorbed_by` accessor. No producer-validator divergence; FA8 T-8's determinism guarantee carries forward to the extended pool.
- Region-aware MERGE_EVENT (carrying `merging_shard_region`) preserves the refugee's region tag so that the partner's stress-branch lookup `registry.eligible_in_region(refugee_region)` matches the refugee's original region. The cross-region pool extension is explicit, deterministic, and carried in chain state — not inferred at runtime.

Conclusion: T-1 + T-3 + T-4 compose with FA8 T-8 to give committee-selection determinism under merge.

### 4.2 FA-Apply-15 (MultiEventComposition.md) — heterogeneous multi-event apply

FA-Apply-15 T-M4 establishes: per-block joint state-root binding across heterogeneous event types (TRANSFER, REGISTER, STAKE, UNSTAKE, DEREGISTER, PARAM_CHANGE, MERGE_EVENT, DAPP_REGISTER, DAPP_CALL, ABORT_RECORDED, EQUIVOCATION_EVENT, CROSS_SHARD_RECEIPT). The state-root commitment via S-033's 10-namespace coverage (the `m:` namespace for `merge_state_`) jointly binds all event-effects in one Merkle root.

The composition with this proof:

- A MERGE_EVENT applied alongside any other event types in the same block produces a single post-apply state. T-1's gate runs at validate time (before apply); T-2's idempotence runs at apply time; FA-Apply-15 T-M4's joint state-root commitment captures the combined effect.
- The apply-time state_root gate at chain.cpp:1421-1446 fires identically for MERGE_EVENT-bearing blocks as for any other block. The S-033 promise composes orthogonally.
- A_merge_replay's defense (T-2) composes with the FA-Apply-3 nonce monotonicity surface: the MERGE_EVENT rides on a signed transaction with a per-sender nonce; replay requires either a new tx envelope (nonce mismatch ⇒ apply rejects) or byte-identical replay (tx_hash already in block ⇒ block-level dedup catches).

### 4.3 FA1 (Safety.md) — per-shard K-of-K safety preserved post-merge

FA1's K-of-K committee signature requirement establishes that at most one digest finalizes per height per shard, with bound `≤ 2⁻¹²⁸ · K`. The post-merge target shard absorbs refugee validators into its committee pool; the per-shard apply rule still requires K signatures over the target's `block_digest`.

T-4's invocation of FA1:

- The target shard's committee at height `h_T` is selected from the extended pool. The pool is deterministic (by FA8 composition + T-1 + T-2).
- K-of-K signatures over `block_digest` at `h_T` are required for finalization; refugee validators participating in the target's committee sign under their own private keys, with the same EUF-CMA bound.
- No refugee can double-sign across S and T at the same `(height, round)` because (by H2) honest refugees sign at most one digest per `(height, round)`; the refugee's signing on S is at S's heights (different chain identity, different `block_digest`); the refugee's signing on T is at T's heights. H2 binds per-`(shard, height, round)`, not per-validator-globally.

Conclusion: FA1's K-of-K safety bound is preserved unchanged under merge. The S-036 closure does not weaken FA1; it tightens the *origination* path so that baseless MERGE_BEGINs cannot enter the apply path in the first place.

---

## 5. Adversary model

The proof's threat model considers three adversary surfaces; each is bounded by a different mechanism of T-1 + T-2 + T-5.

**(a) `A_beacon_forge` (EXTENDED-mode beacon adversary).** The captured beacon committee fabricates a MERGE_BEGIN against a healthy shard.

- **Current partial closure (T-1).** The leading `evidence_window_start ≤ b.index` past-bound at validator.cpp:772-776 rejects integer-overflow bypass attempts. The semantic remaining gap — fabricated-but-overflow-safe `evidence_window_start` values pointing to past-but-false windows — is bounded to a single under-quorum-window-sized attack per merge. The merge applies if the captured beacon's K-committee co-signs, but the partner shard absorbs the refugee pool deterministically, so the only attack consequence is forcing refugee pooling against the target — the partner's safety is still preserved by T-4 (FA1 + FA7 unchanged).
- **Full closure (T-5, v2.11).** The historical replay at `validate_merge_event_historical` rejects any MERGE_BEGIN whose FSM trajectory doesn't reach `MERGE_PENDING` over `[evidence_window_start, effective_height)`. Captured-beacon adversaries cannot single-handedly issue merges post-v2.11.

**(b) `A_merge_replay` (event-replay adversary).** The adversary captures a finalized MERGE_BEGIN or MERGE_END event and replays it.

- **Defense via T-2 (idempotence) + FA-Apply-3 (nonce monotonicity).** Replaying a MERGE_END after the first apply is a no-op (T-2 outcome 2). Replaying a MERGE_BEGIN against an already-merged shard is a no-op via `std::map::insert` on a pre-existing key (the BEGIN gate at chain.cpp:1027 returns `{existing_iterator, false}` without mutation). Crafting a new transaction envelope with a fresh nonce to carry the same MERGE_EVENT payload requires the adversary to control a valid signing key for the sender — no privilege escalation surface beyond pre-existing tx-replay attack bounds (FA-Apply-3 nonce monotonicity).

**(c) `A_self_merge` (malformed-payload adversary).** The adversary crafts a MERGE_EVENT with `partner_id == shard_id`.

- **Defense via validator gate + apply gate.** Validator at validator.cpp:737-738 rejects with diagnostic "MERGE_EVENT partner_id equals shard_id"; apply at chain.cpp:1021 enforces `partner_id == (shard_id + 1) mod shard_count_` as a defense-in-depth check (the modular arithmetic rejects same-shard pairs because `(s + 1) mod N ≠ s` for `N > 1`; for `N = 1` the apply path early-exits because `shard_count_ > 1` is required at chain.cpp:1020).

**(d) `A_merge_overflow` (integer-overflow specific to S-036).** The adversary sets `evidence_window_start` near `UINT64_MAX` so that `evidence_window_start + threshold` wraps below `b.index`, falsely passing the original post-bound check at validator.cpp:778-783.

- **Defense via S-036 partial closure (T-1 step 6).** The leading past-bound at validator.cpp:772-776 rejects `evidence_window_start > b.index` before the addition. Wrap-around no longer reaches the post-bound check. This was the in-session partial closure.

---

## 6. Findings

### F-1 (Open until v2.11): full S-036 closure path needs on-chain SHARD_TIP records

The full closure of S-036 requires the v2.11 historical-replay check at `BlockValidator::validate_merge_event_historical`. The replay needs deterministic access to the source shard's eligible-region pool at each historical block in `[evidence_window_start, effective_height)`. This in turn requires either:

- **Option A (V2-DESIGN.md §v2.11 default).** On-chain SHARD_TIP records as MERGE_EVENT-like txs that commit each shard's tip to the beacon's chain. Each SHARD_TIP carries `(shard_id, height, eligible_count_at_height)` so the historical replay can deterministically reconstruct the MergeMonitor FSM transitions.
- **Option B (alternative).** Re-derive eligible_in_region(s) from `Chain::registrants_` snapshot at each historical block. This is computable but expensive (O(|registrants_|) per replay step) and requires `ChainHistoryReadHandle` to expose accounts_at_height accessors.

V2-DESIGN.md §v2.11 picks a hybrid: SHARD_TIP arrivals are observed by the beacon (already-public chain state) AND the replay re-derives eligible_in_region(s) from the snapshot pathway. Effort: ~5-7 engineering days per V2-DESIGN.md §v2.11 estimate. Status: design+spec'd; implementation deferred to Phase A v2.11.

### F-2 (EXTENDED-mode-only beacon trust assumption)

Under EXTENDED mode without the v2.11 historical replay, the beacon is the single point of trust for the merge window. The R7 in-session partial closure tightens the wire-level gates but cannot semantically validate the historical claim. This is an EXTENDED-mode-specific concern: SHARD mode does not run merges (single-shard deployments have no partner to absorb into); CURRENT mode is the legacy single-chain path.

The mitigation is operational: deployments running EXTENDED mode should pair the beacon-co-signing requirement (K-of-K committee on the beacon's chain) with operator-side monitoring of pre-merge alerts (via the `mergemonitor_status` RPC once v2.11 ships, or via per-shard registry monitoring scripts in v1.x). Pre-v2.11, the operator-override CLI (`determ submit-merge-event`) remains the audit-trail path for manual merge issuance with chain-event journal entries.

### F-3 (Regional-isolation considerations under R4 region-aware MERGE_EVENT)

The R4 v1.0 substrate carries `merging_shard_region` in the MERGE_EVENT payload (block.hpp:328) so that the partner's stress-branch lookup `registry.eligible_in_region(refugee_region)` retrieves the refugee's original region members. The composition with R4 region-aware committee selection (FA8) is sound because:

- Empty `refugee_region` ⇒ global pool refugees (the refugee shard was running CURRENT mode or used the global pool).
- Non-empty `refugee_region` ⇒ region-scoped refugees; the partner's stress-branch extends with validators tagged with that exact region string.
- The region charset constraint (`[a-z0-9-_]`, ≤ 32 bytes) per validator.cpp:741-748 ensures the region tag is canonicalizable and bounded.

Edge case: a partner whose own region is `R_A` absorbing refugees with region `R_B` results in a committee selected from `R_A ∪ R_B`. If `R_A` and `R_B` are geographically distant, the partner's block-production latency may degrade (cross-region gossip overhead). This is an operational concern, not a safety violation; the V2-DESIGN.md §v2.11 partner-resolution algorithm prefers same-region partners via the region-affinity step (V2-DESIGN.md §v2.11 "Partner-resolution algorithm" step 2).

A future v2.x design item (not blocked on v2.11): partner-resolution could be tightened to prefer partners whose own committee has spare capacity AND whose region overlaps with the refugee's region, falling back to cross-region only when no same-region candidate qualifies. This is informational-only; the v1.x mechanism is sound.

### F-4 (No cascading merges in v1.x)

Per `UnderQuorumMerge.md` §4 "What the proof does NOT cover": if shard `T` (currently absorbing `S`) also drops below `2K` and tries to merge with `U`, the protocol does not chain `S → T → U`. v1.x first-trigger-wins; v2.x design item per `UnderQuorumMerge.md` §4. This is not a soundness concern for the current proof; the protocol gracefully degrades to operator-driven `MERGE_EVENT` issuance via the operator-override path if cascading is needed.

### F-5 (Slashing during merge: refugees slashed on home chain)

Refugees misbehaving on T's merged block are slashed on S (their home chain) via the FA6 EquivocationEvent relay mechanism. Eligibility clears via the stress-branch predicate the next time S's pool is queried. The cross-chain slashing mechanic (B5 EquivocationEvent relay) is already shipped; no special-case logic required for the merge path. T-4's safety preservation composes with FA6 unchanged.

---

## 7. Cross-references

### SECURITY.md sections

- `docs/SECURITY.md` §S-036 — Witness-window forgery finding; EXTENDED-mode-only partial mitigation via the leading `evidence_window_start ≤ b.index` past-bound; v2.11 closes fully.
- `docs/SECURITY.md` §S-016 — Inbound-receipts pool non-determinism; related (cross-shard receipt admission timing) but distinct surface; not composed here.
- `docs/SECURITY.md` §S-030 D2 — Block-body fields not in `block_digest`; MERGE_EVENT tx hashes are bound via `tx_root` (FA2), so block-digest exclusion is not a concern for MERGE_EVENT specifically.

### V2-DESIGN.md sections

- `docs/V2-DESIGN.md` §v2.11 — Auto-detection beacon-side trigger (R4 v1.1). The full S-036 closure path. Includes the MergeMonitor FSM, partner-resolution algorithm, `validate_merge_event_historical` spec, threat-model table, and effort estimate.

### Companion proofs

- `docs/proofs/UnderQuorumMerge.md` (FA9) — Safety preservation under merge (T-9 K-of-K + T-9a cross-shard atomicity + T-9.1 hysteresis no-flapping). The parent FA-track proof; this proof extends FA9's coverage to the origination side (MERGE_BEGIN admission soundness + MERGE_END idempotence + liveness preservation + S-036 closure path).
- `docs/proofs/RegionalSharding.md` (FA8) — Regional-sharding committee soundness. The parent FA-track theorem; this proof's T-3 + T-4 invoke FA8 T-8 (committee-selection determinism) for the stress-branch composition.
- `docs/proofs/Safety.md` (FA1) — K-of-K per-shard safety. The bound `≤ 2⁻¹²⁸ · K` that T-4 preserves under merge.
- `docs/proofs/CrossShardReceipts.md` (FA7) — Cross-shard receipt atomicity. The bound that T-4 preserves under merge.
- `docs/proofs/MultiEventComposition.md` (FA-Apply-15 T-M4) — Per-block joint state-root binding across heterogeneous event types. T-2's idempotence composes orthogonally.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — 10-namespace state-root coverage. The `m:` namespace anchors `merge_state_` into the state_root commitment (T-1 coverage cell for `merge_state_`).
- `docs/proofs/Preliminaries.md` (F0) — §2.1 SHA-256 collision resistance (A2) + Ed25519 EUF-CMA (A1); §3 network and behavior assumptions.

### Implementation sites

- `include/determ/chain/block.hpp:321-337` — `MergeEvent` struct + canonical codec contract.
- `include/determ/chain/chain.hpp:328-353` — `MergePartnerInfo` + `MergeStateMap` + `is_shard_merged` + `shards_absorbed_by` accessors.
- `src/node/validator.cpp:713-788` — Validator MERGE_EVENT branch with full gate sequence (including S-036 partial closure at lines 772-776).
- `src/chain/chain.cpp:1017-1039` — Apply MERGE_EVENT case (BEGIN insert + END erase + idempotence handling).
- `src/chain/chain.cpp:350-360` — `build_state_leaves` `m:` namespace emission (state_root binding of `merge_state_`).
- `src/chain/chain.cpp:1637-1645` — `serialize_state` `merge_state` JSON emission.
- `src/chain/chain.cpp:1790-1793` — `restore_from_snapshot` `merge_state` reconstruction.
- `src/node/node.cpp::check_if_selected` — Producer-side stress branch via `shards_absorbed_by`.
- `src/node/validator.cpp::check_creator_selection` + `check_abort_certs` — Validator-side stress branch (mirror of producer's).
- `src/main.cpp::cmd_submit_merge_event` — Operator-driven `determ submit-merge-event` CLI (the break-glass path for manual merge issuance; remains shipped post-v2.11 as the override).

### Tests

- `tools/test_under_quorum_merge.sh` — Integration test: BEGIN inserts state, END erases, snapshot persists. Lock-in regression for T-1 + T-2 + T-3 + T-4.
- v2.11 will add `tools/test_merge_autodetect.sh` (per V2-DESIGN.md §v2.11) covering the FSM scenarios + historical-replay rejection of bogus events.

### Specifications

- `docs/PROTOCOL.md` §6.4 — R4 substrate (MergeEvent wire format + apply state machine + eligibility stress branch).
- `docs/V2-DESIGN.md` §v2.11 — v2.11 auto-detection beacon-side trigger (full closure path).

---

## 8. Status

**Shipped (analytic composition proof).** The R7 under-quorum-merge mechanism is shipped in the current `main` branch:

- **Wire format + canonical codec:** `include/determ/chain/block.hpp::MergeEvent` (R4 v1.0).
- **Validator gate (with S-036 partial closure):** `src/node/validator.cpp:713-788` (the leading past-bound at lines 772-776 is the S-036 partial-closure mechanism).
- **Apply state machine:** `src/chain/chain.cpp:1017-1039` (the BEGIN insert + END erase + idempotence handling).
- **Chain-state accessors:** `Chain::merge_state()`, `Chain::is_shard_merged`, `Chain::shards_absorbed_by` (all in chain.hpp:328-353).
- **Producer + validator stress branch:** `Node::check_if_selected` + `BlockValidator::check_creator_selection` + `BlockValidator::check_abort_certs`.
- **State-root binding:** `m:` namespace via `Chain::build_state_leaves` (chain.cpp:350-360).
- **Snapshot round-trip:** `serialize_state` (chain.cpp:1637-1645) + `restore_from_snapshot` (chain.cpp:1790-1793).
- **Integration test:** `tools/test_under_quorum_merge.sh`.

**The composition theorem is analytic.** This proof does not change any code; it consolidates the MERGE_EVENT-origination soundness argument so an external auditor can confirm S-036's current partial-closure status without re-reading the validator + apply branches and so the v2.11 closure path is formally pre-composed with T-1 through T-4.

**S-036 closure status.**

- **Current (R7 v1.0, EXTENDED-mode partial):** T-1 covers the validator gate sequence including the S-036 leading past-bound; T-2 covers MERGE_END idempotence; T-3 covers liveness preservation; T-4 covers FA1 + FA7 preservation under merge. The semantic remaining gap is that `evidence_window_start` is currently informational — the validator cannot deterministically replay the source shard's MergeMonitor FSM against the historical chain in v1.0 because the chain does not carry on-chain SHARD_TIP records. Bounded to a single under-quorum-window-sized attack per merge.
- **Future (v2.11 closure):** T-5 covers the v2.11 deterministic-FSM trigger + historical-replay validator gate. Composition with T-1 through T-4 closes S-036 fully under H1 on the gossip-receiver path. The captured-beacon adversary cannot single-handedly issue merges post-v2.11.

**Known limitations** as registered in §6:

- F-1: Full S-036 closure path needs on-chain SHARD_TIP records (Option A in V2-DESIGN.md §v2.11) or per-block snapshot accounts_at_height accessors (Option B). Design+spec'd; implementation deferred to Phase A v2.11.
- F-2: EXTENDED-mode-only beacon-trust assumption pre-v2.11 — operational mitigation via per-shard monitoring + operator-override CLI audit trail.
- F-3: Regional-isolation considerations for region-aware MERGE_EVENT compose with R4 + V2-DESIGN.md §v2.11 partner-resolution algorithm; future v2.x partner-resolution refinement is informational, not blocking.
- F-4: No cascading merges in v1.x (`S → T → U` chains); v2.x design item per `UnderQuorumMerge.md` §4.
- F-5: Refugees misbehaving on T's merged block slashed on S (home chain) via FA6 EquivocationEvent relay; already shipped.

**Future composition.** This proof is the MERGE_EVENT-origination foundation; `UnderQuorumMerge.md` (FA9) covers the safety preservation across BEGIN/END transitions; `RegionalSharding.md` (FA8) covers the regional-sharding committee soundness that the stress branch extends; `MultiEventComposition.md` (FA-Apply-15) covers the per-block joint state-root binding under multi-event apply. A future v2.11 implementation will add a sibling proof (`docs/proofs/v2.11-MergeAutodetect.md` or similar) covering the MergeMonitor FSM determinism + historical-replay soundness; T-5 in this document anchors the composition contract that the v2.11 proof will discharge.
