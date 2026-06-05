# AppliedReceiptSnapshotSoundness — `i:` namespace snapshot round-trip + apply determinism (AR-1..AR-7)

This document proves the soundness of the `i:` (`applied_inbound_receipts`) namespace across the two surfaces that together make the cross-shard no-double-credit guarantee survive a snapshot fast-bootstrap: **(a)** apply-determinism of inbound-receipt admission — the same receipt multiset applied to a fixed prior state yields the same `applied_inbound_receipts_` set, with set semantics doing the dedup; and **(b)** snapshot round-trip identity — `serialize_state → restore_from_snapshot` preserves the `i:` set element-for-element *and* preserves `compute_state_root`, with an S-041-style drop-detection corollary that reduces to **A2**. Composed, these underwrite the no-double-credit theorem (FA7 T-7 / FA-Apply-9 T-R2) at the restore boundary: a node that bootstraps from a snapshot inherits the donor's dedup set exactly, so a previously-credited `(src_shard, tx_hash)` cannot be re-credited on the next gossip delivery.

This proof is the `i:`-namespace analogue of the S-041 / `SnapshotDeterminismComposition.md` work, narrowed to the single longest-lived chain field on a multi-shard deployment (one entry per ever-delivered cross-shard receipt, monotonically accumulating) and the only field whose corruption directly breaks FA7's no-double-credit theorem. It overlaps deliberately with `AppliedReceiptRestore.md` (FA-Apply-12) on the restore-boundary statements; the distinct contribution here is the **joint** apply-determinism + snapshot-round-trip statement with the drop-detection corollary stated as an A2 reduction, so that the `i:` set is pinned by the same regression-guard discipline that S-041 established for the `k:` sub-namespace.

**Cryptographic assumptions** (canonical labels, `Preliminaries.md` §2.0): **A1** = Ed25519 EUF-CMA (§2.2); **A2** = SHA-256 collision resistance (§2.1). This document's only cryptographic reduction is to **A2** (via leaf-key injectivity + the Merkle root's collision-resistance inheritance). **Namespace distinction:** the apply-layer **"A1 unitary-supply invariant"** (`live_total_supply + accumulated_slashed = expected_total`, `AccountStateInvariants.md` I-6) is an *accounting identity* unrelated to the cryptographic assumption A1 (Ed25519 EUF-CMA); they share the letter by historical accident. This proof reduces only to A2 and never invokes Ed25519 (the receipt's *authenticity* — that a credited `(src, tx_hash)` corresponds to a real source-side debit — is FA7 L-7.4's reduction to A1, which this proof composes with but does not re-prove).

**Companion documents.** `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2), §5 + §8 (the V13 destination-side dedup gate and cross-shard apply mechanics); `AppliedReceiptRestore.md` (FA-Apply-12) for the parallel restore-boundary theorems T-AR1..T-AR7 that this document's AR-2..AR-5 mirror at a finer apply-determinism granularity; `SnapshotDeterminismComposition.md` (SD-1..SD-5) for the all-namespace joint round-trip determinism that AR-2/AR-3/AR-4 specialize to the `i:` namespace, and the S-041 drop-detection precedent AR-5 generalizes from `k:` to `i:`; `S033StateRootNamespaceCoverage.md` (T-1..T-5) for the 10-namespace coverage completeness (the `i:` row), namespace disjointness via prefix bytes (T-2, AR-5 injectivity), and deterministic leaf ordering (T-3); `CrossShardReceipts.md` (FA7) for the higher-level no-double-credit theorem T-7 (L-7.2 dedup monotonicity is what AR-1 + AR-2 preserve across restore) and L-7.4 (the A1 source-block ratification this proof composes with but does not re-prove); `SnapshotEquivalence.md` (FA-Apply-2) for the generic serialize-restore identity T-S1 + apply-after-restore equivalence T-S2; `docs/SECURITY.md` §S-033 / §S-037 / §S-038 / §S-041 for the closure narratives; `docs/PROTOCOL.md` §4.1.1 (the `i:` Merkle-leaf encoding) + §11 (the snapshot wire format).

---

## 1. Setup

### 1.1 The dedup set and its mutation channels

`Chain::applied_inbound_receipts_` is declared in `include/determ/chain/chain.hpp` as `std::set<std::pair<ShardId, Hash>>`. Each element pins a cross-shard receipt that has been credited on the destination side: `(src_shard, tx_hash)` uniquely identifies a `CrossShardReceipt` because the source-side block-apply binds `tx_hash` to the source-side `TRANSFER` 1:1 under V12 (`CrossShardReceipts.md` L-7.1) and `src_shard` distinguishes same-`tx_hash` collisions across source shards.

The set has exactly three write channels:

1. **Apply-layer insert** (`src/chain/chain.cpp:1374`) — `applied_inbound_receipts_.insert(key)` immediately after a successful inbound-receipt credit, inside the apply-time inbound loop (`chain.cpp:1363–1381`). This is the only steady-state mutation.
2. **Bulk snapshot restore** (`chain.cpp:1793–1800`) — the restore loop re-inserts every `(src, tx_hash)` from the JSON envelope.
3. **Move-assignment from a `StateSnapshot` rollback** (`chain.cpp:612`) — the A9 atomic-apply lazy-snapshot restore on apply-tail abort, captured on first mutation at `chain.cpp:663–665`. This is internal to a single apply call and does not interact with the wire-level snapshot path.

The set is consulted by two surfaces:

1. **V13 validator gate** (`src/node/validator.cpp::check_inbound_receipts`, definition at `validator.cpp:1118`) — at `validator.cpp:1142` it rejects any block whose `inbound_receipts[]` contains a `(src_shard, tx_hash)` for which `chain.inbound_receipt_applied(...)` returns `true`.
2. **Apply-layer dedup guard** (`chain.cpp:1365`) — `if (applied_inbound_receipts_.count(key)) continue;` defensively skips a receipt that the V13 gate let through (defense-in-depth for snapshot-restore + chain replay where the validator pass is bypassed).

The public read accessor is `Chain::inbound_receipt_applied(src, tx_hash)` (`chain.cpp:204–207`):

```cpp
bool Chain::inbound_receipt_applied(ShardId src_shard,
                                       const Hash& tx_hash) const {
    return applied_inbound_receipts_.count({src_shard, tx_hash}) > 0;
}
```

### 1.2 The `i:` namespace contribution to `state_root`

`Chain::build_state_leaves` (`chain.cpp:267`) iterates the dedup set at `chain.cpp:331–341` and emits one Merkle leaf per entry:

```cpp
// applied_inbound_receipts_  (key = "i:" + src_be8 + tx_hash)
for (auto& [src, tx_hash] : applied_inbound_receipts_) {
    std::vector<uint8_t> key;
    key.reserve(2 + 8 + 32);
    key.push_back('i'); key.push_back(':');
    for (int i = 7; i >= 0; --i) key.push_back((src >> (8*i)) & 0xff);
    key.insert(key.end(), tx_hash.begin(), tx_hash.end());
    crypto::SHA256Builder b;
    uint8_t marker = 1; b.append(&marker, 1);  // presence marker
    leaves.push_back({std::move(key), hash_bytes(b)});
}
```

Each leaf's key is the byte sequence `"i:" ‖ src_be8 ‖ tx_hash` (42 bytes: 2-byte prefix + 8-byte big-endian shard id + 32-byte tx hash). The value-hash is `SHA256(0x01)` — a constant **presence marker**, because the set carries no payload beyond `(src, tx_hash)` membership. The leaf-key encoding is **injective** (no two distinct `(src, tx_hash)` pairs produce the same key bytes) and **prefix-disjoint** from every other namespace (byte 0 is `'i'`, distinct from `a/s/r/d/b/m/p/k`, per `S033StateRootNamespaceCoverage.md` T-2), so adding or removing any entry changes the set of `i:`-namespace leaves, which under the sorted-leaves balanced binary Merkle tree changes `compute_state_root` except with probability `≤ 2⁻¹²⁸` (A2).

`compute_state_root` is the thin wrapper (`chain.cpp:413–415`):

```cpp
Hash Chain::compute_state_root() const {
    return crypto::merkle_root(build_state_leaves());
}
```

Two verification gates consume this contribution:

- **Apply-side S-033 gate** (`chain.cpp:1421–1444`): a received block whose declared `b.state_root` diverges from the receiver's post-apply `compute_state_root()` (recomputed at `chain.cpp:1433`) is rejected with the `state_root mismatch … (S-033)` diagnostic. Post-S-038 every production block carries a non-zero `state_root` (the producer's `Node::try_finalize_round` populates it via a tentative-chain dry-run), so the gate is live.
- **Restore-side G2 gate** (`chain.cpp:1894–1922`): a restored snapshot whose recomputed `compute_state_root()` (at `chain.cpp:1912`) diverges from the tail block's stored `state_root` throws the `snapshot state_root mismatch … (S-033)` diagnostic. A preceding head-hash gate G1 (`chain.cpp:1871–1876`) rejects a tampered tail block independently.

### 1.3 What "preserved" / "determined" means

Two chains' dedup sets `D_A`, `D_B` are **equal** iff `D_A == D_B` under `std::set` equality (same key-set). Because `std::set<std::pair<ShardId, Hash>>` is keyed by lexicographic `(src, tx_hash)` order, equality is invariant under any permutation of insertion order — a property the serialize/restore loops exploit, since the JSON array is iterated in `std::set` order on the donor (`chain.cpp:1586`) and the receiver re-inserts each element via `c.applied_inbound_receipts_.insert(...)` (`chain.cpp:1798`), converging on the same final set regardless of insert order.

**Apply-determinism** of receipt admission means: for a fixed prior state `Σ` and a fixed inbound-receipt multiset `M` baked into a block `B`, `apply_transactions(B)` produces a `applied_inbound_receipts_` set that is a pure function of `(Σ.applied_inbound_receipts_, M)` — no clock, no randomness, no peer query, no iteration-order dependence — and the final set is `Σ.applied_inbound_receipts_ ∪ {(r.src_shard, r.tx_hash) : r ∈ M}` with set-union semantics absorbing any duplicate.

---

## 2. Theorems

Fix a reachable chain `C` (genesis followed by zero or more `apply_transactions`-valid blocks) and a header window `header_count ≥ 1`. Write `S = serialize_state(C, header_count)`, `C' = restore_from_snapshot(S)`.

### AR-1 — Apply-determinism of receipt admission (dedup via set semantics)

**Statement.** Let `Σ` be any reachable prior state and `B` a finalized block whose `inbound_receipts[]` is the multiset `M = {r_1, …, r_n}`. Then `apply_transactions(B)` mutates `applied_inbound_receipts_` to exactly

```
Σ.applied_inbound_receipts_  ∪  { (r.src_shard, r.tx_hash) : r ∈ M },
```

independent of the order in which `M` is presented and independent of any duplicates within `M` or against `Σ`. The result is a pure function of `(Σ.applied_inbound_receipts_, M)`.

**Proof sketch.** The apply-layer inbound loop (`chain.cpp:1363–1381`) iterates `b.inbound_receipts` in vector order. For each `r` it forms `key = (r.src_shard, r.tx_hash)`. If `applied_inbound_receipts_.count(key)` (the dedup guard at `chain.cpp:1365`) is non-zero — i.e. the key is already present, whether from `Σ` or from an earlier iteration in the same loop — the iteration `continue`s with no balance mutation, no insert, no `block_inbound` accumulation. Otherwise the credit branch runs and the key is inserted at `chain.cpp:1374` via `std::set::insert`, which is idempotent. Either branch leaves the set holding `key`. Therefore after the loop the set holds the union of `Σ`'s keys and every distinct `key` derived from `M`; a duplicate (within `M` or against `Σ`) contributes nothing beyond its first occurrence — set-union semantics. No step reads a clock, a CSPRNG, or a peer; the only inputs are `Σ.applied_inbound_receipts_` and the receipt fields. The loop body's effect on the set is therefore a pure, order-independent function of `(Σ.applied_inbound_receipts_, M)`. ∎

This is the apply-side half of `CrossShardReceipts.md` L-7.2 (V13 dedup monotonicity): L-7.2 covers the validator gate; AR-1 covers the apply layer's own guard, which is what carries the dedup contract when the validator pass is bypassed (chain replay, snapshot bootstrap).

**Code witness.** `src/chain/chain.cpp:1363–1381` (inbound loop: dedup guard at 1365, idempotent insert at 1374).

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (the dedup-determinism assertion: applying the same receipt multiset to a fixed prior state yields the same set, and a duplicate is a no-op). `tools/test_cross_shard_receipt_apply.sh` + `tools/test_cross_shard_multi_receipt.sh` (apply-time dedup on an accumulating set).

### AR-2 — Serialization includes the entire `i:` set

**Statement.** `serialize_state(C, header_count)` emits every entry of `C.applied_inbound_receipts_` into the snapshot's `applied_inbound_receipts` JSON array — no entry dropped, duplicated, or reordered relative to `std::set` canonical iteration order.

**Proof sketch.** Inspect `serialize_state` at `chain.cpp:1585–1592`:

```cpp
json applied = json::array();
for (auto& [src, tx_hash] : applied_inbound_receipts_) {
    applied.push_back({
        {"src_shard", src},
        {"tx_hash",   to_hex(tx_hash)},
    });
}
snap["applied_inbound_receipts"] = applied;
```

The loop iterates the entire set (no `break`, no skip, no conditional emit) and emits each element as a 2-field JSON object. The structured binding destructures the `std::pair`; `to_hex(tx_hash)` is a pure, reversible function over the 32-byte hash (lower-case hex, no separators). The output array's element count equals `applied_inbound_receipts_.size()`; its order is `std::set` canonical iteration order (lexicographic by `(src, tx_hash)`). ∎

**Code witness.** `src/chain/chain.cpp:1585–1592`.

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (the snapshot-array-population assertion). `tools/test_applied_receipt_restore.sh` (FA-Apply-12 T-AR1 surface). `tools/test_snapshot_then_apply.sh` (broader snapshot ↔ replay equivalence).

### AR-3 — Restore reconstructs the `i:` set identically

**Statement.** `restore_from_snapshot(S)` rebuilds `c.applied_inbound_receipts_` from the snapshot's `applied_inbound_receipts` array, inserting every `(src, tx_hash)` element. The final set equals `C.applied_inbound_receipts_` under `std::set` equality.

**Proof sketch.** Inspect `restore_from_snapshot` at `chain.cpp:1793–1800`:

```cpp
if (snap.contains("applied_inbound_receipts")) {
    for (auto& a : json_require_array(snap, "applied_inbound_receipts")) {
        ShardId src    = a.value("src_shard", ShardId{0});
        Hash    txhash = from_hex_arr<32>(
                            a.value("tx_hash", std::string(64, '0')));
        c.applied_inbound_receipts_.insert({src, txhash});
    }
}
```

The `snap.contains(...)` guard preserves backward-compatibility: a pre-feature snapshot without the field restores to an empty set, identical to a freshly-constructed Chain (and matching what `build_state_leaves` emits for an empty set — zero `i:` leaves). The `json_require_array` helper (S-018 hardening, `include/determ/util/json_validate.hpp`) enforces array-typed input or throws a clean field-named diagnostic, blocking wrong-type-collection attacks on the SNAPSHOT_RESPONSE channel. Inside the loop, `ShardId` round-trips through the JSON integer codec losslessly (u64 width) and `from_hex_arr<32>` is the exact inverse of `to_hex` over a 32-byte buffer; each element is inserted idempotently. By AR-2 (donor emits the full set) + the lossless field round-trip + `std::set::insert` idempotence, the post-restore set equals the donor's set element-for-element. ∎

**Code witness.** `src/chain/chain.cpp:1793–1800`; `include/determ/util/json_validate.hpp::json_require_array`.

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (post-restore `inbound_receipt_applied` returns `true` for every originally-credited pair). `tools/test_applied_receipt_restore.sh` (FA-Apply-12 T-AR2). `tools/test_snapshot_defense.sh` (S-018 wrong-type rejection).

### AR-4 — `state_root` consistency across the round trip

**Statement.** For the donor `C` at the instant `S = serialize_state(C)` runs and `C' = restore_from_snapshot(S)`,

```
compute_state_root(C) == compute_state_root(C').
```

In particular, the `i:`-namespace contribution is preserved: every `i:`-prefixed Merkle leaf the donor emits is emitted by the receiver, byte-for-byte.

**Proof sketch.** This is the `i:`-namespace specialization of `SnapshotDeterminismComposition.md` SD-2 (state_root preservation). By §1.2, `build_state_leaves` is a pure function of `applied_inbound_receipts_` for the `i:` namespace: identical input sets produce identical `i:` leaves (`"i:" ‖ src_be8 ‖ tx_hash` key, `SHA256(0x01)` value-hash). By AR-3 the receiver's set equals the donor's, so the `i:` leaf multisets coincide. The remaining nine namespaces coincide by the per-namespace coverage of `S033StateRootNamespaceCoverage.md` T-5 / `SnapshotEquivalence.md` L-S0/L-S1. `merkle_root` is a pure function of the sorted leaf set (`S033StateRootNamespaceCoverage.md` T-3 deterministic leaf ordering), so identical leaf sets yield identical roots. Hence the two roots coincide.

The restore-side G2 gate (`chain.cpp:1894–1922`, recompute at 1912) enforces this at the wire boundary: a snapshot whose serialized `applied_inbound_receipts` diverged from its tail block's stored `state_root` (an attacker truncated the array or flipped one `tx_hash` byte) fails G2 and the restore throws. The gate is what makes AR-4 a checkable wire-layer property rather than an honest-only invariant. ∎

**Code witness.** `src/chain/chain.cpp:267` (`build_state_leaves`), `chain.cpp:413` (`compute_state_root`), `chain.cpp:1894–1922` (G2 gate; recompute at 1912), `chain.cpp:1421–1444` (apply-side S-033 gate; recompute at 1433).

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (the `compute_state_root` pre/post-restore identity assertion). `tools/test_state_root_namespaces.sh` (per-namespace sensitivity incl. `i:`). `tools/test_dapp_snapshot.sh` (joint-surface end-to-end where the receiver's recomputed root strictly matches the tail head's stored root).

### AR-5 — `i:` drop-detection (S-041-style, reduces to A2)

**Statement.** Toggling any single entry of `applied_inbound_receipts_` changes `compute_state_root` except with probability `≤ 2⁻¹²⁸` (A2). Consequently, were the `i:` set populated in `compute_state_root` (via `build_state_leaves`) but **dropped** from `serialize_state` (or partially serialized), then for any chain with a non-empty `i:` set the restored chain's `i:` leaf multiset would differ, so `compute_state_root(C') ≠ compute_state_root(C)` — SD-2 fails and the restore-side G2 gate throws loudly. This is the S-041 bug class (a state-root contributor present in `build_state_leaves` but absent from the snapshot surfaces), specialized to the `i:` namespace.

**Proof sketch.** *Sensitivity.* `build_state_leaves` emits one `i:` leaf per set entry; the leaf-key encoding is injective per §1.2 and prefix-disjoint from the other nine namespaces (`S033StateRootNamespaceCoverage.md` T-2). Adding or removing an entry adds or removes its leaf, changing the sorted leaf multiset. By the Merkle root's collision-resistance inheritance (`MerkleTreeSoundness.md` MT-3 / `SnapshotDeterminismComposition.md` SD-3), two distinct leaf multisets that collided on a root would yield an extractable SHA-256 collision; under A2 this has probability `≤ 2⁻¹²⁸`. (Leaf/inner domain separation, MT-2's `0x00`/`0x01` prefix, additionally rules out a structural change preserving the root.)

*Drop-detection corollary.* Suppose a code change dropped the `i:` array from `serialize_state` (or serialized only a prefix of it) while `build_state_leaves` still emitted `i:` leaves. Take any reachable `C` with a non-empty `i:` set. Then `restore_from_snapshot(serialize_state(C))` has a strictly smaller (or empty) `i:` set — the restore loop's `snap.contains` guard leaves the container at whatever the truncated array supplies. So `build_state_leaves(C')` is missing at least one `i:` leaf that `build_state_leaves(C)` had; by sensitivity the roots differ, SD-2 fails, and the G2 gate (`chain.cpp:1894–1922`) recomputes a root that mismatches the tail header's committed root and throws the `snapshot state_root mismatch … (S-033)` diagnostic. The regression is **loud**, not silent — provided a test populates a non-empty `i:` set and exercises the round trip. ∎

This is exactly the regression-guard property S-041 established for the `k:` merge-threshold sub-namespace, transplanted to `i:`. The `i:` round-trip loops shipped earlier than S-037/S-038, but AR-5 makes precise *why* an analogous future drop would be caught: the structural sensitivity result + the live G2 gate. Sibling I1's `determ test-applied-receipt-snapshot` is the test that populates a non-empty `i:` set and asserts both the round-trip root-match (AR-4) and the dedup preservation (AR-1+AR-3), so an `i:`-namespace drop fails it.

**Code witness.** `src/chain/chain.cpp:331–341` (`i:` leaf emission), `chain.cpp:1585–1592` (the serialize loop that a drop would remove), `chain.cpp:1894–1922` (G2 throw site).

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (non-empty-`i:` round-trip root-match). `tools/test_state_root_namespaces.sh` (the `i:` per-namespace mutation-changes-root assertion). `tools/test_snapshot_full_determinism.sh` (the all-namespace SD-3 drop-detection guard, which covers `i:` as one of the ten).

### AR-6 — No-double-credit composition across the restore boundary (FA7 / FA-Apply-9 at a restored chain)

**Statement.** Let `C'` be a chain post-`restore_from_snapshot`. Submitting a block `B` whose `inbound_receipts[]` contains some `(src, tx_hash) ∈ C'.applied_inbound_receipts_` produces no incremental credit for that entry: the V13 validator rejects the block (if the duplicate is the only inclusion-blocking issue), or — if V13 is bypassed under chain replay — the apply-layer dedup guard (`chain.cpp:1365`) silently skips it. Conversely, a *fresh* `(src, tx_hash) ∉ C'.applied_inbound_receipts_` credits `accounts_[r.to].balance += r.amount`, inserts the key, and bumps `block_inbound` along the same path as a never-snapshotted chain. Thus FA7 T-7's no-double-credit clause holds at a post-restore chain.

**Proof sketch.** By AR-3 the post-restore set equals the donor's. The V13 gate (`validator.cpp::check_inbound_receipts`, dedup read at `validator.cpp:1142`) consults `applied_inbound_receipts_` via `inbound_receipt_applied`, which by §1.1 returns `true` iff the pair is in the set; AR-3 guarantees the pair is present whenever it was on the donor, so V13 rejects identically on both sides. If the validator pass is bypassed (a finalized, K-of-K-signed block loaded via chain replay), the apply-layer guard at `chain.cpp:1365` consults the same set and `continue`s — no balance mutation, no insert, no `block_inbound` bump (AR-1). For a fresh key, AR-1's union semantics drive the credit branch (`chain.cpp:1367–1380`): the S-007 overflow-checked credit, the `__ensure_applied_inbound_receipts()` lazy-snapshot materialization (`chain.cpp:663–665`, for apply-tail rollback), the insert, and the `block_inbound` accumulation — reading no field whose value differs between a fresh chain and a restored chain (every input — `accounts_`, `applied_inbound_receipts_`, the scalar guards — round-trips by AR-3 + `SnapshotEquivalence.md` L-S0/L-S1). This is FA-Apply-9 T-R1 (fresh credits) + T-R2 (duplicate skipped) evaluated at a chain whose dedup set originated from a restore; AR-3 makes that origin indistinguishable from an apply-time-accumulated origin, so the FA7 / FA-Apply-9 arguments carry unchanged. ∎

The novel claim is the composition: FA7 T-7 / FA-Apply-9 hold across the snapshot bootstrap. Neither states this explicitly — FA7 covers the steady-state dedup, FA-Apply-9 covers the apply path, and AR-2..AR-4 supply the missing premise (the dedup set survives the restore boundary intact).

**Code witness.** `src/node/validator.cpp:1118` (`check_inbound_receipts`; dedup read at 1142), `src/chain/chain.cpp:1363–1381` (apply-layer guard + credit branch), `chain.cpp:204–207` (`inbound_receipt_applied`).

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (the critical assertion: a duplicate `(src, tx_hash)` on the restored chain is silently skipped — no balance change, no second credit — and a fresh one credits normally). `tools/test_applied_receipt_restore.sh` (FA-Apply-12 T-AR3/T-AR4). `tools/test_cross_shard_receipt_apply.sh` (FA-Apply-9 base case on an unrestored chain; AR-6 inherits).

### AR-7 — Determinism

**Statement.** Identical pre-snapshot chains produce byte-identical restored `applied_inbound_receipts_` sets and identical `compute_state_root`. Formally: for two Chains `C_A`, `C_B` with `C_A.applied_inbound_receipts_ == C_B.applied_inbound_receipts_` (set equality) and otherwise identical state, `restore_from_snapshot(serialize_state(C_A))` and `restore_from_snapshot(serialize_state(C_B))` on a single thread yield byte-identical sets and identical `compute_state_root` outputs.

**Proof sketch.** `serialize_state` is deterministic (`SnapshotDeterminismComposition.md` SD-1 / `SnapshotEquivalence.md` T-S6) — no I/O, clock, randomness, or peer query. The `i:` serialize loop (`chain.cpp:1585–1592`) iterates `std::set` in canonical sorted order (strict-weak ordering on `(src, tx_hash)`), so for `D_A == D_B` the emitted JSON arrays are byte-identical (nlohmann suppresses insignificant whitespace by default). The restore loop (`chain.cpp:1793–1800`) inserts each element into a fresh container; `std::set::insert` is order-independent in its final element set, and the tree's internal node layout is an implementation detail that affects neither set-equality nor `compute_state_root` (which iterates the set in canonical order at `chain.cpp:332–341`). Determinism composes: identical inputs → identical serialization → identical restoration → identical root. ∎

**Code witness.** `src/chain/chain.cpp:1585–1592` (deterministic serialize), `chain.cpp:1793–1800` (deterministic restore), `chain.cpp:332–341` (deterministic leaf emission).

**Test witness.** Sibling I1's `determ test-applied-receipt-snapshot` (the same chain serialized twice → same root). `tools/test_snapshot_roundtrip.sh` (broader "same snapshot → same restored state_root"). `tools/test_state_root_namespaces.sh` (baseline-equality across all 10 namespaces incl. `i:`).

---

## 3. Composition map

The proof is a thin specialization composing three established results, plus the one joint statement that none of them makes:

- **Apply-determinism (AR-1)** is the apply-side half of `CrossShardReceipts.md` L-7.2; it is what `AppliedReceiptRestore.md` (FA-Apply-12) assumes implicitly when it asserts the dedup contract survives restore.
- **Round-trip identity (AR-2 + AR-3 + AR-4)** is `SnapshotDeterminismComposition.md` SD-1/SD-2 restricted to the `i:` namespace, with the per-namespace coverage of `S033StateRootNamespaceCoverage.md` T-5.
- **Drop-detection (AR-5)** is `SnapshotDeterminismComposition.md` SD-3 / the S-041 closure pattern, restricted to `i:` and stated as an explicit A2 reduction.
- **No-double-credit (AR-6)** is FA7 T-7 / FA-Apply-9 T-R1+T-R2 evaluated at a post-restore chain — the composition that is this document's distinct contribution.
- **Determinism (AR-7)** inherits `SnapshotEquivalence.md` T-S6.

The joint statement — apply-determinism + snapshot round-trip + no-double-credit, all on the single `i:` set — is what makes the `i:` namespace's FA7 guarantee robust to fast-bootstrap and to a future S-041-class serialize drop. Sibling I1's `determ test-applied-receipt-snapshot` is the empirical pin: it is the test that populates a non-empty `i:` set, exercises the round trip, and asserts both the dedup preservation and the root-match in one fixture, so it fails under any drift breaking AR-1, AR-3, AR-4, or AR-5.

---

## 4. What this does not cover

- **Receipt authenticity.** That a credited `(src, tx_hash)` corresponds to a real source-side debit on a finalized source block is FA7 L-7.4's reduction to **A1** (Ed25519 EUF-CMA, via the K-of-K source-block ratification on the gossip path). This proof's scope is destination-side dedup-set determinism + preservation; it composes with FA7 but does not re-prove receipt authenticity.
- **Wire-level snapshot provenance.** AR-4 / AR-5 reduce a tampered snapshot to a G2 throw, but G2 catches only internally-inconsistent snapshots. A malicious peer can supply a self-consistent snapshot of a forked chain; operator policy (cross-checking `head_hash` against a trusted source) is the current provenance defense, and a committee-signed snapshot envelope is a tracked future item.
- **Inbound delivery liveness.** The `i:` set's monotonic growth depends on the destination chain's liveness (FA4) and on source-side receipts being gossipped and ratified (FA7 T-7'). This proof assumes both; without them there is simply nothing to dedup against on a silent shard — a livelihood concern, not a soundness one.
- **Apply-time atomic-scope rollback.** The dedup set is `std::optional`-wrapped in `StateSnapshot` (the A9 lazy-snapshot captured at `chain.cpp:663–665`); the wire-level restore path fully replaces the set from JSON and does not interact with the per-block lazy snapshot. The atomic-apply rollback property is `AccountStateInvariants.md` I-1; this proof inherits it but does not re-prove it.
- **The Merkle primitive itself** (MT-1..MT-5, `MerkleTreeSoundness.md`) and the consensus-layer divergent-body question (`S030-D2-Analysis.md`, `F2-SPEC.md`) are out of scope.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) §2.0 / §2.1 | Canonical assumption labels; A2 (the only reduction target); A1 (receipt authenticity, via FA7). |
| `Preliminaries.md` (F0) §5 / §8 | V13 destination-side dedup gate; cross-shard apply mechanics. |
| `AppliedReceiptRestore.md` (FA-Apply-12) | T-AR1..T-AR7 — the parallel restore-boundary theorems this document mirrors at apply-determinism granularity; AR-2..AR-4 ≈ T-AR1/T-AR2/T-AR5, AR-6 ≈ T-AR3/T-AR4. |
| `SnapshotDeterminismComposition.md` (SD-1..SD-5) | SD-1/SD-2 (all-namespace round-trip → AR-2/AR-3/AR-4 `i:` specialization), SD-3 (drop detection → AR-5), and the S-041 precedent AR-5 generalizes. |
| `S033StateRootNamespaceCoverage.md` (T-1..T-5) | The `i:` coverage row (T-1), namespace disjointness via prefix bytes (T-2, AR-5 injectivity), deterministic leaf ordering (T-3, AR-4/AR-7), snapshot round-trip soundness (T-5). |
| `CrossShardReceipts.md` (FA7) | T-7 no-double-credit + L-7.2 dedup monotonicity (AR-1 apply-side half, AR-6 composition); L-7.4 receipt authenticity (A1, composed not re-proved). |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 serialize-restore identity, T-S2 apply-after-restore equivalence, T-S6 serialize determinism (AR-7), L-S0/L-S1 per-namespace coverage. |
| `MerkleTreeSoundness.md` | MT-2 (leaf/inner domain separation), MT-3 (collision-resistance inheritance, reduces to A2 → AR-5 sensitivity). |
| `AccountStateInvariants.md` (FA-Apply-1) | I-1 atomic apply (AR-6 lazy-snapshot rollback); I-6 the accounting A1 (distinct from cryptographic A1). |
| `docs/SECURITY.md` §S-033 | Merkle state commitment + apply / restore verification gates. |
| `docs/SECURITY.md` §S-037 / §S-038 | DApp-registry serialize/restore + producer-side `body.state_root` wiring that activate the gates AR-4/AR-5 rely on. |
| `docs/SECURITY.md` §S-041 | The `k:` merge-threshold serialize-gap closure — the drop-detection precedent AR-5 generalizes to `i:`. |
| `docs/PROTOCOL.md` §4.1.1 | `i:` namespace state-root encoding (`"i:" ‖ src_be8 ‖ tx_hash` key, presence-marker value-hash). |
| `docs/PROTOCOL.md` §11 | Snapshot wire format incl. the `applied_inbound_receipts` field schema. |
| `src/chain/chain.cpp:204` | `Chain::inbound_receipt_applied` public predicate. |
| `src/chain/chain.cpp:267` | `build_state_leaves`. |
| `src/chain/chain.cpp:331` | `build_state_leaves` `i:`-namespace leaf emission. |
| `src/chain/chain.cpp:413` | `Chain::compute_state_root`. |
| `src/chain/chain.cpp:663` | `__ensure_applied_inbound_receipts` lazy-snapshot capture (A9 rollback). |
| `src/chain/chain.cpp:1363` | Apply-layer inbound-receipt loop (dedup guard at 1365 + credit branch + insert at 1374). |
| `src/chain/chain.cpp:1421` | Apply-side S-033 + S-038 verification gate (recompute at 1433). |
| `src/chain/chain.cpp:1585` | `serialize_state` applied-receipt emit loop. |
| `src/chain/chain.cpp:1793` | `restore_from_snapshot` applied-receipt restore loop. |
| `src/chain/chain.cpp:1871` | Restore-side G1 head-hash gate. |
| `src/chain/chain.cpp:1894` | Restore-side G2 state-root gate (recompute at 1912; AR-4/AR-5 throw site). |
| `src/node/validator.cpp:1118` | `check_inbound_receipts` — V13 destination-side dedup gate (dedup read at 1142). |
| `include/determ/util/json_validate.hpp::json_require_array` | S-018-hardened JSON array accessor used by the restore loop. |
| Sibling I1 `determ test-applied-receipt-snapshot` | Canonical empirical pin — populates a non-empty `i:` set, exercises the round trip, asserts AR-1 dedup-determinism + AR-3/AR-4 round-trip + AR-5 root-match + AR-6 duplicate-skip. |
| `tools/test_applied_receipt_restore.sh` | FA-Apply-12 restore-boundary regression (AR-2/AR-3/AR-6). |
| `tools/test_state_root_namespaces.sh` | Per-namespace state-root sensitivity incl. `i:` (AR-4/AR-5). |
| `tools/test_snapshot_full_determinism.sh` | All-namespace SD-3 drop-detection guard (AR-5). |
| `tools/test_dapp_snapshot.sh` | Joint-surface end-to-end root-match (AR-4). |
| `tools/test_snapshot_roundtrip.sh` | Determinism + round-trip (AR-7). |
| `tools/test_snapshot_defense.sh` | S-018 wrong-type rejection (AR-3 input-validation precondition). |
| `tools/test_cross_shard_receipt_apply.sh` / `test_cross_shard_multi_receipt.sh` | FA-Apply-9 apply-time dedup on an unrestored chain (AR-1/AR-6 base case). |

---

## 6. Status

All seven theorems (AR-1 through AR-7) are closed in the current codebase (commit `20784e3`):

- **AR-1** (apply-determinism / dedup via set semantics) — closed via inspection of the apply-layer inbound loop (`chain.cpp:1363–1381`, dedup guard + idempotent insert); the apply-side half of FA7 L-7.2.
- **AR-2** (serialize includes the full set) — closed via inspection of `serialize_state` (`chain.cpp:1585–1592`, deterministic loop over canonical `std::set` iteration).
- **AR-3** (restore reconstructs identically) — closed via inspection of `restore_from_snapshot` (`chain.cpp:1793–1800`, `json_require_array` guard + idempotent `set::insert`).
- **AR-4** (`state_root` consistency) — closed via SD-2 specialized to `i:` + the live S-033/S-038 gates; the restore-side G2 (`chain.cpp:1894–1922`) is the runtime check.
- **AR-5** (`i:` drop-detection, A2 reduction) — closed via leaf-key injectivity + MT-3 collision-resistance inheritance; the S-041 regression-guard pattern transplanted to `i:`, made loud by G2.
- **AR-6** (no-double-credit composition) — closed via AR-3 (set preserved) + FA7 T-7 / FA-Apply-9 T-R1+T-R2 evaluated at a post-restore chain.
- **AR-7** (determinism) — closed via pure-function serialize + deterministic STL set iteration + canonical-order leaf emission.

No theorem is open or partial. The proof's foundation rests jointly on the S-033 + S-037 + S-038 closures (which activate the apply-side and restore-side gates) and the S-041 closure (the drop-detection precedent AR-5 generalizes). The empirical pin is sibling I1's `determ test-applied-receipt-snapshot`; supplementary witnesses (`tools/test_applied_receipt_restore.sh`, `test_state_root_namespaces.sh`, `test_snapshot_full_determinism.sh`, `test_dapp_snapshot.sh`) each cover a subset of the AR properties. The proof is analytic and changes no code.
