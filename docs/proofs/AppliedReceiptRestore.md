# FA-Apply-12 — Applied-receipt dedup-set survives snapshot restore

This document formalizes the snapshot-restore correctness property for `Chain::applied_inbound_receipts_` — the per-shard dedup set whose membership is the V13 destination-side gate against double-credit on cross-shard receipts. The property: after a `serialize_state → restore_from_snapshot` round trip, the restored chain's `applied_inbound_receipts_` set is byte-identical to the donor's set, and the dedup contract (exactly-once cross-shard credit) survives fast-bootstrap intact. Without this property, a node that bootstraps from a snapshot would lose its dedup state and a previously-credited `(src_shard, tx_hash)` could be re-credited on the next gossip delivery — a double-credit forgery on the destination shard's balances.

The proof is mechanical: the restore path's `applied_inbound_receipts` loop is point-for-point inverse to the serializer's loop, the S-033 state-root binding through the `i:`-namespace prevents silent dedup-set divergence, and the post-restore apply path's V13 dedup gate consumes the restored set unchanged. The strength of this document is consolidation: snapshot-restore correctness is implicit in S-012 (snapshot bootstrap state-root verification), S-033 (Merkle state commitment), S-037 (paired registry-restore closure), and S-038 (producer-side state_root population) — but the dedup-set-specific surface deserves its own theorem set because it is the single longest-lived chain field on a long-running multi-shard deployment (one entry per ever-delivered cross-shard receipt, monotonically accumulating) and the only field whose corruption directly breaks FA7's no-double-credit theorem.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15 (with V13 the destination-side dedup gate), and assumptions A1/A3; `AccountStateInvariants.md` (FA-Apply) for I-4 (cross-shard credit channel) and I-5 (balance arithmetic channels); `SnapshotEquivalence.md` (FA-Apply-2) for the generic serialize-restore identity T-S1 + apply-after-restore equivalence T-S2 that this proof specializes to the `i:` namespace; `CrossShardReceiptDedup.md` (FA-Apply-9) for the apply-path dedup theorems T-R1 (fresh receipt credits) and T-R2 (duplicate silently skipped) that this proof composes with at the restore boundary; `AbortEventApply.md` (FA-Apply-11) for the parallel apply-side cache (`abort_records_` / `b:` namespace) whose serialize-restore property follows the same pattern; `CrossShardReceipts.md` (FA7) for the higher-level cross-shard atomicity theorem T-7 whose at-most-once-credit clause is what this proof preserves across snapshot bootstrap; `docs/SECURITY.md` §S-037 for the paired closure (S-037 added `dapp_registry` serialize/restore in the same in-session round as the matching applied_inbound_receipts coverage; the test `tools/test_applied_receipt_restore.sh` exercises both surfaces).

---

## 1. Setup

### 1.1 The dedup set

`Chain::applied_inbound_receipts_` is declared at `include/determ/chain/chain.hpp` as `std::set<std::pair<ShardId, Hash>>`. Each element pins a cross-shard receipt that has been credited on the destination side: `(src_shard, tx_hash)` uniquely identifies a `CrossShardReceipt` because the source-side block-apply binds `tx_hash` to the source-side `TRANSFER` 1:1 under V12 (`CrossShardReceipts.md` lemma L-7.1) and `src_shard` distinguishes same-`tx_hash` collisions across source shards.

The set is consulted by two surfaces:

1. **V13 validator gate** (`src/node/validator.cpp::check_inbound_receipts`) — rejects any block whose `inbound_receipts[]` contains a `(src_shard, tx_hash)` already in `applied_inbound_receipts_`.
2. **Apply-layer dedup guard** (`chain.cpp:1365`) — `if (applied_inbound_receipts_.count(key)) continue;` defensively skips a receipt that the V13 gate let through (defense-in-depth for snapshot-restore + chain replay where the validator is bypassed).

The predicate `Chain::inbound_receipt_applied(src, tx_hash)` (`chain.cpp:204–207`) is the public read accessor. The set's only mutation channel is the apply-layer insert at `chain.cpp:1374` immediately after a successful inbound-receipt credit; nothing else writes to the set under normal operation. Snapshot-restore is the lone exception — it writes the set in bulk from the JSON envelope (`chain.cpp:1778–1785`), which is what this proof covers.

### 1.2 The `i:` namespace contribution to state_root

`Chain::build_state_leaves` (`chain.cpp:267`) iterates the dedup set at lines 331–341 and emits one Merkle leaf per entry:

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

Each leaf's key is the byte sequence `"i:" || src_be8 || tx_hash` (42 bytes total: 2-byte prefix + 8-byte big-endian shard id + 32-byte tx hash). The value-hash is `SHA256(0x01)` — a constant "presence marker" because the set carries no extra payload beyond `(src, tx_hash)` membership. The leaf-key encoding is injective (no two distinct `(src, tx_hash)` pairs produce the same key bytes), so adding or removing any entry changes the set of `i:`-namespace leaves, which under the sorted-leaves Merkle tree changes `compute_state_root` with overwhelming probability (`≥ 1 - 2⁻¹²⁸` per SHA-256 collision resistance).

The S-033 verification gate at `chain.cpp:1430` (apply-side) and `chain.cpp:1893` (restore-side G2) consumes this contribution: a snapshot whose serialized `applied_inbound_receipts` diverges from its tail block's stored `state_root` fails G2 and is rejected. Post-S-038, every production block's `body.state_root` is non-zero (the producer's `try_finalize_round` populates it via a tentative-chain dry-run, `node.cpp:1024–1113`), so the gate fires on every post-S-038 snapshot.

### 1.3 The S-037 dependency

Pre-S-037 closure, `Chain::serialize_state` emitted no `dapp_registry` field. The S-037 closure shipped two paired loops together: (a) the `dapp_registry` serialize/restore that closed the named S-037 finding, and (b) tightened test coverage on the existing `applied_inbound_receipts` serialize/restore loops (which had shipped earlier but whose dedup-contract preservation across the restore boundary was not strictly asserted by any regression test). The matching regression `tools/test_applied_receipt_restore.sh` was added in the same in-session round as the S-037 closure; its first assertion exercises the round-trip and its critical assertion exercises the post-restore duplicate-skip behavior. Without the S-037 surface being in a known-correct state (the L-S0 coverage lemma in `SnapshotEquivalence.md` requires every state-root contributor to round-trip), this proof's theorems would have a parallel `d:`-namespace gap and the joint test `tools/test_dapp_snapshot.sh` would not have been writable.

### 1.4 What "preserved" means

Two chains' dedup sets `D_A`, `D_B` are byte-identical iff `D_A == D_B` under `std::set` equality (same key-set, same canonical iteration order). Because `std::set<std::pair<ShardId, Hash>>` is keyed by lexicographic `(src, tx_hash)` order, equality is invariant under any permutation of input insertion order — a property the serialize/restore loops exploit, since the JSON array is iterated in `std::set` order on the donor and the receiver re-inserts each element via `c.applied_inbound_receipts_.insert(...)`, which converges on the same final set regardless of insert order.

---

## 2. Theorems

### T-AR1 — Serialization includes applied_receipts

**Statement.** `Chain::serialize_state(C, header_count)` emits every entry of `C.applied_inbound_receipts_` into the `applied_inbound_receipts` JSON array of the returned snapshot. No entry is dropped, duplicated, or reordered relative to `std::set` canonical iteration order.

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

The loop iterates the entire set (no `break`, no skip, no conditional emit) and emits each element as a 2-field JSON object. The structured binding `auto& [src, tx_hash]` destructures the `std::pair`, and both fields are emitted under their canonical names. `to_hex(tx_hash)` is a pure function over the 32-byte hash (lower-case hex, no separators) — deterministic and reversible by the receiver's `from_hex_arr<32>`. The output JSON array's element count equals `applied_inbound_receipts_.size()` exactly; its element order is the `std::set` canonical iteration order (lexicographic by `(src, tx_hash)`). ∎

**Code witness.** `src/chain/chain.cpp:1585–1592` (`serialize_state` applied-receipt emit loop).

**Test witness.** `tools/test_applied_receipt_restore.sh` (assertion: snapshot JSON has `applied_inbound_receipts` array with 3 entries after 3 successful inbound credits). `tools/test_snapshot_then_apply.sh` (broader 21-assertion coverage that exercises the same surface as part of the full snapshot ↔ replay equivalence regression).

### T-AR2 — Restore reconstructs applied_receipts

**Statement.** `Chain::restore_from_snapshot(snap)` rebuilds `c.applied_inbound_receipts_` from the snapshot's `applied_inbound_receipts` JSON array, inserting every `(src, tx_hash)` element back into the set. The final set equals the donor's set under `std::set` equality.

**Proof sketch.** Inspect `restore_from_snapshot` at `chain.cpp:1778–1785`:

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

The `snap.contains(...)` guard preserves backward-compatibility — a pre-v2.18 snapshot without the field restores to an empty set, identical to a freshly-constructed Chain. The `json_require_array` helper (S-018 hardening) enforces array-typed input or throws a clean S-018 diagnostic naming the field, blocking wrong-type-collection attacks on the SNAPSHOT_RESPONSE channel. Inside the loop, each element's `src_shard` and `tx_hash` fields are read using the same accessor semantics as the serializer's emit — `ShardId` round-trips through the JSON integer codec losslessly (u64 width), `from_hex_arr<32>` is the exact inverse of `to_hex` over a 32-byte buffer (the default sentinel `std::string(64, '0')` decodes to the all-zero hash if the field were missing, but `json_require_array` guarantees object presence first). Every element is inserted via `c.applied_inbound_receipts_.insert({src, txhash})`, which is idempotent on already-present keys (a defensive property; the JSON shouldn't carry duplicates because the source set is a `std::set`).

By T-AR1 + the lossless field round-trip + `std::set::insert` idempotence: the post-restore set equals the donor's set element-for-element. ∎

**Code witness.** `src/chain/chain.cpp:1778–1785` (restore applied-receipt loop), `include/determ/util/json_validate.hpp::json_require_array` (S-018 hardening).

**Test witness.** `tools/test_applied_receipt_restore.sh` (assertions: post-restore `inbound_receipt_applied` predicate returns `true` for all 3 originally-credited `(src_shard, tx_hash)` pairs; bob's balance equals the pre-snapshot 60). `tools/test_snapshot_defense.sh` (S-018 guard: a wrong-type `applied_inbound_receipts` value — scalar / object / number — fails with the field-named S-018 diagnostic rather than corrupting the set).

### T-AR3 — Post-restore replay rejects duplicates

**Statement.** Let `C` be a chain post-`restore_from_snapshot`. Submitting a block `B` whose `inbound_receipts[]` contains some `(src, tx_hash) ∈ C.applied_inbound_receipts_` produces no state change for that entry: the V13 validator rejects the block (if the duplicate is the only inclusion-blocking issue), or the apply-layer dedup guard at `chain.cpp:1365` silently skips the duplicate (if the V13 path is bypassed under chain replay).

**Proof sketch.** By T-AR2 the post-restore set equals the donor's set. The V13 gate (`validator.cpp::check_inbound_receipts`) reads `applied_inbound_receipts_` via `Chain::inbound_receipt_applied(src, tx_hash)`, which by §1.1 returns `true` iff the pair is in the set. T-AR2 guarantees the pair is in the restored set whenever it was in the donor's set, so V13 rejects with the same `"inbound receipt already applied"` diagnostic on both sides.

If the block is loaded via chain.json replay (the validator pass is intentionally bypassed because the block is already finalized and signed K-of-K), the apply-layer fall-through at `chain.cpp:1363–1365` consults the same set:

```cpp
for (auto& r : b.inbound_receipts) {
    auto key = std::make_pair(r.src_shard, r.tx_hash);
    if (applied_inbound_receipts_.count(key)) continue;
    // … credit branch …
}
```

`continue` here means no `accounts_[r.to].balance` mutation, no `applied_inbound_receipts_.insert(...)`, no `block_inbound` accumulation. The post-restore set is consumed unchanged.

This is precisely the contract that `CrossShardReceiptDedup.md` (FA-Apply-9) theorem T-R2 states for the apply-path dedup guard. T-AR3 specializes T-R2 to the case where the dedup set's origin is a snapshot restore rather than a sequence of prior apply-time inserts — under T-AR2 the two origins produce indistinguishable sets, so T-R2's argument carries unchanged. ∎

**Code witness.** `src/node/validator.cpp::check_inbound_receipts` (V13 gate), `src/chain/chain.cpp:1363–1365` (apply-layer dedup guard), `src/chain/chain.cpp:204–207` (`inbound_receipt_applied` predicate).

**Test witness.** `tools/test_applied_receipt_restore.sh` (the critical assertion: a duplicate `(src_shard, tx_hash)` submitted on the restored chain is silently skipped, no balance change, no second credit). `tools/test_cross_shard_atomicity.sh` (the same dedup contract exercised on the apply-time accumulating set; T-AR3 inherits the proof).

### T-AR4 — Fresh receipts post-restore credit normally

**Statement.** Let `C` be a chain post-`restore_from_snapshot`. A receipt `r` with `(r.src_shard, r.tx_hash) ∉ C.applied_inbound_receipts_` baked into a finalized block `B` and applied via `apply_transactions(B)` credits `accounts_[r.to].balance += r.amount`, inserts `(r.src_shard, r.tx_hash)` into the set, and bumps `block_inbound` by `r.amount`. The credit follows the same path as a never-snapshotted chain.

**Proof sketch.** The apply-layer inbound-receipt loop at `chain.cpp:1363–1381` does not branch on the origin of `applied_inbound_receipts_` — it consults `applied_inbound_receipts_.count(key)` and, on `0`, proceeds through the credit branch. By hypothesis `count(key) == 0` for the fresh `(src_shard, tx_hash)`, so the function enters the credit branch:

```cpp
auto& rcv = accounts_[r.to].balance;
if (!checked_add_u64(rcv, r.amount, &rcv)) {
    throw std::runtime_error("S-007: inbound receipt credit would overflow recipient balance (to=" + r.to + ")");
}
__ensure_applied_inbound_receipts();
applied_inbound_receipts_.insert(key);
if (!checked_add_u64(block_inbound, r.amount, &block_inbound)) {
    throw std::runtime_error("S-007: per-block inbound sum overflowed u64");
}
```

The S-007 overflow checks guard both the recipient credit and the per-block accumulator. The `__ensure_applied_inbound_receipts()` call materializes the lazy snapshot of the set (A9 Phase 2A/2B optimization) on first mutation, so that a rollback at the apply-tail A1 invariant assertion can restore the pre-block state. The insert is idempotent — for a fresh key the set grows by one.

This is precisely the contract that `CrossShardReceiptDedup.md` (FA-Apply-9) theorem T-R1 states for the apply-path credit branch on fresh receipts. T-AR4 specializes T-R1 to a post-restore chain; the credit branch reads no field whose value differs between a freshly-constructed chain and a snapshot-restored chain (every field consulted — `accounts_`, `applied_inbound_receipts_`, scalar overflow guards — is covered by `SnapshotEquivalence.md` L-S0 / L-S1). ∎

**Code witness.** `src/chain/chain.cpp:1363–1381` (apply-layer inbound-receipt credit branch).

**Test witness.** `tools/test_applied_receipt_restore.sh` (assertion: a new `(src_shard, tx_hash)` post-restore credits the recipient normally and grows the set by one). `tools/test_cross_shard_atomicity.sh` (T-R1 base case for an unrestored chain; T-AR4 inherits the apply-path argument).

### T-AR5 — State-root consistency

**Statement.** Let `C` be the donor chain at the moment `snap = serialize_state(C)` runs, and let `C' = restore_from_snapshot(snap)`. Then:

```
Chain::compute_state_root(C) == Chain::compute_state_root(C')
```

In particular, the `i:`-namespace contribution to the state-root is preserved: every `i:`-prefixed Merkle leaf the donor emits is also emitted by the receiver, and the leaves coincide byte-for-byte.

**Proof sketch.** This is the `i:`-namespace specialization of `SnapshotEquivalence.md` theorem T-S3 (cross-namespace coverage). Combine T-AR1 (donor serializes the entire set) and T-AR2 (receiver restores the entire set) with §1.2's observation that `build_state_leaves` is a pure function of `applied_inbound_receipts_` for the `i:` namespace. Identical input sets produce identical Merkle leaves (`"i:" || src_be8 || tx_hash` key, `SHA256(0x01)` value-hash), and the sorted-leaves Merkle tree's `merkle_root` is deterministic over the sorted leaf set (`Preliminaries.md` §2.1 SHA-256 collision resistance + leaf-key injectivity).

Because `compute_state_root` aggregates contributions from all ten namespaces (`a:`, `s:`, `r:`, `d:`, `i:`, `b:`, `m:`, `p:`, `k:`, `k:c:`) and each is preserved by L-S0 / L-S1 in `SnapshotEquivalence.md`, the final root coincides. Equivalently: `compute_state_root` is a pure function of the eight backing maps + scalar constants + counters, every component of which is round-tripped by `serialize` / `restore`.

The S-033 + S-038 verification gate at restore-side G2 (`chain.cpp:1893–1911`) enforces this property at the wire boundary: a snapshot whose serialized `applied_inbound_receipts` diverged from its tail block's stored `state_root` (e.g., an attacker truncated the array or flipped one `tx_hash` byte) fails G2 and the restore throws. The gate's existence is what makes T-AR5 a checkable property at the wire layer rather than an honest-only invariant. ∎

**Code witness.** `src/chain/chain.cpp:267` (`build_state_leaves`), `src/chain/chain.cpp:413` (`Chain::compute_state_root`), `src/chain/chain.cpp:1430` (apply-side S-033 + S-038 verification gate), `src/chain/chain.cpp:1893` (restore-side G2 gate).

**Test witness.** `tools/test_applied_receipt_restore.sh` (assertion: `compute_state_root` identical pre- and post-restore). `tools/test_state_root_namespaces.sh` (12 assertions exhaustively exercising all 10 namespaces, including `i:` — mutating any one entry diverges the root). `tools/test_dapp_snapshot.sh` (S-037 joint-surface end-to-end: receiver's recomputed state-root strictly matches the snapshot tail head's stored state-root post-restore — pre-S-038 this assertion would have been vacuous because the stored field was zero).

### T-AR6 — S-037 closure dependency

**Statement.** The theorems T-AR1, T-AR2 (and by composition T-AR3, T-AR4, T-AR5, T-AR7) require S-037 to be in its closed state — equivalently, `Chain::serialize_state` and `Chain::restore_from_snapshot` must collectively round-trip every state-root-contributing field. Without S-037, the parallel `d:`-namespace coverage gap would cause `compute_state_root(restored) ≠ tail.state_root` on any DApp-active chain, the restore-side G2 gate would reject the snapshot, and `restore_from_snapshot` would throw — so T-AR2's conclusion ("the final set equals the donor's set under `std::set` equality") would be unreachable in practice for any chain whose `dapp_registry_` is non-empty.

**Proof sketch.** S-037's named scope is the `d:`-namespace serialize/restore. Its impact on the `i:`-namespace is indirect but binding through the joint G2 gate: G2 recomputes `compute_state_root` over the entire restored state and compares it to the tail block's stored `state_root`. If any single namespace is corrupt (missing, partial, or out-of-order), the recomputed root diverges and G2 throws.

Pre-S-037, a DApp-active chain whose `dapp_registry_` was non-empty would have:

- Donor side: `build_state_leaves` emits leaves in 10 namespaces including `d:`.
- Donor side: `serialize_state` emits 9 namespaces (no `dapp_registry` field).
- Receiver side: `restore_from_snapshot` loads 9 namespaces; the receiver's `dapp_registry_` is empty.
- Receiver side: `compute_state_root` emits leaves in 9 namespaces — diverges from donor's 10-namespace root.
- Receiver side: G2 fails; `restore_from_snapshot` throws.

The applied-receipts loops shipped pre-S-037 (the `i:`-namespace coverage was older code) but were *unreachable* in production on any DApp-active chain because the joint G2 gate would have rejected the snapshot before the `applied_inbound_receipts` loop's effects became observable. Post-S-037, both namespaces round-trip and G2 passes — so T-AR1 / T-AR2 are observable in the end-to-end behavior, and the regression `tools/test_applied_receipt_restore.sh` can strictly assert the dedup-set preservation.

Conversely: a hypothetical chain whose `dapp_registry_` is empty would never have hit the S-037 gap (the `d:` namespace would emit zero leaves on both sides), and the `i:`-namespace round-trip would have worked correctly. The dependency is a joint-state property of the apply-layer's state-root binding, not a logical dependency between the two namespace's loops. ∎

**Code witness.** `src/chain/chain.cpp:1654–1668` (S-037-added `dapp_registry` serialize loop), `src/chain/chain.cpp:1834–1860` (S-037-added `dapp_registry` restore loop), `src/chain/chain.cpp:1893` (G2 gate that consumes both namespaces jointly).

**Test witness.** `tools/test_applied_receipt_restore.sh` (verifies the `i:`-namespace round-trip on a chain whose `dapp_registry_` is empty — exercises the cross-shard surface in isolation). `tools/test_dapp_snapshot.sh` (S-037 joint-surface end-to-end: a DApp-active chain whose snapshot also carries applied-receipt entries restores correctly across both namespaces). The two regressions are disjoint in their setup but jointly defend T-AR6.

### T-AR7 — Determinism

**Statement.** Identical pre-snapshot chains produce byte-identical restored `applied_inbound_receipts_` sets. Formally: for any two Chains `C_A`, `C_B` with `C_A.applied_inbound_receipts_ == C_B.applied_inbound_receipts_` (set equality) and otherwise identical state, two evaluations of `restore_from_snapshot(serialize_state(C_A))` and `restore_from_snapshot(serialize_state(C_B))` on a single thread produce sets that are byte-identical and produce identical `compute_state_root` outputs.

**Proof sketch.** `serialize_state` is deterministic by `SnapshotEquivalence.md` T-S6 — no I/O, no clock reads, no random sampling, no peer queries. The `applied_inbound_receipts_` serialize loop at lines 1585–1592 iterates `std::set` in canonical sorted order (a property of `std::set` over `std::pair<u64, std::array<u8, 32>>` — strict-weak ordering on `(src, tx_hash)` lexicographic comparison). For input sets `D_A == D_B`, the canonical iteration produces the same element sequence on both sides, and the JSON array is byte-identical (modulo whitespace, which nlohmann json's default output suppresses).

`restore_from_snapshot`'s loop at lines 1778–1785 inserts each element into a fresh `c.applied_inbound_receipts_`; `std::set::insert` is deterministic over the input sequence (the final set is independent of insert order, and the data structure's internal node layout is a tree-balancing implementation detail that doesn't affect set-equality or `compute_state_root`). For input sequences `s_A == s_B`, the resulting sets are byte-identical under `std::set::operator==`, and `compute_state_root` is a pure function of the set's contents (it iterates `applied_inbound_receipts_` in canonical order at lines 332–341 of `build_state_leaves`).

Determinism composes: identical inputs → identical serialization → identical restoration → identical state-root. ∎

**Code witness.** `src/chain/chain.cpp:1585–1592` (deterministic serialize loop over canonical `std::set` iteration), `src/chain/chain.cpp:1778–1785` (deterministic restore loop), `src/chain/chain.cpp:332–341` (deterministic state-root leaf emission).

**Test witness.** `tools/test_applied_receipt_restore.sh` (the same chain serialized twice produces the same state-root, asserted via determinism comparison). `tools/test_snapshot_roundtrip.sh` (broader "same snapshot → same restored state_root" assertion that covers the `applied_inbound_receipts` round-trip as one of its 14 assertions). `tools/test_state_root_namespaces.sh` (baseline-equality assertion: two identical fresh chains produce identical state-roots, exercised across all 10 namespaces).

---

## 3. Composition with FA-Apply-9 and FA-Apply-2

The proof's structure is intentionally a thin specialization of `SnapshotEquivalence.md` (FA-Apply-2) restricted to the `i:`-namespace + `CrossShardReceiptDedup.md` (FA-Apply-9) restricted to a post-restore chain:

- **From FA-Apply-2 T-S1** (serialize-restore identity): the entire chain restores byte-identically; T-AR1 + T-AR2 are the `i:`-namespace projection.
- **From FA-Apply-2 T-S2** (apply-after-restore equivalence): the apply path on a restored chain produces the same posterior state as a full replay; T-AR3 + T-AR4 inherit the post-restore apply behavior from this.
- **From FA-Apply-2 T-S3** (cross-namespace coverage): every state-root contributor round-trips; T-AR5 is the `i:`-namespace specialization.
- **From FA-Apply-2 T-S6** (determinism of `serialize_state`): the loop is pure; T-AR7 inherits.
- **From FA-Apply-9 T-R1** (fresh receipt credits): the apply-path credit branch is unchanged by the dedup set's origin; T-AR4 inherits.
- **From FA-Apply-9 T-R2** (duplicate silently skipped): the apply-path dedup guard is unchanged by the dedup set's origin; T-AR3 inherits.

What's novel here is the joint statement: the dedup contract survives the restore boundary intact. Neither FA-Apply-2 nor FA-Apply-9 makes this claim explicitly — FA-Apply-2 covers byte-level restore equivalence, FA-Apply-9 covers apply-path dedup correctness, but the composition (FA7's no-double-credit theorem holds across snapshot bootstrap) is what FA-Apply-12 names. The regression `tools/test_applied_receipt_restore.sh` is the joint-surface witness: its critical assertion ("duplicate receipt on the restored chain is silently skipped") is exactly the FA7 + FA-Apply-9 contract evaluated at a post-restore chain, and it would fail under any drift that broke either the serialize/restore loops (T-AR1 + T-AR2) or the post-restore dedup gate (T-AR3).

---

## 4. What this doesn't cover

- **Wire-level snapshot authentication.** This proof assumes the snapshot's bytes are honest (or are reduced to honesty by the G2 state-root verification gate). It does not authenticate the snapshot's provenance — a malicious peer could supply a self-consistent snapshot of a forked chain. The G2 gate catches internally-inconsistent snapshots; operator policy (cross-checking `head_hash` against a trusted source) is the current provenance defense. A future v2.x committee-signed snapshot envelope would close the gap.
- **Cross-shard receipt source-side correctness.** This proof's scope is destination-side dedup-set preservation. The source-side cross-shard `TRANSFER` debit + receipt emission is covered by `CrossShardReceipts.md` (FA7) and the per-receipt 1:1 binding is L-7.1; this proof composes with FA7 but does not re-prove it.
- **Liveness of inbound delivery.** The dedup set's monotonic growth depends on the destination chain's liveness (FA4) and on the source chain's receipts being gossipped and ratified. This proof assumes both — without source-side finalization the receipt would never enter `pending_inbound_receipts_` and never be apply-eligible. The end-to-end delivery liveness is `CrossShardReceipts.md` T-7'.
- **Cross-shard partition refunds.** If a destination shard goes permanently silent, the source-side debit is unrecoverable and the receipt is stuck in `Pending` (per `CrossShardReceipts.md` §6.1). This is a livelihood concern, not a soundness one — the dedup-set property still holds; there's just nothing to dedup against on the silent shard.
- **Apply-time atomic-scope rollback semantics.** The dedup set is `std::optional`-wrapped in `StateSnapshot` (the A9 Phase 2A/2B lazy-snapshot optimization, captured on first mutation at `chain.cpp:663–665`). The snapshot-restore path does not interact with the per-block lazy snapshot — it fully replaces the set from JSON. The apply-time rollback property is `AccountStateInvariants.md` I-1 (atomic apply); this proof inherits it but does not re-prove it.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | V13 validator-predicate definition; assumption A1 (Ed25519 EUF-CMA) for receipt authenticity; A3 (SHA-256 CR) for leaf-key injectivity. |
| `AccountStateInvariants.md` (FA-Apply) | I-4 (cross-shard credit channel) and I-5 (balance arithmetic) — the per-account invariants the post-restore apply path preserves. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 / T-S2 / T-S3 / T-S6 — the generic snapshot ↔ replay equivalence theorems this proof specializes to the `i:` namespace. |
| `CrossShardReceiptDedup.md` (FA-Apply-9) | T-R1 (fresh receipt credits) and T-R2 (duplicate silently skipped) — the apply-path dedup theorems this proof composes with at the restore boundary. |
| `AbortEventApply.md` (FA-Apply-11) | Parallel apply-side cache (`abort_records_` / `b:` namespace) whose serialize-restore property follows the same pattern as this proof. |
| `CrossShardReceipts.md` (FA7) | T-7 no-double-credit + T-7.1 supply atomicity; the higher-level claim that this proof's dedup-preservation underwrites across snapshot bootstrap. |
| `docs/SECURITY.md` §S-012 | Snapshot-bootstrap state-root verification — the security finding behind the G2 gate. |
| `docs/SECURITY.md` §S-033 | Merkle state commitment + Block.state_root + apply / restore verification gates. |
| `docs/SECURITY.md` §S-037 | DApp-registry serialize/restore — paired closure; without S-037 this proof's T-AR1 / T-AR2 would be unreachable on a DApp-active chain. |
| `docs/SECURITY.md` §S-038 | Producer-side wiring that populates `body.state_root` on broadcast; without it the G2 gate would be dormant. |
| `docs/PROTOCOL.md` §4.1.1 | `i:` namespace state-root encoding (`"i:" || src_be8 || tx_hash` key, presence-marker value-hash). |
| `docs/PROTOCOL.md` §11 | Snapshot wire format including the `applied_inbound_receipts` field schema. |
| `tools/test_applied_receipt_restore.sh` | Canonical regression — 10 assertions covering T-AR1 / T-AR2 / T-AR3 / T-AR4 / T-AR5 / T-AR7 end-to-end. |
| `tools/test_snapshot_then_apply.sh` | Broader snapshot ↔ replay equivalence regression (21 assertions); covers T-AR1 / T-AR2 / T-AR5 as part of the FA-Apply-2 coverage. |
| `tools/test_snapshot_roundtrip.sh` | Determinism assertion + 14-assertion snapshot round-trip; T-AR7 specializes. |
| `tools/test_state_root_namespaces.sh` | Per-namespace state-root sensitivity (12 assertions across all 10 namespaces including `i:`); T-AR5 inherits. |
| `tools/test_dapp_snapshot.sh` | S-037 joint-surface end-to-end; T-AR6 dependency witness. |
| `tools/test_snapshot_defense.sh` | S-018 hardening — wrong-type `applied_inbound_receipts` field rejected with field-named diagnostic; defends T-AR2's input-validation precondition. |
| `tools/test_cross_shard_atomicity.sh` | FA-Apply-9 base regression for T-R1 / T-R2 on an unrestored chain. |
| `src/chain/chain.cpp:1585` | `serialize_state` applied-receipt emit loop. |
| `src/chain/chain.cpp:1778` | `restore_from_snapshot` applied-receipt restore loop. |
| `src/chain/chain.cpp:1363` | Apply-layer inbound-receipt loop (dedup guard + credit branch). |
| `src/chain/chain.cpp:204` | `Chain::inbound_receipt_applied` public predicate. |
| `src/chain/chain.cpp:331` | `build_state_leaves` `i:`-namespace leaf emission. |
| `src/chain/chain.cpp:413` | `Chain::compute_state_root`. |
| `src/chain/chain.cpp:1430` | Apply-side S-033 + S-038 verification gate. |
| `src/chain/chain.cpp:1893` | Restore-side G2 state-root gate. |
| `src/node/validator.cpp::check_inbound_receipts` | V13 destination-side dedup gate. |
| `include/determ/util/json_validate.hpp::json_require_array` | S-018-hardened JSON array accessor used by the restore loop. |

---

## 6. Status

All seven theorems (T-AR1 through T-AR7) are closed in the current codebase:

- **T-AR1** closed via inspection of `serialize_state` lines 1585–1592 (deterministic loop over `std::set` canonical iteration); regression `test_applied_receipt_restore.sh`.
- **T-AR2** closed via inspection of `restore_from_snapshot` lines 1778–1785 (json_require_array guard + idempotent set::insert); regressions `test_applied_receipt_restore.sh` + `test_snapshot_defense.sh`.
- **T-AR3** closed via composition of T-AR2 (set preserved) + FA-Apply-9 T-R2 (dedup guard semantics); regression `test_applied_receipt_restore.sh` critical assertion.
- **T-AR4** closed via composition of T-AR2 (set preserved) + FA-Apply-9 T-R1 (credit-branch semantics); regression `test_applied_receipt_restore.sh` fresh-receipt assertion.
- **T-AR5** closed via FA-Apply-2 T-S3 specialized to `i:`-namespace + S-033 + S-038 gates; regressions `test_applied_receipt_restore.sh` + `test_state_root_namespaces.sh` + `test_dapp_snapshot.sh`.
- **T-AR6** closed via SECURITY.md §S-037 paired closure (both `d:` and `i:` namespaces must round-trip jointly for G2 to pass on DApp-active chains); regression `test_dapp_snapshot.sh` end-to-end witness.
- **T-AR7** closed via inspection of pure-function serialize + deterministic STL set iteration; regression `test_applied_receipt_restore.sh` determinism assertion.

No theorem is open or partial. The proof's foundation rests jointly on the S-033 + S-037 + S-038 closures shipped earlier in-session; the matching regressions exercise both the in-isolation `i:`-namespace round-trip (`test_applied_receipt_restore.sh`) and the joint DApp-active surface (`test_dapp_snapshot.sh`) where the dependency on S-037 becomes operationally observable.
