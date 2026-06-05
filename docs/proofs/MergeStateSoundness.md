# MergeStateSoundness — `m:` merge-state namespace apply + snapshot determinism (MS-1..MS-6)

This document proves the soundness of the `m:` (merge_state) namespace of the S-033 `state_root` commitment as a single closed contract: that `Chain::merge_state_` is a deterministic function of the chain's `MERGE_EVENT` multiset (apply-determinism), that the apply path is idempotent under duplicate / replayed `MERGE_END`, that the `m:` namespace round-trips byte-identically through `serialize_state → restore_from_snapshot`, and that any silent drop of `merge_state_` from the snapshot surface is detected (reduces to A2 via an S-041-style argument) rather than corrupting the chain. It is the `m:`-namespace sibling of the per-namespace state-root soundness proofs (`S033StateRootNamespaceCoverage.md` for the `i:`/`k:`/`s:`/… surface; `SnapshotDeterminismComposition.md` for the all-namespace joint statement). Where those proofs cover `m:` only as one cell of a larger table, this document isolates the merge-state namespace and discharges its apply-side determinism + snapshot-side round-trip identity in full, then composes the result with the R7 under-quorum-merge safety (FA9 / S-036).

The proof exists because three previously-distinct results touch `merge_state_` without ever stating its namespace-local soundness as one theorem: `UnderQuorumMerge.md` (FA9) covers safety preservation across BEGIN/END (FA1 K-of-K + FA7 cross-shard atomicity stay sound), `S036UnderQuorumMerge.md` covers the MERGE_BEGIN admission gate + MERGE_END idempotence + the S-036 closure path, and `S033StateRootNamespaceCoverage.md` covers the `m:` cell of the 10-namespace coverage table. None states the `m:`-namespace **apply-determinism + snapshot round-trip identity** as a self-contained contract that an external auditor can verify by reading exactly five source sites (the `m:` leaf in `build_state_leaves`, the `MERGE_EVENT` apply case, the rollback-snapshot capture, the `serialize_state` emit, and the `restore_from_snapshot` read). This proof fills that gap and reduces the whole namespace's cryptographic guarantee to **A2** (SHA-256 collision resistance, `Preliminaries.md` §2.1).

**Cryptographic assumptions** (canonical labels, `Preliminaries.md` §2.0): **A2** = SHA-256 collision resistance (§2.1) — the sole cryptographic reduction target of this document, via the Merkle-binding of the `m:` value-hash and the snapshot drop-detection gate. **A1** = Ed25519 EUF-CMA (§2.2) is invoked only at the composition boundary (MS-6) where the `MERGE_EVENT` rides on a K-of-K-signed block; it is not a reduction target of MS-1..MS-5.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (assumption labels) + §2.1 (A2); `UnderQuorumMerge.md` (FA9) for the safety preservation across BEGIN/END that MS-6 composes; `S036UnderQuorumMerge.md` for the MERGE_BEGIN admission gate (T-1) + MERGE_END idempotence (T-2) that MS-2 sharpens at the namespace layer + the S-036 closure path (T-5); `S033StateRootNamespaceCoverage.md` for the 10-namespace coverage completeness (T-1) + disjointness (T-2) + deterministic leaf ordering (T-3) that MS-3/MS-4 invoke; `SnapshotDeterminismComposition.md` (SD-1..SD-5) for the all-namespace joint round-trip that this document's MS-4 specializes to `m:`; `RegionalSharding.md` (FA8) for the stress-branch committee-selection determinism that MS-5 anchors; `docs/SECURITY.md` §S-033 / §S-036 / §S-041 for the closure-status narratives; `docs/PROTOCOL.md` §4.1.1 (the `m:` Merkle-leaf encoding) + §6.4 (the R4 substrate wire contract) + §11 (snapshot wire format).

---

## 1. Scope

### 1.1 What this proves

Let `Chain` denote the type at `include/determ/chain/chain.hpp`. The merge-state surface is the single member field `merge_state_` (`chain.hpp:598`), a `std::map<ShardId, MergePartnerInfo>` (`MergeStateMap`, `chain.hpp:332`), where `MergePartnerInfo` is `{ShardId partner_id; std::string refugee_region;}` (`chain.hpp:328-331`). It is keyed by the **refugee** shard id; absence from the map is the canonical NOT-MERGED state.

For a chain `C`, write `m(C) := C.merge_state_` for the map, `S := serialize_state(C)` for the snapshot JSON (`chain.cpp:1541`), and `R(S) := restore_from_snapshot(S)` for the restored chain (`chain.cpp:1703`). This document proves six theorems:

- **MS-1 — apply-determinism**: for any chain prefix and any block `B`, `apply_transactions(B)` mutates `merge_state_` as a deterministic function of the `MERGE_EVENT` transactions in `B` (and the pre-state map) alone — the same `MERGE_EVENT` sequence applied to the same starting map yields a byte-identical resulting map on every honest node, with no dependence on platform, allocator, or insertion history.
- **MS-2 — MERGE_END idempotence + BEGIN idempotence**: duplicate / replayed `MERGE_BEGIN` (same `shard_id`) and duplicate / replayed / mismatched-partner / pre-BEGIN `MERGE_END` are all no-ops on `merge_state_`, via `std::map::insert` / `find`+`erase` semantics. The map is a function of the *set* of currently-active merges, not of the apply trace.
- **MS-3 — `m:` leaf injectivity + state-root sensitivity**: the `m:` leaf key/value encoding is injective over `merge_state_` and disjoint from every other namespace; toggling any single field of any `MergePartnerInfo` (or adding/removing a refugee shard) changes `compute_state_root` except with probability `≤ 2⁻¹²⁸` (A2).
- **MS-4 — snapshot round-trip identity for `m:`**: `serialize_state → restore_from_snapshot` preserves `merge_state_` byte-for-byte, hence preserves the `m:` leaf set, hence `compute_state_root(R(S))`'s `m:` contribution equals `C`'s. The re-serialized `merge_state` JSON is byte-identical.
- **MS-5 — silent-drop detection (S-041-style, reduces to A2)**: if a future code change dropped `merge_state_` from `serialize_state` while leaving it in `build_state_leaves`, then for any chain with a non-empty `merge_state_` the restore-side G2 state-root gate (`chain.cpp:1893-1911`) throws loudly rather than restoring a divergent chain. The drop is detectable, not silent.
- **MS-6 — composition with R7 safety (FA9 / S-036)**: MS-1..MS-5 compose with FA9's safety preservation (FA1 K-of-K + FA7 atomicity stay sound across BEGIN/END) and with the S-036 admission gate so that a snapshot-bootstrapped node resumes mid-merge with the identical committee-selection behavior as a fully-replayed node.

### 1.2 What this adds over the per-namespace and FA9 proofs

| Proof | Covers `merge_state_` as |
|---|---|
| `UnderQuorumMerge.md` (FA9) | the *safety-preservation* surface across BEGIN/END (T-9, T-9a, T-9.1). Notes idempotency as a "bonus" (FA9 §3.3) but does not state the namespace-local apply-determinism or snapshot round-trip as a theorem. |
| `S036UnderQuorumMerge.md` | the *origination/admission* surface (T-1 BEGIN gate, T-2 END idempotence, T-5 S-036 closure). States the `m:` state-root binding as a one-line cross-reference (its §1.3) but does not prove the namespace round-trip. |
| `S033StateRootNamespaceCoverage.md` | one *cell* of the 10-namespace coverage table (T-1 row for `merge_state_ ↦ m:`). |
| `SnapshotDeterminismComposition.md` | one *row* of the all-namespace joint round-trip (SD-1..SD-5 over `{a:,…,m:,…,c:}`). |

What none states is the **`m:`-namespace-isolated apply-determinism + snapshot round-trip identity** as a self-contained, five-site-verifiable contract reducing to A2. MS-1..MS-5 are that contract; MS-6 re-composes it with FA9/S-036 so the merge-state namespace is closed end-to-end.

### 1.3 What this does not prove

The MERGE_BEGIN admission soundness (why a captured beacon cannot forge `evidence_window_start`) is `S036UnderQuorumMerge.md` T-1 + T-5, not re-proved here. The FA1 K-of-K per-shard safety and FA7 cross-shard atomicity preservation across merge are `UnderQuorumMerge.md` T-9 / T-9a, invoked at MS-6 but not re-derived. The Merkle primitive itself (determinism, collision-resistance inheritance) is `MerkleTreeSoundness.md`. Byzantine snapshot *bytes* (a hostile operator shipping a self-inconsistent snapshot) are caught by the restore-side G2 gate per `S012SnapshotStateRootGate.md`; MS-5 reuses that gate but does not re-prove its tamper-resistance. The consensus-layer divergent-body question is `S030-D2-Analysis.md` / `F2-SPEC.md`.

---

## 2. Model

### 2.1 The `m:` leaf encoding (read off `build_state_leaves`)

`Chain::build_state_leaves` (`src/chain/chain.cpp:267-411`) emits one `MerkleLeaf` `(key, value_hash)` per live `merge_state_` entry at `chain.cpp:349-360`:

```cpp
// merge_state_  (key = "m:" + shard_id_be4)
for (auto& [shard, info] : merge_state_) {
    std::vector<uint8_t> key;
    key.reserve(2 + 4);
    key.push_back('m'); key.push_back(':');
    for (int i = 3; i >= 0; --i) key.push_back((shard >> (8*i)) & 0xff);   // shard_id big-endian, 4 bytes
    crypto::SHA256Builder b;
    b.append(static_cast<uint64_t>(info.partner_id));                       // partner_id, 8 bytes BE
    b.append(static_cast<uint64_t>(info.refugee_region.size()));           // region length, 8 bytes BE
    b.append(info.refugee_region);                                          // region bytes (utf8)
    leaves.push_back({std::move(key), hash_bytes(b)});
}
```

So the `m:` leaf for a refugee shard `s` with partner `p` and region `ρ` is:

- **key** = `"m:"` (2 bytes ASCII) ‖ `s` (4 bytes big-endian) — a fixed 6-byte key.
- **value_hash** = `SHA256( partner_id_u64_BE ‖ |ρ|_u64_BE ‖ ρ_bytes )` — binds the partner id, the region length, and the region bytes, with an explicit length-prefix so two distinct `(partner, region)` pairs cannot alias by region-boundary ambiguity.

This matches PROTOCOL.md §4.1.1's `m:` row and the `S033StateRootNamespaceCoverage.md` §2.1 table (key `"m:" + shard_id_be4`, value `SHA256(partner_id ‖ region_len ‖ region_bytes)`). The map is iterated in `std::map<ShardId, …>` sorted-key order (ascending `ShardId`); the downstream `crypto::merkle_root` re-sorts all leaves by key before reduction, so the emission order is immaterial to the root (S033 T-3).

### 2.2 The apply state machine (read off `apply_transactions`)

`Chain::apply_transactions`'s `MERGE_EVENT` case (`src/chain/chain.cpp:1017-1039`) is the **only** mutation site for `merge_state_` inside the apply boundary:

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
            __ensure_merge_state();                          // rollback-snapshot capture
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

Three structural facts to record precisely:

1. **Canonical-decode gate.** `MergeEvent::decode(tx.payload)` returns `std::nullopt` on size mismatch, invalid `event_type`, or `region_len > 32` (`block.hpp:332-336` codec contract). A failed decode falls through to `sender.next_nonce++` with no map mutation — fee charged, nonce advanced, state untouched. This is the defensive-on-malformed-payload posture that keeps honest replay consistent if a malformed tx ever slips past the validator (`validator.cpp` MERGE_EVENT branch).

2. **Partner well-formedness gate.** The mutation is gated on `shard_count_ > 1` AND `partner_id == (shard_id + 1) mod shard_count_`. For `N > 1`, `(s+1) mod N ≠ s`, so a self-merge (`partner_id == shard_id`) can never insert; for `N ≤ 1` the gate fails outright (no partner exists). This is the apply-time defense against `A_self_merge` (`S036UnderQuorumMerge.md` §5(c)).

3. **`__ensure_merge_state()` is the rollback snapshot, not the persistent map.** The lambda at `chain.cpp:659-661` lazily captures the *pre-mutation* `merge_state_` into `__snapshot.merge_state` (A9 Phase 2A/2B lazy capture) so that if the block apply fails downstream (e.g. an A1 supply-invariant trip), `restore_state_snapshot` (`chain.cpp:598-614`, line 609-610) rolls `merge_state_` back to its pre-block value. This is an *intra-apply* rollback artifact (a `std::optional<MergeStateMap>`), categorically distinct from the inter-apply persistent field `merge_state_` and from the snapshot-JSON pathway of MS-4. It is correctly **outside** the state-root universe `S` (it is a local rollback buffer, not block-derived persistent state), exactly as `S033StateRootNamespaceCoverage.md` §4.1.5 excludes the `__snapshot` locals.

### 2.3 The snapshot pathway (read off serialize / restore)

`Chain::serialize_state` emits `merge_state_` at `chain.cpp:1645-1653`:

```cpp
json merge_arr = json::array();
for (auto& [s, info] : merge_state_) {
    merge_arr.push_back({
        {"shard_id",       s},
        {"partner_id",     info.partner_id},
        {"refugee_region", info.refugee_region},
    });
}
snap["merge_state"] = merge_arr;
```

`Chain::restore_from_snapshot` reads it back at `chain.cpp:1801-1810`:

```cpp
if (snap.contains("merge_state")) {
    for (auto& m : json_require_array(snap, "merge_state")) {
        ShardId s = m.value("shard_id",   ShardId{0});
        Chain::MergePartnerInfo info;
        info.partner_id     = m.value("partner_id", ShardId{0});
        info.refugee_region = m.value("refugee_region", std::string{});
        c.merge_state_.insert({s, std::move(info)});
    }
}
```

The `if (snap.contains("merge_state"))` guard is the backward-compat shim: a pre-R4 snapshot omits the field and the restored chain's `merge_state_` is left empty — which is exactly what `build_state_leaves` emits for a chain with no active merges (no `m:` leaves), so a pre-R4-feature snapshot of a no-merge chain round-trips identically. The field is emitted as an empty JSON array (not absent, not null) for a chain with no active merges on the *current* code path, giving wire-schema stability for fast-bootstrap peers (pinned by `test_merge_state_determinism.sh` scenario 2).

### 2.4 Restore-side gates

`restore_from_snapshot` enforces two gates that an honest `m:` round trip satisfies by construction (and that catch a dropped/tampered `m:`, §MS-5):

- **G1** — head-hash match (`chain.cpp:1855-1862`): the loaded tail block re-hashes to `snap.head_hash`.
- **G2** — state-root match (`chain.cpp:1893-1911`): `compute_state_root(restored)` equals the tail block's stored `state_root`, skipped iff that stored root is the all-zero sentinel (the pre-S-038 backward-compat path). G2 is the runtime check that MS-5 fires.

---

## 3. Theorems

Fix a reachable chain `C` (genesis followed by zero or more `apply_transactions`-valid blocks). Write `m = m(C) = C.merge_state_`.

### MS-1 — Apply-determinism of `merge_state_`

**Statement.** Let `m₀` be the merge-state map before applying block `B`, and let `E(B) = [e₁, e₂, …, e_j]` be the subsequence of well-formed (decode-succeeds, partner-well-formed, fee-payable) `MERGE_EVENT` transactions in `B` in block order. Then the post-apply map `m₁ = apply(m₀, E(B))` is a pure deterministic function of `(m₀, E(B))`: two honest nodes holding byte-identical `m₀` and applying the same block `B` reach byte-identical `m₁`, with no dependence on platform, allocator, ABI, or insertion history.

**Proof.** The `MERGE_EVENT` case (§2.2) mutates `merge_state_` only via `std::map::insert({shard_id, info})` (BEGIN) and `std::map::erase(it)` (END). Each operation is:

- **Deterministic in effect.** `insert({k, v})` on a `std::map` adds `(k, v)` iff `k` is absent and is a no-op otherwise; `erase(it)` removes the pointed element. Neither operation's *final container contents* depend on insertion history — a `std::map` is determined by its element set, not by the order or path by which elements were added (`[map.overview]` element-uniqueness). Two maps that received the same multiset of insert/erase operations (modulo no-op collisions) hold the same elements.
- **Deterministic in the value written.** For BEGIN, `info.partner_id` and `info.refugee_region` are copied verbatim from the decoded `MergeEvent` (`ev->partner_id`, `ev->merging_shard_region`); `MergeEvent::decode` is a pure function of `tx.payload` bytes. For END, no value is written. So the value associated with each key is a deterministic function of the event bytes.
- **Deterministic in the gate.** The `shard_count_ > 1 && partner_id == (shard_id+1) mod shard_count_` gate reads only `shard_count_` (a genesis-pinned constant, identical across honest nodes) and event fields. `charge_fee` reads/writes `accounts_` deterministically (FA-Apply-1).

Composing over the block-order sequence `E(B)`: `m₁` is the left-fold of the deterministic `apply_one` over `E(B)` starting from `m₀`. Block order is fixed (the block body is gossiped byte-identical to all honest peers; `BlockchainStateIntegrity.md` T-4). Therefore `m₁` is a deterministic function of `(m₀, E(B))`. By induction over the block sequence from genesis (`m₀ = ∅` at genesis — no MERGE_EVENT can precede the first block), `merge_state_` at any height is a deterministic function of the chain's full `MERGE_EVENT` multiset.   ∎

**Code witness.** `chain.cpp:1017-1039` (apply case), `chain.cpp:349-360` (deterministic `std::map`-order leaf emission). **Test witness.** `tools/test_merge_event_determinism.sh` (event wire + apply + state_root determinism); `tools/test_merge_state.sh` (read-API on the in-memory map, 11 assertions).

### MS-2 — MERGE_END idempotence + MERGE_BEGIN idempotence

**Statement.** The apply path is idempotent over duplicate / replayed / malformed merge events. Specifically, `merge_state_` is a function of the *set* of currently-active `(shard_id → {partner_id, region})` merges, not of the apply trace:

1. **Duplicate BEGIN** (same `shard_id`, already merged). `merge_state_.insert({shard_id, info})` on a present key returns `{existing_iterator, false}` and does **not** overwrite — no mutation. The map is unchanged.
2. **First END after a matching BEGIN.** `find(shard_id)` returns a valid iterator with `partner_id == ev->partner_id`; `erase(it)` removes the entry. The next state-root recompute drops the `m:` leaf for `shard_id` (§2.1).
3. **Replayed END** (entry already erased). `find(shard_id)` returns `end()`; the gate at `chain.cpp:1030-1031` short-circuits — no mutation, no exception.
4. **Mismatched-partner END.** `find(shard_id)` returns a valid iterator but `it->second.partner_id != ev->partner_id`; the gate short-circuits — no mutation.
5. **Pre-BEGIN END.** `find(shard_id)` returns `end()` — no mutation.

**Proof.** Cases (1)–(5) are read directly off the `std::map` contract and the `find`+present-and-partner-match gate (§2.2). `std::map::insert(value_type)` is specified to have no effect when an element with the equivalent key already exists (it returns an iterator to the existing element and `false`). `std::map::erase(iterator)` removes exactly the pointed element. The surrounding `it != end() && it->second.partner_id == ev->partner_id` predicate confines `erase` to the present-and-partner-matching case; every other END path is a structural no-op. Therefore the post-apply map depends only on which `shard_id`s are currently active and their `(partner_id, region)`, not on how many times BEGIN/END were issued or in what redundant pattern — `merge_state_` is a function of the active-merge *set*.

This sharpens `S036UnderQuorumMerge.md` T-2 (which states the three END outcomes) to the namespace-local invariant: idempotence is what makes MS-1's "function of the multiset" actually a "function of the *active set*", which is the property MS-4 needs (the snapshot serializes the active set, and a restored chain that re-applies a replayed END converges to the same set).   ∎

**Defends against** `A_merge_replay` (`S036UnderQuorumMerge.md` §5(b)): a captured-and-replayed BEGIN/END cannot oscillate `merge_state_` — the second application is a no-op. Replay via a fresh tx envelope additionally requires a valid signing key + monotone nonce (FA-Apply-3). **Code witness.** `chain.cpp:1022-1034`. **Test witness.** `tools/test_merge_event_apply.sh`, `tools/test_merge_event_apply_edge.sh`.

### MS-3 — `m:` leaf injectivity + state-root sensitivity

**Statement.** The `m:` leaf encoding is injective over `merge_state_` (distinct maps yield distinct leaf sets) and disjoint from every other namespace; consequently, toggling any single field of any `MergePartnerInfo` — or adding/removing any refugee shard — changes `compute_state_root` except with probability `≤ 2⁻¹²⁸` under A2.

**Proof.** *Injectivity of the key.* The `m:` key is `"m:" ‖ shard_id_be4`, a fixed 6-byte string; the big-endian 4-byte encoding of `ShardId` (a `uint32_t`) is a bijection on the shard-id space, so distinct refugee shards map to distinct keys, and `std::map` key-uniqueness guarantees one leaf per shard. *Disjointness.* The 2-byte prefix `'m'` (0x6D) `':'` distinguishes `m:` from every other namespace prefix (`a:`/`s:`/`r:`/`d:`/`i:`/`b:`/`p:`/`k:` differ in byte 0; `k:c:` differs in bytes 0+2) — `S033StateRootNamespaceCoverage.md` T-2 namespace disjointness.

*Value-hash injectivity.* The value-hash preimage is `partner_id_u64_BE ‖ |ρ|_u64_BE ‖ ρ_bytes`. The explicit 8-byte length prefix on `ρ` makes the concatenation prefix-free in the region field: two preimages `(p, ρ)` and `(p', ρ')` are byte-equal iff `p = p'` and `ρ = ρ'`. So distinct `(partner_id, refugee_region)` pairs produce distinct preimages, and by A2 distinct preimages collide on `SHA256` with probability `≤ 2⁻¹²⁸`.

*Sensitivity.* Toggling `partner_id` or any byte of `refugee_region` (including its length) changes the preimage, hence the value-hash (except w.p. `≤ 2⁻¹²⁸`). Adding or removing a refugee shard adds or removes a leaf, changing the leaf *set*. In either case the sorted leaf set fed to `crypto::merkle_root` differs, and by MerkleTreeSoundness MT-1/MT-3 (root is a function of the leaf set; distinct leaf sets colliding on a root yield an extractable SHA-256 collision) the root differs except w.p. `≤ 2⁻¹²⁸`.   ∎

**Reduction target: A2.** **Code witness.** `chain.cpp:349-360`. **Test witness.** `tools/test_merge_state_determinism.sh` scenario 5 (toggling `partner_id` OR `refugee_region` changes `compute_state_root`); `tools/test_state_root_namespaces.sh` (exhaustive per-namespace mutation-changes-root, including `m:`).

### MS-4 — Snapshot round-trip identity for the `m:` namespace

**Statement.** For every reachable chain `C`, `serialize_state → restore_from_snapshot` preserves `merge_state_` byte-for-byte:

```
restore_from_snapshot(serialize_state(C)).merge_state_  ==  C.merge_state_
```

as `std::map` element-sets, hence the re-serialized `merge_state` JSON is byte-identical and the `m:`-namespace contribution to `compute_state_root(R(serialize_state(C)))` equals that of `C`.

**Proof.** `serialize_state` (§2.3) emits one JSON object `{shard_id, partner_id, refugee_region}` per map entry, iterating in `std::map` sorted-key order. Every field of `MergePartnerInfo` (`partner_id`, `refugee_region`) plus the key (`shard_id`) is emitted — this is the full field set, with no derived or lossy encoding (`partner_id` and `shard_id` are integers emitted verbatim; `refugee_region` is a UTF-8 string emitted verbatim, length implied by JSON string encoding). `restore_from_snapshot` (§2.3) reads each object back and `insert`s `{shard_id, {partner_id, refugee_region}}`. The read is the exact inverse of the emit: `m.value("shard_id", …)`, `m.value("partner_id", …)`, `m.value("refugee_region", …)` recover the three fields; `insert` re-establishes the map entry. Because `std::map` is determined by its element set (not insertion order), the restored map equals the source map regardless of JSON array order — and the array order is itself the deterministic sorted-key order, so even a byte-level JSON comparison matches.

Therefore the restored `merge_state_` equals `C.merge_state_` as element-sets. By MS-3 the `m:` leaf set is a deterministic function of `merge_state_`, so the restored chain emits the identical `m:` leaves, contributing the identical bytes to the sorted leaf vector. Re-serializing the restored chain emits the identical `merge_state` JSON array (SD-1 byte-identity specialized to the `m:` field). This is the `m:` row of `SnapshotDeterminismComposition.md`'s SD-1 + SD-2 statement; MS-4 is its namespace-local proof.

*Backward-compat corner.* A pre-R4 snapshot omits `merge_state`; the `if (snap.contains("merge_state"))` guard leaves `merge_state_` empty on restore, which matches `build_state_leaves` emitting no `m:` leaves for a no-merge chain. So the round trip is exact for both the populated and the absent-field cases, and the G2 gate (§2.4) passes for an honest snapshot of either.   ∎

**Code witness.** `chain.cpp:1645-1653` (emit), `chain.cpp:1801-1810` (read). **Test witness.** `tools/test_merge_state_determinism.sh` scenarios 1–4 (round-trip byte-identity, empty-array schema, distinct-fixture non-folding, deterministic sorted-by-ShardId order); `tools/test_under_quorum_merge.sh` (BEGIN inserts, END erases, snapshot persists end-to-end).

### MS-5 — Silent-drop detection (S-041-style, reduces to A2)

**Statement.** Suppose a future code change dropped `merge_state_` from `serialize_state` (emitting nothing for it) while `build_state_leaves` still emitted `m:` leaves — the S-037/S-041 bug class specialized to `m:`. Then for any reachable chain `C` with a non-empty `merge_state_`, `restore_from_snapshot(serialize_state(C))` would have an **empty** `merge_state_`, so its recomputed `state_root` would omit every `m:` leaf that the tail block's stored `state_root` committed to; the restore-side G2 gate (`chain.cpp:1893-1911`) would find `computed != claimed` and throw the `(S-033)` diagnostic. The regression is **loud**, not silent — provided a test populates `m:` and exercises the round trip.

**Proof.** By MS-3, a non-empty `merge_state_` produces at least one `m:` leaf in `build_state_leaves`, so the tail block's stored `state_root` (computed by the honest producer via the S-038 tentative-chain dry-run over a state that *included* `merge_state_`) commits to those leaves. Under the hypothetical drop, the restore loop has no `merge_state` field to read; `c.merge_state_` stays empty; `c.compute_state_root()` is taken over a leaf set missing every `m:` leaf. By MS-3's sensitivity result, the two leaf sets differ in the `m:` leaves, so the two roots differ except w.p. `≤ 2⁻¹²⁸` (A2). The G2 gate recomputes the root and compares against the stored `claimed` root; on mismatch it throws (`S012SnapshotStateRootGate.md` is the gate's tamper-resistance proof; here the "tamper" is the drop). Hence the drop cannot ship silently on a merge-active chain that is round-trip-tested.

This is the precise namespace-local instance of `SnapshotDeterminismComposition.md` SD-3 (every-namespace-contributes / no-silent-drop) for `π = m:`. The S-041 history (the `k:` merge-threshold sub-fields were in `build_state_leaves` but absent from `serialize_state`, detectable only on a non-default-threshold chain) is the canonical sibling instance; MS-5 confirms `m:` is **not** currently in that gap state — `serialize_state` emits the field (§2.3) — and pins the detection property that would catch any future regression.   ∎

**Reduction target: A2.** **Code witness.** `chain.cpp:1893-1911` (G2 throw site), `chain.cpp:349-360` (the `m:` leaves the gate commits to). **Test witness.** `tools/test_merge_state_determinism.sh` (populates `m:` AND exercises the round trip — the single test that would catch an `m:` drop); `determ test-snapshot-full-determinism` (all-namespace round trip, R40 sibling F1).

### MS-6 — Composition with R7 under-quorum-merge safety (FA9 / S-036)

**Statement.** MS-1..MS-5 compose with FA9's safety preservation and the S-036 admission gate so that a snapshot-bootstrapped node resumes mid-merge with committee-selection behavior byte-identical to a fully-replayed node, and the merge mechanism's FA1 + FA7 safety is unaffected by the snapshot boundary.

**Proof.** The committee-selection stress branch reads `merge_state_` only through the pure accessors `is_shard_merged` (`chain.hpp:337-342`) and `shards_absorbed_by` (`chain.hpp:346-353`), both of which iterate `merge_state_` and are therefore pure functions of the map. The producer side (`Node::check_if_selected`) and validator side (`BlockValidator::check_creator_selection` + `check_abort_certs`) call the identical accessors — no producer/validator divergence (FA9 §3.1). Compose:

- By MS-4, a snapshot-restored node holds a `merge_state_` byte-identical to the donor's at the snapshot height. By MS-1, every subsequent block applied on top mutates the map identically to a fully-replayed node. So `shards_absorbed_by(partner)` returns the identical refugee `(shard_id, region)` list on the restored node and the replayed node at every height ≥ the snapshot height.
- The stress branch extends the partner's eligible pool with `registry.eligible_in_region(refugee_region)` for each absorbed refugee. Identical `merge_state_` ⇒ identical extension ⇒ identical committee (FA8 T-8 committee-selection determinism). The restored node selects the same committee the replayed node does.
- FA9 T-9 (FA1 K-of-K safety preserved under merge) and T-9a (FA7 cross-shard atomicity preserved across BEGIN/END) depend only on the merged committee being deterministic and on the per-shard apply rule being unchanged — both hold for the restored node by the above. The S-036 admission gate (`S036UnderQuorumMerge.md` T-1) runs at validate time on every honest node, restored or replayed, identically.

Therefore the snapshot boundary is transparent to the R7 mechanism: a node that fast-bootstraps mid-merge is indistinguishable, in committee selection and safety, from one that replayed every block. The `m:`-namespace round-trip identity (MS-4) is exactly the property that makes "resume mid-merge correctly" (the `serialize_state` R4-Phase-2 comment at `chain.cpp:1643-1644`) a theorem rather than a hope.   ∎

**Composition boundary: A1** (the `MERGE_EVENT` rides on a K-of-K-signed block; a Byzantine producer that manufactures a divergent `merge_state_` is caught by the S-038 producer-wiring + G2 receiver gate, reducing forgery to Ed25519 EUF-CMA). **Code witness.** `chain.hpp:337-353` (accessors), `chain.cpp:1645-1653` + `1801-1810` (the round-trip that MS-4 proves). **Companion:** `UnderQuorumMerge.md` (FA9) T-9 / T-9a; `S036UnderQuorumMerge.md` T-1 / T-5.

---

## 4. Composition with the FA-track

### 4.1 FA9 (UnderQuorumMerge.md) — safety preservation across BEGIN/END

FA9 proves the merge mechanism preserves FA1 (per-shard K-of-K safety, bound `≤ 2⁻¹²⁸ · K`) and FA7 (cross-shard receipt atomicity) across BEGIN/END transitions, with the apply-time idempotency guard noted as a bonus (FA9 §3.3). MS-1 + MS-2 elevate that bonus to a stated theorem (apply-determinism + idempotence as a function of the active-merge set), and MS-4 + MS-6 extend FA9's "the map is persisted in snapshots so a snapshot-bootstrapped node observes identical state" (FA9 §1) from a sentence to a proof reducing to A2. FA9 T-9 / T-9a are invoked unchanged at MS-6.

### 4.2 S-036 (S036UnderQuorumMerge.md) — origination/admission soundness

`S036UnderQuorumMerge.md` covers the MERGE_BEGIN admission gate (T-1), MERGE_END idempotence (T-2, three outcomes), and the v2.11 closure path (T-5). MS-2 is the namespace-local restatement of T-2 sharpened to the active-set invariant; MS-1/MS-3/MS-4/MS-5 are the apply-determinism + state-root + snapshot surface that S-036 references only as cross-links (its §1.3 "State-root binding" + "Snapshot-serialized via serialize_state / restored via restore_from_snapshot"). This proof discharges those cross-links. The S-036 residual gap (a captured beacon claiming a past-but-false `evidence_window_start`, bounded to a single under-quorum-window attack until v2.11) is an *admission* concern orthogonal to the *namespace* soundness proved here: even a baseless-but-admitted MERGE_BEGIN produces a `merge_state_` that round-trips deterministically (MS-1..MS-5) and preserves FA1/FA7 (MS-6 / FA9 T-9).

### 4.3 S-033 / S-041 (S033StateRootNamespaceCoverage.md, SnapshotDeterminismComposition.md)

This document is the `m:` specialization of the 10-namespace coverage proofs. `S033StateRootNamespaceCoverage.md` T-1 lists `merge_state_ ↦ m:` as one coverage cell; MS-3 proves that cell's injectivity + sensitivity in full. `SnapshotDeterminismComposition.md` SD-1..SD-5 state the all-namespace joint round trip; MS-4 is the `m:` row of SD-1/SD-2 and MS-5 is the `m:` instance of SD-3's drop-detection corollary. The S-041 closure (the `k:` merge-threshold serialize gap) is the sibling regression that the SD-3 structural argument surfaced; MS-5 confirms `m:` is not in that gap state and pins the guard against a future `m:` regression. The three merge-policy constants `merge_threshold_blocks` / `revert_threshold_blocks` / `merge_grace_blocks` live in the **`k:`** namespace (`chain.cpp:392-394`), not `m:` — the `m:` namespace carries only the per-refugee `(partner_id, region)` runtime map. Their S-041 serialize-gap closure is therefore a `k:`-namespace matter; this proof depends on it only insofar as MS-6's committee-selection determinism reads `merge_grace_blocks` / `merge_threshold_blocks` from the (now round-tripped) `k:` scalars.

---

## 5. Adversary model

The proof's threat surfaces and the MS-theorem that bounds each:

**(a) `A_merge_replay` (event-replay).** Captures a finalized BEGIN/END and replays it. Bounded by **MS-2** (idempotence — the replay is a no-op on `merge_state_`) + FA-Apply-3 nonce monotonicity (a fresh envelope needs a valid key + monotone nonce). The map cannot be oscillated to perturb committee selection or inflate state-root recompute cost.

**(b) `A_self_merge` (malformed payload).** Crafts `partner_id == shard_id` or a non-canonical partner pairing. Bounded by the apply-time `partner_id == (shard_id+1) mod shard_count_` gate (§2.2 fact 2) + the validator-side `partner_id ≠ shard_id` reject (`S036UnderQuorumMerge.md` §5(c)). The malformed event charges fee + advances nonce but leaves `merge_state_` untouched, so it cannot pollute the `m:` namespace with self-referential leaves.

**(c) `A_snapshot_drop` (silent-namespace-drop, code-regression).** A future change drops `merge_state_` from `serialize_state` while leaving it in `build_state_leaves`. Bounded by **MS-5** + the G2 restore gate (reduces to A2): on any merge-active round-tripped chain the gate throws the `(S-033)` diagnostic. Detectable, not silent. Lock-in: `tools/test_merge_state_determinism.sh` + `determ test-snapshot-full-determinism`.

**(d) `A_snapshot_tamper` (Byzantine snapshot bytes).** A hostile operator ships a snapshot whose `merge_state` array doesn't match the tail block's stored `state_root`. Bounded by the G2 gate (`S012SnapshotStateRootGate.md` T-1..T-3, reduces to A2) + G1 head-hash gate + the two-adversary composition (tampering state *and* rewriting the tail `state_root` requires forging the committee's Ed25519 signature over `signing_bytes`, which binds `state_root` — defeated by A1). Out of MS-1..MS-5's honest-round-trip scope; cross-referenced, not re-proved.

**(e) `A_platform_divergence` (cross-node non-determinism).** A node on a different platform/allocator restores or applies a divergent `merge_state_`. Bounded by **MS-1** (apply-determinism — `std::map` is determined by its element set, not insertion order) + **MS-4** (round-trip identity) + S033 T-3 (deterministic leaf ordering — the Merkle re-sort erases emission-order). No platform/allocator/ABI dependence anywhere in the `m:` path.

---

## 6. Identified gaps and known limitations

### F-1 (No gap in the current `m:` serialize/restore surface)

Unlike the S-037 (`d:`) and S-041 (`k:` merge-thresholds) historical gaps, the `m:` namespace is **not** currently in a serialize-drop state: `serialize_state` emits `merge_state` (`chain.cpp:1645-1653`) and `restore_from_snapshot` reads it (`chain.cpp:1801-1810`), with the full `MergePartnerInfo` field set and a backward-compat `contains` guard. MS-4 + MS-5 confirm this and pin the regression guard. This is reported honestly as a *closed* surface, with the detection property (MS-5) standing as the lock-in against a future regression.

### F-2 (Admission-side gap is S-036's, not this namespace's)

The remaining open item on the merge mechanism is the S-036 captured-beacon `evidence_window_start` semantic gap (bounded to a single under-quorum-window attack per merge until v2.11, per `S036UnderQuorumMerge.md` T-5 / SECURITY.md §S-036). That is an *admission* concern: it governs whether a MERGE_BEGIN *should* have been admitted, not whether the resulting `merge_state_` is sound. MS-1..MS-6 hold regardless of admission legitimacy — a baseless-but-admitted merge still round-trips deterministically and preserves FA1/FA7. The two surfaces are orthogonal; this proof does not narrow the S-036 gap and does not need to.

### F-3 (`ShardId` width asymmetry in the `m:` value-hash, informational)

The `m:` **key** encodes `shard_id` as 4 big-endian bytes (`ShardId` is `uint32_t`), while the **value-hash** preimage encodes `partner_id` as 8 big-endian bytes (`static_cast<uint64_t>(info.partner_id)`, `chain.cpp:356`). Both are lossless for the `uint32_t` value space (the high 4 bytes of the `u64` partner encoding are always zero), so there is no collision or ambiguity — the widening is a fixed-width canonicalization choice, not a soundness issue. Recorded only so an external client computing `m:` leaves matches the implementation byte-for-byte: a verifier MUST use the 4-byte key width and the 8-byte partner-id value width as written, not a uniform width.

### F-4 (Rollback-snapshot vs JSON-snapshot are distinct surfaces)

`__ensure_merge_state` / `__snapshot.merge_state` (the A9 Phase-2 intra-apply rollback buffer, `chain.cpp:659-661` + `restore_state_snapshot` at `chain.cpp:609-610`) and the `serialize_state` / `restore_from_snapshot` JSON pathway (MS-4) are two different "snapshot" surfaces that share a name. The rollback buffer is a `std::optional<MergeStateMap>` consumed within a single failed `apply_transactions` call and is correctly **outside** the state-root universe `S` (S033 §4.1.5). MS-4 is exclusively about the JSON pathway. An auditor reading the source should not conflate the two; this note disambiguates them.

---

## 7. Cross-references

### SECURITY.md sections

- `docs/SECURITY.md` §S-033 — Merkle state commitment; the `m:` namespace is one of its ten leaf families. MS-3 proves the `m:` cell.
- `docs/SECURITY.md` §S-036 — Witness-window forgery (admission side); orthogonal to this namespace proof (F-2).
- `docs/SECURITY.md` §S-041 — `k:` merge-threshold serialize-gap closure; the sibling regression whose SD-3 detection argument MS-5 specializes to `m:`.

### Companion proofs

- `docs/proofs/UnderQuorumMerge.md` (FA9) — safety preservation across BEGIN/END (T-9 K-of-K, T-9a cross-shard atomicity, T-9.1 hysteresis); composed at MS-6.
- `docs/proofs/S036UnderQuorumMerge.md` — MERGE_BEGIN admission (T-1), MERGE_END idempotence (T-2), S-036 closure (T-5); MS-2 sharpens T-2 at the namespace layer.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — 10-namespace coverage completeness (T-1), disjointness (T-2), deterministic leaf ordering (T-3); MS-3/MS-4 invoke these.
- `docs/proofs/SnapshotDeterminismComposition.md` (SD-1..SD-5) — all-namespace joint round trip; MS-4 is the `m:` row of SD-1/SD-2, MS-5 the `m:` instance of SD-3.
- `docs/proofs/RegionalSharding.md` (FA8) — committee-selection determinism (T-8) that MS-6's stress-branch composition anchors.
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (root = function of leaf set), MT-3 (collision-resistance inheritance → A2); MS-3 invokes both.
- `docs/proofs/S012SnapshotStateRootGate.md` — the G2 restore gate's tamper-resistance (T-1..T-4); MS-5 reuses the gate, §5(d) cross-references its Byzantine-bytes coverage.
- `docs/proofs/Preliminaries.md` (F0) — §2.0 assumption labels; §2.1 A2 (the sole reduction target of MS-1..MS-5).

### Implementation sites

- `include/determ/chain/chain.hpp:328-353` — `MergePartnerInfo` + `MergeStateMap` + `merge_state()` / `is_shard_merged` / `shards_absorbed_by` accessors.
- `include/determ/chain/chain.hpp:598` — `merge_state_` member; `chain.hpp:692` — the `__snapshot.merge_state` rollback optional.
- `include/determ/chain/block.hpp:303-336` — `MergeEvent` wire format + canonical codec contract.
- `src/chain/chain.cpp:349-360` — `build_state_leaves` `m:` leaf emission (key `"m:"+shard_be4`, value `SHA256(partner_id ‖ region_len ‖ region_bytes)`).
- `src/chain/chain.cpp:1017-1039` — apply `MERGE_EVENT` case (BEGIN insert / END find+erase / idempotence / partner-gate).
- `src/chain/chain.cpp:659-661` + `598-614` — `__ensure_merge_state` lazy rollback capture + `restore_state_snapshot` rollback (F-4).
- `src/chain/chain.cpp:1645-1653` — `serialize_state` `merge_state` JSON emit (MS-4).
- `src/chain/chain.cpp:1801-1810` — `restore_from_snapshot` `merge_state` read (MS-4).
- `src/chain/chain.cpp:1893-1911` — G2 post-restore state-root gate (MS-5 throw site).

### Tests

- `tools/test_merge_state.sh` — Chain merge-state read API + R4 governance threshold setters (11 assertions). Pins MS-2's read-API surface + the in-memory map invariants.
- `tools/test_merge_state_determinism.sh` — `m:` serialize round-trip + deterministic sorted-by-ShardId eviction order + `m:`-namespace state_root binding (7 assertions, 5 scenarios). Lock-in for MS-3 + MS-4 + MS-5.
- `tools/test_merge_event_determinism.sh` — MERGE_EVENT wire + apply + state_root determinism. Lock-in for MS-1.
- `tools/test_merge_event_apply.sh` + `tools/test_merge_event_apply_edge.sh` — BEGIN/END apply + idempotence edge cases. Lock-in for MS-2.
- `tools/test_under_quorum_merge.sh` — integration: BEGIN inserts, END erases, snapshot persists end-to-end. Composite MS-1 + MS-2 + MS-4 + MS-6.
- `tools/operator_merge_state_audit.sh` — R7 operator audit: currently-merged pairs (sourced via a transient `snapshot create` since `status --json` does not expose `merge_state`), recent MERGE_EVENT classification, anomaly detection. The empirical operator-side anchor for the snapshot-as-merge-state-projection property that MS-4 proves.
- `determ test-snapshot-full-determinism` (R40 sibling F1) — all-namespace round trip; the all-namespace pin in which `m:` participates (MS-5 supplementary).

### Specifications

- `docs/PROTOCOL.md` §4.1.1 — canonical `m:` Merkle-leaf encoding (key/value table).
- `docs/PROTOCOL.md` §6.4 — R4 substrate (MergeEvent wire format + apply state machine + eligibility stress branch).
- `docs/PROTOCOL.md` §11 — snapshot wire format (the `merge_state` array field).

---

## 8. Status

**Analytic composition proof; surface shipped.** The `m:` merge-state namespace is shipped in the current branch across all five load-bearing sites (the `m:` leaf in `build_state_leaves`, the `MERGE_EVENT` apply case, the rollback capture, the `serialize_state` emit, the `restore_from_snapshot` read). This proof changes no code; it consolidates the namespace's apply-determinism + snapshot round-trip identity into one A2-reducing contract.

- **MS-1** (apply-determinism) — `merge_state_` is a deterministic function of the `MERGE_EVENT` multiset; `std::map` element-set determinism + pure decode + genesis-pinned gate.
- **MS-2** (BEGIN + END idempotence) — the map is a function of the active-merge *set*, not the apply trace; sharpens `S036UnderQuorumMerge.md` T-2.
- **MS-3** (`m:` injectivity + sensitivity) — reduces to A2; toggling any `MergePartnerInfo` field changes the root.
- **MS-4** (snapshot round-trip identity) — byte-identical `merge_state_` across `serialize → restore`; the `m:` row of SD-1/SD-2.
- **MS-5** (silent-drop detection) — reduces to A2; the G2 gate fires on any `m:` drop from `serialize_state`; the `m:` instance of SD-3.
- **MS-6** (composition with FA9 / S-036) — snapshot boundary transparent to R7 committee selection; FA1 + FA7 preserved.

**No theorem is open or partial.** The single recorded surface-level note is F-2: the S-036 admission-side captured-beacon gap (closes fully at v2.11) is orthogonal to this namespace's soundness — MS-1..MS-6 hold regardless of whether a given merge was admission-legitimate. F-1 reports the `m:` serialize/restore surface as currently closed (no S-037/S-041-class drop), with MS-5 standing as the regression guard. The reduction target throughout MS-1..MS-5 is A2; A1 enters only at the MS-6 composition boundary (the K-of-K-signed block the MERGE_EVENT rides on).
