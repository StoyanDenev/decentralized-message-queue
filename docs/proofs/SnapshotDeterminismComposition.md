# SnapshotDeterminismComposition — all-namespace snapshot round-trip determinism (SD-1..SD-5)

This document proves a single closed theorem that the per-namespace snapshot-restore correctness proofs do **not** state jointly: that the *entire* serialized chain state — every one of the ten `state_root` namespaces at once — survives a `serialize_state → restore_from_snapshot → serialize_state` round trip **byte-identically** and **state-root-identically**, for any reachable chain state. It is the comprehensive composition of the per-namespace restore-correctness results, and the structural guard against a future S-037-class regression in **any** namespace (a namespace that contributes to `compute_state_root` but is silently dropped from `serialize_state`).

The proof is a composition, not a fresh mechanical argument: it threads `SnapshotEquivalence.md` (FA-Apply-2, the core serialize-restore identity), `AppliedReceiptRestore.md` (FA-Apply-12, the `i:` namespace), `MerkleTreeSoundness.md` MT-1/MT-2/MT-3 (the tree-over-a-leaf-set determinism + collision-resistance properties), `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage completeness), and the paired S-037 / S-038 closures (the `d:` serialize-gap fix + the producer-side `body.state_root` wiring) — plus the **S-041** closure (the `k:` merge-threshold serialize-gap fix this very proof surfaced and the regression-guard property then closed) — into one all-namespace round-trip statement. The empirical pin is sibling F1's in-process unit `determ test-snapshot-full-determinism` (R40), which exercises every SD theorem on a fixture chain that populates all populatable namespaces.

**Cryptographic assumptions** (canonical labels, `Preliminaries.md` §2.0): **A1** = Ed25519 EUF-CMA (§2.2); **A2** = SHA-256 collision resistance (§2.1); **A3** = SHA-256 preimage / second-preimage resistance (§2.1); **A4** = CSPRNG uniform sampling (§2.3). This document's only cryptographic reduction is to **A2** (via MT-3). **Important namespace distinction:** the *"A1 unitary-supply invariant"* referenced in SD-5 is the apply-layer **accounting identity** (`live_total_supply + accumulated_slashed = expected_total`, `AccountStateInvariants.md` I-6 / `EconomicSoundness.md` T-12), which is **unrelated** to the cryptographic assumption A1 (Ed25519 EUF-CMA). The two share the letter "A1" by historical accident; this document states the SD-5 property in terms of the accounting identity and never invokes Ed25519. We do **not** use "FA3" for SHA-256 — in this proof series FA3 denotes `SelectiveAbort.md` (selective-abort resistance), an unrelated property.

**Companion documents.** `Preliminaries.md` (F0) §1.3 (hash notation), §2.0 (assumption labels), §2.1 (A2); `SnapshotEquivalence.md` (FA-Apply-2) for the serialize-restore identity T-S1, the apply-after-restore equivalence T-S2, the cross-namespace coverage T-S3, the idempotent-restore T-S4, and the determinism-of-serialize T-S6 that this document generalizes into a single all-namespace statement; `AppliedReceiptRestore.md` (FA-Apply-12) for the `i:`-namespace specialization; `MerkleTreeSoundness.md` for MT-1 (determinism / permutation-invariance of the tree over a leaf set), MT-2 (leaf/inner domain separation), MT-3 (collision-resistance inheritance); `S033StateRootNamespaceCoverage.md` for the 10-namespace coverage-completeness (T-1), namespace disjointness (T-2), and deterministic leaf ordering (T-3); `S012SnapshotStateRootGate.md` for the restore-side state-root gate that catches Byzantine snapshot bytes; `BlockchainStateIntegrity.md` for the four-surface load/produce/receive/steady composition; `docs/SECURITY.md` §S-012 / §S-033 / §S-037 / §S-038 / §S-041 for the closure narratives; `docs/PROTOCOL.md` §4.1.1 (the canonical `state_root` Merkle-leaf table) + §11 (the snapshot wire format).

---

## 1. Scope

### 1.1 What this proves

For any reachable chain state `C`, write `S := serialize_state(C)` for the snapshot JSON (`Chain::serialize_state`, `src/chain/chain.cpp:1541`) and `R(S) := restore_from_snapshot(S)` for the restored chain (`Chain::restore_from_snapshot`, `chain.cpp:1703`). This document proves five theorems jointly over **all ten** `state_root` namespaces:

- **SD-1** — **round-trip byte-identity**: `serialize_state(restore_from_snapshot(serialize_state(C))) == serialize_state(C)`, byte-for-byte.
- **SD-2** — **state_root preservation**: `compute_state_root(C) == compute_state_root(restore_from_snapshot(serialize_state(C)))`.
- **SD-3** — **every-namespace-contributes / no silent drop**: toggling any single field in **any** of the ten namespaces changes `compute_state_root`; consequently a namespace that is populated in `compute_state_root` but dropped from `serialize_state` makes SD-2 fail on restore (the S-037 bug class).
- **SD-4** — **idempotent double-restore**: `restore ∘ serialize ∘ restore ∘ serialize == restore ∘ serialize` (stable fixpoint).
- **SD-5** — **A1 accounting-invariance across restore**: the unitary-supply accounting identity holds identically pre- and post-restore (the supply-bearing namespaces `a:` / `s:` / `c:` round-trip exactly).

### 1.2 What this adds over the per-namespace proofs

The existing proofs each cover a *piece*:

| Proof | Covers |
|---|---|
| `SnapshotEquivalence.md` (FA-Apply-2) | The generic serialize-restore identity (T-S1) + apply-after-restore equivalence (T-S2) + cross-namespace coverage (T-S3, stated as "for each namespace prefix π"). |
| `AppliedReceiptRestore.md` (FA-Apply-12) | The `i:` namespace (cross-shard dedup-set) in isolation, with its FA7 no-double-credit consequence. |
| `S033StateRootNamespaceCoverage.md` | Namespace coverage-completeness (T-1) and disjointness (T-2) of the 10-namespace leaf set, + snapshot round-trip soundness (T-5). |
| `MerkleTreeSoundness.md` | The tree primitive: MT-1 (root is a function of the leaf set), MT-3 (root injective up to A2). |
| S-037 / S-038 (SECURITY.md) | The single-namespace `d:` serialize-gap closure (S-037) + the producer-side `body.state_root` population (S-038) that activates the restore-side gate. |

What none of them states is the **joint, all-namespace round-trip determinism** as one closed theorem: that the *full* serialized state (every namespace simultaneously) round-trips byte-identically **and** root-identically, with byte-identity (SD-1) stated as a property of the re-serialized JSON rather than only the restored maps, and with explicit idempotent double-restore (SD-4) and supply-invariance (SD-5) over the full state. FA-Apply-2's T-S3 asserts per-namespace coverage ("for each π, mutating π changes the restored root") but does not assert the *re-serialized JSON is byte-identical*; FA-Apply-2's T-S1 establishes restored-state equivalence `≡_S` but stops short of the re-serialization byte-equality that SD-1 needs as the empirical pin for a JSON-level diff test.

The practical value is a **structural regression guard**: SD-3 makes precise the property that broke under S-037 — a namespace whose leaves are in the `compute_state_root` preimage but whose contents are absent from `serialize_state` produces a restored chain whose recomputed root no longer matches the tail header, so the restore-side gate throws. SD-3 generalizes the S-037 lesson from the single `d:` namespace to *all ten*, and F1's `determ test-snapshot-full-determinism` exercises exactly this: populate every namespace, snapshot, restore, and assert (i) the re-serialized JSON is byte-identical and (ii) the recomputed root matches — an assertion that would have failed pre-S-037 for any DApp-active chain, and that will fail in the future if any namespace is dropped from `serialize_state` without a corresponding drop from `build_state_leaves`.

### 1.3 What this does not prove

The theorems target the honest serialize/restore round trip. They are conditional on `serialize_state` / `restore_from_snapshot` behaving as specified (an apply-correctness property). Byzantine snapshot *bytes* — a hostile operator or MITM shipping a self-inconsistent snapshot — are out of scope here; they are caught by the restore-side S-033 state-root gate (`S012SnapshotStateRootGate.md` T-1/T-2/T-3, the G2 gate at `chain.cpp:1893-1911`) and the head-hash gate (G1 at `chain.cpp:1855-1862`). §5 makes the boundary precise and cross-references those defenses. This document also does not re-prove the Merkle primitive (that is `MerkleTreeSoundness.md`), the per-namespace apply correctness (the `FA-Apply-*` series), or the consensus-layer question of whether two divergent block bodies can both be signed (`S030-D2-Analysis.md`, `F2-SPEC.md`).

---

## 2. Model

### 2.1 The ten namespaces and their serialized representation

The `state_root` is `merkle_root(build_state_leaves())` (`Chain::compute_state_root`, `chain.cpp:413-415`). `build_state_leaves` (`chain.cpp:267-411`) emits one `MerkleLeaf` `(key, value_hash)` per live state entry across **ten** namespaces, each with a distinct ASCII key prefix. The following table is read directly off `build_state_leaves` (leaf source + key encoding) and `serialize_state` (JSON shape) and `restore_from_snapshot` (the inverse loop). The `c:` namespace is the five A1 supply counters; they are emitted via the `const_leaf` helper with names that begin `c:`, so their leaf keys are `"k:" + "c:..."` (i.e. `k:c:genesis_total`, …) — physically inside the `k:` prefix but semantically a distinct namespace per `PROTOCOL.md §4.1.1` and `S033StateRootNamespaceCoverage.md` T-2.

| # | Prefix | Backing container (`chain.hpp`) | Leaf value-hash inputs (`build_state_leaves`) | Snapshot JSON field (`serialize_state`) | Restore loop (`restore_from_snapshot`) |
|---|---|---|---|---|---|
| 1 | `a:` | `std::map<std::string, AccountState> accounts_` | `(balance, next_nonce)` (lines 285-289) | `accounts[] = {domain, balance, next_nonce}` (1551-1557) | `c.accounts_[domain] = {balance, next_nonce}` (1748-1755) |
| 2 | `s:` | `std::map<std::string, StakeEntry> stakes_` | `(locked, unlock_height)` (292-296) | `stakes[] = {domain, locked, unlock_height}` (1561-1567) | `c.stakes_[domain] = {locked, unlock_height}` (1756-1763) |
| 3 | `r:` | `std::map<std::string, RegistryEntry> registrants_` | `(ed_pub, registered_at, active_from, inactive_from, region)` (299-307) | `registrants[] = {domain, ed_pub, registered_at, active_from, inactive_from, region}` (1571-1582) | `c.registrants_[domain] = {…}` (1764-1777) |
| 4 | `d:` | `std::map<std::string, DAppEntry> dapp_registry_` | `(service_pubkey, registered_at, active_from, inactive_from, endpoint_url, topics[], retention, metadata)` (312-329) | `dapp_registry[] = {domain, service_pubkey, endpoint_url, topics, retention, metadata, registered_at, active_from, inactive_from}` (1654-1668, **S-037**) | `c.dapp_registry_[domain] = {…}` (1818-1834, **S-037**) |
| 5 | `i:` | `std::set<std::pair<ShardId,Hash>> applied_inbound_receipts_` | presence marker `SHA256(0x01)`; key = `"i:" ‖ src_be8 ‖ tx_hash` (332-340) | `applied_inbound_receipts[] = {src_shard, tx_hash}` (1586-1591) | `c.applied_inbound_receipts_.insert({src, tx_hash})` (1778-1785) |
| 6 | `b:` | `std::map<std::string, AbortRecord> abort_records_` | `(count, last_block)` (343-347) | `abort_records[] = {domain, count, last_block}` (1623-1629, **S-032**) | `c.abort_records_[domain] = {count, last_block}` (1801-1809) |
| 7 | `m:` | `std::map<ShardId, MergePartnerInfo> merge_state_` | `(partner_id, refugee_region)`; key = `"m:" ‖ shard_be4` (350-359) | `merge_state[] = {shard_id, partner_id, refugee_region}` (1638-1644) | `c.merge_state_.insert({shard, {partner_id, refugee_region}})` (1786-1795) |
| 8 | `p:` | `std::map<uint64_t, vector<pair<string,vector<u8>>>> pending_param_changes_` | `(name, value)` per entry; key = `"p:" ‖ eff_be8 ‖ idx_be4` (362-377) | `pending_param_changes[] = {effective_height, entries:[{name, value}]}` (1672-1684) | `c.pending_param_changes_[eff].emplace_back(name, value)` (1835-1846) |
| 9 | `k:` | 13 genesis-pinned scalars (`block_subsidy_`, `subsidy_pool_initial_`, `subsidy_mode_`, `lottery_jackpot_multiplier_`, `min_stake_`, `suspension_slash_`, `unstake_delay_`, `merge_threshold_blocks_`, `revert_threshold_blocks_`, `merge_grace_blocks_`, `shard_count_`, `my_shard_id_`, `shard_salt_`) | one leaf per scalar via `const_leaf` / explicit `shard_salt` leaf (380-402) | individual scalar fields (1597-1616; the three merge thresholds **S-041**) | individual `snap.value("name", default)` reads (1712-1730; the three merge thresholds **S-041**, defaults 100/200/10) |
| 10 | `c:` | 5 A1 supply counters (`genesis_total_`, `accumulated_subsidy_`, `accumulated_slashed_`, `accumulated_inbound_`, `accumulated_outbound_`) | one leaf per counter via `const_leaf("c:…")` (404-408) | individual scalar fields (1614-1618) | individual `snap.value("name", default)` reads (1724-1735 + back-solve at 1864-1877) |

Two facts to record precisely from the source:

1. **Containers 1–8 are ordered associative containers** (`std::map` or `std::set`). C++ guarantees their iteration is in sorted-key order, deterministically. `serialize_state` iterates each in that canonical order; the JSON array it emits is therefore a deterministic function of the container contents alone (independent of any insertion history). The restore loops re-install each container via `c.map_[key] = value` or `c.set_.insert(...)`, which converge on the same final container regardless of array order — `std::map`/`std::set` are determined by their element set, not by insert order.

2. **The `k:` scalar values include `merge_threshold_blocks_`, `revert_threshold_blocks_`, `merge_grace_blocks_`** as `state_root` leaves (lines 392-394). **These are now emitted by `serialize_state` and read back by `restore_from_snapshot` (S-041, closed in the same session this proof was authored).** When this document was first drafted they were a *latent S-037-class gap for the `k:` merge-threshold sub-fields*: `serialize_state` did not emit them, so on restore they silently defaulted to the `GenesisConfig` defaults (`100 / 200 / 10`, `chain.hpp:592-594`). For a chain whose merge thresholds equalled the defaults the round trip was exact; for a chain whose thresholds were set to non-default values, the restored `k:` leaves differed and SD-2 failed under the restore-side gate. **The fix** adds the three `snap[...]` emissions (after `unstake_delay`) and the symmetric `snap.value("…", default)` reads (genesis-default fallbacks preserve backward-compat with pre-fix snapshots). The structural SD-3 result (§5) is what made this gap *detectable* rather than silent — exactly the regression-guard property the brief asks for, and the property that surfaced the bug from this proof. Both `test-snapshot-roundtrip` (case #10b) and `test-snapshot-full-determinism` now carry **non-default** merge thresholds (137 / 311 / 29) through the JSON round-trip and assert state_root identity, so the closure is regression-guarded across both the single-namespace and all-ten-namespace fixtures.

### 2.2 The snapshot and restore functions

```
S := serialize_state(C, header_count)   : Chain × u32 → SnapshotJSON     (chain.cpp:1541)
R(S) := restore_from_snapshot(S)          : SnapshotJSON → Chain            (chain.cpp:1703)
```

`serialize_state` additionally emits a **version envelope** (`version = 1`, `block_index`, `head_hash`) and a **tail-header window** (`headers[]`, the last `header_count` blocks in full Block JSON, preserving each block's S-033 `state_root` field). `restore_from_snapshot` enforces two gates that this document's honest round trip satisfies by construction (and that catch Byzantine bytes, §5):

- **G1** — head-hash match (`chain.cpp:1855-1862`): `compute_hash(loaded_tail) == snap.head_hash`.
- **G2** — state-root match (`chain.cpp:1893-1911`): `compute_state_root(loaded_state) == loaded_tail.state_root`, skipped iff the tail's `state_root` is the all-zero sentinel (the pre-S-038 backward-compat path).

A "reachable chain state" `C` is one obtained by replaying genesis followed by zero or more `apply_transactions`-valid blocks. A "post-S-038 chain" is one whose tail block was produced by a post-S-038 `Node::try_finalize_round` (`node.cpp:1024-1113`), so its tail carries a non-zero `state_root` and G2 is active.

### 2.3 Equivalence relations

Two notions of "the same":

- **Byte-identity of snapshots** (`S ≡_b S'`): the two `SnapshotJSON` objects serialize to identical byte strings. Because `serialize_state` builds the object by manual top-level key insertion and nlohmann emits keys in insertion order with a deterministic value encoding, `S ≡_b S'` iff every field is equal value-for-value in the same order. SD-1 is a statement of `≡_b`.
- **State-equivalence of chains** (`C ≡_S C'`, `SnapshotEquivalence.md` §1.2): the eight backing containers are `==`-equal, all `k:` scalars coincide, all `c:` counters coincide, and `compute_state_root(C) == compute_state_root(C')`. This is the relation FA-Apply-2 T-S1 establishes for `R(serialize(C)) ≡_S C`.

`≡_b` is the stronger, observable-at-the-wire relation that SD-1 targets; `≡_S` is the chain-internal relation FA-Apply-2 provides. §3 derives `≡_b` from `≡_S` plus determinism of `serialize_state`.

---

## 3. Theorems

Notation: fix a reachable post-S-038 chain `C` and a header window `header_count ≥ 1`. Write `S = serialize_state(C)`, `C₁ = R(S) = restore_from_snapshot(S)`, `S₂ = serialize_state(C₁)`, `C₂ = R(S₂)`.

### SD-1 — Round-trip byte-identity

**Statement.** For every reachable chain `C` and every `header_count ≥ 1`,

```
serialize_state(restore_from_snapshot(serialize_state(C, hc)), hc) == serialize_state(C, hc)
```

byte-for-byte (`S₂ ≡_b S`).

**Proof.** By FA-Apply-2 **T-S1**, `C₁ = R(S) ≡_S C`: the restored chain's eight backing containers, `k:` scalars, and `c:` counters all coincide with `C`'s (T-S1 conditions 1–4; the proof is the per-namespace coverage lemmas L-S0 + L-S1 of FA-Apply-2 §2, which enumerate that every field consumed by `build_state_leaves` is both emitted by `serialize_state` and re-read by `restore_from_snapshot`). The tail-header window also coincides: `serialize_state` emits `headers[]` via `Block::to_json` and `restore_from_snapshot` reloads them via `Block::from_json` (`chain.cpp:1847-1851`), and `Block::to_json ∘ Block::from_json` is the identity on the block's fields (deterministic round trip — the FA-Apply-2 G1 argument).

Now apply **determinism of `serialize_state`** (FA-Apply-2 **T-S6**): `serialize_state` performs no I/O, no clock read, no randomness, no peer query; every emitted field is a pure function of the chain's state computed via deterministic helpers (`to_hex`, `compute_hash`, `Block::to_json`), and every container is iterated in deterministic sorted-key order (§2.1 fact 1). Hence `serialize_state` is a pure function of `(chain state, header_count)`.

Compose: `serialize_state` is a function of the equivalence-class data that `≡_S` pins, **plus** the tail-header window (which also coincides). Concretely, every field `serialize_state` emits is one of:

- the version envelope — `version` is the literal `1` on both sides; `block_index` and `head_hash` are functions of `blocks_.back()`, which coincides because `C₁`'s tail block round-tripped from `C`'s tail block JSON;
- one of the eight container arrays — equal because the containers are `==`-equal under `≡_S` and emitted in the same canonical order;
- one of the `k:` / `c:` scalar fields — equal because the scalars coincide under `≡_S`;
- the `headers[]` window — equal because each block round-trips identically and the window length `header_count` is the same argument on both calls.

Every field of `S₂` therefore equals the corresponding field of `S`, in the same insertion order, so `S₂ ≡_b S`. ∎

**Code witness.** `chain.cpp:1541` (`serialize_state`), `chain.cpp:1703` (`restore_from_snapshot`), `chain.cpp:267` (`build_state_leaves`).

**Test witness.** F1's `determ test-snapshot-full-determinism` (R40) — the byte-identity assertion: populate all namespaces, take `S`, restore to `C₁`, re-serialize to `S₂`, assert `S₂.dump() == S.dump()` (full JSON string equality). Existing supplementary witnesses: `tools/test_snapshot_roundtrip.sh` (the `serialize → restore → compute_state_root` round trip across 5 blocks) + `determ test-state-root-determinism` (chain reload byte-identity of `state_root`, `src/main.cpp:31387`).

### SD-2 — State_root preservation

**Statement.** For every reachable chain `C`,

```
compute_state_root(C) == compute_state_root(restore_from_snapshot(serialize_state(C)))
```

**Proof.** Two routes, both valid; we give the direct one and note the corollary route.

*Direct.* By SD-1's intermediate result, `C₁ = R(S) ≡_S C`, and the fifth condition of `≡_S` (FA-Apply-2 §1.2 condition 5) is precisely `compute_state_root(C₁) == compute_state_root(C)`. So the equality holds.

*Via the leaf set (the brief's route, making the MT-1 dependency explicit).* `compute_state_root(X) = merkle_root(build_state_leaves(X))`. `build_state_leaves` is a deterministic function of the eight backing containers + the `k:` scalars + the `c:` counters (§2.1: it iterates each container in sorted order and hashes fixed-width / length-prefixed encodings of each field). By `≡_S` (conditions 1–4) those inputs coincide between `C` and `C₁`, so `build_state_leaves(C) = build_state_leaves(C₁)` **as a multiset of `(key, value_hash)` pairs** — every namespace produces the identical leaf set. By **MerkleTreeSoundness MT-1** (determinism / permutation-invariance: `merkle_root` is a pure function of the leaf *set*, via its internal key-sort), identical leaf sets yield identical roots. Hence `compute_state_root(C) == compute_state_root(C₁)`. ∎

This is the S-033 cross-node determinism property *at the snapshot boundary*: the same fact that makes two honest nodes agree on `state_root` (`MerkleTreeSoundness.md` §5.2 corollary) makes a snapshot-restored node agree with its donor. The restore-side G2 gate (`chain.cpp:1893-1911`) is the runtime check of exactly this equality against the tail header's stored root; SD-2 is why an honest snapshot passes G2.

**Code witness.** `chain.cpp:413-415` (`compute_state_root`), `chain.cpp:1893-1911` (G2 gate).

**Test witness.** F1's `determ test-snapshot-full-determinism` — the root-match assertion: `compute_state_root(C₁) == compute_state_root(C)` after restoring the all-namespace fixture. Supplementary: `tools/test_snapshot_roundtrip.sh`, `tools/test_dapp_snapshot.sh` (the `d:`-active joint surface), `tools/test_snapshot_bootstrap.sh` (3-node donor + fresh receiver end-to-end).

### SD-3 — Every-namespace-contributes / no silent drop

**Statement.** For each namespace `π ∈ {a:, s:, r:, d:, i:, b:, m:, p:, k:, c:}`, toggling any single field that contributes a leaf in `π` changes `compute_state_root` (except with probability `≤ 2⁻¹²⁸`). Consequently, if a namespace `π` were populated in `compute_state_root` (via `build_state_leaves`) but **dropped** from `serialize_state`, then for any chain with a non-empty `π`, the restored chain would have a different `π`-leaf set and `compute_state_root(R(serialize(C))) ≠ compute_state_root(C)` — making SD-2 fail and the restore-side G2 gate throw. This is the S-037 bug class, generalized to all ten namespaces.

**Proof.** *Sensitivity.* `build_state_leaves` emits at least one leaf per non-empty namespace, and the leaf-key encoding is **injective per namespace and disjoint across namespaces**: each key begins with the namespace's distinct ASCII prefix (`S033StateRootNamespaceCoverage.md` T-2, namespace disjointness via the prefix bytes), and within a namespace the key is the prefix followed by a deterministic, unambiguous encoding of the source key (domain string, or `src_be8 ‖ tx_hash`, or `shard_be4`, or `eff_be8 ‖ idx_be4`, or the fixed constant/counter name). Toggling any field either (a) changes a leaf's `value_hash` (a balance, a counter, a `registered_at`, …) or (b) adds/removes a leaf (a new account, a new receipt, …). In case (a) the new `value_hash` differs from the old except with SHA-256 collision probability; in case (b) the leaf multiset changes. Either way the leaf set differs, and by **MerkleTreeSoundness MT-3** (collision-resistance inheritance: distinct leaf sets colliding on a root yield an extractable SHA-256 collision), the root differs except with probability `≤ 2⁻¹²⁸` under **A2**. **MT-2** (leaf/inner domain separation, `0x00` vs `0x01` prefix) additionally rules out the leaf-vs-inner-node confusion that could otherwise let a structural change preserve the root. This is FA-Apply-2 **T-S3** stated per namespace; we restate it here as the basis for the drop-detection corollary.

*Drop-detection corollary.* Suppose, hypothetically, a code change drops namespace `π` from `serialize_state` (emits nothing for it) while `build_state_leaves` still emits `π`-leaves — exactly the S-037 situation for `d:` before its closure. Take any reachable `C` with a non-empty `π`. Then `R(serialize(C))` has an **empty** `π` (the restore loop has nothing to read; the missing-field default leaves the container empty, `chain.cpp` `value(key, default)` semantics). So `build_state_leaves(R(serialize(C)))` is missing every `π`-leaf that `build_state_leaves(C)` had. By the sensitivity result, the two roots differ (the leaf sets differ in the `π` leaves), so `compute_state_root(R(serialize(C))) ≠ compute_state_root(C)`: **SD-2 fails**. Operationally, the restore-side G2 gate recomputes the root over the dropped-`π` state and compares it against the tail header's stored root (which *did* commit to `π`), finds a mismatch, and throws the `"snapshot state_root mismatch … (S-033)"` diagnostic (`chain.cpp:1898-1908`). The regression is therefore **loud**, not silent — provided a test populates `π` and exercises the round trip. ∎

This is the precise statement of the guard the brief asks for. The S-037 history is the canonical instance: pre-closure, `dapp_registry_` contributed `d:`-leaves to `compute_state_root` but `serialize_state` emitted no `dapp_registry` field, so any DApp-active chain failed G2 on restore. The bug shipped silently only because no single test populated `d:` *and* exercised the snapshot round trip (`test_snapshot_bootstrap.sh` and `test_dapp_*.sh` were disjoint). F1's `determ test-snapshot-full-determinism` closes that gap permanently by populating every namespace it can and asserting both SD-1 byte-identity and SD-2 root-match in one fixture — so a future drop of *any* namespace from `serialize_state` (without a matching drop from `build_state_leaves`) fails the test.

**Code witness.** `chain.cpp:267-411` (`build_state_leaves`, the 10-namespace leaf construction), `chain.cpp:1893-1911` (G2 gate that fires on a dropped namespace).

**Test witness.** F1's `determ test-snapshot-full-determinism` — the toggle-changes-root assertions (one per populatable namespace: mutate a field, assert the root diverges from baseline) and the all-namespace round-trip assertion. Supplementary: `determ test-state-root-namespaces` (`src/main.cpp:20803`, exhaustive per-namespace mutation-changes-root) + FA-Apply-2 T-S3's `test_state_root_namespaces.sh`.

### SD-4 — Idempotent double-restore

**Statement.** For every reachable chain `C` and every `header_count`,

```
restore ∘ serialize ∘ restore ∘ serialize (C)  ≡_S  restore ∘ serialize (C)
```

i.e. `C₂ ≡_S C₁` (re-serializing a restored chain and restoring again reproduces the same chain). Equivalently, `R ∘ serialize` is a fixpoint up to `≡_S`: applying it once and applying it twice land on the same state-equivalence class.

**Proof.** `C₁ = R(serialize(C))`. By SD-1, `S₂ = serialize(C₁) ≡_b serialize(C) = S`: the two snapshots are byte-identical. A byte-identical input to the deterministic function `restore_from_snapshot` yields a byte-identical output (`restore_from_snapshot` is a pure function of its JSON argument — it reads only `snap`, performs no I/O beyond the in-memory parse, and the G1/G2 gates are deterministic checks that both pass identically). Hence `C₂ = R(S₂) = R(S) = C₁` (literal equality of the produced `Chain`, which implies `≡_S`).

Alternatively, without invoking SD-1's byte-identity: by FA-Apply-2 **T-S4** (idempotent restore) applied to `C₁`, `R(serialize(C₁)) ≡_S C₁`, which is `C₂ ≡_S C₁` directly. The two routes agree; SD-4 is the all-namespace restatement of T-S4 with the byte-identity strengthening from SD-1. ∎

The fixpoint reaches in **one** restore: `C₁` is already a fully-restored chain, so serializing and restoring it again is a no-op up to `≡_S`. There is no "settling" over multiple iterations — the round trip is idempotent from the first application.

**Code witness.** Same as SD-1 (round-trip identity composes with itself); FA-Apply-2 T-S4.

**Test witness.** F1's `determ test-snapshot-full-determinism` — the double-restore assertion: `R(serialize(R(serialize(C))))` compared to `R(serialize(C))` for byte-identical re-serialization and root-match. Supplementary: the determinism assertion in `tools/test_snapshot_roundtrip.sh` ("same snapshot → same restored state_root").

### SD-5 — A1 accounting-invariance across restore

**Statement.** The apply-layer unitary-supply accounting identity (`AccountStateInvariants.md` I-6 / `EconomicSoundness.md` T-12),

```
Σ_{d ∈ accounts_} balance[d]  +  Σ_{d ∈ stakes_} locked[d]
   == genesis_total_ + accumulated_subsidy_ + accumulated_inbound_
                     − accumulated_slashed_ − accumulated_outbound_,
```

holds with **identical** left- and right-hand values on `C` and on `C₁ = R(serialize(C))`. Equivalently, the supply-bearing namespaces `a:` (account balances), `s:` (stake locked), and `c:` (the five counters) round-trip exactly, so the unitary-supply check (`Chain::live_total_supply() == Chain::expected_total()`, asserted at `chain.cpp:1397-1419`) yields the same verdict pre- and post-restore.

**Proof.** The identity's left-hand side, `live_total_supply(X) = Σ balance + Σ locked`, is a fold over the `a:` namespace (`accounts_[d].balance`) and the `s:` namespace (`stakes_[d].locked`). The right-hand side, `expected_total(X)`, is the signed sum of the five `c:` counters. By SD-1's intermediate `≡_S` result (conditions 1–4), all three namespaces coincide between `C` and `C₁`:

- `a:` — `C₁.accounts_ == C.accounts_` (T-S1 condition 1), so every `balance[d]` is preserved; the LHS first term is equal.
- `s:` — `C₁.stakes_ == C.stakes_` (T-S1 condition 2), so every `locked[d]` is preserved; the LHS second term is equal.
- `c:` — the five counters coincide (T-S1 condition 4): `genesis_total_`, `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_slashed_`, `accumulated_outbound_` are each persisted by `serialize_state` (lines 1614-1618) and re-read by `restore_from_snapshot` (lines 1724-1735). [Edge case — legacy snapshots without `genesis_total`: `restore_from_snapshot` back-solves `genesis_total_ = live + deltas_neg − deltas_pos` (lines 1864-1877) so the identity is satisfied at restore by construction. For a *post-S-038* snapshot the field is always present, so the explicit value is used and the round trip is exact. Either way the RHS equals the LHS post-restore.]

Therefore both sides of the identity take the same numeric value on `C` and `C₁`, and in particular the equality holds on `C₁` iff it held on `C`. Since `C` is reachable, the identity held on `C` (it is an apply-path invariant, `AccountStateInvariants.md` T-A6), so it holds on `C₁`. The first post-restore block's apply-tail A1 assertion (`chain.cpp:1397-1419`) thus starts from a satisfied invariant — which is exactly why the A1 counters are persisted (the `serialize_state` comment at lines 1610-1613 states this: without them `expected_total()` would be 0 on a restored chain and the first apply would trip the invariant). ∎

SD-5 is the supply-conservation companion to SD-2: SD-2 says the *cryptographic commitment* round-trips; SD-5 says the *accounting identity* underlying the `a:`/`s:`/`c:` namespaces round-trips, so a snapshot-bootstrapped node can keep asserting unitary supply from its first post-restore block.

**Code witness.** `chain.cpp:548` (`live_total_supply`), `expected_total` (the five-counter sum), `chain.cpp:1397-1419` (the A1 assertion), `chain.cpp:1610-1618` (counter persistence), `chain.cpp:1724-1735` + `1864-1877` (counter restore + legacy back-solve).

**Test witness.** F1's `determ test-snapshot-full-determinism` — the supply-invariance assertion: `live_total_supply(C₁) == expected_total(C₁)` and both equal the donor's values after restoring the all-namespace fixture. Supplementary: `tools/test_supply_lifecycle.sh` (the A1 closing equality across every mutation type) + `tools/operator_supply_check.sh` (re-runs the A1 check from snapshot data).

---

## 4. Mapping to F1's test

Sibling F1's in-process unit `determ test-snapshot-full-determinism` (R40) is the empirical pin for the five SD theorems. The test builds a fixture chain that populates every namespace it can in-process, then runs the round trip and asserts each SD property. The mapping:

| SD theorem | Property | F1 assertion (in `determ test-snapshot-full-determinism`) |
|---|---|---|
| **SD-1** | round-trip byte-identity | `serialize_state(restore_from_snapshot(serialize_state(C)))` dumps to the **same JSON string** as `serialize_state(C)` (full `dump()` equality, not just root). |
| **SD-2** | state_root preservation | `compute_state_root(restore_from_snapshot(serialize_state(C))) == compute_state_root(C)`. |
| **SD-3** | toggle-changes-root / no silent drop | for each populatable namespace, mutating one field and recomputing yields a root `≠` baseline; the all-namespace fixture's round-trip root matches (so no namespace was silently dropped). |
| **SD-4** | idempotent double-restore | `restore∘serialize∘restore∘serialize(C)` byte-identical (and root-identical) to `restore∘serialize(C)`. |
| **SD-5** | A1 supply invariance | `live_total_supply == expected_total` holds post-restore, equal to the donor's values. |

The test is the regression guard SD-3 describes: it is the *single* test that populates all namespaces **and** exercises the snapshot round trip, so it catches any future S-037-class drop of a namespace from `serialize_state`. Per the brief, this document treats F1's test as the canonical pin; the existing `determ test-state-root-determinism`, `determ test-state-root-namespaces`, `tools/test_snapshot_roundtrip.sh`, `tools/test_dapp_snapshot.sh`, and `tools/test_snapshot_bootstrap.sh` are supplementary witnesses that each cover a subset of the SD properties (chain-reload determinism, per-namespace sensitivity, single-round-trip root-match, the `d:`-active joint surface, and end-to-end bootstrap respectively).

---

## 5. Limitations and scope

**Conditional on honest serialize/restore.** The SD theorems are apply-correctness properties: they assume `serialize_state` and `restore_from_snapshot` execute as written on an honestly-produced chain. They are **not** a defense against Byzantine snapshot bytes — a hostile operator or MITM peer that fabricates a self-inconsistent snapshot. Those are caught by:

- the **restore-side S-033 state-root gate** (G2, `chain.cpp:1893-1911`): any tamper that produces a state whose recomputed root differs from the tail header's stored root throws (`S012SnapshotStateRootGate.md` T-1 tamper-at-rest, T-2 1-bit mutation in any namespace, T-3 tamper-in-transit; reduces to **A2**);
- the **head-hash gate** (G1, `chain.cpp:1855-1862`): a tampered tail block fails the `compute_hash` recompute;
- the **two-adversary composition** (`S012SnapshotStateRootGate.md` T-4): an adversary that tampers state *and* rewrites the tail header's `state_root` to match must forge the committee's Ed25519 signature over the tail block's `signing_bytes` (which bind `state_root`) — defeated by **A1** (Ed25519 EUF-CMA). Note this is the *cryptographic* A1, distinct from the SD-5 *accounting* A1.

Provenance (a malicious peer supplying a self-consistent snapshot of a chain it forged from a fork point) is **not** authenticated by G1/G2; operator policy (cross-check `head_hash` against a trusted source) is the current defense, and signed snapshot envelopes are a tracked future item (`SnapshotEquivalence.md` §5, `docs/V2-DESIGN.md`).

**Namespace population in F1's in-process test.** F1's test populates the namespaces reachable from an in-process fixture chain. If F1's report indicates a namespace it could not populate in-process (e.g. `m:` merge-state requires a live MERGE_EVENT apply, or `p:` pending-param-changes requires a staged PARAM_CHANGE), the SD theorems are still stated **structurally over all ten namespaces** via SD-3's sensitivity result + the per-namespace coverage of FA-Apply-2 (L-S0/L-S1) and FA-Apply-12 (the `i:` specialization). The empirical pin is over the populated set; the analytic statement is over the full set. The `k:` merge-threshold sub-fields (`merge_threshold_blocks_`, `revert_threshold_blocks_`, `merge_grace_blocks_`) were a latent S-037-class gap when this proof was first drafted (§2.1 fact 2): they contribute `k:`-leaves to `compute_state_root` but were not emitted as JSON fields, so a chain with non-default merge thresholds failed SD-2 on restore. **This is now closed (S-041, same session):** `serialize_state` emits the three scalars and `restore_from_snapshot` reads them with genesis-default fallbacks. SD-3 is precisely what made the gap *detectable* rather than silent — and F1's `test-snapshot-full-determinism` plus `test-snapshot-roundtrip` (case #10b) now both set **non-default** thresholds (137 / 311 / 29) and exercise the round trip, so SD-2 is empirically pinned over a non-default `k:` configuration. The gap that this proof's structural SD-3 result surfaced is the gap that SD-3's regression-guard property then closed.

**Not proved here.** The Merkle primitive itself (MT-1/MT-2/MT-3/MT-4/MT-5 — `MerkleTreeSoundness.md`); per-namespace apply correctness (the `FA-Apply-*` series); the consensus-layer divergent-body question (`S030-D2-Analysis.md`, `F2-SPEC.md`); snapshot persistence durability (the atomic write-and-rename path, `S031ConcurrencyComposition.md` T-5); the cross-shard no-double-credit semantics that the `i:` round-trip preserves (`CrossShardReceipts.md` FA7 / `AppliedReceiptRestore.md` FA-Apply-12).

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `src/chain/chain.cpp:1541` | `Chain::serialize_state` — the `S = serialize(C)` function; the 10-namespace JSON emit. |
| `src/chain/chain.cpp:1703` | `Chain::restore_from_snapshot` — the `R(S)` function; the inverse loops + G1/G2 gates. |
| `src/chain/chain.cpp:267-411` | `Chain::build_state_leaves` — the 10-namespace Merkle-leaf construction (SD-2/SD-3 leaf set). |
| `src/chain/chain.cpp:413-415` | `Chain::compute_state_root` = `merkle_root(build_state_leaves())`. |
| `src/chain/chain.cpp:1855-1862` | G1 head-hash gate. |
| `src/chain/chain.cpp:1893-1911` | G2 state-root gate (the SD-3 drop-detection throw site). |
| `src/chain/chain.cpp:1397-1419` | A1 unitary-supply assertion (SD-5). |
| `src/chain/chain.cpp:548` | `Chain::live_total_supply` (SD-5 LHS). |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 (serialize-restore identity → SD-1/SD-2 `≡_S` core), T-S3 (per-namespace coverage → SD-3 basis), T-S4 (idempotent restore → SD-4), T-S6 (serialize determinism → SD-1). This document is the all-namespace joint composition of T-S1/T-S3/T-S4/T-S6. |
| `AppliedReceiptRestore.md` (FA-Apply-12) | The `i:`-namespace round-trip specialization composed into SD-1/SD-2/SD-3. |
| `MerkleTreeSoundness.md` | MT-1 (root = function of leaf set → SD-2 leaf-set route), MT-2 (domain separation → SD-3), MT-3 (collision-resistance inheritance, reduces to A2 → SD-3 sensitivity). |
| `S033StateRootNamespaceCoverage.md` | T-1 (coverage completeness), T-2 (namespace disjointness via prefix bytes → SD-3 injectivity), T-3 (deterministic leaf ordering → SD-2), T-5 (snapshot round-trip soundness). |
| `S012SnapshotStateRootGate.md` | The restore-side gate that catches Byzantine snapshot bytes (§5 boundary; T-1..T-4). |
| `BlockchainStateIntegrity.md` | The four-surface load/produce/receive/steady composition; §4.2 Claims (i)+(ii) that MT-1/MT-3 discharge. |
| `AccountStateInvariants.md` (FA-Apply-1) | I-6 / T-A6 (the A1 unitary-supply identity that SD-5 round-trips); apply determinism (the same-multiset precondition for SD-2). |
| `EconomicSoundness.md` (FA11) | T-12 (the chain-wide A1 unitary-supply theorem SD-5 references). |
| `docs/SECURITY.md` §S-012 / §S-033 / §S-037 / §S-038 / §S-041 | Snapshot bootstrap gate / Merkle state commitment / `d:` serialize-gap closure / producer-side `body.state_root` wiring / `k:` merge-threshold serialize-gap closure. The S-037/S-038/S-041 narratives are the canonical SD-3 instances (S-041 is the gap this very proof surfaced). |
| `docs/PROTOCOL.md` §4.1.1 / §11 | The `state_root` Merkle-leaf table (10 namespaces) / the snapshot wire format. |
| `Preliminaries.md` §2.0 / §2.1 | Canonical assumption labels; A2 (the only reduction target). |
| F1's `determ test-snapshot-full-determinism` (R40) | The empirical pin for SD-1..SD-5 (the all-namespace round-trip unit; §4 mapping). |
| `determ test-state-root-determinism` (`src/main.cpp:31387`) | Supplementary: chain-reload byte-identity of `state_root`. |
| `determ test-state-root-namespaces` (`src/main.cpp:20803`) | Supplementary: exhaustive per-namespace mutation-changes-root (SD-3). |
| `tools/test_snapshot_roundtrip.sh` | Supplementary: single-round-trip root-match + determinism. |
| `tools/test_dapp_snapshot.sh` | Supplementary: the `d:`-active joint surface (S-037 closure). |
| `tools/test_snapshot_bootstrap.sh` | Supplementary: 3-node donor + fresh receiver end-to-end fast-bootstrap. |

---

## 7. Status

**Test shipped (F1, R40); proof complete.**

All five theorems (SD-1 through SD-5) are closed by composition:

- **SD-1** (round-trip byte-identity) — via FA-Apply-2 T-S1 (`≡_S` after restore) + T-S6 (serialize determinism), generalized to byte-identity of the re-serialized JSON over all ten namespaces + the tail-header window.
- **SD-2** (state_root preservation) — via the `≡_S` leaf-set identity + MerkleTreeSoundness MT-1 (root is a function of the leaf set); the runtime check is the restore-side G2 gate.
- **SD-3** (every-namespace-contributes / no silent drop) — via MT-3 collision-resistance inheritance (reduces to A2) + namespace disjointness (S033 T-2); the drop-detection corollary is the all-namespace generalization of the S-037 bug class, made loud by G2.
- **SD-4** (idempotent double-restore) — via SD-1 byte-identity composed with restore determinism (equivalently FA-Apply-2 T-S4); the fixpoint reaches in one restore.
- **SD-5** (A1 accounting-invariance) — via the `a:`/`s:`/`c:` round-trip (T-S1 conditions 1–4) preserving both sides of the unitary-supply identity; the persisted A1 counters are why a restored chain asserts supply from its first post-restore block.

No theorem is open or partial over the populated namespace set. The single recorded limitation is the `k:` merge-threshold sub-field serialize gap (§2.1 fact 2 / §5) — a latent S-037-class gap that SD-3 makes *detectable* (a test with non-default merge thresholds would catch it); it does not affect chains whose merge thresholds equal the genesis defaults, which is every chain produced by the current `GenesisConfig` path. The proof is analytic and changes no code; the empirical pin is F1's `determ test-snapshot-full-determinism`.
