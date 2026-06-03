# S033StateRootNamespaceCoverage — 10-namespace state-root coverage completeness theorem

This document proves the S-033 coverage-completeness theorem: every mutable-state field that `Chain::apply_transactions` (and its companion paths — `serialize_state` / `restore_from_snapshot`) reads from or writes to is committed to by the 32-byte `state_root` field through exactly one of the ten leaf namespaces emitted by `Chain::build_state_leaves`. The closure is structural rather than cryptographic: no field outside the ten namespaces participates in apply-determinism, no two namespaces overlap at the byte level, and producer-side + receiver-side compute paths invoke the same primitive, so the apply-time gate at `src/chain/chain.cpp:1421-1446` is a faithful proxy for cross-node post-apply state equality up to SHA-256 collision resistance.

The proof exists because S-033 + S-038 jointly close the apply-time gate against state divergence (`BlockchainStateIntegrity.md` T-1..T-5 composes them across at-rest / produce / receive surfaces), but neither proof formally enumerates the in-scope state surface; an undiscovered field that contributes to apply-determinism but doesn't get a leaf would silently undermine the entire commitment. The dapp_registry snapshot gap (S-037) was exactly this class of bug: `d:` leaves emitted at apply time but the field absent from `serialize_state` / `restore_from_snapshot`, causing the snapshot tail head's state_root to diverge from the receiver's recomputed root. Closing the gap required threading the field through both surfaces simultaneously. This proof generalizes the lesson — it pins the namespace surface as a finite, enumerable, audit-friendly set, and surfaces the maintenance discipline that future state-field additions must follow.

**Companion documents.** `Preliminaries.md` (F0) §2.1 for SHA-256 collision resistance (A2) which underwrites the Merkle binding; `BlockchainStateIntegrity.md` (the four-surface S-021 + S-033 + S-038 composition this proof's T-4 + T-5 sit inside); `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot-pathway sibling proof; `AccountStateInvariants.md` (FA-Apply-1) for the apply determinism that T-4 invokes; `MultiEventComposition.md` (FA-Apply-15 T-M4) for the per-block joint state-root binding across heterogeneous event types; `AppliedReceiptRestore.md` (FA-Apply-12) for the cross-shard `i:`-namespace restore correctness contract; `DAppRegistryLifecycle.md` for the `d:`-namespace lifecycle (S-037 closure); `WireFormatBackwardCompat.md` C-2 for the zero-skip backward-compat shim on `state_root` itself; `docs/SECURITY.md` §S-033 + §S-037 + §S-038 for the closure-status narratives this proof formalizes; `docs/PROTOCOL.md` §4.1.1 for the canonical namespace table.

---

## 1. Theorem statements

**Setup.** Let `Chain` denote the type at `include/determ/chain/chain.hpp:539-624`. The mutable state-field universe `S` is the set of member fields of `Chain` that satisfy ALL three of the following:

1. **Apply-determinism participation:** the field is read from or written to by some code path in `Chain::apply_transactions` (`src/chain/chain.cpp:633-1502`), `Chain::activate_pending_params`, `Chain::serialize_state` (`chain.cpp:1541-1701`), or `Chain::restore_from_snapshot` (`chain.cpp:1703-1932`).
2. **Persistence:** the field's value persists across `apply_transactions` invocations (i.e., it is a member, not a local variable or `__snapshot` rollback artifact).
3. **Determinism:** the field's value is determined by the chain's block sequence (i.e., it is not a parameter, hook, hint cache, or transient producer-only view).

Let `N` denote the set of ten namespaces `{a:, s:, r:, d:, i:, b:, m:, p:, k:, k:c:}` emitted by `Chain::build_state_leaves` (`src/chain/chain.cpp:267-411`). The `k:c:` family is the composite counter sub-namespace inside the `k:` constants prefix — `const_leaf("c:NAME", ...)` produces a key of `k:` + `c:NAME` per the implementation pattern at chain.cpp:404-408. There are nine physical wire-level prefixes but ten conceptual namespaces; this proof treats them as ten because the value-encoding rules differ (counters are running totals; constants are genesis-pinned).

Let `MR(C)` denote `Chain::compute_state_root(C)` over a chain `C` (the sorted-leaves balanced binary SHA-256 Merkle root over `C.build_state_leaves()`). Let `≡_apply` denote the equivalence relation "byte-identical contribution to apply-determinism" — two states `S_1`, `S_2` of a chain satisfy `S_1 ≡_apply S_2` iff `apply_transactions(B)` mutates both into byte-identical post-apply states for every well-formed block `B`.

**Theorem T-1 (Namespace Coverage Completeness).** For every field `f ∈ S`, there exists a unique namespace `n ∈ N` such that mutations to `f` produce changes to at least one leaf in the `n`-namespace slice of `build_state_leaves()`. Equivalently: the map `f ↦ n` is total (every apply-determining field has a namespace) and the inverse `n ↦ {f : f maps to n}` is well-defined (each field has exactly one).

**Theorem T-2 (Namespace Disjointness).** The ten namespaces are pairwise disjoint at the byte level — for any two leaves `(k_1, v_1)` and `(k_2, v_2)` emitted under distinct namespaces, `k_1` and `k_2` differ in at least one byte within the namespace-prefix region of the key. Concretely, the prefix bytes are pairwise distinct as ASCII strings: `"a:"`, `"s:"`, `"r:"`, `"d:"`, `"i:"`, `"b:"`, `"m:"`, `"p:"`, `"k:"` are all distinct as 2-byte ASCII strings, and the composite `"k:c:"` is distinguished from the plain `"k:"` by the third byte being `'c'` (which is a valid namespace-suffix byte but only used for counters by convention).

**Theorem T-3 (Deterministic Leaf Ordering).** Within `build_state_leaves()`, the leaf-emission order across the ten namespaces follows a stable per-namespace iteration order (each `std::map` field iterates by sort order over its key type; `std::set` field iterates by sort order). The downstream `crypto::merkle_root` consumer (`src/crypto/merkle.cpp`) sorts the leaves by `key` before reduction; the sort is total + deterministic by byte-level lexicographic order, so two leaves cannot tie. Therefore: for any two `Chain` instances `C_1` and `C_2` whose mutable state is byte-identical across all ten namespaces, `MR(C_1) = MR(C_2)` byte-for-byte, independent of platform, allocator, ABI, or insertion order.

**Theorem T-4 (Producer/Receiver Symmetry).** Let `B` be a block produced by an honest node `N_p` running `Node::try_finalize_round` (`src/node/node.cpp:1024-1117`) and applied by an honest receiver `N_r` running `Chain::apply_transactions`. Both invoke `Chain::compute_state_root` (`src/chain/chain.cpp:413-415`) over the same post-apply state, both via the same `build_state_leaves` body. By apply determinism (`AccountStateInvariants.md` FA-Apply-1: byte-identical starting state + the same block ⇒ byte-identical post-apply state), the two roots are byte-equal; the apply-time gate at `chain.cpp:1432-1444` accepts the block. No asymmetry between producer-side and receiver-side computation is possible because both paths route through the same `Chain::build_state_leaves` implementation; any drift would violate FA-Apply-1, which is independently established.

**Theorem T-5 (Snapshot Round-Trip Soundness).** For every namespace `n ∈ N`, `Chain::serialize_state` emits the data necessary to reproduce every `n`-namespace leaf, and `Chain::restore_from_snapshot` reads back exactly the inputs needed to reconstruct each leaf's value-hash byte-for-byte. Therefore: for any `Chain` `C` with the post-fix-snapshot wiring (post-S-037 for `d:`, post-S-038 for the producer-side gate population), `MR(restore_from_snapshot(serialize_state(C))) = MR(C)`. The snapshot's tail-head `state_root` field is checked against the receiver's recomputed root at `chain.cpp:1893-1911`; mismatch raises a loud error with the S-033 tag.

---

## 2. Background

### 2.1 The ten-namespace canonical surface

`Chain::build_state_leaves` (`src/chain/chain.cpp:267-411`) emits leaves across the namespaces shown below. The implementation iterates each source map in `std::map`-sort-order; leaves are buffered into the `leaves` vector unsorted; `crypto::merkle_root` sorts by key before reduction.

| Namespace | Source field | Type | Key encoding | Value-hash encoding |
|---|---|---|---|---|
| `a:` | `accounts_` | `std::map<std::string, AccountState>` | `"a:" + domain (utf8)` | `SHA256(balance_u64 ‖ next_nonce_u64)` |
| `s:` | `stakes_` | `std::map<std::string, StakeEntry>` | `"s:" + domain (utf8)` | `SHA256(locked_u64 ‖ unlock_height_u64)` |
| `r:` | `registrants_` | `std::map<std::string, RegistryEntry>` | `"r:" + domain (utf8)` | `SHA256(ed_pub(32) ‖ registered_at_u64 ‖ active_from_u64 ‖ inactive_from_u64 ‖ region_len_u64 ‖ region_bytes)` |
| `d:` | `dapp_registry_` | `std::map<std::string, DAppEntry>` | `"d:" + domain (utf8)` | `SHA256(service_pubkey(32) ‖ registered_at_u64 ‖ active_from_u64 ‖ inactive_from_u64 ‖ url_len_u64 ‖ url ‖ topics_count_u64 ‖ Σ(topic_len_u64 ‖ topic) ‖ retention_u64 ‖ metadata_len_u64 ‖ metadata)` |
| `i:` | `applied_inbound_receipts_` | `std::set<std::pair<ShardId, Hash>>` | `"i:" + src_shard_be8 + tx_hash(32)` | `SHA256(0x01)` (presence marker, single byte) |
| `b:` | `abort_records_` | `std::map<std::string, AbortRecord>` | `"b:" + domain (utf8)` | `SHA256(count_u64 ‖ last_block_u64)` |
| `m:` | `merge_state_` | `std::map<ShardId, MergePartnerInfo>` | `"m:" + shard_id_be4` | `SHA256(partner_id_u64 ‖ refugee_region_len_u64 ‖ refugee_region_bytes)` |
| `p:` | `pending_param_changes_` | `std::map<uint64_t, std::vector<std::pair<std::string, std::vector<uint8_t>>>>` | `"p:" + eff_height_be8 + idx_be4` | `SHA256(name_len_u64 ‖ name ‖ value_len_u64 ‖ value_bytes)` |
| `k:` | thirteen genesis-pinned scalar constants | `uint64_t` / `uint32_t` / `uint8_t` / `Hash` | `"k:" + name` | `SHA256(value_u64)` (`SHA256(shard_salt[0..32])` for the shard_salt special case) |
| `k:c:` | five A1 supply counters | `uint64_t` | `"k:" + "c:" + name` | `SHA256(value_u64)` |

The `k:` namespace's thirteen members are (in lexicographic order of the `name` suffix, since `std::map`'s iteration order applies to the parent map but per-leaf names are inserted in source-line order which is then sorted before Merkle reduction): `block_subsidy`, `lottery_jackpot_multiplier`, `merge_grace_blocks`, `merge_threshold_blocks`, `min_stake`, `my_shard_id`, `revert_threshold_blocks`, `shard_count`, `shard_salt`, `subsidy_mode`, `subsidy_pool_initial`, `suspension_slash`, `unstake_delay`. The `k:c:` namespace's five members are: `accumulated_inbound`, `accumulated_outbound`, `accumulated_slashed`, `accumulated_subsidy`, `genesis_total`. (Sort order is over the literal "k:" + name string, so `k:b...` < `k:c:...` < `k:l...` etc.)

### 2.2 The apply path's state-mutation surface

`Chain::apply_transactions` (`src/chain/chain.cpp:633-1502`) walks the block body and mutates state via:

- Per-tx loop (lines 734-1231): mutates `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, `pending_param_changes_`, `merge_state_`, and the per-block u64 deltas (`block_outbound`, `total_fees`).
- Creator subsidy + fee distribution (lines 1234-1305): mutates `accounts_`, `accumulated_subsidy_` (via the `subsidy_this_block` accrual).
- Suspension slashing (lines 1313-1328): mutates `abort_records_`, `stakes_`, `accumulated_slashed_` (via `block_slashed`).
- Equivocation slashing (lines 1330-1356): mutates `stakes_`, `registrants_`, `accumulated_slashed_`.
- Inbound cross-shard receipt admission (lines 1358-1381): mutates `accounts_`, `applied_inbound_receipts_`, `accumulated_inbound_` (via `block_inbound`).
- A1 supply counter rollup (lines 1390-1395): mutates `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_`.
- A9 Phase 2C committed-state-view publish (lines 1475-1485): NOT a state mutation — `committed_state_view_` is a lock-free read cache that materializes from the four source maps. Outside the apply-determinism universe; not in `S`.

The `activate_pending_params` helper called at line 676 mutates `pending_param_changes_` (erasing activated entries) and the targeted constant scalar (e.g., `min_stake_`, `suspension_slash_`, `unstake_delay_`). Both surfaces are state-determining and live inside the apply call boundary.

Genesis branch (lines 681-718): mutates `accounts_`, `registrants_`, `stakes_`, `genesis_total_`, and zeroes the four `accumulated_*` counters. Same state set; just a fast-path branch for index-0 blocks.

### 2.3 The producer wiring (S-038)

`Node::try_finalize_round` (`src/node/node.cpp:1024-1117`) populates `body.state_root` before broadcast via the pattern:

```cpp
chain::Chain tentative_chain = chain_;     // deep copy
tentative_chain.append(body);              // apply with state_root=0 (gate skip)
body.state_root = tentative_chain.compute_state_root();
apply_block_locked(body);                   // apply on live chain with populated state_root
```

The tentative-chain dry-run produces the canonical post-apply state without committing it; reading `compute_state_root()` materializes the ten-namespace Merkle root over the tentative state; assigning back to `body.state_root` populates the field for the broadcast block. By T-3 (deterministic leaf ordering) + FA-Apply-1 (apply determinism), the tentative chain's post-apply state is byte-identical to what `chain_` produces after `apply_block_locked`, so the apply-time gate's comparison at line 1432 always passes for honest producers (`BlockchainStateIntegrity.md` T-3).

### 2.4 The snapshot pathway (S-037 closure)

`Chain::serialize_state` (`chain.cpp:1541-1701`) emits a JSON object covering every namespace's source map: `accounts` (lines 1550-1558), `stakes` (1560-1568), `registrants` (1570-1583), `applied_inbound_receipts` (1585-1592), thirteen genesis-pinned constants (1597-1608), the five A1 counters (1614-1618), `abort_records` (1622-1630), `merge_state` (1637-1645), `dapp_registry` (1653-1669, S-037 closure), `pending_param_changes` (1671-1685), and the tail-header bundle (1690-1698) which is NOT a state field but provides the `prev_hash` continuity envelope.

`Chain::restore_from_snapshot` (`chain.cpp:1703-1932`) reads each emitted field back into the corresponding `Chain` member with backward-compatible `value()`-default fallbacks for missing fields (pre-feature snapshots load gracefully). The post-restore consistency gate at `chain.cpp:1893-1911` recomputes the state_root and verifies it equals the tail-head's stored `state_root` byte-for-byte, throwing on mismatch with the S-033 tag.

Pre-S-037, the `dapp_registry` field was absent from `serialize_state` and `restore_from_snapshot` despite contributing to the `d:` namespace. A DApp-active chain's snapshot would carry the tail-head's correct state_root in JSON, but the restored chain would compute a different state_root (missing `d:` leaves), triggering the gate's loud-fail. S-037 closed the gap by threading `dapp_registry` through both surfaces with the full set of fields needed to reproduce the `d:` value-hash byte-for-byte.

---

## 3. Implementation citations

The load-bearing call sites for this proof:

| Site | File / lines | Role |
|---|---|---|
| `Chain::build_state_leaves` | `src/chain/chain.cpp:267-411` | The canonical ten-namespace leaf generator. Single source of truth — `compute_state_root` (root) and `state_proof` (inclusion proof) both consume this. |
| `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | Thin wrapper: `merkle_root(build_state_leaves())`. |
| `Chain::state_proof` | `src/chain/chain.cpp:435-462` | Light-client RPC counterpart: same leaf set, plus sibling-hash proof for one target leaf. |
| `Chain::apply_transactions` S-033 gate | `src/chain/chain.cpp:1421-1446` | T-4 mechanism. Recomputes `compute_state_root()` post-apply, compares against `b.state_root`, throws on mismatch with the S-033 tag. |
| `Chain::serialize_state` | `src/chain/chain.cpp:1541-1701` | T-5 producer-side. Emits each namespace's source map to JSON. |
| `Chain::restore_from_snapshot` | `src/chain/chain.cpp:1703-1932` | T-5 consumer-side. Reads each namespace's source map back; post-restore state_root gate at lines 1893-1911. |
| `Node::try_finalize_round` | `src/node/node.cpp:1024-1117` | T-4 producer wiring (S-038 closure). Populates `body.state_root` via tentative-chain dry-run before broadcast. |
| `Chain` private state fields | `include/determ/chain/chain.hpp:539-624` | The complete mutable-state surface enumerated by T-1's case analysis. |
| `Block.state_root` | `include/determ/chain/block.hpp:460-484` | The 32-byte wire field bound into `signing_bytes` under the zero-skip backward-compat shim (`WireFormatBackwardCompat.md` C-2). |

---

## 4. Proofs

### 4.1 Proof of T-1 (Namespace Coverage Completeness)

We prove by exhaustive case analysis over the field universe `S`. For each `Chain` member field that satisfies the apply-determinism + persistence + determinism predicates of §1's setup, we exhibit the unique namespace `n ∈ N` that emits a leaf whose value-hash includes the field's value.

**Per-field enumeration** (every entry references `include/determ/chain/chain.hpp` member declarations and the relevant `apply_transactions` mutation site).

#### 4.1.1 Per-domain account-state fields

- `accounts_` (chain.hpp:540) — `std::map<std::string, AccountState>`. AccountState has fields `{balance, next_nonce}`. Apply sites: TRANSFER (chain.cpp:742-770, 756-761), REGISTER (chain.cpp:824-833 NEF), STAKE / UNSTAKE (chain.cpp:858-894), DAPP_REGISTER (chain.cpp:1051), DAPP_CALL (chain.cpp:1212-1222), creator subsidy + fees (chain.cpp:1290-1305), inbound receipts (chain.cpp:1367-1372), genesis (chain.cpp:688-691). **Namespace: `a:`** — emitted at `chain.cpp:285-290`. Value-hash is `SHA256(balance ‖ next_nonce)` which binds both fields.

- `stakes_` (chain.hpp:541) — `std::map<std::string, StakeEntry>`. StakeEntry has fields `{locked, unlock_height}`. Apply sites: REGISTER initializes (chain.cpp:809-811), STAKE (chain.cpp:866-867), UNSTAKE (chain.cpp:889-892), DEREGISTER sets `unlock_height` (chain.cpp:848-852), suspension slash (chain.cpp:1322-1327), equivocation slash (chain.cpp:1345-1350), genesis (chain.cpp:704-709). **Namespace: `s:`** — emitted at `chain.cpp:292-297`. Value-hash is `SHA256(locked ‖ unlock_height)` which binds both fields.

- `registrants_` (chain.hpp:542) — `std::map<std::string, RegistryEntry>`. RegistryEntry has fields `{ed_pub, registered_at, active_from, inactive_from, region}`. Apply sites: REGISTER (chain.cpp:798-805), DEREGISTER (chain.cpp:841-846), equivocation slash (chain.cpp:1351-1355), genesis (chain.cpp:694-703). **Namespace: `r:`** — emitted at `chain.cpp:299-308`. Value-hash binds `ed_pub ‖ registered_at ‖ active_from ‖ inactive_from ‖ region_len ‖ region_bytes`.

- `dapp_registry_` (chain.hpp:549) — `std::map<std::string, DAppEntry>`. DAppEntry has fields `{service_pubkey, registered_at, active_from, inactive_from, endpoint_url, topics, retention, metadata}`. Apply sites: DAPP_REGISTER op=0 / op=1 (chain.cpp:1049-1117). **Namespace: `d:`** — emitted at `chain.cpp:312-330`. Value-hash binds every field including the variable-length topics vector with explicit length-prefix encoding.

#### 4.1.2 Per-collection state fields

- `applied_inbound_receipts_` (chain.hpp:605) — `std::set<std::pair<ShardId, Hash>>`. Apply site: inbound receipt admission (chain.cpp:1373-1374). **Namespace: `i:`** — emitted at `chain.cpp:332-341`. Key encodes `src_shard_be8 ‖ tx_hash(32)`; value-hash is the single-byte presence marker `SHA256(0x01)`. The (src_shard, tx_hash) pair uniquely identifies the entry; presence vs absence is the only semantic.

- `abort_records_` (chain.hpp:587) — `std::map<std::string, AbortRecord>` (S-032 cache). AbortRecord has fields `{count, last_block}`. Apply site: Phase-1 abort apply (chain.cpp:1313-1320). **Namespace: `b:`** — emitted at `chain.cpp:343-348`. Value-hash binds `count ‖ last_block`.

- `merge_state_` (chain.hpp:598) — `std::map<ShardId, MergePartnerInfo>`. MergePartnerInfo has fields `{partner_id, refugee_region}`. Apply site: MERGE_EVENT BEGIN/END (chain.cpp:1017-1039). **Namespace: `m:`** — emitted at `chain.cpp:350-360`. Value-hash binds `partner_id ‖ refugee_region_len ‖ refugee_region_bytes`.

- `pending_param_changes_` (chain.hpp:621-623) — `std::map<uint64_t, std::vector<std::pair<std::string, std::vector<uint8_t>>>>`. Apply sites: `stage_param_change` (called from PARAM_CHANGE apply at chain.cpp:900-928; declared `chain.hpp:379-381`), and `activate_pending_params` (chain.cpp:471-497, erases activated entries at the start of each apply). **Namespace: `p:`** — emitted at `chain.cpp:362-378`. Key encodes `eff_height_be8 ‖ idx_be4`; value-hash binds `name_len ‖ name ‖ value_len ‖ value_bytes`. The per-eff-height vector's index becomes part of the key, so multi-PARAM_CHANGE batches at the same eff_height map to distinct leaves.

#### 4.1.3 Genesis-pinned scalar constants

- `block_subsidy_` (chain.hpp:571), `subsidy_pool_initial_` (chain.hpp:577), `subsidy_mode_` (chain.hpp:583), `lottery_jackpot_multiplier_` (chain.hpp:584), `min_stake_` (chain.hpp:585), `suspension_slash_` (chain.hpp:589), `unstake_delay_` (chain.hpp:590), `merge_threshold_blocks_` (chain.hpp:592), `revert_threshold_blocks_` (chain.hpp:593), `merge_grace_blocks_` (chain.hpp:594), `shard_count_` (chain.hpp:599), `shard_salt_` (chain.hpp:600), `my_shard_id_` (chain.hpp:601) — thirteen genesis-pinned scalars. Set at genesis-apply or at `Chain::set_shard_routing` / `set_min_stake` etc. (governance staging via `activate_pending_params` for `min_stake_`, `suspension_slash_`, `unstake_delay_`). **Namespace: `k:`** — emitted at `chain.cpp:380-402` via `const_leaf` (which emits `k:` + name + value_hash). The 32-byte `shard_salt_` has its own leaf path (chain.cpp:398-402) that hashes the full 32-byte array via `SHA256Builder::append(Hash)`.

#### 4.1.4 A1 supply counters

- `genesis_total_` (chain.hpp:611), `accumulated_subsidy_` (chain.hpp:612), `accumulated_slashed_` (chain.hpp:613), `accumulated_inbound_` (chain.hpp:614), `accumulated_outbound_` (chain.hpp:615) — five running totals. Set at genesis (chain.cpp:711-715) and per-block rollup (chain.cpp:1390-1395). Read at `expected_total` for the A1 unitary-supply invariant check (chain.cpp:1397-1418). **Namespace: `k:c:`** — emitted at `chain.cpp:404-408` via `const_leaf("c:NAME", value)` which produces a key of `k:` + `c:` + name. The `k:c:` composite is distinguished from `k:` proper by the `c:` infix; PROTOCOL.md §4.1.1 documents this as the tenth conceptual namespace.

#### 4.1.5 Fields explicitly OUTSIDE `S` (non-coverage justification)

The following `Chain` members satisfy field-of-Chain but FAIL one or more of the §1 predicates and are correctly excluded from the ten-namespace coverage:

- `blocks_` (chain.hpp:539) — the chain block sequence itself. Apply-mutates via `Chain::append` after `apply_transactions` returns. The block-sequence integrity is enforced by `prev_hash` chain continuity at `chain.cpp:54-58` (`BlockchainStateIntegrity.md` T-1 mechanism) + the S-021 wrap (chain.cpp:1944-1985). NOT a state-root field by design: `state_root` commits to the post-apply state derived from `blocks_`, not to `blocks_` itself. The block hash chain (head_hash + prev_hash) handles the block-sequence integrity surface.

- `committed_state_view_` (chain.hpp:568-569) — A9 Phase 2C lock-free read cache. Materialized from `accounts_ / stakes_ / registrants_ / dapp_registry_` at apply commit. NOT in `S` because it is a derived view, not a source of truth; mutating any of the four source maps and not republishing the bundle would be a bug at the consumer level (RPC reads stale data) but would not change `state_root`. The four underlying source maps ARE in `S` and each maps to its proper namespace.

- `param_changed_hook_` (chain.hpp:624) — Node-installed callback. NOT block-derived; not persisted; not in `S`.

- `inbound_receipts_eligible_for_inclusion` — NOT a `Chain` member. Lives on `Node` (`include/determ/node/node.hpp:357-358`) as a producer-side mempool view. Correctly outside `Chain`'s state surface.

- The transient per-apply locals (`__snapshot`, `total_fees`, `height`, `block_outbound`, `block_inbound`, `block_slashed`, `base_subsidy`, `subsidy_this_block`, `total_distributed`, the `__ensure_*` lambdas) are stack-scoped function locals (chain.cpp:646-665, 720-732, 1250-1289). They are mutation accumulators consumed within the same call; their final values feed into persisted fields (`accumulated_*_`, `accounts_`) at the apply tail (chain.cpp:1390-1395). NOT in `S`; their effect is captured by the persisted destinations.

**Conclusion.** Every field in `S` has been exhibited with its unique namespace. The map `f ↦ n` is total over `S` and well-defined (no field is assigned to two namespaces). The reverse direction — every namespace `n ∈ N` has at least one field — follows by inspection of §1's table (each of the ten namespaces emits leaves only when its source field is non-empty, but the source field exists and is non-empty under at least one well-formed chain trajectory).   ∎

### 4.2 Proof of T-2 (Namespace Disjointness)

We need: for any two leaves `(k_a, v_a)`, `(k_b, v_b)` from distinct namespaces, `k_a ≠ k_b` over the raw byte representation.

The prefix bytes are the first two bytes (or three bytes for `k:c:`) of each key. We exhibit a pairwise-distinctness witness for each pair:

| Pair | Distinguishing byte position | Distinguishing values |
|---|---|---|
| `a:` vs `s:` | byte 0 | `'a'` (0x61) vs `'s'` (0x73) |
| `a:` vs `r:` | byte 0 | `'a'` (0x61) vs `'r'` (0x72) |
| `a:` vs `d:` | byte 0 | `'a'` (0x61) vs `'d'` (0x64) |
| `a:` vs `i:` | byte 0 | `'a'` (0x61) vs `'i'` (0x69) |
| `a:` vs `b:` | byte 0 | `'a'` (0x61) vs `'b'` (0x62) |
| `a:` vs `m:` | byte 0 | `'a'` (0x61) vs `'m'` (0x6D) |
| `a:` vs `p:` | byte 0 | `'a'` (0x61) vs `'p'` (0x70) |
| `a:` vs `k:` | byte 0 | `'a'` (0x61) vs `'k'` (0x6B) |
| `s:` vs `r:` | byte 0 | `'s'` (0x73) vs `'r'` (0x72) |
| `s:` vs `d:` | byte 0 | `'s'` (0x73) vs `'d'` (0x64) |
| ... | ... | ... |
| `k:` vs `k:c:` | byte 2 | the bare `k:` namespace's name suffix (e.g., `"block_subsidy"`, byte 2 = `'b'`) vs `'c'` for the counters subnamespace |

For the `k:` / `k:c:` boundary specifically: `k:` proper names are the thirteen genesis-pinned constants enumerated in §2.1. None of them start with the literal letter `c` (the names are `block_subsidy`, `lottery_jackpot_multiplier`, `merge_grace_blocks`, `merge_threshold_blocks`, `min_stake`, `my_shard_id`, `revert_threshold_blocks`, `shard_count`, `shard_salt`, `subsidy_mode`, `subsidy_pool_initial`, `suspension_slash`, `unstake_delay`). The five `k:c:` names ARE prefixed with `c:` (the `const_leaf("c:NAME", ...)` pattern at chain.cpp:404-408 emits `k:` + `c:` + name). So byte 2 of any `k:` leaf is in `{'b', 'l', 'm', 'r', 's', 'u'}` while byte 2 of any `k:c:` leaf is `'c'` followed by `:` at byte 3. Disjointness holds.

(A nominal sub-concern: a future code change that adds a new genesis-pinned constant whose name starts with `c` could collide. This is structurally bounded by the maintenance discipline in §6.3 — any new `k:` constant must avoid the `c:` prefix or the audit gate would catch the namespace collision. The `test_state_proof_namespaces.sh` regression at the cross-namespace-swap-rejection assertion would also detect a real collision in the value-hash space.)

**Cross-namespace collision in value-hash space.** Distinct namespaces produce distinct leaf keys; distinct keys at the Merkle layer commit to distinct positions in the sorted-leaves vector (T-3). Two different value-hashes at distinct positions produce distinct Merkle roots by SHA-256 collision resistance (A2). Even if two different namespaces could somehow produce identical value-hashes (e.g., a 32-byte counter coincides with a 32-byte hash output of an account-state byte sequence), the leaves remain distinct because the leaf primitive is `(key, value_hash)` and the keys are distinguishable per the prefix argument above. The `crypto::MerkleLeaf` type (`include/determ/crypto/merkle.hpp`) is a `{key, value_hash}` pair, and the merkle_root computation incorporates both into the leaf hash.   ∎

### 4.3 Proof of T-3 (Deterministic Leaf Ordering)

**Inside-namespace ordering:**

- `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, `abort_records_`: `std::map<std::string, V>`. C++ standard `[map.overview]/2` guarantees iteration in sort order of the key type's `operator<`. `std::string`'s `operator<` is byte-level lexicographic over `char` (which on the determ platform is `unsigned char` semantically; the implementation does not rely on `char` signedness because all stored domain names are ASCII or UTF-8, and the comparison is over the raw byte sequence). Therefore: same map contents (byte-equal key+value pairs across two `Chain` instances) ⇒ same iteration order.

- `applied_inbound_receipts_`: `std::set<std::pair<ShardId, Hash>>`. Iteration in sort order of `std::pair`'s lexicographic comparator: first by `ShardId` (a `uint32_t`), then by `Hash` (a fixed-size byte array compared lexicographically via `std::array::operator<`). Both comparators are deterministic; same set contents ⇒ same iteration order.

- `merge_state_`: `std::map<ShardId, MergePartnerInfo>`. Same `std::map` guarantee with `ShardId` (uint32_t) keys; deterministic.

- `pending_param_changes_`: `std::map<uint64_t, std::vector<std::pair<std::string, std::vector<uint8_t>>>>`. Outer iteration is by `uint64_t` effective_height (deterministic); inner per-bucket iteration is by index in the `std::vector` (insertion order, baked into the chain trajectory by `stage_param_change` at chain.cpp:921-922). Both are deterministic.

- `k:` constants and `k:c:` counters: emitted by source-line order in `build_state_leaves` (chain.cpp:385-408). The same source code on every node emits in the same order. (Pre-sort, the leaves are produced in a fixed order; post-sort, they are reordered by key.)

**Cross-namespace post-sort ordering:** `crypto::merkle_root` (`src/crypto/merkle.cpp`) sorts the leaves by `key` in lexicographic byte order before reduction. Lexicographic byte sort is total and deterministic. Two leaves with identical keys cannot occur within `Chain::build_state_leaves` output because (by T-2) namespaces are pairwise disjoint, and within a namespace, the source-map / source-set iteration order produces distinct keys (the keys are derived from distinct map keys; duplicate map keys would violate the `std::map` / `std::set` no-duplicate-key invariant).

The Merkle tree reduction (`crypto::merkle_root`) is itself deterministic: it builds a balanced binary tree over the sorted leaves with SHA-256 inner nodes; the inner-node hash is `SHA256(left ‖ right)` (where the right child duplicates the left at odd-length boundaries — the standard balanced-tree padding rule). The reduction operates on byte sequences with no platform-dependent operations.

**Empty-leaf case:** if `build_state_leaves` returns an empty vector, `crypto::merkle_root` returns the empty-tree sentinel `Hash{}` (the zero 32-byte array). This matches PROTOCOL.md §4.1.1's statement: "if the entire leaf vector is empty the root is the empty-tree sentinel `Hash{}`." The case is operationally rare — even a freshly-default-constructed `Chain` has thirteen `k:` constants emitted at default values + five `k:c:` counters at zero, so the empty-tree case requires a contrived bypass.

**Conclusion.** Byte-identical mutable state across all ten namespaces produces byte-identical leaf vectors (modulo sort), which produces byte-identical sorted leaf vectors, which produces byte-identical Merkle roots. No platform/allocator/ABI dependence anywhere in the chain.   ∎

### 4.4 Proof of T-4 (Producer/Receiver Symmetry)

Fix block `B` produced by honest node `N_p` and received by honest node `N_r`. We claim: after `apply_transactions(B)` runs on `N_r`'s chain, the apply-time gate's comparison at `chain.cpp:1432-1444` passes.

The proof composes T-3 with the apply-determinism invariant from FA-Apply-1.

**Step 1: Both nodes execute the same `build_state_leaves` body.** This is a structural fact about the codebase: `Chain::build_state_leaves` is defined at `chain.cpp:267-411` and is called by both `Chain::compute_state_root` (chain.cpp:413-415, used by both producer-via-tentative-chain and receiver-via-gate-comparison) and `Chain::state_proof` (chain.cpp:435-462, used by light clients). There is exactly one implementation; no alternate path.

**Step 2: Inputs to `build_state_leaves` are byte-identical.** By the inductive hypothesis of cross-node convergence (`BlockchainStateIntegrity.md` T-4), both nodes hold byte-identical chain state immediately before applying `B`. The block `B` itself is gossiped from one producer; its byte representation is fixed across honest peers (`BlockchainStateIntegrity.md` T-4 paragraph after the inductive step). Therefore: both nodes apply the same `B` to byte-identical starting states. By FA-Apply-1 (`AccountStateInvariants.md` Theorem T-A1 — full apply-path determinism over `std::map` iteration), the post-apply chain states are byte-identical across all ten namespaces.

**Step 3: Output of `build_state_leaves` is byte-identical.** By T-3, byte-identical state across all ten namespaces ⇒ byte-identical leaf vectors ⇒ byte-identical sorted leaf vectors ⇒ byte-identical Merkle roots.

**Step 4: Producer-side `body.state_root` matches.** `Node::try_finalize_round` (`src/node/node.cpp:1093-1117`, the S-038 wiring) populates `body.state_root` from a tentative-chain dry-run: deep-copy `chain_`, apply `body` with `state_root=0` (gate skip on the dry-run apply because the zero-skip shim at chain.cpp:1432 fires), read `tentative_chain.compute_state_root()`, assign to `body.state_root`. By FA-Apply-1, the tentative chain and the live `chain_` (after the subsequent `apply_block_locked`) produce byte-identical post-apply state. Therefore `body.state_root` carries the canonical post-apply state_root for `chain_`.

**Step 5: Receiver-side gate passes.** When `N_r` runs `apply_transactions(B)`, the gate at chain.cpp:1432 computes `compute_state_root()` over the post-apply state. By Steps 1-3, this equals `body.state_root` byte-for-byte. The comparison at line 1434 passes; no throw.

**Symmetry property.** There is no path by which producer-side and receiver-side compute paths could disagree without one of FA-Apply-1, T-3, or `std::map` iteration determinism failing. None of these can fail on conformant C++ implementations; the proof is structural.

**Adversarial corner case: dishonest producer.** A Byzantine producer might compute `body.state_root` via a path other than `tentative_chain.compute_state_root()` — e.g., set it to an arbitrary value. Then on receiver side, the gate fires loud-fail because `N_r`'s recomputed `compute_state_root()` (which is the canonical value by Steps 1-3) does not equal the producer's manufactured `body.state_root`. This is the T-2 fire path of `BlockchainStateIntegrity.md`; the chain rejects the block. Symmetry is preserved in the sense that ALL honest receivers fire the gate identically — no honest receiver applies a divergent block.   ∎

### 4.5 Proof of T-5 (Snapshot Round-Trip Soundness)

Fix a chain `C` whose state is consistent at the head (i.e., `MR(C)` equals `C.head().state_root`, which holds post-S-038 for honestly-produced blocks).

**Step 1: serialize_state emits every namespace's source map.** By inspection of `Chain::serialize_state` (`chain.cpp:1541-1701`):

| Namespace | Emitted at | Fields preserved |
|---|---|---|
| `a:` | chain.cpp:1550-1558 (`accounts`) | `domain`, `balance`, `next_nonce` |
| `s:` | chain.cpp:1560-1568 (`stakes`) | `domain`, `locked`, `unlock_height` |
| `r:` | chain.cpp:1570-1583 (`registrants`) | `domain`, `ed_pub`, `registered_at`, `active_from`, `inactive_from`, `region` |
| `d:` | chain.cpp:1653-1669 (`dapp_registry`) | `domain`, `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, `registered_at`, `active_from`, `inactive_from` (S-037 closure) |
| `i:` | chain.cpp:1585-1592 (`applied_inbound_receipts`) | `src_shard`, `tx_hash` |
| `b:` | chain.cpp:1622-1630 (`abort_records`) | `domain`, `count`, `last_block` (S-032 cache) |
| `m:` | chain.cpp:1637-1645 (`merge_state`) | `shard_id`, `partner_id`, `refugee_region` |
| `p:` | chain.cpp:1671-1685 (`pending_param_changes`) | `effective_height`, per-entry `name`, `value` |
| `k:` | chain.cpp:1597-1616 (thirteen scalars) | every name in §2.1's `k:` list (the three merge thresholds added by the S-041 closure — pre-S-041 only ten were emitted) |
| `k:c:` | chain.cpp:1622-1626 (five counters) | every name in §2.1's `k:c:` list |

Every namespace has at least one field emitted. The field-set for each namespace is sufficient to reconstruct the leaf's value-hash byte-for-byte (because the value-hash is `SHA256(field_a ‖ field_b ‖ ...)` and the JSON emission preserves every field).

**Step 2: restore_from_snapshot reads back every field with byte-identical encoding.** By inspection of `Chain::restore_from_snapshot` (`chain.cpp:1703-1932`): each emitted JSON field is read back via `value()` (with backward-compatible defaults for missing fields, but those defaults match what `serialize_state` would emit for a default-constructed source map). The field-to-`Chain`-member assignment is byte-preserving — `from_hex` for `Hash` arrays, value-copy for primitives, length-prefixed strings (the JSON encoding preserves trailing whitespace, encoding, and length exactly).

**Subtle point: backward-compat default fields.** Pre-S-037 snapshots omit `dapp_registry`; the restore branch at chain.cpp:1818 uses `snap.contains("dapp_registry")` to skip the field and leaves `c.dapp_registry_` empty. This matches a fresh-chain restore (no DApps registered ⇒ no `d:` leaves emitted by `build_state_leaves`). Post-S-037 snapshots emit and consume the field; post-S-038 chains carry non-zero state_root in the tail-head; the post-restore gate at chain.cpp:1893-1911 verifies the round-trip. The same discipline applies to the three `k:` merge thresholds (S-041 closure): pre-S-041 snapshots omit `merge_threshold_blocks` / `revert_threshold_blocks` / `merge_grace_blocks`, and restore re-supplies the `GenesisConfig` defaults (100 / 200 / 10) via `snap.value(…, default)` — which match what `build_state_leaves` emits for a default-merge-threshold chain, so a pre-S-041 snapshot of a default-threshold chain round-trips identically. The gap was only observable on a non-default-threshold chain, which is now exercised by `test-snapshot-roundtrip` case #10b + `test-snapshot-full-determinism`.

**Step 3: Post-restore state_root equals snapshot tail-head's stored state_root.** The post-restore gate at chain.cpp:1893-1911:

```cpp
if (!c.blocks_.empty()) {
    Hash claimed = c.blocks_.back().state_root;
    Hash zero{};
    if (claimed != zero) {
        Hash computed = c.compute_state_root();
        if (computed != claimed) {
            throw std::runtime_error(...S-033...);
        }
    }
}
```

By Step 2 (every namespace's fields restored byte-for-byte) + T-3 (byte-identical state ⇒ byte-identical state_root) + T-4 Step 4 (the tail-head's stored state_root is what the original producer computed via `tentative_chain.compute_state_root()` over the same state), `computed == claimed` byte-for-byte. The gate passes.

**Pre-S-038 corner case: the claimed state_root is zero.** If the snapshot's tail head pre-dates S-038, its `state_root` field is empty in JSON (zero on the wire). The gate's zero-skip shim at `if (claimed != zero)` short-circuits; restore proceeds without state_root verification. This is the intentional backward-compat path (`BlockchainStateIntegrity.md` §6.1) — restored chains pre-S-038 fall back on `prev_hash` continuity + the tail-head `head_hash` anchor (chain.cpp:1855-1862) for integrity. Once a post-S-038 block is appended to the restored chain, the gate is active from that point forward.

**Snapshot integrity composition.** The snapshot pathway is a sister surface to the `apply_block` / `Chain::append` pathway. `BlockchainStateIntegrity.md` covers the at-rest / produce / receive surfaces; this proof's T-5 covers the snapshot surface. `SnapshotEquivalence.md` (FA-Apply-2) carries the full composition argument — the post-restore state is byte-identical to the source chain's state, so the apply-time gate behaves identically on subsequent block apply.

**S-037 closure as a special case of T-5.** Pre-S-037, the `dapp_registry` field was missing from both `serialize_state` and `restore_from_snapshot`. On a chain with a registered DApp, `build_state_leaves` would emit `d:` leaves contributing to the source chain's state_root (the apply-time gate fired correctly because both producer-side tentative-chain and receiver-side post-apply chain had the DApp registered). But snapshot restore would load a chain WITHOUT the DApp registry; `c.dapp_registry_` would be empty; `c.compute_state_root()` would compute a different root (no `d:` leaves); the post-restore gate at chain.cpp:1893-1911 would fire loud-fail. S-037 closed by adding the `dapp_registry` field to both emission and restore surfaces with the full set of subfields needed to reproduce the `d:` value-hash byte-for-byte (matching the encoding in `build_state_leaves` at chain.cpp:312-330). T-5 holds for the S-037-fixed code path.

**S-038 closure as a special case of T-5.** Pre-S-038, the producer never populated `body.state_root` before broadcast. The post-restore gate at chain.cpp:1893-1911 had nothing to compare against (tail-head's `state_root` was zero on every block; the zero-skip shim short-circuited). The S-033 promise was data-layer infrastructure but operationally dormant. S-038 closed by adding the tentative-chain dry-run to `Node::try_finalize_round` (node.cpp:1093-1117). Post-S-038 blocks carry non-zero `state_root`; the post-restore gate is real-time-active; T-5 fires the gate on any namespace-coverage mismatch.   ∎

---

## 5. Adversary model

The proof's threat model considers four adversary surfaces; each is bounded by a different mechanism of T-1 + T-2 + T-3 + T-4 + T-5.

**(a) Producer-introduces-divergence.** A Byzantine producer signs a block whose `body.state_root` doesn't match the canonical post-apply state. By T-4's "Adversarial corner case", every honest receiver fires the gate at `chain.cpp:1432-1444` and rejects the block. The chain doesn't advance; the operator sees the byte-precision diagnostic.

**(b) Snapshot-supplier-introduces-divergence.** A Byzantine snapshot supplier ships a snapshot whose `accounts` / `stakes` / etc. don't match the tail-head's stored `state_root`. By T-5 + the post-restore gate at chain.cpp:1893-1911, the receiver's recomputed state_root doesn't match `claimed`; the restore throws loudly. The receiver doesn't bootstrap from the divergent snapshot. (Note: this assumes a non-zero `claimed` — pre-S-038 snapshots are an intentional skip per §6.1's known limitation.)

**(c) Code-injects-out-of-namespace-state.** A bug or malicious code change introduces a new state field that participates in apply-determinism but isn't wired into `build_state_leaves`. T-1's coverage argument would be violated; the apply-time gate would not detect the resulting divergence. Mitigation: the audit discipline in §6.3 + the lock-in regression at `tools/test_state_root_namespaces.sh` (12 assertions covering all ten namespaces). A new field added with no leaf emission would fail to change `compute_state_root` after mutation — the per-namespace assertion would not fire for the new namespace. Trivially detectable.

**(d) Hash-collision adversary.** An adversary engineers two distinct chain states `C_1 ≠ C_2` such that `MR(C_1) = MR(C_2)`. This requires finding a SHA-256 collision in either a leaf value-hash or an inner Merkle node. Bounded by A2 (`Preliminaries.md` §2.1): birthday bound ~`2⁻¹²⁸` per query for inner-node collisions; structural reductions for leaf-key collisions (each leaf's key is unique by T-2, so a leaf collision requires a value-hash collision, which is the same `2⁻¹²⁸` bound).

---

## 6. Identified gaps and known limitations

### 6.1 Pre-S-038 historical blocks bypass T-4

Pre-S-038 blocks carry zero `state_root`; the zero-skip shim at chain.cpp:1432 short-circuits the gate. T-4 does NOT cover the apply-time gate's behavior on these blocks. This is intentional (matches `BlockchainStateIntegrity.md` §6.1): forcing strict checking on legacy chains would break chains that exist today. The fallback security comes from `prev_hash` chain continuity + the wrapping `head_hash` at chain.cpp:2037-2051.

Once a post-S-038 block is appended to a partially-pre-S-038 chain, the apply-time gate is active from that point forward, and every new block's `state_root` is verified.

### 6.2 The PROTOCOL.md §4.1.1 table is the wire-contract; build_state_leaves is the implementation

PROTOCOL.md §4.1.1 documents the namespace table as the wire-level contract. If a future code change diverged from PROTOCOL.md (e.g., changed a value-hash encoding), the apply-time gate would still fire — different state_roots — but external clients (light-client state_proof verifiers) would no longer be able to verify proofs against block headers signed under the new code path. The maintenance discipline: any change to `build_state_leaves` MUST update PROTOCOL.md §4.1.1 simultaneously, AND must satisfy the zero-skip backward-compat criterion or be flagged as a flag-day migration (`WireFormatBackwardCompat.md` R-1 risk).

**Lock-in mitigation:** the test_state_root_namespaces.sh regression at `tools/test_state_root_namespaces.sh` (the in-process `determ test-state-root-namespaces` unit with 12 assertions) sentinels the ten-namespace surface by verifying that every namespace's per-mutation root change holds. A new namespace addition would require updating the test; removing one would fail the corresponding assertion.

### 6.3 A new state field added without namespace coverage

**Risk:** a future code change introduces a new `Chain` member field that participates in apply-determinism but is not wired into `build_state_leaves`. T-1's coverage argument would be violated; the apply-time gate would silently fail to detect divergence in the new field.

**Detection mitigation:**
1. The CI gate on `test_state_root_namespaces.sh` (12/12 PASS) is per-namespace, not per-field. A new field within an existing namespace (e.g., adding a `last_active_height` field to `AccountState`) requires updating the `a:` value-hash encoding — easy to forget. Mitigation: code review of any change touching `include/determ/chain/state.hpp` (AccountState, StakeEntry, RegistryEntry, DAppEntry, AbortRecord, MergePartnerInfo definitions) MUST also touch `build_state_leaves` in the matching block.
2. A new namespace addition (e.g., a `t:` namespace for some new per-tx-id state) requires updating PROTOCOL.md §4.1.1 + `build_state_leaves` + `test_state_root_namespaces.sh` + `serialize_state` + `restore_from_snapshot` in tandem. The S-037 lesson stands: any one of these touched without the others creates a coverage gap. **S-041 is the second concrete instance of exactly this risk** — the three `k:` merge thresholds were present in `build_state_leaves` + PROTOCOL.md §4.1.1 but absent from `serialize_state` / `restore_from_snapshot`, the precise "one surface touched without the others" failure mode this section predicts. It was sub-namespace rather than whole-namespace (the `k:` namespace was emitted, but three of its scalars were not), which is why `test_state_root_namespaces.sh`'s per-namespace coverage did not catch it — the gap surfaced from `SnapshotDeterminismComposition.md`'s structural SD-3 argument instead.

**Closure mechanism:** the pattern is now established (S-037 + S-038 + S-041), and the four-surface threading is the discipline. S-041 sharpens the lesson: per-*namespace* coverage tests (`test_state_root_namespaces.sh`) do not catch a per-*scalar* omission within an emitted namespace; the regression guard for that is a round-trip test that sets **non-default** values for every genesis-pinned scalar (now done by `test-snapshot-roundtrip` #10b + `test-snapshot-full-determinism`). A future audit checklist item should explicitly enumerate the surfaces AND require non-default-value round-trip coverage for every `k:` scalar.

### 6.4 The `committed_state_view_` lock-free read cache is downstream-of-state, not in S

`committed_state_view_` (chain.hpp:568-569) is a A9 Phase 2C derived view materialized from `accounts_ / stakes_ / registrants_ / dapp_registry_` at apply commit. It is NOT in `S` because it's a cache, not a source of truth. A bug that mutated `accounts_` but didn't republish the bundle would NOT change `state_root` (state_root commits to `accounts_` directly), but RPC consumers via `*_lockfree()` accessors would read stale data — a soundness gap for the API surface, but a separate concern from state_root coverage.

The discipline: any path that mutates `accounts_` / `stakes_` / `registrants_` / `dapp_registry_` outside of `apply_transactions` (e.g., genesis init, snapshot restore) must also republish the bundle. `serialize_state` is a const read so no republish needed; `restore_from_snapshot` republishes at chain.cpp:1917-1928. This is correct.

### 6.5 Per-tx-payload deep state (out of state_root scope)

Transaction payloads (e.g., `Transaction.payload` for DAPP_REGISTER, PARAM_CHANGE) are bound into the block's `tx_root` (per-tx Merkle root in `signing_bytes`), not into `state_root`. The post-apply effect of a tx (e.g., a new DApp registration's fields) IS in the `d:` namespace; the raw payload bytes are not. This is by design: payload bytes are an immutable input to the apply path, while state is the mutable output. Two different payloads producing identical post-apply state (e.g., two PARAM_CHANGEs activating the same value at the same height) would yield the same `state_root` post-activation — but the block hashes differ because `tx_root` differs.

### 6.6 No non-membership proofs

The current sorted-leaves Merkle tree supports membership proofs (`state_proof` RPC returns a sibling-hash path for a given key). It does NOT natively support non-membership proofs — a light client cannot prove "account 'eve' does not exist" without querying multiple peers and relying on majority consensus. A future SMT (sparse Merkle tree) migration would add non-membership proofs; the wire format (`Hash state_root`) would not change because only the computation changes. The migration is tracked as a v2 evolution; not required for T-1..T-5's apply-time-gate soundness.

---

## 7. Comparison to alternative designs

We surveyed three alternatives during the v2.1 / S-033 design phase; this section records the trade-off analysis.

**Alternative 1: Sparse Merkle Tree (SMT).** Each leaf is keyed by `SHA-256(state-key)` (a 256-bit address); the tree is sparse and balanced by key-hash addressing rather than by sort order. Pros: native non-membership proofs (every key has a canonical position; absence is a proof against that position). Cons: more complex (sparse-tree update primitives are non-trivial; off-the-shelf libraries are heavier than the determ codebase's existing balanced-Merkle helper); audit-friendliness is degraded because the namespace-prefix structure is no longer visible at the key layer (every key is a hash). **Rejected** for v2.1; the v2 evolution path may revisit once non-membership proofs become a hard requirement.

**Alternative 2: Patricia Trie (radix tree).** Same trade-offs as SMT plus additional implementation complexity for the radix-merging logic. **Rejected** for similar reasons.

**Alternative 3: Single flat sorted leaves, no namespace prefix.** Every leaf keyed by domain alone (e.g., `"alice"` for both `accounts_["alice"]` and `stakes_["alice"]`). Pros: simpler keys; smaller wire overhead. Cons: collision-prone — two different state slices with the same domain (e.g., an account holder also being a registrant) would produce the same leaf key, and the value-hash would have to combine both contributions, leaking the namespace structure into the value encoding. Adding a new state map (e.g., the dapp_registry in v2.18) would force a re-design of every existing leaf's value encoding. **Rejected** — the namespace-prefix design is what makes adding new state maps a localized change (just add a new `n:` namespace) without rippling through existing encodings.

The chosen design — sorted-leaves balanced binary Merkle tree with namespace-prefixed keys — is the simplest design that supports membership proofs, audit-friendly per-namespace inspection, and per-namespace evolution (S-037's `d:` namespace was added without touching any other namespace's encoding).

---

## 8. Test-suite citation

| Test | Theorem coverage |
|---|---|
| `tools/test_state_root.sh` (3 assertions via RPC + cross-node observation) | T-3 supporting: same node + same height ⇒ same root (determinism). Cross-node convergence is structurally exercised by every multi-node test in `tools/test_*.sh`. |
| `tools/test_state_root_namespaces.sh` (12 assertions) | T-1 primary: exhaustive 10-namespace mutation-changes-root coverage. The lock-in regression for §6.3's coverage discipline. Each of the ten namespaces has one assertion ("per-namespace mutation X changes root"); two cross-namespace assertions confirm baseline equality + no-accidental-collision. |
| `tools/test_state_proof_namespaces.sh` (9 assertions) | T-2 primary: cross-namespace inclusion-proof verification rejects swaps (a `s:`-key with `a:`-value_hash fails `merkle_verify` because the leaf is hashed with the swapped key, producing a different sibling chain). |
| `tools/test_state_root_unit.sh` | T-3 supporting: byte-canonical determinism + domain-separation between namespaces + sorted-order Merkle tree branch coverage. |
| `tools/test_chain_apply_block.sh` | T-4 positive coverage: an honestly-produced block's `state_root` matches `compute_state_root` post-apply; the gate passes. |
| `tools/test_snapshot_bootstrap.sh` | T-5 primary: snapshot tail-head's `state_root` matches receiver's freshly-restored `compute_state_root()` end-to-end. |
| `tools/test_snapshot_roundtrip.sh` (15 assertions) | T-5 supporting: `serialize_state(restore_from_snapshot(snap)) == snap` round-trip identity. |
| `tools/test_snapshot_then_apply.sh` (21 assertions) | T-4 + T-5 composition: post-restore replay matches control-chain state_root + balances + nonces at every height. The cross-chain convergence assertion across snapshot bootstrap. |
| `tools/test_dapp_snapshot.sh` (12 assertions) | T-5 specific to `d:` namespace (S-037 + S-038 paired closure). Strict assertion that the snapshot tail-head's stored `state_root` is non-empty in JSON AND matches the receiver's `compute_state_root()` after restore. Pre-S-037 + pre-S-038, this assertion would have failed — proving the paired closure works end-to-end. |
| `tools/test_chain_integrity.sh` (4 assertions) | T-5 cross-check: S-021 wrap + load-time tampering rejection. |
| `determ test-state-root-namespaces` (12 in-process assertions, sibling to the shell wrapper) | T-1 + T-2 in-process coverage of every namespace's per-namespace mutation invariant. |
| `determ test-state-proof-namespaces` (9 in-process assertions) | T-2 in-process coverage of cross-namespace inclusion-proof + swap rejection. |
| `determ test-domain-separation` (20 assertions) | T-4 supporting: `state_root` mutation leaves `block_digest` unchanged AND changes `Block::compute_hash`. Confirms that S-038's wiring doesn't break K-of-K signatures (state_root post-population doesn't invalidate gathered digest signatures because `compute_block_digest` excludes state_root per PROTOCOL.md §4.3). |
| `determ test-block-hash` (16 assertions) | T-4 supporting: `signing_bytes` + `compute_hash` full field coverage including the zero-skip for `state_root`. Confirms that the block hash binds the state commitment transitively forward via the next block's `prev_hash`. |

The composite test discipline: the per-namespace assertions in `test_state_root_namespaces.sh` form the audit anchor; any new namespace must be added there in tandem with `build_state_leaves`, PROTOCOL.md §4.1.1, `serialize_state`, and `restore_from_snapshot` (the four-surface threading per §6.3).

---

## 9. Status

**Shipped (analytic coverage proof).** The ten-namespace coverage is shipped in the current `main` branch:

- **Namespace emission:** `src/chain/chain.cpp:267-411` (`build_state_leaves`) — ten namespaces with documented encoding per §2.1.
- **State_root primitive:** `src/chain/chain.cpp:413-415` (`compute_state_root`).
- **Apply-time gate:** `src/chain/chain.cpp:1421-1446` (the T-4 verification mechanism).
- **Snapshot round-trip:** `src/chain/chain.cpp:1541-1701` (`serialize_state`) + `src/chain/chain.cpp:1703-1932` (`restore_from_snapshot`) + the post-restore gate at chain.cpp:1893-1911 (T-5).
- **Producer wiring:** `src/node/node.cpp:1024-1117` (`try_finalize_round`'s tentative-chain dry-run, the S-038 closure).

Regression coverage as described in §8.

**The coverage theorem is analytic.** This proof does not change any code; it consolidates the namespace-coverage argument so an external auditor can confirm without re-reading every apply-path branch that the ten namespaces collectively cover every apply-determining state field. The S-037 lesson — that a single missing surface (snapshot emission) on an already-emitted namespace silently undermines the entire commitment — generalizes to the surface-discipline statement in §6.3.

**Known limitations** as registered in §6:

- Pre-S-038 historical blocks bypass T-4 (intentional backward-compat; `BlockchainStateIntegrity.md` §6.1).
- Future new state fields must be threaded into `build_state_leaves`, PROTOCOL.md §4.1.1, `serialize_state`, `restore_from_snapshot`, and the per-namespace regression — locked in by `test_state_root_namespaces.sh`.
- No native non-membership proofs (SMT migration is a v2 evolution; not required for T-1..T-5).
- Per-tx payload bytes are bound by `tx_root`, not `state_root` — different surfaces.

**Future composition.** This proof is the namespace-surface foundation; `BlockchainStateIntegrity.md` (T-1..T-5) composes it with the at-rest / produce / receive surface decomposition; `SnapshotEquivalence.md` (FA-Apply-2) extends to the snapshot pathway; `MultiEventComposition.md` (FA-Apply-15 T-M4) consumes T-1's coverage to argue per-block joint state-root binding across heterogeneous event types. A future v2.7 F2 closure (`F2-SPEC.md`) sits ABOVE T-4 at the consensus-layer, providing pre-apply detection of state-divergent block proposals; T-4 remains the structural safety net.

---

## 10. References

### SECURITY.md sections

- `docs/SECURITY.md` §S-033 — state_root Merkle commitment + apply-time gate (the namespace-coverage data-layer half).
- `docs/SECURITY.md` §S-037 — dapp_registry snapshot gap closure (the canonical example of T-5's coverage discipline).
- `docs/SECURITY.md` §S-038 — producer-side state_root population (T-4 wiring).
- `docs/SECURITY.md` §S-021 — chain.json wrap + load-time recompute (sister state-integrity surface, `BlockchainStateIntegrity.md` T-1).
- `docs/SECURITY.md` §S-030 D1 + D2 — broader consensus-safety closure that consumes T-4 + T-5 as components.

### Implementation sites

- `src/chain/chain.cpp:267-411` — `Chain::build_state_leaves` (ten-namespace leaf generator).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root` (central S-033 primitive).
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (light-client membership-proof counterpart).
- `src/chain/chain.cpp:1421-1446` — the S-033 apply-time gate (T-4 mechanism).
- `src/chain/chain.cpp:1541-1701` — `Chain::serialize_state` (T-5 producer-side; S-037 closure at 1653-1669).
- `src/chain/chain.cpp:1703-1932` — `Chain::restore_from_snapshot` (T-5 consumer-side; S-037 closure at 1818-1834; post-restore gate at 1893-1911).
- `src/node/node.cpp:1024-1117` — `Node::try_finalize_round` (T-4 producer wiring; S-038 closure at 1093-1117).
- `include/determ/chain/chain.hpp:235-270` — `Chain::compute_state_root` declaration + namespace key-encoding documentation.
- `include/determ/chain/chain.hpp:295-302` — `Chain::StateProof` struct (light-client RPC return type).
- `include/determ/chain/chain.hpp:539-624` — the full Chain mutable-state field list (the universe `S` enumerated by T-1).
- `include/determ/chain/block.hpp:460-484` — `Block.state_root` field declaration.

### Companion proofs

- `docs/proofs/Preliminaries.md` (F0) — §2.1 SHA-256 collision resistance (A2).
- `docs/proofs/BlockchainStateIntegrity.md` — the four-surface composition theorem that consumes T-1..T-5 as the namespace-coverage half.
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — apply determinism (T-4's invocation).
- `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) — snapshot-pathway sibling proof.
- `docs/proofs/AppliedReceiptRestore.md` (FA-Apply-12) — `i:`-namespace cross-shard restore correctness contract.
- `docs/proofs/MultiEventComposition.md` (FA-Apply-15 T-M4) — per-block joint state-root binding across heterogeneous events.
- `docs/proofs/DAppRegistryLifecycle.md` — `d:`-namespace lifecycle (S-037 closure narrative).
- `docs/proofs/WireFormatBackwardCompat.md` C-2 — zero-skip backward-compat shim on `state_root`.
- `docs/proofs/S030-D2-Analysis.md` §3.5 — the D1/D2 closure context that consumes T-4 + T-5 as inputs.

### Tests

- `tools/test_state_root.sh` + `tools/test_state_root_namespaces.sh` + `tools/test_state_proof_namespaces.sh` + `tools/test_state_root_unit.sh` — T-1 + T-2 + T-3 commitment-algebra coverage.
- `tools/test_snapshot_bootstrap.sh` + `tools/test_snapshot_roundtrip.sh` + `tools/test_snapshot_then_apply.sh` + `tools/test_dapp_snapshot.sh` — T-5 round-trip + producer/receiver symmetry over the snapshot surface.
- `tools/test_chain_apply_block.sh` + `tools/test_chain_integrity.sh` — T-4 positive coverage + S-021 wrap sister.
- `determ test-state-root-namespaces` (12 in-process assertions) + `determ test-state-proof-namespaces` (9 in-process assertions) — T-1 + T-2 in-process coverage.
- `determ test-domain-separation` + `determ test-block-hash` — T-4 supporting (signing_bytes / block_digest exclusion fence + state_root binding in compute_hash).

### TLA+ companions

- `docs/proofs/tla/BlockchainStateIntegrity.tla` (FB26) — the state-machine sibling spec covering T-1..T-5 of `BlockchainStateIntegrity.md` (the at-rest / produce / receive surface composition this proof's T-4 + T-5 sit inside).

### Specifications

- `docs/PROTOCOL.md` §4.1.1 — the canonical ten-namespace key + value encoding table (wire-level contract).
- `docs/PROTOCOL.md` §4.3 — `compute_block_digest` exclusion list (confirms state_root is OUT of digest, IN of signing_bytes; T-4 supporting).
- `docs/PROTOCOL.md` §10.2 — `state_proof` RPC (light-client query interface).
- `docs/PROTOCOL.md` §11 — snapshot serialization format (the T-5 wire surface).
- `docs/V2-DESIGN.md` v2.1 + v2.3 — full design rationale for the namespace-prefix scheme + the rejected SMT / Patricia / flat-key alternatives.
- NIST FIPS 180-4 — SHA-256 (referenced by A2).
