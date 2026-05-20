# FA-Apply — Snapshot ↔ replay equivalence

This document formalizes the property that fast-bootstrap from a snapshot is observationally equivalent to a full chain replay from genesis. Concretely: a node that loads a snapshot taken at chain tip `C_k` and then appends blocks `B_{k+1}, …, B_n` produces a chain state byte-identical (modulo timestamp metadata on the snapshot envelope itself) to a node that replayed `genesis + B_1 + … + B_n` from scratch. The property underwrites Determ's fast-sync path (`SNAPSHOT_RESPONSE` gossip + operator-pinned `snapshot_path` config), the B6.basic offline-bootstrap workflow, and the light-client foundation in v2.2 (`state_proof` RPC consumes the same Merkle commitment that this equivalence depends on).

The proof is mechanical: every chain field that contributes to the S-033 state-root commitment is enumerated, the snapshot serializer is shown to persist every such field, the restorer is shown to load every such field, and the apply path is shown to be a pure function of (prior state, block) for a fixed block — so two chains whose prior state is byte-identical and which apply the same block produce a byte-identical posterior state. The strength is consolidation: snapshot equivalence is implicit in S-012 + S-033 + S-037 + S-038 closures, but those findings address it from a defensive ("snapshot tampering rejected") angle. Here we state and prove the constructive direction: an honest snapshot restores to a state that genuinely reproduces the original chain's apply behavior.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the block-validity definition; `AccountStateInvariants.md` (FA-Apply) for the per-account invariants I-1 through I-6 that the apply path preserves and that snapshot restore must preserve to keep replay equivalence intact; `Safety.md` (FA1) for the chain-anchor identity that the snapshot's tail header carries via `compute_hash`; `CrossShardReceipts.md` (FA7) for the destination-side dedup set whose restore is covered separately under the V13 invariant.

---

## 1. Setup

### 1.1 Snapshot object

A snapshot is a JSON object emitted by `Chain::serialize_state(uint32_t header_count) const` at `src/chain/chain.cpp:1541`. Its schema is documented in `PROTOCOL.md` §11 and consists of three structural parts:

1. **A version envelope** — `version = 1` (literal integer), `block_index` (u64 = tail height), `head_hash` (hex string = `compute_hash(B_n)`).
2. **Mutable state collections** — `accounts[]`, `stakes[]`, `registrants[]`, `applied_inbound_receipts[]`, `abort_records[]`, `merge_state[]`, `pending_param_changes[]`, `dapp_registry[]` (S-037-restored field).
3. **Genesis-pinned + governance-mutable scalars** — `block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, `lottery_jackpot_multiplier`, `min_stake`, `suspension_slash`, `unstake_delay`, `shard_count`, `shard_salt`, `shard_id` plus the five A1 counters (`genesis_total`, `accumulated_subsidy`, `accumulated_slashed`, `accumulated_inbound`, `accumulated_outbound`).
4. **Tail-header chain** — `headers[]`: the last `header_count` blocks in full Block JSON, preserving each one's S-033 `state_root` field.

Let `serialize : Chain → SnapshotJSON` and `restore : SnapshotJSON → Chain` denote the two functions. Write `snap_k = serialize(C_k)` for a snapshot taken at tip `B_k`. Write `restore_from_snapshot` for `restore`. The verification gates inside `restore` are:

- **G1** `head_hash` match (`chain.cpp:1855–1862`) — `compute_hash(loaded_tail) == snap.head_hash`.
- **G2** `state_root` match (`chain.cpp:1893–1911`) — `compute_state_root(loaded_state) == loaded_tail.state_root`, skipped iff the tail's `state_root` field is the all-zero sentinel (backward-compat path for pre-S-033/S-038 blocks).

A snapshot that fails G1 or G2 throws and produces no chain. Throughout this document, "valid snapshot" means a snapshot produced by `serialize` on a Chain whose tail block was produced by a post-S-038 `Node::try_finalize_round` — equivalently, any snapshot whose tail head carries a non-zero `state_root`.

### 1.2 State-equivalence relation

Two Chains `C` and `C'` are **state-equivalent**, written `C ≡_S C'`, iff:

1. `C.accounts_ == C'.accounts_` (map equality: same key set, same `AccountState` values).
2. `C.stakes_ == C'.stakes_`, `C.registrants_ == C'.registrants_`, `C.dapp_registry_ == C'.dapp_registry_`, `C.applied_inbound_receipts_ == C'.applied_inbound_receipts_`, `C.abort_records_ == C'.abort_records_`, `C.merge_state_ == C'.merge_state_`, `C.pending_param_changes_ == C'.pending_param_changes_`.
3. All scalar constants (`block_subsidy_`, `min_stake_`, `suspension_slash_`, `unstake_delay_`, `shard_count_`, `shard_salt_`, `my_shard_id_`, `subsidy_pool_initial_`, `subsidy_mode_`, `lottery_jackpot_multiplier_`) coincide.
4. All A1 counters (`genesis_total_`, `accumulated_subsidy_`, `accumulated_slashed_`, `accumulated_inbound_`, `accumulated_outbound_`) coincide.
5. `compute_state_root(C) == compute_state_root(C')`.

`≡_S` is finer than what an external observer can distinguish via RPC, but coarser than literal C++ struct identity (it excludes the `blocks_` vector tail-length and the lock-free bundle pointer, neither of which is consumed by `apply_transactions`). The Chain fields excluded from `≡_S` are either re-derivable (`live_total_supply` is a fold over `accounts_` + `stakes_`) or are scratch buffers that do not influence the apply path (`committed_state_view_` is a read-side cache populated post-restore at `chain.cpp:1917–1927`).

**Equivalence is preserved by apply.** For any valid block `B`, if `C ≡_S C'` then `apply_transactions(C, B) ≡_S apply_transactions(C', B)`. This is a corollary of `apply_transactions` being a pure function of its inputs (the prior `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`, applied-receipt set, abort cache, merge-state, pending-param-changes, constants, and counters — every field enumerated in §1.1 part (1)+(2)+(3)+(4)). No apply-path branch consults `blocks_` directly except to read `blocks_.back().prev_hash` for the V1 chain-link check, which is identical on both sides because G1 forces them to share the same tail.

### 1.3 Genesis-init fields that snapshot omits

Snapshots do not persist:

- The `blocks_` vector beyond the trailing `header_count` window (default 16). The trailing window is enough to satisfy V1 (`prev_hash == compute_hash(blocks_.back())`) for the next block.
- The `committed_state_view_` lock-free bundle pointer (regenerated by `restore` at `chain.cpp:1917–1927`).
- Process-local scratch (mempool, peer connections, RPC state) — these are properties of the node, not the chain.

Equivalence claims below are stated up to these omissions; they do not affect the apply path or the state-root commitment.

---

## 2. Coverage lemma — every state-root contributor is persisted

The S-033 state-root commitment is the union of leaves emitted by `Chain::build_state_leaves` (`chain.cpp:267`). The function emits leaves across ten namespaces (PROTOCOL.md §4.1.1):

| Prefix | Source map / field | Snapshot field |
|---|---|---|
| `a:` | `accounts_[domain]` → `(balance, next_nonce)` | `accounts[]` |
| `s:` | `stakes_[domain]` → `(locked, unlock_height)` | `stakes[]` |
| `r:` | `registrants_[domain]` → `(ed_pub, registered_at, active_from, inactive_from, region)` | `registrants[]` |
| `d:` | `dapp_registry_[domain]` → all v2.18 fields | `dapp_registry[]` (S-037) |
| `i:` | `applied_inbound_receipts_` → `(src_shard, tx_hash)` presence | `applied_inbound_receipts[]` |
| `b:` | `abort_records_[domain]` → `(count, last_block)` | `abort_records[]` (S-032) |
| `m:` | `merge_state_[shard_id]` → `(partner_id, refugee_region)` | `merge_state[]` |
| `p:` | `pending_param_changes_[eff][idx]` → `(name, value)` | `pending_param_changes[]` |
| `k:` | scalar constants × 12 (subsidy / min_stake / shard / merge thresholds) | individual scalar fields |
| `k:c:` | A1 counters × 5 (`genesis_total` etc.) | individual scalar fields |

**Lemma L-S0 (Snapshot coverage of state-root namespaces).** For every leaf `L` emitted by `build_state_leaves(C)`, the snapshot `serialize(C)` carries every byte that contributes to `L`'s key or value-hash.

*Proof.* By inspection of `serialize_state` (`chain.cpp:1541–1700`). The function iterates over each of the ten backing data sources in turn and emits a JSON entry per element with all fields used by the corresponding `build_state_leaves` branch:

- The `accounts_` loop at lines 1551–1557 emits `{domain, balance, next_nonce}` — the exact triple `build_state_leaves` consumes at lines 285–289.
- The `stakes_` loop (1561–1567) emits `{domain, locked, unlock_height}` — matches lines 292–296.
- The `registrants_` loop (1571–1582) emits every field consumed at lines 299–307 including `region` (R1) and `ed_pub` (the v2.16 ed25519 verification key).
- The `dapp_registry_` loop (1654–1668), added by S-037 closure, emits every field consumed at lines 312–329 including the variable-length `topics[]` array and the `metadata` byte vector.
- The `applied_inbound_receipts_` loop (1586–1591) emits `{src_shard, tx_hash}` — the `(src, tx_hash)` pair consumed at lines 332–340.
- The `abort_records_` loop (1623–1629) emits `{domain, count, last_block}` — matches lines 343–347.
- The `merge_state_` loop (1638–1644) emits `{shard_id, partner_id, refugee_region}` — matches lines 350–359.
- The `pending_param_changes_` loop (1672–1684) emits `{effective_height, entries: [{name, value}]}` — matches lines 362–377.
- The scalar `k:` constants (lines 1597–1608) are persisted one per field; `build_state_leaves` consumes them via the `const_leaf` helper (lines 385–401).
- The A1 counters `k:c:` (lines 1614–1618) are persisted one per field; `build_state_leaves` consumes them at lines 404–408.

No field consumed by `build_state_leaves` is absent from `serialize_state`; no field emitted by `serialize_state` is dropped on the receive side (see L-S1 below). ∎

The S-037 row in this table is load-bearing: pre-S-037 closure, snapshots emitted no `dapp_registry` field, so the `d:` namespace contributed leaves on the producer side that the receiver could not reconstruct, causing `compute_state_root(restored) ≠ tail.state_root` and rejecting the snapshot under G2. The closure shipped the matching emit + restore loops together; both are required for L-S0 to hold.

**Lemma L-S1 (Restorer recovers every persisted field).** For every key `k` written by `serialize_state` whose presence affects `build_state_leaves`, `restore_from_snapshot` reads `k` back into the same backing map / scalar. Missing fields default to the empty / zero value that `build_state_leaves` treats as "no leaf in this slot."

*Proof.* By inspection of `restore_from_snapshot` (`chain.cpp:1703–1933`). Each `if (snap.contains(...))` guard wraps a load loop into the corresponding map (lines 1748 / 1756 / 1764 / 1778 / 1786 / 1801 / 1818 / 1835); each scalar `snap.value("name", default)` loads into the corresponding field (lines 1712–1735). The `value(key, default)` form preserves backward compatibility: a legacy snapshot omitting one of the optional fields restores to the same empty default that an unmodified Chain would have, which produces zero leaves in that namespace on both sides. The default values for `min_stake`, `suspension_slash`, `unstake_delay` are pre-A5 (`{1000, 10, 1000}`), matching the legacy chain's initial values. ∎

---

## 3. Theorems

### T-S1 — Serialization-restore identity

**Statement.** For every valid Chain `C` (one obtained by replaying genesis followed by zero or more validly-applied blocks via `apply_transactions`):

```
restore_from_snapshot(serialize_state(C, header_count)) ≡_S C
```

for any `header_count ≥ 1`.

*Proof.* Coverage (L-S0) shows every state-bearing field appears in `snap = serialize_state(C)`. The restore path (L-S1) loads every such field into the same backing map / scalar position. The five equivalence-class conditions in §1.2 are then witnessed directly:

1. `accounts_` equality — `serialize_state` enumerates `C.accounts_` in `std::map` sorted order; `restore_from_snapshot` inserts each entry into the fresh `c.accounts_` map. Because `std::map` is keyed by `std::string` and the restorer uses `c.accounts_[domain] = s`, the final map has the same key set and same `AccountState` values.
2–4. Identical arguments for `stakes_`, `registrants_`, `dapp_registry_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `pending_param_changes_`, plus the scalar constants and counters.
5. `compute_state_root` equality follows from (1)–(4) plus the fact that `build_state_leaves` is a deterministic function of those eight maps + 17 scalars; identical inputs produce identical leaves and `merkle_root` is deterministic over a sorted-by-key leaf set.

The receiver also satisfies G1 (`head_hash` recompute matches because the tail block was re-deserialized from its own JSON via `Block::from_json` and `compute_hash` is a pure function of the block's signing bytes) and G2 (the state-root recompute matches by argument (5) above). ∎

**Code witness.** `src/chain/chain.cpp:1541` (`serialize_state`), `src/chain/chain.cpp:1703` (`restore_from_snapshot`), `src/chain/chain.cpp:267` (`build_state_leaves`).

**Test witness.** `tools/test_snapshot_roundtrip.sh` (14 assertions across 5 blocks, including the central S-033/S-037/S-038 assertion that `compute_state_root` is preserved across round-trip) + `tools/test_snapshot_defense.sh` (S-018 hardening — wrong-type collection fields rejected, baseline round-trip succeeds).

### T-S2 — Apply-after-restore equivalence

**Statement.** Let `C_n = genesis ⨁ apply(B_1) ⨁ apply(B_2) ⨁ … ⨁ apply(B_n)` be the full-replay chain. Let `k < n` and define:

```
C'_n = restore_from_snapshot(serialize_state(C_k)) ⨁ apply(B_{k+1}) ⨁ … ⨁ apply(B_n)
```

If every `B_i` (`k < i ≤ n`) satisfies `BlockValidator::validate` against the corresponding prefix chain, then:

```
C_n ≡_S C'_n
```

In particular, `compute_state_root(C_n) == compute_state_root(C'_n)`, `compute_hash(blocks_.back()) on both sides coincide`, and for every domain `d` the per-account `accounts_[d]` and per-stake `stakes_[d]` values are identical.

*Proof.* By induction on `j = n − k`.

**Base case (j = 0).** No post-restore blocks applied. `C'_k ≡_S C_k` by T-S1.

**Inductive step.** Assume `C_{k+j} ≡_S C'_{k+j}` for some `j ≥ 0`. We show `apply(C_{k+j}, B_{k+j+1}) ≡_S apply(C'_{k+j}, B_{k+j+1})`.

`apply_transactions` is a pure function of the prior chain state's eight backing maps + 17 scalars + the block argument. Concretely, every read inside `apply_transactions` (`chain.cpp:633–1502`) consults one of:

- `accounts_[...]`, `stakes_[...]`, `registrants_[...]`, `dapp_registry_[...]` (read for sender authentication, stake checks, registration window checks, DApp routing).
- `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `pending_param_changes_` (read for V13 dedup, S-006 + S-032 evidence-window checks, merge-state cascade, A5 governance activation at this height).
- Scalar constants and counters (read for subsidy distribution, A1 invariant evaluation, fee distribution dust).
- The trailing `blocks_.back()` for the V1 prev-hash check.

Every such read is covered by `≡_S` (§1.2 conditions 1–4); the trailing `blocks_.back()` coincides because G1 forces the snapshot's tail block to be `B_k` byte-identical (the head's JSON serialization round-trips through `Block::from_json` deterministically). The function has no other input — no hidden global state, no entropy from time-of-day, no peer-network reads.

`apply_transactions` is also deterministic in its writes: every `accounts_[d].balance += amount` etc. is gated by computable predicates over the inputs (V15 checks, S-007 overflow checks, nonce gates), and where the gates pass, the magnitude written is a deterministic function of the inputs. Therefore the post-state of the two sides coincides under `≡_S`.

The S-033 + S-038 verification gate at `chain.cpp:1430` is also satisfied identically on both sides: post-S-038, the producer of `B_{k+j+1}` populated `body.state_root` via its own tentative-chain dry-run (`Node::try_finalize_round` at `node.cpp:1111–1113`); this value is what both `C_{k+j}.apply(B_{k+j+1})` and `C'_{k+j}.apply(B_{k+j+1})` compare against, and both produce the same recomputed state-root because their prior states satisfy `≡_S`. ∎

**Code witness.** `src/chain/chain.cpp:633` (`apply_transactions`), `src/chain/chain.cpp:1430` (S-033 + S-038 verification gate), `src/node/node.cpp:1024` (`try_finalize_round` with the tentative-chain dry-run that populates `body.state_root`).

**Test witness.** `tools/test_snapshot_then_apply.sh` — the dedicated regression that exercises exactly this construction (21 assertions across the restore-apply boundary: Chain A replays 5 blocks from genesis, Chain B replays 3 then snapshot-restores then applies 4 + 5, then asserts state_root equality + per-account balance equality + per-account nonce equality + A1 counter equality at every post-restore height). `tools/test_snapshot_bootstrap.sh` exercises the same property end-to-end across a 3-node donor cluster + a fresh receiver bootstrapping from `snapshot_path`.

### T-S3 — Cross-namespace coverage

**Statement.** Snapshot serialization preserves every namespace that contributes to `compute_state_root`. Formally: for each namespace prefix `π ∈ {a:, s:, r:, d:, i:, b:, m:, p:, k:, k:c:}`, mutating any backing data source on the donor side produces a distinct snapshot whose restored chain has a `compute_state_root` differing from the unmutated baseline.

*Proof.* Direct corollary of L-S0 + L-S1 + the fact that `build_state_leaves` emits at least one leaf per namespace's backing change. The leaf-key encoding for each namespace is injective (the prefix byte plus deterministic-encoded data uniquely identifies the source field), and `merkle_root` is collision-resistant under SHA-256 (Preliminaries §2.1), so distinct leaf sets produce distinct roots with probability ≥ 1 − 2⁻¹²⁸. ∎

**Code witness.** `src/chain/chain.cpp:267` (`build_state_leaves`), `src/crypto/random.cpp::merkle_root`.

**Test witness.** `tools/test_state_root_namespaces.sh` — 12 assertions exhaustively exercising all 10 namespaces (one mutation per namespace, asserting the state-root diverges from baseline) + baseline equality + cross-namespace independence (different mutations on different namespaces produce distinct roots). `tools/test_snapshot_then_apply.sh` provides the end-to-end check that a snapshot taken after mutations in every namespace restores to a chain whose state-root matches the donor.

### T-S4 — Idempotent restore

**Statement.** For every valid snapshot `snap`:

```
restore_from_snapshot(serialize_state(restore_from_snapshot(snap))) ≡_S restore_from_snapshot(snap)
```

equivalently: re-serializing a restored chain and restoring the result reproduces the same Chain.

*Proof.* Let `C₁ = restore_from_snapshot(snap)`, `snap₂ = serialize_state(C₁)`, `C₂ = restore_from_snapshot(snap₂)`. By T-S1 applied to `C₁` we have `C₂ ≡_S C₁`. The G1 / G2 gates inside the second restore are satisfied by the same arguments as in T-S1: `C₁`'s tail block was loaded from `snap.headers`, and `serialize_state` re-emits it byte-identically inside `snap₂` because `Block::to_json` is deterministic; the tail's `state_root` field is preserved verbatim. ∎

**Code witness.** Same as T-S1: round-trip identity composes with itself.

**Test witness.** `tools/test_snapshot_roundtrip.sh` exercises the determinism assertion explicitly ("same snapshot → same restored state_root"). The idempotence claim follows from determinism plus T-S1.

### T-S5 — Version-gate soundness

**Statement.** A snapshot whose `version` field is anything other than the integer literal `1` is rejected with a clean diagnostic and produces no Chain. Equivalently: future-version migration paths (`version = 2`, `version = 999`) must explicitly update the version-gate code; legacy snapshots with `version = 0` or missing-version are not silently coerced.

*Proof.* The gate at `chain.cpp:1706–1709` reads `int v = snap.value("version", 0)` and throws `"unsupported snapshot version: " + std::to_string(v)` unless `v == 1`. The `value(key, default)` semantics give `v = 0` for missing-version, which is `≠ 1`, so missing-version is rejected. Negative values, future positive values, and non-integer values that fail to coerce to `int` all fall outside the `v == 1` branch. A separate prior gate (`chain.cpp:1704–1705`) catches non-object input (`if (!snap.is_object())`) before the version field is even read, producing a distinct `"snapshot is not a JSON object"` diagnostic. ∎

**Code witness.** `src/chain/chain.cpp:1704–1709`.

**Test witness.** `tools/test_snapshot_version_rejection.sh` — 10 assertions across 9 scenarios pinning the gate: `version=1` accepted; `version=0` / `version=-1` / `version=999` / missing-version / non-object input / null / string / array / wrong-type version all rejected with the expected error string naming the offending value. The regression locks the gate against silent-coercion drift.

### T-S6 — Determinism of `serialize_state`

**Statement.** For any Chain `C` and any `header_count`, two evaluations of `serialize_state(C, header_count)` on a single thread produce byte-identical JSON objects (modulo the JSON library's stable-key-order property, which is enforced by nlohmann's default `ordered_json` semantics over the manually-inserted top-level keys).

*Proof.* `serialize_state` performs no I/O, no clock reads, no random sampling, no peer queries. It iterates `std::map<std::string, ...>` containers (deterministic sorted-by-key iteration), `std::set<std::pair<ShardId, Hash>>` (deterministic), `std::map<ShardId, ...>` (deterministic), `std::map<uint64_t, ...>` (deterministic), and a few `std::vector` fields whose elements were inserted by the apply path in deterministic order. Every JSON field assigned inside the function is computed from `C`'s state via pure functions (`to_hex`, `compute_hash`, `Block::to_json`). The output is therefore a deterministic function of `(C, header_count)`.

The "modulo timestamp metadata" caveat in the abstract refers to environment metadata an operator-side wrapper might prepend (e.g., `determ snapshot create` adds a creation-time header outside the `serialize_state` return value); the function itself emits no such fields. ∎

**Code witness.** `src/chain/chain.cpp:1541–1701` — every line is either a deterministic field assignment or a deterministic map iteration.

**Test witness.** `tools/test_snapshot_roundtrip.sh` final assertion ("same snapshot → same restored state_root") + `tools/test_state_root_namespaces.sh` baseline-equality assertion (two identical fresh chains produce identical state-roots, which is the same determinism property pushed through `build_state_leaves`).

---

## 4. S-033 + S-038 dependency

Theorems T-S1, T-S3, T-S4, T-S5, T-S6 are stated without reference to S-033 / S-038: they would hold even on a hypothetical Determ revision where blocks carried no state-root field, because the round-trip is purely a property of `serialize_state` + `restore_from_snapshot`.

**T-S2 is the load-bearing exception.** Without S-033 + S-038, the apply-after-restore equivalence does not hold in any operationally useful sense. The argument has two halves:

**Without S-033** (no `body.state_root` field in blocks). A producer could create two blocks `B'_{k+1}` and `B''_{k+1}` with identical `compute_block_digest` (the same transactions, same dh_inputs, same prev_hash) but divergent post-apply states — for example, by including different `equivocation_events[]` or `cross_shard_receipts[]` payloads, which are not bound into `compute_block_digest` (per S-030 D2). Both blocks would carry the same Phase-2 K-of-K signatures (signatures only cover the digest). A snapshot taken after one variant would not be detectably inconsistent with a chain that applied the other variant — both restores would pass G1 (the head hashes coincide because `compute_hash` post-S-033 includes `state_root` in signing_bytes, but pre-S-033 they coincide on digest-equivalent blocks), and there would be no G2 gate to catch divergence. T-S2 would then fail: the donor's "future" applies could diverge from the receiver's, depending on which variant each side observed first.

**Without S-038** (the producer-side wiring that populates `body.state_root` on broadcast). The G2 gate exists in code but never fires on production blocks because `body.state_root` is always the all-zero sentinel; the backward-compat skip at `chain.cpp:1896` triggers unconditionally. A malicious snapshot supplier could ship a snapshot whose tail header carries `state_root = zero` and an `accounts[]` array that diverges arbitrarily from what the chain ever committed to — the receiver would accept it. Post-S-038, the producer populates `state_root` via a tentative-chain dry-run between body assembly and broadcast (`node.cpp:1111–1113`), so every post-S-038 block has a non-zero `state_root` and the G2 gate fires. The combination of S-033 (the field) + S-038 (the producer wiring) is what makes T-S2's claim "apply-after-restore equivalence under restored-chain correctness" not vacuous.

The two findings are explicitly cited in `docs/SECURITY.md` §S-033 (the field definition + apply-side gate) and §S-038 (the producer-side `try_finalize_round` wiring). Both shipped in the same in-session round; the `test_dapp_snapshot.sh` regression exercises the joint surface (a DApp-active chain snapshotted post-S-037, restored, with the receiver's `compute_state_root` strictly compared against the snapshot tail head's stored `state_root` — pre-S-038 this assertion would have been vacuously trivial because the stored field would have been zero).

---

## 5. What this doesn't prove

The equivalence theorems target the snapshot ↔ replay path. They do not extend to:

- **Cross-shard receipt dedup-set restore correctness in isolation.** T-S2 covers it indirectly (V13 reads `applied_inbound_receipts_`, which is restored under L-S1), but the formal at-most-once / at-least-once cross-shard credit property is the scope of `CrossShardReceipts.md` (FA7), which proves the joint correctness of the source-side V12 check + destination-side V13 check + apply-side `applied_inbound_receipts_.insert`. The regression test for this surface specifically is `tools/test_applied_inbound_receipt_restore.sh` (witness — not in this proof's scope).
- **DApp registry semantics post-restore.** T-S2 covers byte-level restore of `dapp_registry_`, which transitively ensures that DAPP_CALL routing, dapp-info RPC, and the `d:`-namespace state-root contribution all behave identically on the receiver. The richer "DApp messaging behavior survives snapshot bootstrap" claim is the scope of S-037 closure and is exercised end-to-end by `tools/test_dapp_snapshot.sh` (12 assertions across donor → snapshot → receiver → dapp-info / dapp-list parity).
- **MITM defense against in-flight snapshot tampering on the gossip wire.** The proof assumes snapshot integrity (no in-flight bit-flips, no malicious peer manufacturing a forged snapshot). The G1 + G2 gates catch any tamper that produces an internally-inconsistent snapshot, but they do not authenticate the snapshot's provenance — a malicious peer could supply a self-consistent snapshot of a chain it forged from a fork point. Operator-policy is the current defense (cross-check `head_hash` against a trusted source before accepting `snapshot_path`). A future v2.x item adds signed snapshot envelopes (one committee member signs `serialize_state` output as a wire-level attestation); this is tracked in `docs/V2-DESIGN.md` as a follow-on to the v2.2 light-client work but is not in this proof's scope.
- **Snapshot persistence durability.** Writing the snapshot JSON to disk is the operator's responsibility (or `determ snapshot create`'s shell-level write). Atomicity of `chain.save` is covered separately by the A9 atomic-save invariant in `EconomicSoundness.md` §3; snapshots use the same atomic write-and-rename path but the durability property is orthogonal to equivalence.
- **Apply correctness of the post-restore blocks themselves.** T-S2 assumes each `B_{k+1}, …, B_n` is `BlockValidator::validate`-valid against the corresponding prefix. If one of the post-restore blocks is invalid, both replay and restore-then-apply will reject it identically (V1–V15 are pure functions of the prior chain, and the prior chain is `≡_S` on both sides by induction), so the equivalence still holds at the boundary up to the rejection point.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V1–V15; the snapshot-restore path validates the tail block under V1 + S-033's G1 + G2. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 through I-6 hold on the restored chain because their preservation is a function of the maps that L-S0 / L-S1 preserve. The induction in T-S2 inherits I-X preservation from the apply path. |
| `Safety.md` (FA1) | T-S2's apply-after-restore equivalence depends on `compute_hash` covering `state_root` in signing_bytes — the chain-identity claim of FA1 is what makes G1 a meaningful gate. |
| `CrossShardReceipts.md` (FA7) | V13 dedup-set restore is covered by L-S0 / L-S1 row `i:`; the at-most-once credit property is FA7's scope. |
| `S030-D2-Analysis.md` | The D2 attack vector (block-body fields not bound into `block_digest`) is closed at the apply layer by the S-033 + S-038 mechanism that T-S2 depends on. Section 3.5 of S030-D2-Analysis lists exactly which fields are protected via this path. |
| `docs/SECURITY.md` §S-012 | Snapshot bootstrap state-root verification — the security finding behind G2; closed by S-033 + S-038. |
| `docs/SECURITY.md` §S-033 | Merkle state commitment + Block.state_root + signing_bytes binding + apply / restore verification. |
| `docs/SECURITY.md` §S-037 | DApp registry serialize/restore — the L-S0 / L-S1 row `d:` is the closure. |
| `docs/SECURITY.md` §S-038 | Producer-side wiring that populates `body.state_root` on broadcast; without it, the G2 gate would be dormant and T-S2 vacuous. |
| `docs/PROTOCOL.md` §11 | Snapshot wire format (the `SnapshotJSON` schema from §1.1). |
| `tools/test_snapshot_roundtrip.sh` | T-S1, T-S4, T-S6 (14 assertions). |
| `tools/test_snapshot_then_apply.sh` | T-S2 — the canonical apply-after-restore equivalence regression (21 assertions). |
| `tools/test_state_root_namespaces.sh` | T-S3 — all 10 state-root namespaces exercised (12 assertions). |
| `tools/test_snapshot_version_rejection.sh` | T-S5 (10 assertions). |
| `tools/test_snapshot_bootstrap.sh` | End-to-end 3-node donor + fresh receiver fast-bootstrap path (operator-facing). |
| `tools/test_snapshot_defense.sh` | S-018 hardening — wrong-type collection fields rejected (11 assertions). |
| `tools/test_dapp_snapshot.sh` | S-037 joint surface — DApp-active chain snapshot → restore → state-root parity (12 assertions). |
| `src/chain/chain.cpp:1541` | `Chain::serialize_state` implementation. |
| `src/chain/chain.cpp:1703` | `Chain::restore_from_snapshot` implementation. |
| `src/chain/chain.cpp:267` | `Chain::build_state_leaves` (Merkle-leaf enumeration). |
| `src/chain/chain.cpp:413` | `Chain::compute_state_root`. |
| `src/chain/chain.cpp:1430` | Apply-side S-033 + S-038 verification gate. |
| `src/chain/chain.cpp:1893` | Restore-side S-033 + S-038 verification gate (G2). |
| `src/node/node.cpp:1024` | `Node::try_finalize_round` — the S-038 producer-side wiring. |

---

## 7. Status

All six theorems (T-S1 through T-S6) are closed in the current codebase:

- **T-S1** closed via coverage lemma L-S0 + L-S1 in §2; regressions `test_snapshot_roundtrip.sh` + `test_snapshot_defense.sh`.
- **T-S2** closed via T-S1 + apply-path determinism + S-033 + S-038; regression `test_snapshot_then_apply.sh`.
- **T-S3** closed via L-S0 + injective per-namespace key encoding + SHA-256 collision resistance; regression `test_state_root_namespaces.sh`.
- **T-S4** closed via T-S1 composition; determinism assertion in `test_snapshot_roundtrip.sh`.
- **T-S5** closed via the version-gate code at `chain.cpp:1706–1709`; regression `test_snapshot_version_rejection.sh`.
- **T-S6** closed via inspection of `serialize_state` (no I/O, no clock, no entropy) + deterministic STL container iteration; baseline-equality assertions throughout the snapshot test suite.

No theorem is open or partial. The proof's foundation rests on the S-033 + S-038 closures shipped earlier in-session; the matching `test_dapp_snapshot.sh` regression provides end-to-end witness that the producer-side wiring (S-038) actually populates `state_root` on broadcast — without which T-S2 would be vacuous and the entire fast-bootstrap path would be unauthenticated against state-divergence attacks.
