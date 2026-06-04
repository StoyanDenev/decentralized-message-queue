# ParamChangeDeterminism — `p:` governance-namespace apply + snapshot + activation determinism (PC-1..PC-3)

This document proves three theorems that pin the determinism of the `p:` (`pending_param_changes_`) governance namespace as a state-commitment surface: (PC-1) **apply-determinism of staging** — replaying the same PARAM_CHANGE transaction multiset against byte-identical starting state produces a byte-identical `pending_param_changes_` map on every node; (PC-2) **snapshot round-trip identity** — `serialize_state → restore_from_snapshot` preserves every `p:` entry and reproduces `compute_state_root` byte-for-byte; (PC-3) **deterministic height-triggered activation** — `activate_pending_params` drains exactly the staged entries whose `effective_height ≤ b.index`, in canonical order, identically on every node. The three theorems compose the `p:`-slice of `S033StateRootNamespaceCoverage.md` (10-namespace coverage completeness) and `SnapshotDeterminismComposition.md` (all-namespace round-trip determinism) into a single namespace-scoped statement, and absorb the **S-041 lesson** that per-scalar / per-sub-entry omissions inside an already-emitted namespace are caught only by a **non-default-value round-trip test**, not by per-namespace coverage tests.

The proof exists because the `p:` namespace is the one governance-mutable state surface, and it is structurally the most fragile of the ten: unlike the per-domain account / stake / registry namespaces, the `p:` namespace's leaf key carries an **index** (`"p:" + eff_be8 + idx_be4`) derived from the *position* of an entry inside a per-height `std::vector`, so its determinism depends not only on the height-keyed `std::map` ordering but also on the apply-order-preserving `push_back` discipline of the inner vector. A regression that reordered same-height staging — or that dropped the `pending_param_changes` field from `serialize_state` (the S-037 bug class) or omitted a sub-entry on restore (the S-041 bug class) — would silently diverge the `p:` leaf set and trip the S-033 state_root gate on snapshot restore. This document fixes the determinism contract for the namespace so an auditor can confirm the three surfaces (apply, snapshot, activation) without re-deriving the apply-path branch-by-branch. It is the determinism / commitment companion to `GovernanceParamChange.md` (FA-Apply, the apply-layer state-machine proof T-G1..T-G8): that proof establishes *what* the staging + activation transitions do; this proof establishes that they do it *byte-identically across nodes and across the snapshot boundary*.

**Cryptographic assumptions** (canonical labels, `Preliminaries.md` §2.0): **A1** = Ed25519 EUF-CMA (§2.2); **A2** = SHA-256 collision resistance (§2.1); **A3** = SHA-256 preimage / second-preimage resistance (§2.1); **A4** = CSPRNG uniform sampling (§2.3). This document's only cryptographic reduction is to **A2**, via the sorted-leaves balanced binary Merkle tree that binds the `p:` leaf set into `state_root` (`MerkleTreeSoundness.md` MT-3 / `S033StateRootNamespaceCoverage.md` T-2). PC-1 and PC-3 are structural determinism arguments (C++ container ordering + apply-path purity) with no crypto reduction; PC-2's "no silent divergence" half reduces to A2.

**Companion documents.** `Preliminaries.md` (F0) §1.3 (hash notation), §2.0 (assumption labels), §2.1 (A2 — the only reduction target), §3.3 (apply rules) for the validity predicate `pending_param_changes` mutation site; `GovernanceParamChange.md` (FA-Apply) for the apply-layer state-machine theorems T-G1 (staging stages exactly one entry), T-G4 (in-order, exactly-once activation drain), T-G5 (future-effective preservation), T-G7 (idempotent activation) — PC-1 / PC-3 are the cross-node-determinism strengthenings of T-G1 / T-G4 / T-G7; `Governance.md` (FA10) for the validator-side consent gate (mode + whitelist + multisig) whose acceptance is the precondition for any staging, and T-10.1 (activation determinism) which PC-1+PC-3 jointly refine into a state-commitment statement; `S033StateRootNamespaceCoverage.md` for T-1 (the `p:` namespace's coverage membership), T-2 (namespace disjointness via prefix bytes — the `p:` injectivity PC-2 needs), T-3 (deterministic leaf ordering), T-5 (snapshot round-trip soundness, of which PC-2 is the `p:` specialization); `SnapshotDeterminismComposition.md` for SD-1 (round-trip byte-identity), SD-2 (state_root preservation), SD-3 (every-namespace-contributes / no silent drop — the S-037/S-041 regression-guard property PC-2 instantiates for `p:`); `SnapshotEquivalence.md` (FA-Apply-2) for the generic serialize-restore identity T-S1 + per-namespace coverage T-S3 + idempotent-restore T-S4 that PC-2 specializes; `MerkleTreeSoundness.md` for MT-1 (root is a function of the leaf set) + MT-3 (collision-resistance inheritance, reduces to A2); `AccountStateInvariants.md` (FA-Apply-1) for the apply determinism (byte-identical start + same block ⇒ byte-identical post-apply state) that PC-1 invokes; `S012SnapshotStateRootGate.md` for the restore-side G2 gate that fires on a divergent `p:` leaf set; `docs/SECURITY.md` §S-033 / §S-037 / §S-038 / §S-041 for the closure narratives this proof formalizes; `docs/PROTOCOL.md` §4.1.1 (the canonical `state_root` Merkle-leaf table including the `p:` row) + §11 (the snapshot wire format).

---

## 1. Theorem statements

**Setup.** Let `Chain` denote the type at `include/determ/chain/chain.hpp`. The `p:` namespace is backed by the single member field

```cpp
std::map<uint64_t,
         std::vector<std::pair<std::string, std::vector<uint8_t>>>>
                                            pending_param_changes_;   // chain.hpp:621-623
```

keyed by `effective_height` and valued by a `std::vector` of `(name, value)` pairs whose order is the apply-order of the staging transactions (`stage_param_change`'s `emplace_back`, `chain.cpp:212-217`). Write `P(C)` for the value of `pending_param_changes_` on chain `C`.

`build_state_leaves` (`chain.cpp:267-411`) emits the `p:`-namespace leaves at `chain.cpp:361-378`: for each `(eff, entries)` bucket in `std::map`-sorted order, and for each `idx ∈ [0, entries.size())` in vector order, it emits a leaf with key `"p:" + eff_be8 + idx_be4` and value-hash `SHA256(name_len_u64 ‖ name ‖ value_len_u64 ‖ value_bytes)`. Let `L_p(C)` denote the multiset of `p:`-leaves of `C`, and `MR(C) := compute_state_root(C) = merkle_root(build_state_leaves(C))` (`chain.cpp:413-415`).

Let `serialize_state` (`chain.cpp:1541`) and `restore_from_snapshot` (`chain.cpp:1703`) be the snapshot emit / consume functions; their `p:` handling is the JSON `pending_param_changes` array at `chain.cpp:1679-1693` (emit) and the inverse loop at `chain.cpp:1850-1861` (restore). Let `activate_pending_params(H)` (`chain.cpp:471-497`) be the height-`H` activation drain, called once at the top of every `apply_transactions(b)` for `b.index > 0` (`chain.cpp:676`).

**Theorem PC-1 (Apply-determinism of staging).** Fix a block sequence `B_0, …, B_n` and two chains `C`, `C'` that begin from byte-identical state and apply the identical sequence. Then after every prefix, `P(C) == P(C')` as `std::map` values (byte-identical keys, byte-identical inner vectors in byte-identical order). Equivalently: the staged `pending_param_changes_` map is a deterministic function of the applied PARAM_CHANGE transaction multiset together with the inclusion order of those transactions across the block sequence — no platform, allocator, ABI, insertion-history-beyond-apply-order, or iteration-order dependence.

**Theorem PC-2 (Snapshot round-trip identity for `p:`).** For every reachable chain `C`,

1. **Entry preservation:** `P(restore_from_snapshot(serialize_state(C))) == P(C)` (every `(eff, name, value)` triple round-trips byte-for-byte, in the same per-height order).
2. **Leaf-set + root preservation:** `L_p(restore_from_snapshot(serialize_state(C))) == L_p(C)` as multisets, and consequently `MR(restore_from_snapshot(serialize_state(C))) == MR(C)`.

Moreover (the S-041 regression-guard corollary): if the `pending_param_changes` field were dropped from `serialize_state`, or any sub-entry (`name` or `value`) omitted from the restore loop, then for any `C` with a non-empty / non-default `P(C)` the restored `L_p` would differ, `MR` would diverge, and the restore-side G2 state_root gate (`chain.cpp:1908-1916`) would throw with the S-033 tag. The divergence is therefore **loud, not silent — provided a test populates `p:` with non-default contents and exercises the round trip.**

**Theorem PC-3 (Deterministic height-triggered activation).** Fix a chain state with `P(C)` containing buckets at heights `h_1 < h_2 < … < h_k`, and a block `B` at height `b.index = H`. Then `activate_pending_params(H)` (`chain.cpp:471-497`):

1. processes exactly the buckets with `h_i ≤ H`, in ascending `h_i` order (the `std::map` begin-to-`H` walk);
2. within each processed bucket, processes the `(name, value)` pairs in vector (apply-) order;
3. mutates the targeted chain-instance scalar (`min_stake_` / `suspension_slash_` / `unstake_delay_`) and/or fires the `param_changed_hook_` deterministically per entry;
4. erases each processed bucket, so `P` afterward is exactly `{ (eff, …) : eff > H }` and no processed entry is ever re-activated on a later block;

and the entire transition is byte-identical across every honest node that reaches height `H` from byte-identical state. Equivalently: the activated set, the activation order, the resulting scalar values, and the residual `pending_param_changes_` map are all deterministic functions of `(P(C), H)`.

---

## 2. Background

### 2.1 The `p:` namespace leaf encoding

`build_state_leaves` emits the `p:` slice at `chain.cpp:361-378`:

```cpp
// pending_param_changes_  (key = "p:" + eff_be8 + idx_be4)
for (auto& [eff, entries] : pending_param_changes_) {
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        auto& [name, value] = entries[idx];
        std::vector<uint8_t> key;                       // "p:" + eff_be8 + idx_be4
        key.push_back('p'); key.push_back(':');
        for (int i = 7; i >= 0; --i) key.push_back((eff >> (8*i)) & 0xff);
        for (int i = 3; i >= 0; --i) key.push_back((uint32_t(idx) >> (8*i)) & 0xff);
        crypto::SHA256Builder b;
        b.append(static_cast<uint64_t>(name.size()));
        b.append(name);
        b.append(static_cast<uint64_t>(value.size()));
        if (!value.empty()) b.append(value.data(), value.size());
        leaves.push_back({std::move(key), hash_bytes(b)});
    }
}
```

Two facts to record precisely from the source:

1. **The key carries both the height and the intra-bucket index.** A bucket at `effective_height = E` containing `m` entries produces `m` distinct leaves with keys `"p:" + E_be8 + 0_be4`, …, `"p:" + E_be8 + (m-1)_be4`. The index is taken from the *vector position*, so two PARAM_CHANGE transactions that stage at the same `E` (in different blocks) map to leaves `idx=0` and `idx=1` in the order their blocks were applied. This is what makes the inner-vector apply-order load-bearing for the state_root, and it is the structural reason PC-1's "apply-order" qualifier is necessary (a reordered inner vector would relabel the indices and change the leaf keys).

2. **The value-hash is a length-prefixed encoding of `(name, value)`.** Both fields are length-prefixed (`name_len_u64 ‖ name ‖ value_len_u64 ‖ value`), so the encoding is injective over `(name, value)` pairs of any length — no two distinct pairs collide pre-hash, and the empty-value case (`value.size() == 0`) is unambiguous (the `if (!value.empty())` guard skips the body append but the `value_len = 0` prefix is still hashed).

The `eff` key is **big-endian** (`for i = 7..0`), matching the `Preliminaries.md` §1.3 convention that multi-byte integers in hash inputs are big-endian. Big-endian keys mean the sorted-leaves Merkle sort (which sorts keys lexicographically by raw byte, `S033StateRootNamespaceCoverage.md` T-3) orders the `p:` leaves by ascending `effective_height`, then ascending `idx` — i.e. the leaf sort order coincides with the natural `(height, position)` order. (This is a determinism-friendly coincidence; correctness does not depend on it, only on the sort being total + deterministic.)

### 2.2 The staging primitive and the apply branch

`stage_param_change` (`chain.cpp:212-217`) is the sole writer to `pending_param_changes_` during ordinary apply:

```cpp
void Chain::stage_param_change(uint64_t effective_height,
                                  std::string name, std::vector<uint8_t> value) {
    pending_param_changes_[effective_height].emplace_back(
        std::move(name), std::move(value));
}
```

It is reached only from the PARAM_CHANGE apply branch at `chain.cpp:900-928`, which (per `GovernanceParamChange.md` T-G1) consumes the tx fee, defensively re-parses the canonical `[name_len, name, value_len, value, effective_height]` header, calls `stage_param_change(eff, name, value)`, and bumps the sender nonce. The validator's mode + whitelist + multisig gate (`Governance.md` FA10) is the unique consent surface; apply trusts it for deterministic replay and does not re-verify signatures. The `emplace_back` is a single `std::vector::push_back`, so the bucket's order is exactly the order in which staging transactions are applied.

### 2.3 The activation drain

`activate_pending_params` (`chain.cpp:471-497`) is invoked at the top of every non-genesis apply (`chain.cpp:676`, `if (b.index > 0) activate_pending_params(b.index);`) — before the tx-replay loop, so a tx in block `b` that depends on the new value sees it. The drain (full body at `GovernanceParamChange.md` T-G4):

```cpp
void Chain::activate_pending_params(uint64_t current_height) {
    auto it = pending_param_changes_.begin();              // smallest key
    while (it != pending_param_changes_.end() && it->first <= current_height) {
        for (auto& [name, value] : it->second) {           // vector (apply) order
            auto parse_u64 = [&](uint64_t& dst) { /* 8-byte LE decode */ };
            if (name == "MIN_STAKE")            { parse_u64(min_stake_); }
            else if (name == "SUSPENSION_SLASH") { parse_u64(suspension_slash_); }
            else if (name == "UNSTAKE_DELAY")    { parse_u64(unstake_delay_); }
            if (param_changed_hook_) param_changed_hook_(name, value);
        }
        it = pending_param_changes_.erase(it);             // exactly-once + advance
    }
}
```

The `std::map::begin()` + `it->first <= current_height` + `erase(it)`-returns-next loop drains in ascending-height order, processes each bucket's vector in apply-order, and removes drained buckets so they are never re-encountered (the exactly-once property, `GovernanceParamChange.md` T-G7). The three chain-instance scalars it can write (`min_stake_`, `suspension_slash_`, `unstake_delay_`) are themselves `k:`-namespace leaves; the value forwarded to `param_changed_hook_` reaches validator/Node-mirror fields that are *not* state-root committed (they live on the Node, outside `Chain`). PC-3 covers the deterministic mutation of the `Chain`-side surface; the hook's validator-side consistency is `GovernanceParamChange.md` T-G6.

### 2.4 The snapshot pathway

`serialize_state` emits the `p:` namespace as a JSON array at `chain.cpp:1679-1693`:

```cpp
json pending = json::array();
for (auto& [eff, entries] : pending_param_changes_) {       // sorted-key order
    json bucket = json::array();
    for (auto& [name, value] : entries)                     // vector order
        bucket.push_back({{"name", name}, {"value", to_hex(value.data(), value.size())}});
    pending.push_back({{"effective_height", eff}, {"entries", bucket}});
}
snap["pending_param_changes"] = pending;
```

`restore_from_snapshot` reads it back at `chain.cpp:1850-1861`:

```cpp
if (snap.contains("pending_param_changes")) {
    for (auto& b : json_require_array(snap, "pending_param_changes")) {
        uint64_t eff = b.value("effective_height", uint64_t{0});
        for (auto& e : b.value("entries", json::array())) {
            std::string name = e.value("name", std::string{});
            std::vector<uint8_t> value = from_hex(e.value("value", std::string{}));
            c.pending_param_changes_[eff].emplace_back(std::move(name), std::move(value));
        }
    }
}
```

The emit iterates the `std::map` in sorted-key order and each bucket's vector in position order; the restore re-installs each `(eff, name, value)` triple via the same `emplace_back` primitive used by `stage_param_change`, in the JSON array order — which the emit produced in the canonical sorted-height + vector-position order. The round trip therefore reconstructs `pending_param_changes_` with identical keys and identical inner-vector order. The `snap.contains(...)` guard is the backward-compat shim: a pre-feature snapshot with no `pending_param_changes` field leaves the restored map empty, which matches a chain that never staged a change (no `p:` leaves emitted by `build_state_leaves`).

Unlike the `d:` namespace (S-037) and the `k:` merge-threshold scalars (S-041), the `p:` namespace was **threaded through both snapshot surfaces from its introduction** — there is no historical `p:`-specific serialize/restore gap. PC-2 nonetheless states the round-trip identity explicitly and the drop-detection corollary generically, because (i) the `p:` namespace is the structural archetype of the S-037/S-041 bug class (a namespace whose leaves are in the `compute_state_root` preimage), and (ii) the regression-guard property is exactly what the sibling `test-pending-param-change-determinism` unit pins so a future drop of the `pending_param_changes` field — or a future omission of a sub-entry on restore (the precise S-041 failure mode, but applied to `p:`) — fails loudly.

---

## 3. Implementation citations

The load-bearing call sites for this proof:

| Site | File / lines | Role |
|---|---|---|
| `pending_param_changes_` field | `include/determ/chain/chain.hpp:621-623` | The `p:`-namespace backing container (the universe PC-1 / PC-3 reason over). |
| `Chain::stage_param_change` | `src/chain/chain.cpp:212-217` | The sole ordinary-apply writer (PC-1 mutation; `emplace_back` apply-order). |
| `Chain::build_state_leaves` `p:` block | `src/chain/chain.cpp:361-378` | The `p:` leaf generator (key = `"p:" + eff_be8 + idx_be4`; value-hash over `(name, value)`). |
| `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | `merkle_root(build_state_leaves())` — binds `L_p` into `state_root`. |
| `Chain::activate_pending_params` | `src/chain/chain.cpp:471-497` | The height-triggered drain (PC-3). |
| Drain call site | `src/chain/chain.cpp:676` | `if (b.index > 0) activate_pending_params(b.index);` — single call, at apply entry before tx replay. |
| PARAM_CHANGE apply branch | `src/chain/chain.cpp:900-928` | The validator-accepted staging flow (PC-1 source of the tx multiset). |
| `serialize_state` `p:` block | `src/chain/chain.cpp:1679-1693` | PC-2 producer-side: emit `pending_param_changes` JSON array. |
| `restore_from_snapshot` `p:` block | `src/chain/chain.cpp:1850-1861` | PC-2 consumer-side: re-install via `emplace_back`. |
| post-restore G2 state_root gate | `src/chain/chain.cpp:1908-1916` | PC-2 drop-detection: recompute root, compare to tail-head `state_root`, throw on mismatch (S-033 tag). |
| apply-time S-033 gate | `src/chain/chain.cpp:1430-1446` | Cross-node mechanism: every receiver recomputes `state_root` (including `L_p`) and rejects on mismatch. |

---

## 4. Proofs

### 4.1 Proof of PC-1 (Apply-determinism of staging)

We show `P(C) == P(C')` by induction over the block-sequence prefix, given byte-identical starting state and the identical applied sequence `B_0, …, B_n`.

**Base case.** Before any block, both chains hold the genesis `pending_param_changes_` (empty after `Chain` construction / genesis-apply — genesis installs accounts/stakes/registrants only, `chain.cpp:681-718`, and never stages a parameter change). So `P(C) == P(C') == ∅`.

**Inductive step.** Assume `P(C) == P(C')` after applying `B_0, …, B_{i-1}`. Apply `B_i` on both. The only writers to `pending_param_changes_` during `apply_transactions(B_i)` are (a) `activate_pending_params` at apply entry (`chain.cpp:676`) which only *erases* buckets, and (b) the PARAM_CHANGE branch (`chain.cpp:900-928`) which only *appends* via `stage_param_change`.

*Erase determinism.* By PC-3 (proved below, no circular dependency — PC-3's argument is over a fixed `(P, H)` and does not invoke PC-1), `activate_pending_params(B_i.index)` removes exactly the buckets with `eff ≤ B_i.index` from both chains. Since `P(C) == P(C')` entering the call and the height argument `B_i.index` is identical, the post-erase maps coincide.

*Append determinism.* The PARAM_CHANGE branch walks `B_i`'s transaction list in block order. `B_i` is a single block with a fixed, ordered `txs` vector — both chains iterate the *same* vector in the *same* order (the block is one object, gossiped identically; `AccountStateInvariants.md` FA-Apply-1 + `S033StateRootNamespaceCoverage.md` T-4 establish that honest peers hold byte-identical block bytes, so the `txs` order is fixed). For each PARAM_CHANGE tx that passes the apply-side shape check (a deterministic predicate on the tx payload bytes, `chain.cpp:907-914`), both chains call `stage_param_change(eff, name, value)` with byte-identical arguments decoded from the same payload (`chain.cpp:908-920` is a pure byte-decode). `stage_param_change` performs `pending_param_changes_[eff].emplace_back(name, value)`:
- the `std::map::operator[]` either reuses an existing `eff` bucket (identical on both chains by the inductive hypothesis + erase-determinism) or default-constructs a new empty vector (identical);
- the `emplace_back` appends at the vector tail; since both chains process the same txs in the same order, the tail grows identically.

Therefore after `B_i` both chains hold the same set of `eff` keys, each mapping to the same inner vector with the same elements in the same order. `P(C) == P(C')`.

**No iteration-order dependence.** `stage_param_change` writes are keyed by the *tx-supplied* `eff` value, not by any map-iteration order, and the inner-vector order is the *tx-application* order, not an insertion-into-map order. The only ordering input is the block-sequence + intra-block tx order, both of which are fixed by the (identically-gossiped) blocks. `std::map` and `std::vector` are determined by their contents + the operations applied, never by allocator addresses or platform ABI. Hence the byte-identity is platform-independent. ∎

**Cross-node corollary (the empirical-pin form).** Two honest nodes applying the same finalized block sequence reach byte-identical `pending_param_changes_` after every block. Combined with PC-3's activation determinism and PC-2's snapshot identity, this is the `p:`-slice of the S-033 cross-node determinism property (`S033StateRootNamespaceCoverage.md` T-4): the `p:` leaves `L_p` are byte-identical across nodes, so the `p:` contribution to `state_root` agrees, and the apply-time gate (`chain.cpp:1430-1446`) never fires on the `p:` namespace for honest nodes.

**Code witness.** `chain.cpp:212-217` (`stage_param_change`), `chain.cpp:900-928` (PARAM_CHANGE branch), `chain.cpp:676` (drain-before-replay ordering).

**Test witness.** Sibling unit `determ test-pending-param-change-determinism` (added this round) — the staging-determinism assertions: stage the same multiset of `(eff, name, value)` triples into two independent chains via the apply path (including same-height multi-stage to exercise the inner-vector apply-order), and assert `pending_param_changes()` is element-equal AND the recomputed `state_root` (which folds `L_p`) is byte-equal. Supplementary: `tools/test_pending_param_changes.sh` (`determ test-pending-param-changes`, 13 assertions on the staging primitive, including same-height insertion-order preservation + chain independence) and `tools/test_param_change_apply.sh` (`determ test-param-change-apply`, the "determinism: two chains with identical staging produce identical state_root" assertion) per `GovernanceParamChange.md` T-G1/T-G4.

### 4.2 Proof of PC-2 (Snapshot round-trip identity for `p:`)

Write `S = serialize_state(C)`, `C₁ = restore_from_snapshot(S)`.

**Part 1 — entry preservation (`P(C₁) == P(C)`).** By inspection of the emit (`chain.cpp:1679-1693`) and restore (`chain.cpp:1850-1861`) loops:

- *Emit* iterates `pending_param_changes_` in `std::map` sorted-key (ascending `eff`) order; for each bucket it emits `{"effective_height": eff, "entries": [{"name", "value": to_hex(value)}, …]}` with the inner array in vector (position) order. `to_hex` is an injective, deterministic encoding of a byte vector (lower-case hex, 2 chars/byte, length-preserving), so `value` is recoverable exactly.
- *Restore* iterates the JSON `pending_param_changes` array in array order (= the emit's sorted-`eff` order); for each bucket it reads `eff`, then iterates `entries` in array order (= the emit's vector order); for each entry it reads `name` (exact string) and `value = from_hex(hex)` (the exact inverse of `to_hex`, `from_hex ∘ to_hex = id` on byte vectors), and appends via `c.pending_param_changes_[eff].emplace_back(name, value)`.

Because the restore re-installs the triples in the same global order the emit produced them (sorted `eff`, then vector position), and `std::map::operator[]` + `emplace_back` reconstruct buckets in that order, `C₁.pending_param_changes_` has identical keys, each mapping to a vector with identical elements in identical order. (The inner-vector order is preserved even though `std::map` is order-insensitive on its *keys*, because the restore appends within each bucket in the JSON-array order, which is the original vector order.) Hence `P(C₁) == P(C)` byte-for-byte. The empty-value edge case round-trips: `to_hex` of an empty vector is the empty string, `from_hex("")` is the empty vector.

**Part 2 — leaf-set + root preservation.** By Part 1, `C₁.pending_param_changes_ == C.pending_param_changes_`. `build_state_leaves`'s `p:` block (`chain.cpp:361-378`) is a pure function of `pending_param_changes_` (it iterates the map + inner vectors and hashes fixed-width / length-prefixed encodings, with no other input). Identical `pending_param_changes_` ⇒ identical `p:`-leaf multiset: `L_p(C₁) == L_p(C)`. The other nine namespaces round-trip by `S033StateRootNamespaceCoverage.md` T-5 / `SnapshotDeterminismComposition.md` SD-2 (the full-state composition), so `build_state_leaves(C₁) == build_state_leaves(C)` as a multiset. By `MerkleTreeSoundness.md` MT-1 (the root is a pure function of the leaf *set* via the internal key-sort, `S033StateRootNamespaceCoverage.md` T-3), `MR(C₁) == MR(C)` byte-for-byte. The runtime check of this equality is the post-restore G2 gate at `chain.cpp:1908-1916`, which recomputes `compute_state_root()` and compares it against the tail-head's stored `state_root`; PC-2 is exactly why an honest snapshot passes G2.

**Drop-detection corollary (the S-041 lesson, instantiated for `p:`).** Suppose hypothetically a code change dropped the `pending_param_changes` field from `serialize_state` (emitting nothing) while `build_state_leaves` still emits `p:`-leaves — the S-037 situation, or omitted the `value` sub-field on restore — the S-041 situation (a per-sub-entry omission inside an emitted namespace). Take any reachable `C` with a non-empty `P(C)` (in the omission case, with a non-default `value`). Then `C₁ = restore_from_snapshot(serialize_state(C))` has an empty or wrong-valued `P` (the restore loop has nothing / the wrong bytes to read; the `value(key, default)` semantics leave the field at its default). So `L_p(C₁) ≠ L_p(C)` — leaves are missing or carry a different value-hash. By the per-namespace sensitivity result (`SnapshotDeterminismComposition.md` SD-3, which reduces to **A2** via MT-3: distinct leaf sets colliding on a root yield an extractable SHA-256 collision), `MR(C₁) ≠ MR(C)` except with probability `≤ 2⁻¹²⁸`. The G2 gate (`chain.cpp:1908-1916`) recomputes the root over the dropped/wrong-`p:` state, finds it `≠` the tail header's stored root (which *did* commit to the original `p:` leaves), and throws the `"snapshot state_root mismatch … (S-033)"` diagnostic. The regression is **loud** — provided a test populates `p:` with non-default contents and exercises the round trip.

This is the precise S-041 discipline: per-*namespace* coverage tests (`test_state_root_namespaces.sh`) do **not** catch a per-*sub-entry* omission within an emitted namespace, because the `p:` namespace would still be emitted (just with a missing field); the guard for that failure mode is a round-trip test that stages **non-default** `(eff, name, value)` content and asserts both entry-equality and `state_root`-equality across the round trip — which is exactly what the sibling `test-pending-param-change-determinism` unit does. The S-041 fix to the `k:` merge thresholds (`chain.cpp:1611-1613` emit + the symmetric `snap.value(..., default)` restore) is the same-session sibling of this discipline; `SnapshotDeterminismComposition.md` §2.1 fact 2 records the `k:` instance, and this corollary records that the `p:` namespace is structurally guarded against the identical bug class. ∎

**Code witness.** `chain.cpp:1679-1693` (emit), `chain.cpp:1850-1861` (restore), `chain.cpp:361-378` (`p:` leaf construction), `chain.cpp:1908-1916` (G2 gate).

**Test witness.** Sibling unit `determ test-pending-param-change-determinism` — the round-trip assertions: build a chain with non-default `pending_param_changes_` (multiple heights, same-height multi-entry, non-empty + empty values), `serialize_state` it, `restore_from_snapshot`, and assert (i) `pending_param_changes()` is element-equal and (ii) the restored `compute_state_root()` equals the donor's. Supplementary: `tools/test_snapshot_roundtrip.sh` (the generic `serialize → restore → compute_state_root` round trip), F1's `determ test-snapshot-full-determinism` (the all-namespace fixture that populates `p:` among the ten and asserts SD-1 byte-identity + SD-2 root-match, `SnapshotDeterminismComposition.md` §4), and `tools/test_pending_param_changes.sh` (the staging-primitive round-trip edge cases).

### 4.3 Proof of PC-3 (Deterministic height-triggered activation)

Fix `P(C)` with buckets at `h_1 < h_2 < … < h_k` and a block `B` at height `H`. We trace `activate_pending_params(H)` (`chain.cpp:471-497`).

**Claim 1 — activated set + order.** The loop opens `auto it = pending_param_changes_.begin()`, which by the `std::map` red-black-tree contract is the iterator to the smallest key. The predicate `it != end() && it->first <= current_height` admits buckets in strictly ascending key order. Because `H` is fixed, the loop body executes for exactly the buckets with `h_i ≤ H`, smallest-first, and stops at the first bucket with key `> H` (or `end()`). By the sorted-key contract, every bucket past that point also has key `> H`, so none of them is processed. Activated set `= { h_i : h_i ≤ H }`, processed smallest-`h_i`-first. (This is `GovernanceParamChange.md` T-G4's ordering claim + T-G5's future-effective-preservation, restated as the determinism input.)

**Claim 2 — intra-bucket order + per-entry effect.** For each processed bucket, `for (auto& [name, value] : it->second)` iterates the inner `std::vector` in position (apply-) order — deterministic, and identical across nodes because the vector contents + order are byte-identical by PC-1. Per entry, the `if/else if` chain dispatches on the exact string `name`: `"MIN_STAKE"` / `"SUSPENSION_SLASH"` / `"UNSTAKE_DELAY"` decode `value` via the 8-byte little-endian `parse_u64` and write the corresponding `Chain` scalar; any other name matches no branch (no chain-instance write). Then `param_changed_hook_(name, value)` fires unconditionally if a hook is installed. The decode + dispatch are pure functions of `(name, value)`, so the resulting scalar values and the hook arguments are deterministic. `parse_u64` is total and deterministic: it checks `value.size() == 8` and either writes the decoded `u64` or leaves the destination unchanged (a malformed-length value is a no-op write, identical on every node).

**Claim 3 — exactly-once + residual map.** Each processed bucket is removed by `it = pending_param_changes_.erase(it)`, whose `std::map::erase(iterator)` return value is the iterator past the erased element — so the loop advances without invalidation and never re-visits a drained bucket. After the loop, `pending_param_changes_` contains exactly `{ (eff, …) : eff > H }`. On the next `apply_transactions(b')` with `b'.index = H' ≥ H`, `begin()` returns the smallest *remaining* key; a previously-drained bucket cannot reappear because the only writer that could re-insert it is `stage_param_change`, which inserts under a tx-supplied `eff`, not a drained one (PC-1). Hence each `(eff, name, value)` triple activates exactly once, at the first block whose index `≥ eff`. (This is `GovernanceParamChange.md` T-G7, restated.)

**Cross-node byte-identity.** Every input to the drain is deterministic: the starting `P(C)` is byte-identical across honest nodes (PC-1), the height argument `H = b.index` is the block's index (fixed by the gossiped block), the `std::map` iteration order is the sorted-key contract, the inner-vector order is byte-identical (PC-1), and the per-entry decode + dispatch + erase are pure. Therefore the activated set, activation order, resulting `min_stake_` / `suspension_slash_` / `unstake_delay_` values, hook-argument sequence, and residual `pending_param_changes_` map are all byte-identical functions of `(P(C), H)` — identical on every node that reaches height `H` from byte-identical state. The three scalars the drain may write are themselves `k:`-namespace leaves (`chain.cpp:389-391`), so the activation's state-commitment effect is captured in `state_root` and verified cross-node by the apply-time gate (`chain.cpp:1430-1446`); the residual `p:` leaves likewise. ∎

**Drain-before-replay corollary.** Because the single call site is at apply entry (`chain.cpp:676`, before the tx-replay loop), every transaction in block `B` observes the post-activation scalar values. The placement is itself deterministic (one call site, unconditional for `b.index > 0`), so two nodes never disagree on whether a given tx saw the old or new parameter value — eliminating a validate-vs-apply divergence class (the S-030 D1 concern that the state_root gate exists to catch).

**Code witness.** `chain.cpp:471-497` (the drain), `chain.cpp:676` (the single call site at apply entry), `chain.cpp:473` (the `it->first <= current_height` predicate), `chain.cpp:495` (`erase(it)` + iterator advance).

**Test witness.** Sibling unit `determ test-pending-param-change-determinism` — the activation-determinism assertions: stage entries at multiple heights (including same-height multi-entry), apply blocks across the activation thresholds on two independent chains, and assert the activated scalar values, the residual `pending_param_changes()`, and the recomputed `state_root` all coincide between the chains and across the activation boundary. Supplementary: `tools/test_param_change_apply.sh` (`determ test-param-change-apply`, the "Activation" + "Multi-param same-height" + "Multi-param different-height" + determinism blocks, `GovernanceParamChange.md` T-G4/T-G5/T-G7) and the end-to-end `tools/test_governance_param_change.sh` (3-node 3-of-3 governed chain activating `MIN_STAKE` through gossip).

---

## 5. Adversary model

The proof's threat model considers three adversary surfaces against the `p:` namespace; each is bounded by a different mechanism of PC-1 + PC-2 + PC-3 composed with the upstream consent gate.

**(a) Producer-introduces-`p:`-divergence.** A Byzantine producer finalizes a block whose `body.state_root` reflects a `pending_param_changes_` map other than the canonical post-apply one (e.g., it staged an entry the block's txs do not justify, or reordered a same-height bucket). By PC-1 + PC-3, every honest receiver recomputes the canonical `L_p` from the block's actual txs and the deterministic drain, producing a `state_root` that differs from the producer's manufactured value; the apply-time gate (`chain.cpp:1430-1446`) fires and rejects the block (`S033StateRootNamespaceCoverage.md` T-4 adversarial corner case). The chain does not advance on the divergent `p:` state.

**(b) Snapshot-supplier-introduces-`p:`-divergence.** A Byzantine snapshot supplier ships a snapshot whose `pending_param_changes` array does not match the tail-head's committed `state_root` (entries added, dropped, reordered, or value-mutated). By PC-2 Part 2 + the G2 gate (`chain.cpp:1908-1916`), the receiver's recomputed root over the tampered `p:` leaves differs from the tail-head's `claimed` root (assuming a non-zero `claimed` — pre-S-038 snapshots are the intentional skip per §6); the restore throws loudly with the S-033 tag. The receiver does not bootstrap from the divergent snapshot. The two-adversary composition (tamper `p:` *and* rewrite the tail header's `state_root` to match) additionally requires forging the committee's Ed25519 signature over the tail block's `signing_bytes` (which bind `state_root`) — defeated by **A1** (`S012SnapshotStateRootGate.md` T-4).

**(c) Unauthorized-staging adversary.** An adversary attempts to stage a parameter change without satisfying the governance gate (off-whitelist name, wrong mode, sub-threshold signatures). This never reaches `stage_param_change`: the validator's mode + whitelist + multisig gate (`Governance.md` FA10 T-10/T-11, `GovernanceParamChange.md` T-G2/T-G3) rejects the tx upstream, so no honest node finalizes a block containing it, and the `p:` namespace never gains an unauthorized entry. PC-1's "applied PARAM_CHANGE transaction multiset" is therefore the *validator-accepted* multiset; the consent surface is FA10's scope, and the determinism of what happens *after* acceptance is this proof's scope. The cryptographic bound on forging a sub-threshold acceptance is `≤ 2⁻¹²⁸` per Ed25519 forgery attempt under **A1** (`Governance.md` §7).

**(d) Hash-collision adversary.** An adversary engineers two distinct `pending_param_changes_` maps producing the same `L_p`-induced root (so a tampered `p:` set passes the gate). By the length-prefixed injective leaf encoding (§2.1) + namespace disjointness (`S033StateRootNamespaceCoverage.md` T-2) + MT-3, this requires a SHA-256 collision in a leaf value-hash or an inner Merkle node, bounded by **A2** (birthday bound `~2⁻¹²⁸`).

---

## 6. Identified gaps and known limitations

### 6.1 Pre-S-038 historical blocks bypass the apply-time + restore-side gates

Pre-S-038 blocks carry zero `state_root`; the zero-skip shim at `chain.cpp:1432` (apply-time) and `chain.cpp:1911` (restore-side G2) short-circuits the gate. On such blocks the `p:` namespace's cross-node + snapshot determinism is not *enforced* by the state_root check (it still *holds* structurally by PC-1 + PC-3, but the runtime gate is dormant). This is intentional backward-compat, matching `S033StateRootNamespaceCoverage.md` §6.1 and `SnapshotDeterminismComposition.md` §2.2: the fallback integrity comes from `prev_hash` continuity + the tail-head `head_hash` anchor. Once a post-S-038 block is appended, the gate is active from that point forward and every new block's `p:` contribution is verified.

### 6.2 The hook's validator-side mirror is not state-root committed

`activate_pending_params` forwards every activation to `param_changed_hook_` (`chain.cpp:493`), which for the six no-chain-storage names (`bft_escalation_threshold`, `param_keyholders`, `param_threshold`, `tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`) writes validator/Node-side fields that live on `Node`, outside `Chain`. Those fields are **not** `state_root`-committed, so PC-3's byte-identity claim covers only the `Chain`-side surface (the three chain-instance scalars + the residual `p:` map). The validator-side consistency — that every honest node's hook writes the same value for the same name — is `GovernanceParamChange.md` T-G6, and the necessity of the hook (without it, chain-view and validator-view diverge) is that proof's §4. This proof treats the hook as a deterministic black box keyed on `(name, value)`; the cross-node consistency of the *validator* mirror is an honest-node-installs-canonical-hook assumption (Preliminaries §3 H1–H4), not a state_root-enforced property.

### 6.3 A future per-sub-entry serialize/restore omission (the S-041 risk applied to `p:`)

**Risk.** A future change to the `p:` entry shape — e.g., adding a `submitted_at` or `proposer` field to each pending entry — that updates `build_state_leaves`'s `p:` value-hash but forgets the matching field in `serialize_state` / `restore_from_snapshot` would reproduce the S-041 failure mode *inside* the `p:` namespace: the namespace is still emitted (so per-namespace coverage tests pass), but a chain with a non-default value for the new field fails the G2 gate on restore.

**Detection mitigation.** PC-2's drop-detection corollary makes this loud *provided* a test stages **non-default** content for every sub-field of a `p:` entry and exercises the round trip. The sibling `test-pending-param-change-determinism` unit is that guard for the current `(name, value)` shape; any future sub-field addition MUST extend the unit's fixture to set a non-default value for the new field, exactly as the S-041 closure added non-default merge thresholds (`137 / 311 / 29`) to `test-snapshot-roundtrip` #10b + `test-snapshot-full-determinism`. The four-surface threading discipline (`build_state_leaves` + PROTOCOL.md §4.1.1 + `serialize_state` + `restore_from_snapshot`) of `S033StateRootNamespaceCoverage.md` §6.3 applies unchanged.

### 6.4 The `idx` key relabeling on bucket mutation

The `p:` leaf key embeds the intra-bucket vector index (§2.1). Because `pending_param_changes_` entries are only ever *appended* (by `stage_param_change` / the restore loop) and whole buckets are only ever *erased* (by `activate_pending_params`), no operation removes a single entry from the middle of a bucket — so the indices of surviving entries never shift during normal operation, and the `p:` leaf keys are stable between staging and the bucket's eventual whole-bucket activation. (A hypothetical future "cancel a single pending change" operation that erased one entry from a multi-entry bucket would relabel the indices of the entries after it, changing their leaf keys; such an operation would need to be designed with the index-stability consequence in mind, or to re-key by a content hash instead of position. No such operation exists today.) This is a design constraint recorded for future maintainers, not a current gap.

### 6.5 Cross-shard governance is per-shard

In a multi-shard chain each shard's `Chain` has its own `pending_param_changes_`; PARAM_CHANGE is per-shard. PC-1/PC-2/PC-3 are single-shard determinism statements. The cross-shard coordination story (operators broadcasting matching PARAM_CHANGE txs to every shard) is a deployment concern, not an apply-layer mechanism (`GovernanceParamChange.md` §6).

---

## 7. Test-suite citation

| Test | Theorem coverage |
|---|---|
| `determ test-pending-param-change-determinism` (sibling unit, added this round) | PC-1 + PC-2 + PC-3 primary in-process pin: same-multiset staging ⇒ identical `pending_param_changes_` + `state_root` (PC-1); non-default `p:` round-trip preserves entries + root (PC-2); height-triggered activation coincides across chains + across the activation boundary (PC-3). The non-default-content fixture is the S-041 regression guard for the `p:` namespace (§6.3). |
| `tools/test_pending_param_changes.sh` (`determ test-pending-param-changes`, 13 assertions) | PC-1 supporting: staging-primitive determinism — default-empty, single/multi-stage same-height insertion-order preservation, multi-height sorted iteration, edge values (empty + 256-byte), chain independence. |
| `tools/test_param_change_apply.sh` (`determ test-param-change-apply`, ~16 assertions) | PC-3 primary: the activation drain — in-order, exactly-once, multi-param same-height apply-order, future-effective preservation, and the "two chains with identical staging produce identical state_root" determinism assertion. |
| `tools/test_governance_param_change.sh` (end-to-end 3-node 3-of-3 governed chain) | PC-1 + PC-3 composition with the validator pipeline: a `MIN_STAKE` activation propagated through gossip, verified via snapshot inspect (the activated scalar is a `k:` leaf; the residual `p:` map is empty post-activation). |
| `tools/test_snapshot_roundtrip.sh` | PC-2 supporting: generic `serialize → restore → compute_state_root` round-trip identity (the `p:` namespace round-trips among the ten). |
| `determ test-snapshot-full-determinism` (F1, R40) | PC-2 supporting: the all-namespace fixture populates `p:` among the ten and asserts SD-1 byte-identity + SD-2 root-match (`SnapshotDeterminismComposition.md` §4). |
| `tools/test_state_root_namespaces.sh` (`determ test-state-root-namespaces`, 12 assertions) | PC-2 sensitivity: the per-namespace mutation-changes-root assertion for `p:` (mutating a pending entry changes the root). Note per §6.3 this is per-*namespace*, not per-*sub-entry* — the sibling unit closes that finer surface. |

The composite discipline: `test-pending-param-change-determinism` is the audit anchor for the `p:` namespace's apply + snapshot + activation determinism; any future change to the `p:` entry shape must extend its non-default-content fixture in tandem with `build_state_leaves`, PROTOCOL.md §4.1.1, `serialize_state`, and `restore_from_snapshot` (the four-surface threading per `S033StateRootNamespaceCoverage.md` §6.3, sharpened by the S-041 per-sub-entry lesson).

---

## 8. Status

**Proof complete (analytic); empirical pin is the sibling unit (added this round).**

The three theorems are closed:

- **PC-1** (apply-determinism of staging) — by induction over the block-sequence prefix: `stage_param_change`'s `emplace_back` apply-order + the genesis-empty base + the deterministic erase (PC-3) compose to a platform-independent byte-identity of `pending_param_changes_` across nodes. No crypto reduction; structural over C++ container semantics + `AccountStateInvariants.md` FA-Apply-1 (block bytes fixed across honest peers).
- **PC-2** (snapshot round-trip identity for `p:`) — by inspection of the symmetric emit/restore loops (`to_hex`/`from_hex` injectivity + sorted-`eff`-then-vector-position ordering) for entry preservation, then `build_state_leaves` purity + MT-1 for leaf-set + root preservation; the drop-detection corollary reduces to **A2** via SD-3/MT-3 and is the `p:`-namespace instantiation of the S-037/S-041 regression-guard discipline. The runtime check is the restore-side G2 gate (`chain.cpp:1908-1916`).
- **PC-3** (deterministic height-triggered activation) — by inspection of the `std::map` begin-to-`H` drain (ascending-height) + the apply-order inner-vector walk + the pure per-entry decode/dispatch + `erase`-on-drain (exactly-once); the cross-node byte-identity follows because every input is deterministic. The activated `k:` scalars + residual `p:` leaves are state_root-committed and verified by the apply-time gate (`chain.cpp:1430-1446`).

No theorem is open or partial. The recorded limitations (§6) are: pre-S-038 blocks' dormant gate (intentional backward-compat), the validator-side hook mirror being outside the `state_root` surface (covered by `GovernanceParamChange.md` T-G6, not this proof), the future per-sub-entry omission risk (the S-041 lesson, guarded by the sibling unit's non-default fixture), the `idx`-key relabeling constraint on any future single-entry-cancel operation, and the single-shard scope.

**The proof is analytic and changes no code.** It consolidates the `p:`-namespace determinism argument across the apply, snapshot, and activation surfaces so an auditor can confirm the namespace's cross-node + cross-snapshot determinism without re-deriving the apply path. It composes `S033StateRootNamespaceCoverage.md` (the `p:` coverage + disjointness + leaf-ordering) and `SnapshotDeterminismComposition.md` (the all-namespace round-trip + SD-3 drop-detection), refines `GovernanceParamChange.md` T-G1/T-G4/T-G7 into cross-node-determinism statements, and absorbs the S-041 lesson that per-sub-entry omissions inside an emitted namespace are caught only by non-default-value round-trip tests.

---

## 9. References

### SECURITY.md sections

- `docs/SECURITY.md` §S-033 — state_root Merkle commitment + apply-time gate (the `p:` leaf set is part of the committed surface).
- `docs/SECURITY.md` §S-037 — dapp_registry snapshot gap closure (the canonical whole-namespace instance of the drop-detection bug class PC-2 guards against for `p:`).
- `docs/SECURITY.md` §S-038 — producer-side state_root population (activates the apply-time + restore-side gates PC-2/PC-3 rely on).
- `docs/SECURITY.md` §S-041 — `k:` merge-threshold serialize-gap closure (the per-sub-entry instance of the drop-detection bug class; the lesson PC-2 §6.3 applies to `p:`).

### Implementation sites

- `src/chain/chain.cpp:212-217` — `Chain::stage_param_change` (PC-1 mutation; `emplace_back` apply-order).
- `src/chain/chain.cpp:361-378` — `Chain::build_state_leaves` `p:` block (key = `"p:" + eff_be8 + idx_be4`; value-hash over `(name, value)`).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root` (folds `L_p` into `state_root`).
- `src/chain/chain.cpp:471-497` — `Chain::activate_pending_params` (PC-3 drain).
- `src/chain/chain.cpp:676` — the single drain call site at apply entry (`b.index > 0`, before tx replay).
- `src/chain/chain.cpp:900-928` — PARAM_CHANGE apply branch (PC-1 source of the validator-accepted multiset).
- `src/chain/chain.cpp:1430-1446` — the apply-time S-033 gate (cross-node `p:` verification mechanism).
- `src/chain/chain.cpp:1679-1693` — `Chain::serialize_state` `p:` block (PC-2 producer-side).
- `src/chain/chain.cpp:1850-1861` — `Chain::restore_from_snapshot` `p:` block (PC-2 consumer-side).
- `src/chain/chain.cpp:1908-1916` — the post-restore G2 state_root gate (PC-2 drop-detection throw site).
- `include/determ/chain/chain.hpp:621-623` — `pending_param_changes_` field declaration.
- `include/determ/chain/chain.hpp:379` + `:386` + `:629` — `stage_param_change` declaration, `pending_param_changes()` accessor, `activate_pending_params` declaration.

### Companion proofs

- `docs/proofs/Preliminaries.md` (F0) — §2.0 assumption labels; §2.1 SHA-256 collision resistance (A2, the only reduction target); §3.3 apply rules.
- `docs/proofs/GovernanceParamChange.md` (FA-Apply) — T-G1 (staging stages exactly one entry), T-G4 (in-order exactly-once drain), T-G5 (future-effective preservation), T-G7 (idempotent activation); PC-1/PC-3 are the cross-node-determinism strengthenings.
- `docs/proofs/Governance.md` (FA10) — the validator-side consent gate (mode + whitelist + multisig) + T-10.1 (activation determinism) that PC-1+PC-3 refine into a state-commitment statement.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (`p:` coverage membership), T-2 (namespace disjointness / `p:` injectivity), T-3 (deterministic leaf ordering), T-4 (producer/receiver symmetry), T-5 (snapshot round-trip soundness, of which PC-2 is the `p:` specialization), §6.3 (the four-surface threading discipline).
- `docs/proofs/SnapshotDeterminismComposition.md` — SD-1 (round-trip byte-identity), SD-2 (state_root preservation), SD-3 (every-namespace-contributes / no silent drop — the regression-guard PC-2 instantiates for `p:`), §2.1 fact 2 (the `k:` / S-041 instance).
- `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) — T-S1 (serialize-restore identity), T-S3 (per-namespace coverage), T-S4 (idempotent restore) that PC-2 specializes to `p:`.
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (root = function of leaf set, → PC-2 root preservation), MT-3 (collision-resistance inheritance, reduces to A2, → PC-2 drop-detection sensitivity).
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — apply determinism (byte-identical start + same block ⇒ byte-identical post-apply state) that PC-1 invokes.
- `docs/proofs/S012SnapshotStateRootGate.md` — the restore-side G2 gate that fires on a divergent `p:` leaf set; the two-adversary A1 composition (§5(b)).

### Tests

- `determ test-pending-param-change-determinism` (sibling unit, added this round) — PC-1 + PC-2 + PC-3 primary pin.
- `tools/test_pending_param_changes.sh` (`determ test-pending-param-changes`) — PC-1 staging-primitive determinism (13 assertions).
- `tools/test_param_change_apply.sh` (`determ test-param-change-apply`) — PC-3 activation drain (~16 assertions).
- `tools/test_governance_param_change.sh` — PC-1 + PC-3 end-to-end through the 3-node validator pipeline.
- `tools/test_snapshot_roundtrip.sh` + `determ test-snapshot-full-determinism` (F1) — PC-2 round-trip identity (generic + all-namespace).
- `tools/test_state_root_namespaces.sh` (`determ test-state-root-namespaces`) — PC-2 per-namespace `p:` sensitivity (12 assertions).

### Specifications

- `docs/PROTOCOL.md` §4.1.1 — the canonical `state_root` Merkle-leaf table including the `p:` row (key `"p:" + eff_height_be8 + idx_be4`).
- `docs/PROTOCOL.md` §3.3 — apply rules for PARAM_CHANGE (the `pending_param_changes` mutation site).
- `docs/PROTOCOL.md` §11 — snapshot serialization format (the PC-2 wire surface).
- NIST FIPS 180-4 — SHA-256 (referenced by A2).
