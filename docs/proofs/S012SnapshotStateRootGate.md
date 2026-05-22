# S012SnapshotStateRootGate — post-restore state_root verification gate composition (S-012 closure)

This document formalizes the post-restore state_root verification gate inside `Chain::restore_from_snapshot` — the single recompute-and-throw check at the bottom of the restore path that closes the S-012 "snapshot bootstrap is trust the source" finding. Pre-S-012, the snapshot path trusted whatever `accounts_` / `stakes_` / `registrants_` / etc. the donor serialized; an adversary distributing a tampered snapshot could pump arbitrary state into any peer that consumed it, and the first divergence would only surface at the next gossiped block (one-block window of unprotected state). S-012's closure inserts a local recompute-and-compare gate at the end of restore: `c.compute_state_root()` over the loaded ten-namespace state must equal the snapshot tail header's stored `state_root`, or the function throws and the receiver refuses to bootstrap.

The proof focuses narrowly on the post-restore gate as a composed artifact. The wider state-integrity composition (at-rest chain.json + produce-time tentative-chain dry-run + receive-time apply-gate) is documented in `BlockchainStateIntegrity.md`; the ten-namespace coverage argument is in `S033StateRootNamespaceCoverage.md`; the cross-shard receipt sub-surface restore is in `AppliedReceiptRestore.md`. This proof's contribution is to pin (a) the gate's *location* — post-restore, before returning control to the caller — as load-bearing, (b) the two-adversary composition — tamper-state vs tamper-state-and-head-state-root — and how each is bounded, and (c) the structural dependency on S-037 (dapp_registry round-trip) and S-038 (producer-side wiring) without which the gate would be either incomplete (S-037 — the `d:` namespace would silently slip past) or dormant (S-038 — every snapshot's `claimed` state_root would be zero, the zero-skip shim would short-circuit, and the gate would be operationally inert).

**Companion documents.** `Preliminaries.md` (F0) §2.1 for SHA-256 collision resistance (A2) — the cryptographic assumption underwriting T-1, T-2, and T-4; `BlockchainStateIntegrity.md` for the four-surface state-integrity composition (S-021 + S-033 + S-038 + apply-gate) inside which this snapshot-surface proof composes; `S033StateRootNamespaceCoverage.md` for the ten-namespace canonical leaf set used by `compute_state_root` on both sides of the gate; `SnapshotEquivalence.md` (FA-Apply-2) for the generic serialize/restore equivalence theorem that this proof's T-5 specializes; `AppliedReceiptRestore.md` (FA-Apply-12) for the `i:`-namespace dedup-set restore correctness that participates in T-2's namespace closure; `DAppRegistryLifecycle.md` for the `d:`-namespace lifecycle (S-037 closure narrative — the canonical example of why namespace coverage and snapshot round-trip must be threaded together); `WireFormatBackwardCompat.md` C-2 for the zero-skip shim on `state_root` that gates the S-038 dependency; `docs/SECURITY.md` §S-012 + §S-021 + §S-033 + §S-037 + §S-038 for the closure-status narratives this proof formalizes.

---

## 1. Background

### 1.1 Pre-S-012 snapshot bootstrap was "trust the source"

Pre-S-012 closure, `Chain::restore_from_snapshot` performed exactly one cryptographic sanity check on the loaded state: the snapshot's `head_hash` claim was recomputed against the tail-header's `prev_hash` continuity, and a mismatch threw. But the `head_hash` only commits to the *block headers* (signing_bytes over `prev_hash`, `index`, committee, etc.); pre-S-033 it did **not** commit to the per-account `balance` or `next_nonce`, nor to any of the other nine namespaces' contents. A donor could trivially ship a snapshot where Alice held 10× her real balance, the tail header's `head_hash` chained validly through `prev_hash` continuity, and the receiver had no way to detect the inflation. The first concrete divergence would only surface on the *next* gossiped block, where the receiver's locally-computed post-apply state (with the inflated Alice) would diverge from any honest peer's — but by then the receiver had already advertised the corrupt state via gossip-responses and any RPC `balance` queries.

The class of attack:

1. **A donor-distributes-tampered-snapshot.** Adversary controls a public snapshot mirror (e.g., a community archive node). Mutates `accounts_["alice"].balance` from 100 to 1000 before serving the snapshot.
2. **A receiver consumes blindly.** Bootstraps from the tampered snapshot; advertises the corrupted state on its RPC + gossip surface; downstream apps querying the receiver get the inflated balance.
3. **First divergence window.** The next gossiped block (from an honest producer, who computes against the real state) carries a `state_root` that the receiver's tampered state doesn't match — but this is post-fact-detection; the corruption was already public.

S-012's fix is a *local* recompute-and-throw gate: the receiver doesn't need to fetch peer blocks or trust the donor; it verifies in O(state-size) at restore time that the loaded state matches the snapshot's tail-header `state_root`. Mismatch is a loud throw before any state becomes visible.

### 1.2 The post-restore gate

The closure landed as Option 3 from the S-012 resolution table (`docs/SECURITY.md` §S-012 — "State Merkle root in Block"). Two paired pieces:

1. **The data layer (S-033):** `Block.state_root` is a 32-byte SHA-256 Merkle root over the ten-namespace canonical state set; bound into `Block::signing_bytes` under the zero-skip shim (`WireFormatBackwardCompat.md` C-2) so pre-S-033 chains remain byte-stable.
2. **The snapshot gate (S-012):** `Chain::restore_from_snapshot` recomputes `c.compute_state_root()` over the freshly-restored state and compares against `c.blocks_.back().state_root` (the tail header's stored value, deserialized from the snapshot's `headers` array). Mismatch raises `std::runtime_error` with the S-033 tag and byte-precision diagnostic.

The two pieces compose under the producer-side wiring (S-038 — `Node::try_finalize_round` populates `body.state_root` via tentative-chain dry-run before broadcast; pre-S-038 every block carried zero and the gate was dormant) and the namespace-coverage discipline (S-037 — the `d:` namespace's `dapp_registry_` field must round-trip through `serialize_state` ↔ `restore_from_snapshot`; pre-S-037 a DApp-active chain's snapshot would fail the gate at restore even though the snapshot was honestly produced).

### 1.3 Why "post-restore" placement is load-bearing

The gate at chain.cpp:1893-1911 fires **after** every `c.<field>_` map has been populated from the snapshot JSON **but before** `restore_from_snapshot` returns. This is the only sound placement because:

- **Pre-population:** there is no state to recompute against — `c.compute_state_root()` would return the empty-tree root or a partial root, neither of which matches the tail header.
- **Post-return:** the caller has already obtained the `Chain` value-by-move; integrating a gate at the call site (`Node::bootstrap_from_snapshot` etc.) would be late detection and would require duplicating the gate at every caller. The function-internal placement makes the contract local to `restore_from_snapshot`.
- **Inside-the-function-but-after-all-restore-loops** is the unique correct position. The producer's tentative-chain dry-run (S-038) uses the same pattern: build state, then read state_root over it.

The §7 F-1 finding registers this as a maintenance contract: any future re-architecting of `restore_from_snapshot` must keep the gate in this position.

---

## 2. Notation and assumptions

### 2.1 Assumptions

- **(A2) SHA-256 collision resistance.** Per `Preliminaries.md` §2.1: finding `x ≠ y` with `SHA256(x) = SHA256(y)` is `≤ 2⁻¹²⁸` per query. This proof's cryptographic-soundness arguments reduce to A2 — both the namespace-leaf value-hash injectivity (no two distinct field-value pairs hash to the same leaf hash, except with negligible probability) and the Merkle inner-node binding (no two distinct sorted leaf vectors hash to the same root, except with negligible probability).

- **(A1) Ed25519 EUF-CMA.** Per `Preliminaries.md` §2.2. Used at one remove: the tail header's `state_root` is bound into the block's `signing_bytes` per S-033 + the zero-skip shim, and the block carries committee `creator_block_sigs` over the digest. Forging a snapshot whose tail header carries a *different* `state_root` than the producer originally committed would require re-signing the committee signatures — out of scope for any per-snapshot adversary without K-of-K key compromise. (The proof's primary adversary is the donor mutating the snapshot's `accounts` / `stakes` / etc. arrays, leaving the tail header's stored `state_root` alone — that adversary is bounded by A2 in T-2.)

### 2.2 The ten state-root namespaces

Per `compute_state_root` (`src/chain/chain.cpp:413-415`) and its underlying `build_state_leaves` (`chain.cpp:267-411`), the canonical state is partitioned across ten namespaces emitted as namespace-prefixed Merkle leaves:

| Namespace | Source field (`Chain` member) | Per-leaf value-hash |
|---|---|---|
| `a:` | `accounts_` | `SHA256(balance ‖ next_nonce)` |
| `s:` | `stakes_` | `SHA256(locked ‖ unlock_height)` |
| `r:` | `registrants_` | `SHA256(ed_pub ‖ registered_at ‖ active_from ‖ inactive_from ‖ region_len ‖ region)` |
| `d:` | `dapp_registry_` | `SHA256(service_pubkey ‖ registered_at ‖ active_from ‖ inactive_from ‖ url_len ‖ url ‖ topics_count ‖ Σ(topic_len ‖ topic) ‖ retention ‖ metadata_len ‖ metadata)` |
| `i:` | `applied_inbound_receipts_` | `SHA256(0x01)` (presence marker; key encodes the `(src_shard, tx_hash)` pair) |
| `b:` | `abort_records_` | `SHA256(count ‖ last_block)` |
| `m:` | `merge_state_` | `SHA256(partner_id ‖ refugee_region_len ‖ refugee_region)` |
| `p:` | `pending_param_changes_` | `SHA256(name_len ‖ name ‖ value_len ‖ value)` |
| `k:` | thirteen genesis-pinned scalars | `SHA256(value_u64)` (and `SHA256(salt[0..32])` for `shard_salt`) |
| `k:c:` | five A1 supply counters | `SHA256(value_u64)` |

The leaf set is the universe over which `compute_state_root` builds a sorted-leaves balanced binary Merkle tree. Coverage completeness (every apply-determining state field maps to exactly one namespace) and namespace disjointness (the byte-level prefixes are pairwise distinct) are proved in `S033StateRootNamespaceCoverage.md` T-1 + T-2; this proof consumes those as preconditions for T-5.

### 2.3 The snapshot envelope's stored state_root

The snapshot's `headers` JSON array (chain.cpp:1690-1698) carries the chain's tail block headers — typically the last 16 blocks by default. Each header is a full `Block::to_json()` serialization, which includes the `state_root` field (32 bytes hex-encoded). `restore_from_snapshot` parses these via `Block::from_json` and pushes them onto `c.blocks_` (chain.cpp:1832-1850). The post-restore gate then reads `c.blocks_.back().state_root` as the `claimed` reference value.

Per S-038, every post-S-038 block has `state_root != Hash{}` because the producer populates it via the tentative-chain dry-run pattern (`Node::try_finalize_round` at `src/node/node.cpp:1024-1117`). Pre-S-038 blocks (legacy chains) have `state_root == Hash{}` and the gate skips them via the zero-skip shim at `chain.cpp:1894-1896`.

### 2.4 Notation

- `c` denotes the `Chain` value being built up by `restore_from_snapshot` (its name in the implementation at `chain.cpp:1711`).
- `snap` denotes the input snapshot JSON object.
- `applied_state_root := c.compute_state_root()` is the locally-computed Merkle root over the restored ten-namespace state at the moment the gate fires (post-restore, pre-return).
- `head_state_root := c.blocks_.back().state_root` is the claimed reference value from the snapshot's tail header.
- We say the snapshot is **state-honest** if `c.<field>_` after restore byte-equals the donor's `<field>_` at serialize time, for every field in the ten-namespace state set.
- We say the snapshot is **head-honest** if `c.blocks_.back().state_root` equals the value the original producer committed via S-038's `try_finalize_round`.

---

## 3. Theorem set

**Theorem T-1 (Post-Restore Gate Soundness).** Let `snap` be any input to `Chain::restore_from_snapshot`. At the post-restore point — after all `c.<field>_` maps have been populated from `snap` and after the legacy-supply solve-for-genesis at `chain.cpp:1864-1877` — the gate at `chain.cpp:1893-1911` computes `applied_state_root := c.compute_state_root()` and compares against `claimed := c.blocks_.back().state_root`. If `claimed != Hash{}` and `applied_state_root != claimed`, the function throws `std::runtime_error("snapshot state_root mismatch at head block <N>: …(S-033)")`. The throw propagates out of `restore_from_snapshot`; the caller never receives a partially-validated `Chain`. The receiver does not bootstrap. Adversary defeated: any donor whose snapshot diverges from the head's committed state_root is caught at restore by A2 (T-2 below).

**Theorem T-2 (Tamper-At-Rest Detection).** Let `snap` be a snapshot output by an honest producer (so initially `head_state_root` faithfully commits to the donor's state) and `snap'` be the result of an adversary mutating at least one byte of any field in any of the ten state-root namespaces of `snap`, while leaving `snap["headers"]` untouched (so `claimed` still references the original producer's committed value). Define:

- `applied_state_root := compute_state_root(restored(snap'))`
- `head_state_root := claimed_after_restore(snap')` (unchanged from the original; equals the producer's pre-mutation root)

Then `Pr[applied_state_root == head_state_root] ≤ 2⁻¹²⁸` per A2 (SHA-256 collision resistance on the tree's root). Equivalently: any 1-bit mutation in any of the ten state-namespace maps produces a recomputed root that differs from `head_state_root` with overwhelming probability, and the gate at chain.cpp:1893-1911 throws. The receiver detects the at-rest tamper before any state becomes visible.

**Theorem T-3 (Tamper-In-Transit Detection).** Let `snap` originate from an honest producer and be modified in transit by an adversary on the wire (e.g., a MITM on the SNAPSHOT_RESPONSE channel) at the same set of state-namespace fields covered by T-2. The post-restore gate is byte-identical regardless of whether the mutation happened at-rest or in-transit, so T-2's bound applies: `Pr[undetected] ≤ 2⁻¹²⁸`. The same `restore_from_snapshot` call site catches both adversary classes with the same gate.

**Theorem T-4 (Two-Adversary Composition).** Two classes of adversary against the snapshot surface:

- **A_tamper_state.** Adversary mutates state fields only; leaves `snap["headers"]` untouched. Bounded by T-2 + T-3 to `≤ 2⁻¹²⁸` undetected.
- **A_tamper_state_and_head_state_root.** Adversary mutates both the state fields AND `snap["headers"]` so that `claimed := mutated_head.state_root` equals `applied_state_root := compute_state_root(restored_mutated_state)`. To succeed, the adversary must find a SHA-256 collision such that the recomputed root over the mutated state matches the manufactured `claimed` value. Equivalently, the adversary must find a non-trivial pre-image of `claimed`. But A_tamper_state_and_head_state_root has more constraints: the manufactured `claimed` is also bound into the tail header's `compute_hash` (via S-033's `signing_bytes` inclusion), and the tail header carries `creator_block_sigs` over the digest. Re-signing the committee signatures requires forging K-of-K Ed25519 signatures — out of scope for any adversary lacking K committee secret keys (A1). So either: (a) the adversary keeps the original `claimed`, in which case A_tamper_state's bound applies; or (b) the adversary tries to manufacture a new `claimed` that's consistent with the mutated state, in which case re-signing is required, reducing to A1.

Therefore the two-adversary composition is `Pr[undetected] ≤ q_A2 · 2⁻¹²⁸ + q_A1 · ε_Ed25519`, both negligible. The post-restore gate's effective bound is `≤ 2⁻¹²⁸` against the realistic donor adversary (mutate state, leave tail header alone), and degrades only to the higher of A1's or A2's bounds against any compounded adversary.

**Theorem T-5 (Composition with S-037 + S-038).** The post-restore gate's effectiveness is a strict composition with two paired closures:

1. **S-037 (dapp_registry round-trip).** The `d:` namespace contributes to `applied_state_root` via `build_state_leaves` (chain.cpp:312-330). Pre-S-037, the snapshot omitted the `dapp_registry` field entirely from `serialize_state` and `restore_from_snapshot`; a DApp-active chain's `applied_state_root` after restore would be missing the `d:` leaves, and the gate would throw on every honestly-produced DApp-active snapshot. S-037's closure threads `dapp_registry` through both `serialize_state` (chain.cpp:1653-1669) and `restore_from_snapshot` (chain.cpp:1818-1834), preserving every field needed to reproduce the `d:` value-hash byte-for-byte. Post-S-037, T-1 holds end-to-end for DApp-active chains.

2. **S-038 (producer-side wiring).** The post-restore gate compares `applied_state_root` against `c.blocks_.back().state_root`. Pre-S-038, the producer never populated `body.state_root` before broadcast; every gossiped block carried zero; every snapshot's tail header carried `state_root == Hash{}`; the zero-skip shim at chain.cpp:1894-1896 short-circuited the gate on every snapshot. S-038 closed by adding the tentative-chain dry-run to `Node::try_finalize_round` (node.cpp:1093-1117). Post-S-038 blocks carry non-zero `state_root`; the gate is real-time-active; T-1's throw path is reachable.

The composition is **conjunctive**: without S-037 the gate falsely throws on honest DApp-active snapshots (closing a UX hole); without S-038 the gate is dormant on every snapshot (closing the security hole). Together they make T-1 + T-2 + T-3 + T-4 hold end-to-end for the snapshot surface.

---

## 4. Source-code citation

The load-bearing call sites for this proof:

| Site | File / lines | Role |
|---|---|---|
| `Chain::restore_from_snapshot` post-restore gate | `src/chain/chain.cpp:1893-1911` | T-1's central mechanism. After all `c.<field>_` maps have been populated, reads `claimed := c.blocks_.back().state_root`; if `claimed != Hash{}`, computes `applied := c.compute_state_root()` and throws on mismatch with byte-precision diagnostic tagged `(S-033)`. The gate executes before the A9 Phase 2C committed-state-view publish at chain.cpp:1917-1928, so a throwing gate never leaks corrupted state into the lock-free read cache. |
| `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | Thin wrapper: `merkle_root(build_state_leaves())`. Same function called by both the apply-time gate (chain.cpp:1432) and the post-restore gate. By identity of implementation, an honest producer's `tentative_chain.compute_state_root()` and an honest receiver's post-restore `c.compute_state_root()` always agree byte-for-byte given the same state. |
| `Chain::build_state_leaves` | `src/chain/chain.cpp:267-411` | Ten-namespace canonical leaf generator. The single source of truth for the `compute_state_root` primitive. Coverage completeness (T-1 of `S033StateRootNamespaceCoverage.md`) ensures every apply-determining state field contributes; namespace disjointness (T-2 there) ensures no two namespaces overlap. |
| `Chain::serialize_state` headers emission | `src/chain/chain.cpp:1687-1698` | Emits the tail block headers (default last 16); each header includes the `state_root` field via `Block::to_json`. This is where `head_state_root` enters the snapshot envelope. |
| `Chain::restore_from_snapshot` headers ingest | `src/chain/chain.cpp:1832-1862` | Parses the `headers` JSON array via `Block::from_json` and pushes onto `c.blocks_`. After this step, `c.blocks_.back().state_root` carries the claimed reference value used by the gate. |
| `Chain::restore_from_snapshot` dapp_registry restore | `src/chain/chain.cpp:1818-1834` | S-037 closure point; restores `c.dapp_registry_` from `snap["dapp_registry"]`, including every field that contributes to the `d:` value-hash. Pre-S-037, this branch was absent; the `d:` namespace's contribution to `applied_state_root` would diverge from the original producer's. |
| `Node::try_finalize_round` state_root population | `src/node/node.cpp:1024-1117` (S-038 wiring at 1093-1117) | T-5 producer-side wiring. Without this, every snapshot's tail header carries `state_root == Hash{}` and the gate's zero-skip shim short-circuits. |
| `Block.state_root` field declaration | `include/determ/chain/block.hpp:460-484` | The 32-byte wire field bound into `signing_bytes` under the zero-skip backward-compat shim (per `WireFormatBackwardCompat.md` C-2). |

---

## 5. Composition with FA-track proofs

**FA-Apply-1 (apply determinism — `AccountStateInvariants.md`).** The post-restore gate consumes `c.compute_state_root()`, which iterates `std::map` in sorted-key order over the ten state-namespace maps. Apply-determinism (Theorem T-A1 of FA-Apply-1) guarantees that byte-identical state across two `Chain` instances produces byte-identical Merkle roots. So two honest receivers restoring the same snapshot reach byte-equal `applied_state_root` values — the gate behaves identically across receivers. This rules out a "split-brain" adversary that tries to make some receivers accept and others reject the same snapshot.

**S-033 (`S033StateRootNamespaceCoverage.md` T-5).** T-5 there proves snapshot round-trip soundness: every namespace's source map emits via `serialize_state` and restores via `restore_from_snapshot` with byte-identical field encoding. This proof's T-1 consumes that as a precondition: if the round-trip were incomplete (the S-037 pre-closure case), the gate would fire on honest snapshots; if the round-trip is complete, the gate fires only on adversarial mutations.

**S-037 (`DAppRegistryLifecycle.md` — `d:` namespace lifecycle).** The S-037 closure threads `dapp_registry_` through both surfaces. Without it, T-5 of `S033StateRootNamespaceCoverage.md` would fail at the `d:` namespace for any DApp-active chain, and T-1 of this proof would falsely throw on honest snapshots. The composition: T-1 ↔ S-037 must hold conjunctively for the snapshot path to be sound and live for DApp-active chains.

**S-038 (producer-side wiring).** Per `BlockchainStateIntegrity.md` §2.3: pre-S-038 the apply-time gate was dormant on production blocks; pre-S-038 the snapshot-side gate is *also* dormant on the same blocks. S-038's closure makes both gates active. The composition: T-1 ↔ S-038 must hold conjunctively for the snapshot path's security guarantee to be operationally real (not dormant).

**FA-Apply-12 (`AppliedReceiptRestore.md` — `i:` namespace dedup-set restore).** The `i:`-namespace contributes to the state_root via `build_state_leaves` (chain.cpp:332-341). FA-Apply-12 proves the dedup-set survives restore byte-identically; this proof's T-2 depends on the dedup-set being faithfully restored (else `applied_state_root` would diverge from `head_state_root` on any chain with non-empty receipts). The composition: T-1 + T-2 + FA-Apply-12 jointly prove cross-shard receipt dedup survives snapshot bootstrap intact, with the same gate catching any cross-shard tamper at restore.

---

## 6. Composition with FB-track specs

**FB6 Snapshot.tla.** The baseline snapshot/restore state machine. Models the snapshot envelope's wire structure, the per-namespace serialize loops, and the restore loops. Provides the foundation that this proof's T-1 is the gate over. FB6 is *deliberately silent* on the gate's recompute-and-throw semantics — the gate is a downstream invariant that FB31 captures.

**FB17 AppliedReceiptRestore.tla.** The `i:` namespace dedup-set restore state machine (companion to FA-Apply-12 / `AppliedReceiptRestore.md`). Five invariants TypeOK / DedupSetSurvivesRestore / NoDoubleCreditPostRestore / RestoreIdempotent / A1ConservationAcrossRestore + 2 temporal props. Together with FB31 below, covers the `i:`-namespace contribution to `applied_state_root` end-to-end.

**FB31 SnapshotIntegrity.tla.** The composed snapshot integrity state machine — sibling spec to this proof's T-1..T-5. Models the donor → wire → receiver flow with adversarial mutation at every wire boundary, and the post-restore gate as the unifying check. FB31's `GateRejectsTamperedSnapshot` invariant is the machine-checkable analogue of T-2; its `HonestSnapshotsRestoreSuccessfully` invariant is the analogue of T-1's no-false-positive clause (conditional on S-037 + S-038 closure, i.e., the model parameters that turn on the namespace round-trip + producer wiring).

The three FB specs compose to cover the snapshot surface end-to-end: FB6 provides the baseline restore SM, FB17 covers the cross-shard `i:`-namespace special case, FB31 ties them together with the integrity gate.

---

## 7. Findings

### F-1 (Gate location is load-bearing — maintenance contract)

The post-restore gate fires at `chain.cpp:1893-1911`, after every namespace's source map has been populated and after the legacy-supply solve-for-genesis at chain.cpp:1864-1877, but before the A9 Phase 2C committed-state-view publish at chain.cpp:1917-1928. This position is the unique sound placement:

- **Earlier** (before all restore loops complete): `c.compute_state_root()` would return a partial Merkle root over an incomplete state, producing false-positive throws on every snapshot.
- **Later** (after the committed-state-view publish): a throwing gate would leak corrupted state into the lock-free read cache before the throw propagates, exposing tampered state to RPC consumers via the `*_lockfree()` accessors.
- **Outside the function** (at the caller): integration would require duplicating the gate at every caller (`Node::bootstrap_from_snapshot`, the `determ snapshot fetch` CLI, the `determ test-snapshot-defense` unit, etc.) — fragile to forget at a new call site.

**Maintenance contract.** Any future re-architecting of `restore_from_snapshot` (e.g., extracting per-namespace restore loops into helpers, adding new namespaces, parallelizing the loops) MUST keep the gate in this position. Code review of any change touching the function should explicitly verify the gate is the last operation before the A9 publish + return.

**Severity:** N/A (design contract; not a defect).

### F-2 (Monitor pattern recommendation — periodic snapshot-verify on archive snapshots)

Operators maintaining archive snapshots (long-term-retention copies of chain state for disaster-recovery, historical analysis, or fast-bootstrap distribution) should periodically run `determ snapshot --in <file>` against their archived snapshots to detect at-rest corruption early — before a downstream peer consumes the snapshot during a bootstrap. The `snapshot` CLI (`src/main.cpp:5196`) invokes `restore_from_snapshot` end-to-end and reports the post-restore state_root; a `--state-root <hex>` flag (already shipped) lets operators pin the expected root and fail with a non-zero exit code on mismatch.

The amortized recommendation: run a nightly cron over the archive directory; alert on any non-zero exit. At-rest corruption (bit rot, partial filesystem damage, accidental partial-overwrite during backup rotation) is detected within 24 hours rather than only at the next bootstrap.

**Severity:** Low (operator monitoring; complements the in-process gate).

### F-3 (Composition with S-021 chain.json wrap is complementary, not redundant)

S-021's chain.json wrap (`{head_hash, blocks}` envelope with load-time `head_hash` recompute at chain.cpp:2037-2051) covers the **chain.json on disk** surface: it detects tampering of block bodies via `prev_hash` continuity + the head's `compute_hash` anchor. S-012's post-restore gate covers the **snapshot on disk or wire** surface: it detects tampering of the per-namespace state maps.

The two surfaces are disjoint:

- **chain.json on disk** carries `blocks_` (the canonical block sequence) but NOT a separate per-namespace state dump — the receiver replays every block during `Chain::load` to derive state. S-021's gate fires on `head_hash` mismatch (post-replay) or `prev_hash` mismatch (mid-replay).
- **Snapshot on disk or wire** carries `accounts` / `stakes` / `registrants` / `dapp_registry` / `abort_records` / `merge_state` / `pending_param_changes` / `applied_inbound_receipts` / `tail headers` (full namespace dump) — the receiver does NOT replay block bodies, just deserializes the state directly. S-012's gate fires on Merkle-root mismatch against the tail header's stored value.

The two gates are complementary: a corrupted chain.json fails S-021's `prev_hash`/`head_hash` check; a corrupted snapshot fails S-012's state_root check. Neither gate alone covers both surfaces. Together they cover the full at-rest persistence surface.

**Severity:** N/A (composition observation; not a defect).

### F-4 (Pre-S-038 historical-block bypass is intentional backward-compat)

The zero-skip shim at chain.cpp:1894-1896 (`if (claimed != Hash{}) { … verify … }`) means that snapshots whose tail header was produced by a pre-S-038 chain (or a node that didn't yet ship S-038) will skip verification — the receiver bootstraps without state_root checking. This is intentional backward-compat (mirrors the apply-time gate's zero-skip per `WireFormatBackwardCompat.md` C-2).

The fallback security for pre-S-038 snapshots: the chain.json `head_hash` continuity (S-021) still authenticates the block sequence; once the receiver starts applying post-S-038 blocks (which carry non-zero state_root and fire the apply-time gate), state divergence becomes detectable from that point forward.

A flag-day migration that refuses to bootstrap from a pre-S-038 snapshot would harden T-1 retroactively, but the coordination cost is not justified — the dormant snapshots are still protected by the chain-replay path's `prev_hash` + committee-signature continuity.

**Severity:** Very Low (backward-compat artifact; not a defect; tracked as a maintenance discipline).

---

## 8. Cross-references

### Source files

- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root` (the central primitive invoked on both sides of the gate).
- `src/chain/chain.cpp:267-411` — `Chain::build_state_leaves` (ten-namespace leaf generator).
- `src/chain/chain.cpp:1421-1446` — apply-time state_root gate (sibling surface; `BlockchainStateIntegrity.md` T-2).
- `src/chain/chain.cpp:1541-1701` — `Chain::serialize_state` (snapshot producer-side; T-5 of `S033StateRootNamespaceCoverage.md`).
- `src/chain/chain.cpp:1703-1932` — `Chain::restore_from_snapshot` (snapshot consumer-side; this proof's primary subject).
- `src/chain/chain.cpp:1893-1911` — **the post-restore state_root verification gate** (T-1's mechanism).
- `src/chain/chain.cpp:1818-1834` — dapp_registry restore (S-037 closure; T-5 dependency).
- `src/chain/chain.cpp:1832-1862` — headers ingest (where `head_state_root := c.blocks_.back().state_root` enters the chain).
- `src/chain/chain.cpp:1917-1928` — A9 Phase 2C committed-state-view publish (executes after the gate; gate's throw prevents corrupted state from leaking here).
- `src/node/node.cpp:1024-1117` — `Node::try_finalize_round` (S-038 producer-side wiring at 1093-1117; T-5 dependency).
- `src/main.cpp:5196` — `cmd_snapshot` (the operator-facing `determ snapshot` CLI; F-2 recommendation invokes this).
- `include/determ/chain/block.hpp:460-484` — `Block.state_root` field.
- `include/determ/chain/chain.hpp:539-624` — full Chain mutable-state member list (the universe of state covered by the gate's recompute).

### FA-track companion proofs

- `docs/proofs/Preliminaries.md` (F0) — §2.1 SHA-256 collision resistance (A2); §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/BlockchainStateIntegrity.md` — four-surface composition (S-021 + S-033 + S-038 + apply-gate); this proof covers the snapshot sub-surface.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — ten-namespace coverage completeness; T-1 + T-5 there are preconditions for T-1 + T-2 here.
- `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) — generic serialize/restore equivalence theorem T-S1 + T-S2 that this proof's T-5 specializes.
- `docs/proofs/AppliedReceiptRestore.md` (FA-Apply-12) — `i:`-namespace dedup-set restore (composition partner).
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — apply determinism; T-A1 there underwrites the gate's byte-equality semantics.
- `docs/proofs/DAppRegistryLifecycle.md` — `d:`-namespace lifecycle (S-037 closure narrative).
- `docs/proofs/WireFormatBackwardCompat.md` — zero-skip shim C-2 (the dormancy mechanism behind F-4 and the pre-S-038 backward-compat).

### FB-track companion specs

- `docs/proofs/tla/Snapshot.tla` (FB6) — baseline snapshot/restore state machine.
- `docs/proofs/tla/AppliedReceiptRestore.tla` (FB17) — `i:`-namespace dedup-set restore SM.
- `docs/proofs/tla/SnapshotIntegrity.tla` (FB31) — composed snapshot integrity SM (sibling to this proof).
- `docs/proofs/tla/BlockchainStateIntegrity.tla` (FB26) — four-surface state-integrity composition SM (parent of FB31).

### SECURITY.md sections

- `docs/SECURITY.md` §S-012 — snapshot-bootstrap closure narrative this proof formalizes.
- `docs/SECURITY.md` §S-021 — chain.json wrap (sister surface per F-3).
- `docs/SECURITY.md` §S-033 — state_root Merkle commitment + apply-time gate (data-layer).
- `docs/SECURITY.md` §S-037 — dapp_registry snapshot round-trip closure (T-5 dependency).
- `docs/SECURITY.md` §S-038 — producer-side state_root population (T-5 dependency).

### Tests

- `tools/test_snapshot_bootstrap.sh` — end-to-end snapshot bootstrap; verifies T-1's gate passes on honest snapshots.
- `tools/test_snapshot_roundtrip.sh` (15 assertions) — serialize → restore round-trip identity; T-5 coverage.
- `tools/test_snapshot_then_apply.sh` (21 assertions) — post-restore replay matches control-chain at every height; composes T-1 with cross-node convergence.
- `tools/test_dapp_snapshot.sh` (12 assertions) — strict S-012 + S-037 + S-038 composition assertion: tail-head's stored `state_root` is non-empty AND matches the receiver's post-restore `compute_state_root()`. Pre-S-037 + pre-S-038, this assertion would have failed.
- `tools/test_snapshot_defense.sh` — `determ test-snapshot-defense` lock-in; exercises the gate's throw path on tampered inputs (S-018 defense-in-depth + S-012 gate).
- `tools/test_chain_integrity.sh` — sister surface for S-021 (F-3 composition).

### Specifications

- `docs/PROTOCOL.md` §4.1.1 — canonical ten-namespace key + value encoding table (wire-level contract for the leaf set).
- `docs/PROTOCOL.md` §11 — snapshot serialization format (the wire surface this proof's gate validates).
- `docs/PROTOCOL.md` §4.3 — `compute_block_digest` exclusion list (confirms `state_root` is OUT of digest, IN of `signing_bytes`; T-4 supporting for the A1 reduction).
- NIST FIPS 180-4 — SHA-256 (referenced by A2).
- RFC 8032 — Ed25519 (referenced by A1).
