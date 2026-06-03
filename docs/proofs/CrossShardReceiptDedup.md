# FA-Apply — Cross-shard receipt dedup (applied_inbound_receipts_)

This document formalizes the apply-layer dedup mechanism that guarantees exactly-once credit of cross-shard inbound receipts. The mechanism is the `Chain::applied_inbound_receipts_` set (declared at `include/determ/chain/chain.hpp:605`, type `std::set<std::pair<ShardId, Hash>>`), the public query predicate `Chain::inbound_receipt_applied(src_shard, tx_hash)` (`chain.cpp:204–207`), and the apply-side check + insert at `chain.cpp:1363–1374`. Together they pin the central FA7 dedup invariant from the apply-layer angle: every cross-shard receipt credits the destination account *exactly once*, regardless of how many times the underlying bundle is gossiped, how many candidate blocks include the same `(src_shard, tx_hash)`, or how many snapshot-bootstrap round-trips the receiving chain undergoes.

The proof is mechanical: the apply-side dedup is a single `if (applied_inbound_receipts_.count(key)) continue; ... applied_inbound_receipts_.insert(key);` pair on the V13-cleared inbound-receipt loop; the dedup-set is a `std::set` whose insertion is idempotent by construction; the set is enumerated by `Chain::build_state_leaves` under the `i:` namespace (`chain.cpp:331–341`) so its contents are cryptographically bound into S-033 + S-038 state-root commitment; and the snapshot writer/restorer pair (`chain.cpp:1585–1592` + `chain.cpp:1778–1785`) covers the round-trip. The strength is consolidation: FA7 (`CrossShardReceipts.md`) covers the protocol-level no-double-credit / no-fabrication claim via the L-7.2 dedup-monotone lemma + L-7.4 K-of-K gossip ratification; the present proof drills into the apply-side mechanism that L-7.2 cites as a black box, exhibits the seven theorem-grade invariants its `std::set` semantics produce, and pins the snapshot round-trip dependency that FA-Apply-2 T-S3 cross-namespace coverage carries through.

**Companion documents:** `Preliminaries.md` (F0) for notation and the V12 + V13 validator predicates; `AccountStateInvariants.md` (FA-Apply) for the I-4 auto-creation path (2) (cross-shard inbound credit creates an `accounts_` entry on first reference) + I-5 credit-channel decomposition (inbound receipt is one of the eight credit channels) + I-6 A1 closure that consumes `accumulated_inbound_`; `SnapshotEquivalence.md` (FA-Apply-2) for T-S3 cross-namespace coverage that includes the `i:` namespace and L-S0 / L-S1 dedup-set restore round-trip; `CrossShardReceipts.md` (FA7) for the upstream atomicity + no-fabrication theorems T-7 / T-7.1 (the present proof drills into the destination-side mechanism L-7.2 cites); `GovernanceParamChange.md` (FA-Apply-8) for the structural-template (a state-mutating apply-side primitive whose semantics survive snapshot bootstrap).

---

## 1. Setup

### 1.1 Storage

Per `include/determ/chain/chain.hpp:602–605`:

```cpp
// rev.9 B3.4: dedup tracking for delivered inbound receipts.
// Populated during apply (also during replay via load), consulted
// by producer + validator to guarantee exactly-once credit.
std::set<std::pair<ShardId, Hash>>           applied_inbound_receipts_;
```

The set is keyed by the pair `(ShardId, Hash)` where `ShardId` is the source shard the receipt originated from and `Hash` is the 32-byte SHA-256 of the originating cross-shard `TRANSFER` transaction. The choice of `std::set` (not `std::unordered_set`) is load-bearing: the red-black tree's sorted-key iteration is consumed by `Chain::build_state_leaves` (`chain.cpp:332–341`) which emits one `i:`-namespace leaf per element in deterministic order, then `Chain::compute_state_root` folds the leaves through the balanced-Merkle construction. Replacing `std::set` with an unordered container would silently fork the state_root across implementations.

### 1.2 Query predicate

Per `chain.cpp:204–207`:

```cpp
bool Chain::inbound_receipt_applied(ShardId src_shard,
                                       const Hash& tx_hash) const {
    return applied_inbound_receipts_.count({src_shard, tx_hash}) > 0;
}
```

A pure-read accessor; no chain-state mutation. The predicate is the canonical "has this receipt already been credited?" query consumed at three sites:

- **Producer-side admission** at `src/node/producer.cpp:511`: `if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash)) continue;`. The producer skips a duplicate receipt from `pending_inbound_receipts_` when composing the block body so the block doesn't carry a no-op entry that V13 would reject.
- **Validator-side V13 check** at `src/node/validator.cpp:1142`: `if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash)) return {false, "inbound_receipts[...] already credited in earlier block"};`. The validator rejects a block whose `inbound_receipts[]` includes an already-credited pair.
- **Apply-side belt-and-suspenders** at `chain.cpp:1365`: `if (applied_inbound_receipts_.count(key)) continue;`. Even with V13 having rejected duplicates upstream, the apply-side guard makes chain *replay* (e.g., on `Chain::load` from disk, or by a snapshot-receiving node re-running the inbound-receipt-bearing block) safe against double-credit if the dedup set was carried into the replay state.

### 1.3 Apply-side check + insert

Per `chain.cpp:1363–1381`:

```cpp
for (auto& r : b.inbound_receipts) {
    auto key = std::make_pair(r.src_shard, r.tx_hash);
    if (applied_inbound_receipts_.count(key)) continue;
    // S-007: overflow-checked credit on the cross-shard inbound path.
    auto& rcv = accounts_[r.to].balance;
    if (!checked_add_u64(rcv, r.amount, &rcv)) {
        throw std::runtime_error(
            "S-007: inbound receipt credit would overflow recipient "
            "balance (to=" + r.to + ")");
    }
    __ensure_applied_inbound_receipts();
    applied_inbound_receipts_.insert(key);
    if (!checked_add_u64(block_inbound, r.amount, &block_inbound)) {
        throw std::runtime_error(
            "S-007: per-block inbound sum overflowed u64");
    }
}
```

The body executes a fixed five-step sequence on any not-yet-applied key: (a) skip on dedup hit; (b) S-007 overflow-checked credit to `accounts_[r.to].balance`; (c) record the key in `applied_inbound_receipts_`; (d) S-007 overflow-checked accumulation into per-block `block_inbound`; (e) advance to the next receipt. The per-block `block_inbound` is then folded into `accumulated_inbound_` at apply-tail (`chain.cpp:1393`).

---

## 2. Theorems

### T-R1 — First-application credits the recipient

**Statement.** For every successful apply of a block `B` containing a `CrossShardReceipt r` whose key `k = (r.src_shard, r.tx_hash)` satisfies `k ∉ state_n.applied_inbound_receipts_`, the apply produces exactly the deltas:

```
Δaccounts_[r.to].balance          = +r.amount
Δapplied_inbound_receipts_         = insert(k)         (single insertion)
Δblock_inbound (then →             = +r.amount
   Δaccumulated_inbound_ at tail)
```

with no other state mutation from the inbound-receipt loop iteration on `r`. The S-007 overflow checks on both `accounts_[r.to].balance += r.amount` and `block_inbound += r.amount` ensure no u64 wrap; either throw aborts the entire apply via the outer `try { ... } catch { restore_state_snapshot(...); }` (A9 atomic apply, FA-Apply I-1 failure-mode).

**Proof sketch.** By inspection of `chain.cpp:1363–1381`. The dedup miss at line 1365 (`count(key) == 0`) skips the `continue` and falls through to the credit body. `checked_add_u64(rcv, r.amount, &rcv)` writes the post-overflow-checked sum back into `accounts_[r.to].balance`. `applied_inbound_receipts_.insert(key)` is a single `std::set::insert` on a not-yet-present key, which inserts and returns `{iterator, true}`. `checked_add_u64(block_inbound, r.amount, &block_inbound)` advances the per-block counter. No other state field is read or written from this loop iteration on `r`. The block-tail accumulation at `chain.cpp:1393` then folds `block_inbound` into `accumulated_inbound_` once per block, so a single receipt's amount contributes once to the chain-wide counter.

**Code witness.** `src/chain/chain.cpp:1363–1381` (the inbound-receipt apply loop body); `src/chain/chain.cpp:1393` (per-block accumulation tail); `src/chain/chain.cpp:33` (`checked_add_u64` S-007 helper).

**Test witness.** `tools/test_cross_shard_receipt_apply.sh` "Basic credit" assertion (`bob credited 10 from receipt`) + "A1 accumulated_inbound" assertions (counter bumped by exact amount; invariant holds). End-to-end `tools/test_cross_shard_transfer.sh` exercises the same property through a 3-node beacon + 2-shard cluster.

### T-R2 — Duplicate-application silent skip

**Statement.** For every successful apply of a block `B` containing a `CrossShardReceipt r` whose key `k = (r.src_shard, r.tx_hash)` satisfies `k ∈ state_n.applied_inbound_receipts_`, the apply produces NO mutation from the inbound-receipt loop iteration on `r`. Specifically:

```
Δaccounts_[r.to].balance          = 0
Δapplied_inbound_receipts_         = ∅                (no insertion)
Δblock_inbound                     = 0  (so Δaccumulated_inbound_ = 0 for r)
```

The dedup-set mutation is idempotent under the same key: a second insert of an already-present key is a no-op (`std::set::insert` returns `{iterator, false}` and does not duplicate). This is the central FA7 dedup invariant from the apply-side: regardless of how many times a receipt's bundle is re-gossiped, how many candidate blocks include it, or how many chain replays a receiving node runs, every `(src_shard, tx_hash)` credits the recipient at most once.

**Proof sketch.** By inspection of `chain.cpp:1365`. The `if (applied_inbound_receipts_.count(key)) continue;` predicate evaluates to `true` under the hypothesis `k ∈ applied_inbound_receipts_`, so control jumps to the next loop iteration without executing the credit body, the insert, or the `block_inbound` accumulation. The `std::set::count` query is a pure read with no side effects. No other state field is touched. The "silent" character is preserved: no exception throws, no validator-side log, no tx-fee charged (cross-shard inbound receipts carry the *originating* tx's fee, which was already debited on the source shard — see FA7 L-7.3 source-debit-precedes-emission; there is no fee on the destination side to refund or skip).

The argument composes with V13. On every honest chain, the apply-side dedup hit fires only on the *replay* path (chain re-loaded from disk, snapshot bootstrap re-applying intervening blocks, etc.), because V13 at `validator.cpp:1142` rejects any block whose `inbound_receipts[]` carries a key that the receiver's chain has already credited. The two layers are mutually reinforcing: V13 is the deny-by-default consensus rule (an honest network never finalizes a block with a duplicate receipt); the apply-side dedup is the replay-defense rule (after the chain accepts the block, re-running `apply_transactions` for any reason cannot re-credit). The apply-side belt-and-suspenders pattern matches the AccountStateInvariants I-2 "insufficient-balance does NOT bump nonce" pattern — both are no-op-on-replay defenses that the validator should have caught upstream, but the apply layer keeps as a structural backstop.

**Code witness.** `src/chain/chain.cpp:1365` (apply-side dedup-skip predicate); `src/node/validator.cpp:1142` (V13 upstream rejection); `src/node/producer.cpp:511` (producer-side admission skip — third layer, pre-block-composition).

**Test witness.** `tools/test_cross_shard_receipt_apply.sh` "Dedup contract" block (3 assertions: duplicate `(src_shard, tx_hash)` NOT re-credited; `accumulated_inbound` NOT double-counted; setup credited correctly). `tools/test_cross_shard_multi_receipt.sh` "Dedup across BLOCKS in presence of additional mixed-direction traffic" assertion exercises dedup-set isolation from the outbound flow.

### T-R3 — Per-source-shard independence

**Statement.** For two `CrossShardReceipt` entries `r₁, r₂` with `r₁.tx_hash == r₂.tx_hash` but `r₁.src_shard ≠ r₂.src_shard`, the dedup mechanism treats them as DISTINCT keys. Both receipts apply on the destination shard (assuming each passes V12 + V13 + the K-of-K gossip ratification for its respective source); both credit their respective recipients' balances; both insert their respective keys into `applied_inbound_receipts_`. Equivalently: the dedup is keyed on the *pair* `(src_shard, tx_hash)`, not on the bare `tx_hash`.

**Proof sketch.** By inspection of the key construction at `chain.cpp:1364`: `auto key = std::make_pair(r.src_shard, r.tx_hash);`. `std::pair<A, B>::operator<` is lexicographic over `(A, B)`, so `(s₁, h) < (s₂, h)` iff `s₁ < s₂` (the tx_hash tiebreaker only fires for equal source shards). Therefore `applied_inbound_receipts_.count({s₁, h}) == 0` does not imply `count({s₂, h}) == 0` for `s₁ ≠ s₂`; the two pairs are distinct elements of the set. The apply-side dedup-skip predicate at line 1365 fires only on exact-pair match. Each pair is credited and inserted independently.

**Why the pair-key and not bare tx_hash.** The bare-tx_hash variant would defend exactly against the unlikely case where two different source shards happen to produce a tx with the same SHA-256 hash — a collision that A2 (Preliminaries §2.1) bounds to `≤ 2⁻¹²⁸`. The pair-key design is defense-in-depth: it preserves the dedup mechanism's correctness even if A2 were partially broken (e.g., under a future cryptanalytic advance on SHA-256), since the source-shard component additionally disambiguates. The trade-off: the pair-key admits the unlikely "two compromised shards each produce a tx with the same hash" attack as TWO distinct credits, but this case is already covered by FA7's source-shard validity check (L-7.4: forging a source block requires breaking the K-of-K Ed25519 gate, EUF-CMA `≤ 2⁻¹²⁸`). The pair-key choice therefore strictly improves the dedup-mechanism's robustness without weakening any other property — see §3 "Dedup key choice" for the longer rationale.

**Code witness.** `src/chain/chain.cpp:1364` (key construction via `std::make_pair`); `src/chain/chain.cpp:1365` (exact-pair dedup-skip); the `i:` namespace key encoding at `chain.cpp:333–340` (the leaf key prepends the 8-byte big-endian `src_shard` before the 32-byte `tx_hash`, making the pair injection into the state-root injective on the pair).

**Test witness.** `tools/test_cross_shard_atomicity.sh` exercises BOTH the source and destination chains in lock-step across a chain-pair; the pair-key disambiguation is implicit (each receipt carries its source shard). `tools/test_cross_shard_multi_receipt.sh` "Two receipts to SAME destination in one block" + "Two receipts to DISTINCT destinations in one block" cover the cumulative-credit + independence cases; the per-source-shard key independence falls out as a structural consequence of `std::pair` equality.

### T-R4 — Snapshot restore preserves dedup set

**Statement.** For every Chain `C` and every `header_count ≥ 1`, the restored chain produced by `restore_from_snapshot(serialize_state(C, header_count))` has `applied_inbound_receipts_` byte-identical to `C.applied_inbound_receipts_`. Equivalently: snapshot bootstrap carries the dedup set across the round-trip; a node bootstrapped from a snapshot at chain tip `B_k` carries every `(src_shard, tx_hash)` that the donor credited at any height `≤ k`, and duplicate receipts re-gossiped to the receiver post-restore still silently skip via T-R2.

**Proof sketch.** This is a direct corollary of `SnapshotEquivalence.md` (FA-Apply-2) T-S1 (Serialization-restore identity) + the `applied_inbound_receipts` row of the L-S0 / L-S1 coverage table (FA-Apply-2 §2). Concretely:

- **Serialize side** at `chain.cpp:1585–1592`: a `json applied = json::array()` loop emits one entry per `(src, tx_hash)` pair in the set, with each entry as `{"src_shard": src, "tx_hash": to_hex(tx_hash)}`. The `std::set` iteration order is the deterministic lexicographic order on `(ShardId, Hash)` pairs, which the JSON output preserves.
- **Restore side** at `chain.cpp:1778–1785`: `if (snap.contains("applied_inbound_receipts"))` guards a load loop that re-inserts each `{src_shard, tx_hash}` pair into `c.applied_inbound_receipts_`. Missing field defaults to empty set (the legacy snapshot path; not exercised on any post-S-035 chain).
- **State-root binding** via the `i:` namespace at `chain.cpp:331–341`: `build_state_leaves` emits one Merkle leaf per pair, with key `"i:" + src_be8 + tx_hash` (16-byte source-shard big-endian prefix + 32-byte hash) and a fixed presence-marker value-hash. The leaves contribute to `compute_state_root`. The receiver's `compute_state_root` after restore must match the snapshot tail head's `state_root` field (G2 gate at `chain.cpp:1893–1911`), so any divergence in the restored `applied_inbound_receipts_` would surface as a G2 failure that throws and rolls back the restore.

The three layers compose: the JSON round-trip carries the pairs verbatim; the `std::set` re-insertion is order-independent (sorted-key invariant of the red-black tree), so two re-inserts of the same pair-multiset produce the same final tree shape; the S-033 + S-038 state-root gate is the cryptographic backstop that catches any silent divergence between donor and receiver. Theorem T-R2 then carries forward on the restored chain because the set membership is preserved.

**Code witness.** `src/chain/chain.cpp:1585–1592` (snapshot serialize loop); `src/chain/chain.cpp:1778–1785` (snapshot restore loop); `src/chain/chain.cpp:331–341` (`i:` namespace state-root contribution); `src/chain/chain.cpp:1893–1911` (G2 state-root verification gate inside `restore_from_snapshot`).

**Test witness.** `tools/test_applied_receipt_restore.sh` (9 assertions exercising the joint surface: 3 receipts credited pre-restore → snapshot JSON carries `applied_inbound_receipts[]` array with 3 entries → restored chain's `inbound_receipt_applied` predicate is true for all 3 pairs → duplicate receipt on restored chain silently skipped → fresh post-restore receipt credits normally → `compute_state_root` identical pre- and post-restore via the `i:` namespace contribution → A1 invariant counter `accumulated_inbound` preserved at 60 with `expected == live`). `tools/test_state_root_namespaces.sh` cross-checks the `i:` namespace as one of the 10 state-root namespaces.

### T-R5 — A1 invariance under dedup

**Statement.** Across any finite sequence of blocks `B_1, B_2, ..., B_n` applied to a Chain `C`, including blocks whose `inbound_receipts[]` contains duplicate submissions, the chain-wide counter `accumulated_inbound_` advances by exactly:

```
Σ {r.amount : r is the FIRST application of pair (r.src_shard, r.tx_hash)
              in the sequence B_1..B_n}
```

i.e., the total of *unique* receipt amounts. Duplicate submissions contribute zero (T-R2 short-circuits the per-block `block_inbound` accumulation; the per-block sum then folds into `accumulated_inbound_` at apply-tail at `chain.cpp:1393`, but the duplicate's amount was never added to `block_inbound` in the first place). The A1 unitary-balance invariant `live_total_supply == expected_total` (FA-Apply I-6) closes correctly under this restriction because every duplicate's "missing" credit is matched by the unchanged `accounts_[r.to].balance`: the receiver's balance also did not advance, so the per-account sum and the chain-wide counter remain in lock-step.

**Proof sketch.** By induction on the block index. Base case: `accumulated_inbound_ = 0` at genesis and `applied_inbound_receipts_ = ∅`; the equality holds vacuously. Inductive step: assume the equality after applying `B_1..B_k`. Apply `B_{k+1}`. Within the inbound-receipt loop, each receipt `r ∈ B_{k+1}.inbound_receipts` either (a) takes the dedup-hit branch at `chain.cpp:1365` and contributes nothing to `block_inbound` (T-R2), or (b) takes the apply branch and contributes `r.amount` to `block_inbound` exactly once (T-R1). At apply-tail (`chain.cpp:1393`), `accumulated_inbound_ += block_inbound`, so the chain-wide counter advances by exactly the sum of (b)-branch amounts, which is the sum of *first* applications across `B_{k+1}`'s receipt list. The induction hypothesis combined with this step gives the equality for `B_1..B_{k+1}`.

The A1 closure (FA-Apply I-6) at `chain.cpp:1397–1419` consumes `accumulated_inbound_` as one of the five terms in `expected_total`: `live = genesis + accumulated_subsidy + accumulated_inbound - accumulated_slashed - accumulated_outbound`. The duplicate-skip preserves both sides — the recipient's balance is unchanged AND the counter is unchanged — so the equality holds. A regression that incremented `accumulated_inbound_` on a duplicate (e.g., the bug pattern "increment counter then check dedup, instead of check then increment") would produce an A1 mismatch at apply-tail and throw the rollback diagnostic.

**Code witness.** `src/chain/chain.cpp:1377–1380` (per-block `block_inbound` overflow-checked accumulation, gated by the line-1365 dedup-skip); `src/chain/chain.cpp:1393` (block-tail fold into `accumulated_inbound_`); `src/chain/chain.cpp:1397–1419` (A1 apply-tail assertion + rollback diagnostic).

**Test witness.** `tools/test_cross_shard_receipt_apply.sh` "Dedup contract" assertion (`accumulated_inbound NOT double-counted` on duplicate submission). `tools/test_applied_receipt_restore.sh` "A1 invariant" assertion (`accumulated_inbound` counter preserved at 60 across snapshot round-trip; `expected == live`). `tools/test_supply_lifecycle.sh` exercises A1 closure across mixed cross-shard inbound + outbound traffic. `tools/test_cross_shard_atomicity.sh` cross-checks the chain-pair conservation `src.accumulated_outbound == dst.accumulated_inbound` which only holds if T-R5 holds on the destination side.

### T-R6 — Apply-determinism with dedup

**Statement.** For any two Chain instances `C₁` and `C₂` with `C₁ ≡_S C₂` (per FA-Apply-2 §1.2 state-equivalence), and any block `B` containing inbound receipts (including blocks where the same `(src_shard, tx_hash)` pair appears in earlier blocks of either chain's history), the apply results satisfy `apply_transactions(C₁, B) ≡_S apply_transactions(C₂, B)`. In particular, the final `applied_inbound_receipts_` sets coincide, the final `accumulated_inbound_` counters coincide, and the final `compute_state_root` values coincide byte-identically.

**Proof sketch.** This is the apply-after-restore equivalence (FA-Apply-2 T-S2) specialized to the inbound-receipt apply path. The argument has three components:

- **Set-equality preserved by apply.** Under hypothesis `C₁.applied_inbound_receipts_ == C₂.applied_inbound_receipts_`, the dedup-skip predicate at `chain.cpp:1365` evaluates identically on both sides for every receipt in `B`. Each receipt either takes the credit branch on both sides (and inserts the same key into both sets) or takes the skip branch on both sides (and mutates neither). After the loop, the two sets remain equal.
- **Counter-equality preserved by apply.** The per-block `block_inbound` accumulation at `chain.cpp:1377` adds the same amounts on both sides (same receipts × same dedup decisions × same `r.amount`). The block-tail fold at line 1393 then advances `accumulated_inbound_` by the same amount on both sides. The pre-fold equality `C₁.accumulated_inbound_ == C₂.accumulated_inbound_` carries forward.
- **State-root-equality preserved by apply.** Under hypothesis `compute_state_root(C₁) == compute_state_root(C₂)` (FA-Apply-2 §1.2 condition 5), and given the post-apply set + counter equalities, `compute_state_root(apply(C₁, B)) == compute_state_root(apply(C₂, B))` follows from `build_state_leaves` being a deterministic function of the maps (FA-Apply-2 §2 L-S0) and `merkle_root` being a deterministic function of the leaves.

The dedup-set mutation is order-independent within a single block (the `std::set::insert` is commutative on distinct keys; the iteration order over `b.inbound_receipts` is the block's serialized order which is consensus-pinned). Across blocks, the dedup-set is monotonically growing (no `erase` path on `applied_inbound_receipts_` exists in the codebase — verified by `Grep applied_inbound_receipts_.erase` returning no matches), so two chains applying the same block sequence reach the same final set regardless of any timing or scheduling differences in the surrounding apply-path branches.

**Code witness.** `src/chain/chain.cpp:1363–1381` (deterministic apply loop body); `src/chain/chain.cpp:267` (`build_state_leaves` deterministic enumeration); the absence of any `applied_inbound_receipts_.erase` call site in the codebase (only insertions and read queries).

**Test witness.** `tools/test_cross_shard_receipt_apply.sh` "Determinism" assertion (two chains applying the same receipt sequence produce identical state_roots). `tools/test_cross_shard_multi_receipt.sh` "Determinism" assertion across mixed inbound/outbound traffic. `tools/test_applied_receipt_restore.sh` "S-033 state_root preservation" assertion (snapshot round-trip preserves state_root via the `i:` namespace).

### T-R7 — Pre-receipt-application non-existence guarantee

**Statement.** For any Chain `C` and any pair `(src_shard, tx_hash)` such that no block in `C`'s apply history credited the pair (i.e., no apply-loop iteration executed the line-1374 `applied_inbound_receipts_.insert(key)` for this key), the predicate `C.inbound_receipt_applied(src_shard, tx_hash)` returns `false`. The predicate is therefore the canonical queryable witness for "this receipt is eligible for inclusion in a new block."

**Proof sketch.** By inspection of `chain.cpp:204–207`: the predicate returns `applied_inbound_receipts_.count({src_shard, tx_hash}) > 0`. The `std::set::count` query is a pure function of the set's contents. Under hypothesis "no prior apply credited the pair," no `insert(key)` call occurred for this pair, so `count(key) == 0` and the predicate returns `false`.

The contrapositive direction (T-R7'): if the predicate returns `true`, then the pair was inserted by *some* apply-loop iteration. By the codebase-search argument in T-R6 (no `erase` path on `applied_inbound_receipts_`), the pair has remained in the set since its first insertion, which is uniquely tied to the first credit via the dedup-skip predicate at line 1365 (T-R2 establishes the unique-first-application semantics). The contrapositive establishes the predicate's soundness: `true` implies "credited at least once" (in practice, exactly once, by T-R2).

The producer's admission gate at `producer.cpp:511` consumes the predicate's `false` value to decide whether to bake a receipt from `pending_inbound_receipts_` into the next block; the validator's V13 check at `validator.cpp:1142` consumes the predicate's `true` value to reject an honest-replay attempt that would duplicate-credit. The predicate is therefore the unique surface through which two protocol layers (producer + validator) coordinate the dedup contract before the apply-side line-1365 backstop fires.

**Code witness.** `src/chain/chain.cpp:204–207` (predicate body); `src/node/producer.cpp:511` (producer's `false`-branch admission); `src/node/validator.cpp:1142` (validator's `true`-branch rejection); `include/determ/chain/chain.hpp:401–407` (declaration with the producer + validator usage comment).

**Test witness.** `tools/test_cross_shard_receipt_apply.sh` "inbound_receipt_applied predicate" block (2 assertions: `false` before apply; `true` after apply). `tools/test_applied_receipt_restore.sh` "inbound_receipt_applied predicate true post-restore" assertion (all 3 credited pairs return `true` after snapshot restore — establishes that the predicate's semantics survive the round-trip).

---

## 3. Dedup key choice

The dedup-set key is the pair `(src_shard, tx_hash)`, not the bare `tx_hash`. The choice is documented at `include/determ/chain/chain.hpp:602–604`:

> `// rev.9 B3.4: dedup tracking for delivered inbound receipts.`
> `// Populated during apply (also during replay via load), consulted`
> `// by producer + validator to guarantee exactly-once credit.`

and at `chain.cpp:332`:

> `// applied_inbound_receipts_  (key = "i:" + src_be8 + tx_hash)`

**The case for bare-`tx_hash` keying.** Under A2 (SHA-256 collision resistance, Preliminaries §2.1), two distinct transactions producing the same hash is bounded `≤ 2⁻¹²⁸` per attempt. For an adversary budget `Q ≤ 2⁶⁰` and a chain with `≤ 2³² ≈ 4·10⁹` total transactions, the cumulative collision probability is `≤ 2⁻³⁶` per attack attempt. Bare-`tx_hash` keying would in principle catch every double-submission of the same logical transaction (same originating shard, same tx) cleanly, without the source-shard component.

**Why the pair-key is the right choice.** Three reasons compound:

1. **Defense-in-depth against A2 partial-break.** If a future cryptanalytic advance reduced SHA-256's effective collision-resistance to `2⁻⁶⁰` or worse, bare-`tx_hash` keying would allow a malicious source shard to manufacture a tx whose hash collides with a tx on a different source shard. The dedup-set would treat both as "already applied" once one of them landed; the second would silently skip on the destination side without crediting. The pair-key disambiguates by source: each source's tx is dedup'd against only its own prior submissions. Under a partial-A2 break, the worst case is "two credits for two tx with the same hash but different sources" — a per-source credit, not a missed credit; the source-shard validity check (FA7 L-7.4) bounds this case via K-of-K Ed25519 EUF-CMA, which is independent of A2.

2. **Matches the protocol's accounting structure.** The cross-shard receipt's `src_shard` field is one of its primary identifying fields — V12 (`validator.cpp::check_cross_shard_receipts`) requires that the receipt's `(src_shard, dst_shard)` matches the routing of the originating `TRANSFER`, so every receipt carries its source explicitly. The dedup key's `src_shard` component is therefore "free" data — already present in the receipt struct — and using it strictly increases the key's discriminative power. The state-root `i:` namespace encoding (`chain.cpp:333–340`) prepends the 8-byte big-endian `src_shard` before the tx_hash, making the encoding injective on the pair.

3. **No downside under standard assumptions.** Under standard A2 (collision-resistance `≤ 2⁻¹²⁸`), the bare-`tx_hash` keying and the pair-keying produce the same observable behavior on any non-pathological chain — distinct logical transactions have distinct hashes with overwhelming probability, so the source-shard component is redundant. The pair-key adds no consensus overhead (the receipt struct already carries `src_shard`), no state-root size cost (one Merkle leaf per applied receipt either way), and no apply-path complexity (a single `std::make_pair` call vs a bare assignment).

The pair-key is therefore the conservative choice: it strictly improves the dedup mechanism's robustness without weakening any other property, at zero overhead. The edge case it admits — two compromised shards each producing a tx with the same hash — would credit the destination *twice*, but this case is already covered by FA7's K-of-K source-block ratification: forging a source-block requires breaking Ed25519 EUF-CMA on at least one honest source-committee member (`≤ 2⁻¹²⁸` per attempt, FA7 L-7.4), and "two compromised shards" is the doubly-compromised case that FA1's K-of-K mutual-distrust safety branch addresses (one honest member per committee suffices).

---

## 4. Snapshot dedup-set restoration

Theorem T-R4 establishes that snapshot serialize → restore preserves the dedup set byte-identically. The mechanism depends on three cooperating components:

- **Serialize coverage** at `chain.cpp:1585–1592` — emits one JSON entry per `std::set` element.
- **Restore coverage** at `chain.cpp:1778–1785` — reads each entry back into the receiving chain's set.
- **State-root binding** via the `i:` namespace at `chain.cpp:331–341` — the set's contents contribute to `compute_state_root`, which the G2 gate (FA-Apply-2 §1.1) checks at restore time.

The three components were originally shipped together as part of the S-033 + S-038 + S-035-option-1 closure thread. Pre-closure, the dedup set existed in memory only; a node bootstrapping from a snapshot would lose the dedup state and re-credit any receipt re-gossiped post-restore. The closure pattern is documented in `docs/SECURITY.md` S-033 (the state-root field), S-038 (the producer's tentative-chain dry-run that populates `body.state_root`), and `tools/test_applied_receipt_restore.sh`'s 9-assertion suite which exercises the joint surface.

The dependency direction is one-way: FA-Apply-9 (the present proof) depends on FA-Apply-2 T-S1 / T-S3 for the round-trip identity, not vice versa. FA-Apply-2's L-S0 / L-S1 coverage table includes the `applied_inbound_receipts` row as one of ten state-bearing collections; the cross-namespace coverage theorem T-S3 cites the `i:` namespace as one of ten that contribute to the state-root. Without FA-Apply-2's guarantees, T-R4 above would be unprovable — the dedup set could silently diverge across donor + receiver, leaving a window for replay attacks against newly-bootstrapped nodes. The snapshot-equivalence proof is therefore a structural prerequisite for the dedup mechanism's correctness under fast-sync.

The S-033 + S-038 state-root binding is the cryptographic backstop: even if a malicious snapshot supplier provided a snapshot whose JSON `applied_inbound_receipts[]` array diverged from the chain's actual credits, the receiver's `compute_state_root` after restore would diverge from the snapshot tail head's `state_root` field and the G2 gate at `chain.cpp:1893–1911` would reject the snapshot. This makes the dedup-set restoration "authenticated against state divergence" without requiring a separate signature over the dedup-set itself — the existing S-033 commitment already covers it via the `i:` namespace.

---

## 5. What this doesn't prove

The theorems above target the apply-layer dedup mechanism. They do not extend to:

- **Cross-shard receipt wire format / encoding.** The `CrossShardReceipt` struct's binary layout, the V12 (`check_cross_shard_receipts`) source-side field-equality check, and the validator's payload-shape verification are the scope of FA7 + `docs/PROTOCOL.md` §6. The present proof references the receipt fields `src_shard`, `tx_hash`, `to`, `amount` only insofar as the apply-side dedup loop consumes them; the canonical definitions live in `include/determ/chain/block.hpp::CrossShardReceipt`.

- **Source-shard validity (the SHARD_TIP / K-of-K committee-signed validation).** The gossip-side ratification path (`net/gossip.cpp::on_cross_shard_receipt_bundle` → `node.cpp::on_cross_shard_receipt_bundle` → K Ed25519 signatures verified against the source-committee pool) is the scope of FA7 L-7.4. The present proof's T-R3 assumes V12 has already accepted the source-side binding; the cryptographic argument (forge K signatures `≤ K · 2⁻¹²⁸`) is FA7's responsibility. The apply-side dedup is the *last* line of defense — it depends on the earlier gates having rejected fabricated receipts.

- **Atomic outbound-debit (the source-side `accumulated_outbound_` channel).** The TRANSFER cross-shard branch at `chain.cpp` debits the sender by `tx.amount + tx.fee` and increments `block_outbound`, which folds into `accumulated_outbound_` at apply-tail. The chain-pair conservation `src.accumulated_outbound == dst.accumulated_inbound` (modulo in-flight `Pending`) is the scope of FA7 Corollary T-7.1. The present proof's T-R5 covers only the destination-side `accumulated_inbound_` accounting; the symmetric source-side claim is tracked separately by FA-Apply I-5 (the "TRANSFER source (cross-shard)" channel + the `block_outbound` accumulation) and by FA7 T-7.1's global atomicity composition.

- **Liveness of receipt delivery.** FA7 T-7' (Receipt completeness — eventual delivery) covers the "every emitted receipt is eventually credited" property under FA4 liveness on both shards. The present proof's T-R1 / T-R2 / T-R5 cover only the *correctness* of credits that *do* occur; the *eventuality* claim is FA7's scope. If a destination shard goes permanently silent, the receipt is stuck in `Pending` indefinitely — see FA7 §6.1's "Failure modes" discussion and `docs/V2-DESIGN.md` for the v2+ refund-mechanism proposal.

- **MITM defense against in-flight snapshot tampering on the gossip wire.** As in FA-Apply-2 §5, the present proof assumes snapshot integrity (no in-flight bit-flips, no malicious peer manufacturing a forged snapshot whose dedup-set diverges from the chain's actual credits). The G1 + G2 gates catch any tamper that produces an internally-inconsistent snapshot, but they do not authenticate provenance. Operator-policy is the current defense (cross-check `head_hash` against a trusted source before accepting `snapshot_path`).

- **Per-receipt fee semantics.** Cross-shard receipts carry no destination-side fee — the fee was already debited on the source shard as part of the originating TRANSFER (FA7 L-7.3). The present proof's T-R1 / T-R2 are silent on fees because the destination apply path does not touch them.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V1–V15 (specifically V12 + V13 for cross-shard receipts) + assumption A2 (SHA-256 collision resistance) that underpins the dedup-key-choice rationale + A1 (Ed25519 EUF-CMA) backing FA7's K-of-K ratification. |
| `AccountStateInvariants.md` (FA-Apply) | I-4 auto-creation path (2) (cross-shard inbound credit on a non-existent recipient creates the `accounts_` entry); I-5 credit-channel decomposition (inbound receipt is one of the eight credit channels at line 1368); I-6 A1 closure consuming `accumulated_inbound_`. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 (Serialization-restore identity) + T-S3 (Cross-namespace coverage including `i:`) + L-S0 / L-S1 (snapshot coverage + restore identity for the `applied_inbound_receipts` field); T-R4 is the apply-side specialization. |
| `CrossShardReceipts.md` (FA7) | Upstream protocol-level atomicity theorems T-7 / T-7' / T-7.1; L-7.2 cites the apply-side dedup set as a black box that the present proof formalizes; L-7.4 K-of-K source-block ratification (the prereq for T-R3's pair-key choice). |
| `GovernanceParamChange.md` (FA-Apply-8) | Structural template — both are apply-side state-machine proofs over a chain-instance container whose semantics survive snapshot bootstrap. |
| `EconomicSoundness.md` (FA11) | A1 unitary-balance invariant (T-12); the `accumulated_inbound_` channel that T-R5 + T-R1 advance. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table including the `i:` namespace. |
| `docs/PROTOCOL.md` §6 | Cross-shard receipt wire format + V12 / V13 validator predicates. |
| `docs/PROTOCOL.md` §11 | Snapshot wire format including the `applied_inbound_receipts` field. |
| `docs/SECURITY.md` §S-033 / §S-038 | State-root commitment + producer-side wiring that makes T-R4 non-vacuous. |
| `tools/test_cross_shard_receipt_apply.sh` | T-R1 / T-R2 / T-R5 / T-R7 (~12 assertions on the single-chain inbound apply). |
| `tools/test_applied_receipt_restore.sh` | T-R4 + T-R7 across the snapshot round-trip (9 assertions). |
| `tools/test_cross_shard_atomicity.sh` | T-R5 chain-pair conservation (10 assertions). |
| `tools/test_cross_shard_multi_receipt.sh` | T-R2 + T-R3 across multi-receipt + dedup-across-blocks scenarios (19 assertions). |
| `tools/test_cross_shard_outbound_apply.sh` | Source-side counterpart (out-of-scope for the present proof; covered by FA-Apply I-5 + FA7). |
| `tools/test_cross_shard_transfer.sh` | End-to-end 3-node beacon + 2-shard cluster (network-level cross-shard transfer). |
| `tools/test_state_root_namespaces.sh` | `i:` namespace state-root contribution (cross-checks T-R4's state-root binding). |
| `include/determ/chain/chain.hpp:401–407` | `inbound_receipt_applied` declaration with the producer + validator usage comment. |
| `include/determ/chain/chain.hpp:602–605` | `applied_inbound_receipts_` field declaration. |
| `src/chain/chain.cpp:204–207` | `inbound_receipt_applied` predicate body. |
| `src/chain/chain.cpp:331–341` | `i:` namespace state-root contribution. |
| `src/chain/chain.cpp:1363–1381` | Inbound-receipt apply loop (the central dedup + credit + accumulation flow). |
| `src/chain/chain.cpp:1393` | Block-tail fold of `block_inbound` into `accumulated_inbound_`. |
| `src/chain/chain.cpp:1585–1592` | Snapshot serialize for `applied_inbound_receipts_`. |
| `src/chain/chain.cpp:1778–1785` | Snapshot restore for `applied_inbound_receipts_`. |
| `src/node/producer.cpp:511` | Producer-side dedup-skip on block-body composition. |
| `src/node/validator.cpp:1142` | V13 validator-side dedup rejection. |

---

## 7. Status

All seven theorems (T-R1 through T-R7) are closed in the current codebase:

- **T-R1** (first-application credits the recipient) closed via the credit + insert + `block_inbound` accumulation at `chain.cpp:1367–1380`, gated by the line-1365 dedup-skip-predicate-miss; regression `test_cross_shard_receipt_apply.sh` "Basic credit" + "A1 accumulated_inbound" assertions.
- **T-R2** (duplicate-application silent skip) closed via the line-1365 `if (count(key)) continue;` predicate-hit; regression `test_cross_shard_receipt_apply.sh` "Dedup contract" block (3 assertions).
- **T-R3** (per-source-shard independence) closed via the `std::make_pair(src_shard, tx_hash)` key construction at line 1364 + the `std::pair` lexicographic equality; regression `test_cross_shard_atomicity.sh` + `test_cross_shard_multi_receipt.sh`.
- **T-R4** (snapshot restore preserves dedup set) closed via the serialize / restore loops at `chain.cpp:1585–1592` + `chain.cpp:1778–1785` + the `i:` namespace state-root binding at `chain.cpp:331–341` + the G2 gate at `chain.cpp:1893–1911`; regression `test_applied_receipt_restore.sh` (9 assertions, including the central S-033 state_root preservation).
- **T-R5** (A1 invariance under dedup) closed via the per-block `block_inbound` accumulation being gated by the line-1365 dedup-skip + the apply-tail fold at `chain.cpp:1393` + A1 closure at `chain.cpp:1397–1419`; regression `test_supply_lifecycle.sh` + `test_cross_shard_receipt_apply.sh` "accumulated_inbound NOT double-counted".
- **T-R6** (apply-determinism with dedup) closed via the inbound-receipt loop's reliance on only the chain's deterministic state + the block's consensus-pinned receipt order + the codebase-verified absence of any `applied_inbound_receipts_.erase` path; regression `test_cross_shard_receipt_apply.sh` "Determinism" assertion.
- **T-R7** (pre-receipt-application non-existence guarantee) closed via the `inbound_receipt_applied` predicate body at `chain.cpp:204–207` (`std::set::count > 0`); regression `test_cross_shard_receipt_apply.sh` "inbound_receipt_applied predicate" block.

No theorem is open or partial. The proof rests on a small set of primitives: the `std::set<std::pair<ShardId, Hash>>` typed container (sorted-key invariant of the red-black tree), the apply-side check-then-insert pattern at line 1365–1374 (the dedup primitive), the `inbound_receipt_applied` public predicate (the queryable witness), the `i:` namespace state-root contribution (the cryptographic binding), and the snapshot serialize/restore pair (the round-trip identity). The breadth of consequences — seven theorems plus the dedup-key-choice clarification + the snapshot-dedup-restoration dependency — is testimony to how few primitives the chain needs to express the exactly-once cross-shard credit guarantee without compromising replay determinism, A1 conservation, or fast-sync bootstrap correctness.
