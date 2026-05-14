# FA7 — Cross-shard receipt atomicity

This document proves that Determ's cross-shard transfer mechanism preserves the supply invariant and never double-credits a destination account, under the cryptographic and behavioral assumptions of `Preliminaries.md`.

The mechanism: a `TRANSFER` whose `to` address routes (via `shard_id_for_address`) to a different shard debits the sender on the source shard and emits a `CrossShardReceipt`. The destination shard credits `to.balance += amount` when a future block bakes the receipt into `inbound_receipts`. The properties to prove are *safety* (no double-credit, no fabrication) and *atomicity* (the per-shard supply counters compose into a global invariant).

**Companion documents:** `Preliminaries.md` (F0); `Safety.md` (FA1) for per-shard K-of-K safety; `Liveness.md` (FA4) for delivery bounds.

---

## 1. Theorem statements

**Setup.** Let `S = {0, 1, ..., shard_count - 1}` be the shard set. Each shard `s ∈ S` runs an independent Determ chain. A `CrossShardReceipt r` carries:

- `src_shard, dst_shard ∈ S` with `src_shard ≠ dst_shard`
- `src_block_index, src_block_hash`: pin the producing block
- `tx_hash, from, to, amount, fee, nonce`: copies of the source-side `TRANSFER` fields

Validator V12 (`check_cross_shard_receipts`) requires: source-side, each cross-shard `TRANSFER` in `b.transactions` has exactly one matching entry in `b.cross_shard_receipts` with field-wise equality and correct `(src_shard, dst_shard)`.

Validator V13 (`check_inbound_receipts`) requires: destination-side, each entry in `b.inbound_receipts` has `dst_shard == my_shard_id`, `src_shard ≠ my_shard_id`, is unique within the block, and is not yet in `applied_inbound_receipts_`.

Chain apply (`apply_transactions`, Preliminaries §9) does:

- Source-side: `sender.balance -= (amount + fee)`; if cross-shard, `block_outbound += amount` (no destination credit on this shard).
- Destination-side: for each `r ∈ b.inbound_receipts` not yet applied, `accounts_[r.to].balance += r.amount`; insert `(src_shard, tx_hash)` into `applied_inbound_receipts_`; `block_inbound += r.amount`.

**Theorem T-7 (Receipt safety — no double-credit, no fabrication).** Under:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2)
- **(A3) SHA-256 collision resistance** (Preliminaries §2.1)
- **(H1) Honest validator behavior** (Preliminaries §4) — at least one honest committee member per shard, per height (or the shard's FA1/FA5 safety branch covers full Byzantine via T-1.1's vacuous case)

then for every `(src, tx_h)`:

1. **(No double-credit)** No finalized destination chain credits `(src, tx_h)` more than once.
2. **(No fabrication)** Every credited `(src, tx_h)` on dst corresponds to a real cross-shard `TRANSFER` that was source-debited in a finalized block on `src`, with probability `≥ 1 - negl(λ)`.

**Theorem T-7' (Receipt completeness — eventual delivery).** Under T-7's assumptions plus FA4 liveness on both shards and bounded gossip delay `Δ_g`, every cross-shard TRANSFER finalized on `src` at height `h_s` is credited on `dst` at some finalized height `h_d` with `E[h_d - h_s] ≤ Δ_g / Δ_block + O(1)` block periods.

**Corollary T-7.1 (Per-shard A1 invariance composes to global supply atomicity).** Define global live supply as:

```
LiveGlobal = Σ_{s ∈ S} LiveLocal(s)
```

where `LiveLocal(s) = Σ accounts_[a].balance + Σ stakes_[v].locked` on shard `s`. Under T-7 and the per-shard A1 invariant (`live_s = genesis_s + subsidy_s + inbound_s - slashed_s - outbound_s`), at any consistent multi-shard cut (each shard at some finalized height with all in-flight receipts either delivered or pending):

```
LiveGlobal + Σ Pending = GenesisGlobal + SubsidyGlobal - SlashedGlobal
```

where `Pending = Σ in-flight receipt amounts not yet baked into a dst block`. **No mass is created or destroyed by cross-shard motion.**

---

## 2. Lemmas

### Lemma L-7.1 — V12 binds receipt to source transaction

For any block `b` accepted by V12 on shard `src`, and any cross-shard `TRANSFER tx ∈ b.transactions`, there is **exactly one** `r ∈ b.cross_shard_receipts` with `r.tx_hash == tx.hash`, `r.from == tx.from`, `r.to == tx.to`, `r.amount == tx.amount`, `r.fee == tx.fee`, `r.nonce == tx.nonce`, and `r.dst_shard == shard_id_for_address(tx.to, ...)`.

**Proof.** V12 iterates the cross-shard tx subset and asserts `cross.size() == cross_shard_receipts.size()` (size match) plus field-wise equality at each index (`src/node/validator.cpp::check_cross_shard_receipts`). Acceptance is contingent on this check passing. ∎

### Lemma L-7.2 — V13 dedup is monotone-correct

For any sequence of blocks `b_0, b_1, ..., b_n` on shard `dst` accepted in order, no pair `(b_i, b_j)` with `i ≤ j` has the same `(src_shard, tx_hash)` in their respective `inbound_receipts`.

**Proof.** When `b_i` is applied, every `r ∈ b_i.inbound_receipts` is inserted into `applied_inbound_receipts_` (chain.cpp, inbound-receipt apply loop). When `b_j` is validated, V13 rejects any `r` with `chain.inbound_receipt_applied(r.src_shard, r.tx_hash) == true` (validator.cpp `check_inbound_receipts`). V13 also rejects within-block duplicates via a `seen` set in the same function. Thus across all blocks, each `(src_shard, tx_hash)` is credited at most once. ∎

### Lemma L-7.3 — Source-side debit precedes receipt emission

In any block `b` on shard `src` accepted by the full validator pipeline, for each `r ∈ b.cross_shard_receipts` the corresponding source-side state transition `accounts_[r.from].balance -= (r.amount + r.fee)` is applied to chain state in the same `apply_transactions` call.

**Proof.** Block apply is atomic: `apply_transactions` either commits all state changes for `b` or none (it is invoked under chain lock, and any throw aborts state writes via the per-block tx loop's local-scope mutations on `accounts_` + the post-loop A1 invariant assertion at the apply tail). The TRANSFER branch (chain.cpp `case TxType::TRANSFER`) executes the sender debit before adding to `block_outbound`. The receipt list `b.cross_shard_receipts` was already finalized in the block before apply runs (validator gate). Hence "block finalized" ⇒ "sender debited" ⇒ "receipt embedded in finalized block". ∎

### Lemma L-7.4 — Forging a source block requires breaking FA1

A `CrossShardReceipt` on dst is only credited if it appears in `b.inbound_receipts` on a *finalized* dst block. The producer-side pipeline (`producer.cpp::build_body` inbound-receipts admission + `node.cpp::on_cross_shard_receipt_bundle`) only enqueues receipts whose source block carries `K` valid Ed25519 signatures from the source's committee at `src_block_index`.

**Proof.** The receipt bundle gossip path (`net/gossip.cpp::on_cross_shard_receipt_bundle`) hands the source block to `Node::on_cross_shard_receipt_bundle`, which verifies the K-of-K committee signatures against the beacon-anchored pool view for `src_shard`. Only then is the receipt added to `pending_inbound_receipts_`. Producing a fake K-of-K signed source block requires either:

- Forging at least one honest signature (A1/EUF-CMA), probability `≤ 2⁻¹²⁸`, OR
- Compromising all K committee members at `src` (which by FA1's T-1.1 is the vacuous case — no honest party in committee, no soundness claim from FA1 directly, but the slashing path FA6 still catches equivocators).

Under FA1's standard assumption that not all K committee members are Byzantine at every height, fabricated source blocks have negligible probability. ∎

---

## 3. Proof of Theorem T-7

### 3.1 No double-credit

Direct from L-7.2. Each `(src_shard, tx_hash)` is credited at most once across the destination chain's history. ∎

### 3.2 No fabrication

Suppose a finalized dst block `b_d` credits `(src_shard = s, tx_hash = h)`. By V13 acceptance, `b_d.inbound_receipts` contained an entry `r` with these fields. By the gossip-ratification pipeline (L-7.4), this entry was admitted to `pending_inbound_receipts_` only after K-of-K signature verification on the claimed source block `B_s` at index `r.src_block_index` with hash `r.src_block_hash`.

By L-7.4 and EUF-CMA, with probability `≥ 1 - K · 2⁻¹²⁸ ≥ 1 - negl(λ)`, the K signatures on `B_s` were produced by the actual source committee. By L-7.1 applied to `B_s`, the receipt is bound to a real cross-shard `TRANSFER tx` in `B_s.transactions` with matching fields. By L-7.3, applying `B_s` on `src` debited `tx.from.balance` by `tx.amount + tx.fee`.

Therefore the destination credit corresponds to a real source-side debit with overwhelming probability. ∎

---

## 4. Proof of Theorem T-7'

Liveness sketch (full treatment defers to FA4):

1. After source block `B_s` finalizes at `h_s`, gossip propagates `B_s` (and via the bundle path, its receipt set) to all connected nodes within `Δ_g`.
2. Destination producers at the next selected height observe the pending receipt in `pending_inbound_receipts_` and, by `producer.cpp::assemble_block`, bake it into `b_d.inbound_receipts` unless already applied.
3. By FA4, the next destination committee selection succeeds (round 1) with probability `≥ 1 - p_abort` and within bounded rounds w.h.p.

Hence `E[h_d - h_s] ≤ Δ_g / Δ_block + 1 / (1 - p_abort)`. ∎

---

## 5. Proof of Corollary T-7.1

Per-shard A1 (Preliminaries §9, `Chain::expected_total`):

```
LiveLocal(s) = genesis_s + accumulated_subsidy_s + accumulated_inbound_s
              - accumulated_slashed_s - accumulated_outbound_s
```

Sum over shards:

```
LiveGlobal = GenesisGlobal + SubsidyGlobal + Σ_s inbound_s - SlashedGlobal - Σ_s outbound_s
```

By T-7's no-double-credit and no-fabrication: every credited receipt corresponds to one and only one source-side debit. Define `Delivered(s_dst, s_src) =` set of receipts originating at `s_src`, credited at `s_dst`. Then:

```
Σ_s inbound_s   = Σ_{(src,dst)} amount(Delivered(dst, src))
Σ_s outbound_s = Σ_{(src,dst)} amount(Emitted(src, dst))
                = Σ_{(src,dst)} amount(Delivered(dst, src))  +  Pending
```

(Every emitted receipt is either delivered or pending; T-7's no-fabrication ensures the partition is clean.)

Substituting:

```
LiveGlobal = GenesisGlobal + SubsidyGlobal - SlashedGlobal
            + (Σ inbound) - (Σ outbound)
           = GenesisGlobal + SubsidyGlobal - SlashedGlobal - Pending
```

Rearranging:

```
LiveGlobal + Pending = GenesisGlobal + SubsidyGlobal - SlashedGlobal
```

The right-hand side is a global invariant whose components evolve only by genesis allocation (one-time), block subsidy (monotone, capped by `subsidy_pool_initial` under E4), and slashing (forfeit, monotone). The cross-shard flow contributes only the `Pending` term, which is positive in flight and zero at quiescence. ∎

---

## 6. Discussion

### 6.1 Atomicity vs. classic 2PC

Determ does not use two-phase commit. The source-side debit is *unconditional* once `B_s` finalizes; the destination-side credit happens whenever a future dst block bakes the receipt. The two halves are not simultaneously committed.

**Why this is sound:** the supply invariant T-7.1 books in-flight receipts to the `Pending` ledger, not to any local account. From a global-supply accounting view, the funds *do exist* during transit (they're tracked in `accumulated_outbound_` on src). They simply aren't claimable by any account until delivery.

**Failure modes:**

- **Source finalizes, destination never credits.** Liveness violation on dst chain. The funds are permanently in `Pending`. Mitigation: a future protocol revision could add a timeout-refund mechanism, but in the current design the assumption is that all live shards stay live (FA4).
- **Source rolls back after emitting.** Cannot happen: FA1 says finalized blocks don't rewind. The source debit and receipt emission are baked into a K-of-K signed block whose finalization is unconditional.
- **Replay attack: gossip the same receipt twice.** Blocked by V13 dedup (L-7.2).

### 6.2 What this proof does NOT cover

- **Timeout/refund** for stuck receipts: not implemented. If a dst shard goes permanently silent, funds are stuck in `Pending`. A future R5/R6 revision could add a refund mechanism gated on observed absence of dst liveness over many epochs.
- **Cross-shard atomic swaps**: a TRANSFER that should succeed iff a corresponding TRANSFER on another shard succeeds. Not a primitive of Determ; would require an explicit two-phase protocol layered on top of receipts.
- **Beacon-mediated receipts**: when `shard_count == 0` (BEACON-only) cross-chain transfers route through the beacon. The mechanism is the same (V12/V13 generalize) but the beacon's role as routing oracle adds a single-point-of-trust assumption equivalent to FA1 on the beacon chain.

### 6.3 Concrete-security bound

Per L-7.4, fabricating an inbound receipt requires forging K signatures, probability `≤ K · 2⁻¹²⁸` per attempt. For K ≤ 100 and adversary budget `Q ≤ 2⁶⁰`, the cumulative fabrication probability is `≤ 2⁻⁶⁰`. Under Grover (post-quantum), `K · Q · 2⁻⁶⁴ ≤ 2⁻⁴`, which would degrade the bound; a PQ-signature upgrade (Dilithium, etc.) would restore it. This is the same posture as FA6.

---

## 7. Implementation cross-reference

| Document | Source |
|---|---|
| `CrossShardReceipt` struct | `include/determ/chain/block.hpp::CrossShardReceipt` |
| V12 source-side receipt binding | `src/node/validator.cpp::check_cross_shard_receipts` |
| V13 destination-side dedup | `src/node/validator.cpp::check_inbound_receipts` |
| Apply credit + dedup-set update | `src/chain/chain.cpp::apply_transactions` (inbound-receipt apply loop) |
| Source debit + outbound counter | `src/chain/chain.cpp::apply_transactions` (TRANSFER cross-shard arm) |
| `applied_inbound_receipts_` set | `src/chain/chain.hpp` private member |
| Receipt bundle gossip + ratification | `src/net/gossip.cpp::on_cross_shard_receipt_bundle`; `src/node/node.cpp::on_cross_shard_receipt_bundle` |
| Producer-side baking from pending pool | `src/node/producer.cpp::build_body` (inbound_receipts admission loop) |
| Per-shard A1 invariant assertion | `src/chain/chain.cpp::apply_transactions` (A1 invariant assertion tail) |

A reviewer can confirm:

- V12 size + field equality forces 1:1 receipt-to-tx binding.
- V13 dedup set is consulted before any credit happens.
- Apply is atomic per block; partial state cannot leak.
- The K-of-K verification on source blocks (gossip ratification) is the only door receipts pass through before reaching `pending_inbound_receipts_`.

---

## 8. Conclusion

T-7 establishes that cross-shard transfers preserve supply integrity with cryptographic certainty: no double-credit (validator V13 + chain dedup set), no fabrication (gossip-side K-of-K ratification, EUF-CMA), and global atomicity (T-7.1's per-shard A1 invariants compose).

The mechanism is not atomic in the 2PC sense — source debit and destination credit are temporally decoupled — but the `Pending` term in the global supply invariant accounts for in-flight value precisely. Under FA4 liveness on all shards, all emitted receipts are eventually delivered (T-7'), so `Pending → 0` in quiescence.

The remaining gap is timeout-refund for a permanently-silent destination; this is a livelihood concern, not a soundness one, and is left as a v2+ design item.
