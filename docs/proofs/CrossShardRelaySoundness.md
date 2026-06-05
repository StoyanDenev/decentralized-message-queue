# CrossShardRelaySoundness — the cross-shard receipt relay + untrusted-buffer staging layer carries zero trust (CR-1..CR-7)

This document isolates and proves the soundness of the **cross-shard receipt relay / transport layer** — the path a `CROSS_SHARD_RECEIPT_BUNDLE` travels from a finalized source-shard block, through the beacon's relay re-broadcast, into the destination shard's *untrusted* staging buffer `pending_inbound_receipts_` (`src/node/node.cpp::on_cross_shard_receipt_bundle`, lines 1612–1649). Where the cross-shard family proves what happens *once a receipt is credited* — `CrossShardReceipts.md` (FA7) proves no-double-credit / no-fabrication, `CrossShardReceiptDedup.md` (FA-Apply-9) proves the apply-side dedup contract, `CrossShardOutboundApply.md` (FA-Apply-13) proves the source-side debit-then-emit, `S016InboundReceiptTimeOrdered.md` proves the *producer-side admission* latency-gate / per-source ordering, `ShardRoutingSoundness.md` proves the `dst_shard` routing partition — *this* proof covers the surface immediately **upstream of admission**: the transport and staging mechanics that move a receipt from "finalized on the source shard" to "buffered as a candidate for inclusion on the destination shard", and the central claim that this entire layer is **non-trusting**.

The relay/buffer layer is structurally distinct from every existing cross-shard proof because of one nuance the source makes explicit (the comment at `node.cpp:1606–1611`):

> "Full K-of-K verification of the source block against the source-shard committee is deferred to B3.4 (where the destination producer bakes verified receipts into a block and apply credits `to`). For B3.3 the receipt is held in `pending_inbound_receipts_` as **untrusted transit data** — it doesn't affect any state until B3.4 verifies + credits."

So the trust boundary is **not** at bundle-receive. The receive handler is a pure staging step; the safety gate lives entirely downstream at the destination-producer baking step (`start_block_sig_phase` → `build_body`) followed by validator V12/V13 and the K-of-K-finalized apply (FA7 L-7.4 / FA-Apply-9). The relay layer's correctness therefore reduces to a non-trust property: **no action the relay layer can take — relaying, buffering, deduping, or dropping a bundle — can credit an account, inflate supply, or otherwise affect any finalized chain state.** A fully-Byzantine beacon relay and an attacker who floods malformed bundles are bounded to a *liveness/buffer-occupancy* nuisance, never a *safety* breach. `S016InboundReceiptTimeOrdered.md` §1.1 summarizes the handler as one that "verifies the K-of-K committee-signature gate"; this proof states precisely where that gate actually lives (downstream, not at receive) and proves the receive layer is sound *because* it carries no trust.

CR-1..CR-7 also pin three mechanical staging invariants the cross-shard family assumes but never states: the **role-dispatch trichotomy** (BEACON relays-only and never mutates state; SHARD buffers; SINGLE ignores), the **buffer dedup + parallel-first-seen-map synchrony** (the `(src_shard, tx_hash)` key, the S-016 first-seen co-insertion + co-erasure), and the **state-root exclusion** (`pending_inbound_receipts_` is transit data outside the S-033 commitment, so it cannot perturb `state_root` or the snapshot identity).

**Cryptographic assumptions** (canonical labels, `Preliminaries.md` §2.0): **A1** = Ed25519 EUF-CMA (§2.2) — the reduction target of the *downstream* K-of-K source-block ratification (CR-4) that this layer feeds into; **A2** = SHA-256 collision resistance (§2.1) — underpins the `(src_shard, tx_hash)` dedup-key uniqueness (CR-3) and the `state_root` binding the buffer is excluded from (CR-6). CR-1/CR-2/CR-5 are unconditional (pure-function / control-flow arguments).

**Companion documents.** `Preliminaries.md` (F0) §2.0 (assumption labels) + §2.1 (A2) + §2.2 (A1) + validator predicates V12 (`check_cross_shard_receipts`) / V13 (`check_inbound_receipts`); `CrossShardReceipts.md` (FA7) — its **L-7.4** names the K-of-K source-block ratification this layer feeds (CR-4 makes precise *where* that gate runs), its **L-7.2** V13 dedup is the downstream canonical dedup the buffer is merely a fast-path for (CR-3); `CrossShardReceiptDedup.md` (FA-Apply-9) — the apply-side `applied_inbound_receipts_` dedup set (T-R1..T-R7) that is *canonical*, vs. this proof's *advisory* buffer dedup; `S016InboundReceiptTimeOrdered.md` — the **producer-side admission** latency-gate (`inbound_receipts_eligible_for_inclusion`, `CROSS_SHARD_RECEIPT_LATENCY = 3`) + per-source ordering that consumes the buffer this proof stages into; CR-5 cites its first-seen-map synchrony and the conservative-admit fallback; `CrossShardOutboundApply.md` (FA-Apply-13) — the source-side emission that produces the bundle's `cross_shard_receipts`; `AppliedReceiptRestore.md` (FA-Apply-12) — the `i:` namespace (canonical applied-receipt set) snapshot restore, contrasted at CR-6 with the buffer's state-root exclusion; `ShardRoutingSoundness.md` — the `dst_shard` routing partition the receive filter at `node.cpp:1631` relies on; `RegionalSharding.md` (FA8) — the beacon-relay topology context (the beacon as cross-shard relay); `S008BoundedMempool.md` — the sibling bounded-buffer posture for the unbounded-growth concern noted at F-2; `S033StateRootNamespaceCoverage.md` — the 10-namespace coverage that *excludes* `pending_inbound_receipts_` (CR-6); `S031ConcurrencyComposition.md` — the `state_mutex_` discipline the handler holds (CR-7); `docs/SECURITY.md` §S-016 (the admission-latency closure) + §S-033 (state-root coverage); `docs/PROTOCOL.md` §6.x (the cross-shard receipt bundle wire + relay flow) + §11 (snapshot field set, which omits the transit buffer). The empirical pinning is `tools/test_cross_shard_atomicity.sh` + `tools/test_cross_shard_multi_receipt.sh` + `tools/operator_receipt_flow.sh` (the end-to-end relay→buffer→bake→credit trace).

---

## 1. Scope

### 1.1 The relay/staging surface (read off source)

Two functions and one constant, all in `src/node/node.cpp`:

**The receive handler** `Node::on_cross_shard_receipt_bundle` (`node.cpp:1612–1649`):

```cpp
void Node::on_cross_shard_receipt_bundle(ShardId src_shard,
                                            const chain::Block& src_block,
                                            const net::Message& relay) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    if (cfg_.chain_role == ChainRole::BEACON) {
        gossip_.broadcast(relay);   // relay only — re-broadcast, no state mutation
        return;
    }
    if (cfg_.chain_role != ChainRole::SHARD) return;       // SINGLE: ignore
    if (src_shard == cfg_.shard_id) return;                // don't ingest our own bundle
    size_t added = 0;
    for (auto& r : src_block.cross_shard_receipts) {
        if (r.dst_shard != cfg_.shard_id) continue;        // not addressed to us
        if (r.src_shard != src_shard)     continue;        // sanity
        auto key = std::make_pair(r.src_shard, r.tx_hash);
        if (pending_inbound_receipts_.count(key)) continue; // already buffered
        pending_inbound_receipts_[key]  = r;
        pending_inbound_first_seen_[key] = chain_.height(); // S-016 parallel map
        ++added;
    }
    /* log only */
}
```

**The buffer-to-candidate projection** `Node::inbound_receipts_eligible_for_inclusion` (`node.cpp:1576–1599`) — the S-016 latency gate that the destination *producer* consults; proved in `S016InboundReceiptTimeOrdered.md`, consumed here only as the buffer's reader.

**The post-credit prune** (`node.cpp:1826–1835`) — after a finalized block credits `b.inbound_receipts`, the matching `(src_shard, tx_hash)` entries are erased from *both* `pending_inbound_receipts_` and `pending_inbound_first_seen_`, with the explicit comment "The on-chain dedup set is canonical; pending is just a fast path for inclusion."

### 1.2 The two state objects, and which one is canonical

| Object | Where | Trust | In state_root? |
|---|---|---|---|
| `pending_inbound_receipts_` | `Node` (`node.cpp`), per-node | **untrusted transit buffer** | **No** (CR-6) |
| `pending_inbound_first_seen_` | `Node`, parallel to the above | advisory (S-016 latency) | No |
| `applied_inbound_receipts_` | `Chain` (`chain.cpp`), the `i:` namespace | **canonical** dedup set | **Yes** (`i:`, S-033) |

The receive handler writes only the first two (node-local, untrusted). The credit + canonical dedup happens entirely in `Chain::apply_transactions` against the third (FA-Apply-9). This separation is the spine of the non-trust property.

### 1.3 The seven theorems

| Theorem | Property |
|---|---|
| **CR-1** (Beacon relay is state-pure) | On a BEACON node the handler only re-broadcasts the relay message and returns; it never writes `pending_inbound_receipts_`, never credits, never touches chain state. A Byzantine beacon relay is a transport actor, not a state actor. |
| **CR-2** (Role-dispatch trichotomy) | The handler partitions behavior exactly three ways by `chain_role`: BEACON → relay-only; SHARD → buffer; SINGLE (or any other) → ignore. No fourth path, no fall-through that mutates state outside the SHARD branch. |
| **CR-3** (Buffer dedup + advisory semantics) | Within a SHARD the buffer is deduped by the `(src_shard, tx_hash)` pair-key; a re-delivered bundle is a no-op on the buffer. The buffer dedup is *advisory* (a fast path); the *canonical* no-double-credit guarantee is the downstream V13 + `applied_inbound_receipts_` dedup (FA7 L-7.2 / FA-Apply-9 T-R2), so even a buffer-dedup bypass cannot double-credit. |
| **CR-4** (Non-trust: the safety gate is downstream) | No bundle reaching the receive handler can credit an account or finalize. Crediting requires: (a) the destination *producer* baking the receipt into a tentative block, (b) validator V12/V13 acceptance, and (c) K-of-K finalized apply with K-of-K source-block ratification (FA7 L-7.4). Buffering is necessary-but-not-sufficient; the trust boundary is the K-of-K apply, not the receive. A malformed / forged / unverified bundle that lands in the buffer dies there unless the source block carries K honest source-committee signatures (A1). |
| **CR-5** (First-seen-map synchrony) | `pending_inbound_first_seen_` is co-inserted on buffer-add (`node.cpp:1640`) and co-erased on post-credit prune (`node.cpp:1834`), so the two maps share the same key set at every quiescent point; the S-016 producer-side latency gate (`S016InboundReceiptTimeOrdered.md`) is well-defined, with a conservative-admit fallback for the (unreachable) missing-first-seen case. |
| **CR-6** (State-root exclusion) | `pending_inbound_receipts_` and `pending_inbound_first_seen_` are *not* in the S-033 `state_root` (no `build_state_leaves` namespace emits them) and *not* in the snapshot state object (`serialize_state` omits them; only the `pending_inbound_receipts` *count* appears in `status --json`, never the contents). Therefore buffer contents cannot perturb `state_root`, cannot cause a snapshot-restore state-root mismatch, and two nodes with different buffer contents still agree on `state_root`. |
| **CR-7** (Concurrency-safe receive) | The handler holds `state_mutex_` (`node.cpp:1615`, unique lock) across the entire role-dispatch + buffer mutation, so a concurrent producer-side read (`inbound_receipts_eligible_for_inclusion`) or apply never observes a torn buffer; composes with S-031's lock discipline. |

### 1.4 What this does not prove

The downstream K-of-K source-block ratification + V12/V13 + apply credit are FA7 (L-7.4, T-7) and FA-Apply-9 (T-R1..T-R7); CR-4 names them as the trust boundary but does not re-derive them. The producer-side admission latency gate / per-source ordering is `S016InboundReceiptTimeOrdered.md` (T-1..T-5); CR-5 supplies the map-synchrony that gate assumes. The source-side emission is FA-Apply-13. The `dst_shard` routing partition that the receive filter relies on is `ShardRoutingSoundness.md` (SR-1..SR-7). The `i:` canonical-set snapshot restore is FA-Apply-12. The gossip-layer message framing / size caps are S-022. SHA-256 / Ed25519 hardness is assumed per `Preliminaries.md` §2.

---

## 2. Model

### 2.1 The relay topology

Cross-shard receipt delivery is a three-hop relay (`docs/PROTOCOL.md` cross-shard flow):

1. A source-shard producer finalizes block `B_src` carrying `B_src.cross_shard_receipts` (FA-Apply-13), and emits a `CROSS_SHARD_RECEIPT_BUNDLE` carrying `(src_shard, B_src, signatures)`.
2. The **beacon** receives the bundle and *relays* it: `gossip_.broadcast(relay)` re-broadcasts to its peers (CR-1). The beacon performs no verification and no state mutation here — it is a fan-out relay.
3. Each **destination shard** node receives the relayed bundle, filters `B_src.cross_shard_receipts` to those with `dst_shard == my_shard_id`, and buffers the new ones into `pending_inbound_receipts_` (CR-3). This buffer is *untrusted transit data* (§1.1 comment).

The actual credit happens only in a *later* destination block (hops 4–5, downstream, FA7/FA-Apply-9), gated by K-of-K source-block ratification and K-of-K finalization. Hops 1–3 are this proof's scope; the non-trust property (CR-4) is that hops 1–3 cannot affect finalized state.

### 2.2 The buffer as a node-local set

For a destination SHARD node `n`, model the buffer as a partial map `Buf_n : (ShardId × Hash) ⇀ CrossShardReceipt` keyed by `(src_shard, tx_hash)`, with a parallel map `Seen_n : (ShardId × Hash) ⇀ uint64` (first-seen heights). The handler's effect on `(Buf_n, Seen_n)` is the only mutation in hops 1–3 on a SHARD node; on a BEACON node hops 1–3 mutate nothing (CR-1).

### 2.3 The canonical dedup set, by contrast

The chain's `applied_inbound_receipts_` (the `i:` namespace, `chain.cpp` build_state_leaves `i:` loop) is the *canonical* exactly-once ledger. It is mutated only inside `apply_transactions` (FA-Apply-9), is bound into `state_root` (S-033), and round-trips through snapshots (FA-Apply-12). `Buf_n` is a *fast path for inclusion* (the `node.cpp:1829` comment); a node could discard `Buf_n` entirely and re-learn pending receipts from re-gossiped bundles without any safety effect — only a liveness/latency effect.

---

## 3. Theorems

Fix a network with a beacon and `N ≥ 2` shards under EXTENDED sharding mode.

### CR-1 — Beacon relay is state-pure

**Statement.** On a node with `cfg_.chain_role == ChainRole::BEACON`, `on_cross_shard_receipt_bundle` executes exactly `gossip_.broadcast(relay); return;` and performs **no** mutation of `pending_inbound_receipts_`, `pending_inbound_first_seen_`, any account balance, or any chain state. A Byzantine beacon is therefore a transport adversary (it may drop, reorder, duplicate, or fabricate relayed bundles) but never a state adversary on its own node.

**Proof.** The first branch of the handler (`node.cpp:1617–1623`) tests `cfg_.chain_role == ChainRole::BEACON` and, if true, calls `gossip_.broadcast(relay)` then `return`s — control never reaches the SHARD buffer-mutation loop (which is guarded by the subsequent `if (cfg_.chain_role != ChainRole::SHARD) return;`). `gossip_.broadcast` is a network send; it does not write `Buf` / `Seen` or chain state. Therefore on a BEACON node the handler's only effect is the re-broadcast. Any state the beacon *does* hold (e.g. its own beacon-chain state) is untouched by this handler. A Byzantine beacon that relays garbage or withholds bundles affects *delivery* (liveness) but cannot, through this path, credit any account anywhere — the destination shards' downstream K-of-K apply (CR-4) is the gate, and a beacon cannot forge K source-committee signatures (A1).   ∎

**Code witness.** `node.cpp:1617–1623`. **Companion.** `RegionalSharding.md` (beacon-relay topology); FA7 L-7.4 (the downstream gate a Byzantine relay cannot bypass).

### CR-2 — Role-dispatch trichotomy

**Statement.** The handler's behavior is partitioned exactly three ways by `chain_role`, with no fourth path and no state-mutating fall-through outside the SHARD branch: BEACON → relay-and-return (CR-1); SHARD → proceed to the buffer loop; any other role (SINGLE, or an unset/unknown role) → return immediately with no effect.

**Proof.** Read off the two guards (`node.cpp:1617`, `1624`). The first guard handles `BEACON` (relay + return). After it, `if (cfg_.chain_role != ChainRole::SHARD) return;` returns for *every* role that is not `SHARD` — this is the catch-all that makes SINGLE (and any future or unset role enum value) a no-op. Only when `chain_role == SHARD` does control reach the buffer-mutation loop. The three cases are exhaustive and mutually exclusive by the enum's value at the two equality tests, and the only state-mutating path is the SHARD branch. There is no `default`-style fall-through that could mutate state for an unhandled role.   ∎

**Code witness.** `node.cpp:1617`, `1624`. **Defends against** a deployment-misconfiguration class where a node with an unexpected role silently buffers/credits — CR-2 shows the only buffering path is the explicit SHARD branch.

### CR-3 — Buffer dedup + advisory semantics

**Statement.** Within a SHARD node, the buffer is deduplicated by the `(src_shard, tx_hash)` pair-key: a receipt whose key is already present is skipped (`node.cpp:1634`), so re-delivery of the same bundle (or of a bundle sharing receipts with a prior one) is a no-op on `Buf`. This dedup is **advisory** — its sole purpose is to avoid re-proposing the same receipt; the **canonical** no-double-credit guarantee is the downstream V13 + `applied_inbound_receipts_` dedup. Even if the buffer dedup were bypassed entirely (e.g. two distinct buffer entries for one logical receipt), no double-credit could result.

**Proof.** *Buffer dedup.* The loop computes `key = (r.src_shard, r.tx_hash)` and `if (pending_inbound_receipts_.count(key)) continue;` (`node.cpp:1633–1634`) before insertion, so a present key is skipped. By A2 the `(src_shard, tx_hash)` pair is collision-free across distinct logical receipts (`tx_hash` is a SHA-256 over the source tx; FA7 / FA-Apply-9 T-R3 key-pair uniqueness), so distinct logical receipts get distinct keys and identical ones collapse. *Advisory semantics.* The credit path is `apply_transactions` over a finalized block's `inbound_receipts`, gated by V13 (`check_inbound_receipts`) which rejects any receipt whose `(src_shard, tx_hash)` is already in `applied_inbound_receipts_` (FA7 L-7.2) and any within-block duplicate (its `seen` set), and by the apply-side dedup (FA-Apply-9 T-R2) which silently skips an already-applied key. So a credit happens at most once per `(src_shard, tx_hash)` *regardless of buffer state*: if the buffer somehow held a logical receipt twice, the producer might propose it twice, but V13 + the apply dedup admit it at most once into a finalized credit. The post-credit prune (`node.cpp:1831–1835`) then removes the buffered key so it is not re-proposed. Hence the buffer dedup is a performance optimization, not a safety dependency.   ∎

**Reduction target: A2** (pair-key uniqueness). **Code witness.** `node.cpp:1633–1634` (buffer dedup), `node.cpp:1826–1835` (post-credit prune + canonical-set note). **Companion.** FA7 L-7.2 + FA-Apply-9 T-R2 (the canonical dedup). **Test witness.** `tools/test_cross_shard_multi_receipt.sh` (re-delivery / multi-receipt dedup), `tools/test_cross_shard_atomicity.sh`.

### CR-4 — Non-trust: the safety gate is downstream

**Statement.** No bundle that reaches `on_cross_shard_receipt_bundle` can, by being received / relayed / buffered, credit any account, inflate supply, or affect any finalized chain state. Crediting `accounts_[r.to].balance += r.amount` requires the *conjunction* of: (a) a destination producer baking `r` into a tentative block (`start_block_sig_phase` → `build_body`, consuming `inbound_receipts_eligible_for_inclusion`), (b) validator V12/V13 acceptance, and (c) a K-of-K-finalized apply in which the source block carrying `r` is ratified by K honest source-committee Ed25519 signatures (FA7 L-7.4). Buffering is necessary-but-not-sufficient. An attacker who delivers a malformed, forged, or unverified bundle gets the receipt staged in `Buf` (occupancy only) but no credit unless the source block carries K honest signatures — forging which is `≤ 2^{-128}` per attempt under A1.

**Proof.** The receive handler writes only `Buf` / `Seen` on a SHARD node (CR-1/CR-2/CR-3) and nothing on a beacon. Neither map is read by `apply_transactions`; the credit path reads a *finalized block's* `inbound_receipts` field. The only way a buffered receipt enters a finalized block's `inbound_receipts` is via the destination producer's `build_body` snapshot of the *eligible* subset (`node.cpp:2238–2240` builds `inbound_snapshot` from `pending_inbound_receipts_`, fed to `build_body`; S-016 gates eligibility). That tentative block must then (b) pass V12 (`check_cross_shard_receipts` re-derives `dst_shard` and binds fields, `ShardRoutingSoundness.md` SR-6) and V13 (`check_inbound_receipts`, dedup + `dst_shard == my_shard_id`), and (c) be finalized K-of-K. The finalized-apply credit is itself gated by the gossip-side K-of-K ratification of the *source* block (FA7 L-7.4): the destination only credits a receipt whose source block carried K valid source-committee signatures at `src_block_index`. Composing: a buffered receipt with no valid source-committee backing cannot survive (c) — the source block fails K-of-K verification, so apply does not credit it. The only forgery path is producing a fake K-of-K-signed source block, which requires forging ≥ 1 honest source-committee signature (A1, `≤ 2^{-128}`) or compromising all K source-committee members (FA1 T-1.1 vacuous case, outside the honest-committee assumption). Therefore receive/relay/buffer carries no trust: it is a pre-stage whose worst case is buffer occupancy, never a credit.   ∎

**Reduction target: A1** (the residual forge-a-source-signature path), via FA7 L-7.4. **Code witness.** `node.cpp:2238–2240` (producer snapshots buffer → build_body), the *absence* of any `accounts_` write in `on_cross_shard_receipt_bundle`, and the `node.cpp:1606–1611` comment locating the verify+credit at B3.4. **Companion.** FA7 L-7.4 + T-7 (no-fabrication), FA-Apply-9 (apply dedup), `ShardRoutingSoundness.md` SR-6 (V12 `dst_shard` re-derivation). **Test witness.** `tools/test_cross_shard_atomicity.sh` (end-to-end: a receipt credits only via a finalized block), `tools/operator_receipt_flow.sh` (relay→buffer→bake→credit trace).

### CR-5 — First-seen-map synchrony

**Statement.** `pending_inbound_first_seen_` shares the key set of `pending_inbound_receipts_` at every quiescent point: a key is co-inserted into both on buffer-add (`node.cpp:1635` + `1640`) and co-erased from both on post-credit prune (`node.cpp:1833` + `1834`). Consequently the S-016 producer-side latency gate (`inbound_receipts_eligible_for_inclusion`) reads a well-defined first-seen height for every buffered receipt, with a conservative-admit fallback for the (control-flow-unreachable) missing-first-seen case.

**Proof.** *Co-insertion.* In the SHARD buffer loop, the two writes `pending_inbound_receipts_[key] = r;` (`node.cpp:1635`) and `pending_inbound_first_seen_[key] = chain_.height();` (`node.cpp:1640`) execute unconditionally and adjacently for each newly-admitted `key`, under the same `state_mutex_` unique lock (CR-7) — no interleaving can separate them. *Co-erasure.* The post-credit prune loop (`node.cpp:1831–1835`) erases `key` from both maps for each credited `r.inbound_receipts` entry, with the explicit S-016 comment "keep parallel-map in sync". *Fallback.* `inbound_receipts_eligible_for_inclusion` (`node.cpp:1581–1597`) looks up `Seen[key]`; the `if (fit == end())` branch (the missing-first-seen case the source flags as "shouldn't happen") admits conservatively (`node.cpp:1586–1589`) rather than dropping, so even a hypothetical desync can only *under*-gate (admit early), never silently delay forever — and CR-5's co-insertion shows the branch is unreachable in honest operation. Hence the two maps are synchronized and the latency gate is well-defined.   ∎

**Code witness.** `node.cpp:1635` + `1640` (co-insert), `node.cpp:1833` + `1834` (co-erase), `node.cpp:1586–1589` (conservative fallback). **Companion.** `S016InboundReceiptTimeOrdered.md` (the gate that consumes this synchrony). **Test witness.** `tools/test_cross_shard_atomicity.sh` (the soak window exercises first-seen).

### CR-6 — State-root exclusion

**Statement.** The transit buffer `pending_inbound_receipts_` and its parallel `pending_inbound_first_seen_` are excluded from the S-033 `state_root` and from the snapshot state object: no `build_state_leaves` namespace emits them, and `serialize_state` does not serialize them (only the buffer *count* surfaces in `status --json`, never the contents). Therefore (i) buffer contents cannot perturb `compute_state_root`; (ii) two honest nodes with *different* buffer contents (due to asynchronous gossip) still compute the *same* `state_root` at the same height; (iii) a snapshot restored by a node with an empty buffer passes the G2 state-root gate identically to one restored mid-transit.

**Proof.** *Not in state_root.* The ten S-033 namespaces (`a|s|r|d|i|b|m|p|k|c`, `S033StateRootNamespaceCoverage.md`) are all `Chain`-member-derived; `pending_inbound_receipts_` is a `Node` member (`node.cpp`), not a `Chain` member, and `build_state_leaves` (a `Chain` method) has no access to it and emits no leaf for it. The *canonical* applied-receipt set `applied_inbound_receipts_` (the `i:` namespace, a `Chain` member) is the one that is committed — the transit buffer is a distinct object (§2.2 vs §2.3). *Not in snapshot.* `Chain::serialize_state` serializes chain state; the node-local transit buffer is outside the chain object and is not in the snapshot JSON. The only place buffer state appears is `status --json` as `pending_inbound_receipts` = `.size()` (a count, `node.cpp:2421`, flagged "shard-only"), which is operational telemetry, not consensus state. *Consequences.* (i)+(ii): since `compute_state_root` reads only the committed namespaces, buffer divergence across nodes does not change the root — this is precisely why S-016's pre-mitigation divergence was a *latency* (round-retry) concern and never a *state-root fork* concern. (iii): a restored node starts with an empty buffer (the snapshot omits it) and rebuilds it from re-gossiped bundles; its `state_root` matches the tail block's committed root (S-033 G2 gate) regardless, because the root never depended on the buffer.   ∎

**Reduction target: A2** (the Merkle binding of the committed namespaces that the buffer is *not* part of). **Code witness.** `node.cpp:2421` (count-only status surface), the absence of `pending_inbound_receipts_` from `chain.cpp` `build_state_leaves` + `serialize_state`. **Companion.** `S033StateRootNamespaceCoverage.md` (the namespaces that *are* committed), `AppliedReceiptRestore.md` (the `i:` canonical set that *is* restored). **Test witness.** `tools/test_cross_shard_atomicity.sh` + `determ test-snapshot-full-determinism` (state_root identity across nodes/restore independent of buffer).

### CR-7 — Concurrency-safe receive

**Statement.** `on_cross_shard_receipt_bundle` acquires `state_mutex_` as a `std::unique_lock<std::shared_mutex>` (`node.cpp:1615`) and holds it across the entire role-dispatch + buffer-mutation body, so a concurrent producer-side reader (`inbound_receipts_eligible_for_inclusion`, `build_body`'s buffer snapshot) or a concurrent apply never observes a partially-mutated buffer. The receive integrates into the S-031 lock discipline without introducing a new race.

**Proof.** The unique lock at the top of the handler (`node.cpp:1615`) excludes all other writers and all shared-lock readers of `state_mutex_` for the handler's duration. The buffer mutations (CR-3 insert, CR-5 co-insert) and the beacon relay (CR-1) all occur inside this critical section. The producer-side reads that snapshot the buffer (`node.cpp:2238–2240`) and the eligibility gate (`node.cpp:1576–1599`, a `const` method) run under the same `state_mutex_` (per S-031's discipline that all `Node` shared-state access is mutex-guarded), so they serialize against the receive handler: a reader sees either the pre-insert or post-insert buffer, never a torn intermediate. The co-insertion of `Buf` and `Seen` (CR-5) being inside one critical section is what makes the two maps' synchrony observable atomically. No lock is held across a network call that could block indefinitely except the beacon `broadcast` (a bounded enqueue), consistent with S-031's gossip-out-of-lock posture for the hot consensus path (the relay broadcast is a fan-out enqueue, not a blocking round-trip).   ∎

**Code witness.** `node.cpp:1615` (unique lock), `node.cpp:2238–2240` (guarded reader). **Companion.** `S031ConcurrencyComposition.md` (the lock discipline this composes with). 

---

## 4. Composition with the FA-track

### 4.1 FA7 (CrossShardReceipts.md) — atomicity downstream of the relay

FA7's L-7.4 states the destination admits a receipt to `pending_inbound_receipts_` "only after K-of-K signature verification on the claimed source block." CR-4 sharpens the *location* of that verification: the receive handler (`on_cross_shard_receipt_bundle`) is explicitly an *untrusted* stage (the `node.cpp:1606–1611` comment), and the K-of-K source-block ratification that L-7.4 relies on is enforced at the destination-producer-bake + finalized-apply step (B3.4), not at receive. CR-4 proves this re-location is sound: because the buffer carries no trust, deferring the K-of-K gate to apply loses nothing — a buffered-but-unratified receipt simply never reaches a finalized credit. FA7 T-7 (no-fabrication) is invoked unchanged; CR-4 is the precise statement of *which hop* enforces it.

### 4.2 FA-Apply-9 (CrossShardReceiptDedup.md) — the canonical dedup vs. the advisory buffer dedup

FA-Apply-9 proves the *canonical* `applied_inbound_receipts_` dedup (T-R1..T-R7). CR-3 distinguishes the *advisory* buffer dedup (a fast path to avoid re-proposal) from that canonical guarantee, and proves a buffer-dedup bypass cannot double-credit because V13 + the apply dedup are the real gate. The two proofs are complementary: FA-Apply-9 secures the credit ledger; CR-3 secures the staging buffer that feeds it, and shows the staging layer's correctness does not *depend* on its own dedup for safety.

### 4.3 S016InboundReceiptTimeOrdered.md — the producer-side admission gate this stages into

S-016 proves the producer-side latency gate (`inbound_receipts_eligible_for_inclusion`, `CROSS_SHARD_RECEIPT_LATENCY`) and the per-source total order it induces. CR-5 supplies the precondition that gate assumes: the `Seen` map is synchronized with `Buf` (co-insert / co-erase), so every buffered receipt has a well-defined first-seen height. CR-6 supplies the orthogonal fact that the gate's *divergence* across committee members (the S-016 motivation) is a latency concern only — never a state-root fork — because the buffer is outside `state_root`. Together: this proof stages receipts into the buffer (CR-1..CR-3, CR-7), guarantees the map the S-016 gate reads (CR-5), and bounds the blast radius of buffer divergence (CR-6); S-016 then gates eligibility; FA7/FA-Apply-9 credit.

### 4.4 ShardRoutingSoundness.md / RegionalSharding.md — the routing + topology context

The receive filter `if (r.dst_shard != cfg_.shard_id) continue;` (`node.cpp:1631`) trusts `r.dst_shard`, but CR-4 shows this trust is harmless at the buffer layer (no credit yet), and V12 (`ShardRoutingSoundness.md` SR-6) re-derives `dst_shard` independently at the finalized-apply gate, so a forged `dst_shard` that survives the receive filter is caught downstream. The beacon-relay topology (CR-1) is the FA8 regional-sharding deployment context (the beacon as cross-region relay).

---

## 5. Adversary model

The proof's threat surfaces and the CR-theorem that bounds each:

**(a) `A_byz_beacon` (Byzantine relay).** A compromised beacon drops, reorders, duplicates, or fabricates relayed bundles. Bounded by **CR-1** (the beacon mutates no state) + **CR-4** (no fabricated bundle credits without K honest source-committee signatures, A1). Worst case: delivery degradation (liveness) — the destination shards' downstream K-of-K apply is the gate. Withholding is a censorship concern handled by the multi-path gossip topology (FA8), not a safety breach.

**(b) `A_bundle_flood` (buffer-occupancy DoS).** An attacker floods a destination shard with bundles to grow `pending_inbound_receipts_` unboundedly. Bounded for *safety* by **CR-4** (occupancy is not a credit) + **CR-3** (dedup collapses re-delivery of the same receipt) + **CR-6** (buffer is outside state_root, so it cannot perturb consensus state). The residual *resource* concern (an unbounded distinct-receipt flood) is noted at F-2 and bounded operationally; it is the sibling of S-008 bounded-mempool and is a liveness/resource matter, never safety.

**(c) `A_forged_bundle` (fabricated source block).** An attacker delivers a bundle whose `src_block` is fabricated (fake receipts, fake K-of-K). Bounded by **CR-4** + FA7 L-7.4: the receipt is buffered (occupancy) but never credited because the finalized-apply ratification requires K honest source-committee signatures (A1, `≤ 2^{-128}` to forge). The buffer's lack of receive-time verification is *intentional* (the gate is downstream) and *safe* (CR-4).

**(d) `A_dst_spoof` (mis-addressed receipt).** A bundle carries a receipt with `dst_shard` set to a shard that does not own `tx.to`. The receive filter (`node.cpp:1631`) admits it only if `dst_shard == cfg_.shard_id`; even then, V12's independent `dst_shard` re-derivation at finalized apply (`ShardRoutingSoundness.md` SR-6) rejects the mismatch. Bounded by **CR-4** + SR-6: occupancy only, no credit.

**(e) `A_buffer_desync` (map-desync).** An attacker (or a code regression) tries to desynchronize `Buf` and `Seen` to break the S-016 gate. Bounded by **CR-5** (co-insert / co-erase under one lock, CR-7) + the conservative-admit fallback (a desync can only under-gate, never silently delay forever). No state effect (CR-6).

**(f) `A_state_root_perturb` (consensus via buffer).** An attacker tries to make two honest nodes' buffer divergence cause a `state_root` disagreement / fork. Bounded by **CR-6**: the buffer is outside the committed namespaces, so divergence is invisible to `compute_state_root`. Reduces to A2 (the Merkle binding of the committed namespaces).

---

## 6. Identified gaps and known limitations

### F-1 (The relay layer is a *transport* contract, not the *trust* boundary)

CR-1..CR-7 prove the relay/buffer layer carries no trust; the actual safety gate is the downstream K-of-K source-block ratification + V12/V13 + finalized apply (FA7 / FA-Apply-9), which this proof invokes (CR-4) but does not re-derive. An auditor must read those companions to see the *positive* credit-soundness; this proof's contribution is the *negative* result that the transport layer cannot subvert it. The two are complementary, not redundant.

### F-2 (Buffer is unbounded in the current code; a resource, not a safety, gap)

`pending_inbound_receipts_` has no explicit size cap in `on_cross_shard_receipt_bundle` (unlike the mempool's S-008 bound). A distinct-receipt flood from a misbehaving source (`A_bundle_flood` (b)) could grow it. This is a *resource/liveness* concern bounded by CR-3 (dedup of repeats) + the post-credit prune (`node.cpp:1831–1835`, which drains credited entries) + the gossip-layer S-022 message size caps + the source-side requirement that each receipt rides a real K-of-K-signed source block (so an attacker cannot cheaply mint distinct *valid* receipts). It is **not** a safety gap (CR-4 / CR-6): an oversized buffer cannot credit or fork. A future hardening could add an explicit cap mirroring S-008; recorded honestly as a resource-side item, sibling to `S008BoundedMempool.md`. No safety theorem here depends on the buffer being bounded.

### F-3 (`status --json` count surface is telemetry, not consensus)

The `pending_inbound_receipts` field in `status --json` (`node.cpp:2421`, a `.size()` count) is operator telemetry and is explicitly *not* part of `state_root` or the snapshot (CR-6). Recorded so an auditor does not mistake the count surface for committed state: it is per-node, transient, and informational.

### F-4 (Full deterministic committee agreement is S-016 Option 1 / v2.7 F2, not this layer)

This proof stages receipts into the buffer and bounds buffer divergence to a non-state-root concern (CR-6). The *full* deterministic agreement of every committee member on the eligible set (eliminating even the residual round-retry window) is S-016 Option 1 / v2.7 F2 (`F2-SPEC.md`), a block-format change orthogonal to the transport layer. CR-1..CR-7 hold under both the current Option 2 and a future F2; the relay/buffer transport semantics are unchanged by F2.

---

## 7. Cross-references

### SECURITY.md sections

- `docs/SECURITY.md` §S-016 — inbound-receipt pool admission (the producer-side latency gate this layer stages into; CR-5).
- `docs/SECURITY.md` §S-033 — Merkle state commitment; the buffer is *excluded* (CR-6).
- `docs/SECURITY.md` §S-022 — per-message-type size caps (the framing-layer bound on bundle messages; F-2).
- `docs/SECURITY.md` §S-008 — bounded mempool (the sibling bounded-buffer posture; F-2).

### Companion proofs

- `docs/proofs/CrossShardReceipts.md` (FA7) — atomicity (T-7) + the K-of-K source-block ratification (L-7.4) that CR-4 locates downstream of the relay.
- `docs/proofs/CrossShardReceiptDedup.md` (FA-Apply-9) — the canonical `applied_inbound_receipts_` dedup (T-R1..T-R7) vs. CR-3's advisory buffer dedup.
- `docs/proofs/S016InboundReceiptTimeOrdered.md` — the producer-side admission latency gate + per-source ordering that CR-5 supplies map-synchrony for.
- `docs/proofs/CrossShardOutboundApply.md` (FA-Apply-13) — the source-side emission that produces the bundle's receipts.
- `docs/proofs/AppliedReceiptRestore.md` (FA-Apply-12) — the `i:` canonical-set snapshot restore, contrasted at CR-6 with the buffer's state-root exclusion.
- `docs/proofs/ShardRoutingSoundness.md` — the `dst_shard` routing partition (SR-6) the receive filter relies on and that V12 re-derives downstream.
- `docs/proofs/RegionalSharding.md` (FA8) — the beacon-relay deployment topology (CR-1 context).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — the committed namespaces the buffer is excluded from (CR-6).
- `docs/proofs/S031ConcurrencyComposition.md` — the `state_mutex_` discipline CR-7 composes with.
- `docs/proofs/S008BoundedMempool.md` — the sibling bounded-buffer posture (F-2).
- `docs/proofs/Preliminaries.md` (F0) — §2.0 assumption labels; §2.1 A2 (CR-3/CR-6); §2.2 A1 (CR-4); V12/V13 predicates.

### Implementation sites

- `src/node/node.cpp:1612–1649` — `on_cross_shard_receipt_bundle` (the receive handler; CR-1..CR-3, CR-5, CR-7).
- `src/node/node.cpp:1617–1623` — BEACON relay branch (CR-1).
- `src/node/node.cpp:1624` — SHARD/SINGLE role guard (CR-2).
- `src/node/node.cpp:1631–1634` — `dst_shard` filter + `(src_shard, tx_hash)` buffer dedup (CR-3).
- `src/node/node.cpp:1635` + `1640` — buffer + first-seen co-insert (CR-5).
- `src/node/node.cpp:1576–1599` — `inbound_receipts_eligible_for_inclusion` + `CROSS_SHARD_RECEIPT_LATENCY` (the S-016 gate; CR-5).
- `src/node/node.cpp:1606–1611` — the "untrusted transit data / verify+credit deferred to B3.4" comment (CR-4 anchor).
- `src/node/node.cpp:2238–2240` — producer snapshots the buffer into `build_body` (CR-4 path to credit).
- `src/node/node.cpp:1826–1835` — post-credit prune of both maps (CR-3, CR-5).
- `src/node/node.cpp:2421` — `status --json` pending count (telemetry; CR-6 / F-3).
- `src/chain/chain.cpp` `apply_transactions` inbound-receipt credit + `applied_inbound_receipts_` (the canonical gate; FA-Apply-9).

### Tests

- `tools/test_cross_shard_atomicity.sh` — end-to-end relay→buffer→bake→credit; a receipt credits only via a finalized block (CR-4), soak window exercises first-seen (CR-5).
- `tools/test_cross_shard_multi_receipt.sh` — multi-receipt + re-delivery dedup (CR-3), mixed-direction.
- `tools/operator_receipt_flow.sh` — operator-side relay/buffer/credit flow trace (the empirical anchor for CR-1/CR-4).
- `determ test-snapshot-full-determinism` — state_root identity across nodes/restore independent of buffer contents (CR-6).

### Specifications

- `docs/PROTOCOL.md` — the cross-shard receipt bundle wire + beacon-relay flow (the transport this proof secures).
- `docs/PROTOCOL.md` §11 — snapshot field set (which omits the transit buffer; CR-6).

---

## 8. Status

**Analytic soundness proof; surface shipped.** The cross-shard receipt relay + untrusted-buffer staging layer is shipped (`on_cross_shard_receipt_bundle` + the producer-side buffer snapshot + the post-credit prune). This proof changes no code; it isolates the transport layer's non-trust property into one contract so the cross-shard family's "the receive handler holds untrusted transit data" comment is a theorem, and the location of the real safety gate (downstream K-of-K apply) is made precise.

- **CR-1** (beacon relay state-pure) — a BEACON node only re-broadcasts; no state mutation; unconditional.
- **CR-2** (role-dispatch trichotomy) — BEACON / SHARD / else, exhaustive + mutually exclusive, only SHARD buffers; unconditional.
- **CR-3** (buffer dedup advisory) — `(src_shard, tx_hash)` dedup is a fast path; canonical dedup is V13 + `applied_inbound_receipts_`; reduces to A2.
- **CR-4** (non-trust) — receive/relay/buffer cannot credit; the gate is the downstream K-of-K apply; reduces to A1 (residual forge-source-signature path).
- **CR-5** (first-seen synchrony) — `Buf` and `Seen` co-insert / co-erase under one lock; the S-016 gate is well-defined; unconditional.
- **CR-6** (state-root exclusion) — the buffer is outside the 10 committed namespaces + the snapshot; buffer divergence cannot fork or perturb `state_root`; reduces to A2.
- **CR-7** (concurrency-safe) — the handler holds `state_mutex_` across role-dispatch + mutation; composes with S-031; unconditional.

**No theorem is open or partial.** The recorded notes are scoping/resource clarifications: F-1 (this is the transport contract; the credit-soundness positive result is FA7/FA-Apply-9), F-2 (the buffer is unbounded — a resource/liveness item sibling to S-008, never a safety gap by CR-4/CR-6), F-3 (the `status --json` count is telemetry, not consensus state), and F-4 (full deterministic committee agreement is S-016 Option 1 / v2.7 F2, orthogonal to and unchanged by this transport layer). The safety reductions are A1 (CR-4) + A2 (CR-3/CR-6); CR-1/CR-2/CR-5/CR-7 are unconditional control-flow / concurrency arguments.
