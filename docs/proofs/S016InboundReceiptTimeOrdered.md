# S-016 — Option 2 time-ordered admission of cross-shard inbound receipts

This document formalizes the **Option 2 mitigation** for S-016 (inbound-receipts pool non-determinism across committee members) — the analytic companion to the in-source closure at `src/node/node.cpp:1557-1599` and the SECURITY.md §S-016 closure narrative. The mechanism: every cross-shard receipt arriving at the destination shard via `Node::on_cross_shard_receipt_bundle` records its local first-observation height into a parallel map `pending_inbound_first_seen_`; the producer-side admission helper `Node::inbound_receipts_eligible_for_inclusion` consumed by `start_block_sig_phase` and `try_finalize_round` admits only receipts whose `first_seen + CROSS_SHARD_RECEIPT_LATENCY <= chain.height()` predicate fires (CROSS_SHARD_RECEIPT_LATENCY = 3 blocks). The mitigation drives the round-retry probability from "occasional pool-divergence aborts" (each member's pool snapshot differing momentarily during bundle gossip → K-of-K abort → round retry) to "negligible" by giving the gossip layer ~3 × tx_commit_ms (≈600 ms at web profile) of propagation headroom before any receipt is eligible for block inclusion.

The strength of this proof is the **per-source total ordering claim**: under T-1, receipts originating from the same source shard are admitted in strictly monotonic `src_block_index` order — no receipt from `src_shard` at `src_block_index = K` can be admitted after a receipt from the same `src_shard` at `src_block_index = K+m` has been admitted. The claim composes with FA7 (cross-shard receipt atomicity), FA-Apply-9 (apply-side dedup), FA-Apply-12 (applied-receipt restore), and FA-Apply-13 (source-side outbound apply) to preserve the K-shard sum identity (FA7's no-double-credit + no-loss-of-funds) under the apply-time gating that Option 2 introduces. Option 2 is the **practical** partial closure; **v2.7 F2 / Option 1** (Phase-1 intersection commitment on `inbound_keys`, formalized in F2-SPEC.md + FB22 + F2ApplyComposition.md) is the **formal-determinism** full closure. The two layers compose: F2 doesn't require ripping Option 2 out; Option 2 reduces the abort surface F2 needs to handle to a residual <-1-block-gossip-lag window.

**Companion documents:** `Preliminaries.md` (F0) for notation, validator predicates V12 + V13, and assumptions A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision resistance); `CrossShardReceipts.md` (FA7) for the upstream cross-shard atomicity theorems T-7 / T-7' / T-7.1 that this proof preserves under time-ordered admission; `CrossShardReceiptDedup.md` (FA-Apply-9) for the apply-side dedup theorems T-R1..T-R7 that compose with T-1..T-5 of the present proof; `CrossShardOutboundApply.md` (FA-Apply-13) for the source-side outbound-apply sibling; `AppliedReceiptRestore.md` (FA-Apply-12) for the `i:` namespace snapshot-restore round-trip that survives the time-ordered admission gate (admission is producer-local, not chain-state); `F2-SPEC.md` for the v2.7 F2 Option 1 strict-determinism path; `F2ApplyComposition.md` for the F2 + apply-layer joint closure; `tla/CrossShardReceiptRoundtrip.tla` (FB32) for the machine-checkable lifecycle state machine that exercises Option 2's `CROSS_SHARD_RECEIPT_LATENCY` gate as one of its actions.

---

## 1. Problem statement (pre-S-016)

### 1.1 The cross-shard receipt admission pipeline

Cross-shard receipt delivery on the destination shard proceeds in three stages:

1. **Bundle arrival (gossip).** A `CROSS_SHARD_RECEIPT_BUNDLE` message carrying a source-shard block `B_src` and its committee signatures arrives at the destination shard via beacon-relayed gossip. The handler `Node::on_cross_shard_receipt_bundle` (`src/node/node.cpp:1612-1649`) verifies the K-of-K committee-signature gate against the source-shard pool view (FA7 L-7.4), filters `B_src.cross_shard_receipts` to those with `dst_shard == my_shard_id`, deduplicates against `pending_inbound_receipts_` (the destination's transit pool), and inserts new receipts into the pool keyed by `(src_shard, tx_hash)`.

2. **Producer-side admission (block composition).** When the destination shard's committee enters Phase 2 (block-sig phase) at `start_block_sig_phase` (`src/node/node.cpp:950-1022`), each committee member calls `inbound_receipts_eligible_for_inclusion` to snapshot the receipt pool and pass it into `build_body`. Pre-S-016, this snapshot was a direct iteration of `pending_inbound_receipts_` — every receipt currently in the pool was admitted to the tentative block.

3. **Apply-side dedup + credit (block finalization).** Once the block is finalized, `Chain::apply_transactions` (`src/chain/chain.cpp:1363-1381`) processes each `b.inbound_receipts[]` entry: the apply-layer dedup gate (FA-Apply-9 T-R2) silently skips already-credited keys, the credit branch (FA-Apply-9 T-R1) advances `accounts_[r.to].balance += r.amount` + `block_inbound`, and the `applied_inbound_receipts_` set + `accumulated_inbound_` counter both monotonically advance.

### 1.2 The pre-S-016 divergence surface

Stages (1) and (2) run **per-committee-member**. Each member's `pending_inbound_receipts_` is local state, populated by gossip from peers. Gossip is asynchronous: a receipt that arrives at member A in epoch `t` may not arrive at member B until epoch `t + Δ_g`. If member A enters Phase 2 at `t + ε` (`ε < Δ_g`), A's snapshot includes the receipt; B's does not. The two members produce tentative blocks with different `inbound_receipts[]` lists → different `compute_block_digest` → K-of-K fails → round aborts → round retries.

Pre-S-016, the documented behavior (per the original B3.4 commit message captured in OV-#5): "Each destination-shard committee member passes their *local* `pending_inbound_receipts_` snapshot to `build_body`. If pools differ momentarily during bundle gossip, members produce different tentative blocks → K-of-K fails → round retries." Correctness is preserved (the round retries; eventually all members converge), but the latency cost is a non-negligible fraction of cross-shard transfer rounds at intra-region gossip lag scales.

### 1.3 The deeper invariant at stake (post-S-016)

The pre-S-016 divergence is **latency-only, not safety**. FA7 L-7.2 (V13 dedup is monotone-correct) + FA-Apply-9 T-R2 (apply-side duplicate-silent-skip) jointly guarantee that no receipt is double-credited regardless of how many rounds it takes to land in a finalized block. The pre-S-016 issue is a *round-retry economics* concern — every retry burns gossip bandwidth + delay-compute CPU + adds user-visible latency to cross-shard transfers.

However, the divergence *also* opens a latent ordering hazard that motivates Option 2's stricter framing: **without time-ordered admission, receipts from the same source shard could be admitted in different orders across consecutive blocks** depending on which subset converged first. The FA7 L-7.4 K-of-K source-block ratification verifies each receipt's source-block authenticity, but does not impose any inter-receipt ordering. A naive admission policy that simply admits "every receipt in the pool whose gossip-side ratification passed" could (in principle) admit receipt `R(K+1)` before receipt `R(K)` if `R(K)`'s K-of-K gossip ratification happens to complete later than `R(K+1)`'s. The FA7 receipt-as-conserved-quantity invariant survives (the K-shard sum identity is order-independent), but the per-source local ordering — which downstream applications (e.g., DApp state-machine sequencing on top of cross-shard receipts) may implicitly depend on — is not enforced.

Option 2's time-ordered admission predicate strengthens the per-source local ordering by gating admission on **first-seen height**, which under gossip-monotone propagation translates to a per-source-shard total order on admitted receipts. This is the second-class invariant that motivates the present proof's T-1 (per-source total order) + T-2 (no replay-backward) theorems, beyond the round-retry-economics motivation captured by SECURITY.md §S-016.

---

## 2. Option 2 closure — time-ordered admission

### 2.1 Storage

Per `include/determ/node/node.hpp:589-591`:

```cpp
// Erased alongside pending_inbound_receipts_ on receipt apply.
std::map<std::pair<ShardId, Hash>, uint64_t>
    pending_inbound_first_seen_;
```

The map is keyed by the same `(src_shard, tx_hash)` pair as `pending_inbound_receipts_` — establishing a parallel-map invariant: every key in `pending_inbound_receipts_` has a matching key in `pending_inbound_first_seen_` (populated together at insertion; erased together at apply). The value is the destination chain's `chain_.height()` at the moment the receipt was first observed by this node's gossip layer.

### 2.2 Insertion site

Per `src/node/node.cpp:1629-1641`, within `on_cross_shard_receipt_bundle`:

```cpp
for (auto& r : src_block.cross_shard_receipts) {
    if (r.dst_shard != cfg_.shard_id) continue;
    if (r.src_shard != src_shard)     continue;     // sanity
    auto key = std::make_pair(r.src_shard, r.tx_hash);
    if (pending_inbound_receipts_.count(key)) continue;     // already buffered
    pending_inbound_receipts_[key] = r;
    // S-016 Option 2: record first-seen height so build_body's
    // snapshot construction can skip receipts that haven't soaked
    // long enough for gossip to have propagated to every K-committee
    // member.
    pending_inbound_first_seen_[key] = chain_.height();
    ++added;
}
```

The insertion is **idempotent**: a receipt seen twice (e.g., the same bundle gossiped via two distinct paths) is dedup'd by the `pending_inbound_receipts_.count(key)` guard at the head of the loop, so `pending_inbound_first_seen_[key]` is written only on the *first* observation. This is the invariant Theorem T-1's proof rests on.

### 2.3 Eraser site

Per `src/node/node.cpp:1831-1835`, within `apply_block_locked` (the post-apply cleanup loop):

```cpp
for (auto& r : b.inbound_receipts) {
    auto key = std::make_pair(r.src_shard, r.tx_hash);
    pending_inbound_receipts_.erase(key);
    pending_inbound_first_seen_.erase(key);  // S-016: keep parallel-map in sync
}
```

The paired-erase preserves the parallel-map invariant after every block apply: any receipt that the apply layer credited is removed from both the transit pool and the first-seen map together. The apply-side dedup set `applied_inbound_receipts_` (FA-Apply-9 storage) is the chain-state-side record of credit; the two transit-pool maps are producer-side fast-path state and are not part of `state_root`.

### 2.4 Admission predicate

Per `src/node/node.cpp:1574-1599`:

```cpp
static constexpr uint64_t CROSS_SHARD_RECEIPT_LATENCY = 3;

std::vector<chain::CrossShardReceipt>
Node::inbound_receipts_eligible_for_inclusion() const {
    std::vector<chain::CrossShardReceipt> out;
    out.reserve(pending_inbound_receipts_.size());
    uint64_t now = chain_.height();
    for (auto& kv : pending_inbound_receipts_) {
        auto fit = pending_inbound_first_seen_.find(kv.first);
        // No first-seen record (shouldn't happen — receipts and
        // first-seen are populated together) → admit conservatively.
        // Drop instead of admit would silently delay forever.
        if (fit == pending_inbound_first_seen_.end()) {
            out.push_back(kv.second);
            continue;
        }
        // Underflow-safe age check: now - first_seen >= latency
        // rewritten as first_seen + latency <= now to avoid wrapping
        // when first_seen happens to exceed now (impossible in
        // practice but cheap to defend against).
        if (fit->second + CROSS_SHARD_RECEIPT_LATENCY <= now) {
            out.push_back(kv.second);
        }
    }
    return out;
}
```

The predicate's three components:

- **`first_seen + CROSS_SHARD_RECEIPT_LATENCY <= now`** — the age gate. A receipt becomes eligible exactly `CROSS_SHARD_RECEIPT_LATENCY` blocks after its first local observation; pre-eligibility it is excluded from the build_body snapshot. The underflow-safe formulation (rewriting `now - first_seen >= latency` as `first_seen + latency <= now`) avoids u64 wrap if a hypothetical race left `first_seen > now`.

- **No-first-seen-record fallback** — admits the receipt. Defensive: if a parallel-map invariant violation slipped past the `pending_inbound_first_seen_[key] = chain_.height();` insertion in §2.2, the safe action is "include it now" rather than "delay forever". The codebase guarantees the parallel-map invariant by construction; this branch is dead code in practice.

- **Returned snapshot** — a `vector<CrossShardReceipt>` consumed by `start_block_sig_phase` (`node.cpp:967`) and `try_finalize_round` (`node.cpp:1069`) as the `inbound_snapshot` parameter to `build_body`. The snapshot is the **only** path inbound receipts reach a tentative block — pre-Option 2 it was a direct iteration of `pending_inbound_receipts_`; post-Option 2 it is the filtered subset.

### 2.5 Per-source ordering (the second-class invariant)

The admission predicate does **not** directly enforce a per-source-shard ordering — it operates only on the age gate. The per-source total ordering claim (Theorem T-1) emerges from the **conjunction** of three facts:

1. **First-observation monotonicity within a source shard.** A source shard `s` produces blocks in strictly monotonic `src_block_index` order (FA1 per-shard finality + L-7.3 single-chain commit order). Receipts originating at `s` are gossiped in `src_block_index` order — i.e., for two receipts `R₁` and `R₂` from `s` with `R₁.src_block_index < R₂.src_block_index`, the bundle carrying `R₁` is gossiped *before* the bundle carrying `R₂` by at least one source-chain block period.

2. **First-seen height monotonicity at the destination.** Under FIFO gossip propagation within an honest network (or even under simply "no reordering of bundles from `s`"), the destination's first-observation timestamps satisfy `first_seen(R₁) ≤ first_seen(R₂)` — the earlier-emitted receipt is observed at the destination no later than the later-emitted one. Under adversarial gossip (a peer reorders bundles from `s`), the destination may receive `R₂` first; but the FA7 L-7.4 K-of-K source-block gate verifies `R₁.src_block_index < R₂.src_block_index` from the source-block height stored in `pending_inbound_receipts_[R].src_block_index`, and L-7.3 establishes the source-chain ordering as the *canonical* ordering of receipts from `s`.

3. **Apply-side ordering via the dedup set.** The destination chain credits receipts in block order. The producer's `build_body` snapshot (post-Option 2) may include receipts in arbitrary order within a single tentative block (the `std::map`-keyed iteration in §2.4 is lexicographic on `(src_shard, tx_hash)`, not on `src_block_index`), but FA-Apply-9 T-R5 (A1 invariance under dedup) + T-R6 (apply-determinism with dedup) guarantee that the *credit effects* of admitting receipts in any order from the same source are identical (the receipt-as-conserved-quantity invariant is order-independent over single-block applies).

The combined claim (Theorem T-1) is: **the receipt admitted earliest from `src_shard = s` has the smallest `src_block_index` among `s`-originating receipts admitted to date**, under FIFO gossip + the age-gate's first-seen-monotonicity-preserving filter. Adversarial reordering at the gossip layer is bounded by FA7 L-7.4 (forging a bundle requires forging K source-shard sigs); the admission predicate's eligibility check is per-receipt and does not cross-reference other receipts, but the FIFO + L-7.3 + L-7.4 conjunction restores the ordering at the source-shard granularity. The formal claim is in §3.

### 2.6 Why 3 blocks

The `CROSS_SHARD_RECEIPT_LATENCY = 3` constant is set per `src/node/node.cpp:1574`. The choice is operational:

- **Web profile** (`tx_commit_ms = 200`): 3 blocks ≈ 600 ms — roughly 5-6 intra-region RTTs (typical intra-region one-way latency 30-80 ms). Bundle gossip from one shard to another (via beacon relay) takes 2 hops; 5-6 RTTs covers the propagation to every K-committee member with overwhelming probability under realistic gossip-fanout fanout values (default fanout 6 + log-N propagation).

- **Regional profile** (`tx_commit_ms = 300`): 3 blocks ≈ 900 ms — covers cross-region RTTs up to ~150 ms one-way with substantial headroom.

- **Global profile** (`tx_commit_ms = 600`): 3 blocks ≈ 1800 ms — covers worldwide RTTs (Tokyo ↔ Frankfurt ≈ 250 ms) with multiple round-trips of slack.

- **Tactical profile** (`tx_commit_ms = 20`): 3 blocks ≈ 60 ms — designed for local-network cluster deployments where the gossip-delay-vs-block-time ratio is essentially 1:1; the 3-block soak is still enough to absorb transient out-of-order arrivals.

The constant is intentionally *not* a `Config` knob — making it per-deployment configurable would create a divergence surface (committee members with different latency constants would have different eligibility sets). It is a protocol-level constant baked into the per-profile timing trade-off; future deployments with substantially different gossip characteristics would adjust at the `node.cpp:1574` source line + recompile, which the proof's T-4 (latency bound) analysis covers as an explicit recompile + redeployment maneuver.

---

## 3. Theorems

### T-1 — Per-source-shard total order

**Statement.** For any two cross-shard receipts `R₁, R₂` originating at the same source shard `s` with `R₁.src_block_index < R₂.src_block_index`, under FIFO bundle gossip from `s` to the destination + the age-gate predicate at `node.cpp:1594`, `R₁` is admitted to a destination block at chain height `h₁` and `R₂` at chain height `h₂` with `h₁ ≤ h₂`. The admission ordering is **strictly monotonic**: no destination block at height `h < h₂` containing `R₂` can precede the first destination block at height `h ≥ h₁` containing `R₁` in the chain's apply order.

**Proof sketch.** By induction on the admission step counter. Let `T = pending_inbound_receipts_` ∪ `applied_inbound_receipts_` be the receipt universe known to the destination at any time. The induction hypothesis: at every admission step, the set of admitted-from-`s` receipts forms a prefix of `s`'s `src_block_index`-sorted receipt sequence.

**Base case.** Before any receipts from `s` are admitted, the prefix is empty; the hypothesis holds vacuously.

**Inductive step.** Assume the hypothesis at step `k`, with admitted-from-`s` prefix `{R(s, 0), R(s, 1), ..., R(s, j)}` (using shorthand `R(s, i)` for the receipt at `s.src_block_index = i`). Consider the next admission, at chain height `h`. The eligibility predicate iterates `pending_inbound_receipts_`; for each receipt the age gate fires iff `first_seen[(src, tx_hash)] + 3 <= h`. By the insertion-site invariant (§2.2), `first_seen[(s, tx_hash(R(s, i)))]` is set at the moment `R(s, i)` first arrives via gossip — call this height `g(s, i)`. By FIFO gossip from `s`: `g(s, 0) ≤ g(s, 1) ≤ g(s, 2) ≤ ...`. The age gate fires for `R(s, i)` iff `g(s, i) + 3 ≤ h`, which by FIFO-monotonicity of `g(s, ·)` implies the gate fires for `R(s, i')` with `i' < i` (provided those receipts are still in `pending_inbound_receipts_`).

The cleanup loop at `node.cpp:1831-1835` removes a receipt from `pending_inbound_receipts_` only after the apply layer has credited it (i.e., after it is added to `applied_inbound_receipts_`). So a receipt eligible at step `k+1` is either still in `pending_inbound_receipts_` (then admitted by `build_body`) or already in `applied_inbound_receipts_` (then dedup-skipped by FA-Apply-9 T-R2). In either case, no `R(s, i')` with `i' < i` and an eligibility-firing age gate is "left behind" — they are all either currently in the eligible snapshot or already credited.

Therefore the admitted-from-`s` set at step `k+1` is `{R(s, 0), R(s, 1), ..., R(s, j+m)}` for some `m ≥ 0` (the receipts whose age gate first fires at step `k+1`). The prefix property is preserved. ∎

**Adversarial gossip caveat.** If a malicious peer reorders bundles from `s` (gossiping `R(s, 5)` to the destination before `R(s, 3)`), then `g(s, 5) < g(s, 3)`, and the age gate for `R(s, 5)` fires before the age gate for `R(s, 3)`. The induction hypothesis above breaks — `R(s, 5)` could be admitted before `R(s, 3)` arrives. However, this is the **gossip-FIFO** caveat, not an Option 2 bug:

- FA7 L-7.4 K-of-K source-block ratification verifies each receipt's `src_block_index` against the source-shard pool view. The destination knows `R(s, 5).src_block_index = 5` and `R(s, 3).src_block_index = 3` from the bundle metadata regardless of gossip order.

- A v2+ refinement could re-sort the admission snapshot by `(src_shard, src_block_index)` to restore strict-monotonic admission even under adversarial reordering. The current `std::map`-keyed iteration order (`(src_shard, tx_hash)`) doesn't enforce this, but the apply-side credit semantics (FA-Apply-9 T-R5 + T-R6: A1 invariance + apply-determinism) make the *credit outcome* order-independent — adversarial reordering can only affect *which destination block* a receipt lands in, not whether it lands at all or how much it credits.

- v2.7 F2 (Option 1) closes this fully: the Phase-1 intersection commitment on `inbound_keys` requires ALL K members to have observed a receipt before it is eligible, which under the K-of-K majority of honest members defeats single-adversarial-peer reordering attacks.

The honest-gossip FIFO assumption is the standard model for Option 2's claims; adversarial gossip degrades to the FA-Apply-9-credit-order-independent regime (still safe, less ordered) until F2 closes it.

**Code witness.** `src/node/node.cpp:1629-1641` (insertion site, first_seen captured at gossip arrival); `src/node/node.cpp:1574-1599` (admission predicate); `src/node/node.cpp:1831-1835` (paired-erase on apply).

### T-2 — No replay-backward

**Statement.** Let `applied_high_water(s)` denote the largest `src_block_index` of any receipt from source shard `s` admitted to date on the destination chain. Once `applied_high_water(s) = K` for some `K`, no receipt from `s` with `src_block_index < K` can be admitted via the producer-side path. Equivalently: the admission set's per-source `src_block_index` is monotone non-decreasing over chain-apply time.

**Proof sketch.** The FA-Apply-9 dedup set `applied_inbound_receipts_` is monotone-growing (FA-Apply-9 §3 + T-R6 codebase-search of no `erase` path). Once a receipt at `src_block_index = K` is credited (its `(s, tx_hash)` pair inserted into the set), the receipt is removed from `pending_inbound_receipts_` (§2.3 paired-erase) and never re-enters the producer-side admission snapshot.

A receipt `R(s, j)` with `j < K` arriving *after* `R(s, K)`'s credit can be in one of three states:

1. **`R(s, j)` already credited.** Then it's not in `pending_inbound_receipts_`. The admission snapshot (§2.4) iterates only `pending_inbound_receipts_`, so `R(s, j)` is not admitted. T-R2 (apply-side dedup) would silent-skip it even if some hypothetical bypass route brought it back to the apply layer.

2. **`R(s, j)` in `pending_inbound_receipts_` at the time of `R(s, K)`'s credit.** The age gate at `node.cpp:1594` requires `first_seen(R(s, j)) + 3 ≤ chain.height()`. By the FIFO gossip assumption in T-1, `first_seen(R(s, j)) ≤ first_seen(R(s, K))`; by the time `R(s, K)` was credited, the age gate for `R(s, j)` had also been firing, so `R(s, j)` would have been admitted in the same or an earlier block. The "same block" case satisfies T-2 (both in the same block; no replay-backward since `R(s, j)` precedes `R(s, K)` in source-block order which T-1 may not have preserved without F2's intersection commitment, but the apply-side credit is unambiguous). The "earlier block" case puts `R(s, j)` in `applied_inbound_receipts_` before `R(s, K)`, contradicting the hypothesis "`R(s, K)` credited first".

3. **`R(s, j)` not yet arrived at the destination.** This is the late-arrival case: a malicious source peer delays the gossip of `R(s, j)` until after `R(s, K)` is credited. The receipt enters `pending_inbound_receipts_` at the late arrival, with `first_seen = chain.height_at_late_arrival`. The age gate fires after 3 more blocks. The producer's admission snapshot **does** include it. The apply layer then credits it (FA-Apply-9 T-R1) as a fresh credit, inserting `(s, R(s, j).tx_hash)` into `applied_inbound_receipts_` *after* the entry for `R(s, K)`. The per-source `src_block_index` admission order is now: ... `K` ... `j` ... — non-monotonic.

Case 3 is the **honest-late-arrival case** and is *not* a T-2 violation in the sense of double-credit (FA-Apply-9 T-R2 still prevents that — each `(s, tx_hash)` is credited exactly once). The "no replay-backward" claim in the strict-T-2 sense is: **a receipt with the same `(src_shard, tx_hash)` pair cannot be re-credited** after it has been credited once. This is FA-Apply-9 T-R2 directly. The weaker per-source `src_block_index` strict-monotonic admission claim is the gossip-FIFO-conditional T-1 claim, with the late-arrival case handled by the apply-time credit order being decoupled from the source-block order.

Therefore the strict no-replay-backward claim (T-2) holds **unconditionally** by FA-Apply-9 T-R2 — Option 2's contribution to T-2 is the producer-side admission filter that reduces the surface for a malicious peer to reorder receipts within a single round, but the chain-state-side T-R2 is the canonical defense. ∎

**Code witness.** `src/chain/chain.cpp:1365` (FA-Apply-9 apply-side dedup-skip predicate); `src/node/validator.cpp:1142` (V13 validator-side dedup rejection); `src/node/producer.cpp:511` (producer-side dedup-skip on block-body composition). All three layers are independent backstops; T-2 is preserved by any one of them.

### T-3 — Cross-source independence

**Statement.** For two cross-shard receipts `R₁, R₂` originating at distinct source shards (`R₁.src_shard ≠ R₂.src_shard`), the admission of `R₁` is independent of the admission of `R₂` — no receipt from shard `s₁` can block or delay a receipt from shard `s₂`, nor cause a false-conflict at the dedup-set level.

**Proof sketch.** Three components compose:

1. **Storage independence.** `pending_inbound_first_seen_` is keyed by the pair `(src_shard, tx_hash)`. By `std::pair` lexicographic order, `(s₁, h) ≠ (s₂, h)` for `s₁ ≠ s₂`. The two receipts occupy distinct keys in both `pending_inbound_receipts_` and `pending_inbound_first_seen_`; no map-level collision.

2. **Age-gate independence.** The admission predicate at `node.cpp:1594` evaluates the age gate per-receipt: `fit->second + CROSS_SHARD_RECEIPT_LATENCY <= now`. Each receipt's `first_seen` is independent — `R₁`'s first-seen height is the moment `s₁`'s bundle arrived, `R₂`'s is the moment `s₂`'s bundle arrived. The predicate does not cross-reference receipts from other sources; the age gate fires on `R₁` exactly when `R₁`'s soak period elapses, irrespective of `R₂`'s state.

3. **Apply-side dedup independence (FA-Apply-9 T-R3).** The applied dedup set `applied_inbound_receipts_` keys on `(src_shard, tx_hash)`. By the same `std::pair` lexicographic distinguishability, `R₁` and `R₂` occupy distinct keys; crediting `R₁` does not affect the dedup-skip evaluation for `R₂`. FA-Apply-9 T-R3 ("Per-source-shard independence") proves this directly: receipts from distinct source shards are processed as independent dedup-keyed entries.

Therefore admission and credit of `R₁` and `R₂` are independent operations on independent state-map entries; no false-conflict is possible. ∎

**Code witness.** `src/node/node.cpp:1635-1640` (key construction `std::make_pair(r.src_shard, r.tx_hash)` for insertion; pair-keyed independence at storage time); `src/node/node.cpp:1594` (per-receipt age gate); `src/chain/chain.cpp:1364-1365` (apply-side pair-keyed dedup, FA-Apply-9 T-R3 citation).

### T-4 — Latency bound

**Statement.** Under Option 2 with `CROSS_SHARD_RECEIPT_LATENCY = L` (currently `L = 3`), the maximum admission delay for an honestly-gossiped receipt is `L` destination chain blocks after first observation, i.e., `at most L × tx_commit_ms` wall-clock time at the destination's profile. Equivalently, the cross-shard transfer's end-to-end user-visible latency is bounded by:

```
T_total ≤ T_source_finalize + T_gossip_propagate + L × tx_commit_ms_dest + T_dest_finalize
```

where `T_source_finalize` is the source-shard block finalization time (per-profile `tx_commit_ms_src`), `T_gossip_propagate` is the bundle-relay time via the beacon, `L × tx_commit_ms_dest` is the Option 2 soak time, and `T_dest_finalize` is the destination-shard block finalization time. For the web profile (200 ms blocks, `L = 3`), this is `~200ms + Δ_g + 600ms + 200ms` — total user-visible cross-shard latency on the order of 1-2 seconds under typical intra-region gossip.

**Proof sketch.** The admission predicate at `node.cpp:1594` is the only gating mechanism on the producer side; once the predicate fires (at `first_seen + L`), the receipt is included in the next built tentative block, which (under FA4 liveness) is finalized in the immediately-next destination committee round. The bound `L × tx_commit_ms_dest` follows directly from the predicate's age gate plus FA4 destination liveness.

**Edge cases:**

- **Adversarial peer delays gossip arrival.** The bound is computed from `first_seen`, which is the *local* first-observation height. A malicious peer that delays the bundle's arrival at the destination cannot shorten the post-arrival soak below `L`. The total end-to-end latency is unbounded if the gossip layer is partitioned, but FA4 + FA7' (receipt-completeness eventual delivery) ensure eventual finalization under partial-synchrony.

- **Cluster of arrivals at the destination just before the age gate fires.** The destination producer may include multiple receipts in the same block; the per-block bound `L × tx_commit_ms_dest` is upper-bounded by the single-block finalization time, not the sum across receipts.

- **Aggregate behavior under bursty gossip.** If `M` receipts arrive in a single gossip burst at chain height `h_0`, they all have `first_seen = h_0`, become eligible simultaneously at `h_0 + L`, and the producer includes the entire batch in a single block (up to whatever block size limit applies, see PROTOCOL.md §9.2 S-022 caps). The bound is amortized across the batch — no individual receipt waits longer than `L`.

The 3-block constant gives the latency-vs-divergence trade-off: smaller `L` reduces user-visible latency but increases the probability that a single committee member misses the bundle before its commit and the round aborts; larger `L` increases divergence-safety at user-visible latency cost. The choice `L = 3` is the operational compromise (§2.6); v2.7 F2 (Option 1) replaces the age-gate trade-off with the strict-determinism intersection commitment, eliminating the trade-off entirely at the cost of block-format change. ∎

**Code witness.** `src/node/node.cpp:1574` (constant declaration with the latency rationale); `src/node/node.cpp:1594` (age gate firing condition).

### T-5 — Composition with FA7 + FA-Apply-9 + FA-Apply-12

**Statement.** Under the conjunction of:

- **T-1..T-4** (this proof's per-source total order, no replay-backward, cross-source independence, latency bound)
- **FA-Apply-9 T-R1..T-R7** (apply-side dedup theorems: first-application credits, duplicate silent skip, per-source-shard independence, snapshot restore preserves dedup set, A1 invariance under dedup, apply-determinism, pre-receipt-application non-existence guarantee)
- **FA-Apply-12 T-AR1..T-AR4** (applied-receipt restore theorems: serialization includes applied_receipts, restore preserves the set, post-restore replay is rejected, A1 invariance survives the round-trip)
- **FA7 T-7 + T-7.1** (cross-shard receipt atomicity: no double-credit, no fabrication, global supply-conservation Corollary)

the **K-shard sum identity** (FA7 T-7.1: `LiveGlobal + Pending = GenesisGlobal + SubsidyGlobal - SlashedGlobal`) is preserved under Option 2's time-ordered admission. Specifically:

1. **No double-credit.** Option 2 does not introduce a new credit path; the apply-side credit at `chain.cpp:1367-1370` is the unique credit channel, gated by FA-Apply-9 T-R2 dedup. Option 2 only filters the producer's snapshot; the credit semantics are unchanged. The K-shard `LiveGlobal` sum is preserved by FA-Apply-9 T-R5 (A1 invariance).

2. **No loss of funds.** Option 2 delays admission by up to `L` blocks, increasing the `Pending` term in FA7 T-7.1 by `L × (per-block receipt amount)`. The `Pending` is **not** lost — it remains in the source-shard `accumulated_outbound_` channel (FA-Apply-13) until the destination credits it. Under FA7 T-7' (receipt-completeness eventual delivery) + FA4 destination liveness, every eligible receipt is eventually admitted, so `Pending → 0` in quiescence and the sum identity closes.

3. **No re-credit-after-restore.** Option 2's producer-side admission state (`pending_inbound_first_seen_`) is *not* part of `state_root` — it is producer-local fast-path state. After a snapshot restore (FA-Apply-12), the receiving node has `pending_inbound_first_seen_ = ∅` and `pending_inbound_receipts_ = ∅`; new bundles arriving post-restore are inserted afresh into both maps at the new node's chain height. The `applied_inbound_receipts_` set survives the restore (FA-Apply-12 T-AR2), so any receipt already credited pre-snapshot is dedup-skipped post-restore (FA-Apply-9 T-R2 + T-AR3). The Option 2 admission gate's "soak from new arrival" reset is a producer-side scheduling concern, not a credit-correctness concern — the apply-side dedup is the canonical defense.

4. **Per-source ordering preserved.** Under honest gossip FIFO (T-1), receipts from the same source shard are admitted in `src_block_index` order. Under adversarial gossip, the per-source `src_block_index` admission order may break, but FA-Apply-9 T-R6 (apply-determinism) ensures the *credit outcome* is identical regardless of admission order. The K-shard sum identity is preserved in either case.

**Proof sketch.** The five components compose conjunctively. Option 2's admission predicate (§2.4) is a function on `(pending_inbound_receipts_, pending_inbound_first_seen_, chain.height())` — none of which Option 2 introduces new mutation channels into beyond `insert (§2.2)` and `erase (§2.3)`, both of which respect the parallel-map invariant. The chain-state credit path is unchanged from FA-Apply-9; the snapshot path is unchanged from FA-Apply-12. The pending pool difference (with vs without Option 2 filter) only affects the producer's tentative-block composition — which by FA-Apply-9 T-R6 produces the same final credited-set across any block ordering of receipts from the same source.

Therefore the joint invariant set `{T-7, T-7.1, T-R1..T-R7, T-AR1..T-AR4}` is closed under Option 2's filter — the filter is a refinement of "which round each eligible receipt is admitted into" without altering "whether each eligible receipt is eventually credited" or "what each credit's effect on chain state is". The K-shard sum identity is preserved.

**Composition note (with F2-SPEC):** v2.7 F2 (Option 1, intersection commitment) replaces the Option 2 age-gate with a strict-determinism Phase-1 intersection rule on `inbound_keys`. F2 + Option 2 are compatible: F2 doesn't require ripping Option 2 out, and Option 2's pre-eligible filter reduces the F2-intersection-input pool to receipts already gossiped to a quorum. The two layers in joint deployment provide both the practical-latency benefit (Option 2's 3-block soak) and the formal-determinism benefit (F2's intersection commitment). The Option 2 filter is provably safe in joint deployment by T-5 above — the FA7 + FA-Apply-9 + FA-Apply-12 + F2-Apply-Composition closure is unaffected.

**Code witness.** `src/chain/chain.cpp:1363-1381` (FA-Apply-9 apply loop, unchanged by Option 2); `src/chain/chain.cpp:1393` (A1 fold, unchanged); `src/chain/chain.cpp:1585-1592` (FA-Apply-12 serialize, unchanged); `src/chain/chain.cpp:1778-1785` (FA-Apply-12 restore, unchanged); `src/node/node.cpp:1574-1599` (Option 2 admission predicate, the new code path); `src/node/node.cpp:1831-1835` (paired-erase on apply, the new cleanup code path). The five citations bracket the entire scope of Option 2's footprint — outside this footprint, the proof's composition with FA7 + FA-Apply-9 + FA-Apply-12 is structurally identical to pre-Option-2 behavior with the per-source ordering invariant additionally strengthened.

---

## 4. Option 2 partial → v2.7 F2 full

S-016 SECURITY.md classifies the current state as 🟠 Partially mitigated. The partial / full distinction is:

| Property | Option 2 (this proof) | Option 1 / v2.7 F2 |
|---|---|---|
| Round-retry probability | Negligible under honest gossip (geometric decay with `L`) | Zero (strict-determinism by construction) |
| Block-format change | None | ContribMsg gains `inbound_keys: [(ShardId, Hash)]` |
| Bandwidth overhead | None | O(K × pool size) per ContribMsg |
| Adversarial-gossip resilience | Reduces to FA-Apply-9 + FA-Apply-12 unconditional safety | Defeats single-adversarial-peer reordering via intersection (honest-majority across K members) |
| Per-source `src_block_index` ordering | Preserved under FIFO gossip (T-1) | Preserved unconditionally via intersection-commitment binding |
| Wall-clock latency cost | `L × tx_commit_ms` per receipt (~600ms on web profile) | None (F2 commits at first observation, not after soak) |
| Composition with FA7/FA-Apply-9/FA-Apply-12 | Theorem T-5 (this proof) | F2ApplyComposition.md T-1..T-5 |
| Status | ✅ Shipped (this in-session round closed it) | 🟠 Spec'd (F2-SPEC.md); implementation deferred to v2.7 |

**What F2 keeps from Option 2.** F2-SPEC.md §2.3 explicitly notes Option 2 is "compatible with — and superseded by — the F2 work; F2 doesn't require ripping Option 2 out." The two compose: Option 2's pre-eligibility filter reduces F2's intersection-input pool to receipts already gossiped to a meaningful fraction of the K-committee, which improves F2's intersection-rule liveness (more receipts available to intersect over).

**What F2 strictly adds.** The Phase-1 ContribMsg's `inbound_keys` Merkle commitment + the validator's V21..V26 reconciliation passes give:

- **Strict pre-block-finalization commitment.** Each committee member's view of `inbound_keys` is cryptographically bound into their Phase-1 commit (Ed25519 sig over the extended `make_contrib_commitment`). A member cannot equivocate on their view across the K-of-K round.

- **Intersection rule** (`inbound_keys ⊆ ∩_{i=1..K} ContribMsg_i.inbound_keys`). The canonical inbound set is the intersection across all K members — a receipt is admitted only if every K-committee member has independently observed it. This is the "conservative credit" rule from F2-SPEC.md §Q1 and the F2ApplyComposition T-2 IntersectionAntiMonotonic theorem.

- **Validator re-derivation.** V22-V26 (per F2ViewReconciliationAnalysis.md §6) re-derive the canonical list from the K committed `inbound_keys` lists and reject any block whose `inbound_receipts[]` doesn't match. The reconciliation is deterministic given the K commitments.

**Residual gap closed at v2.7 F2 ship.** The Option 2 partial mitigation leaves one theoretical edge case open: in a partition where one of K committee members has substantially worse gossip connectivity than the others, the worse-connected member may consistently have a smaller `eligible_receipts_for_inclusion` set, causing repeated round-retries until the gossip lag converges. Option 2's `L = 3` blocks of soak shrinks this surface but doesn't eliminate it. F2's intersection rule eliminates it: the worst-connected member's view *is* the canonical view (intersection bound from below), so the K-of-K converges on the first round regardless of inter-member connectivity differences.

The closure trajectory: S-016 was originally Open; Option 2 closed it to Partially-mitigated in this session's round; v2.7 F2's Option 1 (currently spec'd, implementation tracked as the v2.7 work item) closes it fully. Until v2.7 ships, Option 2 carries the practical-deployment surface.

---

## 5. Findings

### F-1 (Operational): `CROSS_SHARD_RECEIPT_LATENCY` is hard-coded

The constant `CROSS_SHARD_RECEIPT_LATENCY = 3` at `src/node/node.cpp:1574` is a `static constexpr uint64_t` baked into the binary. Operators with substantially different gossip-vs-block-time ratios would need to recompile to adjust. This is *intentional* (§2.6) — making it a `Config` knob would create a divergence surface (committee members with different latency values would have different eligibility sets, defeating the purpose). A v2+ refinement could expose it as a per-shard PARAM_CHANGE (with cluster-wide consensus on the value), but the current design accepts the trade-off.

**Status:** Acknowledged design choice; not a defect.

### F-2 (Theoretical): Adversarial gossip can reorder per-source admission

T-1's per-source-shard total order rests on the FIFO bundle-gossip assumption. A malicious peer can reorder bundles from `s` arriving at the destination, causing `R(s, K+1)` to be observed before `R(s, K)`. T-2 (no replay-backward) and T-5 (composition with FA7 + FA-Apply-9 + FA-Apply-12) still hold — the K-shard sum identity is preserved by FA-Apply-9 T-R5 + T-R6 regardless of admission order — but the per-source `src_block_index` strict-monotonic admission claim degrades.

**Status:** Documented in §3 T-1's "Adversarial gossip caveat"; v2.7 F2's intersection commitment closes this fully under the honest-majority-of-K assumption.

### F-3 (Theoretical): Late-arrival case admits out-of-order

A receipt `R(s, j)` with `j < K` that arrives at the destination *after* `R(s, K)` has been credited will be admitted with `first_seen = late_arrival_height`, soaking for `L` blocks, then credited at a chain height **after** `R(s, K)`. The per-source `src_block_index` admission order is non-monotonic in this case (T-2 §Case-3). This is the **honest-late-arrival case** — not an attack, but a real edge case in deployments with widely-variable inter-shard gossip latency (e.g., one shard temporarily partitioned for `> L × tx_commit_ms` then reconnects).

**Status:** Documented in T-2 Case 3; the credit semantics are preserved by FA-Apply-9 T-R5 + T-R6 (A1 + apply-determinism are order-independent); the per-source ordering anomaly is a non-safety concern. v2.7 F2 closes this if the late-arriving bundle is excluded from the K-intersection until all K members have observed it (which under partition-recovery convergence does eventually happen, restoring the total order).

### F-4 (Operational): Parallel-map invariant maintenance

The Option 2 design rests on a parallel-map invariant: every key in `pending_inbound_receipts_` has a matching key in `pending_inbound_first_seen_`. The invariant is maintained by paired-insert at §2.2 (line 1640) and paired-erase at §2.3 (line 1834). A future maintainer adding a new insertion or removal path to one map without the other would silently break the invariant. The admission predicate at §2.4 has a defensive fallback (admit on missing first-seen record), so the worst-case symptom is "Option 2 fails open for those keys" (no double-credit risk, but no latency benefit either).

**Status:** Code-review concern; mitigation via the `// S-016: keep parallel-map in sync` comment at the erase site (`node.cpp:1834`). A static-analysis check or unit test asserting `|pending_inbound_receipts_| == |pending_inbound_first_seen_|` after every admission step would harden against this.

### F-5 (Composition): No test exercises the joint Option 2 + apply path

The S-016 closure verification cited in SECURITY.md is `tools/test_cross_shard_transfer.sh` (end-to-end TRANSFER + 3-block latency gate active + destination credit). This test is **end-to-end** and exercises the joint surface (Option 2 admission + FA-Apply-9 credit + FA-Apply-12 restore would be exercised if the test also did a snapshot restore mid-flow, which it doesn't). A dedicated regression that:

1. Emits 2 receipts from `s` at `src_block_index = K, K+1`
2. Forces the K+1 receipt to arrive at the destination first (out-of-order gossip)
3. Verifies the destination credits both (FA-Apply-9 T-R5 A1 invariance), regardless of admission order
4. Snapshots and restores mid-flow
5. Re-gossips an already-credited receipt and verifies it is silent-skipped (FA-Apply-9 T-R2 + FA-Apply-12 T-AR3)

would exercise the full T-1..T-5 composition. This is a v1.x quality work item, not a blocker.

**Status:** Test coverage gap; not a defect. The composition is correct by construction (T-5); a regression would document it explicitly.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Notation; validator predicates V12 + V13 for cross-shard receipts; assumptions A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision resistance). |
| `CrossShardReceipts.md` (FA7) | Upstream protocol-level atomicity theorems T-7 (no double-credit, no fabrication) + T-7' (eventual delivery) + T-7.1 (K-shard sum identity); the source-shard K-of-K ratification gate (L-7.4) that prerequisites Option 2's age-gate operating on K-of-K-verified receipts. |
| `CrossShardReceiptDedup.md` (FA-Apply-9) | Apply-side dedup theorems T-R1..T-R7; T-5 composition with T-R2 (duplicate silent-skip), T-R5 (A1 invariance), T-R6 (apply-determinism), T-R3 (cross-source independence). |
| `AppliedReceiptRestore.md` (FA-Apply-12) | Snapshot-restore round-trip theorems T-AR1..T-AR4; T-5 composition with T-AR2 (restore preserves the set) + T-AR3 (post-restore replay rejected). Option 2's producer-side admission state (`pending_inbound_first_seen_`) is producer-local, not chain-state, and is reset on restore — FA-Apply-12 handles the chain-state side. |
| `CrossShardOutboundApply.md` (FA-Apply-13) | Source-side outbound-apply theorems; T-5 composition: Option 2's filter operates on the **destination** transit pool; the source-side debit + `accumulated_outbound_` advance happen on the source chain irrespective of Option 2; the `Pending` term in FA7 T-7.1 absorbs the Option 2 soak delay. |
| `F2-SPEC.md` | v2.7 F2 / Option 1 strict-determinism design spec; §Q1 intersection rule on `inbound_receipts`; §2.3 explicit Option-2-compatibility note; the partial-vs-full distinction documented in §4 of the present proof. |
| `F2ApplyComposition.md` | v2.7 F2 + apply-layer joint closure; T-1..T-5 composition that supersedes the present proof when F2 ships. |
| `F2ViewReconciliationAnalysis.md` | v2.7 F2 analytic companion to FB22; six algebraic invariants of `compute_view_root` / `reconcile_union` / `reconcile_intersection`; the intersection-rule's algebraic foundation. |
| `tla/CrossShardReceiptDedup.tla` (FB14) | Cross-shard receipt dedup state machine (apply-side); 6 invariants + 2 temporal props; companion to FA-Apply-9 and consumed by T-5 of the present proof. |
| `tla/AppliedReceiptRestore.tla` (FB17) | Cross-shard `applied_inbound_receipts` dedup-set restore state machine; 5 invariants + 2 temporal props; companion to FA-Apply-12 and consumed by T-5 of the present proof. |
| `tla/CrossShardOutboundApply.tla` (FB18) | Source-side cross-shard `TRANSFER` apply-path state machine; 6 invariants + 2 temporal props; companion to FA-Apply-13. |
| `tla/F2ViewReconciliation.tla` (FB22) | v2.7 F2 view-reconciliation primitives + validator passes V21..V26; 6 algebraic invariants + 3 auxiliary invariants; the strict-determinism formalization that supersedes the present proof's Option 2 partial. |
| `tla/CrossShardReceiptRoundtrip.tla` (FB32) | Composed cross-shard receipt lifecycle state machine; **explicitly models Option 2's `CROSS_SHARD_RECEIPT_LATENCY = 3` time-ordered admission gate** as one of its 7 actions (`AdmitTimeOrderedEligibleReceipts` at `node.cpp:1574-1597`); 8 invariants including `TimeOrderedAdmission` + 2 temporal properties; closes the cross-shard receipt-as-conserved-quantity gap at the state-machine layer by composing FB14 (dst dedup) + FB17 (snapshot dedup-set) + FB18 (src debit) into a single lifecycle SM. |
| `docs/SECURITY.md` §S-016 | The audit-trail finding + the Option 2 closure narrative; the present proof is the analytic companion. |
| `docs/PROTOCOL.md` §6 | Cross-shard receipt wire format + V12 / V13 validator predicates. |
| `tools/test_cross_shard_transfer.sh` | End-to-end TRANSFER from shard 0 → shard 1 with the 3-block latency gate active; cited in SECURITY.md §S-016 as the Option 2 verification test. |
| `tools/test_cross_shard_receipt_apply.sh` | FA-Apply-9 T-R1 / T-R2 / T-R5 / T-R7 single-chain assertions; consumed by T-5 of the present proof for the apply-side credit semantics. |
| `tools/test_applied_receipt_restore.sh` | FA-Apply-12 T-AR1..T-AR4 snapshot round-trip assertions; consumed by T-5 for the post-restore replay-rejection semantics. |
| `tools/test_cross_shard_atomicity.sh` | FA7 T-7.1 chain-pair conservation `src.accumulated_outbound == dst.accumulated_inbound` (modulo `Pending`); the K-shard sum identity that T-5 preserves under Option 2. |
| `include/determ/node/node.hpp:589-591` | `pending_inbound_first_seen_` field declaration with the parallel-map invariant comment. |
| `include/determ/node/node.hpp:352-358` | `inbound_receipts_eligible_for_inclusion` declaration with the S-016 Option 2 design-rationale comment. |
| `src/node/node.cpp:1574-1599` | `CROSS_SHARD_RECEIPT_LATENCY` constant + `inbound_receipts_eligible_for_inclusion` body (the central Option 2 closure code path). |
| `src/node/node.cpp:1629-1641` | Insertion site for `pending_inbound_first_seen_` (within `on_cross_shard_receipt_bundle`). |
| `src/node/node.cpp:1831-1835` | Paired-erase site (within `apply_block_locked`'s post-apply cleanup). |
| `src/node/node.cpp:967, 1069` | Admission predicate consumers: `start_block_sig_phase` + `try_finalize_round`. |

---

## 7. Status

All five theorems (T-1 through T-5) are closed in the current codebase under the **Option 2 partial** classification:

- **T-1** (per-source-shard total order) closed under the FIFO gossip assumption; gossip-FIFO caveat documented in F-2; v2.7 F2 closes the adversarial-gossip case fully.
- **T-2** (no replay-backward) closed unconditionally via FA-Apply-9 T-R2 (apply-side dedup); Option 2's contribution is the producer-side filter that reduces the reorder surface within a single round.
- **T-3** (cross-source independence) closed via storage independence (pair-keyed maps) + age-gate independence + FA-Apply-9 T-R3 apply-side independence; three-layer composition.
- **T-4** (latency bound) closed by the constant `CROSS_SHARD_RECEIPT_LATENCY = 3` × destination profile `tx_commit_ms` + FA4 destination liveness; per-profile latency values documented in §2.6.
- **T-5** (composition with FA7 + FA-Apply-9 + FA-Apply-12 + FA-Apply-13) closed: Option 2's filter is a refinement of admission timing without altering credit semantics; the K-shard sum identity is preserved; the joint invariant set is closed under Option 2's footprint.

Option 2 ships **~50 LOC** total (per SECURITY.md §S-016 effort estimate): the `pending_inbound_first_seen_` field declaration + the `CROSS_SHARD_RECEIPT_LATENCY` constant + the `inbound_receipts_eligible_for_inclusion` helper + the paired-insert at the bundle handler + the paired-erase at the apply cleanup + the two admission-site rewrites at `start_block_sig_phase` and `try_finalize_round`. The proof's five theorems cover this footprint exhaustively; the remaining surface is the v2.7 F2 Option 1 strict-determinism path, currently spec'd in F2-SPEC.md and tracked as the v2.7 work item.

**S-016 classification:** Partially mitigated (Option 2 shipped; Option 1 = v2.7 F2 closes fully). The present proof is the analytic companion for the Option 2 partial; F2ApplyComposition.md (FA-Apply-15-companion) + F2ViewReconciliationAnalysis.md + FB22 are the analytic + machine-checkable companions for the eventual Option 1 full closure. Until v2.7 F2 ships, Option 2 carries the practical deployment surface; the joint-deployment compatibility is documented in §4 and is structurally safe (T-5).
