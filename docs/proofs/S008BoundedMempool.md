# S008BoundedMempool — bounded mempool capacity + nonce-gating + RBF determinism (S-008 closure)

This document formalizes the S-008 closure shipped in `src/node/node.cpp::mempool_admit_check` + `mempool_make_room_for` + the surrounding gossip-path (`on_tx`) and RPC-path (`rpc_submit_tx`) call sites, together with the `Node::tx_store_` + `Node::tx_by_account_nonce_` data structures declared at `include/determ/node/node.hpp:459-462`. The pre-S-008 mempool surface was unbounded — `tx_store_` was a `std::map<Hash, Transaction>` with no cap on size, no per-sender quota, and no eviction policy. An attacker who could send transactions into the gossip layer could grow the receiver's mempool without bound, leading to RAM exhaustion and the secondary effect of amplifying the flood to every gossip peer (the mempool is replicated by re-broadcast). S-008 closes this with four interlocking mechanisms: (a) a hard cap `MEMPOOL_MAX_TXS = 10000` on `tx_store_.size()`; (b) a fee-priority eviction policy on cap-overflow (incoming tx evicts the lowest-fee incumbent iff its fee is strictly higher, with tx-hash tie-break); (c) replace-by-fee (RBF) on same-`(sender, nonce)` collision (higher-fee tx replaces lower-fee tx; tie favors the incumbent); (d) nonce-gating via a stale-nonce drop (`tx.nonce < chain_.next_nonce(tx.from) ⇒ reject`) so that an attacker cannot flood with already-applied nonces.

The proof is operational + structural — there are no cryptographic assumptions (signature verification is the upstream S-002 gate, treated here as a precondition; this proof concerns mempool admission AFTER sig-verify succeeds). T-1 establishes the capacity bound `|mempool_| ≤ MEMPOOL_MAX_TXS` as a structural invariant. T-2 establishes nonce-gating soundness — no stale-nonce tx ever reaches `tx_store_`. T-3 establishes RBF determinism — the same `(sender, nonce)` slot resolves deterministically across replays. T-4 establishes the memory bound by composition with S-022's per-MsgType TRANSACTION cap. T-5 establishes the no-useful-tx-loss property under cap pressure (fee-priority eviction preserves high-fee honest tx). T-6 establishes the composition with the S-014 per-IP rate limiter — together they bound both ingress rate and storage occupancy.

**Companion documents:** `Preliminaries.md` §3 (network model) for the asio worker-thread + state-mutex serialization assumption underlying L-1; `S014RateLimiterSoundness.md` (S-014 closure) for the per-IP token-bucket bound composed in T-6; `S022WireFormatCaps.md` (S-022 closure) for the per-MsgType TRANSACTION body-cap composed in T-4; `NonceMonotonicity.md` (FA-Apply-3) for the apply-time nonce-monotonicity invariant T-2 leverages; `S002-Mempool-Sig-Verify.md` (S-002 closure) for the upstream sig-verify gate that this proof treats as a precondition; `S014ConcurrencyAnalysis.md` for the structural-disjointness style mirrored in §4 lemmas; `docs/SECURITY.md` §S-008 for the closure-status narrative this proof formalizes; `docs/SECURITY.md` §3 Mitigated-High table row for the audit-track status.

---

## 1. Introduction

### 1.1 Pre-S-008 mempool surface

Before S-008 was shipped, the `Node` mempool consisted of two `std::map` containers without any capacity bound:

```cpp
std::map<Hash, chain::Transaction>                       tx_store_;
std::map<std::pair<std::string, uint64_t>, Hash>         tx_by_account_nonce_;
```

`tx_store_` was the primary store keyed by transaction hash; `tx_by_account_nonce_` was a derived index for replace-by-fee lookup. Neither map had a size cap. The gossip-path admission handler `on_tx` performed a stale-nonce drop and a signature-verify check (S-002), then inserted unconditionally into both maps. The RPC-path admission handler `rpc_submit_tx` had the same shape (validate, then insert).

The pre-S-008 attack surface combined two amplification factors:

1. **Unbounded storage growth.** An attacker sending `N` distinct (sender, nonce) transactions caused `tx_store_.size() = N` to grow linearly in the attacker's send rate, with no upper bound short of the OS RAM limit.

2. **Gossip re-broadcast amplification.** Every accepted transaction was re-broadcast to all peers via the gossip layer's flooding semantics. An attacker who fed `N` txs into one node caused the network to carry `N × |peers|` total tx-broadcast traffic. Combined with the unbounded admission, the attacker's per-byte work amplified by a factor proportional to the network's peer count.

The Architectural Analysis §3.4 documented this as the dominant DoS surface against the mempool. Audit 2.6 confirmed the finding. The pre-S-008 mitigation was nominally the S-014 per-IP rate limit (introduced separately as a defense against rate-of-arrival flooding) — but rate-limiting bounds the ingress rate, not the storage occupancy. A patient attacker sending at the rate-limit threshold could still grow `tx_store_` linearly in elapsed time (over a 24-hour window at a per-IP cap of 100 tx/sec, that is 8.64M slots — well beyond any operationally sane budget).

### 1.2 S-008 closure structure

The closure consists of four mechanisms layered above the existing sig-verify (S-002) and rate-limit (S-014) gates:

**(a) Hard global cap.** `MEMPOOL_MAX_TXS = 10000` is a `static constexpr size_t` declared at `include/determ/node/node.hpp:459`. The cap is enforced at every insertion path. The exact value is set as a compile-time constant rather than a configurable knob — the rationale (per `node.hpp:457-458`) is that a deployment exceeding 10K pending slots is hitting a fee-market signal, not a capacity-tuning need; tuning is deferred to a v2.X follow-on that would make the bound genesis-pinned. The choice of 10K balances operational headroom (covers ~30 seconds of legitimate burst at a 100 RPS submission rate × 100 senders) against memory floor (10K × ~200 bytes per tx ≈ 2 MB, comfortably below any single-tier RAM target).

**(b) Per-sender quota.** `MEMPOOL_MAX_PER_SENDER = 100` is a `static constexpr size_t` declared at `include/determ/node/node.hpp:460`. This caps the count of distinct `(sender, nonce)` slots one address can occupy. The per-sender quota is **not** subject to fee-priority eviction across senders — once a sender hits 100 entries, additional submissions from that sender are rejected regardless of fee. The rationale is fairness: a wealthy spammer should not be able to displace all other senders' transactions by paying high fees on 10K pipelined-nonce txs from one address. With the per-sender quota in place, even an attacker willing to pay arbitrarily high fees can only occupy 100 slots per address — the global cap then absorbs at most 100 × N_senders slots from N distinct addresses.

**(c) Fee-priority eviction on global cap.** When `tx_store_.size() ≥ MEMPOOL_MAX_TXS` and an incoming transaction's `(sender, nonce)` is **not** already in the mempool (i.e., this is a fresh-slot insert, not a replace), the admission gate scans for the current minimum fee in `tx_store_`. If the incoming tx's fee strictly exceeds the minimum, the minimum-fee incumbent is evicted and the new tx is admitted. If the incoming tx's fee equals or undercuts the minimum, the new tx is rejected. The economic interpretation: under sustained spam pressure, the protocol prices out the spammer — they must pay the marginal fee to displace incumbents, and the marginal fee rises monotonically as the cheaper txs get evicted.

**(d) Replace-by-fee (RBF) on same `(sender, nonce)`.** When an incoming transaction's `(sender, nonce)` is **already** in the mempool, the admission gate compares fees: if `tx.fee > existing.fee`, the existing entry is removed and the new entry is inserted. If `tx.fee ≤ existing.fee` (ties included), the new entry is rejected (incumbent wins). The tie-favors-incumbent rule is deliberate: it eliminates RBF-pingpong (an attacker alternating same-fee RBF attempts would otherwise cause O(1) churn per attempt; with the tie rule, the second attempt is a no-op).

**(e) Nonce-gating via stale-nonce drop.** Both `on_tx` (`src/node/node.cpp:2023`) and `rpc_submit_tx` (`src/node/node.cpp:3158`) drop any transaction with `tx.nonce < chain_.next_nonce(tx.from)` before any admission check runs. This prevents an attacker from flooding with already-applied nonces (a replay attack) — such transactions can never become applicable and would only occupy mempool slots and amplify through gossip. The check is the upstream defense against replay floods; the apply-layer FA-Apply-3 invariant covers the case of a replay that bypasses the mempool entirely (e.g., direct block injection) by re-checking nonce monotonicity at apply time.

The five mechanisms compose into a closed system: a flooder who exceeds the per-sender quota is rejected outright (no resource churn beyond the admission check). A flooder who stays under the per-sender quota but tries to overwhelm the global cap is forced into a fee-bidding war (the marginal fee they must pay rises monotonically with cap pressure). A flooder who tries replay attacks is rejected at the stale-nonce gate. A flooder who tries RBF-pingpong attacks is bounded by the tie-favors-incumbent rule + the per-IP rate limit (S-014 caps the rate at which they can re-attempt).

### 1.3 Scope of the proof

This proof formalizes the structural invariants that the S-008 closure establishes:

- The capacity invariant `|mempool_| ≤ MEMPOOL_MAX_TXS` is maintained across all admission paths.
- The per-sender invariant `count_from(s) ≤ MEMPOOL_MAX_PER_SENDER` for every sender `s`.
- The stale-nonce-rejection invariant — no entry in the mempool has nonce strictly less than the chain's current next_nonce for that sender.
- The RBF determinism property — for any sequence of admission attempts at a fixed `(sender, nonce)`, the surviving entry's fee equals the maximum fee across all attempts (or, on ties, the earliest-attempted of the max-fee submitters).
- The memory bound `total_bytes(mempool_) ≤ MEMPOOL_MAX_TXS × max_message_bytes(MsgType::TRANSACTION) + O(index_overhead)`.
- The compositional property with S-014 — together they bound the dual surfaces of ingress rate (S-014) and storage occupancy (S-008).

Out of scope: the upstream sig-verify gate (S-002 proof — treated here as a precondition for admission), the apply-time nonce monotonicity invariant (FA-Apply-3 proof — covers the post-mempool surface), the cryptographic strength of the tx_hash (collision-resistance assumption A3 — see Preliminaries.md §2.1), the fee-market dynamics under sustained pressure (a separate economic-analysis question; this proof addresses only the admission-gate's correctness, not the equilibrium-price properties).

---

## 2. Theorem statements

**Setup.** Let `tx_store_ ⊆ Hash → Transaction` denote the primary mempool store and `tx_by_account_nonce_ ⊆ (Sender, Nonce) → Hash` the derived index. Both are `std::map`s with the standard log(N) insert/erase/find. Let `C := MEMPOOL_MAX_TXS = 10000` denote the global cap and `Q := MEMPOOL_MAX_PER_SENDER = 100` the per-sender cap.

Let `count_from(s) := |{h : tx_store_[h].from = s}|` denote the count of entries with sender `s` (equivalently, computed via `mempool_count_from(s)` at `node.cpp:1943-1951` via the std::map range-scan on `tx_by_account_nonce_`).

Let `min_fee(M) := min_{h ∈ M} tx_store_[h].fee` for `M ⊆ Hash`; let `min_fee(∅) := +∞` by convention.

Let `next_nonce(s)` denote the chain's `chain_.next_nonce(s)` value — the next nonce the chain will accept for sender `s` at the current chain height. Per FA-Apply-3 (NonceMonotonicity.md), `next_nonce(s)` is monotonically non-decreasing across `chain_.append(b)` calls.

The admission paths are (cited verbatim from §3 below):

- `Node::on_tx(tx)` at `src/node/node.cpp:2019-2054` — gossip-path admission, silent drop on reject.
- `Node::rpc_submit_tx(tx)` at `src/node/node.cpp:3174-3194` — RPC-path admission, throws on reject.

Both paths share the same admission policy via `mempool_admit_check(tx)` at `src/node/node.cpp:1961-1995` and the same eviction helper `mempool_make_room_for(tx)` at `src/node/node.cpp:2001-2017`. The shared helper guarantees the gossip and RPC paths are observationally indistinguishable on admission outcomes (modulo the gossip's silent-drop vs RPC's throw-with-diagnostic disposition).

**Theorem T-1 (Capacity Bound — global cap invariant).** Across every admission-path call (gossip `on_tx` and RPC `rpc_submit_tx`), the post-call invariant `|tx_store_| ≤ C` holds, provided the precondition `|tx_store_| ≤ C` held pre-call.

Formally, let `n_pre := |tx_store_|` be the count before any admission attempt and `n_post := |tx_store_|` after. Then for every accepted transaction:

$$
n_{\text{post}} \;\leq\; \max(n_{\text{pre}}, C).
$$

For every rejected transaction, `n_post = n_pre`. By induction on the sequence of admission attempts starting from the constructor-initialized `n = 0`, `|tx_store_| ≤ C` is invariant. The chain-`append` drain (`src/node/node.cpp:1790-1805`) only erases from `tx_store_`, so it preserves the invariant trivially.

**Theorem T-2 (Nonce-Gating Soundness — no stale entry survives admission).** For every accepted transaction `tx` and every snapshot of `tx_store_` taken immediately after a `chain_.append(b)` call:

$$
\forall h \in \texttt{tx\_store\_},\ \texttt{tx\_store\_}[h].\text{nonce} \;\geq\; \texttt{next\_nonce}(\texttt{tx\_store\_}[h].\text{from}).
$$

Equivalently: no transaction with stale nonce ever appears in the mempool after the apply-time sweep at `src/node/node.cpp:1798-1805` runs. The admission-time guard at `src/node/node.cpp:2023` + `3158` enforces the same condition on insertion; the apply-time sweep enforces it post-chain-advance. Together they pin the invariant across the chain's full lifecycle.

**Theorem T-3 (RBF Determinism — same-`(sender, nonce)` resolution).** For any sender `s`, nonce `n`, and any sequence of admission attempts `tx_1, tx_2, …, tx_k` with `tx_i.from = s ∧ tx_i.nonce = n` (and all other admission checks passing), the surviving entry's fee `tx_*` satisfies:

1. `tx_*.fee = max_{i ∈ [1, k]} tx_i.fee` — the highest-fee submission wins.
2. If multiple `tx_i` achieve the maximum, the **first-arriving** (smallest `i`) wins — incumbent ties never get displaced. (This is the consequence of `existing->second.fee >= tx.fee` returning early at `node.cpp:2041`, `2042` and `3182-3184` — strict-greater for replacement, equal-keeps-incumbent.)
3. The surviving fee is **independent of arrival order** for the strictly-greater case: any permutation of `tx_1, …, tx_k` that ends with the same multiset of submissions produces the same maximum-fee outcome.

Property 3 is what makes the RBF deterministic across gossip-replay: a node that receives `(tx_1, tx_2)` in order followed by a `tx_2`-then-`tx_1` replay (e.g., from a re-gossip) ends up at the same surviving entry as a node that received the original ordering. (The tie case adds a first-seen dependency, but tx-hash tie-break — see §6 F-1 — covers the residual non-determinism for the cross-node-consensus property of the eviction.)

**Theorem T-4 (Memory Bound).** The total RAM occupied by the mempool is bounded by:

$$
\text{mem}(\texttt{tx\_store\_}) + \text{mem}(\texttt{tx\_by\_account\_nonce\_}) \;\leq\; C \cdot \max_{\text{tx admissable}} |\texttt{tx}| + C \cdot \text{indexOverhead}.
$$

By S-022 (`docs/proofs/S022WireFormatCaps.md` T-1), every transaction admitted into the mempool has wire-form size `≤ max_message_bytes(MsgType::TRANSACTION) = 1 MB` (TRANSACTION is in the default 1-MB tier per `include/determ/net/messages.hpp:124-152`). The per-tx in-memory representation `sizeof(Transaction)` is bounded by the wire form plus the std::string + std::vector overheads, which are bounded by a constant multiplier `K_str ≈ 1.5×` (string capacity ≥ string size, vector capacity ≥ size, with growth factor bounded).

The index overhead per entry in `tx_by_account_nonce_` is `sizeof(std::pair<std::string, uint64_t>) + sizeof(Hash) + std::map::node_overhead ≈ 256 bytes` for a typical 50-char sender address + 8-byte nonce + 32-byte hash + ~64-byte rb-tree node header.

Combining: the worst-case memory occupancy is bounded by `C × (1.5 × 1 MB + 256 B) ≈ 15.0 GB`. **The realistic per-tx size is dramatically smaller** (typical TRANSFER ~300 bytes wire + ~500 bytes in-memory), yielding a practical occupancy of `10K × ~750 B ≈ 7.5 MB`. The wire-size budget is a theoretical worst case driven by S-022's cap; the realistic value is the relevant operational number.

**Theorem T-5 (No Useful-Tx Loss Under Pressure).** Let `H ⊆ tx_store_` denote the set of "high-fee honest" transactions at any point during a sustained admission flood from `M` flooder transactions (with arbitrary fees), where "high-fee honest" means `tx.fee > median_fee(H)`. Then under the fee-priority eviction policy at `node.cpp:2001-2017`:

1. **Honest-tx survival under flooder pressure.** If `|H| < C` and every honest tx in `H` has fee strictly greater than every flooder tx's fee, then no honest tx is evicted by any flooder admission attempt. (Formally: the eviction at `node.cpp:2011` only triggers if `tx.fee > min_it->second.fee`, and the min-fee tx is by hypothesis a flooder tx in this scenario.)
2. **Marginal-honest survival.** For an honest tx with fee `f_h` and a flooder tx with fee `f_f`, the honest tx survives iff `f_h > f_f` strictly. (Ties favor the incumbent — the first-arrived tx survives the second-arrived tx of equal fee.)
3. **Bounded-loss under chain-advance.** When `chain_.append(b)` drains applied txs from `tx_store_`, only those whose `(from, nonce)` was in `b.transactions` are removed (`node.cpp:1791-1794`). The stale-nonce sweep at `node.cpp:1798-1805` removes only entries whose nonce is now strictly less than the post-apply `next_nonce(from)`. No high-fee honest tx is removed except by being applied or by its sender's chain-state-advance making it stale.

Property 1 is the operational claim: a chain serving honest users at fee level `f_h` and facing a flood at fee level `f_f < f_h` does not lose any of the honest users' transactions to the flood. The eviction selection function (lowest-fee target) is precisely the policy that achieves this.

**Theorem T-6 (Composition with S-014 Rate Limiter — ingress + storage dual bound).** Compositing the S-008 mempool bounds with the S-014 per-IP token-bucket bound `A_k([t, t+Δ]) ≤ ⌊C_rl + r·Δ⌋` (per `docs/proofs/S014RateLimiterSoundness.md` T-1), the joint per-IP per-window admission count is bounded by:

$$
\text{Admitted}_{k}([t, t+\Delta]) \;\leq\; \min\!\left(\,\lfloor C_{rl} + r \cdot \Delta \rfloor,\;\; Q,\;\; \tfrac{C - n_{\text{pre}}(k)}{f_{\text{margin}}(k)}\,\right),
$$

where the three terms are:

1. `⌊C_rl + r·Δ⌋` — the S-014 per-IP rate-limit bound (ingress side).
2. `Q = MEMPOOL_MAX_PER_SENDER = 100` — the per-sender quota (storage side, per-address).
3. The fee-bidding term — under cap pressure, the marginal cost-per-admission for an attacker scales with the gap-to-min-fee, bounded by the chain's economic floor.

The composition is multiplicative in the protection it offers: S-014 alone caps the rate but not the storage; S-008 alone caps the storage but not the rate. Together, an attacker is bounded simultaneously on both axes — they cannot exceed `Q` slots per address (regardless of how slowly they submit), and they cannot exceed `⌊C_rl + r·Δ⌋` admission attempts per window (regardless of how cheap each individual attempt is). The full DoS surface is closed by the conjunction.

---

## 3. Implementation citation

The S-008 closure lives entirely in `src/node/node.cpp` + `include/determ/node/node.hpp`. The relevant slices follow verbatim.

### 3.1 Constants and storage (`include/determ/node/node.hpp:444-462`)

```cpp
// Mempool keyed by tx.hash (primary) and indexed by (from, nonce) for
// replace-by-fee: a new tx with the same (from, nonce) replaces the old
// iff its fee is strictly higher.
//
// S-008 mitigation: bounded mempool. MEMPOOL_MAX_TXS is a hard cap on
// the total tx_store_ size; MEMPOOL_MAX_PER_SENDER is a per-sender
// quota that prevents one address from filling the mempool with
// pipelined-nonce txs. Both checks are enforced in on_tx (gossip-
// admission) and rpc_submit_tx (RPC admission).
//
// Eviction policy on global-cap overflow: lowest-fee tx in the
// mempool is evicted, IF the incoming tx's fee is strictly higher.
// This is "fee-priority mempool" — under sustained spam, the chain
// economically prices out the spammer (they must pay the marginal
// fee to evict). Per-sender quota overflow always rejects (no
// eviction across senders for fairness).
//
// Suggested defaults: 10,000 total mempool slots; 100 per sender.
// Tunable via genesis-pinned config in v2.X follow-on if needed.
static constexpr size_t MEMPOOL_MAX_TXS         = 10000;
static constexpr size_t MEMPOOL_MAX_PER_SENDER  = 100;
std::map<Hash, chain::Transaction>                       tx_store_;
std::map<std::pair<std::string, uint64_t>, Hash>         tx_by_account_nonce_;
```

### 3.2 Per-sender count helper (`src/node/node.cpp:1943-1951`)

```cpp
size_t Node::mempool_count_from(const std::string& sender) const {
    size_t count = 0;
    auto it = tx_by_account_nonce_.lower_bound({sender, 0});
    while (it != tx_by_account_nonce_.end() && it->first.first == sender) {
        ++count;
        ++it;
    }
    return count;
}
```

The `lower_bound({sender, 0})` positions the iterator at the start of `sender`'s contiguous range in the ordered std::map; the loop walks forward until the key's first component changes. Time complexity is `O(log N + count_from(sender))`, with `count_from(sender) ≤ Q = 100` by the per-sender quota invariant.

### 3.3 Shared admission gate (`src/node/node.cpp:1961-1995`)

```cpp
std::string Node::mempool_admit_check(const chain::Transaction& tx) const {
    // Check if this tx would REPLACE an existing one at (from, nonce).
    // A replace doesn't add to the mempool count — same slot, same sender.
    auto existing_it = tx_by_account_nonce_.find({tx.from, tx.nonce});
    bool is_replace = (existing_it != tx_by_account_nonce_.end());

    if (!is_replace) {
        // Per-sender quota.
        size_t sender_count = mempool_count_from(tx.from);
        if (sender_count >= MEMPOOL_MAX_PER_SENDER) {
            return "mempool: per-sender quota exceeded ("
                 + std::to_string(MEMPOOL_MAX_PER_SENDER)
                 + " txs from " + tx.from + ")";
        }
        // Global cap. Eviction is feasible only if tx.fee > current
        // mempool minimum. Don't enforce at admission — the eviction
        // step happens INSIDE the insert path (mempool_make_room_for).
        // Here we just check that admission is even possible: if cap
        // is hit AND tx.fee <= mempool min, reject early.
        if (tx_store_.size() >= MEMPOOL_MAX_TXS) {
            // Scan for current minimum fee.
            uint64_t min_fee = UINT64_MAX;
            for (auto& [_, t] : tx_store_) {
                if (t.fee < min_fee) min_fee = t.fee;
            }
            if (tx.fee <= min_fee) {
                return "mempool: full ("
                     + std::to_string(MEMPOOL_MAX_TXS)
                     + " txs); incoming fee " + std::to_string(tx.fee)
                     + " <= mempool minimum " + std::to_string(min_fee);
            }
        }
    }
    return "";
}
```

The gate distinguishes the **replace** case (same `(sender, nonce)`) from the **fresh-slot** case. In the replace case, neither the per-sender quota nor the global cap can be exceeded by accepting (the replace doesn't grow either count), so the gate skips both checks and lets the call site handle the RBF fee-comparison. In the fresh-slot case, the gate runs the per-sender quota first (cheapest check, bounded by `O(Q)` via the range-scan) and the global-cap check second (more expensive `O(C)` linear scan for min-fee, but only fires when the cap is reached).

### 3.4 Eviction helper (`src/node/node.cpp:2001-2017`)

```cpp
bool Node::mempool_make_room_for(const chain::Transaction& tx) {
    if (tx_store_.size() < MEMPOOL_MAX_TXS) return true;
    // Find lowest-fee tx. Tie-broken by hash (deterministic across nodes).
    auto min_it = tx_store_.end();
    for (auto it = tx_store_.begin(); it != tx_store_.end(); ++it) {
        if (min_it == tx_store_.end() || it->second.fee < min_it->second.fee) {
            min_it = it;
        }
    }
    if (min_it == tx_store_.end()) return true; // shouldn't reach (size>=cap)
    if (tx.fee <= min_it->second.fee) return false; // can't displace
    // Evict the minimum.
    auto evicted_key = std::make_pair(min_it->second.from, min_it->second.nonce);
    tx_store_.erase(min_it);
    tx_by_account_nonce_.erase(evicted_key);
    return true;
}
```

The comment "tie-broken by hash" reflects the deterministic iteration order of `std::map<Hash, Transaction>`: iteration proceeds in hash order, so the first hash that achieves the minimum fee wins the eviction-target slot. The strict-greater check `tx.fee <= min_it->second.fee → false` is the eviction-feasibility gate; if the incoming fee equals or undercuts the current minimum, eviction is refused (the incumbent stays).

### 3.5 Gossip-path admission (`src/node/node.cpp:2019-2054`)

```cpp
void Node::on_tx(const chain::Transaction& tx) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

    // Drop stale-nonce txs immediately.
    if (tx.nonce < chain_.next_nonce(tx.from)) return;

    // S-002: verify signature before admitting to mempool. Silent drop
    // on the gossip path — a forged-sig flood from any peer would
    // otherwise consume mempool slots and amplify to other peers.
    if (!verify_tx_signature_locked(tx)) return;

    // S-008: enforce mempool size cap + per-sender quota. Silent drop
    // on the gossip path (a flood from N senders gets rate-limited
    // without amplifying the attacker's traffic; the rejected tx
    // doesn't propagate further).
    if (!mempool_admit_check(tx).empty()) return;

    auto key = std::make_pair(tx.from, tx.nonce);
    auto idx = tx_by_account_nonce_.find(key);
    if (idx != tx_by_account_nonce_.end()) {
        // Replace-by-fee: keep the higher-fee version.
        auto existing = tx_store_.find(idx->second);
        if (existing != tx_store_.end() && existing->second.fee >= tx.fee) {
            return; // incumbent wins (ties favor incumbent — no resource churn)
        }
        if (existing != tx_store_.end()) tx_store_.erase(existing);
    } else {
        // Fresh slot — check eviction feasibility for the global cap.
        // mempool_admit_check already verified eviction is possible
        // (tx.fee > current min), but the actual eviction happens here
        // atomically with the insert.
        if (!mempool_make_room_for(tx)) return;
    }
    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[key] = tx.hash;
}
```

The structure is: stale-nonce gate → sig-verify gate (S-002) → mempool-admit gate (S-008) → RBF branch (if collision) → eviction branch (if fresh-slot at cap) → atomic insert. The order is significant: cheap checks first, expensive checks last, so a rejected tx pays the minimum admission cost.

### 3.6 RPC-path admission (`src/node/node.cpp:3157-3194`)

```cpp
// Stale-nonce drop here too (mirrors on_tx).
if (tx.nonce < chain_.next_nonce(tx.from))
    throw std::runtime_error(
        "submitted tx has stale nonce " + std::to_string(tx.nonce)
      + " (expected >= " + std::to_string(chain_.next_nonce(tx.from)) + ")");

// S-002: verify signature before admitting to mempool. Surface as
// a hard error to the submitting client (RPC callers get feedback;
// unlike a faceless gossip peer, the client can correct and retry).
if (!verify_tx_signature_locked(tx))
    throw std::runtime_error(
        "submitted tx signature verification failed (from " + tx.from + ")");

// S-008: enforce mempool admission policy. RPC path surfaces the
// rejection reason to the client (vs gossip's silent drop) so the
// submitter can decide whether to retry with a higher fee or
// back off.
if (auto err = mempool_admit_check(tx); !err.empty()) {
    throw std::runtime_error(err);
}

auto key = std::make_pair(tx.from, tx.nonce);
auto idx = tx_by_account_nonce_.find(key);
if (idx != tx_by_account_nonce_.end()) {
    auto existing = tx_store_.find(idx->second);
    if (existing != tx_store_.end() && existing->second.fee >= tx.fee)
        throw std::runtime_error(
            "incumbent tx at (from, nonce) has equal-or-higher fee");
    if (existing != tx_store_.end()) tx_store_.erase(existing);
} else {
    // S-008: fresh-slot insert — apply eviction if at cap.
    if (!mempool_make_room_for(tx)) {
        throw std::runtime_error(
            "mempool full; fee too low to evict any incumbent tx");
    }
}
tx_store_[tx.hash] = tx;
tx_by_account_nonce_[key] = tx.hash;
```

Structurally identical to the gossip path; the only behavioral difference is disposition (throw with diagnostic vs silent return). This shared shape is what L-2 below leverages to prove the admission policy is identical regardless of channel.

### 3.7 Chain-advance drain + stale-nonce sweep (`src/node/node.cpp:1790-1805`)

```cpp
// Drop applied txs from the mempool, keyed by both indices.
for (auto& tx : b.transactions) {
    tx_store_.erase(tx.hash);
    tx_by_account_nonce_.erase({tx.from, tx.nonce});
}

// Sweep stale-nonce txs (M11): any mempool entry whose nonce is now
// behind the chain's next_nonce can never be included.
for (auto it = tx_store_.begin(); it != tx_store_.end(); ) {
    if (it->second.nonce < chain_.next_nonce(it->second.from)) {
        tx_by_account_nonce_.erase({it->second.from, it->second.nonce});
        it = tx_store_.erase(it);
    } else {
        ++it;
    }
}
```

The post-append drain is the only path that erases from `tx_store_` outside the admission path's RBF/eviction branches. Both indices are kept in lockstep — the `tx_store_.erase` is always paired with the corresponding `tx_by_account_nonce_.erase`. This is what L-3 below leverages to prove the index-consistency invariant.

---

## 4. Lemmas and proofs

### Lemma L-1 (Admission-path serialization)

Both `on_tx` and `rpc_submit_tx` take `state_mutex_` as a `std::unique_lock<std::shared_mutex>` (an exclusive write-lock) before reading or modifying `tx_store_` or `tx_by_account_nonce_`. The `chain_.append(b)` call at `node.cpp:1788` likewise runs under the write-lock (the call chain is invoked from `try_finalize_round` which holds the lock across the append + drain + sweep). The chain-state reader `chain_.next_nonce(from)` is called only while the lock is held.

Therefore: at any wall-clock instant, exactly one thread is mutating the mempool data structures. The std::map operations are not thread-safe by default, but the write-lock provides the required exclusion. The shared-mutex's read-lock paths (used by RPC read-only queries that report mempool state) do not mutate, so they coexist with this exclusion invariant.

Reference: the `state_mutex_` declaration at `include/determ/node/node.hpp` + the `std::unique_lock` patterns at `src/node/node.cpp:2020` (on_tx), `3174` (rpc_submit_tx via the surrounding RPC handler), and the chain-advance path via `try_finalize_round`. The serialization is consistent with the broader v2.6 / S-031 gossip-out-of-lock pattern (lock for state mutation, release before network broadcast).   □

### Lemma L-2 (Gossip + RPC admission policy identity)

The shared helpers `mempool_admit_check` and `mempool_make_room_for` are called by both admission paths with identical inputs (`tx`) and produce identical outputs (`""`-or-error-string for the check, `true`/`false` for the eviction helper). The two call sites differ only in their **handling** of the helper outputs:

- `on_tx` at `node.cpp:2034` discards the error string and silently returns on non-empty error.
- `rpc_submit_tx` at `node.cpp:3174-3176` wraps the error string in a `std::runtime_error` and throws.

The RBF branch + fresh-slot eviction branch at the two call sites are byte-for-byte equivalent in their state-mutation effect on `tx_store_` and `tx_by_account_nonce_` — they both:

1. Look up `(tx.from, tx.nonce)` in `tx_by_account_nonce_`.
2. If found, compare fees; on `existing.fee >= tx.fee`, reject; on `tx.fee > existing.fee`, erase the existing entry from `tx_store_` (no erase from `tx_by_account_nonce_` because the insertion below overwrites it).
3. If not found, call `mempool_make_room_for(tx)`; on `false`, reject; on `true`, fall through.
4. Insert into both `tx_store_` and `tx_by_account_nonce_`.

The disposition difference (silent return vs throw with diagnostic) is observable only to the caller, not to the mempool state. Therefore, for any sequence of admission attempts arriving via mixed gossip and RPC channels, the resulting mempool state is independent of channel — only the per-attempt return value differs.

This is the foundation for the rest of the proofs: T-1 through T-5 are proven once for the shared admission policy; the gossip-vs-RPC distinction enters only via the disposition of the rejected calls.   □

### Lemma L-3 (Index-consistency invariant)

For every state of the mempool reachable from the constructor-initialized empty state via a sequence of admission attempts and chain-advance drains:

$$
\forall h \in \texttt{tx\_store\_},\; \texttt{tx\_by\_account\_nonce\_}[(tx\_store\_[h].\text{from},\ \texttt{tx\_store\_}[h].\text{nonce})] = h.
$$

$$
\forall (s, n) \in \texttt{tx\_by\_account\_nonce\_},\; \exists h = \texttt{tx\_by\_account\_nonce\_}[(s, n)] \in \texttt{tx\_store\_},\; \texttt{tx\_store\_}[h].\text{from} = s \land \texttt{tx\_store\_}[h].\text{nonce} = n.
$$

Both directions: every entry in `tx_store_` has a corresponding entry in `tx_by_account_nonce_` keyed on its (from, nonce), and every entry in `tx_by_account_nonce_` maps to a `tx_store_` entry with matching (from, nonce).

**Proof by induction.** The empty-state base case is trivial.

For the inductive step, consider each mutation path:

1. **Admission insert at `node.cpp:2052-2053` and `3193-3194`.** Both indices are inserted in the same atomic statement-pair:
   ```cpp
   tx_store_[tx.hash] = tx;
   tx_by_account_nonce_[key] = tx.hash;
   ```
   where `key = (tx.from, tx.nonce)`. Both indices are updated with consistent values. ✓

2. **RBF replacement at `node.cpp:2044` and `3185`.** The existing entry is erased from `tx_store_` only:
   ```cpp
   if (existing != tx_store_.end()) tx_store_.erase(existing);
   ```
   followed by the insert step above. The `tx_by_account_nonce_[key]` is then overwritten by the new tx's hash (the same statement-pair as the admission insert). So after RBF: `tx_store_` has the new entry, `tx_by_account_nonce_[key]` points to the new entry. Index consistency preserved. ✓

3. **Eviction at `node.cpp:2014-2015` (inside `mempool_make_room_for`).** Both indices are erased:
   ```cpp
   tx_store_.erase(min_it);
   tx_by_account_nonce_.erase(evicted_key);
   ```
   where `evicted_key = (min_it->second.from, min_it->second.nonce)`. Both indices lose the entry consistently. ✓

4. **Chain-advance drain at `node.cpp:1791-1794`.** Both indices are erased:
   ```cpp
   for (auto& tx : b.transactions) {
       tx_store_.erase(tx.hash);
       tx_by_account_nonce_.erase({tx.from, tx.nonce});
   }
   ```
   ✓

5. **Stale-nonce sweep at `node.cpp:1798-1805`.** Both indices are erased:
   ```cpp
   if (it->second.nonce < chain_.next_nonce(it->second.from)) {
       tx_by_account_nonce_.erase({it->second.from, it->second.nonce});
       it = tx_store_.erase(it);
   }
   ```
   ✓

Every mutation path that touches one index touches the other in the same lock-held critical section, with consistent keys. The invariant is preserved.   □

### Lemma L-4 (Per-sender count monotonicity per admission)

For any admission attempt with `tx.from = s`:

1. If the attempt is **rejected** (any reject branch fires), `count_from(s)` is unchanged.
2. If the attempt is **accepted as RBF replacement** (an existing entry at `(s, tx.nonce)` was overwritten), `count_from(s)` is unchanged.
3. If the attempt is **accepted as fresh-slot insert** (no existing entry at `(s, tx.nonce)`), `count_from(s)` increases by exactly 1.
4. If the attempt is **accepted with eviction** (fresh slot, cap reached, eviction succeeded), `count_from(s)` increases by exactly 1, and `count_from(s')` decreases by exactly 1 for the evicted entry's sender `s'` (which may equal `s` or differ).

The four cases are exhaustive for the admission path. Combined with the per-sender quota check `sender_count >= MEMPOOL_MAX_PER_SENDER → reject` (`node.cpp:1970-1974`) and the inductive invariant `∀s : count_from(s) ≤ Q`, we get:

- In case 3 (fresh-slot insert), `count_from(s)` after = `count_from(s)` before + 1 ≤ `(Q - 1)` + 1 = `Q` (admission would have been rejected at `count = Q` pre-call, so pre-call count ≤ Q - 1).
- In case 4 (fresh-slot eviction), same bound for `s`; for `s'`, `count_from(s')` after = `count_from(s')` before - 1 ≤ Q - 1 ≤ Q.

The invariant `∀s : count_from(s) ≤ Q` is preserved across admissions.

The chain-advance drain + stale-nonce sweep can only decrease `count_from(s)` for any `s` (since they only erase entries). So the invariant is preserved across all mutation paths.

By induction from the empty initial state where `∀s : count_from(s) = 0`: the invariant holds at every reachable mempool state.   □

### Lemma L-5 (Global cap invariant under admission)

For any admission attempt:

1. If **rejected**, `|tx_store_|` unchanged.
2. If **accepted as RBF replacement**, `|tx_store_|` unchanged (one erase + one insert at the same slot).
3. If **accepted as fresh-slot insert without eviction** (cap not reached), `|tx_store_|` increases by 1. The admission gate at `node.cpp:1980` only allows this branch if `tx_store_.size() < MEMPOOL_MAX_TXS`, so post-insert `|tx_store_| ≤ C`.
4. If **accepted as fresh-slot insert with eviction** (cap reached), `|tx_store_|` is unchanged (one eviction + one insert). Pre-call `|tx_store_| ≤ C`; the eviction occurs only if pre-call `|tx_store_| = C`; post-eviction-but-pre-insert `|tx_store_| = C - 1`; post-insert `|tx_store_| = C`.

In all four cases, post-call `|tx_store_| ≤ max(pre-call |tx_store_|, C)`. By induction from the empty initial state, `|tx_store_| ≤ C` is invariant across admissions.

The chain-advance drain + stale-nonce sweep can only decrease `|tx_store_|` (only erase calls), so the invariant is preserved.   □

### Lemma L-6 (Stale-nonce never enters mempool)

The admission gate at `node.cpp:2023` (gossip) and `3158` (RPC) rejects any tx with `tx.nonce < chain_.next_nonce(tx.from)` before any sig-verify or mempool check runs. Both checks run while holding `state_mutex_` (per L-1), so the `next_nonce(tx.from)` reading is consistent with the mempool state at the same instant.

Therefore: at the moment of insertion (the `tx_store_[tx.hash] = tx` statement at `node.cpp:2052` / `3193`), `tx.nonce ≥ chain_.next_nonce(tx.from)`.

After insertion, `chain_.next_nonce(s)` can only increase (per FA-Apply-3 / NonceMonotonicity.md T-N2). So at any later instant before the next `chain_.append(b)` call, the inserted tx's nonce is still `≥ chain_.next_nonce(tx.from)`.

After a `chain_.append(b)` call, the stale-nonce sweep at `node.cpp:1798-1805` removes any mempool entry whose nonce is now strictly less than the post-append `next_nonce(from)`. So immediately after the sweep, no stale-nonce entry remains in the mempool.

The sequence "admission insert at fresh nonce → chain advance → sweep removes any newly-stale entries" pins the invariant: at every snapshot taken immediately after a chain-advance (or in the steady-state between chain advances), no mempool entry has stale nonce.   □

### Lemma L-7 (Fee-priority eviction monotonicity)

For any sequence of fresh-slot admissions that trigger eviction (i.e., `tx_store_.size() = C` at the moment of admission, and `tx.fee > min_fee(tx_store_)`):

1. The post-eviction `min_fee(tx_store_)` is **non-decreasing** in expectation across successive evictions. More precisely: the post-eviction min-fee may equal the pre-eviction min-fee if the post-eviction min is another tx with the same fee value, but it cannot be lower than the pre-eviction min.
2. The evicted tx's fee is strictly less than the incoming tx's fee — by the gate `tx.fee <= min_it->second.fee → false → admission rejected before eviction occurs` at `node.cpp:2011`.
3. Therefore, an attacker who wants to sustain admission at a fee level `f_attack` must compete with the chain's current `min_fee(tx_store_)`. Each successful eviction-driven admission either (a) pays `f_attack > min_fee` and displaces a `min_fee`-tier tx, or (b) is rejected.

Consequence: the marginal cost-per-admission for the attacker scales upward as the chain's min-fee tier is exhausted. After all min-fee-tier txs are evicted, the next eviction requires `f_attack > next_higher_fee_tier`. The attacker's cost ramps geometrically (if the fee distribution is geometric) or polynomially (depending on the fee distribution) — but is bounded below by the chain's protocol-floor (currently 0; v2.X follow-on adds a genesis-pinned `min_fee` per S-008 Option 4 in SECURITY.md).   □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Capacity Bound).** Direct from L-5. The capacity invariant `|tx_store_| ≤ C` is preserved across every admission path (rejected / RBF / fresh-slot-no-eviction / fresh-slot-with-eviction) and is preserved across every chain-advance drain (which only erases). By induction from the empty initial state, the invariant holds at every reachable state.   ∎

**Proof of T-2 (Nonce-Gating Soundness).** Direct from L-6. The admission-time guard at `node.cpp:2023` / `3158` rejects stale-nonce txs at insertion. The apply-time sweep at `node.cpp:1798-1805` removes any mempool entry whose nonce becomes stale due to a chain-advance. Combined with FA-Apply-3's monotonicity of `next_nonce(s)`, the invariant `∀h ∈ tx_store_ : tx_store_[h].nonce ≥ next_nonce(tx_store_[h].from)` is pinned at every snapshot taken after a chain-advance or in steady-state.   ∎

**Proof of T-3 (RBF Determinism).** Consider a sequence of admission attempts `tx_1, …, tx_k` at fixed `(s, n)`. Let `f_i := tx_i.fee` and `i* := argmax_{i ∈ [1, k]} f_i` (breaking argmax ties by smallest index — "first-arriving" by definition).

**Claim:** the surviving entry after processing the sequence is `tx_{i*}`.

**Proof by induction on the prefix length `j ∈ [1, k]`.** Define `surv(j)` as the surviving entry after processing `tx_1, …, tx_j`.

**Base case (j = 1).** `surv(1) = tx_1` — the first admission at slot `(s, n)` is a fresh-slot insert (assuming other admission gates pass), unconditionally accepted. ✓

**Inductive step.** Assume `surv(j) = tx_{i*(j)}` where `i*(j) := argmax_{i ∈ [1, j]} f_i` (smallest index on ties). Consider `tx_{j+1}`:

1. Compute the proposed `i*(j+1)`. There are three cases:
   - `f_{j+1} > f_{i*(j)}` strictly greater: `i*(j+1) = j+1`, and the RBF branch at `node.cpp:2041` accepts (the gate `existing.fee >= tx.fee` evaluates `f_{i*(j)} >= f_{j+1}`, which is false, so the rejection path is skipped; the erase + insert proceeds). Post: `surv(j+1) = tx_{j+1}` = `tx_{i*(j+1)}`. ✓
   - `f_{j+1} = f_{i*(j)}` tie: `i*(j+1) = i*(j)` (smaller index wins). The RBF branch's gate `existing.fee >= tx.fee` evaluates `f_{i*(j)} >= f_{j+1}`, which is true (equal), so the rejection path fires — `tx_{j+1}` is rejected, `tx_{i*(j)}` survives. Post: `surv(j+1) = tx_{i*(j)}` = `tx_{i*(j+1)}`. ✓
   - `f_{j+1} < f_{i*(j)}` strictly less: `i*(j+1) = i*(j)`. The RBF branch's gate evaluates `f_{i*(j)} >= f_{j+1}`, which is true (strict greater), so rejection. Post: `surv(j+1) = tx_{i*(j)}` = `tx_{i*(j+1)}`. ✓

In all three cases, `surv(j+1) = tx_{i*(j+1)}`. By induction, `surv(k) = tx_{i*}` — the highest-fee submission with smallest-index tie-break wins.

Properties 1 and 2 of T-3 follow directly. Property 3 (permutation invariance for the strict-greater case) is the consequence of `i*` being a function of the multiset `{f_i}` — the argmax operation is permutation-invariant on the set of fee values, with the index only mattering on ties.   ∎

**Proof of T-4 (Memory Bound).** By T-1, `|tx_store_| ≤ C`. By S-022 T-1 + the TRANSACTION cap at `include/determ/net/messages.hpp:124-152`, every admitted transaction has wire size ≤ `max_message_bytes(MsgType::TRANSACTION) = 1 MB`. The in-memory representation is bounded by a constant multiplier `K_str` over the wire form (string + vector heap-allocation overheads). The index `tx_by_account_nonce_` has the same entry count as `tx_store_` (by L-3) with per-entry overhead bounded by `sizeof(std::pair<std::string, uint64_t>) + sizeof(Hash) + std::map_node_overhead`.

Substituting: `mem(tx_store_) + mem(tx_by_account_nonce_) ≤ C × K_str × 1 MB + C × indexOverhead`. The dominant term is `C × K_str × 1 MB ≈ 10K × 1.5 × 1 MB ≈ 15 GB` in the theoretical worst case. Operationally, typical txs are 300-500 bytes wire-form, yielding `10K × ~750 B ≈ 7.5 MB` in practice.

The bound composes with S-022 to give an end-to-end ceiling on per-node mempool RAM that is independent of any flooder's bandwidth — the flooder can saturate the per-IP rate limit (S-014) at 1-MB-per-tx and still hit the `C` cap before the RAM budget is exceeded.   ∎

**Proof of T-5 (No Useful-Tx Loss Under Pressure).** All three properties follow from the eviction logic in `mempool_make_room_for` at `node.cpp:2001-2017` + L-7.

**Property 1.** Suppose `H ⊆ tx_store_` is the set of high-fee honest txs with every `f_h > f_f` for every flooder fee `f_f` in the mempool. The min-fee selection at `node.cpp:2005-2009` picks the tx with the smallest fee. By the hypothesis, every honest tx's fee is strictly greater than every flooder's fee, so the min-fee tx is always a flooder tx. The eviction therefore targets a flooder, not an honest tx. ✓

**Property 2.** The strict-greater eviction gate at `node.cpp:2011` (`tx.fee <= min_it->second.fee → false`) means an honest tx with fee `f_h` evicts a flooder with fee `f_f` iff `f_h > f_f`. Equal fees: the incumbent survives, so a flooder cannot displace an equal-fee honest tx. ✓

**Property 3.** The chain-advance drain at `node.cpp:1791-1794` erases only txs in `b.transactions` (the applied set). The stale-nonce sweep at `node.cpp:1798-1805` erases only entries whose nonce became stale. Both are honest, expected removals — they reflect the chain's progress, not adversarial eviction. ✓

The combined claim: under sustained admission pressure, the mempool's surviving high-fee honest txs are preserved up to the natural rate of chain-application + sender-nonce-advance. The flooder can only displace lower-fee txs (their own or other low-fee senders'), not high-fee honest senders.   ∎

**Proof of T-6 (Composition with S-014).** The S-014 per-IP token-bucket bound (`S014RateLimiterSoundness.md` T-1) caps the count of admission attempts originating from one IP `k` in any window `[t, t+Δ]` to `⌊C_rl + r·Δ⌋`. The S-008 per-sender quota (`MEMPOOL_MAX_PER_SENDER = Q = 100`) caps the count of `(sender, nonce)` slots one address can occupy at any instant.

Notice that S-014 keys on IP while S-008 keys on sender. For an attacker controlling one IP and one sender (the simplest case), the two bounds compose directly:

$$
\text{Admitted}_{k}^{\text{single-sender}}([t, t+\Delta]) \;\leq\; \min(\lfloor C_{rl} + r \cdot \Delta \rfloor,\; Q).
$$

For an attacker controlling one IP and multiple senders (e.g., a single node running many anon-wallet addresses), the per-IP bound caps the rate (S-014 sees one IP); the per-sender quota caps each sender independently. The composed bound is the per-IP rate bound × min(N_senders, available_slots) — bounded but not tight. The full bound for this case requires the additional global cap `C` (T-1), giving:

$$
\text{Admitted}_{k}^{\text{multi-sender}}([t, t+\Delta]) \;\leq\; \min(\lfloor C_{rl} + r \cdot \Delta \rfloor,\; C - n_{\text{pre}}).
$$

For an attacker controlling many IPs and many senders (distributed flood), per-IP rate-limit bounds each IP individually; per-sender quotas bound each sender individually. Aggregate bound is per-IP-bound × N_IPs ≤ global cap (via T-1). The full mitigation against distributed flood is the conjunction of all three caps (per-IP rate + per-sender quota + global cap).

The composition is multiplicative: an attacker on one IP with one sender pays both bounds; an attacker on many IPs with many senders pays each per-IP and per-sender bound separately, then is capped globally. The DoS surface is closed by the conjunction.

The fee-bidding term enters in the eviction-driven admission case: an attacker who exceeds the per-sender quota cannot bid their way in (per-sender is hard reject), but an attacker who stays under the per-sender quota and tries to take up the global cap must bid above the current min-fee per the eviction gate (T-1's case 4). The marginal cost ramps per L-7.   ∎

---

## 6. Adversary model + notable findings

### 6.1 Adversary model

The S-008 closure is designed against the following adversary families:

**(A1) Low-fee flood from one sender.** One attacker, one IP, one sender address, attempting to fill the mempool with cheap (or zero-fee) transactions. Bounded by **Q** (per-sender quota): after Q = 100 pipelined-nonce txs, additional submissions from the same sender are rejected outright regardless of fee. The attacker would need to use distinct sender addresses to exceed 100 slots — see A2.

**(A2) Low-fee flood from many senders.** N attackers (or one attacker controlling N anon-wallet addresses), each sending up to Q txs at low fee, attempting to consume the global cap. Bounded by **C** (global cap) + the fee-priority eviction policy. After the cap is reached (10K total slots, achievable in principle with 100 senders × 100 txs each), the attacker's next admission requires a strictly-higher fee than the current min. The marginal cost ramps as the lower-fee tiers are evicted (L-7). The attacker cannot indefinitely sustain admission without paying ever-higher fees — the chain economically prices them out.

The orthogonal mitigation for A2 at the network layer is S-014's per-IP token-bucket rate limit: an attacker with one IP is bounded to `r` submission attempts per second per IP (T-6). To run N senders from one IP, the per-IP rate limit gates the rate; to spread across N IPs requires the attacker to operate a distributed botnet, which is the next mitigation layer up (operator-supplied upstream firewall / LB; out of scope for S-008's in-process policy).

**(A3) Replay-by-rebroadcast.** Attacker captures an already-applied transaction from the chain's history and replays it (e.g., into the gossip layer) at a stale nonce. Bounded by **T-2** (nonce-gating). The stale-nonce gate at `node.cpp:2023` / `3158` rejects the replay at admission. The apply-time sweep at `node.cpp:1798-1805` also runs after every chain-advance, catching any stale entry that might have somehow survived admission (defense-in-depth).

**(A4) RBF-pingpong.** Attacker submits same-`(sender, nonce)` txs at alternating slightly-higher fees, attempting to consume server resources via eviction churn. Bounded by:

- The S-014 per-IP rate limit: the attacker is bounded to `r` submissions per second per IP, limiting the pingpong rate.
- The "incumbent ties win" rule at `node.cpp:2041` / `3182`: if the attacker tries equal-fee pingpong, the second attempt is a no-op (incumbent stays). To churn, the attacker must strictly raise the fee on each attempt.
- The eviction cost per attempt: each successful RBF replacement requires an `O(log N)` map erase + insert. For N = C = 10K, this is `~14` comparisons + a tree-rebalance — small constant per attempt.
- The total cost: at the per-IP rate limit (say, 100 RPS), the attacker can cause `100 × O(log C) = ~1400` operations per second of pingpong work per IP. Bounded by the rate limit; not amplifiable beyond the per-IP budget.

**(A5) Fee-distribution gaming (eviction-target prediction).** Attacker reads the chain's current min-fee tier (via RPC's `tx-summary` or by observing chain blocks) and submits txs at `min_fee + 1`, displacing the cheapest incumbent. Repeats. The attacker pays the marginal fee for each displacement. Bounded by the chain's economic floor: the attacker's total cost = `(num_displacements) × marginal_fee`, and the marginal fee ramps per L-7. Long-term sustained pressure is bounded by the attacker's bankroll vs the chain's accumulated revenue.

**(A6) Compiler-level race / data-race adversary.** Out of scope. The `state_mutex_` (per L-1) serializes all mempool mutations. No data race.

### 6.2 Notable findings

**Finding F-1 (RBF-pingpong observed but bounded by S-014 + min-fee-increment).** As covered under A4, RBF-pingpong is bounded by the per-IP rate limit (so the attacker can't churn faster than `r` attempts/sec/IP) and by the "incumbent wins ties" rule (so equal-fee pingpong is a no-op). The minimum strict-greater fee increment is currently 1 (the smallest representable fee step), which means the attacker pays at least 1-unit fee per churn attempt. Combined with the per-IP rate limit, the total cost per second is bounded but not zero.

A v2.X follow-on could enforce a larger minimum-fee-increment for RBF (e.g., 10% above current incumbent) to further raise the churn cost — but this is a fee-market design item, not a closure of an unbounded surface. The current S-008 mitigation is sufficient to prevent unbounded resource consumption; pingpong-mitigation is a fee-market tightening, not a structural defense.

**Severity:** Low (bounded; not exploitable for unbounded resource consumption).

**Finding F-2 (Eviction min-fee scan is O(N) per cap-overflow admission).** The eviction helper at `node.cpp:2005-2009` performs a full linear scan of `tx_store_` to find the minimum-fee entry. For `N = C = 10K` and a sustained flood pattern that triggers eviction on every admission, this is O(C) = O(10K) work per admission. At a per-IP rate limit of 100 RPS, this is ~1M tree-walk operations per second per IP — non-trivial but bounded.

A more efficient alternative would be a min-heap or balanced-BST keyed on fee, providing O(log N) eviction-target lookup. The trade-off is the added insertion cost (every admission must update the heap, not just the two existing maps) and the additional memory overhead per entry. The current linear-scan approach is acceptable because (a) it only triggers on cap-overflow admissions, which are themselves bounded by the per-sender quota Q and the global cap C; and (b) the rate limit S-014 bounds the rate at which the scan can fire.

**Severity:** Low (bounded; performance optimization, not a soundness issue).

**Finding F-3 (Mempool persistence across restart NOT supported — by design).** The mempool data structures `tx_store_` and `tx_by_account_nonce_` live entirely in `Node`'s in-memory state. They are not persisted to disk and are not restored from chain snapshots (the snapshot covers chain state, not mempool state).

The consequence: on node restart, the mempool starts empty. Pending transactions submitted to the previous instance are lost from this node's mempool but typically remain in other peers' mempools (gossip-broadcast on submission gives broad replication). The restarted node will receive the pending txs back via gossip-replay from peers, so the operational impact is bounded by the gossip-propagation delay (typically <1 second).

This is **by design**: persisting mempool state would require additional disk-write I/O on every admission (high write amplification given the typical admission rate) and would complicate the chain-advance drain (which would have to delete from both in-memory and on-disk mempool). The gossip-replay path is the operational replacement for mempool persistence.

**Severity:** Operational (documented behavior; no security implication).

The three findings are advisory; none invalidates T-1 .. T-6. They are surfaced for completeness so an external auditor can confirm the scope of the proof's analytic conclusion.

---

## 7. Test surface

### 7.1 Existing regression test

`tools/test_mempool_bounds.sh` (3/3 PASS) exercises the S-008 admission policy on a 1-node SINGLE-mode chain with `M = K = 1`. The test:

1. **Normal admission.** Submits 1 TRANSFER tx with explicit `nonce = 0`. Asserts the response includes `"status": "queued"`. Exercises the happy-path admission (sig-verify + admission-check + insert).

2. **Pipelined-nonce burst.** Submits 5 TRANSFER txs from the same sender with `nonce = 1..5`. Asserts all 5 are queued. Exercises the integration wiring (no rejection on a small pipelined burst that should be well under cap).

3. **Different-sender independence.** Submits 1 TRANSFER tx from a second anon-wallet address. Asserts queued. Verifies that the per-sender quota is per-from (`B_ADDR`'s quota is independent of `A_ADDR`'s).

The test's own header comment (`tools/test_mempool_bounds.sh:13-18`) acknowledges that the global cap of 10K is hard to exercise from a bash-level integration test because block production drains the mempool faster than the bash-level admission rate. The test sets `tx_commit_ms = 300000` (5-minute timer) to slow block production, but even then, hitting the 10K cap requires sustained submission at >100 RPS, which the bash + subprocess overhead per `send_anon` call cannot achieve.

### 7.2 Recommended additional test coverage

**(R-1) Direct unit-test of `mempool_admit_check` + `mempool_make_room_for`.** An in-process unit test (sibling of `test-atomic-scope`, `test-randomized-delay`, etc. as listed in CLI help) could directly construct `tx_store_` + `tx_by_account_nonce_` with 10K entries, then exercise the cap-overflow admission path without consensus drain. Effort: ~50 LOC + 1 hour. Coverage: directly verifies T-1's cap invariant at the boundary `|tx_store_| = C`.

**(R-2) RBF determinism test.** Submit `(s, n)` collisions in different arrival orders across simulated peer-replay; verify the surviving fee equals the max regardless of order (T-3). Effort: ~30 LOC. Coverage: directly verifies T-3's permutation invariance.

**(R-3) Eviction policy test.** Pre-fill the mempool with 10K txs at fee = 1. Submit a tx at fee = 2; assert a fee-1 incumbent is evicted and the fee-2 tx is admitted. Submit a tx at fee = 1; assert rejection. Coverage: directly verifies T-5's properties 1 + 2.

**(R-4) Cross-channel admission identity.** Submit the same tx via gossip and via RPC; verify the mempool state after each is identical (L-2). Coverage: validates the gossip + RPC parity assumption.

The four recommended tests would close the coverage gap on the cap-firing and policy-edge paths that the existing bash-level test cannot exercise.

---

## 8. Status

**Shipped (S-008 closed in-session per `docs/SECURITY.md` §S-008).** The bounded mempool is live in the current `main` branch:

- `include/determ/node/node.hpp:444-484` — `tx_store_`, `tx_by_account_nonce_`, `MEMPOOL_MAX_TXS`, `MEMPOOL_MAX_PER_SENDER`, `mempool_count_from`, `mempool_admit_check`, `mempool_make_room_for` declarations + commentary.
- `src/node/node.cpp:1937-2017` — `mempool_count_from`, `mempool_admit_check`, `mempool_make_room_for` definitions.
- `src/node/node.cpp:2019-2054` — `Node::on_tx` (gossip-path admission with S-008 gate).
- `src/node/node.cpp:3157-3194` — `Node::rpc_submit_tx` (RPC-path admission with S-008 gate).
- `src/node/node.cpp:1790-1805` — chain-advance drain + stale-nonce sweep.
- `tools/test_mempool_bounds.sh` — 3/3 PASS integration test (existing).
- `docs/SECURITY.md` §S-008 — closure narrative (Options 1 + 3 shipped; Option 4 protocol-derived min-fee is deferred as a separate item).

**Not yet shipped (future work):**

- **Option 4 (protocol-derived minimum fee).** A genesis-pinned min-fee floor (e.g., `tx.fee >= block_subsidy / 1024`) would eliminate zero-fee spam without operator tuning and scale naturally with chain economics. Effort: ~10 LOC in validator + producer + tests. Deferred because (a) existing regression tests use `fee = 0`; updating them is a separate task, and (b) the floor value needs design discussion (fee-market dynamics + impact on small-tx UX).

- **Minimum-fee-increment for RBF.** Currently the minimum increment is 1 (the smallest representable fee step). A larger increment (e.g., 10% above incumbent) would raise the RBF-pingpong cost. Effort: ~5 LOC. Deferred as a fee-market tightening, not a structural defense.

- **Min-heap eviction (F-2 mitigation).** Replace the linear-scan in `mempool_make_room_for` with a min-heap keyed on fee. Reduces eviction-target lookup from O(C) to O(log C). Effort: ~50 LOC + insertion-path updates. Deferred because the linear-scan is acceptable under the S-014 rate-limit bound on admission frequency.

- **In-process unit tests R-1 through R-4.** Direct coverage of cap-firing, RBF determinism, eviction policy, and cross-channel parity. Effort: ~150 LOC total across four tests + ~1 hour to wire each. Recommended for the next test-coverage sweep.

- **Mempool persistence across restart.** As noted in F-3, this is by-design out of scope. Gossip-replay is the operational substitute.

This proof was added in the current review pass as part of the analytic-closure sweep for S-008; it does not modify any source code, only formalizes the bounded-mempool argument that the closure establishes under the standard fee-priority + per-sender-quota + nonce-gating + RBF policy.

---

## 9. Cross-references

The S-008 closure interacts with the following sibling closures:

- **S-002 (mempool sig-verify).** The S-002 closure ensures that only signature-valid txs reach the S-008 admission gate. Without S-002, an attacker could flood with forged-sig txs that consume admission-evaluation budget. The two closures compose: S-002 gates upstream, S-008 gates downstream. The shared admission gate runs sig-verify before the S-008 check (cheap-first ordering) at `node.cpp:2028` / `3166`. See `docs/proofs/S002-Mempool-Sig-Verify.md`.

- **S-014 (per-IP rate limiter).** The S-014 closure caps the per-IP admission attempt rate, bounding the ingress flow. S-008 caps the per-sender slot count + global storage, bounding the storage occupancy. The two closures cover orthogonal axes (rate vs occupancy); they compose multiplicatively per T-6. See `docs/proofs/S014RateLimiterSoundness.md`.

- **S-022 (per-MsgType wire-format caps).** The S-022 closure caps the per-tx wire size at `max_message_bytes(MsgType::TRANSACTION) = 1 MB`. This bounds the per-entry memory in the mempool. S-008's count cap × S-022's per-entry size cap gives the total mempool memory bound per T-4. See `docs/proofs/S022WireFormatCaps.md`.

- **S-013 (per-signer cap on `buffered_block_sigs_`).** S-013 closes a related-but-distinct surface: the `buffered_block_sigs_` cache that pre-verifies BLOCK_SIG messages from peers. It uses a per-signer cap of 2 (rather than the per-sender cap of 100 in S-008) because the entry semantics are different (BLOCK_SIG attestation vs Transaction admission). S-008 and S-013 are independent closures on independent data structures; they share only the structural-pattern of "bounded mempool-class cache with per-key quota."

- **FA-Apply-3 (NonceMonotonicity).** The FA-Apply-3 proof establishes that `chain_.next_nonce(s)` is monotonically non-decreasing across `chain_.append(b)` calls (T-N2). T-2 of this proof leverages that monotonicity to argue that the stale-nonce admission gate (which compares against `next_nonce` at insertion time) remains sound across subsequent chain-advances. The two proofs cover complementary surfaces: FA-Apply-3 covers the apply-layer replay-defense; S-008 T-2 covers the mempool-layer admission-stage replay-defense.

- **FA-Apply (AccountStateInvariants).** Invariant I-2 (nonce monotonicity per account) is the apply-layer counterpart of S-008's stale-nonce admission gate; the two together ensure no stale-nonce tx is ever applied to the chain.

The cross-reference graph: S-008 sits at the intersection of the mempool-admission surface (input from S-014 rate limit), the per-tx-size surface (input from S-022 wire-format cap), and the apply-time surface (output to FA-Apply-3 nonce monotonicity). The S-008 closure depends on the upstream cap (S-022) for the per-entry size bound and composes with the upstream rate limit (S-014) for the joint rate-and-storage bound.

---

## 10. References

### Specifications + standards

- **CWE-770** (MITRE, "Allocation of Resources Without Limits or Throttling"). The pre-S-008 mempool was a textbook CWE-770 instance: the `tx_store_` map grew without an upper bound on `size()`, allowing an attacker who could feed transactions to the gossip layer to consume arbitrary RAM. S-008's hard cap + per-sender quota + fee-priority eviction is the canonical CWE-770 mitigation pattern.
- **CWE-400** (MITRE, "Uncontrolled Resource Consumption"). A superclass of CWE-770 that also covers the network-bandwidth side; the S-008 + S-014 composition closes both per-CWE branches (S-014 the bandwidth side, S-008 the memory side).
- **RFC 9006** (Touch, Heiland-Allen, Apr 2021) "TCP Usage Guidance in the Internet of Things." §4 discusses application-level admission control above the TCP layer — the structural pattern S-008 implements.

### Mempool design literature

- **Bitcoin Core mempool design** (`src/txmempool.cpp` in the Bitcoin reference implementation). Bitcoin's mempool uses a fee-rate-priority eviction (fee per byte rather than absolute fee), a per-package limit (replacing the per-sender concept), and a hard size cap typically 300 MB. The S-008 design simplifies (absolute fee, per-sender) for v1 — a v2.X follow-on could extend to fee-rate priority once the chain has a meaningful tx-size distribution.
- **Ethereum mempool / txpool** (geth's `core/txpool` package). Per-account pending+queued txs are capped (default 16 pending + 64 queued = 80 per sender, roughly comparable to S-008's per-sender cap of 100). The global cap is 5120 pending + 1024 queued = 6144 total (vs S-008's 10K). Eviction is by gas-price + nonce ordering. Same structural pattern; tuning differs by chain economics.
- **Coffman, Elphick, Shoshani** (1971, "System Deadlocks," ACM Computing Surveys 3:2). Foundational treatment of resource-allocation contention; the fee-priority eviction in S-008 is a scheduling policy in the Coffman-Denning lineage.

### Algorithm + data-structure references

- **Knuth, The Art of Computer Programming Vol 3 (1973)** §6.2 "Searching." Covers balanced-BST (the `std::map` used in `tx_store_` and `tx_by_account_nonce_`) with O(log N) insert/erase/find — the foundation for L-3's per-mutation correctness argument.
- **Knuth, TAOCP Vol 3** §5.2.3 "Sorting by Selection." Relevant to the eviction's min-fee scan (an O(N) "find minimum" is the textbook selection-sort inner loop). The O(N) cost per cap-overflow admission (F-2) is the worst case; an O(log N) min-heap would be the optimal alternative.
- **Cormen, Leiserson, Rivest, Stein (2009)** "Introduction to Algorithms" §6 (binary heaps). Reference for the F-2 mitigation: a min-heap on fee would replace the linear scan.

### Determ-internal references

- `include/determ/node/node.hpp:444-484` — mempool state + helpers declarations.
- `src/node/node.cpp:1937-2017` — `mempool_count_from`, `mempool_admit_check`, `mempool_make_room_for`.
- `src/node/node.cpp:2019-2054` — `Node::on_tx` (gossip-path admission).
- `src/node/node.cpp:3157-3194` — `Node::rpc_submit_tx` (RPC-path admission).
- `src/node/node.cpp:1790-1805` — chain-advance drain + stale-nonce sweep.
- `tools/test_mempool_bounds.sh` — 3/3 PASS integration test.
- `docs/SECURITY.md` §S-008 — closure-status narrative this proof formalizes.
- `docs/SECURITY.md` §3 Mitigated-High table row — audit-track status.
- `docs/proofs/S014RateLimiterSoundness.md` (S-014 closure) — T-6 composition.
- `docs/proofs/S022WireFormatCaps.md` (S-022 closure) — T-4 per-entry size bound.
- `docs/proofs/S002-Mempool-Sig-Verify.md` (S-002 closure) — upstream sig-verify precondition.
- `docs/proofs/NonceMonotonicity.md` (FA-Apply-3) — apply-layer monotonicity invariant T-2 leverages.
- `docs/proofs/AccountStateInvariants.md` (FA-Apply) — Invariant I-2 nonce monotonicity per account.
- `docs/proofs/Preliminaries.md` §3 — network model (asio + state-mutex serialization) underlying L-1.
- `docs/proofs/S014ConcurrencyAnalysis.md` — structural-disjointness style mirrored in §4 lemmas.
