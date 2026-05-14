# FA2 — Censorship resistance theorem (K-conjunction)

This document proves Determ's structural censorship-resistance claim: a transaction `t` known to any honest committee member at Phase-1 commit time is included in the next finalized block. The dual corollary gives the per-round probability that an adversary can censor `t` as `(f/N)^K`, exponential in the committee size `K`.

**Companion documents:** `Preliminaries.md` (F0) for notation; `Safety.md` (FA1) for the finalization guarantee that the included `t` survives.

---

## 1. Theorem statement

**Theorem T-2 (Censorship resistance).** Let `B` be the unique valid block at height `h` against chain prefix `B₀, …, B_{h-1}` (existence and uniqueness guaranteed by FA1). Let `t` be a transaction such that:

- `t` is well-formed: passes Preliminaries §5 V15 against the prefix state.
- At Phase-1 commit time of round `r` at height `h`, at least one honest committee member `v_i ∈ K_{h,r} \ F` (honest set per §4) has `t ∈ mempool(v_i)`.

Under the assumptions of `Preliminaries.md` §2 (SHA-256 collision/preimage, Ed25519 EUF-CMA) plus the honest-behavior definition §4 (specifically H4: deterministic mempool snapshot at Phase-1 start):

then `t ∈ B.transactions`.

**Corollary T-2.1 (K-conjunction probability bound).** Under uniform-random committee selection from a pool of size `N` with an adversarial subset `F ⊂ V`, `|F| = f`:

$$
\Pr[t \text{ censored in round } h] = \left(\frac{f}{N}\right)^K + O(K^2/N) \;\text{(rejection-sampling correction)}
$$

For `K = 3`, `N = 100`, `f/N = 0.1`: `P_censor ≈ 10⁻³` per round. Over `R` rounds, `P_persistent_censor ≈ (f/N)^{KR}` — exponential in `KR`.

In plain terms: censoring `t` requires **every** committee member at every retry round to be Byzantine *and* to censor coherently. The protocol guarantees this through union-tx-root construction.

---

## 2. Lemmas

### Lemma L-2.1 — Union-tx-root membership

If for some `i ∈ [0, K)`, `t.hash ∈ B.creator_tx_lists[i]`, then under V7 (Preliminaries §5: `B.tx_root = SHA256-tree-root over ⋃ creator_tx_lists[i]`), `t.hash` is in the multiset-union represented by `B.tx_root`.

**Proof.** V7's tx_root construction takes the union of the K Phase-1 hash lists. Set-union of a family of sets containing `t.hash` in at least one member trivially contains `t.hash`. Tree-root construction is order-stable (sorted, deduplicated per Preliminaries §1.3 + `compute_tx_root` in `src/node/producer.cpp`). So `t.hash` is hash-bound into `B.tx_root` via SHA-256 (collision-resistant under A2).   ∎

### Lemma L-2.2 — Phase-1 commitment binds tx_hashes

For each `i ∈ [0, K)`, V4 (Preliminaries §5) requires that `B.creator_ed_sigs[i]` is a valid Ed25519 signature by `pk_{B.creators[i]}` over the commitment:

```
commit_i = SHA256(B.index ‖ B.prev_hash ‖ inner_root(B.creator_tx_lists[i]) ‖ B.creator_dh_inputs[i])
```

where `inner_root` is the SHA-256 of the concatenation of `tx_hashes` entries in order.

Under EUF-CMA (A1) and collision resistance (A2): if member `v_i = B.creators[i]` is honest, then `B.creator_tx_lists[i]` is exactly the tx_hashes set that `v_i` snapshotted from its mempool at Phase-1 start (§4 H4) — no other set is consistent with `v_i`'s signed commitment.

**Proof.** Suppose `v_i` is honest and the chain records `B.creator_tx_lists[i] = L'` while `v_i`'s actual H4 snapshot was `L ≠ L'`.

By H4, `v_i`'s broadcast `ContribMsg` carries the actual `L` and a signature over `make_contrib_commitment(B.index, B.prev_hash, L, ·)`. By EUF-CMA, no party other than `v_i` can produce a signature by `pk_i` over a different commitment.

If `L ≠ L'` after deduplication and sorting (the canonical form `compute_tx_root` takes), then `inner_root(L) ≠ inner_root(L')` with probability `1 - 2⁻¹²⁸` (collision resistance on SHA-256 of the canonical-form serialization). So `commit_i` for `L` and `L'` differ, requiring two distinct signed commitments. The chain's `creator_ed_sigs[i]` was produced by `v_i` for one specific commitment; by H2 (signs at most one Phase-1 commitment per round) and the round's deterministic protocol state, that's the commitment for `L`.

So `L' = L` (the chain's recorded `creator_tx_lists[i]` matches the honest snapshot), modulo collisions of probability ≤ `2⁻¹²⁸`.   ∎

### Lemma L-2.3 — Honest mempool inclusion

If `t ∈ mempool(v_i)` at Phase-1 commit time of round `r` at height `h`, and `v_i` is honest, then `t.hash ∈ ContribMsg_i.tx_hashes` for this round.

**Proof.** Definition §4 H4: "Constructs `ContribMsg.tx_hashes` as a deterministic function of its local mempool at Phase-1 start (sorted, deduplicated). The selection rule is implementation-defined but applied uniformly to all mempool entries."

The "uniformly to all mempool entries" clause is the operative one: an honest member's selection rule cannot single out `t` for exclusion. So `t.hash` must appear in the result. The deterministic-function part rules out non-reproducible "I forgot" selections.   ∎

---

## 3. Proof of Theorem T-2

By hypothesis there exists an honest `v_i ∈ K_{h,r} \ F` with `t ∈ mempool(v_i)` at Phase-1 commit time.

**Step 1.** By L-2.3, `t.hash ∈ ContribMsg_i.tx_hashes` for round `r` at height `h`.

**Step 2.** Suppose the round finalizes producing block `B`. By V4 (and L-2.2 applied to `v_i`), `B.creator_tx_lists[i] = ContribMsg_i.tx_hashes` (the honest member's actual snapshot, not a tampered version). So `t.hash ∈ B.creator_tx_lists[i]`.

**Step 3.** By L-2.1, `t.hash` is in the union `⋃ B.creator_tx_lists[*]` and hash-bound into `B.tx_root` (V7).

**Step 4.** By the body-assembly rule in `src/node/producer.cpp::build_body` (the body-assembly loop, Preliminaries §10): the proposer materializes `B.transactions` by mapping each hash in the union to its tx-store entry. Under V15 (Preliminaries §5), the assembled body's tx_root recomputes to `B.tx_root`. Two outcomes:

- (a) `t` is in the proposer's tx_store: `t` enters `B.transactions`. ✓
- (b) `t.hash` is in the union but `t` itself is not in the proposer's tx_store: the assembly skips `t` (the body-assembly loop's lookup-miss branch), the tx_root recomputed from the assembled body diverges from `B.tx_root`, and V15 (transaction apply consistency) plus V7 reject the block.

Under partial synchrony (Preliminaries §3.1) + gossip propagation + H5 (broadcast everything), `t` reaches the proposer's tx_store within `Δ` of being known to `v_i`. If the proposer is honest, case (a) holds. If the proposer is Byzantine and forces case (b), the block is invalid and never finalizes.

The hypothesis "the round finalizes producing block `B`" then implies the block validates → case (a) → `t ∈ B.transactions`.

**Step 5 (round aborts → next round).** If the round at `r` aborts (no finalization), the honest `v_i` continues to hold `t` in its mempool. At round `r+1`, the same argument applies. Provided some round eventually finalizes (liveness — see FA4), `t` will appear in that round's block by H4 + Steps 1-4.

Therefore `t ∈ B.transactions` at height `h` for the finalized block.   ∎

---

## 4. Proof of Corollary T-2.1

The probability that all `K` committee members at round `r` are Byzantine is the probability that the deterministic `select_m_creators(rand, N, K)` outputs `K` indices all within `F`.

**Step 1.** `select_m_creators` is a deterministic hybrid sampler (S-020): rejection-sampling when `2K ≤ N` (draws indices from `[0, N)` uniformly via SHA-256-derived hashes, discards duplicates) or partial Fisher-Yates shuffle when `2K > N` (initialises the `[0, N)` index array and swaps `indices[i]` with `indices[i + h_i mod (N − i)]` for `i ∈ [0, K)`). Both branches consume the same ROM source; under the random-oracle model on the seed (Preliminaries §2.1 ROM) each produces the uniform distribution over `K`-element subsets of `[0, N)` — rejection sampling is the classical construction, and Fisher-Yates with uniform `j ∈ [i, N)` at every step is the textbook uniform-permutation generator (Knuth Vol 2 §3.4.2).

**Step 2.** The fraction of `K`-subsets entirely within `F` is:

$$
\frac{\binom{f}{K}}{\binom{N}{K}} = \frac{f(f-1)(f-2)\cdots(f-K+1)}{N(N-1)(N-2)\cdots(N-K+1)}
$$

**Step 3.** For `K ≪ N`, this approximates `(f/N)^K`. The exact form is bounded by:

$$
\left(\frac{f-K+1}{N-K+1}\right)^K \leq \Pr[K\text{-subset} \subseteq F] \leq \left(\frac{f}{N-K+1}\right)^K
$$

Both bounds equal `(f/N)^K + O(K²/N)` for `K ≪ N`. For Determ's typical parameters (`K ∈ {2, 3, 5, 7}`, `N` from 10s to 100s), the `K²/N` correction is bounded by `~5%`.

**Step 4 (persistent censorship).** Suppose the adversary's goal is to keep `t` out of *all* blocks at height `h` (forever). After the first round, if the committee fails to censor (any honest member rotates in and includes `t`), `t` is in the block; the adversary loses. So persistent censorship requires every round at `h` to draw a fully-Byzantine committee.

If aborts force `R` rounds at height `h`, the probability that *every* round draws a fully-Byzantine committee is:

$$
\Pr[\text{persistent censorship over } R \text{ rounds}] = \left(\frac{f}{N}\right)^{KR}
$$

For `K = 3`, `R = 5`, `f/N = 0.1`: `P ≈ 10⁻¹⁵` per height. Effectively impossible for any economically rational adversary.

In a malicious scenario the adversary can also *abort* rounds to force re-selection, hoping to land a fully-Byzantine committee on a later try. The number of abort events `R` is bounded by the chain's `bft_escalation_threshold` (default 5) at which point BFT mode engages and a designated proposer single-sigs the block (cf. FA5); we don't need to extend `R` arbitrarily.   ∎

---

## 5. Discussion

### 5.1 The "union of K" insight

The proof's key step is L-2.1: tx inclusion is a **union over the committee's K hash lists**, not an intersection or a majority. One honest member is enough to force inclusion.

This contrasts sharply with:

- **Leader-based protocols** (Bitcoin, Solana, Tendermint): the leader chooses the tx set. A Byzantine leader can censor `t` by not including it; the next leader may rectify, but per-slot censorship is `(f/N)¹` not `(f/N)^K`.
- **Threshold-signature protocols** (Dfinity): a threshold committee co-produces blocks but the tx set is still leader-proposed. K-of-N threshold sigs say nothing about whose tx_root won.

Determ's K-conjunction censorship resistance is a structural property of the union construction, not a probabilistic-quorum property. Even a single honest member among K Byzantines forces tx inclusion.

### 5.2 What does "fair selection rule" mean (H4 fine print)

L-2.3's H4 requires: "selection rule applied uniformly to all mempool entries." This rules out an honest validator with a buggy or biased selection (e.g., "exclude txs from address X") — such a validator would be Byzantine under §4.

For the proof, H4's natural reading is: any mempool-tx selection rule that doesn't depend on the tx's content (e.g., "first 1000 by fee", "all", "random sample with deterministic seed") counts as honest. Rules that depend on the tx's address or memo content count as censorship (Byzantine).

Implementation note: Determ's current node code uses "all of `tx_store_`" (the mempool snapshot loop in `src/node/node.cpp::start_contrib_phase`). This is the strongest form of H4 — every mempool entry goes into `tx_hashes`. The censorship bound `(f/N)^K` holds unconditionally for honest nodes running this rule.

### 5.3 Cross-shard cases

T-2 is per-shard. For a cross-shard TRANSFER (`shard_id_for_address(to) ≠ my_shard`):

- The source-shard inclusion claim is exactly T-2 applied to the source shard's committee. The transaction enters `B_src.transactions` with one honest source-committee member.
- The destination-shard credit (via `inbound_receipts` and `applied_inbound_receipts_`) is governed by FA7 — cross-shard receipt atomicity. Censorship at the *destination* committee is not in scope here; FA7 covers it.

### 5.4 What this proof does NOT cover

- **Censorship via tx-store eviction.** If `t` is evicted from `mempool(v_i)` before Phase-1 due to mempool size limits (Preliminaries §4 H4's selection rule taking only a subset), the hypothesis fails. Mempool-size DoS is a separate concern (S-008 in SECURITY.md). The proof assumes `t` survives to Phase-1.
- **Censorship via partition.** If `v_i` is partitioned from the proposer and `t` never reaches the proposer's tx_store, Step 4 (a)→(b) flips: the proposer omits `t`, the block fails V7/V15, the round aborts. Liveness handles this (FA4): eventually the round retries with a connected committee and case (a) holds.
- **Selective abort against jackpot blocks.** FA3 (Selective-abort defense) handles the case where a Byzantine member aborts conditionally based on the randomness output. Censorship-via-selective-abort against specific txs is not in this proof's scope — the abort itself, not the tx selection, is the attack vector.

### 5.5 Concrete-security bound

Each lemma loses negligible probability:

- L-2.1: SHA-256 collision, ≤ `2⁻¹²⁸`.
- L-2.2: SHA-256 collision (inner_root) + Ed25519 forgery, each ≤ `2⁻¹²⁸`.
- L-2.3: no cryptographic step; pure protocol-definition.

Combined: T-2 holds with probability `1 - O(2⁻¹²⁸)` per height per honest committee member.

T-2.1's `(f/N)^K` bound is a uniform-distribution claim; it assumes `select_m_creators`'s output is uniform over `K`-subsets, which holds under ROM. The `O(K²/N)` correction is small for typical Determ parameters.

---

## 6. Implementation cross-reference

| Document | Source |
|---|---|
| Union tx_root V7 | `src/node/producer.cpp::compute_tx_root` |
| Phase-1 commit signing | `src/node/producer.cpp::make_contrib_commitment` |
| Validator V4 / V7 / V15 | `src/node/validator.cpp::check_creator_tx_commitments`, `check_transactions` |
| Build-body resolution | `src/node/producer.cpp::build_body` |
| Mempool snapshot H4 | `src/node/node.cpp::start_contrib_phase` |
| Committee selection (uniform under ROM) | `src/crypto/random.cpp::select_m_creators` |

A reviewer can re-validate by reading the source-level objects in the right column against the lemmas in the left.
