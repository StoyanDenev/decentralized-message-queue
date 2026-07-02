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

In a malicious scenario the adversary can also *abort* rounds to force re-selection, hoping to land a fully-Byzantine committee on a later try. The number of abort events `R` is bounded by the chain's `bft_escalation_threshold` (shipped default 1 post-S-045; was 5): once that threshold is crossed AND the remaining gates hold (`bft_enabled`, available pool `< K`, available pool `≥ ⌈2K/3⌉`; see Liveness.md §6 and PROTOCOL.md §5.3 for the full four-gate condition), BFT mode engages. In BFT mode the committee shrinks to `|K_h| = k_bft = ⌈2K/3⌉`, the designated proposer must sign, and the within-committee 2/3 quorum `Q = ⌈2·k_bft/3⌉` finalizes the block (cf. FA5). Censorship in BFT mode still requires `k_bft`-conjunction over the smaller committee (the union-tx-root rule covers all `k_bft` Phase-1 contributions; only Phase-2 `BlockSigMsg` slots accept sentinels). `R` does not need to extend arbitrarily.   ∎

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

---

## 7. F2 view-reconciliation composition with FA2

**Background.** The S-030 closure narrative threads two complementary mechanisms: the apply-layer state_root binding (S-033 + S-038, both shipped) closes the gap between block-digest coverage and the full block-body, while v2.7 F2 (specified in `docs/proofs/F2-SPEC.md`, implementation pending) closes the remaining consensus-layer view-divergence surface. The FA2 censorship-resistance theorem proven in §1–§3 above rests on the union-tx-root construction (Lemma L-2.1), but the union rule assumes the K committee members' Phase-1 contribs are gathered into a coherent view by the producer. F2 is the protocol mechanism that ensures that gathering is itself censorship-resistant.

### 7.1 Threat refinement — induced view-divergence censorship

Consider a Byzantine coalition `F' ⊊ K_{h,r}` with `|F'| ≤ K − 1` (i.e., at least one honest member `v_i ∉ F'` exists, satisfying T-2's hypothesis). Suppose `v_i` correctly broadcasts a ContribMsg containing `t.hash`. The straightforward FA2 attack — producer omits `t` from the union — is closed by L-2.1 + V7 (the assembled body's tx_root recomputes to mismatch, the block fails V15, the round aborts).

A more subtle attack vector remains:

- **A_view_divergence.** The Byzantine coalition manipulates the gossip-async-pool view fields (per S030-D2-Analysis.md §1: `equivocation_events`, `abort_events`, `inbound_receipts`, …) such that the producer's view of the contrib-set diverges from the honest creators' views of the same set. Pre-F2, these fields are NOT covered by `compute_block_digest`, so Phase-2 signatures can gather over a block-body whose pool-fed fields encode a different view than any honest creator observed. The block can still validate at apply time (no rule rejects a divergent view), but the resulting commit *encodes a censored view* — the round finalizes a block where the honest creator's contribution to a pool-field is silently dropped.

Pre-S-033 + pre-F2, this attack class was bounded only by gossip-async robustness (probabilistically, the honest creator's view eventually converges and re-asserts the dropped item in a future block). Post-S-033 + post-S-038 (shipped), the apply-layer state_root binding closes it: the producer's claimed `body.state_root` is computed over the producer's view of every pool-fed namespace; any peer recomputing from its own apply yields a divergent root, so the divergent block fails the apply-layer gate at `chain.cpp::apply_transactions`. The attack still requires the producer to land on the consensus path, but cannot survive apply-layer verification.

### 7.2 F2 closure mechanism

F2 (`docs/proofs/F2-SPEC.md` §2 Q1–Q9) requires *view convergence as a precondition for signature gathering*, lifting the closure from the apply layer to the consensus layer:

1. **Per-field reconciliation rules** (F2-SPEC.md Q1). Each pool-fed field (`equivocation_events`, `abort_events`, `inbound_receipts`) gets an explicit reconciliation rule (union, intersection, or deterministic-from-state). The producer applies these rules to the K ContribMsgs to derive the canonical lists.
2. **Phase-1 commit binding** (F2-SPEC.md Q3 + Q4). Each ContribMsg carries a Merkle root over the member's view of each pool-fed field, signed under the existing `make_contrib_commitment`. By Lemma L-2.2 (the same lemma FA2 relies on), an honest member's signed view is unforgeable: no party other than `v_i` can produce a sig binding `v_i`'s identity to a different view-root.
3. **Phase-2 sign-over-reconciled** (F2-SPEC.md Q5). The Phase-2 digest is computed over the *reconciled canonical lists*, not over any single member's view. Each member at Phase-2 sign-time re-derives the canonical lists from the K Phase-1 commits via the reconciliation rules, verifies the proposed block body matches, and only then signs.

If a Byzantine coalition tries to induce view divergence, one of two outcomes follows:

- **(a) Reconciliation produces a canonical list that does not include the censored item.** Impossible under the union rule for `equivocation_events` and `abort_events`: a single honest member's commit contributes their view, and union admits any single member's element (by §5.1's "union of K" insight, applied to the pool-fed fields rather than tx_hashes). Under the intersection rule for `inbound_receipts`, divergence yields an *empty* intersection rather than a censored one — the block either includes the receipt (because all K members observed it) or excludes it (because at least one didn't). The intersection rule cannot manufacture asymmetric censorship of a specific honest member's contribution.
- **(b) The producer's proposed block body diverges from the canonical reconciliation.** Phase-2 sign-time re-derivation by each honest member catches the mismatch; the honest member declines to sign; the round fails to gather K of K signatures (or `Q` of `k_bft` under BFT escalation per §4 Step 4 + Liveness.md §6 four-gate condition); the round aborts and re-runs. No silent censorship-via-divergence is possible.

Composition with the existing FA2 result: the four-gate BFT escalation trigger (cited in §4 Step 4) becomes the *gracefully-degrading fallback* when F2 reconciliation cannot converge across the K committee. In MD mode, F2 hard-requires consensus on the reconciled view; in BFT mode, the shrunken committee `K_h` reconciles within its `k_bft` members, and the same union/intersection rules apply over the smaller set.

### 7.3 Composition statement

**Lemma L-2.4 (F2 view-convergence-then-sign).** Under H1–H4 (honest behavior) + A1 (Ed25519 EUF-CMA) + the F2 reconciliation rules (F2-SPEC.md Q1), at most one canonical reconciled view per `(height, round)` can gather K honest signatures.

**Proof sketch.** Each honest member's Phase-1 commit binds them (by L-2.2 lifted to the view-root field) to their snapshot view. The reconciliation function is deterministic over the K commits. An honest member's Phase-2 sign predicate is "the block body's pool-fed fields equal `f(commits_1, …, commits_K)`" where `f` is the per-field reconciliation. Two distinct reconciled views can both gather K honest sigs only if at least one honest member signs both, but each honest member runs the deterministic `f` on the same K commits and arrives at the same answer (Lemma L-2.2 ensures the commits are unique per `(member, round)`). So only one reconciled view satisfies the predicate; honest members converge.   ∎

**Closure of the induced-view-divergence attack.** Pre-F2: the attack required apply-layer state_root rejection (S-033 + S-038) to catch — the consensus layer signed indifferently over any view, and only post-apply did the gate fire. Post-F2: the consensus layer itself refuses to commit a divergent view. Both layers compose:

- *Apply-layer (shipped):* `body.state_root` mismatch at `chain.cpp::apply_transactions` → block rejected → fork-choice (S-029) picks the consistent fork.
- *Consensus-layer (pending v2.7):* F2 view-convergence predicate fails → ≤ K−1 sigs gather → round aborts via the four-gate escalation → next round retries with the honest member's contribution preserved (Step 5 of §3's proof).

The corollary T-2.1 censorship probability bound `(f/N)^K` is preserved across the composition: the union-tx-root rule is the operative censorship-resistance mechanism for tx inclusion; F2 + S-033/S-038 ensure that the round which finalizes the union-tx-root block also encodes a consistent pool-fed view, so the censored item in the *pool-fed* field cannot be silently dropped either.

**References.** `docs/proofs/F2-SPEC.md` (the implementation specification); `docs/proofs/S030-D2-Analysis.md` §3.5 (apply-layer vs consensus-layer closure table); `docs/SECURITY.md` §S-030 (the audit finding); `docs/proofs/Safety.md` §5.3 (D2 footnote — to be removed post-F2 per F2-SPEC.md Q9).

---

## 8. S-014 rate-limiter interaction with FA2

S-014 (`docs/SECURITY.md` §S-014; shipped) introduces per-peer-IP token-bucket rate limiting on both the RPC accept layer and the gossip receive layer via a shared `net::RateLimiter` helper at `include/determ/net/rate_limiter.hpp`. The rate-limiter touches FA2's threat model in two ways: it tightens one direction of the censorship-resistance surface and introduces a bounded new attack surface that requires examination.

### 8.1 FA2 upside — bounded flood attacks against honest signal

Pre-S-014, a Byzantine coalition could attempt to dilute the honest signal in two ways relevant to FA2:

- **Junk-contrib flood.** Byzantine peers flood the gossip mesh with malformed or low-value ContribMsg analogues, hoping to (a) congest the network so honest creators' ContribMsgs drop or arrive late at the producer, or (b) saturate the producer's tx_store so honest mempool entries get evicted before Phase-1 (§5.4's "tx-store eviction" caveat).
- **RPC-side mempool flood.** Byzantine peers spam the RPC `submit_tx` endpoint with low-fee transactions, hoping to evict legitimate higher-fee txs from the honest creator's mempool before Phase-1 snapshot.

Post-S-014, both attacks are bounded by per-peer-IP token rates (defaults: `gossip_rate=500/s, burst=1000`; `rpc_rate=100/s, burst=200` per `docs/SECURITY.md` §S-014). A flooder operating from a single IP exhausts their bucket within burst-time and gets rate-limited at the receive layer before their messages reach the dispatch path. The bucket recovers at the configured steady rate, capping sustained attack throughput.

Critically for FA2's hypothesis (§1: "at least one honest committee member `v_i` has `t ∈ mempool(v_i)`"), HELLO is exempt from the gossip rate-limit (per `tools/test_gossip_rate_limit.sh` and `include/determ/net/rate_limiter.hpp` invocation comments in `src/net/gossip.cpp::handle_message`). So an honest peer joining under network pressure can always complete its 3-way handshake; once connected, the honest peer's outbound ContribMsg traffic is its own rate-limit budget, not the flooder's. The honest creator's contribution to the union-tx-root construction (L-2.1) is preserved.

**Effect on the censorship-resistance bound.** Corollary T-2.1's `(f/N)^K` is a per-round probability over the committee-selection randomness; S-014 does not change `N`, `f`, or `K`. The rate-limiter shifts the *attack-throughput axis* (how many junk messages a coalition can inject per unit time) without altering the *committee-composition axis*. So T-2.1 is unchanged in form, but the practical surface for sustained attack-amplification (e.g., flooding to keep the chain in BFT mode where committee size is smaller) is bounded.

### 8.2 New attack surface — IP spoofing against the rate-limiter

S-014 introduces a new attack vector: a Byzantine coalition could attempt to *deny service* to a victim honest peer by spoofing the victim's source IP to drain the victim's bucket before the victim's own legitimate messages arrive. If successful, the victim peer's gossip traffic gets rate-limited at the receiver, effectively excluding the victim from the union-tx-root contribution.

**Mitigations.**

- **TCP 3-way handshake requirement.** Both the RPC and gossip layers operate over TCP (per `src/net/peer.cpp`). Establishing a connection requires completing the 3WHS, which off-LAN attackers cannot do with a spoofed source IP because the SYN-ACK packet would route to the legitimate owner of the spoofed IP, not the attacker. Internet-scale spoofing across uncooperative routers is effectively closed by BCP 38 / RFC 2827 ingress filtering on most production networks.
- **HELLO exemption preserves honest handshake.** Per §8.1, HELLO bypasses the rate-limiter. Even if a Byzantine peer somehow drained the victim's bucket through a different mechanism, the victim's outbound HELLO to a fresh peer still completes; the victim retains connectivity for ContribMsg gossip.
- **Per-layer bucket independence.** Each consumer of `RateLimiter` (RpcServer + GossipNet) owns its own bucket map (per `docs/SECURITY.md` §S-014: "Each consumer (RPC, GossipNet) owns its own `RateLimiter` instance — separate per-IP buckets per layer, but identical refill semantics"). An attack on the RPC bucket doesn't degrade the gossip bucket; the FA2-relevant channel is gossip, so RPC-side noise is structurally isolated.
- **F-1 closure — bucket time-decay eviction.** The unbounded-buckets growth concern (S014RateLimiterSoundness.md §6.2 F-1) is closed by amortized idle-bucket sweep (default `eviction_threshold_sec = 600`, `sweep_interval_sec = 60`). A spoofing flooder cycling IPv6 /64 prefixes or IPv4 source addresses cannot exhaust the bucket-map memory; honest peers' buckets are reaped only after sustained idleness, and re-creation is full-capacity (semantically equivalent to the un-evicted bucket having refilled).

**Residual risk.** A LAN-adjacent attacker (e.g., on the same broadcast domain as the victim) can spoof the victim's IP at L2/L3 because BCP 38 ingress filtering is operationally upstream of the LAN. Mitigation: operator network segmentation; production deployments should run nodes on dedicated subnets or behind a firewall that filters spoofed source IPs at the L3 boundary. This is an *operational* mitigation, not a protocol-layer one, and is documented as such.

### 8.3 Composition statement

S-014 does not weaken FA2's union-tx-root censorship-resistance guarantee. It tightens FA2 in the practical-attack-surface dimension by bounding flood-attack throughput while preserving honest-channel availability via the HELLO exemption. The composition is asymmetric: the rate-limiter constrains the *attacker's* injection-rate budget without constraining the *protocol's* convergence-rate budget — honest peers' rate-limit budgets are sized (defaults: 500 gossip msgs/s) to cover normal consensus traffic plus generous burst headroom.

**References.** `docs/SECURITY.md` §S-014 (the closure narrative); `include/determ/net/rate_limiter.hpp` (the token-bucket implementation); `tools/test_gossip_rate_limit.sh` (the gossip-side closure test — 3/3 PASS, demonstrating chain advances under sensible defaults and stalls under deliberately-too-tight settings); `tools/test_rpc_rate_limit.sh` (the RPC-side closure test — 4/4 PASS); `docs/proofs/S014RateLimiterSoundness.md` (the analytic soundness proof, including F-1 closure for unbounded-buckets growth).

---

## 9. Updated FA2 closure footing

With v2.7 F2 (pending implementation, spec'd in `docs/proofs/F2-SPEC.md`) and S-014 (shipped + F-1 closure), FA2's closure footing strengthens from "apply-layer rejection of divergence-censored blocks via S-033 + S-038 state_root binding" to "consensus-layer refusal to commit divergent views (via F2 reconciliation + view-convergence-then-sign) + rate-limit-bounded flood attacks (via S-014 per-IP token bucket with HELLO exemption)". Both directions of the censorship threat surface — the *committee-composition axis* (covered by the original T-2 + T-2.1 union-tx-root construction) and the *gossip-pool-view axis* (covered by F2) — are now closed at multiple layers, with the rate-limiter constraining attack throughput as a complementary defense-in-depth.

The corollary T-2.1 censorship probability bound `(f/N)^K` per round (with persistent-censorship bound `(f/N)^{KR}` over R rounds) is preserved across the composition. F2 and S-014 do not change the bound; they change which attacks the bound applies to and the practical surface available to an adversary trying to defeat it.


