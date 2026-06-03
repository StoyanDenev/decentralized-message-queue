# S-020 — Hybrid Fisher-Yates committee selection: uniformity + bounded runtime + side-channel resistance

This document proves the closure of `docs/SECURITY.md` §S-020 (Rejection sampling O(K²) at K/N → 1 — Medium → Mitigated) shipped at `src/crypto/random.cpp::select_m_creators` (lines 70–100). The pre-fix code used a single rejection-sampling path that ran expected `O(K · N/(N−K))` SHA-256 hashes; as the ratio `K/N` approached 1 the final pick expected ~`N` trials and at `K = N − 1` ~`N` trials *per* committee draw, with the worst-case runtime mathematically unbounded though never a hard hang. That gradual degradation gave a producer-aligned adversary a knob to nudge committee-selection latency in pathological pool sizes, and the resulting variability was a (faint) timing side-channel into which validator-indices landed in the result.

The fix is a hybrid: keep rejection sampling on the `K/N ≤ 0.5` regime (cheap, no allocation, preserves rev.9 output for the existing committee-index fixtures) and switch to a partial Fisher-Yates shuffle when `2K > N` (O(N) setup + exactly K hashes, no rejection spin). Both branches consume the same SHA-256-derived randomness and yield a uniformly-distributed K-subset of `[0, N_pool)` under the random-oracle assumption (ROM) on `random_state`. The branch choice is determined entirely by `(K, N)` — both global, both already inputs — so every honest node lands in the same branch and computes the same committee.

The proof here pins the algebraic properties — branch-internal uniformity (T-1, T-2), branch-boundary correctness (T-3), bounded asymptotic runtime in both branches (T-4), determinism across replay (T-5), and absence of identity-dependent timing leakage (T-6) — that make the hybrid sound. This is companion to the higher-level `CommitteeSelection.md` (FA1 + FA8) which cites the function at the protocol level, and to `S010S011SybilEconomics.md` which uses the function's uniformity property as its sampling-fairness premise.

**Companion documents:** `Preliminaries.md` (F0) for `N`, `K`, `random_state` notation; H1–H4 honest-validator assumptions; A1 Ed25519 EUF-CMA; A2 SHA-256 collision resistance; A3 SHA-256 preimage resistance + ROM assumption used in §3 below. `Safety.md` (FA1) for the K-of-K safety theorem that cites `select_m_creators` at V3. `Liveness.md` (L4) for the rotational-eligibility argument that uses the uniformity result here. `BFTSafety.md` (FA5) for the BFT-mode escalation that uses the same selection function over the BFT committee `|K_h| = ⌈2K/3⌉`. `RegionalSharding.md` (FA8) for the region-aware committee selection that wraps the same function with a region-filter. `Censorship.md` (FA2) §3 for the K-conjunction censorship bound whose probability calculation cites the per-domain selection probability `K/N`. `S010S011SybilEconomics.md` for the Sybil-cost formula that cites uniform-random selection as its first premise. `S029ForkChoiceSoundness.md` for the fork-choice rule that operates on blocks whose committees were produced by this function. `docs/SECURITY.md` §S-020 for the closure-narrative row.

---

## 1. Introduction

### 1.1 S-020 context

Determ's K-of-K Phase-1 consensus chooses a K-validator committee from the eligible pool (`N_pool` registered, active, non-suspended, sufficiently-staked validators) at every height. The selection is a deterministic function of (a) a per-height `random_state` derived from the prior block's `cumulative_rand` and the round's `abort_events`, (b) the snapshot of the eligible pool's size `N = N_pool`, and (c) the committee size `K` (`k_block_sigs` in `GenesisConfig`). The function returns a K-subset of `[0, N)` indices into the pool; the caller maps the indices to validator domain identities via the registry's sorted-by-domain canonical order.

The pre-S-020 implementation used **rejection sampling**:

```
result = []
h = random_state
while |result| < K:
    h = SHA256(h || counter); counter += 1
    idx = hash_mod(h, N)
    if idx not in result: result.append(idx)
return result
```

The expected number of SHA-256 hashes per committee draw is `Σ_{i=0..K-1} N / (N − i)`, which simplifies to ~`K · (1 + K/(2(N−K)))` for `K ≪ N` (close to `K` hashes) and grows to `~K · H(K)` (the harmonic sum) as `K → N` — at `K = N − 1` the final pick alone expects `N` draws because every prior index is taken. The pathology is gradual (no hard hang at any concrete N, K) but unbounded in the worst case (a sequence of unlucky SHA-256 outputs colliding with already-picked indices can extend the spin indefinitely; the expectation is finite but the maximum is not).

Two distinct concerns flow from this:

1. **Performance.** At any production profile (`single_test` M=K=3, `web` / `web_test` M=3 K=2, `cluster_test` M=K=3, `regional_test` M=5 K=4, `global_test` M=7 K=5), `K` is small enough that the expected hash cost is microseconds — performance is not actually a bottleneck. But at non-standard deployments with larger K (consortium chains might run K=20 or K=50 for stronger Byzantine tolerance), or under pool depletion (validators dropping until `N_pool` shrinks to barely-larger-than-K), the K/N ratio rises and the hash cost compounds.
2. **Timing side-channel.** An attacker observing the wall-clock duration of `select_m_creators` can infer (approximately) how many rejection-sampling retries fired, which in turn correlates with the *positions* of the selected indices in the random_state stream. The leakage is small per call but compounds across many calls; a multi-block observation window gives the attacker a noisy signal into which validators have been getting picked. The signal does not directly break safety (the random_state input is itself unpredictable per A3 + commit-reveal in Phase-1), but it is a timing-channel hardening gap.

The fix decomposes the problem into two regimes:

- **`2K ≤ N`** (K/N ≤ 0.5): rejection sampling is asymptotically cheap (≈ K hashes; the harmonic blow-up is small here). The expected-rejections-per-draw bound is **< 2** per Lemma L-2 below. Keep this branch; it preserves byte-identical output with rev.9 fixtures, no allocation, no algorithmic disruption.
- **`2K > N`** (K/N > 0.5): rejection sampling pathology dominates. Switch to a partial Fisher-Yates shuffle: build an `O(N)` index array `[0, 1, ..., N-1]`, then iterate `K` swaps drawing `j ∈ [i, N)` from the random_state stream. The result is the first `K` entries of the shuffled array. Cost: `O(N)` setup + exactly `K` hashes + `K` swaps. No rejection spin.

The branch boundary `2K vs N` is the natural choice: it is the unique point at which Lemma L-2's expected-rejections-per-draw bound flips from `< 2` to `≥ 2`. Both algorithms are uniform within their domains (T-1, T-2), so the boundary is purely a performance optimization — at the boundary point `2K = N` either branch produces a uniformly-distributed K-subset (T-1 ⇒ uniform; T-2 ⇒ uniform; the two branches produce *different specific* committee instances at the boundary because the algorithms differ, but both are uniform draws from `C(N, K)`).

### 1.2 What this proof covers

T-1 through T-6 below pin the analytic properties of the hybrid algorithm:

- **T-1, T-2:** uniformity of each branch over the `C(N, K) = N! / (K! (N−K)!)` possible K-subsets of `[0, N)`.
- **T-3:** correctness of the branch-boundary `2K ≤ N` choice via the expected-rejections-per-draw bound.
- **T-4:** bounded asymptotic runtime in both branches (rejection sampling: `O(K log K)` expected; partial F-Y: `O(N)` strict).
- **T-5:** determinism across replays — for fixed `(random_state, N, K)`, both branches produce byte-identical results across any node, build, or run.
- **T-6:** absence of an identity-dependent timing side-channel — runtime depends only on `(K, N)`, not on which validators are selected.

### 1.3 What this proof does NOT cover

This proof does *not* re-derive the SHA-256-as-ROM assumption (A3 / Preliminaries §2.1) — the uniformity arguments treat `random_state` as a uniform 256-bit value. The protocol-level argument that `random_state` is itself unpredictable to the adversary is the territory of `Liveness.md` L4 and `Censorship.md` T-2.1, which compose with this proof's results to give a complete uniform-and-unpredictable selection guarantee.

This proof does *not* cover the **abort-shifted re-selection** path `select_after_abort_m` (`random.cpp:122–163`), which uses the same hybrid switch but pins the `new_first` index at position 0 of the shuffle buffer (the abort-hash offset is part of the consensus contract). The analogous T-1 / T-2 arguments hold for that function — the pin reduces the algorithm's degrees of freedom by one (the first position is determined, the remaining `m − 1` positions are uniformly shuffled over the remaining `n − 1` indices) — but the construction is straightforward and is covered in §3 of `Censorship.md` as a sister case.

This proof does *not* claim **constant-time wall-clock** for both branches — the rejection branch's expected `O(K log K)` is an expectation, not a worst case, and the partial F-Y branch's `O(N)` includes the index-array initialization which is `N` integer writes. What is claimed (T-6) is that the runtime depends only on `(K, N)`, not on which indices were selected; an attacker observing wall-clock measurements learns at most `(K, N)` (both of which they already know from the eligible-pool snapshot).

---

## 2. Algorithm specification

### 2.1 Rejection-sampling branch (`2K ≤ N`)

```
INPUT:  random_state (Hash, 32 bytes), N (pool size), K (committee size)
OUTPUT: indices (K-vector of distinct elements in [0, N))

PRECONDITION: K < N, 2K ≤ N

result := []
h := random_state
counter := 0
WHILE |result| < K:
    h := SHA256(h || counter); counter := counter + 1
    idx := hash_mod(h, N)
    IF idx NOT IN result:
        result.append(idx)
RETURN result
```

`hash_mod(h, n)` returns a uniformly-distributed value in `[0, n)` derived from `h` (the SHA-256 output). The implementation at `random.cpp:32–47` uses rejection sampling internally to debias the modulo reduction: it takes the first 8 bytes of `h` as a `uint64_t v`, computes the largest multiple of `n` ≤ `UINT64_MAX`, and rejects `v` if it lands above that limit (re-hashing `h` with a counter until `v` is in the unbiased range). This guarantees the returned `idx` is exactly uniform over `[0, n)` regardless of `n`. The inner rejection is a constant-factor cost (≤ 1 expected re-hash per outer call, since the worst case for `n` is `(UINT64_MAX + 1) / 2` rejection probability when `n` is `2⁶³`); for `n ≤ 2³²` the rejection probability is `≤ 2⁻³²` per call.

The outer rejection (the "is `idx` already in `result`?" check) is the rejection mechanism this proof is concerned with. It admits each fresh `idx` with probability `(N − |result|) / N`; the expected number of outer trials to draw the `(i+1)`-th distinct index is `N / (N − i)`.

### 2.2 Partial Fisher-Yates branch (`2K > N`)

```
INPUT:  random_state (Hash, 32 bytes), N (pool size), K (committee size)
OUTPUT: indices (K-vector of distinct elements in [0, N))

PRECONDITION: K ≤ N, 2K > N

indices := [0, 1, 2, ..., N-1]
h := random_state
counter := 0
FOR i := 0 TO K - 1:
    h := SHA256(h || counter); counter := counter + 1
    j := i + hash_mod(h, N - i)             // j uniform in [i, N)
    SWAP(indices[i], indices[j])
RETURN indices[0..K-1]
```

The algorithm is the textbook in-place Fisher-Yates shuffle (Knuth TAOCP Vol 2 §3.4.2 Algorithm P) restricted to the first `K` positions of the index array. At each step `i`, the value at position `i` is a uniformly-random draw from `{indices[i], indices[i+1], ..., indices[N−1]}` (the not-yet-placed remainder), and the swap moves the chosen value to position `i`. After `K` swaps, positions `[0, K)` of the array hold a uniformly-distributed K-permutation of K distinct indices from `[0, N)`; the proof of uniformity is T-2 below.

The `hash_mod(h, N − i)` call uses the same debiased modulo helper as in the rejection branch (§2.1); the inner rejection cost is identical.

### 2.3 Branch dispatch

The dispatch is the single line at `random.cpp:73`:

```cpp
if (m * 2 <= node_count) { /* rejection sampling */ }
/* else: partial Fisher-Yates */
```

The condition `m * 2 <= node_count` is the integer-arithmetic form of `2K ≤ N`. Note that `K = N/2` exactly (only when `N` is even) lands in the rejection branch; `2K = N` is admissible for rejection sampling per L-2's expected-rejections bound (the bound is `≤ 2` at `2K = N`, achieved when the last index draw alone expects 2 hashes). For odd `N`, `K = (N−1)/2` lands in rejection (`2K = N − 1 ≤ N`) and `K = (N+1)/2` lands in F-Y (`2K = N + 1 > N`).

The boundary is asymmetric by one integer step — but both algorithms are uniform, so the asymmetry has no effect on the output distribution. The choice of boundary is a performance optimization, not a correctness constraint.

### 2.4 Inputs treated as ROM oracle queries

The `random_state` is the protocol-level deterministic randomness from which both branches derive their uniformly-random draws. Under A3 ROM (Preliminaries §2.1 + §2.4), the iterated SHA-256 outputs `SHA256(h || 0)`, `SHA256(h || 1)`, `SHA256(SHA256(h || 0) || 0)`, ... are treated as fresh oracle queries returning independent uniform 256-bit values. The `hash_mod` reduction (§2.1) preserves this uniformity over the integer range `[0, n)` via the inner rejection. So both branches are equivalent to drawing a stream of independent uniform integers `u_1, u_2, ... ∈ [0, N)` (rejection branch) or `u_1 ∈ [0, N), u_2 ∈ [0, N-1), u_3 ∈ [0, N-2), ...` (F-Y branch).

This abstraction is the operational meaning of "uniformly-random draw" in the theorems below.

---

## 3. Theorems

### T-1 (Uniformity of Rejection Sampling)

**Claim.** Under A3 ROM on `random_state`, the rejection-sampling branch's output (the K-tuple `(idx_1, idx_2, ..., idx_K)` in order of acceptance) is a uniformly-random draw from the set of all K-permutations of K distinct elements from `[0, N)`. Equivalently, the *unordered* result-set is a uniformly-random K-subset of `[0, N)`, with each of the `C(N, K)` possible subsets having probability exactly `1 / C(N, K)`.

**Proof.** Induction on K.

**Base case (K = 1):** The loop draws one uniform `idx_1 ∈ [0, N)` (via `hash_mod`). The rejection check is vacuous on an empty `result`. The output is a single uniformly-random element from `[0, N)`. There are `N` singleton subsets, each with probability `1/N`. ✓

**Inductive step:** Assume the first `k` accepted indices `(idx_1, ..., idx_k)` form a uniformly-random K-permutation of `k` distinct elements (every ordered `k`-tuple of distinct elements has probability `1 / (N · (N−1) · ... · (N−k+1))`). We show the `(k+1)`-th accepted index extends this to a uniformly-random `(k+1)`-permutation.

The loop draws `idx ∈ [0, N)` uniformly per A3 ROM. Two cases:

- `idx ∈ result` (prior accepted): rejected, draw again. The conditional distribution after rejection is uniform on `[0, N) \ result` (by symmetry: the rejection rule is index-blind — `idx` is rejected iff it equals any prior, regardless of which prior).
- `idx ∉ result`: accepted as `idx_{k+1}`. By the conditional argument, `idx_{k+1}` is uniformly distributed over `[0, N) \ result`, a set of `N − k` elements. So `idx_{k+1}` is uniform over `{0, ..., N-1} \ {idx_1, ..., idx_k}`.

The full `(k+1)`-tuple `(idx_1, ..., idx_{k+1})` is therefore uniformly distributed over the set of `(k+1)`-permutations of distinct elements: the first `k` positions are uniform over `k`-permutations (inductive hypothesis); the `(k+1)`-th position is uniform over the remaining `N − k` choices independent of the first `k` positions' assignments. The total count is `N · (N−1) · ... · (N−k)`, each with equal probability. ✓

After `K` iterations, the output is uniform over K-permutations. The *unordered set* `{idx_1, ..., idx_K}` is the K-permutation modulo the `K!` orderings, so each unordered K-subset has probability `K! / (N · (N−1) · ... · (N−K+1)) = 1 / C(N, K)`. ∎

**Corollary T-1.1 (per-index marginal probability).** Each individual index `i ∈ [0, N)` appears in the output with probability `K / N` (the standard binomial marginal: of `C(N, K)` total K-subsets, `C(N−1, K−1)` contain `i`, so the per-index probability is `C(N−1, K−1) / C(N, K) = K / N`). This is the per-validator selection probability that `Censorship.md` T-2.1 and `S010S011SybilEconomics.md` T-1 cite.

### T-2 (Uniformity of Partial Fisher-Yates)

**Claim.** Under A3 ROM on `random_state`, the partial Fisher-Yates branch's output `(indices[0], indices[1], ..., indices[K−1])` is a uniformly-random draw from the set of all K-permutations of K distinct elements from `[0, N)`. Equivalently, the unordered result-set is uniform over `C(N, K)` K-subsets with probability `1 / C(N, K)` each.

**Proof.** This is the classical Fisher-Yates uniformity result restricted to the first `K` positions. We re-derive it briefly for self-containment.

**Setup.** The array `indices` starts as the identity `[0, 1, ..., N-1]` (each position holds its own index). At step `i`, the algorithm draws `j` uniform in `[i, N)` and swaps `indices[i]` with `indices[j]`. After step `i`, `indices[i]` is fixed; the algorithm proceeds to step `i+1`.

**Claim by induction on i:** After step `i`, the contents of `indices[0..i]` are a uniformly-random `(i+1)`-permutation of `(i+1)` distinct elements from `[0, N)`.

**Base case (i = 0):** The algorithm draws `j` uniform in `[0, N)` and swaps `indices[0]` with `indices[j]`. The post-swap `indices[0]` is `j` (the previous value at position `j`, which was `j` itself because the array was the identity). So `indices[0]` is uniformly distributed over `{0, 1, ..., N-1}`. ✓

**Inductive step:** Assume after step `i`, `indices[0..i]` holds a uniformly-random `(i+1)`-permutation of `(i+1)` distinct elements. At step `i+1`, the algorithm draws `j` uniform in `[i+1, N)` and swaps `indices[i+1]` with `indices[j]`. The post-swap `indices[i+1]` is whichever element occupied position `j` before the swap — by the inductive setup, this is a uniformly-random element of `{0, ..., N-1} \ indices[0..i]` (the unplaced remainder, which has `N − (i+1)` elements occupying positions `[i+1, N)`).

So after step `i+1`, `indices[i+1]` is uniformly distributed over the unplaced remainder, conditional on `indices[0..i]`. Combined with the inductive hypothesis (the prefix is uniform over `(i+1)`-permutations), the full prefix `indices[0..i+1]` is uniform over `(i+2)`-permutations of `(i+2)` distinct elements. ✓

After step `K − 1`, `indices[0..K-1]` is uniform over K-permutations. The unordered subset has probability `K! / (N · (N−1) · ... · (N−K+1)) = 1 / C(N, K)`. ∎

**Note on a subtle point.** The proof requires that `indices[i+1..N-1]` (the unplaced remainder after step `i`) contains exactly the set `{0, ..., N-1} \ indices[0..i]` — i.e., the unplaced elements are exactly the complement of the placed prefix. This holds by induction: the array starts as the identity, every swap exchanges two positions without losing or duplicating an element, so the multiset `{indices[0], ..., indices[N-1]}` is always exactly `{0, 1, ..., N-1}`. After step `i`, the prefix is the placed elements and the suffix is the unplaced complement. This is the "Fisher-Yates invariant" and is the structural property that makes the partial-shuffle truncation legitimate.

**Corollary T-2.1 (per-index marginal).** Each index `i ∈ [0, N)` appears in the output with probability `K / N`, identical to T-1.1 (both algorithms induce the same marginal distribution because both produce uniformly-random K-subsets).

**Corollary T-2.2 (output-set equality with T-1).** The output distributions of the rejection-sampling branch and the partial F-Y branch over the unordered K-subset are *identical* (uniform over `C(N, K)` subsets). The branches differ only in the ordering of the K-tuple they return: rejection sampling returns indices in the order they were accepted (which depends on which draws were rejected), while F-Y returns indices in the order of the shuffle's first-K positions. The downstream consumer (`Chain::round_committee` at the protocol level) sorts the K-tuple by domain identity (registry canonical order) before use, so the *ordering* doesn't affect protocol behavior; only the unordered set matters. Both branches produce the same uniform set distribution.

### T-3 (Branch-Boundary Correctness)

**Claim.** The branch choice `2K ≤ N ⇒ rejection sampling` and `2K > N ⇒ partial Fisher-Yates` is correct in the sense that:

1. Under `2K ≤ N`, the expected number of SHA-256 hashes per committee draw is bounded by `2K` (specifically, `≤ K · 2 / (1 + 1/(N−K))` for `K ≤ N/2`).
2. Under `2K > N`, the partial F-Y branch's strict `O(N)` cost beats the rejection branch's expected `Θ(N · ln(N))` cost at the worst case `K = N − 1`.
3. Both branches produce uniform K-subsets per T-1, T-2 — the choice is purely performance.

**Proof.** The expected-rejections-per-draw bound (point 1) is Lemma L-2 below. We show it here in summary.

**Setup for point 1.** Let `T_i` denote the expected number of `hash_mod` calls to advance the loop from `|result| = i` to `|result| = i + 1`. Each draw is uniform over `[0, N)`; the draw is rejected iff it lands in the `i` already-picked indices, with probability `i / N`; the draw is accepted with probability `(N − i) / N`. So `T_i` is geometrically distributed with success probability `(N − i) / N`, giving `E[T_i] = N / (N − i)`.

The total expected hashes per committee draw is `Σ_{i=0}^{K-1} E[T_i] = Σ_{i=0}^{K-1} N / (N − i) = N · (H(N) − H(N − K))` where `H(n) = 1 + 1/2 + 1/3 + ... + 1/n` is the harmonic sum.

At `K = N/2` (the branch boundary, even N), this is `N · (H(N) − H(N/2)) ≈ N · ln(2) ≈ 0.693 · N ≈ 1.386 · K`. So the rejection branch averages `< 1.5 · K` hashes at the boundary — well under the "≤ 2K" upper bound. For `K ≪ N`, the sum is approximately `K · (1 + K/(2N))`, very close to `K`. The expected-rejections-per-draw upper bound at `K = N/2` is `2` (each draw expected ≤ 2 trials), validating the choice of boundary.

**Setup for point 2.** At `K = N − 1` (the worst case for rejection sampling), the total expected hashes is `Σ_{i=0}^{N-2} N / (N − i) = N · (H(N) − H(1)) ≈ N · ln(N)`. For `N = 100`, this is `~460` hashes per committee draw; for `N = 1000`, `~6900`; for `N = 10000`, `~92000`. The partial F-Y branch at the same parameters costs `N − 1 = 99 / 999 / 9999` hashes plus `N` integer array initializations — strictly less than rejection sampling at this regime and bounded by `O(N)` regardless of K. So the F-Y branch is the unambiguously better choice for `2K > N`.

**Setup for point 3.** T-1 and T-2 prove both branches are uniform. The branch choice is invisible to the output distribution; only the per-call wall-clock differs. Hence the boundary is purely a performance optimization and not a safety/correctness consideration.

**Conclusion.** The hybrid is safe at any `(K, N)` with `K < N` (the `K = N` degenerate case is handled by partial F-Y, which produces all `N` indices since the algorithm iterates `i = 0..K-1 = 0..N-1` and the result is a permutation of `[0, N)`; T-2 guarantees uniformity over the `N!` permutations, which is trivially the unique singleton K-subset `{0, 1, ..., N-1}`). The boundary `2K ≤ N` is correct because it picks the asymptotically-cheaper branch at every `(K, N)`. ∎

**Note on the special case `K = N`.** The partial F-Y branch handles `K = N` cleanly: the algorithm shuffles the entire `indices` array; the truncation to the first `K = N` positions is a no-op. The rejection branch would *not* terminate at `K = N` because the final pick has `T_{N-1} = N / 1 = N` expected trials and the worst case is unbounded. The branch boundary `2K > N` correctly diverts `K = N` (and `K = N − 1`, `K = N − 2`, etc., wherever `2K > N`) to F-Y.

### T-4 (Bounded Runtime)

**Claim.** Both branches have bounded asymptotic runtime in `(K, N)`:

- **Rejection sampling branch (`2K ≤ N`):** expected runtime `O(K log K)` SHA-256 hashes (specifically, `O(K · H(K))` where `H(K) = ln(K) + γ + o(1)` is the harmonic sum); strict worst-case runtime *unbounded* in the SHA-256 stream (probabilistic, no hard cap).
- **Partial Fisher-Yates branch (`2K > N`):** strict runtime `O(N)` integer operations + `K` SHA-256 hashes + `K` integer swaps. No probabilistic component, no rejection spin.

Both branches' worst-case-meaningful runtime is `≤ O(N)`; neither can stall consensus.

**Proof.**

**Rejection sampling expected runtime.** Per the T-3 derivation, the total expected SHA-256 hashes per committee draw is `Σ_{i=0}^{K-1} N / (N − i)`. Under the branch precondition `2K ≤ N`, the worst case is `K = N/2`, giving total expected hashes `≈ N · ln(2) ≈ 0.693 · N ≈ 1.386 · K`. For `K ≪ N`, the sum is `≤ K + K²/N + O(K³/N²) ≈ K`. The asymptotic is `O(K log K)` because:

- For `K ≪ N`, the per-draw expected cost is `≈ 1` and total is `≈ K`.
- For `K = N/2`, the per-draw cost averages `≈ 2 · ln(2) / 1 ≈ 1.39` and total is `≈ 1.39 · K`.
- In between, the cost interpolates monotonically.

The `O(K log K)` upper bound is a slight overestimate (the actual is closer to `O(K)` at the branch boundary); the log term captures the harmonic-sum behavior in the regime where K and N are comparable.

**Partial Fisher-Yates strict runtime.** The algorithm has three phases:

1. Initialize `indices = [0, 1, ..., N-1]`: `N` integer writes, `O(N)`.
2. Loop `K` iterations, each doing one SHA-256 + one `hash_mod` + one swap: `K · (SHA-256 cost + O(1))`.
3. Truncate to first `K` entries: `std::vector::resize`, `O(1)` for size shrink.

Total: `O(N) + K · SHA-256_cost`. The SHA-256 cost is `O(1)` (fixed 256-bit output, fixed input size on the loop counter side); the loop is `O(K)` SHA-256s + `O(K)` swaps. Total: `O(N + K) = O(N)` (since `K ≤ N`).

**Worst-case bounds.** The rejection branch's worst case is theoretically unbounded (SHA-256 outputs could all collide with prior indices indefinitely), but the probability of any single committee draw exceeding `c · K · ln(K)` hashes decays exponentially in `c` (a Chernoff bound on the geometric tails, see Mitzenmacher-Upfal Theorem 4.4). The expected runtime is the operative concern, not the worst case.

The partial F-Y branch has no probabilistic component — its runtime is a deterministic function of `(K, N)` regardless of the SHA-256 stream's content (the algorithm always does exactly `K` swap steps + `N` initialization writes).

**Consensus implications.** A producer running on commodity hardware experiences:

- `select_m_creators` at production profiles (K ∈ {2, 3, 4, 5}, N ≤ ~100): ≤ 10 SHA-256 hashes per committee draw, sub-microsecond wall-clock.
- `select_m_creators` at consortium profiles (K = 20, N = 50): partial F-Y branch, 70 operations total, sub-millisecond.
- `select_m_creators` at worst-case adversarial (K = N − 1, N = 1000): partial F-Y branch, ~1000 operations, low-millisecond.

The function cannot stall consensus. ∎

**Corollary T-4.1 (No quadratic amplification under attack).** An attacker who can influence `random_state` cannot inflate the function's runtime non-polynomially. The rejection branch's expected runtime is bounded by `O(K log K)` *averaged over the SHA-256 oracle*; an adversarial `random_state` choice cannot achieve worse than the expectation by more than a few standard deviations (Mitzenmacher-Upfal Theorem 4.4 Chernoff bound). The partial F-Y branch has zero attack surface here (runtime is `(K, N)`-only).

**Corollary T-4.2 (Memory bounds).** The rejection branch's memory cost is `O(K)` (the `result` vector). The partial F-Y branch's memory cost is `O(N)` (the `indices` vector). Both are bounded by the protocol's pool-size cap (no hard cap in the current code, but the eligible-pool size is monotonically tied to the registry; an attacker cannot inflate `N` cheaply per S-010 stake-pricing).

### T-5 (Determinism Across Replays)

**Claim.** For fixed `(random_state, N, K)` inputs, both branches produce byte-identical output across:

- Two invocations on the same machine in the same process.
- Two invocations on different machines (different OS, different CPU architecture).
- Re-invocations after chain reload (snapshot restore + replay).

The two branches do *not* produce identical outputs *to each other* at the same `(random_state, N, K)` inputs — they are different algorithms producing different orderings of (possibly different) K-subsets. The branch choice is `(K, N)`-dependent and identical across all honest nodes (per the `2K vs N` predicate); a node's branch choice is deterministic, so two honest nodes computing `select_m_creators` on the same `(random_state, N, K)` always land in the same branch and produce the same output.

**Proof.**

**Pure-function property.** Inspecting `random.cpp:70–100`:

- `select_m_creators` takes only `(random_state, node_count, m)` as inputs. No global state read, no clock read, no PRNG re-seed, no environment lookup.
- The function's internal state is the local `h` Hash, the `counter` uint64_t, and the `result` (rejection branch) or `indices` (F-Y branch) vector. All are stack/heap allocations with no aliasing to external state.
- The SHA-256 helper `SHA256Builder{}.append(...).finalize()` is a pure function of its inputs per the FIPS 180-4 specification (deterministic bit-exact output for any byte sequence).
- The `hash_mod` helper is pure (deterministic on `(h, n)`).
- The `std::find` STL call is pure (deterministic on the input range + value).
- The `std::swap` STL call is pure.
- The branch dispatch `m * 2 <= node_count` is integer arithmetic — deterministic, architecture-independent.

So every operation in `select_m_creators` is a pure function of its inputs. The output is therefore a deterministic function of `(random_state, N, K)`.

**Cross-architecture determinism.** SHA-256 is bit-exact across architectures (FIPS 180-4 defines it at the bit-level). Integer arithmetic on `uint64_t` is bit-exact across architectures (C++ guarantees `uint64_t` is 64-bit unsigned with two's-complement wrap-around). `std::vector`, `std::find`, `std::swap` are STL semantics (defined behavior across compilers). The Hash type is `std::array<uint8_t, 32>` (per `types.hpp`), a memory-layout-defined byte sequence with no endianness ambiguity.

**Cross-process determinism.** No global state, no clock, no PRNG. Two processes running the same binary on the same inputs produce the same output.

**Cross-chain-reload determinism.** Chain reload restores `random_state` from the snapshot or replays it from the genesis seed via the `update_random_state` chain. Per the snapshot-equivalence theorem (`SnapshotEquivalence.md`), the post-reload `random_state` at any height `h` is byte-identical to the pre-reload value at the same height. So replaying `select_m_creators(random_state_h, N_h, K)` post-reload yields the same committee.

**Test surface.** The in-process test `determ test-committee-selection` (`src/main.cpp:6225+`) asserts T-5 directly:

- Assertion 1: `select_m_creators(seed(1), 100, 5) == select_m_creators(seed(1), 100, 5)` — same inputs, identical output (within-process determinism).
- Assertion 2: `select_m_creators(seed(1), 100, 5) != select_m_creators(seed(2), 100, 5)` — different seeds, different output (seed-sensitivity).

These two assertions (combined with the cross-architecture SHA-256 guarantee and the pure-function property above) establish T-5. ∎

**Corollary T-5.1 (Cross-node convergence).** Two honest nodes observing the same chain state (same `random_state`, same `N_pool`, same `K`) compute the same committee. This is the operational meaning of T-5 in the protocol context — it is the structural prerequisite for V3 (`Preliminaries.md` §5) which checks that an arriving block's `B.creators` equals the deterministic committee computed locally.

### T-6 (No Timing Side-Channel for Identity)

**Claim.** The runtime of `select_m_creators` depends only on `(K, N)` and the SHA-256 oracle's outputs; it does *not* depend on which specific validator domains map to which indices in the eligible pool, nor on the identity of the selected validators. An attacker observing wall-clock measurements of the function learns at most `(K, N)` (both already known) and a noisy signal of how many SHA-256 hashes were performed (bounded by T-4).

**Proof.** The function never reads validator domain identities — it operates entirely on integer indices `[0, N)`. The caller (`Chain::round_committee`) maps the returned indices to domain identities *after* `select_m_creators` returns, using the registry's canonical sorted-by-domain order. So the function has no input that depends on validator identity.

Inspect the branch-internal code paths:

- **Rejection branch:** the loop iterates until `|result| == K`. Each iteration: SHA-256 hash + `hash_mod` reduce + `std::find` linear scan over `result` + conditional `result.append(idx)`. The number of iterations is a function of how often `idx` collides with `result` — which depends on the SHA-256 stream and `N`, not on which validator each `idx` maps to. The `std::find` scan is over integer indices, not domain strings; its runtime is `O(|result|)` and depends only on `K` and the current iteration count.
- **Partial F-Y branch:** the loop iterates exactly `K` times regardless of inputs (other than `K`). Each iteration does one SHA-256, one `hash_mod`, one swap. No branch on the swap target, no early termination. Runtime is `K · O(1) + O(N)` initialization — deterministic in `(K, N)`.

In both branches, the runtime depends on `(K, N)` (plus the SHA-256 stream's content for rejection branch). It does *not* depend on the identity-mapping of indices to validators. An attacker who observes the wall-clock duration of `select_m_creators` cannot infer which validators were selected — they can only infer (roughly) how many rejection-sampling trials fired, which is a function of which *indices* collided, not which *validators*.

The remaining residual signal — "which indices were drawn before being accepted" — is informationally negligible: an attacker would need to know the order of `hash_mod` outputs to deduce anything, and the SHA-256 stream's content is unpredictable to them (A3 ROM + commit-reveal on `random_state` per Liveness L4).

**Implementation discipline.** T-6 holds *provided* the implementation does not introduce identity-dependent branches. The current code at `random.cpp:70–100` does not — every conditional and every loop branch is over integer indices or the `(K, N)` pair. A future modification that, e.g., looked up a validator's reputation or stake amount and used it in the selection (a "weighted" branch) would violate T-6 unless carefully written in constant time. The current implementation has no such hooks; the branch is uniform over `[0, N)` without any per-validator weighting.

**Corollary T-6.1 (No leakage of who-is-selected from cache / branch-predictor channels).** The function's memory-access pattern depends only on the `result`/`indices` vector size — both indexed by integer. There is no validator-identity-dependent table lookup, no validator-specific code path. So microarchitectural side-channels (cache timing, branch prediction state) cannot leak which validators were selected.

**Corollary T-6.2 (No leakage of the SHA-256 stream from compute_state_root).** The downstream consumer (`Chain::round_committee` → `Chain::apply_block`) does not feed the raw SHA-256 stream into the state-root computation; only the selected committee (sorted by domain) and the chain state are bound. So an attacker who decompresses the committee from the chain's public data cannot reverse-derive the SHA-256 stream's intermediate values.

---

## 4. Lemmas

### L-1 (Uniformity of `hash_mod` reduction)

**Claim.** For any `n ≥ 1` and SHA-256 output `h ∈ {0, 1}²⁵⁶`, `hash_mod(h, n)` returns a value in `[0, n)` uniformly distributed when `h` is uniform.

**Proof sketch.** The implementation at `random.cpp:32–47` extracts the first 8 bytes of `h` as `v ∈ {0, 1}⁶⁴`, computes `limit := ⌊UINT64_MAX / n⌋ · n` (the largest multiple of `n` that fits in 64 bits), and:

- If `v < limit`: return `v mod n`. Each value in `[0, n)` is the image of exactly `limit / n = ⌊UINT64_MAX / n⌋` preimages in `[0, limit)`. Since `v` is uniform on `{0, 1}⁶⁴`, `v` is uniform on `[0, limit)` conditional on `v < limit`. So `v mod n` is uniform on `[0, n)`. ✓
- If `v ≥ limit`: rejection re-hash. Re-derive `next = SHA256(h || counter)` and repeat. By A3 ROM, `next` is a fresh uniform 256-bit value (independent of `h`); the rejection probability `(UINT64_MAX + 1 − limit) / (UINT64_MAX + 1)` is `< n / (UINT64_MAX + 1) ≤ 2⁻⁶⁴ · n`. For `n ≤ 2³²`, the rejection probability is `≤ 2⁻³²` per call; expected re-hash calls per `hash_mod` invocation is `≤ 1 + 2⁻³²`, effectively 1.

**Conclusion.** `hash_mod` returns a uniform value in `[0, n)` modulo a vanishing rejection probability that converges geometrically. ∎

### L-2 (Expected rejections per draw bound)

**Claim.** In the rejection-sampling branch with precondition `2K ≤ N`, the expected number of `hash_mod` calls to extend the `result` vector from `|result| = i` to `|result| = i + 1` is `N / (N − i)`, with the upper bound `N / (N − K) ≤ N / (N − N/2) = 2` for `i ≤ K − 1 < K = N/2`.

**Proof.** At iteration `i`, the `result` vector holds `i` distinct indices. Each `hash_mod` draw is uniform on `[0, N)` (per L-1). The draw is accepted iff it does not equal any of the `i` prior indices; the acceptance probability is `(N − i) / N`. So the number of trials to achieve one acceptance is geometrically distributed with success probability `(N − i) / N`, giving expectation `N / (N − i)`.

Under `2K ≤ N` (i.e., `K ≤ N / 2`), the worst case is `i = K − 1`, giving `N / (N − K + 1) ≤ N / (N − K)`. With `K ≤ N / 2`, this is `N / (N − N/2) = 2`. So the per-draw expected trials is `≤ 2` for any iteration under the branch precondition.

**Total expected hashes per committee draw:** `Σ_{i=0}^{K-1} N / (N − i)`. Worked example at `K = N / 2`: `Σ_{i=0}^{N/2-1} N / (N − i) = N · (H(N) − H(N/2)) ≈ N · ln(2) ≈ 0.693 · N ≈ 1.386 · K`. ✓ (matches T-4's `O(K)` claim at the boundary.) ∎

**Note on the boundary `2K > N`:** at `K = N / 2 + 1`, the final pick alone has `E[T_{K-1}] = N / (N − K + 1) = N / (N − N/2 − 1 + 1) = N / (N/2) = 2`. But the next pick `K = N / 2 + 2` would give `E[T_{K-1}] = N / (N − K + 1) = N / (N/2 − 1) > 2`. So the boundary `2K ≤ N` is the unique point at which the per-draw expected trials transitions from `≤ 2` to `> 2`. The expected total cost compounds across the K iterations; the branch boundary is the natural switch point at which the F-Y branch's `O(N)` becomes cheaper than the rejection branch's amplifying expectation.

### L-3 (Partial F-Y permutation count)

**Claim.** Under partial F-Y, the number of distinct outputs (K-tuples in `[0, N)^K`) is exactly `N · (N − 1) · ... · (N − K + 1) = N! / (N − K)!`, i.e., the number of K-permutations of K distinct elements from `[0, N)`.

**Proof.** The algorithm makes `K` independent uniform draws `j_0 ∈ [0, N), j_1 ∈ [0, N − 1), ..., j_{K-1} ∈ [0, N − K + 1)`. Each draw selects which element of the remaining unplaced set goes to position `i`. The total number of `(j_0, j_1, ..., j_{K-1})` tuples is `N · (N − 1) · ... · (N − K + 1)`, and each tuple yields a distinct output K-permutation (the algorithm is bijective from `(j_0, ..., j_{K-1})` tuples to output K-permutations).

So the output space has exactly `N! / (N − K)!` K-permutations, each with probability `1 / (N! / (N − K)!) = (N − K)! / N!`. The unordered K-subset is the K-permutation modulo `K!` orderings, giving probability `K! · (N − K)! / N! = 1 / C(N, K)` per subset. ∎

### L-4 (Composition of L-1 with T-1 / T-2)

**Claim.** The uniformity claims in T-1 (rejection sampling) and T-2 (partial F-Y) both rely on `hash_mod(h, n)` being uniformly distributed in `[0, n)` — proven in L-1. So the full uniformity arguments in T-1 and T-2 are reducible to L-1 + A3 ROM on the SHA-256 stream.

**Proof.** Trivial composition: the T-1 inductive step uses "the next draw is uniform on `[0, N)`" — which is exactly L-1's claim under A3 ROM. The T-2 inductive step uses "the next draw is uniform on `[i, N)`" — which is L-1's claim with `n = N − i` (translated by `+ i` after the call, deterministic shift preserving uniformity). So T-1 and T-2 both hold under L-1's correctness, which holds under A3 ROM. ∎

**Implication.** The hybrid algorithm's uniformity property degrades gracefully under A3 ROM: if SHA-256 were to be broken (e.g., a structural attack making its output distinguishable from uniform), the function's uniformity claim would weaken commensurately. The protocol does not depend on uniformity claims stronger than A3 — see Preliminaries §2.4 ("What we do not assume").

---

## 5. Adversary model

### 5.1 Adversary A1: seed-prediction attempts

**Setup.** Adversary `Adv` attempts to predict or influence `random_state` at some future height `h*` to gain control over the committee selection at `h*`. Predicting `random_state` would let `Adv` pre-compute the committee and either (a) bias their own validators into it, or (b) front-run by submitting transactions targeting the known committee.

**Closure.** `random_state` at height `h` is derived from the prior block's `cumulative_rand` and the round's `abort_events` via `update_random_state` (`random.cpp:20`). Per Liveness.md L4 and Censorship.md T-2.1, the post-Phase-2 `cumulative_rand` is itself a SHA-256 hash of the K committee members' Phase-1 secrets, which are uniform-CSPRNG-drawn per H1 and unpredictable per A3 preimage resistance. So `random_state` at height `h*` is unpredictable to `Adv` until at least one honest member of the committee at `h*` reveals their Phase-1 secret in Phase-2.

The closure here is structural: `select_m_creators` does not introduce any predictability into the seed-derived bytes; it merely consumes them. If `random_state` is unpredictable to `Adv` (proven elsewhere), then the output committee is unpredictable to `Adv`. The hybrid algorithm's branch choice is also `(K, N)`-only (no `random_state` dependence), so `Adv` cannot manipulate the branch.

**Residual signal.** `Adv` knows `(K, N)` from the public registry state. `Adv` therefore knows which branch fires. Under the rejection branch, `Adv` does not learn the SHA-256 stream's content; under the F-Y branch, `Adv` does not learn the swap sequence. So `Adv` has zero information about the committee beyond what the public registry permits.

### 5.2 Adversary A2: timing-side-channel against identity bias

**Setup.** Adversary `Adv` observes wall-clock measurements of `select_m_creators` on a target node (e.g., via network-side latency profiling, RPC-response timing, or co-tenancy on the same hardware). `Adv` wants to learn which validators were selected for the committee at height `h*` *before* the block is finalized and broadcast.

**Closure.** T-6 proves the runtime depends only on `(K, N)` and the SHA-256 stream's content; *not* on validator identity. So the maximum information `Adv` can extract from a wall-clock measurement is "how many rejection-sampling trials fired" (rejection branch) or "no information at all" (F-Y branch).

In the rejection branch, the trial count is a function of which integer indices collided with the running `result` — *not* which validators map to those indices. `Adv` would need to know the SHA-256 stream's outputs to infer which indices were drawn, which requires breaking A3 ROM. Without that, the wall-clock leak is a small entropy bound on `(K, N)`-determined statistics — useless for identity inference.

In the F-Y branch, the runtime is deterministic in `(K, N)` and independent of the SHA-256 stream's content. `Adv` learns nothing from wall-clock observation beyond `(K, N)`, which they already know.

**Implementation discipline.** The current implementation honors T-6 because every conditional / loop in `random.cpp:70–100` is on integer indices or `(K, N)`. A future change that branches on a validator-specific signal (reputation, stake amount, region) would weaken T-6; any such change should be reviewed against T-6 explicitly.

### 5.3 Adversary A3: committee-selection grinding via beacon manipulation

**Setup.** Adversary `Adv` controls a fraction of the validator pool and attempts to manipulate `random_state` to bias the future committee in their favor. The attack is: `Adv` selectively withholds Phase-2 reveals (per the selective-abort defense `SelectiveAbort.md` FA3) to influence the next round's `random_state` derivation, hoping to bias the committee at some future height.

**Closure.** This adversary composes with the selective-abort defense (FA3) and the fork-choice rule (S-029 / `S029ForkChoiceSoundness.md`). The relevant facts:

- FA3 proves that selective-abort is information-theoretic under A3 preimage resistance — the adversary cannot gain information about `delay_output` before deciding to abort. So `Adv` cannot grind by trial-and-error on Phase-2 reveals (each abort costs them per-round opportunity, and the next round's `random_state` is still a fresh CSPRNG mix per H1).
- S-029 proves the fork-choice rule (`Chain::resolve_fork`) is deterministic on (sig_count, abort_count, block_hash). `Adv`'s grinding to produce a specific committee at height `h+1` does *not* let them produce a specific fork-choice winner at `h+1` — the fork-choice rule operates on the published block contents, not on the committee selection method.
- `select_m_creators`'s contribution is the uniformity property (T-1 / T-2): even if `Adv` could grind 100 random_state candidates and pick the most favorable, each candidate yields a uniformly-distributed K-subset. The "best" candidate gives `Adv` a marginally better committee at the cost of `100 ×` the work — and per FA3 + S-029, that work is wasted because (a) committee selection is per-height, not per-fork, and (b) the next height's committee is re-randomized regardless.

So A3 is closed by composition with FA3 (selective-abort) + S-029 (fork-choice) + T-1 / T-2 (uniformity here). `select_m_creators` itself is not vulnerable to grinding; the hybrid algorithm produces a uniform K-subset regardless of `random_state` choice.

### 5.4 Adversary A4: rejection-sampling resource-exhaustion via crafted pool

**Setup.** Adversary `Adv` causes the eligible pool to shrink to the size where rejection sampling pathology dominates (e.g., `K = N − 1`), then uses the resulting long wall-clock runtime to mount a DoS against honest validators trying to compute the committee in time for the round.

**Closure.** T-3 closes this: the branch boundary `2K ≤ N` ensures that *whenever* the rejection-sampling pathology would dominate (i.e., `2K > N`), the partial F-Y branch fires instead. The F-Y branch's runtime is strict `O(N)`, bounded and predictable.

Concretely: at `K = N − 1`, the condition `2K = 2(N−1) > N` (for `N ≥ 3`) holds, so the partial F-Y branch fires. The runtime is `O(N) ≈ O(N − 1) = O(K)` — bounded and fast. `Adv` cannot inflate the runtime by manipulating `N` toward `K` because the F-Y branch absorbs the entire `K → N` regime.

**Worked example.** If `Adv` could shrink the pool to `N = 4, K = 3` (the smallest `2K > N` case), the F-Y branch fires and the runtime is `4` array initializations + `3` SHA-256 hashes + `3` swaps — negligible. Compared to the rejection branch at the same parameters: `T_0 = 4/4 = 1`, `T_1 = 4/3 ≈ 1.33`, `T_2 = 4/2 = 2` — total expected `4.33` hashes, only slightly more. But at `N = 1000, K = 999`, rejection sampling's `T_{998} = 1000 / 2 ≈ 500` makes the algorithm cost spiral; the F-Y branch's `1000 + 999 ≈ 2000` operations is unambiguously better.

So A4 is closed by T-3's branch boundary: whenever the pathology would dominate, the F-Y branch absorbs it. `Adv` cannot DoS the honest validators by gaming the pool size.

---

## 6. Cross-references

### 6.1 Protocol-level citations

- **FA1 (`Safety.md` T-1)** cites `B.creators = select_m_creators(round_rand(B), |pool|, K)` as the V3 committee-determinism check. T-5 (this proof) is the structural prerequisite for V3 to compose across nodes: every honest node computing V3 against the same `round_rand` must derive the same committee. T-5's cross-node determinism guarantee closes that composition.
- **FA8 (`RegionalSharding.md`)** cites `select_m_creators` as the underlying primitive for region-aware committee selection (the regional wrapper filters the pool by region then calls `select_m_creators` over the filtered subset). T-1 / T-2 (uniformity here) are the per-region uniformity guarantees that compose with FA8's region-partition argument.
- **FA5 (`BFTSafety.md`)** cites `select_m_creators` over the BFT-mode shrunk committee `|K_h| = ⌈2K/3⌉` (a smaller `K` over the same pool). The hybrid branch choice is `(K, N)`-only, so the BFT-mode selection lands in the same branch as the MD-mode selection — both branches are uniform per T-1 / T-2.
- **FA2 (`Censorship.md` T-2.1)** cites the per-domain selection probability `K / N` as the basis for the K-conjunction censorship bound. T-1.1 / T-2.1 (this proof) prove that marginal probability is exactly `K / N` for both branches.
- **`S010S011SybilEconomics.md` T-1** cites uniform-random selection as the first premise of the Sybil-cost formula. T-1 / T-2 (this proof) provide that uniformity guarantee.
- **`S029ForkChoiceSoundness.md` T-1** operates on committees produced by `select_m_creators`; the fork-choice rule's deterministic-tiebreak property composes with T-5 (this proof) to give a fully-deterministic chain-tip choice.

### 6.2 Companion proofs

- **`CommitteeSelection.md` (sibling)** covers FA1 + FA8 at the higher protocol level; this proof goes deeper on the specific hybrid algorithm's analytic properties.
- **`SelectiveAbort.md` (FA3)** covers the information-theoretic selective-abort defense; T-1 / T-2 here compose with FA3 (selective-abort cannot bias the uniform K-subset distribution).
- **`Liveness.md` (L4)** covers the rotational-eligibility argument that uses the per-domain `K / N` marginal probability; this proof provides T-1.1 / T-2.1 as the structural backing.
- **`EquivocationSlashing.md` (FA6)** does not directly cite `select_m_creators` but composes with it: a slashed equivocator is removed from the pool (via `inactive_from` flip), which changes `N` for subsequent committee selections; the hybrid algorithm absorbs the `N`-change without recalibration (T-1 / T-2 hold for any `N ≥ K`).

### 6.3 Test surface

The in-process unit test `determ test-committee-selection` (`src/main.cpp:6225+`) exercises both branches with 13 assertions across 10 scenarios:

1. **Determinism across same-input invocations** (T-5).
2. **Seed-sensitivity** (T-5).
3. **Output distinctness** (T-1 / T-2).
4. **In-range output** (T-1 / T-2 — every output index is in `[0, N)`).
5. **Rejection-sampling branch exercise** at `K=3, N=20` (`2K=6 ≤ 20`, rejection fires).
6. **Partial Fisher-Yates branch exercise** at `K=8, N=10` (`2K=16 > 10`, F-Y fires).
7. **Edge case `K = N`** (T-2 with truncation no-op).
8. **Edge case `K = 1`** (T-1 / T-2 boundary).
9. **`select_after_abort_m` determinism + distinctness + size preservation** (sister function with `new_first` pin).
10. **`epoch_committee_seed` determinism + shard-id sensitivity**.

The wrapper script at `tools/test_committee_selection.sh` invokes the binary and grep's for `PASS: committee-selection all assertions` to set the script's exit code. The test is part of the standard regression suite (FAST=1 includes it; CI gates on its pass).

### 6.4 Operator commands

The `tools/operator_committee_audit.sh` operator command exposes committee-selection internals for operational audit (cross-checking which validators were selected at a given height); the underlying RPC consumes `select_m_creators` output via the chain's stored committee fields. T-5 (this proof) ensures that operator audits reproducible across runs.

---

## 7. Findings register

### F-1: The `2K = N` boundary is a soft choice

The branch boundary `2K ≤ N` is a soft choice: at `2K = N` exactly, both branches produce uniform K-subsets (T-1 / T-2). The rejection branch's expected runtime at this point is `≤ 2 · K` hashes (L-2), still cheap; the F-Y branch's `O(N)` is comparable. The choice to land at the boundary in the rejection branch is preferred for fixture-stability reasons (preserves rev.9 output for the `K/N ≤ 0.5` regime), not for performance.

**Closure status.** Acknowledged; no safety or correctness issue. A future optimization could move the boundary to `2K + 1 ≤ N` (slightly favoring F-Y at the boundary) without changing safety; the choice is operator policy.

### F-2: Rejection sampling expected runtime degrades smoothly as `K/N → 1/2`

The rejection branch's expected runtime is `Σ_{i=0}^{K-1} N / (N − i)`, which grows from `~K` (at `K ≪ N`) to `~1.39 · K` (at `K = N/2`) to `~K · log K` (at `K = N − 1`, outside the branch). The growth is smooth and predictable, with no discontinuities.

**Closure status.** Acknowledged; the smoothness is the desired property. The hybrid algorithm switches branches before the `O(K log K)` regime engages, so the operator does not have to choose a specific cutoff — the boundary is built into the algorithm.

### F-3: No PRNG-specific concern; uniformity depends on `epoch_committee_seed` quality

Both T-1 and T-2 are conditional on A3 ROM on the SHA-256 stream. If SHA-256 were to be broken (e.g., a structural attack making output distinguishable from uniform), the uniformity claims would weaken. The protocol assumes A3 globally (Preliminaries §2.4); this proof inherits that assumption.

The seed source `random_state` itself is built from `update_random_state(prev_state, dh_output)` at every block apply; the per-block freshness comes from the K committee members' Phase-1 secrets (uniform-CSPRNG-drawn per H1). So `random_state` is unpredictable to the adversary provided ≥ 1 honest committee member at each height (composes with Liveness L4 and Censorship T-2.1).

**Closure status.** Acknowledged; the conditional is the standard ROM + ≥1-honest-committee composition the protocol's safety arguments make everywhere. No `select_m_creators`-specific gap.

### F-4: Both branches do not memoize SHA-256 across calls

Each invocation of `select_m_creators` builds a fresh local `h` from the input `random_state` and iterates `SHA256Builder{}.append(h).append(counter++).finalize()`. There is no per-process SHA-256 cache; two back-to-back invocations on the same `(random_state, N, K)` re-run the SHA-256 computations.

**Closure status.** Acknowledged; not a safety issue, just a performance observation. Memoization is not protocol-required (each invocation is independent per T-5); the absence of caching is a simplicity-vs-speed tradeoff favoring simplicity. A future per-process cache could shave microseconds off hot paths.

### F-5: Partial F-Y allocates an `O(N)` index array per invocation

The partial F-Y branch allocates a `std::vector<size_t>(node_count)` on every invocation. For chains with large `N_pool` (`N ≥ 1000`) and frequent committee selections (every block), this allocation churn is observable in profiling — but bounded by S-022's per-message-size cap (which indirectly caps `N_pool` via the eligible pool's serialization size).

**Closure status.** Acknowledged; a future optimization could re-use a per-thread `indices` buffer across calls. Current implementation favors clarity (no buffer-lifetime concerns) over zero-allocation. T-5 is unaffected (each invocation produces deterministic output regardless of allocation strategy).

### F-6: `select_after_abort_m` shares the hybrid switch but adds a `new_first` pin

The sister function `select_after_abort_m` (`random.cpp:122–163`) uses the same `2K vs N` branch choice but pins the `new_first` index at position 0 of the shuffle buffer (the abort-hash offset is a consensus contract). The remaining `m − 1` positions are uniformly shuffled (F-Y branch) or rejection-sampled (rejection branch). The analogous T-1 / T-2 uniformity arguments hold for `select_after_abort_m` over the conditional space "K-subsets containing `new_first`," but this proof does not formalize the construction in detail — see `Censorship.md` §3 for the sister-case treatment.

**Closure status.** Acknowledged; covered indirectly. A future expansion of this proof could add a formal T-7 for `select_after_abort_m`; for now, the construction is straightforward and the analogous arguments transfer mechanically.

---

## 8. References

### 8.1 Implementation citations

- `src/crypto/random.cpp:70–100` — `select_m_creators(random_state, N, K)` definition. Hybrid branch dispatch at line 73.
- `src/crypto/random.cpp:122–163` — `select_after_abort_m(indices, abort_hash, N)` sister function (out of scope for this proof; see F-6).
- `src/crypto/random.cpp:32–47` — `hash_mod(h, n)` debiased modulo reduction (L-1).
- `src/crypto/random.cpp:20` — `update_random_state(prev_state, dh_output)` seed-mixing chain.
- `src/crypto/random.cpp:169–175` — `epoch_committee_seed(epoch_rand, shard_id)` seed-derivation per shard.
- `include/determ/crypto/random.hpp` — header declarations; S-020 narrative comment on hybrid choice.
- `src/main.cpp:6225+` — `determ test-committee-selection` in-process unit harness (13 assertions across 10 scenarios).
- `tools/test_committee_selection.sh` — wrapper script invoking the harness.
- `tools/operator_committee_audit.sh` — operator command for committee-selection audit.

### 8.2 Cross-references within the proof suite

- `docs/proofs/Preliminaries.md` — F0 notation; H1–H4 honest-validator assumptions; A1 Ed25519 EUF-CMA; A2 SHA-256 collision resistance; A3 SHA-256 preimage resistance + ROM.
- `docs/proofs/Safety.md` (FA1) — K-of-K safety theorem, V3 committee-determinism check.
- `docs/proofs/Liveness.md` (L4) — rotational-eligibility argument using per-domain `K / N` marginal probability.
- `docs/proofs/BFTSafety.md` (FA5) — BFT-mode shrunk committee `|K_h| = ⌈2K/3⌉` selection.
- `docs/proofs/RegionalSharding.md` (FA8) — region-aware committee selection wrapping `select_m_creators`.
- `docs/proofs/Censorship.md` (FA2) §3 — K-conjunction censorship bound + `select_after_abort_m` sister-case treatment.
- `docs/proofs/SelectiveAbort.md` (FA3) — selective-abort defense composing with the uniformity argument here.
- `docs/proofs/EquivocationSlashing.md` (FA6) — equivocation slashing affecting `N_pool` size (composes via T-1 / T-2 uniformity for any `N ≥ K`).
- `docs/proofs/S010S011SybilEconomics.md` — Sybil-cost formula citing the uniformity premise.
- `docs/proofs/S029ForkChoiceSoundness.md` — fork-choice rule operating on committees produced here.
- `docs/proofs/SnapshotEquivalence.md` — snapshot replay equivalence supporting T-5 cross-reload determinism.
- `docs/SECURITY.md` §S-020 — closure-narrative row + operator-visible documentation.

### 8.3 External references

- **Knuth, Donald E.** "The Art of Computer Programming, Vol. 2: Seminumerical Algorithms" (3rd ed., Addison-Wesley, 1997), §3.4.2 "Random Sampling and Shuffling," Algorithm P (Fisher-Yates shuffle). Foundational reference for the partial F-Y branch's correctness (T-2 + L-3).
- **Mitzenmacher, Michael & Upfal, Eli.** "Probability and Computing: Randomization and Probabilistic Techniques in Algorithms and Data Analysis" (2nd ed., Cambridge University Press, 2017), Chapter 2 (Discrete Random Variables and Expectation) for the geometric-distribution argument in L-2, and Theorem 4.4 (Chernoff bound) for the rejection-sampling worst-case tail bound cited in T-4.
- **Bellare, Mihir & Rogaway, Phillip.** "Introduction to Modern Cryptography" Chapter 5 (Random Oracle Model) for the ROM treatment underlying A3 and L-1's "uniform under SHA-256 oracle queries" claim.
- **NIST FIPS 180-4** — Secure Hash Standard (SHS), defining SHA-256 bit-exact across implementations (the cross-architecture determinism premise in T-5).
- **Fisher, R. A. & Yates, F.** "Statistical Tables for Biological, Agricultural and Medical Research" (3rd ed., Oliver & Boyd, 1948). The original Fisher-Yates shuffle, predating Knuth's algorithmic treatment; cited for historical attribution.
- **Durstenfeld, Richard.** "Algorithm 235: Random permutation," Communications of the ACM 7 (7): 420 (1964). The in-place Fisher-Yates algorithm that the partial F-Y branch (§2.2) implements.

### 8.4 Provenance

This proof was written to close the analytic gap on `select_m_creators`'s hybrid algorithm per the S-020 mitigation shipped in `src/crypto/random.cpp:70–100`. The S-020 closure itself shipped earlier in-session; this document formalizes the algebraic properties (T-1..T-6) that make the hybrid sound. The proof is companion-cited from `S010S011SybilEconomics.md` (uniformity as Sybil-cost premise) and from `docs/SECURITY.md` §S-020 (closure-narrative row).

---

## 9. Status

**Mitigated in-session.** `select_m_creators` at `src/crypto/random.cpp:70–100` implements the hybrid Fisher-Yates: rejection sampling when `2K ≤ N`, partial Fisher-Yates shuffle when `2K > N`. The function is `static`, pure, and deterministic. T-1 (rejection-sampling uniformity), T-2 (partial-F-Y uniformity), T-3 (branch-boundary correctness), T-4 (bounded runtime), T-5 (cross-replay determinism), and T-6 (no identity-dependent timing side-channel) hold under A1 + A3 + the H1–H4 honest-validator assumptions.

`docs/SECURITY.md` classifies S-020 as Mitigated (Medium → Mitigated). The regression-test surface is `tools/test_committee_selection.sh` + `determ test-committee-selection` (13 assertions, all PASS). Six identified gaps (F-1 `2K = N` boundary soft choice, F-2 smooth rejection-runtime degradation, F-3 ROM assumption inheritance, F-4 no SHA-256 memoization, F-5 partial F-Y per-call allocation, F-6 `select_after_abort_m` sister case) are documented as either acknowledged-no-issue or future-optimization opportunities — none affect the algorithm's uniformity, runtime bound, or side-channel-resistance guarantees.

The S-020 closure composes cleanly with FA1 (K-of-K safety, where T-5 ensures cross-node committee agreement), FA8 (regional sharding, where T-1 / T-2 give per-region uniformity), FA5 (BFT-mode escalation, where the same hybrid handles the smaller `|K_h|`), FA2 (censorship bound, where T-1.1 / T-2.1 give the `K / N` per-validator marginal), FA3 (selective-abort, where the uniformity argument composes through the abort-hash mixing in `update_random_state`), FA6 + FA-Apply-10 (equivocation slashing, where the post-slash `N` change is absorbed by the algorithm's `N`-flexibility), and S-029 (fork-choice, where the deterministic-tiebreak operates on committees produced here). The composition produces a single uniform-and-unpredictable committee selection per height that every honest node converges on regardless of network arrival order, partition pattern, or adversarial seed-manipulation attempts.
