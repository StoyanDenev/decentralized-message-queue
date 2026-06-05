# F2 view-reconciliation primitives — analytic invariants

> **⚠ Implementation status (corrected 2026-06-05).** The reconciliation
> *primitives* proven below (`compute_view_root` / `reconcile_union` /
> `reconcile_intersection`) and the validator-side passes
> (`validate_contrib_view_roots` V21–V24, `validate_view_reconciliation`
> V25–V26) **exist, are unit-tested (`determ test-view-root`), and are
> TLA-modeled (FB22) — but they are NOT yet wired into the live consensus
> path.** Verified against the current tree: `Node::start_contrib_phase`
> (`src/node/node.cpp`) calls `make_contrib` with NO view lists, so every
> shipped `ContribMsg` carries empty view lists + zero view-roots (the v1
> commit short-circuit fires); `compute_block_digest` (`src/node/producer.cpp`)
> binds none of the view roots; `validator.cpp` never calls
> `validate_view_reconciliation`; and the migration gate
> `v2_7_f2_active_from_height` (`include/determ/chain/genesis.hpp`) has **zero
> readers in `src/`**. The algebraic invariants below are therefore sound as a
> **specification** of the intended wiring (tracked as the S-016 / v2.7 F2
> closure), not a description of live behavior. The §6 claim that "S-030 D2 is
> consensus-layer complete via F2" is premature: S-030 D2 is closed only at the
> **apply layer** (S-033 `state_root` + S-038 producer wiring, which ARE
> shipped); the consensus-layer view-binding described here is the remaining
> open work. This banner is removed when sites 1–4 of the wiring land.

This document is the analytic companion to **FB22** (`docs/proofs/tla/F2ViewReconciliation.tla`). FB22 formalizes the v2.7 F2 view-reconciliation primitives + the validator-side passes V21..V26 in TLA+; the present document states and proves the same six algebraic invariants in plain prose, with line-by-line citations to the C++ implementation at `src/node/producer.cpp:335..496`.

The proof is short and structural. The three reconciliation primitives (`compute_view_root`, `reconcile_union`, `reconcile_intersection`) reduce to standard `std::set` semantics after the canonical-sort pre-step; the algebraic claims (monotonicity, anti-monotonicity, order-independence, idempotence, censorship-resistance lift, intersection-conservativeness) follow from set-theoretic axioms once the implementation's "set-coerce then deterministic-iterate" structure is made explicit. The proof exists so an external reviewer can confirm — without running TLC and without re-reading the C++ — that the validator's V25/V26 re-derivation produces exactly the canonical lists the producer commits to, regardless of which honest committee member assembled the block body.

**Companion documents:** `Preliminaries.md` (F0) for notation and the cryptographic assumptions A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision + 2nd-preimage resistance); `F2-SPEC.md` §Q1 + §Q3 + §Q5 for the design spec these primitives realize; `S030-D2-Analysis.md` for the surrounding D2-closure story (F2 is the consensus-layer half; S-033 + S-038 cover the apply-layer half); `MakeContribCommitmentBackwardCompat.md` for the paired Phase-1 commit-binding proof; `tla/F2ViewReconciliation.tla` (FB22) for the machine-checkable companion.

---

## 1. Theorem statements

**Setup.** Let `Hash := std::array<uint8_t, 32>` (`include/determ/types.hpp:15`) with its inherited lexicographic `operator<`. Let a *member list* `L_i ∈ List(Hash)` be a finite (possibly empty, possibly multi-occurrence) sequence of hash values — the i-th committee member's pool snapshot at Phase-1 commit time per F2-SPEC.md §Q2. Let `[L_1, …, L_K]` denote the K-vector of such member lists in producer-chosen order, as supplied to `reconcile_union` / `reconcile_intersection` at `src/node/producer.cpp:345` + `:357`. Let `set(L) := { h : h ∈ L }` denote the underlying set of a list (duplicates collapse). Write `U(L_1, …, L_K) := reconcile_union([L_1, …, L_K])` and `I(L_1, …, L_K) := reconcile_intersection([L_1, …, L_K])` for the two reconciliation outputs.

The six theorems below pin the algebraic contract that the consensus-layer F2 closure of S-030 D2 depends on. Each holds *unconditionally* (no probabilistic terms) because the primitives are pure-function set operations; the cryptographic content (collision-resistance of the Merkle root in `compute_view_root`) is folded into `MakeContribCommitmentBackwardCompat.md` and `Preliminaries.md` §2.1, and is invoked here only inside §5 (validator-pass composition).

**Theorem T-1 (UnionMonotonic).** For every K ≥ 0, member lists `L_1, …, L_K`, and any additional list `L_{K+1}`:

$$
U(L_1, \ldots, L_K) \;\subseteq\; U(L_1, \ldots, L_K, L_{K+1}).
$$

Adding any honest member's contribution to the committee never shrinks the union.

**Theorem T-2 (IntersectionAntiMonotonic).** For every K ≥ 1, member lists `L_1, …, L_K`, and any additional list `L_{K+1}`:

$$
I(L_1, \ldots, L_K, L_{K+1}) \;\subseteq\; I(L_1, \ldots, L_K).
$$

Adding any member's contribution (even an empty one) to the committee never grows the intersection.

**Theorem T-3 (OrderIndependent).** For every K ≥ 0, every permutation `π : {1, …, K} → {1, …, K}`, and every list-vector `[L_1, …, L_K]`:

$$
U(L_1, \ldots, L_K) = U(L_{\pi(1)}, \ldots, L_{\pi(K)}), \qquad
I(L_1, \ldots, L_K) = I(L_{\pi(1)}, \ldots, L_{\pi(K)}).
$$

The producer's choice of member ordering does not change the canonical lists every validator re-derives.

**Theorem T-4 (UnionIdempotent).** For every list `L` and every K ≥ 1:

$$
U(\underbrace{L, L, \ldots, L}_{K \text{ copies}}) = U(L) = \mathrm{set}(L)\text{ (as a canonically-sorted vector)}.
$$

Duplicate per-member contributions merge via set semantics, not multiset.

**Theorem T-5 (UnionCensorshipResistant — FA2 lift).** For every K ≥ 1, member lists `L_1, …, L_K`, every index `i ∈ {1, …, K}`, and every hash `h ∈ L_i`:

$$
h \in U(L_1, \ldots, L_K).
$$

A single honest committee member's observation is sufficient to land a hash in the reconciled union. This is the FA2 censorship-resistance contract lifted from the gossip layer (where one honest peer suffices for propagation) to the consensus view (where one honest committer suffices for inclusion).

**Theorem T-6 (IntersectionConservative).** For every K ≥ 1, member lists `L_1, …, L_K`, and every hash `h`:

$$
h \in I(L_1, \ldots, L_K) \;\iff\; \forall j \in \{1, \ldots, K\} : h \in L_j.
$$

A hash appears in the reconciled intersection if and only if every committee member's list contains it. One bad relayer cannot unilaterally cause a credit-bearing inclusion.

---

## 2. Background

### 2.1 F2-SPEC.md §Q1 — heterogeneous per-field reconciliation rules

F2 closes the consensus-layer view of S-030 D2 by adding three pool-fed fields to the K-of-K Phase-2 signature surface: `equivocation_events`, `abort_events`, and `inbound_receipts`. F2-SPEC.md §Q1 records the design decision that these three fields use *different* reconciliation rules:

- **Union** for `equivocation_events` and `abort_events`. Slashing-bearing and abort-bearing fields are individually-verifiable (V11 + V10 per `Preliminaries.md` §5), so any single honest committee member's observation is enough to land the evidence. The cost of "extra" inclusion is bounded — the validator rejects any invalid event regardless of how many members witnessed it. This is the **censorship-resistance** posture: T-5 is the formal statement.
- **Intersection** for `inbound_receipts`. Credit-bearing fields are conservatively gated: a receipt is only credited if every K members independently observed it. Reduces the risk of double-credit if cross-shard relay is partially corrupted; one bad relayer can't unilaterally cause credit. This is the **conservative-credit** posture: T-6 is the formal statement.

The two posture choices are dual — union is permissive toward inclusion, intersection is restrictive toward inclusion — and the per-field assignment is the consequence of the field's incentive structure. The algebraic contract these primitives satisfy must compose cleanly across the two rules; T-1..T-6 are the minimal invariants the validator's V25..V26 re-derivation needs to be sound regardless of which rule applies to which field.

### 2.2 RFC-9591 view-binding pattern

The view-binding pattern F2 uses — "each committee member commits to their *view* of a pool at Phase-1 sign-time; canonical reconciliation happens at the boundary; Phase-2 signs the reconciled result" — mirrors the canonical-tx_root pattern Determ already uses for `tx_root` (`Preliminaries.md` §5 V7). It is also structurally analogous to the FROST round-coordination pattern in RFC 9591 §4.5 (signing-round message-binding via commitment vectors) and the IETF FrostSpec view-binding examples used in distributed-signature literature: each participant commits to a position; the aggregator reconciles; the aggregated result is signed in a later round and bound back into the per-participant commits via cross-verification. F2's `make_contrib_commitment` extension (proved in `MakeContribCommitmentBackwardCompat.md`) is the Phase-1 commit-binding step; the present proof covers the Phase-2 reconciliation step.

The cryptographic content of the view-binding step is folded into `compute_view_root`: each member's list is hashed (canonical SHA-256 over the sorted-deduped set) and the resulting 32-byte root is bound into the Phase-1 Ed25519 commit signature. Under A1 (EUF-CMA) + A2 (collision-resistance), a member cannot equivocate on their view between Phase-1 commit and Phase-2 reveal. T-1..T-6 below are the algebraic claims; the cryptographic claims (no view equivocation) are in `MakeContribCommitmentBackwardCompat.md` T-1 + T-2.

---

## 3. Implementation primitives

### 3.1 `compute_view_root` — deterministic Merkle root over the sorted set

```cpp
// src/node/producer.cpp:335-340
Hash compute_view_root(const std::vector<Hash>& items) {
    std::set<Hash> u(items.begin(), items.end());
    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}
```

**Contract.** Two input lists with the same underlying set produce the same root; two lists with different sets produce different roots (the latter modulo SHA-256 collision under A2).

**Mechanism.** Line `336` set-coerces the input (dedup + canonical sort via `std::set<Hash>`'s strict-weak-ordering on the inherited `operator<` of `std::array<uint8_t,32>`, which is lexicographic per `[array.syn]` / `[lex.compare]`). The range-for loop at line `338` iterates `u` in canonical sorted order (per `[associative.reqmts]` — `std::set` iterates in non-descending key order). Each hash is fed byte-stream-deterministically into `SHA256Builder::append` (line `338` calls `append(const Hash&)` from `include/determ/crypto/sha256.hpp:17`, which forwards to the byte-stream `append` at `src/crypto/sha256.cpp:25-28` and ultimately to OpenSSL `EVP_DigestUpdate`). The output at line `339` is the 32-byte `Hash` per `EVP_DigestFinal_ex` (`src/crypto/sha256.cpp:40-45`).

**Algebraic claim.** `compute_view_root(L) = compute_view_root(L')` if and only if `set(L) = set(L')`, modulo SHA-256 collision-resistance (A2 / `Preliminaries.md` §2.1). The `if` direction is by construction (the `std::set` coercion is a function of the underlying set, not the input ordering); the `only-if` direction is the collision-resistance bound `Pr ≤ 2^{-128}` per attempt.

### 3.2 `reconcile_union` — canonical-list union across K member lists

```cpp
// src/node/producer.cpp:345-351
std::vector<Hash> reconcile_union(
        const std::vector<std::vector<Hash>>& member_lists) {
    std::set<Hash> u;
    for (auto& list : member_lists)
        for (auto& h : list) u.insert(h);
    return std::vector<Hash>(u.begin(), u.end());
}
```

**Contract.** Returns the canonical-sorted-vector representation of `set(L_1) ∪ set(L_2) ∪ … ∪ set(L_K)`. Members' duplicate observations collapse; per-member ordering is irrelevant; the output is byte-identical across honest re-derivations.

**Mechanism.** Lines `347-349` set-coerce-then-union: insert every hash from every member list into a single `std::set<Hash>` `u`. `std::set::insert` is a no-op on duplicates (`[set.modifiers]`), so the post-loop `u` is exactly `⋃_i set(L_i)`. Line `350` materializes `u` as a canonically-sorted `std::vector<Hash>` (the set's iteration order is the sorted iteration order per `[associative.reqmts]`). Output is byte-identical for any two invocations with the same set-of-sets input — no nondeterministic-iteration surface remains.

### 3.3 `reconcile_intersection` — canonical-list intersection across K member lists

```cpp
// src/node/producer.cpp:357-372
std::vector<Hash> reconcile_intersection(
        const std::vector<std::vector<Hash>>& member_lists) {
    if (member_lists.empty()) return {};
    std::set<Hash> isect(member_lists[0].begin(), member_lists[0].end());
    for (size_t i = 1; i < member_lists.size(); ++i) {
        std::set<Hash> other(member_lists[i].begin(), member_lists[i].end());
        std::set<Hash> tmp;
        std::set_intersection(isect.begin(), isect.end(),
                               other.begin(), other.end(),
                               std::inserter(tmp, tmp.begin()));
        isect = std::move(tmp);
        if (isect.empty()) break;  // early exit
    }
    return std::vector<Hash>(isect.begin(), isect.end());
}
```

**Contract.** Returns the canonical-sorted-vector representation of `set(L_1) ∩ set(L_2) ∩ … ∩ set(L_K)`. Empty result if `K = 0` (line `359`) OR if any `L_i` is empty (the line-`362-370` loop reduces `isect` to empty on first empty intersection). The K = 1 case returns `set(L_1)` directly via the line-`361` initial seed.

**Mechanism.** Line `361` seeds the running intersection with `set(L_1)`. The loop at lines `362-370` iteratively intersects `isect` with each subsequent `set(L_i)`. `std::set_intersection` (`[set.intersection]`) consumes its two ordered ranges in lockstep and emits elements present in *both* in sorted order; it is associative when applied iteratively to the *intersected* prefix (formally: `(A ∩ B) ∩ C = A ∩ B ∩ C` by set-theoretic associativity of `∩`). The line-`369` early-exit on empty `isect` is an O(K) shortcut that preserves correctness — once the running intersection is empty, any further intersection remains empty. Line `371` materializes the canonical-sorted-vector output.

---

## 4. Proofs of T-1..T-6

### 4.1 Proof of T-1 (UnionMonotonic)

Fix K ≥ 0 and lists `L_1, …, L_K, L_{K+1}`. By the §3.2 mechanism,
$$
U(L_1, \ldots, L_K) = \mathrm{set}(L_1) \cup \cdots \cup \mathrm{set}(L_K),
$$
and
$$
U(L_1, \ldots, L_K, L_{K+1}) = \mathrm{set}(L_1) \cup \cdots \cup \mathrm{set}(L_K) \cup \mathrm{set}(L_{K+1}).
$$

By the set-theoretic axiom `A ⊆ A ∪ B`, the right-hand-side superset contains the left. Therefore `U(L_1, …, L_K) ⊆ U(L_1, …, L_K, L_{K+1})`.    ∎

**Implementation citation.** `src/node/producer.cpp:347-349`. The set-union construction is monotone in its inputs because `std::set::insert` is monotone: adding more `insert` calls can only grow `u`, never shrink it.

### 4.2 Proof of T-2 (IntersectionAntiMonotonic)

Fix K ≥ 1 and lists `L_1, …, L_K, L_{K+1}`. By the §3.3 mechanism applied K+1 times,
$$
I(L_1, \ldots, L_K, L_{K+1}) = \mathrm{set}(L_1) \cap \cdots \cap \mathrm{set}(L_K) \cap \mathrm{set}(L_{K+1}).
$$

Let `X := set(L_1) ∩ … ∩ set(L_K) = I(L_1, …, L_K)` (by the same mechanism applied K times). By the set-theoretic axiom `A ∩ B ⊆ A`, applied with `A = X` and `B = set(L_{K+1})`:
$$
X \cap \mathrm{set}(L_{K+1}) \;\subseteq\; X.
$$

Substituting back: `I(L_1, …, L_K, L_{K+1}) ⊆ I(L_1, …, L_K)`.    ∎

**Implementation citation.** `src/node/producer.cpp:362-370`. The iterative `std::set_intersection` is anti-monotone in its inputs because each `std::set_intersection` call can only shrink `isect`, never grow it.

### 4.3 Proof of T-3 (OrderIndependent)

Fix K ≥ 0 and lists `L_1, …, L_K`. Let `π : {1, …, K} → {1, …, K}` be any permutation.

**Union case.** By §3.2,
$$
U(L_1, \ldots, L_K) = \bigcup_{i=1}^{K} \mathrm{set}(L_i)
$$
and
$$
U(L_{\pi(1)}, \ldots, L_{\pi(K)}) = \bigcup_{i=1}^{K} \mathrm{set}(L_{\pi(i)}).
$$

Set union is commutative and associative; the indexed family on the right is the same multiset of sets as the family on the left (a permutation of indices is a bijection on `{1, …, K}`, so `{ set(L_{π(i)}) : i ∈ 1..K } = { set(L_i) : i ∈ 1..K }` as a multiset of sets, and the union over either multiset is identical). Therefore `U(L_1, …, L_K) = U(L_{π(1)}, …, L_{π(K)})`.

**Intersection case.** By §3.3,
$$
I(L_1, \ldots, L_K) = \bigcap_{i=1}^{K} \mathrm{set}(L_i)
$$
and similarly for the permuted family. Set intersection is also commutative and associative, so by the same multiset argument the two are equal.    ∎

**Implementation citation.** `src/node/producer.cpp:347-349` (union) + `:362-370` (intersection). The order-independence comes from two sources: (a) within each member's list, `std::set` coercion erases ordering; (b) across member lists, the outer for-loop's iteration order over `member_lists` is irrelevant because the operation it composes (`insert` for union, `set_intersection` for intersection) is associative and commutative. The K-of-K committee order chosen by the producer does not affect the output.

### 4.4 Proof of T-4 (UnionIdempotent)

Fix any list `L` and any K ≥ 1. By §3.2,
$$
U(\underbrace{L, L, \ldots, L}_{K}) = \bigcup_{i=1}^{K} \mathrm{set}(L) = \mathrm{set}(L)
$$
where the last equality is `A ∪ A = A` (idempotence of union, applied K-1 times). For K = 1, `U(L) = set(L)` directly by §3.2.    ∎

**Implementation citation.** `src/node/producer.cpp:347-349`. The K-times-inserted hashes collapse to a single set-membership in `u` because `std::set::insert` is a no-op on already-present keys (`[set.modifiers]/4`). The output `std::vector<Hash>(u.begin(), u.end())` is `set(L)` in canonical sorted order, independent of K.

### 4.5 Proof of T-5 (UnionCensorshipResistant — FA2 lift)

Fix K ≥ 1, lists `L_1, …, L_K`, an index `i ∈ {1, …, K}`, and a hash `h ∈ L_i`.

By definition of `set`, `h ∈ L_i` implies `h ∈ set(L_i)`. By the set-theoretic axiom `A_i ⊆ ⋃_j A_j`, applied with `A_j = set(L_j)`:
$$
h \in \mathrm{set}(L_i) \;\subseteq\; \bigcup_{j=1}^{K} \mathrm{set}(L_j) = U(L_1, \ldots, L_K).
$$

Therefore `h ∈ U(L_1, …, L_K)`.    ∎

**Implementation citation.** `src/node/producer.cpp:347-349`. The inner for-loop at line `349` calls `u.insert(h)` for every `h` in every member's list. By line `348`'s outer loop covering every `i ∈ {1, …, K}`, the inner loop visits every `h ∈ L_i`. Therefore every such `h` is inserted into `u` and appears in the output vector.

**FA2 connection.** This is the censorship-resistance contract lifted from the gossip layer to the consensus view. FA2 (Censorship Resistance) per `Censorship.md` already proves that a single honest peer's relay is sufficient for any non-Byzantine validator to observe a transaction or evidence. T-5 lifts that guarantee from the gossip layer (where the observation enters the pool) to the consensus layer (where the observation enters the canonical block via F2 reconciliation). The two-layer composition: any single honest peer's evidence → propagates via gossip → reaches at least one honest committee member's pool → enters that member's `view_eq_list` → enters the F2 canonical `equivocation_events` via T-5 → bound into the K-of-K Phase-2 signature → finalized.

### 4.6 Proof of T-6 (IntersectionConservative)

Fix K ≥ 1, lists `L_1, …, L_K`, and a hash `h`.

**(⇒)** Suppose `h ∈ I(L_1, …, L_K)`. By §3.3,
$$
h \in \bigcap_{j=1}^{K} \mathrm{set}(L_j).
$$
By the set-theoretic axiom `x ∈ ⋂_j A_j ⇒ ∀j : x ∈ A_j`, we have `∀j ∈ {1, …, K} : h ∈ set(L_j)`, which (by definition of `set`) means `h ∈ L_j` for every j.

**(⇐)** Suppose `∀j ∈ {1, …, K} : h ∈ L_j`. Then `∀j : h ∈ set(L_j)`. By the set-theoretic axiom `(∀j : x ∈ A_j) ⇒ x ∈ ⋂_j A_j`:
$$
h \in \bigcap_{j=1}^{K} \mathrm{set}(L_j) = I(L_1, \ldots, L_K).
$$

The biconditional holds.    ∎

**Implementation citation.** `src/node/producer.cpp:361-371`. The iterative `std::set_intersection` at line `365-367` retains `h` in `isect` only if `h` is in both the running `isect` and the next member's `other` (`[set.intersection]`'s contract). By induction over the K loop iterations, after iteration K, `h ∈ isect` iff `h ∈ set(L_j)` for every `j ∈ {1, …, K}`. The output vector at line `371` materializes this intersection in canonical sorted order.

**FA7 connection.** The biconditional underpins the cross-shard receipt credit story. FA7 (Cross-Shard Atomicity) per `CrossShardReceipts.md` proves that destination-side credit is dedup'd via `applied_inbound_receipts_` (V13). T-6 supplies the *consensus-layer* analog: a receipt is only proposed for inclusion in `block.inbound_receipts` if every K committee members independently witnessed it. The combination — T-6 at consensus + V13 at apply — gives end-to-end "exactly-once credit even under partial relay corruption": one corrupt relayer can't unilaterally cause inclusion (T-6's ⇐ direction); even if inclusion happens, the apply-layer dedup catches double-credit (V13).

---

## 5. Validator-pass composition: V21..V26 close S-030 D2

The six theorems above are the algebraic contract; the validator-side V21..V26 passes compose them into the S-030 D2 closure. The composition lives in two helpers at `src/node/producer.cpp:391-496`.

### 5.1 `validate_contrib_view_roots` — V21..V24 per-contrib well-formedness

```cpp
// src/node/producer.cpp:391-436
bool validate_contrib_view_roots(const ContribMsg& msg, std::string* reason) { … }
```

The per-contrib check at line `391` enforces:

- **V21** (lines `406-418`): `msg.view_X_list.size() ≤ F2_VIEW_LIST_CAP = 64` (per `include/determ/node/producer.hpp:212`). Bandwidth budget per F2-SPEC.md §Q3 — the bounded-cost half of the safety story.
- **V22** (lines `423-426`): `msg.view_eq_root == compute_view_root(msg.view_eq_list)`. Binds the committed equivocation view to the Phase-1 signature.
- **V23** (lines `427-430`): same for `view_abort_root`.
- **V24** (lines `431-434`): same for `view_inbound_root`.

The v1-compat short-circuit at lines `394-404` (all-roots-zero AND all-lists-empty ⇒ accept as a no-op pre-F2 contrib) is the matching half of the `MakeContribCommitmentBackwardCompat.md` T-1 byte-identity argument: pre-F2 ContribMsg gossiped into an F2-aware peer trivially pass V21..V24.

V22..V24's correctness follows directly from §3.1 (compute_view_root) — the root is a deterministic function of `set(list)`, so the equality check is the same on every honest re-derivation. A member that signs a Phase-1 commit with `view_eq_root = R` and later attempts to claim a different `view_eq_list` would either fail V22 (mismatch) or attempt to find a second pre-image collision (`set(L) ≠ set(L')` with `compute_view_root(L) = compute_view_root(L')`) — negligible under A2.

### 5.2 `derive_canonical_view_lists` + `validate_view_reconciliation` — V25..V26 cross-contrib reconciliation

```cpp
// src/node/producer.cpp:438-456
F2CanonicalViews derive_canonical_view_lists(
        const std::vector<ContribMsg>& contribs) {
    F2CanonicalViews out;
    std::vector<std::vector<Hash>> eq_views, abort_views, inbound_views;
    …
    for (auto& c : contribs) {
        eq_views.push_back(c.view_eq_list);
        abort_views.push_back(c.view_abort_list);
        inbound_views.push_back(c.view_inbound_list);
    }
    out.equivocation_events = reconcile_union(eq_views);
    out.abort_events         = reconcile_union(abort_views);
    out.inbound_receipts     = reconcile_intersection(inbound_views);
    return out;
}
```

```cpp
// src/node/producer.cpp:458-496
bool validate_view_reconciliation(
        const std::vector<ContribMsg>& contribs,
        const std::vector<Hash>& block_eq,
        const std::vector<Hash>& block_abort,
        const std::vector<Hash>& block_inbound,
        std::string* reason) { … }
```

The composite check at line `458` enforces:

- **V21..V24** (lines `467-475`): re-run per-contrib well-formedness for every contrib. Any single contrib failing aborts the block.
- **V25** (lines `483-490`): `block_eq == reconcile_union(eq_views)` AND `block_abort == reconcile_union(abort_views)`.
- **V26** (lines `491-494`): `block_inbound == reconcile_intersection(inbound_views)`.

The equality checks at lines `483, 487, 491` are direct `std::vector<Hash>` equality (`operator==` on `std::vector` is element-wise per `[vector.syn]`). Both the validator's canonical lists (produced by `derive_canonical_view_lists`) and the block's canonical lists (produced by the assembler running the same primitives) are in canonical sorted order by construction (§3.2 + §3.3), so a direct vector comparison suffices — no order normalization needed.

### 5.3 How T-1..T-6 close S-030 D2 (consensus-layer)

S-030 D2 (per `S030-D2-Analysis.md` §1) is the gap that `compute_block_digest` does not bind `equivocation_events`, `abort_events`, `inbound_receipts`, `partner_subset_hash`, `timestamp` — fields covered by `signing_bytes` but not by the K-of-K Phase-2 signature. Pre-F2, two distinct block instances could share the same `block_digest` (and therefore the same K signatures) but differ in these fields; honest nodes applying the two instances would diverge in state for one block.

F2's closure is structural, not a one-line digest extension (the naive extension breaks under gossip-async per `S030-D2-Analysis.md` §2). The structural fix layers:

1. **Phase-1 commit binding** (`MakeContribCommitmentBackwardCompat.md` T-1 + T-2). Each member's `ContribMsg` is extended with `view_eq_root`, `view_abort_root`, `view_inbound_root`. The K-of-K Phase-1 signatures bind each member to their *view* of the three pools at commit time. Under A1 + A2, no member can equivocate on their view between Phase-1 commit and Phase-2 reveal.

2. **Phase-2 canonical reconciliation** (the present T-1..T-6). The producer assembles the block body by running `derive_canonical_view_lists` over the K Phase-1 commits. The validator runs the same primitives over the same K commits and gets the same canonical lists by T-3 (order-independent) + T-1/T-2 (monotone in committee composition) + T-4 (idempotent under duplicate views).

3. **Block-digest binding via state_root + signing_bytes**. The reconciled lists are included in `signing_bytes` and (post-S-033) folded into `state_root`, which is itself bound into `signing_bytes` and (post-S-038) populated by the producer's `try_finalize_round` tentative-chain dry-run. Cross-block tampering is caught at `prev_hash` mismatch; within-block tampering is caught at V25/V26.

T-5 (censorship-resistance lift) + T-6 (intersection-conservative) preserve the per-field semantics F2-SPEC.md §Q1 requires: equivocation + abort evidence flows through union (one observer suffices); inbound receipts flow through intersection (unanimous observation required). The validator's V25/V26 re-derivation is sound because the primitives are pure-function set operations (T-3 + T-4), and any honest validator running `derive_canonical_view_lists` over the same K signed ContribMsg produces the same canonical lists.

The chain of inference, end-to-end:

| Step | Invariant | Source |
|---|---|---|
| Each contrib's view is signed | A1 (EUF-CMA) | `Preliminaries.md` §2.2 + `MakeContribCommitmentBackwardCompat.md` T-2 |
| Each contrib's view-root binds the view-list | A2 (collision-resistance) + V22..V24 | §3.1 + §5.1 |
| Canonical reconciliation is deterministic | T-3 + T-4 | §4.3 + §4.4 |
| Censorship-resistance lifts to consensus view | T-5 | §4.5 |
| Conservative-credit holds at consensus view | T-6 | §4.6 |
| Block body's canonical lists are checked against re-derived lists | V25 + V26 | §5.2 |
| Tampering one field breaks one of V25/V26 | T-1 + T-2 + T-3 monotonicity argument | §4.1 + §4.2 + §4.3 |

The closure is **consensus-layer**; the apply-layer half is handled by S-033 (state_root binding) + S-038 (producer-side wiring). Both halves are required: F2 ensures the K signatures cover the right canonical content; S-033 + S-038 ensure the cross-block `prev_hash` chain authenticates each block's full state. Together they close S-030 D2 per `S030-D2-Analysis.md` §3.5.

---

## 6. Test-suite citation

The six theorems are exercised in the determ test suite under `test-view-root` (run via `tools/test_view_root.sh`, invoking `determ test-view-root` at `src/main.cpp:9390-10074`). Scenarios 1-8 cover `compute_view_root`'s structural properties (§3.1); scenarios 9-22 are the F2-helper assertion block covering T-1..T-6 + V21..V26. Key assertions:

| Test | Source line | Theorem exercised |
|---|---|---|
| `compute_view_root: order-independent (1)` + `(2)` | `src/main.cpp:9431-9434` | T-3 specialized to K=1 (within-list) |
| `compute_view_root: dedup (1)` + `(2)` | `src/main.cpp:9444-9447` | T-4 specialized to K=1 (within-list idempotence) |
| `compute_view_root: content-sensitive (1)` + `(2)` | `src/main.cpp:9457-9460` | §3.1 collision-distinguishing under A2 |
| `reconcile_union: 3 disjoint members yield 3 items` | `src/main.cpp:9487-9489` | T-5 (every member's hash appears) + T-1 (monotone) |
| `reconcile_union: overlapping members dedupe to 3` | `src/main.cpp:9497-9500` | T-4 across K=3 members |
| `reconcile_union: one observer suffices (F2 Q1)` | `src/main.cpp:9509-9512` | T-5 (censorship-resistance lift, single observer) |
| `reconcile_intersection: any empty list yields empty (F2 Q1)` | `src/main.cpp:9539-9541` | T-6 ⇐ + T-2 (anti-monotone shrinks to empty) |
| `reconcile_intersection: unanimous K members → full set` | `src/main.cpp:9548-9551` | T-6 ⇒ (unanimous observation guarantees inclusion) |
| `reconcile_intersection: b in all → result {b}` | `src/main.cpp:9559-9562` | T-6 biconditional with partial overlap |
| `reconcile_union / reconcile_intersection: deterministic across calls` | `src/main.cpp:9572-9577` | §3.2 + §3.3 determinism (pure function) |
| `reconcile_union / reconcile_intersection: member-order independent` | `src/main.cpp:9588-9591` | T-3 union + intersection cases across K=2 |
| `validate_contrib_view_roots: bound contrib PASSES V21..V24` | `src/main.cpp:9904-9905` | §5.1 V22..V24 positive case |
| `validate_contrib_view_roots: V21 / V22 / V23 / V24 REJECTED` | `src/main.cpp:9917-9954` | §5.1 V21 + V22 + V23 + V24 negative cases |
| `derive_canonical: eq union size = 3 / inbound intersection = {C2}` | `src/main.cpp:9985-9993` | T-5 + T-6 composed across 3 contribs |
| `validate_view_reconciliation: matching block PASSES` | `src/main.cpp:10007-10013` | §5.2 V25 + V26 positive case |
| `validate_view_reconciliation: V25 missing eq REJECTED` | `src/main.cpp:10026-10032` | T-5 negative case at validator boundary (V25 fires) |
| `validate_view_reconciliation: V26 extra inbound REJECTED` | `src/main.cpp:10046-10054` | T-6 negative case at validator boundary (V26 fires) |
| `validate_view_reconciliation: corrupted contrib REJECTED first` | `src/main.cpp:10066-10073` | §5.2 V21..V24 runs before V25/V26 |

T-1 + T-2 are exercised implicitly via the "disjoint members" / "overlapping members" / "any empty list" tests (adding lists never shrinks union; adding lists never grows intersection). The regression harness asserts `PASS: view-root all assertions`; CI gates on this passing.

---

## 7. Cross-reference to FB22

`docs/proofs/tla/F2ViewReconciliation.tla` (FB22) is the machine-checkable TLA+ companion to this document. FB22's `PROPERTIES` section lists the six algebraic invariants under abbreviated names that map directly to T-1..T-6:

| FB22 invariant | Analytic theorem |
|---|---|
| `INV_UnionMonotonic` (lines 319-323) | T-1 |
| `INV_IntersectionAntiMonotonic` (lines 333-337) | T-2 |
| `INV_OrderIndependent` (lines 354-366) | T-3 |
| `INV_UnionIdempotent` (lines 372-378) | T-4 |
| `INV_UnionCensorshipResistant` (lines 385-389) | T-5 |
| `INV_IntersectionConservative` (lines 395-399) | T-6 |

FB22 additionally asserts three auxiliary invariants exercising the V21..V26 validator-pass surface:

- `INV_AllContribsValid` (lines 411-413) — every generated contrib passes V21..V24 by construction of `HonestContrib`.
- `INV_BlockReconcilesContribs` (lines 416-420) — the generated (contribs, block) tuple passes V25..V26 by construction of `DeriveCanonical`.
- `INV_BandwidthCapHonored` (lines 425-430) — every contrib's view-list lengths respect `F2_VIEW_LIST_CAP = 64`.

These three auxiliary invariants correspond to §5.1 + §5.2 of this document. They are checkable in TLC across a bounded universe (recommended `K = 3, |Hashes| = 3, CAP = 64`); the analytic proof above covers them implicitly via §3 (each primitive is pure-function and deterministic) + §5 (the validator's V21..V26 pass composes the primitives correctly).

The two artifacts are designed to be co-readable. A reviewer skeptical of the prose argument can run `tlc F2ViewReconciliation.tla -config F2ViewReconciliation.cfg` and observe TLC enumerate the bounded state-space (state count ≤ 10⁴ at the recommended config) with no invariant violations. A reviewer skeptical of the TLA+ formalization can read this document's §4 lemma chain and confirm each invariant reduces to a standard set-theoretic axiom. Both artifacts reference the same C++ implementation at `src/node/producer.cpp:335..496`.

---

## 8. Status

**Shipped this round.** This analytic proof was added alongside the FB22 TLA+ companion (`docs/proofs/tla/F2ViewReconciliation.tla`, merged in the round-18 series). The C++ implementation it analyzes — `compute_view_root`, `reconcile_union`, `reconcile_intersection`, `validate_contrib_view_roots`, `derive_canonical_view_lists`, `validate_view_reconciliation` at `src/node/producer.cpp:335..496` — shipped earlier in the v2.7 F2 sub-step 0 + sub-step 3 commit pair on the `worktree-agent-a9aab716c0b0b7aa4` branch (see `git log v2.7 F2`). The regression test suite (`tools/test_view_root.sh` invoking `determ test-view-root`) covers T-1..T-6 with concrete examples (§6).

This proof does not change any code; it consolidates the algebraic argument that the validator's V25..V26 re-derivation is structurally sound, so an external implementer can confirm — without re-running TLC — that any independent reimplementation of the reconciliation primitives must produce byte-identical canonical lists for byte-identical input committee views.

The surrounding S-030 D2 closure is **consensus-layer complete** via F2 (this proof + FB22 + the `MakeContribCommitmentBackwardCompat.md` paired Phase-1 commit-binding proof). The apply-layer half (S-033 state_root + S-038 producer wiring) shipped earlier; together the two halves close S-030 D2 end-to-end per `S030-D2-Analysis.md` §3.5.

---

## 9. References

- `src/node/producer.cpp:335..496` — F2 helpers (primary object of the proof). Lines `335-340` `compute_view_root`; `345-351` `reconcile_union`; `357-372` `reconcile_intersection`; `391-436` `validate_contrib_view_roots`; `438-456` `derive_canonical_view_lists`; `458-496` `validate_view_reconciliation`.
- `include/determ/node/producer.hpp:146..268` — header declarations including `F2_VIEW_LIST_CAP = 64` (line 212), `F2CanonicalViews` (lines 239-243), and the V21..V26 docstring.
- `include/determ/types.hpp:15` — `using Hash = std::array<uint8_t, 32>` (inherited lexicographic `operator<` used by `std::set<Hash>`).
- `src/crypto/sha256.cpp:25-45` — `SHA256Builder::append` + `finalize` (backing the §3.1 determinism argument).
- `src/main.cpp:9390-10074` — `determ test-view-root` unit-test suite (assertions cited in §6).
- `tools/test_view_root.sh` — regression harness; CI-gated.
- `docs/proofs/Preliminaries.md` §1.3 (hash conventions), §2.1 (SHA-256 collision-resistance — A2), §2.2 (Ed25519 EUF-CMA — A1), §4 (honest behavior H1-H6), §5 (block validity V1-V15).
- `docs/proofs/F2-SPEC.md` §Q1 (per-field reconciliation rules), §Q3 (wire format + `F2_VIEW_LIST_CAP`), §Q5 (validator-side re-derivation + Phase-2 sig semantics).
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — companion paired proof for the Phase-1 commit-binding step (T-1 v1 byte-identity + T-2 DTM-F2-v1 replay defense).
- `docs/proofs/S030-D2-Analysis.md` — audit-finding analysis + comparison of closure paths.
- `docs/proofs/Safety.md` §5.3 — FA1 D2 footnote (closed by F2 + S-033 + S-038).
- `docs/proofs/tla/F2ViewReconciliation.tla` (FB22) — the TLA+ companion (cross-reference table in §7).
- `docs/SECURITY.md` §S-030 — the audit finding F2 closes (consensus-layer half).
- `docs/proofs/Censorship.md` (FA2) — T-5 is the consensus-layer lift of FA2's gossip-layer guarantee.
- `docs/proofs/CrossShardReceipts.md` (FA7) — T-6 is the consensus-layer half of destination-side dedup (apply-layer half: V13 + `applied_inbound_receipts_`).
- ISO/IEC 14882:2020 [C++20]: `[array.syn]` (lexicographic compare on `std::array`), `[associative.reqmts]` (sorted iteration on `std::set`), `[set.modifiers]` (insertion is no-op on duplicates), `[set.intersection]`, `[vector.syn]` (element-wise `operator==`).
- NIST FIPS 180-4 — SHA-256 reference for `compute_view_root`.
- RFC 9591 (FROST) §4.5 — view-binding pattern; structural analogy to F2's commitment-then-reconciliation flow.
