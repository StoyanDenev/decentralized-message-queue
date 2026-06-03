# MerkleTreeSoundness — sorted-leaves balanced binary Merkle tree structural + inclusion-proof soundness

This document formalizes the structural and security properties of Determ's state-commitment Merkle primitive — the **sorted-leaves balanced binary Merkle tree** implemented in `src/crypto/merkle.cpp` (the v2.1 / S-038 primitive). It is the cryptographic substrate on top of which the S-033 `state_root` commitment, the `state_proof` light-client RPC, and the `determ verify-state-proof` local-verification command are built.

Two adjacent proofs treat the *composition* of this primitive with the rest of the chain — `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 four-surface composition) and `S033StateRootNamespaceCoverage.md` (10-namespace coverage completeness) — but **neither proves the primitive itself**. Both invoke, without proof, two properties of the Merkle root function `MR`: that it is a *function* (same leaf set ⇒ same root — `BlockchainStateIntegrity.md` §4.2 Claim (i)) and that it is *injective up to SHA-256 collision resistance* (different leaf sets ⇒ different roots except with negligible probability — Claim (ii)). This document discharges both claims at the level of the `merkle_root` / `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_verify` source, and adds the inclusion-proof soundness theorem (MT-4) that the light-client surface rests on, plus an explicit analysis of the CVE-2012-2459 last-leaf-duplication malleability class (verdict: **does not apply** — see §6.1).

The proof is partly structural (tree shape, domain separation, determinism) and partly cryptographic (collision-resistance reductions for second-preimage and inclusion-forgery resistance). Where a reduction is to a base assumption, it is to **A2 (SHA-256 collision / second-preimage resistance)** as stated in `Preliminaries.md` §2.1 — *not* to FA3, which in Determ's proof series denotes `SelectiveAbort.md` (selective-abort resistance), an unrelated property.

**Companion documents.** `Preliminaries.md` (F0) §1.3 for hash notation (`H`, `‖`, big-endian integer encoding) and §2.1 for SHA-256 collision / preimage / second-preimage resistance (A2); `S033StateRootNamespaceCoverage.md` (the 10-namespace leaf-set enumeration this proof composes with — its T-3 deterministic-leaf-ordering result and this document's MT-1 jointly give `state_root` reproducibility); `BlockchainStateIntegrity.md` (the four-surface S-021 + S-033 + S-038 composition whose §4.2 Claims (i) + (ii) this document formally discharges); `AccountStateInvariants.md` (FA-Apply-1) for the apply-determinism that supplies the *identical-leaf-set* precondition MT-1 consumes; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot-pathway sibling that reuses MT-1; `docs/SECURITY.md` §S-033 + §S-038 + §S-040 for the closure / limitation narratives this proof formalizes; `docs/PROTOCOL.md` §4.1.1 for the canonical `state_root` Merkle-leaf table.

---

## 1. Scope

### 1.1 In scope

The four functions in `src/crypto/merkle.cpp` and their header contracts in `include/determ/crypto/merkle.hpp`:

| Function | Signature | Role |
|---|---|---|
| `merkle_leaf_hash` | `(key, value_hash) → Hash` | Domain-prefixed leaf hash (`0x00` prefix). |
| `merkle_inner_hash` | `(left, right) → Hash` | Domain-prefixed inner-node hash (`0x01` prefix). |
| `merkle_root` | `(leaves) → Hash` | Sorted-leaves balanced binary tree root. |
| `merkle_proof` | `(leaves, target_index) → [Hash]` | Inclusion-proof sibling-hash path. |
| `merkle_verify` | `(root, key, value_hash, target_index, leaf_count, proof) → bool` | Inclusion-proof verifier. |

Their consumers, as exercised by the test surface:

- **S-033 `state_root`:** `Chain::compute_state_root` (`src/chain/chain.cpp:413-415`) = `merkle_root(build_state_leaves())`. The apply-time gate at `chain.cpp:1421-1446` and the snapshot-restore gate at `chain.cpp:1880-1911` both compare a recomputed `merkle_root` against a stored value.
- **Light-client inclusion proofs:** `Chain::state_proof` (`chain.cpp:435-462`) returns a `(key, value_hash, target_index, leaf_count, proof)` tuple via `merkle_proof`; the `determ verify-state-proof` CLI (`src/main.cpp:5471-5589`) reconstructs the root locally via `merkle_verify` against an operator-trusted `state_root`.

### 1.2 Test-surface anchors

The structural and tamper-detection behavior proved here is pinned by three regression surfaces (all in `tools/` + the in-binary unit tests):

- **`determ test-merkle`** (`src/main.cpp:6217-6364`, 10 assertions) — empty/single-leaf base cases, determinism, balanced (8-leaf) and unbalanced (7-leaf) round-trips, value/sibling/index tamper rejection, **leaf-vs-inner domain separation** (assertion 9), and **sort-invariance** (assertion 10). Driven end-to-end by `tools/test_merkle.sh`.
- **`determ test-merkle-proof-tampering`** (`src/main.cpp:28555-28934`, 15 scenarios) — exhaustive proof-tamper detection across balanced + heavily-padded (5-leaf, 7-leaf, 16-leaf) trees, including the **key-binding** scenarios #14 (cross-key value swap rejected) and #15 (in-place key tamper rejected) and the **S-040 `leaf_count` caller-trust limitation** pinned by scenario #12. Driven by `tools/test_merkle_proof_tampering.sh`.
- **`tools/test_verify_state_proof.sh`** (9 assertions) — the end-to-end light-client demonstrator: a 3-node cluster, `determ state-proof` fetch, `determ verify-state-proof` local verification, including the external-`--state-root` light-client mode (assertion 6) and the mismatched-root rejection (assertion 9).

> **Note on test naming.** The task brief referenced an 8-assertion `determ test-merkle-tree-balanced` command and a `light/verify.cpp::verify_state_proof` source unit. Neither exists in this tree: the balanced/unbalanced structural assertions live inside `determ test-merkle` (assertions 4–5, 10) and `determ test-merkle-proof-tampering` (scenarios #12–#13), and the light-client verifier is the `determ verify-state-proof` CLI in `src/main.cpp` calling `crypto::merkle_verify` directly (there is no `light/` subtree). This document cites the surfaces that actually ship. A planned `LightClientThreatModel.md` (T-L3) is referenced below as a forward pointer, not a present cross-reference.

### 1.3 Out of scope

- The leaf *encoding* scheme (which `Chain` field maps to which namespace, and the value-hash byte layout per namespace) is the subject of `S033StateRootNamespaceCoverage.md`. This document treats the leaf set abstractly as a multiset of `(key, value_hash)` pairs and proves properties of the tree built over it.
- Sparse-Merkle-tree (SMT) non-membership proofs: the current primitive is **not** an SMT (leaf position is sort-order, not key-path). MT-5 documents the actual non-membership capability (it is *not* a native one) rather than claiming an SMT property.
- The consensus-layer question of whether two divergent bodies can both be signed (S-030 D2) — covered by `BlockchainStateIntegrity.md` §6.3 and `F2-SPEC.md`.

---

## 2. Construction specification

All statements in this section are read directly off `src/crypto/merkle.cpp` (functions `merkle_leaf_hash`, `merkle_inner_hash`, `merkle_root`, `merkle_proof`, `merkle_verify`) and the contract comments in `include/determ/crypto/merkle.hpp`.

Throughout, `H : {0,1}* → {0,1}²⁵⁶` is SHA-256 (`Preliminaries.md` §1.3), `‖` is byte concatenation, and `u32_be(n)` / `u8(n)` denote the big-endian fixed-width encodings emitted by the `SHA256Builder` append helpers and the local `append_be_u32` (`merkle.cpp:13-21`).

### 2.1 Leaf hash (`merkle_leaf_hash`, lines 25-34)

For a leaf with opaque key `k ∈ {0,1}*` and 32-byte `value_hash v`:

$$
\mathrm{LH}(k, v) \;=\; H\big(\,\texttt{0x00} \,\|\, u32\_be(|k|) \,\|\, k \,\|\, v\,\big).
$$

Two facts to record precisely:

1. **The leaf domain byte is `0x00`** (`merkle.cpp:28`: `uint8_t prefix = 0x00`).
2. **The key is length-prefixed** with its 4-byte big-endian length before the key bytes (`merkle.cpp:30`: `append_be_u32(b, key.size())`), and the empty-key case appends only the length prefix (the `if (!key.empty())` guard at line 31 skips the zero-length `append`, which is a no-op anyway). This length-prefix is stronger than the brief's simplified `LH(x) = H(0x00 ‖ x)`: it makes the `(key, value_hash)` boundary unambiguous so that no two distinct `(k, v)` pairs collide by concatenation aliasing (e.g. `("ab", v)` vs `("a", "b"‖v)` — the length prefix on `k` separates them). Because `v` is a fixed 32-byte `Hash`, the trailing field is fixed-width and needs no length prefix.

### 2.2 Inner hash (`merkle_inner_hash`, lines 36-43)

For two 32-byte child hashes `l, r`:

$$
\mathrm{IH}(l, r) \;=\; H\big(\,\texttt{0x01} \,\|\, l \,\|\, r\,\big).
$$

The inner domain byte is `0x01` (`merkle.cpp:38`: `uint8_t prefix = 0x01`). Both children are fixed-width (32 bytes each), so no length prefix is needed and the 65-byte preimage `0x01 ‖ l ‖ r` is unambiguously parseable.

### 2.3 Sort (`merkle_root`, lines 50-52; `merkle_proof`, lines 79-81; `state_proof`, lines 441-444)

Before any hashing, `merkle_root` copies the input and sorts it:

```cpp
std::vector<MerkleLeaf> sorted = leaves;
std::sort(sorted.begin(), sorted.end(),
    [](const MerkleLeaf& a, const MerkleLeaf& b) { return a.key < b.key; });
```

The comparator is `a.key < b.key` where `key` is `std::vector<uint8_t>`; C++'s lexicographic `operator<` on `std::vector<uint8_t>` is **byte-wise lexicographic, unsigned, with shorter-is-smaller on a common prefix** (`std::lexicographical_compare` semantics). This is a strict total order on distinct byte strings. `merkle_proof` applies the identical sort, and `Chain::state_proof` sorts once and then `lower_bound`s the target key in the same order — so the `target_index` a light client receives is a *sorted-order* index, matching `merkle_verify`'s expectation.

**Uniqueness is a caller obligation, not enforced here.** The comment at `merkle.cpp:48-49` states: *"keys are assumed unique by caller; we don't enforce here."* `std::sort` is not stable, so if two leaves shared a key their relative order would be unspecified. §6.1 shows why this obligation is discharged for the only production caller (`build_state_leaves`), making the unspecified-order case unreachable in practice.

### 2.4 Tree reduction + odd-count rule (`merkle_root`, lines 55-72)

After sorting, each leaf is hashed into a working row, then levels are reduced pairwise until one node remains:

```cpp
std::vector<Hash> row;                       // row[i] = LH(sorted[i].key, sorted[i].value_hash)
while (row.size() > 1) {
    if (row.size() % 2 == 1) row.push_back(row.back());   // duplicate last node
    std::vector<Hash> next;
    for (size_t i = 0; i + 1 < row.size(); i += 2)
        next.push_back(merkle_inner_hash(row[i], row[i + 1]));
    row = std::move(next);
}
return row[0];
```

The **odd-count rule** (`merkle.cpp:64`) is **Bitcoin-style last-node duplication at each level**: whenever the current level has an odd number of nodes, the last node is duplicated to make the count even, and then adjacent pairs are combined left-to-right. This is exactly the shape the brief described: a 3-leaf set reduces as

$$
\mathrm{root} \;=\; \mathrm{IH}\big(\mathrm{IH}(L_0, L_1),\; \mathrm{IH}(L_2, L_2)\big),
$$

where `L_i = LH(sorted[i].key, sorted[i].value_hash)`. (Level 0 has 3 nodes → duplicate `L_2` → pairs `(L_0,L_1)`, `(L_2,L_2)`; level 1 has 2 nodes → pair them → root.) The duplication fires at *every* odd level on the way up — a 5-leaf tree duplicates at level 0 (5→6) and again at level 1 (3→4); a 7-leaf tree duplicates at level 0 (7→8 via the 7th node, then the resulting 4 → no dup, then 2 → no dup — but note 7→8 only adds one node so level 0 becomes 8, level 1 becomes 4, level 2 becomes 2, level 3 = root; the brief's "every odd level" describes the general 5/3-style cascade). The `determ test-merkle-proof-tampering` scenarios #12 (5-leaf) and #13 (7-leaf) pin this cascade.

### 2.5 Base cases (`merkle_root`, line 46; `determ test-merkle` assertions 1–2)

- **Empty leaf set** (`merkle.cpp:46`: `if (leaves.empty()) return Hash{};`): the root is the all-zero 32-byte hash `Hash{}`. The header (`merkle.hpp:46-47`) documents this as the *"no committed state"* sentinel. Pinned by `determ test-merkle` assertion 1.
- **Single leaf**: the `while (row.size() > 1)` loop never executes, so `merkle_root` returns `row[0] = LH(k, v)`. The root *equals the leaf hash*. The corresponding `merkle_proof` returns the empty vector (no siblings). Pinned by `determ test-merkle` assertion 2.

### 2.6 Verifier (`merkle_verify`, lines 113-141)

The verifier recomputes the root from `(key, value_hash, target_index, leaf_count, proof)` without access to the other leaves:

```cpp
if (leaf_count == 0) return false;
if (target_index >= leaf_count) return false;     // input-validation gate
Hash current = merkle_leaf_hash(key, value_hash);  // re-derive LH(leaf)
size_t idx = target_index, level_size = leaf_count, proof_idx = 0;
while (level_size > 1) {
    if (level_size % 2 == 1) level_size += 1;       // simulate the level's duplication
    if (proof_idx >= proof.size()) return false;    // proof too short → reject
    Hash sibling = proof[proof_idx++];
    current = (idx % 2 == 0) ? merkle_inner_hash(current, sibling)
                             : merkle_inner_hash(sibling, current);
    idx /= 2; level_size /= 2;
}
return proof_idx == proof.size() && current == root;   // exact-consume AND root-equality
```

Three structural checks make the verifier sound against malformed proofs (all pinned by `determ test-merkle-proof-tampering` scenarios #5–#8):

1. **Range gate**: `target_index >= leaf_count` is rejected up front (scenario #5).
2. **Underflow gate**: a proof shorter than the level count triggers `proof_idx >= proof.size()` mid-loop and returns false (scenario #6, truncation).
3. **Exact-consume gate**: a proof longer than the level count fails the post-loop `proof_idx == proof.size()` check (scenario #7, phantom-sibling extension).

The **left/right composition order** at each level is driven by the *parity of `idx`* (`idx % 2 == 0` ⇒ current is the left child), which matches `merkle_proof`'s sibling-selection logic (`merkle.cpp:100`: `sibling = (idx%2==0) ? idx+1 : idx-1`). A wrong `target_index` therefore composes siblings in the wrong order and fails root-equality (scenarios #4, #8 of `test-merkle`).

**`leaf_count` is NOT bound into any hash.** The verifier uses `leaf_count` only to drive the *number of levels* and the per-level duplication parity; it is not an input to `LH` or `IH`. This is the **S-040 caller-trust invariant** documented at `merkle.hpp:64-83` and analyzed in §6.2.

---

## 3. Structural theorems

Notation: for a finite multiset of leaves `Λ = {(k_1, v_1), …, (k_n, v_n)}` with pairwise-distinct keys, write `MR(Λ)` for `merkle_root(Λ)`. Write `sort(Λ)` for the key-sorted sequence and `L_i = LH(k_{(i)}, v_{(i)})` for the hash of the `i`-th leaf in sorted order.

### MT-1 (Determinism / permutation-invariance)

**Statement.** `MR` is a function of the leaf *set*, not the input order: for any two orderings `Λ`, `Λ'` of the same multiset of distinct-keyed leaves, `MR(Λ) = MR(Λ')` byte-for-byte. Equivalently, `MR = f ∘ sort` for a pure function `f` of the sorted sequence.

**Proof.** `merkle_root` first computes `sorted := sort(Λ)` via `std::sort` with comparator `a.key < b.key` (§2.3). Since all keys are distinct, the strict-total-order sort yields a *unique* permutation `sort(Λ) = sort(Λ')` regardless of the input order (`std::sort`'s output on a strict weak ordering with no ties is the unique sorted sequence; non-stability is irrelevant because there are no equal elements). Everything downstream of the sort is a deterministic pure computation: the per-leaf `LH` is a deterministic hash; the level-reduction loop (§2.4) is a fixed sequence of `IH` evaluations driven only by `row.size()` parity; `IH` is a deterministic hash. SHA-256 is a deterministic function (no randomness, no platform-dependent state), and the `SHA256Builder` append order is fixed by source. Therefore `f` is a pure function of the sorted sequence, and `MR(Λ) = f(sort(Λ)) = f(sort(Λ')) = MR(Λ')`. ∎

**Corollary (state_root reproducibility).** Two honest nodes whose post-apply state is byte-identical across all ten namespaces produce byte-identical `state_root` values. This is exactly the precondition `BlockchainStateIntegrity.md` §4.2 Claim (i) needs and `S033StateRootNamespaceCoverage.md` T-3 asserts: `build_state_leaves` emits the *same multiset* of `(key, value_hash)` pairs on both nodes (by FA-Apply-1 apply determinism), and MT-1 turns "same multiset" into "same root." MT-1 is the half that lives in the Merkle primitive; FA-Apply-1 + T-3 supply the same-multiset half. Pinned by `determ test-merkle` assertions 3 (determinism) + 10 (sort-invariance: `merkle_root(L) == merkle_root(reverse(L))`).

### MT-2 (Domain separation: leaf preimages ⊥ inner preimages)

**Statement.** No byte string is simultaneously a valid `LH` preimage and a valid `IH` preimage. Consequently, an adversary cannot present an inner-node hash and have it accepted as a leaf hash (or vice versa) — the second-preimage / leaf-vs-node confusion attack on Merkle trees is structurally ruled out.

**Proof.** Every `LH` preimage begins with the byte `0x00` (§2.1); every `IH` preimage begins with the byte `0x01` (§2.2). The two prefix sets are disjoint singletons `{0x00} ≠ {0x01}`, so the preimage languages `0x00·{0,1}*` and `0x01·{0,1}*` are disjoint. A value accepted by the verifier as "the leaf at `target_index`" is recomputed as `LH(key, value_hash) = H(0x00 ‖ …)`; a value used as an internal node is `IH(·,·) = H(0x01 ‖ …)`. For an adversary to make a verifier treat some intended-inner hash `h` as the leaf (or splice a leaf where an inner node is expected) *without* recomputing — i.e. to find one string that the construction reads as both — would require a preimage with first byte both `0x00` and `0x01`, which is impossible. To instead *find a collision* `H(0x00 ‖ x) = H(0x01 ‖ y)` is a SHA-256 collision and reduces to A2 (probability `≤ 2⁻¹²⁸`). Hence leaf/inner confusion is impossible structurally for the no-collision case and negligible otherwise. ∎

This is the standard defense (Bitcoin's `0x00`/`0x01` tagged hashing à la BIP-340 tagged hashes, RFC 6962 Certificate-Transparency's `0x00` leaf / `0x01` node prefixes) against the classic Merkle ambiguity attack where a 64-byte "leaf" is reinterpreted as two concatenated child hashes. Pinned by `determ test-merkle` assertion 9 (`merkle_leaf_hash(k, v) != merkle_inner_hash(zero, zero)` even on degenerate inputs) and documented at `merkle.hpp:93-96`.

### MT-3 (Collision-resistance inheritance)

**Statement.** Two leaf sets `Λ ≠ Λ'` (differing in at least one `(key, value_hash)` pair, with distinct keys within each) that produce the same root `MR(Λ) = MR(Λ')` yield, by an efficient extraction, a SHA-256 collision. Hence `MR` is injective up to A2: `Pr[MR(Λ) = MR(Λ') ∧ Λ ≠ Λ'] ≤ 2⁻¹²⁸` for any efficiently-found pair.

**Proof.** Suppose `Λ ≠ Λ'` but `MR(Λ) = MR(Λ')`. Let `T`, `T'` be the two trees (sorted-leaf sequences `s = sort(Λ)`, `s' = sort(Λ')`, with the level structure of §2.4). We extract a collision by walking down from the shared root. Maintain a pair of "current" nodes `(x, x')` from `T` and `T'`, initialized to the roots; invariant: `hash(x) = hash(x')` at entry to each step.

- *Root step:* `hash(root) = hash(root')` by hypothesis.
- *Descent:* At an internal step, `x = IH(a, b)` and `x' = IH(a', b')`. We have `H(0x01 ‖ a ‖ b) = H(0x01 ‖ a' ‖ b')`. If `(a‖b) ≠ (a'‖b')` as byte strings, the two distinct 65-byte preimages collide under `H` — output them and stop. Otherwise `a = a'` and `b = b'` (the 65-byte preimage parses uniquely into two 32-byte halves after the fixed prefix), and we recurse into a child where the two trees still disagree (one must, since the overall sequences differ — see the descent-termination argument below).
- *Leaf step:* If both currents are leaves, `x = LH(k, v)` and `x' = LH(k', v')` with `H(0x00 ‖ u32(|k|) ‖ k ‖ v) = H(0x00 ‖ u32(|k'|) ‖ k' ‖ v')`. If the preimages differ (which they must, since the leaf sets differ at this position — distinct `k` or distinct `v` ⇒ distinct preimage by the unambiguous length-prefixed encoding of §2.1), output the collision.
- *Shape step (leaf vs inner):* If one current is a leaf and the other is an inner node, their hashes are equal but their preimages start with different domain bytes (`0x00` vs `0x01`), an immediate collision by MT-2.

**Descent terminates at a disagreement.** If `Λ ≠ Λ'`, either the two sorted sequences differ in some position's `(k, v)` value, or they differ in length (different leaf counts). In both cases the trees cannot be hash-identical at every node down to the leaves *without* exhibiting a collision at some node: by contrapositive, if no node ever collides, then equal node hashes force equal preimages all the way down (the unique-parse property), which forces identical sorted sequences and hence `Λ = Λ'`, contradiction. So the walk reaches some node where equal hashes coincide with unequal preimages — a collision. The extraction is `O(depth) = O(log n)` hash evaluations. ∎

**Last-leaf duplication introduces no collision surface.** The duplication rule (§2.4) creates a subtree `IH(L_j, L_j)` whose two children are the *identical* leaf hash `L_j` of *identical content*. This is *not* an adversarial duplicate-leaf injection: the duplicated node is a deterministic function of the honest leaf set, computed by `merkle_root` itself, not supplied by an attacker. The preimage `0x01 ‖ L_j ‖ L_j` is well-formed and unique; two *different* honest leaf sets that both duplicate still differ at the first disagreeing leaf, so the MT-3 extraction applies unchanged. The genuinely subtle malleability question — can an adversary craft a *different* leaf set that produces the *same* root by exploiting duplication? — is the CVE-2012-2459 question, answered in §6.1.

Reduction target: **A2** (`Preliminaries.md` §2.1, collision resistance, `≤ 2⁻¹²⁸` birthday bound on the 256-bit output). MT-3 is the formal discharge of `BlockchainStateIntegrity.md` §4.2 Claim (ii) ("`MR` is injective up to A2").

---

## 4. Inclusion-proof soundness

This is the load-bearing section for the light-client surface: a light client that holds only a committee-signed `state_root` (from header-sync, a verified snapshot, or a trusted-anchor attestation) must be able to learn the value of any single state entry from an *untrusted* full node and verify it without trusting that node.

### MT-4 (Inclusion-proof soundness)

**Statement.** Fix a leaf set `Λ` with root `r = MR(Λ)` and `n = |Λ|`. For any `(key⋆, value⋆, target_index⋆, proof⋆)` with `target_index⋆ < n`, if

$$
\texttt{merkle\_verify}(r,\; key⋆,\; value⋆,\; target\_index⋆,\; n,\; proof⋆) = \texttt{true},
$$

then either (a) `(key⋆, value⋆)` is the leaf at sorted position `target_index⋆` of `Λ` — i.e. it is a genuine member — or (b) an efficient extractor produces a SHA-256 collision from `(Λ, proof⋆)`. Hence, under A2, a passing verification proves membership except with probability `≤ 2⁻¹²⁸`. An adversarial full node cannot forge a passing proof for a non-member `(key⋆, value⋆)` without breaking A2.

**Proof.** `merkle_verify` (§2.6) recomputes a chain of hashes

$$
c_0 = \mathrm{LH}(key⋆, value⋆),\qquad c_{j+1} = \begin{cases} \mathrm{IH}(c_j, proof⋆[j]) & \text{if } idx_j \text{ even}\\ \mathrm{IH}(proof⋆[j], c_j) & \text{if } idx_j \text{ odd}\end{cases}
$$

for `j = 0 … d-1` where `d` is the level count derived from `n`, and accepts iff `proof_idx == proof⋆.size()` (exact-consume) **and** `c_d = r`.

Let `c_0^{hon}, …, c_d^{hon} = r` be the honest hash chain along the same root-path of the *real* tree `T = MR(Λ)` from the genuine leaf `L_{target\_index⋆} = LH(k_{(target\_index⋆)}, v_{(target\_index⋆)})` up to the root, with honest siblings `p_0^{hon}, …, p_{d-1}^{hon}`. Both chains terminate at the *same* value `r` (the verifier checks `c_d = r`; the honest chain ends at `r` by definition of the tree).

Compare the two chains from the top down. `c_d = c_d^{hon} = r`. Suppose, for contradiction, that the leaf differs: `(key⋆, value⋆) ≠ (k_{(target\_index⋆)}, v_{(target\_index⋆)})`, so `c_0 ≠ c_0^{hon}` (distinct preimages ⇒ distinct hash, except with collision probability — and if `c_0 = c_0^{hon}` despite distinct leaf content, that *is* a leaf-level collision under the §2.1 unambiguous encoding, output it). Then there is a *highest* level `j+1` where the chains agree (`c_{j+1} = c_{j+1}^{hon}`) but the level below disagrees (`c_j ≠ c_j^{hon}` or `proof⋆[j] ≠ p_j^{hon}`). At that level,

$$
\mathrm{IH}(\text{left}_j, \text{right}_j) = c_{j+1} = c_{j+1}^{hon} = \mathrm{IH}(\text{left}_j^{hon}, \text{right}_j^{hon}),
$$

with the two ordered child-pairs unequal as byte strings (they disagree in the current-slot or the sibling-slot, with the slot fixed by the *shared* parity `idx_j` — both chains use the same `target_index⋆`-derived index sequence). Two distinct 65-byte preimages mapping to the same `H` output is a SHA-256 collision; output it. (The exact-consume + range gates ensure `d` and the per-level parities are the genuine ones for an `n`-leaf tree, so the comparison is against the real root-path and not a length-mismatched walk — a length mismatch is rejected outright by the gates of §2.6, scenarios #5–#8.)

Therefore a passing verification with a non-member leaf yields a collision; contrapositively, under A2, a passing verification implies genuine membership with probability `≥ 1 - 2⁻¹²⁸`. ∎

**Light-client composition.** In `determ verify-state-proof` (`main.cpp:5537-5566`), the operator may supply `--state-root` (an independently-trusted root). The CLI verifies against *that* root, not the server-reported one (`main.cpp:5537`: `Hash verify_root = claimed_root;` overridden by the supplied root at 5546), and warns loudly on mismatch (5552-5562). MT-4 then says: a `true` result proves the entry is committed under the *trusted* root. The end-to-end demonstrator `tools/test_verify_state_proof.sh` pins both the positive case (assertion 6: matching external root verifies) and the attack case (assertion 9: a fabricated `--state-root` of all-`a` makes verification fail — a malicious node cannot fabricate a root to make its tampered proof self-consistent against a client that already trusts a different root). Tamper-rejection on `value_hash` and sibling hashes is pinned by assertions 7–8 and by `determ test-merkle-proof-tampering` scenarios #2–#3.

> **Forward reference.** When the planned `LightClientThreatModel.md` lands, its T-L3 (inclusion-proof soundness against a malicious responding node) should cite MT-4 as its cryptographic core, and its anchor-trust precondition should cite §6.2 (S-040) as the operational obligation on where `state_root` *and* `leaf_count` are sourced.

### MT-5 (Non-membership: actual capability — positive only)

**Statement.** The current primitive supports **positive membership proofs only**. It does **not** natively support non-membership (absence) proofs, and a light client **cannot** conclude from a sorted-leaves inclusion proof alone that a given key is absent. We state this explicitly to avoid overclaiming; the sorting of leaves does *not* upgrade the construction to support absence proofs.

**Analysis.** A true non-membership proof in a sorted structure would require the prover to exhibit two *adjacent* committed leaves `(k_{(i)}, k_{(i+1)})` with `k_{(i)} < key⋆ < k_{(i+1)}`, *together with* inclusion proofs for both and a guarantee that they are adjacent in the committed set (i.e. nothing sorts between them). The shipped `merkle_proof` / `merkle_verify` pair proves *one* leaf's membership at a *caller-asserted* sorted index; it does **not** prove adjacency, and the verifier has no way to confirm that `target_index` and `target_index+1` are consecutive with no intervening committed key (the verifier never sees the neighboring leaves, only sibling hashes). The header is explicit (`merkle.hpp:13-16`): *"this isn't a sparse Merkle tree in the literal sense (leaf position is determined by sort order, not by key path), so it doesn't support non-membership proofs natively."* `Chain::state_proof` returns `std::nullopt` for an absent key (`chain.cpp:449`); the comment there (chain.cpp:423-429) notes a light client receiving `nullopt` can only take a *majority vote across peers* as a heuristic — this is **not** a cryptographic absence proof, and an all-Byzantine peer set could lie.

**What the sort *does* buy.** Sorting gives MT-1 (deterministic root over the set) and makes the `target_index` well-defined and binary-searchable (`chain.cpp:445` `lower_bound`). It does not, by itself, yield verifiable absence. A future SMT migration (key-path-indexed leaves) would add native non-membership; the header notes the root stays a 32-byte `Hash` so the wire format would not cascade (`merkle.hpp:18-21`). Until then, protocol-level uses requiring absence proofs (none ship today) must not rely on this primitive.

---

## 5. Composition with `state_root` (S-033 / S-038)

This section threads MT-1 and MT-4 into the chain-level commitment, showing precisely which primitive theorem each composition step consumes.

### 5.1 `state_root` is `MR` over the ten-namespace leaf set

`Chain::compute_state_root` (`chain.cpp:413-415`) is literally `merkle_root(build_state_leaves())`. `build_state_leaves` (`chain.cpp:267-411`) emits one `MerkleLeaf` per live state entry across the ten namespaces `a: s: r: d: i: b: m: p: k: c:` (the `c:` counters ride inside the `k:` prefix as `k:c:` — see `PROTOCOL.md §4.1.1` and `S033StateRootNamespaceCoverage.md` T-2). Each namespace key carries a distinct ASCII prefix, so cross-namespace key collisions are impossible (a string `domain` that is both an account and a registrant yields distinct leaves `"a:"+domain` and `"r:"+domain`). The leaf encodings are the subject of `S033StateRootNamespaceCoverage.md`; this document treats them as an opaque distinct-keyed multiset.

### 5.2 MT-1 ⇒ reproducible `state_root` (apply-determinism composition)

By **FA-Apply-1** (`AccountStateInvariants.md`), two honest nodes that start from byte-identical state and apply the same block reach byte-identical post-apply state — hence `build_state_leaves` emits the *same multiset* of `(key, value_hash)` pairs on both. By **MT-1**, the same multiset yields the same root. Therefore both nodes compute the same `state_root`, and the apply-time gate at `chain.cpp:1432-1444` (`if (computed != b.state_root) throw …`) accepts an honestly-produced block on every honest receiver. This is the primitive-level justification for `BlockchainStateIntegrity.md` T-2's Claim (i) and `S033StateRootNamespaceCoverage.md` T-3/T-4.

### 5.3 MT-3 ⇒ divergence detection (apply-gate soundness)

By **MT-3**, two *different* post-apply states (any divergence in any namespace — a different balance, a missing receipt, a different counter) produce *different* roots except with probability `≤ 2⁻¹²⁸`. So if a Byzantine producer ships a block whose declared `state_root` does not match the canonical post-apply state, every honest receiver's recomputed root differs from the declared one and the gate fires loudly (`"state_root mismatch at block <h> … (S-033)"`). This is the primitive-level justification for `BlockchainStateIntegrity.md` T-2's Claim (ii). The dormancy gap that made this gate inactive before S-038 (the producer never populated `body.state_root`) is `BlockchainStateIntegrity.md` §2.3 / SECURITY.md §S-038 — orthogonal to the primitive's soundness, which MT-3 establishes unconditionally.

### 5.4 MT-4 ⇒ trustworthy light-client state-proofs

By **MT-4**, a light client holding a committee-signed `state_root` can verify any single state entry returned by an untrusted full node: a passing `merkle_verify` proves the entry is committed under that root (the committee-signed `Block.state_root` is bound into the block hash via `signing_bytes`, which is in turn bound by the K-of-K creator signatures — `PROTOCOL.md §4.1` + `BlockchainStateIntegrity.md` §2.3). The chain of trust is: committee signatures (A1) → `block_hash` → `state_root` (when non-zero) → [MT-4] → leaf membership. The `determ verify-state-proof` CLI is the shipped local-verifier; the planned `LightClientThreatModel.md` T-L3 will formalize the end-to-end light-client trust composition with MT-4 as its core.

### 5.5 Cross-reference to BlockchainStateIntegrity.md

`BlockchainStateIntegrity.md` proves the four-surface composition (at-rest / produce / receive / steady) and explicitly defers the two Merkle-primitive sub-claims to "MR is a function" (§4.2 Claim (i)) and "MR is injective up to A2" (§4.2 Claim (ii)). **This document is the cited proof of those two claims** — MT-1 discharges Claim (i), MT-3 discharges Claim (ii). The relationship is: `MerkleTreeSoundness` (primitive) ⊂ `S033StateRootNamespaceCoverage` (leaf-set completeness) ⊂ `BlockchainStateIntegrity` (four-surface composition).

---

## 6. Known limitations and residual notes

### 6.1 CVE-2012-2459 (Bitcoin duplicate-tx Merkle malleability) — DOES NOT APPLY

**The CVE.** CVE-2012-2459 was a Bitcoin block-validity denial-of-service rooted in the *same* last-node-duplication rule Determ uses. In Bitcoin's transaction Merkle tree, the duplication at odd levels means certain *distinct* transaction lists produce the *identical* merkle root. Concretely: a list of `2k` txs ending in `[…, A, B]` and a *different* list of `2k+1` txs ending in `[…, A, B, B]` (B duplicated by the attacker) hash to the same root, because the honest `2k`-list with an odd internal level would itself duplicate `B`, matching the attacker's explicit duplicate. An attacker could take a valid block, append duplicate transactions to craft a *mutant* with the same merkle root but a different (invalid) transaction set, and relay it; a node that cached the mutant as "invalid" by its (shared) block hash would then reject the genuine block — a cache-poisoning DoS. The root cause is **attacker-controlled duplicate leaves**: the tx list is attacker-supplied and may contain crafted duplicates that alias the honest duplication.

**Why Determ is not vulnerable.** Determ's Merkle leaves are **not** an attacker-supplied ordered list. They are the **sorted, unique, namespace-keyed entries of the chain state**, assembled by `Chain::build_state_leaves` (`chain.cpp:267-411`) from `std::map` and `std::set` iterations. Three structural facts together close the attack:

1. **Keys are unique within each namespace.** Every leaf's key is `prefix ‖ map_key`, and the source containers are keyed maps/sets: `accounts_` is `std::map<std::string, …>` keyed by domain, `stakes_` likewise, `registrants_`, `dapp_registry_`, `abort_records_` likewise; `applied_inbound_receipts_` is a `std::set<std::pair<ShardId, Hash>>`; `merge_state_` / `pending_param_changes_` are keyed by shard / `(eff_height, idx)`. A `std::map`/`std::set` cannot contain two entries with the same key. Across namespaces, the distinct ASCII prefixes (`a:`, `s:`, …; §5.1) keep keys disjoint. **Therefore the leaf set has pairwise-distinct keys by construction.**

2. **The set is sorted, and `merkle_root` re-sorts it.** Even if a caller passed leaves in some order, `merkle_root` sorts by key (§2.3). The tree shape is a deterministic function of the *sorted distinct-key sequence*, which is uniquely determined by the *set*. There is no "ordering freedom" an attacker could exploit to alias a duplicate.

3. **There is no attacker-controlled path that injects a duplicate leaf.** A block does not carry the Merkle leaves; it carries `state_root` (a 32-byte hash) plus the *transactions*, and each honest receiver *recomputes* `build_state_leaves()` from its own post-apply state. An attacker cannot hand a node a crafted leaf list — the node derives the leaves itself, deterministically, from a unique-keyed state. The only attacker influence on the leaf set is via *transactions* that mutate state, and any such mutation changes a leaf's *value_hash* at a *unique key*, which (by MT-3) changes the root — it cannot produce a second distinct state with the same root except by a SHA-256 collision.

**Formal statement.** The CVE-2012-2459 malleability requires the existence of two *distinct* leaf sequences `s ≠ s'` with `MR(s) = MR(s')` that are both *reachable by an adversary as inputs*. In Determ, (a) the leaf set is canonicalized to a sorted distinct-key sequence, so `s` is a function of the underlying set with no ordering or duplication freedom (the duplication is internal to `merkle_root`, deterministic, and over identical content per MT-3's "no collision surface" note), and (b) the adversary cannot supply leaves directly — they are recomputed from unique-keyed state. The honest `2k`-vs-`2k+1` aliasing the CVE exploits has no analog: there is exactly one canonical leaf sequence per state, and producing a *different* state with the same root reduces to a SHA-256 collision (MT-3, A2). **Verdict: the attack does not apply.** No finding.

A residual hardening note: the `merkle.cpp:48-49` comment ("keys assumed unique by caller; we don't enforce here") means the uniqueness guarantee is a *caller contract*, discharged by `build_state_leaves`'s use of keyed containers rather than by `merkle_root` itself. A *future* caller that fed `merkle_root` an attacker-influenced list with possible duplicate keys would need to re-examine this analysis. Today there is exactly one production caller (`build_state_leaves`) and it satisfies the contract; the unit-test caller (`make_leaves` in `determ test-merkle*`) uses `{'k', i}` distinct keys. This is captured as a documentation obligation, not a code defect.

### 6.2 S-040 — `leaf_count` is not bound into the hash (registered caller-trust limitation)

**The limitation.** `merkle_verify` consumes `leaf_count` only to drive the level count and per-level duplication parity; it is **not** an input to `LH` or `IH` (§2.6). Two distinct `(target_index, leaf_count)` pairs that yield the *same walk shape* — same `ceil(log2(N))` level count and the same per-level parity sequence — share the same proof structure and verify identically. The concrete failure, pinned by `determ test-merkle-proof-tampering` scenario #12 (`main.cpp:28829-28844`): claiming `leaf_count = 8` for a genuinely-5-leaf tree at index 2 verifies as **true**, because both yield identical 3-level walks consuming the same 3 siblings in the same left/right order, so the recomputed hash equals the 5-leaf root.

**Why this is not a soundness break of MT-4.** MT-4 is stated and proved with `n = |Λ|` — the *genuine* leaf count of the tree the root commits to. The S-040 issue is a *caller-trust* problem orthogonal to MT-4: it bites only a caller that sources `leaf_count` from an *untrusted* channel *different* from the channel that supplied the trusted root. The header documents the mitigation (`merkle.hpp:64-83`): **always source `leaf_count` from the same committed/anchored source as `state_root`.** In the shipped path this holds: `Chain::state_proof` returns `leaf_count` from the daemon's own canonical state (`chain.cpp:456`: `p.leaf_count = leaves.size()`), and a light client verifying against a single trusted daemon gets a consistent `(root, leaf_count)` pair. The danger is the split-source case — proof from one untrusted node, `leaf_count` from another — which a careful light client avoids by binding `leaf_count` into its trusted anchor.

**Status.** Registered as **S-040 (Low/Op)** in `docs/SECURITY.md`; the structural fix path (domain-separate `leaf_count` into the leaf hash, e.g. `LH = H(0x00 ‖ u32(leaf_count) ‖ u32(|k|) ‖ k ‖ v)`) breaks v1 wire compatibility and is tracked for a future v2.x flag-day. This document does not re-open S-040; it records that MT-4 holds with the genuine `leaf_count` and that the operational obligation is to source it from the anchor.

### 6.3 Not a sparse Merkle tree — no native non-membership

Per MT-5: the construction proves positive membership only. Any future protocol use requiring verifiable absence proofs must migrate to an SMT (key-path-indexed leaves). The header (`merkle.hpp:18-21`) notes the migration is wire-compatible at the root level (still a 32-byte `Hash`). Today no shipped feature relies on non-membership, so this is a documented design boundary, not a gap.

### 6.4 Single-leaf root equals leaf hash (degenerate but sound)

For `n = 1`, `MR({(k,v)}) = LH(k, v)` with an empty proof (§2.5). A light client verifying a single-leaf tree recomputes `LH(k, v)` and compares directly to the root with zero siblings consumed (`proof_idx == 0 == proof.size()`). This is sound — there is exactly one leaf, MT-4 holds vacuously (the only `target_index` is 0), and MT-2's domain separation still distinguishes this leaf-root from any inner hash. Pinned by `determ test-merkle` assertion 2 + `determ test-merkle-proof-tampering` scenario #9 (`main.cpp:28747-28767`).

---

## 7. Implementation cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| `merkle_leaf_hash` | `src/crypto/merkle.cpp:25-34` | LH definition (§2.1); `0x00` prefix + length-prefixed key. |
| `merkle_inner_hash` | `src/crypto/merkle.cpp:36-43` | IH definition (§2.2); `0x01` prefix. |
| `merkle_root` | `src/crypto/merkle.cpp:45-73` | Sort (§2.3) + odd-count duplication (§2.4) + base cases (§2.5); subject of MT-1, MT-3. |
| `merkle_proof` | `src/crypto/merkle.cpp:75-111` | Sibling-path generator; sort + parity-driven sibling selection. |
| `merkle_verify` | `src/crypto/merkle.cpp:113-141` | Verifier (§2.6); subject of MT-4; range/underflow/exact-consume gates. |
| `MerkleLeaf` + header contracts | `include/determ/crypto/merkle.hpp:37-103` | Leaf struct; `0x00`/`0x01` domain-sep note (lines 93-102); SMT/non-membership note (13-21); **S-040 caller-trust note (64-83)**. |
| `Chain::build_state_leaves` | `src/chain/chain.cpp:267-411` | The unique-keyed 10-namespace leaf assembly; the §6.1 CVE non-applicability rests on its `std::map`/`std::set` sources. |
| `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | `merkle_root(build_state_leaves())`; the S-033 root. |
| `Chain::state_proof` | `src/chain/chain.cpp:435-462` | Light-client proof producer; sorts, `lower_bound`s the key, returns `(key, value_hash, target_index, leaf_count, proof)`. |
| apply-time gate | `src/chain/chain.cpp:1421-1446` | Recompute-and-throw; consumes MT-1 + MT-3 (§5.2-§5.3). |
| snapshot-restore gate | `src/chain/chain.cpp:1880-1911` | Tail-head `state_root` check; sibling surface (FA-Apply-2). |
| `determ verify-state-proof` CLI | `src/main.cpp:5471-5589` | The shipped light-client local verifier; `--state-root` override at 5537-5566; consumes MT-4 (§5.4). |
| `determ test-merkle` | `src/main.cpp:6217-6364` (10 assertions) | Base cases, determinism, round-trips, domain-sep (a.9), sort-invariance (a.10). |
| `determ test-merkle-proof-tampering` | `src/main.cpp:28555-28934` (15 scenarios) | Exhaustive tamper detection; S-040 limitation pin (#12); key-binding (#14-#15); padded-tree round-trips (#12-#13). |
| `tools/test_merkle.sh` | `tools/test_merkle.sh` | Driver for `determ test-merkle`. |
| `tools/test_merkle_proof_tampering.sh` | `tools/test_merkle_proof_tampering.sh` | Driver for `determ test-merkle-proof-tampering`. |
| `tools/test_verify_state_proof.sh` | `tools/test_verify_state_proof.sh` (9 assertions) | End-to-end light-client demonstrator; MT-4 in practice (assertions 6-9). |
| Canonical spec | `docs/PROTOCOL.md §4.1.1` | The `state_root` Merkle-leaf table + balanced-binary-tree statement + empty-tree sentinel. |

---

## 8. Status

**Spec complete; implementation shipped; structural + tamper tests shipped; proof complete.**

- **Implementation** — the four primitive functions live in `src/crypto/merkle.cpp` (v2.1 foundation; the S-038 closure made the producer actually populate `body.state_root`, activating the apply-time gate that consumes MT-1 + MT-3). The light-client verifier is the `determ verify-state-proof` CLI in `src/main.cpp`.
- **Tests** — `determ test-merkle` (10 assertions, commit `47f1119`), `determ test-merkle-proof-tampering` (15 scenarios, commit `fbeec00`), and `tools/test_verify_state_proof.sh` (9 assertions) collectively pin every structural and tamper-detection property proved here, including the S-040 `leaf_count` limitation (scenario #12) and the leaf/inner domain separation (assertion 9). CI gates on these passing.
- **Proof** — this document is analytic; it changes no code. MT-1 (determinism) and MT-3 (collision-resistance inheritance) discharge the two Merkle-primitive sub-claims that `BlockchainStateIntegrity.md` §4.2 and `S033StateRootNamespaceCoverage.md` T-3/T-4 cite without proof. MT-4 (inclusion-proof soundness) is the cryptographic core the light-client surface rests on. MT-2 (domain separation) and MT-5 (non-membership capability boundary) document the structural defenses and the SMT design boundary.
- **CVE-2012-2459 verdict (§6.1):** **does NOT apply.** Determ's leaves are sorted, unique, namespace-keyed state entries recomputed by each node from its own state via `build_state_leaves`; the attacker cannot supply a crafted duplicate-leaf list, so the Bitcoin duplicate-tx aliasing has no analog. The last-leaf duplication is over identical honest content and introduces no collision surface (MT-3). No finding.
- **Open limitation:** S-040 (`leaf_count` not bound into the hash) is a registered Low/Op caller-trust item, orthogonal to MT-4's soundness, mitigated operationally by sourcing `leaf_count` from the same anchor as `state_root` (§6.2). Structural fix tracked for a future wire-breaking v2.x flag-day.

---

## 9. References

### Implementation sites
- `src/crypto/merkle.cpp:25-34` — `merkle_leaf_hash` (LH, `0x00`).
- `src/crypto/merkle.cpp:36-43` — `merkle_inner_hash` (IH, `0x01`).
- `src/crypto/merkle.cpp:45-73` — `merkle_root` (sort + duplication + base cases).
- `src/crypto/merkle.cpp:75-111` — `merkle_proof`.
- `src/crypto/merkle.cpp:113-141` — `merkle_verify`.
- `include/determ/crypto/merkle.hpp:13-103` — header contracts (SMT note, S-040 note, domain-sep note).
- `src/chain/chain.cpp:267-411` — `Chain::build_state_leaves` (unique-keyed leaf assembly; §6.1).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root`.
- `src/chain/chain.cpp:435-462` — `Chain::state_proof`.
- `src/chain/chain.cpp:1421-1446` — apply-time state_root gate.
- `src/chain/chain.cpp:1880-1911` — snapshot-restore state_root gate.
- `src/main.cpp:5471-5589` — `determ verify-state-proof` CLI.
- `src/main.cpp:6217-6364` — `determ test-merkle`.
- `src/main.cpp:28555-28934` — `determ test-merkle-proof-tampering`.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §1.3 hash notation; §2.1 SHA-256 collision / preimage / 2nd-preimage (A2); §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/BlockchainStateIntegrity.md` — four-surface S-021 + S-033 + S-038 composition; §4.2 Claims (i)+(ii) discharged here by MT-1 + MT-3.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — 10-namespace coverage completeness; T-3 (deterministic leaf ordering) composes with MT-1; T-2 (namespace disjointness) underwrites §5.1 + §6.1.
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — apply determinism; supplies the same-multiset precondition MT-1 consumes (§5.2).
- `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) — snapshot-pathway sibling; reuses MT-1 for round-trip soundness.
- `docs/proofs/SelectiveAbort.md` (FA3) — cited only to disambiguate: FA3 is *selective-abort resistance*, NOT SHA-256 collision resistance; reductions in this document target A2, not FA3.
- *(forward)* `LightClientThreatModel.md` (planned) — T-L3 should cite MT-4 as its inclusion-proof-soundness core.

### Tests
- `tools/test_merkle.sh` + `determ test-merkle` (10 assertions) — MT-1, MT-2, base cases.
- `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` (15 scenarios) — MT-4 tamper rejection, S-040 limitation (#12), key-binding (#14-#15).
- `tools/test_verify_state_proof.sh` (9 assertions) — MT-4 end-to-end light-client verification.

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` algorithm + Merkle-leaf table.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population (activates the apply-gate).
- `docs/SECURITY.md §S-040` — `leaf_count` caller-trust invariant (§6.2).
- NIST FIPS 180-4 — SHA-256 (A2).
- RFC 6962 §2.1 — Certificate Transparency `0x00`/`0x01` leaf/node tagged hashing (the MT-2 domain-separation pattern Determ follows).
- CVE-2012-2459 — Bitcoin duplicate-transaction Merkle malleability (analyzed in §6.1; does not apply).
