# MerkleRootRecomputeSoundness — OFFLINE whole-leaf-set `state_root` recompute (`determ-wallet merkle-root`)

This document proves the soundness of the `determ-wallet merkle-root` subcommand: a **fully OFFLINE, one-shot recompute of the S-033 committed `state_root` from a FULL leaf set**. An operator hands it a JSON array of every leaf `{value_hash, key | key_hex}` in the committed state; it sorts the leaves by raw key bytes, hashes each into a leaf node, builds the sorted-leaves balanced binary Merkle tree (Bitcoin-style duplicate-last on odd rows), applies the S-040 leaf-count root-wrapper, and emits the resulting 32-byte root. With `--check <hex64>` it byte-compares the recomputed root against an operator-supplied (committee-signed) expected root and reports VALID / INVALID with a monitor-friendly exit code (`0` success or `--check` match, `1` args/parse/IO, `2` mismatch). It is the **inverse** of `state-proof-verify`: `state-proof-verify` proves ONE leaf is *in* the tree given a root; `merkle-root` proves a WHOLE leaf set *reconstructs* the root.

**The load-bearing design fact (TCB separation).** `determ-wallet` deliberately does **not** link `libdeterm_chain`. Consequently the canonical Merkle root function (`src/crypto/merkle.cpp::merkle_root`, with its `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap` helpers) is **reimplemented inline** in `wallet/main.cpp::cmd_merkle_root` over `std::array<uint8_t,32>` rows + OpenSSL `SHA256`, rather than called from the chain library. MR-1 proves this reimplementation is **byte-identical** to the daemon's `merkle_root` on every leaf set — so `merkle-root`'s output equals the daemon's `Chain::compute_state_root` (which is literally `merkle_root(build_state_leaves())`, `src/chain/chain.cpp:413-415`) for the same leaf set. This mirrors `OfflineBlockVerifySoundness.md` BV-1's byte-equivalence posture for the `tx_root` recompute, and is the *cost* of the wallet's lean TCB paid as a stated, proved byte-equivalence rather than a hidden assumption.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision / second-preimage resistance (§2.1), **A3** = SHA-256 preimage resistance (§2.1), **A4** = CSPRNG uniform sampling (§2.3). `merkle-root` reduces to **A2 only**; A1, A3, A4 are not used by the recompute itself (A1 enters only by *reference*, in MR-3, as the source of trust for the `--check` root — and that is an operator precondition, not a probability term in this command).

**Companion documents.** `Preliminaries.md` (F0) §1.3 (hash notation `H`, `‖`, big-endian integer encoding), §2.0 (assumption labels), §2.1 (A2); `MerkleTreeSoundness.md` (the primitive whose MT-1 determinism, MT-2 domain separation, MT-3 collision-resistance inheritance, and §6.2 S-040 `leaf_count` binding `merkle-root` recomputes verbatim — this document composes those theorems over the wallet's reimplementation rather than re-deriving them); `StateRootAnchorSoundness.md` (SR-1 — why a `--check` root must come from a committee-signed header, not from the daemon's bare assertion; the trust-anchor `merkle-root` consumes as a parameter exactly as `block-verify` consumes `--block-digest`); `S033StateRootNamespaceCoverage.md` (T-1..T-5 — the ten-namespace leaf-set completeness; `merkle-root`'s "supply ALL leaves" precondition is exactly the completeness this proof's T-1 enumerates); `OfflineBlockVerifySoundness.md` (the sibling wallet-TCB-separated OFFLINE verifier whose BV-1 byte-equivalence posture and F-BV-style honest-boundary findings this document mirrors); `docs/PROTOCOL.md §4.1.1` (the canonical `state_root` Merkle-leaf table) + §10.2 (`state_proof` RPC return shape); `docs/SECURITY.md` §S-033 / §S-038 / §S-040 (the closures this recompute exercises).

---

## 0. Implementation status

**`int cmd_merkle_root(int argc, char** argv)` is IMPLEMENTED in `wallet/main.cpp`** (search `int cmd_merkle_root`; dispatched on `merkle-root`). It is read directly off source for this proof; there is no spec-vs-implementation divergence to reconcile. The command:

1. Parses `--leaves <file>` (required), `--check <hex64>` (optional), `--json` (optional).
2. Loads the leaf JSON: a top-level array of objects each carrying `value_hash` (64-hex / 32 bytes, required) and **exactly one** of `key` (UTF-8 string → raw bytes) or `key_hex` (even-length hex → binary bytes). Any malformed entry → `return 1` (fail-closed parse fault), never a silent root.
3. Recomputes the root inline (the §2 construction).
4. With `--check`: lowercases the expected hex, byte-compares against the recomputed root hex, sets `match`, and `return (have_check && !match) ? 2 : 0`.

The two cryptographic helpers it reimplements inline are byte-for-byte copies of the chain primitive: `leaf_hash` (`wallet/main.cpp` `cmd_merkle_root` lambda) mirrors `crypto::merkle_leaf_hash`; `inner_hash` mirrors `crypto::merkle_inner_hash`; the trailing `0x02 ‖ u32_be(leaf_count) ‖ inner_root` wrapper mirrors `crypto::merkle_root_wrap`. The **same** leaf/inner lambdas appear in the sibling `cmd_state_proof_verify` (`wallet/main.cpp`, `int cmd_state_proof_verify`), so the two wallet commands share one reimplemented hash core — `merkle-root` walks the *whole* tree bottom-up, `state-proof-verify` walks *one* root-path.

---

## 1. Scope

### 1.1 In scope

The `determ-wallet merkle-root` command per §0. Its three soundness obligations:

| Theorem | What it establishes | Backing |
|---|---|---|
| **MR-1** | The wallet's inline recompute is **byte-identical** to `src/crypto/merkle.cpp::merkle_root` on every leaf set — so its output equals the daemon's `compute_state_root` for the same set. | Deterministic function equality (unconditional); doubles as a regression tripwire over the hand-rolled reimplementation. |
| **MR-2** | Under A2, a `--check` MATCH means the supplied leaf *set* is **exactly** the set committed by the expected root — any single missing / extra / altered leaf yields a different root except with an A2 break; domain separation + length-prefixing prevent leaf/inner/wrap and key/value confusion; the S-040 wrap binds `leaf_count`. | A2 (via MT-2 + MT-3 + §6.2). |
| **MR-3** | The honest boundary: a MATCH proves the *set* commits to the *given* root; it does **not** prove the root is genuine (it must come from a committee-signed header — `StateRootAnchorSoundness.md`), nor that the supplied set is complete / canonical (a strict subset simply won't match). | Statement of preconditions (no new assumption). |

### 1.2 Out of scope (intentional — the recompute's coverage boundary)

- **Root authenticity.** `merkle-root --check R` takes `R` as a *parameter*. It does not verify `R` is the chain's genuine committee-committed `state_root` at any height — that is `StateRootAnchorSoundness.md` SR-1's job (`determ-light verify-state-root`), and the operator must source `R` from a committee-signed header / verified snapshot tail / `verify-state-root` output. This is the exact analog of `block-verify` trusting its `--block-digest` (`OfflineBlockVerifySoundness.md` F-BV2): the wallet trusts the anchor it is handed. §5 F-MR2.
- **Leaf-set completeness / canonicity.** `merkle-root` hashes *whatever leaves the JSON carries*. It does not — and cannot, with no chain link — confirm the supplied array is the *complete* ten-namespace leaf set (`S033StateRootNamespaceCoverage.md` T-1) or that each `value_hash` was correctly derived from real chain state (the per-namespace value-hash encodings of `S033StateRootNamespaceCoverage.md §2.1`). It asserts only that *this* set reconstructs (or does not reconstruct) the given root. §5 F-MR3.
- **The semantics of any single leaf.** Whether leaf `("a:"+domain, vh)` encodes the *correct* `(balance, nonce)` for that account is the apply-layer's concern (`AccountStateInvariants.md`); `merkle-root` treats `value_hash` as opaque 32 bytes. §5 F-MR4.
- **Non-membership.** Per `MerkleTreeSoundness.md` MT-5, the primitive proves positive structure only. A subset that *fails* to match tells the operator "this is not the committed set" but does not cryptographically prove *which* leaf is missing/extra. §5 F-MR5.

---

## 2. Construction specification

Read directly off `wallet/main.cpp::cmd_merkle_root` and the chain reference `src/crypto/merkle.cpp`. Throughout, `H : {0,1}* → {0,1}²⁵⁶` is SHA-256 (`Preliminaries.md §1.3`), `‖` is byte concatenation, `u32_be(n)` is the 4-byte big-endian encoding, and a leaf is an opaque `(key ∈ {0,1}*, value_hash ∈ {0,1}²⁵⁶)` pair.

### 2.1 Leaf hash (the `leaf_hash` lambda)

For a leaf with key bytes `k` and 32-byte `value_hash v`:

$$
\mathrm{LH}(k, v) \;=\; H\big(\,\texttt{0x00} \,\|\, u32\_be(|k|) \,\|\, k \,\|\, v\,\big).
$$

The wallet lambda pushes `0x00`, then the four big-endian length bytes via the `be_u32` helper, then `key.begin()..key.end()`, then `vh.begin()..vh.end()`, and `SHA256`s the buffer. This is byte-for-byte `crypto::merkle_leaf_hash` (`merkle.cpp::merkle_leaf_hash`): same `0x00` prefix, same `append_be_u32(key.size())` length prefix, same trailing fixed-width 32-byte value. (The chain function guards `if (!key.empty())` before appending key bytes; the wallet `insert`s an empty range — a no-op — so the empty-key preimage `0x00 ‖ u32_be(0) ‖ v` is identical on both sides.)

### 2.2 Inner hash (the `inner_hash` lambda)

For two 32-byte child hashes `l, r`:

$$
\mathrm{IH}(l, r) \;=\; H\big(\,\texttt{0x01} \,\|\, l \,\|\, r\,\big).
$$

The wallet lambda pushes `0x01`, then `l`, then `r`, and `SHA256`s. Byte-for-byte `crypto::merkle_inner_hash` (`merkle.cpp::merkle_inner_hash`): same `0x01` prefix, same fixed-width 32+32 children, no length prefix needed (both children fixed-width).

### 2.3 Sort, key decoding, and the distinct-key precondition

Before hashing, `cmd_merkle_root` sorts the parsed `leaves` vector by raw key bytes:

```cpp
std::sort(leaves.begin(), leaves.end(),
          [](const Leaf& a, const Leaf& b) { return a.key < b.key; });
```

`Leaf::key` is `std::vector<uint8_t>`; C++'s `operator<` is byte-wise lexicographic, unsigned, shorter-is-smaller on a common prefix — **the identical strict total order** `crypto::merkle_root` uses (`merkle.cpp` `a.key < b.key`, `MerkleTreeSoundness.md §2.3`). The key bytes themselves are produced identically to what the daemon commits: a `key` string becomes its UTF-8 bytes (ASCII namespaces `a: s: r: d: k: c:`), and a `key_hex` string becomes the decoded binary bytes (the composite `i: m: p:` keys, which carry big-endian shard/height integers — `S033StateRootNamespaceCoverage.md §2.1`). The "exactly one of `key`/`key_hex`" parse gate (`hk == hs` → `return 1`) ensures every leaf has a well-defined key. Distinct keys are a **caller precondition** (the daemon's `build_state_leaves` discharges it by construction via keyed `std::map`/`std::set` sources — `MerkleTreeSoundness.md §6.1`); §5 F-MR6 states the residual obligation for the operator supplying the JSON.

### 2.4 Tree reduction + odd-row rule + base cases

After sorting, each leaf is hashed into a working row, then levels reduce pairwise until one node remains, duplicating the last node on odd rows:

```cpp
std::vector<std::array<uint8_t,32>> row;
for (auto& l : leaves) row.push_back(leaf_hash(l.key, l.vh));
while (row.size() > 1) {
    if (row.size() % 2 == 1) row.push_back(row.back());   // duplicate-last
    std::vector<std::array<uint8_t,32>> next;
    for (size_t i = 0; i + 1 < row.size(); i += 2)
        next.push_back(inner_hash(row[i], row[i + 1]));
    row = std::move(next);
}
```

This is line-for-line `crypto::merkle_root`'s reduction loop (`merkle.cpp`): same `row.size() % 2 == 1` Bitcoin-style last-node duplication at every odd level, same left-to-right pairing, same `IH` composition order. The **empty leaf set** is the all-zero sentinel: `cmd_merkle_root` initializes `root` to `std::array<uint8_t,32>{}` (32 zero bytes) and the `if (leaf_count > 0)` guard skips the whole computation — exactly `merkle_root`'s `if (leaves.empty()) return Hash{};` (`MerkleTreeSoundness.md §2.5`, the "no committed state" sentinel). The **single-leaf** case skips the `while` loop, so `root` (before wrapping) is `LH(k, v)` — identical on both sides.

### 2.5 The S-040 leaf-count wrapper

The committed root is **not** the bare inner root. After the reduction, both the wallet and the daemon wrap:

$$
\mathrm{root} \;=\; H\big(\,\texttt{0x02} \,\|\, u32\_be(\text{leaf\_count}) \,\|\, \text{inner\_root}\,\big),
$$

where `leaf_count` is the genuine number of supplied leaves (`leaves.size()`, captured *before* the odd-row duplications that only mutate the working row). The wallet pushes `0x02`, the four big-endian `leaf_count` bytes, then the 32-byte `inner_root`, and `SHA256`s — byte-for-byte `crypto::merkle_root_wrap` (`merkle.cpp::merkle_root_wrap`), with the `0x02` prefix domain-separated from the `0x00` leaf / `0x01` inner tags (extending the `MerkleTreeSoundness.md` MT-2 separation to a third class). This is the S-040 binding (`MerkleTreeSoundness.md §6.2`, `SECURITY.md §S-040`): the committed root binds the *true* leaf count, so a forged count yields a different wrapper hash. The wallet's `cmd_state_proof_verify` applies the **same** `0x02` wrapper to the inner root it reconstructs from a single proof path before comparing to `--root` — the two wallet commands agree on the wrap byte-for-byte.

### 2.6 The `--check` comparison

With `--check <hex>`, the command lowercases the expected hex (`std::tolower` over each char), renders the recomputed root as lowercase hex (`to_hex(root)`), and sets `match = (expected_lower == root_hex)`. The exit code is `(have_check && !match) ? 2 : 0`. There is no hex-shape validation on `--check` beyond the case-fold (a malformed expected string simply never equals a 64-hex root, yielding INVALID / exit 2 — fail-closed, not a false MATCH). Output is read-only over the verdict.

---

## 3. Soundness theorems

Let `MR(Λ)` denote `crypto::merkle_root(Λ)` (the daemon primitive) and `MR_w(Λ)` denote the wallet's `cmd_merkle_root` recompute, both over a finite multiset of distinct-keyed leaves `Λ = {(k_1,v_1),…,(k_n,v_n)}`. Bounds follow `Preliminaries.md §2.0` (A2 ≈ `2⁻¹²⁸`).

### 3.1 MR-1 (byte-equivalence to `crypto::merkle_root`)

**Statement.** For every leaf set `Λ`, `MR_w(Λ) = MR(Λ)` byte-for-byte. Consequently `merkle-root`'s emitted root equals the daemon's `Chain::compute_state_root` (`= merkle_root(build_state_leaves())`, `chain.cpp:413-415`) for the same leaf set, and a `merkle-root --check R` MATCH is *exactly* the equality the daemon's apply-time S-033 gate checks (`chain.cpp:1432-1444`: `if (computed != b.state_root) throw …`). This is **unconditional** — pure deterministic function equality, no cryptographic assumption.

**Proof.** Match the five operations of the two routines:

1. **Parse → leaf domain.** Both consume the same abstract leaf set: a multiset of `(key ∈ {0,1}*, value_hash ∈ {0,1}²⁵⁶)` pairs. The wallet decodes `value_hash` to a fixed 32-byte array (rejecting non-32-byte at parse, `return 1` — never a silent PASS) and `key`/`key_hex` to raw bytes (§2.3); the daemon receives `MerkleLeaf{key, value_hash}` already in that form. The byte content of each `(key, value_hash)` is identical on inputs the daemon could hold.

2. **Sort.** Both sort by `a.key < b.key` over `std::vector<uint8_t>` — the *same* unsigned byte-wise lexicographic strict total order (§2.3). On a distinct-keyed set the sorted sequence is the *unique* permutation regardless of input order (non-stability is irrelevant with no ties — `MerkleTreeSoundness.md` MT-1). ⇒ both produce the same sorted leaf sequence.

3. **Leaf hash.** Both compute `LH(k,v) = H(0x00 ‖ u32_be(|k|) ‖ k ‖ v)` with identical byte layout (§2.1). SHA-256 is a deterministic, unkeyed function; the streaming `SHA256Builder` append on the daemon side and the one-shot `SHA256(buf)` on the wallet side produce identical digests over the identical preimage (Merkle–Damgård: appending the same byte sequence then finalizing equals one-shot hashing the concatenation — the same argument `OfflineBlockVerifySoundness.md` BV-1 step 2 makes for `tx_root`). ⇒ identical leaf row.

4. **Reduction.** Both run the identical `while (row.size() > 1)` loop with the identical `row.size() % 2 == 1` duplicate-last rule, the identical left-to-right pairing, and the identical `IH(l,r) = H(0x01 ‖ l ‖ r)` composition (§2.2, §2.4). The loop is a fixed sequence of `IH` evaluations driven only by `row.size()` parity, identical on both sides. ⇒ identical `inner_root`. The empty-set and single-leaf base cases coincide (§2.4): both emit the all-zero sentinel for `n = 0` and (pre-wrap) `LH(k,v)` for `n = 1`.

5. **Wrap.** Both apply `root = H(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` with `leaf_count = n` the genuine supplied count (§2.5), byte-identical layout. ⇒ identical committed root.

Each stage is byte-identical, so the composition is byte-identical: `MR_w(Λ) = MR(Λ)`. Since `Chain::compute_state_root() = merkle_root(build_state_leaves())`, feeding `merkle-root` the leaf set `build_state_leaves()` would emit equals the daemon's `state_root`. ∎

**Regression-tripwire corollary.** Because MR-1 is an *exact* function equality over a hand-rolled reimplementation, any future drift between `cmd_merkle_root`'s inline lambdas and `crypto::merkle_root` (a changed prefix byte, a flipped endianness, a dropped length prefix, a different odd-row rule, a missing wrap) manifests as `MR_w(Λ) ≠ MR(Λ)` on some `Λ` — a `merkle-root --check R` against a daemon-emitted `R` would then report INVALID on an honest leaf set. The command therefore doubles as an offline tripwire over the reimplementation: a CI fixture that recomputes a known leaf set's root and `--check`s it against the daemon's `compute_state_root` output pins the byte-equivalence MR-1 asserts. (This is the wallet-TCB-separation cost — `OfflineBlockVerifySoundness.md §0`/BV-1 — paid as a proved equivalence plus a tripwire, not a hidden assumption.)

### 3.2 MR-2 (`--check` soundness)

**Statement.** Under A2, if `merkle-root --leaves L --check R` reports MATCH (exit 0), then the supplied leaf *set* `Λ_L` is **exactly** the set committed by `R` — i.e. `R = MR(Λ_L)` and no leaf set `Λ' ≠ Λ_L` that an efficient adversary could have intended also satisfies `R = MR(Λ')`, except with probability `≤ 2⁻¹²⁸` (an A2 collision / second-preimage break). Concretely:

- **(a) Faithful commitment.** A MATCH means `R` is exactly the canonical S-040-wrapped root over `Λ_L` (MR-1 + §2.5), byte-identical to what the daemon would commit for `Λ_L`.
- **(b) Set sensitivity.** Any single **missing**, **extra**, or **altered** leaf — a changed `key` *or* a changed `value_hash` — changes `MR(Λ_L)` and so flips the MATCH to INVALID, except with an A2 break. (`MerkleTreeSoundness.md` MT-3: two distinct distinct-keyed leaf sets producing the same root yield, by an `O(log n)` extraction, a SHA-256 collision.)
- **(c) No confusion.** The `0x00` / `0x01` / `0x02` domain separation prevents leaf-as-inner, inner-as-wrap, and wrap-as-leaf confusion (`MerkleTreeSoundness.md` MT-2, extended to the `0x02` tag); the `u32_be(|k|)` length prefix prevents key/value concatenation aliasing (`("ab", v)` vs `("a", "b"‖v)` — `MerkleTreeSoundness.md §2.1`).
- **(d) Count binding.** The S-040 wrap binds `leaf_count` into `R`; a leaf set of a *different cardinality* that somehow reconstructs the same inner root would still fail the wrapper comparison, because `H(0x02 ‖ u32_be(M) ‖ ·) ≠ H(0x02 ‖ u32_be(N) ‖ ·)` for `M ≠ N` except under A2 (`MerkleTreeSoundness.md §6.2`).

**Proof.** A MATCH is the predicate `MR_w(Λ_L) = R`. By MR-1, `MR_w(Λ_L) = MR(Λ_L)`, so a MATCH is exactly `MR(Λ_L) = R` — establishing (a) directly: `R` is the canonical root over the supplied set.

For (b): suppose an operator (or an adversary supplying the JSON) presents `Λ_L` and `R`, and there exists a *different intended* set `Λ' ≠ Λ_L` such that `R` was genuinely the commitment to `Λ'` (i.e. the operator believes `R` commits `Λ'` but is checking `Λ_L`). A MATCH requires `MR(Λ_L) = R = MR(Λ')` with `Λ_L ≠ Λ'`. By MT-3 (`MerkleTreeSoundness.md §3`, MT-3), an efficient extractor walks the two trees from the shared root down to the first disagreeing node and outputs a SHA-256 collision (a 65-byte inner-preimage collision, a length-prefixed leaf-preimage collision, a `0x00`/`0x01` cross-domain collision, or a `0x02` wrapper collision). The extraction handles every single-leaf perturbation: a missing leaf shortens the sorted sequence (and changes `leaf_count`, caught by (d)); an extra leaf lengthens it; an altered `value_hash` or `key` changes the disagreeing leaf's preimage (unambiguous by the §2.1 length-prefixed encoding). Hence `Pr[\text{MATCH} ∧ Λ_L ≠ Λ'] ≤ 2⁻¹²⁸` (A2). Contrapositively, a MATCH pins the committed set to `Λ_L` up to A2.

(c) is MT-2 (`MerkleTreeSoundness.md`) plus the §2.1 length prefix, carried through MR-1's byte-equivalence: the wallet uses the identical `0x00`/`0x01` prefixes and the identical `0x02` wrapper, so the domain-separation and aliasing-freedom properties hold for `merkle-root` exactly as for the daemon primitive. (d) is the S-040 binding (`MerkleTreeSoundness.md §6.2`): `leaf_count = |Λ_L|` is the genuine supplied count (§2.5), bound into `R` via the `0x02` wrapper; a count forgery is rejected unless an A2 collision is found. ∎

**Bound.** `Pr[\text{merkle-root --check } R \text{ reports MATCH} ∧ Λ_L \text{ is not the set committed by } R] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class (one collision in the leaf/inner/wrap reduction). No A1 term: the `--check` recompute uses no signatures.

### 3.3 MR-3 (the honest boundary — what a MATCH does and does NOT prove)

**Statement.** A `merkle-root --check R` MATCH proves the supplied leaf *set* commits to *the given root* `R` (MR-2). It does **NOT** prove:

- **(a) That `R` is genuine.** `R` is an operator-supplied parameter. A MATCH against an arbitrary `R` only says "this set hashes to this number." For the verdict to mean "this set is the chain's committed state at height `H`," `R` must be the **committee-committed `state_root(H)`** — which the operator must obtain from a committee-signed source: `determ-light verify-state-root --height H` (`StateRootAnchorSoundness.md` SR-1), a verified snapshot tail, or a committee-signed header field anchored as in `StateRootAnchorSoundness.md §3.3` (`state_root(H) ∈ signing_bytes(H) ∈ block_hash(H) = prev_hash(H+1) ∈ digest(H+1)`, committee-signed under A1). This is the **exact** dual of `block-verify` consuming an operator-supplied `--block-digest` (`OfflineBlockVerifySoundness.md` F-BV2): `merkle-root` takes its trust anchor as a parameter and verifies *against* it, never *establishing* it.

- **(b) That the supplied leaf set is complete / canonical.** The caller must supply **ALL** leaves in the committed set — the full ten-namespace surface of `S033StateRootNamespaceCoverage.md` T-1 (`a: s: r: d: i: b: m: p: k: k:c:`). A **strict subset** simply will not match: dropping any leaf changes the sorted sequence, the tree, and the `leaf_count` wrap, so `MR(subset) ≠ R` (MR-2(b)+(d)). The command **cannot** detect "you forgot the `c:` counters" beyond reporting INVALID; it has no chain link to recompute `build_state_leaves` and cross-check completeness. An operator who supplies an incomplete set gets a *correct* INVALID, but the *reason* (incompleteness vs. a genuine tamper) is not distinguished by the command. This is the contrapositive of completeness being a caller obligation — `merkle-root` is sound *given* a complete set, and fails-closed (INVALID) on an incomplete one.

**The dual relationship (load-bearing).** `merkle-root` is the inverse of `state-proof-verify`:

| | `state-proof-verify` (`cmd_state_proof_verify`) | `merkle-root` (`cmd_merkle_root`) |
|---|---|---|
| Input | ONE leaf + sibling path + `target_index` + `leaf_count` | The FULL leaf set |
| Walks | One root-path bottom-up (`MerkleTreeSoundness.md` MT-4) | The whole tree bottom-up (MR-1) |
| Proves (given a trusted root `R`) | `(key, value_hash)` **is in** the tree committed by `R` | The set **reconstructs** `R` (so it **is** the committed set, MR-2) |
| Root source | `--root`, operator-supplied (SR-1) | `--check`, operator-supplied (SR-1) |
| Shared hash core | `0x00` leaf / `0x01` inner / `0x02` wrap lambdas (identical) | same lambdas (identical) |

Both consume a committee-signed root as a parameter and both reduce to A2 over the reimplemented hash core; neither establishes the root's authenticity (that is `StateRootAnchorSoundness.md`'s job). `state-proof-verify` answers "is *this leaf* in the set?"; `merkle-root` answers "is *this set* the whole committed set?". A `merkle-root` MATCH is the stronger claim (it pins the entire set), but it requires the operator to *have* the entire set — which a light client typically does not, hence `state-proof-verify`'s single-leaf path exists for the partial-knowledge case.

**Proof.** (a) follows because `R` enters as a CLI argument with no provenance check in `cmd_merkle_root` (the command reads `--check` into `check_hex` and compares; nothing verifies `R` against any chain artifact). The recompute's soundness (MR-2) is *conditional* on `R` being the genuine committed root — exactly the `OfflineBlockVerifySoundness.md` BV-2 conditional structure, here on the root rather than the digest. (b) follows because `cmd_merkle_root` hashes precisely the leaves present in the JSON array and nothing else; with no `libdeterm_chain` link it has no access to `build_state_leaves` to enumerate the canonical set, so completeness is necessarily a caller precondition (MR-2(b) shows a strict subset fails to match — the fail-closed direction — but the command cannot affirmatively certify the set is complete). ∎

---

## 4. Composition with companion proofs

### 4.1 `MerkleTreeSoundness.md` — the primitive `merkle-root` recomputes

`merkle-root` is a faithful reimplementation of `crypto::merkle_root`. MR-1 establishes byte-equivalence; from there `merkle-root` *inherits* the primitive's theorems over the wallet's inline code:

- **MT-1** (determinism / permutation-invariance) ⇒ `merkle-root` produces the same root regardless of the JSON array order (it re-sorts, §2.3).
- **MT-2** (domain separation) ⇒ the `0x00`/`0x01`/`0x02` tags prevent leaf/inner/wrap confusion (MR-2(c)).
- **MT-3** (collision-resistance inheritance) ⇒ a `--check` MATCH pins the set up to A2 (MR-2(b)).
- **§6.2 / S-040** (`leaf_count` binding) ⇒ the `0x02` wrapper binds the count (MR-2(d)).
- **§6.1** (CVE-2012-2459 verdict: does NOT apply) — the duplicate-last odd-row rule introduces no malleability *for the canonical sorted distinct-key state leaf set*. The caveat: `merkle-root` accepts an *operator-supplied* JSON array, so unlike the daemon's `build_state_leaves` (whose `std::map`/`std::set` sources guarantee distinct keys), the *operator* must supply distinct keys (§2.3, §5 F-MR6). Given distinct keys, the §6.1 analysis carries over verbatim; with duplicate keys the sort is non-stable and the recompute is well-defined but the "set" is ill-posed — a documentation obligation, not a recompute defect.

This document does **not** re-derive MT-1..MT-3 or §6.2; it composes them over the proved-equivalent reimplementation, exactly as `OfflineBlockVerifySoundness.md` BV-1 composes the `tx_root` set-commitment argument over the wallet's reimplementation.

### 4.2 `StateRootAnchorSoundness.md` — where the `--check` root must come from

MR-3(a) defers the root's authenticity to SR-1. The composition `SR-1 → MR-2` is the whole-set analog of `MerkleTreeSoundness.md §5.4`'s `SR-1 → MT-4`: SR-1 establishes *"committee signatures (A1) → block_hash → state_root(H)"*; MR-2 establishes *"state_root(H) ⇔ this exact leaf set"* (the whole-set version of MT-4's *"state_root → this one leaf is in it"*). An operator who runs `verify-state-root --height H` to obtain a trust-anchored `R`, then `merkle-root --leaves L --check R`, learns under A1+A2 that `L` is *exactly* the committee-committed state at `H` — a complete, trust-minimized state attestation. (This requires the operator to *hold* the full leaf set, e.g. from a snapshot or a full-node export; it is the audit/reconciliation use case, not the light-client partial-read case.)

### 4.3 `S033StateRootNamespaceCoverage.md` — the completeness `merkle-root` presumes

MR-3(b)'s "supply ALL leaves" precondition is precisely the ten-namespace surface T-1 enumerates as complete. T-2 (namespace disjointness, distinct ASCII prefixes) underwrites the distinct-key precondition (§2.3) for the canonical set: cross-namespace keys never collide. T-3 (deterministic leaf ordering) composes with MR-1's sort to give platform-independent reproducibility. An operator reconstructing the leaf JSON must cover all ten namespaces with the value-hash encodings of §2.1; `merkle-root` cannot verify this coverage (no chain link) — it only fails-closed (INVALID) on an incomplete set.

### 4.4 `OfflineBlockVerifySoundness.md` — the sibling wallet-TCB-separated verifier

`merkle-root` and `block-verify` are siblings: both OFFLINE, both reimplementing a chain commitment over OpenSSL SHA-256 because `determ-wallet` does not link the chain library, both consuming an operator-supplied trust anchor (`--check R` here, `--block-digest` there) that the wallet cannot self-establish. MR-1 ↔ BV-1 (byte-equivalence of the reimplementation to the daemon's commitment); MR-3(a) ↔ F-BV2 (the soundness is conditional on a correct operator-supplied anchor). The difference: `block-verify`'s `tx_root` is a *flat sorted-dedup-union* SHA-256 (NOT a Merkle tree — `OfflineBlockVerifySoundness.md §2.1`), so it imports no MT-* theorems; `merkle-root` *is* the Merkle primitive and imports MT-1..MT-3 + S-040 directly (§4.1). Both reduce to A2 only; neither uses A3 or A4.

### 4.5 `Preliminaries.md` — the assumption base

MR-1 is unconditional (function equality). MR-2 reduces to A2 (§2.1) via MT-2 + MT-3 + the S-040 wrap. MR-3 states preconditions and contributes no probability term. A1 appears only by *reference* in MR-3(a) (the source of trust for `R`, via SR-1) and is not a term in any bound this command computes. A3, A4 unused.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `merkle-root --check R` MATCH does and does not assert. None undermines MR-2's per-invocation soundness; all are coverage/scope statements or the one anchor conditional.

### F-MR1 MR-1 is exact and unconditional — but only as good as the next CI pin

The byte-equivalence MR-1 asserts is a *current-source* fact about the inline lambdas vs. `crypto::merkle_root`. It holds by inspection today, but it is a hand-rolled reimplementation with no compiler-enforced link to the primitive. A future edit to either side (a changed prefix, endianness, length prefix, odd-row rule, or the `0x02` wrap) silently breaks the equivalence. The §3.1 tripwire corollary is the mitigation: a CI fixture recomputing a known leaf set and `--check`ing against the daemon's `compute_state_root` pins MR-1. **Recommendation:** add/maintain such a cross-binary fixture (the `merkle-root` analog of `tools/test_merkle.sh`'s in-binary assertions).

### F-MR2 The `--check` root is operator-supplied and unauthenticated by this command (the TCB-separation anchor)

`merkle-root` takes `R` as a parameter and verifies *against* it; it does **not** establish that `R` is the chain's genuine committee-committed `state_root`. A MATCH against a bogus `R` is a *vacuous* verdict (it correctly says "this set hashes to this number," but the number may be meaningless). The operator MUST source `R` from a committee-signed anchor — `determ-light verify-state-root` (`StateRootAnchorSoundness.md` SR-1), a verified snapshot tail, or a committee-signed header field. This is the deliberate cost of the wallet's chain-library-free TCB, paid as a stated operator obligation exactly as `block-verify`'s `--block-digest` (`OfflineBlockVerifySoundness.md` F-BV2). An operator who supplies a root of unknown provenance gets a MATCH/INVALID verdict of unknown meaning.

### F-MR3 Completeness is a caller obligation — `merkle-root` cannot certify the set is whole

A MATCH proves the supplied set *is* the committed set (MR-2). But the operator must supply **every** leaf (all ten namespaces, `S033StateRootNamespaceCoverage.md` T-1). The command has no chain link, so it cannot recompute `build_state_leaves` to confirm completeness; it only fails-closed (INVALID) on an incomplete or altered set. A strict subset *correctly* reports INVALID, but the command does not distinguish "you omitted a namespace" from "a leaf was tampered." Operators reconstructing the leaf JSON must derive it from a complete source (a full-node state export / snapshot), not a partial query.

### F-MR4 Per-leaf semantics are out of scope — `value_hash` is opaque

`merkle-root` treats each `value_hash` as opaque 32 bytes. It does not verify that `("a:"+domain, vh)` encodes the *correct* `(balance, next_nonce)` for that account (the `S033StateRootNamespaceCoverage.md §2.1` value-hash encoding), nor that a leaf reflects real apply-layer state (`AccountStateInvariants.md`). A MATCH says "these are the committed `(key, value_hash)` pairs," not "these `value_hash`es were honestly derived." Verifying a single leaf's `value_hash` against daemon-reported cleartext is the `verify-state-proof` + `T-L4` cleartext-cross-check path, not this command.

### F-MR5 No native non-membership; INVALID does not localize the discrepancy

Per `MerkleTreeSoundness.md` MT-5, the primitive proves positive structure only. An INVALID verdict tells the operator "this set is not the set committed by `R`," but does **not** cryptographically prove *which* leaf is missing, extra, or altered (the recompute yields one root; it does not diff against the committed set, which the command never sees). Localizing a discrepancy requires an out-of-band diff (e.g. per-leaf `state-proof-verify` against the same `R`), not a single `merkle-root` run.

### F-MR6 Distinct keys are a caller precondition (the operator-supplied-JSON caveat)

`crypto::merkle_root`'s distinct-key precondition is discharged for the daemon by `build_state_leaves`'s keyed `std::map`/`std::set` sources (`MerkleTreeSoundness.md §6.1`). `merkle-root` instead accepts an *operator-supplied* JSON array, so the operator inherits the obligation: duplicate keys make the non-stable sort's relative order unspecified and the "set" ill-posed (the CVE-2012-2459 non-applicability of `MerkleTreeSoundness.md §6.1` assumes distinct keys). The command does not enforce uniqueness (it mirrors the primitive's "keys assumed unique by caller" contract). Given a distinct-keyed set sourced from a real chain export, this is satisfied automatically; a hand-edited JSON with accidental duplicates is the operator's responsibility. No code defect — a documented contract, consistent with the primitive.

### F-MR7 Empty leaf set ⇒ all-zero root (the "no committed state" sentinel)

An empty `--leaves` array yields the all-zero 32-byte root (`leaf_count = 0`, the `if (leaf_count > 0)` guard skips the computation — §2.4), matching `merkle_root`'s `Hash{}` sentinel (`MerkleTreeSoundness.md §2.5`, "no committed state"). A `--check` of all-zeros against an empty set therefore MATCHes. This is sound but degenerate: a real chain's state is never empty (it carries ≥ 13 `k:` constants + 5 `k:c:` counters even at genesis — `S033StateRootNamespaceCoverage.md §4.3`), so an all-zero `state_root` from a live chain signals a pre-S-033 / feature-inactive chain (`StateRootAnchorSoundness.md` SR-5), not an empty state. An operator seeing an all-zero `--check` MATCH should treat it as "no S-033 commitment," not "verified empty state."

---

## 6. Implementation cross-references

| Theorem | Component | File / location | Role |
|---|---|---|---|
| MR-1 | wallet recompute | `wallet/main.cpp::cmd_merkle_root` (search `int cmd_merkle_root`) | Inline sort + leaf/inner hash + reduction + `0x02` wrap — the reimplementation. |
| MR-1 | wallet leaf/inner lambdas | `cmd_merkle_root` `leaf_hash` / `inner_hash` lambdas | `0x00 ‖ u32_be(\|k\|) ‖ k ‖ v` / `0x01 ‖ l ‖ r` — byte-identical to the primitive. |
| MR-1 | wallet `0x02` wrapper | `cmd_merkle_root` `wbuf` block | `0x02 ‖ u32_be(leaf_count) ‖ inner_root` — byte-identical to `merkle_root_wrap`. |
| MR-1 | daemon primitive | `src/crypto/merkle.cpp::merkle_root` + `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap` | The byte-identical reference. |
| MR-1 | daemon consumer | `src/chain/chain.cpp:413-415` (`compute_state_root`) | `merkle_root(build_state_leaves())` — what `merkle-root` reproduces. |
| MR-1 | daemon apply-gate | `src/chain/chain.cpp:1432-1444` | `if (computed != b.state_root) throw …` — the equality a `--check` MATCH mirrors. |
| MR-2 | A2 collision-resistance inheritance | `MerkleTreeSoundness.md` MT-3 | Different sets ⇒ different roots except `≤ 2⁻¹²⁸`. |
| MR-2 | domain separation | `MerkleTreeSoundness.md` MT-2 + §2.1 | `0x00`/`0x01`/`0x02` + length prefix; no leaf/inner/wrap or key/value confusion. |
| MR-2 | leaf-count binding | `MerkleTreeSoundness.md §6.2` / `SECURITY.md §S-040` | `0x02` wrapper binds `leaf_count`. |
| MR-3 | sibling single-leaf verifier | `wallet/main.cpp::cmd_state_proof_verify` (search `int cmd_state_proof_verify`) | The dual: ONE leaf IN the tree vs. WHOLE set reconstructs; shares the leaf/inner/wrap lambdas. |
| MR-3 | root authenticity (anchor) | `StateRootAnchorSoundness.md` SR-1 | Where the `--check` root must come from (committee-signed). |
| MR-3 | leaf-set completeness | `S033StateRootNamespaceCoverage.md` T-1 (ten namespaces) | The "supply ALL leaves" precondition. |
| MR-E | bound | — | `Pr[\text{false MATCH}] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class; MR-1 unconditional; no A1/A3/A4 term. |
| — | sibling TCB-separated verifier | `OfflineBlockVerifySoundness.md` (BV-1 / F-BV2) | The posture this document mirrors. |
| — | canonical spec | `docs/PROTOCOL.md §4.1.1` | `state_root` Merkle-leaf table + balanced-binary-tree statement + empty-tree sentinel. |

---

## MR-E — error bound

The recompute (MR-1) is an exact deterministic function equality — **probability-1 correct**, no cryptographic term. The `--check` soundness (MR-2) reduces to a single A2 break in the leaf/inner/wrap reduction:

$$
\Pr\big[\,\text{merkle-root --check } R \text{ reports MATCH} \ \wedge\ \Lambda_L \text{ is not the set committed by } R\,\big]
\;\le\; \varepsilon_{A2} \;\le\; 2^{-128}\text{-class}.
$$

The MR-3 conditionals — that `R` is the genuine committee-committed root, and that `Λ_L` is the complete canonical leaf set — are **not** probability terms; they are operator-supplied preconditions (§5 F-MR2, F-MR3), exactly as `OfflineBlockVerifySoundness.md` BV-E excludes the digest conditional from its bound. The honest statement: *MR-1 unconditional; MR-2 sound under A2 for the supplied root; meaningful for a chain iff `R` is committee-anchored and `Λ_L` is complete.* No A1 term (no signatures in the recompute), no A3 (no preimage argument), no A4 (no sampling).

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_merkle_root` is in `wallet/main.cpp` (dispatched on `merkle-root`), an OFFLINE recompute over OpenSSL SHA-256 with no RPC / daemon / chain-library link. It reimplements `src/crypto/merkle.cpp::merkle_root` inline, sharing the leaf/inner/wrap lambdas with the sibling `cmd_state_proof_verify`.
- **Proof.** Complete (this document). **MR-1** (byte-equivalence: the wallet recompute equals `crypto::merkle_root`, hence the daemon's `compute_state_root`, for the same leaf set — unconditional; doubles as the regression tripwire over the reimplementation). **MR-2** (`--check` soundness: under A2 a MATCH means the supplied leaf set is exactly the set committed by `R` — any single missing/extra/altered leaf flips to INVALID except with an A2 break; `0x00`/`0x01`/`0x02` domain separation + length prefix prevent confusion; the S-040 wrap binds `leaf_count`). **MR-3** (the honest boundary: a MATCH proves the set commits to the *given* root, NOT that the root is genuine — `StateRootAnchorSoundness.md` SR-1 — nor that the supplied set is complete/canonical — `S033StateRootNamespaceCoverage.md` T-1; the dual of `state-proof-verify`). **MR-E** bound: `≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class; the recompute is unconditional; the anchor + completeness conditionals are operator preconditions, not probability terms.
- **Cryptographic assumptions used.** A2 (SHA-256 collision / second-preimage resistance) only. A1 enters by reference in MR-3(a) (trust source for `R`, via SR-1), not as a term. A3, A4 unused. Per `Preliminaries.md §2.0`.
- **The TCB-separation posture (load-bearing).** `determ-wallet` deliberately does not link the chain library; `merkle_root` is reimplemented inline. MR-1 proves the reimplementation byte-identical, so a `--check` MATCH is exactly the daemon's apply-time S-033 equality — unconditional under no assumption for the *recompute*, sound under A2 for the *set-commitment*, and *conditional* (on a committee-anchored `R` and a complete leaf set) for the *meaning* — the precise boundary between what `merkle-root` proves unconditionally, cryptographically, and by operator precondition.
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-2/MT-3 + §6.2 S-040, recomputed over the wallet code via MR-1), `StateRootAnchorSoundness.md` (SR-1 — the root anchor MR-3(a) defers to), `S033StateRootNamespaceCoverage.md` (T-1..T-3 — the completeness MR-3(b) presumes), `OfflineBlockVerifySoundness.md` (BV-1 / F-BV2 — the sibling byte-equivalence + anchor-conditional posture), `Preliminaries.md` (A2 base).
- **Known limitations (§findings).** F-MR1 (MR-1 is exact but only as good as the next CI pin — add a cross-binary tripwire fixture); **F-MR2 (the load-bearing one: the `--check` root is operator-supplied and unauthenticated by this command — the wallet-TCB-separation anchor cost; a bogus root yields a vacuous verdict)**; F-MR3 (completeness is a caller obligation — `merkle-root` fails-closed on an incomplete set but cannot certify wholeness); F-MR4 (per-leaf `value_hash` semantics out of scope); F-MR5 (no native non-membership — INVALID does not localize the discrepancy); F-MR6 (distinct keys are a caller precondition for the operator-supplied JSON); F-MR7 (empty leaf set ⇒ all-zero "no committed state" sentinel — degenerate but sound). None undermines MR-2's per-invocation soundness.

---

## 8. References

### Implementation sites
- `wallet/main.cpp::cmd_merkle_root` (search `int cmd_merkle_root`) — the OFFLINE recompute; inline leaf/inner hash + reduction + `0x02` wrap; `--check` compare; exit `0`/`1`/`2`.
- `wallet/main.cpp::cmd_state_proof_verify` (search `int cmd_state_proof_verify`) — the sibling single-leaf verifier sharing the leaf/inner/wrap lambdas (the dual of MR-3).
- `src/crypto/merkle.cpp::merkle_root` / `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap` — the byte-identical reference primitive.
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root` = `merkle_root(build_state_leaves())`.
- `src/chain/chain.cpp:1432-1444` — apply-time S-033 `state_root` gate (the equality a `--check` MATCH mirrors).
- `src/chain/chain.cpp:267-411` — `Chain::build_state_leaves` (the ten-namespace canonical leaf set).

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §1.3 hash notation; §2.0 assumption labels; §2.1 A2 (SHA-256 collision / second-preimage resistance).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (domain separation), MT-3 (collision-resistance inheritance), §6.1 (CVE-2012-2459 — does not apply), §6.2 (S-040 `leaf_count` binding); recomputed over the wallet code via MR-1.
- `docs/proofs/StateRootAnchorSoundness.md` — SR-1 (committee-anchored root); the source of trust for the `--check` root (MR-3(a)).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (ten-namespace coverage completeness), T-2 (namespace disjointness), T-3 (deterministic leaf ordering); the completeness MR-3(b) presumes.
- `docs/proofs/OfflineBlockVerifySoundness.md` — the sibling wallet-TCB-separated OFFLINE verifier; BV-1 (byte-equivalence) / F-BV2 (operator-supplied-anchor conditional) posture mirrored.

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` algorithm + Merkle-leaf table + balanced-binary-tree statement + empty-tree sentinel.
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC return shape (key_bytes, value_hash, target_index, leaf_count, proof).
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` root-wrapper binding (the `0x02` wrap).
- NIST FIPS 180-4 — SHA-256 (A2).
- RFC 6962 §2.1 — Certificate Transparency `0x00`/`0x01` leaf/node tagged hashing (the domain-separation pattern Determ follows, here extended to `0x02`).
