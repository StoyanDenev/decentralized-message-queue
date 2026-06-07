# MerkleProofGenSoundness — OFFLINE single-leaf inclusion-proof generation (`determ-wallet merkle-proof`)

This document proves the soundness of the `determ-wallet merkle-proof` subcommand: a **fully OFFLINE, one-shot generation of a Merkle inclusion proof for ONE leaf from a FULL leaf set**. An operator hands it a JSON array of every leaf `{value_hash, key | key_hex}` in the committed state plus a target `--key`/`--key-hex`; it sorts the leaves by raw key bytes, locates the target key's **sorted** index, collects the sibling hash at each level (Bitcoin-style duplicate-last on odd rows), reduces with `inner_hash = SHA-256(0x01 ‖ L ‖ R)`, and emits the **exact `rpc_state_proof` reply shape** `{key_bytes, value_hash, target_index, leaf_count, proof:[hex…], state_root}`, where `state_root = SHA-256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` is the S-040-wrapped `merkle_root` over the same set. The output **round-trips**: `state-proof-verify --in <out> --root <emitted state_root>` returns VALID.

`merkle-proof` is the **proof GENERATOR** completing the offline Merkle triad: **`merkle-root` BUILDS** the committed root from a full leaf set (`MerkleRootRecomputeSoundness.md`), **`state-proof-verify` CONSUMES** a proof against an anchored root (`cmd_state_proof_verify`), and **`merkle-proof` GENERATES** one. It is the inverse half of the verifier: `state-proof-verify` answers "is *this leaf* in the tree committed by `R`?"; `merkle-proof` answers "what is the proof path for *this leaf* in the tree built from *this set*?"

**The load-bearing design fact (TCB separation).** `determ-wallet` deliberately does **not** link `libdeterm_chain`. Consequently the canonical proof-path function (`src/crypto/merkle.cpp::merkle_proof`, with its `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap` helpers) is **reimplemented inline** in `wallet/main.cpp::cmd_merkle_proof` over `std::array<uint8_t,32>` rows + OpenSSL `SHA256`, rather than called from the chain library. MP-1 proves this reimplementation is **byte-identical** to the daemon's `merkle_proof` — same sort-by-key, same `target_index` (the *sorted* position of the target key), same sibling selection (`idx^1` via `(idx%2==0)?idx+1:idx-1`), same duplicate-last odd-row rule, same `inner_hash` — and that the emitted `state_root` is byte-identical to `merkle_root` over the same set (reusing `MerkleRootRecomputeSoundness.md` MR-1). So `merkle-proof` emits exactly the proof the daemon's `rpc_state_proof` (= `Chain::state_proof`, `chain.cpp:435-462`) would return for the same (sorted) leaf set. This mirrors `MerkleRootRecomputeSoundness.md` MR-1's byte-equivalence posture for the root recompute and `OfflineBlockVerifySoundness.md` BV-1's for the `tx_root` recompute, and is the *cost* of the wallet's lean TCB paid as a stated, proved byte-equivalence rather than a hidden assumption.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision / second-preimage resistance (§2.1), **A3** = SHA-256 preimage resistance (§2.1), **A4** = CSPRNG uniform sampling (§2.3). `merkle-proof` reduces to **A2 only** for its security claim (MP-2); the generation itself (MP-1) is unconditional. A1 enters only by *reference*, in MP-3, as the source of trust for the `state_root` the operator must cross-check against a committee-signed header — an operator precondition, not a probability term this command computes. A3, A4 unused.

**Companion documents.** `Preliminaries.md` (F0) §1.3 (hash notation `H`, `‖`, big-endian integer encoding), §2.0 (assumption labels), §2.1 (A2); `MerkleTreeSoundness.md` (the primitive whose **MT-4 inclusion-proof soundness** `merkle-proof`'s output is the generated witness for, whose MT-2 domain separation / MT-3 collision-resistance inheritance / §6.2 S-040 `leaf_count` binding it reproduces verbatim, and whose §2.6 verifier walk it round-trips with — this document composes those theorems over the wallet's reimplementation rather than re-deriving them); `MerkleRootRecomputeSoundness.md` (the sibling — MR-1's byte-equivalence posture for the `state_root` wrap is reused directly here; `merkle-proof`'s emitted `state_root` IS `merkle-root`'s output over the same set); `StateRootAnchorSoundness.md` (SR-1 — why the emitted `state_root` is trust-minimized only when cross-checked against a committee-signed header, exactly as `merkle-root`'s `--check` root and `block-verify`'s `--block-digest`); `OfflineBlockVerifySoundness.md` (the sibling wallet-TCB-separated OFFLINE tool whose BV-1 byte-equivalence + F-BV-style honest-boundary posture this document mirrors); `S033StateRootNamespaceCoverage.md` (T-1..T-5 — the ten-namespace leaf-set completeness `merkle-proof`'s "supply the real committed set" precondition presumes); `docs/PROTOCOL.md §4.1.1` (the canonical `state_root` Merkle-leaf table) + §10.2 (`state_proof` RPC return shape, which `merkle-proof` reproduces byte-for-byte); `docs/SECURITY.md` §S-033 / §S-038 / §S-040 (the closures this generation exercises).

---

## 0. Implementation status

**`int cmd_merkle_proof(int argc, char** argv)` is IMPLEMENTED in `wallet/main.cpp`** (search `int cmd_merkle_proof`; dispatched on `merkle-proof`). It is read directly off source for this proof; there is no spec-vs-implementation divergence to reconcile. The command:

1. Parses `--leaves <file>` (required), **exactly one** of `--key <string>` (UTF-8 → raw bytes) / `--key-hex <hex>` (even-length hex → binary bytes) (required), and `--json` (optional). The `have_key == have_key_hex` gate (`return 1`) enforces the exclusive-or.
2. Loads the leaf JSON — a top-level array of objects each carrying `value_hash` (64-hex / 32 bytes, required) and **exactly one** of `key` / `key_hex` (the `merkle-root` leaf shape). Any malformed entry → `return 1` (fail-closed parse fault). An empty array → `return 1` (no leaf to prove).
3. Sorts the parsed `leaves` by raw key bytes (`a.key < b.key`), then linear-scans for the target key to find its **sorted** index; if the target key is not present → `return 1` (`"target key not present in --leaves"`).
4. Hashes each sorted leaf into a working row, then walks levels collecting the sibling (`(idx%2==0)?idx+1:idx-1`, duplicate-last on odd rows) and reducing with `inner_hash`, exactly per `src/crypto/merkle.cpp::merkle_proof`.
5. Wraps the inner root as `state_root = SHA-256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` (the S-040 `merkle_root_wrap`).
6. Emits `{key_bytes, value_hash, target_index, leaf_count, proof:[hex…], state_root}` (one-line with `--json`, pretty-printed otherwise). Exit `0` success, `1` args/parse/IO error or target key not found.

The two cryptographic helpers it reimplements inline are byte-for-byte copies of the chain primitive: `leaf_hash` (a `cmd_merkle_proof` lambda) mirrors `crypto::merkle_leaf_hash`; `inner_hash` mirrors `crypto::merkle_inner_hash`; the trailing `0x02 ‖ u32_be(leaf_count) ‖ inner_root` wrapper mirrors `crypto::merkle_root_wrap`. The **same** leaf/inner/wrap lambdas appear in the sibling `cmd_merkle_root` and `cmd_state_proof_verify` (`wallet/main.cpp`), so all three wallet commands share one reimplemented hash core — `merkle-root` walks the *whole* tree to a root, `merkle-proof` collects a *single* root-path's siblings, `state-proof-verify` re-walks *one* root-path to check it.

---

## 1. Scope

### 1.1 In scope

The `determ-wallet merkle-proof` command per §0. Its three soundness obligations:

| Theorem | What it establishes | Backing |
|---|---|---|
| **MP-1** | The wallet's inline generator is **byte-identical** to `src/crypto/merkle.cpp::merkle_proof` (same sort-by-key, same `target_index` = the *sorted* position of the target key, same `idx^1` sibling selection, same duplicate-last odd-row rule, same `inner_hash`), AND the emitted `state_root` is byte-identical to `merkle_root` over the same set (reusing `MerkleRootRecomputeSoundness.md` MR-1) — so for any leaf set + target, `merkle-proof` emits exactly the proof the daemon's `rpc_state_proof` would for the same (sorted) leaf set. | Deterministic function equality (unconditional); doubles as a regression tripwire over the hand-rolled reimplementation. |
| **MP-2** | **Generator/verifier inverse — round-trip soundness.** The emitted `(key_bytes, value_hash, target_index, leaf_count, proof)` verifies VALID under `merkle_verify` / `state-proof-verify` against the emitted `state_root`; and `merkle_proof` / `merkle_verify` are inverse — feeding `merkle-proof`'s output to `state-proof-verify` is VALID **iff** the target leaf is in the committed set. Under A2, an adversary cannot produce a leaf set whose generated proof verifies for a leaf **not** in the set except via a SHA-256 collision (`≤ 2⁻¹²⁸`-class). | A2 (via MT-4 + the §2.6 verifier round-trip); the positive round-trip is unconditional (MP-1 + MT-4). |
| **MP-3** | The honest boundary: `merkle-proof` is a GENERATOR over a **caller-supplied** leaf set; the emitted `state_root` is computed *from* that set, NOT obtained from a committee-signed header. So the proof is trust-minimized **only** when the caller cross-checks the emitted `state_root` against a committee-signed header's `state_root` (`StateRootAnchorSoundness.md` SR-1) AND the supplied set is the real committed state. By itself `merkle-proof` proves "this leaf is in THIS tree (the one built from the supplied set)", not "this leaf is in the REAL chain state". | Statement of preconditions (no new assumption). |

### 1.2 Out of scope (intentional — the generator's coverage boundary)

- **Root authenticity.** `merkle-proof` *computes* `state_root` from the supplied leaves; it does not verify that root is the chain's genuine committee-committed `state_root` at any height — that is `StateRootAnchorSoundness.md` SR-1's job (`determ-light verify-state-root`). The operator must cross-check the emitted `state_root` against a committee-signed header before the generated proof means "in the real chain state." This is the exact analog of `merkle-root` trusting its `--check` root and `block-verify` trusting its `--block-digest` (`MerkleRootRecomputeSoundness.md` F-MR2, `OfflineBlockVerifySoundness.md` F-BV2). §5 F-MP2.
- **Leaf-set completeness / canonicity.** `merkle-proof` hashes *whatever leaves the JSON carries* and proves membership in *that* tree. It does not — and cannot, with no chain link — confirm the supplied array is the *complete* ten-namespace committed set (`S033StateRootNamespaceCoverage.md` T-1) or that each `value_hash` was correctly derived from real chain state. A proof generated over an incomplete or fabricated set verifies fine *against its own emitted `state_root`* but says nothing about the real chain. §5 F-MP3.
- **The semantics of any single leaf.** Whether the target leaf `("a:"+domain, vh)` encodes the *correct* `(balance, nonce)` for that account is the apply-layer's concern (`AccountStateInvariants.md`); `merkle-proof` treats `value_hash` as opaque 32 bytes. §5 F-MP4.
- **Non-membership.** Per `MerkleTreeSoundness.md` MT-5, the primitive proves positive structure only; `merkle-proof` errors (`return 1`) for an absent target key — it does **not** emit a cryptographic absence proof. §5 F-MP5.

---

## 2. Construction specification

Read directly off `wallet/main.cpp::cmd_merkle_proof` and the chain reference `src/crypto/merkle.cpp::merkle_proof` / `merkle_root_wrap`. Throughout, `H : {0,1}* → {0,1}²⁵⁶` is SHA-256 (`Preliminaries.md §1.3`), `‖` is byte concatenation, `u32_be(n)` is the 4-byte big-endian encoding, and a leaf is an opaque `(key ∈ {0,1}*, value_hash ∈ {0,1}²⁵⁶)` pair.

### 2.1 Leaf hash, inner hash, and the S-040 wrapper (shared with `merkle-root`)

The three byte-layout primitives are byte-for-byte the ones `MerkleRootRecomputeSoundness.md §2.1–§2.2, §2.5` characterizes (the *same* inline lambdas):

$$
\mathrm{LH}(k, v) = H\big(\texttt{0x00} \,\|\, u32\_be(|k|) \,\|\, k \,\|\, v\big),\qquad
\mathrm{IH}(l, r) = H\big(\texttt{0x01} \,\|\, l \,\|\, r\big),
$$
$$
\mathrm{state\_root} = H\big(\texttt{0x02} \,\|\, u32\_be(\text{leaf\_count}) \,\|\, \text{inner\_root}\big).
$$

The wallet `leaf_hash` lambda pushes `0x00`, the four big-endian key-length bytes, the key bytes, then the 32-byte `value_hash`, and `SHA256`s — byte-identical to `crypto::merkle_leaf_hash` (the chain guards `if (!key.empty())` before appending the key; the wallet `insert`s an empty range, a no-op, so the empty-key preimage `0x00 ‖ u32_be(0) ‖ v` matches). The `inner_hash` lambda pushes `0x01 ‖ l ‖ r` — byte-identical to `crypto::merkle_inner_hash`. The `0x02` wrapper block matches `crypto::merkle_root_wrap`, with `0x02` domain-separated from the `0x00` leaf / `0x01` inner tags (MT-2 extended to a third class). These are the *identical* lambdas the sibling `cmd_merkle_root` and `cmd_state_proof_verify` use, so all three wallet commands agree on the hash core byte-for-byte.

### 2.2 Sort, target-index location, and the distinct-key precondition

After parsing, `cmd_merkle_proof` sorts the leaves by raw key bytes and then locates the target's **sorted** index by linear scan:

```cpp
std::sort(leaves.begin(), leaves.end(),
          [](const Leaf& a, const Leaf& b) { return a.key < b.key; });
size_t target_index = leaves.size();
for (size_t i = 0; i < leaves.size(); ++i)
    if (leaves[i].key == target_key) { target_index = i; break; }
if (target_index == leaves.size()) { /* not found */ return 1; }
```

`Leaf::key` is `std::vector<uint8_t>`; C++'s `operator<` is byte-wise lexicographic, unsigned, shorter-is-smaller on a common prefix — **the identical strict total order** `crypto::merkle_proof` and `crypto::merkle_root` use (`merkle.cpp` `a.key < b.key`, `MerkleTreeSoundness.md §2.3`). The `target_key` is decoded identically to a leaf key: `--key` → UTF-8 bytes (ASCII namespaces `a: s: r: d: k: c:`), `--key-hex` → decoded binary bytes (the composite `i: m: p:` keys, `S033StateRootNamespaceCoverage.md §2.1`).

**This is the key fact MP-1 hinges on.** The daemon's `crypto::merkle_proof(leaves, target_index)` takes the **sorted** index as a parameter — its header contract states *"the caller passes the sorted-leaf index"* (`merkle.cpp` comment) — and the daemon's `Chain::state_proof` discharges this by sorting once and `lower_bound`-ing the key (`chain.cpp:441-449`, `MerkleTreeSoundness.md §2.3`). `cmd_merkle_proof` performs the **same** sort-then-locate-by-key: it sorts, then finds the index `i` where `leaves[i].key == target_key`. Because the sort is the same strict total order and the keys are distinct (the precondition, §2.3 below), the located `i` is *exactly* the `lower_bound` position the daemon would pass to `merkle_proof`. So `cmd_merkle_proof`'s `target_index` equals the daemon's `target_index` for the same `(set, key)`, and the resulting proof path is identical. (`merkle-proof` is thus the "find-by-key" front-end the daemon's `state_proof` provides and the bare `merkle_proof(leaves, idx)` signature does not.)

**Distinct keys are a caller precondition.** The daemon discharges it by construction: `build_state_leaves` sources from keyed `std::map`/`std::set`, with distinct ASCII namespace prefixes (`MerkleTreeSoundness.md §6.1`, `S033StateRootNamespaceCoverage.md` T-2). `merkle-proof` accepts an *operator-supplied* JSON array, so the operator inherits the obligation (§5 F-MP6). With duplicate keys the non-stable sort's relative order is unspecified and the linear scan returns the *first* sorted leaf with a matching key, which may not be the index the daemon's `lower_bound` would return for the duplicate — the "set" is ill-posed, mirroring the primitive's "keys assumed unique by caller" contract.

### 2.3 Sibling collection, odd-row rule, and base cases

After sorting, each leaf is hashed into a working row, then levels reduce pairwise — collecting the sibling at the current `idx` before each reduction — until one node remains:

```cpp
std::vector<std::array<uint8_t,32>> row;
for (auto& l : leaves) row.push_back(leaf_hash(l.key, l.vh));
std::vector<std::array<uint8_t,32>> proof;
size_t idx = target_index;
while (row.size() > 1) {
    if (row.size() % 2 == 1) row.push_back(row.back());          // duplicate-last
    size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;          // idx^1
    proof.push_back(row[sibling]);
    std::vector<std::array<uint8_t,32>> next;
    for (size_t i = 0; i + 1 < row.size(); i += 2)
        next.push_back(inner_hash(row[i], row[i + 1]));
    row = std::move(next);
    idx /= 2;
}
```

This is line-for-line `crypto::merkle_proof`'s loop (`merkle.cpp:116-127`): same `row.size() % 2 == 1` Bitcoin-style last-node duplication at each odd level, same `sibling = (idx%2==0)?idx+1:idx-1` selection (the `idx^1` rule — at an even position the sibling is the right neighbor `idx+1`, at an odd position the left neighbor `idx-1`), same left-to-right `IH` pairing, same `idx /= 2` ascent. The collected `proof` is the bottom-up sequence of sibling hashes along the target's root-path. After the loop, `row[0]` is the bare inner root, wrapped per §2.1 into `state_root`.

**Base cases.**
- **Single leaf** (`leaf_count == 1`): the `while (row.size() > 1)` loop never executes, so `proof` is **empty** and `inner_root = row[0] = LH(k, v)`. The emitted `state_root = H(0x02 ‖ u32_be(1) ‖ LH(k,v))`, `target_index = 0`, `proof = []`. Byte-identical to `crypto::merkle_proof` returning `{}` for a single-leaf set (`merkle.cpp:116`, `MerkleTreeSoundness.md §2.5`). This is the empty-proof edge case (§5 F-MP7); `cmd_state_proof_verify` consumes a zero-length proof correctly (its `while (level_size > 1)` loop also never runs, so it compares `H(0x02 ‖ u32_be(1) ‖ LH(k,v))` directly to `--root` — VALID, `MerkleTreeSoundness.md §6.4`).
- **Empty leaf set**: `cmd_merkle_proof` `return 1`s up front (`"--leaves is empty (no leaf to prove)"`) — there is no leaf to prove, so unlike `merkle-root` (which emits the all-zero "no committed state" sentinel) this command fails-closed rather than emitting a degenerate proof.

---

## 3. Soundness theorems

Let `MP(Λ, j)` denote `crypto::merkle_proof(Λ, j)` (the daemon primitive) over a finite multiset of distinct-keyed leaves `Λ` with sorted-index `j`; let `MP_w(L, key)` denote the wallet's `cmd_merkle_proof` generation over leaf JSON `L` (parsed to leaf set `Λ_L`) and target `key`. Let `MR(Λ)` / `MR_w(Λ_L)` be the daemon / wallet committed roots (`MerkleRootRecomputeSoundness.md`), and `MV` be `crypto::merkle_verify` / its `cmd_state_proof_verify` reimplementation. Bounds follow `Preliminaries.md §2.0` (A2 ≈ `2⁻¹²⁸`).

### 3.1 MP-1 (byte-equivalence to `crypto::merkle_proof` + `merkle_root`)

**Statement.** For every leaf set `Λ_L` and target `key` present in `Λ_L`, let `j` be `key`'s sorted index in `Λ_L`. Then:

- **(i)** `MP_w(L, key).\text{target\_index} = j` (the sorted position of `key`);
- **(ii)** `MP_w(L, key).\text{proof} = MP(Λ_L, j)` byte-for-byte (the daemon's sibling path);
- **(iii)** `MP_w(L, key).\text{state\_root} = MR(Λ_L)` byte-for-byte (the daemon's committed root, by `MerkleRootRecomputeSoundness.md` MR-1);
- **(iv)** `MP_w(L, key).\{\text{key\_bytes}, \text{value\_hash}, \text{leaf\_count}\}` equal `key`'s bytes, `Λ_L[j]`'s `value_hash`, and `|Λ_L|`.

Consequently `merkle-proof` emits exactly the `{key_bytes, value_hash, target_index, leaf_count, proof, state_root}` tuple the daemon's `rpc_state_proof` (= `Chain::state_proof`, `chain.cpp:435-462`) would return for the same (sorted) leaf set and key. This is **unconditional** — pure deterministic function equality, no cryptographic assumption.

**Proof.** Match the operations of the two routines, reusing the `MerkleRootRecomputeSoundness.md` MR-1 stages where they coincide:

1. **Parse → leaf domain.** Both consume the same abstract leaf set: a multiset of `(key ∈ {0,1}*, value_hash ∈ {0,1}²⁵⁶)` pairs (the wallet decodes `value_hash` to a fixed 32-byte array, rejecting non-32-byte at parse; `key`/`key_hex` to raw bytes; §2.1–§2.2). The `target_key` decodes by the *same* rule as a leaf key, so it compares byte-equal to the matching leaf's key.

2. **Sort + target-index.** Both sort by `a.key < b.key` over `std::vector<uint8_t>` — the same unsigned byte-wise lexicographic strict total order (§2.2). On a distinct-keyed set the sorted sequence is the *unique* permutation regardless of input order (`MerkleTreeSoundness.md` MT-1). The daemon's `state_proof` `lower_bound`s `key` in that sorted order to get `j`; `cmd_merkle_proof` linear-scans the same sorted vector for the first `i` with `leaves[i].key == key`. On distinct keys both yield the *same* unique index `j` (§2.2). ⇒ (i), and the leaf at `j` is the same `(key, value_hash)` pair ⇒ (iv)'s `key_bytes`/`value_hash`.

3. **Leaf hash.** Both compute `LH(k,v) = H(0x00 ‖ u32_be(|k|) ‖ k ‖ v)` with identical byte layout (§2.1); SHA-256 is deterministic and unkeyed, and the streaming `SHA256Builder` append (daemon) vs. one-shot `SHA256(buf)` (wallet) produce identical digests over identical preimages (Merkle–Damgård; the same argument `MerkleRootRecomputeSoundness.md` MR-1 step 3 makes). ⇒ identical leaf row.

4. **Sibling collection + reduction.** Both run the identical `while (row.size() > 1)` loop with the identical `row.size() % 2 == 1` duplicate-last rule, the identical `sibling = (idx%2==0)?idx+1:idx-1` selection, the identical left-to-right `IH(l,r) = H(0x01 ‖ l ‖ r)` pairing, and the identical `idx /= 2` ascent (§2.3). The loop is a fixed sequence of `push_back(row[sibling])` + `IH` evaluations driven only by `row.size()` parity and the descending `idx` derived from the *same* `target_index = j`. ⇒ identical `proof` sequence (ii) and identical `inner_root`. The single-leaf base case coincides: both produce an empty `proof` and `inner_root = LH(k,v)` (§2.3).

5. **Wrap.** The wallet applies `state_root = H(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` with `leaf_count = |Λ_L|` (§2.1); by `MerkleRootRecomputeSoundness.md` MR-1 stage 5 this is byte-identical to `merkle_root_wrap`, and since the inner root matches (stage 4) the wrapped root equals `MR(Λ_L)`. ⇒ (iii).

Each stage is byte-identical, so the emitted tuple is byte-identical to the daemon's `state_proof` output for `(Λ_L, key)`. ∎

**Regression-tripwire corollary.** MP-1 is an *exact* function equality over a hand-rolled reimplementation. Any future drift between `cmd_merkle_proof`'s inline lambdas/loop and `crypto::merkle_proof` + `merkle_root_wrap` (a changed prefix, flipped endianness, a wrong sibling rule, a different odd-row rule, a missing wrap) manifests as a proof or `state_root` that the daemon would not have produced — and, because the verifier shares MP-1's hash core (`MerkleRootRecomputeSoundness.md` MR-1, applied to `cmd_state_proof_verify`), as a round-trip that *passes the wallet's own verifier* but *fails against a daemon-served root* on an honest set. The command therefore doubles as an offline tripwire over the reimplementation: a CI fixture that generates a proof for a known leaf set, verifies it round-trip with `state-proof-verify`, and diffs the emitted tuple against the daemon's `state_proof` output pins MP-1 (this is the `merkle-proof` analog of `tools/test_merkle_proof_tampering.sh`'s in-binary assertions, run cross-binary). This is the wallet-TCB-separation cost (`MerkleRootRecomputeSoundness.md §0`/MR-1, `OfflineBlockVerifySoundness.md` BV-1) paid as a proved equivalence plus a tripwire, not a hidden assumption.

### 3.2 MP-2 (generator/verifier inverse — round-trip soundness)

**Statement.** Two parts, an unconditional positive and an A2-conditional negative:

- **(a) Positive round-trip (unconditional).** For any leaf set `Λ_L` and target `key ∈ Λ_L`, feeding `merkle-proof`'s emitted tuple to `state-proof-verify --in <out> --root <emitted state_root>` returns **VALID**. I.e. `merkle_proof` and `merkle_verify` are inverse on the honest path: `MV\big(MR(Λ_L),\, key,\, v,\, j,\, |Λ_L|,\, MP(Λ_L, j)\big) = \texttt{true}` where `(key,v) = Λ_L[j]`.
- **(b) Negative soundness (under A2).** No leaf set + target an efficient adversary could supply yields a `merkle-proof` output that `state-proof-verify` accepts against the emitted `state_root` for a `(key, value_hash)` pair that is **not** the genuine member at the proven sorted index — except via a SHA-256 collision (`≤ 2⁻¹²⁸`-class). Equivalently: the round-trip is VALID **iff** the target leaf is in the tree committed by the emitted root.

**Proof.**

*(a)* By MP-1, the emitted tuple is exactly `(key, v, j, n, MP(Λ_L, j), MR(Λ_L))` with `n = |Λ_L|` and `(key,v) = Λ_L[j]` the genuine member at sorted index `j`. The verifier `state-proof-verify` reproduces `crypto::merkle_verify` byte-for-byte (its leaf/inner/wrap lambdas are the *same* shared hash core, and its walk is the §2.6 `MerkleTreeSoundness.md` loop — verified by reading `cmd_state_proof_verify`: `current = leaf_hash(key, vh)`, then the `while (level_size > 1)` loop consuming siblings with the `idx % 2` parity, then the `0x02 ‖ u32_be(leaf_count) ‖ current` wrap compared to `--root`). `merkle_verify` re-derives the *honest* root-path from `(key, v)` using exactly the siblings `MP(Λ_L, j)` records and the parity sequence `j` induces — which is the same parity sequence `merkle_proof` used to *select* those siblings (both use `idx /= 2` from the same `j`; the verifier's `idx % 2 == 0 ? IH(current, sib) : IH(sib, current)` is the inverse of the generator's `sibling = (idx%2==0)?idx+1:idx-1`, placing `current` on the side `merkle_proof` left open). So the verifier recomputes the genuine `inner_root`, the exact-consume gate passes (`proof_idx == proof.size()`, since the proof has exactly the level count), the `0x02` wrap with the genuine `leaf_count = n` reproduces `MR(Λ_L)`, and the comparison to `--root = MR(Λ_L)` succeeds. The verifier's `root_matches_proof` cross-check also passes because the emitted tuple's self-asserted `state_root` field *equals* the `--root` (both are `MR(Λ_L)`). Hence VALID. This is `MerkleTreeSoundness.md` MT-4's positive direction, instantiated with the generator's own output and root — unconditional (no collision needed for the honest case). ∎(a)

*(b)* Suppose an adversary supplies leaves `Λ_L` and target `key`, and `state-proof-verify` accepts the emitted tuple against the emitted `state_root` for a leaf `(key, value⋆)` that is **not** the genuine member at sorted index `j` of `Λ_L` — i.e. `(key, value⋆) ≠ Λ_L[j]`. By MP-1 the emitted root is `MR(Λ_L)` and the emitted `target_index` is `j` with `leaf_count = n = |Λ_L|`. Acceptance is the predicate `MV(MR(Λ_L), key, value⋆, j, n, proof⋆) = true`. Apply `MerkleTreeSoundness.md` MT-4: a passing `merkle_verify` over a leaf that is not the genuine member at `(j, n)` yields, by the top-down chain comparison against the honest root-path of the tree `MR(Λ_L)` commits, an efficient extraction of a SHA-256 collision (a 65-byte inner-preimage collision, a length-prefixed leaf-preimage collision, a `0x00`/`0x01` cross-domain collision, or — for a count mismatch — a `0x02` wrapper collision per S-040). Hence `Pr[\text{accept} ∧ (key,value⋆) ∉ Λ_L \text{ at } (j,n)] ≤ 2⁻¹²⁸` (A2). Contrapositively, an accepted round-trip pins `(key, value⋆)` to the genuine member at the proven index up to A2 — the round-trip is VALID iff the target leaf is in the committed set. ∎(b)

**The "committed set" caveat (load-bearing for MP-3).** MP-2(b) proves membership in the tree committed by **the emitted `state_root`** — which is the tree built from the *operator-supplied* `Λ_L`, NOT necessarily the real chain state. An adversary who *controls* `Λ_L` can trivially make any `(key, value⋆)` "verify" by simply *including* it in `Λ_L`: then it IS the genuine member at its sorted index, MP-2(a) makes the round-trip VALID, and no collision is needed. This is not a break of MP-2 — it is the precise reason MP-2's guarantee is **relative to the emitted root**, and the reason MP-3 insists the emitted root be cross-checked against a committee-signed header before the proof means anything about the *real* chain. The inverse property (MP-2) is airtight; the *meaning* is conditional (MP-3).

**Bound.** `Pr[\text{state-proof-verify accepts merkle-proof's output for a non-member at the proven index, against the emitted root}] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class. The positive round-trip (a) is unconditional (probability-1 VALID on the honest path). No A1 term: the generation and round-trip use no signatures.

### 3.3 MP-3 (the honest boundary — what a generated proof does and does NOT prove)

**Statement.** `merkle-proof` is a GENERATOR over a **caller-supplied** leaf set, and the emitted `state_root` is computed **from that set**, not obtained from a committee-signed header. Therefore:

- **(a) The emitted root is self-asserted, not anchored.** A `merkle-proof` run proves only "leaf `(key, value_hash)` is at sorted index `target_index` of the tree whose root is the emitted `state_root`" (MP-1 + MP-2). For the proof to mean "this leaf is in the chain's committed state at height `H`," the operator must **cross-check the emitted `state_root` against the committee-committed `state_root(H)`** — obtained from a committee-signed source: `determ-light verify-state-root --height H` (`StateRootAnchorSoundness.md` SR-1), a verified snapshot tail, or a committee-signed header field anchored as in `StateRootAnchorSoundness.md §3` (`state_root(H) ∈ signing_bytes(H) ∈ block_hash(H) = prev_hash(H+1) ∈ digest(H+1)`, committee-signed under A1). This is the **exact** dual of `merkle-root` consuming an operator-supplied `--check R` (`MerkleRootRecomputeSoundness.md` F-MR2) and `block-verify` consuming an operator-supplied `--block-digest` (`OfflineBlockVerifySoundness.md` F-BV2): the wallet *produces* an artifact and the operator *anchors* it, never the reverse.

- **(b) The supplied set must be the real committed state.** Because the emitted root is *derived from* `Λ_L`, an operator who feeds a fabricated or incomplete `Λ_L` gets a perfectly valid round-trip (MP-2(a)) against a root that is *not* `state_root(H)` — so the cross-check (a) fails (the emitted root will not equal the committee-signed root), correctly flagging the set as non-canonical. The trust-minimization is therefore a **conjunction**: the proof is meaningful for the real chain iff *both* the emitted `state_root` matches a committee-signed header's `state_root` *and* `Λ_L` is the complete canonical ten-namespace set (`S033StateRootNamespaceCoverage.md` T-1) — the latter being implied by the former under A2 (a complete-and-correct set is the unique set, up to A2, whose root equals the anchored root, by `MerkleRootRecomputeSoundness.md` MR-2).

**Contrast with the daemon's `rpc_state_proof`.** The daemon's `Chain::state_proof` (`chain.cpp:435-462`) serves proofs over the **real committed leaves** (`build_state_leaves()`, the genuine post-apply state), with `leaf_count` and `state_root` reflecting the daemon's own canonical state. A light client trusts the daemon's served proof *because it cross-checks the daemon's claimed root against a committee-signed header* (`MerkleTreeSoundness.md §5.4`, `StateRootAnchorSoundness.md`). `merkle-proof` differs only in *where the leaf set comes from*: the operator supplies it, rather than the daemon serving it from real state. The verification math (MP-2 = MT-4) is identical; the trust difference is entirely in the leaf-set provenance.

**The legitimate uses.** Given (a)+(b), `merkle-proof` is sound and useful for exactly three workflows:
1. **Fixture construction** — generate a known-good proof over a hand-built leaf set for tests / documentation / the `state-proof-verify` round-trip CI tripwire (MP-1's corollary).
2. **Offline proof construction over a known-good leaf set** — an operator holding a *full-node state export* / *verified snapshot* (whose `state_root` they have already anchored via `verify-state-root` / `merkle-root --check`) generates inclusion proofs for individual leaves *without* a live daemon, for downstream consumers.
3. **Diffing against a daemon-served proof** — generate the proof locally and byte-compare it to the daemon's `state_proof` reply for the same `(namespace, key)`; MP-1 says they must be identical, so any difference localizes a daemon misbehavior or a state divergence.

In none of these does `merkle-proof` *establish* the root's authenticity — that is always sourced out-of-band (SR-1).

**Proof.** (a) follows because `cmd_merkle_proof` *computes* `state_root` from the supplied leaves (§2.1, the `wbuf` block) with no provenance check — there is no `--root` parameter to verify against, and with no `libdeterm_chain` link the command has no access to a committee-signed header to anchor the result. The generation's *meaning* (MP-2's "in the committed set") is therefore conditional on the emitted root being the genuine committee-committed root — exactly the `MerkleRootRecomputeSoundness.md` MR-3(a) / `OfflineBlockVerifySoundness.md` BV-2 conditional structure, here on the *self-emitted* root. (b) follows because `cmd_merkle_proof` hashes precisely the leaves present in the JSON and proves membership in *that* tree; a fabricated/incomplete set yields a valid proof against a non-canonical root, caught only by the (a) cross-check (which fails when the emitted root ≠ the committee-signed root). ∎

---

## 4. Composition with companion proofs

### 4.1 `MerkleTreeSoundness.md` — the primitive `merkle-proof` generates witnesses for

`merkle-proof` is a faithful reimplementation of `crypto::merkle_proof` whose output is the witness MT-4 consumes. MP-1 establishes byte-equivalence; from there `merkle-proof` *inherits* the primitive's theorems over the wallet's inline code:

- **MT-1** (determinism / permutation-invariance) ⇒ `merkle-proof` produces the same `target_index` + proof + `state_root` regardless of the JSON array order (it re-sorts, §2.2).
- **MT-2** (domain separation) ⇒ the `0x00`/`0x01`/`0x02` tags prevent leaf/inner/wrap confusion in both the generated proof and the verifier round-trip (MP-2).
- **MT-4** (inclusion-proof soundness) ⇒ the generated proof verifies for a member and only a member (up to A2) against the committed root — this is *exactly* MP-2(b), instantiated with the generator's output. MP-2(a) is MT-4's honest-path positive direction.
- **§6.2 / S-040** (`leaf_count` binding) ⇒ the `0x02` wrapper binds the count into the emitted `state_root`; a verifier handed the proof with a forged `leaf_count` is rejected (the same S-040 rejection `MerkleTreeSoundness.md` scenario #12 pins).
- **§6.1** (CVE-2012-2459: does NOT apply) — for the canonical sorted distinct-key state leaf set. The caveat is the operator-supplied-JSON one (§2.2, §5 F-MP6): the operator must supply distinct keys, which a real chain export satisfies automatically.

This document does **not** re-derive MT-1/MT-2/MT-4 or §6.2; it composes them over the proved-equivalent reimplementation, exactly as `MerkleRootRecomputeSoundness.md` MR-1 composes the root over the wallet code and `OfflineBlockVerifySoundness.md` BV-1 composes the `tx_root`.

### 4.2 `MerkleRootRecomputeSoundness.md` — the shared `state_root` wrap (MR-1 reused)

`merkle-proof`'s emitted `state_root` IS `merkle-root`'s output over the same set: the `0x02 ‖ u32_be(leaf_count) ‖ inner_root` wrapper is the *identical* inline block, and MP-1(iii) is literally a citation of `MerkleRootRecomputeSoundness.md` MR-1 (the wrapped root equals `crypto::merkle_root`, hence `Chain::compute_state_root`). So the three offline Merkle commands form a closed triad over one shared hash core: `merkle-root --leaves L` and `merkle-proof --leaves L --key K` emit the *same* `state_root` for the same `L`, and `state-proof-verify --in (merkle-proof output) --root (that state_root)` is VALID (MP-2(a)). An operator can therefore: (1) `merkle-root --leaves L --check R` to confirm `L` reconstructs an anchored `R` (MR-2); then (2) `merkle-proof --leaves L --key K` to extract a single-leaf proof whose `state_root` *equals* that same `R` (MP-1(iii)); the proof is then anchored transitively through step (1)'s `--check` against the committee-signed `R`.

### 4.3 `StateRootAnchorSoundness.md` — where the emitted root must be anchored

MP-3(a) defers the emitted root's authenticity to SR-1. The composition `SR-1 → MP-2` is the single-leaf analog of `MerkleTreeSoundness.md §5.4`'s `SR-1 → MT-4`: SR-1 establishes *"committee signatures (A1) → block_hash → state_root(H)"*; MP-2 establishes *"state_root(H) ⇔ this one leaf is committed at this index"* (given the emitted root equals `state_root(H)`). An operator who runs `verify-state-root --height H` to obtain a trust-anchored `R`, confirms `merkle-proof`'s emitted `state_root == R`, and round-trips the proof, learns under A1+A2 that the target leaf is *exactly* a committee-committed state entry at `H`. (This requires the operator to *hold* the full leaf set — the offline-export use case of MP-3, not the light-client partial-read case, which uses the daemon's `state_proof` directly.)

### 4.4 `S033StateRootNamespaceCoverage.md` — the completeness MP-3(b) presumes

MP-3(b)'s "supply the real committed set" precondition is the ten-namespace surface T-1 enumerates as complete. T-2 (namespace disjointness, distinct ASCII prefixes) underwrites the distinct-key precondition (§2.2) for the canonical set; T-3 (deterministic leaf ordering) composes with MP-1's sort to give the platform-independent `target_index`. `merkle-proof` cannot verify this coverage (no chain link) — it proves membership in whatever tree the supplied set forms; completeness/canonicity is enforced only by the MP-3(a) cross-check of the emitted root against the committee-signed root (under A2 the complete-correct set is the unique set whose root matches).

### 4.5 `OfflineBlockVerifySoundness.md` — the sibling wallet-TCB-separated tool

`merkle-proof`, `merkle-root`, and `block-verify` are siblings: all OFFLINE, all reimplementing a chain commitment over OpenSSL SHA-256 (and `block-verify` additionally libsodium) because `determ-wallet` does not link the chain library, all consuming/producing an operator-trusted anchor the wallet cannot self-establish. MP-1 ↔ MR-1 ↔ BV-1 (byte-equivalence of the reimplementation to the daemon's commitment); MP-3(a) ↔ F-MR2 ↔ F-BV2 (the *meaning* is conditional on a correctly-anchored root/digest). The difference: `block-verify`'s `tx_root` is a *flat sorted-dedup-union* SHA-256 (NOT a Merkle tree — `OfflineBlockVerifySoundness.md §2.1`), so it imports no MT-* theorems; `merkle-proof` *generates the Merkle inclusion witness itself* and imports MT-1/MT-2/MT-4 + S-040 directly (§4.1). All three reduce to A2 (and `block-verify` additionally A1 for its SIGS check); `merkle-proof` uses no A1 in its own bound.

### 4.6 `Preliminaries.md` — the assumption base

MP-1 is unconditional (function equality). MP-2(a) is unconditional (honest round-trip); MP-2(b) reduces to A2 (§2.1) via MT-4 + the S-040 wrap. MP-3 states preconditions and contributes no probability term. A1 appears only by *reference* in MP-3(a) (the source of trust for the emitted root, via SR-1) and is not a term in any bound this command computes. A3, A4 unused.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `merkle-proof` output does and does not assert. None undermines MP-1's exactness or MP-2's per-invocation inverse soundness; all are coverage/scope statements or the one anchor conditional.

### F-MP1 MP-1 is exact and unconditional — but only as good as the next CI pin

The byte-equivalence MP-1 asserts is a *current-source* fact about the inline lambdas/loop vs. `crypto::merkle_proof` + `merkle_root_wrap`. It holds by inspection today, but it is a hand-rolled reimplementation with no compiler-enforced link to the primitive. A future edit to either side (a changed prefix, endianness, sibling rule, odd-row rule, or the `0x02` wrap) silently breaks the equivalence. The §3.1 tripwire corollary is the mitigation: a CI fixture that generates a proof for a known leaf set, round-trips it through `state-proof-verify`, and diffs the emitted tuple against the daemon's `state_proof` output pins MP-1. **Recommendation:** add/maintain such a cross-binary fixture (the `merkle-proof` analog of `tools/test_merkle_proof_tampering.sh`'s in-binary assertions).

### F-MP2 The emitted `state_root` is self-asserted, not anchored (the TCB-separation anchor)

`merkle-proof` *computes* `state_root` from the supplied leaves; it does **not** establish that root is the chain's genuine committee-committed `state_root`. A proof that round-trips VALID against its own emitted root is a *closed loop* — it correctly says "this leaf is in the tree I just built," but that tree may not be the real chain state. The operator MUST cross-check the emitted `state_root` against a committee-signed anchor — `determ-light verify-state-root` (`StateRootAnchorSoundness.md` SR-1), a verified snapshot tail, or a committee-signed header field — before the proof means "in the real chain state." This is the deliberate cost of the wallet's chain-library-free TCB, the dual of `merkle-root`'s `--check` root (`MerkleRootRecomputeSoundness.md` F-MR2) and `block-verify`'s `--block-digest` (`OfflineBlockVerifySoundness.md` F-BV2). **An operator who consumes a generated proof without anchoring its `state_root` has verified nothing about the chain.**

### F-MP3 The supplied leaf set is uncertified — a proof over a fabricated set verifies fine

`merkle-proof` proves membership in the tree formed by *whatever leaves the JSON carries*. It has no chain link, so it cannot confirm the array is the complete canonical ten-namespace committed set (`S033StateRootNamespaceCoverage.md` T-1) or that each `value_hash` reflects real apply-layer state. An adversary (or a careless operator) who includes a fabricated `(key, value⋆)` in `Λ_L` gets a perfectly valid round-trip — because the leaf IS a genuine member of *that* tree (MP-2(a), no collision needed). The only defense is F-MP2's cross-check: the emitted `state_root` of a fabricated/incomplete set will not equal the committee-signed root, so the anchor step catches it (under A2, by `MerkleRootRecomputeSoundness.md` MR-2). Operators constructing the leaf JSON must derive it from a complete, verified source (a full-node state export / anchored snapshot), not a partial or hand-edited array.

### F-MP4 Per-leaf semantics are out of scope — `value_hash` is opaque

`merkle-proof` treats the target leaf's `value_hash` as opaque 32 bytes. It does not verify that `("a:"+domain, vh)` encodes the *correct* `(balance, next_nonce)` for that account (the `S033StateRootNamespaceCoverage.md §2.1` value-hash encoding), nor that the leaf reflects real apply-layer state (`AccountStateInvariants.md`). A round-trip VALID says "this `(key, value_hash)` pair is committed at this index," not "this `value_hash` was honestly derived." Cross-checking a leaf's `value_hash` against daemon-reported cleartext is the `verify-state-proof` cleartext-cross-check path, not this command.

### F-MP5 Absent target key → error, not a non-membership proof

Per `MerkleTreeSoundness.md` MT-5, the primitive proves positive structure only. `merkle-proof` `return 1`s with `"target key not present in --leaves"` when the target is absent — it does **not** emit a cryptographic absence proof, and the operator cannot conclude from a `merkle-proof` error alone that the key is absent from the *real* chain state (only that it is absent from the *supplied* set). A genuine non-membership claim requires the SMT migration `MerkleTreeSoundness.md §6.3` notes (not shipped), not this command.

### F-MP6 Distinct keys are a caller precondition (the operator-supplied-JSON caveat)

`crypto::merkle_proof`'s distinct-key precondition is discharged for the daemon by `build_state_leaves`'s keyed `std::map`/`std::set` sources (`MerkleTreeSoundness.md §6.1`). `merkle-proof` accepts an *operator-supplied* JSON array, so the operator inherits the obligation: duplicate keys make the non-stable sort's relative order unspecified, and the linear scan returns the *first* sorted leaf with a matching key — which may not be the `lower_bound` index the daemon would use, so MP-1's `target_index` equality can break for the duplicated key (the "set" is ill-posed). The command does not enforce uniqueness (it mirrors the primitive's "keys assumed unique by caller" contract). Given a distinct-keyed set sourced from a real chain export, this is satisfied automatically; a hand-edited JSON with accidental duplicates is the operator's responsibility. No code defect — a documented contract consistent with the primitive.

### F-MP7 Single-leaf set ⇒ empty proof (degenerate but sound)

A `--leaves` array with exactly one leaf yields `target_index = 0`, `proof = []` (the empty array — the `while (row.size() > 1)` loop never runs), and `state_root = H(0x02 ‖ u32_be(1) ‖ LH(k,v))` (§2.3). This round-trips VALID: `state-proof-verify`'s walk also skips its loop and compares the wrapped leaf hash directly to `--root` (`MerkleTreeSoundness.md §6.4`). Sound but degenerate — a real chain's committed state is never a single leaf (it carries ≥ 13 `k:` constants + 5 `k:c:` counters even at genesis — `S033StateRootNamespaceCoverage.md §4.3`), so a single-leaf `merkle-proof` is a fixture/test artifact, not a real-chain proof. The empty leaf set is rejected outright (`return 1`, "no leaf to prove"), unlike `merkle-root`'s all-zero sentinel — there is no leaf to generate a proof for.

---

## 6. Implementation cross-references

| Theorem | Component | File / location | Role |
|---|---|---|---|
| MP-1 | wallet generator | `wallet/main.cpp::cmd_merkle_proof` (search `int cmd_merkle_proof`) | Inline sort + target-index scan + sibling collection + `0x02` wrap — the reimplementation. |
| MP-1 | wallet leaf/inner lambdas | `cmd_merkle_proof` `leaf_hash` / `inner_hash` lambdas | `0x00 ‖ u32_be(\|k\|) ‖ k ‖ v` / `0x01 ‖ l ‖ r` — byte-identical to the primitive; shared with `cmd_merkle_root` / `cmd_state_proof_verify`. |
| MP-1 | wallet `0x02` wrapper | `cmd_merkle_proof` `wbuf` block | `0x02 ‖ u32_be(leaf_count) ‖ inner_root` — byte-identical to `merkle_root_wrap`; the emitted `state_root`. |
| MP-1 | daemon primitive | `src/crypto/merkle.cpp::merkle_proof` (+ `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap`) | The byte-identical reference. |
| MP-1 | daemon served-proof | `src/chain/chain.cpp:435-462` (`Chain::state_proof`) | The `rpc_state_proof` reply `merkle-proof` reproduces (sort + `lower_bound` + `merkle_proof`). |
| MP-1 | byte-equivalence of the wrap | `MerkleRootRecomputeSoundness.md` MR-1 | The emitted `state_root` = `crypto::merkle_root` = `compute_state_root`. |
| MP-2 | inverse / inclusion soundness | `MerkleTreeSoundness.md` MT-4 | Generated proof verifies for a member and only a member (up to A2). |
| MP-2 | verifier (round-trip target) | `wallet/main.cpp::cmd_state_proof_verify` (search `int cmd_state_proof_verify`) | The dual: re-walks the proof to VALID/INVALID; shares the leaf/inner/wrap lambdas. |
| MP-2 | daemon verifier reference | `src/crypto/merkle.cpp::merkle_verify` | The byte-identical reference the verifier reimplements. |
| MP-2 | S-040 count binding | `MerkleTreeSoundness.md §6.2` / `SECURITY.md §S-040` | `0x02` wrapper binds `leaf_count` into the emitted root. |
| MP-3 | emitted-root authenticity (anchor) | `StateRootAnchorSoundness.md` SR-1 | Where the emitted `state_root` must be cross-checked (committee-signed). |
| MP-3 | leaf-set completeness | `S033StateRootNamespaceCoverage.md` T-1 (ten namespaces) | The "supply the real committed set" precondition. |
| MP-3 | sibling whole-set recompute | `MerkleRootRecomputeSoundness.md` (MR-1 / MR-3) | The triad sibling; `merkle-root`'s `--check` anchors the same root. |
| MP-E | bound | — | `Pr[\text{false-member accept}] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class; MP-1 + MP-2(a) unconditional; no A1/A3/A4 term. |
| — | sibling TCB-separated tools | `OfflineBlockVerifySoundness.md` (BV-1 / F-BV2), `MerkleRootRecomputeSoundness.md` (MR-1 / F-MR2) | The posture this document mirrors. |
| — | canonical spec | `docs/PROTOCOL.md §10.2` | `state_proof` RPC return shape `merkle-proof` reproduces byte-for-byte. |

---

## MP-E — error bound

The generation (MP-1) is an exact deterministic function equality — **probability-1 correct**, no cryptographic term. The positive round-trip (MP-2(a)) is likewise unconditional — **probability-1 VALID** on the honest path (the generator's output always verifies against its own emitted root). The negative soundness (MP-2(b)) reduces to a single A2 break in the leaf/inner/wrap reduction:

$$
\Pr\big[\,\text{state-proof-verify accepts merkle-proof's output for a non-member at the proven index, against the emitted root}\,\big]
\;\le\; \varepsilon_{A2} \;\le\; 2^{-128}\text{-class}.
$$

The MP-3 conditionals — that the emitted `state_root` equals the genuine committee-committed root, and that `Λ_L` is the complete canonical leaf set — are **not** probability terms; they are operator-supplied preconditions (§5 F-MP2, F-MP3), exactly as `MerkleRootRecomputeSoundness.md` MR-E excludes the anchor conditional and `OfflineBlockVerifySoundness.md` BV-E excludes the digest conditional. The honest statement: *MP-1 unconditional; MP-2(a) unconditional round-trip; MP-2(b) sound under A2; meaningful for the real chain iff the emitted `state_root` is committee-anchored and `Λ_L` is the real committed set.* No A1 term (no signatures in the generation or round-trip), no A3 (no preimage argument), no A4 (no sampling).

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_merkle_proof` is in `wallet/main.cpp` (dispatched on `merkle-proof`), an OFFLINE generator over OpenSSL SHA-256 with no RPC / daemon / chain-library link. It reimplements `src/crypto/merkle.cpp::merkle_proof` + `merkle_root_wrap` inline, sharing the leaf/inner/wrap lambdas with the sibling `cmd_merkle_root` and `cmd_state_proof_verify`, and emits the `rpc_state_proof` reply shape verbatim.
- **Proof.** Complete (this document). **MP-1** (byte-equivalence: the wallet generator's `target_index` / `proof` / `state_root` equal `crypto::merkle_proof` + `merkle_root` — hence the daemon's `state_proof` — for the same sorted leaf set; unconditional; doubles as the regression tripwire). **MP-2** (generator/verifier inverse: the emitted tuple round-trips VALID through `state-proof-verify` against the emitted root — unconditional positive (MP-2(a)) — and, under A2, verifies for a leaf iff it is in the committed set (MP-2(b)); the "committed set" is the tree built from the *supplied* leaves, which is why the meaning is conditional on MP-3). **MP-3** (the honest boundary: a generated proof proves "this leaf is in THIS tree", NOT "in the REAL chain state" — the emitted `state_root` is self-asserted and must be cross-checked against a committee-signed header (`StateRootAnchorSoundness.md` SR-1), and the supplied set must be the real committed state (`S033StateRootNamespaceCoverage.md` T-1); contrast the daemon's `rpc_state_proof` over real committed leaves; legitimate uses: fixture construction, offline proof construction over a known-good set, diffing against a daemon-served proof). **MP-E** bound: `≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class; the generation and honest round-trip are unconditional; the anchor + set-completeness conditionals are operator preconditions, not probability terms.
- **Cryptographic assumptions used.** A2 (SHA-256 collision / second-preimage resistance) only, for MP-2(b). MP-1 and MP-2(a) are unconditional. A1 enters by reference in MP-3(a) (trust source for the emitted root, via SR-1), not as a term. A3, A4 unused. Per `Preliminaries.md §2.0`.
- **The TCB-separation posture (load-bearing).** `determ-wallet` deliberately does not link the chain library; `merkle_proof` is reimplemented inline. MP-1 proves the reimplementation byte-identical, so a generated proof is exactly the daemon's `state_proof` reply for the same set — unconditional for the *generation*, unconditional for the honest *round-trip*, sound under A2 for the *non-member rejection*, and *conditional* (on a committee-anchored emitted `state_root` and a real committed leaf set) for the *meaning* — the precise boundary between what `merkle-proof` proves unconditionally, cryptographically, and by operator precondition.
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-2/MT-4 + §6.2 S-040, recomputed over the wallet code via MP-1), `MerkleRootRecomputeSoundness.md` (MR-1 — the shared `state_root` wrap; the triad sibling), `StateRootAnchorSoundness.md` (SR-1 — the anchor MP-3(a) defers to), `S033StateRootNamespaceCoverage.md` (T-1..T-3 — the completeness MP-3(b) presumes), `OfflineBlockVerifySoundness.md` (BV-1 / F-BV2 — the sibling byte-equivalence + anchor-conditional posture), `Preliminaries.md` (A2 base).
- **Known limitations (§findings).** F-MP1 (MP-1 is exact but only as good as the next CI pin — add a cross-binary round-trip tripwire fixture); **F-MP2 (the load-bearing one: the emitted `state_root` is self-asserted and must be cross-checked against a committee-signed header — the wallet-TCB-separation anchor cost; an unanchored round-trip verifies nothing about the chain)**; F-MP3 (the supplied leaf set is uncertified — a proof over a fabricated set round-trips fine, caught only by the F-MP2 anchor cross-check); F-MP4 (per-leaf `value_hash` semantics out of scope); F-MP5 (absent target key → error, not a non-membership proof); F-MP6 (distinct keys are a caller precondition for the operator-supplied JSON); F-MP7 (single-leaf ⇒ empty proof — degenerate but sound; empty set rejected outright). None undermines MP-1's exactness or MP-2's per-invocation inverse soundness.

---

## 8. References

### Implementation sites
- `wallet/main.cpp::cmd_merkle_proof` (search `int cmd_merkle_proof`) — the OFFLINE generator; inline sort + target-index scan + sibling collection + `0x02` wrap; emits the `rpc_state_proof` reply shape; exit `0`/`1`.
- `wallet/main.cpp::cmd_merkle_root` (search `int cmd_merkle_root`) — the sibling whole-set root recompute sharing the leaf/inner/wrap lambdas (the triad's BUILD side; `MerkleRootRecomputeSoundness.md`).
- `wallet/main.cpp::cmd_state_proof_verify` (search `int cmd_state_proof_verify`) — the sibling single-leaf verifier sharing the lambdas (the triad's CONSUME side; the round-trip target of MP-2).
- `src/crypto/merkle.cpp::merkle_proof` / `merkle_verify` / `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root_wrap` — the byte-identical reference primitives.
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (the daemon's `rpc_state_proof`; sort + `lower_bound` + `merkle_proof` — what `merkle-proof` reproduces).

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §1.3 hash notation; §2.0 assumption labels; §2.1 A2 (SHA-256 collision / second-preimage resistance).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (domain separation), MT-4 (inclusion-proof soundness — the core MP-2 instantiates), §6.1 (CVE-2012-2459 — does not apply), §6.2 (S-040 `leaf_count` binding), §6.4 (single-leaf base case); recomputed over the wallet code via MP-1.
- `docs/proofs/MerkleRootRecomputeSoundness.md` — MR-1 (byte-equivalence of the shared `state_root` wrap), MR-2 (`--check` set-commitment), MR-3 (the anchor boundary); the triad sibling.
- `docs/proofs/StateRootAnchorSoundness.md` — SR-1 (committee-anchored root); the source of trust for the emitted `state_root` (MP-3(a)).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (ten-namespace coverage completeness), T-2 (namespace disjointness), T-3 (deterministic leaf ordering); the completeness MP-3(b) presumes.
- `docs/proofs/OfflineBlockVerifySoundness.md` — the sibling wallet-TCB-separated OFFLINE tool; BV-1 (byte-equivalence) / F-BV2 (operator-supplied-anchor conditional) posture mirrored.

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` algorithm + Merkle-leaf table + balanced-binary-tree statement.
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC return shape (key_bytes, value_hash, target_index, leaf_count, proof, state_root) — the shape `merkle-proof` reproduces byte-for-byte.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` root-wrapper binding (the `0x02` wrap).
- NIST FIPS 180-4 — SHA-256 (A2).
- RFC 6962 §2.1 — Certificate Transparency `0x00`/`0x01` leaf/node tagged hashing (the domain-separation pattern Determ follows, here extended to `0x02`).
