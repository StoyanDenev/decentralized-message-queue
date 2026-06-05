# StateProofCompositeKeySoundness — byte-exact composite-key reconstruction + hex-transport necessity for the `i:`/`m:`/`p:` `state_proof` RPC extension

This document formalizes the soundness of the **daemon-side** extension of the generic `state_proof` RPC to the three **composite-key** namespaces `i:` (applied-inbound-receipts), `m:` (merge-state), and `p:` (pending-param-changes). Where `ReceiptInclusionProofSoundness.md` proves the **verifier-side** read-back of an `i:` leaf (what an honest light client may conclude from a passing proof), *this* proof covers the surface immediately upstream of it: that the daemon's `Node::rpc_state_proof` (`src/node/node.cpp` rpc_state_proof, lines 3287–3378) reconstructs the canonical leaf key **byte-for-byte identically** to `Chain::build_state_leaves` (`src/chain/chain.cpp:331–378`) from a hex-encoded binary body, that its length-check provably rejects every malformed body before it can alias a different leaf, and that the soundness of the whole pipeline is **independent of how the key was sourced** because the verifier re-derives the leaf hash from `key_bytes` and gates on a committee-signed root.

The proof exists because the composite namespaces are **structurally different** from the simple namespaces `a|s|r|d|b|k|c` in one way that creates a new attack surface at the RPC boundary:

1. **The leaf-key suffix is raw binary, not an ASCII `domain` string.** For the simple namespaces the RPC's `key` parameter *is* the human-readable suffix and the full leaf key is the trivial concatenation `"<ns>:" + key` (node.cpp:3314–3329). For `i|m|p` the suffix is a fixed-width packing of big-endian integers and 32-byte hashes — `i:` = `u64_be(src_shard) ‖ tx_hash[32]` (40 B), `m:` = `u32_be(shard_id)` (4 B), `p:` = `u64_be(eff_height) ‖ u32_be(idx)` (12 B) — read directly off the three `build_state_leaves` loops at `chain.cpp:331–341` (`i:`), `:349–360` (`m:`), `:361–378` (`p:`). A SHA-256 `tx_hash` is uniformly random over 256 bits, so with overwhelming probability it contains bytes that are not valid UTF-8 continuation sequences; `nlohmann::json::dump()` throws `type_error.316` on such bytes. Raw binary therefore **cannot** ride inside a JSON string field, which forces the hex-transport design (§4.4) and creates the decode/length-check boundary this proof secures (§4.1–§4.2).

The claim is narrow and mechanical but load-bearing for the entire composite-key light-client family: **an honest daemon serving a composite-key proof returns a proof for *exactly* the leaf the caller named, or an explicit error — never a proof for a silently-aliased neighboring leaf.** The companion verifier-side guarantee (the daemon cannot make an honest client *accept* a wrong-key proof even if it tried) is `ReceiptInclusionProofSoundness.md` RI-2; the two compose into the end-to-end result that the composite read is sound under a fully-Byzantine daemon. No new cryptographic primitive is introduced; the daemon-side reconstruction is a pure deterministic function and the soundness of the *verification* reduces to **A2** (SHA-256 collision resistance) exactly as the simple-key reads do.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1) — the *verification* of a composite-key proof reduces to **A2** only, identical to the simple-key reads; the daemon-side reconstruction (SP-CK-1/SP-CK-2) is *unconditional* (a deterministic-function-equality argument, no assumption); `ReceiptInclusionProofSoundness.md` (the verifier-side `i:` read this proof is the daemon-side complement of — its **RI-2** re-derives the leaf hash from `key_bytes` and is exactly the property SP-CK-3 shows makes our reconstruction *sourcing-independent*; its §1.4 R-ext/R-cli sourcing dichotomy is the same one SP-CK-3 formalizes; its §1.2 `i:` encoding table is the source-of-truth the byte-equality in SP-CK-1 is checked against); `MerkleTreeSoundness.md` (the sorted-leaves Merkle primitive — its **MT-1** determinism, **MT-2** leaf-key domain separation / unambiguous length-prefixed key encoding, **MT-3** collision-resistance inheritance, **MT-4** inclusion-proof soundness; SP-CK-3's sourcing-independence rests on MT-4's property that a passing `merkle_verify` against a committee-signed root proves membership of the *specific* `key_bytes` re-derived by the verifier; **MT-2** is why a one-byte length error in the reconstructed key produces a different leaf hash, the mechanism SP-CK-2 leans on); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding that turns "a proof against root `R`" into "a proof against the *committee-certified* root", inherited verbatim; the reconstruction proof here is orthogonal to and composes underneath SR-1); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** namespace table fixes the canonical `i:`/`m:`/`p:` key encodings the byte-equality argument of SP-CK-1 is matched against, its **T-2** namespace disjointness guarantees `"i:"+… ≠ "m:"+… ≠ "p:"+…` at byte 0 so a correct-length body in the wrong namespace still cannot alias, and its **T-3** deterministic leaf ordering is what makes `Chain::state_proof`'s `lower_bound` (`chain.cpp:445–449`) find the unique target); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon` and the **T-L3** state-proof-correctness flow this proof specializes to composite keys); `TxInclusionProofSoundness.md` + `StakeProofSoundness.md` (the membership / `s:` siblings whose *simple-key* RPC path this proof shows the composite path is byte-faithful to); `docs/SECURITY.md` §S-033 + §S-040 for the closure narratives (S-040 CLOSED — `leaf_count` is bound into the committed root via the root-wrapper hash, so a forged count is rejected by `merkle_verify`; the former caller-trust framing is superseded); `docs/PROTOCOL.md` §4.1.1 for the canonical composite Merkle-leaf rows + §10.2 for the `state_proof` RPC contract (`namespace`/`key` params, hex-body convention for `i|m|p`).

---

## 1. Scope

### 1.1 In scope

The `i|m|p` branch of `Node::rpc_state_proof` (`src/node/node.cpp:3330–3356`) and its three obligations:

> Given a caller-supplied `(namespace ∈ {i,m,p}, key = hex(body))`, the daemon (a) hex-decodes `key` to `body`, (b) **rejects** any `body` whose length is not the exact canonical width for that namespace, and (c) for a correct-length body, reconstructs the leaf key `k = "<ns>:" ‖ body` and serves `Chain::state_proof(k)` — and the reconstructed `k` is **byte-identical** to the key `build_state_leaves` would emit for the same logical entry.

The three theorems:

| Theorem | Property |
|---|---|
| **SP-CK-1** (Byte-exact reconstruction) | For every logical composite entry, the daemon's reconstructed key equals the `build_state_leaves` key byte-for-byte; the served proof is therefore a proof of the *intended* leaf. |
| **SP-CK-2** (Length-check completeness) | Every `body` whose length ≠ the canonical width is rejected with an explicit error *before* `Chain::state_proof` is called; no malformed body can produce a (silently-aliased) proof. |
| **SP-CK-3** (Sourcing-independent soundness) | Whether `key_bytes` is rebuilt by the daemon (R-ext) or supplied verbatim by the client (R-cli), the verifier re-derives the leaf hash from `key_bytes` and gates on the committee-signed root, so a daemon that serves a proof for the wrong key is caught — the reconstruction is a *convenience*, not a *trust assumption*. |

Plus the transport lemma:

| Lemma | Property |
|---|---|
| **SP-CK-T** (Hex-transport necessity) | The raw composite suffix cannot ride inside a JSON string (a SHA-256 `tx_hash` breaks `json::dump()`'s UTF-8 contract), so hex encoding of the body is *necessary*, not stylistic; and the encoding is byte-lossless under `to_hex`/`from_hex`. |

### 1.2 The composite-key encodings (read off source)

From `Chain::build_state_leaves`, the three composite loops (`src/chain/chain.cpp`):

```cpp
// i:  applied_inbound_receipts_  (key = "i:" + src_be8 + tx_hash)        chain.cpp:331-341
key.push_back('i'); key.push_back(':');
for (int i = 7; i >= 0; --i) key.push_back((src >> (8*i)) & 0xff);   // src_shard, u64 big-endian
key.insert(key.end(), tx_hash.begin(), tx_hash.end());              // 32-byte source tx hash
// value = SHA256(0x01)  (constant presence marker)

// m:  merge_state_  (key = "m:" + shard_id_be4)                          chain.cpp:349-360
key.push_back('m'); key.push_back(':');
for (int i = 3; i >= 0; --i) key.push_back((shard >> (8*i)) & 0xff); // shard_id, u32 big-endian

// p:  pending_param_changes_  (key = "p:" + eff_be8 + idx_be4)           chain.cpp:361-378
key.push_back('p'); key.push_back(':');
for (int i = 7; i >= 0; --i) key.push_back((eff >> (8*i)) & 0xff);   // eff_height, u64 big-endian
for (int i = 3; i >= 0; --i) key.push_back((uint32_t(idx) >> (8*i)) & 0xff); // entry index, u32 big-endian
```

So the canonical leaf key for each composite namespace is:

$$
\begin{aligned}
\text{key}_i(S, H) &= \texttt{"i:"} \,\|\, u64\_be(S) \,\|\, H_{32}, & |\text{body}_i| &= 8 + 32 = 40 \text{ B},\\
\text{key}_m(D) &= \texttt{"m:"} \,\|\, u32\_be(D), & |\text{body}_m| &= 4 \text{ B},\\
\text{key}_p(E, j) &= \texttt{"p:"} \,\|\, u64\_be(E) \,\|\, u32\_be(j), & |\text{body}_p| &= 8 + 4 = 12 \text{ B}.
\end{aligned}
$$

The daemon-side reconstruction (`node.cpp:3330–3353`):

```cpp
} else if (ns == "i" || ns == "m" || ns == "p") {
    std::vector<uint8_t> body;
    try { body = from_hex(key); }
    catch (const std::exception&) {
        return {{"error", "invalid hex key for composite namespace"}, ...};
    }
    const size_t want = (ns == "i") ? (8 + 32)   // src_be8 + tx_hash[32]
                      : (ns == "m") ? 4           // shard_be4
                                    : (8 + 4);    // eff_be8 + idx_be4
    if (body.size() != want) {
        return {{"error", "composite key wrong length"}, ...};
    }
    k.reserve(2 + body.size());
    k.push_back(ns[0]); k.push_back(':');
    k.insert(k.end(), body.begin(), body.end());
}
```

`want` is `40`/`4`/`12` for `i`/`m`/`p` respectively — exactly the body widths above. The reconstructed `k = ns[0] ‖ ':' ‖ body`; the byte-equality of this to the `build_state_leaves` key is the subject of SP-CK-1.

### 1.3 Out of scope (intentional)

- **The cryptographic membership soundness of the returned proof.** That `merkle_verify` against a committee-signed root proves membership is `MerkleTreeSoundness.md` MT-4; that the root is committee-certified is `StateRootAnchorSoundness.md` SR-1; that the verifier acts soundly on the result for the `i:` namespace is `ReceiptInclusionProofSoundness.md` RI-1..RI-5. This proof secures only the *key-reconstruction + transport* boundary upstream of those.
- **Non-membership / absence proofs.** A composite query for an entry not in the tree returns `{"error":"not_found"}` (`node.cpp:3359–3361`), inheriting the sorted-leaves membership-only boundary (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449`). This proof covers the *positive* reconstruction path; the negative is the same one-sided limitation `ReceiptInclusionProofSoundness.md` RI-3 records.
- **The `leaf_count` binding (S-040 CLOSED).** `leaf_count` is now bound into the committed root via the root-wrapper hash `root = SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`; `0x02` domain-separated from `0x00` leaf / `0x01` inner). `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the caller-supplied `leaf_count`, and compares to the committed root — so a forged `leaf_count` (`M ≠ N`) yields a different wrapper hash and is **rejected**. The former "single-envelope-sourcing" obligation is now enforced by the hash, not just a caller guideline. Orthogonal to reconstruction; `ReceiptInclusionProofSoundness.md` RI-4 owns the verifier-side detail.
- **RPC authentication, rate-limiting, transport encryption, the mutating side of the three maps.** Inherited from `S001RpcAuthSoundness.md`, `S014RateLimiterSoundness.md`, `LightClientThreatModel.md` §6, and the apply-layer proofs (`CrossShardReceiptDedup.md`, `S036UnderQuorumMerge.md`, `ParamChangeDeterminism.md`) respectively.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1, and a complementary **malicious caller** `A_caller` for the length-check obligation:

- **`A_daemon`** controls the RPC endpoint and may return arbitrary JSON. The reconstruction code runs *inside* `A_daemon`, so SP-CK-1 (byte-exactness of an *honest* reconstruction) is not a defense against `A_daemon` — it is a *correctness* property of the honest implementation that makes the composite read usable at all, and a *regression tripwire* (SP-CK-1 is the invariant any future edit to the `i|m|p` branch must preserve). The defense against a *Byzantine* daemon that deliberately reconstructs the wrong key is SP-CK-3, which shows the verifier catches it regardless. So the two theorems play distinct roles: SP-CK-1 secures the honest-daemon happy path, SP-CK-3 secures against the Byzantine daemon.
- **`A_caller`** is an untrusted RPC client that submits a malformed `key` — wrong-length body, odd-length hex, non-hex characters, or a correct-length body in the wrong namespace — attempting to make the daemon (a) crash, (b) read out of bounds, or (c) silently serve a proof for a *different* leaf than the one the malformed body nominally addresses (a "key-aliasing" confusion). SP-CK-2 closes (a)/(b)/(c).

**Security goal.**

- (SP-CK-1) An honest daemon's reconstructed composite key is byte-identical to the `build_state_leaves` key for the same entry — so a served proof is a proof of the *intended* leaf, never an off-by-one or wrong-endianness neighbor.
- (SP-CK-2) No malformed `body` — including a 41-byte "`i:` plus one trailing byte" or a 40-byte body submitted under `namespace=m` — reaches `Chain::state_proof`; every such body is rejected with an explicit structured error and the daemon does not crash or alias.
- (SP-CK-3) Under a fully-Byzantine `A_daemon`, an honest client never *accepts* a proof whose `key_bytes` differ from the canonical key it can recompute from its own logical inputs — so even a daemon that ignores SP-CK-1 and reconstructs a wrong key gains nothing.

---

## 3. Reconstruction and verification primitives reused

The composite branch reuses, unchanged:

1. **`from_hex` / `to_hex`** (`include/determ/types.hpp:61–82`) — the byte-lossless hex codec. `from_hex` throws `std::invalid_argument("odd hex length")` on odd-length input (types.hpp:75–76) and `std::stoul` throws on non-hex digits; both are caught by the `try { body = from_hex(key); } catch` at `node.cpp:3333–3338`. `to_hex` is a pure base-16 expansion of each byte (types.hpp:61–67). The round-trip `from_hex(to_hex(b)) = b` is exact for all byte vectors `b` (SP-CK-T).
2. **`Chain::state_proof(k)`** (`src/chain/chain.cpp:435–462`) — builds the full sorted leaf set, `lower_bound`s the exact key `k`, and returns `nullopt` if `it->key != k` (chain.cpp:449). This is namespace-agnostic: it operates on the reconstructed raw-byte key, so once SP-CK-1 establishes `k = build_state_leaves` key, the proof targets the unique correct leaf (or `nullopt` if absent).
3. **`crypto::merkle_verify(root, key_bytes, value_hash, target_index, leaf_count, proof)`** (`src/crypto/merkle.cpp`) — the verifier re-derives the leaf hash `merkle_leaf_hash(key_bytes, value_hash) = H(0x00 ‖ u32_be(|key|) ‖ key ‖ value_hash)` (`merkle.cpp:25–34`) from the **returned `key_bytes`** and walks the sibling chain to the root. The light client calls it at `light/verify.cpp:333–335` over `key_bytes = from_hex(proof_json["key_bytes"])` (verify.cpp:304–305). This is the load-bearing fact for SP-CK-3: verification consumes `key_bytes`, not `(namespace, key)`, so soundness is decided by whether `key_bytes` rolls up to the committee-signed root, independent of who produced it.

---

## 4. Security theorems

Throughout, fix a composite namespace `ns ∈ {i,m,p}`, write `want(ns) ∈ {40, 4, 12}` for the canonical body width (`node.cpp:3341–3343`), and let `body` be the caller-supplied hex-decoded suffix. Let `recon(ns, body) := ns[0] ‖ ':' ‖ body` be the daemon's reconstructed key (`node.cpp:3350–3353`) and `bsl(·)` the corresponding `build_state_leaves` key (`chain.cpp:331–378`).

### 4.1 Theorem SP-CK-1 (byte-exact key reconstruction equals `build_state_leaves`)

**Statement.** For every logical composite entry,

- `i:` entry `(S, H)` ∈ `applied_inbound_receipts_`, with `body = u64\_be(S) ‖ H`,
- `m:` entry `D` ∈ `keys(merge_state_)`, with `body = u32\_be(D)`,
- `p:` entry `(E, j)`, with `body = u64\_be(E) ‖ u32\_be(j)`,

the daemon's reconstructed key `recon(ns, body)` equals the `build_state_leaves` key `bsl(entry)` **byte-for-byte**.

**Proof.** Both `recon` and `bsl` build the key as the literal concatenation `ns[0] ‖ ':' ‖ body`, and we show the `body` parts coincide bit-for-bit by matching the two code sites:

- **`i:`.** `bsl` emits `'i' ':' ‖ (src >> 8·i for i=7..0) ‖ tx_hash[0..31]` (`chain.cpp:335–337`). The caller forms `body = u64\_be(S) ‖ H`; `u64\_be(S)` is *by definition* the bytes `(S >> 8·i) & 0xff` for `i = 7..0` (most-significant first), and `H` is the 32-byte `tx_hash`. `recon` prepends `'i' ':'`. Hence `recon = 'i' ':' ‖ u64\_be(S) ‖ H = bsl(S,H)`. The big-endian byte order is identical because both loops run `for (int i = 7; i >= 0; --i)`.
- **`m:`.** `bsl` emits `'m' ':' ‖ (shard >> 8·i for i=3..0)` (`chain.cpp:353–354`). `body = u32\_be(D)` is `(D >> 8·i) & 0xff` for `i = 3..0`. `recon = 'm' ':' ‖ u32\_be(D) = bsl(D)`.
- **`p:`.** `bsl` emits `'p' ':' ‖ (eff >> 8·i for i=7..0) ‖ (idx >> 8·i for i=3..0)` (`chain.cpp:367–370`). `body = u64\_be(E) ‖ u32\_be(j)`; the two big-endian packings concatenate in the same `(eff, idx)` order. `recon = 'p' ':' ‖ u64\_be(E) ‖ u32\_be(j) = bsl(E,j)`.

In all three, `recon(ns, body)` and `bsl(entry)` are the same byte sequence. Because `Chain::state_proof` indexes leaves by exact-key `lower_bound` + equality (`chain.cpp:445–449`, relying on `S033StateRootNamespaceCoverage.md` T-3 deterministic ordering), a byte-identical key selects the *same unique leaf* `build_state_leaves` produced — so the served `(value_hash, target_index, leaf_count, proof)` is a proof of the intended entry, or `nullopt` if the entry is genuinely absent.   ∎

**Remark (regression tripwire).** SP-CK-1 is the invariant any future edit to either the `build_state_leaves` composite loops or the `node.cpp` `i|m|p` branch must preserve. A drift — e.g. switching one side to little-endian, or changing `want(p) = 12` without updating the `bsl` packing — would break it silently for an *honest* daemon: the daemon would serve `not_found` for a present entry (best case) or, if both sides drift inconsistently, a proof for a neighboring leaf. The end-to-end test `tools/test_light_verify_receipt_inclusion.sh` (a real 2-shard INCLUDED) is the executable guard; this theorem is its specification.

### 4.2 Theorem SP-CK-2 (length-check rejects every malformed body before key construction)

**Statement.** For any caller-supplied `key`, if either (a) `key` is not valid even-length hex, or (b) `from_hex(key)` has length ≠ `want(ns)`, then `rpc_state_proof` returns an explicit `{"error": …}` object and **does not** call `Chain::state_proof` — and in particular never constructs a key of the wrong width that could alias a different leaf.

**Proof.** The `i|m|p` branch executes in strict order (`node.cpp:3330–3356`):

1. `try { body = from_hex(key); } catch (…) { return {{"error","invalid hex key for composite namespace"}, …}; }` — case (a). `from_hex` throws on odd length (types.hpp:75) and `std::stoul` throws `std::invalid_argument` on a non-hex digit; both derive from `std::exception` and are caught here. Control returns; `Chain::state_proof` is unreached.
2. `const size_t want = (ns=="i")?40:(ns=="m")?4:12;` followed by `if (body.size() != want) { return {{"error","composite key wrong length"}, {"expected_bytes",want}, {"got_bytes",body.size()}}; }` — case (b). Any decoded length other than the exact canonical width returns the structured error *before* the `k.push_back(ns[0]); … k.insert(…body…)` reconstruction at lines 3350–3353. Control returns; `Chain::state_proof` is unreached.

Only a body that passes **both** gates — valid even-length hex **and** `|body| = want(ns)` — reaches the reconstruction. Therefore every `recon(ns, body)` that is ever built has exactly the canonical width `2 + want(ns)`, and SP-CK-1 applies to it. The two failure returns are total: there is no path from a malformed body to `Chain::state_proof`.

**Why the width-exactness matters (no aliasing).** Suppose the check were absent and a caller submitted, under `namespace=i`, a 41-byte body `u64\_be(S) ‖ H ‖ 0x00`. The reconstructed key `'i' ':' ‖ S ‖ H ‖ 0x00` is **42+1 = 43** bytes vs. the canonical 42. By `MerkleTreeSoundness.md` MT-2 (length-prefixed key in the leaf hash, `merkle.cpp:25–34` binds `u32_be(|key|)`), this is a *different leaf preimage* — it would simply `not_found` against the genuine tree (no 43-byte `i:` leaf exists), so even an *omitted* check is not a soundness break for `merkle_verify` (the verifier re-derives over whatever `key_bytes` is returned, MT-4). The length-check's role is therefore two-fold and both reasons are real: (i) it converts a confusing silent `not_found` into an actionable `composite key wrong length` diagnostic (operability), and (ii) it guarantees `from_hex` already bounded the body so the subsequent `key.insert(key.end(), body.begin(), body.end())` is in-bounds (memory safety — `body` is a `std::vector`, the insert range is well-formed). Crucially, **a correct-length body in the wrong namespace still cannot alias** a leaf of another namespace, because the namespace byte 0 differs: a 4-byte body under `namespace=m` rebuilds `'m' ':' ‖ …` which by `S033StateRootNamespaceCoverage.md` T-2 disjointness can never equal an `'i'`/`'p'`/`'a'`/… leaf key. So the width check is sufficient — there is no residual cross-namespace confusion to close.   ∎

### 4.3 Theorem SP-CK-3 (soundness is sourcing-independent)

**Statement.** Let the composite-key proof be obtained by either route:

- **(R-ext)** the daemon hex-decodes the caller's `body`, reconstructs `k = recon(ns, body)` per SP-CK-1, and returns `(key_bytes := to_hex(k), value_hash, target_index, leaf_count, proof, state_root, height)` (`node.cpp:3367–3377`); or
- **(R-cli)** the client builds the canonical key `k* = bsl(entry)` *locally* from its own `(S,H)` / `D` / `(E,j)` inputs and treats it as the `key_bytes` the verifier consumes.

Then under a fully-Byzantine `A_daemon`, an honest verifier that (i) re-derives `merkle_leaf_hash(key_bytes, value_hash)` from the returned `key_bytes` (`verify.cpp:304–305, 333–335`), (ii) checks the path against a **committee-signed** `state_root` (SR-1), and (iii) checks `key_bytes` equals the canonical key it can recompute from its own logical inputs, never accepts a proof for a key other than the one it named — **regardless of which route produced `key_bytes`**.

**Proof.** Verification at `light/verify.cpp:333–335` consumes `key_bytes` and `value_hash`, not `(namespace, key)`. So the only daemon-controlled inputs that can influence the verdict are `(key_bytes, value_hash, target_index, leaf_count, proof, state_root)`.

- The honest verifier recomputes the canonical key `k* = bsl(entry)` from its *own* logical inputs (the `(S,H)`/`D`/`(E,j)` it queried) — this is the §4.2.1-style cross-check that `ReceiptInclusionProofSoundness.md` performs for `i:` (verify side), generalized here to all three composite namespaces. If the returned `key_bytes ≠ k*`, the verifier rejects (or, equivalently, re-derives over its own `k*` and any daemon-served proof for a *different* leaf fails the root-equality below).
- Given `key_bytes = k*`, the verifier re-derives `L = merkle_leaf_hash(k*, value_hash)` and walks `proof` to a candidate root `R'`. By `MerkleTreeSoundness.md` MT-4, `R' = state_root` (the committee-signed root, SR-1) holds only if `k*` is a genuine member of the tree `state_root` commits to, except with probability ≤ `log₂(leaf_count) · 2⁻¹²⁸` (an A2 collision). A daemon that reconstructed (R-ext) or was handed (R-cli) the wrong key cannot make a wrong-key proof roll up to the genuine root without exhibiting a collision.

Hence the daemon's *reconstruction step* in (R-ext) is a **convenience that saves the client a few bytes of concatenation, not a trust assumption**: even if a Byzantine daemon ignores SP-CK-1 and reconstructs `recon(ns, body) ≠ bsl(entry)`, the served proof is for the wrong leaf and fails the verifier's root-equality gate. (R-cli) is *strictly stronger* on key-integrity because `key_bytes` never originates from the daemon at all; it is the recommended default (mirroring `ReceiptInclusionProofSoundness.md` §1.4). The decisive property both routes share — *the verifier checks `key_bytes` against the key it can recompute and gates on the committee-signed root* — is what makes SP-CK-1's honest-daemon reconstruction sound to rely on while not being a thing the verifier must *trust*.   ∎

**Composition.** SP-CK-3 is the daemon-side complement of `ReceiptInclusionProofSoundness.md` RI-2: RI-2 proves the verifier cannot be made to *accept* a wrong-key `i:` proof; SP-CK-3 proves that the daemon's *reconstruction* (the new code this round) does not weaken that, and extends the argument to `m:`/`p:`. Together with SR-1 (committee-anchored root) and MT-4 (Merkle membership), the composite-key read is sound under a fully-Byzantine daemon.

### 4.4 Lemma SP-CK-T (hex transport is necessary, and lossless)

**Statement.** (Necessity) The raw composite suffix cannot be carried inside a JSON string field of the RPC reply or request; hex-encoding the body is required for the transport to function at all. (Losslessness) `from_hex(to_hex(b)) = b` for every byte vector `b`, so the hex layer introduces no ambiguity into the reconstructed key.

**Proof.**

- **Necessity.** The `i:` body contains a 32-byte `tx_hash` that is the output of SHA-256 and is, under A3 / uniformity, indistinguishable from 32 uniformly-random bytes. A uniformly-random byte is a valid lead byte of a UTF-8 scalar with probability well below 1 (any byte in `0x80–0xBF` is an illegal *lead* byte; any multi-byte lead must be followed by the correct number of `0x80–0xBF` continuation bytes), so the probability that a random 32-byte string is wholly valid UTF-8 is negligible. `nlohmann::json::dump()` validates UTF-8 and throws `type_error.316 ("invalid UTF-8 byte")` on the first offending byte; the same applies to `u64_be(src_shard)` high bytes for large shard ids and to the `p:`/`m:` integer packings. Therefore a design that placed the raw `body` into the `{"key": …}` JSON string would throw on `dump()` for the overwhelming majority of real composite keys — it is non-functional, not merely ugly. Hex-encoding maps every byte to two characters in `[0-9a-f]`, all of which are ASCII (hence valid UTF-8 and `dump()`-safe). This is exactly the rationale recorded in the `node.cpp:3298–3309` comment block.
- **Losslessness.** `to_hex` writes each byte as two zero-padded lowercase hex digits (types.hpp:61–67); `from_hex` reads two characters at a time via `std::stoul(substr(i,2),16)` and rejects odd length (types.hpp:74–82). For any byte `0x00 ≤ x ≤ 0xff`, `from_hex(to_hex({x})) = {x}`; by concatenation `from_hex(to_hex(b)) = b` for all `b`. So the hex layer is an exact bijection between byte vectors and even-length lowercase-hex strings — the reconstructed `body` the daemon length-checks and prepends is *identical* to the body the caller intended, with no transport-introduced corruption.   ∎

**Consequence.** Necessity (the raw bytes break `dump()`) is *why* the composite branch exists at all; losslessness is *why* it is safe — combined with SP-CK-2's width-check and SP-CK-1's byte-equality, the full path `caller body → hex → JSON → from_hex → width-check → recon → bsl key` is the identity on the body with an explicit-error escape for every malformed input.

---

## 5. Composition with the light-client proof family

The composite-key RPC extension slots beneath the existing light-client stack with no change to the cryptographic core:

```
                         A1 (Ed25519 EUF-CMA)        A2 (SHA-256 collision)
                                  │                          │
   StateRootAnchorSoundness SR-1 (committee-signed state_root)│
                                  │                          │
                          MerkleTreeSoundness MT-4 (inclusion proof sound)
                                  │
        ┌─────────────────────────┴──────────────────────────┐
   simple-key reads (a|s|r|d|b|k|c)            composite-key reads (i|m|p)
   StakeProofSoundness / TxInclusion /         ── THIS DOC ──
   SupplyProofSoundness                        SP-CK-1 (byte-exact recon)
        │                                      SP-CK-2 (length-check complete)
        │                                      SP-CK-3 (sourcing-independent)
        │                                      SP-CK-T (hex transport)
        └─────────────────────────┬──────────────────────────┘
                ReceiptInclusionProofSoundness RI-1..RI-5 (i: verifier read-back)
```

- **SP-CK-1/SP-CK-2 are unconditional** (deterministic-function equality + total case split); they assume no cryptographic hardness.
- **SP-CK-3 reduces to A2** via MT-4, identically to the simple-key reads — the composite extension adds *zero* new cryptographic assumptions.
- **SP-CK-T's necessity half** uses the SHA-256-output uniformity already assumed for `tx_hash` (A3 / `Preliminaries.md` §2.3); its losslessness half is unconditional.

The end-to-end composite read is sound under `A_daemon` because: SR-1 certifies the root (A1+A2) → MT-4 makes a passing proof prove membership of `key_bytes` (A2) → SP-CK-3 makes the verdict independent of daemon-side reconstruction → RI-1..RI-5 (for `i:`) interpret the membership verdict soundly. SP-CK-1/SP-CK-2 secure the honest-daemon path and the malformed-input boundary that the cryptographic theorems do not address.

---

## 6. Known limitations and findings

- **F-1 (reconstruction-equality is implementation-pinned, not type-enforced).** SP-CK-1 holds because two *separate* code sites (`build_state_leaves` and `rpc_state_proof`) hand-roll the same big-endian packings. There is no shared helper forcing them to agree; a future edit to one without the other would break the equality silently for an honest daemon (caught only by the end-to-end test, not the compiler). Mitigation: the regression tripwire of §4.1 + the `tools/test_light_verify_receipt_inclusion.sh` real-INCLUDED assertion. A structural fix (a single `compose_composite_key(ns, …)` helper shared by both sites) is a clean refactor tracked as a code-quality item, not a security gap (SP-CK-3 means even a drifted reconstruction cannot fool an honest verifier).
- **F-2 (width-check is necessary-and-sufficient only modulo namespace disjointness).** SP-CK-2's no-aliasing conclusion leans on `S033StateRootNamespaceCoverage.md` T-2 (byte-0 namespace disjointness). If a future namespace were added with a colliding prefix byte, a correct-length body could in principle address two namespaces; T-2 must remain an invariant. No such collision exists in the 10-namespace set.
- **F-3 (one-sided / membership-only).** A composite query for an absent entry returns `not_found`, indistinguishable from a withholding daemon — the same `MerkleTreeSoundness.md` MT-5 boundary `ReceiptInclusionProofSoundness.md` RI-3 records. The composite extension does not change this; non-membership remains non-attestable under the sorted-leaves primitive.
- **F-4 (head-only `state_root`).** `rpc_state_proof` returns `compute_state_root()` + `height()` at the *current* head (`node.cpp:3375–3376`); per-height historical proofs are the head-only-RPC constraint `AccountHistorySoundness.md` §6.4 documents. Orthogonal to reconstruction.

---

## 7. Summary

The `i:`/`m:`/`p:` extension of `state_proof` adds a hex-encoded binary-body path to a previously ASCII-only RPC. This document proves the three obligations that path creates: **SP-CK-1** — the daemon rebuilds the canonical leaf key byte-for-byte identically to `build_state_leaves`, so a served proof targets the intended leaf; **SP-CK-2** — the exact-width length-check (40/4/12 B) rejects every malformed body before key construction, with a structured diagnostic and no aliasing or memory-safety hazard; **SP-CK-3** — soundness is sourcing-independent because the verifier re-derives the leaf hash from `key_bytes` and gates on the committee-signed root, making the daemon's reconstruction a convenience rather than a trust assumption (R-cli is strictly stronger and is the default). The transport lemma **SP-CK-T** establishes that hex encoding is *necessary* (raw SHA-256 bytes break `json::dump()`'s UTF-8 contract) and *lossless* (`from_hex ∘ to_hex = id`). SP-CK-1/SP-CK-2 are unconditional; SP-CK-3 reduces to **A2** exactly as the simple-key reads do — the composite extension adds no new cryptographic assumption. The result composes underneath `StateRootAnchorSoundness.md` SR-1 and `MerkleTreeSoundness.md` MT-4 and feeds `ReceiptInclusionProofSoundness.md` RI-1..RI-5, completing the daemon-side half of the composite-key light-client read.
