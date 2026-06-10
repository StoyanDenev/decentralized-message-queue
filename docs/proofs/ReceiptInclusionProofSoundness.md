# ReceiptInclusionProofSoundness — trust-minimized `i:`-namespace cross-shard receipt-inclusion soundness (`determ-light verify-receipt-inclusion`)

This document formalizes the soundness of a **trust-minimized cross-shard receipt-inclusion read** by the light client: the `determ-light verify-receipt-inclusion --src-shard <S> --tx-hash <H>` command (sibling I3, parallel this round), which lets an operator learn whether a cross-shard receipt for source transaction `H` originating on shard `S` has been **applied** (credited) on the chain it is querying — verified locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client believe a receipt was applied when it was not. The read targets the `i:` (applied-inbound-receipts) namespace of the S-033 state-commitment surface.

The proof exists because the `i:` namespace is **structurally different** from the `a:` (balance) and `s:` (stake) namespaces the existing trustless reads cover, in two ways that matter for soundness:

1. **The receipt's identity lives entirely in the Merkle *key*, not the value.** From `Chain::build_state_leaves` (`src/chain/chain.cpp:331-341`), an `i:` leaf has key `"i:" + src_shard_be8 + tx_hash(32)` and a **constant value-hash** `SHA256(0x01)` — a single-byte *presence marker*. There is no `(locked, unlock_height)`-style cleartext pair to cross-check (contrast `StakeProofSoundness.md` SP-2's value-hash decode); the *only* semantic is *present (applied) vs. absent (not applied)*. So the binding from "committee-signed root" to "this specific (src_shard, tx_hash) receipt was applied" runs through the **leaf-key** domain separation (`MerkleTreeSoundness.md` MT-2), not through a value-hash content decode.

2. **The `i:` namespace IS served by the generic `state_proof` RPC (R-ext, shipped).** `Node::rpc_state_proof` (`src/node/node.cpp` rpc_state_proof) now handles the composite-key namespaces `i|m|p` alongside the simple-key `a|s|r|d|b|k|c`. The sourcing route chosen is **R-ext** (extend the daemon RPC), with a binary-safe transport twist: because the composite key suffix is raw bytes (a SHA-256 `tx_hash` almost always breaks UTF-8 `json::dump()`), the caller hex-encodes the post-prefix body and the daemon hex-decodes it, length-checks it (`i` = 40B `src_be8‖tx_hash`, `m` = 4B, `p` = 12B), and prepends `"<ns>:"` to rebuild the canonical key byte-for-byte. So `verify-receipt-inclusion` reuses the `{{"namespace","i"},{"key", hex(src_be8‖tx_hash)}}` call shape, structurally mirroring how `stake-trustless` reuses `{{"namespace","s"},...}`. The cryptographic soundness (RI-1..RI-3) is independent of the sourcing route — the verifier still re-derives the leaf hash from the returned `key_bytes` and gates on root-equality (`light/verify.cpp:349-350`) — and §4.2.1's key + marker cross-check pins the proven leaf to the operator's `(src_shard, tx_hash)` regardless of how the daemon built it. (Historically I3 shipped fail-closed against a daemon that declined `i:`; that gap is now closed, and `tools/test_light_verify_receipt_inclusion.sh` asserts a *real* INCLUDED end-to-end via a 2-shard cross-shard flow.)

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a "receipt applied" verdict that is inconsistent with the genesis-pinned chain's committed `i:` leaf set. The proof mirrors the `s:` read (`StakeProofSoundness.md` SP-1/SP-2/SP-3) and the `tx_root` membership read (`TxInclusionProofSoundness.md` TI-1/TI-2), specialized to the `i:` namespace's presence-marker encoding.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1, **A4** = CSPRNG §2.3) — this proof reduces to **A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-2** leaf/inner domain separation, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core RI-2 consumes, and its **MT-5** non-membership boundary is exactly the limitation RI-3 honours, and its **§6.2 (S-040, CLOSED)** is the now-enforced root-wrapper `leaf_count` binding RI-4 records); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding RI-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding; the transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` mechanism — *not* a direct digest append — is reused verbatim); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `i:` key + `SHA256(0x01)` value-hash encoding read off `chain.cpp:331-341`, and **T-1** confirms `applied_inbound_receipts_` is committed to the root through `i:` and **T-2** namespace disjointness guarantees `"i:"+… ≠ "a:"+…` at byte 0); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the balance/nonce trustless-read flow this proof specializes to receipts — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** composite read with race-window mitigation, **L-6** fail-closed exit); `StakeProofSoundness.md` (the `s:` sibling — RI-1/RI-2/RI-4 are the `i:` analogs of SP-1/SP-2/SP-3, with the value-hash-decode step replaced by the presence-marker/key-binding argument); `TxInclusionProofSoundness.md` (the membership sibling — TI-2's `NOT-INCLUDED` honesty vs. RI-3's `not-applied` non-proof boundary differ precisely because `tx_root` membership is decided by full-set recompute while `i:` non-applied is a *non-membership* question the sorted-leaves tree cannot answer); `CrossShardReceipts.md` (FA7 — the apply-side guarantee, **T-7**, that an applied receipt corresponds to one and only one source debit, and **Corollary T-7.1** global supply atomicity; this proof is the verification-side read-back of FA7's `applied_inbound_receipts_` insertion); `CrossShardReceiptDedup.md` (the **T-R1**/**T-R2**/**T-R7** dedup semantics that fix what "applied" means for the `i:` leaf — first-application credits, duplicate-application silently skips, pre-application the entry does not exist); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 four-surface composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-038 + §S-040 + §S-016 for the closure / limitation narratives; `docs/PROTOCOL.md` §4.1.1 for the canonical `i:` Merkle-leaf row + §10.2 for the `state_proof` RPC contract.

---

## 1. Scope

### 1.1 In scope

The `determ-light verify-receipt-inclusion --src-shard <S> --tx-hash <H>` composite command (sibling I3), which answers a single question without trusting the daemon that serves the data:

> Has a cross-shard receipt for source transaction `H` (32-byte hash) originating on shard `S` been **applied** (credited) on the chain at the committee-verified height, or is its applied-status not cryptographically provable?

Its logical pipeline mirrors `read_account_trustless` (`light/trustless_read.cpp:439-599`) with the `i:` composite key:

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:55-82`). Compute `compute_genesis_hash(genesis_O)` locally, fetch block 0 from the daemon, byte-compare. (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:105-230`), invoking `verify_headers` (`light/verify.cpp:135-233`) per page and `verify_block_sigs` (`light/verify.cpp:235-328`) per block, end-to-end from block 0. (T-L2.) This yields a committee-anchored `state_root` (SR-1).
3. **State-proof fetch for the `i:` leaf** — the composite key `"i:" + src_be8(S) + H` is presented to the daemon's proof builder via the hex-encoded body (`{{"namespace","i"},{"key", hex(src_be8(S)‖H)}}`); `Node::rpc_state_proof` serves the `i:` namespace (R-ext, §1.4 item 2), hex-decodes the body, and rebuilds the composite key. The reply carries `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Merkle inclusion verify** — `verify_state_proof(proof, root)` (`light/verify.cpp:330-396`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`), with the verifier re-deriving the leaf hash from the supplied `key_bytes`. (T-L3 / RI-2.)
5. **Committee-binding of the proof root (S-042)** — the proof's claimed `state_root` is bound to a committee-signed header by `committee_bound_state_root` (`light/trustless_read.cpp:335-437`): a stale-height gate (`:528-533`) rejects a proof before the verified head, then `anchor_index = proof_height − 1` (`:545`) and the helper recomputes the full anchor block's `block_hash` and requires the committee-signed **successor**'s `prev_hash` to equal it (`:424-432`) — the anchor header's own digest excludes `state_root`, so signing it does not bind it; the head fails closed (no signed successor) unless `--wait` is supplied. (T-L4 §4.4.1 / RI-1 / `StateProofRaceWindowSoundness.md` PRW-1..PRW-5.)
6. **Presence-marker check** — confirm the verified leaf's `value_hash` equals the canonical presence marker `SHA256(0x01)` and the `key_bytes` equal the locally-recomputed `"i:" + src_be8(S) + H`. (RI-2 leaf-key binding + §4.2.1.)

The verdict:

| Verdict | Condition |
|---|---|
| `APPLIED` | steps 1–6 pass: the `i:` leaf for `(S, H)` is committed under the committee-signed `state_root`, with `value_hash == SHA256(0x01)` and `key_bytes == "i:"+src_be8(S)+H`. |
| `UNVERIFIABLE` | any of: genesis anchor fails (T-L1); header sig/continuity fails (T-L2); the recomputed-against-`R` `merkle_verify` rejects; the daemon returns `not_found`/`error` (the receipt is *not applied*, OR the daemon is withholding — **indistinguishable**, §4.3); a committee not in the seed map (§6.2 caveat); or any RPC/parse error. |

There is **no positive `NOT-APPLIED` verdict** — see §1.3 and RI-3. Non-application is *not* a cryptographically provable statement under the sorted-leaves primitive (`MerkleTreeSoundness.md` MT-5); a daemon withholding a genuine `i:` leaf is indistinguishable from a genuinely-absent leaf. `verify-receipt-inclusion` is therefore a **one-sided** verifier: it can prove `APPLIED` cryptographically, but the negative is always `UNVERIFIABLE`, never an authoritative `NOT-APPLIED`.

### 1.2 The `i:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:331-341`):

```cpp
// applied_inbound_receipts_  (key = "i:" + src_be8 + tx_hash)
for (auto& [src, tx_hash] : applied_inbound_receipts_) {
    std::vector<uint8_t> key;
    key.reserve(2 + 8 + 32);
    key.push_back('i'); key.push_back(':');
    for (int i = 7; i >= 0; --i) key.push_back((src >> (8*i)) & 0xff);   // src_shard, big-endian u64
    key.insert(key.end(), tx_hash.begin(), tx_hash.end());              // 32-byte source tx hash
    crypto::SHA256Builder b;
    uint8_t marker = 1; b.append(&marker, 1);                          // presence marker
    leaves.push_back({std::move(key), hash_bytes(b)});
}
```

so for an applied receipt `(S, H)`:

$$
\text{key}_i(S, H) \;=\; \texttt{"i:"} \,\|\, u64\_be(S) \,\|\, H_{32}, \qquad
\text{value\_hash}_i \;=\; H(\texttt{0x01}) \quad (\text{constant, identity-free}).
$$

The source container is `applied_inbound_receipts_ : std::set<std::pair<ShardId, Hash>>` (`include/determ/chain/chain.hpp:605`), inserted on first inbound-receipt admission at `chain.cpp:1373-1374` and queried by `Chain::inbound_receipt_applied` (`chain.cpp:204-207`: `applied_inbound_receipts_.count({src_shard, tx_hash}) > 0`). This is exactly the `i:` row of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 and `PROTOCOL.md` §4.1.1.

**The load-bearing structural fact (§4.2).** Because the value-hash is the *constant* `SHA256(0x01)` for **every** `i:` leaf, two distinct applied receipts `(S_1, H_1) ≠ (S_2, H_2)` have **identical value-hashes** but **distinct keys**. The Merkle leaf hash `merkle_leaf_hash(key, value_hash) = H(0x00 ‖ u32_be(|key|) ‖ key ‖ value_hash)` (`merkle.cpp:25-34`) therefore distinguishes them *entirely through the length-prefixed key* — the `value_hash` contributes the same 32 bytes to both preimages. This is why RI-2's soundness rests on `MerkleTreeSoundness.md` **MT-2** (leaf-key domain separation / unambiguous length-prefixed key encoding) rather than on a value-hash decode: a daemon cannot serve the leaf for `(S', H') ≠ (S, H)` and pass it off as `(S, H)`'s receipt, because the recomputed leaf hash incorporates `(S, H)`'s key, producing a different sibling chain and failing root-equality.

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-application of a receipt (the negative).** A light client *cannot* prove "receipt `(S, H)` has **not** been applied" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). A daemon withholding a genuinely-applied receipt is indistinguishable from a genuinely-not-applied receipt. This is the **same** boundary as `StakeProofSoundness.md` §6.1 (unstaked domains) and `TxInclusionProofSoundness.md` §6.3 (per-height membership), sharpened here by the presence-marker semantics: the `i:` leaf exists *iff* the receipt was applied (`CrossShardReceiptDedup.md` T-R7 pre-application non-existence), so absence-of-leaf is exactly non-application — but absence is not cryptographically attestable. RI-3 records this honestly; `verify-receipt-inclusion` never emits an authoritative `NOT-APPLIED`.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1–§6.7. Within one invocation the race-window mitigation (RI-1 / L-5) is sound; cross-invocation head-regression is operator-visible but not auto-detected.
- **The mutating side of receipts** (the inbound-receipt admission path, the `accumulated_inbound_` A1 counter, the FA7 source-debit-precedes-credit atomicity, the S-016 time-ordered admission, the cross-shard supply invariant). Those are apply-layer correctness (`CrossShardReceipts.md` FA7, `CrossShardReceiptDedup.md`, `S016InboundReceiptTimeOrdered.md`, `CrossShardSupplyConservation.md`); this proof reads the *committed* `i:` leaf and does not re-prove how it got there.
- **Which destination shard / which recipient / what amount.** The `i:` leaf is a bare presence marker keyed only by `(src_shard, src_tx_hash)`; it carries **no** amount, recipient, or destination-shard data in the value-hash (§1.2). `verify-receipt-inclusion` proves *"a receipt for this source tx was applied on this chain,"* not *"X coins were credited to Y."* An operator wanting the credited *amount* must additionally read the recipient's `a:` balance leaf (a separate `balance-trustless` call) and reason about it via FA7 / the source block's `tx_root` — out of scope here. §6.5 records this.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged receipt replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM), `A_genesis` (tampered pinned `genesis.json`).

Specialized to the receipt-inclusion question, `A_daemon` will attempt one of two deceptions:

- **(a) False-applied (phantom receipt).** Convince the verifier that receipt `(S, H)` *was applied* when it genuinely was not — e.g., to make an operator believe a cross-shard payment landed when it did not, so the operator releases goods or off-chain value.
- **(b) Suppressed-applied (withheld receipt).** Convince the verifier that receipt `(S, H)` is *not provably applied* when it genuinely was — e.g., to hide an on-chain credit from an auditor. Note this deception lands the verifier in `UNVERIFIABLE`, **not** in a false `NOT-APPLIED`: the verifier has no positive non-application proof to forge (§1.3 / RI-3). So (b) is an *availability/honesty* downgrade, never a *soundness* break.

**Security goal.** Under `A_daemon`, an honest light client running `verify-receipt-inclusion --src-shard S --tx-hash H`:

- never returns `APPLIED` for a receipt `(S, H)` not genuinely committed in the `i:` leaf set of the genesis-pinned chain at the verified height;
- never acts on a substituted leaf — any leaf whose recomputed Merkle path does not roll up to the committee-signed `state_root`, or whose `key_bytes`/`value_hash` do not match the canonical `i:` encoding for `(S, H)`, yields `UNVERIFIABLE`, never a verdict.

"Acts on" means *displays as authoritative* or *feeds into a downstream decision* (e.g., releasing off-chain value on belief a cross-shard credit settled). The negation form is **fail-closed exit**: any detected inconsistency throws and propagates to a non-zero process exit with a structured stderr diagnostic (inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

`verify-receipt-inclusion` reuses the four light-client primitives unchanged — genesis anchor (`LightClientThreatModel.md` §3.1), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies with the state-proof stage targeting the composite key `key_i(S, H)`. Two specializations distinguish this read from the `a:`/`s:` reads:

1. **Composite-key construction (R-ext sourcing, shipped).** The `i:` key is not an ASCII `domain` string but the 42-byte composite `"i:" + u64_be(S) + H`. `Node::rpc_state_proof` now serves the `i:` namespace: the `{{"namespace","i"},{"key", hex(u64_be(S)‖H)}}` call returns the proof, with the binary body hex-encoded for JSON transport and the daemon hex-decoding + length-checking + prefixing it (§1.4 item 2). The `m:`/`p:` namespaces are served identically.

2. **Presence-marker value-hash.** Unlike the `s:` read's `(locked, unlock_height)` cleartext cross-check (`StakeProofSoundness.md` SP-2), there is no value-hash decode — the value-hash is the constant `SHA256(0x01)`. The binding to the specific `(S, H)` receipt is carried by the **leaf key** (RI-2 / MT-2), and the verifier additionally checks that the served `value_hash` *equals* the canonical marker (§4.2.1), so a daemon cannot smuggle a non-`i:` leaf with arbitrary value-hash through as a receipt.

Crucially, whichever sourcing of §1.4 is used, the daemon delivers `state_root`, `leaf_count`, `target_index`, `value_hash`, the sibling vector, and `key_bytes` such that the light client verifies the proof's `state_root` against a committee-signed header in the *same* invocation (the S-042 committee-binding, `committee_bound_state_root`, `light/trustless_read.cpp:335-437`). The `leaf_count` is bound into the committed root (S-040 CLOSED — root-wrapper hash; RI-4 §4.4), so a forged count is rejected regardless of source.

### 1.4 The two admissible proof sourcings (and why both are sound)

Because the daemon's generic `state_proof` RPC does not cover `i:`, sibling I3 must obtain the `i:`-leaf proof by one of:

- **(R-ext) Daemon-side RPC extension.** Extend `Node::rpc_state_proof` (or add a dedicated `receipt_proof` RPC) to accept `(src_shard, tx_hash)`, build the composite key `"i:" + u64_be(src) + tx_hash` exactly as `build_state_leaves` does (`chain.cpp:331-341`), call `chain_.state_proof(key)`, and return the same `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)` envelope. The verifier path is then byte-identical to the `s:` read.

- **(R-cli) Client-side key construction.** The light client builds `key_i(S, H) = "i:" + u64_be(S) + H` *locally* (a 42-byte deterministic concatenation, no daemon input), and supplies it as the `key_bytes` field of the proof the verifier consumes (`verify.cpp:349-350` reads `key_bytes` directly via `from_hex`; `merkle_verify` re-derives the leaf hash from it at `verify.cpp:378-380`). Under (R-cli) the daemon still must return the matching `target_index`, `leaf_count`, sibling vector, and `state_root`; if it serves a proof for a *different* leaf, the verifier's recomputed leaf hash (from the *client-built* `key_bytes`) will not roll up to the committee-signed root and the proof is rejected (RI-2).

**Soundness is identical under both.** RI-2 (§4.2) re-derives the leaf hash from `key_bytes` and gates on root-equality against the committee-anchored `R` regardless of *how* `key_bytes` was produced. The decisive trust property — *the verifier checks `key_bytes` against the canonical `key_i(S, H)` it can recompute from its own `(S, H)` inputs* (§4.2.1) — means a daemon cannot make the verifier accept a proof for the wrong key. (R-cli) is in fact *strictly stronger* on key-integrity, because the key never originates from the daemon at all; it is the recommended sourcing and is what §7 cites as the default. Neither sourcing carries any residual `leaf_count` obligation: S-040 is closed — `leaf_count` is bound into the committed root (root-wrapper hash; RI-4 §4.4), so a forged count is rejected whatever the source.

---

## 4. Security theorems

Throughout, let `(S, H)` be the queried `(src_shard, tx_hash)`, `R := state_root(h)` the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to, and write `key_i(S, H) = "i:" ‖ u64\_be(S) ‖ H` and `vmark := H(\texttt{0x01})` (the constant presence marker, identical for every `i:` leaf). Let `L_i(S,H) := \text{merkle\_leaf\_hash}(key_i(S,H), vmark)` be the genuine `i:` leaf hash. The chain's *true* applied-receipt set at height `h` is `\mathcal{I}_T(h) \subseteq \{\,(s, t)\,\}`; `(S, H)` is genuinely applied iff `(S, H) \in \mathcal{I}_T(h)`, which holds iff `key_i(S,H)` is a leaf of the tree `R` commits to (`CrossShardReceiptDedup.md` T-R7: the entry exists iff the receipt was applied).

### 4.1 Theorem RI-1 (committee-signed `state_root` binds the `i:` leaf)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that `verify-receipt-inclusion` anchors and verifies the `i:` proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root the `i:` leaf is checked against is *committee-certified*, not daemon-asserted.

**Proof.** This is `StateRootAnchorSoundness.md` **SR-1** applied at the height the `i:` proof is anchored at, identical to `StakeProofSoundness.md` SP-1 and `LightClientThreatModel.md` T-L4's inline anchoring at the committee-signed successor inside `committee_bound_state_root` (`trustless_read.cpp:409-415`). The binding of `state_root(h)` to the committee is **transitive-forward**, not a direct signature: the committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp:608-693`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root` (the `light/verify.cpp:40-56` exclusion comment). `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim, `block.cpp:336-350`) and hence into `block_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`:

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

Suppose the invocation anchors `R_A ≠ state_root_T(h)`. The SR-1 case split (`StateRootAnchorSoundness.md` §4.1, reproduced for the `i:`-proof anchoring via the committee-signed successor inside `committee_bound_state_root`, `trustless_read.cpp:409-432`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`** (so the `h → h+1` prev_hash link still closes against the committee-signed `digest(h+1)`). The genuine `block_hash_T(h) = SHA256(signing_bytes_T(h) ‖ sigs)` with `signing_bytes_T(h)` containing `state_root_T(h)`. The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).

- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. But the light client committee-verifies `h+1`'s signatures over `digest(h+1)` against `K_0` (`verify_block_sigs` on the successor header inside `committee_bound_state_root`, `trustless_read.cpp:409-415`). The genuine committee signed `digest(h+1)` containing `prev_hash(h+1) = block_hash_T(h)`. To accept `h+1` with a different `prev_hash`, the daemon must present `required` valid signatures over a different digest — an Ed25519 forgery for each of `required ≤ K` distinct committee members, `≤ K · 2⁻¹²⁸` (A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* (that `R` is the root of the operator's pinned chain at `h` specifically, not a fork's or another height's) is supplied by SR-2 + SR-3 + T-L1's genesis anchor; RI-1 inherits them.

**Head-block boundary.** If the operator queries a receipt at the chain *head*, that block's `state_root` has no signed successor yet, so it is committee-certified only once a successor is produced. The shipped flow handles this via S-042's fail-closed head case: `committee_bound_state_root` requires a committee-signed successor header to bind the anchor's `block_hash`, so a head-index anchor (no successor) throws and yields `UNVERIFIABLE` (`trustless_read.cpp:388-401`) unless `--wait` is supplied to poll for the next block (`StateProofRaceWindowSoundness.md` PRW-1..PRW-5). Full nodes enforce the head's root meanwhile via the apply-layer S-033 gate (`StateRootAnchorSoundness.md` §3.4 + §6.3). RI-2 below proves Merkle-path soundness *given* such an `R`; RI-1 is the committee-binding of `R`.

**Concrete-security bound.** `Pr[A_daemon wins RI-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem RI-2 (Merkle state-proof for the `i:` presence-marker leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from RI-1, a verifier holding `R` cannot be made to accept `APPLIED` for a receipt `(S, H)` whose `i:` leaf `key_i(S, H)` is **not** committed under `R`, without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; key_i(S,H),\; vmark,\; target\_index,\; n,\; proof) = \texttt{true}
\quad\wedge\quad value\_hash_{\text{served}} = vmark,
$$

then either (a) `key_i(S, H)` is a genuine leaf of the tree `R` commits to at sorted position `target_index` — i.e., `(S, H) \in \mathcal{I}_T(h)` is genuinely applied — or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves the receipt is applied, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as RI-1: the light client has anchored committee-signed `R` for the `i:` proof.
2. `A_daemon` returns a state-proof `P_A = (key_bytes_A, value\_hash_A, target\_index, n, proof)` claiming receipt `(S, H)` is applied when it is not — i.e., `key_i(S, H) \notin` the committed leaf set. It may (i) serve a genuine `i:` leaf for some *other* applied receipt `(S', H') ≠ (S, H)` and relabel it, (ii) serve a non-`i:` leaf (e.g. an `a:` leaf) with a forged `key_bytes`, (iii) serve `value\_hash_A ≠ vmark`, or (iv) alter `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true` **and** the verdict is `APPLIED`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the `i:` leaf, equivalently `LightClientThreatModel.md` T-L3 specialized to the receipts namespace, plus the **MT-2** leaf-key domain separation that the presence-marker encoding makes load-bearing. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value\_hash_A, target\_index, n, sibs)` (`light/verify.cpp:378-380`), which recomputes the leaf hash

$$
c_0 = \text{merkle\_leaf\_hash}(key_bytes, value\_hash_A) = H(\texttt{0x00} \| u32\_be(|key_bytes|) \| key_bytes \| value\_hash_A)
$$

and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R` (`merkle.cpp:139`).

The verifier additionally requires `key_bytes = key_i(S, H)` (the locally-recomputed canonical key, §4.2.1) **and** `value\_hash_A = vmark`. With those two equalities pinned, the recomputed `c_0 = L_i(S, H)` is *exactly* the genuine `i:` leaf hash for `(S, H)`. By MT-4's extraction: if `L_i(S, H)` is **not** a leaf of the tree `R` commits to, then the recomputed chain and the genuine root-path chain for sorted position `target_index` both terminate at `R` but disagree at the leaf; walking top-down, there is a highest level where the chains agree but the level below disagrees, at which two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` map to the same `H` output — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** does all the work specific to the `i:` namespace, defeating the four attack shapes:

- **(i) relabel another receipt's leaf.** The daemon serves the genuine leaf for `(S', H')` (so `value_hash = vmark` matches) but the verifier's recomputed `c_0` uses `key_i(S, H) ≠ key_i(S', H')` (distinct keys, since `(S, H) ≠ (S', H')` ⇒ the length-prefixed key bytes differ in the `u64_be(S)` or `H_{32}` region). The recomputed leaf hash is `L_i(S, H) ≠ L_i(S', H')`, so it composes the served siblings into a *different* chain and fails root-equality against `R`. By MT-2's unambiguous length-prefixed key encoding (`MerkleTreeSoundness.md` §2.1), a pass requires a leaf-level collision (`≤ 2⁻¹²⁸`).

- **(ii) cross-namespace swap.** The daemon serves an `a:`/`s:`/`b:`/… leaf's siblings and a forged `key_bytes`. The verifier recomputes the leaf hash over the canonical `key_i(S, H) = "i:" + …`, which begins with the `i:` prefix; by `S033StateRootNamespaceCoverage.md` **T-2** namespace disjointness, `"i:"+… ≠ "a:"+…` at byte 0, so the recomputed leaf hash differs from any non-`i:` leaf's hash, producing a different sibling chain and failing root-equality. This is the same cross-namespace-swap rejection `StakeProofSoundness.md` SP-2 invokes (the `test_state_proof_namespaces.sh` swap assertions), here protecting against passing a balance/stake leaf off as a receipt.

- **(iii) wrong value-hash.** The verifier rejects `value\_hash_A ≠ vmark` at the §4.2.1 marker check before honoring `APPLIED`. Even absent that explicit check, a `value\_hash_A ≠ vmark` changes `c_0` and (generically) fails root-equality; the explicit check makes the rejection crisp and prevents a daemon from binding a *different* (non-presence) semantic to the leaf.

- **(iv) index / sibling tamper.** Covered by MT-4's range/underflow/exact-consume gates exactly as in SP-2 (`MerkleTreeSoundness.md` §2.6 scenarios #5-#8; `determ test-merkle-proof-tampering`).

By `S033StateRootNamespaceCoverage.md` **T-1**, the `applied_inbound_receipts_` field is in fact bound to the root through the `i:` namespace, so the leaf RI-2 verifies is the genuine committed receipt-application state.

**No cleartext cross-check (contrast SP-2 / TI-1).** The `s:` read (SP-2) offers an optional `(locked, unlock_height)` cleartext cross-check against the value-hash; the `tx_root` read (TI-1) binds the tx *content* via the tx hash. The `i:` read has **no such content** to cross-check — the value-hash is the constant `SHA256(0x01)` and the receipt carries no amount/recipient in the leaf (§1.3). The verified statement is purely *"`(S, H)` was applied"*; there is no per-receipt cleartext for the verifier to bind. This is not a weakness — it is the honest semantic boundary of a presence-marker leaf. An operator wanting the *amount* credited must read the recipient's `a:` balance separately (§6.5).

**Concrete-security bound.** `Pr[A_daemon wins RI-2] ≤ log₂(n) · 2⁻¹²⁸`; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`.   ∎

#### 4.2.1 The marker + key cross-check (why `APPLIED` is crisp)

Two equalities, both computable by the verifier with **no daemon input**, convert "a Merkle proof verified against `R`" into "the specific receipt `(S, H)` is applied":

1. **Key equality.** `key_bytes == key_i(S, H)`, where `key_i(S, H) = "i:" + u64_be(S) + H` is built locally from the operator's `--src-shard S --tx-hash H` arguments. Under sourcing (R-cli) the verifier *is* the source of `key_bytes`, so this is trivially satisfied; under (R-ext) the verifier re-derives `key_i(S, H)` and byte-compares against the daemon-returned `key_bytes`, rejecting any mismatch. Either way the proven leaf is pinned to *this* `(S, H)`.

2. **Marker equality.** `value_hash == SHA256(0x01) = vmark`. This confirms the leaf is a genuine `i:` *presence* leaf and not some other leaf the daemon coerced the key onto. (Belt-and-suspenders: combined with the byte-0 `i:` prefix in (1) and MT-2 domain separation, a non-`i:` leaf cannot pass; the marker check additionally rules out a hypothetical future `i:`-prefixed leaf with a non-marker value.)

With (1)+(2) pinned and RI-2's root-equality, `APPLIED` means exactly *"the leaf `(key_i(S,H), SHA256(0x01))` is committed under the committee-signed `R`,"* which by `CrossShardReceiptDedup.md` T-R7 (entry-exists-iff-applied) means the receipt was applied. The verifier emits `APPLIED` only on this conjunction; any failure of (1), (2), RI-1, or RI-2 yields `UNVERIFIABLE` (fail-closed, RI-5).

### 4.3 Theorem RI-3 (one-sided verifier; sound non-application is NOT provable — honesty boundary)

**Statement.** `verify-receipt-inclusion` is a **one-sided** verifier: it can establish `APPLIED` cryptographically (RI-1 + RI-2), but it **cannot** establish an authoritative `NOT-APPLIED`. A daemon that returns `not_found`/`error` for `(S, H)` — or otherwise withholds the `i:` leaf — leaves the verifier in `UNVERIFIABLE`, which is *indistinguishable* between "the receipt is genuinely not applied" and "the daemon is suppressing a genuinely-applied receipt." No false `NOT-APPLIED` is ever emitted, because none exists to emit.

**Analysis.** The sorted-leaves balanced binary Merkle primitive supports **positive membership only** (`MerkleTreeSoundness.md` **MT-5**): there is no native non-membership (absence) proof. A true non-application proof would require the prover to exhibit the two committed leaves *adjacent* to `key_i(S, H)` in sort order, *together with* inclusion proofs for both and a guarantee that nothing sorts between them — a capability the shipped `merkle_proof` / `merkle_verify` pair does not provide (it proves one leaf at a caller-asserted sorted index, never adjacency). `Chain::state_proof` returns `std::nullopt` for an absent key (`chain.cpp:449`), surfaced by the daemon as `{"error":"not_found"}` (`node.cpp:3318` under R-ext, or the verifier's own absent-leaf handling under R-cli). An honest light client receiving this can only conclude *"this daemon did not give me a proof,"* which an all-Byzantine peer set could produce by withholding. This is the **same** MT-5 boundary `StakeProofSoundness.md` §6.1 (unstaked domain → `not_found`) and `TxInclusionProofSoundness.md` §6.3 (per-height membership, no chain-wide absence) honour, inherited unchanged.

**Why the asymmetry is fundamental here.** For the `i:` namespace the asymmetry is especially sharp because *the leaf exists iff the receipt was applied* (`CrossShardReceiptDedup.md` **T-R7** pre-receipt-application non-existence: before application the `(src, tx_hash)` entry is genuinely absent from `applied_inbound_receipts_`). So "leaf absent" semantically *is* "not applied" — yet "leaf absent" is exactly the statement the primitive cannot attest. The gap is not in the chain's bookkeeping (which is exact) but in the *proof system's* inability to prove absence. `verify-receipt-inclusion` therefore reports `UNVERIFIABLE` for the negative and lets the operator fall back to a multi-peer cross-check or the daemon's direct (trusted) RPC, with the attendant trust cost.

**Consequence for the threat model.** Attack §2.1(b) (suppressed-applied) cannot produce a *false* answer — it produces `UNVERIFIABLE`, which is operator-visible and actionable (switch daemons / cross-check peers, §6.1). The operator learns *"this daemon would not prove the receipt applied,"* never a misleading *"the receipt was not applied."* The soundness goal (§2) — never a false `APPLIED`, never act on a substituted leaf — is fully met; the *completeness* gap (a withholding daemon forces `UNVERIFIABLE`) is an availability limitation, not a soundness one.   ∎

### 4.4 Theorem RI-4 (`leaf_count` is bound into the committed root — S-040 CLOSED)

**Statement.** RI-2's soundness is stated with `n` = the *genuine* leaf count of the tree `R` commits to. **S-040 is closed:** `leaf_count` is now cryptographically bound into the committed root via the root-wrapper hash, so a forged `leaf_count` is rejected and `n` cannot be decoupled from `R`. The former caller-trust obligation — source `leaf_count` from the same committee-anchored origin as `state_root` — is now **enforced by the hash, not a caller guideline**. The shipped flow inherits this directly: under sourcing (R-ext), `state_root` and `leaf_count` arrive in one `rpc_state_proof`-shaped reply, but soundness no longer depends on that co-sourcing — even a `leaf_count` supplied from any other channel is rejected if it does not match the count bound into `R`.

**The closure.** `crypto::merkle_root` wraps the inner Merkle root with the leaf count: `root = SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`merkle.cpp::merkle_root_wrap`), where `0x02` is domain-separated from the `0x00` leaf-hash and `0x01` inner-hash prefixes. `merkle_verify` re-derives the *inner* root from the supplied siblings exactly as before, then re-applies the wrapper with the **caller-supplied** `leaf_count` and compares the result to the committed `R` (`merkle.cpp:113-141`). A forged `leaf_count = M ≠ N` (the genuine count) therefore produces `SHA256(0x02 ‖ be_u32(M) ‖ inner_root) ≠ R` and is **rejected** — the exact inversion pinned by `determ test-merkle-proof-tampering` scenario #12 (now asserting a forged `leaf_count` is REJECTED). The light client inherits the wrapper because `light/verify.cpp`'s `verify_state_proof` delegates to `crypto::merkle_verify` (`verify.cpp:378-380`).

**Why the former split-source attack is now cryptographically dead.** Pre-closure, `merkle_verify` consumed `leaf_count` only to drive the level count and per-level duplication parity (it was not an input to any hash), so two `(target_index, leaf_count)` pairs yielding the same walk shape verified identically. The wrapper closes exactly that gap: `leaf_count` is now a hashed input to the committed root, so a wrong `leaf_count` — whether co-sourced or split-sourced, consistent walk shape or not — changes the wrapper preimage and fails root-equality against `R`. In `verify-receipt-inclusion`:

1. The proof envelope returns `state_root`, `leaf_count`, `target_index`, `value_hash`, and `proof` as fields of **one** JSON object, with `leaf_count = build_state_leaves().size()` (`chain.cpp:456`) — the genuine count for the very tree whose wrapped root is `compute_state_root()` in the same reply.
2. The light client anchors *that reply's* `state_root` to a committee-signed header (RI-1) in the same invocation, then verifies the `i:` proof against the anchored root, the wrapper re-binding the reply's `leaf_count` to `R` (`verify.cpp:363-380`). A tampered `state_root` fails RI-1's committee anchoring; a tampered `leaf_count` fails the wrapper re-derivation against the genuine `R`. Either deception yields `UNVERIFIABLE`, never a false `APPLIED`.

**Status.** S-040 is **closed** (shipped pre-launch as a wire-compat break — every `state_root` value changed, no installed base). There is no residual caller obligation, no integrator guideline, and no flag-day pending; the leaf-count binding is part of the committed root (`MerkleTreeSoundness.md` §6.2; `docs/SECURITY.md` §S-040). RI-2's core soundness was always stated with the genuine `leaf_count` and is unchanged; RI-4 now records that the genuine `leaf_count` is the only one that verifies.

**Concrete-security bound.** RI-4 adds no independent term beyond RI-1 + RI-2: a forged `leaf_count` reduces to a SHA-256 collision on the wrapper preimage (`≤ 2⁻¹²⁸`, already subsumed by RI-2's `log₂(n)·2⁻¹²⁸` root-equality term).   ∎

### 4.5 Lemma RI-5 (fail-closed exit)

**Statement.** Any signature failure, chain break, genesis mismatch, malformed proof, `not_found`/`error` reply, `key_bytes ≠ key_i(S, H)`, `value_hash ≠ vmark`, or `merkle_verify` rejection causes `verify-receipt-inclusion` to exit non-zero with a structured diagnostic (verdict `UNVERIFIABLE`) — never a bare daemon-asserted `APPLIED`.

**Proof.** By inheritance from `LightClientThreatModel.md` Lemma **L-6** for the reused T-L1/T-L2/T-L3 surfaces (`verify_headers`, `verify_block_sigs`, `verify_state_proof` each set `r.ok=false` + `r.detail` on every error branch and return to a caller that throws; `anchor_genesis` throws on genesis mismatch at `trustless_read.cpp:75-79`), plus the §4.2.1 structural property that `APPLIED` is reached *only* on the conjunction (RI-1 anchored ∧ RI-2 root-equality ∧ key-equality ∧ marker-equality). The `not_found`/`error` reply is caught at `verify_state_proof`'s error branch (`verify.cpp:334-336`: *"RPC error in proof"*) → `UNVERIFIABLE`. There is no code path from a detected inconsistency to `APPLIED`. This is the per-command instance of L-6; the throw-discipline is structural.   □

### 4.6 End-to-end composition

**Corollary RI-E (trust-minimized receipt-inclusion read).** Under A1 + A2, `verify-receipt-inclusion --src-shard S --tx-hash H` yields an `APPLIED` verdict bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis (or a fail-closed `UNVERIFIABLE`). Composing RI-1 (committee-anchored root) + RI-2 (`i:` Merkle inclusion + key/marker binding) + RI-4 (`leaf_count` bound into the committed root — S-040 CLOSED) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline (the per-step independent bounds of `LightClientThreatModel.md` T-L4):

$$
\Pr[A_{\text{daemon}} \text{ wins RI-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4 and the stake-read bound of `StakeProofSoundness.md` SP-E exactly, as expected: the `i:` and `a:`/`s:` reads differ only in the key construction and the leaf encoding, both of which are namespace-agnostic in every cryptographic step. RI-E covers the *positive* (`APPLIED`) verdict only; the negative is always `UNVERIFIABLE` per RI-3.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

RI-2 *is* MT-4 applied at the `i:` leaf, with **MT-2** (leaf/inner + key domain separation) carrying the load that a value-hash decode carries in the `s:` read — because the `i:` value-hash is the identity-free constant `SHA256(0x01)`, the binding to `(S, H)` lives in the length-prefixed key, and MT-2's unambiguous key encoding is what stops a daemon relabeling another receipt's leaf or swapping a cross-namespace leaf. MT-1 (determinism) guarantees the `i:` leaf's position and the root are reproducible across honest nodes; MT-3 (collision-resistance inheritance) makes any wrong committed receipt-set produce a different root. RI-3 is the `i:`-specific statement of MT-5's positive-only boundary; RI-4 is the `verify-receipt-inclusion`-specific statement of MT-4's §6.2 (S-040, CLOSED) — the now-enforced root-wrapper `leaf_count` binding.

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

RI-1 *is* SR-1 applied at the height the `i:` proof is anchored at, plus SR-2 (genesis-binding, no floating header) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism (read carefully: `state_root` is **not** in `compute_block_digest`, contrary to a naive reading; it is in `signing_bytes`/`block_hash` and committee-bound *transitively forward* via the successor block's signed digest); RI-1 names the `i:` read as a consumer of it, exactly as `LightClientThreatModel.md` T-L4 does for the `a:` read at the committee-signed successor inside `committee_bound_state_root` (`trustless_read.cpp:409-415`).

### 5.3 `S033StateRootNamespaceCoverage.md` — the namespace surface

**T-1** (coverage completeness) confirms `applied_inbound_receipts_` is committed to the root through the `i:` namespace (and through *no other*, by **T-2** disjointness), so the leaf RI-2 verifies is the genuine committed receipt-application state. §2.1's table fixes the byte-exact `i:` key (`"i:" + src_shard_be8 + tx_hash(32)`) + value-hash (`SHA256(0x01)`) encoding this proof reads off `chain.cpp:331-341`. T-3 (deterministic leaf ordering) — for the `i:` namespace specifically, the `std::set<std::pair<ShardId, Hash>>` iterates in lexicographic order (first by `ShardId u32`, then by `Hash` byte-array, per `S033StateRootNamespaceCoverage.md` §iteration-order) — + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes, so the committee that signed `digest(h+1)` signed over a `block_hash(h)` derived from the canonical `i:` leaf set.

### 5.4 `LightClientThreatModel.md` — the adversary model and read flow

This proof specializes T-L3 (state-proof correctness) + T-L4 (composite read with race-window mitigation) from the `a:` namespace to `i:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6 / RI-5), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. RI-E's bound equals T-L4's bound. The light client's `read_account_trustless` (`trustless_read.cpp:439-599`) is the structural template I3's `verify-receipt-inclusion` follows, with the `a:`-key construction replaced by the composite `i:`-key of §1.4, now served by the R-ext RPC extension (§6.4).

### 5.5 `CrossShardReceipts.md` (FA7) + `CrossShardReceiptDedup.md` — the apply-side dual

FA7 **T-7** establishes the production-side guarantee: every applied receipt corresponds to one and only one source debit (no double-credit, no fabrication), and the `applied_inbound_receipts_` insertion at `chain.cpp:1373-1374` is the one-time record of that credit. `CrossShardReceiptDedup.md` **T-R1** (first-application credits) / **T-R2** (duplicate silently skips) / **T-R7** (pre-application non-existence) fix the precise semantics of the `i:` leaf: it exists iff the receipt was applied exactly once. `verify-receipt-inclusion` is the **read-back** of that record: FA7 + dedup say "an applied receipt is recorded in `applied_inbound_receipts_` exactly once," and RI-2 says "a holder of the committee-signed `state_root` can *confirm* that record trustlessly." The two are duals — FA7/dedup say "it was applied and recorded," RI-2 says "you can prove it was applied." (The global-supply atomicity Corollary T-7.1 is the accounting frame; this proof does not re-derive it, but an operator combining RI-2 over the `i:` leaf with `balance-trustless` over the recipient's `a:` leaf can read back both sides of a settled cross-shard transfer.)

### 5.6 `StakeProofSoundness.md` / `TxInclusionProofSoundness.md` — the sibling reads

RI-1/RI-2/RI-4 are the `i:` analogs of `StakeProofSoundness.md` SP-1/SP-2/SP-3 (the `s:` read), with the value-hash-decode step (SP-2's `(locked, unlock_height)` cleartext cross-check) replaced by the presence-marker + key-binding argument (RI-2 / §4.2.1), since the `i:` value-hash carries no per-receipt content. RI-3's one-sided / non-application boundary is the `i:` counterpart of `TxInclusionProofSoundness.md`'s membership honesty — but note the **structural difference**: `tx_root` membership (TI-1/TI-2) is decided by a *full-set recompute* of a flat hash, so `tx_root` supports a sound *non*-membership verdict (`NOT-INCLUDED`) by exhibiting the whole body; the `i:` leaf lives in a *sorted-leaves Merkle tree* with no full-set readback, so non-application is **not** provable (RI-3). This asymmetry — same "membership" framing, opposite non-membership capability — traces directly to the two commitments' different constructions (`tx_root` flat-hash-over-set vs. `state_root` sorted-leaves-Merkle), exactly as `TxInclusionProofSoundness.md` §4.5 contrasts.

### 5.7 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the `i:` proof anchors against an S-033-committed root. As with the balance/stake reads, the flow must fail-closed with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`trustless_read.cpp:458-464`) — a chain-level deployment prerequisite, not a light-client design choice. RI-1's interior regime is exactly the S-033-active regime.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Several are worth calling out for the receipt read specifically.

### 6.1 One-sided: no provable non-application (RI-3)

`verify-receipt-inclusion` can prove `APPLIED` but not `NOT-APPLIED`. A daemon returning `not_found` for a genuinely-applied receipt is indistinguishable from a genuinely-absent one (`MerkleTreeSoundness.md` MT-5). The negative is always `UNVERIFIABLE`. Multi-peer cross-check (out of scope) is the only mitigation against a withholding daemon. This is the same positive-only boundary `StakeProofSoundness.md` §6.1 and `TxInclusionProofSoundness.md` §6.3 inherit, sharpened by the presence-marker semantics (`CrossShardReceiptDedup.md` T-R7: leaf-exists-iff-applied).

### 6.2 Committee-rotation (genesis committee `K_0` only)

Like every other light-client verifier, `verify-receipt-inclusion` seeds its committee map from genesis `initial_creators` (`build_genesis_committee`, `trustless_read.cpp:46-53`) and requires every creator in the `0..h` walk to be in that map (`verify_block_sigs`, verify.cpp:268-273). On a chain with mid-chain REGISTER/DEREGISTER that rotated the committee, the walk **fails closed** at the first non-`K_0` signer → `UNVERIFIABLE` — a positive safety property, never a wrong verdict. This is the shared `K_0` caveat (`LightClientThreatModel.md` §6.5 + F-1, `StakeProofSoundness.md` §6.3, `StateRootAnchorSoundness.md` §6.2), inherited unchanged.

### 6.3 S-040 CLOSED — leaf_count bound into the committed root (RI-4)

S-040 is **closed**. `leaf_count` is now bound into the committed root via the root-wrapper hash `root = SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`merkle.cpp::merkle_root_wrap`; `0x02` domain-separated from `0x00` leaf / `0x01` inner). `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the caller-supplied `leaf_count`, and compares to the committed root, so a forged `leaf_count` (`M ≠ N`) yields a different wrapper hash and is **rejected** regardless of source. The former single-envelope-sourcing requirement is therefore enforced by the hash, not a caller guideline; there is no residual integrator obligation and no flag-day pending (shipped pre-launch as a wire-compat break — every `state_root` value changed, no installed base; `MerkleTreeSoundness.md` §6.2, `docs/SECURITY.md` §S-040).

### 6.4 `i:` namespace sourcing (R-ext, shipped — formerly a sourcing obligation)

`Node::rpc_state_proof` now **serves** the `i:` namespace (R-ext): the call shape is `{{"namespace","i"},{"key", hex(u64_be(S)‖H)}}`, the daemon hex-decodes the body, length-checks it (40B for `i:`), and prepends `"i:"` to rebuild the canonical key — reproducing `build_state_leaves` byte-for-byte (`m:`/`p:` served identically). The hex transport is forced by JSON: a raw `tx_hash` byte string breaks UTF-8 `json::dump()` (`light/rpc_client.cpp` call), so the binary body cannot ride a JSON string un-encoded — the historically-considered R-cli (raw `key_bytes` client-side) is *not* JSON-transportable for an `i:` body containing a SHA-256 hash, which is why R-ext (hex body, daemon-rebuilt key) is the shipped route. Soundness is sourcing-independent: RI-2 re-derives the leaf hash from the returned `key_bytes` and gates on root-equality, and §4.2.1's key + marker cross-check pins the proven leaf to the operator's `(S, H)` regardless of how the daemon built it — so a daemon that rebuilt the wrong key (or returned a different leaf) yields `UNVERIFIABLE`, never a false `APPLIED`. (Confirmed against the present tree: `rpc_state_proof` lists `a|s|r|d|b|k` then `c`, then an `i|m|p` branch that hex-decodes the composite body; the verifier `verify_state_proof` consumes `key_bytes` directly at `verify.cpp:349-350`.)

### 6.5 Presence-only semantics: no amount / recipient / dst-shard in the leaf

The `i:` leaf is a bare presence marker keyed by `(src_shard, src_tx_hash)`; its value-hash is the constant `SHA256(0x01)` (§1.2). `APPLIED` proves *"a receipt for this source tx was applied on this chain,"* **not** *"X coins were credited to recipient Y on destination shard Z."* The amount/recipient/dst-shard are not in the leaf and are not verified by this command. An operator needing the credited amount must additionally `balance-trustless`-read the recipient's `a:` leaf and reason via FA7 / the source block's `tx_root` (sibling `TxInclusionProofSoundness.md`). This is an intentional scope boundary of the presence-marker design, not a defect — and it is the cleanest honest framing of what a one-byte marker leaf can attest.

### 6.6 Per-chain, not cross-shard-global

The verdict is about the chain the light client is querying (the *destination* shard's applied-receipt set). It does not, by itself, attest the *source*-side debit on shard `S` (that requires a separate trust-minimized read against `S`'s chain — FA7 T-7's source half). `verify-receipt-inclusion` proves the destination credited; the global cross-shard supply atomicity (`CrossShardReceipts.md` Corollary T-7.1) composes the two sides but is out of scope for a single-chain light read.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem / step | Component | File:lines | Role |
|---|---|---|---|
| Pipeline (I3) | `verify-receipt-inclusion` subcommand | `light/verify_receipt_inclusion.cpp` / `.hpp`; `light/main.cpp::cmd_verify_receipt_inclusion` (sibling I3, parallel R41 — spec-level cite) | Anchor → header trust → `i:` proof → key/marker cross-check → APPLIED / UNVERIFIABLE. |
| RI-1 (T-L1) | `anchor_genesis` | `light/trustless_read.cpp:55-82` | Genesis-hash anchor (reused; `LightClientThreatModel.md` T-L1). |
| RI-1 (committee-anchor) | `committee_bound_state_root` (S-042) in the read flow | `light/trustless_read.cpp:335-437` | Bind the `i:` proof's `state_root` to a committee-signed header: recompute the anchor block_hash, require the committee-signed **successor**'s `prev_hash` to equal it (`:424-432`); head fails closed (no signed successor). |
| RI-1 (T-L2) | `verify_block_sigs` | `light/verify.cpp:235-328` | Per-block Ed25519 K-of-K committee-sig verify over `light_compute_block_digest`. |
| RI-1 (T-L2) | `verify_headers` | `light/verify.cpp:135-233` | prev_hash continuity walk from genesis (SR-2 genesis-binding). |
| RI-1 (binding) | `compute_block_digest` (excludes `state_root`) | `src/node/producer.cpp:608-693`; `light/verify.cpp:57-92` | The committee-signed digest; `state_root` absent → transitive-forward binding (SR-1). |
| RI-1 (binding) | `Block::signing_bytes` / `compute_hash` | `src/chain/block.cpp:336-364` | Binds `state_root` into `block_hash` when non-zero (S-033 shim). |
| RI-2 | `verify_state_proof` | `light/verify.cpp:330-396` | Parse proof JSON, delegate to `merkle_verify`; consumes `key_bytes` directly (`:349-350`); `--state-root` override. |
| RI-2 | `merkle_verify` | `src/crypto/merkle.cpp:113-141` | Recompute root from `i:` leaf + siblings; range/underflow/exact-consume gates. |
| RI-2 / §1.2 | `i:` leaf encoding | `src/chain/chain.cpp:331-341` | Key `"i:" + src_be8 + tx_hash(32)`; value-hash = `SHA256(0x01)` presence marker. |
| RI-2 / §4.2.1 | `merkle_leaf_hash` (length-prefixed key) | `src/crypto/merkle.cpp:25-34` | Leaf hash binds the composite key (MT-2 domain separation). |
| RI-3 (non-application) | `Chain::state_proof` nullopt + `inbound_receipt_applied` | `src/chain/chain.cpp:449`, `:204-207` | Absent key → `nullopt` (no non-membership proof, MT-5); `count{src,tx} > 0` is the apply predicate. |
| RI-4 | proof envelope (`state_root` + `leaf_count`) | `src/node/node.cpp:3325-3335`; `src/chain/chain.cpp:456` | Reply `(state_root, leaf_count)` from one locked state; `leaf_count` bound into the committed root (S-040 CLOSED — root-wrapper). |
| RI-4 (S-040 closure) | `crypto::merkle_root` wrapper + `merkle_verify` re-derivation | `src/crypto/merkle.cpp::merkle_root_wrap`; `src/crypto/merkle.cpp:113-141` | `root = SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)`; forged `leaf_count` → wrapper mismatch → REJECTED. |
| §6.4 (RPC sourcing) | `Node::rpc_state_proof` composite-namespace branch | `src/node/node.cpp` rpc_state_proof (`i\|m\|p` hex-decoded + length-checked) | `i:` served via R-ext (hex key body); soundness sourcing-independent (RI-2). |
| §5.5 (apply-side dual) | inbound-receipt admission + insert | `src/chain/chain.cpp:1358-1381` (insert `:1373-1374`) | FA7/T-R1 first-application credit; the record `i:` reads back. |
| RPC transport | `RpcClient::call` | `light/rpc_client.cpp` | Generic JSON-RPC the proof/header fetch rides on. |
| `state_proof` RPC dispatch | `src/rpc/rpc.cpp:235-238` | `method == "state_proof"` → `rpc_state_proof(namespace, key)`. |

**Tests** (the `i:` read shares the light-client + Merkle test surface; sibling I3 adds an end-to-end `verify-receipt-inclusion` script this round):

| Test | Coverage |
|---|---|
| `tools/test_light_verify_receipt_inclusion.sh` (I3, parallel — spec-level cite) | RI-2 (applied receipt → APPLIED), RI-3 (unapplied / withheld → UNVERIFIABLE, no false NOT-APPLIED), RI-2 attacks (relabeled / cross-namespace / wrong-marker leaf → UNVERIFIABLE), §6.2 committee caveat. |
| `tools/test_light_verify_state_proof.sh` | RI-2 core — happy path + tampered value_hash → FAIL + tampered sibling → FAIL + wrong state_root → FAIL. |
| `tools/test_state_proof_namespaces.sh` | RI-2 leaf-key binding — cross-namespace swap rejected (the MT-2 defense `i:` relies on). |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` (15 scenarios) | RI-2 tamper rejection; RI-4 / S-040 CLOSED — forged `leaf_count` REJECTED via root-wrapper binding (#12, inverted to assert rejection); key-binding (#14-#15). |
| `tools/test_state_root_namespaces.sh` | `i:`-namespace mutation-changes-root coverage (`S033StateRootNamespaceCoverage.md` T-1). |
| `tools/test_light_verify_block_sigs.sh` | RI-1 tripwire: a digest/light-digest divergence surfaces as a sig-verify failure on a real producer block. |

---

## 8. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** The `i:` namespace is already committed by `build_state_leaves` (`chain.cpp:331-341`) and its apply path / dedup are shipped (`chain.cpp:1358-1381`, `:204-207`). The `determ-light verify-receipt-inclusion` composite command is sibling I3 (parallel this round), structurally a `read_*_trustless` skeleton with the composite `i:`-key of §1.4. The generic `state_proof` RPC now serves `i:` via the R-ext extension (hex-encoded composite key body, daemon-rebuilt key; §6.4); soundness is sourcing-independent (RI-2). A real INCLUDED is exercised end-to-end by `tools/test_light_verify_receipt_inclusion.sh` (2-shard cross-shard flow).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2), A2 (SHA-256 collision / second-preimage resistance, §2.1). No A3/A4 dependence beyond what T-L1's genesis anchor already carries.
- **Adversary model.** `A_daemon` (malicious single daemon controlling RPC), reused from `LightClientThreatModel.md` §2.1. Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.
- **Theorems.** **RI-1** (committee-signed `state_root` binds the `i:` leaf — reduces to A1 forgery on `h+1` or A2 collision at `h`, via SR-1); **RI-2** (`i:` Merkle inclusion soundness — MT-1/MT-2/MT-3/MT-4 at the presence-marker leaf, with MT-2 leaf-key domain separation carrying the binding the value-hash carries elsewhere); **RI-3** (one-sided verifier — sound non-application is NOT provable under MT-5; `not_found`/withheld → UNVERIFIABLE, never a false NOT-APPLIED); **RI-4** (`leaf_count` bound into the committed root — S-040 CLOSED via root-wrapper hash; a forged count is rejected); **RI-5** (fail-closed exit — L-6 per-command). Corollary **RI-E** composes RI-1 + RI-2 + RI-4 with T-L1 + T-L2 to the same `≤ 2⁻⁹²` end-to-end bound as the balance / stake reads (positive verdict only).
- **The presence-marker finding (load-bearing).** The `i:` value-hash is the **constant** `SHA256(0x01)` (`chain.cpp:331-341`) — all receipt identity lives in the length-prefixed Merkle **key** `"i:" + src_be8 + tx_hash`. So RI-2's binding to a specific `(S, H)` runs through MT-2 leaf-key domain separation, not a value-hash decode (contrast `StakeProofSoundness.md` SP-2). There is no per-receipt cleartext to cross-check; the verified statement is purely *applied vs. not-applied*, with the negative un-provable (RI-3).
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-2/MT-3/MT-4/MT-5 + §6.2 S-040), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `S033StateRootNamespaceCoverage.md` (T-1/T-2/T-3/T-4 + §2.1 `i:` row), `LightClientThreatModel.md` (T-L1/T-L2/T-L3/T-L4 + `A_daemon` + L-6), `CrossShardReceipts.md` (FA7 T-7 + Cor. T-7.1 — apply-side dual), `CrossShardReceiptDedup.md` (T-R1/T-R2/T-R7 — applied-iff-leaf semantics), `StakeProofSoundness.md` + `TxInclusionProofSoundness.md` (sibling reads), `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 prerequisite).
- **Known limitations.** One-sided / no provable non-application (§6.1, RI-3); genesis-only committee map (§6.2); `i:` served by the generic `state_proof` RPC via R-ext (§6.4 — formerly a sourcing obligation, now shipped: hex-encoded composite key body); presence-only semantics, no amount/recipient/dst-shard in the leaf (§6.5); per-chain, not cross-shard-global (§6.6). (S-040 is **not** a limitation: `leaf_count` is bound into the committed root — §6.3, RI-4.) None undermine the per-invocation `APPLIED` soundness claim.
- **Concrete-security bound.** Per invocation (positive verdict): `≤ (vc.height + K + log₂(n) + 2)·2⁻¹²⁸`; `≤ 2⁻⁹²` for `vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`. Under Grover (PQ), degrades to `≤ 2⁻⁴⁷` on the A1 term — operationally secure, with PQ-signature migration the long-term path (`Preliminaries.md` §2.2 note).

---

## 9. References

### Implementation sites
- `src/chain/chain.cpp:331-341` — `i:` leaf encoding (`"i:" + src_be8 + tx_hash`, value-hash `SHA256(0x01)`).
- `src/chain/chain.cpp:204-207` — `Chain::inbound_receipt_applied` (the apply predicate `count{src,tx} > 0`).
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (`leaf_count` at `:456`; `nullopt` for absent key at `:449`).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root`.
- `src/chain/chain.cpp:1358-1381` — inbound-receipt admission + insert (`:1373-1374`); the apply-side record RI reads back.
- `include/determ/chain/chain.hpp:605` — `applied_inbound_receipts_ : std::set<std::pair<ShardId, Hash>>`.
- `src/node/node.cpp:3287-3336` — `Node::rpc_state_proof` (`i:` declined at `:3294`, `:3312-3313`; single envelope `:3325-3335`).
- `src/node/producer.cpp:608-693` — `compute_block_digest` (excludes `state_root`).
- `src/chain/block.cpp:336-364` — `Block::signing_bytes` / `compute_hash` (binds `state_root` when non-zero).
- `src/crypto/merkle.cpp:25-34` — `merkle_leaf_hash` (length-prefixed key; MT-2).
- `src/crypto/merkle.cpp:113-141` — `merkle_verify`.
- `src/rpc/rpc.cpp:235-238` — `state_proof` RPC dispatch.
- `light/verify.cpp:330-396` — `verify_state_proof` (consumes `key_bytes` at `:349-350`).
- `light/trustless_read.cpp:439-599` — `read_account_trustless` (template for the `i:` read); S-042 committee-binding `committee_bound_state_root` `:335-437`.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels; §2.1 SHA-256 (A2/A3); §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (leaf/inner + key domain separation — RI-2 core), MT-3 (collision-resistance inheritance), MT-4 (inclusion-proof soundness — RI-2 core), MT-5 (non-membership boundary — RI-3), §6.2 (S-040 — RI-4).
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1 (committee-anchored root — RI-1 core), SR-2 (genesis-binding), SR-3 (height-binding).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (coverage completeness), T-2 (namespace disjointness), §2.1 (`i:` row).
- `docs/proofs/LightClientThreatModel.md` — `A_daemon` model; T-L1/T-L2/T-L3/T-L4; L-5 (race-window); L-6 (fail-closed exit — RI-5).
- `docs/proofs/CrossShardReceipts.md` (FA7) — T-7 (receipt safety, no double-credit / no fabrication), Cor. T-7.1 (global supply atomicity) — the apply-side dual.
- `docs/proofs/CrossShardReceiptDedup.md` — T-R1/T-R2/T-R7 (applied-iff-leaf semantics fixing what `i:` membership means).
- `docs/proofs/StakeProofSoundness.md` — SP-1/SP-2/SP-3 (the `s:` sibling RI-1/RI-2/RI-4 mirror).
- `docs/proofs/TxInclusionProofSoundness.md` — the membership sibling; §4.5 (flat-hash vs. Merkle non-membership asymmetry — why `i:` cannot prove non-application).
- `docs/proofs/BlockchainStateIntegrity.md` — S-021 + S-033 + S-038 four-surface composition (chain-level prerequisite).

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` Merkle-leaf table (`i:` row).
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC contract.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` bound into the committed root via root-wrapper hash (CLOSED; RI-4).
- `docs/SECURITY.md §S-016` — time-ordered inbound-receipt admission (apply-side context).
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (A1).
