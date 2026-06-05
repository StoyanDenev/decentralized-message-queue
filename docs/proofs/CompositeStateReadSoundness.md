# CompositeStateReadSoundness — trust-minimized `m:` (merge-state) + `p:` (pending-param-change) light-client read soundness (CR-1..CR-5)

This document formalizes the soundness of two **trust-minimized composite-key light-client reads** enabled by the composite-key `state_proof` RPC shipped this round: reading a refugee shard's **merge-state** (`m:` namespace — `partner_id` + `refugee_region`) and a staged **pending parameter change** (`p:` namespace — `(name, value)` at an `effective_height`/`idx` slot) from a *single untrusted daemon*, verified locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client act on a merge-partnership or a pending governance change that is inconsistent with the genesis-pinned chain. Both reads target composite-key namespaces of the S-033 state-commitment surface whose leaf-key suffix is **raw binary** rather than an ASCII domain.

The proof exists because the `m:` and `p:` namespaces are **structurally different** from both the simple-key reads (`a:`/`s:` — `StakeProofSoundness.md`) and the presence-marker receipts read (`i:` — `ReceiptInclusionProofSoundness.md`) in three ways that matter for soundness:

1. **The leaf key is a fixed-width *binary* composite, not an ASCII string.** From `Chain::build_state_leaves` (`src/chain/chain.cpp:349-378`), an `m:` leaf has key `"m:" + u32_be(shard_id)` (6 bytes) and a `p:` leaf has key `"p:" + u64_be(eff_height) + u32_be(idx)` (14 bytes). Neither suffix is a human-readable `domain`; both are big-endian integers that cannot ride raw inside a JSON string (`nlohmann::json::dump()` throws on non-UTF-8 bytes). The caller therefore **hex-encodes the post-prefix body** and the daemon hex-decodes it, **length-checks it** against the exact namespace width (`m` = 4B, `p` = 12B; `node.cpp:3341-3349`), and prepends `"<ns>:"` to rebuild the canonical key byte-for-byte. This is the same R-ext composite-key transport `ReceiptInclusionProofSoundness.md` §1.4 documents for `i:`, here exercised for the *two non-presence-marker* composite namespaces.

2. **Unlike `i:`, both namespaces carry a non-constant value-hash with real cleartext content.** The `m:` value-hash is `SHA256(u64_be(partner_id) ‖ u64_be(|refugee_region|) ‖ refugee_region)` (`chain.cpp:355-359`); the `p:` value-hash is `SHA256(u64_be(|name|) ‖ name ‖ u64_be(|value|) ‖ value)` (`chain.cpp:371-376`). So unlike `ReceiptInclusionProofSoundness.md`'s identity-free `SHA256(0x01)` marker, these reads admit a **value-hash cleartext cross-check** in the style of `StakeProofSoundness.md` SP-2's `(locked, unlock_height)` decode — the verifier recomputes the value-hash from a daemon-asserted `(partner_id, refugee_region)` or `(name, value)` and detects any mismatch by A2.

3. **Both namespaces ARE now served by the generic `state_proof` RPC.** `Node::rpc_state_proof` (`src/node/node.cpp:3287-3378`) handles the composite-key namespaces `i|m|p` alongside the simple-key `a|s|r|d|b|k|c`. The cryptographic soundness (CR-1..CR-3) is independent of the sourcing route — the verifier re-derives the leaf hash from the returned `key_bytes` and gates on root-equality (`light/verify.cpp:333-335`) — and §4.2.1's key + value-hash cross-check pins the proven leaf to the operator's `(shard_id)` or `(eff_height, idx)` regardless of how the daemon built it.

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a merge-state or pending-param-change value that is inconsistent with the genesis-pinned chain's committed `m:` / `p:` leaf set at the verified height. The proof mirrors the `s:` read (`StakeProofSoundness.md` SP-1/SP-2/SP-3) and the `i:` read (`ReceiptInclusionProofSoundness.md` RI-1/RI-2/RI-4/RI-5), specialized to the two binary-composite-key namespaces and their respective value-hash encodings. It is the **read-side / verification dual** of the apply-and-snapshot determinism proofs `MergeStateSoundness.md` (the `m:` apply + snapshot contract, MS-1..MS-6) and `ParamChangeDeterminism.md` (the `p:` apply + snapshot contract, PC-1..PC-3): those prove the leaf is *deterministically produced and faithfully round-tripped*; this proves a light client can *trustlessly read it back* against a committee-signed root.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1, **A4** = CSPRNG §2.3) — this proof reduces to **A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-2** leaf/inner domain separation, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core CR-2 consumes, **MT-5** non-membership boundary is exactly the limitation CR-3 honours, and **§6.2 (S-040)** is the `leaf_count` caller-trust limitation CR-4 addresses); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding CR-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding; the transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` mechanism is reused verbatim); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `m:` / `p:` key + value-hash encodings read off `chain.cpp:349-378`, **T-1** confirms `merge_state_` / `pending_param_changes_` are committed to the root through `m:` / `p:`, and **T-2** namespace disjointness guarantees `"m:"+… ≠ "p:"+… ≠ "a:"+…` at byte 0); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the balance/nonce trustless-read flow this proof specializes — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** composite read with race-window mitigation, **L-4** cleartext cross-check, **L-6** fail-closed exit); `StakeProofSoundness.md` (the `s:` value-hash-decode sibling — CR-1/CR-2/CR-4 are the `m:`/`p:` analogs of SP-1/SP-2/SP-3, with the cleartext cross-check carried over directly because both namespaces commit real content); `ReceiptInclusionProofSoundness.md` (the `i:` composite-key sibling — CR shares its binary-body hex transport, its one-sided non-membership boundary CR-3 ≡ RI-3, and its single-envelope sourcing CR-4 ≡ RI-4, differing only in that `m:`/`p:` decode a non-constant value-hash where `i:` cannot); `MergeStateSoundness.md` (MS-1..MS-6 — the apply-determinism + snapshot round-trip of `merge_state_` that produces the `m:` leaf CR-2 reads back) + `ParamChangeDeterminism.md` (PC-1..PC-3 — the same for `pending_param_changes_` / `p:`); `GovernanceParamChange.md` (FA-Apply — the PARAM_CHANGE staging primitive `stage_param_change` that originates a `p:` entry) + `GovernanceWhitelistSoundness.md` (GW-1..GW-3 — the whitelist gate that bounds *which* `name` can appear in a `p:` leaf); `RegionalSharding.md` (FA8) + `UnderQuorumMerge.md` (FA9) for the R4/R7 merge semantics that fix what a `m:` leaf *means*; `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-038 + §S-040 for the closure / limitation narratives; `docs/PROTOCOL.md` §4.1.1 for the canonical `m:` / `p:` Merkle-leaf rows + §10.2 for the `state_proof` RPC contract.

---

## 1. Scope

### 1.1 In scope

Two trust-minimized composite-key reads, each answering a single question without trusting the daemon that serves the data:

> **(`m:` read)** Is refugee shard `S` currently **merged** into a partner shard, and if so, with which `partner_id` and under which `refugee_region`, at the committee-verified height?
>
> **(`p:` read)** Is the parameter-change slot `(effective_height E, index J)` committed with a specific `(name, value)` pair at the committee-verified height — i.e., is a named governance change *staged* to activate at `E`?

Each read's logical pipeline mirrors `read_account_trustless` (`light/trustless_read.cpp:188-350`) with the composite key substituted:

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:52-79`). (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:81-186`), invoking `verify_headers` + `verify_block_sigs` end-to-end from block 0. (T-L2.) This yields a committee-anchored `state_root` (SR-1).
3. **State-proof fetch for the composite leaf** — the composite key is presented to the daemon via the hex-encoded body: `{{"namespace","m"},{"key", hex(u32_be(S))}}` for the merge read, or `{{"namespace","p"},{"key", hex(u64_be(E)‖u32_be(J))}}` for the param read. `Node::rpc_state_proof` hex-decodes the body, length-checks it (`m` = 4B, `p` = 12B; `node.cpp:3341-3349`), rebuilds the composite key, and returns `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Merkle inclusion verify** — `verify_state_proof(proof, root)` (`light/verify.cpp:285-349`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`), the verifier re-deriving the leaf hash from the supplied `key_bytes`. (T-L3 / CR-2.)
5. **Race-window anchor of the proof root to a committee-signed header** — the three-branch `proof_height < / == / > vc.height` dispatch (`light/trustless_read.cpp:226-307`). (T-L4 §4.4.1 / CR-1.)
6. **Value-hash cleartext cross-check** — recompute the canonical value-hash from a daemon-asserted cleartext `(partner_id, refugee_region)` (for `m:`) or `(name, value)` (for `p:`) and require equality against the proof's verified `value_hash`, plus require `key_bytes` to equal the locally-recomputed composite key. (CR-2 / §4.2.1.)

The verdict (per read):

| Verdict | Condition |
|---|---|
| `VERIFIED` | steps 1–6 pass: the composite leaf is committed under the committee-signed `state_root`, with `key_bytes` matching the locally-recomputed composite key and `value_hash` matching the recomputed cleartext encoding. The `(partner_id, refugee_region)` / `(name, value)` is committee-anchored truth. |
| `UNVERIFIABLE` | any of: genesis anchor fails (T-L1); header sig/continuity fails (T-L2); `merkle_verify` rejects; the daemon returns `not_found`/`error`/`composite key wrong length`/`invalid hex` (the slot is *absent*, OR the daemon is withholding — **indistinguishable**, §4.3); a committee not in the seed map (§6.2 caveat); or any RPC/parse error. |

There is **no positive `NOT-MERGED` / `NOT-STAGED` verdict** — see §1.3 and CR-3. Absence is *not* a cryptographically provable statement under the sorted-leaves primitive (`MerkleTreeSoundness.md` MT-5); a daemon withholding a genuine `m:`/`p:` leaf is indistinguishable from a genuinely-absent leaf. Both reads are therefore **one-sided** verifiers: each can prove `VERIFIED` cryptographically, but the negative is always `UNVERIFIABLE`, never an authoritative `NOT-MERGED` / `NOT-STAGED`.

### 1.2 The `m:` and `p:` leaf encodings (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:349-378`):

```cpp
// merge_state_  (key = "m:" + shard_id_be4)
for (auto& [shard, info] : merge_state_) {
    std::vector<uint8_t> key;
    key.reserve(2 + 4);
    key.push_back('m'); key.push_back(':');
    for (int i = 3; i >= 0; --i) key.push_back((shard >> (8*i)) & 0xff);   // shard_id, big-endian u32
    crypto::SHA256Builder b;
    b.append(static_cast<uint64_t>(info.partner_id));                       // partner_id, big-endian u64
    b.append(static_cast<uint64_t>(info.refugee_region.size()));
    b.append(info.refugee_region);
    leaves.push_back({std::move(key), hash_bytes(b)});
}
// pending_param_changes_  (key = "p:" + eff_be8 + idx_be4)
for (auto& [eff, entries] : pending_param_changes_) {
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        auto& [name, value] = entries[idx];
        std::vector<uint8_t> key;
        key.reserve(2 + 8 + 4);
        key.push_back('p'); key.push_back(':');
        for (int i = 7; i >= 0; --i) key.push_back((eff >> (8*i)) & 0xff);  // effective_height, big-endian u64
        for (int i = 3; i >= 0; --i) key.push_back((uint32_t(idx) >> (8*i)) & 0xff); // slot idx, big-endian u32
        crypto::SHA256Builder b;
        b.append(static_cast<uint64_t>(name.size()));
        b.append(name);
        b.append(static_cast<uint64_t>(value.size()));
        if (!value.empty()) b.append(value.data(), value.size());
        leaves.push_back({std::move(key), hash_bytes(b)});
    }
}
```

so for a merged refugee shard `S` and a staged param slot `(E, J)`:

$$
\text{key}_m(S) \;=\; \texttt{"m:"} \,\|\, u32\_be(S), \qquad
\text{value\_hash}_m(S) \;=\; H\big(\,u64\_be(\texttt{partner\_id}) \,\|\, u64\_be(|\texttt{region}|) \,\|\, \texttt{region}\,\big),
$$

$$
\text{key}_p(E, J) \;=\; \texttt{"p:"} \,\|\, u64\_be(E) \,\|\, u32\_be(J), \qquad
\text{value\_hash}_p(E, J) \;=\; H\big(\,u64\_be(|\texttt{name}|)\|\texttt{name}\|u64\_be(|\texttt{value}|)\|\texttt{value}\,\big).
$$

The `m:` source container is `merge_state_ : std::map<ShardId, MergePartnerInfo>` (`include/determ/chain/chain.hpp:598`, `MergePartnerInfo = {ShardId partner_id; std::string refugee_region;}` at `chain.hpp:328-331`), keyed by the **refugee** shard id; **absence from the map is the canonical NOT-MERGED state** (`chain.hpp:323`). The `p:` source container is `pending_param_changes_ : std::map<uint64_t, std::vector<std::pair<std::string, std::vector<uint8_t>>>>` (`chain.hpp:623`), keyed by `effective_height`, with each `idx` a position in that height's bucket; **absence is the canonical NOT-STAGED state**. These are exactly the `m:` and `p:` rows of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 and `PROTOCOL.md` §4.1.1.

**The load-bearing structural fact for `m:` (the key/value width asymmetry).** The `m:` **key** encodes `shard_id` as **4** big-endian bytes (`u32_be`), but the value-hash encodes `partner_id` as **8** big-endian bytes (`u64_be`). This is lossless (both fit `ShardId`), but a cross-implementation `m:`-leaf verifier MUST match the asymmetric widths — a verifier that wrote `partner_id` as `u32` into the value-hash preimage would compute a different `value_hash` and reject a genuine leaf. CR-2's cleartext cross-check (§4.2.1) is stated against the canonical 8-byte value-hash width. (This is the same asymmetry `MergeStateSoundness.md` §6 records as finding **F-3**; CR-2 consumes it on the read side.)

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-membership (the negative for either read).** A light client *cannot* prove "shard `S` is **not** merged" or "slot `(E, J)` is **not** staged" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). A daemon withholding a genuine `m:`/`p:` leaf is indistinguishable from a genuinely-absent one. This is the **same** boundary as `StakeProofSoundness.md` §6.1 (unstaked domains), `ReceiptInclusionProofSoundness.md` §6.1 (non-applied receipts), and `TxInclusionProofSoundness.md` §6.3 (per-height membership). CR-3 records it honestly; neither read ever emits an authoritative `NOT-MERGED` / `NOT-STAGED`.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1–§6.7. Within one invocation the race-window mitigation (CR-1 / L-5) is sound; cross-invocation head-regression is operator-visible but not auto-detected.
- **The mutating side of merges and params** (the MERGE_BEGIN/MERGE_END apply rules and idempotence, the R7 under-quorum-merge admission gate, the PARAM_CHANGE validator whitelist + multisig gate, the height-triggered `activate_pending_params` drain, the A5 governance mode). Those are apply-layer correctness (`MergeStateSoundness.md` MS-1/MS-2, `UnderQuorumMerge.md` FA9, `S036UnderQuorumMerge.md`, `ParamChangeDeterminism.md` PC-1/PC-3, `GovernanceParamChange.md`, `GovernanceWhitelistSoundness.md` GW-1); this proof reads the *committed* `m:`/`p:` leaf and does not re-prove how it got there.
- **Whether a staged `p:` change is *legal* / *whitelisted* / *bounded*.** The `p:` read proves *"slot `(E, J)` commits `(name, value)`,"* not *"`name` is on the governance whitelist"* or *"`value` is within range." `GovernanceWhitelistSoundness.md` GW-1/GW-2 cover the legality gate (GW-2 honestly flagging that only an 8-byte width gate, not a semantic range check, is enforced); an operator reasoning about a *committed* `p:` leaf still benefits from GW-1's guarantee that the validator already rejected off-whitelist names before staging — but the `p:` read itself attests only membership, not legality. §6.5 records this.
- **Whether a merge is *safe* / *quorum-satisfying*.** The `m:` read proves *"shard `S` is recorded as merged into `partner_id`,"* not *"the merge satisfied the R7 under-quorum gate."* `UnderQuorumMerge.md` FA9 + `S036UnderQuorumMerge.md` cover the safety preservation; this read attests only the committed partnership.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged merge/param replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM), `A_genesis` (tampered pinned `genesis.json`).

Specialized to the two reads, `A_daemon` will attempt one of:

- **(a) False-merge / false-stage.** Convince the verifier that shard `S` is merged into `partner_id'` (when it is not, or into a different partner), or that slot `(E, J)` commits `(name', value')` (when it commits something else, or nothing) — e.g., to mislead an operator's committee-pool reasoning, or to make a governance auditor believe a parameter change is (or is not) staged.
- **(b) Suppressed-merge / suppressed-stage.** Convince the verifier that a genuine merge/stage is *not provably present* — landing the verifier in `UNVERIFIABLE`, **not** in a false `NOT-MERGED` / `NOT-STAGED` (§1.3 / CR-3). So (b) is an *availability/honesty* downgrade, never a *soundness* break.

**Security goal.** Under `A_daemon`, an honest light client running either read:

- never returns `VERIFIED` for a `(partner_id, refugee_region)` / `(name, value)` not genuinely committed in the `m:`/`p:` leaf set of the genesis-pinned chain at the verified height;
- never acts on a substituted leaf — any leaf whose recomputed Merkle path does not roll up to the committee-signed `state_root`, or whose `key_bytes`/`value_hash` do not match the canonical encoding for the queried slot, yields `UNVERIFIABLE`, never a verdict.

"Acts on" means *displays as authoritative* or *feeds into a downstream decision* (e.g., an operator deciding whether to extend a committee pool with a refugee region, or a governance auditor confirming a staged change). The negation form is **fail-closed exit**: any detected inconsistency throws and propagates to a non-zero process exit with a structured stderr diagnostic (inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

Both reads reuse the four light-client primitives unchanged — genesis anchor (`LightClientThreatModel.md` §3.1), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies with the state-proof stage targeting the composite key `key_m(S)` or `key_p(E, J)`. Two specializations distinguish these reads:

1. **Composite-key construction (binary-body hex transport).** Neither key is an ASCII `domain`; both are fixed-width big-endian integer composites built locally and hex-encoded for JSON transport, with the daemon hex-decoding + length-checking + prefixing them (`node.cpp:3330-3353`). This is the same R-ext transport `ReceiptInclusionProofSoundness.md` §1.4 establishes for `i:`; the **length check** (`node.cpp:3344-3349`) is a daemon-side defense that rejects a malformed body before it can alias a different leaf, but the *verifier* does not rely on it — CR-2's key cross-check (§4.2.1) re-pins the leaf to the operator's own inputs regardless.

2. **Non-constant value-hash with a cleartext cross-check.** Unlike `i:`'s identity-free `SHA256(0x01)`, both `m:` and `p:` commit real content in the value-hash, so the verifier performs the optional belt-and-suspenders cleartext cross-check of `StakeProofSoundness.md` SP-2 / `LightClientThreatModel.md` L-4: recompute `H(u64_be(partner_id) ‖ u64_be(|region|) ‖ region)` (or the `p:` analog) from the daemon-asserted cleartext and require equality against the proof's verified `value_hash`. A daemon lying about either field while serving an honest proof must find a colliding value-hash (A2).

Crucially, the daemon delivers `state_root`, `leaf_count`, `target_index`, `value_hash`, the sibling vector, and `key_bytes` such that the light client verifies the proof's `state_root` against a committee-signed header in the *same* invocation (`trustless_read.cpp:226-307`). This single-envelope sourcing is the precondition CR-4 formalizes.

---

## 4. Security theorems

Throughout, fix one of the two reads. For the `m:` read let `S` be the queried refugee shard, `key_m(S) = "m:" ‖ u32\_be(S)`, and `(\text{partner}_T, \text{region}_T)` the true merge-partner pair (with true value-hash `\text{value\_hash}_m^T(S)`). For the `p:` read let `(E, J)` be the queried slot, `key_p(E, J) = "p:" ‖ u64\_be(E) ‖ u32\_be(J)`, and `(\text{name}_T, \text{value}_T)` the true staged pair. Let `R := state_root(h)` be the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to. The chain's *true* committed set at height `h` is `\mathcal{M}_T(h)` / `\mathcal{P}_T(h)`; the queried slot is genuinely present iff its composite key is a leaf of the tree `R` commits to.

### 4.1 Theorem CR-1 (committee-signed `state_root` binds the composite leaf)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that either read anchors and verifies the composite proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root the `m:`/`p:` leaf is checked against is *committee-certified*, not daemon-asserted.

**Proof.** This is `StateRootAnchorSoundness.md` **SR-1** applied at the height the composite proof is anchored at, identical to `StakeProofSoundness.md` SP-1 and `ReceiptInclusionProofSoundness.md` RI-1's inline anchoring at `trustless_read.cpp:277-285`. The binding of `state_root(h)` to the committee is **transitive-forward**, not a direct signature: the committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp::compute_block_digest`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root` (the `light/verify.cpp` digest-exclusion comment). `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim) and hence into `block_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`:

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

Suppose the invocation anchors `R_A ≠ state_root_T(h)`. The SR-1 case split (reproduced for the composite-proof anchoring at `trustless_read.cpp:269-285`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`.** The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).
- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. To accept `h+1` with a different `prev_hash`, the daemon must present `required` valid signatures over a different digest — an Ed25519 forgery for each of `required ≤ K` distinct committee members, `≤ K · 2⁻¹²⁸` (A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* is supplied by SR-2 + SR-3 + T-L1's genesis anchor; CR-1 inherits them.

**Head-block boundary.** If the operator queries a slot at the chain *head*, that block's `state_root` has no signed successor yet, so it is committee-certified only once a successor is produced; the shipped flow handles this via the race-window dispatch matching a head-height proof byte-for-byte against `vc.head_state_root` (`trustless_read.cpp:302-307`; `LightClientThreatModel.md` L-5). CR-2 below proves Merkle-path soundness *given* such an `R`; CR-1 is the committee-binding of `R`.

**Concrete-security bound.** `Pr[A_daemon wins CR-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem CR-2 (Merkle state-proof for the composite leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from CR-1, a verifier holding `R` cannot be made to accept `VERIFIED` for a queried slot whose composite leaf (`key_m(S)` or `key_p(E, J)`) is **not** committed under `R`, nor accept a wrong `(partner_id, refugee_region)` / `(name, value)` cleartext, without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; key_{\bullet},\; value\_hash_{\text{served}},\; target\_index,\; n,\; proof) = \texttt{true}
\quad\wedge\quad value\_hash_{\text{served}} = H(\text{cleartext}_A),
$$

then either (a) `key_{\bullet}` is a genuine leaf of the tree `R` commits to at sorted position `target_index` with the genuine committed cleartext `= \text{cleartext}_A`, or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves the slot is committed with the asserted content, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as CR-1: the light client has anchored committee-signed `R`.
2. `A_daemon` returns a state-proof `P_A = (key_bytes_A, value\_hash_A, target\_index, n, proof)` claiming the slot is present with content `\text{cleartext}_A` when it is not. It may (i) serve a genuine leaf for some *other* committed composite slot and relabel it, (ii) serve a non-`m:`/non-`p:` leaf (e.g. an `a:` leaf) with a forged `key_bytes`, (iii) serve a `value\_hash_A` inconsistent with the cleartext it asserts, or (iv) alter `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true` **and** the verdict is `VERIFIED`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the composite leaf, equivalently `LightClientThreatModel.md` T-L3 specialized, plus the **MT-2** leaf-key domain separation. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value\_hash_A, target\_index, n, sibs)` (`light/verify.cpp:333-335`), which recomputes the leaf hash

$$
c_0 = \text{merkle\_leaf\_hash}(key_bytes, value\_hash_A) = H(\texttt{0x00} \| u32\_be(|key_bytes|) \| key_bytes \| value\_hash_A)
$$

and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R` (`merkle.cpp:139`).

The verifier additionally requires `key_bytes = key_{\bullet}` (the locally-recomputed canonical composite key, §4.2.1) **and** `value\_hash_A = H(\text{cleartext}_A)` for the asserted cleartext. With those equalities pinned, the recomputed `c_0` is *exactly* the genuine composite leaf hash for the queried slot iff the committed cleartext equals `\text{cleartext}_A`. By MT-4's extraction: if the leaf for `key_{\bullet}` with value-hash `value\_hash_A` is **not** committed under `R`, then the recomputed chain and the genuine root-path chain for sorted position `target_index` both terminate at `R` but disagree, exhibiting two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` mapping to the same `H` output at the highest divergence level — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** defeats the four attack shapes:

- **(i) relabel another slot's leaf.** The daemon serves the genuine leaf for a *different* committed slot, but the verifier's recomputed `c_0` uses `key_{\bullet}` for the *queried* slot; since distinct slots have distinct length-prefixed composite keys (different `u32_be(S)` for `m:`, different `u64_be(E)‖u32_be(J)` for `p:`), the recomputed leaf hash composes the served siblings into a *different* chain and fails root-equality. By MT-2's unambiguous length-prefixed key encoding, a pass requires a leaf-level collision (`≤ 2⁻¹²⁸`).
- **(ii) cross-namespace swap.** The daemon serves an `a:`/`s:`/`i:`/… leaf's siblings and a forged `key_bytes`. The verifier recomputes the leaf hash over `key_{\bullet}`, which begins with the `m:` / `p:` prefix; by `S033StateRootNamespaceCoverage.md` **T-2** namespace disjointness, `"m:"+… ≠ "a:"+…` (and `"m:"+… ≠ "p:"+…`) at byte 0, so the recomputed leaf hash differs from any cross-namespace leaf's hash, producing a different sibling chain and failing root-equality. This is the same cross-namespace-swap rejection `StakeProofSoundness.md` SP-2 and `ReceiptInclusionProofSoundness.md` RI-2 invoke (the `test_state_proof_namespaces.sh` swap assertions).
- **(iii) value-hash / cleartext inconsistency.** The verifier recomputes `H(\text{cleartext}_A)` and rejects unless it equals `value\_hash_A`; a daemon asserting a cleartext that does not hash to the served value-hash is caught at the §4.2.1 cross-check. And a daemon serving a `value\_hash_A` that does *not* match the genuine committed value-hash changes `c_0` and (by MT-4) fails root-equality against `R`. So a daemon lying about the merge-partner or the param `value` while serving an honest proof must find a colliding value-hash — A2 (`≤ 2⁻¹²⁸`). **This is the step the `i:` read cannot offer** (`ReceiptInclusionProofSoundness.md` RI-2's "no cleartext cross-check"): because `m:`/`p:` commit real content, the verified statement is *"slot `X` commits this specific `(partner_id, region)` / `(name, value)`,"* not merely *"slot `X` is present."*
- **(iv) index / sibling tamper.** Covered by MT-4's range/underflow/exact-consume gates exactly as in SP-2 / RI-2 (`MerkleTreeSoundness.md` §2.6 scenarios #5-#8; `determ test-merkle-proof-tampering`).

By `S033StateRootNamespaceCoverage.md` **T-1**, the `merge_state_` / `pending_param_changes_` fields are bound to the root through `m:` / `p:`, so the leaf CR-2 verifies is the genuine committed merge / param state. The leaf this read returns is exactly the leaf `MergeStateSoundness.md` MS-3/MS-4 (resp. `ParamChangeDeterminism.md` PC-1/PC-2) prove is deterministically produced and faithfully snapshot-round-tripped — CR-2 is the trustless read-back of those apply-side guarantees.

**Concrete-security bound.** `Pr[A_daemon wins CR-2] ≤ log₂(n) · 2⁻¹²⁸`; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`.   ∎

#### 4.2.1 The key + value-hash cross-check (why `VERIFIED` is crisp)

Two equalities, both computable by the verifier with **no daemon trust**, convert "a Merkle proof verified against `R`" into "the specific slot commits this specific content":

1. **Key equality.** `key_bytes == key_{\bullet}`, where `key_m(S) = "m:" + u32_be(S)` or `key_p(E, J) = "p:" + u64_be(E) + u32_be(J)` is built locally from the operator's arguments. The verifier re-derives the canonical composite key and byte-compares against the daemon-returned `key_bytes`, rejecting any mismatch — pinning the proven leaf to *this* `(S)` or `(E, J)`. (Note the `m:` key uses `u32_be` for `shard_id` while the value-hash uses `u64_be` for `partner_id` — §1.2's F-3 asymmetry; the verifier must build each with its canonical width.)
2. **Value-hash equality.** `value_hash == H(\text{cleartext}_A)`, where the verifier recomputes the canonical value-hash preimage (`u64_be(partner_id) ‖ u64_be(|region|) ‖ region` for `m:`, or `u64_be(|name|) ‖ name ‖ u64_be(|value|) ‖ value` for `p:`) from the daemon-asserted cleartext. This confirms the leaf commits the asserted `(partner_id, region)` / `(name, value)` and not some other content.

With (1)+(2) pinned and CR-2's root-equality, `VERIFIED` means exactly *"the leaf `(key_{\bullet}, H(\text{cleartext}_A))` is committed under the committee-signed `R`."* The verifier emits `VERIFIED` only on this conjunction; any failure of (1), (2), CR-1, or CR-2 yields `UNVERIFIABLE` (fail-closed, CR-5).

### 4.3 Theorem CR-3 (one-sided verifier; sound non-membership is NOT provable — honesty boundary)

**Statement.** Both reads are **one-sided** verifiers: each can establish `VERIFIED` cryptographically (CR-1 + CR-2), but **cannot** establish an authoritative `NOT-MERGED` / `NOT-STAGED`. A daemon that returns `not_found`/`error` for the queried slot — or otherwise withholds the leaf — leaves the verifier in `UNVERIFIABLE`, which is *indistinguishable* between "the slot is genuinely absent" and "the daemon is suppressing a genuinely-present slot." No false negative is ever emitted, because none exists to emit.

**Analysis.** The sorted-leaves balanced binary Merkle primitive supports **positive membership only** (`MerkleTreeSoundness.md` **MT-5**): there is no native non-membership (absence) proof. `Chain::state_proof` returns `std::nullopt` for an absent key (`chain.cpp:449`), surfaced by the daemon as `{"error":"not_found"}` (`node.cpp:3358-3361`). An honest light client receiving this can only conclude *"this daemon did not give me a proof,"* which an all-Byzantine peer set could produce by withholding. This is the **same** MT-5 boundary `StakeProofSoundness.md` §6.1, `ReceiptInclusionProofSoundness.md` §6.1, and `TxInclusionProofSoundness.md` §6.3 honour, inherited unchanged.

**Why the asymmetry is sharp here.** For `m:`, absence-of-leaf semantically *is* NOT-MERGED (`chain.hpp:323`: absence from the map is the canonical not-merged state); for `p:`, absence-of-leaf is NOT-STAGED. Yet "leaf absent" is exactly the statement the primitive cannot attest. The gap is not in the chain's bookkeeping (which is exact — `MergeStateSoundness.md` MS-2 / `ParamChangeDeterminism.md` PC-1 prove the map is a faithful function of the apply trace) but in the *proof system's* inability to prove absence. Both reads therefore report `UNVERIFIABLE` for the negative and let the operator fall back to a multi-peer cross-check, with the attendant trust cost.

**Consequence for the threat model.** Attack §2(b) (suppressed-merge / suppressed-stage) cannot produce a *false* answer — it produces `UNVERIFIABLE`, which is operator-visible and actionable. The soundness goal (§2) — never a false `VERIFIED`, never act on a substituted leaf — is fully met; the *completeness* gap (a withholding daemon forces `UNVERIFIABLE`) is an availability limitation, not a soundness one.   ∎

### 4.4 Theorem CR-4 (`leaf_count` caller-trust boundary; single-envelope sourcing)

**Statement.** CR-2's soundness is stated with `n` = the *genuine* leaf count of the tree `R` commits to. Because `merkle_verify` does **not** bind `leaf_count` into any leaf or inner hash (the **S-040** caller-trust invariant; `MerkleTreeSoundness.md` §6.2), the soundness of either composite read additionally requires that the light client source `leaf_count` from the *same committee-anchored origin* as `state_root`. The shipped flow discharges this: `state_root` and `leaf_count` arrive in one `rpc_state_proof` reply (`node.cpp:3367-3377`), computed atomically under the daemon's `state_mutex_` read lock (`node.cpp:3289`) over a single consistent state, and that reply's `state_root` is committee-anchored by CR-1 in the same invocation. Hence CR-4 holds operationally and the split-source attack is unreachable.

**Why the obligation exists.** `merkle_verify` consumes `leaf_count` only to drive the number of levels and the per-level duplication parity (`merkle.cpp:130-138`); it is not an input to `merkle_leaf_hash` or `merkle_inner_hash`. Two distinct `(target_index, leaf_count)` pairs that yield the *same walk shape* verify identically — the concrete failure pinned by `determ test-merkle-proof-tampering` scenario #12.

**Why the shipped flow is safe.** The danger is exclusively the *split-source* case: proof + `leaf_count` from one untrusted channel, `state_root` from a different (trusted) channel, with the two inconsistent. In either composite read, the proof envelope returns `state_root`, `leaf_count`, `target_index`, `value_hash`, and `proof` as fields of **one** JSON object, with `leaf_count = build_state_leaves().size()` (`chain.cpp:456`) — the genuine count for the very tree whose root is `compute_state_root()` in the same reply (`node.cpp:3375`). The light client anchors *that reply's* `state_root` to a committee-signed header (CR-1) in the same invocation, then verifies the composite proof against the anchored root using *that reply's* `leaf_count`. There is no second channel; the `(state_root, leaf_count)` pair is consistent-by-construction, and the anchoring step rejects any `state_root` the committee did not sign. Even in the degenerate same-walk-shape coincidence of S-040, the value the verifier accepts is still the genuine composite leaf under the genuine root — the daemon gains no ability to substitute a *wrong* slot's content, only (at most) to mislabel which sorted slot it occupies, which the `key_{\bullet}`-binding of CR-2 still ties to the queried slot.

**Status.** S-040 is a registered **Low/Op** caller-trust item, orthogonal to CR-2's soundness (which holds with the genuine `leaf_count`). The structural fix — domain-separating `leaf_count` into the leaf hash — breaks v1 wire compatibility and is tracked for a future v2.x flag-day (`MerkleTreeSoundness.md` §6.2). CR-4 records that the shipped composite-read flow does not split the source and is therefore unaffected.

**Concrete-security bound.** CR-4 adds no independent term beyond CR-1 + CR-2 under single-envelope sourcing.   ∎

### 4.5 Lemma CR-5 (fail-closed exit)

**Statement.** Any signature failure, chain break, genesis mismatch, malformed proof, `not_found`/`error`/`composite key wrong length`/`invalid hex` reply, `key_bytes ≠ key_{\bullet}`, value-hash/cleartext mismatch, or `merkle_verify` rejection causes the read to exit non-zero with a structured diagnostic (verdict `UNVERIFIABLE`) — never a bare daemon-asserted `VERIFIED`.

**Proof.** By inheritance from `LightClientThreatModel.md` Lemma **L-6** for the reused T-L1/T-L2/T-L3 surfaces (`verify_headers`, `verify_block_sigs`, `verify_state_proof` each set `r.ok=false` + `r.detail` on every error branch and return to a caller that throws; `anchor_genesis` throws on genesis mismatch), plus the §4.2.1 structural property that `VERIFIED` is reached *only* on the conjunction (CR-1 anchored ∧ CR-2 root-equality ∧ key-equality ∧ value-hash-equality). The composite-namespace daemon-side guards (`invalid hex` at `node.cpp:3336`, `composite key wrong length` at `node.cpp:3345`, `not_found` at `node.cpp:3360`) all surface as RPC errors caught at `verify_state_proof`'s error branch → `UNVERIFIABLE`. There is no code path from a detected inconsistency to `VERIFIED`. This is the per-command instance of L-6; the throw-discipline is structural.   □

### 4.6 End-to-end composition

**Corollary CR-E (trust-minimized composite read).** Under A1 + A2, either composite read yields a `VERIFIED` verdict bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis (or a fail-closed `UNVERIFIABLE`). Composing CR-1 (committee-anchored root) + CR-2 (composite Merkle inclusion + key/value-hash binding) + CR-4 (single-envelope `leaf_count`) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline:

$$
\Pr[A_{\text{daemon}} \text{ wins CR-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4, the stake-read bound of `StakeProofSoundness.md` SP-E, and the receipt-read bound of `ReceiptInclusionProofSoundness.md` RI-E exactly, as expected: the `m:`/`p:` reads differ only in the key construction and the leaf encoding, both namespace-agnostic in every cryptographic step. CR-E covers the *positive* (`VERIFIED`) verdict only; the negative is always `UNVERIFIABLE` per CR-3.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

CR-2 *is* MT-4 applied at the `m:` / `p:` leaf, with **MT-2** (leaf/inner + key domain separation) carrying the cross-namespace-swap rejection and the relabel rejection (distinct composite keys ⇒ distinct leaf hashes). MT-1 (determinism) guarantees the composite leaf's position and the root are reproducible across honest nodes; MT-3 (collision-resistance inheritance) makes any wrong committed merge/param set produce a different root. CR-3 is the composite-namespace statement of MT-5's positive-only boundary; CR-4 is the composite-read-specific statement of MT-4's §6.2 (S-040) operational obligation.

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

CR-1 *is* SR-1 applied at the height the composite proof is anchored at, plus SR-2 (genesis-binding) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism (`state_root` is **not** in `compute_block_digest`; it is committee-bound transitively forward via the successor block's signed digest); CR-1 names the composite reads as consumers of it, exactly as `LightClientThreatModel.md` T-L4 does for the `a:` read.

### 5.3 `S033StateRootNamespaceCoverage.md` — the namespace surface

**T-1** (coverage completeness) confirms `merge_state_` / `pending_param_changes_` are committed to the root through `m:` / `p:` (and through *no other*, by **T-2** disjointness), so the leaf CR-2 verifies is the genuine committed state. §2.1's table fixes the byte-exact `m:` key (`"m:" + u32_be(shard_id)`) + value-hash (`SHA256(u64_be(partner_id) ‖ len ‖ region)`) and `p:` key (`"p:" + u64_be(eff) + u32_be(idx)`) + value-hash this proof reads off `chain.cpp:349-378`. T-3 (deterministic leaf ordering) — `merge_state_` iterates by ascending `ShardId`, `pending_param_changes_` by ascending `effective_height` then bucket `idx` — + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes.

### 5.4 `LightClientThreatModel.md` — the adversary model and read flow

This proof specializes T-L3 (state-proof correctness) + T-L4 (composite read with race-window mitigation) + L-4 (cleartext cross-check) from the `a:` namespace to `m:` / `p:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6 / CR-5), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. CR-E's bound equals T-L4's bound. The light client's `read_account_trustless` (`trustless_read.cpp:188-350`) is the structural template both reads follow, with the `a:`-key construction replaced by the composite key of §1.2.

### 5.5 `StakeProofSoundness.md` / `ReceiptInclusionProofSoundness.md` — the sibling reads

CR-1/CR-2/CR-4 are the `m:`/`p:` analogs of `StakeProofSoundness.md` SP-1/SP-2/SP-3 (the `s:` read) and `ReceiptInclusionProofSoundness.md` RI-1/RI-2/RI-4 (the `i:` read). CR shares the `s:` read's **value-hash cleartext cross-check** (SP-2 / L-4) — because `m:`/`p:`, like `s:`, commit real content — *and* the `i:` read's **binary-body hex transport** (RI §1.4) and **one-sided non-membership boundary** (CR-3 ≡ RI-3) — because `m:`/`p:`, like `i:`, are composite binary-key namespaces. The composite reads thus sit at the intersection of the two siblings: composite-key like `i:`, content-bearing like `s:`. This is exactly the gap the lane fills — the two siblings each cover one of the two structural axes; the `m:`/`p:` reads exercise both at once.

### 5.6 `MergeStateSoundness.md` / `ParamChangeDeterminism.md` — the apply-side duals

`MergeStateSoundness.md` (MS-1..MS-6) proves the *production-side* guarantee for `m:`: `merge_state_` is a deterministic function of the MERGE_EVENT multiset (MS-1), idempotent under replay (MS-2), injectively encoded into the `m:` leaf (MS-3), and faithfully snapshot-round-tripped (MS-4/MS-5). `ParamChangeDeterminism.md` (PC-1..PC-3) proves the same for `p:`: staging determinism (PC-1), snapshot round-trip identity (PC-2), and deterministic height-triggered activation (PC-3). These composite reads are the **read-back dual** of both: MS/PC say "the `m:`/`p:` leaf is deterministically produced and faithfully preserved," and CR-2 says "a holder of the committee-signed `state_root` can *confirm* that leaf trustlessly." The two are duals — apply-side determinism + read-side verifiability. (CR also consumes MS-3's F-3 key/value width asymmetry directly: §1.2 / §4.2.1 build the value-hash preimage with the canonical 8-byte `partner_id` width.)

### 5.7 `GovernanceWhitelistSoundness.md` / `GovernanceParamChange.md` — the `p:` legality frame

The `p:` read attests *membership* of a `(name, value)` slot, not its *legality*. `GovernanceWhitelistSoundness.md` GW-1 (whitelist closure) guarantees the validator already rejected off-whitelist `name`s before any `p:` leaf could be staged, and GW-2 honestly flags that only an 8-byte width gate (not a semantic range check) bounds the `value`. `GovernanceParamChange.md` covers the `stage_param_change` primitive that originates the leaf and the activation drain. An operator combining the `p:` read (membership + content) with GW-1 (legality precondition) gets the full trustless picture: *"a whitelisted name is staged with this value at this height."* §6.5 records that the read alone proves only the first clause.

### 5.8 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the composite proof anchors against an S-033-committed root. As with the other trustless reads, the flow must fail-closed with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`trustless_read.cpp:202-208`) — a chain-level deployment prerequisite. CR-1's interior regime is exactly the S-033-active regime.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Several are worth calling out for the composite reads specifically.

### 6.1 One-sided: no provable non-membership (CR-3)

Neither read can prove `NOT-MERGED` / `NOT-STAGED`. A daemon returning `not_found` for a genuinely-present slot is indistinguishable from a genuinely-absent one (`MerkleTreeSoundness.md` MT-5). The negative is always `UNVERIFIABLE`. Multi-peer cross-check (out of scope) is the only mitigation against a withholding daemon. Same positive-only boundary as the `s:` / `i:` siblings.

### 6.2 Committee-rotation (genesis committee `K_0` only)

Like every other light-client verifier, both reads seed the committee map from genesis `initial_creators` (`build_genesis_committee`, `trustless_read.cpp:43-50`) and require every creator in the `0..h` walk to be in that map. On a chain with mid-chain REGISTER/DEREGISTER that rotated the committee, the walk **fails closed** at the first non-`K_0` signer → `UNVERIFIABLE` — a positive safety property, never a wrong verdict. Shared `K_0` caveat (`LightClientThreatModel.md` §6.5 + F-1, `StakeProofSoundness.md` §6.2, `ReceiptInclusionProofSoundness.md` §6.2).

### 6.3 S-040 leaf_count caller-trust (CR-4)

Recorded in §4.4: sound under the shipped single-envelope sourcing; a future split-source integrator must source `leaf_count` from the committee-anchored envelope. Low/Op; structural fix tracked for a v2.x wire-breaking flag-day.

### 6.4 `m:` key/value width asymmetry (F-3) is a cross-impl footgun, not a soundness gap

The `m:` key writes `shard_id` as `u32_be` while the value-hash writes `partner_id` as `u64_be` (§1.2). A cross-implementation verifier that builds the value-hash preimage with the wrong `partner_id` width computes a different `value_hash` and rejects a genuine leaf — yielding a (safe) `UNVERIFIABLE`, never a false `VERIFIED`. The asymmetry is lossless and consensus-fixed; CR-2's cross-check (§4.2.1) is stated against the canonical widths. This is the read-side mirror of `MergeStateSoundness.md` §6 finding F-3.

### 6.5 The reads attest membership + content, not legality or safety

The `p:` read does not prove the staged `name` is whitelisted or the `value` is in range (that is `GovernanceWhitelistSoundness.md` GW-1/GW-2, §5.7); the `m:` read does not prove the merge satisfied the R7 under-quorum gate (that is `UnderQuorumMerge.md` FA9, §5.6). Each read attests only that the queried slot is committed with the asserted content under the committee-signed root. An operator needing the legality/safety frame must compose with the apply-side proofs.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| CR-1 | committee-anchor (race-window) | `light/trustless_read.cpp:226-307` | Anchor the composite proof's `state_root` to a committee-signed header. |
| CR-1 | `verify_block_sigs` | `light/verify.cpp:190-283` | Per-block Ed25519 K-of-K committee-sig verify. |
| CR-1 | `verify_headers` | `light/verify.cpp:104-188` | prev_hash continuity walk from genesis (SR-2 genesis-binding). |
| CR-1 | `anchor_genesis` | `light/trustless_read.cpp:52-79` | T-L1 genesis pin. |
| CR-2 | `verify_state_proof` | `light/verify.cpp:285-349` | Parse composite proof JSON, delegate to `merkle_verify`. |
| CR-2 | `merkle_verify` | `src/crypto/merkle.cpp:113-141` | Recompute root from composite leaf + siblings; range/underflow/exact-consume gates. |
| CR-2 | `m:` leaf encoding | `src/chain/chain.cpp:349-360` | key `"m:" + u32_be(shard)`, value `SHA256(u64_be(partner) ‖ len ‖ region)`. |
| CR-2 | `p:` leaf encoding | `src/chain/chain.cpp:361-378` | key `"p:" + u64_be(eff) + u32_be(idx)`, value `SHA256(len‖name‖len‖value)`. |
| CR-2 | `MergePartnerInfo` | `include/determ/chain/chain.hpp:328-332` | `{partner_id, refugee_region}`; absence = NOT-MERGED. |
| CR-2 | `pending_param_changes_` view | `include/determ/chain/chain.hpp:384-386` | read-only diagnostic view of staged changes. |
| CR-3 | non-membership boundary | `src/chain/chain.cpp:449` | `Chain::state_proof` returns `nullopt` for absent key (→ `not_found`). |
| CR-4 | `Node::rpc_state_proof` | `src/node/node.cpp:3287-3378` | `i|m|p` composite namespaces served (l.3330-3353); single envelope (l.3367-3377). |
| CR-4 | composite length check | `src/node/node.cpp:3341-3349` | `m` = 4B / `p` = 12B body width enforced before leaf lookup. |
| CR-4 | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | `leaf_count = leaves.size()` (l.456) from the same tree as the root. |
| CR-1 | `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | `merkle_root(build_state_leaves())` — the root the committee transitively signs. |
| CR-E | state_proof RPC dispatch | `src/rpc/rpc.cpp:235-238` | `method == "state_proof"` → `rpc_state_proof(namespace, key)`. |
| CR-E | `read_account_trustless` (template) | `light/trustless_read.cpp:188-350` | The composite read skeleton; `m:`/`p:` differ by namespace + composite key construction. |

**Tests** (the composite reads share the light-client + Merkle + composite-namespace test surface):

| Test | Coverage |
|---|---|
| `tools/test_light_verify_receipt_inclusion.sh` | The composite-key R-ext transport (CR-4 envelope) end-to-end; `m:`/`p:` reuse the identical hex-body call shape with the namespace + body swapped. |
| `tools/test_light_verify_state_proof.sh` | CR-2 — happy path + tampered value_hash → FAIL + tampered sibling → FAIL + wrong state_root → FAIL. |
| `tools/test_state_proof_namespaces.sh` | CR-2 leaf-key binding — cross-namespace swap rejected. |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` | CR-2 tamper rejection; CR-4 / S-040 `leaf_count` limitation (#12). |
| `tools/test_merge_event_determinism.sh` + `determ test-merge-event-determinism` | the `m:` apply-side determinism (`MergeStateSoundness.md` MS-1) whose leaf CR-2 reads back. |
| `tools/test_governance_param_determinism.sh` | the `p:` apply-side determinism (`ParamChangeDeterminism.md` PC-1) whose leaf CR-2 reads back. |

---

## 8. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** The `m:` and `p:` composite namespaces are already served by `Node::rpc_state_proof` (`node.cpp:3330-3353`, shipped this round) and committed by `build_state_leaves` (`chain.cpp:349-378`); the composite-key R-ext transport is exercised end-to-end by `tools/test_light_verify_receipt_inclusion.sh` (the `i:` sibling). A `merge-trustless` / `param-trustless` composite command in `light/main.cpp` is the natural next step, structurally identical to `read_account_trustless` with the composite key of §1.2.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision / second-preimage resistance). No A3/A4 dependence beyond what T-L1's genesis anchor already carries.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis` (inherited from `LightClientThreatModel.md` §2.2).
- **Theorems.** CR-1 (committee-signed `state_root` binds the composite leaf — reduces to A1 forgery on `h+1` or A2 collision at `h`, via SR-1); CR-2 (composite Merkle inclusion + key/value-hash binding — MT-1/MT-2/MT-3/MT-4 at the `m:`/`p:` leaf, with the value-hash cleartext cross-check the `i:` read lacks); CR-3 (one-sided verifier — non-membership not provable under MT-5; withheld → `UNVERIFIABLE`, never a false negative); CR-4 (`leaf_count` caller-trust — S-040, discharged by single-envelope sourcing); CR-5 (fail-closed exit). Corollary CR-E composes them with T-L1 + T-L2 to the same `≤ 2⁻⁹²` end-to-end bound as the balance/stake/receipt reads.
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-2/MT-3/MT-4 + §6.2 S-040), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `S033StateRootNamespaceCoverage.md` (T-1/T-2/T-3/T-4 + §2.1 `m:`/`p:` rows), `LightClientThreatModel.md` (T-L1/T-L2/T-L3/T-L4 + L-4 + `A_daemon` + L-6), `StakeProofSoundness.md` (the value-hash-decode sibling), `ReceiptInclusionProofSoundness.md` (the composite-key sibling), `MergeStateSoundness.md` (the `m:` apply-side dual), `ParamChangeDeterminism.md` (the `p:` apply-side dual), `GovernanceWhitelistSoundness.md` (the `p:` legality frame), `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 prerequisite).
- **Known limitations.** No non-membership (§6.1); genesis-only committee map (§6.2); S-040 `leaf_count` caller-trust, mitigated by single-envelope sourcing (§6.3); `m:` key/value width asymmetry is a cross-impl footgun not a soundness gap (§6.4); the reads attest membership + content, not legality/safety (§6.5). None undermine the per-invocation soundness claim.

---

## 9. References

### Implementation sites
- `src/chain/chain.cpp:349-360` — `m:` leaf encoding (`SHA256(u64_be(partner_id) ‖ len ‖ region)`).
- `src/chain/chain.cpp:361-378` — `p:` leaf encoding (`SHA256(len‖name‖len‖value)`).
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (`leaf_count` at l.456; `nullopt` for absent at l.449).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root`.
- `src/node/node.cpp:3287-3378` — `Node::rpc_state_proof` (`i|m|p` composite at l.3330-3353; length check l.3341-3349; single envelope l.3367-3377).
- `src/rpc/rpc.cpp:235-238` — `state_proof` RPC dispatch.
- `include/determ/chain/chain.hpp:328-332` — `MergePartnerInfo` + `MergeStateMap`.
- `include/determ/chain/chain.hpp:384-386, 623` — `pending_param_changes_` view + field.
- `src/crypto/merkle.cpp:113-141` — `merkle_verify`.
- `light/verify.cpp:285-349` — `verify_state_proof`.
- `light/trustless_read.cpp:188-350` — `read_account_trustless` (template); race-window dispatch l.226-307.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels; §2.1 SHA-256 (A2/A3); §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (domain separation), MT-3 (collision-resistance inheritance), MT-4 (inclusion-proof soundness — CR-2 core), MT-5 (non-membership boundary — CR-3), §6.2 (S-040 — CR-4).
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1 (committee-anchored root — CR-1 core), SR-2 (genesis-binding), SR-3 (height-binding).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (coverage completeness), T-2 (namespace disjointness), T-3 (deterministic leaf ordering), §2.1 (`m:`/`p:` rows).
- `docs/proofs/LightClientThreatModel.md` — `A_daemon` model; T-L1/T-L2/T-L3/T-L4; L-4 (cleartext cross-check); L-5 (race-window); L-6 (fail-closed exit).
- `docs/proofs/StakeProofSoundness.md` — SP-1/SP-2/SP-3 (the `s:` value-hash-decode sibling — CR analogs).
- `docs/proofs/ReceiptInclusionProofSoundness.md` — RI-1/RI-2/RI-3/RI-4/RI-5 (the `i:` composite-key sibling — shared transport + one-sided boundary).
- `docs/proofs/MergeStateSoundness.md` — MS-1..MS-6 (the `m:` apply + snapshot dual; F-3 width asymmetry).
- `docs/proofs/ParamChangeDeterminism.md` — PC-1..PC-3 (the `p:` apply + snapshot dual).
- `docs/proofs/GovernanceWhitelistSoundness.md` — GW-1/GW-2/GW-3 (the `p:` legality frame).
- `docs/proofs/GovernanceParamChange.md` — the `stage_param_change` staging primitive + activation drain.
- `docs/proofs/UnderQuorumMerge.md` (FA9) — the `m:` R7 merge-safety frame.
- `docs/proofs/BlockchainStateIntegrity.md` — S-021 + S-033 + S-038 four-surface composition (chain-level prerequisite).

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` Merkle-leaf table (`m:`/`p:` rows).
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC contract.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` caller-trust invariant (CR-4).
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (A1).
