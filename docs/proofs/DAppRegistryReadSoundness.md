# DAppRegistryReadSoundness — trust-minimized `d:`-namespace DApp-registry read soundness (DR-1..DR-6)

This document formalizes the soundness of a **trust-minimized DApp-registry read** by the light client: an operator (or DApp client) learns a domain `D`'s on-chain `DAppEntry` — its `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, and the `(registered_at, active_from, inactive_from)` lifecycle anchors — from a *single untrusted daemon* and verifies it locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client act on a forged DApp registration (a substituted `service_pubkey` for payload-encryption, a spoofed `endpoint_url`, a fabricated active/deactivated lifecycle, or an unsupported `topics` set). The read targets the `d:` (DApp-registry) namespace of the S-033 state-commitment surface.

The proof exists because the `d:` namespace **extends the trustless-read family across the content-bearing namespaces**: the simple-key value-bearing reads (`a:` — `LightClientThreatModel.md` T-L4; `s:` — `StakeProofSoundness.md`; `c:` — `SupplyProofSoundness.md`), the composite-key presence-marker read (`i:` — `ReceiptInclusionProofSoundness.md`), and the composite-key content-bearing reads (`m:`/`p:` — `CompositeStateReadSoundness.md`). (The `r:` registrants namespace — the validator set the committee is drawn from — got its trustless reader last, via `determ-light verify-registrant`, completing the simple-key family `a:`/`s:`/`d:`/`r:`; its `r:`-leaf cross-check mirrors this `d:` proof's value-hash binding over `ed_pub ‖ registered_at ‖ active_from ‖ inactive_from ‖ region`.) The `d:` read is the **simple-ASCII-key sibling of `s:`** — its leaf key `"d:" + domain` is a human-readable domain string, not a binary composite, so it rides a JSON string raw and needs no hex-body transport (unlike `i:`/`m:`/`p:`). But its value-hash is the **richest of any namespace**: eight fields including two variable-length byte strings (`endpoint_url`, `metadata`) and a variable-length nested list (`topics`), versus the two fixed-width `u64`s of `a:`/`s:`. The proof's contribution is to fix that multi-field, variable-length value-hash encoding byte-for-byte and show the cleartext cross-check (in the style of `StakeProofSoundness.md` SP-2 / `LightClientThreatModel.md` L-4) still pins the verified leaf to the operator-asserted `DAppEntry` content with no daemon trust, despite the encoding's length-prefixed structural complexity.

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a `DAppEntry` that is inconsistent with the genesis-pinned chain's committed `d:` leaf at the verified height. The proof mirrors the `s:` read (`StakeProofSoundness.md` SP-1/SP-2/SP-3) one-for-one, specialized to the `d:` namespace and its `SHA256(service_pubkey ‖ registered_at ‖ active_from ‖ inactive_from ‖ |endpoint_url| ‖ endpoint_url ‖ |topics| ‖ {|t_i| ‖ t_i}* ‖ retention ‖ |metadata| ‖ metadata)` value-hash encoding. It is the **read-side / verification dual** of the apply-and-snapshot determinism proof `DAppRegistryLifecycle.md` (the `d:` apply + lifecycle contract, T-D1..T-D8): that proves the `d:` leaf is *deterministically produced, owner-bound by construction, and faithfully snapshot-round-tripped* (S-037); this proves a light client can *trustlessly read it back* against a committee-signed root. The read is the application-layer companion to the consensus-layer reads — a DApp client deciding which `service_pubkey` to `crypto_box_seal` a DAPP_CALL payload to, or an operator auditing whether a domain's DApp is `active`/`deactivating`/`inactive`, now has a trust-minimized path that does not require running a full node.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1, **A4** = CSPRNG §2.3) — this proof reduces to **A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-2** leaf/inner + key domain separation, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core DR-2 consumes, **MT-5** non-membership boundary is exactly the limitation DR-3 honours, and **§6.2 (S-040, CLOSED)** is the now-enforced `leaf_count` root-binding DR-4 consumes); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding DR-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding; the transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` mechanism is reused verbatim); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `d:` key + value-hash encoding read off `chain.cpp:309-330`, **T-1** confirms `dapp_registry_` is committed to the root through `d:`, and **T-2** namespace disjointness guarantees `"d:"+… ≠ "a:"+… ≠ "s:"+…` at byte 0); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the balance/nonce trustless-read flow this proof specializes — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** simple-key read with race-window mitigation, **L-4** cleartext cross-check, **L-6** fail-closed exit); `StakeProofSoundness.md` (the `s:` simple-ASCII-key value-bearing sibling — DR-1/DR-2/DR-4 are the `d:` analogs of SP-1/SP-2/SP-3, with the cleartext cross-check carried over directly because both namespaces commit real content under an ASCII domain key); `SupplyProofSoundness.md` (the `c:` simple-key sibling — DR shares its value-hash decode mechanism, differing in the leaf content and in that `c:`'s counter values race across invocations while `d:`'s fields are append-stable per registration); `CompositeStateReadSoundness.md` (the `m:`/`p:` content-bearing composite-key siblings — DR shares their value-hash cleartext cross-check, differing in the simple-ASCII-key transport: `d:` needs no hex body); `DAppRegistryLifecycle.md` (FA-Apply — T-D1..T-D8, the apply-determinism + owner-binding + deferred-deactivation + S-037 snapshot round-trip of `dapp_registry_` that produces the `d:` leaf DR-2 reads back); `S019DAppEndpointSpoof.md` (the threat-model frame for endpoint trust — the `d:` read's `service_pubkey` cross-check is the trust-minimized defense complementing the off-chain endpoint-authentication discussion); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-037 + S-038 composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-037 + §S-038 + §S-040 for the closure narratives (all CLOSED); `docs/PROTOCOL.md` §4.1.1 for the canonical `d:` Merkle-leaf row + §10.2 for the `state_proof` RPC contract + §3.3 for the DAPP_REGISTER apply rules.

---

## 1. Scope

### 1.1 In scope

A single trust-minimized read answering one question without trusting the daemon that serves the data:

> **(`d:` read)** Is domain `D` currently registered as a DApp, and if so, with which `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, and lifecycle anchors `(registered_at, active_from, inactive_from)`, at the committee-verified height?

The read's logical pipeline mirrors `read_account_trustless` (`light/trustless_read.cpp:439-599`) with the `a:`-namespace argument replaced by `"d"` and the value-hash decode replaced by the `DAppEntry` encoding:

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:55-82`): compute `compute_genesis_hash(genesis_O)` locally, fetch block 0, byte-compare. (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:234-248`, delegating to the shared `verify_chain_walk` core `:105-230`), invoking `verify_headers` + `verify_block_sigs` end-to-end from block 0. (T-L2.) This yields a committee-anchored `state_root` (SR-1).
3. **State-proof fetch for the `d:` namespace** — `rpc.call("state_proof", {{"namespace","d"},{"key",domain}})`. The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3287-3378`) explicitly handles the `"d"` namespace in the simple-key branch (`node.cpp:3314`: `if (ns == "a" || ns == "s" || ns == "r" || ns == "d" || ...)`), building the prefixed key `"d:" + domain` byte-for-byte as `build_state_leaves` does, and returning `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Merkle inclusion verify** — `verify_state_proof(proof, root)` (`light/verify.cpp:330-396`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`), the verifier re-deriving the leaf hash from the supplied `key_bytes`. (T-L3 / DR-2.)
5. **Committee-binding of the proof root (S-042)** — the proof's claimed `state_root` is bound to a committee-signed header by `committee_bound_state_root` (`light/trustless_read.cpp:335-437`): a stale-height gate (`:528-533`) rejects a proof before the verified head, then `anchor_index = proof_height − 1` (`:545`) and the helper recomputes the full anchor block's `block_hash` and requires the committee-signed **successor**'s `prev_hash` to equal it (`:424-432`) — the anchor header's own digest excludes `state_root`, so signing it does not bind it; the head fails closed (no signed successor) unless `--wait` is supplied. (T-L4 §4.4.1 / DR-1 / `StateProofRaceWindowSoundness.md` PRW-1..PRW-5.)
6. **Value-hash cleartext cross-check** — recompute the canonical `DAppEntry` value-hash from the daemon-asserted cleartext fields (fetched via the `dapp_info` RPC) and require equality against the proof's verified `value_hash`, plus require `key_bytes` to equal the locally-recomputed `"d:" + D`. (DR-2 / §4.2.1.)

The verdict:

| Verdict | Condition |
|---|---|
| `VERIFIED` | steps 1–6 pass: the `d:` leaf is committed under the committee-signed `state_root`, with `key_bytes` matching the locally-recomputed `"d:" + D` and `value_hash` matching the recomputed `DAppEntry` encoding. The `DAppEntry` is committee-anchored truth. |
| `UNVERIFIABLE` | any of: genesis anchor fails (T-L1); header sig/continuity fails (T-L2); `merkle_verify` rejects; the daemon returns `not_found`/`error` (the domain is *unregistered as a DApp*, OR the daemon is withholding — **indistinguishable**, §4.3); a committee not in the seed map (§6.2 caveat); or any RPC/parse error. |

There is **no positive `NOT-REGISTERED` verdict** — see §1.3 and DR-3. Absence is *not* a cryptographically provable statement under the sorted-leaves primitive (`MerkleTreeSoundness.md` MT-5); a daemon withholding a genuine `d:` leaf is indistinguishable from a genuinely-absent leaf. The read is therefore **one-sided**: it can prove `VERIFIED` cryptographically, but the negative is always `UNVERIFIABLE`, never an authoritative `NOT-REGISTERED`.

### 1.2 The `d:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:309-330`):

```cpp
// v2.18 Theme 7: dapp_registry_ (key = "d:" + domain).
for (auto& [domain, e] : dapp_registry_) {
    crypto::SHA256Builder b;
    b.append(e.service_pubkey.data(), e.service_pubkey.size());     // 32 raw bytes
    b.append(e.registered_at);                                      // uint64, big-endian
    b.append(e.active_from);                                        // uint64, big-endian
    b.append(e.inactive_from);                                      // uint64, big-endian
    b.append(static_cast<uint64_t>(e.endpoint_url.size()));         // len prefix u64_be
    b.append(e.endpoint_url);                                       // utf8 bytes
    b.append(static_cast<uint64_t>(e.topics.size()));               // topic count u64_be
    for (auto& t : e.topics) {
        b.append(static_cast<uint64_t>(t.size()));                  // per-topic len u64_be
        b.append(t);                                                // topic bytes
    }
    b.append(static_cast<uint64_t>(e.retention));                   // retention byte promoted to u64_be
    b.append(static_cast<uint64_t>(e.metadata.size()));             // metadata len u64_be
    if (!e.metadata.empty()) b.append(e.metadata.data(), e.metadata.size());
    leaves.push_back({k_with_prefix("d:", domain), hash_bytes(b)});
}
```

so for a registered DApp at domain `D` with entry `e`:

$$
\text{key}_d(D) \;=\; \texttt{"d:"} \,\|\, D \quad(\text{ASCII domain, no hex body}),
$$

$$
\begin{aligned}
\text{value\_hash}_d(e) \;=\; H\big(\,
&\texttt{service\_pubkey}[32] \,\|\, u64\_be(\texttt{registered\_at}) \,\|\, u64\_be(\texttt{active\_from}) \,\|\, u64\_be(\texttt{inactive\_from}) \\
&\|\, u64\_be(|\texttt{endpoint\_url}|) \,\|\, \texttt{endpoint\_url} \\
&\|\, u64\_be(|\texttt{topics}|) \,\|\, \big[\,u64\_be(|t_i|) \,\|\, t_i\,\big]_{i} \\
&\|\, u64\_be(\texttt{retention}) \,\|\, u64\_be(|\texttt{metadata}|) \,\|\, \texttt{metadata}\,\big).
\end{aligned}
$$

The source container is `dapp_registry_ : std::map<std::string, DAppEntry>` (`include/determ/chain/chain.hpp:549`, `DAppEntry` at `chain.hpp:46-81`), keyed by the DApp's owning Determ domain; **absence from the map is the canonical NOT-REGISTERED state**. This is exactly the `d:` row of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 and `PROTOCOL.md` §4.1.1.

**The load-bearing structural fact for `d:` (the variable-length, length-prefixed value-hash).** Unlike `a:`/`s:` (two fixed-width `u64`s) and `m:`/`p:` (a fixed-width composite plus one or two length-prefixed strings), the `d:` value-hash preimage contains **three** sources of variable length — `endpoint_url`, the `topics` list (variable count, each entry variable length), and `metadata` — and the `retention` byte is promoted to a `u64`. Every variable-length field is **length-prefixed** by a `u64_be` count immediately before its bytes, and the `topics` list is preceded by a `u64_be` element count before the per-element `(len, bytes)` pairs. This length-prefixing is what makes the encoding **injective** (T-D3-class: no two distinct `DAppEntry` values collide on the preimage without a length ambiguity), and it is what a cross-implementation `d:`-leaf verifier MUST reproduce field-for-field — a verifier that omitted the topic-count prefix, or wrote `retention` as a single byte instead of a `u64`, or reordered the fields, would compute a different `value_hash` and reject a genuine leaf. DR-2's cleartext cross-check (§4.2.1) is stated against this exact canonical preimage. (This is the read-side mirror of the apply-side injectivity that `DAppRegistryLifecycle.md` T-D1/T-D2 rely on when proving the entry's fields round-trip deterministically.)

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-membership (the negative).** A light client *cannot* prove "domain `D` is **not** a registered DApp" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). A daemon withholding a genuine `d:` leaf is indistinguishable from a genuinely-absent one. This is the **same** boundary as `StakeProofSoundness.md` §6.1 (unstaked domains), `ReceiptInclusionProofSoundness.md` §6.1 (non-applied receipts), `CompositeStateReadSoundness.md` §6.1 (not-merged / not-staged), and `TxInclusionProofSoundness.md` §6.3 (per-height membership). DR-3 records it honestly; the read never emits an authoritative `NOT-REGISTERED`. (The general negative-verdict frame is `NegativeVerdictSoundness.md` NV-2/NV-3.)
- **Lifecycle *interpretation* beyond the committed fields.** The `d:` read returns `(active_from, inactive_from)`; whether the DApp is currently `active` / `deactivating` / `inactive` at the verifier's wall-clock is a *derived* predicate (`inactive_from <= current_height`, the DAPP_CALL gate of `DAppRegistryLifecycle.md` T-D6) that the operator computes from the verified fields plus the committee-verified head height. The read proves the *fields* are committee-anchored; the lifecycle classification is a deterministic function of them, not a separate trust assumption. §6.5 records this.
- **`service_pubkey` cryptographic validity + endpoint authenticity.** The read proves the chain committed *this* `service_pubkey` and *this* `endpoint_url` for domain `D`; it does **not** prove the `service_pubkey` is a sound libsodium box key, nor that the live server at `endpoint_url` is actually operated by `D`'s owner (an off-chain network-layer property). The on-chain commitment defeats a daemon *substituting* a different key/URL than the chain committed; it does not defeat the DApp owner registering a malicious key, nor a MITM on the endpoint connection. `S019DAppEndpointSpoof.md` covers the endpoint-trust frame; the `d:` read is the trust-minimized *retrieval* half (the operator learns the committed key without trusting the serving daemon), composed with the off-chain authentication the operator performs against the recovered key. §6.4 records this.
- **The mutating side of the registry** (the DAPP_REGISTER op=0 create/update + op=1 deferred-deactivate apply rules, owner-binding-by-`tx.from`-keying, the `DAPP_GRACE_BLOCKS` deferral, the NEF non-drain). Those are apply-layer correctness (`DAppRegistryLifecycle.md` T-D1..T-D8); this proof reads the *committed* `d:` leaf and does not re-prove how it got there.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1–§6.7. Within one invocation the race-window mitigation (DR-1 / L-5 / PRW-1..PRW-5) is sound; cross-invocation head-regression is operator-visible but not auto-detected.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged `dapp_info` replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM — including a MITM on the off-chain endpoint connection, §6.4), `A_genesis` (tampered pinned `genesis.json`).

Specialized to the `d:` read, `A_daemon` will attempt one of:

- **(a) False-registration.** Convince the verifier that domain `D` has a DApp with `service_pubkey'` / `endpoint_url'` / `topics'` (when it has different committed fields, or none) — e.g., to make a DApp client encrypt a DAPP_CALL payload to an attacker-controlled `service_pubkey'` (so the attacker can decrypt it), or to redirect the client to a malicious `endpoint_url'`, or to misrepresent the active/deactivated lifecycle so a client sends to a DApp the chain has deactivated.
- **(b) Suppressed-registration.** Convince the verifier that a genuine registration is *not provably present* — landing the verifier in `UNVERIFIABLE`, **not** in a false `NOT-REGISTERED` (§1.3 / DR-3). So (b) is an *availability/honesty* downgrade, never a *soundness* break.

**Security goal.** Under `A_daemon`, an honest light client running the `d:` read:

- never returns `VERIFIED` for a `DAppEntry` not genuinely committed in the `d:` leaf set of the genesis-pinned chain at the verified height;
- never acts on a substituted leaf — any leaf whose recomputed Merkle path does not roll up to the committee-signed `state_root`, or whose `key_bytes`/`value_hash` do not match the canonical encoding for the queried domain, yields `UNVERIFIABLE`, never a verdict.

"Acts on" means *displays as authoritative*, *encrypts a payload to the recovered `service_pubkey`*, *connects to the recovered `endpoint_url`*, or *feeds the lifecycle classification into a downstream decision*. The negation form is **fail-closed exit**: any detected inconsistency throws and propagates to a non-zero process exit with a structured stderr diagnostic (inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

The read reuses the four light-client primitives unchanged — genesis anchor (`LightClientThreatModel.md` §3.1), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies with the state-proof stage targeting the simple ASCII key `key_d(D) = "d:" + D`. Two specializations distinguish the `d:` read from the balance read:

1. **Namespace argument + simple-ASCII-key transport.** The state-proof query is `{{"namespace","d"},{"key",D}}` with `D` the plain ASCII domain — **no hex-body encoding** (unlike the composite `i:`/`m:`/`p:` reads of `ReceiptInclusionProofSoundness.md` §1.4 / `CompositeStateReadSoundness.md` §1.2). The daemon's simple-key branch (`node.cpp:3314-3322`) prepends `"d:"` and forwards. This is the *same* simple-key transport as `a:`/`s:`/`r:`/`b:`/`k:`; the `d:` namespace is explicitly enumerated in that branch.

2. **Multi-field, variable-length value-hash with a cleartext cross-check.** Unlike `a:`/`s:` (two `u64`s) or `i:` (the identity-free constant `SHA256(0x01)`), the `d:` leaf commits a rich `DAppEntry` in the value-hash, so the verifier performs the cleartext cross-check of `StakeProofSoundness.md` SP-2 / `LightClientThreatModel.md` L-4: recompute the canonical preimage of §1.2 from the daemon-asserted `DAppEntry` fields (fetched via `dapp_info`) and require equality against the proof's verified `value_hash`. A daemon lying about any field — `service_pubkey`, `endpoint_url`, a topic, `retention`, `metadata`, or any lifecycle anchor — while serving an honest proof must find a colliding value-hash (A2).

Crucially, the daemon delivers `state_root`, `leaf_count`, `target_index`, `value_hash`, the sibling vector, and `key_bytes` such that the light client binds the proof's `state_root` to a committee-signed header in the *same* invocation via the S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`), and `leaf_count` is itself bound into the committed root via the S-040 root-wrapper hash (`SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)`) — so a forged count is rejected regardless of source. This root-binding is the property DR-4 formalizes (S-040 CLOSED).

---

## 4. Security theorems

Throughout, fix the queried domain `D`, `key_d(D) = "d:" ‖ D`, and `e_T` the true committed `DAppEntry` for `D` (with true value-hash `value\_hash_d^T(e_T)`). Let `R := state_root(h)` be the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to. The chain's *true* committed registry at height `h` is `\mathcal{D}_T(h)`; `D` is genuinely registered iff `key_d(D)` is a leaf of the tree `R` commits to.

### 4.1 Theorem DR-1 (committee-signed `state_root` binds the `d:` leaf)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that the `d:` read anchors and verifies the proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root the `d:` leaf is checked against is *committee-certified*, not daemon-asserted.

**Proof.** This is `StateRootAnchorSoundness.md` **SR-1** applied at the height the `d:` proof is anchored at, identical to `StakeProofSoundness.md` SP-1, `ReceiptInclusionProofSoundness.md` RI-1, and `CompositeStateReadSoundness.md` CR-1's inline anchoring at `trustless_read.cpp:409-415`. The binding of `state_root(h)` to the committee is **transitive-forward**, not a direct signature: the committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp::compute_block_digest`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root` (the `light/verify.cpp` digest-exclusion comment). `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim) and hence into `block_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`:

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

Suppose the invocation anchors `R_A ≠ state_root_T(h)`. The SR-1 case split (reproduced for the `d:`-proof anchoring at `trustless_read.cpp:335-437`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`.** The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).
- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. To accept `h+1` with a different `prev_hash`, the daemon must present `required ≤ K` valid signatures over a different digest — an Ed25519 forgery for each of `required` distinct committee members, `≤ K · 2⁻¹²⁸` (A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* is supplied by SR-2 + SR-3 + T-L1's genesis anchor; DR-1 inherits them.

**Head-block boundary.** If the operator queries a DApp at the chain *head*, that block's `state_root` has no signed successor yet, so it is committee-certified only once a successor is produced; under S-042 the shipped flow **fails closed** at the head — `committee_bound_state_root` throws when no committee-signed successor exists (`trustless_read.cpp:388-401`) — unless `--wait <seconds>` is supplied to poll for the next block before binding the held proof (`LightClientThreatModel.md` L-5; `StateProofRaceWindowSoundness.md` PRW-1..PRW-3). DR-2 below proves Merkle-path soundness *given* such an `R`; DR-1 is the committee-binding of `R`.

**Concrete-security bound.** `Pr[A_daemon wins DR-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem DR-2 (Merkle state-proof for the `d:` leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from DR-1, a verifier holding `R` cannot be made to accept `VERIFIED` for a queried domain `D` whose `d:` leaf (`key_d(D)`) is **not** committed under `R`, nor accept a wrong `DAppEntry` cleartext, without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; key_d(D),\; value\_hash_{\text{served}},\; target\_index,\; n,\; proof) = \texttt{true}
\quad\wedge\quad value\_hash_{\text{served}} = H(\text{preimage}(e_A)),
$$

then either (a) `key_d(D)` is a genuine leaf of the tree `R` commits to at sorted position `target_index` with the genuine committed entry `= e_A`, or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves `D`'s DApp is registered with the asserted `DAppEntry`, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as DR-1: the light client has anchored committee-signed `R`.
2. `A_daemon` returns a state-proof `P_A = (key_bytes_A, value\_hash_A, target\_index, n, proof)` claiming the domain is registered with entry `e_A` when it is not. It may (i) serve a genuine leaf for some *other* registered domain and relabel it, (ii) serve a non-`d:` leaf (e.g. an `a:` or `s:` leaf for the same domain) with a forged `key_bytes`, (iii) serve a `value\_hash_A` inconsistent with the `e_A` it asserts, or (iv) alter `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true` **and** the verdict is `VERIFIED`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the `d:` leaf, equivalently `LightClientThreatModel.md` T-L3 specialized, plus the **MT-2** leaf-key domain separation. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value\_hash_A, target\_index, n, sibs)` (`light/verify.cpp:378-380`), which recomputes the leaf hash

$$
c_0 = \text{merkle\_leaf\_hash}(key_bytes, value\_hash_A) = H(\texttt{0x00} \| u32\_be(|key_bytes|) \| key_bytes \| value\_hash_A)
$$

and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R` (`merkle.cpp:139`).

The verifier additionally requires `key_bytes = key_d(D)` (the locally-recomputed `"d:" + D`, §4.2.1) **and** `value\_hash_A = H(\text{preimage}(e_A))` for the asserted entry. With those equalities pinned, the recomputed `c_0` is *exactly* the genuine `d:` leaf hash for `D` iff the committed entry equals `e_A`. By MT-4's extraction: if the leaf for `key_d(D)` with value-hash `value\_hash_A` is **not** committed under `R`, then the recomputed chain and the genuine root-path chain for sorted position `target_index` both terminate at `R` but disagree, exhibiting two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` mapping to the same `H` output at the highest divergence level — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** defeats the four attack shapes:

- **(i) relabel another domain's leaf.** The daemon serves the genuine `d:` leaf for a *different* registered domain `D' ≠ D`, but the verifier's recomputed `c_0` uses `key_d(D)` for the *queried* domain; since distinct domains have distinct length-prefixed keys (`"d:" + D ≠ "d:" + D'`), the recomputed leaf hash composes the served siblings into a *different* chain and fails root-equality. By MT-2's unambiguous length-prefixed key encoding, a pass requires a leaf-level collision (`≤ 2⁻¹²⁸`).
- **(ii) cross-namespace swap.** The daemon serves an `a:`/`s:`/`r:`/… leaf's siblings (e.g. the *account* leaf for the *same* domain `D`) and a forged `key_bytes`. The verifier recomputes the leaf hash over `key_d(D)`, which begins with the `"d:"` prefix; by `S033StateRootNamespaceCoverage.md` **T-2** namespace disjointness, `"d:"+D ≠ "a:"+D` (and `≠ "s:"+D`, `≠ "r:"+D`) at byte 0, so the recomputed leaf hash differs from any cross-namespace leaf's hash, producing a different sibling chain and failing root-equality. This is the same cross-namespace-swap rejection `StakeProofSoundness.md` SP-2 and `CompositeStateReadSoundness.md` CR-2 invoke (the `test_state_proof_namespaces.sh` swap assertions). The `d:` case is *especially* relevant because the **same** domain string `D` keys both an `a:` account leaf and a `d:` DApp leaf — only the namespace byte distinguishes them, and T-2's byte-0 disjointness is exactly what prevents an account-leaf proof from being relabeled as a DApp-leaf proof.
- **(iii) value-hash / cleartext inconsistency.** The verifier recomputes `H(\text{preimage}(e_A))` over the full §1.2 length-prefixed preimage and rejects unless it equals `value\_hash_A`; a daemon asserting a `DAppEntry` that does not hash to the served value-hash is caught at the §4.2.1 cross-check. And a daemon serving a `value\_hash_A` that does *not* match the genuine committed value-hash changes `c_0` and (by MT-4) fails root-equality against `R`. So a daemon lying about the `service_pubkey`, `endpoint_url`, any topic, `retention`, `metadata`, or any lifecycle anchor while serving an honest proof must find a colliding value-hash — A2 (`≤ 2⁻¹²⁸`). This is the step the `i:` read cannot offer (`ReceiptInclusionProofSoundness.md` RI-2's "no cleartext cross-check"): because `d:` commits real content, the verified statement is *"domain `D` is registered with this specific `DAppEntry`,"* not merely *"`D` is present."* The injectivity of the §1.2 length-prefixed preimage (every variable-length field length-prefixed) ensures a single canonical preimage per `DAppEntry`, so the cross-check is unambiguous.
- **(iv) index / sibling tamper.** Covered by MT-4's range/underflow/exact-consume gates exactly as in SP-2 / RI-2 / CR-2 (`MerkleTreeSoundness.md` §2.6 scenarios #5-#8; `determ test-merkle-proof-tampering`).

By `S033StateRootNamespaceCoverage.md` **T-1**, the `dapp_registry_` map is bound to the root through `d:`, so the leaf DR-2 verifies is the genuine committed DApp registration. The leaf this read returns is exactly the leaf `DAppRegistryLifecycle.md` T-D1/T-D2 prove is deterministically produced (and T-S2 / S-037 prove is faithfully snapshot-round-tripped) — DR-2 is the trustless read-back of those apply-side guarantees.

**Concrete-security bound.** `Pr[A_daemon wins DR-2] ≤ log₂(n) · 2⁻¹²⁸`; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`.   ∎

#### 4.2.1 The key + value-hash cross-check (why `VERIFIED` is crisp)

Two equalities, both computable by the verifier with **no daemon trust**, convert "a Merkle proof verified against `R`" into "domain `D` is registered with this specific `DAppEntry`":

1. **Key equality.** `key_bytes == key_d(D)`, where `key_d(D) = "d:" + D` is built locally from the operator's `--domain` argument. The verifier re-derives the canonical key and byte-compares against the daemon-returned `key_bytes`, rejecting any mismatch — pinning the proven leaf to *this* domain `D`. (Because the same `D` also keys the `a:`/`s:`/`r:` leaves, the namespace byte in `key_d(D)` is load-bearing — §4.2.1's recomputation includes the `"d:"` prefix, and T-2 disjointness makes a cross-namespace relabel fail.)
2. **Value-hash equality.** `value_hash == H(\text{preimage}(e_A))`, where the verifier recomputes the canonical §1.2 preimage (`service_pubkey ‖ registered_at ‖ active_from ‖ inactive_from ‖ |endpoint_url| ‖ endpoint_url ‖ |topics| ‖ {|t_i| ‖ t_i}* ‖ retention ‖ |metadata| ‖ metadata`) from the daemon-asserted `DAppEntry` fields. This confirms the leaf commits the asserted entry and not some other content. The **field order, the `u64_be` width of every length prefix and of the promoted `retention` byte, and the topic-count-then-per-topic-(len,bytes) nesting** are all part of the canonical preimage; a verifier that deviates computes a different hash and (safely) rejects a genuine leaf.

With (1)+(2) pinned and DR-2's root-equality, `VERIFIED` means exactly *"the leaf `(key_d(D), H(\text{preimage}(e_A)))` is committed under the committee-signed `R`."* The verifier emits `VERIFIED` only on this conjunction; any failure of (1), (2), DR-1, or DR-2 yields `UNVERIFIABLE` (fail-closed, DR-5).

### 4.3 Theorem DR-3 (one-sided verifier; sound non-membership is NOT provable — honesty boundary)

**Statement.** The `d:` read is a **one-sided** verifier: it can establish `VERIFIED` cryptographically (DR-1 + DR-2), but **cannot** establish an authoritative `NOT-REGISTERED`. A daemon that returns `not_found`/`error` for the queried domain — or otherwise withholds the leaf — leaves the verifier in `UNVERIFIABLE`, which is *indistinguishable* between "the domain is genuinely not a registered DApp" and "the daemon is suppressing a genuinely-present registration." No false negative is ever emitted, because none exists to emit.

**Analysis.** The sorted-leaves balanced binary Merkle primitive supports **positive membership only** (`MerkleTreeSoundness.md` **MT-5**): there is no native non-membership (absence) proof. `Chain::state_proof` returns `std::nullopt` for an absent key (`chain.cpp:449`), surfaced by the daemon as `{"error":"not_found"}` (`node.cpp:3358-3361`). An honest light client receiving this can only conclude *"this daemon did not give me a proof,"* which an all-Byzantine peer set could produce by withholding. This is the **same** MT-5 boundary `StakeProofSoundness.md` §6.1, `ReceiptInclusionProofSoundness.md` §6.1, `CompositeStateReadSoundness.md` §6.1, and `TxInclusionProofSoundness.md` §6.3 honour, inherited unchanged.

**Why the asymmetry is sharp here.** Absence-of-leaf semantically *is* NOT-REGISTERED (`dapp_registry_.find(D) == end()`). Yet "leaf absent" is exactly the statement the primitive cannot attest. The gap is not in the chain's bookkeeping (which is exact — `DAppRegistryLifecycle.md` T-D1/T-D7 prove the map is a faithful, owner-bound, per-domain-independent function of the apply trace) but in the *proof system's* inability to prove absence. The read therefore reports `UNVERIFIABLE` for the negative and lets the operator fall back to a multi-peer cross-check, with the attendant trust cost. A subtle but important corollary for DApp clients: a `not_found` MUST NOT be treated as "the DApp is safely gone" — a deactivated-but-withheld registration looks identical to a never-registered one, so a client relying on the negative could be steered toward treating an active malicious DApp as nonexistent. The caller contract of `NegativeVerdictSoundness.md` NV-6 applies: a `d:` `NOT-REGISTERED`/`not_found` is "no membership proof obtained" (`≈ UNVERIFIABLE`) for value-affecting decisions, never authoritative absence.

**Consequence for the threat model.** Attack §2(b) (suppressed-registration) cannot produce a *false* answer — it produces `UNVERIFIABLE`, which is operator-visible and actionable. The soundness goal (§2) — never a false `VERIFIED`, never act on a substituted leaf — is fully met; the *completeness* gap (a withholding daemon forces `UNVERIFIABLE`) is an availability limitation, not a soundness one.   ∎

### 4.4 Theorem DR-4 (`leaf_count` is bound into the committed root — S-040 CLOSED)

**Statement.** DR-2's soundness is stated with `n` = the *genuine* leaf count of the tree `R` commits to. **S-040 is CLOSED:** `crypto::merkle_root` binds `leaf_count` into the committed root via a root-wrapper hash `root = SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`; `0x02` domain-separated from the `0x00` leaf / `0x01` inner tags), and `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the **caller-supplied** `leaf_count`, and compares to the committed root. A forged `leaf_count` (`M ≠ n`) therefore yields a different wrapper hash and is **rejected** regardless of where the verifier sourced the count from. The former obligation — source `leaf_count` from the same committee-anchored origin as `state_root` — is now enforced by the hash, not merely a caller guideline. The light client inherits this because `verify_state_proof` calls `crypto::merkle_verify` directly (`light/verify.cpp:378-380`).

**How the binding works.** `merkle_verify` consumes `leaf_count` to drive the number of levels and the per-level duplication parity (`merkle.cpp:130-138`), and *additionally* feeds it into the root-wrapper recomputation. A verifier handed `(target_index, leaf_count)` that does not match the count committed into `R`'s wrapper recomputes a wrapper hash `≠ R` and rejects — even when the inner-tree walk shape would otherwise coincide. The concrete rejection is pinned by `determ test-merkle-proof-tampering` scenario #12 (forged `leaf_count` REJECTED).

**Why the shipped flow is sound.** The proof envelope returns `state_root`, `leaf_count`, `target_index`, `value_hash`, and `proof` as fields of **one** JSON object, with `leaf_count = build_state_leaves().size()` (`chain.cpp:456`) — the genuine count for the very tree whose root is `compute_state_root()` in the same reply (`node.cpp:3375`). The light client anchors *that reply's* `state_root` to a committee-signed header (DR-1) in the same invocation, then verifies the `d:` proof against the anchored root. Because `leaf_count` is bound into the wrapper, even a split-source integrator could not be fooled. The daemon gains no ability to substitute a *wrong* domain's content (DR-2) nor to forge the leaf's tree-position via a mismatched `leaf_count` (this theorem); the `key_d(D)`-binding of DR-2 still ties the accepted leaf to the queried domain.

**Status.** S-040 is **CLOSED** (shipped pre-launch as a wire-compat break — every `state_root` value changed; there is no installed base). `leaf_count` is cryptographically bound into the committed root; a forged count is rejected by the hash, so there is no residual caller-trust obligation and no deferred structural fix (`MerkleTreeSoundness.md` §6.2). DR-4 is a cryptographic-binding theorem, not an operational caveat.

**Concrete-security bound.** DR-4 adds no independent term beyond DR-1 + DR-2; the wrapper binding folds into the same A2 collision reduction (forging a `leaf_count` that re-wraps to the genuine `R` is a SHA-256 collision, `≤ 2⁻¹²⁸`).   ∎

### 4.5 Lemma DR-5 (fail-closed exit)

**Statement.** Any signature failure, chain break, genesis mismatch, malformed proof, `not_found`/`error` reply, `key_bytes ≠ key_d(D)`, value-hash/cleartext mismatch, or `merkle_verify` rejection causes the read to exit non-zero with a structured diagnostic (verdict `UNVERIFIABLE`) — never a bare daemon-asserted `VERIFIED`.

**Proof.** By inheritance from `LightClientThreatModel.md` Lemma **L-6** for the reused T-L1/T-L2/T-L3 surfaces (`verify_headers`, `verify_block_sigs`, `verify_state_proof` each set `r.ok=false` + `r.detail` on every error branch and return to a caller that throws; `anchor_genesis` throws on genesis mismatch), plus the §4.2.1 structural property that `VERIFIED` is reached *only* on the conjunction (DR-1 anchored ∧ DR-2 root-equality ∧ key-equality ∧ value-hash-equality). The simple-key daemon-side `not_found` (`node.cpp:3358-3361`) surfaces as an RPC error caught at the read's `proof.contains("error")` branch (mirroring `trustless_read.cpp:469-473`) → `UNVERIFIABLE`. There is no code path from a detected inconsistency to `VERIFIED`. This is the per-command instance of L-6; the throw-discipline is structural.   □

### 4.6 Theorem DR-6 (lifecycle classification is a sound derived predicate)

**Statement.** Given a `VERIFIED` `DAppEntry` (DR-1 + DR-2) at committee-verified head height `h`, the lifecycle classification

$$
\text{state}(D, h) = \begin{cases}
\texttt{active} & \texttt{inactive\_from} = \texttt{UINT64\_MAX} \\
\texttt{deactivating} & \texttt{inactive\_from} < \texttt{UINT64\_MAX} \;\wedge\; h < \texttt{inactive\_from} \\
\texttt{inactive} & h \ge \texttt{inactive\_from}
\end{cases}
$$

is a **deterministic function of the committee-anchored fields** `(inactive_from)` and the committee-verified head height `h`, and matches the chain's own DAPP_CALL apply-time gate (`DAppRegistryLifecycle.md` T-D6, `chain.cpp:1142`: `dapp.inactive_from <= height`). It introduces **no additional trust assumption** beyond DR-1 + DR-2: both inputs are committee-certified (the `inactive_from` field via the `d:` value-hash cross-check, the head height `h` via the verified-chain walk).

**Proof.** `inactive_from` is one of the eight fields committed in the §1.2 value-hash preimage, so DR-2's value-hash cross-check certifies its value under the committee-signed root. The head height `h` is `vc.height` from the verified header walk (T-L2 / `trustless_read.cpp:105-230`), bound to the committee by the per-block sig check. The classification is a pure comparison `h <?> inactive_from` against the sentinel — identical to the on-chain gate at `chain.cpp:1142` that `DAppRegistryLifecycle.md` T-D6 proves governs whether a DAPP_CALL to `D` is credited or silently rejected. Since both operands are committee-certified and the predicate is a deterministic comparison, the classification a light client computes from a `VERIFIED` read agrees byte-for-byte with what a full node would compute at the same height. No daemon can present a `VERIFIED` entry whose `inactive_from` differs from the committed value (DR-2 (iii)), so no daemon can flip the classification. The one residual subtlety is the **race-window honesty boundary** (§6.3): a DApp can transition `deactivating → inactive` purely as a function of `h` advancing, with no apply event (T-D6); a verifier reading at head height `h_0` classifies for `h_0`, and the classification is only as current as the verified head — a stale head (operator-visible per §6 / `LightClientThreatModel.md` §6.1) would classify against an old `h`. Within one invocation against a non-stale head, the classification is sound.   ∎

**Why this matters for the DApp-client use case.** The dominant consumer of the `d:` read is a DApp client deciding whether to send a DAPP_CALL to `D`. T-D6 establishes that the chain silently rejects (and does not credit) a DAPP_CALL to a DApp with `inactive_from <= height`. DR-6 lets the *client* compute that same gate trustlessly **before** spending a fee on a DAPP_CALL that the chain would reject — turning the on-chain apply-time gate into a pre-flight check the client can run against a single untrusted daemon. This is the read-side dual of T-D6's apply-side gate.

### 4.7 End-to-end composition

**Corollary DR-E (trust-minimized DApp-registry read).** Under A1 + A2, the `d:` read yields a `VERIFIED` verdict bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis (or a fail-closed `UNVERIFIABLE`). Composing DR-1 (committee-anchored root) + DR-2 (`d:` Merkle inclusion + key/value-hash binding) + DR-4 (root-bound `leaf_count`, S-040 CLOSED) + DR-6 (sound lifecycle derivation) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline:

$$
\Pr[A_{\text{daemon}} \text{ wins DR-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4, the stake-read bound of `StakeProofSoundness.md` SP-E, the receipt-read bound of `ReceiptInclusionProofSoundness.md` RI-E, and the merge/param-read bound of `CompositeStateReadSoundness.md` CR-E exactly, as expected: the `d:` read differs only in the key construction (simple ASCII) and the leaf encoding (the rich `DAppEntry` value-hash), both namespace-agnostic in every cryptographic step. DR-E covers the *positive* (`VERIFIED`) verdict only; the negative is always `UNVERIFIABLE` per DR-3.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

DR-2 *is* MT-4 applied at the `d:` leaf, with **MT-2** (leaf/inner + key domain separation) carrying the cross-namespace-swap rejection (especially the `a:`-leaf-vs-`d:`-leaf-for-the-same-domain case) and the relabel rejection (distinct domains ⇒ distinct keys). MT-1 (determinism) guarantees the `d:` leaf's position and the root are reproducible across honest nodes; MT-3 (collision-resistance inheritance) makes any wrong committed registry produce a different root. DR-3 is the `d:`-namespace statement of MT-5's positive-only boundary; DR-4 is the `d:`-read-specific statement of MT-4's §6.2 (S-040 CLOSED) `leaf_count` root-binding.

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

DR-1 *is* SR-1 applied at the height the `d:` proof is anchored at, plus SR-2 (genesis-binding) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism (`state_root` is **not** in `compute_block_digest`; it is committee-bound transitively forward via the successor block's signed digest); DR-1 names the `d:` read as a consumer of it, exactly as `LightClientThreatModel.md` T-L4 does for the `a:` read.

### 5.3 `S033StateRootNamespaceCoverage.md` — the namespace surface

**T-1** (coverage completeness) confirms `dapp_registry_` is committed to the root through `d:` (and through *no other*, by **T-2** disjointness), so the leaf DR-2 verifies is the genuine committed DApp registration. §2.1's table fixes the byte-exact `d:` key (`"d:" + domain`) + the eight-field value-hash this proof reads off `chain.cpp:309-330`. T-3 (deterministic leaf ordering) — `dapp_registry_` iterates by ascending `domain` (std::map ordering) — + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes. The byte-0 namespace disjointness of T-2 is *especially* load-bearing for `d:` because the same domain string `D` keys leaves in four namespaces (`a:`, `s:`, `r:`, `d:`); only the prefix byte distinguishes them, and DR-2's cross-namespace-swap rejection (ii) relies on exactly that.

### 5.4 `LightClientThreatModel.md` — the adversary model and read flow

This proof specializes T-L3 (state-proof correctness) + T-L4 (simple-key read with race-window mitigation) + L-4 (cleartext cross-check) from the `a:` namespace to `d:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6 / DR-5), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. DR-E's bound equals T-L4's bound. The light client's `read_account_trustless` (`trustless_read.cpp:439-599`) is the structural template the read follows, with the `a:`-key construction replaced by the `d:` simple ASCII key and the `(balance, next_nonce)` decode replaced by the `DAppEntry` decode of §1.2.

### 5.5 `StakeProofSoundness.md` / `SupplyProofSoundness.md` / `CompositeStateReadSoundness.md` — the sibling reads

DR-1/DR-2/DR-4 are the `d:` analogs of `StakeProofSoundness.md` SP-1/SP-2/SP-3 (the `s:` read) and `CompositeStateReadSoundness.md` CR-1/CR-2/CR-4 (the `m:`/`p:` reads). DR shares the **value-hash cleartext cross-check** with both (`s:` decodes `(locked, unlock_height)`; `m:`/`p:` decode `(partner_id, region)` / `(name, value)`; `d:` decodes the full `DAppEntry`) — because all four commit real content. DR shares the **simple-ASCII-key transport** with `s:` and `c:` (no hex body), distinguishing it from the composite `i:`/`m:`/`p:` reads. The `d:` read thus sits with `s:`/`c:` on the *transport* axis (simple ASCII key) and with `s:`/`m:`/`p:` on the *content* axis (rich value-hash decode), and is the **richest value-hash** of the family — eight fields, three of them variable-length. This is exactly the gap the lane fills: the prior siblings cover at most two fixed-width values (`a:`/`s:`) or a fixed composite plus one/two strings (`m:`/`p:`); `d:` exercises a multi-field, variable-count, length-prefixed encoding, and DR-2 (iii) proves the cleartext cross-check remains unambiguous under that complexity via the injectivity of the length-prefixed preimage. The `d:` read completes the trustless-read family across **every** queryable S-033 namespace (`a:`/`s:`/`r:`/`d:`/`b:`/`k:`/`c:` simple + `i:`/`m:`/`p:` composite).

### 5.6 `DAppRegistryLifecycle.md` — the apply-side dual

`DAppRegistryLifecycle.md` (T-D1..T-D8) proves the *production-side* guarantee for `d:`: `dapp_registry_` is a deterministic function of the DAPP_REGISTER tx multiset (T-D1/T-D2), owner-bound by `tx.from`-keying with no cross-domain write reachable (T-D3/T-D5/T-D7), deferred-deactivated by exactly `DAPP_GRACE_BLOCKS` (T-D4), gated at DAPP_CALL apply-time on `inactive_from <= height` (T-D6), A1-invariant under the fee-only-debit channel (T-D8), and faithfully snapshot-round-tripped (S-037, `SnapshotEquivalence.md` L-S0 row `d:`). This read is the **read-back dual**: T-D say "the `d:` leaf is deterministically produced, owner-bound, and faithfully preserved," and DR-2 says "a holder of the committee-signed `state_root` can *confirm* that leaf trustlessly." DR-6 specifically is the read-side mirror of T-D6 — T-D6 proves the chain gates DAPP_CALL crediting on `inactive_from <= height`; DR-6 lets a light client compute that same gate as a sound pre-flight predicate. The two are duals — apply-side determinism + read-side verifiability.

### 5.7 `S019DAppEndpointSpoof.md` — the endpoint-trust frame

The `d:` read defeats a daemon *substituting* the committed `service_pubkey` / `endpoint_url` for a domain (DR-2 (iii)); it does **not** defeat a DApp owner registering a malicious key, nor a MITM on the live endpoint connection (§6.4). `S019DAppEndpointSpoof.md` frames the endpoint-trust surface; the `d:` read is the trust-minimized *retrieval* primitive that surface composes with — the operator learns the chain-committed key without trusting the serving daemon, then performs whatever off-chain authentication the endpoint demands against the recovered key. The combination gives "the chain committed *this* `service_pubkey` for `D`" (DR) + "the live endpoint proves possession of it" (off-chain, S019 frame) = trust-minimized DApp discovery.

### 5.8 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the `d:` proof anchors against an S-033-committed root that includes the `d:` namespace (S-037 wired `dapp_registry_` into the snapshot serialize/restore + the state-root binding). As with the other trustless reads, the flow must fail-closed with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`trustless_read.cpp:458-464`) — a chain-level deployment prerequisite. DR-1's interior regime is exactly the S-033-active regime. Note the historical dependency: pre-S-037, a DApp-active chain's snapshot emitted an empty `dapp_registry_` and the receiver's S-033 gate (made live by S-038) would reject the next block; S-037 + S-038 jointly make the `d:` leaf survive the snapshot ↔ replay boundary, which is what makes DR-2's "the daemon's served root is the genuine committed root" hypothesis hold even on a snapshot-bootstrapped daemon.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Several are worth calling out for the `d:` read specifically.

### 6.1 One-sided: no provable non-membership (DR-3)

The read cannot prove `NOT-REGISTERED`. A daemon returning `not_found` for a genuinely-present registration is indistinguishable from a genuinely-absent one (`MerkleTreeSoundness.md` MT-5). The negative is always `UNVERIFIABLE`. Multi-peer cross-check (out of scope) is the only mitigation against a withholding daemon. Same positive-only boundary as the `s:` / `i:` / `m:` / `p:` siblings; the caller contract of `NegativeVerdictSoundness.md` NV-6 applies (a `d:` `not_found` is "no proof obtained," never authoritative absence — especially relevant since a withheld deactivated DApp looks identical to a never-registered one).

### 6.2 Committee-rotation (genesis committee `K_0` only)

Like every other light-client verifier, the read seeds the committee map from genesis `initial_creators` (`build_genesis_committee`, `trustless_read.cpp:46-53`) and requires every creator in the `0..h` walk to be in that map. On a chain with mid-chain REGISTER/DEREGISTER that rotated the committee, the walk **fails closed** at the first non-`K_0` signer → `UNVERIFIABLE` — a positive safety property, never a wrong verdict. Shared `K_0` caveat (`LightClientThreatModel.md` §6.5 + F-1, `StakeProofSoundness.md` §6.2, `ReceiptInclusionProofSoundness.md` §6.2, `CompositeStateReadSoundness.md` §6.2).

### 6.3 Lifecycle currency is bounded by head freshness (DR-6)

DR-6's classification is sound *for the verified head height `h`*. A DApp transitions `deactivating → inactive` purely as `h` advances (T-D6), with no apply event. A verifier reading against a stale head classifies against an old `h` and could report `active`/`deactivating` for a DApp that the *current* chain considers `inactive`. Stale-head detection is operator-visible (`LightClientThreatModel.md` §6.1) but not auto-detected within a single invocation; the classification is "as of the verified head," and a client wanting current-tip lifecycle must re-read against a fresh head. This is the lifecycle-specific form of the general cross-invocation stale-state limitation.

### 6.4 The read attests the committed key/URL, not endpoint authenticity (§5.7)

The `d:` read proves the chain committed *this* `service_pubkey` and `endpoint_url` for `D`; it does not prove the `service_pubkey` is a sound box key, nor that the live server at `endpoint_url` is operated by `D`'s owner (an `A_net` / off-chain property out of scope per §2). A DApp owner who registers a malicious key is not defeated by this read — the read defeats a *daemon* substituting a different key than the chain committed, not a malicious *registration*. Endpoint authentication against the recovered key is the off-chain composition (`S019DAppEndpointSpoof.md` frame, §5.7).

### 6.5 The read attests committed fields, not application semantics

The read does not prove the `metadata` is well-formed, the `topics` set is meaningful, or the `retention` policy is honored by the operator's snapshot tooling (the `retention` byte is an operator-policy hint, not a consensus-enforced pruning rule — `chain.hpp:46-81` comment). Each is committed-as-bytes; the read attests the committed value, and any application-level interpretation is the consumer's responsibility. The lifecycle classification (DR-6) is the one derived predicate proven sound; all other field interpretations are out of scope.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Statement | Primary code citation | Composition |
|---|---|---|---|
| DR-1 | Committee-signed `state_root` binds the `d:` leaf | `light/trustless_read.cpp:335-437` (`committee_bound_state_root`, S-042 committee-binding); `src/node/producer.cpp::compute_block_digest`; `src/chain/block.cpp::signing_bytes` | `StateRootAnchorSoundness.md` SR-1/SR-2/SR-3; `LightClientThreatModel.md` T-L2 |
| DR-2 | Merkle state-proof for the `d:` leaf is sound | `light/verify.cpp:330-396`; `src/crypto/merkle.cpp:113-141`; leaf encoding `src/chain/chain.cpp:309-330` | `MerkleTreeSoundness.md` MT-1/MT-2/MT-4; `S033StateRootNamespaceCoverage.md` T-1/T-2 |
| DR-3 | One-sided verifier; non-membership NOT provable | `src/chain/chain.cpp:449` (`nullopt`); `src/node/node.cpp:3358-3361` (`not_found`) | `MerkleTreeSoundness.md` MT-5; `NegativeVerdictSoundness.md` NV-2/NV-6 |
| DR-4 | `leaf_count` bound into committed root (S-040 CLOSED) | `src/crypto/merkle.cpp::merkle_root_wrap`; `merkle.cpp:130-138`; `node.cpp:3373-3375` | `MerkleTreeSoundness.md` §6.2 |
| DR-5 | Fail-closed exit | `light/verify.cpp` (`r.ok=false` branches); `light/trustless_read.cpp:469-473` (error→throw) | `LightClientThreatModel.md` L-6 |
| DR-6 | Lifecycle classification is a sound derived predicate | `inactive_from` field in `chain.cpp:317`; on-chain gate `src/chain/chain.cpp:1142` | `DAppRegistryLifecycle.md` T-D6 |
| DR-E | End-to-end composition `≤ 2⁻⁹²` | `light/trustless_read.cpp:439-599` (the `read_account_trustless` template) | T-L1 + T-L2 + DR-1 + DR-2 + DR-4 + DR-6 |

| Surface | Citation |
|---|---|
| `d:` leaf encoding (8-field value-hash) | `src/chain/chain.cpp:309-330` (`build_state_leaves`) |
| `DAppEntry` struct | `include/determ/chain/chain.hpp:46-81` |
| `dapp_registry_` map | `include/determ/chain/chain.hpp:549` (`std::map<std::string, DAppEntry>`) |
| `state_proof` RPC simple-key `d:` branch | `src/node/node.cpp:3287-3378` (`d` enumerated at `node.cpp:3314`) |
| Trustless-read skeleton | `light/trustless_read.cpp:439-599` (`read_account_trustless`) |
| Genesis anchor / committee-sig verify | `light/trustless_read.cpp:46-248`; `light/verify.cpp:135-328` |
| Merkle state-proof verify | `light/verify.cpp:330-396`; `src/crypto/merkle.cpp:113-141` |
| DAPP_CALL inactive-gate (DR-6 dual) | `src/chain/chain.cpp:1142` |
| `state_proof` RPC contract | `docs/PROTOCOL.md` §10.2 |
| `d:` canonical Merkle-leaf row | `docs/PROTOCOL.md` §4.1.1 |
| DAPP_REGISTER apply rules | `docs/PROTOCOL.md` §3.3; `DAppRegistryLifecycle.md` |
| S-037 / S-038 / S-040 closures | `docs/SECURITY.md` §S-037 / §S-038 / §S-040 |

---

## 8. Status

All six theorems (DR-1 through DR-6) and the corollary DR-E are closed for the `d:` namespace read against the in-tree light-client substrate:

- **DR-1** (committee-anchored root) closed by inheritance from `StateRootAnchorSoundness.md` SR-1 + the shared S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`); reduces to A1 + A2, bound `≤ K·2⁻¹²⁸ + 2⁻¹²⁸`.
- **DR-2** (Merkle inclusion + key/value-hash binding) closed via `crypto::merkle_verify` (`merkle.cpp:113-141`) + the §4.2.1 cross-check over the eight-field §1.2 preimage; reduces to A2, bound `≤ log₂(n)·2⁻¹²⁸`.
- **DR-3** (one-sided verifier) closed honestly — the sorted-leaves primitive (MT-5) admits no non-membership proof, so `NOT-REGISTERED` is always `UNVERIFIABLE`.
- **DR-4** (`leaf_count` root-binding) closed via the S-040 root-wrapper hash; no residual caller-trust item.
- **DR-5** (fail-closed exit) closed structurally — `VERIFIED` is reached only on the full conjunction; every error path throws.
- **DR-6** (sound lifecycle derivation) closed — the classification is a deterministic comparison of the committee-certified `inactive_from` against the committee-verified head height, matching the on-chain gate `DAppRegistryLifecycle.md` T-D6.
- **DR-E** composes to `≤ 2⁻⁹²` end-to-end, matching the balance/stake/receipt/merge-param read bounds.

The `d:` read is the **last simple-key namespace** to receive its trust-minimized read proof, completing the family across all ten S-033 namespaces. Its distinguishing contribution over the prior siblings is the **richest value-hash encoding** — eight fields, three of them variable-length and one a variable-count nested list — and the proof that the cleartext cross-check (DR-2 (iii) / §4.2.1) remains unambiguous under that complexity by the injectivity of the length-prefixed canonical preimage. The proof's foundation rests on the same small set of primitives every trustless read uses — the committee-anchored `state_root` (SR-1), the sorted-leaves Merkle inclusion proof (MT-4), the root-wrapped `leaf_count` (S-040), and the value-hash cleartext cross-check (L-4) — specialized to the `d:` namespace and composed with the apply-side determinism of `DAppRegistryLifecycle.md`.
