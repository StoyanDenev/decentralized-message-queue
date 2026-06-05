# DAppRegistryCommitmentSoundness — `d:`-leaf encoding injectivity + the registry/message commitment-coverage boundary

This document formalizes two facets of the v2.18/v2.19 DApp subsystem that are *upstream* of any trustless `d:`-namespace read and *orthogonal* to the apply-layer lifecycle state machine. First, the **injectivity** of the `d:`-namespace leaf-value encoding in `Chain::build_state_leaves` (`src/chain/chain.cpp:312-329`): the SHA-256 preimage that becomes a `d:` leaf's `value_hash` is a length-prefixed (TLV) serialization of the eight `DAppEntry` fields, so the preimage map `DAppEntry → bytes` is injective, and therefore — under **A2** (SHA-256 collision resistance) — a passing `value_hash` binds to **exactly one** `DAppEntry` field-tuple. Second, the **commitment-coverage boundary**: the `d:` leaf commits the *registration record* (service pubkey, endpoint, topics, retention, metadata, lifecycle anchors) to the S-033 `state_root`, but it commits **none** of the per-`DAPP_CALL` *message bodies* that `Node::rpc_dapp_messages` (`src/node/node.cpp:3028-3082`) surfaces — those live only in block bodies under the per-block `tx_root`, never in the `d:` leaf. The two surfaces have different trust roots: a `dapp_info`/`dapp_list` answer is verifiable against the *committee-signed `state_root`* via the `d:` state-proof; a `dapp_messages` answer is verifiable only against the *committee-signed `tx_root`* of each enclosing block (per-tx inclusion, the `TxInclusionProofSoundness.md` surface), and a Byzantine daemon can omit or reorder messages within a window without breaking any `state_root`-level invariant.

The proof exists because the DApp subsystem is the first application-layer namespace whose RPC query surface (`dapp_info` / `dapp_list` / `dapp_messages`) spans **two different commitment roots in a single conceptual object** ("a DApp"). The registry entry is durable, single-leaf, `state_root`-committed, and replaces-in-place; the message stream is append-only, multi-block, `tx_root`-committed, and *not* deduplicated or totalized by any state field. Conflating the two trust roots is the natural client-side error this proof pins against: an operator who trusts a `dapp_messages` page the way it trusts a `dapp_info` answer has overextended the `state_root` guarantee onto data the `state_root` never covered. The injectivity lemma (DC-1) is the foundation every `d:` trustless reader rests on (it is the `d:` analogue of the per-namespace value-binding lemmas in `StakeProofSoundness.md` SP and `TxInclusionProofSoundness.md`); the boundary theorem (DC-3 / DC-4) is the novel contribution — it states precisely what a passing `d:` proof does and does not let a light client conclude about a DApp's *message history*, and what weaker (tx-root) guarantee the message stream carries instead. No new cryptographic primitive is introduced; injectivity reduces to **A2**, and the boundary is an inspection result over which fields enter `compute_state_root` versus `tx_root`.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1) — DC-1 reduces to **A2** only; DC-2 (encoding totality/determinism) is *unconditional* (a deterministic-function argument); the tx-root weaker guarantee in DC-4 reduces to **A1** + **A2** exactly as `TxInclusionProofSoundness.md` does; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-2** leaf-key domain separation / length-prefixed unambiguous key encoding, **MT-3** collision-resistance inheritance, **MT-4** inclusion-proof soundness; DC-1's leaf-*value* injectivity is the value-side analogue of MT-2's leaf-*key* injectivity, and the two together are what make a `d:` inclusion proof bind a unique `(domain, DAppEntry)` pair; **§6.2 (S-040, CLOSED)** binds `leaf_count` into the committed root via the root-wrapper); `DAppRegistryLifecycle.md` (FA-Apply-5 — the apply-layer three-state machine `(unregistered, active, deactivating)`; this proof takes its `DAppEntry` field semantics, owner-binding-by-keying, and the `inactive_from`/`registered_at` anchors as given, and asks the orthogonal question "what does the *committed leaf* bind, and what does it not"); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** namespace table fixes the canonical `d:` key + value-hash encoding DC-1 is matched against, its **T-1** "every apply-determining field is committed" is the property DC-3 specializes to the registry entry, and its **T-2** namespace disjointness guarantees `"d:"+…` never aliases another namespace's leaf); `StateProofCompositeKeySoundness.md` (the daemon-side composite-key reconstruction proof — DC contrasts the *simple* `d:` namespace with the *composite* `i:`/`m:`/`p:` ones: the `d:` suffix is the raw ASCII `domain` string, so the hex-transport boundary that proof secures does **not** arise for `d:`); `StakeProofSoundness.md` + `TxInclusionProofSoundness.md` (the sibling per-namespace trustless-read soundness proofs whose value-binding lemmas DC-1 mirrors for `d:`; `TxInclusionProofSoundness.md` is the exact `tx_root` surface DC-4 invokes for the message-stream guarantee); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon` and the **T-L3** state-proof-correctness flow DC-3 specializes to `d:`, plus the fail-closed posture DC-4's omission-attack analysis depends on); `StateRootAnchorSoundness.md` (F6 — **SR-1** per-height committee-anchored-root binding inherited verbatim by both DC-3 and the per-block `tx_root` anchor in DC-4); `docs/SECURITY.md` §S-033 + §S-037 + §S-040 (the `d:`-namespace coverage + dapp_registry snapshot serialize/restore closure + leaf_count binding); `docs/PROTOCOL.md` §4.1.1 (the canonical `d:` Merkle-leaf row) + §10.2 (the `state_proof`, `dapp_info`, `dapp_list`, `dapp_messages` RPC contracts); `docs/V2-DAPP-DESIGN.md` §3–§5 (the design intent for the registry-vs-message-stream split).

---

## 1. Scope

### 1.1 In scope

The `d:`-namespace leaf-value preimage built by `Chain::build_state_leaves` (`src/chain/chain.cpp:312-329`) and the commitment-coverage relationship between (a) the `d:` state-leaf, (b) the per-block `tx_root` over `DAPP_CALL` transactions, and (c) the three DApp RPC query surfaces `rpc_dapp_info` / `rpc_dapp_list` / `rpc_dapp_messages` (`src/node/node.cpp:2987-3120`).

The four theorems plus one lemma:

| Theorem | Property |
|---|---|
| **DC-1** (Leaf-value injectivity) | The encoding map `enc_d : DAppEntry → bytes` (the SHA-256 preimage of the `d:` leaf value) is injective; under **A2**, a passing `d:` inclusion proof binds the verifier to exactly one `DAppEntry` field-tuple — no two distinct entries share a `value_hash` except with collision-negligible probability. |
| **DC-2** (Encoding totality + determinism) | `enc_d` is total (every reachable `DAppEntry`, including empty endpoint / zero topics / empty metadata / the `inactive_from = UINT64_MAX` sentinel, has a well-defined preimage) and deterministic (byte-identical across replays, hosts, and snapshot restore). Unconditional. |
| **DC-3** (Registry-entry commitment) | Every field the apply layer or any query consumes from a `DAppEntry` is committed to `state_root` via the `d:` leaf; a `dapp_info` / `dapp_list` answer is therefore fully verifiable against the committee-signed `state_root` by a `d:` state-proof read (specialization of S-033 T-1 + LightClientThreatModel T-L3). |
| **DC-4** (Message-stream commitment boundary) | No `DAPP_CALL` message **body** enters the `d:` leaf or any `state_root` namespace; the message stream is committed only by the per-block `tx_root`. Hence (i) a `dapp_messages` answer is verifiable only at per-tx granularity against each enclosing block's committee-signed `tx_root` (the `TxInclusionProofSoundness.md` surface), and (ii) a Byzantine daemon may omit, truncate, or reorder a `dapp_messages` page *without* contradicting any `state_root`-level proof — the page is **advisory completeness, sound non-membership-resistant only per-tx**. |

Plus the structural lemma:

| Lemma | Property |
|---|---|
| **DC-K** (Key/value separation for `d:`) | The `d:` leaf *key* is `"d:" ‖ domain` (ASCII, no hex transport — unlike the composite `i:`/`m:`/`p:` namespaces) and the leaf *value* is `SHA256(enc_d(entry))`; the key binds the *domain* (MT-2) and the value binds the *entry* (DC-1), so a `d:` inclusion proof binds the full pair `(domain, DAppEntry)`. |

### 1.2 Out of scope

- The apply-layer lifecycle transitions (`DAppRegistryLifecycle.md` FA-Apply-5) — owner-binding-by-keying, `DAPP_GRACE_BLOCKS` deferral, `registered_at` immutability — are taken as given; this proof reasons about the *committed leaf*, not how the entry got there.
- The daemon-side key reconstruction / hex-transport boundary (`StateProofCompositeKeySoundness.md`) — `d:` is a simple ASCII namespace, so that boundary does not arise (DC-K).
- The end-to-end `determ-light` trustless-read pipeline for `d:` (genesis anchor → header-chain walk → committee-sig verify → Merkle verify) is the sibling reader's surface; DC-1/DC-K supply the value-binding lemma that pipeline consumes, exactly as SP-1/SP-2 do for `s:`.
- DAPP_CALL *ciphertext* confidentiality (v2.22) and topic-routing semantics — the chain treats the payload as opaque past the topic-tag prefix; DC-4 is about *commitment*, not *confidentiality*.

---

## 2. Setup

### 2.1 The `d:` leaf-value encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:312-329`), with the key built by the shared `k_with_prefix` lambda (`chain.cpp:275-281`) and `crypto::SHA256Builder::append(uint64_t)` being a **fixed 8-byte big-endian** writer (`src/crypto/sha256.cpp:30-34`):

```cpp
for (auto& [domain, e] : dapp_registry_) {
    crypto::SHA256Builder b;
    b.append(e.service_pubkey.data(), e.service_pubkey.size()); // 32 raw bytes (PubKey, fixed width)
    b.append(e.registered_at);                                  // u64 be
    b.append(e.active_from);                                    // u64 be
    b.append(e.inactive_from);                                  // u64 be (UINT64_MAX = active sentinel)
    b.append(static_cast<uint64_t>(e.endpoint_url.size()));     // u64 be length prefix
    b.append(e.endpoint_url);                                   // |endpoint_url| bytes
    b.append(static_cast<uint64_t>(e.topics.size()));           // u64 be topic count
    for (auto& t : e.topics) {
        b.append(static_cast<uint64_t>(t.size()));              // u64 be per-topic length prefix
        b.append(t);                                            // |t| bytes
    }
    b.append(static_cast<uint64_t>(e.retention));               // retention (u8) promoted to u64 be
    b.append(static_cast<uint64_t>(e.metadata.size()));         // u64 be metadata length prefix
    if (!e.metadata.empty()) b.append(e.metadata.data(), e.metadata.size()); // |metadata| bytes
    leaves.push_back({k_with_prefix("d:", domain), hash_bytes(b)});
}
```

So the leaf-value preimage is the byte string

$$
\mathrm{enc}_d(e) \;=\; \underbrace{P_{32}}_{\text{service\_pubkey}} \,\|\, \underbrace{u64(R)}_{\text{registered\_at}} \,\|\, u64(A_f) \,\|\, u64(I_f) \,\|\, u64(\ell_u) \,\|\, U_{\ell_u} \,\|\, u64(n_t) \,\|\, \Big[\,u64(\ell_{t,j}) \,\|\, T_{j}\,\Big]_{j=0}^{n_t-1} \,\|\, u64(r) \,\|\, u64(\ell_m) \,\|\, M_{\ell_m},
$$

where $P_{32}$ is the 32-byte service pubkey, $\ell_u = |\text{endpoint\_url}|$, $n_t = |\text{topics}|$, $\ell_{t,j} = |T_j|$, $r \in [0,255]$ is the retention byte, and $\ell_m = |\text{metadata}|$. The leaf value committed to the tree is $H(\mathrm{enc}_d(e)) = \texttt{SHA256}(\mathrm{enc}_d(e))$. The leaf key is $\texttt{"d:"} \,\|\, \text{domain}$ (raw ASCII, no length prefix on the key — the key namespace prefix `"d:"` plus the `domain` ASCII string, exactly as `a:`/`s:`/`r:`/`b:` are built, per MT-2's key domain-separation argument).

### 2.2 Field provenance — every field is apply-relevant or query-relevant

| Field | Width | Apply-layer role (FA-Apply-5) | Query exposure |
|---|---|---|---|
| `service_pubkey` | 32 (fixed) | identity of the off-chain service endpoint | `dapp_info.service_pubkey` |
| `registered_at` | 8 (u64) | immutable creation-height owner-anchor (T-D2) | `dapp_info.registered_at` |
| `active_from` | 8 (u64) | re-anchored on every successful update | `dapp_info.active_from` |
| `inactive_from` | 8 (u64) | lifecycle sentinel; `≤ height` ⇒ inactive (T-D6) | `dapp_info.inactive_from`, `dapp_list.active` |
| `endpoint_url` | TLV | off-chain routing URL | `dapp_info.endpoint_url`, `dapp_list.endpoint_url` |
| `topics` | TLV vector | DAPP_CALL topic-routing whitelist | `dapp_info.topics`, `dapp_list.topics` |
| `retention` | 1 (→u64) | retention policy hint | `dapp_info.retention` |
| `metadata` | TLV | opaque registration metadata | `dapp_info.metadata` |

Every byte of `enc_d(e)` is sourced from one of the eight `DAppEntry` fields (`include/determ/chain/chain.hpp:46-81`); no field is omitted. This exhaustiveness is the premise DC-3 discharges.

### 2.3 The two commitment roots

A finalized block `B` at height `h` carries two independent Merkle commitments relevant here (per `include/determ/chain/block.hpp` body layout, `PROTOCOL.md` §4):

- **`tx_root`** — the Merkle root over the block's ordered transaction list, including every `DAPP_CALL` transaction. This binds the *message bodies* (each `DAPP_CALL` payload rides in its transaction, `chain.cpp:1118-1123` comment: "the payload sits in the block, indexed by tx_root, consumed off-chain by DApp nodes filtering on tx.to"). It is the `TxInclusionProofSoundness.md` surface.
- **`state_root`** — the S-033 sorted-leaves balanced binary Merkle root over the 10 namespaces, including `d:`. This binds the *registry entry* but **no** `DAPP_CALL` payload byte.

Both roots are inside the block header's signing bytes, so both are covered by the committee's Ed25519 signature set (StateRootAnchorSoundness SR-1; the `tx_root` analogue is the standard header binding). The novelty of DC-4 is that these are *different* roots over *different* data, and the DApp query surface straddles both.

---

## 3. Theorems

### DC-1 — Leaf-value injectivity (`enc_d` is injective ⇒ value_hash binds a unique entry)

**Statement.** The encoding $\mathrm{enc}_d : \mathtt{DAppEntry} \to \{0,1\}^*$ is injective: for any two `DAppEntry` values $e \neq e'$, $\mathrm{enc}_d(e) \neq \mathrm{enc}_d(e')$. Consequently, under **A2** (SHA-256 collision resistance), a `value_hash` $v = H(\mathrm{enc}_d(e))$ returned by a passing `d:` inclusion proof binds the verifier to the unique field-tuple $e$ except with probability $\le \mathrm{Adv}^{\mathrm{coll}}_{\texttt{SHA256}}(\mathcal{A}) \le q^2 \cdot 2^{-256}$ over the verifier's view (birthday bound over $q$ hash queries).

*Proof.* The encoding is a **prefix-free, fully length-prefixed (TLV) serialization** parseable left-to-right with no ambiguity. We exhibit the parser, which inverts $\mathrm{enc}_d$ and hence witnesses injectivity:

1. Read the first **32 bytes** → `service_pubkey` (fixed width, `PubKey` is `std::array<uint8_t,32>`; no length ambiguity).
2. Read **8 bytes** → `registered_at` (u64 be; fixed width).
3. Read **8 bytes** → `active_from`.
4. Read **8 bytes** → `inactive_from`.
5. Read **8 bytes** → $\ell_u$; then read exactly $\ell_u$ bytes → `endpoint_url`.
6. Read **8 bytes** → $n_t$; then **for** $j = 0 \dots n_t-1$: read **8 bytes** → $\ell_{t,j}$, then read exactly $\ell_{t,j}$ bytes → $T_j$.
7. Read **8 bytes** → `retention` (the low byte determines $r \in [0,255]$; the apply layer only ever writes $r \le 255$ because the source field is `uint8_t`, `chain.hpp:50`).
8. Read **8 bytes** → $\ell_m$; then read exactly $\ell_m$ bytes → `metadata`.

At every step the number of bytes to read next is determined either by a fixed constant (steps 1–4, 7) or by a length field that was *itself* just read at a fixed offset (steps 5, 6, 8). The decode is therefore a deterministic total function on its own output range, and the position of every field boundary is a function of the preceding bytes alone. Hence two preimages that decode to the same field-tuple are byte-identical, and two distinct field-tuples cannot share a preimage:

- If $e, e'$ differ in any fixed-width field (`service_pubkey`, `registered_at`, `active_from`, `inactive_from`, `retention`), the differing bytes sit at the *same* fixed offset in both encodings (because all preceding fields are fixed-width or already length-delimited up to that point), so the byte strings differ. (For `retention`, distinct $r \neq r'$ in $[0,255]$ produce distinct 8-byte big-endian encodings.)
- If they differ in a variable-length field's *length* ($\ell_u$, $n_t$, $\ell_{t,j}$, $\ell_m$), the corresponding 8-byte length prefix differs, so the byte strings differ at that prefix.
- If they differ only in a variable-length field's *content* with equal length, the content bytes (which occupy the same offset range given equal preceding lengths) differ.

No "field-boundary smuggling" attack exists (the classic ambiguity where `("ab","")` and `("a","b")` collide under naive concatenation) precisely because every variable-length field carries its own explicit u64 length prefix; the topic vector additionally carries an explicit count $n_t$ before any per-topic length, so a topic boundary can never be confused with the start of the `retention` field. This is the value-side analogue of MT-2's length-prefixed *key* domain separation.

Injectivity of $\mathrm{enc}_d$ established, the binding claim is the standard collision-resistance reduction: if an adversary could exhibit two accepted entries $e \neq e'$ with $H(\mathrm{enc}_d(e)) = H(\mathrm{enc}_d(e'))$, then $(\mathrm{enc}_d(e), \mathrm{enc}_d(e'))$ is a SHA-256 collision (they are distinct preimages by injectivity), contradicting **A2**. The verifier re-derives the leaf value from `key_bytes` (the `"d:" ‖ domain` key) and the committed root via `merkle_verify` (MT-4); the bound is the birthday bound $q^2 2^{-256}$ over the verifier's hash-query count. ∎

**Code witness.** `src/chain/chain.cpp:312-329` (`enc_d` construction); `src/crypto/sha256.cpp:30-34` (8-byte big-endian `append(uint64_t)` — the fixed-width guarantee steps 2–4, 5, 6, 7, 8 rely on); `include/determ/chain/chain.hpp:46-81` (`DAppEntry` field types, esp. `retention` being `uint8_t`).

**Cross-reference.** This is the `d:` analogue of `StakeProofSoundness.md` SP value-binding and `S033StateRootNamespaceCoverage.md` §2.1; it discharges the value-binding premise that any `determ-light` `d:` trustless reader cites without proof.

### DC-2 — Encoding totality + determinism (unconditional)

**Statement.** $\mathrm{enc}_d$ is **total** — it is well-defined on every reachable `DAppEntry`, including the boundary cases: empty `endpoint_url` ($\ell_u = 0$), zero topics ($n_t = 0$, the inner loop runs zero times), empty `metadata` ($\ell_m = 0$, the `if (!e.metadata.empty())` guard at `chain.cpp:328` skips the content append but the preceding `append(0)` length prefix is still emitted), and the active sentinel `inactive_from = UINT64_MAX` (a valid u64, encoded as eight `0xFF` bytes). $\mathrm{enc}_d$ is **deterministic** — for fixed field values it produces byte-identical output on every host, every replay, and after snapshot restore.

*Proof.* Totality: each of the four variable-length sites (`endpoint_url`, the topic vector, each topic, `metadata`) emits its u64 length prefix *unconditionally* (the `append(static_cast<uint64_t>(...size()))` calls at `chain.cpp:318,320,322,327`), so the zero-length cases are not special-cased away — the parser of DC-1 reads a length of 0 and advances 0 content bytes, which is well-defined. The `metadata` content append is guarded (`chain.cpp:328`), but the *length prefix* is not, so an empty-metadata entry still emits `append(0)` and the parser stays aligned. There is no reachable `DAppEntry` for which any `append` call is undefined: `service_pubkey` is a fixed-size `std::array`, the three lifecycle anchors and `retention` are integers, and the three variable fields are `std::string` / `std::vector` with `.size()` total.

Determinism: `enc_d` is a pure function of the field values — `SHA256Builder::append` is a deterministic streaming hash with no host-dependent state (no pointer values, no locale, no platform-endian writes; the big-endian loop in `sha256.cpp:32` fixes byte order independent of host endianness), and the field iteration order is the fixed lexical order of the eight struct fields. The only iteration over a container is `for (auto& t : e.topics)`, which walks the `std::vector<std::string>` in stable insertion order — and that order is itself deterministic because the apply layer writes `topics` from the wire payload in decode order (FA-Apply-5; the snapshot restore at `chain.cpp:1826-1847` rebuilds the vector in the same JSON-array order). The outer `for (auto& [domain, e] : dapp_registry_)` walks a `std::map` in sorted key order (this affects *leaf ordering* in the tree, covered by S-033 T-3, not `enc_d` per-entry). Therefore the per-entry preimage is byte-identical across replays and restore, as required by the S-038 producer-side `state_root` population and the FA-Apply-2 snapshot equivalence. ∎

**Code witness.** `src/chain/chain.cpp:318-328` (unconditional length prefixes + guarded content append); `src/crypto/sha256.cpp:30-34` (host-endian-independent big-endian write); `src/chain/chain.cpp:1826-1847` (snapshot restore rebuilds `topics` in JSON-array order, preserving determinism across restore).

**Cross-reference.** Composes with FA-Apply-2 (`SnapshotEquivalence.md` T-S3 cross-namespace coverage) and S-037 (the `dapp_registry_` serialize/restore wiring that makes the `d:` leaf survive snapshot bootstrap with an identical `value_hash`).

### DC-3 — Registry-entry commitment (every queried field is `state_root`-bound)

**Statement.** For every domain $d$ with an entry $e \in \mathtt{dapp\_registry\_}$ at height $h$, every field that `rpc_dapp_info(d)` (`node.cpp:2987-3008`) or `rpc_dapp_list` (`node.cpp:3084-3120`) returns about $d$ is committed to the height-$h$ `state_root` via the single `d:` leaf $\big(\texttt{"d:"} \| d,\ H(\mathrm{enc}_d(e))\big)$. Hence a light client that (i) anchors $h$'s `state_root` to a committee-signed header (SR-1), (ii) fetches the `d:` state-proof for key $d$, and (iii) `merkle_verify`s it (MT-4), can reconstruct and trust every `dapp_info` field about $d$ without trusting the daemon — a Byzantine daemon cannot make the client accept a wrong `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, `registered_at`, `active_from`, or `inactive_from` except with collision-negligible probability.

*Proof.* By §2.2, the eight returned fields are exactly the eight `DAppEntry` fields, and by §2.1 all eight are inputs to $\mathrm{enc}_d$. By DC-1, $H(\mathrm{enc}_d(e))$ binds the unique tuple $e$ under **A2**; by DC-K the key binds $d$ under MT-2. The S-033 coverage theorem T-1 states the `d:` leaf is one of the tree's leaves and that `compute_state_root` includes the full `dapp_registry_` loop (`chain.cpp:1655-1662` is the parallel `serialize_state` side; the `build_state_leaves` `d:` loop is the root-computation side — both iterate the same map with the same `enc_d`, the S-037/S-038 wiring). The committee signs the header binding `state_root` (SR-1). So the verification chain is: committee-sig ⟹ trusted `state_root` (T-L2 / SR-1) ⟹ `merkle_verify` binds the `(d, value_hash)` leaf (MT-4) ⟹ DC-1 binds `value_hash` to the unique $e$ ⟹ the client reconstructs the eight fields. The `active` boolean that `dapp_list` returns (`node.cpp:3115`: `entry.inactive_from > h`) is a pure function of the committed `inactive_from` and the proof's `height`, so it too is derivable from the verified leaf (this is the T-D6 "post-deactivation queries skip the entry" predicate, evaluated client-side). Any daemon deviation requires either forging the committee signature (**A1**, $\le q\,2^{-128}$) or a SHA-256 collision (**A2**, DC-1). ∎

**Code witness.** `src/node/node.cpp:2987-3008` (`rpc_dapp_info` returns exactly the eight fields + `height`); `src/node/node.cpp:3084-3120` (`rpc_dapp_list` compact summary derives `active` from `inactive_from > h`); `src/chain/chain.cpp:312-329` (the same eight fields enter `enc_d`); `src/node/node.cpp` `rpc_state_proof` `d:` branch (the `"d"` namespace is in the simple-namespace set `if (ns == "a" || ns == "s" || ... )`).

**Cross-reference.** Specializes S-033 T-1 + LightClientThreatModel T-L3 to the `d:` namespace; the dual of `StakeProofSoundness.md` SP-2 for the registry namespace.

### DC-4 — Message-stream commitment boundary (DAPP_CALL bodies are tx-root-bound, not state-root-bound)

**Statement.** Let $W = [\,h_0, h_1)$ be a height window and $d$ a domain. The `rpc_dapp_messages(d, h_0, h_1, topic)` answer (`node.cpp:3028-3082`) is a projection of the `DAPP_CALL` transactions with `tx.to == d` in blocks $[h_0, h_1)$. Then:

1. **No message body is `state_root`-committed.** No byte of any `DAPP_CALL` payload appears in $\mathrm{enc}_d$ or in any of the 10 `state_root` namespaces. (The registry leaf binds the *registration record*, not the *message log*.) The only `state_root`-side trace a `DAPP_CALL` leaves is the *indirect* one: it debits/credits `accounts_` balances and bumps `next_nonce` (the `a:` namespace, `chain.cpp:1118-1175`), and those deltas are `state_root`-committed — but the *payload/topic/body* is not.
2. **Per-tx soundness via `tx_root` only.** Each returned event carries a `tx_hash` (`node.cpp:3056`); a light client can verify that *specific* transaction's inclusion in block $h$ against block $h$'s committee-signed `tx_root` (the `TxInclusionProofSoundness.md` surface, reducing to **A1** + **A2**). So *positive membership* of a returned message is soundly verifiable per-tx.
3. **No `state_root`-level completeness.** A Byzantine daemon may **omit**, **truncate** (it advertises a `truncated` flag and a `DAPP_MESSAGES_PAGE_LIMIT` of 256, `node.cpp:3025`), or **reorder** the events of a `dapp_messages` page without contradicting any `state_root` proof — because no `state_root` field totalizes, counts, or orders the `DAPP_CALL` stream for $d$. Completeness of a page is therefore **advisory**: it is only as trustworthy as the daemon, unless the client independently walks every block header in $W$ (committee-signed), fetches each block body, and re-filters — i.e., completeness reduces to *full-block availability*, not to a succinct `state_root` proof.

*Proof.* (1) Inspection of `build_state_leaves` (`chain.cpp:284-410`, the full 10-namespace loop): the `d:` loop (§2.1) reads only `DAppEntry` fields; no loop reads any transaction payload. The `DAPP_CALL` apply branch (`chain.cpp:1133-1175`) mutates only `accounts_[sender]` / `accounts_[tx.to]` (balance + nonce, the `a:` namespace) and `total_fees`; it writes **nothing** to `dapp_registry_` and stores **no** payload anywhere in chain state. The payload exists solely inside the transaction object, which lives in the block body and is committed by `tx_root`, per the `chain.cpp:1118-1123` design comment. Hence no payload byte is `state_root`-reachable.

(2) `rpc_dapp_messages` returns, per event, `(block_height, tx_hash, from, to, amount, fee, nonce, topic, payload_hex)` (`node.cpp:3054-3064`). Given `(block_height = h, tx_hash)`, a client fetches block $h$'s header (committee-signed, T-L2 / SR-1), confirms the header's `tx_root`, and verifies a Merkle inclusion proof of `tx_hash` against that `tx_root` (`TxInclusionProofSoundness.md`). That proves the transaction — and hence its payload, since `tx_hash` binds the full transaction under **A2** — was genuinely in block $h$. This is the *positive* guarantee: a daemon cannot fabricate a `dapp_messages` event that was never on-chain without breaking **A1**/**A2**.

(3) The *completeness* (negative) direction has no succinct `state_root` witness. The `state_root` commits the registry entry and the post-window account balances, but neither encodes "the set of `DAPP_CALL` txs to $d$ in $[h_0,h_1)$." Concretely: a daemon that drops one `DAPP_CALL` event from the page leaves the `d:` leaf unchanged (the registry entry is independent of message traffic) and leaves the account-balance leaves consistent with *some* execution (the dropped tx's balance delta is just not reflected if the daemon also serves a stale balance — but the client reading `dapp_messages` is not cross-checking balances). The `truncated` flag and pagination (`node.cpp:3065-3071`) are *cooperative* signals, not enforced by any commitment. Therefore page-completeness can be established only by the client itself enumerating every block in $W$ against committee-signed headers and re-filtering on `tx.to == d` and `topic` — the same filter the daemon claims to have run (`node.cpp:3041-3053`) — which requires full block-body availability, not a single state-proof. This is the precise boundary: **`dapp_info`/`dapp_list` are succinctly trustless (DC-3); `dapp_messages` is per-tx-sound but only block-availability-complete.** The fail-closed posture (`LightClientThreatModel.md`) dictates that a client requiring complete message history must either (a) run a full node, or (b) treat the daemon's page as a *hint* and independently verify each `tx_hash` it acts on. ∎

**Code witness.** `src/node/node.cpp:3028-3082` (`rpc_dapp_messages` — scans block bodies, paginates at `DAPP_MESSAGES_PAGE_LIMIT = 256`, returns `truncated`/`last_scanned` cooperative signals); `src/chain/chain.cpp:1118-1175` (`DAPP_CALL` apply — mutates only `a:` balances/nonces + `total_fees`, stores no payload in chain state); `src/chain/chain.cpp:284-410` (`build_state_leaves` — no namespace reads any tx payload); `include/determ/chain/block.hpp` (block body carries `transactions` under `tx_root`).

**Cross-reference.** Composes `TxInclusionProofSoundness.md` (the per-tx `tx_root` membership surface DC-4(2) invokes) with `LightClientThreatModel.md` (the `A_daemon` omission adversary + fail-closed posture). The boundary is the application-layer instance of the general "state commitment vs. transaction commitment" split that S-033 (`S033StateRootNamespaceCoverage.md`) draws for the whole chain.

---

## 4. Adversary table

| Adversary | Capability | Defeated by | Residual |
|---|---|---|---|
| `A_value_collide` | Serve a `d:` proof for a forged `DAppEntry` sharing a `value_hash` with the real one | DC-1 injectivity + **A2** (birthday bound $q^2 2^{-256}$) | none beyond A2 |
| `A_field_smuggle` | Craft two entries whose naive-concat encodings alias (e.g. shift bytes between `endpoint_url` and a topic) | DC-1 — every variable field is u64-length-prefixed + the topic vector carries an explicit count; no boundary ambiguity | none |
| `A_retention_overflow` | Exploit the `retention` u8→u64 promotion to alias two retentions | DC-1 — source field is `uint8_t` (≤255); distinct values give distinct 8-byte big-endian encodings | none |
| `A_key_alias` | Serve a `d:` proof for domain $d'$ but claim it is $d$ | DC-K + MT-2 — the leaf key `"d:"‖d` is part of the verified leaf; `merkle_verify` binds it | none |
| `A_msg_fabricate` | Return a `dapp_messages` event for a `DAPP_CALL` that was never on-chain | DC-4(2) — client verifies `tx_hash` against block $h$'s committee-signed `tx_root` (**A1**+**A2**) | none for acted-upon events |
| `A_msg_omit` | Drop / truncate / reorder events in a `dapp_messages` page | **NOT defeated by any `state_root` proof** — DC-4(3): completeness needs full block-body availability | the documented boundary; mitigated only by full-node re-scan |
| `A_root_confuse` | Make a client accept a `dapp_messages` page as if `state_root`-committed | DC-4(1) — no payload byte is in `state_root`; the page's only commitment is per-block `tx_root` | client-side discipline (treat page as hint) |

The `A_msg_omit` / `A_root_confuse` rows are the load-bearing novelty: they are the *honest negative results* this proof establishes — the DApp message stream does **not** inherit the succinct trustless-read guarantee that the registry entry enjoys, and a client must not assume it does.

---

## 5. Relationship to sibling proofs

- **vs. `DAppRegistryLifecycle.md` (FA-Apply-5):** that proof governs *how* a `DAppEntry` is created/updated/deactivated by the apply layer (the `(unregistered, active, deactivating)` state machine, owner-binding-by-keying, `DAPP_GRACE_BLOCKS`). This proof is orthogonal: it takes a *committed* entry and asks what its `d:` leaf binds (DC-1/DC-3) and what the surrounding query surface does *not* bind (DC-4). Lifecycle ↔ apply-time mutation; commitment ↔ post-apply leaf semantics.
- **vs. `StateProofCompositeKeySoundness.md`:** that proof secures the daemon-side hex-transport + length-check for the *composite* `i:`/`m:`/`p:` namespaces, whose suffixes are raw binary. `d:` is a *simple* ASCII namespace (DC-K), so no hex-transport boundary arises; the two proofs partition the namespace family (simple vs. composite) on the RPC-encoding axis.
- **vs. `StakeProofSoundness.md` / `TxInclusionProofSoundness.md`:** DC-1 is the `d:` value-binding lemma mirroring SP for `s:`; DC-4 invokes `TxInclusionProofSoundness.md` directly as the (weaker) `tx_root` guarantee the message stream carries.
- **vs. `S033StateRootNamespaceCoverage.md`:** DC-3 specializes S-033 T-1 ("every apply-determining field is committed") to the registry entry; DC-4(1) is the explicit complement — the `DAPP_CALL` payload is *deliberately* outside the 10-namespace coverage, by design, and that absence is sound precisely because the payload is `tx_root`-committed instead.

---

## 6. Empirical anchors

The injectivity and commitment-coverage claims are exercised indirectly by existing regressions (no new test is added by this analytic proof):

- `tools/test_dapp_register.sh` + `tools/test_dapp_state_transition.sh` — populate `dapp_registry_` with concrete entries (including zero-topic, empty-metadata, multi-topic cases) that exercise every `enc_d` branch.
- `tools/test_dapp_snapshot.sh` — asserts the receiver's `state_root` exactly matches the snapshot tail head's stored `state_root` end-to-end, which holds **only if** the `d:` leaf `enc_d` is deterministic across serialize/restore (DC-2) and the `d:` namespace is covered by `state_root` (DC-3 premise / S-037).
- `tools/test_state_root_determinism.sh` — pins byte-identical `state_root` across replays, covering the `d:` loop's determinism (DC-2).
- `tools/test_light_*` trustless-read regressions — exercise the `state_proof` + `merkle_verify` pipeline DC-3 composes onto for the simple namespaces; the `d:` reader (sibling-agent work this round) consumes DC-1 as its value-binding lemma.

The negative result DC-4(3) (message-stream non-completeness under `state_root`) is, by construction, *not* falsifiable by a passing test — it is a statement about the absence of a commitment, established by inspection of `build_state_leaves` (no namespace reads a tx payload) rather than by execution.
