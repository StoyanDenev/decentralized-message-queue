# RegistrantProofSoundness — trust-minimized `r:`-namespace registrant-read soundness (RP-1..RP-6)

This document formalizes the soundness of a **trust-minimized registrant read** by the light client: the `determ-light verify-registrant --domain <D>` command lets an operator (or a would-be DApp client, or a peer auditing the validator set) learn a domain `D`'s on-chain `RegistryEntry` — its `ed_pub` (the validator's Ed25519 consensus key), its `region` tag, and the `(registered_at, active_from, inactive_from)` lifecycle anchors — from a *single untrusted daemon*, and verify it locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client act on a forged registration (a substituted `ed_pub`, a spoofed `region`, or a fabricated active/inactive lifecycle). The read targets the `r:` (registrants) namespace of the S-033 state-commitment surface.

The proof exists because the `r:` namespace **carries a load that none of its siblings do: it *is* the committee source.** The `a:`/`s:`/`d:` reads (`LightClientThreatModel.md` T-L4; `StakeProofSoundness.md`; `DAppRegistryReadSoundness.md`) attest balances, stakes, and DApp registrations — application/account state. The `r:` namespace is the **validator set the consensus committee is drawn from**: a registrant's `ed_pub` is the very key that signs the block digests every other trustless read anchors against (`StateRootAnchorSoundness.md` SR-1). A trustless `verify-registrant` therefore lets a light client **check validator-set membership** — answer "is domain `D` a registered validator at this height, with which consensus key, and is it currently in the active committee-eligible set?" — without running a full node. This is the read that closes the reflexive loop: the same committee whose signatures certify a `state_root` is itself certified, leaf-by-leaf, against that `state_root`.

Structurally the `r:` read is the **sibling of BOTH `s:` and `d:`**. Like `s:` (`StakeProofSoundness.md`) it is a **single-leaf value-bearing simple-ASCII-key** read: the leaf key `"r:" + domain` is a human-readable domain string (not a binary composite), so it rides a JSON string raw with no hex-body transport, and the leaf commits real content under one 32-byte value-hash. Like `d:` (`DAppRegistryReadSoundness.md`) the leaf is **lifecycle-bearing** — it carries `(active_from, inactive_from)`, so the read emits an `ACTIVE`/`INACTIVE` derived predicate, and it carries the same **value-hash cleartext cross-check** binding (recompute the committed leaf hash from a cleartext registry served over the `account` RPC) and the same **one-sided NOT-REGISTERED honesty boundary** (absence is `not_found`, never an authoritative negative). The `r:` value-hash is five fields — `ed_pub[32] ‖ registered_at ‖ active_from ‖ inactive_from ‖ |region| ‖ region` — one fixed-width 32-byte key, three fixed-width `u64`s, and one length-prefixed variable-length string: simpler than `d:`'s eight fields, richer than `s:`'s two `u64`s.

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a `RegistryEntry` that is inconsistent with the genesis-pinned chain's committed `r:` leaf at the verified height. The proof mirrors the `s:` read (`StakeProofSoundness.md` SP-1/SP-2/SP-3) and the `d:` read (`DAppRegistryReadSoundness.md` DR-1..DR-6) one-for-one, specialized to the `r:` namespace and its `SHA256(ed_pub ‖ registered_at ‖ active_from ‖ inactive_from ‖ |region| ‖ region)` value-hash encoding.

**Coverage significance.** With `verify-registrant`, `r:` becomes the **last simple-key namespace to receive a trustless reader**, completing the simple-key family `a:`/`s:`/`d:`/`r:` (each a single-leaf value-bearing read against a `"<ns>:" + domain` ASCII key). One S-033 namespace remains without a state-proof reader: **`b:` (abort_records, the S-032 cache)** is internal-only consensus bookkeeping with no operator-facing read surface; this proof does **not** claim `b:` is covered, and §6.6 records that boundary honestly. The composite-key namespaces (`i:`/`m:`/`p:`) are covered by their own proofs (`ReceiptInclusionProofSoundness.md` / `CompositeStateReadSoundness.md`); `c:` by `SupplyProofSoundness.md`.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1, **A4** = CSPRNG §2.3) — this proof reduces to **A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-2** leaf/inner + key domain separation, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core RP-2 consumes, **MT-5** non-membership boundary is exactly the limitation RP-4 honours, and **§6.2 (S-040, CLOSED)** is the now-enforced `leaf_count` root-binding); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding RP-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding; the transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` mechanism is reused verbatim — and is *especially* apt here because the `ed_pub` the `r:` leaf commits is the key that signs `digest(h+1)`); `StakeProofSoundness.md` (the `s:` simple-ASCII-key value-bearing sibling — RP-1/RP-2/RP-3 are the `r:` analogs of SP-1/SP-2/SP-3); `DAppRegistryReadSoundness.md` (the `d:` simple-ASCII-key lifecycle-bearing sibling — RP-4 mirrors DR-3's one-sided NOT-REGISTERED verdict + value-hash cross-check, RP-5 mirrors DR-6's lifecycle derived predicate, RP-6 mirrors DR-5's fail-closed exit discipline); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `r:` key + value-hash encoding read off `chain.cpp:298-308`, **T-1** confirms `registrants_` is committed to the root through `r:`, and **T-2** namespace disjointness guarantees `"r:"+D ≠ "a:"+D ≠ "s:"+D ≠ "d:"+D` at byte 0); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the trustless-read flow this proof specializes — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** simple-key read with race-window mitigation, **L-4** cleartext cross-check, **L-6** fail-closed exit); `NegativeVerdictSoundness.md` (the negative-verdict caller contract — **NV-6** governs that a `not_found`/`NOT-REGISTERED` is "no membership proof obtained," never authoritative absence, the contract RP-4 honours); `docs/SECURITY.md` §S-042 (the `committee_bound_state_root` state-root-binding RP-1 actually consumes — full-block recompute + committee-signed successor `prev_hash` binding; head fails closed); `StateProofRaceWindowSoundness.md` (PRW-1..PRW-5 — the *pre*-S-042 three-branch race-window dispatch; its off-by-one + stale-reject carry over, the `==`/extension-walk branches are superseded; predates S-042, pending its own update); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-038 + §S-040 for the closure narratives (all CLOSED); `docs/PROTOCOL.md` §4.1.1 for the canonical `r:` Merkle-leaf row + §10.2 for the `state_proof` RPC contract.

---

## 1. Scope

### 1.1 In scope

A single trust-minimized read answering one question without trusting the daemon that serves the data:

> **(`r:` read)** Is domain `D` currently a registered validator (a member of the set the consensus committee is drawn from), and if so, with which `ed_pub` consensus key, `region` tag, and lifecycle anchors `(registered_at, active_from, inactive_from)`, at the committee-verified height — and is it currently `ACTIVE` or `INACTIVE` against that height?

The read's logical pipeline mirrors `read_account_trustless` (`light/trustless_read.cpp:439-599`) with the `a:`-namespace argument replaced by `"r"` and the value-hash decode replaced by the `RegistryEntry` encoding; the shipped implementation is `cmd_verify_registrant` (`light/main.cpp:4456-4773`):

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:55-82`; invoked at `light/main.cpp:4499`): compute `compute_genesis_hash(genesis_O)` locally, fetch block 0, byte-compare. (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:234-248`; invoked at `light/main.cpp:4511`), invoking `verify_headers` + `verify_block_sigs` end-to-end from block 0, capturing `vc.head_state_root` + `vc.height`. (T-L2.) This yields a committee-anchored `state_root` (SR-1). If `vc.head_state_root` is empty the read throws (S-033 not active — `light/main.cpp:4512-4517`).
3. **State-proof fetch for the `r:` namespace** — `rpc.call("state_proof", {{"namespace","r"},{"key",domain}})` (`light/main.cpp:4520-4521`). The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3355-3429`) handles `"r"` in the simple-key branch (`node.cpp:3382`: `if (ns == "a" || ns == "s" || ns == "r" || ns == "d" || ns == "b" || ns == "k")`), building the prefixed key `"r:" + domain` byte-for-byte as `build_state_leaves` does, and returning `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Key binding** — bind `proof.key_bytes == "r:" + domain`, recomputed locally (`light/main.cpp:4504-4507` builds `local_key`; the byte-compare is at `light/main.cpp:4561-4570`). A mismatch ⇒ `UNVERIFIABLE`.
5. **Value-hash cleartext cross-check** — fetch the cleartext registrant via the `account` RPC (`light/main.cpp:4577`), recompute the canonical `RegistryEntry` value-hash from the daemon-asserted cleartext fields (`light/main.cpp:4614-4621`), and require equality against the proof's verified `value_hash` (`light/main.cpp:4623-4632`). (RP-3 / §4.3.)
6. **Committee-binding of the proof root (S-042)** — a stale-reject (`proof_height < vc.height` ⇒ throw, `light/main.cpp:4644-4650`) followed by `committee_bound_state_root` (`light/trustless_read.cpp:335-437`; invoked at `light/main.cpp:4667-4670`), which binds the proof's claimed `state_root` to the committee signature on the **successor** header rather than to the daemon-reported `state_root` field (which the committee digest excludes). (T-L4 §4.4.1 / RP-1; the mechanism is `docs/SECURITY.md` §S-042. The same helper backs every trustless reader — `verify-param-change`, `read_account_trustless`, `stake-trustless`, etc.)
7. **Merkle inclusion verify** — `verify_state_proof(proof, anchor_root)` (`light/verify.cpp:330-396`; invoked at `light/main.cpp:4690`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`). (T-L3 / RP-2.)
8. **Lifecycle derivation** — on `INCLUDED`, derive `ACTIVE`/`INACTIVE` from the committee-certified `(active_from, inactive_from)` against the committee-verified anchored head height (`light/main.cpp:4705-4708`). (RP-5 / §4.5.)

The verdict tri-state (mirroring `verify-dapp-registration` / `verify-param-change`):

| Verdict | Exit | Condition |
|---|---|---|
| `INCLUDED` | 0 | steps 1–8 pass: the `r:` leaf is committed under the committee-signed `state_root`, `key_bytes` matches the locally-recomputed `"r:" + D`, and `value_hash` matches the recomputed `RegistryEntry` encoding. The `RegistryEntry` is committee-anchored truth, plus a verified `ACTIVE`/`INACTIVE` verdict. (`light/main.cpp:4695-4708, 4768`.) |
| `NOT_INCLUDED` | 0 | the daemon returns the literal `not_found` for the *exact* `"r:" + D` key, **and** the `account` RPC's `registry` is also null/absent (cross-check). A **daemon-asserted negative** — sound only under the single-daemon negative-honesty premise (H-neg), NOT a cryptographic absence proof (`NegativeVerdictSoundness.md` NV-2/NV-3; the cross-check catches a *self-contradicting* daemon only, not a consistent liar); tagged `"negative_footing": "daemon_asserted"` in `--json` (F-2). Exit 0 (a definite answer) matches the whole InclusionVerdict reader family — `verify-dapp-registration` / `-receipt-inclusion` / `-merge-state` / `-param-change` all return 0 for INCLUDED *and* NOT-INCLUDED; only UNVERIFIABLE is non-zero. |
| `UNVERIFIABLE` | 3 | any of: a non-`not_found` daemon refusal; `key_bytes ≠ "r:"+D`; value-hash/cleartext mismatch; `merkle_verify` rejects; a `not_found` contradicted by a non-null cleartext registry; a present `r:` proof contradicted by a null cleartext registry. Fail-closed — refuses to assert either way. (`light/main.cpp:4546-4555, 4565-4570, 4626-4632, 4691-4693, 4767`.) |
| (transport/args) | 1 | usage error, RPC open failure, malformed hex, or any thrown exception. (`light/main.cpp:4470-4478, 4769-4772`.) |

### 1.2 The `r:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:298-308`):

```cpp
// registrants_
for (auto& [domain, r] : registrants_) {
    crypto::SHA256Builder b;
    b.append(r.ed_pub.data(), r.ed_pub.size());     // 32 raw bytes
    b.append(r.registered_at);                       // uint64, big-endian
    b.append(r.active_from);                         // uint64, big-endian
    b.append(r.inactive_from);                       // uint64, big-endian
    b.append(static_cast<uint64_t>(r.region.size()));// len prefix u64_be
    b.append(r.region);                              // utf8 bytes
    leaves.push_back({k_with_prefix("r:", domain), hash_bytes(b)});
}
```

so for a registered validator at domain `D` with entry `r`:

$$
\text{key}_r(D) \;=\; \texttt{"r:"} \,\|\, D \quad(\text{ASCII domain, no hex body}),
$$

$$
\begin{aligned}
\text{value\_hash}_r(r) \;=\; H\big(\,
&\texttt{ed\_pub}[32] \,\|\, u64\_be(\texttt{registered\_at}) \,\|\, u64\_be(\texttt{active\_from}) \,\|\, u64\_be(\texttt{inactive\_from}) \\
&\|\, u64\_be(|\texttt{region}|) \,\|\, \texttt{region}\,\big).
\end{aligned}
$$

`SHA256Builder::append(uint64_t)` writes the integer **big-endian** (the same width-and-endianness convention as `a:`/`s:`/`d:`), and the leaf hash recomputation in the light client (`light/main.cpp:4614-4621`) is **byte-identical** to this `chain.cpp:298-308` branch — `ed_pub.data()/size()`, then `registered_at`, `active_from`, `inactive_from`, then `region.size()` as a `u64`, then the `region` bytes. The source container is `registrants_ : std::map<std::string, RegistryEntry>` (`include/determ/chain/chain.hpp:549`, `RegistryEntry` at `chain.hpp:32-44`), keyed by the validator's Determ domain; **absence from the map is the canonical NOT-REGISTERED state**. This is exactly the `r:` row of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 and `PROTOCOL.md` §4.1.1.

**The load-bearing structural fact for `r:` (one length-prefixed variable-length field).** Four of the five sub-fields are fixed-width (`ed_pub` is 32 raw bytes; `registered_at`/`active_from`/`inactive_from` are `u64_be`). The fifth, `region`, is variable-length and is **length-prefixed** by a `u64_be` count immediately before its bytes. This length-prefixing is what makes the encoding **injective** (no two distinct `RegistryEntry` values collide on the preimage without a length ambiguity), and it is what a cross-implementation `r:`-leaf verifier MUST reproduce field-for-field: a verifier that omitted the `region.size()` prefix, or wrote it at a different width, or reordered the fields, would compute a different `value_hash` and reject a genuine leaf. RP-3's cleartext cross-check (§4.3) is stated against this exact canonical preimage. Note the `region` field was the last to join the leaf set (added with the cleartext exposure in commit `48a6f5d`; the leaf branch and the `account` RPC's `registry` block — `node.cpp:2727-2731` — were updated together so the cleartext source and the committed leaf agree field-for-field).

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-membership (the negative as a Merkle statement).** A light client *cannot* produce a Merkle proof that "domain `D` is **not** a registered validator" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). What `verify-registrant` *can* soundly emit is a `NOT_INCLUDED` verdict **conditioned on the daemon's literal `not_found` for the exact key plus a corroborating null cleartext registry** (§4.4 / RP-4) — a verified *daemon-honesty* statement, not a cryptographic absence proof. A daemon withholding a genuine `r:` leaf is still indistinguishable, under one peer, from genuine absence; the cross-check fails closed on any *detected* inconsistency, but a consistently-lying daemon (`not_found` + null registry for a genuine registrant) still forges the negative — so the verdict is sound only under (H-neg), never authoritative absence. This is the same boundary as `StakeProofSoundness.md` §6.1, `DAppRegistryReadSoundness.md` §6.1, and `NegativeVerdictSoundness.md` NV-6, inherited.
- **Lifecycle *interpretation* beyond the committed fields.** The `r:` read returns `(active_from, inactive_from)`; whether the validator is currently committee-eligible at the verifier's wall-clock is a *derived* predicate (`active_from <= h ∧ ¬(inactive_from deactivated)`) that the operator computes from the verified fields plus the committee-verified head height. The read proves the *fields* are committee-anchored; the lifecycle classification is a deterministic function of them, not a separate trust assumption. §4.5 / RP-5 proves the classification sound.
- **`ed_pub` cryptographic validity + committee-selection eligibility beyond the lifecycle gate.** The read proves the chain committed *this* `ed_pub` for `D` and that `D` is in the active set per `(active_from, inactive_from)`; it does **not** re-derive the randomized committee-selection lottery (`select_m_creators`) for a specific height, nor prove `ed_pub` is a well-formed point. Committee-selection determinism is `RegionalSharding.md` / the consensus proofs; the `r:` read is the membership/identity retrieval primitive those compose with.
- **The mutating side of the registry** (REGISTER / DEREGISTER apply rules, the randomized `active_from = height + derive_delay`, the randomized `inactive_from` on DEREGISTER, the stake `unlock_height` cascade). Those are apply-layer correctness (`AccountStateInvariants.md`, `S033StateRootNamespaceCoverage.md` §4.1.1, `PROTOCOL.md` §3.3); this proof reads the *committed* `r:` leaf and does not re-prove how it got there.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1–§6.7. Within one invocation the S-042 state-root binding (RP-1 / L-5; `committee_bound_state_root`) is sound; cross-invocation head-regression is operator-visible but not auto-detected.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged `account` registry replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM), `A_genesis` (tampered pinned `genesis.json`).

Specialized to the `r:` read, `A_daemon` will attempt one of:

- **(a) False-registration.** Convince the verifier that domain `D` is a registered validator with `ed_pub'` / `region'` / lifecycle anchors it does not genuinely have (or that an unregistered `D` is registered) — e.g., to make a peer trust a forged consensus key as if it were committee-eligible, or to misrepresent a deactivated validator as active.
- **(b) Suppressed-registration.** Convince the verifier that a genuine registration is *not provably present*. Under RP-4 this lands the verifier in `NOT_INCLUDED` only when the cleartext corroborates absence; any inconsistency yields `UNVERIFIABLE`. So (b) is at worst an *availability/honesty* downgrade against a withholding all-Byzantine peer set, never a false `INCLUDED`.

**Security goal.** Under `A_daemon`, an honest light client running `verify-registrant`:

- never returns `INCLUDED` for a `RegistryEntry` not genuinely committed in the `r:` leaf set of the genesis-pinned chain at the verified height;
- never returns a false `INCLUDED`; a `NOT_INCLUDED` is **daemon-asserted** — sound only under the single-daemon negative-honesty premise (H-neg) (`NegativeVerdictSoundness.md` NV-2/NV-3). An *inconsistent* leaf (a `not_found` contradicted by a non-null cleartext registry) yields `UNVERIFIABLE`, but a *consistent* denial of a genuine registration is forgeable by a Byzantine daemon — the verdict is never treated as authoritative absence (NV-6);
- never acts on a substituted leaf — any leaf whose recomputed Merkle path does not roll up to the committee-signed `state_root`, or whose `key_bytes`/`value_hash` do not match the canonical encoding for the queried domain, yields `UNVERIFIABLE`.

"Acts on" means *displays as authoritative*, *trusts the recovered `ed_pub` as a committee key*, or *feeds the lifecycle classification into a downstream decision*. The negation form is **fail-closed exit**: any detected inconsistency throws (exit 1) or sets `UNVERIFIABLE` (exit 3) with a structured stderr/JSON diagnostic (RP-6, inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

The read reuses the four light-client primitives unchanged — genesis anchor (`LightClientThreatModel.md` §3.1), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton, and the same S-042 `committee_bound_state_root` state-root binding `verify-param-change` / `verify-dapp-registration` use. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies with the state-proof stage targeting the simple ASCII key `key_r(D) = "r:" + D`. Two specializations distinguish the `r:` read from the balance read:

1. **Namespace argument + simple-ASCII-key transport.** The state-proof query is `{{"namespace","r"},{"key",D}}` with `D` the plain ASCII domain — **no hex-body encoding** (unlike the composite `i:`/`m:`/`p:` reads). The daemon's simple-key branch (`node.cpp:3382`) prepends `"r:"` and forwards. This is the *same* simple-key transport as `a:`/`s:`/`d:`/`b:`/`k:`; the `r:` namespace is explicitly enumerated in that branch.

2. **Five-field value-hash with a cleartext cross-check.** The `r:` leaf commits a `RegistryEntry` in the value-hash, so the verifier performs the cleartext cross-check of `StakeProofSoundness.md` SP-2 / `DAppRegistryReadSoundness.md` DR-2(iii) / `LightClientThreatModel.md` L-4: recompute the canonical preimage of §1.2 from the daemon-asserted `RegistryEntry` fields (fetched via the `account` RPC's `registry` block) and require equality against the proof's verified `value_hash`. A daemon lying about `ed_pub`, any lifecycle anchor, or `region` while serving an honest proof must find a colliding value-hash (A2).

Crucially, the daemon delivers `state_root`, `leaf_count`, `target_index`, `value_hash`, the sibling vector, and `key_bytes` from **one** `rpc_state_proof` reply computed atomically under the daemon's `state_mutex_` shared lock (`node.cpp:3357`), and the light client verifies the proof's `state_root` against a committee-signed header in the *same* invocation (`light/main.cpp:4637-4710`); `leaf_count` is itself bound into the committed root via the S-040 root-wrapper hash (`SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)`) — so a forged count is rejected regardless of source. This root-binding is the property the inherited S-040 closure (`MerkleTreeSoundness.md` §6.2) supplies; the `r:` read consumes it through `crypto::merkle_verify` exactly as `s:`/`d:` do (the `r:`-specific statement folds into RP-2 with no independent term — see §4.2's note).

---

## 4. Security theorems

Throughout, fix the queried domain `D`, `key_r(D) = "r:" ‖ D`, and `r_T` the true committed `RegistryEntry` for `D` (with true value-hash `value\_hash_r^T(r_T)`). Let `R := state_root(h)` be the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to. `D` is genuinely registered iff `key_r(D)` is a leaf of the tree `R` commits to.

### 4.1 Theorem RP-1 (committee-signed `state_root` binds the `r:` leaf)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that `verify-registrant` anchors and verifies the `r:` proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root the `r:` leaf is checked against is *committee-certified*, not daemon-asserted.

**Proof.** This is `StateRootAnchorSoundness.md` **SR-1** applied at the height the `r:` proof is anchored at, identical to `StakeProofSoundness.md` SP-1, `DAppRegistryReadSoundness.md` DR-1, and the inline anchoring at `light/main.cpp:4637-4710`. The binding of `state_root(h)` to the committee is **transitive-forward**, not a direct signature: the committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp::compute_block_digest`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root` (the `light/verify.cpp` digest-exclusion comment). `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim) and hence into `block_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`:

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

A reflexive remark unique to `r:`: the keys that sign `digest(h+1)` are precisely the `ed_pub` values committed in the `r:` leaves of (an earlier) committed state — so the `r:` read verifies the validator set *against a root that set's own keys certify forward*. This is not circular: the genesis committee `K_0` (loaded by `build_genesis_committee`, `light/main.cpp:4493`) is the trust root pinned out-of-band, and every subsequent root is bound to `K_0` through the SR-2 genesis-binding of the whole `0..h` walk; the `r:` read then *reads back* the on-chain registrant record, which a rotated committee would have to be in `K_0` to have signed for (the `K_0`-only caveat, §6.2).

Suppose the invocation anchors `R_A ≠ state_root_T(h)`. The SR-1 case split (reproduced for the `r:`-proof anchoring at `light/main.cpp:4637-4710`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`.** The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).
- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. The light client committee-verifies `h+1`'s signatures over `digest(h+1)` against `K_0` (`committee_bound_state_root`'s successor-sig check, `light/main.cpp:4667-4684` / `light/trustless_read.cpp:408-415`; and per-block in the `verify_chain_to_head` walk). To accept `h+1` with a different `prev_hash`, the daemon must present `required ≤ K` valid signatures over a different digest — an Ed25519 forgery for each of `required` distinct committee members, `≤ K · 2⁻¹²⁸` (A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* is supplied by SR-2 + SR-3 + T-L1's genesis anchor; RP-1 inherits them.

**Head-block boundary (S-042 binding + hold-and-wait).** The shipped flow does **not** trust the daemon-reported `state_root` field at any height (the committee digest excludes it, and stripped headers can't recompute `block_hash`). Instead it does exactly two things (`light/main.cpp:4644-4684`): (1) a **stale-reject** — `proof_height < vc.height` throws (`:4644-4650`), refusing a proof against a root predating the verified head; (2) otherwise it calls `committee_bound_state_root(anchor_index = proof_height − 1)` (`light/trustless_read.cpp:335-437`, invoked at `:4667-4670`), which fetches the **full** block at `anchor_index` via the `"block"` RPC, recomputes its `block_hash` locally, fetches the committee-signed **successor** header at `anchor_index + 1`, verifies its committee signatures, and binds `successor.prev_hash == recomputed block_hash(anchor_index)` (`trustless_read.cpp:417-432`) — the run-time construction of the Case (i)/(ii) argument above. A mismatch with the proof's claimed root throws (`light/main.cpp:4671-4679`). There is **no** separate head-height byte-match branch and **no** prev_hash extension walk. The head case — where the queried block IS the chain head and has no committee-signed successor yet — is handled inside `committee_bound_state_root` by an opt-in **hold-and-wait**: it polls up to `--wait <seconds>` for the next block to be produced, then binds the **already-held** proof (never re-fetching, so no state race); with `--wait 0` (default) the head read fails closed immediately (`trustless_read.cpp:375-401`; S-042 liveness follow-up). This is `LightClientThreatModel.md` L-5, mechanized by S-042. RP-2 below proves Merkle-path soundness *given* such an `R`; RP-1 is the committee-binding of `R`. (`StateProofRaceWindowSoundness.md` PRW-1..PRW-5 formalizes the *pre*-S-042 three-branch race-window dispatch — its off-by-one PRW-2 and stale-reject carry over, but its `==`-byte-match and prev_hash-extension-walk branches are superseded by the single successor-binding above; that proof predates S-042 and is pending its own update.)

**Concrete-security bound.** `Pr[A_daemon wins RP-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem RP-2 (Merkle state-proof for the `r:` leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from RP-1, a verifier holding `R` cannot be made to accept `INCLUDED` for a queried domain `D` whose `r:` leaf (`key_r(D)`) is **not** committed under `R`, nor accept a wrong `RegistryEntry` cleartext, without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; key_r(D),\; value\_hash_{\text{served}},\; target\_index,\; n,\; proof) = \texttt{true}
\quad\wedge\quad value\_hash_{\text{served}} = H(\text{preimage}(r_A)),
$$

then either (a) `key_r(D)` is a genuine leaf of the tree `R` commits to at sorted position `target_index` with the genuine committed entry `= r_A`, or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves `D` is registered with the asserted `RegistryEntry`, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as RP-1: the light client has anchored committee-signed `R`.
2. `A_daemon` returns a state-proof `P_A = (key_bytes_A, value\_hash_A, target\_index, n, proof)` claiming `D` is registered with entry `r_A` when it is not. It may (i) serve a genuine leaf for some *other* registered domain and relabel it, (ii) serve a non-`r:` leaf (e.g. an `a:` or `s:` or `d:` leaf for the **same** domain) with a forged `key_bytes`, (iii) serve a `value\_hash_A` inconsistent with the `r_A` it asserts over the `account` RPC, or (iv) alter `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true` **and** the verdict is `INCLUDED`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the `r:` leaf, plus the **MT-2** leaf-key domain separation. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value\_hash_A, target\_index, n, sibs)` (`light/verify.cpp:378-380`), which recomputes the leaf hash

$$
c_0 = \text{merkle\_leaf\_hash}(key_bytes, value\_hash_A) = H(\texttt{0x00} \| u32\_be(|key_bytes|) \| key_bytes \| value\_hash_A)
$$

and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R` (`merkle.cpp:139`).

The verifier additionally requires `key_bytes = key_r(D)` (the locally-recomputed `"r:" + D`, `light/main.cpp:4561-4570`) **and** `value\_hash_A = H(\text{preimage}(r_A))` for the asserted entry (`light/main.cpp:4623-4632`). With those equalities pinned, the recomputed `c_0` is *exactly* the genuine `r:` leaf hash for `D` iff the committed entry equals `r_A`. By MT-4's extraction: if the leaf for `key_r(D)` with value-hash `value\_hash_A` is **not** committed under `R`, then the recomputed chain and the genuine root-path chain for sorted position `target_index` both terminate at `R` but disagree, exhibiting two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` mapping to the same `H` output at the highest divergence level — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** defeats the four attack shapes:

- **(i) relabel another domain's leaf.** The daemon serves the genuine `r:` leaf for a *different* registered domain `D' ≠ D`, but the verifier's recomputed `c_0` uses `key_r(D)` for the *queried* domain; since distinct domains have distinct length-prefixed keys (`"r:" + D ≠ "r:" + D'`), the recomputed leaf hash composes the served siblings into a *different* chain and fails root-equality. A pass requires a leaf-level collision (`≤ 2⁻¹²⁸`).
- **(ii) cross-namespace swap — the byte-0 disjointness is load-bearing here.** This is the case that most distinguishes the `r:` read. **The same domain string `D` keys an `a:` account leaf, an `s:` stake leaf, a `d:` DApp leaf, AND an `r:` registrant leaf** — only the namespace prefix byte distinguishes the four. The daemon could serve the genuine `a:`-leaf (the account/balance) for `D` and forge `key_bytes` to claim it is the `r:` leaf. The verifier recomputes the leaf hash over `key_r(D)`, which begins with the `"r:"` prefix; by `S033StateRootNamespaceCoverage.md` **T-2** namespace disjointness, `"r:"+D ≠ "a:"+D` (and `≠ "s:"+D`, `≠ "d:"+D`) **at byte 0**, so the recomputed leaf hash differs from any cross-namespace leaf's hash, producing a different sibling chain and failing root-equality. Only the `"r:"` prefix prevents an **account-leaf-relabel** from passing as a registrant proof. This is the same cross-namespace-swap rejection `StakeProofSoundness.md` SP-2 and `DAppRegistryReadSoundness.md` DR-2(ii) invoke (the `test_state_proof_namespaces.sh` swap assertions), made sharper here because all four same-`D` namespaces collide on the suffix and disjoin only on the prefix byte.
- **(iii) value-hash / cleartext inconsistency.** The verifier recomputes `H(\text{preimage}(r_A))` over the full §1.2 length-prefixed preimage (`light/main.cpp:4614-4621`) and rejects unless it equals `value\_hash_A` (`light/main.cpp:4625`); a daemon asserting a `RegistryEntry` over the `account` RPC that does not hash to the served value-hash is caught at the §4.3 cross-check → `UNVERIFIABLE`. And a daemon serving a `value\_hash_A` that does *not* match the genuine committed value-hash changes `c_0` and (by MT-4) fails root-equality against `R`. So a daemon lying about `ed_pub`, any lifecycle anchor, or `region` while serving an honest proof must find a colliding value-hash — A2 (`≤ 2⁻¹²⁸`). The verified statement is *"domain `D` is registered with this specific `ed_pub`/`region`/lifecycle,"* not merely *"`D` is present."* The injectivity of the §1.2 length-prefixed preimage (the lone variable-length field, `region`, length-prefixed) ensures a single canonical preimage per `RegistryEntry`, so the cross-check is unambiguous.
- **(iv) index / sibling tamper.** Covered by MT-4's range/underflow/exact-consume gates exactly as in SP-2 / DR-2 (`MerkleTreeSoundness.md` §2.6 scenarios #5-#8; `determ test-merkle-proof-tampering`).

By `S033StateRootNamespaceCoverage.md` **T-1**, the `registrants_` map is bound to the root through `r:`, so the leaf RP-2 verifies is the genuine committed registration. **`leaf_count` note (S-040 CLOSED, inherited):** `merkle_verify` re-applies the root-wrapper `SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` with the caller-supplied `leaf_count` and compares to `R`, so a forged count is rejected by the hash regardless of source — exactly as `StakeProofSoundness.md` SP-3 / `DAppRegistryReadSoundness.md` DR-4 establish for `s:`/`d:`. The `r:` read consumes this closure with no independent term; the wrapper binding folds into the same A2 collision reduction.

**Concrete-security bound.** `Pr[A_daemon wins RP-2] ≤ log₂(n) · 2⁻¹²⁸`; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`.   ∎

#### 4.2.1 The key + value-hash cross-check (why `INCLUDED` is crisp)

Two equalities, both computable by the verifier with **no daemon trust**, convert "a Merkle proof verified against `R`" into "domain `D` is registered with this specific `RegistryEntry`":

1. **Key equality.** `key_bytes == key_r(D)`, where `key_r(D) = "r:" + D` is built locally from the operator's `--domain` argument (`light/main.cpp:4504-4507`). The verifier re-derives the canonical key and byte-compares against the daemon-returned `key_bytes` (`light/main.cpp:4561-4570`), rejecting any mismatch — pinning the proven leaf to *this* domain `D`. Because the same `D` also keys the `a:`/`s:`/`d:` leaves, the namespace byte in `key_r(D)` is load-bearing (RP-2 (ii)).
2. **Value-hash equality.** `value_hash == H(\text{preimage}(r_A))`, where the verifier recomputes the canonical §1.2 preimage (`ed_pub ‖ registered_at ‖ active_from ‖ inactive_from ‖ |region| ‖ region`) from the daemon-asserted cleartext registry fields (`light/main.cpp:4614-4621`). This confirms the leaf commits the asserted entry and not some other content. The **field order, the `u64_be` width of each scalar and of the `region` length prefix, and the 32-byte raw `ed_pub`** are all part of the canonical preimage; the verifier decodes the 64-hex `ed_pub` back to its 32 raw bytes and rejects if it is not 32 bytes (`light/main.cpp:4602-4607`).

With (1)+(2) pinned and RP-2's root-equality, `INCLUDED` means exactly *"the leaf `(key_r(D), H(\text{preimage}(r_A)))` is committed under the committee-signed `R`."* The verifier emits `INCLUDED` only on this conjunction; any failure of (1), (2), RP-1, or RP-2 yields `UNVERIFIABLE` (fail-closed, RP-6).

### 4.3 Theorem RP-3 (value-hash cross-check binding — the load-bearing step)

**Statement.** Under (A2), the cleartext cross-check pins the daemon's human-readable `RegistryEntry` (served over the `account` RPC's `registry` block) to the committee-committed `r:` leaf: a daemon that lies about `ed_pub`, `registered_at`, `active_from`, `inactive_from`, or `region` while serving an otherwise-honest Merkle proof must exhibit a SHA-256 collision to pass. The recomputed value-hash

$$
H\big(\texttt{ed\_pub}[32] \| u64\_be(\texttt{registered\_at}) \| u64\_be(\texttt{active\_from}) \| u64\_be(\texttt{inactive\_from}) \| u64\_be(|\texttt{region}|) \| \texttt{region}\big)
$$

computed by the light client at `light/main.cpp:4614-4621` is **byte-identical** to the committed-leaf computation at `src/chain/chain.cpp:300-307`, so equality against the proof's verified `value_hash` (`light/main.cpp:4625`) is the binding from cleartext to commitment.

**Proof.** The `account` RPC (`node.cpp:2722-2748`) returns, for a registered domain, a `registry` object with `ed_pub` (hex), `registered_at`, `active_from`, `inactive_from`, and `region` (`node.cpp:2727-2731`) — sourced from the same `registrants_` map (`node.cpp:2716-2719`) that `build_state_leaves` hashes. The light client decodes `ed_pub` from 64-hex to 32 raw bytes (`light/main.cpp:4602`), reads the three `u64` height fields and the `region` string (`light/main.cpp:4594-4598`), and feeds them to a `SHA256Builder` in the exact field order and width of the `chain.cpp:300-307` `r:` branch. Because `SHA256Builder::append(uint64_t)` is big-endian on both sides and the `region` length prefix is a `u64` on both sides, the two preimages are byte-equal iff the cleartext fields equal the committed fields.

Now suppose the daemon serves a cleartext `r_A` differing from the genuine committed `r_T` in any field, alongside the genuine committed `value\_hash_r^T`. The cross-check recomputes `H(\text{preimage}(r_A))` and compares to `value\_hash_r^T`. For the comparison to pass, `H(\text{preimage}(r_A)) = H(\text{preimage}(r_T))` with `\text{preimage}(r_A) ≠ \text{preimage}(r_T)` — a SHA-256 collision, `≤ 2⁻¹²⁸` (A2). The **injectivity** of the encoding makes `\text{preimage}(r_A) ≠ \text{preimage}(r_T)` follow from `r_A ≠ r_T`: the lone variable-length field (`region`) is length-prefixed, so a difference in any field — including a `region` of a different length, or one whose bytes shift across the boundary — produces a distinct preimage with no parsing ambiguity, keeping the cross-check unambiguous. Conversely, if the daemon keeps the cleartext honest but serves a tampered `value\_hash_A ≠ value\_hash_r^T`, the cross-check fails directly (`H(\text{preimage}(r_T)) ≠ value\_hash_A`) → `UNVERIFIABLE` (`light/main.cpp:4626-4632`); and if it tampers *both* consistently, RP-2's root-equality catches it (a wrong committed value-hash fails the Merkle walk against `R`). The cross-check thus binds the displayed `ed_pub` / lifecycle / `region` to committee-anchored truth, identically to the balance read's L-4 and the `d:` read's DR-2(iii).

**Concrete-security bound.** `Pr[A_daemon defeats RP-3] ≤ 2⁻¹²⁸` (A2). Folds into RP-2; adds no independent end-to-end term.   ∎

### 4.4 Theorem RP-4 (one-sided verifier; `NOT_INCLUDED` is a daemon-asserted negative via the daemon's literal `not_found`)

**Statement.** The `r:` read is a **one-sided** verifier in the cryptographic sense (no Merkle non-membership proof exists). It emits a `NOT_INCLUDED` verdict that is a **daemon-asserted negative** — sound only under the single-daemon negative-honesty premise (H-neg) (`NegativeVerdictSoundness.md` NV-2/NV-3), *not* a cryptographic absence proof — conditioned on the conjunction:

1. the daemon returns the literal `not_found` error for the **exact** `"r:" + D` key (`light/main.cpp:4532-4536`), **and**
2. the `account` RPC's `registry` for `D` is also null/absent (`light/main.cpp:4542-4544`).

If (1) holds but (2) fails — the daemon says `not_found` for the `r:` proof yet returns a *non-null* registry over `account` — the verifier refuses `NOT_INCLUDED` and emits `UNVERIFIABLE` (inconsistent daemon, `light/main.cpp:4545-4551`). Symmetrically, if a *present* `r:` proof is served but the cleartext registry is **null**, the verifier throws (`light/main.cpp:4584-4591`) — a null registry with a present `r:` proof is an inconsistent daemon, fail closed. The cross-check defeats a *self-contradicting* daemon — any contradiction between the `r:` proof surface and the `account` cleartext collapses to `UNVERIFIABLE`. It does **not** defeat a *consistent* liar: a daemon that answers `not_found` for the `r:` proof **and** returns a null registry for a domain that is genuinely registered forges a false `NOT_INCLUDED` at zero cryptographic cost (NV-2). The verdict is therefore sound only under (H-neg); it is never authoritative absence.

**Analysis.** The sorted-leaves balanced binary Merkle primitive supports **positive membership only** (`MerkleTreeSoundness.md` **MT-5**): there is no native non-membership (absence) proof. `Chain::state_proof` returns `std::nullopt` for an absent key (`chain.cpp:449`), surfaced by the daemon as `{"error":"not_found"}` (`node.cpp:3428`). An honest light client receiving this can only conclude *"this daemon did not give me a proof,"* which an all-Byzantine peer set could produce by withholding. The read therefore does **not** treat `not_found` as a cryptographic absence proof; instead it treats `NOT_INCLUDED` as a *daemon-asserted negative* — sound only under (H-neg) — recording this daemon's consistent claim of absence, gated on the two-sided agreement of (1)+(2). The caller contract of `NegativeVerdictSoundness.md` **NV-6** applies: a `r:` `NOT_INCLUDED`/`not_found` is "no membership proof obtained" for value-affecting decisions against a withholding adversary — the operator falls back to a multi-peer cross-check (out of scope) where authoritative absence matters.

**Why the cross-check matters (and its limit).** The cross-check raises the bar for a *lazy* suppression attack: a daemon that serves `not_found` for the `r:` proof while the genuine registrant is still reflected in its own `account` cleartext trips condition (2), and the verdict is `UNVERIFIABLE`, operator-visible. To force a false `NOT_INCLUDED` the daemon must *also* lie in the cleartext (return a null registry) so both surfaces consistently deny the registration. This is exactly the **(H-neg)** boundary of `NegativeVerdictSoundness.md` NV-2/NV-3: a *consistently* lying daemon still produces a false `NOT_INCLUDED` at probability 1 — the cross-check makes the lie require two coordinated surfaces, not impossible. The verifier never *asserts* absence as committee-anchored truth; it asserts only that the daemon is internally consistent in denying it, and a caller MUST treat that per NV-6 clause (3) (no authoritative absence). The soundness goal (§2) — never a false `INCLUDED`; a `NOT_INCLUDED` sound only under (H-neg); fail closed on any *detected* inconsistency — is met as stated.   ∎

### 4.5 Theorem RP-5 (ACTIVE/INACTIVE is a sound derived predicate)

**Statement.** Given an `INCLUDED` `RegistryEntry` (RP-1 + RP-2 + RP-3) at committee-verified anchored head height `h := anchored_height`, the lifecycle classification

$$
\text{active}(D, h) \;=\; \big(\texttt{active\_from} \le h\big) \;\wedge\; \neg\,\big(\texttt{inactive\_from} \ne 0 \;\wedge\; \texttt{inactive\_from} \le h\big)
$$

(computed at `light/main.cpp:4705-4708`) is a **deterministic function of the committee-anchored fields** `(active_from, inactive_from)` and the committee-verified head height `h`. It introduces **no additional trust assumption** beyond RP-1 + RP-2 + RP-3: both inputs are committee-certified (the `active_from`/`inactive_from` fields via the §4.3 value-hash cross-check, the head height `h` via the verified-chain walk), so `INACTIVE` is a **verified verdict, not a daemon claim**.

**Proof.** `active_from` and `inactive_from` are two of the five fields committed in the §1.2 value-hash preimage, so RP-3's cross-check certifies their values under the committee-signed root. The head height `h = anchored_height` is the committee-anchored height set by the S-042 binding (`light/main.cpp:4697`), bound to the committee by the successor-sig check (RP-1). The classification is a pure comparison `h <?> active_from` and `h <?> inactive_from` against the deactivation sentinel — matching the on-chain committee-selection gate that admits a registrant to the eligible set once `active_from <= height` and excludes it once it has deactivated.

The reader's deactivation guard uses `inactive_from != 0` as the "never deactivated" sentinel (`light/main.cpp:4706`), whereas the in-memory struct default is `inactive_from = UINT64_MAX` (`chain.hpp:38`). Both sentinels classify as **not-deactivated** under the comparison, soundly: a genesis creator or freshly-registered validator carries `inactive_from = UINT64_MAX`, and `UINT64_MAX <= h` is false for every realizable head height `h`, so the `&& inactive_from <= height` conjunct is false ⇒ `deactivated = false` ⇒ such a registrant classifies `ACTIVE` (once `active_from <= h`). The `!= 0` guard additionally excludes a `0` value (an unset/legacy field) from spuriously reading as a deactivation at height 0. Thus `ACTIVE` holds exactly when the validator is in the active set at `h`, and `INACTIVE` is emitted only when the committee-certified `active_from`/`inactive_from` and the committee-verified `h` jointly place `D` outside that set. Since both operands are committee-certified and the predicate is a deterministic comparison, the classification a light client computes from an `INCLUDED` read agrees with what a full node would compute at the same height. No daemon can present an `INCLUDED` entry whose `active_from`/`inactive_from` differ from the committed values (RP-2 (iii) / RP-3), so no daemon can flip the classification.

The one residual subtlety is the **head-freshness honesty boundary** (§6.3): a registrant can transition `pending → active → inactive` purely as `h` advances; a verifier reading at anchored height `h_0` classifies *as of* `h_0`, and the classification is only as current as the verified head. Within one invocation against a non-stale head, the classification is sound.   ∎

**Why this matters for validator-set membership.** Because `r:` *is* the committee source, RP-5 is the read that lets a light client answer "is `D` a currently-active validator?" — committee-eligibility being gated on exactly `active_from <= h` and not-yet-deactivated. A peer auditing whether a forged `ed_pub` could appear in the committee can now check, trustlessly, both that the chain committed *that* key for `D` (RP-2/RP-3) and that `D` is in the active set at the verified head (RP-5) — turning a full-node-only validator-set query into a single-untrusted-daemon read.

### 4.6 Lemma RP-6 (fail-closed exit-code discipline)

**Statement.** The read's exit codes are sound: `INCLUDED` → 0 on a verified answer (the full RP-2 conjunction); `NOT_INCLUDED` → 0 on the RP-4 two-sided `not_found` agreement (a daemon-asserted negative, (H-neg)); `UNVERIFIABLE` → 3 on any detected inconsistency; args/transport errors → 1. **There is no code path from a detected inconsistency to a false `INCLUDED`.** (Per `light/main.cpp:4767-4768`: `UNVERIFIABLE` returns 3, else returns 0 — so `INCLUDED` AND `NOT_INCLUDED` share the exit-0 *definite-answer* tier — `INCLUDED` cryptographically sound, `NOT_INCLUDED` daemon-asserted — and `UNVERIFIABLE`/error are the non-zero fail-closed tier, matching the whole InclusionVerdict reader family.)

**Proof.** By inheritance from `LightClientThreatModel.md` Lemma **L-6** for the reused T-L1/T-L2/T-L3 surfaces (`verify_headers`, `verify_block_sigs`, `verify_state_proof` each set `r.ok=false` + `r.detail` on every error branch and return to a caller that throws or sets `UNVERIFIABLE`; `anchor_genesis` throws on genesis mismatch — `light/main.cpp:4769-4772` catches every `std::exception` to exit 1), plus the §4.2.1 structural property that `INCLUDED` is reached *only* on the conjunction (RP-1 anchored ∧ RP-2 root-equality ∧ key-equality ∧ value-hash-equality, set at `light/main.cpp:4695`). Every failure branch sets `UNVERIFIABLE` or throws: a non-`not_found` daemon refusal (`light/main.cpp:4552-4555`), `key_bytes` mismatch (`light/main.cpp:4565-4570`), an account-RPC refusal or null-registry on a present proof (`light/main.cpp:4578-4591`, throws), value-hash mismatch (`light/main.cpp:4626-4632`), a stale or non-matching proof root (`light/main.cpp:4644-4650, 4671-4679`, throws), and `merkle_verify` rejection (`light/main.cpp:4691-4693`). The `not_found`-but-non-null-registry contradiction sets `UNVERIFIABLE` (`light/main.cpp:4545-4551`). There is no path from any of these to `INCLUDED`. This is the per-command instance of L-6; the throw-discipline is structural.   □

### 4.7 End-to-end composition

**Corollary RP-E (trust-minimized registrant read).** Under A1 + A2, `verify-registrant --domain D` yields an `INCLUDED` verdict bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis (with a verified `ACTIVE`/`INACTIVE` classification), a daemon-asserted `NOT_INCLUDED` (sound only under (H-neg)), or a fail-closed `UNVERIFIABLE`. Composing RP-1 (committee-anchored root) + RP-2 (`r:` Merkle inclusion + key/value-hash binding, including the inherited S-040 `leaf_count` root-binding) + RP-3 (value-hash cleartext cross-check) + RP-5 (sound lifecycle derivation) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline:

$$
\Pr[A_{\text{daemon}} \text{ wins RP-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4, the stake-read bound of `StakeProofSoundness.md` SP-E, and the DApp-read bound of `DAppRegistryReadSoundness.md` DR-E exactly, as expected: the `r:` read differs only in the key construction (simple ASCII) and the leaf encoding (the five-field `RegistryEntry` value-hash), both namespace-agnostic in every cryptographic step. RP-E covers the *positive* (`INCLUDED`) verdict for soundness; the negative is `NOT_INCLUDED` only under RP-4's two-sided agreement, else `UNVERIFIABLE`.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

RP-2 *is* MT-4 applied at the `r:` leaf, with **MT-2** (leaf/inner + key domain separation) carrying the cross-namespace-swap rejection (especially the `a:`-leaf-vs-`r:`-leaf-for-the-same-domain case — the account-leaf-relabel) and the relabel rejection (distinct domains ⇒ distinct keys). MT-1 (determinism) guarantees the `r:` leaf's position and the root are reproducible across honest nodes; MT-3 (collision-resistance inheritance) makes any wrong committed registrant set produce a different root. RP-4 is the `r:`-namespace statement of MT-5's positive-only boundary; the `leaf_count` root-binding RP-2 consumes is MT-4's §6.2 (S-040 CLOSED).

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

RP-1 *is* SR-1 applied at the height the `r:` proof is anchored at, plus SR-2 (genesis-binding) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism (`state_root` is **not** in `compute_block_digest`; it is committee-bound transitively forward via the successor block's signed digest). The `r:` read is *reflexively* a consumer of SR-1: the `ed_pub` it reads back is the very class of key that produces the signatures SR-1 reduces to, with the genesis committee `K_0` as the out-of-band trust root (§4.1 remark).

### 5.3 `StakeProofSoundness.md` — the `s:` value-bearing simple-key sibling

RP-1/RP-2/RP-3 are the `r:` analogs of `StakeProofSoundness.md` SP-1/SP-2/SP-3. Both `r:` and `s:` are single-leaf value-bearing reads against a `"<ns>:" + domain` ASCII key, share the value-hash cleartext cross-check, and share the simple-ASCII-key transport (no hex body). The differences: `s:` decodes two `u64`s `(locked, unlock_height)` with no variable-length field and no lifecycle verdict; `r:` decodes five fields including one length-prefixed `region` and emits a lifecycle verdict. Both inherit the S-040 `leaf_count` root-binding (SP-3 ≡ the note in RP-2) and the one-sided non-membership boundary (SP §6.1 ≡ RP-4's cryptographic side).

### 5.4 `DAppRegistryReadSoundness.md` — the `d:` lifecycle-bearing simple-key sibling

RP-4/RP-5/RP-6 mirror `DAppRegistryReadSoundness.md` DR-3/DR-6/DR-5. RP-4 is the `r:` form of DR-3's one-sided NOT-REGISTERED verdict + the value-hash cleartext cross-check (RP-4 adds the `account`-RPC two-sided `not_found` corroboration that `verify-registrant` performs, where the `d:` read uses `dapp_info`). RP-5 is the `r:` form of DR-6's lifecycle derived predicate — both classify `active`/`inactive` from a committee-certified `inactive_from` vs the committee-verified head, matching the chain's own apply-time gate. RP-6 is the `r:` form of DR-5's fail-closed exit discipline. The structural difference: `d:`'s value-hash is the richest (eight fields, three variable-length) while `r:`'s is intermediate (five fields, one variable-length); `d:`'s lifecycle drives a DAPP_CALL pre-flight check while `r:`'s drives a validator-set-membership check.

### 5.5 `S033StateRootNamespaceCoverage.md` — the namespace surface

**T-1** (coverage completeness) confirms `registrants_` is committed to the root through `r:` (and through *no other*, by **T-2** disjointness), so the leaf RP-2 verifies is the genuine committed registration. §2.1's table fixes the byte-exact `r:` key (`"r:" + domain`) + the five-field value-hash this proof reads off `chain.cpp:298-308`. T-3 (deterministic leaf ordering) — `registrants_` iterates by ascending `domain` (`std::map` ordering, noted at `chain.hpp:239`) — + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes. The byte-0 namespace disjointness of T-2 is **especially** load-bearing for `r:` because the same domain string `D` keys leaves in four namespaces (`a:`, `s:`, `d:`, `r:`); only the prefix byte distinguishes them, and RP-2's cross-namespace-swap rejection (ii) — the account-leaf-relabel defense — relies on exactly that.

### 5.6 `LightClientThreatModel.md` / `NegativeVerdictSoundness.md` / `StateProofRaceWindowSoundness.md` — the adversary model, negative contract, and state-root binding

This proof specializes T-L3 (state-proof correctness) + T-L4 (simple-key read with race-window mitigation) + L-4 (cleartext cross-check) from the `a:` namespace to `r:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6 / RP-6), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. RP-E's bound equals T-L4's bound. `NegativeVerdictSoundness.md` NV-6 is the caller contract RP-4 honours (a `not_found`/`NOT_INCLUDED` is "no membership proof obtained" against a withholding adversary, never authoritative absence). The state-root binding RP-1 actually consumes is **S-042** `committee_bound_state_root` (`light/trustless_read.cpp:335-437`; invoked at `light/main.cpp:4644-4684`): full-block recompute + committee-signed successor `prev_hash` binding, head fails closed (opt-in `--wait` hold-and-wait). `StateProofRaceWindowSoundness.md` PRW-1..PRW-5 formalizes the *superseded* pre-S-042 three-branch `proof_height < / == / >` dispatch — its off-by-one (PRW-2) and stale-reject (`<` branch) carry over to S-042, but the `==`-byte-match and prev_hash-extension-walk branches no longer exist; that proof predates S-042 and is pending its own update.

### 5.7 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the `r:` proof anchors against an S-033-committed root. As with the other trustless reads, the flow must fail-closed with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`light/main.cpp:4512-4517`) — a chain-level deployment prerequisite. RP-1's interior regime is exactly the S-033-active regime. The `registrants_` map is part of the S-033-committed state (and round-trips through the snapshot serialize/restore), so RP-2's "the daemon's served root is the genuine committed root" hypothesis holds even on a snapshot-bootstrapped daemon.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Several are worth calling out for the `r:` read specifically.

### 6.1 One-sided: no cryptographic non-membership; `NOT_INCLUDED` is daemon-honesty-conditioned (RP-4)

The read cannot produce a Merkle proof of `NOT-REGISTERED`. Its `NOT_INCLUDED` verdict is sound only as a *verified daemon-honesty* statement (literal `not_found` for the exact key + corroborating null cleartext registry); a withholding all-Byzantine peer set is indistinguishable from genuine absence under one peer. Multi-peer cross-check (out of scope) is the only mitigation. The caller contract of `NegativeVerdictSoundness.md` NV-6 applies. Same positive-only cryptographic boundary as the `s:`/`d:`/`i:`/`m:`/`p:` siblings.

### 6.2 Committee-rotation (genesis committee `K_0` only)

Like every other light-client verifier, the read seeds the committee map from genesis `initial_creators` (`build_genesis_committee`, `light/main.cpp:4493`) and requires every creator in the `0..h` walk to be in that map. On a chain with mid-chain REGISTER/DEREGISTER that rotated the committee, the walk **fails closed** at the first non-`K_0` signer → exit 1 / `UNVERIFIABLE` — a positive safety property, never a wrong verdict. This is the reflexive caveat for the `r:` read in particular: the very registrant churn the `r:` namespace records is what would rotate the committee away from `K_0`, so a `verify-registrant` against a long-rotated chain may fail to anchor even as it reads back a genuine registrant. Shared `K_0` caveat (`LightClientThreatModel.md` §6.5 + F-1, `StakeProofSoundness.md` §6.2, `DAppRegistryReadSoundness.md` §6.2).

### 6.3 Lifecycle currency is bounded by head freshness (RP-5)

RP-5's classification is sound *for the verified anchored height `h`*. A registrant transitions `pending → active → inactive` purely as `h` advances, with no apply event needed for the `pending → active` and `active → inactive` boundaries. A verifier reading against a stale head classifies against an old `h` and could report `ACTIVE` for a registrant the *current* chain considers deactivated (or vice versa). Stale-head detection is operator-visible (`LightClientThreatModel.md` §6.1) but not auto-detected within a single invocation; the classification is "as of the verified head," and a client wanting current-tip lifecycle must re-read against a fresh head.

### 6.4 The read attests the committed `ed_pub`, not committee-selection for a specific height

The `r:` read proves the chain committed *this* `ed_pub` for `D` and that `D` is in the active set per its lifecycle anchors (RP-5); it does **not** re-run the randomized committee-selection lottery to prove `D` is in the committee `K_h` for a *specific* height `h`. Active-set membership is necessary but not sufficient for selection in any given round. Committee-selection determinism is the consensus/`RegionalSharding.md` surface; the `r:` read is the membership/identity retrieval primitive that composes with it.

### 6.5 The read attests committed fields, not key validity or off-chain control

The read proves the chain committed `ed_pub`/`region`/lifecycle for `D`; it does not prove `ed_pub` is a well-formed Ed25519 point, nor that the operator of `D` controls the corresponding secret key today (a registration could commit a compromised or adversarial key). The read defeats a *daemon* substituting a different key than the chain committed, not a malicious *registration*. Any downstream trust in the recovered key is the consumer's responsibility.

### 6.6 Coverage boundary — `b:` (abort_records) has no reader

With `verify-registrant`, `r:` is the **last simple-key namespace to receive a trustless reader**, completing the simple-key family `a:`/`s:`/`d:`/`r:`. One S-033 namespace remains **without** any state-proof reader: **`b:` (abort_records, the S-032 cache)** is internal consensus bookkeeping (the daemon enumerates it in the simple-key branch at `node.cpp:3382` so a proof *could* be requested, but no operator-facing `verify-*` command consumes it, and there is no value-bearing cleartext to cross-check against). This proof makes **no** claim that `b:` is covered. The composite-key namespaces `i:`/`m:`/`p:` have their own readers (`ReceiptInclusionProofSoundness.md` / `CompositeStateReadSoundness.md`), `c:` has `SupplyProofSoundness.md`, and `k:` (constants) is committee-fixed. The trustless-read family is thus complete across every *value-bearing, operator-queryable* namespace, with `b:` the lone internal-only exception.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Statement | Primary code citation | Composition |
|---|---|---|---|
| RP-1 | Committee-signed `state_root` binds the `r:` leaf | `light/main.cpp:4644-4684` (S-042 binding) → `light/trustless_read.cpp:335-437` (`committee_bound_state_root`); `src/node/producer.cpp::compute_block_digest`; `src/chain/block.cpp::signing_bytes` | `docs/SECURITY.md` §S-042; `StateRootAnchorSoundness.md` SR-1/SR-2/SR-3; `LightClientThreatModel.md` T-L2 |
| RP-2 | Merkle state-proof for the `r:` leaf is sound | `light/verify.cpp:330-396`; `src/crypto/merkle.cpp:113-141`; leaf encoding `src/chain/chain.cpp:298-308` | `MerkleTreeSoundness.md` MT-1/MT-2/MT-4 + §6.2 (S-040); `S033StateRootNamespaceCoverage.md` T-1/T-2 |
| RP-3 | Value-hash cleartext cross-check binding | recompute `light/main.cpp:4614-4621` ≡ committed `src/chain/chain.cpp:300-307`; compare `light/main.cpp:4625`; cleartext source `src/node/node.cpp:2725-2735` | `LightClientThreatModel.md` L-4; `StakeProofSoundness.md` SP-2; `DAppRegistryReadSoundness.md` DR-2(iii) |
| RP-4 | One-sided verifier; daemon-asserted `NOT_INCLUDED` ((H-neg)) via `not_found` + cleartext corroboration | `light/main.cpp:4532-4551` (`not_found` + null-registry cross-check); `light/main.cpp:4584-4591` (present-proof + null-registry → throw); `src/chain/chain.cpp:449` (`nullopt`); `src/node/node.cpp:3428` (`not_found`) | `MerkleTreeSoundness.md` MT-5; `NegativeVerdictSoundness.md` NV-6 |
| RP-5 | ACTIVE/INACTIVE is a sound derived predicate | `light/main.cpp:4705-4708`; struct sentinel `include/determ/chain/chain.hpp:38` | `DAppRegistryReadSoundness.md` DR-6 |
| RP-6 | Fail-closed exit-code discipline | `light/main.cpp:4767-4772` (exit codes + catch-all); error branches throughout `4532-4693` | `LightClientThreatModel.md` L-6; `DAppRegistryReadSoundness.md` DR-5 |
| RP-E | End-to-end composition `≤ 2⁻⁹²` | `light/main.cpp:4456-4773` (`cmd_verify_registrant`) | T-L1 + T-L2 + RP-1 + RP-2 + RP-3 + RP-5 |

| Surface | Citation |
|---|---|
| `r:` leaf encoding (5-field value-hash) | `src/chain/chain.cpp:298-308` (`build_state_leaves`) |
| `RegistryEntry` struct | `include/determ/chain/chain.hpp:32-44` (`ed_pub`, `registered_at`, `active_from`, `inactive_from{UINT64_MAX}`, `region`) |
| `registrants_` map | `include/determ/chain/chain.hpp:549` (`std::map<std::string, RegistryEntry>`) |
| `account` RPC registry block (cleartext source) | `src/node/node.cpp:2725-2735` (`region` added commit `48a6f5d`) |
| `state_proof` RPC simple-key `r:` branch | `src/node/node.cpp:3355-3429` (`r` enumerated at `node.cpp:3382`; `not_found` at `3428`) |
| `cmd_verify_registrant` (the reader) | `light/main.cpp:4456-4773` |
| Genesis anchor / committee-sig verify | `light/trustless_read.cpp:46-230`; `light/verify.cpp:135-328` |
| Merkle state-proof verify | `light/verify.cpp:330-396`; `src/crypto/merkle.cpp:113-141` |
| CLI dispatch | `light/main.cpp:7286` (`verify-registrant` → `cmd_verify_registrant`, defined at `:4456`) |
| `state_proof` RPC contract | `docs/PROTOCOL.md` §10.2 |
| `r:` canonical Merkle-leaf row | `docs/PROTOCOL.md` §4.1.1 |
| REGISTER/DEREGISTER apply rules | `docs/PROTOCOL.md` §3.3 |
| S-033 / S-038 / S-040 closures | `docs/SECURITY.md` §S-033 / §S-038 / §S-040 |

---

## 8. Status

All six theorems (RP-1 through RP-6) and the corollary RP-E are closed for the `r:` namespace read against the in-tree light-client substrate:

- **RP-1** (committee-anchored root) closed by inheritance from `StateRootAnchorSoundness.md` SR-1 + the shared S-042 `committee_bound_state_root` binding (`light/main.cpp:4644-4684`); reduces to A1 + A2, bound `≤ K·2⁻¹²⁸ + 2⁻¹²⁸`.
- **RP-2** (Merkle inclusion + key/value-hash binding + inherited S-040 `leaf_count` root-binding) closed via `crypto::merkle_verify` (`merkle.cpp:113-141`) + the §4.2.1 cross-check over the five-field §1.2 preimage; reduces to A2, bound `≤ log₂(n)·2⁻¹²⁸`.
- **RP-3** (value-hash cleartext cross-check) closed — the light-client recomputation (`light/main.cpp:4614-4621`) is byte-identical to the committed-leaf computation (`chain.cpp:300-307`); a daemon lie about `ed_pub`/lifecycle/`region` needs an A2 collision.
- **RP-4** (one-sided verifier) closed honestly — the sorted-leaves primitive (MT-5) admits no non-membership proof, so `NOT_INCLUDED` is a daemon-asserted negative ((H-neg), NV-2/NV-3) gated on `not_found` + cleartext corroboration; an *inconsistent* leaf collapses to `UNVERIFIABLE`, but a *consistent* liar still forges the negative; a null registry with a present proof fails closed.
- **RP-5** (sound lifecycle derivation) closed — the classification is a deterministic comparison of the committee-certified `active_from`/`inactive_from` against the committee-verified head height, matching the on-chain committee-selection gate; `INACTIVE` is a verified verdict; genesis creators (`inactive_from = UINT64_MAX`) classify `ACTIVE`.
- **RP-6** (fail-closed exit-code discipline) closed structurally — `INCLUDED`/`NOT_INCLUDED` exit 0 only on a verified answer, `UNVERIFIABLE` exits 3, args/transport exit 1; no path from a detected inconsistency to a false `INCLUDED`.
- **RP-E** composes to `≤ 2⁻⁹²` end-to-end, matching the balance/stake/DApp read bounds.

The `r:` read is the **last simple-key namespace** to receive its trust-minimized read proof, completing the family `a:`/`s:`/`d:`/`r:` across the value-bearing simple-key namespaces; the lone S-033 namespace without a reader is `b:` (abort_records, internal-only — §6.6). Its distinguishing significance is that `r:` **is the committee source** — a trustless `verify-registrant` lets a light client check validator-set membership (the consensus key `ed_pub` and the active-set lifecycle) without a full node, reading back the very registrant records that, leaf-by-leaf, define the committee whose signatures certify every `state_root` the read anchors against. The proof's foundation rests on the same small set of primitives every trustless read uses — the committee-anchored `state_root` (SR-1), the sorted-leaves Merkle inclusion proof (MT-4), the root-wrapped `leaf_count` (S-040), and the value-hash cleartext cross-check (L-4) — specialized to the `r:` namespace under assumptions **A1 + A2 only**, against the malicious-daemon adversary `A_daemon`.
