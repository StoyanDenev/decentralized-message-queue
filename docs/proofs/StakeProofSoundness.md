# StakeProofSoundness — trust-minimized `s:`-namespace stake-read soundness

This document formalizes the security of a **trust-minimized stake read** by the light client: the new `determ-light stake-trustless --domain <D>` command (sibling-agent work this round) lets an operator learn a domain's `(locked, unlock_height)` stake pair from a *single untrusted daemon* and verify it locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client act on a wrong stake value. The read targets the `s:` (stakes) namespace of the S-033 state-commitment surface.

The proof exists because the trust posture is structural, not cryptographic: it composes the same three primitives the balance read (`a:` namespace) already rests on — (1) the committee's Ed25519 signature set binds `state_root` to the operator's pinned chain via the successor-block prev_hash chain, (2) the sorted-leaves Merkle inclusion proof binds a single `s:` leaf to that root, and (3) the root-wrapper binds `leaf_count` into the committed `state_root` itself (S-040 CLOSED), so a forged count is rejected by the hash — into an end-to-end pipeline under a malicious-daemon adversary. No new cryptographic primitive is introduced; the claim is that an honest light client never acts on a `(locked, unlock_height)` pair that is inconsistent with the genesis-pinned chain. The proof mirrors the balance-read threat model (`LightClientThreatModel.md` T-L3 / T-L4) one-for-one, specialized to the `s:` namespace and its `SHA256(locked_u64 ‖ unlock_height_u64)` value-hash encoding.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — A1 = Ed25519 EUF-CMA §2.2, A2 = SHA-256 collision / second-preimage §2.1, A3 = SHA-256 preimage §2.1, A4 = CSPRNG §2.3) — this proof reduces to **A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core SP-2 consumes, and its **§6.2 (S-040, now CLOSED)** is the `leaf_count` binding — `leaf_count` is hashed into the committed root via the root-wrapper, so the former caller-trust obligation SP-3 discusses is now cryptographically enforced); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `s:` key + value-hash encoding, and its **T-1** confirms every apply-determining stake field is committed to the root); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is exactly the binding SP-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the balance/nonce trustless-read flow this proof specializes to stakes — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** composite read with race-window mitigation); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 four-surface composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-038 + §S-040 for the closure / limitation narratives; `docs/PROTOCOL.md` §4.1.1 for the canonical `s:` Merkle-leaf row + §10.2 for the `state_proof` RPC contract.

---

## 1. Scope

### 1.1 In scope

The `determ-light stake-trustless --domain <D>` composite command, which (mirroring `read_account_trustless` at `light/trustless_read.cpp:188-350`) executes:

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:52-79`). Compute `compute_genesis_hash(genesis_O)` locally, fetch block 0 from the daemon, byte-compare. (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:81-186`), invoking `verify_headers` (`light/verify.cpp:104-188`) per page and `verify_block_sigs` (`light/verify.cpp:190-283`) per block, end-to-end from block 0. (T-L2.)
3. **State-proof fetch for the `s:` namespace** — `rpc.call("state_proof", {{"namespace","s"},{"key",domain}})`. The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3287-3336`) explicitly supports the `"s"` namespace (`node.cpp:3296`: `if (ns == "a" || ns == "s" || ...)`), building the prefixed key `"s:" + domain` and returning `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Merkle inclusion verify** — `verify_state_proof(proof, root)` (`light/verify.cpp:285-349`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`). (T-L3 / SP-2.)
5. **Race-window anchor of the proof root to a committee-signed header** — the three-branch `proof_height < / == / > vc.height` dispatch (`light/trustless_read.cpp:226-307`). (T-L4 §4.4.1 / SP-1.)

The single difference from the balance read is the namespace argument (`"s"` instead of `"a"`) and the **value-hash decode** of the verified leaf: instead of `SHA256(balance_u64 ‖ next_nonce_u64)`, the `s:` leaf commits to `SHA256(locked_u64 ‖ unlock_height_u64)` (`src/chain/chain.cpp:292-297`). Every cryptographic step is namespace-agnostic; the proof below makes the specialization explicit.

### 1.2 The `s:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:291-297`):

```cpp
// stakes_
for (auto& [domain, st] : stakes_) {
    crypto::SHA256Builder b;
    b.append(st.locked);          // uint64, big-endian
    b.append(st.unlock_height);   // uint64, big-endian
    leaves.push_back({k_with_prefix("s:", domain), hash_bytes(b)});
}
```

so for a stake entry at `domain`:

$$
\text{key}_s(D) \;=\; \texttt{"s:"} \,\|\, D_{\text{utf8}}, \qquad
\text{value\_hash}_s(D) \;=\; H\big(\,u64\_be(\texttt{locked}) \,\|\, u64\_be(\texttt{unlock\_height})\,\big).
$$

`StakeEntry` is `{ uint64_t locked; uint64_t unlock_height; }` (`include/determ/chain/chain.hpp:23-30`), with `unlock_height` held at `UINT64_MAX` while the domain is registered and set to `inactive_from + unstake_delay` on DEREGISTER (`chain.hpp:25-29`). The `s:` leaf binds *both* scalars under one 32-byte value-hash, so a verifier that recovers `value_hash_s(D)` from a proof and recomputes `H(u64_be(locked) ‖ u64_be(unlock_height))` from a daemon-asserted cleartext pair detects any mismatch in either field by A2 (§4.2 / SP-2 cleartext cross-check, analogous to `LightClientThreatModel.md` L-4).

This is exactly the `s:` row of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 and `PROTOCOL.md` §4.1.1.

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-membership of a stake entry.** A light client cannot prove "`domain` D has no stake entry" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). A `stake-trustless` query for an unstaked domain yields `{"error":"not_found"}` from the RPC, which the light client must treat as a non-proof (an all-Byzantine peer set could lie about absence). This proof covers only the membership case.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1-§6.7. Within one invocation the race-window mitigation (SP-1 §4.1.1) is sound; cross-invocation head-regression is operator-visible but not auto-detected.
- **The mutating side of stakes** (STAKE / UNSTAKE / DEREGISTER apply rules, the unlock-height cascade, the A1 unitary-supply invariant `Σ balance + Σ locked = expected_total`). Those are apply-layer correctness (`AccountStateInvariants.md`, `S033StateRootNamespaceCoverage.md` §4.1.1); this proof reads the *committed* `s:` leaf and does not re-prove how it got there.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged stake replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM), `A_genesis` (tampered pinned `genesis.json`).

**Security goal.** Under `A_daemon`, an honest light client running `stake-trustless --domain D` never **acts on** a `(locked, unlock_height)` pair that is inconsistent with the genesis-pinned chain's `s:` leaf for `D` at the verified height. "Acts on" means *displays as authoritative* or *feeds into a downstream decision* (e.g., an operator deciding whether a domain's stake clears `min_stake`, or whether its UNSTAKE unlock_height has matured). The negation form is **fail-closed exit**: any detected inconsistency throws and propagates to a non-zero process exit with a structured stderr diagnostic (inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

`stake-trustless` reuses the four light-client primitives unchanged — genesis anchor (§3.1 of the threat model), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton. The only specialization is the `"s"` namespace argument to `state_proof` and the `s:` value-hash decode. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies verbatim with the state-proof stage targeting `("s", domain)`.

Crucially, the daemon sources `state_root`, `leaf_count`, `target_index`, `value_hash`, and the sibling vector from **one** `rpc_state_proof` reply (`node.cpp:3325-3335` returns them in a single JSON object), and the light client verifies the proof's `state_root` against a committee-signed header in the *same* invocation (`trustless_read.cpp:226-307`). Since **S-040 is CLOSED** — `leaf_count` is bound into the committed root via the root-wrapper `H(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` — a forged `leaf_count` is now rejected cryptographically regardless of source; the single-envelope shape remains the implementation reality but is no longer a soundness precondition. SP-3 formalizes this enforced binding.

---

## 4. Security theorems

Throughout, let `D` be the queried domain, `R := state_root(h)` the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to, and `(\text{locked}_T, \text{unlock}_T)` the true stake pair for `D` in the chain's actual state at height `h` (with true leaf `\text{value\_hash}_s^T(D) = H(u64\_be(\text{locked}_T) \| u64\_be(\text{unlock}_T))`).

### 4.1 Theorem SP-1 (committee-signed `state_root` binds the `s:` leaf)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that `stake-trustless` anchors and verifies the `s:` proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root the `s:` leaf is checked against is *committee-certified*, not daemon-asserted — forging a different anchored root reduces to an A1 forgery on block `h+1` or an A2 collision at `h`.

**Adversary game.**

1. Operator pins `genesis_O`; the genesis-seeded committee `K_0 = {(domain_i, pk_i)}` is loaded into the seed map by `build_genesis_committee` (`trustless_read.cpp:43-50`). The genuine pinned chain has `state_root_T(h) ≠ 0` and a committee-signed `h+1`.
2. Light client runs `stake-trustless --domain D`. Internally it anchors genesis (T-L1), walks + committee-verifies headers `0..h` (and the forward link to `h+1` via the same paged walk), and in the race-window dispatch (`trustless_read.cpp:243-301`) verifies the anchor header's committee signatures and matches its `state_root` to the proof's claimed root.
3. `A_daemon` wins if the invocation anchors and uses a root `R_A ≠ state_root_T(h)` without throwing.

**Proof.** The binding of `state_root(h)` to the committee is *transitive-forward*, not a direct signature. The committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp::compute_block_digest`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root`. `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim) and hence into `block_hash(h) = compute_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`. So

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

This is exactly the chain of bindings `StateRootAnchorSoundness.md` SR-1 establishes, applied here to the height the `s:` proof is anchored at. Suppose the invocation anchors `R_A ≠ state_root_T(h)`. Two exhaustive cases (the SR-1 case split, reproduced for the `s:`-proof anchoring at `trustless_read.cpp:269-285`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`** (so the `h → h+1` prev_hash link still closes against the committee-signed `digest(h+1)`). The genuine `block_hash_T(h) = SHA256(signing_bytes_T(h) ‖ sigs)` with `signing_bytes_T(h)` containing `state_root_T(h)`. The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).

- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. But the light client committee-verifies `h+1`'s signatures over `digest(h+1)` against `K_0` (`verify_block_sigs` invoked at `trustless_read.cpp:277-285`). The genuine committee signed `digest(h+1)` containing `prev_hash(h+1) = block_hash_T(h)`. To accept `h+1` with a different `prev_hash`, the daemon must present `required` valid signatures over a different digest — an Ed25519 forgery for each of `required ≤ K` distinct committee members, `≤ K · 2⁻¹²⁸` (A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* (that `R` is the root of the operator's pinned chain at `h` specifically, not a fork's or another height's) is supplied by SR-2 + SR-3 + T-L1's genesis anchor; SP-1 inherits them.

**Head-block boundary.** If the operator queries a stake at the chain *head*, that block's `state_root` has no signed successor yet, so it is committee-certified only once a successor is produced. The shipped flow handles this via the race-window dispatch: a head-height proof (`proof_height == vc.height`) is matched byte-for-byte against `vc.head_state_root`, itself extracted from the committee-signed header at `vc.height − 1` (`trustless_read.cpp:302-307`; `LightClientThreatModel.md` L-5 case `proof_height == vc.height`). Full nodes enforce the head's root meanwhile via the apply-layer S-033 gate (`StateRootAnchorSoundness.md` §3.4 + §6.3). SP-2 below proves Merkle-path soundness *given* such an `R`; SP-1 is the committee-binding of `R`.

**Concrete-security bound.** `Pr[A_daemon wins SP-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem SP-2 (Merkle state-proof for the `s:` leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from SP-1, a verifier holding `R` cannot be made to accept a wrong stake pair `(\text{locked}_A, \text{unlock}_A) ≠ (\text{locked}_T, \text{unlock}_T)` for `D` without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; \text{key}_s(D),\; \text{value\_hash}_A,\; \text{target\_index},\; n,\; \text{proof}) = \texttt{true},
$$

then either (a) `value_hash_A` is the genuine `s:`-leaf value-hash for `D` at sorted position `target_index` of the tree `R` commits to, or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves the `s:` leaf is committed under `R`, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as SP-1: the light client has anchored committee-signed `R` for the `s:` proof.
2. `A_daemon` returns a state-proof `P_A = (\text{key}_s(D), \text{value\_hash}_A, \text{target\_index}, n, \text{proof})` where `value_hash_A ≠ value_hash_s^T(D)` (a wrong stake leaf), or alters `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the `s:` leaf, equivalently `LightClientThreatModel.md` T-L3 specialized to the stakes namespace. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value_hash_A, target_index, n, sibs)` (`light/verify.cpp:333-335`), which recomputes the leaf hash `c_0 = \text{merkle\_leaf\_hash}(\text{key}_s(D), \text{value\_hash}_A) = H(\texttt{0x00} \| u32\_be(|\text{key}_s(D)|) \| \text{key}_s(D) \| \text{value\_hash}_A)` and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R`.

By MT-4's extraction: if `value_hash_A ≠ value_hash_s^T(D)`, then `c_0 ≠ c_0^{hon}` (distinct preimages under the unambiguous length-prefixed leaf encoding of `MerkleTreeSoundness.md` §2.1 — or, if `c_0 = c_0^{hon}` despite distinct content, that *is* a leaf-level collision, output it). Both the recomputed chain and the honest root-path chain for `D` terminate at `R`. Walking top-down, there is a highest level where the chains agree but the level below disagrees; at that level two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` map to the same `H` output — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path, so the comparison is not length-mismatched. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** matters specifically for the `s:` namespace: the leaf hash is over `key_s(D) = "s:" + D`, so a daemon cannot serve an `a:`-leaf value-hash (a balance) and pass it off as a stake — the recomputed leaf hash incorporates the `"s:"`-prefixed key, producing a different sibling chain and failing root-equality (the cross-namespace-swap rejection of `MerkleTreeSoundness.md` MT-2 domain separation + the `test_state_proof_namespaces.sh` swap assertions; `S033StateRootNamespaceCoverage.md` T-2 namespace disjointness guarantees `"s:"+D ≠ "a:"+D` at byte 0). By `S033StateRootNamespaceCoverage.md` T-1, the `stakes_` field's `(locked, unlock_height)` is in fact bound to the root through the `s:` namespace, so the leaf SP-2 verifies is the genuine committed stake state.

**Cleartext cross-check (optional belt-and-suspenders, mirroring L-4).** If `stake-trustless` additionally fetches the daemon's cleartext stake (e.g., a `stake`/`account`-class RPC exposing `locked` + `unlock_height`) and recomputes `H(u64\_be(\text{locked}_A) \| u64\_be(\text{unlock}_A))` to compare against the proof's verified `value_hash`, then a daemon lying about either scalar while serving an honest proof must find `(\text{locked}_A, \text{unlock}_A) ≠ (\text{locked}_T, \text{unlock}_T)` with colliding value-hashes — a SHA-256 collision, `≤ 2⁻¹²⁸` (A2). This binds the human-readable pair to the committed leaf identically to the balance read's L-4; whether the sibling command ships this cross-check or decodes the pair from a second proof field, the value-hash is the load-bearing binding and SP-2 holds on the proof alone.

**Concrete-security bound.** `Pr[A_daemon wins SP-2] ≤ log₂(n) · 2⁻¹²⁸`; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`.   ∎

### 4.3 Theorem SP-3 (`leaf_count` is bound into the committed root — S-040 CLOSED)

**Statement.** SP-2's soundness is stated with `n` = the *genuine* leaf count of the tree `R` commits to. **S-040 is CLOSED:** `crypto::merkle_root` now binds `leaf_count` into the committed root via a root-wrapper hash `R = H(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`; the `0x02` tag is domain-separated from the `0x00` leaf and `0x01` inner tags), and `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the **caller-supplied** `leaf_count`, and compares to the committed root. A forged `leaf_count` `M ≠ n` therefore yields a different wrapper hash and is **rejected**. The soundness of the `s:` read consequently no longer rests on the light client sourcing `leaf_count` from any particular origin: the former single-envelope-sourcing obligation is now enforced by the hash, not a caller guideline. SP-3 records this enforced binding.

**Why a forged `leaf_count` is rejected.** `merkle_verify` consumes the caller-supplied `leaf_count` to drive the number of levels and the per-level duplication parity (`merkle.cpp:130-138`) **and** to re-apply the root-wrapper `H(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` before comparing to the committed root. Two distinct `(target_index, leaf_count)` pairs that yield the *same inner walk shape* used to verify identically against the bare inner root (the pre-S-040 hazard — `determ test-merkle-proof-tampering` scenario #12 originally pinned that a claimed `leaf_count = 8` against a genuinely-5-leaf tree verified as `true`). Under the closed design the committed root commits to `leaf_count`, so a claimed `M ≠ n` re-wraps the inner root with the wrong `be_u32(M)` and fails root-equality unless the attacker exhibits a SHA-256 collision on the wrapper input (A2, `≤ 2⁻¹²⁸`). Lock-in scenario #12 was inverted accordingly: it now asserts a forged `leaf_count` is **REJECTED**.

**Consequence for the `stake-trustless` flow.** `Node::rpc_state_proof` still returns `state_root`, `leaf_count`, `target_index`, `value_hash`, and `proof` as fields of **one** JSON object (`node.cpp:3325-3335`), computed atomically under the daemon's `state_mutex_` read lock (`node.cpp:3289`) over a single consistent state; `leaf_count` is `chain_.state_proof(...).leaf_count = build_state_leaves().size()` (`chain.cpp:456`) — the genuine count for the very tree whose root is `compute_state_root()` in the same reply (`node.cpp:3333`). That single-envelope shape remains the implementation reality, but it is no longer load-bearing for soundness:

1. If a malicious daemon serves the genuine `leaf_count` but a tampered `state_root`, the tampered root fails SP-1's committee anchoring (it won't match a committee-signed header, throwing at `trustless_read.cpp:269-275`).
2. If it serves a tampered `leaf_count` `M ≠ n` with the genuine `state_root`, `merkle_verify` re-wraps the genuine inner root with `be_u32(M)` and the result no longer equals the committee-anchored `R` — rejected by the wrapper hash (A2), independent of where the light client obtained `leaf_count`.

In either case the daemon gains no ability to substitute a *wrong* `(locked, unlock_height)`, and (unlike the pre-S-040 design) cannot even mislabel the sorted slot via a forged count, because the count is now part of what `R` commits to. The light client inherits the closure directly: the trustless read calls `crypto::merkle_verify` (`light/verify.cpp:333-335`), which performs the root-wrapper re-derivation.

**Status.** **S-040 is CLOSED** (shipped pre-launch as a wire-compat break — every `state_root` value changed; no installed base). It is no longer an open / deferred / flag-day item. SP-2's soundness already held with the genuine `leaf_count`; SP-3 now adds that a forged `leaf_count` is cryptographically rejected, so the read is sound for *any* `leaf_count` source.

**Concrete-security bound.** A forged `leaf_count` is accepted only on a SHA-256 collision of the root-wrapper input, `≤ 2⁻¹²⁸` (A2) — the same order as SP-2's per-level bound; SP-3 adds no term beyond SP-1 + SP-2.   ∎

### 4.4 End-to-end composition

**Corollary SP-E (trust-minimized stake read).** Under A1 + A2, `stake-trustless --domain D` yields a `(locked, unlock_height)` pair bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis. Composing SP-1 (committee-anchored root) + SP-2 (`s:` Merkle inclusion) + SP-3 (single-envelope `leaf_count`) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline (the per-step independent bounds of `LightClientThreatModel.md` T-L4):

$$
\Pr[A_{\text{daemon}} \text{ wins SP-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4 exactly, as expected: the `s:` and `a:` reads differ only in the namespace argument and the leaf value-hash decode, both of which are namespace-agnostic in every cryptographic step.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

SP-2 *is* MT-4 applied at the `s:` leaf; it asserts no new cryptographic claim. MT-1 (determinism) guarantees the `s:` leaf's position and the root are reproducible across honest nodes; MT-2 (domain separation) underwrites the cross-namespace-swap rejection that stops an `a:` balance leaf from masquerading as an `s:` stake leaf; MT-3 (collision-resistance inheritance) is the divergence-detection that makes any wrong committed stake state produce a different root. SP-3 is the `stake-trustless`-specific statement of MT-4's §6.2 (S-040, now CLOSED): `leaf_count` is bound into the committed root by the root-wrapper, so a forged count is rejected by the hash.

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

SP-1 *is* SR-1 applied at the height the `s:` proof is anchored at, plus SR-2 (genesis-binding, no floating header) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism; SP-1 names the `s:` read as a consumer of it, exactly as `LightClientThreatModel.md` T-L4 does for the `a:` read at `trustless_read.cpp:277-285`.

### 5.3 `S033StateRootNamespaceCoverage.md` — the namespace surface

T-1 (coverage completeness) confirms the `stakes_` field's `(locked, unlock_height)` is committed to the root through the `s:` namespace (and through *no other*, by T-2 disjointness), so the leaf SP-2 verifies is the genuine committed stake. §2.1's table fixes the byte-exact `s:` key + value-hash encoding this proof reads off `chain.cpp:291-297`. T-3 (deterministic leaf ordering) + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes, so the committee that signed `digest(h+1)` signed over a `block_hash(h)` derived from the canonical `s:` leaf set.

### 5.4 `LightClientThreatModel.md` — the adversary model and read flow

This proof specializes T-L3 (state-proof correctness) + T-L4 (composite read with race-window mitigation) from the `a:` namespace to `s:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. SP-E's bound equals T-L4's bound. The light client's `read_account_trustless` (`trustless_read.cpp:188-350`) is the structural template the sibling agent's `read_stake_trustless` follows with `namespace="s"`.

### 5.5 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the `s:` proof anchors against an S-033-committed root. As with the balance read, `read_stake_trustless` must throw with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`trustless_read.cpp:202-208`) — a chain-level deployment prerequisite, not a light-client design choice. SP-1's interior regime is exactly the S-033-active regime.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Two are worth calling out for the stakes read specifically:

### 6.1 No non-membership: unstaked domains yield a non-proof

A domain with no `stakes_` entry produces no `s:` leaf, so `state_proof("s", D)` returns `{"error":"not_found"}` (`node.cpp:3318`; `chain.cpp:449`). The light client cannot cryptographically conclude "`D` has zero stake" — only "this daemon claims `D` is absent." An honest operator querying an unstaked domain sees the error and must treat it as non-authoritative (a Byzantine daemon could withhold a genuine entry; multi-peer cross-check, out of scope, is the only mitigation). This is the `MerkleTreeSoundness.md` MT-5 / `S033StateRootNamespaceCoverage.md` §6.6 non-membership boundary, inherited.

### 6.2 `unlock_height = UINT64_MAX` is a valid committed value, not a sentinel-for-absent

While a domain is registered, its `unlock_height` is held at `UINT64_MAX` (`chain.hpp:25-29`). This is a genuine committed scalar — `value_hash_s(D) = H(u64_be(locked) ‖ u64_be(UINT64_MAX))` is a normal leaf, proven by SP-2 like any other. A verifier must not misread a successfully-proven `UINT64_MAX` unlock_height as "no proof" or "absent"; it means "registered, not yet unlockable." The distinction matters for an operator deciding whether an UNSTAKE has matured: a *proven* `unlock_height` (any value, including `UINT64_MAX`) is committee-anchored truth; only the `not_found` RPC error (§6.1) is a non-proof.

### 6.3 S-040 leaf_count binding (SP-3) — CLOSED, not a limitation

Recorded in §4.3 for completeness, but **no longer a limitation**: **S-040 is CLOSED.** `leaf_count` is bound into the committed root via the root-wrapper `H(0x02 ‖ be_u32(leaf_count) ‖ inner_root)`, and `merkle_verify` re-applies the wrapper with the caller-supplied count, so a forged `leaf_count` is cryptographically rejected regardless of source. The `s:` read is sound for any `leaf_count` origin; the former single-envelope-sourcing obligation is now enforced by the hash, not a caller guideline. No deferral, flag-day, or open item remains.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| SP-1 | committee-anchor (race-window) in the read flow | `light/trustless_read.cpp:226-307` | Anchor the `s:` proof's `state_root` to a committee-signed header; the three-branch `proof_height < / == / >` dispatch. |
| SP-1 | `verify_block_sigs` | `light/verify.cpp:190-283` | Per-block Ed25519 K-of-K committee-sig verify over `light_compute_block_digest`. |
| SP-1 | `verify_headers` | `light/verify.cpp:104-188` | prev_hash continuity walk from genesis (SR-2 genesis-binding). |
| SP-1 | `anchor_genesis` | `light/trustless_read.cpp:52-79` | T-L1 genesis pin (`compute_genesis_hash` byte-compare). |
| SP-2 | `verify_state_proof` | `light/verify.cpp:285-349` | Parse `s:` proof JSON, delegate to `merkle_verify`; optional `--state-root` override. |
| SP-2 | `merkle_verify` | `src/crypto/merkle.cpp:113-141` | Recompute root from `s:` leaf + siblings; range/underflow/exact-consume gates. |
| SP-2 | `s:` leaf encoding | `src/chain/chain.cpp:291-297` | `value_hash = SHA256(locked_u64 ‖ unlock_height_u64)`, key `"s:" + domain`. |
| SP-2 | `StakeEntry` | `include/determ/chain/chain.hpp:23-30` | `{locked, unlock_height}`; `unlock_height = UINT64_MAX` while registered. |
| SP-3 | `Node::rpc_state_proof` | `src/node/node.cpp:3287-3336` | `s:` namespace supported (l.3296); returns `state_root` + `leaf_count` in one envelope (l.3325-3335). |
| SP-3 | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | `leaf_count = leaves.size()` (l.456) from the same tree as the root. |
| SP-E | `read_account_trustless` (template for `read_stake_trustless`) | `light/trustless_read.cpp:188-350` | The composite read skeleton; `stake-trustless` differs only by `namespace="s"`. |
| SP-1 | `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | `merkle_root(build_state_leaves())` — the root the committee transitively signs. |
| SP-1 | state_proof RPC dispatch | `src/rpc/rpc.cpp:235-238` | `method == "state_proof"` → `rpc_state_proof(namespace, key)`. |

**Tests** (the `s:` read shares the light-client + Merkle test surface; the sibling agent adds an end-to-end `stake-trustless` script this round):

| Test | Coverage |
|---|---|
| `tools/test_light_balance_trustless.sh` | T-L4 sibling shape; `stake-trustless` mirrors it with `namespace="s"` (sibling-agent `tools/test_light_stake_trustless.sh` this round). |
| `tools/test_light_verify_state_proof.sh` | SP-2 — happy path + tampered value_hash → FAIL + tampered sibling → FAIL + wrong state_root → FAIL. |
| `tools/test_state_proof_namespaces.sh` (9 assertions) | SP-2 leaf-key binding — cross-namespace swap (`s:`-key with `a:`-value_hash) rejected. |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` (15 scenarios) | SP-2 tamper rejection; SP-3 / S-040 `leaf_count` binding — scenario #12 (inverted post-closure) asserts a forged `leaf_count` is REJECTED. |
| `tools/test_state_root_namespaces.sh` (12 assertions) | `s:`-namespace mutation-changes-root coverage (`S033StateRootNamespaceCoverage.md` T-1). |

---

## 8. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** The `s:` namespace is already served by `Node::rpc_state_proof` (`node.cpp:3296`) and committed by `build_state_leaves` (`chain.cpp:291-297`); the `determ-light stake-trustless` composite command is sibling-agent work this round, structurally identical to `read_account_trustless` with `namespace="s"`.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision / second-preimage resistance). No A3/A4 dependence beyond what T-L1's genesis anchor already carries.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis` (inherited from `LightClientThreatModel.md` §2.2).
- **Theorems.** SP-1 (committee-signed `state_root` binds the `s:` leaf — reduces to A1 forgery on `h+1` or A2 collision at `h`, via SR-1); SP-2 (`s:` Merkle inclusion soundness — MT-1/MT-3/MT-4 at the `s:` leaf); SP-3 (`leaf_count` bound into the committed root — S-040 CLOSED; a forged count is rejected by the root-wrapper hash). Corollary SP-E composes them with T-L1 + T-L2 to the same `≤ 2⁻⁹²` end-to-end bound as the balance read.
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-3/MT-4 + §6.2 S-040 CLOSED), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `S033StateRootNamespaceCoverage.md` (T-1/T-2/T-3/T-4 + §2.1 `s:` row), `LightClientThreatModel.md` (T-L1/T-L2/T-L3/T-L4 + `A_daemon` + L-6), `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 prerequisite).
- **Known limitations.** No non-membership for unstaked domains (§6.1); `unlock_height = UINT64_MAX` is a committed value not an absent-sentinel (§6.2). S-040 `leaf_count` is **CLOSED** (bound into the committed root via the root-wrapper; a forged count is rejected — §6.3), so it is no longer a limitation. None of the above undermine the per-invocation soundness claim.

---

## 9. References

### Implementation sites
- `src/chain/chain.cpp:291-297` — `s:` leaf encoding (`SHA256(locked_u64 ‖ unlock_height_u64)`).
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (`leaf_count` at l.456).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root`.
- `src/node/node.cpp:3287-3336` — `Node::rpc_state_proof` (`s:` supported l.3296; single envelope l.3325-3335).
- `src/rpc/rpc.cpp:235-238` — `state_proof` RPC dispatch.
- `include/determ/chain/chain.hpp:23-30` — `StakeEntry`.
- `src/crypto/merkle.cpp:113-141` — `merkle_verify`.
- `light/verify.cpp:285-349` — `verify_state_proof`.
- `light/trustless_read.cpp:188-350` — `read_account_trustless` (template for `read_stake_trustless`); race-window dispatch l.226-307.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels; §2.1 SHA-256 (A2/A3); §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (domain separation), MT-3 (collision-resistance inheritance), MT-4 (inclusion-proof soundness — SP-2 core), §6.2 (S-040 CLOSED — `leaf_count` bound into the committed root via the root-wrapper; SP-3).
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1 (committee-anchored root — SP-1 core), SR-2 (genesis-binding), SR-3 (height-binding).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (coverage completeness), T-2 (namespace disjointness), §2.1 (`s:` row).
- `docs/proofs/LightClientThreatModel.md` — `A_daemon` model; T-L1/T-L2/T-L3/T-L4; L-4 (cleartext cross-check); L-6 (fail-closed exit).
- `docs/proofs/BlockchainStateIntegrity.md` — S-021 + S-033 + S-038 four-surface composition (chain-level prerequisite).

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` Merkle-leaf table (`s:` row).
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC contract.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` bound into the committed root via the root-wrapper (CLOSED; SP-3).
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (A1).
