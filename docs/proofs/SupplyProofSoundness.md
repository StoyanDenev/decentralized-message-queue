# SupplyProofSoundness — trust-minimized `c:`-namespace supply-counter read soundness

This document formalizes the security of a **trust-minimized supply-counter read** by the light client: the `determ-light supply-trustless` command (`cmd_supply_trustless`, `light/main.cpp`) lets an operator learn the chain's five A1 supply accumulators — `genesis_total`, `accumulated_subsidy`, `accumulated_slashed`, `accumulated_inbound`, `accumulated_outbound` — from a *single untrusted daemon* and verify each locally against a committee-signed `state_root`, so that even a Byzantine daemon cannot make an honest light client act on a wrong supply figure. The read targets the **`c:` supply-counter namespace** of the S-033 state-commitment surface (which, at the wire/leaf level, is the composite `k:c:` sub-namespace inside the `k:` constants prefix — see §1.2).

> **Implementation status: SHIPPED (R51, 2026-07-03) — the race this banner documented is CLOSED.** The command was first implemented in R41 and reverted over the cleartext-sourcing race (the five A1 counters increment every block, so a `chain_summary` cleartext fetched before the sequential proof round-trips systematically mismatched the proofs' committed values — `TAMPERED` against an *honest* daemon). It was re-landed with same-root binding, and in **R51 the prescribed daemon-side fix shipped**: `rpc_state_proof` now returns the raw counter value (`value_hex`/`value_u64`) for the `c:` namespace ATOMICALLY with the proof — the whole RPC holds `state_mutex_`, so value, proof, `state_root`, and `height` are one snapshot, and the field is attached only after a server-side self-check that `SHA256(u64_be(value))` equals the proof's `value_hash` (fail-closed on encoding drift; the accessor↔leaf correspondence is unit-pinned by `test-state-proof-namespaces` assertion 10). `supply-trustless` prefers the atomic value (falling back to the legacy `chain_summary` path against pre-R51 daemons, which retains the documented race) and the optional `total_supply` cross-check is now height-gated (compared only when a fresh `chain_summary`'s height equals the anchored height — skipped rather than falsely `VIOLATED` on a live chain). The trust argument is UNCHANGED: the atomic value must still hash to the Merkle-verified `value_hash` under the committee-anchored root — SU-1..SU-4 below apply verbatim; the daemon gained no new trust.

The proof exists because the trust posture is structural, not cryptographic: it composes the same three primitives the balance read (`a:` namespace) and the stake read (`s:` namespace) already rest on — (1) the committee's Ed25519 signature set binds `state_root` to the operator's pinned chain via the successor-block prev_hash chain, (2) the sorted-leaves Merkle inclusion proof binds a single `c:` counter leaf to that root, and (3) the `(state_root, leaf_count)` pair is sourced from one committee-signed envelope — into an end-to-end pipeline under a malicious-daemon adversary. No new cryptographic primitive is introduced; the claim is that an honest light client never acts on a supply counter that is inconsistent with the genesis-pinned chain's committed state. **One result is new to this namespace and has no analog in the balance/stake reads: SU-3** shows that once the light client has verified *all five* counters against the root, it can recompute the chain-wide A1 unitary-supply identity itself, so a daemon cannot present a set of counters that are individually leaf-committed yet mutually inconsistent. The proof mirrors `StakeProofSoundness.md` (the `s:` sibling) one-for-one for SU-1/SU-2/SU-4 and adds SU-3 for the cross-counter identity check.

**A note on the overloaded label "A1" (read carefully).** Per `Preliminaries.md §2.0`, the symbol **A1** is used in two unrelated senses in the proof series: **A1 (the assumption)** = Ed25519 EUF-CMA (§2.2), and the **A1 unitary-supply invariant** = the *accounting* identity `live_total_supply = expected_total` enforced at apply tail (`AccountStateInvariants.md` I-6 / `EconomicSoundness.md` T-12). They are not the same thing. To avoid the collision this document writes **"assumption A1"** for the Ed25519 reduction and **"the A1 supply identity"** (or "the unitary-supply identity") for the accounting invariant. The brief's reference to `SupplyInvariantComposition SI-1` names a composition that does not ship under that filename; the real supply-conservation results this proof composes are `EconomicSoundness.md` T-12 (the per-shard closed-form identity, FA11), `AccountStateInvariants.md` I-6 (the per-account → chain-wide bridge, FA-Apply-1), and `CrossShardSupplyConservation.md` XS-5 (the K-shard aggregate, FA-Apply-17). SU-3 below cites those directly.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **assumption A1** = Ed25519 EUF-CMA §2.2, A2 = SHA-256 collision / second-preimage §2.1, A3 = SHA-256 preimage §2.1, A4 = CSPRNG §2.3; and the explicit "A1 unitary-supply invariant ≠ assumption A1" disambiguation at §2.0) — this proof reduces to **assumption A1** and **A2** only; `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-1** determinism, **MT-3** collision-resistance inheritance, and **MT-4** inclusion-proof soundness are the cryptographic core SU-2 consumes, **MT-2** domain separation underwrites the `k:c:`-vs-`a:`-vs-`s:` leaf-key binding, and its **§6.2 (S-040 CLOSED)** is the `leaf_count` root-wrapper binding SU-4 inherits); `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is exactly the binding SU-1 invokes, and **SR-2** / **SR-3** the genesis- and height-binding); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its **§2.1** table fixes the `k:c:` key + value-hash encoding, **T-1** confirms the five `accumulated_*` / `genesis_total` fields are committed to the root, and **T-2** proves the `k:` ↔ `k:c:` byte-level disjointness SU-2's leaf-key binding rests on); `LightClientThreatModel.md` (the malicious-daemon adversary model `A_daemon` and the balance/nonce trustless-read flow this proof specializes to supply counters — **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L3** state-proof correctness, **T-L4** composite read with race-window mitigation); `StakeProofSoundness.md` (the `s:`-namespace sibling whose structure this document mirrors for SU-1/SU-2/SU-4 — its SP-1/SP-2/SP-3 are the per-theorem templates); `AccountStateInvariants.md` (FA-Apply-1 — **I-6** the A1 supply identity SU-3 lets the light client re-check); `EconomicSoundness.md` (FA11 — **T-12** the closed-form A1 identity, **T-12.1** counter determinism); `CrossShardSupplyConservation.md` (FA-Apply-17 — **XS-5** the K-shard aggregate identity, the multi-shard generalization SU-3 §6.4 flags); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 four-surface composition the daemon's served data inherits); `docs/SECURITY.md` §S-033 + §S-038 + §S-040 for the closure narratives; `docs/PROTOCOL.md` §4.1.1 for the canonical `k:c:` Merkle-leaf row + §10.2 for the `state_proof` RPC contract.

---

## 1. Scope

### 1.1 In scope

The `determ-light supply-trustless` composite command, which (mirroring `read_account_trustless` at `light/trustless_read.cpp:439-599` and the `s:` sibling `read_stake_trustless`) executes, for each of the five supply counters:

1. **Genesis anchor** — `anchor_genesis(rpc, genesis_O)` (`light/trustless_read.cpp:55-82`). Compute `compute_genesis_hash(genesis_O)` locally, fetch block 0 from the daemon, byte-compare. (T-L1.)
2. **Header-chain walk + per-block committee-sig verify** — `verify_chain_to_head` (`light/trustless_read.cpp:234-248`, delegating to the `verify_chain_walk` core at `light/trustless_read.cpp:105-230`), invoking `verify_headers` (`light/verify.cpp:135-233`) per page and `verify_block_sigs` (`light/verify.cpp:235-328`) per block, end-to-end from block 0. (T-L2.)
3. **State-proof fetch for the `c:` namespace** — `rpc.call("state_proof", {{"namespace","c"},{"key",counter_name}})` for `counter_name ∈ {genesis_total, accumulated_subsidy, accumulated_slashed, accumulated_inbound, accumulated_outbound}`. The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3287-3336`) explicitly supports the `"c"` namespace (`node.cpp:3305`: `else if (ns == "c")`), building the composite key `"k:" + "c:" + counter_name` (`node.cpp:3308-3311`) and returning `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)`.
4. **Merkle inclusion verify** — `verify_state_proof(proof, root)` (`light/verify.cpp:330-396`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`). (T-L3 / SU-2.)
5. **Committee-binding of the proof root (S-042)** — the proof's claimed `state_root` is bound to a committee-signed header by `committee_bound_state_root` (`light/trustless_read.cpp:335-437`): a stale-height gate (`:528-533`) rejects a proof before the verified head, then `anchor_index = proof_height − 1` (`:545`) and the helper recomputes the full anchor block's `block_hash` and requires the committee-signed **successor**'s `prev_hash` to equal it (`:424-432`) — the anchor header's own digest excludes `state_root`, so signing it does not bind it; the head fails closed (no signed successor) unless `--wait` is supplied. (T-L4 §4.4.1 / SU-1 / `StateProofRaceWindowSoundness.md` PRW-1..PRW-5.)
6. **Chain-wide A1-identity recompute (supply-specific, new in this namespace)** — having verified all five counters against the same committee-anchored root, recompute `expected_total = genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` (`include/determ/chain/chain.hpp:443-449`) and (optionally, if a cleartext supply RPC is also fetched) check it against the daemon's asserted live supply. (SU-3.)

The differences from the balance read are the namespace argument (`"c"` instead of `"a"`), the **composite-key construction** (`"k:c:" + name`, not a bare `"a:" + key`), the **value-hash decode** of each verified leaf (`SHA256(counter_u64)` — a single big-endian `uint64`, not the `SHA256(balance_u64 ‖ next_nonce_u64)` pair of `a:`), and the **five-leaf multi-read + cross-counter identity check** of SU-3. Every cryptographic step is namespace-agnostic; the proof below makes the specialization explicit.

### 1.2 The `c:` (`k:c:`) counter leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:403-408`), the five counters are emitted via the `const_leaf` lambda (`chain.cpp:380-384`):

```cpp
auto const_leaf = [&](const char* name, uint64_t value) {
    crypto::SHA256Builder b;
    b.append(value);                                  // uint64, big-endian
    leaves.push_back({k_with_prefix("k:", name), hash_bytes(b)});
};
// ... (thirteen genesis-pinned k: constants) ...
// A1 supply counters.
const_leaf("c:genesis_total",        genesis_total_);
const_leaf("c:accumulated_subsidy",  accumulated_subsidy_);
const_leaf("c:accumulated_slashed",  accumulated_slashed_);
const_leaf("c:accumulated_inbound",  accumulated_inbound_);
const_leaf("c:accumulated_outbound", accumulated_outbound_);
```

so the literal leaf key for a counter named `c:NAME` is `k_with_prefix("k:", "c:NAME")` = `"k:" + "c:NAME"` = `"k:c:NAME"`. For a counter `NAME ∈ {genesis_total, accumulated_subsidy, accumulated_slashed, accumulated_inbound, accumulated_outbound}`:

$$
\text{key}_c(\text{NAME}) \;=\; \texttt{"k:c:"} \,\|\, \text{NAME}_{\text{utf8}}, \qquad
\text{value\_hash}_c(\text{NAME}) \;=\; H\big(\,u64\_be(\text{counter value})\,\big).
$$

This is exactly the `k:c:` row of the canonical namespace table in `S033StateRootNamespaceCoverage.md` §2.1 (`| k:c: | five A1 supply counters | uint64_t | "k:" + "c:" + name | SHA256(value_u64) |`) and `PROTOCOL.md` §4.1.1's tenth conceptual namespace. The five counter fields are declared at `include/determ/chain/chain.hpp:611-615`. The RPC's namespace argument is the *short* form `"c"`; the daemon maps `("c", NAME)` to the composite leaf key `"k:c:" + NAME` at `node.cpp:3305-3311`. A verifier that recovers `value_hash_c(NAME)` from a proof and recomputes `H(u64_be(asserted_value))` from a daemon-asserted cleartext counter detects any mismatch by A2 (§4.2 / SU-2 cleartext cross-check, analogous to `LightClientThreatModel.md` L-4).

### 1.3 Out of scope (intentional, inherited from the medium tier)

- **Non-membership of a counter.** A light client cannot prove "counter NAME does not exist" — the sorted-leaves tree supports positive membership only (`MerkleTreeSoundness.md` MT-5; `chain.cpp:449` returns `nullopt` for an absent key). In practice the five `c:` counters are *always present* on any chain (they are emitted unconditionally at `chain.cpp:404-408`, even on a fresh default-constructed `Chain` where they are all zero except `genesis_total` — `S033StateRootNamespaceCoverage.md` §2.1 / §3 notes the empty-tree case requires a contrived bypass), so a `not_found` reply to a `supply-trustless` query for a canonical counter name is itself a daemon misbehavior signal, treated as a non-proof. This proof covers the (universal) membership case.
- **Stale-state lies across invocations, multi-peer redundancy, persistence, transport encryption, RPC auth.** All inherited verbatim from `LightClientThreatModel.md` §6.1-§6.7. Within one invocation the race-window mitigation (SU-1 §4.1.1) is sound; cross-invocation head-regression is operator-visible but not auto-detected.
- **The mutating side of supply** (the per-block rollup `accumulated_* += block_*` at `chain.cpp:1390-1395`, the genesis seeding at `chain.cpp:711-715`, the suspension/equivocation slash crediting `block_slashed`, the cross-shard inbound/outbound accounting). Those are apply-layer correctness (`AccountStateInvariants.md` I-1..I-6, `CrossShardSupplyConservation.md` XS-0..XS-5, `S033StateRootNamespaceCoverage.md` §4.1.4); this proof reads the *committed* `c:` counters and does not re-prove how they got their values. SU-3 re-checks the *closed-form identity among the committed counters*, not the per-block transition that produced them.
- **The single-shard scope of SU-3's identity check.** SU-3 lets the light client verify the *per-shard* A1 identity `expected_total = genesis_total + Σsubsidy + Σinbound − Σslashed − Σoutbound` against the counters of the *one* daemon it queries. The *cross-shard aggregate* identity (`CrossShardSupplyConservation.md` XS-5, summing over the K-shard set with paired inbound/outbound) is out of scope — it requires querying every shard's daemon, which the single-daemon medium tier does not do (§6.4).

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: the single RPC endpoint the light client talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged supply replies), drop or stall requests, mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope, identically to that document §2.2: `A_crypto` (the proof rests on assumption A1 + A2 being infeasible), `A_local` (operator machine compromise), `A_net` (transport MITM), `A_genesis` (tampered pinned `genesis.json`).

**Security goal.** Under `A_daemon`, an honest light client running `supply-trustless` never **acts on** a supply counter (or a derived total) that is inconsistent with the genesis-pinned chain's committed `c:` state at the verified height. "Acts on" means *displays as authoritative* or *feeds into a downstream decision* (e.g., an operator computing the circulating supply, auditing total minted subsidy against the genesis-pinned cap, or reconciling cross-shard inbound vs. outbound flows). The negation form is **fail-closed exit**: any detected inconsistency throws and propagates to a non-zero process exit with a structured stderr diagnostic (inherited from `LightClientThreatModel.md` L-6).

---

## 3. Verification primitives reused

`supply-trustless` reuses the four light-client primitives unchanged — genesis anchor (§3.1 of the threat model), committee-sig verify (§3.2), header continuity (§3.3), and Merkle state-proof verify (§3.4) — composed by the same `read_*_trustless` skeleton, once per counter against the *same* committee-anchored head. The only specializations are the `"c"` namespace argument to `state_proof`, the composite `"k:c:"` key the daemon builds from it, the `SHA256(counter_u64)` value-hash decode, and the SU-3 cross-counter identity recompute over the five verified values. The pipeline diagram of `LightClientThreatModel.md` §3.5 applies verbatim with the state-proof stage targeting `("c", NAME)` and repeated five times.

Crucially, the daemon sources `state_root`, `leaf_count`, `target_index`, `value_hash`, and the sibling vector from **one** `rpc_state_proof` reply per counter (`node.cpp:3325-3335` returns them in a single JSON object), and the light client binds each proof's `state_root` to a committee-signed header in the *same* invocation via the S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`). For the five-counter read to be mutually consistent, the light client must anchor all five proofs to the *same* `state_root` (the head it committee-verified once); a daemon that serves five proofs against five *different* roots is caught because at most one root can match the single committee-anchored head, and any mismatch throws (§4.3 SU-3, §4.4 single-root precondition). This single-envelope-per-counter sourcing plus the shared-root anchoring is the precondition SU-4 formalizes.

---

## 4. Security theorems

Throughout, let `NAME` be a queried counter name, `R := state_root(h)` the committee-anchored root at the verified height `h`, `n := leaf_count(h)` the genuine leaf count of the tree `R` commits to, and `v_T(\text{NAME})` the true value of counter `NAME` in the chain's actual state at height `h` (with true leaf `\text{value\_hash}_c^T(\text{NAME}) = H(u64\_be(v_T(\text{NAME})))`).

### 4.1 Theorem SU-1 (committee-signed `state_root` binds the `c:` counter leaf)

**Statement.** Under (assumption A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance, in the **S-033-active interior regime** (`state_root(h) ≠ 0` and a committee-signed successor block `h+1` exists on the operator's pinned chain), the `state_root R` that `supply-trustless` anchors and verifies each `c:` proof against equals the genuine `state_root_T(h)` of the pinned chain at `h`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation. Consequently the root each `c:` counter leaf is checked against is *committee-certified*, not daemon-asserted — forging a different anchored root reduces to an assumption-A1 forgery on block `h+1` or an A2 collision at `h`.

**Adversary game.**

1. Operator pins `genesis_O`; the genesis-seeded committee `K_0 = {(domain_i, pk_i)}` is loaded into the seed map by `build_genesis_committee` (`trustless_read.cpp:46-53`). The genuine pinned chain has `state_root_T(h) ≠ 0` and a committee-signed `h+1`.
2. Light client runs `supply-trustless`. Internally it anchors genesis (T-L1), walks + committee-verifies headers `0..h` (and the forward link to `h+1` via the same paged walk), and in the S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`) — reached after a stale-height gate (`trustless_read.cpp:528-533`) — recomputes the anchor block's `block_hash` and requires the committee-signed successor's `prev_hash` to equal it, transitively binding the anchor's `state_root` to each `c:` proof's claimed root.
3. `A_daemon` wins if the invocation anchors and uses a root `R_A ≠ state_root_T(h)` without throwing.

**Proof.** The binding of `state_root(h)` to the committee is *transitive-forward*, not a direct signature. The committee directly Ed25519-signs `compute_block_digest(h)` (`producer.cpp::compute_block_digest`), which carries `index, prev_hash, tx_root, …` but **NOT** `state_root`. `state_root(h)` is bound into `Block::signing_bytes(h)` (when non-zero, via the S-033 zero-skip shim) and hence into `block_hash(h) = compute_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`. So

$$
\text{state\_root}(h) \in \text{signing\_bytes}(h) \in \text{block\_hash}(h) = \text{prev\_hash}(h+1) \in \text{digest}(h+1).
$$

This is exactly the chain of bindings `StateRootAnchorSoundness.md` SR-1 establishes, applied here to the height the `c:` proofs are anchored at. Suppose the invocation anchors `R_A ≠ state_root_T(h)`. Two exhaustive cases (the SR-1 case split, reproduced for the `c:`-proof anchoring in `committee_bound_state_root` at `trustless_read.cpp:335-437`):

- **Case (i): the daemon kept the served `block_hash(h)` equal to the genuine `block_hash_T(h)`** (so the `h → h+1` prev_hash link still closes against the committee-signed `digest(h+1)`). The genuine `block_hash_T(h) = SHA256(signing_bytes_T(h) ‖ sigs)` with `signing_bytes_T(h)` containing `state_root_T(h)`. The served header has `state_root = R_A ≠ state_root_T(h)`, so its `signing_bytes` differ; for it to hash to the same `block_hash_T(h)` is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2).

- **Case (ii): the daemon changed `block_hash(h)` to be internally consistent with `R_A`.** Then `prev_hash(h+1)` as served must equal the new `block_hash_A(h) ≠ block_hash_T(h)`. But the light client committee-verifies `h+1`'s signatures over `digest(h+1)` against `K_0` (`verify_block_sigs` invoked on the successor header inside `committee_bound_state_root` at `trustless_read.cpp:409-415`). The genuine committee signed `digest(h+1)` containing `prev_hash(h+1) = block_hash_T(h)`. To accept `h+1` with a different `prev_hash`, the daemon must present `required` valid signatures over a different digest — an Ed25519 forgery for each of `required ≤ K` distinct committee members, `≤ K · 2⁻¹²⁸` (assumption A1). This reuses T-L2's reduction verbatim.

Summing the exhaustive cases, `Pr[A_daemon anchors R_A ≠ state_root_T(h)] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. The genesis- and height-binding of the *whole walk* (that `R` is the root of the operator's pinned chain at `h` specifically, not a fork's or another height's) is supplied by SR-2 + SR-3 + T-L1's genesis anchor; SU-1 inherits them. Because all five counter proofs are anchored to the *same* committee-verified head, the single root `R` SU-1 establishes is the root every counter leaf is checked against (§4.4).

**Head-block boundary.** If the operator queries supply at the chain *head*, that block's `state_root` has no signed successor yet, so it is committee-certified only once a successor is produced. The shipped flow (S-042) handles this by **failing closed**: `committee_bound_state_root` fetches the successor header at `anchor_index + 1`, and when the anchor IS the head that successor does not exist, so the helper throws (`trustless_read.cpp:388-401`) rather than report an unbound head `state_root` — unless the operator passes `--wait <seconds>`, in which case it polls for the next block and then binds the held proof. Full nodes enforce the head's root meanwhile via the apply-layer S-033 gate (`StateRootAnchorSoundness.md` §3.4 + §6.3). SU-2 below proves Merkle-path soundness *given* such an `R`; SU-1 is the committee-binding of `R`. (This is the `race window` phenomenon — the chain may advance between the head walk and the proof fetch — handled by the S-042 successor binding rather than the former branch dispatch; the standalone temporal proof is `StateProofRaceWindowSoundness.md` PRW-1..PRW-5.)

**Concrete-security bound.** `Pr[A_daemon wins SU-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸` per invocation; for `K ≤ 64`, `≤ 2⁻¹²¹`.   ∎

### 4.2 Theorem SU-2 (Merkle state-proof for a `c:` counter leaf is sound)

**Statement.** Under (A2) SHA-256 collision resistance, given the committee-anchored root `R = state_root(h)` from SU-1, a verifier holding `R` cannot be made to accept a wrong counter value `v_A(\text{NAME}) ≠ v_T(\text{NAME})` without exhibiting a SHA-256 collision. Formally: if

$$
\texttt{merkle\_verify}(R,\; \text{key}_c(\text{NAME}),\; \text{value\_hash}_A,\; \text{target\_index},\; n,\; \text{proof}) = \texttt{true},
$$

then either (a) `value_hash_A` is the genuine `k:c:`-leaf value-hash for `NAME` at sorted position `target_index` of the tree `R` commits to, or (b) an efficient extractor produces a SHA-256 collision. Hence under A2 a passing verification proves the `c:` counter leaf is committed under `R`, except with probability `≤ log₂(n) · 2⁻¹²⁸`.

**Adversary game.**

1. Setup as SU-1: the light client has anchored committee-signed `R` for the `c:` proof.
2. `A_daemon` returns a state-proof `P_A = (\text{key}_c(\text{NAME}), \text{value\_hash}_A, \text{target\_index}, n, \text{proof})` where `value_hash_A ≠ value_hash_c^T(\text{NAME})` (a wrong counter leaf), or alters `target_index` / a sibling.
3. `A_daemon` wins if `verify_state_proof(P_A, R)` returns `ok = true`.

**Proof.** This is the direct application of `MerkleTreeSoundness.md` **MT-4** (inclusion-proof soundness) at the `k:c:` leaf, equivalently `LightClientThreatModel.md` T-L3 specialized to the supply-counter namespace and structurally identical to `StakeProofSoundness.md` SP-2. `verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value_hash_A, target_index, n, sibs)` (`light/verify.cpp:378-380`), which recomputes the leaf hash `c_0 = \text{merkle\_leaf\_hash}(\text{key}_c(\text{NAME}), \text{value\_hash}_A) = H(\texttt{0x00} \| u32\_be(|\text{key}_c(\text{NAME})|) \| \text{key}_c(\text{NAME}) \| \text{value\_hash}_A)` and walks up the sibling chain (`merkle.cpp:129-138`), accepting iff the exact-consume gate (`proof_idx == proof.size()`) holds **and** the recomputed root equals `R`.

By MT-4's extraction: if `value_hash_A ≠ value_hash_c^T(\text{NAME})`, then `c_0 ≠ c_0^{hon}` (distinct preimages under the unambiguous length-prefixed leaf encoding of `MerkleTreeSoundness.md` §2.1 — or, if `c_0 = c_0^{hon}` despite distinct content, that *is* a leaf-level collision, output it). Both the recomputed chain and the honest root-path chain for `NAME` terminate at `R`. Walking top-down, there is a highest level where the chains agree but the level below disagrees; at that level two distinct ordered 65-byte child-pairs `0x01 ‖ l ‖ r` map to the same `H` output — a SHA-256 collision. The range / underflow / exact-consume gates (`merkle.cpp:127-128, 133, 139`; `MerkleTreeSoundness.md` §2.6 scenarios #5-#8) ensure the walk is against the genuine `n`-leaf root-path, so the comparison is not length-mismatched. Each of the `≤ log₂(n)` levels contributes `≤ 2⁻¹²⁸`; union bound `≤ log₂(n) · 2⁻¹²⁸`.

The **leaf-key binding** is sharper for the `c:` namespace than for any other, because its key is the *composite* `"k:c:" + NAME` and must be distinguished both from the bare `k:` constants and from the `a:` / `s:` namespaces. The recomputed leaf hash incorporates the full `"k:c:"`-prefixed key (`node.cpp:3308-3311` builds exactly `"k:" + "c:" + NAME`), so:
- a daemon cannot serve a bare-`k:` constant leaf (e.g., the `min_stake` value-hash) and pass it off as a counter — by `S033StateRootNamespaceCoverage.md` T-2's `k:` ↔ `k:c:` boundary argument (byte 2 of any `k:` constant key is in `{'b','l','m','r','s','u'}`, never `'c'`; the five counter names are the only `k:`-prefixed keys whose byte 2 is `'c'`), the keys differ, the sibling chain differs, and root-equality fails;
- a daemon cannot serve an `a:` balance leaf or an `s:` stake leaf as a counter — `S033StateRootNamespaceCoverage.md` T-2's prefix-disjointness gives `"k:c:"+NAME ≠ "a:"+x ≠ "s:"+y` at byte 0/1, the `MerkleTreeSoundness.md` MT-2 domain separation plus the `test_state_proof_namespaces.sh` swap assertions reject it.

By `S033StateRootNamespaceCoverage.md` T-1, the five `accumulated_*` / `genesis_total` fields are in fact bound to the root through the `k:c:` namespace (and through *no other*, by T-2), so the leaf SU-2 verifies is the genuine committed counter.

**Cleartext cross-check (optional belt-and-suspenders, mirroring L-4 / SP-2).** If `supply-trustless` additionally fetches the daemon's cleartext counter (e.g., a `supply`/`chain-info`-class RPC exposing the five `accumulated_*` / `genesis_total` accessors at `chain.hpp:437-441`) and recomputes `H(u64\_be(v_A(\text{NAME})))` to compare against the proof's verified `value_hash`, then a daemon lying about a counter value while serving an honest proof must find `v_A(\text{NAME}) ≠ v_T(\text{NAME})` with colliding value-hashes — a SHA-256 second-preimage on a single `u64` field, `≤ 2⁻¹²⁸` (A2). This binds the human-readable counter to the committed leaf identically to the balance read's L-4; whether the sibling command ships this cross-check or decodes the value from the proof field directly, the value-hash is the load-bearing binding and SU-2 holds on the proof alone.

**Concrete-security bound.** `Pr[A_daemon wins SU-2] ≤ log₂(n) · 2⁻¹²⁸` per counter; for `n ≤ 2⁶⁴`, `≤ 2⁻¹²²`. Across all five counters, union-bounded, `≤ 5 · log₂(n) · 2⁻¹²⁸ ≤ 2⁻¹¹⁹`.   ∎

### 4.3 Theorem SU-3 (verified counters let the light client check the A1 supply identity itself)

**Statement.** Once `supply-trustless` has verified all five `c:` counters against the *same* committee-anchored root `R` (each by SU-1 + SU-2), the light client can recompute the chain's closed-form A1 unitary-supply identity

$$
\text{expected\_total} \;=\; \texttt{genesis\_total} + \texttt{accumulated\_subsidy} + \texttt{accumulated\_inbound} - \texttt{accumulated\_slashed} - \texttt{accumulated\_outbound}
$$

(`Chain::expected_total`, `include/determ/chain/chain.hpp:443-449`) entirely from committee-committed values. Consequently a daemon cannot present a set of five counters that are *each* individually leaf-committed under `R` yet *mutually* inconsistent with the genesis-pinned chain's accounting: every honest node's committed counters satisfy the same per-block rollup that maintains this identity (`AccountStateInvariants.md` I-6 / `EconomicSoundness.md` T-12), so the five committed values the light client reads are the genuine post-apply accumulators, and any derived total the operator computes equals the value `expected_total()` returns on the daemon's own honest chain at height `h`.

**Why this is new to the supply namespace.** The balance read (`a:`) and stake read (`s:`) each verify a *single* leaf in isolation; there is no cross-leaf invariant a verifier can re-check. The supply counters are different: the five values are bound by the closed-form identity that the apply path *enforces at every block* (`chain.cpp:1397-1419`: `if (live_total_supply() != expected_total()) throw`). SU-3 is the observation that this identity is *publicly recomputable* from the five committed counters alone — the light client does not need `live_total_supply()` (the sum over all `a:` + `s:` leaves, which would require reading every account) to gain a meaningful consistency guarantee on the counters themselves.

**Proof.**

1. *Each counter is the genuine committed value.* By SU-1 (committee-anchored `R`) + SU-2 (Merkle inclusion at the `k:c:` leaf), for each of the five `NAME`, the value the light client decodes is `v_T(\text{NAME})` — the genuine value in the chain's actual state at `h` — except with the SU-1 + SU-2 negligible probability. This holds *simultaneously* for all five because all five proofs are anchored to the same `R` (the single committee-verified head; §4.4 establishes there is exactly one such `R` per invocation, so a daemon cannot mix counters from two different states).

2. *The genuine committed counters satisfy the A1 identity.* On the daemon's honest chain, the apply path maintains `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_outbound_`, `accumulated_slashed_` by the per-block rollup at `chain.cpp:1390-1395` and sets `genesis_total_` once at genesis (`chain.cpp:711-715`); `expected_total()` is defined as the closed form above (`chain.hpp:443-449`). By `EconomicSoundness.md` T-12 (the closed-form A1 invariant, proved for every finalized block) and `AccountStateInvariants.md` I-6 (the per-account → chain-wide bridge), the post-apply state at every height satisfies `live_total_supply() == expected_total()`, with the five counters as the right-hand-side inputs. The state_root `R` commits to the *post-apply* counters at `h` (the producer's tentative-chain dry-run populates `body.state_root` after apply, per S-038 / `S033StateRootNamespaceCoverage.md` §2.3), so the five committed leaves SU-2 verifies are exactly the inputs `expected_total()` consumed on the honest chain.

3. *Therefore the light client's recompute equals the chain's.* Composing (1) + (2): the five values the light client reads are the genuine post-apply counters, and plugging them into the same closed form yields the same `expected_total` the daemon's honest chain holds at `h`. A daemon that wishes to mislead the operator about supply must therefore either (i) tamper an individual counter leaf — caught by SU-2 (the tampered value-hash fails root-equality), or (ii) anchor different counters to different roots — caught by the single-root precondition (§4.4: at most one root matches the committee-bound anchor, so the other proofs throw at the `attested != proof_root` check, `trustless_read.cpp:549-555`), or (iii) present a wholly different but still committee-signed state at a different height — caught by SU-1's SR-2/SR-3 genesis/height binding. In every case the attack reduces to assumption A1 or A2.

**What SU-3 does *not* give (the live-supply boundary).** SU-3's recompute checks the *identity among the five committed counters*. It does **not**, by itself, confirm that the committed counters match the *sum over the account/stake leaves* (`live_total_supply()`), because the light client does not read every `a:`/`s:` leaf — enumerating the full account set is simply not part of the single-daemon medium-tier read. The full apply-layer guarantee `live_total_supply() == expected_total()` is enforced *on every full node* at apply tail (`chain.cpp:1397-1419`) and is the property the *chain* maintains; SU-3 lets the light client confirm the *counter half* of that identity is internally consistent and committee-committed, which is the trust-minimized read's deliverable. (Note: `leaf_count` is no longer a caller-trust assumption — S-040 CLOSED binds it into the committed root via the root-wrapper hash, so a forged count is rejected; see SU-4 below. The boundary here is purely that the light client does not enumerate the account set to re-derive `live_total_supply()`.)

**Concrete-security bound.** SU-3 adds no independent cryptographic term beyond SU-1 + SU-2 applied five times under the single-root precondition; its guarantee is the *logical* composition of five sound leaf reads with the publicly-known closed form `expected_total()`. `Pr[A_daemon presents internally-inconsistent committee-committed counters] ≤ Pr[SU-1] + 5·Pr[SU-2] ≤ (K + 1)·2⁻¹²⁸ + 5·log₂(n)·2⁻¹²⁸`.   ∎

### 4.4 Theorem SU-4 (`leaf_count` is cryptographically bound into the committed root; S-040 closed)

**Statement.** SU-2's soundness is stated with `n` = the *genuine* leaf count of the tree `R` commits to, and SU-3's cross-counter check requires all five proofs to anchor to a *single* `R`. **As of S-040 (CLOSED), `leaf_count` is bound into the committed root via the root-wrapper hash** `R = SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`; `0x02` domain-separated from the `0x00` leaf / `0x01` inner tags). `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the *caller-supplied* `leaf_count`, and compares to the committed root — so a forged `leaf_count` (`M ≠ N`) yields a different wrapper hash and is **rejected** under A2, regardless of which channel supplied it. The former single-envelope/single-root sourcing *obligation* is therefore now *enforced by the hash*, not merely a caller guideline: a daemon cannot make a proof for one tree shape validate against the root of a different shape. The shipped `supply-trustless` flow still sources `state_root` and `leaf_count` from one `rpc_state_proof` reply per counter and anchors every proof to the same committee-verified head — but this is now defense-in-depth rather than a soundness precondition.

**Why the binding holds.** `merkle_verify` re-derives the inner Merkle root from `(target_index, leaf_count, siblings)`, then computes the wrapper `SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` and checks it byte-for-byte against the committed `R` (`merkle.cpp:113-141`). A forged `(target_index, leaf_count)` pair that yields the *same inner walk shape* as the genuine tree still feeds a *different* `leaf_count` into the wrapper preimage, so the wrapper hash differs from the genuine `R` and verification fails — except with the negligible A2 collision probability of finding two distinct `(leaf_count, inner_root)` preimages mapping to the same wrapper output. The historical failure pinned by `determ test-merkle-proof-tampering` scenario #12 (claiming `leaf_count = 8` for a genuinely-5-leaf tree at index 2) is now **rejected**; the lock-in scenario was inverted to assert that a forged `leaf_count` is REJECTED.

**Consequence for the supply read.** Both the historical *split-source* concern (proof + `leaf_count` from one channel, `state_root` from another) and the *split-root* concern (five proofs anchored to five different roots) are now closed cryptographically:

1. `Node::rpc_state_proof` returns `state_root`, `leaf_count`, `target_index`, `value_hash`, and `proof` as fields of **one** JSON object per counter (`node.cpp:3325-3335`), computed atomically under the daemon's `state_mutex_` read lock (`node.cpp:3289`) over a single consistent state. The `leaf_count` is `chain_.state_proof(...).leaf_count = build_state_leaves().size()` (`chain.cpp:456`) — the genuine count for the very tree whose root is `compute_state_root()` in the same reply (`node.cpp:3333`).
2. The light client binds *that reply's* `state_root` to a committee-signed header (SU-1) in the same invocation, then verifies the `c:` proof against the bound root using *that reply's* `leaf_count` (the `merkle_verify` call inside `verify_state_proof`, `verify.cpp:378-380`). Because `leaf_count` is bound into the wrapper that produced `R`, any `leaf_count` other than the genuine one fails root-equality against the committee-anchored `R` — there is no longer any reliance on the daemon presenting a consistent `(state_root, leaf_count)` pair; an inconsistent one is caught by the wrapper check itself.
3. *Single-root precondition (supply-specific).* For SU-3's cross-counter identity to be meaningful, all five counter proofs must commit to the *same* state. The flow enforces this because each proof's `state_root` is matched against the *one* committee-bound anchor (`committee_bound_state_root(anchor_index = proof_height − 1)`): a daemon serving counter A against root `R₁` and counter B against root `R₂ ≠ R₁` can have at most one of `R₁, R₂` equal the committee-attested root, so the other proof throws at the `attested != proof_root` check (`trustless_read.cpp:549-555`). The light client therefore reads five counters that are all committed under the same `R`.

If a malicious daemon serves an inconsistent `(state_root, leaf_count)` — e.g., the genuine `leaf_count` but a tampered `state_root` — the tampered root fails SU-1's committee anchoring. If it serves a *tampered* `leaf_count` with the genuine `state_root`, the wrapper re-derivation `SHA256(0x02 ‖ be_u32(leaf_count_forged) ‖ inner_root)` no longer equals the committee-anchored `R`, so verification fails under A2 — the daemon gains no ability to substitute a wrong tree shape, a wrong slot count, or a wrong counter value. The S-040 closure makes the binding cryptographic rather than procedural.

**Status.** **S-040 CLOSED.** `leaf_count` is bound into the committed root via the root-wrapper hash (`merkle.cpp::merkle_root_wrap`, `0x02` domain tag); a forged count is rejected, so the former single-envelope/single-root sourcing obligation is now enforced by the hash, not just a caller guideline. Shipped pre-launch as a wire-compat break (every `state_root` value changed; no installed base). The light client inherits it (`light/verify.cpp` calls `crypto::merkle_verify` directly). Not a deferred / open / flag-day item.

**Concrete-security bound.** SU-4 adds no independent term beyond SU-1 + SU-2 + SU-3; a forged `leaf_count` is rejected by the wrapper check under the same A2 collision bound (`≤ 2⁻¹²⁸`) that already underwrites SU-2.   ∎

### 4.5 End-to-end composition

**Corollary SU-E (trust-minimized supply read).** Under assumption A1 + A2, `supply-trustless` yields five supply counters — and any total derived from them via the public closed form `expected_total()` — bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis. Composing SU-1 (committee-anchored root) + SU-2 (`k:c:` Merkle inclusion, five times) + SU-3 (cross-counter A1-identity recompute) + SU-4 (single-envelope + single-root `leaf_count`) with the genesis-anchor + header-walk steps (T-L1 + T-L2), and taking the union bound over the pipeline (the per-step independent bounds of `LightClientThreatModel.md` T-L4):

$$
\Pr[A_{\text{daemon}} \text{ wins SU-E}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; 5\cdot\log_2(n)\cdot 2^{-128}.
$$

For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible. This matches the balance-read bound of `LightClientThreatModel.md` T-L4 (and the `s:` bound of `StakeProofSoundness.md` SP-E) up to the small `5×` factor on the Merkle term for the five-leaf read, as expected: the `c:`, `s:`, and `a:` reads differ only in the namespace argument, the key-construction, the leaf value-hash decode, and (for `c:`) the count of leaves read, all of which are namespace-agnostic in every cryptographic step.   ∎

---

## 5. Composition with companion proofs

### 5.1 `MerkleTreeSoundness.md` — the inclusion-proof core

SU-2 *is* MT-4 applied at the `k:c:` leaf; it asserts no new cryptographic claim. MT-1 (determinism) guarantees the `c:` counter leaves' positions and the root are reproducible across honest nodes; MT-2 (domain separation) underwrites the cross-namespace-swap rejection that stops an `a:` balance leaf, an `s:` stake leaf, or a bare-`k:` constant leaf from masquerading as a `k:c:` counter leaf; MT-3 (collision-resistance inheritance) is the divergence-detection that makes any wrong committed counter produce a different root. SU-4 is the `supply-trustless`-specific statement of MT-4's §6.2 (S-040 CLOSED) `leaf_count` root-wrapper binding — `leaf_count` is committed into the root, so a forged count is rejected; the former operational obligation is now enforced by the hash, and the single-root anchoring the five-leaf read uses is defense-in-depth.

### 5.2 `StateRootAnchorSoundness.md` — the committee binding

SU-1 *is* SR-1 applied at the height the `c:` proofs are anchored at, plus SR-2 (genesis-binding, no floating header) + SR-3 (height-binding) inherited for the walk. The transitive-forward `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` chain is the SR-series mechanism; SU-1 names the `c:` read as a consumer of it, exactly as `LightClientThreatModel.md` T-L4 does for the `a:` read via the S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`; successor committee-sig verify at `:409-415`) and `StakeProofSoundness.md` SP-1 does for the `s:` read.

### 5.3 `S033StateRootNamespaceCoverage.md` — the namespace surface

T-1 (coverage completeness) confirms the five `accumulated_*` / `genesis_total` fields are committed to the root through the `k:c:` namespace (and through *no other*, by T-2 disjointness — including the sharp `k:` ↔ `k:c:` byte-2 boundary), so the leaves SU-2 verifies are the genuine committed counters. §2.1's table fixes the byte-exact `k:c:` key (`"k:" + "c:" + name`) + value-hash (`SHA256(value_u64)`) encoding this proof reads off `chain.cpp:380-384, 403-408`. T-3 (deterministic leaf ordering) + T-4 (producer/receiver symmetry) guarantee the daemon's served `state_root` is the same value every honest node computes, so the committee that signed `digest(h+1)` signed over a `block_hash(h)` derived from the canonical `k:c:` counter leaf set. §4.1.4 is the per-field provenance of the five counters this read targets.

### 5.4 `LightClientThreatModel.md` — the adversary model and read flow

This proof specializes T-L3 (state-proof correctness) + T-L4 (composite read with race-window mitigation) from the `a:` namespace to `c:`. The adversary `A_daemon`, the fail-closed-exit operational statement (L-6), the genesis anchor (T-L1), and the per-block committee-sig verify (T-L2) are all inherited unchanged. SU-E's bound equals T-L4's up to the `5×` Merkle-term factor for the five-leaf read. The light client's `read_account_trustless` (`trustless_read.cpp:439-599`) is the structural template the shipped `cmd_supply_trustless` (`light/main.cpp`) follows with `namespace="c"`, repeated per counter against the same anchored head.

### 5.5 `StakeProofSoundness.md` — the sibling namespace proof

SU-1/SU-2/SU-4 mirror `StakeProofSoundness.md` SP-1/SP-2/SP-3 one-for-one, with the `s:`→`c:`/`k:c:` namespace substitution, the composite-key construction, and the `SHA256(counter_u64)` single-`u64` value-hash decode (vs. the `s:` pair `SHA256(locked_u64 ‖ unlock_height_u64)`). The structural identity is intentional: the two reads share the entire `read_*_trustless` skeleton and differ only at the namespace argument + leaf decode. SU-3 is the one result with no `s:`/`a:` analog (the supply counters carry a publicly-recomputable cross-leaf identity that single balances and single stakes do not).

### 5.6 `AccountStateInvariants.md` / `EconomicSoundness.md` / `CrossShardSupplyConservation.md` — the A1 supply identity SU-3 re-checks

SU-3 lets the light client recompute the closed-form A1 identity `expected_total()` over the five committed counters. That identity is the *output* of the apply-layer proofs: `EconomicSoundness.md` T-12 (the per-block closed-form invariant, FA11) + `AccountStateInvariants.md` I-6 (the per-account → chain-wide bridge, FA-Apply-1) prove the chain *maintains* `live_total_supply() == expected_total()` at every block; `CrossShardSupplyConservation.md` XS-5 (FA-Apply-17) generalizes it to the K-shard aggregate. SU-3 does *not* re-prove those — it consumes T-12's conclusion (the committed counters are the genuine A1 right-hand-side inputs) and observes that the right-hand side is publicly recomputable from the five leaves alone. The cross-*shard* aggregate (XS-5) is out of SU-3's single-daemon scope (§6.4). `EconomicSoundness.md` T-12.1 (counter determinism) is the MT-1 corollary that makes the five committed counters reproducible across honest nodes.

### 5.7 `BlockchainStateIntegrity.md` — chain-level prerequisite

The daemon's served chain has passed S-021 load validation; its served headers carry S-038-populated `state_root` fields; the `c:` proofs anchor against an S-033-committed root. As with the balance and stake reads, `read_supply_trustless` must throw with the "chain has not activated state_root (S-033)" diagnostic if the verified head's `state_root` is empty (`trustless_read.cpp:458-464`) — a chain-level deployment prerequisite, not a light-client design choice. SU-1's interior regime is exactly the S-033-active regime.

---

## 6. Known limitations

All limitations of `LightClientThreatModel.md` §6 apply verbatim (no persistence, no multi-peer redundancy, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). Three are worth calling out for the supply read specifically.

### 6.1 SU-3 checks the counter-identity, not the full supply equation

SU-3's recompute confirms the five committed counters satisfy `expected_total = genesis_total + Σsubsidy + Σinbound − Σslashed − Σoutbound` — the *right-hand side* of the A1 invariant. It does **not** confirm that this equals `live_total_supply()` (the sum over every `a:` balance + `s:` locked stake leaf), because the light client does not read every account/stake leaf (enumerating the full account set is simply not part of the single-daemon medium-tier read). The full equation `live_total_supply() == expected_total()` is enforced on every full node at apply tail (`chain.cpp:1397-1419`) and is the *chain*'s guarantee; the light client's trust-minimized deliverable is the committee-committed, internally-consistent counter set. An operator wanting the full live-supply cross-check runs a full node (which enforces it) or accepts the chain-level guarantee that the apply gate has never thrown on any accepted block.

### 6.2 Single-shard scope of the A1 identity (no cross-shard aggregate)

SU-3 verifies the *per-shard* A1 identity against the one daemon queried. The cross-shard aggregate conservation (`CrossShardSupplyConservation.md` XS-5: `Σ_s genesis_total(C_s)` conserved across the K-shard set with paired inbound/outbound) requires querying every shard's daemon and summing — the single-daemon medium tier does not do this. An operator auditing global supply across a sharded deployment must run `supply-trustless` against each shard's daemon and compose the results by hand (with the attendant multi-invocation trust caveat of `LightClientThreatModel.md` §6.2). This is the supply analog of the DApp/sharding-aware-read gap noted in `LightClientThreatModel.md` §1.

### 6.3 S-040 leaf_count binding (SU-4) — CLOSED, not a limitation

Recorded in §4.4: **S-040 is CLOSED.** `leaf_count` is bound into the committed root via the root-wrapper hash `R = SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`merkle.cpp::merkle_root_wrap`), so a forged count is rejected under A2 regardless of source. This is no longer a caller-trust limitation — it is listed here only to flag that the former single-envelope/single-root sourcing guideline is now enforced by the hash, not a precondition. No deferred / flag-day work remains.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| SU-1 | committee-binding (S-042) in the read flow | `light/trustless_read.cpp:335-437` | `committee_bound_state_root` — recompute the full anchor block's `block_hash`, fetch the committee-signed **successor** header, require `successor.prev_hash == recomputed block_hash` (`:424-432`); the anchor digest excludes `state_root`, so signing it does not bind it. Reached via the stale-height gate (`:528-533`) + `anchor_index = proof_height − 1` (`:545`); head fails closed (`:388-401`) unless `--wait`. |
| SU-1 | `verify_block_sigs` (on successor) | `light/verify.cpp:235-328` | Per-block Ed25519 K-of-K committee-sig verify over `light_compute_block_digest`; invoked on the successor header at `trustless_read.cpp:409-415`. |
| SU-1 | `verify_headers` | `light/verify.cpp:135-233` | prev_hash continuity walk from genesis (SR-2 genesis-binding). |
| SU-1 | `anchor_genesis` | `light/trustless_read.cpp:55-82` | T-L1 genesis pin (`compute_genesis_hash` byte-compare). |
| SU-2 | `verify_state_proof` | `light/verify.cpp:330-396` | Parse `c:` proof JSON, delegate to `merkle_verify`; optional `--state-root` override. |
| SU-2 | `merkle_verify` | `src/crypto/merkle.cpp:113-141` | Recompute root from `k:c:` leaf + siblings; range/underflow/exact-consume gates. |
| SU-2 | `c:`/`k:c:` leaf encoding | `src/chain/chain.cpp:380-384, 403-408` | `const_leaf("c:NAME", value)` → key `"k:c:" + NAME`, `value_hash = SHA256(value_u64)`. |
| SU-2 | counter fields | `include/determ/chain/chain.hpp:611-615` | `genesis_total_`, `accumulated_subsidy_/slashed_/inbound_/outbound_`. |
| SU-3 | `Chain::expected_total` | `include/determ/chain/chain.hpp:443-449` | The closed-form A1 identity the light client recomputes over the five committed counters. |
| SU-3 | counter accessors | `include/determ/chain/chain.hpp:437-441` | `genesis_total()`, `accumulated_subsidy()/slashed()/inbound()/outbound()` — the cleartext counters cross-checked against the proofs. |
| SU-3 | A1 apply-tail gate | `src/chain/chain.cpp:1397-1419` | `if (live_total_supply() != expected_total()) throw` — the chain-side enforcement SU-3 consumes (I-6 / T-12). |
| SU-4 | `Node::rpc_state_proof` | `src/node/node.cpp:3287-3336` | `c:` namespace supported (l.3305); composite key `"k:c:"+NAME` (l.3308-3311); returns `state_root` + `leaf_count` in one envelope (l.3325-3335). |
| SU-4 | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | `leaf_count = leaves.size()` (l.456) from the same tree as the root. |
| SU-E | `read_account_trustless` (template for `cmd_supply_trustless`) | `light/trustless_read.cpp:439-599` | The composite read skeleton; `supply-trustless` differs by `namespace="c"`, repeated per counter against the same head. |
| SU-1 | `Chain::compute_state_root` | `src/chain/chain.cpp:413-415` | `merkle_root(build_state_leaves())` — the root the committee transitively signs. |
| SU-1 | state_proof RPC dispatch | `src/rpc/rpc.cpp:235-238` | `method == "state_proof"` → `rpc_state_proof(namespace, key)`. |

**Tests** (the `c:` read shares the light-client + Merkle + supply test surface; `tools/test_light_supply_trustless.sh` is the shipped end-to-end script):

| Test | Coverage |
|---|---|
| `tools/test_light_supply_trustless.sh` | SU-E end-to-end — fetch + verify the five `c:` counters against a committee-signed root; daemon lies about a counter via tampered RPC → light-client detects mismatch. |
| `tools/test_light_balance_trustless.sh` / `tools/test_light_stake_trustless.sh` | T-L4 / SP-E sibling shapes; `supply-trustless` mirrors them with `namespace="c"`. |
| `tools/test_light_verify_state_proof.sh` | SU-2 — happy path + tampered value_hash → FAIL + tampered sibling → FAIL + wrong state_root → FAIL. |
| `tools/test_state_proof_namespaces.sh` | SU-2 leaf-key binding — cross-namespace swap (a `k:c:`-key with an `a:`/`s:`/bare-`k:`-value_hash) rejected. |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` (15 scenarios) | SU-2 tamper rejection; SU-4 / S-040 CLOSED — scenario #12 asserts a forged `leaf_count` is REJECTED by the root-wrapper binding. |
| `tools/test_state_root_namespaces.sh` | `k:c:`-namespace mutation-changes-root coverage (`S033StateRootNamespaceCoverage.md` T-1). |
| `tools/test_supply_invariant.sh` / `tools/test_supply_lifecycle.sh` | The chain-side A1 identity (I-6 / T-12) SU-3 consumes — direct apply-tail assertion that `live_total_supply() == expected_total()`. |
| `tools/test_cross_shard_supply_invariant.sh` | The cross-shard aggregate (XS-5) out of SU-3's single-daemon scope (§6.2). |

---

## 8. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** SHIPPED. The `c:` namespace is served by `Node::rpc_state_proof` (`node.cpp:3305-3311`) — since R51 with the raw counter value (`value_hex`/`value_u64`) returned atomically with the proof (see the status note above §1) — and committed by `build_state_leaves` (`chain.cpp:403-408`); the `determ-light supply-trustless` composite command is `cmd_supply_trustless` (`light/main.cpp`), structurally identical to `read_account_trustless` with `namespace="c"`, repeated per counter against the same committee-anchored head. End-to-end test: `tools/test_light_supply_trustless.sh`.
- **Cryptographic assumptions used.** assumption A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision / second-preimage resistance). No A3/A4 dependence beyond what T-L1's genesis anchor already carries.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis` (inherited from `LightClientThreatModel.md` §2.2).
- **Theorems.** SU-1 (committee-signed `state_root` binds the `c:` counter leaf — reduces to an assumption-A1 forgery on `h+1` or an A2 collision at `h`, via SR-1); SU-2 (`k:c:` Merkle inclusion soundness — MT-1/MT-3/MT-4 at the `k:c:` leaf, MT-2 domain separation for the composite-key binding); SU-3 (the verified counters let the light client recompute the A1 supply identity itself — consuming I-6 / T-12; no `a:`/`s:` analog); SU-4 (`leaf_count` cryptographically bound into the committed root via the root-wrapper hash — S-040 CLOSED, a forged count is rejected under A2). Corollary SU-E composes them with T-L1 + T-L2 to the same `≤ 2⁻⁹²` end-to-end bound as the balance/stake reads (up to a `5×` Merkle-term factor for the five-leaf read).
- **Composes with.** `MerkleTreeSoundness.md` (MT-1/MT-2/MT-3/MT-4 + §6.2 S-040), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `S033StateRootNamespaceCoverage.md` (T-1/T-2/T-3/T-4 + §2.1 `k:c:` row + §4.1.4), `LightClientThreatModel.md` (T-L1/T-L2/T-L3/T-L4 + `A_daemon` + L-6), `StakeProofSoundness.md` (SP-1/SP-2/SP-3 sibling templates), `AccountStateInvariants.md` (I-6), `EconomicSoundness.md` (T-12 / T-12.1), `CrossShardSupplyConservation.md` (XS-5), `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 prerequisite).
- **Known limitations.** SU-3 checks the counter-identity, not the full `live_total_supply()` equation (§6.1); single-shard scope, no cross-shard aggregate (§6.2). (S-040 CLOSED — `leaf_count` is bound into the committed root via the root-wrapper hash, so a forged count is rejected; this is no longer a limitation, recorded at §6.3 only for cross-reference.) None undermine the per-invocation soundness claim.

---

## 9. References

### Implementation sites
- `src/chain/chain.cpp:380-384` — `const_leaf` lambda (`"k:" + name` key, `SHA256(value_u64)` value-hash).
- `src/chain/chain.cpp:403-408` — the five `c:` counter leaves (`const_leaf("c:NAME", value)` → key `"k:c:NAME"`).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root`.
- `src/chain/chain.cpp:435-462` — `Chain::state_proof` (`leaf_count` at l.456).
- `src/chain/chain.cpp:1397-1419` — A1 unitary-supply apply-tail gate (`live_total_supply() == expected_total()`).
- `src/node/node.cpp:3287-3336` — `Node::rpc_state_proof` (`c:` supported l.3305; composite key l.3308-3311; single envelope l.3325-3335).
- `src/rpc/rpc.cpp:235-238` — `state_proof` RPC dispatch.
- `include/determ/chain/chain.hpp:437-441` — counter accessors.
- `include/determ/chain/chain.hpp:443-449` — `Chain::expected_total` (closed-form A1 identity).
- `include/determ/chain/chain.hpp:611-615` — counter fields.
- `src/crypto/merkle.cpp:113-141` — `merkle_verify`.
- `light/verify.cpp:330-396` — `verify_state_proof`.
- `light/trustless_read.cpp:439-599` — `read_account_trustless` (template for `cmd_supply_trustless`); S-042 committee-binding via `committee_bound_state_root` (`light/trustless_read.cpp:335-437`).
- `light/main.cpp` — `cmd_supply_trustless` (the shipped composite command).

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels + the "A1 unitary-supply invariant ≠ assumption A1" disambiguation; §2.1 SHA-256 (A2/A3); §2.2 Ed25519 EUF-CMA (assumption A1).
- `docs/proofs/MerkleTreeSoundness.md` — MT-1 (determinism), MT-2 (domain separation), MT-3 (collision-resistance inheritance), MT-4 (inclusion-proof soundness — SU-2 core), §6.2 (S-040 — SU-4).
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1 (committee-anchored root — SU-1 core), SR-2 (genesis-binding), SR-3 (height-binding).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — T-1 (coverage completeness), T-2 (namespace disjointness, incl. `k:` ↔ `k:c:` boundary), §2.1 (`k:c:` row), §4.1.4 (counter provenance).
- `docs/proofs/LightClientThreatModel.md` — `A_daemon` model; T-L1/T-L2/T-L3/T-L4; L-4 (cleartext cross-check); L-6 (fail-closed exit).
- `docs/proofs/StakeProofSoundness.md` — SP-1/SP-2/SP-3 (`s:`-namespace sibling templates SU-1/SU-2/SU-4 mirror).
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — I-6 (the A1 supply identity SU-3 re-checks).
- `docs/proofs/EconomicSoundness.md` (FA11) — T-12 (closed-form A1 invariant), T-12.1 (counter determinism).
- `docs/proofs/CrossShardSupplyConservation.md` (FA-Apply-17) — XS-5 (K-shard aggregate identity; out of SU-3's single-daemon scope, §6.2).
- `docs/proofs/BlockchainStateIntegrity.md` — S-021 + S-033 + S-038 four-surface composition (chain-level prerequisite).

### Specifications
- `docs/PROTOCOL.md §4.1.1` — `state_root` Merkle-leaf table (`k:c:` row, the tenth conceptual namespace).
- `docs/PROTOCOL.md §10.2` — `state_proof` RPC contract.
- `docs/SECURITY.md §S-033` — state_root commitment closure.
- `docs/SECURITY.md §S-038` — producer-side state_root population.
- `docs/SECURITY.md §S-040` — `leaf_count` root-wrapper binding, CLOSED (SU-4).
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (assumption A1).
