# TxInclusionProofSoundness — trustless transaction-inclusion verification soundness (`determ-light verify-tx-inclusion`)

This document formalizes the soundness of the **`determ-light verify-tx-inclusion`** subcommand (sibling E3, now shipped — `light/verify_tx_inclusion.cpp` / `.hpp`, regression `tools/test_light_verify_tx_inclusion.sh`). The subcommand answers a single question without trusting the daemon that serves the data:

> Is transaction `H` (identified by its 32-byte hash) included in the committee-signed block at height `B`, or is it provably *not* included?

The verdict is one of `INCLUDED`, `NOT-INCLUDED`, or `UNVERIFIABLE`. The first two are *cryptographically anchored* claims (down to the named assumptions); the third is the fail-closed escape hatch that fires whenever the daemon serves data that does not chain back to the operator's pinned genesis.

The reason this proof exists as a distinct document from `LightClientThreatModel.md` is that the per-transaction membership question rests on a **specific binding fact** about Determ's block format: whether the canonical transaction-set commitment (`tx_root`, the union-tx-root) is actually inside the committee-signed block digest. §3 establishes this from the source — and the answer determines whether `verify-tx-inclusion` delivers a cryptographic inclusion proof (the **strong regime**, TI-1..TI-3) or merely a daemon-trusted body echo (the **degraded regime**, TI-4). The verdict, grounded in `include/determ/chain/block.hpp` + `src/node/producer.cpp::compute_block_digest` + `light/verify.cpp::light_compute_block_digest`, is: **Determ is in the strong regime.** `tx_root` is committee-signed; TI-1..TI-3 hold; TI-4 is documented but not the operative case.

**Companion documents.** `LightClientThreatModel.md` (T-L1 genesis anchor, T-L2 committee-sig trust — the two primitives this proof composes); `LightClientArchiveSoundness.md` (sibling temporal flow — proves header *sequences*; this proof proves tx *membership within* a single block); `MerkleTreeSoundness.md` (MT-4 inclusion-proof soundness — cited for its A2-reduction *shape*, with the important caveat in §4.5 that `tx_root` is **not** a Merkle tree, so MT-4 does not apply verbatim); `Censorship.md` (FA2 — the union-tx-root construction whose *inclusion* this verifier reads back, and whose Phase-1 union semantics underwrite the binding in §3.3); `Safety.md` (FA1 — the per-block K-of-K signature-set primitive); `Preliminaries.md` (F0) §2.0 canonical assumption labels — **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage resistance (§2.1); `docs/SECURITY.md` §S-030 + `S030-D2-Analysis.md` for the digest field-coverage analysis that bounds *exactly* which block fields the committee signature does and does not cover.

---

## 1. Scope

### 1.1 In scope

The object of study is `determ-light verify-tx-inclusion --tx-hash H --height B`, a **per-invocation** trustless membership verifier. Its logical pipeline is:

1. **Genesis anchor** (`anchor_genesis`, `LightClientThreatModel.md` T-L1). Establish that the daemon serves the operator's pinned chain.
2. **Header trust for block `B`** (`verify_headers` prev_hash continuity + `verify_block_sigs`, T-L2). Fetch block `B`'s header, verify the committee Ed25519 signature set over the recomputed block digest, and verify the prev_hash linkage so the header is anchored to the genesis-pinned prefix. This makes the **committee-signed block digest** for height `B` trusted.
3. **Digest → tx-root binding** (§3, the load-bearing section). The committee-signed digest binds the block's canonical transaction-set commitment `tx_root` (the union-tx-root). After step 2, the verifier holds a *trusted* `tx_root` for block `B`.
4. **Body fetch + tx-root recompute + membership decision.** Fetch block `B`'s body (its `transactions[]`), recompute `tx_root` from the returned transactions, check byte-equality against the committee-signed `tx_root`, then decide `H ∈ {tx hashes}`.

The verdict:

| Verdict | Condition |
|---|---|
| `INCLUDED` | steps 1–3 pass; recomputed `tx_root` equals the committee-signed `tx_root`; `H` is the hash of some transaction in the body. |
| `NOT-INCLUDED` | steps 1–3 pass; recomputed `tx_root` equals the committee-signed `tx_root`; `H` is the hash of *no* transaction in the body. |
| `UNVERIFIABLE` | any of: genesis anchor fails (T-L1); header sig/continuity fails (T-L2); the chain has no block at height `B`; the recomputed `tx_root` does **not** equal the committee-signed `tx_root` (tampered body — §4.3); a committee not in the seed map (the §6 caveat); or any RPC/parse error. |

The first two are *sound* verdicts in the sense of §4; `UNVERIFIABLE` is the fail-closed exit that never yields a false positive or false negative.

The pipeline composes the two reused primitives with the new membership layer:

```
   operator's --genesis <file>      --tx-hash H        --height B
            │                            │                  │
            ▼                            ▼                  ▼
  ┌──────────────────────┐   ┌────────────────────────────────────┐
  │  anchor_genesis()    │   │  RpcClient::call(...) — fetch:       │
  │  (T-L1, reused)      │   │   • header[B]   • body[B]            │
  └──────────┬───────────┘   └──────────────────┬─────────────────┘
             │ ok → continue; mismatch → UNVERIFIABLE                
             ▼                                   │
  ┌──────────────────────────┐                   │
  │  verify_headers(prev) +   │  T-L2 (reused)    │
  │  verify_block_sigs(hdr B) │  + prev_hash walk │
  │  ⇒ trusted r⋆ = b.tx_root │  ←── §3.1 binding │
  └──────────┬───────────────┘                   │
             │ ok → continue; any fail → UNVERIFIABLE                
             ▼                                   ▼
  ┌────────────────────────────────────────────────────────────┐
  │  recompute r_A = compute_tx_root({compute_hash(tx_i^A)})     │  §4 (NEW layer)
  │  gate:  r_A == r⋆  ?                                         │  TI-3
  │     no  → UNVERIFIABLE (tampered body)                       │
  │     yes → decide  H ∈ {compute_hash(tx_i^A)}  ?              │  TI-1 / TI-2
  │              yes → INCLUDED        no → NOT-INCLUDED         │
  └────────────────────────────────────────────────────────────┘
```

Steps 1–2 are inherited verbatim from `LightClientThreatModel.md`; the only new analytic content is the §3 binding (`r⋆` is committee-signed) and the §4 recompute-gate-and-decide layer.

### 1.2 Relationship to the existing light-client proofs

`verify-tx-inclusion` is a **fourth composite** alongside the `LightClientThreatModel.md` surface (`verify-chain`, `balance-trustless`, `nonce-trustless`, `verify-and-submit`). It reuses T-L1 + T-L2 verbatim for steps 1–2 and adds a *new* membership-decision layer on top. It does **not** use T-L3 (state-proof) / T-L4 (balance/nonce) / T-L5 (sign-submit): a transaction's membership in a block is a *block-body* property, committed by `tx_root`, not a *state* property committed by `state_root`. The two commitments are independent fields of the block (§3.2). This is the cleanest possible composition — the new surface adds exactly one binding argument (the §3 tx-root binding) and one recompute check, with everything else inherited.

`LightClientArchiveSoundness.md` proves a *temporal* property over a *sequence of headers* (an archive attests the header chain over `[from, from+count)`, re-verifiable offline). This proof is *orthogonal*: it proves *membership of one transaction within one block's body*. A header archive (which by default strips `transactions`) does **not** carry the body and therefore cannot answer the inclusion question on its own — §5.3 makes the boundary precise.

### 1.3 Out of scope

- **Cryptographic breaks** (`A_crypto`): SHA-256 collision/preimage finder (A2 / A3), Ed25519 forger (A1). The verifier's soundness rests on these being infeasible — exactly as `LightClientThreatModel.md` §2.2.
- **The auditor's machine** (`A_local`): tampering with the `determ-light` binary itself, ptrace, side-channel. Operator mitigates via OS-level integrity.
- **Tampered pinned `--genesis`** (`A_genesis`): if the operator pins the wrong genesis, the verifier anchors to the wrong chain. The "trust anchor itself is compromised" case; out of scope exactly as in `LightClientThreatModel.md` §2.2.
- **Transport confidentiality / availability** (`A_net`, and a daemon that simply refuses to serve a body): a daemon that stalls or drops is an *availability* failure surfaced as `UNVERIFIABLE`, not a *soundness* failure. §6.2.
- **Non-membership across the whole chain.** `verify-tx-inclusion` answers membership in *the block at height `B`* — the height the operator names. It does **not** prove that `H` is absent from *every* block of the chain (that would require walking every block's body). §6.3.

---

## 2. Threat model

### 2.1 Adversary capability

We reuse the `A_daemon` adversary of `LightClientThreatModel.md` §2.1: a **malicious daemon** that is the single RPC endpoint the light-client talks to, able to return arbitrary JSON, drop/stall requests, mutate responses between calls within an invocation, and coordinate lies across invocations. Specialized to the inclusion question, `A_daemon` will attempt one of three deceptions:

- **(a) False positive inclusion.** Convince the verifier that `H` *is* in block `B` when it genuinely is not (e.g., to make an operator believe a payment they never received was committed).
- **(b) False negative / suppressed inclusion.** Convince the verifier that `H` is *not* in block `B` when it genuinely is (e.g., to hide an on-chain transaction from an auditor).
- **(c) Body substitution.** Serve a block body whose recomputed `tx_root` differs from the committee-signed `tx_root` — i.e., an arbitrary fabricated transaction set — and have the verifier act on it.

### 2.2 Security goal

Under `A_daemon`, an honest light-client (genuine pinned genesis, unmodified released binary, does not bypass its own verification):

- never returns `INCLUDED` for a transaction not genuinely in block `B`;
- never returns `NOT-INCLUDED` for a transaction genuinely in block `B`;
- never acts on a substituted body — any body whose recomputed `tx_root` differs from the committee-signed root yields `UNVERIFIABLE`, never a verdict.

The negation form is **fail-closed exit**: every detected inconsistency throws a `std::runtime_error` that propagates to a non-zero process exit code with a structured stderr diagnostic, exactly as `LightClientThreatModel.md` Lemma L-6.

### 2.3 Trust dependencies (what we assume holds)

The inclusion verdict is sound *conditional on*:

- **T-L1** (genesis-anchored chain identity) and **T-L2** (committee-sig head trust) from `LightClientThreatModel.md`. These are reused, not re-proved, here.
- **A1** (Ed25519 EUF-CMA) — the committee signature over the digest.
- **A2** (SHA-256 collision resistance) — the `tx_root` binding and the body-recompute match.
- The §6 committee-seed caveat (the block-`B` committee map is a superset of `b.creators`).

---

## 3. The binding — is `tx_root` committee-signed? (load-bearing section)

This is the section the whole scheme hinges on. The question: **does the K-of-K committee signature on block `B` actually cover the transaction-set commitment `tx_root`?** We answer it from the source, in three layers: what the committee signs (§3.1), what `tx_root` commits to (§3.2–§3.3), and the explicit field-coverage boundary (§3.4).

### 3.1 What the committee signs: `compute_block_digest` includes `tx_root`

The K-of-K committee signature in Phase 2 is produced by `make_block_sig` (`src/node/producer.cpp:662-675`), which signs the value `block_digest`:

```cpp
m.ed_sig = sign(key, block_digest.data(), block_digest.size());   // producer.cpp:673
```

`block_digest` is computed by `compute_block_digest` (`src/node/producer.cpp:577-591`):

```cpp
Hash compute_block_digest(const Block& b) {
    SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);                 // ← producer.cpp:581 — TX-ROOT IS BOUND
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);   // ← per-creator Phase-1 tx-hash lists also bound
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    return h.finalize();
}
```

Line `producer.cpp:581` (`h.append(b.tx_root)`) places the 32-byte `tx_root` field directly into the SHA-256 preimage of the digest each committee member signs. The light-client recomputes the *identical* digest in `light_compute_block_digest` (`light/verify.cpp:47-61`), which carries a "byte-for-byte copy of `producer.cpp::compute_block_digest`" comment and likewise binds `tx_root`:

```cpp
Hash light_compute_block_digest(const determ::chain::Block& b) {
    determ::crypto::SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);                 // ← light/verify.cpp:51 — same binding, light side
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    return h.finalize();
}
```

`verify_block_sigs` (`light/verify.cpp:190-283`) Ed25519-verifies each committee member's signature against exactly this digest (`light/verify.cpp:254`). Therefore: **after `verify_block_sigs` passes for block `B`, the verifier holds a `tx_root` value that ≥ `required` distinct committee members signed under their registered Ed25519 keys.** This is the strong-regime precondition.

The canonical specification agrees: `README.md §7.4` states `block_digest` is `SHA-256 of idx ‖ prev_hash ‖ tx_root ‖ delay_seed ‖ …`, and `Preliminaries.md` §1.3 names `compute_block_digest(B)` as "what each Phase-2 committee member signs over." The light-side equality is pinned by `LightClientThreatModel.md` Lemma L-2 (byte-equivalence of `light_compute_block_digest` with the producer) and exercised end-to-end by `tools/test_light_verify_block_sigs.sh`.

### 3.2 `tx_root` and `state_root` are independent block fields

`tx_root` (the transaction-set commitment) and `state_root` (the post-apply state commitment, S-033) are distinct fields of `struct Block` (`include/determ/chain/block.hpp:403` and `:484` respectively). `verify-tx-inclusion` reads back `tx_root`; the `LightClientThreatModel.md` T-L3/T-L4 reads read back `state_root`. The two are committed independently:

- `tx_root` is in `compute_block_digest` *unconditionally* (`producer.cpp:581`, every block).
- `state_root` is bound into the **block hash** via `signing_bytes` only when non-zero (`block.cpp:345-350`), and notably is **not** in `compute_block_digest` at all (the comment at `verify.cpp:40-46` enumerates the digest's field set and `state_root` is absent).

This independence is why `verify-tx-inclusion` needs **no** S-033/S-038 deployment prerequisite. Unlike the balance/nonce reads (which throw `chain has not activated state_root` on a pre-S-033 chain — `LightClientThreatModel.md` §5.5), the inclusion verifier works on *every* block, including pre-S-033 blocks, because `tx_root` has been in the digest since v1.

### 3.3 What `tx_root` commits to: the union-tx-root construction

`tx_root` is the **union-tx-root** of FA2 (`Censorship.md`). It is computed by `compute_tx_root` (`src/node/producer.cpp:262-270`):

```cpp
Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists) {
    std::set<Hash> u;
    for (auto& list : creator_tx_lists)
        for (auto& h : list) u.insert(h);     // union across K committee members' lists

    SHA256Builder b;
    for (auto& h : u) b.append(h);            // sorted (std::set order) concat of tx HASHES
    return b.finalize();
}
```

Two facts to record precisely, both load-bearing for §4:

1. **`tx_root` is a flat SHA-256 over the sorted set of transaction hashes** — `SHA256(h_{(1)} ‖ h_{(2)} ‖ … ‖ h_{(n)})` where `{h_{(i)}}` is the union of the K committee members' `creator_tx_lists`, deduplicated and sorted ascending (the `std::set<Hash>` iteration order). It is **not** a Merkle tree (contrast `state_root`, which `MerkleTreeSoundness.md` proves is a sorted-leaves balanced binary Merkle root). Consequence: there is no compact inclusion path; membership verification is a full-set recompute (§6.1). MT-4 does **not** apply verbatim — see §4.5.

2. **The leaves are transaction *hashes*, not transaction bodies.** Each `h_i = Transaction::compute_hash() = SHA256(Transaction::signing_bytes())` (`src/chain/block.cpp:31-34`), where `signing_bytes` covers `type ‖ from ‖ 0x00 ‖ to ‖ 0x00 ‖ amount_be ‖ fee_be ‖ nonce_be ‖ payload` (`block.cpp:17-29`). So `tx_root` commits to the *set of tx hashes*; and because the tx hash binds every consensus-relevant field of a transaction (A2), committing to the hash transitively commits to the content of each included transaction. A daemon cannot serve a body whose transactions hash into the committed set but carry different `(from, to, amount, fee, nonce, type, payload)` — that mutation changes `Transaction::compute_hash`, hence the recomputed `tx_root`, hence fails the §4.3 gate.

The chain-side validator enforces the producer's binding at apply time: `BlockValidator` (`src/node/validator.cpp:161-167`) recomputes `expected_root = compute_tx_root(b.creator_tx_lists)` and rejects any block where `expected_root != b.tx_root` (`tx_root mismatch with union(creator_tx_lists)`). This is the chain-level guarantee that `tx_root` is genuinely the union-tx-root of the committed Phase-1 contributions; the light-client inherits it transitively because honest committee members only sign digests for blocks that pass this validator on their own apply (FA1 / FA2).

### 3.4 Field-coverage boundary (S-030 D2) — what the digest does NOT cover

For an honest treatment, we record precisely what `compute_block_digest` does **not** cover. Per the comment at `producer.cpp:565-576` and `S030-D2-Analysis.md`, the committee-signed digest **excludes** the resolved `transactions[]` body list, `abort_events`, `cross_shard_receipts`, `inbound_receipts`, `initial_state`, `partner_subset_hash`, `delay_output`, `creator_dh_secrets`, and `state_root`. It covers only `index`, `prev_hash`, `tx_root`, `delay_seed`, `consensus_mode`, `bft_proposer`, and the per-creator Phase-1 evidence (`creators`, `creator_tx_lists`, `creator_ed_sigs`, `creator_dh_inputs`).

The crucial observation for *this* proof: the digest covers `tx_root` (the *commitment*) but **not** the resolved `transactions[]` (the *body*). This is exactly why step 4 of the pipeline (§1.1) must **recompute** `tx_root` from the served body and match it against the committee-signed value — the verifier may not trust the body directly, only the commitment. The recompute-and-match is the bridge from "committee signed a 32-byte `tx_root`" to "this is the genuine transaction set." §4.3 (TI-3) proves this bridge is the gate that makes TI-1/TI-2 sound; without it the verifier would be in the degraded regime of §4.4.

The S-030 D2 one-block ambiguity (two valid K-of-K-signed block *instances* differing in excluded fields behind the same digest) does **not** affect inclusion soundness, because `tx_root` is *inside* the digest: any two instances sharing a digest share the same `tx_root`, hence the same committed transaction-hash set. The ambiguity is confined to the *excluded* lists (evidence/receipts), which `verify-tx-inclusion` does not read.

### 3.5 Verdict: STRONG regime

Combining §3.1 (the digest binds `tx_root`) + §3.3 (`tx_root` is a faithful, validator-enforced commitment to the union transaction-hash set, content-binding via A2) + §3.4 (the body itself is *not* in the digest, so a recompute-and-match is mandatory and sufficient):

> **Determ is in the strong regime.** `verify-tx-inclusion` delivers a cryptographic inclusion/non-inclusion proof reducible to A1 (committee-sig unforgeability) + A2 (collision resistance of `tx_root` and the tx-hash binding), *provided* the verifier recomputes `tx_root` from the body and gates on the match. TI-1, TI-2, TI-3 (§4.1–§4.3) are the operative theorems; TI-4 (§4.4) is documented for completeness but is **not** Determ's regime.

---

## 4. Soundness theorems

Throughout, fix the operator's pinned genesis `genesis_O` and a target `(H, B)`. Assume T-L1 and T-L2 have passed for block `B` (otherwise the verdict is `UNVERIFIABLE` and no soundness claim is made). Let `r⋆` denote the **committee-signed** `tx_root` for block `B` — the value bound into the digest that `verify_block_sigs` validated (§3.1). Let `body_A = (tx_1^A, …, tx_m^A)` be the transaction body the daemon serves for block `B`, and let `r_A := compute_tx_root` evaluated over `body_A`'s transaction hashes (the verifier forms the set of `compute_hash(tx_i^A)` — the union over singleton lists is just that set, matching `compute_tx_root`'s set semantics).

### 4.1 Theorem TI-1 (sound positive inclusion)

**Statement.** Under A1 + A2, if `verify-tx-inclusion` returns `INCLUDED` for `(H, B)`, then transaction `H` is genuinely a member of the committee-finalized block at height `B`, except with probability `≤ (K + 1)·2⁻¹²⁸` per invocation.

**Adversary game.** `A_daemon` serves `body_A` and wins if the verifier returns `INCLUDED` while `H` is *not* the hash of any transaction in the genuine block-`B` body.

**Proof.** `INCLUDED` requires three conditions inside the verifier:

1. `verify_block_sigs` accepts block `B`'s header (T-L2), establishing `r⋆` as committee-signed.
2. `r_A = r⋆` byte-for-byte (the §4.3 gate, TI-3).
3. `H = compute_hash(tx_i^A)` for some `tx_i^A ∈ body_A`.

By condition 2, the verifier's recomputed root over the *served* body equals the *committee-signed* root. Let `S⋆` be the genuine union transaction-hash set committed by `r⋆` (the set `compute_tx_root` was evaluated over at production time), and let `S_A = { compute_hash(tx_i^A) }` be the set the verifier recomputed over. Both `compute_tx_root(S⋆) = r⋆` and `compute_tx_root(S_A) = r_A = r⋆`.

If `S_A ≠ S⋆`, then two distinct sorted sequences of 32-byte hashes feed the same flat-SHA-256 `compute_tx_root` and produce the same 32-byte output `r⋆`. The two preimages `(h_{(1)}^A ‖ … )` and `(h_{(1)}^⋆ ‖ … )` are distinct byte strings (distinct sets ⇒ distinct sorted concatenations, because each element is a fixed 32-byte field so the concatenation parses uniquely back to the set — there is no length-aliasing across the fixed-width leaves). Distinct preimages with equal SHA-256 output is exactly an A2 collision, probability `≤ 2⁻¹²⁸`. Hence except with probability `≤ 2⁻¹²⁸`, `S_A = S⋆`.

Given `S_A = S⋆` and condition 3 (`H ∈ S_A`), we have `H ∈ S⋆` — `H` is in the genuine committed transaction-hash set of block `B`. By A1, the value `r⋆` the verifier trusts is genuinely committee-signed (forging the `required` signatures over a different `r⋆` without the members' keys is `≤ K·2⁻¹²⁸`, `LightClientThreatModel.md` T-L2). Composing: the adversary's only paths to a false `INCLUDED` are (i) forge the committee signature over a fabricated `r⋆` (`≤ K·2⁻¹²⁸`, A1) or (ii) find a second hash-set colliding to the genuine `r⋆` that contains `H` (`≤ 2⁻¹²⁸`, A2). Union bound: `≤ (K + 1)·2⁻¹²⁸`. ∎

**Note on content-binding.** TI-1 establishes `H ∈ S⋆`, i.e., the *hash* `H` is committed. Because `H = compute_hash(tx)` binds every field of `tx` (§3.3), an operator who additionally inspects `tx_i^A`'s fields (`from/to/amount/…`) is assured those fields are the genuine ones: a daemon serving a `tx_i^A` with `compute_hash(tx_i^A) = H` but tampered fields would need a second preimage of `H` under `Transaction::signing_bytes` (A2/A3, `≤ 2⁻¹²⁸`). So "the tx with hash `H` is included" *and* "its content is as served" are both sound.

### 4.2 Theorem TI-2 (sound negative / non-inclusion)

**Statement.** Under A1 + A2, if `verify-tx-inclusion` returns `NOT-INCLUDED` for `(H, B)`, then transaction `H` is genuinely *absent* from the committee-finalized block at height `B`, except with probability `≤ (K + 1)·2⁻¹²⁸` per invocation.

**Adversary game.** `A_daemon` serves `body_A` and wins if the verifier returns `NOT-INCLUDED` while `H` *is* the hash of some transaction in the genuine block-`B` body.

**Proof.** `NOT-INCLUDED` requires conditions 1 and 2 of TI-1 (T-L2 passes; `r_A = r⋆`) plus the negation of condition 3: `H ≠ compute_hash(tx_i^A)` for *every* `tx_i^A ∈ body_A`, i.e., `H ∉ S_A`.

By the §4.1 argument, condition 2 gives `S_A = S⋆` except with probability `≤ 2⁻¹²⁸`. The genuine committed set is `S⋆`; the genuine block-`B` body's transaction hashes are exactly `S⋆` (the body the producer finalized is `union(creator_tx_lists)` resolved to transactions, whose hashes are the set `compute_tx_root` committed — `producer.cpp:719-724` + `README §7.4`). So `H ∉ S_A = S⋆` means `H` is the hash of no transaction in the genuine block-`B` body — genuine non-membership.

The adversary's only way to force a false `NOT-INCLUDED` is to make the verifier recompute a set `S_A` that (a) matches `r⋆` yet (b) omits a genuinely-present `H`. By the collision argument, any `S_A ≠ S⋆` matching `r⋆` is an A2 collision (`≤ 2⁻¹²⁸`); and a forged `r⋆` is `≤ K·2⁻¹²⁸` (A1). Union bound `≤ (K + 1)·2⁻¹²⁸`. In particular, a daemon that simply *omits* a real transaction from `body_A` (the natural suppression attack) produces `S_A ⊊ S⋆`, hence `r_A ≠ r⋆` with overwhelming probability, hence the §4.3 gate fires and the verdict is `UNVERIFIABLE`, **not** `NOT-INCLUDED`. ∎

**Scope reminder.** TI-2 proves non-membership *in the block at height `B`* — the height the operator supplied. It is not a chain-wide absence proof; the same `H` could be included at a *different* height. See §6.3.

### 4.3 Theorem TI-3 (tampered-body detection — the gate that makes TI-1/TI-2 hold)

**Statement.** Under A2, any block body `body_A` whose recomputed `tx_root` `r_A` does not equal the committee-signed `r⋆` is rejected with verdict `UNVERIFIABLE` — the verifier never emits `INCLUDED` or `NOT-INCLUDED` for a body inconsistent with the committed root. Conversely, the only bodies that *pass* the gate are those whose transaction-hash set equals the genuine committed set `S⋆`, except with A2-probability.

**Proof.** The verifier's membership decision is reached *only* on the `r_A == r⋆` branch; the `r_A != r⋆` branch throws (fail-closed, Lemma L-6 inherited). This is a structural property of the pipeline (§1.1 step 4): the `tx_root`-match is evaluated *before* the membership scan, and a mismatch short-circuits to `UNVERIFIABLE`.

Soundness of the gate: a body passes iff `compute_tx_root(S_A) = r⋆`. If `S_A = S⋆`, it passes (honest case). If `S_A ≠ S⋆`, passing requires `compute_tx_root(S_A) = compute_tx_root(S⋆)` with `S_A ≠ S⋆` — an A2 collision on the flat-SHA-256 over the fixed-width-leaf concatenation (`≤ 2⁻¹²⁸`, §4.1). Therefore, except with negligible probability, the gate admits exactly the genuine transaction-hash set, which is what TI-1 and TI-2 consume as their `S_A = S⋆` premise. ∎

TI-3 is the load-bearing gate: it converts "committee signed a 32-byte commitment" into "the body in hand is the genuine transaction set." Without it (a verifier that trusted the served body directly), the scheme would collapse into the §4.4 degraded regime regardless of the §3.1 binding.

### 4.4 Theorem TI-4 (degradation honesty — the regime Determ is NOT in)

**Statement (counterfactual).** *If* the canonical transaction-set commitment were **not** part of the committee-signed digest — i.e., if `compute_block_digest` omitted `tx_root` — then `verify-tx-inclusion` would degrade to **daemon-trust for the body**: the committee signature would anchor only the header/height (`index`, `prev_hash`, `delay_seed`, and the Phase-1 evidence), and the served `transactions[]` would carry no cryptographic anchor to the committee. In that regime, TI-1 and TI-2 would **not** hold; the strongest honest verdict would be "the daemon claims `H` is/ isn't in a body it asserts belongs to a committee-signed header at height `B`," with the inclusion claim resting on `A_daemon` honesty rather than A1/A2.

**Why this is the honest framing.** The residual guarantee in the degraded regime would be exactly:

- The *header* at height `B` is committee-signed and genesis-anchored (T-L1 + T-L2 still hold — they do not depend on `tx_root` being in the digest, only on the *header fields* that are).
- The *body* is whatever the daemon serves; the verifier has no committed root to match it against, so a malicious daemon could serve any transaction set, and the membership verdict would be a faithful report of the *daemon's chosen body*, not of the *committee's block*.

The verdict in that regime should therefore be labeled `UNVERIFIABLE` for the inclusion question (or, at most, a clearly-caveated "daemon-asserted" answer), never a cryptographic `INCLUDED` / `NOT-INCLUDED`.

**Determ is not in this regime.** §3.1 establishes by direct source reading (`producer.cpp:581`, `verify.cpp:51`) that `compute_block_digest` **does** bind `tx_root`. TI-4's hypothesis is false for Determ. TI-4 is retained in this document for three reasons: (1) to make the conditional nature of TI-1..TI-3 explicit — they are *contingent* on the §3.1 binding, not free; (2) as a regression tripwire — if a future refactor of `compute_block_digest` ever drops `tx_root` from the digest (or the light-side `light_compute_block_digest` drifts out of sync), the scheme silently falls into the TI-4 regime, and this theorem is the documented warning that the inclusion proof would lose its cryptographic footing; (3) honesty about the boundary an external auditor must check. The tripwire is partially mechanized: `tools/test_light_verify_block_sigs.sh` boots a real cluster and verifies a producer-generated block, so a digest/light-digest divergence that dropped `tx_root` would surface as a sig-verify failure there (Lemma L-2 reasoning).  ∎

### 4.5 Why MerkleTreeSoundness.md MT-4 does not apply verbatim

`MerkleTreeSoundness.md` MT-4 proves inclusion-proof soundness for the **state_root** primitive — a sorted-leaves balanced binary Merkle tree with a compact `O(log n)` sibling-path proof. `tx_root` is a **different** construction: a flat SHA-256 over the sorted set of transaction hashes (§3.3), with **no** sibling-path proof. The two share only the *reduction target* (A2) and the *shape* of the collision argument (a non-member that verifies yields a collision). The differences that matter:

- **No compact proof.** MT-4's verifier consumes `(key, value_hash, target_index, leaf_count, proof_sibs)` and recomputes a path. `verify-tx-inclusion` consumes the **whole body** and recomputes the **whole root** — an `O(m)` operation in the block's transaction count, not `O(log m)` (§6.1).
- **Set membership, not leaf-position membership.** `tx_root` commits to a *set*; membership is `H ∈ S⋆`, decided by scanning the recomputed set. There is no `target_index`, no per-level parity, and consequently none of MT-4's range/underflow/exact-consume gates apply.
- **The S-040 `leaf_count` caller-trust caveat is absent.** Because there is no Merkle `leaf_count` driving a walk, the `tx_root` recompute has no analog of the S-040 limitation. The verifier reconstructs the entire set; there is no untrusted count to source.

Accordingly, §4.1–§4.3 give a **direct** `tx_root`-recompute collision argument rather than invoking MT-4. We cite MT-4 only as the *analogous* result for the sibling `state_root` surface (and to make clear the inclusion verdict here uses a distinct, simpler primitive). The collision-extraction style is the same as MT-3 (`MerkleTreeSoundness.md` §3), specialized to a single flat hash.

### 4.6 Worked adversary scenarios

To make TI-1..TI-3 concrete, we walk the two attacks an auditor is most likely to ask about. In both, `A_daemon` has served an honest, committee-signed header for block `B` (so the verifier holds the genuine `r⋆`); the attack is entirely on the body.

**Scenario X (phantom inclusion — defeated by TI-1/TI-3).** The daemon wants the verifier to believe a transaction `tx_X` with hash `H_X = compute_hash(tx_X)` is in block `B`, when it is not. The daemon serves a body `body_A` that *includes* `tx_X`. Now `S_A = S⋆ ∪ {H_X}` (or some other set containing `H_X`). The verifier recomputes `r_A = compute_tx_root(S_A)`. Since `S_A ≠ S⋆` (it has an extra element), `r_A ≠ r⋆` except with A2-probability `≤ 2⁻¹²⁸` (a collision between two distinct sorted hash-concatenations). The §4.3 gate `r_A == r⋆` fails; the verifier emits `UNVERIFIABLE`, **not** `INCLUDED`. The only way the daemon wins is to (i) find a body whose hash-set collides to `r⋆` yet contains `H_X` (A2, `≤ 2⁻¹²⁸`) or (ii) have forged the committee signature over a fabricated `r⋆` that genuinely commits a set containing `H_X` (A1, `≤ K·2⁻¹²⁸`). Both are infeasible — the phantom inclusion is rejected.

**Scenario Y (suppressed inclusion — defeated by TI-2/TI-3).** The daemon wants the verifier to believe a genuinely-present transaction `tx_Y` (hash `H_Y ∈ S⋆`) is *absent* from block `B`. The daemon serves a body `body_A` that *omits* `tx_Y`, so `S_A = S⋆ \ {H_Y}`. Again `S_A ≠ S⋆`, so `r_A ≠ r⋆` except with A2-probability; the gate fails and the verdict is `UNVERIFIABLE`, **not** `NOT-INCLUDED`. The daemon cannot serve a strict subset of the committed set and have it match the committed root — the omission changes the root. (Note the asymmetry the operator should understand: a suppression attack does not yield a *false* answer; it yields `UNVERIFIABLE`. The operator learns "this daemon would not give me a body consistent with the committed root," which is itself actionable — switch daemons, per §6.2.)

**Scenario Z (content swap — defeated by the TI-1 content-binding note).** The daemon serves a body where the *hash set* is exactly `S⋆` (so `r_A = r⋆`, gate passes) but one transaction `tx_i^A` carries tampered fields (e.g., a redirected `to` or inflated `amount`) while *claiming* hash `H_i ∈ S⋆`. The verifier recomputes `compute_hash(tx_i^A)` from the served fields; if the fields are tampered, `compute_hash(tx_i^A) ≠ H_i`, so `tx_i^A`'s recomputed hash is *not* in `S⋆`, which means the recomputed `S_A ≠ S⋆` and the gate fails (`UNVERIFIABLE`). For the swap to pass, the daemon would need tampered fields that hash to the genuine `H_i` — a second preimage of `H_i` under `Transaction::signing_bytes` (A3, `≤ 2⁻¹²⁸`). So an operator who reads back the transaction *content* (not just the membership bit) gets content-integrity for free.

### 4.7 Supporting lemmas

**Lemma TL-1 (recompute byte-equivalence).** The verifier's `tx_root` recompute over a served body is byte-identical to the producer's `compute_tx_root` over the same transaction-hash set. *Proof.* Both evaluate `compute_tx_root` (`producer.cpp:262-270`): insert each `Hash` into a `std::set<Hash>` (which imposes the unique, ascending ordering), then `SHA256Builder::append` each in iteration order and `finalize`. The verifier obtains each leaf as `Transaction::compute_hash(tx_i^A)` (`block.cpp:31-34`), the same function the producer used to populate `creator_tx_lists` from the mempool. `std::set<Hash>` ordering, `SHA256Builder` append semantics, and `Transaction::compute_hash` are all platform-independent pure functions (no allocator-dependent ordering, no ABI variation), so the recompute is reproducible across the verifier and producer. Hence `S_A = S⋆ ⇒ r_A = r⋆` exactly (not merely with high probability), and the converse direction is the A2 argument of §4.1. □

**Lemma TL-2 (digest binds `tx_root`, light ↔ chain).** `light_compute_block_digest` (`light/verify.cpp:47-61`) and `compute_block_digest` (`producer.cpp:577-591`) append `b.tx_root` at the same position in the same field order, so the digest the verifier computes for a header equals the digest the committee signed, byte-for-byte, *including* the `tx_root` contribution. *Proof.* Field-by-field inspection (§3.1): both append `index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer`, then per-creator `creators ‖ creator_tx_lists ‖ creator_ed_sigs ‖ creator_dh_inputs`. This is the byte-equivalence `LightClientThreatModel.md` Lemma L-2 establishes for the whole digest; TL-2 is the specialization to the `tx_root` field, which is the one this proof depends on. The "keep in sync" comment header (`verify.cpp:32-46`) is the maintenance contract; `tools/test_light_verify_block_sigs.sh` is the runtime tripwire (§4.4). □

**Lemma TL-3 (fail-closed exit).** Every inconsistency the inclusion verifier can detect (genesis mismatch, header sig/continuity failure, missing block `B`, `r_A ≠ r⋆`, committee-not-in-seed) results in `UNVERIFIABLE` via a thrown `std::runtime_error` propagated to a non-zero exit code, never a silent downgrade to a verdict. *Proof.* By inheritance from `LightClientThreatModel.md` Lemma L-6 for the reused T-L1/T-L2 surfaces, plus the §4.3 structural property that the membership decision is reached only on the `r_A == r⋆` branch. There is no code path from a detected inconsistency to `INCLUDED`/`NOT-INCLUDED`. □

---

## 5. Composition

### 5.1 With `LightClientThreatModel.md` (T-L1 + T-L2)

`verify-tx-inclusion` reuses T-L1 (genesis anchor) and T-L2 (committee-sig head trust) verbatim for pipeline steps 1–2. The composition is sequential-dependency: the membership decision (§4) is reached only after both upstream gates pass, and each contributes its independent adversarial bound. Summing across the pipeline for a single `(H, B)` invocation:

- T-L1 genesis-anchor mismatch: `≤ 2⁻¹²⁸` (A2; `LightClientThreatModel.md` T-L1).
- T-L2 committee-sig forge for block `B`'s header: `≤ K·2⁻¹²⁸` (A1; T-L2). If the verifier walks the prev_hash chain from the anchored prefix to height `B` to bind the header to genesis (`verify_headers` continuity), add the per-link `≤ 2⁻¹²⁸` over the walked span — bounded by `B·2⁻¹²⁸`.
- The §4 `tx_root` recompute-and-match + membership: `≤ 2⁻¹²⁸` (A2, TI-3 collision; TI-1/TI-2 reuse the same collision event).

Union bound: `Pr[A_daemon defeats verify-tx-inclusion] ≤ (B + K + 2)·2⁻¹²⁸` per invocation. For practical chains (`B ≤ 2³²`, `K ≤ 16`), this is `≤ 2⁻⁹⁵`, operationally negligible. (The bound matches the structure of `LightClientThreatModel.md` T-L4, with the state-proof term replaced by the simpler `tx_root` term.)

### 5.2 With `Censorship.md` (FA2) and `Safety.md` (FA1)

FA2 establishes that the union-tx-root construction *forces inclusion* of any honest mempool transaction unless **every** committee member omits it (K-conjunction censorship). `verify-tx-inclusion` is, in effect, the *read-back* of that inclusion: FA2 is the production-side guarantee that an honest tx lands in `tx_root`; this proof is the verification-side guarantee that a holder of the committee-signed `tx_root` can *confirm* the landing trustlessly. The two are duals — FA2 says "it got in," TI-1 says "you can prove it got in."

FA1 supplies the per-block K-of-K signature-set primitive that T-L2 (hence step 2 here) rests on. No new FA1 claim is asserted; `verify-tx-inclusion` uses the same per-block primitive `LightClientThreatModel.md` already composed.

### 5.3 Relationship to `LightClientArchiveSoundness.md`

`LightClientArchiveSoundness.md` proves that a **header archive** is a sound, offline-re-verifiable attestation of the chain's *header sequence* over `[from, from+count)`. That flow, by default, **strips** `transactions` from each archived `header_json` (it keeps only the digest-relevant fields plus, optionally, `creator_block_sigs`). Consequently:

- A header archive **cannot, on its own, answer the inclusion question**: it carries `tx_root` (committee-signed) but not the body, so it proves *which `tx_root` the committee signed at height `B`* without proving *what transactions are in the body*.
- `verify-tx-inclusion` is the **complementary** surface: it fetches the *body* and recomputes `tx_root` to match the committee-signed value. A natural composition (future work, not shipped) is "archive → tx-inclusion": an archive attests `tx_root` at height `B` offline; a later body fetch + recompute against the archived `tx_root` would prove membership offline. This is the tx-side analog of the archive→state-proof composition that `MerkleTreeSoundness.md` §5.2 / `LightClientArchiveSoundness.md` §5.2 sketch for `state_root`.

The boundary is clean: **archives prove header sequences; `verify-tx-inclusion` proves tx membership within one block.** Both rest on the same T-L1 + T-L2 trust core and the same A1 + A2 assumptions.

---

## 6. Limitations

### 6.1 Full-body recompute, not a compact inclusion proof

Because `tx_root` is a flat SHA-256 over the transaction-hash set (§3.3), there is **no compact Merkle-path RPC** for a single transaction. The verifier must fetch the **entire block body** and recompute the whole root — an `O(m)` operation in the block's transaction count (`m` hashes inserted into a `std::set`, then `m` appends). For typical block sizes this is trivial; for pathologically large blocks it is linear in the body size, not logarithmic. A future enhancement could expose a Merkle-ized tx-root with a `tx_proof` RPC analogous to `state_proof` (and would then compose with an MT-4-style argument instead of the direct recompute of §4) — but the shipped construction is the union-tx-root flat hash, and this proof matches that reality. The verifier's per-tx work is therefore "download body + rehash," not "verify a short proof."

### 6.2 Single-daemon; availability is not soundness

`verify-tx-inclusion` talks to one daemon. A daemon that refuses to serve block `B`'s body, stalls, or returns malformed JSON yields `UNVERIFIABLE` — an availability failure, surfaced as fail-closed exit, not a soundness break. The verifier cannot say "this daemon is lying; another would tell the truth"; it can only say "this daemon failed verification." Multi-peer cross-checking is the same out-of-scope future tier as in `LightClientThreatModel.md` §6.2. In particular, a daemon that *omits* a real transaction from the body is caught (the recomputed `tx_root` mismatches — TI-2/TI-3), so omission cannot forge a `NOT-INCLUDED`; it can only force `UNVERIFIABLE`.

### 6.3 Membership at a *named* height, not chain-wide

The verdict is about the block at the operator-supplied height `B`. `NOT-INCLUDED` means "not in block `B`," not "not anywhere on the chain." An operator who wants "is `H` anywhere on the chain?" must either know the candidate height or walk every block's body (an `O(chain · avg-block)` scan, not what this subcommand does). This mirrors `MerkleTreeSoundness.md` MT-5's honesty about the absence of native non-membership proofs — here the analog is the absence of a chain-wide membership proof.

### 6.4 Committee-rotation tracking (genesis-only committee map)

T-L2 (hence step 2) requires the block-`B` committee map to be a superset of `b.creators`. The light-client seeds its committee map from genesis `initial_creators` (`LightClientThreatModel.md` §6.5 / F-1). For a chain with mid-chain `REGISTER` / `DEREGISTER` events, block `B`'s committee may include domains absent from the seed map, and `verify_block_sigs` then fails with `creator '<domain>' is not in the supplied committee` → `UNVERIFIABLE`. This is the **same `K_0` caveat** as the other light-client proofs (`LightClientThreatModel.md` §6.5, `LightClientArchiveSoundness.md` AR-4), inherited unchanged: the operator must pre-populate the committee map with every registered domain up to height `B`, or wait for the future stateful-sync tier that tracks committee evolution chain-side. Within committee-stable ranges the verdict is fully sound; across rotations it is `UNVERIFIABLE` (fail-closed), never wrong.

### 6.5 No state-proof dependency (a non-limitation, recorded for clarity)

Unlike `balance-trustless` / `nonce-trustless`, `verify-tx-inclusion` does **not** require S-033/S-038 to be active on the chain (§3.2): `tx_root` has been in `compute_block_digest` since v1, independent of `state_root`. So the inclusion verifier works on pre-S-033 blocks where the balance/nonce reads would throw `chain has not activated state_root`. This widens its applicability relative to the T-L3/T-L4 reads.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem / step | Function | File:lines | Role |
|---|---|---|---|
| Pipeline (E3) | `verify-tx-inclusion` subcommand | `light/verify_tx_inclusion.cpp` / `.hpp`; `light/main.cpp::cmd_verify_tx_inclusion` | Anchor → header trust → tx-root recompute → membership decision; emits INCLUDED / NOT-INCLUDED / UNVERIFIABLE. |
| Step 1 (T-L1) | `anchor_genesis` | `light/trustless_read.cpp:52-79` | Genesis-hash anchor (reused; `LightClientThreatModel.md` T-L1). |
| Step 2 (T-L2) | `verify_block_sigs` | `light/verify.cpp:190-283` | Per-block Ed25519 sig-set verify over the recomputed digest. |
| Step 2 (T-L2) | `verify_headers` | `light/verify.cpp:104-188` | prev_hash continuity binding block `B` to the genesis-anchored prefix. |
| §3.1 binding (light) | `light_compute_block_digest` | `light/verify.cpp:47-61` | Recomputes the committee-signed digest; **binds `tx_root` at line 51**. |
| §3.1 binding (chain) | `compute_block_digest` | `src/node/producer.cpp:577-591` | The producer's signed digest; **binds `tx_root` at line 581**. |
| §3.1 binding (sign) | `make_block_sig` | `src/node/producer.cpp:662-675` | K-of-K Ed25519 signature over `block_digest` (line 673). |
| §3.3 commitment | `compute_tx_root` | `src/node/producer.cpp:262-270` | Flat SHA-256 over the sorted union of tx hashes (the union-tx-root). |
| §3.3 tx hash | `Transaction::compute_hash` / `signing_bytes` | `src/chain/block.cpp:17-34` | The leaf hashes `tx_root` commits to; content-binding (TI-1 note). |
| §3.3 chain gate | `BlockValidator` tx_root check | `src/node/validator.cpp:161-167` | Rejects `tx_root != compute_tx_root(creator_tx_lists)` at apply. |
| §3.2 / §3.4 field set | `Block` struct + digest comment | `include/determ/chain/block.hpp:403`,`:484`; `light/verify.cpp:40-46` | `tx_root` vs `state_root` independence; digest field-coverage boundary. |
| §3.4 / TI-4 boundary | S-030 D2 analysis | `src/node/producer.cpp:565-576`; `docs/proofs/S030-D2-Analysis.md` | What the digest excludes; why inclusion is unaffected. |
| Body resolution | `build_body` + finalize | `src/node/producer.cpp:679-...`; `README.md §7.4` | Body = `union(creator_tx_lists)` resolved + sorted; `tx_root` set at line 724. |
| RPC transport | `RpcClient::call` | `light/rpc_client.cpp:141-169` | Generic JSON-RPC the body/header fetch rides on. |

Integration test:

| Test script | Theorem coverage |
|---|---|
| `tools/test_light_verify_tx_inclusion.sh` (E3, shipped) | TI-1 (real tx in block `B` → INCLUDED), TI-2 (absent tx → NOT-INCLUDED), TI-3 (tampered body / omitted tx → UNVERIFIABLE, no false verdict), and the §6.4 committee caveat (creator not in seed map → UNVERIFIABLE). |
| `tools/test_light_verify_block_sigs.sh` | Lemma L-2 tripwire (§4.4): a digest/light-digest divergence that dropped `tx_root` would surface as a sig-verify failure on a real producer block. |

---

## 8. Status

- **Spec.** Complete (this document).
- **Implementation.** `determ-light verify-tx-inclusion` shipped in sibling E3 (`light/verify_tx_inclusion.cpp` / `.hpp`; dispatched from `light/main.cpp::cmd_verify_tx_inclusion`; regression `tools/test_light_verify_tx_inclusion.sh`). The reused primitives (`anchor_genesis`, `verify_headers`, `verify_block_sigs`, `light_compute_block_digest`) were already shipped (`LightClientThreatModel.md` commits `f597c44` + `5e74097`).
- **Regime (the headline finding).** **STRONG.** The committee-signed `compute_block_digest` binds `tx_root` (`producer.cpp:581`, mirrored light-side at `verify.cpp:51`); `tx_root` is the validator-enforced union-tx-root commitment to the transaction-hash set (`producer.cpp:262-270`, `validator.cpp:161-167`); and the verifier recomputes `tx_root` from the served body and gates on the match (TI-3). TI-1 (sound positive inclusion) and TI-2 (sound non-inclusion) hold, reducing to A1 (committee-sig unforgeability) + A2 (collision resistance). TI-4 (degraded daemon-trust regime) is **not** Determ's case; it is documented as a regression tripwire and an honesty boundary.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2), A2 (SHA-256 collision resistance, §2.1), and transitively A3 (second-preimage on the tx-hash content-binding, TI-1 note). **A4** (CSPRNG) is not used by the inclusion verifier.
- **Adversary model.** `A_daemon` (malicious single daemon controlling RPC), reused from `LightClientThreatModel.md` §2.1. Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.
- **Composes with.** `LightClientThreatModel.md` (T-L1 + T-L2, reused), `Censorship.md` (FA2 — the union-tx-root inclusion this verifier reads back), `Safety.md` (FA1 — per-block sig primitive), `LightClientArchiveSoundness.md` (sibling — header sequences vs tx membership), `MerkleTreeSoundness.md` (MT-4 — analogous result for the sibling `state_root` surface; **not** applied verbatim — §4.5).
- **Known limitations.** Five in §6: full-body recompute (no compact proof), single-daemon (availability ≠ soundness), per-height not chain-wide membership, genesis-only committee map (the shared `K_0` caveat), and the recorded non-limitation that no S-033 dependency exists.
- **Concrete-security bound.** Per invocation: `≤ (B + K + 2)·2⁻¹²⁸`; `≤ 2⁻⁹⁵` for `B ≤ 2³²`, `K ≤ 16`. Under Grover (PQ), degrades to `≤ 2⁻⁴⁷` on the A1 term — operationally secure, with PQ-signature migration the long-term path (`Preliminaries.md` §2.2 note).

---
