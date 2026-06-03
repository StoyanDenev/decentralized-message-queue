# LightClientThreatModel — trust-minimized light-client security posture (`determ-light.exe`)

This document formalizes the security posture of the `determ-light.exe` light-client binary shipped in commits `f597c44` + `5e74097`. The light-client is a separate, ~3–5 MB stripped binary alongside `determ.exe` (full daemon) and `determ-wallet.exe` (offline operations). It connects to ONE operator-controlled daemon for data (head, blocks, state-proofs) but verifies every piece of data locally against a pinned genesis anchor + Ed25519 committee signatures + Merkle state-proofs — so even a malicious daemon cannot trick an honest light-client into acting on inconsistent data.

The proof exists because the trust posture is structural rather than cryptographic: it composes existing FA-series primitives (FA1 inclusion via Ed25519 EUF-CMA, FA2 censorship resistance) together with the SHA-256 collision-resistance assumption (A2, Preliminaries §2.1) into a per-invocation pipeline (`anchor_genesis` → `verify_headers` → `verify_block_sigs` → `verify_state_proof` → sign + submit) under a malicious-daemon adversary model. No new cryptographic primitive is introduced; the security claim is that the per-invocation pipeline is *sound* — an honest light-client never acts on data that is inconsistent with the genesis-pinned chain.

The "medium tier" scope explicitly declines three orthogonal features (persistent state, multi-peer redundancy, periodic poll loop) that a "stateful sync client" tier would add. Those gaps are documented as known limitations in §6 so an external auditor can confirm both what the binary delivers and what it intentionally leaves to operator-level mitigations.

**Companion documents.** `Preliminaries.md` (F0) §2.1 (SHA-256 collision resistance, A2 in this proof's terms) + §2.2 (Ed25519 EUF-CMA, A1 in this proof's terms); `Safety.md` (FA1) for the K-of-K signature-set safety property the light-client inherits via per-block sig verification; `Censorship.md` (FA2) for the censorship-resistance property the light-client does NOT extend (single-daemon scope); `S033StateRootNamespaceCoverage.md` for the state_root commitment surface the light-client anchors against; `BlockchainStateIntegrity.md` for the chain-level integrity composition (S-021 chain.json wrap + S-033 + S-038 producer wiring) the light-client inherits transitively via the daemon's data; `S012SnapshotStateRootGate.md` for the state_root verification gate the light-client mirrors in its per-invocation pipeline; `RpcAuthHmacSoundness.md` for the citation style (multiple-theorem closure proof under a named adversary model); `docs/SECURITY.md` §S-001 + §S-022 for the wire-format / RPC-input considerations not directly in scope here but cross-referenced; `C:/Users/WEIDIAN/.claude/plans/robust-gathering-oasis.md` for the implementation plan that drove these design decisions.

---

## 1. Scope

The light-client `determ-light.exe` is a **per-invocation** verifier-and-actor: each CLI invocation

1. anchors against the genesis JSON the operator supplies on `--genesis <file>`,
2. fetches a finite session worth of headers + state-proofs + (optionally) signs a transaction and submits it,
3. exits.

There is no daemonized loop, no persistent cache of "last verified head," no committee-state continuation across invocations. Every command starts fresh from the operator's pinned `genesis.json` and re-verifies the chain from block 0 up to whatever it needs.

The subcommand surface comprises:

| Subcommand | Class |
|---|---|
| `verify-headers` | pure verifier (offline file in) |
| `verify-block-sigs` | pure verifier (offline file in) |
| `verify-state-proof` | pure verifier (offline file in) |
| `fetch-headers` | network fetch (no verification) |
| `fetch-state-proof` | network fetch (no verification) |
| `verify-chain` | composite: anchor + walk + sig-verify all headers |
| `balance-trustless` | composite: verify-chain + state-proof read |
| `nonce-trustless` | composite: verify-chain + state-proof read |
| `sign-tx` | offline sign (no network) |
| `submit-tx` | network submit (operator pre-signed) |
| `verify-and-submit` | composite: nonce-trustless + sign-tx + submit-tx |

The composite commands (`verify-chain`, `balance-trustless`, `nonce-trustless`, `verify-and-submit`) are where the trust-minimization story lives. The pure-verifier commands and the offline `sign-tx` are not even adversary-exposed; they take operator-controlled JSON or keyfile bytes and emit bytes.

**Out of scope (intentional, per chosen "medium" tier).**

- **Stateful sync.** Persisting the last verified head + committee + state_root across invocations to avoid re-walking the chain. Tracked as a future "stateful sync client" tier; no implementation in this binary.
- **Multi-peer redundancy.** Querying ≥ 2 daemons in parallel and alerting on disagreement. Tracked as a future tier.
- **Periodic poll loop.** Long-lived daemonized "watch the head and alert on regression" mode. A future `watch-head` subcommand could ship a minimal poll loop but would still be per-invocation. Not in this proof.
- **DApp / sharding-aware composite reads.** The current composite reads (`balance-trustless`, `nonce-trustless`) target the `a:` namespace only. DApp `d:`-namespace reads, cross-shard receipt verification, etc., are not in this binary.

---

## 2. Threat model

### 2.1 Adversary capability

We define the adversary `A_daemon` as a **malicious daemon** — the single RPC endpoint the light-client talks to is fully under adversary control. Specifically, `A_daemon` may:

- **Return arbitrary JSON** in response to any RPC request the light-client issues. This includes forged headers, forged block bodies, forged state-proofs, forged account replies, and forged committee sigs.
- **Drop RPC requests** silently or with errors.
- **Stall** RPC requests indefinitely (within OS-level socket timeouts that the operator's environment imposes).
- **Mutate previously-served responses** between two requests in the same invocation (i.e., not just static lies but adaptive responses to the light-client's probing pattern).
- **Coordinate across invocations.** If the operator runs `determ-light` repeatedly against the same daemon, the daemon can vary its lies across invocations (e.g., serve honest data once, lie next time).
- **See the light-client's RPC requests in cleartext** if the operator's transport is unencrypted (no TLS / no wireguard / no SSH tunnel). The light-client itself does NOT encrypt RPC.

### 2.2 Adversary capability EXPLICITLY OUT of scope

The following adversaries are not addressed by the light-client's trust-minimization mechanisms:

- **`A_crypto`: cryptographic adversary.** SHA-256 collision finder, Ed25519 forger. Covered by Preliminaries §2.1 (A2) + §2.2 (A1). Out of scope here; the light-client's defenses rest on `A_crypto` being infeasible.
- **`A_local`: operator's machine compromise.** Key-extraction, ptrace, side-channel on the light-client process. Operator mitigates via OS-level controls + the encrypted keyfile flow at `determ-wallet keyfile-create` (S-004 / S-005). The light-client itself accepts only plaintext keyfile shape.
- **`A_net`: network MITM.** Eavesdropper or active man-in-the-middle on the operator-to-daemon transport. Operator wraps the RPC in TLS / tunnel if exposed to untrusted networks. The light-client makes no transport-layer claims.
- **`A_genesis`: tampered `--genesis <file>` on operator disk.** If the adversary writes a tampered genesis to the operator's disk and the operator pins it, the light-client anchors to the wrong chain. Operator mitigates via OS-level integrity (signed installer, verified download, etc.). Out of scope; this is "the trust anchor itself is compromised" case, not "the daemon is compromised."

### 2.3 Security goal

An **honest light-client** is one that:

- Loads a genuine, operator-trusted `genesis.json` on `--genesis`.
- Runs the released `determ-light.exe` binary without modification.
- Does not bypass its own verification (e.g., by reading from `rpc_account` directly instead of `balance-trustless`).

The security claim is: under `A_daemon`, an honest light-client never **acts on** data that is inconsistent with the genesis-pinned chain. "Acts on" means:

- **Signs and submits a transaction** using a nonce or amount that has not been verified against a committee-signed state_root.
- **Displays a balance** that has not been verified against a committee-signed state_root.
- **Displays a next_nonce** that has not been verified against a committee-signed state_root.
- **Displays a head height / head block_hash** that has not been verified against the genesis anchor + committee sigs.
- **Accepts a state-proof** that does not verify against a committee-signed state_root.

The negation form of the claim — "fail-closed exit" — is the operational statement: any data inconsistency the light-client detects causes a `throw std::runtime_error(...)` that propagates to a non-zero process exit code with a structured diagnostic on stderr.

---

## 3. Verification primitives

The light-client composes four verification primitives over the operator's per-invocation RPC session.

### 3.1 Genesis anchor

**Function.** `determ::light::anchor_genesis` at `light/trustless_read.cpp:52-79`.

**Inputs.**

- `rpc` — an open `RpcClient` to the operator's daemon.
- `genesis` — the parsed `GenesisConfig` from the operator's `--genesis <file>`.

**Procedure.**

1. Compute the expected genesis hash locally: `Hash expected = determ::chain::compute_genesis_hash(genesis)`. This rebuilds the canonical genesis block from the operator's JSON and applies `Block::compute_hash`. See `src/chain/genesis.cpp::compute_genesis_hash` at line 429.
2. Fetch block 0 from the daemon via `rpc_headers` with `{"from": 0, "count": 1}`.
3. Extract the daemon's `block_hash` field for block 0.
4. Compare byte-for-byte. On mismatch, throw with the `GENESIS HASH MISMATCH` tag carrying both hashes.

**Output.** The 64-character hex genesis-hash on success; throw on mismatch.

The anchor runs unconditionally at the start of every composite command that touches chain state (`verify-chain`, `balance-trustless`, `nonce-trustless`, `verify-and-submit`). No code path inside `light/trustless_read.cpp` proceeds past this gate without success.

### 3.2 Committee-signature verification

**Function.** `determ::light::verify_block_sigs` at `light/verify.cpp:190-283`.

**Inputs.**

- `header_in` — a single block header JSON (from `rpc_headers`).
- `committee_json` — a JSON committee shape `{members: [{domain, ed_pub}, ...]}` keyed by registered domain.
- `bft_mode` — MD (full K) vs BFT (`ceil(2K/3)` with sentinel-zero slots allowed) signature threshold.

**Procedure.**

1. Strip-or-pad the header into `Block::from_json` consumable shape (`pad_stripped_header` at `light/verify.cpp:63-69` injects empty arrays for the heavy fields `transactions`, `cross_shard_receipts`, `inbound_receipts`, `initial_state` — none of which participate in `compute_block_digest`).
2. Parse the committee JSON into a `domain → PubKey` map.
3. Confirm every entry in `b.creators` is present in the supplied committee.
4. Confirm `b.creator_block_sigs.size() == b.creators.size()`.
5. Compute the per-block digest via `light_compute_block_digest` at `light/verify.cpp:47-61` — a byte-for-byte copy of `src/node/producer.cpp::compute_block_digest` (lines 577-591) with a "keep in sync" comment header.
6. For each `i ∈ [0, k)`: if the signature is the 64-byte zero sentinel, require `bft_mode == true` (else throw `sentinel-zero signature in MD mode`); else Ed25519-verify the signature against the digest under `pubkey_of[b.creators[i]]`. Any verify failure throws.
7. Enforce the threshold: `valid >= required` where `required = bft_mode ? (2k + 2) / 3 : k`.

**Output.** A `VerifyResult` with `ok=true`, `digest_hex` = the computed digest, and `state_root_hex` = the header's `state_root` if non-zero.

Pre-S-038 (block.state_root absent), the `state_root_hex` field is empty and the downstream composite reads explicitly throw with a "chain has not activated state_root" diagnostic rather than silently proceeding.

### 3.3 Header-chain continuity

**Function.** `determ::light::verify_headers` at `light/verify.cpp:104-188`.

**Inputs.**

- `headers_json` — the daemon's `rpc_headers` reply envelope.
- `genesis_hash_hex` — non-empty if the page starts at block 0.
- `prev_hash_hex` — non-empty if the page starts at block `> 0` (the anchor from the prior page).

**Procedure.**

1. Validate the leading header's `prev_hash`: zero for `index == 0`, or equal to `prev_hash_hex` for `index > 0`.
2. If page starts at block 0 and `genesis_hash_hex` is supplied, verify `headers[0].block_hash == genesis_hash_hex`.
3. Walk consecutive header pairs `headers[i]` and `headers[i-1]`. Require `headers[i].prev_hash == headers[i-1].block_hash`. Any mismatch throws.

**Output.** A `VerifyResult` with `count` and `block_hash_hex` = the page's tail block-hash (suitable as the next page's `prev_hash` anchor).

The `verify-chain` composite at `light/trustless_read.cpp:81-186` walks the chain in pages of 256 (`PAGE` constant) from block 0 to the daemon's reported tip, invoking `verify_headers` per page AND `verify_block_sigs` per block within each page.

### 3.4 Merkle state-proof verification

**Function.** `determ::light::verify_state_proof` at `light/verify.cpp:285-349`, delegating to `determ::crypto::merkle_verify` at `src/crypto/merkle.cpp`.

**Inputs.**

- `proof_json` — the daemon's `rpc_state_proof` reply with fields `{namespace, key, key_bytes, value_hash, target_index, leaf_count, proof, state_root, height}`.
- `expected_root_hex` — optional. If non-empty, verify against this root rather than `proof_json["state_root"]`. (Trustless mode supplies the locally-computed root from a verified header here.)

**Procedure.**

1. Parse the proof JSON into typed fields with `json_require<T>` helpers (S-018 validators).
2. Extract `claimed_root`, `key_bytes`, `value_hash`, `target_index`, `leaf_count`, and the sibling vector `proof`.
3. If `expected_root_hex` is supplied, replace `claimed_root` with that value (trustless mode).
4. Invoke `merkle_verify(verify_root, key_bytes, value_hash, target_index, leaf_count, sibs)`. This recomputes the Merkle path from the leaf up to a root and compares against `verify_root`.

**Output.** A `VerifyResult` with `ok=true` and `state_root_hex` = the root verified against on success; structured `detail` field describing the failure mode on rejection.

The proof verification is *self-anchoring* against the supplied root. The load-bearing step in the composite trustless-read flow at `light/trustless_read.cpp:188-350` is the OUTER one: anchor the proof's `state_root` to a *committee-signed* header, then invoke `verify_state_proof` to confirm the Merkle path actually rolls up to that root.

### 3.5 Pipeline composition diagram

The four primitives compose linearly into the per-invocation pipeline:

```
operator's --genesis <file>           operator's --rpc-port <N>
            │                                     │
            ▼                                     ▼
  ┌─────────────────────────┐           ┌────────────────────┐
  │  load_genesis()         │           │  RpcClient::call() │
  │  GenesisConfig parse    │           │  BSD-socket I/O    │
  └────────────┬────────────┘           └─────────┬──────────┘
               │                                  │
               └──────────────┬───────────────────┘
                              ▼
                  ┌─────────────────────────┐
                  │  anchor_genesis()       │  T-L1
                  │  compute_genesis_hash + │
                  │  rpc_headers (idx=0)    │
                  │  byte-equality check    │
                  └────────────┬────────────┘
                               │ ok → continue; mismatch → throw
                               ▼
                  ┌─────────────────────────┐
                  │  verify_chain_to_head() │  T-L2 + chain continuity
                  │  for each PAGE of 256:  │
                  │    verify_headers       │  (prev_hash walk)
                  │    for each block:      │
                  │      verify_block_sigs  │  (Ed25519 K-of-K)
                  └────────────┬────────────┘
                               │ ok → continue; any failure → throw
                               ▼
                  ┌─────────────────────────┐
                  │  rpc_state_proof()      │
                  │  verify_state_proof()   │  T-L3
                  │  race-window dispatch   │  T-L4 (composite)
                  │    rpc_account cleartext│
                  │    SHA256-rehash check  │
                  └────────────┬────────────┘
                               │ ok → continue; mismatch → throw
                               ▼
                       ┌───────────────┐
                       │  sign_tx()    │  T-L5 (sign + submit only)
                       │  submit_tx()  │
                       └───────────────┘
```

Each downstream stage depends on every upstream stage having passed. Any failure throws and propagates to the CLI dispatcher with a non-zero exit code and structured stderr diagnostic.

---

## 4. Security theorems

### 4.1 Theorem T-L1 (genesis-anchored chain identity)

**Statement.** Under (A2) SHA-256 collision resistance, on every invocation of any composite command (`verify-chain`, `balance-trustless`, `nonce-trustless`, `verify-and-submit`), an adversarial daemon `A_daemon` serving a chain whose genesis differs from the operator's pinned `genesis.json` cannot trick the light-client into proceeding past `anchor_genesis`.

**Adversary game.**

1. Setup. Operator pins `genesis_O` via `--genesis <file>`. Adversary controls a daemon running chain `chain_A` with genesis `genesis_A ≠ genesis_O`.
2. Light-client invokes a composite command. Internally it calls `anchor_genesis(rpc, genesis_O)`.
3. Adversary wins if the function returns success.

**Proof.**

The function computes `expected := compute_genesis_hash(genesis_O)` locally — a deterministic SHA-256 reduction over the canonical genesis-block encoding (`src/chain/genesis.cpp::make_genesis_block` → `Block::compute_hash`). The adversary's daemon, when queried via `rpc_headers from=0 count=1`, returns some JSON. Let the daemon's reported block-0 hash be `daemon_hash`.

**Case 1: daemon serves its honest `chain_A` block 0.** Then `daemon_hash = compute_genesis_hash(genesis_A)`. We need `daemon_hash = expected`, i.e., `compute_genesis_hash(genesis_A) = compute_genesis_hash(genesis_O)`. Since `genesis_A ≠ genesis_O`, the byte-encodings differ. Two distinct byte-encodings producing the same SHA-256 output is exactly the SHA-256 collision-resistance violation; under A2, the probability is `≤ 2⁻¹²⁸` per attempt.

**Case 2: daemon serves a synthesized block-0 hash equal to `expected`.** The adversary returns some `daemon_hash = expected` regardless of what `chain_A` actually contains. The check at `trustless_read.cpp:72-77` passes — but this is a transient win: every downstream step (header walk, block-sig verify, state-proof verify) is now against a chain whose block 0 hashes to `expected`. But the daemon doesn't have a block 0 that *is* `genesis_O` (it has `chain_A`). So either (a) the daemon serves block 0's actual content, in which case `daemon_hash != expected` because hash is collision-resistant — fail at the lookup phase; or (b) the daemon serves fabricated content keyed to the operator's expected hash. In case (b), the daemon must produce a chain prefix whose block 0 honestly hashes to `expected` AND whose subsequent blocks chain via `prev_hash`. But producing block 0 whose hash equals a pre-image-fixed `expected` requires solving SHA-256 preimage; under A3 + Preliminaries §2.1 (SHA-256 preimage resistance), this is `≤ 2⁻²⁵⁶`.

**Concrete-security bound.** `Pr[A_daemon wins T-L1] ≤ 2⁻¹²⁸` per invocation (the loosest of the two cases).   ∎

### 4.2 Theorem T-L2 (head trust via committee signatures)

**Statement.** Under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance + correct local maintenance of the committee map, an adversarial daemon `A_daemon` cannot present a forged block header that the light-client's `verify_block_sigs` accepts as committee-signed.

**Adversary game.**

1. Setup. Operator pins `genesis_O`. The genesis-pinned committee `K_0 := {(domain_i, pk_i)}` for the initial creators is loaded into the light-client's `committee_seed` map by `build_genesis_committee` at `trustless_read.cpp:43-50`.
2. Adversary forges a block header `H_A` claiming to be at some height `h > 0` with creators `K_A ⊂ K_0` (committee subset) and signatures `{σ_i^A : i ∈ [0, |K_A|)}`.
3. Adversary wins if `verify_block_sigs(H_A, committee_json, *)` returns `ok=true`.

**Proof.**

The verifier requires `valid >= required` signatures over `digest_A := light_compute_block_digest(H_A)` under the public keys in `committee_json`. Each accepted signature `σ_i^A` satisfies `Ed25519.Verify(pk_{K_A[i]}, digest_A, σ_i^A) = 1`. By A1 (Ed25519 EUF-CMA), producing a valid signature on any new message without the corresponding `sk_i` succeeds with probability `≤ 2⁻¹²⁸` per attempt.

The threshold `required = k` (MD) or `ceil(2k/3)` (BFT) means the adversary must forge `required` independent signatures from `required` distinct committee members. Without those members' secret keys, each forge is independent under A1. Cumulative bound: `required · 2⁻¹²⁸`. For `K ≤ 64`, this is `≤ 64 · 2⁻¹²⁸ = 2⁻¹²²`.

**Composition with FA1.** This is exactly the FA1 K-of-K safety property restricted to a single block. FA1's full-chain safety (no two finalized blocks at the same height) is not needed by the light-client per se; what the light-client uses is the *per-block* signature-set primitive that FA1 already establishes.

**Caveat: committee evolution.** The genesis-seeded committee map covers the initial creators. Mid-chain REGISTER / DEREGISTER events would shift the active committee. The current `verify_chain_to_head` requires every creator to be in the seed map (`light/verify.cpp:223-229`). For chains with mid-chain REGISTERs, the operator must pre-populate `committee_seed` with every domain that has been registered. This is documented in `light/trustless_read.hpp:71-75` as a scope limitation; chains with mid-chain registry changes need either (a) operator-provided extended committee map, (b) future stateful-sync extension. T-L2's claim holds conditional on the supplied committee map being a superset of every creator encountered on the chain.

**Concrete-security bound.** `Pr[A_daemon wins T-L2] ≤ K · 2⁻¹²⁸` per block forge attempt. Cumulative over `Q` attempts: `Q · K · 2⁻¹²⁸`.   ∎

### 4.3 Theorem T-L3 (state-proof correctness)

**Statement.** Under (A2) SHA-256 collision resistance + a committee-anchored state_root `R := state_root(h)`, an adversarial daemon `A_daemon` cannot present a forged state-proof for a value not actually committed under `R`.

> **Precise binding of `R` to the committee (mechanism note).** "Committee-anchored" here is *transitive-forward*, not a direct signature: the committee directly Ed25519-signs `compute_block_digest` (which carries `index, prev_hash, tx_root, …` but **NOT** `state_root`); `state_root(h)` is bound into `Block::signing_bytes(h)` and hence into `block_hash(h) = SHA256(signing_bytes(h) ‖ creator_block_sigs)`, and `block_hash(h) = prev_hash(h+1)` sits inside the committee-signed `digest(h+1)`. So `R = state_root(h)` is committee-certified via the *successor* block's signature — `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)`. This is the standalone sub-lemma `StateRootAnchorSoundness.md` (F6 R40) SR-1 proves; T-L4 below performs exactly this anchoring inline at `trustless_read.cpp:226-307`. **Head-block boundary:** the chain head's `state_root` has no signed successor yet, so it is committee-certified only once a successor block is produced; full nodes enforce the head's root meanwhile via the apply-layer S-033 gate (`StateRootAnchorSoundness.md` §3.4 + §6.3). T-L3 below proves the Merkle-path soundness *given* such an `R`; the committee-binding of `R` itself is T-L2 + SR-1.

**Adversary game.**

1. Setup. Light-client has anchored a committee-signed `state_root` `R` via T-L1 + T-L2 on some block at height `h`.
2. Adversary chooses a query `(namespace, key)` and returns a state-proof `P_A = (key_bytes, value_hash_A, target_index, leaf_count, proof_sibs)` where `value_hash_A` does not equal the true `value_hash` for that key under the chain's actual state at height `h`.
3. Adversary wins if `verify_state_proof(P_A, R)` returns `ok=true`.

**Proof.**

`verify_state_proof` delegates to `crypto::merkle_verify(R, key_bytes, value_hash_A, target_index, leaf_count, proof_sibs)`. The Merkle verifier recomputes the path: starting from the leaf hash `H_leaf := H(key_bytes ‖ value_hash_A)`, walking up the sibling chain to a root `R'`, and checking `R' == R`.

If the chain's actual leaf at `(namespace, key)` has `value_hash_T ≠ value_hash_A`, then `H_leaf_T := H(key_bytes ‖ value_hash_T) ≠ H_leaf` (by SHA-256 collision-resistance on the leaf input). For both `H_leaf_T` and `H_leaf` to roll up to the same root `R`, the path must "cancel out" the leaf difference at some inner node. By induction over the path: at each inner level, the recomputed left/right pair differs by exactly the propagated leaf-difference, so the next-level hash differs (collision resistance again). The differences cannot cancel without breaking A2 at the leaf, level-1, level-2, ..., level-`log₂(leaf_count)` boundary. Each level's collision-resistance violation is `≤ 2⁻¹²⁸`; the union bound gives `≤ log₂(leaf_count) · 2⁻¹²⁸` per forge attempt.

For chains with `leaf_count ≤ 2⁶⁴` (which is every practical state size), `log₂(leaf_count) ≤ 64`, so the bound is `≤ 64 · 2⁻¹²⁸ = 2⁻¹²²` per attempt.

**Composition with S-033 + S-038.** The light-client's `state_root` anchor is exactly the chain's `Block.state_root` field, which by `S033StateRootNamespaceCoverage.md` T-1 + T-4 commits to the full 10-namespace state surface and by S-038 is populated on every block produced post-S-038. T-L3 inherits T-1's namespace-coverage completeness: any account-state field the light-client can query (`a:` namespace) is in fact bound to the root.

**Concrete-security bound.** `Pr[A_daemon wins T-L3] ≤ log₂(leaf_count) · 2⁻¹²⁸` per forge attempt; `≤ 2⁻¹²²` for chains of any practical size.   ∎

### 4.4 Theorem T-L4 (balance/nonce trust via state-proof composition)

**Statement.** Under T-L1 + T-L2 + T-L3, the composite trustless-read flow `read_account_trustless` at `light/trustless_read.cpp:188-350` yields balance/next_nonce values that are bound, end-to-end, to a committee-signed `state_root` anchored to the operator's pinned genesis.

**Adversary game.**

1. Setup as T-L3. Operator pins `genesis_O`. Adversary controls the daemon serving an honest-or-malicious chain.
2. Operator invokes `read_account_trustless(rpc, committee_seed, genesis_O, domain)`.
3. Adversary attempts to return some `(balance_A, next_nonce_A)` pair that does not match the chain's actual account state at the verified height.
4. Adversary wins if the function returns those values without throwing.

**Proof sketch.**

The function chains:

1. Genesis anchor (T-L1).
2. Header-chain walk + per-block sig verify (T-L2 per block, plus prev_hash continuity).
3. State-proof fetch via `rpc_state_proof` for `(namespace="a", key=domain)`.
4. Self-anchored proof verify via `verify_state_proof(proof, {})` (i.e., against the proof's claimed root — sanity check that the proof is internally consistent).
5. **Race-window mitigation** — see §4.4.1.
6. Cleartext cross-check: fetch `rpc_account` to get `(balance, next_nonce)`, recompute `SHA256(balance_be ‖ next_nonce_be)`, confirm it equals the proof's verified `value_hash`.

Steps 1-2 establish a committee-signed anchor `R_anchor` and a height `vc.height`. Step 3 fetches a proof at some `proof_height >= vc.height` with claimed root `proof_root`. Step 5 binds `proof_root` to a committee-signed header at `proof_height - 1`. Step 6 binds the cleartext `(balance, next_nonce)` to the proof's verified leaf via hash recomputation.

The composition is sound because each step's adversarial-success bound is independent:

- T-L1 mismatch: `≤ 2⁻¹²⁸`.
- T-L2 forge per block: `≤ K · 2⁻¹²⁸`.
- T-L3 leaf forge: `≤ log₂(leaf_count) · 2⁻¹²⁸`.
- Cleartext forge: forcing `SHA256(b_A ‖ n_A) = SHA256(b_T ‖ n_T)` for distinct `(b_A, n_A) ≠ (b_T, n_T)` is a SHA-256 collision, `≤ 2⁻¹²⁸`.

Union bound over the steps: `≤ (1 + K · vc.height + log₂(leaf_count) + 1) · 2⁻¹²⁸`. For `K ≤ 64`, `vc.height ≤ 2⁶⁴`, `leaf_count ≤ 2⁶⁴`: cumulative `≤ 2⁻⁶⁰` per invocation, which is operationally negligible but documented for completeness.

#### 4.4.1 The race-window mitigation

Between the light-client fetching the head (step 2, anchoring height `vc.height`) and fetching the state-proof (step 3, returning at height `proof_height`), the actual chain has advanced. The proof carries `state_root` at `proof_height`, which is generally `≥ vc.height`. Naively comparing `proof.state_root == vc.head_state_root` would fail in the common case (chain advanced); naively trusting the proof's claimed root (no anchoring) would defeat the trust model.

The mitigation at `trustless_read.cpp:226-307` works in three branches:

1. **`proof_height < vc.height`.** This is a stale-state attack — the daemon returned an old proof from before the head the light-client just verified. Throw with `proof.height ... is BEFORE verified-chain head ... — daemon is serving stale state`.

2. **`proof_height > vc.height`.** The chain advanced during the round-trip. The mitigation:
   - Fetch the header at `anchor_index = proof_height - 1` (the header whose state_root commits to the post-apply state at proof_height blocks).
   - Compare `header[anchor_index].state_root == proof.state_root` byte-for-byte. Mismatch throws.
   - Invoke `verify_block_sigs(header[anchor_index], committee_json, false-then-true)` to confirm the committee signed that header. Failure throws.
   - Walk the prev_hash chain from `vc.height - 1` to `anchor_index` via `verify_headers` to confirm the new header chains to the previously-verified head. This catches a "forge a single committee-signed header detached from the chain" attack — the prev_hash walk forces the new tip to extend the verified prefix.

3. **`proof_height == vc.height`.** The proof's claimed root must match `vc.head_state_root` byte-for-byte. Mismatch throws.

The race-window narrative is the load-bearing part of T-L4: without the mitigation, the daemon could serve an honest `vc.head_state_root` for the head walk, then serve a state-proof at some forked future height with a different state_root, and the light-client would naively use the un-anchored future root. With the mitigation, every forked future root must (a) match a header field, (b) be signed by a known committee, (c) chain via prev_hash to the verified prefix. By T-L1 + T-L2, all three conditions defeat the daemon's lie.

**Concrete-security bound.** `Pr[A_daemon wins T-L4] ≤ (vc.height + 2) · K · 2⁻¹²⁸ + 2⁻¹²²`. For practical chains (e.g., `vc.height ≤ 2³², K ≤ 16`), this is `≤ 2⁻⁹²`, negligible.   ∎

### 4.5 Theorem T-L5 (sign-and-submit correctness)

**Statement.** Under T-L4 + (A1) Ed25519 EUF-CMA, a transaction signed by `sign_light_tx` at `light/sign_tx.cpp:64-124` and submitted via `verify-and-submit` is bound to (a) the keyfile's signing key, (b) the operator-supplied envelope fields, and (c) a verified nonce — and the daemon receiving the `submit_tx` RPC cannot mutate the transaction without breaking the signature.

**Adversary game.**

1. Setup. Operator has a keyfile `kf` with secret seed `sk_kf` and `anon_address` = `make_anon_address(pk_kf)`.
2. Operator invokes `verify-and-submit --to addr --amount A --fee F`. The flow:
   - Runs `nonce-trustless` to obtain a verified `(next_nonce, state_root)` via T-L4.
   - Builds canonical signing bytes via `compute_signing_bytes(type, kf.anon_address, addr, A, F, next_nonce)`.
   - Signs them via `crypto::sign(sk_kf, sb)` → produces 64-byte `σ_kf`.
   - Hashes them to a 32-byte `tx_hash` for the envelope's `hash` field.
   - Emits the canonical envelope and submits via `rpc_submit_tx`.
3. Adversary receives the submitted JSON and may attempt to:
   - **Mutate any field** before forwarding to the chain (e.g., redirect `to`, change `amount`, change `fee`, change `nonce`).
   - **Discard the submission** and replace with one of the adversary's choosing.
4. Adversary wins if the chain accepts and applies a transaction whose `(from, to, amount, fee, nonce, type)` differs from the operator's intent.

**Proof.**

The chain's `Transaction::signing_bytes` (at `src/chain/block.cpp::Transaction::signing_bytes`) is byte-for-byte identical to the light-client's `compute_signing_bytes` (at `light/sign_tx.cpp:37-62`). The fields covered by the signing_bytes pre-image are: `type (u8)`, `from ‖ 0x00`, `to ‖ 0x00`, `amount_u64_be`, `fee_u64_be`, `nonce_u64_be`, `payload (empty for the light-client tx types)`. The signature `σ` is over the SHA-256-compatible canonical encoding.

If the adversary mutates any of these fields before forwarding, the recipient chain (`Transaction::verify_signature` in `src/chain/block.cpp`) will recompute `signing_bytes` over the mutated envelope, get a different byte string, and `Ed25519.Verify(pk_kf, signing_bytes_mutated, σ_kf)` returns 0 (verify failure). The chain rejects the transaction. By A1 (Ed25519 EUF-CMA), the adversary cannot produce a new signature `σ_mutated` over the mutated bytes without `sk_kf`; the probability is `≤ 2⁻¹²⁸`.

The `hash` field carries `SHA256(signing_bytes)` — a redundant cross-check but not a security primitive (the signature alone is the load-bearing field). Similarly the `signature` and `sig` fields are aliases for wire-compat between the light-client envelope shape and the chain `Transaction::from_json` shape; both carry the same 128-hex string.

Composition with T-L4: the operator-supplied `nonce` came from a verified state-proof, so a malicious daemon cannot trick the operator into signing over a stale nonce that the chain would reject (or, worse, a future nonce that the chain would accept but at a different state than the operator believed). T-L4 binds `(balance, next_nonce)` to a committee-signed state_root; the operator's tx envelope is built with the verified `next_nonce`; the chain's nonce-monotonicity gate (FA-Apply-3 T-N1..T-N6) ensures the tx applies only at that specific nonce slot.

**Concrete-security bound.** `Pr[A_daemon wins T-L5] ≤ Pr[A_daemon wins T-L4] + 2⁻¹²⁸ = 2⁻⁹² + 2⁻¹²⁸ ≈ 2⁻⁹²` per invocation.   ∎

### 4.6 Supporting lemmas

**Lemma L-1 (canonical genesis encoding determinism).** `compute_genesis_hash(genesis)` is a deterministic function of the `GenesisConfig` value — two operators loading the same `genesis.json` bytes produce byte-identical hashes. Proof: `make_genesis_block(cfg)` at `src/chain/genesis.cpp` is a pure function over the parsed config struct; `Block::compute_hash()` is a SHA-256 reduction over the canonical `signing_bytes` encoding. Both layers are platform-independent (no ABI variation, no allocator-dependent ordering). Therefore the operator's locally-computed `expected` value at `light/trustless_read.cpp:55` equals every honest node's view of genesis on the same chain.   □

**Lemma L-2 (`light_compute_block_digest` byte-equivalence with the chain producer).** `light/verify.cpp:47-61` is documented as a byte-for-byte copy of `src/node/producer.cpp:577-591`. The fields hashed in both are: `index (u64)`, `prev_hash (32)`, `tx_root (32)`, `delay_seed (32)`, `consensus_mode (u8)`, `bft_proposer (32)`, then per-creator `(domain) (utf8) ‖ (tx_list domain by domain) ‖ ed_sig (64) ‖ dh_input (32)`. The two implementations are kept in sync by the "keep in sync" comment header. Any divergence would surface immediately in the `test_light_verify_block_sigs.sh` integration test which boots a real cluster and verifies a real producer-generated block. Therefore: the digest the light-client computes for a header `H` equals the digest the producer signed when it produced `H`, byte-for-byte.   □

**Lemma L-3 (Merkle inclusion soundness).** `crypto::merkle_verify(R, key_bytes, value_hash, target_index, leaf_count, sibs)` returns `true` iff there exists a leaf at position `target_index` in a `leaf_count`-sized balanced binary Merkle tree whose root is `R` and whose `(key_bytes, value_hash)` pair hashes to that leaf. Proof: by induction over the path. At level 0, the leaf hash is `H(key_bytes ‖ value_hash)`. At level `i + 1`, the inner hash is computed from the level-`i` hash and the supplied sibling (left or right depending on the target_index bit). After `ceil(log₂(leaf_count))` steps, the function compares the root against `R`. If `value_hash` differs from the true leaf value at that position, the level-0 hash differs; by A2 (collision resistance) the difference cascades up the tree with probability `1 - 2⁻¹²⁸` per level. Cumulative bound across the tree: `1 - log₂(leaf_count) · 2⁻¹²⁸`. The verifier returns `false` (rejects) on a forged inclusion claim with overwhelming probability.   □

**Lemma L-4 (cleartext-vs-value_hash cross-check binds the daemon's `account` reply).** The composite trustless-read flow at `trustless_read.cpp:309-343` fetches `rpc_account` for the same `domain`, extracts `(balance, next_nonce)`, computes `SHA256(balance_be ‖ next_nonce_be)`, and compares against the proof's verified `value_hash`. Proof: the chain's apply layer at `chain.cpp:285-290` emits the `a:`-namespace leaf with exactly this value-hash encoding (`value_hash = SHA256(balance_u64 ‖ next_nonce_u64)` per `S033StateRootNamespaceCoverage.md` §2.1). For the daemon to lie about `(balance, next_nonce)` while serving an honest proof for the chain's actual state, it would need `(balance_A, next_nonce_A) ≠ (balance_T, next_nonce_T)` with `SHA256(balance_A ‖ next_nonce_A) = SHA256(balance_T ‖ next_nonce_T)` — a SHA-256 collision, `≤ 2⁻¹²⁸` per attempt. Alternatively, the daemon could serve an honest cleartext and a forged proof for some other state; the proof forge is caught by L-3 + the committee-signed anchor.   □

**Lemma L-5 (race-window mitigation soundness).** The three-branch dispatch at `trustless_read.cpp:226-307` for `proof_height < / == / > vc.height` is sound under T-L1 + T-L2: every accepted proof is bound to a committee-signed header that extends the verified prefix.

Proof by case:

- **`proof_height < vc.height`.** Rejected unconditionally at `:237-242`. No proof is accepted with this property.

- **`proof_height == vc.height`.** The proof's `state_root` must equal `vc.head_state_root` byte-for-byte at `:302-307`. Since `vc.head_state_root` was extracted from a committee-signed header at height `vc.height - 1` (the head's index is `vc.height - 1`), any divergence is a daemon lie caught at the byte-equality check. By L-2 (digest binding) + T-L2 (committee-sig binding), the daemon cannot serve a different `state_root` claim at this height without breaking A1.

- **`proof_height > vc.height`.** The dispatch at `:243-301` runs four sub-checks:
  1. Fetch `header[anchor_index]` where `anchor_index = proof_height - 1`. Trust this header's content only after the next three steps.
  2. Compare `header[anchor_index].state_root == proof.state_root` byte-for-byte (`:269-275`). Mismatch throws.
  3. Run `verify_block_sigs(header[anchor_index], committee_json, false-then-true)` (`:277-285`). Failure throws. This binds the daemon to a committee-signed claim about the `(state_root, prev_hash, ...)` content of `header[anchor_index]`.
  4. Walk the prev_hash chain from `vc.height - 1` to `anchor_index` via `verify_headers` (`:289-298`). Failure throws. This binds the new header to the previously-verified chain.
  
  By T-L2, step 3 requires the daemon to present a header whose committee actually signed it under their Ed25519 keys; without those keys, infeasible. By the prev_hash continuity in step 4 (which uses A2 SHA-256 collision resistance on each `prev_hash`-link verification), the new header must extend the verified chain prefix rather than fork off some unrelated chain. Combined, any accepted proof binds to a committee-attested state on the operator's pinned chain.   □

**Lemma L-6 (fail-closed exit).** The light-client's verification surfaces never silently downgrade to "trust the daemon." Every failure path in `light/verify.cpp` and `light/trustless_read.cpp` either returns a `VerifyResult` with `ok=false` (consumed by the caller, which throws) or directly throws. The composite read flows at `light/trustless_read.cpp` re-throw any caller-level failure to the CLI dispatcher in `light/main.cpp`, which converts to a non-zero exit code with a structured stderr diagnostic. Proof: inspection of the verify functions — `verify_headers` (`:104-188`) sets `r.ok = false` and `r.detail` on every error branch and returns to the caller which throws; `verify_block_sigs` (`:190-283`) does the same; `verify_state_proof` (`:285-349`) does the same; `read_account_trustless` (`:188-350`) throws on every inconsistency it detects (lines 64, 72, 91, 132, 141, 156, 167, 202, 213, 222, 237, 263, 270, 281, 294, 303, 317, 334). No silent-accept code path exists.   □

---

## 5. Composition with FA-series theorems

### 5.1 FA1 (Safety) — K-of-K signature-set safety per block

The light-client's `verify_block_sigs` invokes the exact same `Ed25519.Verify` primitive that FA1 reduces to (FA1 §3, FA1 T-1). FA1 establishes per-height block-set safety (at most one finalized digest per height) under K-of-K committee signatures. The light-client uses the *per-block* primitive — for each header it ingests, it confirms K (or `ceil(2k/3)` in BFT) Ed25519 signatures over the computed digest, exactly the structural witness FA1 leverages.

The light-client does NOT separately re-establish FA1's full-chain claim that there cannot be two finalized blocks at the same height; it relies on the fact that the daemon's view of the chain is whatever block at each height satisfies the per-block sig check. If the daemon serves two distinct headers at the same height in two different RPC responses, the light-client's prev_hash walk would diverge — and the second response's prev_hash chain would not connect to the first's verified prefix, so the light-client would throw on the chain-continuity gate.

**Composition statement.** T-L2 = "FA1 per-block primitive applied at the light-client side." No new claim beyond FA1 is asserted.

### 5.2 FA2 (Censorship) — light-client does NOT extend censorship resistance

The light-client connects to one daemon. If that daemon refuses to serve specific transactions or headers (e.g., dropping `rpc_headers` for blocks past a certain height, or refusing `rpc_state_proof` for a specific account), the light-client experiences this as a network-layer failure or a malformed RPC response. The light-client's defense is to **fail-closed exit** rather than silently accept partial data.

FA2's censorship-resistance property is a *consensus-layer* property: it states that the K-of-K union-tx-root construction prevents any sub-quorum subset of the committee from excluding an honest mempool transaction. FA2 holds for the chain regardless of whether a particular light-client can see the chain — the K-of-K committee enforces inclusion at the production step.

The light-client's exposure to censorship is therefore an *availability* issue (daemon refuses to serve), not a *soundness* issue (light-client could be tricked). The "medium tier" scope explicitly declined multi-peer redundancy (the future "stateful sync client" tier), so a censoring daemon is detectable by the light-client only via fail-closed exit — not by cross-checking against a second source.

**Composition statement.** T-L4 + T-L5 inherit FA2's censorship-resistance property *as a chain property*; the light-client does not weaken FA2, but it also does not extend it to defend against single-daemon availability attacks. See §6.2 below for the limitation.

### 5.3 FA3 (Selective-Abort) — light-client inherits randomness binding

Both `light_compute_block_digest` (the light-client's local copy of `compute_block_digest`) AND the chain-side digest cover the per-creator `dh_inputs` (the Phase-1 commits `c_i := SHA256(s_i ‖ pk_i)`). FA3 establishes that no committee member can bias the randomness output `R(B) := SHA256(delay_seed ‖ s_1 ‖ ... ‖ s_K)` because each member is committed to `s_i` via `c_i` before any reveal.

The light-client uses this transitively: if the committee-signed digest passes T-L2, then by FA3 the embedded randomness commit-reveal is binding. The light-client does not need to verify the reveal phase itself; it relies on the committee having signed only digests whose Phase-1 commits chain to a valid reveal in the broader chain.

**Composition statement.** T-L2 + T-L4 inherit FA3 transitively via the chain-side digest. The light-client does not independently re-prove FA3.

### 5.4 FA-Apply series — light-client inherits apply-determinism transitively

The chain's apply-layer invariants (FA-Apply-1 through FA-Apply-16) cover the per-namespace state-mutation soundness that S-033's state_root commits to. The light-client's `verify_state_proof` confirms a leaf is committed under the verified `state_root`; the value at that leaf reflects the chain's apply-layer state.

For example: if the light-client retrieves `(balance, next_nonce)` for account `domain` via T-L4, that value reflects the chain's `accounts_[domain]` after applying every block from genesis to `proof_height`. FA-Apply-3 (NonceMonotonicity) guarantees `next_nonce` is monotonic across blocks; FA-Apply-1 (AccountStateInvariants) guarantees `balance` is non-negative; FA-Apply-15 (MultiEventComposition) guarantees the post-apply state is consistent across heterogeneous block-event mixes.

**Composition statement.** T-L4 reads inherit the chain's apply-determinism via the state_root commitment. No new apply-layer claim is asserted by the light-client; it depends on the FA-Apply suite holding for the chain.

### 5.5 S-021 + S-033 + S-038 — chain-level state integrity

`BlockchainStateIntegrity.md` establishes that:

- S-021 wraps `chain.json` in a `{head_hash, blocks}` envelope, with head_hash recomputation at load.
- S-033 binds the full 10-namespace state surface into `Block.state_root` via Merkle reduction.
- S-038 populates `body.state_root` on every block produced by `try_finalize_round`.

The light-client benefits transitively: a daemon serving chain data has gone through S-021 load validation; the daemon's served headers carry S-038-populated state_root fields; the light-client's state-proof verification anchors against an S-033-committed state_root.

**Composition statement.** T-L3 + T-L4 depend on the chain having S-033 + S-038 active. The light-client's `read_account_trustless` explicitly throws with the diagnostic `chain has not activated state_root (S-033)` if the verified head's state_root is empty (`light/trustless_read.cpp:202-208`). This is a chain-level deployment prerequisite, not a light-client design choice.

---

## 6. Known limitations (per the chosen "medium" tier)

### 6.1 No persistence across invocations

Every CLI invocation re-anchors from genesis and re-walks the chain from block 0. There is no `~/.determ-light/state.json` caching a "last verified head + committee + state_root."

**Implication.** Cost scales with chain height per command: `verify-chain` runs in `O(height)` Ed25519 verifications. For a 100k-block chain, this is roughly 100k sig-verifies per invocation. Operators running balance queries frequently against long chains pay the verification cost each time.

**Mitigation path.** The "stateful sync client" tier (out of scope for the current binary) would cache the last verified state, only walking new blocks since the cached head. Tracked as a follow-on design item; no implementation here.

### 6.2 No multi-peer redundancy

The light-client talks to one daemon per invocation, specified by `--rpc-port <N>` (and an implicit localhost connection). If the operator wants to cross-check against a second daemon, they run the light-client a second time with a different port and compare output by hand.

**Implication.** A maliciously-stalling daemon (`A_daemon` drops requests, returns errors, or returns inconsistent slices) is detected only as an error from the light-client. The light-client cannot say "this daemon is wrong; daemon-B is right" — it can only say "this daemon failed verification at step X."

**Mitigation path.** The "stateful sync client" tier would query 2+ daemons in parallel and alert on disagreement. Operators today mitigate by running multiple invocations against different ports and visual-diffing the output.

### 6.3 No periodic poll loop

The light-client is a CLI, not a daemon. Each command exits after completing its task. There is no long-running "watch the chain and alert on regression" mode.

**Implication.** Operators who want continuous monitoring (e.g., "alert me if my balance changes unexpectedly") must wrap the light-client in their own polling logic (`cron`, `systemd timer`, etc.). The light-client provides the verification primitive; the polling discipline is the operator's responsibility.

**Mitigation path.** A future `watch-head` subcommand could ship a minimal poll loop (e.g., "every 60 seconds, fetch the head and verify it chains to the previously-verified head; alert on regression"). Such a subcommand would still be per-invocation in the sense that it has no persistent state across restarts — it would simply hold its session state in memory until SIGINT. Documented in the round-1 plan as a sibling-agent (A3) item; not in the proof's current scope.

### 6.4 No keyfile encryption

`load_light_keyfile` at `light/keyfile.cpp` accepts only plaintext keyfile shapes (canonical `{address, privkey_hex}` or alternate `{anon_address, ed_priv_hex}`). The binary does not link libsodium and therefore cannot derive AES keys via Argon2id for at-rest decryption.

**Implication.** Operators wanting passphrase-encrypted keyfiles use the wallet's `determ-wallet keyfile-create` (S-004 / S-005 closure paths) to generate the encrypted form, then materialize a plaintext shape via `determ-wallet keyfile-decrypt` and pipe it to `determ-light sign-tx`. Plaintext-on-disk window is operator-controlled.

**Trade-off.** Keeping the light-client's libsodium-free footprint reduces binary size from ~25 MB (with libsodium) to ~3-5 MB stripped. The encryption-at-rest concern lives in the wallet binary, which has the full libsodium dependency for the OPAQUE + Shamir + Argon2id surface.

### 6.5 Genesis-only committee map

The light-client builds its committee map from `genesis.json`'s `initial_creators`. Mid-chain REGISTER / DEREGISTER events would shift the active committee; the current light-client requires every encountered creator to be in the seed map.

**Implication.** Chains with mid-chain registry changes need the operator to pre-populate `committee_seed` with every domain that has been registered (e.g., via the daemon's `creators` RPC). The light-client surfaces this with `"creator '<domain>' is not in the supplied committee"` errors from `verify_block_sigs`.

**Mitigation path.** A future stateful-sync extension would track committee evolution via the chain's REGISTER / DEREGISTER + apply-layer events. Documented in `light/trustless_read.hpp:71-75` as deferred scope.

### 6.6 No RPC authentication

The light-client does not authenticate to the daemon. The daemon's RPC may be HMAC-protected (S-001 closure / `RpcAuthHmacSoundness.md`) but the light-client itself does not generate the HMAC envelope.

**Implication.** Operators running the light-client against an HMAC-protected daemon must either disable HMAC for the light-client's session or supply the HMAC secret via an out-of-band mechanism (env var, config file). The current binary does not implement the HMAC client side.

**Mitigation path.** A small extension to `RpcClient::call` to optionally emit `{"auth": hex(HMAC(secret, canonical(method, params)))}` envelopes would close this gap. Not in the current binary.

### 6.7 Transport-layer encryption

The light-client's `RpcClient` uses plaintext TCP. Eavesdropping (`A_net`) is out of scope.

**Implication.** Operators wanting transport-layer confidentiality wrap the light-client's RPC connection in TLS / SSH tunnel / WireGuard / similar at the OS level. The light-client makes no transport claims.

**Mitigation path.** Operator-level; no binary change planned.

### 6.8 No log-volume controls

The current binary writes diagnostic output to stderr unconditionally. A future operator-facing concern is log-volume tuning for batch / scripted use; today this is handled by the OS-level `2>/dev/null` or `2>>logfile` pattern the operator's wrapper applies.

**Implication.** Light-client is a CLI; consumers typically pipe-and-parse, so verbose diagnostics on stderr are fine.

**Mitigation path.** Not a soundness concern.

---

## 7. Findings register

This section records discoveries from writing the proof that the operator or future maintainers should be aware of.

### F-1 Committee map seeded only from `initial_creators`

**Surface.** `light/trustless_read.cpp:43-50` (`build_genesis_committee`) populates the seed map exclusively from `cfg.initial_creators`. Mid-chain registry changes (REGISTER / DEREGISTER on the chain proper) are not threaded into the seed map at runtime.

**Soundness impact.** T-L2 holds conditional on the seed map being a superset of every encountered creator. If the operator's chain has post-genesis REGISTERs, the operator must pre-populate the committee_seed map (e.g., by hand-editing the JSON consumed by `build_genesis_committee`, or via a future operator-side helper).

**Mitigation.** The existing diagnostic at `light/verify.cpp:223-229` produces `"creator '<domain>' is not in the supplied committee"` — clean fail-closed exit. Operators on chains with REGISTERs need the committee-map hand-extension pattern. A future stateful-sync extension would track committee evolution chain-side.

### F-2 No defense against stale-state lies within the genesis-seed committee

**Surface.** If a committee member's Ed25519 key is compromised, the adversary can serve old (genuine) state-proofs that the light-client correctly verifies but that no longer reflect the current chain state. The light-client treats verified-past-state as authoritative.

**Soundness impact.** T-L4 is per-invocation. Within an invocation, the race-window mitigation (§4.4.1) catches state advancement during the round-trip. But across invocations, the operator might query "balance now" twice and get two old answers from a stale committee key. Each individual query is sound; the cross-invocation correlation is operator-visible (the operator can see `height` is regressing) but not automatically detected.

**Mitigation.** Committee key compromise is an FA6 EquivocationEvent path on the chain side; the light-client benefits from the chain's slashing-based recovery. The chip task for this would be a `watch-head` subcommand (§6.3) that alerts on head regression.

### F-3 Empty committee JSON is rejected by `parse_committee` but not before genesis anchor

**Surface.** `parse_committee` at `light/verify.cpp:98-100` throws on empty committee. If the operator's `genesis.json` lacks `initial_creators` entirely, the seed map is empty, and `verify_block_sigs` rejects the first non-genesis block.

**Soundness impact.** Fail-closed; clean.

**Mitigation.** None needed. Documented for future maintainers — the `parse_committee` check defends downstream operations.

### F-4 No defense against truncated chain claims by the daemon

**Surface.** If the daemon advertises a head height lower than the chain's actual tip (a "I lost some blocks" lie), the light-client walks up to the daemon's claimed head and exits. The operator may not notice missing tail blocks.

**Soundness impact.** T-L1 + T-L2 still hold for what the light-client walks. The omission is an *availability* lie, not a *data* lie.

**Mitigation.** Operator-visible (the `height` field in the output). Cross-invocation comparison or multi-peer query (out-of-scope per §6.2) would surface the truncation.

### F-5 Cleartext-cross-check assumes daemon doesn't lie about `rpc_account` independently of `rpc_state_proof`

**Surface.** `read_account_trustless` step 6 fetches `rpc_account` for `(balance, next_nonce)` cleartext, then hashes and compares to `proof.value_hash`. The cross-check works because both responses must agree.

**Soundness impact.** L-4 establishes this: if the daemon lies about either, the hash check catches it. The probability of a colluding-lie that produces matching hashes is `≤ 2⁻¹²⁸` (SHA-256 second-preimage on the value-hash encoding).

**Mitigation.** None needed; the cross-check is the defense.

---

## 8. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Function | File:lines | Role |
|---|---|---|---|
| T-L1 | `anchor_genesis` | `light/trustless_read.cpp:52-79` | Compute `compute_genesis_hash(genesis_O)` locally, fetch block 0, compare. |
| T-L1 | `compute_genesis_hash` | `src/chain/genesis.cpp:429-432` | `make_genesis_block(cfg).compute_hash()`. |
| T-L1 | `make_genesis_block` | `src/chain/genesis.cpp::make_genesis_block` | Canonical genesis-block encoder. |
| T-L2 | `verify_block_sigs` | `light/verify.cpp:190-283` | Per-block Ed25519 sig set verify. |
| T-L2 | `light_compute_block_digest` | `light/verify.cpp:47-61` | Byte-for-byte copy of `producer.cpp::compute_block_digest`. |
| T-L2 | `verify_chain_to_head` | `light/trustless_read.cpp:81-186` | Per-page header walk + per-block sig verify, end-to-end. |
| T-L2 | `pad_stripped_header` | `light/verify.cpp:63-69` | Inject empty arrays for heavy fields that don't participate in digest. |
| T-L2 | `parse_committee` | `light/verify.cpp:71-102` | Build domain → PubKey map from genesis JSON. |
| T-L2 | `build_genesis_committee` | `light/trustless_read.cpp:43-50` | Seed the committee map from genesis `initial_creators`. |
| T-L3 | `verify_state_proof` | `light/verify.cpp:285-349` | Wrapper over `merkle_verify` with json parsing. |
| T-L3 | `merkle_verify` | `src/crypto/merkle.cpp` | Recompute path from leaf to root, compare. |
| T-L4 | `read_account_trustless` | `light/trustless_read.cpp:188-350` | Full composite: anchor → walk → state-proof → race-window mitigation → cleartext cross-check. |
| T-L4 race-window | `read_account_trustless` race branches | `light/trustless_read.cpp:226-307` | The three-branch handling for `proof_height < / == / > vc.height`. |
| T-L4 cleartext cross-check | `read_account_trustless` value-hash recompute | `light/trustless_read.cpp:309-343` | `SHA256(balance_be ‖ nonce_be) == proof.value_hash` byte-equality. |
| T-L5 | `sign_light_tx` | `light/sign_tx.cpp:64-124` | Build envelope, sign via OpenSSL Ed25519, emit JSON. |
| T-L5 | `compute_signing_bytes` | `light/sign_tx.cpp:37-62` | Byte-for-byte copy of `Transaction::signing_bytes`. |
| T-L5 | `LightKeyfile` load | `light/keyfile.cpp::load_light_keyfile` | Validate keyfile shape, derive PubKey, confirm anon_address binding. |

Integration tests (one script per theorem family):

| Test script | Theorem coverage |
|---|---|
| `tools/test_light_genesis_anchor.sh` | T-L1 — wrong `--genesis` → light-client refuses to connect. |
| `tools/test_light_verify_headers.sh` | T-L1 + chain continuity — happy path + tampered `prev_hash` → FAIL + genesis-hash anchor mismatch → FAIL. |
| `tools/test_light_verify_block_sigs.sh` | T-L2 — happy path + tampered sig → FAIL + wrong committee → FAIL. |
| `tools/test_light_verify_state_proof.sh` | T-L3 — happy path + tampered value_hash → FAIL + tampered sibling → FAIL + wrong state_root → FAIL. |
| `tools/test_light_verify_chain.sh` | T-L2 composite — all blocks since genesis verify; introduce one bad block at height N → FAIL with diagnostic pointing at N. |
| `tools/test_light_balance_trustless.sh` | T-L4 — fetch + verify + extract balance; daemon lies about balance via tampered RPC → light-client detects mismatch. |
| `tools/test_light_nonce_trustless.sh` | T-L4 — same shape, extracts `next_nonce`. |
| `tools/test_light_sign_tx.sh` | T-L5 — offline sign produces canonical envelope; verify with `determ verify-tx` cross-binary. |
| `tools/test_light_verify_and_submit.sh` | T-L4 + T-L5 — end-to-end: trustless nonce → sign → submit → confirm on-chain via second light-client verify pass. |

Nine integration tests total. All passing at the time of the f597c44 + 5e74097 commit pair.

---

## 9. Status

- **Spec.** Complete (this document).
- **Implementation.** Shipped in commits `f597c44` (initial light-client) + `5e74097` (test suite + thread docs).
- **Tests.** 9 integration tests passing under `tools/test_light_*.sh`. No FAST=1 unit tests added (the light-client surface is composite + integration, not in-process).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance), and transitively A3 (SHA-256 preimage resistance, in T-L1 case 2).
- **Adversary model.** `A_daemon` (malicious single daemon controlling RPC). Explicitly out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.
- **Composes with.** FA1 (per-block sig safety), FA2 (chain-level censorship resistance — not extended by the light-client), FA3 (selective-abort randomness binding — inherited transitively), FA-Apply suite (apply-determinism — inherited transitively via state_root), S-021 + S-033 + S-038 (state-integrity composition — chain-level prerequisite).
- **Known limitations.** Six documented in §6 (no persistence, no multi-peer, no poll loop, no keyfile encryption, genesis-only committee map, no RPC auth, no transport encryption). All operator-mitigable; none undermine the per-invocation soundness claim.
- **Concrete-security bound.** Per invocation, summed across T-L1 + T-L2 + T-L3 + T-L4 + T-L5: `≤ 2⁻⁶⁰` for chains with `height ≤ 2³²`, `K ≤ 16`, `leaf_count ≤ 2⁶⁴`. Under Grover (PQ), the bound degrades to `≤ 2⁻³⁰`, which remains operationally secure but tighter PQ-signature migration is the long-term path (Preliminaries §2.2 note).

---
