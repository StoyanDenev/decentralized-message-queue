# Determ v1 Protocol Specification

This document specifies wire formats, hash inputs, and the consensus state machine at a level sufficient for an external implementer to build a compatible client. The reference implementation is in this repository; where implementation behavior diverges from this document, treat the implementation as authoritative and file an issue to reconcile.

**Status:** v1 (rev. 8 + sharding through B6.basic) plus shipped v2 foundation. Frozen for the v1 series.

**Shipped v2 items covered here:** v2.1 state Merkle root (§4.1.1), v2.2 light-client `state_proof` RPC (§10.2), v2.3 snapshot state_root verification (§11.1), v2.4 atomic apply + COMPOSABLE_BATCH (§14.5), v2.5 registry cache (transparent), v2.6 gossip out of lock (transparent), v2.16 HMAC RPC auth (§10.1), v2.17 passphrase keyfile envelopes (§1.2), v2.18 DAPP_REGISTER (§14.5), v2.19 DAPP_CALL (§14.5), A3 binary wire codec + version negotiation (§16.1).

**v2 items NOT yet covered (not yet shipped):** v2.7 F2 view reconciliation (full S-030 D2 closure; `docs/proofs/F2-SPEC.md` is the implementation spec), v2.8 post-quantum signature migration, v2.10 threshold randomness aggregation (`plan.md` A11), v2.14 real OPAQUE wallet recovery (gates on Windows MSVC porting of upstream VLAs), v2.22-v2.24 confidential transactions + cross-chain bridge + audit hooks, v2.25-v2.26 distributed identity provider + on-chain key rotation. See `docs/V2-DESIGN.md` for the full design space.

**Security-closure interop notes covered here:**
- S-001 (RPC auth) §10.1
- S-008 (mempool bounds) — implementation-internal; no wire surface
- S-014 (rate-limit RPC + gossip) §10.1 + framing
- S-016 partial (cross-shard receipt soak) §8.1
- S-017 (UNSTAKE three-layer alignment) §3.3
- S-021 (chain.json head_hash wrap) — storage-side; no wire surface
- S-022 (per-type message caps) §9.1
- S-028 (anon address case normalization) §2.2 + §3.3
- S-029 (resolve_fork) — apply-side; no wire surface
- S-033 (state_root commitment) §4.1.1
- S-036 partial (MERGE_BEGIN bounds + leading past-bound) §14

## 1. Cryptographic primitives

### 1.1 Consensus + on-chain crypto

These two primitives + the commit-reveal randomness are the only crypto the consensus protocol relies on. An external implementation needs SHA-256 and Ed25519; nothing else.

| Primitive | Algorithm |
|---|---|
| Hash | SHA-256 (NIST FIPS 180-4). 32-byte output. |
| Signature | Ed25519 (RFC 8032). 32-byte private seed, 32-byte public key, 64-byte signature. |
| Block randomness | Commit-reveal: each committee member commits to a fresh secret in Phase 1 (`SHA256(secret ‖ pubkey)`) and reveals in Phase 2. The block's `delay_output = SHA256(delay_seed ‖ ordered_secrets)`. |

All multi-byte integers in hash inputs are encoded **big-endian**. Variable-length strings are appended raw (no length prefix) — committee members are expected to use the same string lengths because the inputs are well-typed.

### 1.2 Operational crypto (off-consensus surfaces)

Three additional primitives appear in operator-facing or wallet-side flows but never in the consensus path:

| Primitive | Algorithm | Used in |
|---|---|---|
| MAC | HMAC-SHA-256 | v2.16 / S-001 RPC authentication (§10.1) — `auth = hex(HMAC-SHA-256(secret, method ‖ "|" ‖ params_canonical_json))` |
| AEAD | AES-256-GCM | v2.17 keyfile envelopes (`account create --passphrase`); A2 wallet recovery share envelopes (§15) |
| KDF (passphrase) | PBKDF2-HMAC-SHA-256, 600 000 iterations | v2.17 keyfile envelopes; A2 wallet recovery (passphrase scheme) |
| KDF (memory-hard) | Argon2id | A2 wallet recovery OPAQUE adapter (§15; gated to v2.14 for the real `libopaque` integration) |
| OPRF group + sealed-box | Ristretto255 (libsodium) | A2 wallet recovery OPAQUE adapter; v2.18 DApp `service_pubkey` end-to-end encryption |

These are operationally important but **invisible to consensus** — none of them appear in `signing_bytes()`, `block_digest`, or any validator rule. An implementation that re-implements wallet recovery or DApp encryption against a different curve choice (e.g. P-256 sealed-box) remains consensus-compatible with the reference; only operator-facing tooling needs to match.

## 2. Address format

Two address types coexist:

### 2.1 Registered domain
A UTF-8 string. Convention: a DNS-style name (`alice.example`, `validator1.network`). No format constraint beyond not starting with `0x` and not being all hex.

### 2.2 Anonymous bearer wallet
Key-derived. Format: `0x` + 64 hex characters (66 chars total).
```
addr = "0x" + hex(ed25519_public_key)
```

**Canonical form is lowercase.** S-028 closure (`include/determ/types.hpp`) admits both cases at the RPC ingress / CLI input layer:

* `is_anon_address(s)` — case-insensitive shape check (accepts `0xABC...` and `0xabc...`).
* `normalize_anon_address(s)` — returns the lowercase canonical form for valid anon-shape inputs (domain names pass through unchanged, so RPC handlers can apply it uniformly).
* `make_anon_address(pk)` — always emits lowercase canonical form.

**Wire / storage invariant.** Every `Transaction` on the wire MUST carry the canonical lowercase form for anon-shape `from` and `to`. RPC `submit_tx` rejects non-canonical with a clear `"submitted tx.from is non-canonical (uppercase hex); anon addresses MUST be lowercase"` diagnostic — server-side normalization would invalidate the client's `signing_bytes`-bound signature, so the strict-input rule keeps store-keys unambiguous. Node-authored tx-create paths (`rpc_send`, `rpc_balance`) normalize before storage so users can paste mixed-case addresses without fragmenting balances.

Bearer addresses **cannot** register, stake, or be selected as creators. They can only hold balance and send/receive `TRANSFER`.

## 3. Transaction format

```cpp
struct Transaction {
    TxType    type;           // 0=TRANSFER, 1=REGISTER, 2=DEREGISTER, 3=STAKE,
                              // 4=UNSTAKE, 5=REGION_CHANGE (reserved — validator rejects),
                              // 6=PARAM_CHANGE (§13), 7=MERGE_EVENT (§14),
                              // 8=COMPOSABLE_BATCH (§14.5), 9=DAPP_REGISTER (§14.5),
                              // 10=DAPP_CALL (§14.5)
    string    from;           // domain or bearer address (S-028: anon-shape MUST be
                              //   lowercase canonical at the wire — submit_tx rejects
                              //   uppercase with a diagnostic; node-authored tx-create
                              //   paths normalize automatically)
    string    to;             // TRANSFER + DAPP_CALL; "" otherwise (S-028 same rule)
    uint64    amount;         // TRANSFER + STAKE + DAPP_CALL
    uint64    fee;            // every type
    uint64    nonce;          // sequential per-account
    bytes     payload;        // type-specific (see §3.5 for REGISTER, §3.4 for TRANSFER,
                              //   §13 for PARAM_CHANGE, §14 for MERGE_EVENT,
                              //   §14.5 for COMPOSABLE_BATCH / DAPP_REGISTER / DAPP_CALL)
    Signature sig;            // Ed25519 over signing_bytes()
    Hash      hash;           // = compute_hash() = SHA256(signing_bytes() || sig)
};
```

### 3.1 `signing_bytes()`
SHA-256 of the concatenation:
```
type (1 byte) || from || to || amount (u64) || fee (u64) || nonce (u64) || payload
```

The signature `sig` is `Ed25519_sign(priv_seed, signing_bytes())`.

### 3.2 `compute_hash()`
SHA-256 of `signing_bytes() || sig` (binds the signature into the hash).

### 3.3 Apply rules
- Sequential nonce: a tx is applied only if `tx.nonce == account.next_nonce`. Mismatched nonces are silently skipped (no error, but the tx is not retried — the producer would need to wait for the gap-filling tx to land first, then re-submit).
- For `TRANSFER`: requires `account.balance >= amount + fee`. Sender debited `amount + fee`; receiver credited `amount`. Fee accumulates to creators (subsidy pool path; see economics).
- **Cross-shard variant:** if `shard_id_for_address(to) != my_shard`, sender is debited but `to` is **not** credited locally. A `CrossShardReceipt` is emitted instead (see §8). The fee still accrues to the source shard's creators; the credit waits on receipt admission at the destination.
- For `REGISTER`: requires `balance >= fee`. Charges `fee`; inserts/updates `registrants_[tx.from]` with the payload's `ed_pub` + `region` (R1) + `registered_at = height`. New entries get `active_from = height + derive_delay(b.cumulative_rand, tx.hash)` (anti-grind randomized activation window — see S-010); re-registrations preserve `active_from` and refresh only the pubkey/region. `inactive_from = UINT64_MAX` (active). E1 NEF fires once on first-time registration of `tx.from`.
- For `DEREGISTER`: charges `fee` (no payload). Computes `inactive_from = height + derive_delay(b.cumulative_rand, tx.hash)` — same randomized delay window as REGISTER's `active_from` (S-024: bounds the grind to a 1–10-block window; formally accepted in v1.x). Sets the registry entry's `inactive_from` to that value. If the domain has a stake, the stake's `unlock_height = inactive_from + unstake_delay_` so the staked balance unlocks `unstake_delay_` blocks after deactivation completes. Nonce consumed regardless of stake / registry state.
- For `STAKE`: requires `balance >= amount + fee`. Sender debited `amount + fee`; `stakes_[tx.from].locked` grows by `amount`. The `unlock_height` is set to `UINT64_MAX` (still staked). Suspended validators (`inactive_from <= height`, or pending suspension from FA6 slash) skip committee selection regardless of stake.
- For `UNSTAKE` (S-017 closure): validator + producer + chain layer all enforce `b.index >= chain.stake_unlock_height(tx.from)`. Pre-fix the chain layer was the only gate (with fee refund on too-early); post-fix the validator rejects too-early UNSTAKE at the block-validation layer, the producer skips it during `build_body` assembly, and the chain layer keeps the fee-refund as belt-and-suspenders. Successful UNSTAKE: `stakes_[tx.from].locked -= amount`, sender balance credited by `amount`; the stake entry stays even at `locked == 0` (the entry is treated as "no stake" by the registry-build path).

S-028 case-normalization rules apply at the RPC ingress layer (see §10.2 `submit_tx`); the on-wire `Transaction` always carries the canonical lowercase form for anon-shape `from` / `to`.

### 3.4 TRANSFER payload (general-purpose tokenization slot)

`TRANSFER` MAY carry an optional `payload` of up to **128 bytes** (constant `TRANSFER_PAYLOAD_MAX` in `chain/params.hpp`). Empty payload (the historical default) is unchanged and byte-identical on the wire. A payload larger than 128 bytes is rejected by the validator with the error message `TRANSFER payload exceeds 128-byte cap (got <N> bytes)`.

**Protocol guarantees (integrity only):**
- The payload bytes are part of `signing_bytes()` (§3.1) and are therefore covered by the sender's Ed25519 signature.
- The tx hash binds the payload (`compute_hash()` is taken over `signing_bytes() || sig`), so the block hash transitively binds it.
- The chain stores the payload verbatim in the tx record; it is retrievable via `show-tx`.
- The payload does not affect balances, fees, nonces, or the supply invariant (§A1). It is opaque to the apply path.

**Protocol non-guarantees (semantics are application-level):**
- The protocol does not parse, validate, or interpret the payload bytes. Two applications using the same payload schema can interoperate; conflicts between independent application schemas at the same byte are an application-layer concern.
- There is no on-chain registry of payload schemas or tag namespaces.

**Recommended encodings (non-normative).** Applications choose any encoding that fits within 128 bytes. Common options:

| Encoding | When to use | Trade-off |
|----------|-------------|-----------|
| **Raw bytes** | Single fixed-purpose deployment (one app). | Simplest. Zero overhead. No room for future extension. |
| **Fixed-prefix tagging** (e.g. 1–4 byte ASCII tag + payload) | Multi-application coexistence on the same chain. | One byte of namespace separation. Compact. Easy to grep. Recommended default. |
| **CBOR** ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) | Structured records (object pointers, Ricardian-contract refs, indexed memos). Pairs with downstream features (e.g. A8 directory entries). | Self-describing, deterministic encoding profile available, broad library support. Best general-purpose choice for the 128-byte budget — fits small structured records comfortably. |
| **MessagePack** | Same use-cases as CBOR. | Slightly more compact than CBOR for short objects; less canonical-encoding tooling. |
| **JSON text** | Quick prototyping, human-readable memos. | Verbose; fits short JSON objects within 128 bytes but pricey for non-trivial structures. Discouraged for production. |
| **Encrypted payload** (e.g. `crypto_box_seal(recipient.pubkey, plaintext)`) | Confidential memos between sender and recipient. | ~48 bytes of overhead (ephemeral key + MAC); leaves ~80 bytes for plaintext. Pairs with v2.22 confidential-tx pattern. |

For multi-app interoperability, a fixed-prefix tag (e.g. the first byte being a registered application identifier, the rest being that app's encoding) is the recommended convention. The protocol enforces nothing here — it is purely a coordination mechanism between applications sharing the chain.

### 3.5 REGISTER payload

```
REGISTER payload = [pubkey: 32 bytes] [region_len: u8] [region: utf8 bytes]
```

- `pubkey`: the Ed25519 public key being registered. The tx's own `sig` (over `signing_bytes()`) is signed by the corresponding private key, serving as proof-of-possession.
- `region_len`: u8 byte counting the trailing region string. `0` means no region tag (the global pool / legacy backward-compat path).
- `region`: opaque ASCII-lowercase string, charset `[a-z0-9-_]`, at most 32 bytes. Normalized to lowercase before storage and hashing, so case-mixed payloads round-trip stable.

Legacy REGISTER payloads (32 bytes exactly, just the pubkey) are wire-compatible — the trailing `region_len` byte is absent and the validator treats it as `region_len = 0`. A REGISTER tx with `payload.size() > 32 + 1 + 32` is rejected.

The region is mirrored from the REGISTER tx into the registry. `eligible_in_region(R)` (§5.2) reads it during committee selection.

## 4. Block format

```cpp
struct Block {
    uint64                index;
    Hash                  prev_hash;
    int64                 timestamp;             // Unix seconds, ±30s window (S-003)
    Transaction[]         transactions;          // canonical (from, nonce, hash) order
    string[]              creators;              // K committee members in selection order
    Hash[][]              creator_tx_lists;      // K Phase-1 tx_hashes lists
    Signature[]           creator_ed_sigs;       // K Phase-1 commit signatures
    Hash[]                creator_dh_inputs;     // K Phase-1 commitments to per-round secrets
    Hash[]                creator_dh_secrets;    // K Phase-2 revealed secrets
    Hash                  tx_root;               // SHA256 over union of creator_tx_lists
    Hash                  delay_seed;            // SHA256(index || prev_hash || tx_root || dh_inputs...)
    Hash                  delay_output;          // SHA256(delay_seed || ordered_dh_secrets)
    Signature[]           creator_block_sigs;    // K Phase-2 block-digest sigs
    ConsensusMode         consensus_mode;        // 0=MUTUAL_DISTRUST (K-of-K), 1=BFT (ceil(2K/3))
    string                bft_proposer;          // empty unless mode==BFT
    Hash                  cumulative_rand;       // SHA256(prev.cumulative_rand || delay_output)
    AbortEvent[]          abort_events;          // claims-quorum-certified prior round aborts
    EquivocationEvent[]   equivocation_events;   // two-sig proofs against same height
    CrossShardReceipt[]   cross_shard_receipts;  // outbound (this shard → others)
    CrossShardReceipt[]   inbound_receipts;      // inbound (other shards → this shard)
    GenesisAlloc[]        initial_state;         // genesis only (index == 0)
    Hash                  state_root;            // v2.1 / S-033: SHA-256 Merkle commitment to the
                                                 // post-apply canonical state. See §4.1.1 for the
                                                 // full ten-namespace leaf set (a/s/r/d/i/b/m/p/k/c).
                                                 // All zeros on pre-S-033 blocks (backward-compat
                                                 // shim — signing_bytes binds the field only when
                                                 // non-zero, see §4.1).
};
```

### 4.1 `signing_bytes()`
SHA-256 of, in order:
```
index (u64)
prev_hash
timestamp (i64)
SHA256(concat(tx.signing_bytes() for tx in transactions))
creators[i] for i in 0..K
creator_tx_lists[i][j] for i, j
creator_ed_sigs[i] (64 bytes) for i
creator_dh_inputs[i] for i
creator_dh_secrets[i] for i
tx_root
delay_seed
delay_output
consensus_mode (1 byte)
bft_proposer
cumulative_rand
abort_events[i].event_hash for i
equivocation_events[i].(equivocator, block_index, digest_a, sig_a, digest_b, sig_b, shard_id, beacon_anchor_height) for i
cross_shard_receipts[i].(src_shard, dst_shard, src_block_index, src_block_hash, tx_hash, from, to, amount, fee, nonce) for i
inbound_receipts[i].(src_shard, dst_shard, src_block_index, tx_hash, to, amount) for i  // narrower binding
initial_state[i].(domain, ed_pub, balance, stake) for i  // genesis only
state_root (32 bytes) — bound only when non-zero (S-033 conditional binding: pre-S-033 blocks have zero state_root, preserving byte-identical signing_bytes for backward compat; post-S-033 blocks contribute the field unconditionally).
```

### 4.1.1 `state_root` algorithm (v2.1 / S-033)

`state_root` is a SHA-256 Merkle commitment over ten namespaced state slices. Every leaf is the pair `(namespaced_key_bytes, value_hash)`; leaves are sorted by `namespaced_key_bytes` (lexicographic over raw bytes) before Merkle assembly. Namespace prefixes domain-separate the maps so a same-string key appearing in two maps (e.g., a `domain` that is both an account holder and a registrant) produces two distinct leaves.

| Prefix | Source map | Key suffix | Value hash inputs |
|---|---|---|---|
| `a:` | `accounts_`                  | `domain` (utf8)                   | `balance_u64 ‖ next_nonce_u64` |
| `s:` | `stakes_`                    | `domain` (utf8)                   | `locked_u64 ‖ unlock_height_u64` |
| `r:` | `registrants_`               | `domain` (utf8)                   | `ed_pub(32) ‖ registered_at_u64 ‖ active_from_u64 ‖ inactive_from_u64 ‖ region_len_u64 ‖ region_bytes` |
| `d:` | `dapp_registry_` (v2.18)     | `domain` (utf8)                   | `service_pubkey(32) ‖ registered_at_u64 ‖ active_from_u64 ‖ inactive_from_u64 ‖ endpoint_url ‖ topics[] ‖ retention_u64 ‖ metadata` (length-prefixed) |
| `i:` | `applied_inbound_receipts_`  | `src_shard_be8 ‖ tx_hash(32)`     | `0x01` (presence marker) |
| `b:` | `abort_records_` (S-032)     | `domain` (utf8)                   | `count_u64 ‖ last_block_u64` |
| `m:` | `merge_state_` (R7)          | `shard_id_be4`                    | `partner_id_u64 ‖ refugee_region_len_u64 ‖ refugee_region_bytes` |
| `p:` | `pending_param_changes_`     | `eff_height_be8 ‖ idx_be4`        | `name_len_u64 ‖ name ‖ value_len_u64 ‖ value_bytes` |
| `k:` | genesis-pinned constants     | fixed name (`block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, `lottery_jackpot_multiplier`, `min_stake`, `suspension_slash`, `unstake_delay`, `shard_salt`, ...) | constant-specific (mostly a single `u64`) |
| `c:` | A1 unitary-balance counters  | fixed name (`genesis_total`, `accumulated_subsidy`, `accumulated_slashed`, `accumulated_inbound`, `accumulated_outbound`) | `value_u64` |

`be8` = 8-byte big-endian, `be4` = 4-byte big-endian; SHA-256 builder appends multi-byte integers in big-endian (`crypto::SHA256Builder::append(uint64_t)` etc.). The Merkle tree itself is a balanced binary tree with SHA-256 inner nodes (`merkle_root` helper in `src/crypto/merkle.cpp`). Empty slices contribute no leaves; if the entire leaf vector is empty the root is the empty-tree sentinel `Hash{}`.

The canonical reference is `src/chain/chain.cpp::build_state_leaves`; light-client `state_proof` (v2.2) and `compute_state_root` share this function so inclusion proofs verify against any block's stored `state_root` without re-deriving the leaf-encoding scheme.

Validators recompute `state_root` after `apply_transactions` and reject blocks whose stored `state_root` doesn't match the recomputed value. Snapshot restore performs the same check against the tail head's stored `state_root`. Inclusion proofs against `state_root` are exposed via the `state_proof` RPC (v2.2) — light clients query any node and verify the returned sibling-hash path locally.

See `docs/V2-DESIGN.md` v2.1 + v2.3 for the full design rationale; `docs/SECURITY.md` S-033 for the audit-closure path.

### 4.2 `compute_hash()`
SHA-256 of `signing_bytes() || creator_block_sigs[0] || ... || creator_block_sigs[K-1]`.

This binds creator signatures into the hash so signature equivocation produces a different block hash.

### 4.3 `block_digest` (what creators sign in Phase 2)
SHA-256 over `index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators[], creator_tx_lists[][], creator_ed_sigs[], creator_dh_inputs[]`. **Excludes** `delay_output` and `creator_dh_secrets` so committee members can sign immediately at Phase-2 entry without waiting for the K revealed secrets to gather. The final `delay_output` and `creator_dh_secrets` are bound into the block hash via `signing_bytes()` (§4.1).

## 5. Consensus protocol

### 5.1 Two phases per block

**Phase 1: Contrib + DhInput.** Each committee member generates a fresh 32-byte secret `s_i`, computes the commitment `dh_input = SHA256(s_i ‖ pubkey_i)`, and broadcasts a `ContribMsg`:
```cpp
struct ContribMsg {
    uint64    block_index;
    string    signer;
    Hash      prev_hash;
    uint64    aborts_gen;     // # of abort_events seen at this height
    Hash[]    tx_hashes;      // sorted ascending unique
    Hash      dh_input;       // SHA256(secret || pubkey) — Phase-1 commitment
    Signature ed_sig;         // Ed25519 over make_contrib_commitment(...)
};
```

`make_contrib_commitment(index, prev_hash, tx_hashes, dh_input)`:
```
inner_root = SHA256(concat(tx_hashes))
commit     = SHA256(index (u64) || prev_hash || inner_root || dh_input)
```

**Phase 2: BlockSig.** Once K Phase-1 messages have arrived (sealing the dh_input commitments), each member computes the placeholder `delay_seed = SHA256(index ‖ prev_hash ‖ tx_root ‖ ordered_dh_inputs)`, signs `compute_block_digest(...)`, and broadcasts:
```cpp
struct BlockSigMsg {
    uint64    block_index;
    string    signer;
    Hash      delay_output;   // SHA256(delay_seed) at this stage
    Hash      dh_secret;      // the 32-byte secret revealed (Phase-2 reveal)
    Signature ed_sig;         // Ed25519 over compute_block_digest(...)
};
```

Each receiver verifies that `SHA256(dh_secret ‖ signer.pubkey) == dh_input`. Once K reveals gather, the block's final `delay_output = SHA256(delay_seed ‖ ordered_dh_secrets)` is computed and the block can be finalized. A block is final when **K of K** members have published valid `BlockSigMsg` (MD mode) or **ceil(2K/3) of K** have (BFT mode after escalation).

### 5.2 Committee selection
At each round, the K-committee derives from:
```
epoch_index   = block_index / epoch_blocks
epoch_rand    = chain.cumulative_rand at the block opening this epoch
seed          = epoch_committee_seed(epoch_rand, shard_id)
              = SHA256(epoch_rand || "shard-committee" || shard_id (u64))
rand          = seed, then mixed with each abort_event in order:
              = SHA256(prev_rand || abort_event.event_hash)
pool          = eligible_in_region(chain.committee_region)
indices       = select_m_creators(rand, |pool|, K)
committee[i]  = pool[indices[i]]
```

`pool` is the list of registered+active+staked-≥-min_stake-not-suspended validators, sorted by domain string, then filtered by region. `eligible_in_region(R)` returns:
- The full eligible pool when `R == ""` (default — global committee, used by `ShardingMode::NONE` and `CURRENT`).
- Only validators whose registered `region` matches `R` when `R != ""` (used by `ShardingMode::EXTENDED` per-shard).

Region matching is exact-string after ASCII-lowercase normalization. The chain's `committee_region` is pinned in `GenesisConfig` and bound into the genesis hash, so two shards with the same `shard_id` but different region claims have distinct chain identities. Validators with no region tag (`region == ""`) are eligible only for chains whose `committee_region == ""`.

### 5.2.1 `select_m_creators` — hybrid algorithm (S-020 closure)

`select_m_creators(seed, N, K)` returns K distinct indices in `[0, N)` deterministically from `seed`. The reference implementation switches between two strategies based on the K/N ratio (S-020 closure):

* **`2K ≤ N` (sparse pick)** — rejection sampling. Repeatedly draw `idx = hash_mod(h, N)` where `h = SHA-256(h ‖ counter)` starts at `h = seed` and increments `counter` on every draw; skip duplicates. Expected `O(K)` hashes.

* **`2K > N` (dense pick)** — partial Fisher-Yates shuffle. Initialise `indices = [0, 1, ..., N-1]`; for `i ∈ [0, K)` derive `h = SHA-256(h ‖ counter)` (counter increments per step), compute `j = i + hash_mod(h, N - i)`, swap `indices[i]` and `indices[j]`. Truncate to first K. Exactly `K` hashes; no rejection spin.

`hash_mod(h, n)` is rejection-sampled to remove bias when `n ∤ 2^64`:
```
v     = u64_from_be(h[0..8])
limit = (UINT64_MAX / n) * n
while v >= limit:
    h = SHA-256(h ‖ counter); counter++
    v = u64_from_be(h[0..8])
return v mod n
```

Both branches consume the same SHA-256-derived randomness; both are uniform over K-subsets of `[0, N)` under the random-oracle model on `seed`. The **branch choice is purely a performance optimisation** but it must match the reference exactly — both nodes' committee selection must agree for K-of-K to assemble. An external implementer building rejection sampling alone would produce different indices at `2K > N` and diverge from the reference chain.

The same algorithm appears in `select_after_abort_m` (post-abort recommittee with the first index pinned to a deterministically-shifted slot).

### 5.3 BFT escalation (rev.8)

The next round produces a `consensus_mode = BFT` block iff **all four** of the following are true at re-selection time (`src/node/node.cpp::start_new_round`, ~L760–L770):

1. `bft_enabled = true` (genesis-pinned).
2. `total_aborts >= bft_escalation_threshold` (default 5; round-1 and round-2 aborts both count toward the threshold — any abort indicates a stuck round).
3. `available_pool_size < K` — the abort-narrowed pool can no longer field a full K-of-K committee.
4. `available_pool_size >= ceil(2K/3)` — the pool is still large enough to field a BFT committee. If it falls below this floor the shard simply stalls until the next height (or until R4 under-quorum merge kicks in).

When all four hold, committee size shrinks to `k_bft = ceil(2K/3) = (2K + 2) / 3` and `required_block_sigs` drops from K to k_bft. The proposer must sign; up to `k_bft - ceil(2 · k_bft / 3) = k_bft - required` positions may carry sentinel-zero signatures (all-zero Ed25519 signature; false-positive rate ~2⁻⁵¹².)

### 5.3.1 `proposer_idx` — deterministic BFT proposer selection

`proposer_idx` (`src/node/producer.cpp:172`) returns the committee slot whose member is the designated BFT proposer for the next round:

```
proposer_idx(seed, abort_events, committee_size) :=
    if committee_size == 0: return 0
    H := SHA256(seed
              ‖ abort_events[0].event_hash
              ‖ abort_events[1].event_hash
              ‖ ...
              ‖ "bft-proposer")             // 12-byte ASCII domain separator
    v := big-endian uint64 of H[0..8]
    return v mod committee_size
```

Both the producer (`node.cpp::current_bft_proposer`) and the independent validator path (`validator.cpp::check_block_structure`) compute this identically and reject any block whose `bft_proposer` field disagrees, or whose sentinel-zero signature falls on the proposer slot.

**Inputs.**

- `seed = epoch_committee_seed(epoch_rand, shard_id)` — the same per-epoch, per-shard seed used by `select_m_creators` (the parameter is named `prev_cum_rand` inside the function for historical reasons; semantically it is the committee seed).
- `abort_events` — the same vector that mixes into committee re-selection in §5.2 (the `for ae in current_aborts_: rand = SHA256(rand ‖ ae.event_hash)` loop). Every additional abort in a stuck height changes both the committee *and* `proposer_idx`'s input, so the proposer rotates deterministically across abort retries within an epoch.
- `committee_size` — the K-of-K or k_bft size of the current round's committee.

**Modulo-bias note.** `proposer_idx` uses straight modulo (unlike `select_m_creators` in §5.2.1, which uses rejection sampling via `hash_mod`). Bias is `≤ (2⁶⁴ mod K) / 2⁶⁴`, which for any practical committee size (K ≤ 256) is bounded above by `K / 2⁶⁴ ≤ 2⁻⁵⁶`. This is negligible compared to the cryptographic security margin of the surrounding system, and proposer-slot fairness is not a consensus-safety invariant (the proposer can be anyone in the committee; the rest of BFT verification — `ceil(2K/3)` threshold — does the heavy lifting).

**Why the "bft-proposer" domain separator.** Ensures `proposer_idx`'s input domain is disjoint from the committee-selection input domain. Without the separator, `seed ‖ abort_events.event_hashes` would collide with hash inputs already produced by the §5.2 committee-rand chain, opening the door to grinding attacks that try to align proposer-index outcomes with attacker preferences. The 12-byte ASCII tag is the same construction pattern used elsewhere in the protocol (e.g., epoch_committee_seed's per-shard salt).

### 5.4 Abort handling

When a member's local timer fires with insufficient contributions, they sign and broadcast an `AbortClaimMsg` naming the first missing creator. **M-1 matching claims** form a quorum certificate (`AbortEvent`) that all peers can adopt to advance the round in lockstep.

```cpp
struct AbortClaimMsg {
    uint64    block_index;
    uint8     round;                  // 1 = CONTRIB phase abort, 2 = BLOCK_SIG phase abort
    Hash      prev_hash;
    string    missing_creator;        // first absent committee member in selection order
    string    claimer;                // this member's domain
    Signature ed_sig;                 // Ed25519 over make_abort_claim_message(...)
};
```

The Ed25519 signature covers a domain-separated commitment:
```
abort_claim_message = SHA256(block_index (u64)
                          || round (u8)
                          || prev_hash
                          || missing_creator (length-prefixed UTF-8))
```

`make_abort_claim_message(block_index, round, prev_hash, missing_creator)` in `src/crypto/random.cpp` is the canonical encoder.

```cpp
struct AbortEvent {
    uint8     round;                  // 1 or 2 (matches the underlying claims)
    string    aborting_node;          // = missing_creator from the claims
    int64     timestamp;              // first quorum claim's timestamp
    Hash      event_hash;             // SHA256(round || aborting_node || timestamp || prev_random_state)
    JSON      claims_json;            // inline array of the M-1 signed AbortClaimMsgs that quorumed
};
```

`event_hash` mixes into the next round's randomness (§5.2 committee selection's `rand = SHA256(prev_rand ‖ abort_event.event_hash)`), so different abort sequences yield different committee re-selections — this is what defeats the "cartel keeps picking the same victim" pattern (S-011 closure depends on the rotation here being unpredictable to the cartel).

Quorum semantics: `M - 1` matching claims (where `M = m_creators`, the committee size; one short of unanimity, since the aborting node won't sign a claim against themselves) is the certification threshold. Below quorum, a single claim is informational only and does not advance the round.

## 6. Equivocation slashing (rev.8 follow-on)

An `EquivocationEvent` is proof that one Ed25519 key signed two different commitments at the same height:
```cpp
struct EquivocationEvent {
    string    equivocator;
    uint64    block_index;
    Hash      digest_a, digest_b;     // distinct
    Signature sig_a, sig_b;           // both verify under equivocator's ed_pub
    uint32    shard_id;               // detection origin (rev.9 B2c.4)
    uint64    beacon_anchor_height;
};
```

**Validation (V11):** `digest_a != digest_b`, `sig_a != sig_b`, `equivocator` is registered, both sigs verify under the equivocator's registered Ed25519 key.

**Apply:** when `EquivocationEvent` is baked into a finalized block, the equivocator's full staked balance is forfeited (`locked → 0`) and `inactive_from = block.index + 1` (removed from selection on the next registry build).

### 6.1 Detection sources

The `digest_a` / `digest_b` fields are **digest-agnostic** — V11 only checks "two distinct hashes both signed by the same registered key." Two detection paths feed the same `EquivocationEvent` channel:

* **BlockSigMsg-level (rev.8).** The committee member signs `compute_block_digest(b)` of two different block bodies at the same height. Detection: `Node::apply_block_locked` cross-block check when a duplicate-height block arrives with a different `block_hash`. Both `block_digest`s + the matching `creator_block_sigs[i]` entries form the proof.

* **ContribMsg same-generation (S-006 closure).** The committee member signs `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` over two different `(tx_hashes, dh_input)` snapshots at the same `(block_index, prev_hash, aborts_gen)`. Detection: `Node::on_contrib` comparing recomputed commitments when a same-signer duplicate arrives. Both contrib commitments + the matching `ContribMsg.ed_sig` entries form the proof.

The two paths use **the same struct + the same validator + the same apply path**. An external implementer building consensus message handling MUST detect both — missing either leaves an equivocation surface unslashable. See `docs/proofs/EquivocationSlashing.md` (FA6) — the soundness proof is digest-agnostic and covers both cases simultaneously.

### 6.2 External submission

`submit_equivocation` RPC (§10.2) validates the two-sig proof against the equivocator's registered key, gossips via `EQUIVOCATION_EVIDENCE` (MsgType 11) for slashing, returns `{accepted, equivocator, block_index}` or `{accepted: false, reason}`. Anyone observing equivocation can submit — committee membership is not required.

## 7. Sharding (rev.9)

### 7.1 Roles
`ChainRole {SINGLE = 0, BEACON = 1, SHARD = 2}`. Genesis-pinned. SINGLE is the unsharded default; BEACON/SHARD activate cross-chain coordination paths. With S=1 + SINGLE the protocol is bitwise-identical to rev.8.

### 7.2 Address-to-shard routing
```
shard_id_for_address(addr, S, salt) =
    (S <= 1) ? 0 :
    let h = SHA256(salt || "shard-route" || addr) in
    big_endian_u64(h[0..8]) mod S
```

`salt` is `GenesisConfig.shard_address_salt` (32 random bytes, fixed at chain creation, present in genesis JSON).

### 7.3 Cross-chain coordination (B2c)
- **Beacon → Shard (BEACON_HEADER):** beacon nodes broadcast each newly-applied block; shards verify K-of-K against the validator pool they derive from prior verified beacon headers; store in a light header chain.
- **Shard → Beacon (SHARD_TIP):** shard nodes broadcast newly-applied blocks; beacon validates K-of-K against the shard committee it derives from its own pool + `epoch_committee_seed(beacon_rand, shard_id)`.
- **Zero-trust:** each side independently re-derives committees and verifies signatures — no implicit trust between chains.

## 8. Cross-shard receipts (B3)

When a `TRANSFER` on shard X has `shard_id_for_address(tx.to) = Y ≠ X`:

1. **Source shard X's apply** debits sender (`amount + fee`); does NOT credit `to` locally.
2. **Source producer** appends a `CrossShardReceipt` to `block.cross_shard_receipts`:
   ```cpp
   struct CrossShardReceipt {
       uint32 src_shard, dst_shard;
       uint64 src_block_index;
       Hash   src_block_hash;          // 0 in on-chain stored receipt; filled at gossip relay
       Hash   tx_hash;
       string from, to;
       uint64 amount, fee, nonce;
   };
   ```
3. **Source validator** verifies receipts match the cross-shard tx subset one-for-one.
4. **Gossip:** source emits `CROSS_SHARD_RECEIPT_BUNDLE` carrying the full source block. Beacon nodes act as a relay (re-broadcast verbatim). Destination shards filter receipts where `dst_shard == my_shard`.
5. **Destination shard Y queues** filtered receipts in `pending_inbound_receipts_` keyed by `(src_shard, tx_hash)` for dedup.
6. **Destination producer** dequeues + bakes into `block.inbound_receipts`. Only receipts not already in `chain.applied_inbound_receipts_` are included.
7. **Destination apply** credits `to` for each entry, inserts `(src_shard, tx_hash)` into `applied_inbound_receipts_`. Idempotent: replayed bundles cannot double-credit.
8. **Destination validator** checks shape + dedup: each receipt has `dst_shard == my_shard`, `src_shard != my_shard`, no in-block duplicates, not previously applied.

The destination's K-of-K signing of the block is the collective on-chain attestation that the inbound set was valid. Source K-of-K verification happens at receive time on each member.

### 8.1 S-016 partial mitigation — time-ordered admission (`CROSS_SHARD_RECEIPT_LATENCY`)

Step 6 above describes the *eligible* set for inclusion. Reference implementations also wait **`CROSS_SHARD_RECEIPT_LATENCY = 3`** destination-chain blocks between local first-observation of a receipt (via bundle gossip — step 4) and admission to a produced block. The latency gives committee members time to converge on the same eligible set; without it, momentary pool divergence under gossip-async produces different tentative blocks → K-of-K fails → round retries. The soak threshold is a producer-side behavior, not a wire-format requirement; receivers do not validate it. Alternative implementations that skip the soak are still consensus-compatible (they'll just trigger more round retries under load).

The v2.7 F2 (`docs/proofs/F2-SPEC.md`) consensus-layer closure replaces this with a strict-determinism Phase-1 intersection commitment via `ContribMsg.inbound_keys`. Until v2.7 F2 ships, the 3-block soak is the deployed partial mitigation.

## 9. Wire protocol

### 9.1 Framing
Each message is `4-byte big-endian length || JSON envelope`.

**Length caps (S-022 closure).** Framing-layer ceiling: `kMaxFrameBytes = 16 MB`. Per-message-type cap is applied after deserialize in `Peer::read_body`:
* **1 MB** — consensus chatter: CONTRIB, BLOCK_SIG, ABORT_CLAIM, ABORT_EVENT, EQUIVOCATION_EVIDENCE, HELLO, STATUS_REQUEST / STATUS_RESPONSE, TRANSACTION, GET_CHAIN, SNAPSHOT_REQUEST.
* **4 MB** — bulk payload: BLOCK, BEACON_HEADER, SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE.
* **16 MB** — bootstrap-only: SNAPSHOT_RESPONSE, CHAIN_RESPONSE.
Oversize messages close the connection. See `include/determ/net/messages.hpp::max_message_bytes` for the per-type table.

```
Envelope: { "type": uint8, "payload": <message-specific JSON> }
```

### 9.2 Message types

The full enum lives in `include/determ/net/messages.hpp::MsgType`. Every entry is a `uint8_t` discriminator. The body-size cap column lists the per-type ceiling applied by `Peer::read_body` after JSON deserialize (`include/determ/net/messages.hpp::max_message_bytes`); the framing layer enforces the global 16 MB ceiling before this check.

| ID | Name | Direction | Body cap | Payload |
|---|---|---|---|---|
| 0  | HELLO                     | initial handshake | 1 MB  | `{domain, port, role, shard_id, wire_version}` |
| 1  | BLOCK                     | gossip            | 4 MB  | `Block` JSON |
| 2  | TRANSACTION               | gossip            | 1 MB  | `Transaction` JSON |
| 3  | BLOCK_SIG                 | committee         | 1 MB  | `BlockSigMsg` JSON (Phase 2: digest sig + dh_secret) |
| 4  | CONTRIB                   | committee         | 1 MB  | `ContribMsg` JSON (Phase 1: tx_commit + dh_input + ed sig) |
| 5  | GET_CHAIN                 | sync              | 1 MB  | `{from, count}` |
| 6  | CHAIN_RESPONSE            | sync              | 16 MB | `{blocks, has_more}` (bootstrap-only) |
| 7  | STATUS_REQUEST            | sync              | 1 MB  | `{}` |
| 8  | STATUS_RESPONSE           | sync              | 1 MB  | `{height, genesis}` (peer-discovery only; role/shard_id come from HELLO) |
| 9  | ABORT_CLAIM               | committee         | 1 MB  | `AbortClaimMsg` JSON |
| 10 | ABORT_EVENT               | gossip            | 1 MB  | `{block_index, prev_hash, event}` (event carries inline signed claims) |
| 11 | EQUIVOCATION_EVIDENCE     | gossip            | 1 MB  | `EquivocationEvent` JSON |
| 12 | BEACON_HEADER             | beacon→shard      | 4 MB  | `Block` JSON (beacon block; shard verifies K-of-K from prior-verified pool) |
| 13 | SHARD_TIP                 | shard→beacon      | 4 MB  | `{shard_id, tip}` where `tip` is a full `Block` JSON |
| 14 | CROSS_SHARD_RECEIPT_BUNDLE| shard↔beacon      | 4 MB  | `{src_shard, src_block}` (full source block for independent K-of-K verify) |
| 15 | SNAPSHOT_REQUEST          | client→peer       | 1 MB  | `{headers}` |
| 16 | SNAPSHOT_RESPONSE         | peer→client       | 16 MB | serialized chain-state JSON (bootstrap-only) |

### 9.3 Role-based filter
Cross-role traffic is restricted by the receiving peer:
- `BEACON_HEADER` accepted only from BEACON peers.
- `SHARD_TIP` accepted only from SHARD peers.
- `CROSS_SHARD_RECEIPT_BUNDLE` accepted from BEACON or SHARD.
- `SNAPSHOT_REQUEST` / `SNAPSHOT_RESPONSE` accepted from any role.
- All other types: same role, same shard_id (intra-chain only).

## 10. RPC protocol

JSON-line over TCP on the configured `rpc_port`. Each line is one JSON object: `{"method": "<name>", "params": {...}}`. Response: `{"result": ..., "error": null | "<msg>"}`.

### 10.1 Authentication + rate-limit gates

Two gates run BEFORE method dispatch:

1. **Rate limit (S-014).** If `rpc_rate_per_sec > 0 && rpc_rate_burst > 0` in config, every request consumes one token from the peer-IP bucket (refilled at `rpc_rate_per_sec`/sec up to `rpc_rate_burst`). Bucket empty → `{"result": null, "error": "rate_limited"}`. Check fires **before** JSON parse + auth so rate-limited callers don't burn parse cost and don't reveal whether their auth would have succeeded.

2. **HMAC auth (v2.16 / S-001).** If `rpc_auth_secret` is set (non-empty hex), every request MUST carry an `auth` field that's `hex(HMAC-SHA-256(secret, method || "|" || params_canonical_json))`. Missing `auth` → `{"error": "auth_required: missing 'auth' field"}`. Wrong `auth` → `{"error": "auth_failed"}`. Constant-time compare against timing side-channels.

External-bind without auth (operator sets `rpc_localhost_only=false` AND leaves `rpc_auth_secret=""`) is flagged at startup with `[WARNING: external bind without HMAC auth — set rpc_auth_secret or enable rpc_localhost_only]`.

### 10.2 Methods

| Method | Params | Returns |
|---|---|---|
| **Chain / consensus queries** | | |
| `status` | `{}` | head + head_hash + role + shard_id + epoch_index + peer_count + mempool + MD/BFT counters + `next_creators` preview + **`protections`** block (every operator-tunable security flag — see CLI-REFERENCE.md) |
| `peers` | `{}` | `[address, ...]` |
| `block` | `{index}` | full block JSON or null |
| `chain_summary` | `{last_n}` | array of compact block summaries |
| `validators` | `{}` | array of pool entries |
| `committee` | `{}` | current epoch's K-of-K committee |
| **Account queries (S-028 case-normalised at input)** | | |
| `account` | `{address}` | balance + nonce + registry + stake |
| `balance` | `{domain}` | balance only (lock-free path) |
| `nonce` | `{domain}` | next expected nonce (lock-free path) |
| `stake_info` | `{domain}` | locked stake + unlock_height |
| `tx` | `{hash}` | tx + block_index + block_hash + timestamp |
| **State commitment / light-client (v2.1 + v2.2)** | | |
| `state_root` | `{}` | `{state_root: hex, height, head_hash}` — Merkle commitment readback (§4.1.1) |
| `state_proof` | `{namespace, key}` | `{state_root, key_bytes, value_hash, target_index, leaf_count, proof: [hex...], height}` — Merkle inclusion proof against `state_root`. `namespace ∈ {a, s, r, b, k, c}` (exposed subset — the full ten-namespace state tree §4.1.1 also has `d/i/m/p`, but those use composite keys and are not surfaced via this RPC in v2.2). Returns `{error: "not_found", ...}` if the key is absent (membership proofs only — non-membership proofs require an SMT migration). |
| **Tx submission** | | |
| `submit_tx` | `{tx}` | `{status: "queued", hash}`. S-028: anon-shape `tx.from` / `tx.to` MUST be lowercase canonical; non-canonical rejected with diagnostic. |
| `send` | `{to, amount, fee}` | Node-authored TRANSFER from the RPC host's domain (uses the daemon's own privkey) |
| `stake` / `unstake` | `{amount, fee}` | Node-authored stake operations |
| `register` | `{}` | Submit RegisterTx for the daemon's own domain |
| **Forensics / governance** | | |
| `submit_equivocation` | `{event}` | `{accepted, equivocator, block_index}` |
| **DApp substrate (v2.18 + v2.19)** | | |
| `dapp_list` | `{prefix?, topic?}` | All registered DApps (active + inactive within grace). Optional `prefix` filters by domain prefix; optional `topic` keeps only DApps whose registered topic list contains a match. |
| `dapp_info` | `{domain}` | Per-DApp record (`domain`, `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, `registered_at`, `active_from`, `inactive_from`). |
| `dapp_messages` | `{domain, from_height?, to_height?, topic?}` | Paginated DAPP_CALL events addressed to `domain` in `[from_height, to_height]` (zeros = chain bounds), optionally filtered by `topic`. Up to 256 events per call (`DAPP_MESSAGES_PAGE_LIMIT`). |
| **Snapshot fetch (v2.3 / B6.basic)** | | |
| `snapshot` | `{headers}` | Full state snapshot + N tail headers for state_root verification |

`submit-param-change`, `submit-merge-event`, `submit-dapp-register`, `submit-dapp-call` are CLI verbs that construct the appropriate tx + submit via `submit_tx`; they're not separate RPC methods.

## 11. Snapshot format (B6.basic)

```json
{
  "version":      1,
  "block_index":  1234,
  "head_hash":    "<hex>",

  // Mutable account / validator state
  "accounts":     [{"domain", "balance", "next_nonce"}, ...],
  "stakes":       [{"domain", "locked", "unlock_height"}, ...],
  "registrants":  [{"domain", "ed_pub", "region", "registered_at",
                    "active_from", "inactive_from"}, ...],

  // Cross-shard dedup set (B3.4 + FA7)
  "applied_inbound_receipts": [{"src_shard", "tx_hash"}, ...],

  // Genesis-pinned + governance-mutable economic parameters (A5 whitelist)
  "block_subsidy":               10,
  "subsidy_pool_initial":        0,
  "subsidy_mode":                0,        // 0 = FLAT, 1 = LOTTERY
  "lottery_jackpot_multiplier":  1,
  "min_stake":                   1000,
  "suspension_slash":            10,
  "unstake_delay":               20,

  // Sharding posture
  "shard_count": 1,
  "shard_salt":  "<hex>",
  "shard_id":    0,

  // A1 unitary-balance counters (FA11)
  "genesis_total":         <u64>,
  "accumulated_subsidy":   <u64>,
  "accumulated_slashed":   <u64>,
  "accumulated_inbound":   <u64>,
  "accumulated_outbound":  <u64>,

  // Abort + merge bookkeeping
  "abort_records": [{"domain", "count", "last_block"}, ...],
  "merge_state":   [{"shard_id", "partner_id", "refugee_region"}, ...],

  // A5 governance pending PARAM_CHANGEs (staged for effective_height)
  "pending_param_changes": [
    {"effective_height": <u64>,
     "entries": [{"name", "value": "<hex>"}, ...]}, ...
  ],

  // Chain-continuity tail headers + per-header state_root
  "headers": [<Block JSON>, ...]   // last N blocks; each carries its own
                                    // state_root (S-033)
}
```

> **Known gap (tracked).** The on-disk snapshot does **not** currently include `dapp_registry_`, even though it contributes to `state_root` via the `d:` namespace (§4.1.1). A chain with any active DApp registration cannot be restored via `restore_from_snapshot` today — the `state_root` recompute will diverge. Track-A item: add `serialize_state` / `restore_from_snapshot` emission + readback for `dapp_registry_`, plus a regression test that snapshots a DApp-active chain and restores it. The bug is latent because no current test exercises both surfaces together.

### 11.1 `restore_from_snapshot` verification

Restore performs **two** cryptographic gates before installing state:

1. **`head_hash` match** (always). Recomputes `compute_hash()` of the tail head block; rejects with `"head_hash mismatch"` on divergence.

2. **`state_root` match** (S-033 post-v2.1). After loading every map / counter / pending-entry, the receiver computes `Chain::compute_state_root()` over the restored state and compares against the tail head's stored `state_root`. Mismatch → `"state_root mismatch"` (rejects the snapshot). Pre-S-033 blocks have zero state_root and skip this gate (backward compat).

The two gates together close S-012: a tampered snapshot fails one gate or the other regardless of what the donor manufactures, because the head's compute_hash binds state_root (signing_bytes §4.1), and state_root binds the entire state Merkle (§4.1.1).

## 12. Genesis

Genesis is block 0 with `initial_state` carrying creator/account allocations. Its hash binds the chain identity. Operators distribute the genesis JSON file; nodes compute the hash on load and refuse to start if `Config.genesis_hash` is set and doesn't match (eclipse defense).

### 12.1 Schema

```json
{
  // Chain identity
  "chain_id":       "string",   // free-form, salts the genesis hash
  "shard_id":       0,          // 0 for SINGLE/BEACON; per-shard for SHARD
  "chain_role":     0,          // 0 = SINGLE, 1 = BEACON, 2 = SHARD
  "initial_shard_count": 1,     // S in the sharded deployment
  "shard_address_salt": "<hex>", // 32B; salts the address→shard hash
  "committee_region":   "",     // "" = global; else region tag

  // Consensus
  "m_creators":    3,           // committee size K (genesis-pinned)
  "k_block_sigs":  3,           // Phase-2 threshold; default = m_creators
  "bft_enabled":   true,
  "bft_escalation_threshold": 5,

  // Economics (E1/E3/E4)
  "block_subsidy":  10,
  "subsidy_pool_initial": 0,    // E4 finite-fund cap; 0 = infinite
  "subsidy_mode":   0,          // 0 = FLAT, 1 = LOTTERY
  "lottery_jackpot_multiplier": 5,  // E3 jackpot multiplier
  "zeroth_pool_initial": 0,     // E1 NEF seed (Zeroth address balance)

  // Stake / inclusion policy
  "inclusion_model": 0,         // 0 = STAKE_INCLUSION, 1 = DOMAIN_INCLUSION
  "min_stake":       1000,
  "suspension_slash": 10,
  "unstake_delay":   1000,

  // Sharding mode (genesis-pinned)
  "sharding_mode":   0,         // 0 = NONE, 1 = CURRENT, 2 = EXTENDED
  "epoch_blocks":    1000,

  // R7 under-quorum-merge thresholds (EXTENDED mode only)
  "merge_threshold_blocks":  100,  // BEGIN gate
  "revert_threshold_blocks": 200,  // END gate (2:1 hysteresis)
  "merge_grace_blocks":      10,   // effective_height minimum lead

  // A5 governance (controlled mode)
  "governance_mode":  0,        // 0 = uncontrolled, 1 = governed
  "param_keyholders": ["<hex pubkey>", ...],
  "param_threshold":  0,        // default = len(param_keyholders) = N-of-N

  // Round timer overrides (optional; defaults below)
  "tx_commit_ms":   200,
  "block_sig_ms":   200,
  "abort_claim_ms": 100,

  // Allocations
  "initial_creators": [
    {"domain":  "node1",
     "ed_pub":  "<hex>",        // 32B Ed25519 pubkey
     "initial_stake": 1000,
     "region":  ""}             // R1; empty = global pool
    , ...
  ],
  "initial_balances": [          // optional account pre-funding
    {"domain":  "<domain_or_anon_address>",
     "balance": <u64>},
    ...
  ]
}
```

### 12.2 Genesis hash

`SHA-256` over the canonical field-by-field encoding (sorted by name; the implementation walks specific fields in a fixed order). Genesis-mix appends optional fields only when non-default — pre-feature genesis files remain byte-identical with their pre-feature hash (backward compat for chains that don't use the newer parameters).

A node refusing to start on hash mismatch is the eclipse defense: a peer cannot trick a fresh node onto a fork by serving a fabricated genesis.

### 12.3 Profile presets

`determ init --profile <name>` writes a config matching one of:

| Profile | `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` | Use case |
|---|---|---|
| `cluster` | 100 / 100 / 50 | LAN (~ms-scale RTT) |
| `web` | 200 / 200 / 100 | Public-internet web profile (default) |
| `regional` | 500 / 500 / 200 | Regional / continental RTT |
| `global` | 2000 / 2000 / 1000 | Inter-continental |
| `tactical` | 40 / 40 / 20 | Sub-50ms private link |
| `single_test` | (tight) | Single-node CI/dev |
| `*_test` variants | (matching prod profile w/ smaller stakes) | CI/dev |

Profile is a config-layer concept; the genesis fields it touches are `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` (and `sharding_mode` for `tactical`/etc.). Operators can also write these fields directly in genesis without `--profile`.

## 13. Governance (A5)

Two genesis-pinned modes:

```
governance_mode: u8     // 0 = uncontrolled (default), 1 = governed
param_keyholders: [PubKey ...]
param_threshold: u32    // signature count required for PARAM_CHANGE; default = len(keyholders)
```

Genesis-hash mix appends the three fields only when non-default — pre-A5 genesis files remain byte-identical.

### `PARAM_CHANGE` tx (TxType = 6)

Canonical payload encoding:
```
[name_len: u8][name: utf8]
[value_len: u16 LE][value: bytes]
[effective_height: u64 LE]
[sig_count: u8]
sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
```

Each `(keyholder_index, ed_sig)` is an Ed25519 signature over the canonical signing message:
```
[name_len: u8][name][value_len: u16 LE][value][effective_height: u64 LE]
```

Validator gates (in order):
1. `governance_mode == 1`.
2. Payload shape parsable.
3. `name ∈ {MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY, bft_escalation_threshold, tx_commit_ms, block_sig_ms, abort_claim_ms, param_keyholders, param_threshold}`.
4. ≥ `param_threshold` distinct keyholder signatures verify.

Apply path: `Chain::stage_param_change(effective_height, name, value)` inserts into pending map. At start of every subsequent `apply_transactions(b)`, `activate_pending_params(b.index)` walks pending entries with `eff_height ≤ b.index` and writes to chain state (or fires a Node-side hook for validator-state fields).

Soundness proof: `docs/proofs/Governance.md` (FA10).

## 14. Under-quorum merge (R4)

Two genesis-pinned thresholds + a grace period:

```
merge_threshold_blocks:  u32   // default 100 — observe < 2K + no SHARD_TIP_S
revert_threshold_blocks: u32   // default 200 — 2:1 hysteresis on revert
merge_grace_blocks:      u32   // default 10  — effective_height must exceed block.index + grace
```

### `MERGE_EVENT` tx (TxType = 7)

Canonical payload (variable = 26 + region_len bytes):
```
[event_type: u8]            // 0 = MERGE_BEGIN, 1 = MERGE_END
[shard_id: u32 LE]
[partner_id: u32 LE]
[effective_height: u64 LE]
[evidence_window_start: u64 LE]
[merging_shard_region_len: u8]
[merging_shard_region: utf8 bytes]
```

Validator gates (in order):
1. `sharding_mode == EXTENDED`.
2. Payload size matches `26 + region_len`.
3. `event_type ∈ {0, 1}`, `partner_id ≠ shard_id`.
4. Region charset `[a-z0-9-_]`, ≤ 32 bytes.
5. `effective_height ≥ block.index + merge_grace_blocks`.
6. For BEGIN, two consecutive checks (S-036 partial mitigation):
   a. **Leading past-bound**: `evidence_window_start ≤ block.index`. Catches future-start windows AND prevents an integer-overflow bypass of (6b) — without this check, an attacker setting `evidence_window_start` near `UINT64_MAX` could make the sum in (6b) wrap below `block.index` and falsely pass.
   b. **Threshold-arithmetic**: `evidence_window_start + merge_threshold_blocks ≤ block.index` — ensures the observation window lies entirely in committed history.

Apply path:
- BEGIN: insert `(shard_id → {partner_id, refugee_region})` into `Chain::merge_state_` iff `partner_id == (shard_id + 1) mod shard_count_`.
- END: erase the matching entry.

Committee eligibility stress branch: when `Chain::shards_absorbed_by(my_shard)` is non-empty, producer + validator extend their eligible pool with validators tagged in each refugee region.

Authentication piggybacks on the enclosing beacon block's K-of-K signatures — no per-tx multisig. Auto-detection (beacon observes trigger condition and emits MERGE_BEGIN automatically) is a v1.1 work item; v1.x is operator-driven via `determ submit-merge-event`.

Soundness proof: `docs/proofs/UnderQuorumMerge.md` (FA9).

## 14.5 Composable batch + DApp transactions

Three additional TxTypes shipped post-rev.9 ground the atomic-apply substrate and the Theme-7 DApp surface.

### `COMPOSABLE_BATCH` tx (TxType = 8)

A4 / v2.4 — atomic execution of multiple inner transactions under one outer envelope. Either all inner txs apply or none do; the outer fee + nonce slot is consumed regardless of inner success (same model as EVM gas).

```
Payload (canonical, LE where noted):
  [inner_count: u16 LE]   # 1..MAX_COMPOSABLE_INNER (= 64)
  inner_count × Transaction   # binary_codec serialised
```

Validator constraints:
1. `inner_count ∈ [1, MAX_COMPOSABLE_INNER]`.
2. Each inner tx must validate independently (shape + sig + known sender for non-bearer types).
3. Inner txs MUST NOT themselves be `COMPOSABLE_BATCH` (flat, no recursion).
4. Inner txs MUST have `fee == 0` (outer batch pays the chain fee).

Apply semantics:
- Outer batch consumes submitter's `next_nonce` (one slot).
- Outer fee is charged to submitter regardless of inner success (block-space payment).
- Inner txs are applied in array order via `atomic_scope` (A9 Phase 2D nested-scope primitive).
- On any inner tx failure: rollback all inner mutations; outer fee still charged; outer nonce still consumed.

Use cases: bid+lock+release patterns (auctions, escrow), bundled transfers with single-fee amortisation, M-of-M parallel-approval multisig.

Test: `tools/test_composable_batch.sh` + in-process `determ test-composable-batch`.

### `DAPP_REGISTER` tx (TxType = 9)

v2.18 (Theme 7 — DApp substrate). Registers / updates / deactivates a DApp service. `tx.from` must already be a Determ registered domain.

```
Payload (canonical, LE where noted):
  [op: u8]                 # 0 = create/update, 1 = deactivate
  if op == 0:
    [service_pubkey: 32B]  # libsodium box pubkey (E2E encryption to the DApp)
    [endpoint_url_len: u8]
    [endpoint_url: utf8]   # primary discovery (https/onion/etc.)
    [topic_count: u8]      # <= MAX_DAPP_TOPICS
    topic_count × {
      [topic_len: u8]
      [topic: utf8]        # lowercase [a-z0-9._-]+, <= 64 bytes
    }
    [retention: u8]        # 0 = full, 1 = pruneable-after-K
    [metadata_len: u16 LE]
    [metadata: bytes]      # opaque, <= MAX_DAPP_METADATA
  if op == 1:
    (no further bytes — tx.from identifies the entry)
```

Apply:
- `op == 0`: inserts/updates `dapp_registry_[tx.from]`.
- `op == 1`: sets `inactive_from = current_height + DAPP_GRACE_BLOCKS` (deferred deactivation so in-flight calls finish).

The DApp registry contributes a `"d:"` namespace leaf to `state_root` (analogous to `"r:"` for registrants — see §4.1.1).

### `DAPP_CALL` tx (TxType = 10)

v2.19 (Theme 7 Phase 7.2). Authenticated message to a registered DApp. `tx.to` is the DApp's owning domain; `tx.amount` is an optional payment credited to the DApp's account (same model as TRANSFER).

```
Payload (canonical, LE where noted):
  [topic_len: u8]
  [topic: utf8]                  # routing tag; "" or in DApp's registered topics
  [ciphertext_len: u32 LE]
  [ciphertext: bytes]            # opaque to chain; <= MAX_DAPP_CALL_PAYLOAD
```

Validator constraints (v2.19):
1. `tx.to` is a currently-active DApp in `dapp_registry_`.
2. `topic == ""` OR `topic ∈ DApp.topics`.
3. `ciphertext_len` matches remaining payload bytes.
4. Total payload size ≤ `MAX_DAPP_CALL_PAYLOAD`.
5. `tx.to` not cross-shard (cross-shard DAPP_CALL is Phase 7.6; v2.19 ships single-shard only).

Apply:
- Charge `tx.fee` from sender (paid to validators).
- Debit sender by `tx.amount`, credit DApp by `tx.amount` (S-007 overflow-checked).
- Advance sender's nonce.
- Payload itself triggers NO state mutation. The message is recorded in the block stream, `tx_root` commits to it, and DApp operator nodes filter the chain for it.

Off-chain consumption: a DApp operator node reads finalised blocks (via RPC subscription or chain replay), filters `DAPP_CALL` where `tx.to == own_domain`, decrypts the payload via its `service_pubkey`, dispatches to internal handlers.

CLI: `determ submit-dapp-register`, `determ submit-dapp-call`, `determ dapp-list`, `determ dapp-info`, `determ dapp-messages` (see `docs/CLI-REFERENCE.md`).

Full design: `docs/V2-DAPP-DESIGN.md`.

### Reserved: `REGION_CHANGE` (TxType = 5)

Slot reserved for future use. v1.x validators reject any tx with this type with a "REGION_CHANGE tx type is reserved for future use" error. A future v2.X may use the slot for in-place validator region updates (today, changing a registered validator's region requires DEREGISTER + re-REGISTER).

## 15. Wallet recovery (A2)

Pure client-side feature; no chain protocol changes. The `determ-wallet` binary handles the user's Ed25519 seed offline:

```
seed → Shamir SSS (T-of-N, GF(2^8)) → per-share AEAD envelope
                                      ↑
                              keyed by passphrase (Phase 3, default)
                                      OR
                              keyed by OPAQUE adapter export_key (Phase 7)
```

Recovery setup JSON (canonical, persisted to disk):
```
{ "version": 1,
  "scheme": "shamir-aead-passphrase" | "shamir-aead-opaque-<suite>",
  "threshold": T, "share_count": N, "secret_len": 32,
  "guardian_x": [<u8>, ...],
  "envelopes": ["DWE1.<salt>.<iters>.<nonce>.<aad>.<ct>", ...],
  "opaque_records": ["<hex>", ...],   // only when scheme starts "shamir-aead-opaque-"
  "pubkey_checksum": "<sha256(ed25519_pubkey(seed))>" }
```

Envelope: AES-256-GCM, 12-byte nonce, 16-byte tag, AAD binds `DWR1‖guardian_id‖version`.

OPAQUE adapter (development stub today; **v2.14** ships the real `libopaque`-vendored adapter, gated on the Windows MSVC porting of upstream VLAs — see `wallet/PHASE6_PORTING_NOTES.md`): `register_password(pw, gid) → (record, export_key)`; `authenticate_password(pw, record, gid) → export_key`. The `export_key` becomes the AEAD password for that guardian's envelope. The `is_stub()` flag gates production use until v2.14 lands.

Soundness proof: `docs/proofs/WalletRecovery.md` (FA12). Concrete bounds for real OPAQUE (v2.14): `Q · 2^-bits_password + N · 2^-128` (rate-limited online grind only). For the stub adapter: offline-grindable, NOT for production.

### Cross-references

- [`WHITEPAPER-v1.x.md`](WHITEPAPER-v1.x.md) — standalone academic-style technical paper covering the same material at a higher level.
- [`proofs/`](proofs/README.md) — formal-verification proofs (F0 + FA1–FA12 analytic, FB1–FB4 TLA+).
- [`QUICKSTART.md`](QUICKSTART.md) — operator-facing recipes for the wire formats specified here.
- [`CLI-REFERENCE.md`](CLI-REFERENCE.md) — command-line surface for transactions described in §3.

## 16. Versioning

This document specifies v1. Backward-incompatible changes (new block fields, modified hash inputs, new message types replacing old ones) require a version bump. New optional fields with safe defaults are non-breaking.

The reference implementation tags v1 at the commit corresponding to this document's freeze.

### 16.1 Wire-version negotiation (A3 / S8)

The gossip layer supports per-pair wire-format negotiation, independent of this document's protocol version:

```
kWireVersionLegacy = 0    # JSON-over-TCP envelope (§9.1 default)
kWireVersionBinary = 1    # binary codec (src/net/binary_codec.cpp)
kWireVersionMax    = 1    # highest version this build understands
```

HELLO carries the sender's `wire_version` field:

```json
{
  "domain":       "<peer's domain>",
  "port":         <u16>,
  "role":         <u8>,           // ChainRole — 0=SINGLE, 1=BEACON, 2=SHARD
  "shard_id":     <u32>,
  "wire_version": <u8>            // sender's kWireVersionMax
}
```

On HELLO receipt, each peer sets the negotiated version for the pair to `min(local_max, remote_advertised)`. Subsequent outbound messages on that connection use the negotiated codec.

* Pre-A3 peers omit `wire_version`; the field defaults to `0` (legacy JSON) — backward compat.
* HELLO itself is **always JSON** regardless of negotiated version: both sides must parse it before any negotiation has happened, and the JSON encoding is what carries the `wire_version` advertisement in the first place.
* Binary codec falls back to JSON serialization if it cannot encode a particular message type (current binary codec covers the high-volume types; large/rare types stay JSON). Failure is silent and per-message; connection stays alive.

The negotiation is a pure bandwidth optimization. Block content + hash inputs are codec-agnostic — a block serialized JSON and re-serialized binary produces byte-identical bytes after canonicalization.

### 16.2 Protocol-version vs wire-version

| Axis | Version | Bumps when | Backward-compat policy |
|---|---|---|---|
| Protocol (this document) | v1 | Block format, hash input, validator rules change | Hard fork — new genesis identity |
| Wire-version (gossip codec) | 0 → 1 | New codec lands | Soft — old peers stay on JSON, new peers negotiate up |

The v1.x → v2.X work tracked in `docs/V2-DESIGN.md` is mostly protocol-additive (new tx types, new state fields, new optional behaviors) with backward-compat shims (e.g. `state_root` conditional binding — pre-S-033 blocks remain valid). Specific v2 items that do require a flag-day are called out per-item in V2-DESIGN.md.
