# Determ v1 Protocol Specification

This document specifies wire formats, hash inputs, and the consensus state machine at a level sufficient for an external implementer to build a compatible client. The reference implementation is in this repository; where implementation behavior diverges from this document, treat the implementation as authoritative and file an issue to reconcile.

**Status:** v1 (rev. 8 + sharding through B6.basic). Frozen for the v1 series.

## 1. Cryptographic primitives

| Primitive | Algorithm |
|---|---|
| Hash | SHA-256 (NIST FIPS 180-4). 32-byte output. |
| Signature | Ed25519 (RFC 8032). 32-byte private seed, 32-byte public key, 64-byte signature. |
| Block randomness | Commit-reveal: each committee member commits to a fresh secret in Phase 1 (`SHA256(secret ‖ pubkey)`) and reveals in Phase 2. The block's `delay_output = SHA256(delay_seed ‖ ordered_secrets)`. |

All multi-byte integers in hash inputs are encoded **big-endian**. Variable-length strings are appended raw (no length prefix) — committee members are expected to use the same string lengths because the inputs are well-typed.

## 2. Address format

Two address types coexist:

### 2.1 Registered domain
A UTF-8 string. Convention: a DNS-style name (`alice.example`, `validator1.network`). No format constraint beyond not starting with `0x` and not being all hex.

### 2.2 Anonymous bearer wallet
Key-derived. Format: `0x` + 64 lowercase hex characters (66 chars total).
```
addr = "0x" + hex(ed25519_public_key)
```

The `is_anon_address(s)` predicate in [`include/determ/types.hpp`](../include/determ/types.hpp) is canonical: `len == 66 && s[0..2] == "0x" && all hex`.

Bearer addresses **cannot** register, stake, or be selected as creators. They can only hold balance and send/receive `TRANSFER`.

## 3. Transaction format

```cpp
struct Transaction {
    TxType    type;           // 0=TRANSFER, 1=REGISTER, 2=DEREGISTER, 3=STAKE,
                              // 4=UNSTAKE, 5=REGION_CHANGE (reserved), 6=PARAM_CHANGE (§13),
                              // 7=MERGE_EVENT (§14)
    string    from;           // domain or bearer address
    string    to;             // TRANSFER only; "" otherwise
    uint64    amount;         // TRANSFER + STAKE
    uint64    fee;            // every type
    uint64    nonce;          // sequential per-account
    bytes     payload;        // type-specific (see §3.5 for REGISTER, §3.4 for TRANSFER)
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
- Sequential nonce: a tx is applied only if `tx.nonce == account.next_nonce`. Mismatched nonces are silently skipped.
- For `TRANSFER`: requires `account.balance >= amount + fee`. Sender debited `amount + fee`; receiver credited `amount`. Fee accumulates to creators.
- **Cross-shard variant:** if `shard_id_for_address(to) != my_shard`, sender is debited but `to` is **not** credited locally. A `CrossShardReceipt` is emitted instead (see §8).

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
                                                 // post-apply canonical state (accounts ∪ stakes ∪
                                                 // registrants ∪ applied_inbound_receipts ∪
                                                 // pending_param_changes ∪ merge_state). All zeros
                                                 // on pre-S-033 blocks (backward-compat shim).
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

`state_root` is a SHA-256 Merkle commitment over six namespaced state slices:

- `a:` accounts (balance + nonce)
- `s:` stakes (locked amount + unlock_height)
- `r:` registrants (pubkey + region + inactive_from)
- `b:` beacon-anchor data (per-shard)
- `k:` applied_inbound_receipts (cross-shard dedup set)
- `c:` merge_state (R7 under-quorum-merge entries)

Each slice serializes its entries in deterministic key-sorted order using a fixed-length encoding (e.g., accounts: `SHA-256(balance_le ‖ nonce_le)`). Leaves are namespace-prefixed (`"a:" + key`) and the Merkle tree is built as a binary tree with SHA-256 inner nodes (`merkle_root` helper in `src/crypto/merkle.cpp`). Empty slices contribute the empty-tree sentinel; the overall root binds all six.

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

### 5.3 BFT escalation (rev.8)
If a round accumulates `bft_escalation_threshold` (default 5) round-1 aborts at the same height AND `bft_enabled` is true AND the available pool is < K, the next round produces a `consensus_mode = BFT` block. Required signatures drop to `ceil(2K/3)`. A `bft_proposer` is deterministically chosen as `committee[proposer_idx(seed, abort_events, K)]`. The proposer must sign; up to `K - ceil(2K/3)` other positions may carry sentinel-zero signatures.

### 5.4 Abort handling
When a member's local timer fires with insufficient contributions, they sign and broadcast an `AbortClaimMsg` naming the first missing creator. **M-1 matching claims** form a quorum certificate (`AbortEvent`) that all peers can adopt to advance the round in lockstep.

## 6. Equivocation slashing (rev.8 follow-on)

An `EquivocationEvent` is proof that one Ed25519 key signed two different `block_digest`s at the same height:
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

**Validation:** `digest_a != digest_b`, `sig_a != sig_b`, `equivocator` is registered, both sigs verify.

**Apply:** when `EquivocationEvent` is baked into a finalized block, the equivocator's full staked balance is forfeited (locked → 0) and `inactive_from = block.index + 1`.

External submission: `submit_equivocation` RPC validates the two-sig proof against the equivocator's registered key, gossips for slashing, returns `{accepted, equivocator, block_index}` or `{accepted: false, reason}`.

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

| ID | Name | Direction | Payload |
|---|---|---|---|
| 0 | HELLO | initial handshake | `{domain, port, role, shard_id}` |
| 1 | BLOCK | gossip | `Block` JSON |
| 2 | TRANSACTION | gossip | `Transaction` JSON |
| 3 | BLOCK_SIG | committee | `BlockSigMsg` JSON |
| 4 | CONTRIB | committee | `ContribMsg` JSON |
| 5 | GET_CHAIN | sync | `{from, count}` |
| 6 | CHAIN_RESPONSE | sync | `{blocks, has_more}` |
| 7 | STATUS_REQUEST | sync | `{}` |
| 8 | STATUS_RESPONSE | sync | `{height, genesis}` |
| 9 | ABORT_CLAIM | committee | `AbortClaimMsg` JSON |
| 10 | ABORT_EVENT | gossip | `{block_index, prev_hash, event}` |
| 11 | EQUIVOCATION_EVIDENCE | gossip | `EquivocationEvent` JSON |
| 12 | BEACON_HEADER | beacon→shard | `Block` JSON |
| 13 | SHARD_TIP | shard→beacon | `{shard_id, tip}` |
| 1 | BLOCK | gossip | `Block` JSON |
| 2 | TRANSACTION | gossip | `Transaction` JSON |
| 3 | BLOCK_SIG | committee | `BlockSigMsg` JSON |
| 4 | CONTRIB | committee | `ContribMsg` JSON |
| 5 | GET_CHAIN | sync | `{from, count}` |
| 6 | CHAIN_RESPONSE | sync | `{blocks, has_more}` |
| 7 | STATUS_REQUEST | sync | `{}` |
| 8 | STATUS_RESPONSE | sync | `{height, genesis}` |
| 9 | ABORT_CLAIM | committee | `AbortClaimMsg` JSON |
| 10 | ABORT_EVENT | gossip | `{block_index, prev_hash, event}` |
| 11 | EQUIVOCATION_EVIDENCE | gossip | `EquivocationEvent` JSON |
| 12 | BEACON_HEADER | beacon→shard | `Block` JSON |
| 13 | SHARD_TIP | shard→beacon | `{shard_id, tip}` |
| 14 | CROSS_SHARD_RECEIPT_BUNDLE | shard↔beacon | `{src_shard, src_block}` |
| 15 | SNAPSHOT_REQUEST | client→peer | `{headers}` |
| 16 | SNAPSHOT_RESPONSE | peer→client | snapshot JSON |

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
| `state_proof` | `{ns, key}` | `{state_root, target_index, leaf_count, value_hash, proof: [hex...]}` — SMT inclusion proof; `ns ∈ {a, s, r, b, k, c}` |
| **Tx submission** | | |
| `submit_tx` | `{tx}` | `{status: "queued", hash}`. S-028: anon-shape `tx.from` / `tx.to` MUST be lowercase canonical; non-canonical rejected with diagnostic. |
| `send` | `{to, amount, fee}` | Node-authored TRANSFER from the RPC host's domain (uses the daemon's own privkey) |
| `stake` / `unstake` | `{amount, fee}` | Node-authored stake operations |
| `register` | `{}` | Submit RegisterTx for the daemon's own domain |
| **Forensics / governance** | | |
| `submit_equivocation` | `{event}` | `{accepted, equivocator, block_index}` |
| **DApp substrate (v2.18 + v2.19)** | | |
| `dapp_list` | `{}` | All registered DApps (active + inactive within grace) |
| `dapp_info` | `{dapp_id}` | Per-DApp record (owner, service_pubkey, endpoint, topics, retention, metadata, stake, registered_at, inactive_from) |
| `dapp_messages` | `{dapp_id, from_height?}` | Paginated list of DAPP_CALL events addressed to `dapp_id`; up to 256 events per call (DAPP_MESSAGES_PAGE_LIMIT) |
| **Snapshot fetch (v2.3 / B6.basic)** | | |
| `snapshot` | `{headers}` | Full state snapshot + N tail headers for state_root verification |

`submit-param-change`, `submit-merge-event`, `submit-dapp-register`, `submit-dapp-call` are CLI verbs that construct the appropriate tx + submit via `submit_tx`; they're not separate RPC methods.

## 11. Snapshot format (B6.basic)

```json
{
  "version": 1,
  "block_index": 1234,
  "head_hash": "<hex>",
  "accounts":     [{"domain", "balance", "next_nonce"}, ...],
  "stakes":       [{"domain", "locked", "unlock_height"}, ...],
  "registrants":  [{"domain", "ed_pub", "registered_at", "active_from", "inactive_from"}, ...],
  "applied_inbound_receipts": [{"src_shard", "tx_hash"}, ...],
  "block_subsidy": 10,
  "min_stake":     1000,
  "shard_count":   1,
  "shard_salt":    "<hex>",
  "shard_id":      0,
  "headers":       [<Block JSON>, ...]   // last N blocks for chain continuity
}
```

`restore_from_snapshot` validates `head_hash` against `compute_hash()` of the tail head; rejects on mismatch.

## 12. Genesis

Genesis is block 0 with `initial_state` carrying creator/account allocations. Its hash binds the chain identity. Operators distribute the genesis JSON file; nodes compute the hash on load and refuse to start if `Config.genesis_hash` is set and doesn't match (eclipse defense).

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
6. For BEGIN: `evidence_window_start + merge_threshold_blocks ≤ block.index`.

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
