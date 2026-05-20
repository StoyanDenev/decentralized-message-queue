# Determ v2 — DApp support design

Companion to [`V2-DESIGN.md`](V2-DESIGN.md). Scopes Theme 7 (application layer): how third-party decentralized applications can use Determ as their trust anchor without requiring Determ itself to execute application logic.

**Status:** design only. No code in this document.

---

## 1. Motivation + scope

Determ is a payment + identity chain by intent. It is not a programmable platform (no smart-contract VM, no on-chain state-machine extensions). The DApp design preserves this while exposing two primitives that third-party applications need:

1. **An authenticated message queue.** Ordered, signed, replay-protected, censorship-resistant. Applications running off-chain consume the message stream and apply their own semantics.
2. **A trusted user registry.** Stable identities (domain → pubkey). The chain provides the lookup; applications enforce their own authorization on top.

**Scope (in):**
- DApp self-registration on-chain (analogous to validator registration).
- A `DAPP_CALL` tx type that carries opaque application payloads addressed to a DApp domain.
- Block-level ordering as canonical message ordering.
- RPC surface for DApp discovery and stream subscription.
- Wallet-side ergonomics for sending DApp calls.

**Scope (out):**
- On-chain DApp execution. DApp logic runs off-chain on operator-controlled nodes.
- On-chain DApp state. The chain stores only the message stream + DApp registration metadata.
- Native escrow / smart-contract primitives. Use [v2.4 `COMPOSABLE_BATCH`](../include/determ/chain/block.hpp) for atomicity between a payment and a DApp call.
- Inter-DApp transactions on-chain. DApps coordinate off-chain; Determ provides only individual-message authentication.

**Design philosophy.** Determ as protocol substrate, DApps as protocol consumers. The chain stays small and verifiable; the application ecosystem stays flexible and unconstrained.

**The zk-VM L2 special case.** A particularly powerful instance of the DApp pattern is the "God Stack" — a zero-knowledge Virtual Machine operating as a Layer 2 against Determ as L1. The L2 zk-VM runs arbitrary smart contracts off-chain, generates ZK proofs of correct execution, and submits batch commitments via DAPP_CALL or A4 TRANSFER payload. Determ provides the deterministic ordering + finality (L1 judge role); the L2 provides arbitrary computation + privacy. Together they satisfy Szabo's God Protocol (execution + computation + privacy) without requiring Determ to expand its scope. See [`V2-DESIGN.md`](V2-DESIGN.md) → "Composing with an external zk-VM — the canonical 'God Stack' pattern" for the full architecture. From Determ's perspective, the zk-VM is just another Theme 7 DApp; the pattern is fully implementable today on the existing v2.18/v2.19 substrate without protocol-side changes.

**The distributed-IdP / DSSO special case.** A second class of canonical DApp pattern is **federated single-sign-on built on the K-of-K committee as a mutual-distrust identity provider**. The framework comes from the academic literature on mutual-distrust IdP designs (PAKE-as-black-box); Determ's contribution is to map the K-of-K committee onto the operator group and substitute **T-OPAQUE** for the original-paper SRP, which yields a SIWE-class "Sign-In With Determ" flow that authenticates users against the chain without trusting any single Determ node and without exposing user passwords or recovery secrets to any committee member below the threshold. RPs (relying parties) register via the existing v2.18 DAPP_REGISTER channel; challenges and signed assertions ride the existing v2.19 DAPP_CALL rails. The flow is specified in detail in [`V2-DESIGN.md`](V2-DESIGN.md) → Theme 9 (v2.25 + v2.26). From Determ's perspective, every DSSO RP is again just a Theme 7 DApp; the protocol-side additions (Theme 9) are the threshold-PAKE primitive and the assertion token format, not new DApp infrastructure.

**The cross-deployment federation special case.** A third canonical DApp pattern is **multi-deployment coordination as an ecosystem product** rather than a protocol feature. Each Determ deployment runs its own genesis, chain_id, and committee; cross-deployment value transfer is handled by the v2.23 bridge. Federation goes beyond that: shared identity registry across deployment members, federated DSSO recognizable across the federation, cross-deployment audit aggregation, federation-level governance for member admission / dispute resolution. Earlier drafts considered this a v3 protocol feature; the cleaner answer is to deliver it at the DApp layer using v2.18 (DAPP_REGISTER for the federation coordinator DApp's identity), v2.19 (DAPP_CALL for cross-deployment messaging), v2.23 (light-client proofs to verify cross-deployment claims), and v2.25 + v2.26 (DSSO assertions co-signed at federation scope). The protocol substrate already provides everything needed. Validator portability is the one federation capability that doesn't cleanly fit the DApp layer (slashing economics are per-chain), but it lacks documented commercial demand. Full design pattern: see §14 below.

---

## 2. Conceptual model

### Actors

| Actor | Role | Has chain identity? | Runs Determ node? |
|---|---|---|---|
| **End user / wallet** | sends DApp calls, receives DApp replies | yes (anon or registered domain) | optional (can use a provider full node via RPC) |
| **DApp operator** | publishes the DApp registry entry, runs DApp logic | yes (registered domain — the DApp's identity) | optional (can be a Determ node, a full node, or just chain-RPC client) |
| **DApp validator-node** | one or more nodes that monitor the chain, execute DApp logic, expose RPC for end users | inherits DApp operator's identity | yes (subset of Determ nodes) |
| **Determ validator** | participates in block consensus | yes (registered validator) | yes (full Determ node) |

The first three roles are independent of Determ's validator role. A DApp operator does NOT need to be a Determ validator; they just need to register their DApp and run nodes that filter the chain for their messages.

### Message flow

```
End user             Determ network               DApp node
   │                       │                          │
   │  submit_tx(DAPP_CALL) │                          │
   │  to="dapp.example",   │                          │
   │  payload=<encrypted>  │                          │
   ├──────────────────────>│                          │
   │                       │  gossip + consensus      │
   │                       ├──────┐                   │
   │                       │      │ K-of-K signs      │
   │                       │<─────┘                   │
   │                       │  block N finalized       │
   │                       │ ──────────────────────-> │
   │                       │                          │  filter for to="dapp.example"
   │                       │                          │  decrypt + dispatch
   │                       │                          │  internal handler runs
   │                       │                          │
   │                       │  (optional) reply        │
   │                       │  DAPP_CALL from DApp     │
   │                       │  back to user            │
   │                       │<────────────────────────-│
```

Critical properties:
- **Authentication**: each DAPP_CALL carries an Ed25519 sig of the sender (anon or registered). DApp trusts the chain's sig-verify at validation time.
- **Ordering**: block index + intra-block tx index is canonical. Two DApp nodes monitoring the chain see messages in the same order.
- **Liveness**: the DApp's message gets included as long as ≥1 honest validator includes it (S-002 + S-030 D1 properties).
- **No execution dependency**: the chain does NOT need to know what the DApp does with the message. Payload is opaque bytes.

---

## 3. New tx types

Two new entries in `TxType`:

```cpp
enum class TxType : uint8_t {
    ...existing 0..8...,
    DAPP_REGISTER = 9,  // create / update / deactivate a DApp registry entry
    DAPP_CALL     = 10, // address a message to a registered DApp
};
```

### 3.1 `DAPP_REGISTER`

Creates, updates, or deactivates a DApp registry entry. The `tx.from` is the DApp's owning domain — must already be a registered Determ identity (via the existing `REGISTER` tx).

**Payload (canonical, LE where noted):**

```
[op: u8]               # 0 = create/update, 1 = deactivate
[service_pubkey: 32B]  # Ed25519 pubkey for E2E encryption of payloads
[endpoint_url_len: u8]
[endpoint_url: utf8]   # primary discovery — https://... or onion address
[topic_count: u8]
topic_count × {
    [topic_len: u8]
    [topic: utf8]      # supported message topics (routing tags)
}
[retention: u8]        # 0 = full (default), 1 = pruneable after K blocks
[metadata_len: u16 LE]
[metadata: utf8]       # opaque DApp-defined metadata (icon URL, description, etc.)
```

**Constraints:**
- `tx.from` must already be REGISTER'd as a Determ domain.
- `service_pubkey` cannot equal the all-zero key (Zeroth pool reservation).
- `endpoint_url` ≤ 255 bytes; charset = printable ASCII.
- Each `topic` ≤ 64 bytes; lowercase `[a-z0-9._-]+`.
- `topic_count` ≤ 32.
- `metadata` ≤ 4 KB.
- Operator must pay an anti-spam stake (see §9 Economic model).

**Apply semantics:** inserts/updates/erases the entry in `dapp_registry_` map keyed by `tx.from`. Adds to `compute_state_root` via the `"d:"` namespace (`"d:" + domain` → entry-hash).

### 3.2 `DAPP_CALL`

Carries a message to a DApp. `tx.to` is the DApp's domain (must be a current `DAPP_REGISTER` entry).

**Payload (canonical, LE where noted):**

```
[topic_len: u8]
[topic: utf8]          # optional routing tag (must match one of DApp's registered topics, or empty)
[ciphertext_len: u32 LE]
[ciphertext: bytes]    # opaque to chain; typically AEAD(service_pubkey, plaintext, nonce)
```

**Constraints:**
- `tx.to` must be a registered DApp domain (validator checks `dapp_registry_`).
- `topic` must be `""` or one of the DApp's registered topics.
- `ciphertext_len` ≤ chain-wide `MAX_DAPP_CALL_PAYLOAD` (genesis-pinned; suggested 16 KB).
- `tx.amount` may be non-zero — a DAPP_CALL can carry payment (semantically interpreted by the DApp). Producers credit the DApp domain's account on apply, same as a TRANSFER. This obviates needing a separate `COMPOSABLE_BATCH` for "pay + message" patterns.
- `tx.fee` is the regular chain fee, paid to validators.

**Apply semantics:** credits `tx.to` (DApp domain) with `tx.amount` (S-007 overflow-checked). Advances `tx.from`'s nonce. **The payload itself does not mutate any state** — it's recorded in the block stream and the block hash, but `dapp_registry_` is unchanged, no per-DApp inbox map exists on-chain.

**Cross-shard:** if `tx.to` routes to a different shard, the standard cross-shard receipt path handles the payment leg; the message payload goes with the receipt (see §10 below for the cross-shard nuance).

### 3.3 Optional v2.X.1: `DAPP_REPLY`

A specialization where `tx.from` is a registered DApp and `tx.to` is the user. Semantically a `DAPP_CALL` in the reverse direction. Could reuse `DAPP_CALL` with no special handling, but a distinct type lets validators enforce "only registered DApps can use DAPP_REPLY" for spam control.

**Recommendation:** ship `DAPP_CALL` only in v2.X.0; defer `DAPP_REPLY` until a concrete use case demands it.

---

## 4. DApp registry

New private member on `Chain`:

```cpp
struct DAppEntry {
    PubKey                    service_pubkey;
    std::string               endpoint_url;
    std::vector<std::string>  topics;
    uint8_t                   retention;
    std::string               metadata;
    uint64_t                  registered_at;
    uint64_t                  active_from;
    uint64_t                  inactive_from;   // UINT64_MAX while active
};
std::map<std::string, DAppEntry> dapp_registry_;
```

Mirror of the existing `registrants_` registry, with DApp-specific fields. Lifecycle:
- `DAPP_REGISTER` with `op=0` and new domain → insert
- `DAPP_REGISTER` with `op=0` and existing domain → update (re-version + clear `inactive_from`)
- `DAPP_REGISTER` with `op=1` → mark `inactive_from = current_height + GRACE_PERIOD`

Grace period (suggested: 100 blocks) prevents abrupt service drop — clients see "this DApp is winding down" before its endpoint goes silent. After `inactive_from`, the entry is preserved for history but DApps cannot accept new DAPP_CALL txs (validator rejects).

**State commitment:** integrate with `build_state_leaves`. New leaf encoding:

```
"d:" + domain         → SHA-256(canonical_serialize(DAppEntry))
```

Where `canonical_serialize` is (matches the actual shipped encoding in
`src/chain/chain.cpp::build_state_leaves`'s `d:` branch; canonical
spec at PROTOCOL.md §4.1.1):
```
service_pubkey || u64_be(registered_at) || u64_be(active_from) || u64_be(inactive_from)
  || u64_be(endpoint_url.size()) || endpoint_url
  || u64_be(topics.size()) || (each: u64_be(topic.size()) || topic)
  || u64_be(retention)          // u8 on the wire / in DAppEntry, but
                                // SHA256Builder::append(uint64_t) writes
                                // it big-endian when feeding the state-
                                // root value hash (chain.cpp:324)
  || u64_be(metadata.size()) || metadata
```

Light clients prove DApp registration via `state_proof` RPC. The `d:`
namespace exposure shipped via the state_proof RPC extension (commit
`36b759d`); the broader v2.2 primitive itself was already in place
before the v2.18 DApp substrate landed.

---

## 5. Apply-path semantics

### What changes in `apply_transactions`

Two new switch cases in the tx-type dispatcher:

```cpp
case TxType::DAPP_REGISTER: {
    if (!charge_fee(sender, tx.fee)) continue;
    auto op = decode_dapp_register(tx.payload);
    if (!op) { sender.next_nonce++; break; }
    __ensure_dapp_registry();  // lazy snapshot (Phase 2A/2B pattern)
    apply_dapp_register(tx.from, *op, b.index);
    sender.next_nonce++;
    break;
}
case TxType::DAPP_CALL: {
    if (!charge_fee(sender, tx.fee)) continue;
    // Credit recipient DApp's account (same as TRANSFER's credit leg).
    if (!is_cross_shard(tx.to)) {
        auto& rcv = accounts_[tx.to].balance;
        if (!checked_add_u64(rcv, tx.amount, &rcv))
            throw std::runtime_error("S-007: DAPP_CALL credit overflow");
    } else {
        // Cross-shard path: receipt carries amount + payload to destination
        block_outbound += tx.amount;
    }
    sender.balance -= tx.amount;
    // Payload itself: NO state mutation. Just sits in the block.
    sender.next_nonce++;
    break;
}
```

### What does NOT happen on apply

- No per-DApp inbox map. DApp message history is the chain's block history, filtered by `to == dapp_domain`.
- No DApp-state mutation. Each DApp interprets its message stream however it wants, off-chain.
- No payload validation. Chain treats payload as opaque bytes (subject only to the size cap).

### Concurrency interaction

`dapp_registry_` is mutated by `DAPP_REGISTER` apply. Add to the Phase 2A/2B lazy-snapshot machinery — most blocks have no DApp registration, so the snapshot stays nullopt.

Lock-free reader path (Phase 2C extension): include `dapp_registry_` in the `CommittedStateBundle` so clients can query DApp info via the existing lock-free pattern. ~10 LOC, mechanical.

---

## 6. RPC surface

New RPC methods (in `Node`):

| Method | Args | Returns |
|---|---|---|
| `dapp_info(domain)` | string | `{service_pubkey, endpoint_url, topics, retention, metadata, active_from, inactive_from, height}` or `{error: "not_found"}` |
| `dapp_list(prefix?, topic?, page?)` | optional filters | array of DApp summaries |
| `dapp_messages(domain, from_height?, to_height?, topic?)` | filter args | array of DAPP_CALL txs matching, optionally paginated |
| `dapp_subscribe(domain, topic?)` | live stream args | streaming connection (newline-JSON over the existing RPC socket) emitting DAPP_CALL txs as blocks finalize |

The first three are stateless read-only queries (use the lock-free reader path). `dapp_subscribe` is the only stateful addition — requires the existing async-save worker pattern to also broadcast finalized-block events to subscribed sockets.

**Light-client path:** `dapp_info(domain)` returns the DApp registration; pair with `state_proof("d", domain)` to verify against a trusted state_root. This is the v2.2 light-client foundation extended to DApp metadata.

**Inclusion proofs for DAPP_CALL txs:** existing tx-in-block Merkle (block `tx_root`) plus the block's state_root. Light client verifies "this DAPP_CALL was actually in block N" without trusting the full node. RPC: `tx_proof(tx_hash)` (a follow-on RPC, not yet shipped).

---

## 7. Client wallet integration

Two new wallet primitives in the CLI/SDK:

```
determ dapp-call --to <dapp-domain> [--topic T] [--amount N] [--encrypt-to <pubkey>] \
                 [--from <signing-key-path>] --payload <file-or-string>
determ dapp-info --to <dapp-domain>
```

`dapp-call`:
1. Look up DApp's `service_pubkey` from the chain (lock-free RPC).
2. If `--encrypt-to` is set (or always-on for privacy-recommended profile): encrypt payload with libsodium `crypto_box_seal(service_pubkey)` (ephemeral-key + AEAD).
3. Build `DAPP_CALL` tx, sign with sender's key.
4. Submit via existing `submit_tx` RPC.

`dapp-info`: pure read query; returns the JSON from `dapp_info` RPC. Convenience wrapper.

**Payment + message bundling.** A user who wants atomic "pay for service then call" semantics can use v2.4 `COMPOSABLE_BATCH`:
```
batch = [
    TRANSFER(to=dapp, amount=N),  # service payment
    DAPP_CALL(to=dapp, payload=request),
]
```
Both apply or both roll back. DApp validator-node sees the batch as one unit. **However**, `DAPP_CALL` already carries `tx.amount` natively (§3.2), so the common "pay + call" pattern fits in ONE tx — `COMPOSABLE_BATCH` is for more complex flows (e.g., pay one DApp, call another, both atomic).

---

## 8. DApp node operation modes

DApp operators choose how tightly to integrate with Determ:

**Mode A — RPC client.** Lightest. The DApp's logic runs as a process that opens an RPC connection to a Determ full node (operator's own or a trusted public one). Uses `dapp_subscribe` to receive finalized DAPP_CALL events. Trust: relies on the chosen RPC provider to not censor or fabricate. Best for development, testnet, low-stakes apps.

**Mode B — Full node.** DApp operator runs a Determ full node. The DApp logic is a sidecar process on the same host, talking to localhost RPC (lock-free / no auth needed per S-001 localhost-only default). Trust: minimal — same as any Determ user running their own node.

**Mode C — Validator node.** DApp operator also registers as a Determ validator. Their node participates in block consensus AND filters its own DApp messages. Highest cost (stake required), highest trust minimization. Reasonable when the DApp's economics support running validator infrastructure.

**Mode D — Sharded DApp.** For high-volume DApps, the DApp logic itself shards: multiple DApp domains (`dapp-shard-0.example`, `dapp-shard-1.example`) routed by user identity hash. The chain's existing regional-sharding (R0-R6) lets each shard live on a separate Determ shard, distributing load.

**Recommendation:** ship Mode B as the documented default. Mode A as the lowest-friction onboarding. Modes C/D as ecosystem-driven.

---

## 9. Economic model

### Fees

`DAPP_REGISTER` and `DAPP_CALL` pay the regular chain `tx.fee` to validators. No DApp-specific fee schedule.

### Anti-spam stake (DApp side)

`DAPP_REGISTER` requires the DApp's owning domain to have ≥ `DAPP_MIN_STAKE` locked (genesis-pinned, suggested 10× normal `MIN_STAKE`). This bounds the rate of new DApp registrations (sybil resistance for DApp namespace squatting) and ensures DApp operators have skin in the game (slashable on misbehavior — see below).

### Anti-spam fee floor (call side)

To prevent DApp-spam attacks (flooding a DApp with `DAPP_CALL` from many anon accounts), recommend a chain-wide minimum `DAPP_CALL` fee. Cheapest fix: extend the S-008-Option-4 protocol-derived min-fee to apply specifically to `DAPP_CALL` with a higher floor (e.g., `block_subsidy / 64`). DApps can also enforce off-chain rate limits per identity (their own ACL on top of chain identities).

### Operator economics

The chain doesn't dictate how DApps charge their users. Options for DApp operators:
- Charge per `DAPP_CALL` via the tx's `amount` field — payment is atomic with the call
- Subscription model: pre-pay periodically; DApp logic tracks balance off-chain
- Free-with-Sybil-protection: rely on Determ's identity stake as cost of entry

### Slashable conditions (DApp operator)

A DApp operator's stake CAN be slashed if they violate registered claims. Proposed slashable events (v2.X.2+):
- **Endpoint dishonesty**: registered `endpoint_url` resolves to malware / DoS site. Hard to prove on-chain without an oracle; defer.
- **Service-key compromise**: operator's `service_pubkey` is published or used to decrypt third-party traffic. Provable via signed-by-the-key disclosure transaction.

For v2.X.0 (initial ship), no DApp slashing — just stake-as-bond. DApp slashing is a Theme-7-follow-on.

---

## 10. Privacy & off-chain channels

### On-chain payload privacy

`DAPP_CALL.ciphertext` is opaque to the chain. The recommended pattern:
- Encrypt with `crypto_box_seal(dapp.service_pubkey, plaintext)` (libsodium sealed-box: ephemeral key, ChaCha20-Poly1305, anonymous sender)
- Only the DApp can decrypt
- Chain validators, gossip relayers, other users see ciphertext only

For unencrypted messages (public DApps: public bulletin boards, oracles), plaintext is fine. The chain doesn't care.

### Off-chain large payloads

Block storage scales linearly with `DAPP_CALL.ciphertext.size()`. For large payloads (>1 KB), prefer the **pointer pattern**:
```
ciphertext = canonical_encode({
    storage_ref: "https://storage.example/<hash>",
    storage_hash: <SHA-256 of payload>,
    encryption_metadata: {...}
})
```

Chain commits to the hash; actual payload lives off-chain (IPFS, S3, anything content-addressed). DApp retrieves on demand and verifies hash. Recommended for media-heavy DApps (image hosting, video, model weights).

### Cross-shard DApp calls

`DAPP_CALL` to a DApp on a different shard uses the existing cross-shard receipt path:
- Source shard records outbound (debits sender + emits receipt with payload)
- Beacon relays the receipt bundle
- Destination shard credits DApp + emits an inbound DAPP_CALL "event" (logically a tx, materialized in destination's block stream)
- DApp's validator-node on the destination shard sees the event and processes

Cross-shard adds latency (`CROSS_SHARD_RECEIPT_LATENCY = 3` blocks on destination — same S-016 soak as TRANSFER) but is otherwise identical to in-shard.

**Implementation status.** Today (v2.19) cross-shard DAPP_CALL is rejected at mempool admission (`validator.cpp:914-918`) and at apply (`chain.cpp:1201-1209`). The full design — extending `CrossShardReceipt` with a `dapp_payload` carrier, threading source-emit + destination-credit-and-materialize paths, accounting against the 4 MB `CROSS_SHARD_RECEIPT_BUNDLE` cap, and coordinating activation via a `genesis_params.cross_shard_dapp_call_active_from` height pin — is **fleshed out in §11.7.2 below**. Effort: ~5-7 days; ships as v2.27 (Theme 7 — DApp cross-shard).

### Privacy caveats

- **Metadata leakage**: even with encrypted payload, the chain reveals (sender, recipient DApp, timestamp, payload size). A user's pattern of DApp interaction is on-chain forever. DApps that need stronger metadata privacy should layer mix-net / onion-routing on top.
- **Block-storage immutability**: encrypted payload commits permanent ciphertext on-chain. If the encryption is broken later (post-quantum advances on the DApp's service-key), historical messages become readable. Either use forward-secret protocols or accept this risk.

### Direct-to-DApp delivery pattern (off-chain, arbitrary messages)

The DApp registry publishes `(service_pubkey, endpoint_url)` per DApp — these are public and on-chain. A sender can use this information to bypass the chain entirely for messages that don't need on-chain integrity. The chain provides **identity + endpoint discovery**; the message itself goes directly sender → DApp over the network.

**Use cases:**

| Use case | Why off-chain |
|---|---|
| Real-time DApp interactions | Sub-block-time latency; no need for chain-grade integrity |
| Encrypted streaming media / sensor feeds | Continuous data flow that would overwhelm block storage |
| Pre-payment notification (later finalize on-chain) | Recipient prepares processing during the block round, finalizes on inclusion |
| Push notifications | DApp pushes notifications to subscriber clients |
| Bulk data transfer | Pointer pattern's underlying transport (alternative to IPFS/S3) |
| Tactical command-and-control | Drone receives instructions instantly via direct radio; verifies signature locally; finalizes audit trail on-chain later |
| Authentication challenges | OPAQUE / SRP handshake messages that shouldn't be persisted on-chain |

**Mechanism:**

1. Sender queries `dapp_info(domain)` RPC → gets `service_pubkey + endpoint_url` from the on-chain registry.
2. Sender opens a direct connection (TCP, HTTP, UDP, custom radio link — transport is sender's choice) to `endpoint_url`.
3. Sender encrypts the payload with `crypto_box_seal(service_pubkey, plaintext)` (same primitive as on-chain DAPP_CALL).
4. Sender signs the encrypted envelope with its own Ed25519 key for authentication.
5. DApp receives, verifies sender signature, decrypts payload, processes.

**Format (recommended):**

```
DirectMessage {
    version:      u8       // wire format version (start at 1)
    sender_pubkey: 32 B    // sender's Ed25519 pubkey (NOT a domain; raw key)
    timestamp:    u64      // ms since epoch; DApp rejects skew > 30s
    nonce:        16 B     // sender-chosen random; DApp dedups by (sender_pubkey, nonce)
    ciphertext:   var      // crypto_box_sealed payload (size bounded by DApp policy)
    sig:          64 B     // Ed25519 over [version || sender_pubkey || timestamp || nonce || ciphertext]
}
```

The format is **application-layer**, not protocol-mandatory. The chain provides only the identity/discovery primitives (DAPP_REGISTER); the over-the-wire format is up to the sender and DApp to agree on (recommend the above as a canonical default).

**Composability with on-chain DAPP_CALL:**

Hybrid pattern for higher-trust use cases:
1. Sender direct-messages the DApp with the payload (DApp starts processing).
2. Sender submits an on-chain `DAPP_CALL` with a hash of the direct message + minimal metadata (~32 B on-chain commitment).
3. DApp matches the inclusion to the prior direct message, treats it as finalized.
4. Sender pays the protocol fee + any DApp service fee through the on-chain DAPP_CALL credit.

This pattern gives:
- Sub-block-time DApp processing
- On-chain audit trail (commitment hash)
- On-chain payment (amount field in DAPP_CALL)
- Minimal block storage (32-byte commitment vs full payload)

**Trust model:**

- **DApp authenticity**: sender trusts the on-chain DApp registry to publish a current `endpoint_url`. The chain's K-of-K signing of REGISTER ensures the operator-controlled endpoint is what's published. Endpoint rotation requires a new DAPP_REGISTER update; sender should re-query before each session.
- **Confidentiality**: relies on `crypto_box_seal` (libsodium sealed-box, ChaCha20-Poly1305). Anonymous-sender by default; sender's signature adds authentication.
- **Replay**: nonce + timestamp + DApp-side dedup. DApps should bound a sliding nonce window (e.g., last 10k nonces per sender).
- **Spam / DoS**: DApp endpoint is publicly reachable; standard rate limiting / IP filtering / token-bucket / payment-gated processing per the DApp's policy. No protocol-level mitigation.

**When NOT to use the direct pattern:**

- High-value payments where pre-confirmation is dangerous — recipient should wait for block inclusion before acting.
- When integrity must be globally verifiable — use on-chain DAPP_CALL.
- When audit trail must be tamper-proof — use on-chain DAPP_CALL.
- When the message needs delivery to multiple DApps simultaneously — gossip-broadcast via on-chain is simpler.

**Implementation status:**

- Discovery primitives: ✅ already shipped (v2.18 DAPP_REGISTER + `dapp_info` RPC publishes `endpoint_url`).
- Streaming subscription on DApp side: ⚠️ partial (v2.20 polling shipped; full streaming pending).
- Direct-message format: **application-layer; no protocol code needed** beyond the discovery primitives.
- Reference client library: not yet — sender SDK can be written as a community contribution (~1-2 days), demonstrating the pattern with libsodium-sealed-box + Ed25519.

The pattern is **fully implementable today** with existing v2.18 + libsodium. Adding a reference sender library + DApp-side receiver library would make the pattern turnkey for new DApp developers without changing the protocol.

---

## 11. Implementation roadmap

Phased shipping plan, each phase is a single bounded commit.

**Status as of this revision:** Phases 7.1, 7.2, 7.3 shipped (v2.18 + v2.19). Phase 7.4 shipped the **polling subset** (`dapp_messages` retrospective RPC); the streaming subscription portion remains open. Phases 7.5+ are ecosystem / future work.

### Phase 7.1 — `DAPP_REGISTER` tx + on-chain DApp registry — ✅ shipped (v2.18)

- New `TxType::DAPP_REGISTER` + `DAppEntry` struct + `dapp_registry_` member on Chain
- Wire-format encode/decode helpers
- Validator: shape check + REGISTER-precondition + stake check
- Apply path: insert/update/deactivate
- Integration with `build_state_leaves` (new `"d:"` namespace leaf — note `serialize_state` gap tracked as S-037)
- Phase 2A/2B lazy-snapshot integration
- RPC: `dapp_info(domain)`, `dapp_list(prefix?, topic?)`
- Regression: `tools/test_dapp_register.sh` + in-process `determ test-dapp-register`

### Phase 7.2 — `DAPP_CALL` tx + payload routing — ✅ shipped (v2.19)

- New `TxType::DAPP_CALL` + payload encoding
- Validator: must-resolve-to-active-DApp + payload size cap + topic match
- Apply path: amount credit (TRANSFER-like) + nonce advance
- Anti-spam: chain-wide `DAPP_CALL` min-fee
- RPC: `dapp_messages(domain, from_height, to_height, topic)` — paginated retrospective query (256 events / page)
- Regression: `tools/test_dapp_call.sh` + in-process `determ test-dapp-call`
- CLI: `determ submit-dapp-call`, `determ dapp-info --domain D`, `determ dapp-messages --domain D`

### Phase 7.3 — Lock-free DApp reader path — ✅ shipped

- Extended `CommittedStateBundle` to include `dapp_registry`
- `dapp_lockfree` accessor on Chain (read path used by `rpc_dapp_info` does not require `state_mutex_`)
- ~30 LOC, mechanical — landed alongside Phase 7.1

### Phase 7.4 — Streaming subscription RPC — ⚠️ partial (polling shipped, streaming pending; full spec at §11.7.4 below)

- ✅ Polling subset: `dapp_messages(domain, from_height, to_height, topic)` shipped under Phase 7.2 as a retrospective query (caller polls every N seconds with `from = last_scanned + 1`).
- ⏳ Streaming pending: `dapp_subscribe(domain, topic?)` — newline-JSON streaming over the RPC socket; per-block hook fires after `enqueue_save`; subscribers' filters check `tx.to == domain` for each DAPP_CALL in the new block. Backpressure: bounded per-subscriber queue with disconnect-on-overflow. Regression: spawn 1 DApp-style subscriber, submit a `DAPP_CALL`, verify the event is delivered within K blocks. **Full design (streaming + per-DApp+topic indexer + retention policy state machine) fleshed out in §11.7.4 below.**

### Phase 7.5 — DApp SDK + reference implementation (~1 week, ecosystem)

Out of scope for the chain. Reference DApp written as a small process that:
- Connects to Determ full node via RPC
- Calls `dapp_subscribe`
- Implements a sample app (suggested: public bulletin board)
- Documents the SDK pattern in `docs/DAPP-SDK.md`

### Phase 7.6 — Cross-shard DApp routing (~5-7 days, depends on regional-sharding completion) — fleshed out in §11.7.2 below

The single-shard DAPP_CALL apply path explicitly rejects cross-shard recipients today (chain.cpp:1201-1209: "v2.19 single-shard only: cross-shard DAPP_CALL is Phase 7.6 follow-on"). Lifting that rejection requires extending `CrossShardReceipt` to carry the opaque DAPP_CALL payload bytes alongside the standard amount/fee/nonce, threading the destination shard's apply-path to materialize the message in its block stream, and bounding the new payload-size accounting against the existing 4 MB `CROSS_SHARD_RECEIPT_BUNDLE` cap. See §11.7.2 for the full design.

### Phase 7.7+ (deferred)

- `DAPP_REPLY` distinct tx type
- DApp slashing (proof-of-misbehavior tx types)
- **DApp upgrade flows** (versioned `service_pubkey` rotation with grace period) — fleshed out in §11.7.1 below
- **Cross-shard DApp routing** (DAPP_CALL crossing shard boundaries) — fleshed out in §11.7.2 below
- **Per-DApp rate limiting / quota** (operator-declared call-rate ceiling enforced at validator admission) — fleshed out in §11.7.3 below
- **DApp message-bus indexing + pub-sub backend** (per-DApp+topic LSM index, retention policy state machine, streaming `dapp_subscribe` with backpressure) — fleshed out in §11.7.4 below
- DApp permission groups (on-chain ACL list separate from DApp registry)

---

### 11.7.1 — DApp upgrade flows: versioned `service_pubkey` rotation with grace period

**Tracking slot:** v2.24 (Theme 7 — DApp upgrade). Effort: ~5-7 days. Dependencies: v2.18 (DAPP_REGISTER, shipped), v2.19 (DAPP_CALL, shipped); v2.25/v2.26 ROTATE_KEY adjacent but independent (DApps use a separate tx).

#### Problem statement

A registered DApp publishes a single `service_pubkey` in its `DAppEntry`. This key is the AEAD recipient for `crypto_box_seal` payloads (§10). The current v1.x substrate offers two unsatisfying paths when the operator must change keys:

1. **Re-issue `DAPP_REGISTER` with `op=0`** on the same domain. This rotates the key in-place but creates an undefended overlap: senders who looked up `service_pubkey` at height H but submit `DAPP_CALL` at height H+1 (after the update applied) will have encrypted to a key the DApp may have already retired. In-flight messages become undecryptable; mempool-pending `DAPP_CALL`s are silently bricked.
2. **Deactivate the domain (`op=1`) and re-register under a new domain.** This severs identity continuity. End users must re-discover the DApp; existing client bindings break; the chain's persistent on-chain reputation (history of `DAPP_CALL` activity, age of registration, accumulated stake) is forfeited.

Neither path admits a clean key-rotation: identity continuity (same domain → same DApp) and key freshness (rotate `service_pubkey` periodically; immediate response to suspected compromise) are in tension.

The v2.24 DApp-upgrade flow resolves this by versioning `service_pubkey` and overlapping old + new keys during a defined grace window. Senders read the registry, encrypt to the **current** key by default, and may pin a specific version when replaying. The DApp keeps the prior key decryptable through the overlap and discards it after the grace window expires.

This problem matters because: (a) §10 explicitly warns about historical-message readability under post-quantum advances on the service key, but offers no rotation path; (b) §9 lists "service-key compromise" as a slashable event, but a slashable rotation flow is required for the operator to safely respond; (c) any nontrivial DApp ecosystem will need scheduled rotation cadence (90 / 180 days) as basic hygiene, the same way TLS-cert rotation is operationally routine.

#### Mechanism sketch

Extend `DAppEntry` with a key-history vector and a current-version pointer. Introduce a new tx slot `DAPP_KEY_ROTATE = 11` that the DApp's owning domain (or a delegated rotation key) signs. Apply-path mutates the entry's key list, sets a grace-window expiry on the prior key, and updates the state_root via the `d:` namespace.

Data structures:

```cpp
struct DAppKeyVersion {
    uint32_t version;          // monotonic; v0 is the initial DAPP_REGISTER key
    PubKey   service_pubkey;
    uint64_t active_from;      // block height when this key became current
    uint64_t retire_at;        // UINT64_MAX while current; <future height> when superseded
};

struct DAppEntry {
    // ...existing fields (endpoint_url, topics, retention, metadata,
    //    registered_at, active_from, inactive_from)...
    std::vector<DAppKeyVersion> key_history;  // ordered oldest → newest
    uint32_t                    current_version;  // index into key_history
    PubKey                      rotation_pubkey;  // optional: separate key authorized to rotate (else == owner)
};
```

Lifecycle of `key_history`:

- `DAPP_REGISTER` `op=0` (create): inserts `key_history = [{version=0, service_pubkey=X, active_from=h, retire_at=UINT64_MAX}]`, `current_version=0`. Backward-compatible with v2.18 entries — a v2.18 entry materializes as a single-element history at version 0.
- `DAPP_KEY_ROTATE`: appends `{version=cur+1, service_pubkey=Y, active_from=h, retire_at=UINT64_MAX}`, sets the prior current's `retire_at = h + DAPP_KEY_GRACE_BLOCKS`, advances `current_version`. The prior key remains decryptable-by-DApp through the grace window; the chain considers a `DAPP_CALL` valid against any key version with `active_from ≤ tx.block_height ≤ retire_at`.
- `DAPP_REGISTER` `op=0` (update on existing domain): preserves `key_history` and `current_version` UNCHANGED. Updating endpoint_url / topics / metadata MUST NOT rotate keys — keep the two concerns separate. (This is a behavior tightening relative to v2.18; see Backward-compat below.)
- `DAPP_REGISTER` `op=1` (deactivate): unchanged; `inactive_from` is set, `key_history` frozen for history.

Validator rules for a `DAPP_CALL` at height h targeting DApp D:

1. Resolve D in `dapp_registry_`; if missing or `inactive_from ≤ h`, reject (existing rule).
2. Senders SHOULD encrypt to `D.key_history[D.current_version].service_pubkey` (the current key).
3. The chain does NOT verify the payload's encryption target (payload is opaque). However, a sender MAY include an optional 4-byte `key_version` prefix in the `DAPP_CALL` payload preamble (informational; chain does not validate) so the DApp routes to the matching decryption key without trial-decrypt.
4. Grace window honored: a key version is "live for decrypt" iff `active_from ≤ h ≤ retire_at`. DApps with multiple live versions try each in order of `version` descending.

#### Wire-format changes

**New tx-type slot** (extends §3 enum):

```cpp
enum class TxType : uint8_t {
    ...existing 0..10...,
    DAPP_KEY_ROTATE = 11,
};
```

**`DAPP_KEY_ROTATE` payload** (canonical, LE where noted; consistent with v2.18 DAPP_REGISTER byte conventions in §3.1):

```
[op: u8]                    # 0 = rotate, 1 = set rotation_pubkey, 2 = revoke (emergency)
[new_service_pubkey: 32B]   # the new key (zero-key for op=2)
[grace_blocks_override: u32 LE]  # 0 = use chain-default DAPP_KEY_GRACE_BLOCKS; else clamped to [MIN, MAX]
[rotation_pubkey: 32B]      # if op=1: the new authorized rotator; else 32B zero
[reason_len: u8]
[reason: utf8]              # operator-supplied freeform reason (≤ 64 B; e.g. "scheduled-rotation", "compromise-suspected")
```

Constraints:

- `tx.from` must equal either the DApp's owning domain or the entry's current `rotation_pubkey`. If `rotation_pubkey` is zero (default), only the owning domain may rotate.
- `op=2` (emergency revoke) requires the owning-domain signature; rotation_pubkey alone cannot trigger emergency revoke. Effect: the current key's `retire_at` is set to `h` immediately (no grace window). A subsequent rotate must occur in the same or a later block to install a new current key, else `DAPP_CALL` to D is rejected until that lands. Recommended UX: bundle `op=2` and `op=0` in a v2.4 `COMPOSABLE_BATCH`.
- `grace_blocks_override` clamped: `[DAPP_KEY_GRACE_MIN_BLOCKS, DAPP_KEY_GRACE_MAX_BLOCKS]` (suggested 50 / 10000). Genesis-pinned with v2.X.2 governance-mutability per Q2.
- `key_history.size()` capped at `DAPP_KEY_HISTORY_MAX = 64` to bound state growth. On overflow, the oldest fully-retired (`retire_at < h`) entry is evicted from the live tip of state (still committed in historical block bodies, just not in `dapp_registry_`).

**State-commitment encoding** (extends §4 `d:` namespace canonical serialization):

The `canonical_serialize(DAppEntry)` is extended to append, AFTER the existing `metadata` field:

```
... existing metadata field ...
|| u64_be(rotation_pubkey)               # 32 bytes; zero if unset
|| u64_be(current_version)
|| u64_be(key_history.size())
|| (each version: u32_be(version) || service_pubkey
                  || u64_be(active_from) || u64_be(retire_at))
```

This appended suffix is **conditionally serialized**: a v2.18-style entry (single key, no rotation history) MAY omit the suffix entirely if `key_history.size() == 1 && current_version == 0 && rotation_pubkey == zero && key_history[0].retire_at == UINT64_MAX`. This preserves the v2.18 byte stream (and hence the state_root) for chains that never exercise key rotation, mirroring the v2.18 `state_root` field's "bound only when non-zero" convention. The state_root migration is therefore zero-impact on existing chains; the first `DAPP_KEY_ROTATE` on a domain promotes its entry to the extended form.

#### Apply-path changes

Touch list (files in `src/chain/` and `src/node/`):

| File | Function | Change |
|---|---|---|
| `include/determ/chain/transaction.hpp` | `TxType` enum | Add `DAPP_KEY_ROTATE = 11` |
| `include/determ/chain/dapp.hpp` (extension of v2.18 header) | `DAppEntry`, new `DAppKeyVersion` struct | Add `key_history`, `current_version`, `rotation_pubkey` |
| `src/chain/transaction.cpp` | `binary_codec::encode/decode_tx` | Add `DAPP_KEY_ROTATE` payload case (consistent with §3.1 conventions) |
| `src/chain/chain.cpp` | `apply_transactions` switch | New case for `DAPP_KEY_ROTATE`: charge fee, decode payload, validate authorization (owning-domain or rotation_pubkey), update `dapp_registry_[tx.from]` |
| `src/chain/chain.cpp` | `build_state_leaves` `d:` branch | Extend `canonical_serialize(DAppEntry)` to append the conditional suffix per §11.7.1 wire format |
| `src/chain/chain.cpp` | `serialize_state` / `restore_from_snapshot` | Round-trip the extended fields (closes the v2.18 S-037 gap forward — the same code path needs to learn `key_history`) |
| `src/node/node.cpp` | `validate_tx_shape` for `DAPP_CALL` | No change; the chain doesn't validate payload encryption target. Optional informational `key_version` preamble is opaque to validators |
| `src/node/node.cpp` | `rpc_dapp_info` | Return the full `key_history` + `current_version` + `rotation_pubkey` in the JSON response (light clients need this for trial-decrypt) |
| `src/node/node.cpp` | new `rpc_dapp_rotate` (optional thin wrapper) | CLI ergonomic; not strictly required |
| `tools/test_dapp_key_rotate.sh` | new | Regression: scheduled rotation, grace-window decrypt, emergency revoke, history cap eviction |

The new switch case mirrors `DAPP_REGISTER`'s shape (charge_fee → ensure_dapp_registry → mutate → advance nonce). The lazy-snapshot integration is inherited from §5's Phase 2A/2B pattern.

#### Backward-compat story

This is a **soft-fork** addition under the v2.18 substrate: no existing tx becomes invalid, no existing state_root computation changes for entries that never rotate. Coexistence:

- v2.18 nodes (which do not understand `TxType::DAPP_KEY_ROTATE = 11`) treat the new tx-type as unknown and reject the containing block. This is a **breaking** consensus change; v2.24 must roll out as a coordinated migration with a `genesis_params.dapp_key_rotate_active_from` height pin.
- Until that height, the chain MUST reject `DAPP_KEY_ROTATE` txs (validator-level pre-check). After that height, the chain MUST accept them.
- v2.18 entries (single-key, no history) materialize transparently as `key_history.size() == 1`. Their `state_root` contribution is unchanged by §11.7.1's conditional-suffix rule.
- The behavior tightening "DAPP_REGISTER `op=0` no longer rotates keys" is enforced from the activation height onward. Pre-activation rotations via DAPP_REGISTER are permitted but generate no `key_history`. Post-activation, a sender attempting key rotation via DAPP_REGISTER (i.e., supplying a `service_pubkey` different from the current one) is REJECTED with diagnostic `"use DAPP_KEY_ROTATE for key changes"`.

The coordinated migration follows the same pattern as A11 threshold-randomness activation and S-033 state_root activation (height-pinned, validators upgrade in advance, light clients note the schema version transition).

#### Threat model

| Attack | v2.24 defense | New surface introduced |
|---|---|---|
| **Service-key compromise; operator must respond** | `op=2` emergency revoke + same-block re-rotate via `COMPOSABLE_BATCH`. Window of vulnerability bounded by block latency (typically ≤ 1 block ≈ regional/global per §13.1 of PROTOCOL.md). Slashing event from §9 can now reference a specific compromised version. | None — strictly improves on v2.18's "operator has no recourse but re-REGISTER under a new domain" |
| **Adversarial rotation by stolen owning-domain key** | Attacker with the owning-domain Ed25519 key can already do anything (TRANSFER funds, deactivate the DApp, etc.); rotation is no worse. Mitigation: operator MAY pre-configure `rotation_pubkey` to a hot key while keeping the owning-domain key cold, narrowing the attack surface | Yes: the `rotation_pubkey` delegate is a new authority. Compromise of just `rotation_pubkey` lets an attacker rotate `service_pubkey` but NOT exfiltrate stake or deactivate the DApp. The operator can then issue an `op=1` (set rotation_pubkey to zero) and an `op=0` (install new rotation_pubkey) from the owning-domain key to recover. |
| **Replay during grace window** | The chain's existing nonce + replay-protection rules apply to `DAPP_KEY_ROTATE` itself. For `DAPP_CALL` payloads: a sender who encrypted to the old key during the grace window still has their message decryptable by the DApp; an adversary cannot replay an OLD ciphertext as a NEW message because libsodium sealed-box is non-deterministic (ephemeral key per encryption) and the on-chain `tx.nonce` rejects duplicates. | None |
| **Grace-window abuse to keep a compromised key live** | `op=2` emergency revoke bypasses the grace window. Slashing per §9 disincentivizes operators from leaving a known-compromised key in grace | Operator can choose a `grace_blocks_override` near `DAPP_KEY_GRACE_MAX_BLOCKS`; this is operator-side policy. Compensating control: the on-chain `reason` field is public, audit-trail-visible |
| **State-growth via key-history bloat** | `DAPP_KEY_HISTORY_MAX = 64` cap. Per-DApp size ceiling: 64 × (4 + 32 + 8 + 8) = 3328 bytes per entry's history. Across `DAPP_MAX_REGISTRY_SIZE` DApps (genesis-pinned), worst-case state bloat from rotation history is bounded | Compaction edge case: an attacker who controls many DApp operators could try to maximize history per DApp. The cap + the `DAPP_REGISTER` stake floor in §9 jointly bound the cost (Sybil-equivalent to the v2.18 namespace squatting threat already addressed in §9). |
| **Cross-shard rotation propagation lag** | The `d:` namespace state-root commitment ensures the destination shard sees the new key via the standard beacon-anchored state-proof path. A sender on shard B who reads a stale `dapp_info` may encrypt to a retired key; the grace window provides the recovery margin. | A `DAPP_KEY_GRACE_MIN_BLOCKS` floor MUST exceed the worst-case cross-shard receipt latency (`CROSS_SHARD_RECEIPT_LATENCY = 3` blocks at minimum; see S-016). Suggested floor: 50 blocks. |
| **Equivocating rotation** (two `DAPP_KEY_ROTATE` txs at the same height with different new keys) | Each tx is independently nonce-protected; the chain orders them via the standard intra-block tx index. The second of the two effectively re-rotates the first; the chain-state outcome is deterministic. | None — falls out of normal tx-ordering semantics |
| **Light-client trust** | Light clients verify `key_history` via the extended `d:` namespace state-proof (v2.2 RPC). The DApp operator cannot lie about prior key versions to a light client because the historical state-roots commit to the entire `key_history` vector at each block | Light clients now MUST fetch the full `key_history` per DApp they interact with (up to 64 × 52 bytes = ~3.3 KB). Tolerable for any practical light-client use case |

The relevant cross-references in the existing threat-model docs: `proofs/CrossShardReceipts.md` T-7 (rotation propagation), `proofs/Safety.md` L-1.3 (state-root inclusion of `key_history`), `proofs/EquivocationSlashing.md` H2 (same-generation rotation does not equivocate; ordering is well-defined).

#### Effort estimate

| Sub-component | Effort | Notes |
|---|---|---|
| `TxType::DAPP_KEY_ROTATE` enum + struct extensions | 0.5 day | Mechanical |
| Encoder/decoder + payload validation | 1 day | Mirrors `DAPP_REGISTER` shape |
| `apply_transactions` switch case + authorization check | 1 day | Owning-domain + rotation_pubkey authorization paths |
| `build_state_leaves` `d:` branch extension (conditional suffix) | 0.5 day | Preserves v2.18 state_root byte-for-byte for non-rotated entries |
| `serialize_state` / `restore_from_snapshot` round-trip | 0.5 day | Forward-closes S-037 for the extended schema |
| `rpc_dapp_info` extension to return `key_history` | 0.5 day | JSON additions; mechanical |
| CLI: `determ dapp-key-rotate --domain D [--new-key K] [--rotation-key R] [--grace G] [--reason S]` | 0.5 day | Wallet ergonomic |
| Regression: `tools/test_dapp_key_rotate.sh` (rotate, grace, emergency, history cap, cross-shard) | 1.5 days | Five scenarios; matches the v2.18 / v2.19 test-coverage depth |
| Migration coordination: genesis_params field + activation-height gate + documentation | 0.5 day | Same shape as the A11 / S-033 activation pin |
| **Total** | **~5-7 engineering days** | Single-developer estimate; +1-2 days if cross-shard rotation propagation needs a dedicated test |

#### Dependencies

- **v2.18 DAPP_REGISTER** — shipped. Required for the `dapp_registry_` substrate.
- **v2.19 DAPP_CALL** — shipped. Required for the payload-encryption surface that key rotation protects.
- **v2.4 COMPOSABLE_BATCH** — shipped. Recommended for the emergency-revoke + re-rotate same-block atomic pattern.
- **v2.2 state_proof RPC** — shipped. Required for light-client verification of the extended `d:` namespace encoding (the `36b759d` extension already covers the namespace; the schema extension is conditional-suffix-compatible).
- **v2.25 ROTATE_KEY (user identity)** — **adjacent, independent.** The v2.25/v2.26 work specifies key rotation for end-user identities (Theme 9 DSSO). v2.24's `DAPP_KEY_ROTATE` is the analog for DApp service identities. The two share design DNA (versioned history, grace window, authorization delegation) but are separate tx types and separate registry maps. Shipping order: either can ship first; if v2.25 ships first, v2.24 should mirror its grace-window constants and authorization patterns for consistency.
- **v2.10 threshold randomness** — not required (rotation is operator-initiated, not consensus-randomized).
- **v2.14 OPAQUE / single-server PAKE** — not required (DApp service keys are operator-controlled, not user-passphrase-derived).

No new cryptographic primitives. No new consensus primitives. No new gossip primitives.

#### Cross-references

- §3.1 `DAPP_REGISTER` byte layout — `DAPP_KEY_ROTATE` payload conventions match
- §4 `dapp_registry_` state-commitment via `d:` namespace — extended here with conditional suffix
- §9 Slashable conditions — "service-key compromise" gains a concrete operator-response flow (rotate + slash-the-compromise-event)
- §10 Privacy & off-chain channels — historical-message readability under PQ advances mitigated by periodic rotation
- §11 Phase 7.4 streaming subscription — orthogonal; key rotation is a control-plane event, streaming is data-plane
- `V2-DESIGN.md` Theme 9 (v2.25 ROTATE_KEY, v2.26 identity continuity) — sibling design for user-identity rotation; share design DNA
- `proofs/Safety.md` L-1.3 — state-root inclusion semantics
- `proofs/CrossShardReceipts.md` T-7 — cross-shard rotation visibility
- `SECURITY.md` §S-037 — forward-closes the snapshot-serialize/restore gap for the extended `DAppEntry` schema (the v2.24 implementation MUST round-trip `key_history` or it inherits S-037's symptom)
- `PROTOCOL.md` §4.1.1 — `d:` namespace canonical serialization; extended here
- `src/chain/chain.cpp` `build_state_leaves` — touch site for the conditional suffix
- `tools/test_dapp_register.sh` + `tools/test_dapp_call.sh` — sibling regression patterns; `tools/test_dapp_key_rotate.sh` mirrors their shape
- v2.18 / v2.19 in-process determ subcommands (`test-dapp-register`, `test-dapp-call`) — pattern for `test-dapp-key-rotate`

---

### 11.7.2 — Cross-shard DApp routing: extending DAPP_CALL across shard boundaries

**Tracking slot:** v2.27 (Theme 7 — DApp cross-shard). Effort: ~5-7 days. Dependencies: v2.18 (DAPP_REGISTER, shipped), v2.19 (DAPP_CALL, shipped), R0-R7 regional-sharding (shipped), B3 cross-shard receipt path (shipped). No new cryptographic, consensus, or gossip primitives — strictly extends the existing `CrossShardReceipt` carrier shape.

#### Problem statement

The v2.19 single-shard DAPP_CALL apply path explicitly rejects cross-shard recipients. The exact rejection lives at `src/chain/chain.cpp:1201-1209` (`if (is_cross_shard(tx.to)) { ... break; }`) with the comment "v2.19 single-shard only: cross-shard DAPP_CALL is Phase 7.6 follow-on (requires beacon-relay extension to carry payload bytes across shards)". The validator at `src/node/validator.cpp:914-918` carries the matching mempool-side reject ("DAPP_CALL cross-shard not supported in v2.19 (deferred to Phase 7.6)").

This rejection is a substrate-completeness gap rather than a safety property. The single-shard restriction means:

1. **DApp discovery is global, but DApp interaction is local.** A user on shard 3 querying `dapp_info("foo.example")` via the v2.2 light-client path correctly resolves the DApp's `service_pubkey` and `endpoint_url` regardless of which shard hosts the DApp's registered domain. Yet if the DApp's domain routes to a different shard, the user cannot submit an on-chain DAPP_CALL targeting it — the user must either fall back to the §10 direct-to-DApp off-chain channel (losing the on-chain audit trail) or move to the DApp's home shard (which contradicts the regional-sharding design goal that users stay on their home shard).
2. **Multi-region DApp deployments are forced into Mode D (sharded DApp).** A globally-popular DApp wanting users on every shard must either register a distinct domain per shard (`dapp-shard-0.example`, `dapp-shard-1.example`, ...) or accept that ~⌊(N-1)/N⌋ of its potential users cannot interact on-chain. The §8 Mode D recommendation works for cooperating DApp operators but is friction for any single-domain ecosystem (a DSSO RP per Theme 9, an L2 settlement DApp per the zk-VM God Stack pattern, a federated oracle).
3. **Payment + message bundling is restricted.** v2.19's headline ergonomic — `DAPP_CALL` carries `tx.amount` natively so "pay + call" fits in one tx — silently degrades to "pay separately on home shard, hope the DApp's off-chain logic correlates" when the DApp is cross-shard. The v2.4 `COMPOSABLE_BATCH` workaround does not help here because the batch is atomic only within a single block on a single shard.

The v2.27 cross-shard DAPP_CALL flow resolves this by extending the existing `CrossShardReceipt` shape to carry an opaque `dapp_payload` byte vector, threading the destination shard's apply path to materialize the message in its block stream as an inbound DAPP_CALL event, and bounding the new payload-size accounting against the existing 4 MB `CROSS_SHARD_RECEIPT_BUNDLE` body cap (`include/determ/net/messages.hpp` `max_message_bytes(MsgType::CROSS_SHARD_RECEIPT_BUNDLE)`).

#### Mechanism sketch

Treat a cross-shard DAPP_CALL as a TRANSFER-equivalent at the source side (debit + emit receipt) and a DAPP_CALL-equivalent at the destination side (credit + observable in block stream + filterable by `dapp_messages` RPC). The new wire surface is a single optional field on `CrossShardReceipt`:

```cpp
struct CrossShardReceipt {
    // ...existing v1.x fields (src_shard, dst_shard, src_block_index,
    //    src_block_hash, tx_hash, from, to, amount, fee, nonce)...

    // v2.27 cross-shard DApp extension. Empty for TRANSFER-originated
    // receipts (backward-compat). Non-empty iff the receipt originated
    // from a DAPP_CALL whose `to` routes to a different shard. Carries
    // the original DAPP_CALL payload verbatim: [topic_len:u8][topic:utf8]
    // [ct_len:u32 LE][ciphertext:bytes]. The destination shard's apply
    // path re-validates topic against the local dapp_registry_ entry
    // and inserts a synthetic DAPP_CALL into the destination block's
    // observable stream.
    std::vector<uint8_t> dapp_payload;
};
```

Lifecycle of a cross-shard DAPP_CALL `T` from sender `S` (on shard A) to DApp domain `D` (whose `to` routes to shard B):

1. **Mempool admission (shard A).** Validator at `validator.cpp:914-918` lifts its cross-shard reject only when `v2.27_active_from <= chain_height`. Pre-activation: reject as today. Post-activation: route through the cross-shard DAPP_CALL admission path.
2. **Source-side validation (shard A).** Shard A's producer / validator cannot resolve D in its own `dapp_registry_` because D is registered on shard B. The chain MUST therefore validate against an authoritative cross-shard DApp registry view. Two options:
   - **Option B1: Light-client proof carried in tx.** Sender provides a `state_proof("d", D)` against shard B's latest known state_root. Shard A validates the proof against the beacon-anchored state-root from the most recent shard-tip header. Cost: ~3 KB extra payload per cross-shard DAPP_CALL.
   - **Option B2: Trust-on-emit, validate-on-arrival.** Shard A admits the tx with shape-only checks (topic_len, ct_len, payload framing) and emits the receipt unconditionally. Shard B's apply-path resolves D in its local `dapp_registry_`; if D is missing or inactive at the destination height, the receipt is **dropped** (debit on A is retained as a fee paid to A's validators, identical to the v1.x B3 fee semantics where source-side fees are always retained even if the destination credit fails).

   **Recommended: Option B2.** It mirrors the existing B3 TRANSFER semantics where the source shard does not need to know whether the destination address exists (anon addresses are valid; registered domains may have been deactivated between submission and apply). The asymmetric outcome (sender pays the fee, message vanishes) is consistent with v2.19's same-shard handling of DAPP_CALL targeting a deactivated DApp (chain.cpp:1142-1146 retains the fee on `dapp.inactive_from <= height`). A separate `dapp-missing` receipt-return path is out of scope for v2.27; failed deliveries are observable via the on-chain audit trail and the DApp can reply via Theme-7 conventions.
3. **Source block production (shard A).** When shard A's producer at `producer.cpp:434` iterates transactions and encounters a cross-shard DAPP_CALL, it emits a `CrossShardReceipt` with `dapp_payload = tx.payload` (mirroring the existing TRANSFER cross-shard branch at producer.cpp:449-465). The sender is debited `tx.amount + tx.fee`; the local credit branch is suppressed. The receipt joins `b.cross_shard_receipts`.
4. **Gossip relay (beacon).** The existing `CROSS_SHARD_RECEIPT_BUNDLE` message carries the full source block (per `make_cross_shard_receipt_bundle` in `include/determ/net/messages.hpp:265`). Adding `dapp_payload` to `CrossShardReceipt` automatically extends the bundle's wire footprint by the payload's size. The 4 MB `max_message_bytes(MsgType::CROSS_SHARD_RECEIPT_BUNDLE)` cap absorbs the increment without code change (single 16 KB DAPP_CALL ciphertext on a block with hundreds of receipts stays well under 4 MB; see size-budget table below).
5. **Destination-side admission (shard B).** Shard B's `on_cross_shard_receipt_bundle` handler (`src/node/node.cpp:1612-1649`) accepts the bundle as today, dedupes by `(src_shard, tx_hash)`, stores in `pending_inbound_receipts_` with first-seen height. The S-016 Option-2 admission latency (`CROSS_SHARD_RECEIPT_LATENCY = 3` blocks, `src/node/node.cpp:1574`) applies unchanged — cross-shard DAPP_CALL receipts wait the same 3-block soak before inclusion as cross-shard TRANSFER receipts.
6. **Destination block production (shard B).** When shard B's producer assembles a block, `inbound_receipts_eligible_for_inclusion` (node.cpp:1577) returns the soaked-and-ready receipts. The producer bakes them into `b.inbound_receipts` as today. The apply path at `chain.cpp:1363-1381` credits `r.to` with `r.amount` (existing behavior). When `r.dapp_payload` is non-empty, the apply path additionally:
   - Resolves `r.to` in the local `dapp_registry_`. If missing or `inactive_from <= b.index`, the credit is retained but no DAPP_CALL event is materialized — the message is silently dropped at the destination (per B2 recommendation above).
   - Re-validates the payload framing (topic_len, ct_len, total size) using the same checks as the v2.19 same-shard DAPP_CALL apply branch (chain.cpp:1150-1200). On framing failure, again credit is retained, message dropped.
   - Re-validates the topic against the local DApp's registered topics (chain.cpp:1166-1176). On topic mismatch, again credit retained, message dropped.
   - On all checks passing, the receipt is observable as a "synthetic DAPP_CALL" in the destination block stream. Implementation: `dapp_messages` RPC returns matching inbound receipts alongside same-shard DAPP_CALLs, distinguished by an explicit `source_shard != my_shard_id` field in the JSON response. The synthetic DAPP_CALL's height is `b.index` on shard B; its `(src_shard, tx_hash)` pair retains the original identity for cross-shard traceability.
7. **Block-stream observable.** Subscribers via the (pending) `dapp_subscribe` RPC see the synthetic DAPP_CALL emit at the destination block's finalization, exactly the same way `inbound_receipts` are observable today on TRANSFER cross-shard paths.

#### Wire-format changes

**Extension to `CrossShardReceipt`** (`include/determ/chain/block.hpp:339`):

Append a single new field `dapp_payload: std::vector<uint8_t>` after the existing `nonce: uint64_t`. The JSON encoding (`to_json` / `from_json` on `CrossShardReceipt`) gains an optional `"dapp_payload": "<hex>"` key. The field is omitted when empty, preserving backward-compat with v1.x receipts: any v1.x JSON file decodes to `dapp_payload = {}` and serializes to a byte-identical JSON form, hence the state-root contribution via `applied_inbound_receipts_` (chain.cpp:331-332 `"i:" + src_be8 + tx_hash` namespace) is unchanged for TRANSFER-only chains.

**State-root contribution.** The `i:` namespace key (`include/determ/chain/chain.hpp:605` `applied_inbound_receipts_`) is `{src_shard, tx_hash}`, a 40-byte composite. Extending the receipt with `dapp_payload` does NOT widen the key — the value hash (per chain.cpp:332-337) MAY incorporate the payload digest if needed for tamper-evidence of "this DApp call was actually delivered", but the conservative minimum is to leave the value as today (`"applied" / "✓"`) and rely on the source-shard block's K-of-K signature (transitively covering `dapp_payload` via the source block's `tx_root` since the original DAPP_CALL is in `src_block.transactions`). The destination's `applied_inbound_receipts_` entry plus the source block's identity (`src_block_index, src_block_hash, tx_hash`) is sufficient for any light client to verify cross-shard delivery + recover the original payload.

**`dapp_messages` RPC extension.** Add an optional `include_cross_shard: bool` parameter (default `true`). When true, the response interleaves same-shard DAPP_CALL txs and synthetic DAPP_CALLs from `inbound_receipts` with non-empty `dapp_payload`, ordered by `(block_index, intra_block_index)` on the destination shard. Each entry has a `source_shard` field distinguishing the origin.

**`CROSS_SHARD_RECEIPT_BUNDLE` cap accounting.** No code change to `max_message_bytes` is required. Size budget under v2.27:

| Scenario | Receipt count / block | Bytes per receipt | Total bundle |
|---|---|---|---|
| TRANSFER-only (v1.x baseline) | up to ~10,000 | ~140 B (fixed fields + short strings) | ~1.4 MB |
| Mixed (90% TRANSFER + 10% DAPP_CALL @ 16 KB payload) | 1000 + 100 | ~140 B + ~16 KB × 100 | ~1.7 MB |
| DApp-heavy (50% TRANSFER + 50% DAPP_CALL @ 16 KB) | 100 + 100 | ~14 KB + ~1.6 MB | ~1.8 MB |
| Pathological (all DAPP_CALL @ MAX_DAPP_CALL_PAYLOAD ≈ 16 KB) | 200 | ~16 KB | ~3.2 MB |

The 4 MB cap holds with comfortable headroom across realistic mixes. A worst-case attacker filling a block with maximum-size cross-shard DAPP_CALLs (200 × 16 KB = 3.2 MB) is bounded by the per-block tx count (the chain's tx-count limit per profile, `params.hpp`) and the per-tx fee floor (§9 economic model). The fee floor at `block_subsidy / 64` per DAPP_CALL means a 200-DAPP_CALL spam block costs the attacker ~3× the block subsidy, an order-of-magnitude penalty.

#### Apply-path changes

Touch list (files in `src/chain/`, `src/node/`, and `include/determ/`):

| File | Function | Change |
|---|---|---|
| `include/determ/chain/block.hpp` (`CrossShardReceipt`) | struct definition + `to_json` / `from_json` | Add `dapp_payload: std::vector<uint8_t>` field; omit when empty in JSON; hex-encode when non-empty |
| `src/chain/block.cpp` | `CrossShardReceipt::to_json` / `from_json` | Round-trip the new field; preserve empty-vector default for v1.x deserialization |
| `src/node/producer.cpp` | `produce` (tx switch case for `DAPP_CALL` — currently absent; mirror `TRANSFER`'s cross-shard branch at producer.cpp:449-465) | Detect cross-shard DAPP_CALL via `chain.is_cross_shard(tx.to)`; emit receipt with `dapp_payload = tx.payload`; suppress local credit; do NOT call same-shard apply branch |
| `src/node/validator.cpp` | `check_cross_shard_receipts` (validator.cpp:1081) | Extend pairing: cross-shard DAPP_CALLs in `b.transactions` MUST have matching `cross_shard_receipts` entries; field equality check on `dapp_payload == tx.payload` |
| `src/node/validator.cpp` | `validate_tx` switch case for `DAPP_CALL` (validator.cpp:914-918) | Replace the unconditional reject with: pre-v2.27 height → reject (today's behavior); post-v2.27 height → shape-only validation, defer DApp-existence/topic checks to destination apply (per Option B2 recommendation above) |
| `src/chain/chain.cpp` | `apply_transactions` switch case for `DAPP_CALL` (chain.cpp:1133-1224) | Replace the cross-shard reject at chain.cpp:1201-1209 with the source-side emit branch: debit sender, append to `block_outbound`, emit receipt (mirror TRANSFER's branch at chain.cpp:752-765) |
| `src/chain/chain.cpp` | `apply_transactions` inbound-receipt loop (chain.cpp:1363-1381) | After the existing credit, when `r.dapp_payload` is non-empty: resolve `r.to` in `dapp_registry_`; on missing/inactive/topic-mismatch/framing-fail, retain credit but skip the synthetic DAPP_CALL emit; on success, no state mutation (DAPP_CALL is observable via the receipt itself, no per-DApp inbox map) |
| `src/node/node.cpp` | `rpc_dapp_messages` | Include synthetic DAPP_CALLs from `applied_inbound_receipts_` with non-empty `dapp_payload`; add `source_shard` field per entry; honor optional `include_cross_shard: bool` filter |
| `include/determ/net/messages.hpp` | `max_message_bytes(MsgType::CROSS_SHARD_RECEIPT_BUNDLE)` | No change — 4 MB cap suffices per the size-budget analysis above |
| `tools/test_cross_shard_dapp_call.sh` | new | Regression: scheduled cross-shard DAPP_CALL, payload round-trip, missing-DApp drop, topic-mismatch drop, framing-fail drop, S-016 latency soak, size-cap stress |

The new producer / apply / validator hooks mirror the existing B3 TRANSFER cross-shard machinery one-for-one. There is no new gossip message type, no new RPC type, no new state field on Chain. The extension is strictly additive on `CrossShardReceipt`.

#### Backward-compat story

This is a **soft-fork** addition under the v2.18/v2.19 substrate: no existing tx becomes invalid, no existing receipt-bundle format changes for chains with TRANSFER-only cross-shard traffic. Coexistence:

- v2.19 nodes (which carry the cross-shard reject at validator.cpp:914-918 and chain.cpp:1201-1209) cannot validate or apply v2.27 cross-shard DAPP_CALLs. A v2.27 producer emitting cross-shard DAPP_CALL receipts would diverge from v2.19 validators applying their inbound receipts. This is therefore a **consensus-breaking** change at the apply layer; v2.27 must roll out as a coordinated migration with a `genesis_params.cross_shard_dapp_call_active_from` height pin.
- Until that height, the chain MUST reject cross-shard DAPP_CALLs at mempool admission (today's behavior). After that height, both producer and validator MUST handle them per the spec above.
- v1.x `CrossShardReceipt` JSON without `dapp_payload` decodes to an empty `dapp_payload` field, byte-identical state-root contribution. v2.27 receipts with `dapp_payload != {}` produce a JSON form that v2.19 readers cannot decode (unknown JSON key — depending on JSON library's strictness, either silently dropped or rejected). The coordinated migration ensures no v2.19 reader is in the network when v2.27 receipts begin emitting.
- Chains that never carry cross-shard DAPP_CALL produce byte-identical block streams and state_roots pre- and post-activation. This preserves the v2.27 zero-impact-on-non-users property mirroring the v2.18 → v2.24 DApp-key-rotate transition (§11.7.1 backward-compat).
- The activation pattern parallels v2.24 DApp key rotate (`genesis_params.dapp_key_rotate_active_from`), A11 threshold randomness, and S-033 state_root activation. Validators upgrade in advance; light clients note the schema-version transition.

#### Threat model

| Attack | v2.27 defense | New surface introduced |
|---|---|---|
| **Spam: attacker floods cross-shard DAPP_CALLs to inflate gossip + block size** | Per-tx fee floor at `block_subsidy / 64` (§9). At pathological 200 × 16 KB = 3.2 MB bundle, the attacker pays ~3× block subsidy. The 4 MB `max_message_bytes` cap drops oversize bundles. Block-side tx count limit (per `params.hpp` profile) bounds receipts per block. | None new beyond the v1.x B3 receipt-spam surface. The fee floor scales with `tx.payload.size()` in spirit (paying for the bandwidth consumed) but is not explicitly per-byte; if real-world spam emerges, v2.X.1 could bind `min_fee = base + ciphertext_len / K`. |
| **DApp-existence equivocation: receipt arrives at shard B, but a `DAPP_REGISTER op=1` deactivated D one block earlier** | Per Option B2, the destination apply path resolves D at the destination block's height; deactivated DApps drop the synthetic DAPP_CALL emit but retain the credit (mirroring the v2.19 same-shard handling at chain.cpp:1142-1146). No equivocation surface: the chain's serializability + state_root commitment ensures both shards agree on whether D is active at any given height. | None — falls out of normal apply semantics |
| **Cross-shard DApp-state divergence** (a DApp operator running validator-nodes on multiple shards sees the same DAPP_CALL apply on one shard but not another, due to receipt-loss in transit) | The B3 / S-016 substrate already ensures exactly-once delivery via `applied_inbound_receipts_` dedup keyed on `(src_shard, tx_hash)`. The CROSS_SHARD_RECEIPT_BUNDLE relay is best-effort but the destination chain only credits + emits on first observation; duplicate bundles are no-ops. Receipt loss in transit is bounded by gossip-retry; the same mechanism that ensures TRANSFER cross-shard liveness ensures DAPP_CALL cross-shard liveness. | None — inherits the v1.x B3 liveness story |
| **State-bloat via large `dapp_payload`** | `MAX_DAPP_CALL_PAYLOAD` (genesis-pinned; suggested 16 KB per v2.19) caps per-receipt payload. The CROSS_SHARD_RECEIPT_BUNDLE 4 MB cap caps per-block aggregate. Per-DApp aggregate is governance-mutable via the §9 fee model (operator pays for storage). | The synthetic DAPP_CALL is observable on the destination's `dapp_messages` RPC indefinitely (subject to v1.x block-retention policy). Light clients can prune by height window. |
| **Receipt-payload tampering by beacon-relay node** | Beacon relays the source block verbatim per the v1.x B3.3 contract (`Node::on_cross_shard_receipt_bundle` in node.cpp:1612 simply re-broadcasts). The source block's K-of-K signature transitively binds `dapp_payload` via the source block's `tx_root` (the original DAPP_CALL is in `src_block.transactions`, and its `tx.payload == receipt.dapp_payload`). Destination validators verify this binding before apply. | None — inherits the v1.x B3 source-binding story |
| **Replay of cross-shard DAPP_CALL on destination shard** | `applied_inbound_receipts_` dedup keyed on `(src_shard, tx_hash)`. A second arrival of the same receipt is silently skipped at chain.cpp:1365. Sender's source-shard nonce on the original DAPP_CALL provides the source-side replay barrier. | None |
| **Adversary on shard A submits DAPP_CALL to "victim DApp on shard B" with garbage payload** | Source-side validation is shape-only per Option B2; destination apply retains the fee + drops the synthetic DAPP_CALL emit on framing-fail or topic-mismatch. The victim DApp never sees the garbage; only its balance is incremented by `r.amount` (which the adversary actually paid). This is asymmetric: adversary funds the victim DApp's account, victim DApp sees nothing. | Operator-side caveat: a DApp receiving unexpected balance increments via cross-shard credits should consult the `dapp_messages` audit trail to determine which receipts carried payload-drops vs which were legitimate. UX guidance documented in §7 client wallet integration. |
| **Cross-shard DAPP_CALL latency abuse** | The S-016 `CROSS_SHARD_RECEIPT_LATENCY = 3` blocks soak applies. Senders observe a 3-block-on-destination latency window vs same-shard DAPP_CALL's 1-block window. Wallet UX SHOULD surface "cross-shard" in the send-confirmation flow per the §7 wallet integration recommendation. | None new — inherits the v1.x B3 latency story |
| **Light-client trust** | Light clients verify the destination block's `inbound_receipts` via existing tx-in-block Merkle (block `tx_root` extension for the inbound-receipts vector, already shipped under R0-R7). The source block's K-of-K binding is verifiable independently via the beacon-anchored shard tip and the v2.2 state_proof RPC. Cross-shard DAPP_CALL delivery is therefore fully light-client-verifiable end-to-end. | None |

The relevant cross-references in the existing threat-model docs: `proofs/CrossShardReceipts.md` T-5/T-6 (delivery exactly-once + idempotent apply), `proofs/Safety.md` L-1.3 (state-root inclusion of `applied_inbound_receipts_`), `proofs/UnderQuorumMerge.md` (merge-state interaction — cross-shard DAPP_CALL receipts are subject to the same merge-event eligibility rules as TRANSFER receipts).

#### Effort estimate

| Sub-component | Effort | Notes |
|---|---|---|
| `CrossShardReceipt::dapp_payload` field + JSON round-trip | 0.5 day | Mechanical addition |
| Producer extension for cross-shard DAPP_CALL emit | 0.5 day | Mirrors TRANSFER's cross-shard branch at producer.cpp:449-465 |
| Validator extension to remove cross-shard reject + extend pairing check | 0.5 day | Shape-only validation; defer DApp existence to apply |
| Source-side apply extension at chain.cpp:1201-1209 | 0.5 day | Replace unconditional reject with debit + emit-receipt branch |
| Destination-side apply extension at chain.cpp:1363-1381 | 1 day | Resolve D, re-validate framing + topic, conditionally emit observable DAPP_CALL |
| `rpc_dapp_messages` extension for cross-shard inclusion | 0.5 day | Interleave same-shard + synthetic; add `source_shard` field; honor filter |
| Migration coordination: genesis_params + activation-height gate + documentation | 0.5 day | Same shape as A11 / S-033 / v2.24 activation pins |
| Regression: `tools/test_cross_shard_dapp_call.sh` (delivery, drop, S-016 soak, size-cap stress, dedup) | 1.5 days | Six scenarios; matches v2.18 / v2.19 / B3 test-coverage depth |
| In-process subcommand `determ test-cross-shard-dapp-call` (sibling to `test-dapp-call`) | 0.5 day | CLI entry point for the regression script |
| **Total** | **~5-7 engineering days** | Single-developer estimate; +1-2 days if integration with merge-state under R7 needs a dedicated test |

#### Dependencies

- **v2.18 DAPP_REGISTER** — shipped. Required for destination-side DApp resolution.
- **v2.19 DAPP_CALL** — shipped. Required for the underlying tx type, payload framing, and topic-validation scaffolding.
- **R0-R7 regional sharding** — shipped. Required for cross-shard receipt path (B3.1 through B3.4) and S-016 latency-soak machinery.
- **B3 cross-shard receipt path** — shipped. Required for `CROSS_SHARD_RECEIPT_BUNDLE` gossip, beacon-relay, `pending_inbound_receipts_`, and `applied_inbound_receipts_` state.
- **v2.4 COMPOSABLE_BATCH** — shipped, but not required. A future v2.X composability extension could allow a batch containing both same-shard and cross-shard DAPP_CALLs; deferred as a separate item.
- **v2.24 DAPP_KEY_ROTATE (§11.7.1)** — adjacent, independent. Cross-shard DAPP_CALLs to a DApp whose key has just rotated benefit from the §11.7.1 grace-window mechanism — the destination shard sees the rotation via the state_root commitment, and the grace window's `DAPP_KEY_GRACE_MIN_BLOCKS ≥ CROSS_SHARD_RECEIPT_LATENCY + 3` floor (per §11.7.1 threat model) ensures senders on remote shards reading a stale `dapp_info` have margin to recover.
- **v2.10 threshold randomness** — not required (cross-shard routing is deterministic from shard_id_for_address).
- **v2.7 F2 Phase-1 intersection rule** — not required for shipping v2.27, but recommended as a follow-up to remove the S-016 Option-2 round-retry surface that the latency-soak partially masks.

No new cryptographic primitives. No new consensus primitives. No new gossip primitives.

#### Cross-references

- §3.2 `DAPP_CALL` payload framing — v2.27 receipt carries the same byte layout verbatim
- §3.2 "Cross-shard: if `tx.to` routes to a different shard, the standard cross-shard receipt path handles the payment leg; the message payload goes with the receipt (see §10 below for the cross-shard nuance)" — v2.27 closes the deferred design
- §4 `dapp_registry_` state-commitment via `d:` namespace — destination-side resolution path
- §5 apply-path semantics — extended at chain.cpp:1201-1209 (source emit) and chain.cpp:1363-1381 (destination credit + synthetic emit)
- §6 RPC surface — `dapp_messages` extension with `source_shard` field
- §7 client wallet integration — `dapp-call` CLI gains a "cross-shard latency: 3 blocks" hint in the confirmation flow
- §8 DApp node operation modes — Mode D (sharded DApp) becomes optional rather than mandatory for global DApps
- §9 economic model — fee floor scales attack cost; per-byte fee tightening is a v2.X.1 follow-up if real-world spam emerges
- §10 cross-shard DApp calls (paragraph at lines 378-386) — v2.27 supersedes the 4-bullet thumbnail with this fleshed-out spec
- §11.7.1 DAPP_KEY_ROTATE — adjacent design; grace-window floor coordinates with `CROSS_SHARD_RECEIPT_LATENCY`
- `V2-DESIGN.md` Theme 7 v2.21+ (cross-shard DApp routing) — this is the formal spec for that deferred item
- `V2-DESIGN.md` Theme 9 (v2.25 DSSO) — DSSO RPs can now route challenges + assertions across shards via cross-shard DAPP_CALL, unblocking the multi-region DSSO deployment pattern
- `proofs/CrossShardReceipts.md` T-5 (exactly-once delivery), T-6 (idempotent apply) — extended to cover `dapp_payload` carrier without new safety obligations
- `proofs/Safety.md` L-1.3 — state-root inclusion of `applied_inbound_receipts_` extended to carry `dapp_payload` hash optionally
- `proofs/UnderQuorumMerge.md` — merge-state interaction with cross-shard DAPP_CALL is identical to TRANSFER (no special merge-mode handling required)
- `PROTOCOL.md` §4.1.1 — `i:` namespace canonical serialization; backward-compat preserved (empty `dapp_payload` produces byte-identical encoding)
- `PROTOCOL.md` §11 cross-shard receipt-bundle wire format — extended carrier shape
- `SECURITY.md` §S-016 (cross-shard receipt latency) — unchanged; v2.27 honors the same soak window
- `src/chain/chain.cpp` `apply_transactions` — touch sites at chain.cpp:1201-1209 (source emit) and chain.cpp:1363-1381 (destination credit + synthetic emit)
- `src/node/producer.cpp` `produce` — touch site for cross-shard DAPP_CALL emit (mirror producer.cpp:449-465)
- `src/node/validator.cpp` `validate_tx` + `check_cross_shard_receipts` — touch sites at validator.cpp:914-918 and validator.cpp:1081
- `src/node/node.cpp` `on_cross_shard_receipt_bundle` (node.cpp:1612), `inbound_receipts_eligible_for_inclusion` (node.cpp:1577) — no code change required; inherit the existing handling
- `tools/test_cross_shard_dapp_call.sh` — new regression mirroring `test_cross_shard_transfer.sh` + `test_dapp_call.sh` patterns
- v2.19 in-process determ subcommand (`test-dapp-call`) — pattern for `test-cross-shard-dapp-call`

#### Open questions deferred to implementation

- **Q1: Per-byte fee tightening.** The v2.27 spec uses the §9 fee floor as written (`block_subsidy / 64` per DAPP_CALL, height-flat). A per-byte tightening (`base + ciphertext_len / K`) would harden against worst-case 16 KB payload spam more aggressively, at the cost of a more complex fee schedule. Deferred to v2.X.1 (post-launch monitoring); the v2.27 launch uses the simpler height-flat floor.
- **Q2: dapp_payload digest in `i:` namespace value.** Conservative minimum is unchanged value (`"✓"`); a defensive maximum is to commit `SHA256(dapp_payload)` in the value hash. The conservative choice preserves byte-identical state-root for TRANSFER-only chains; the defensive choice slightly hardens light-client tamper-evidence for cross-shard DAPP_CALL delivery audit trails. Recommended: ship conservative; promote to defensive only if a light-client use case demands it.
- **Q3: Bundled cross-shard COMPOSABLE_BATCH.** A composable batch containing both same-shard and cross-shard DAPP_CALLs would atomically commit both legs only on the source shard; the cross-shard leg's destination application is asynchronous per the receipt-latency soak. This atomicity asymmetry should be documented but not blocked; the v2.27 spec accepts it as part of the cross-shard latency model. Deferred to a v2.X follow-up if a use case emerges where same-block destination apply is required (would require the v2.12 atomic-cross-shard-swap machinery; see V2-DESIGN.md v2.12).
- **Q4: Cross-shard DApp deactivation race.** If shard A admits a cross-shard DAPP_CALL at height H_A targeting D, and D is deactivated on shard B at height H_B (with H_B < H_apply_on_B), the receipt drops silently per Option B2. An alternative is to refund `r.amount` to the sender via a reverse cross-shard receipt. Refund is symmetric and arguably more user-friendly, but introduces a recursive cross-shard receipt pattern (refund-of-refund-of-refund). The v2.27 spec ships the simpler drop-and-credit-DApp pattern; refund is a v2.X.1 follow-up if user-experience research shows the drop pattern is too confusing in practice.
- **Q5: dapp_subscribe synthetic-event filtering.** The pending streaming `dapp_subscribe` RPC (v2.20 / Phase 7.4) needs to interleave synthetic cross-shard DAPP_CALLs with same-shard DAPP_CALLs. Recommended: subscribers see the same event shape with an additional `source_shard` JSON field. Backpressure semantics unchanged; bounded per-subscriber queue applies symmetrically. This is a v2.20 concern more than a v2.27 concern, but the spec is noted here so the v2.20 implementation has a clean target shape.

---

### 11.7.3 — Per-DApp rate limiting / quota: operator-declared call-rate ceiling enforced at validator admission

**Tracking slot:** v2.28 (Theme 7 — DApp rate limiting). Effort: ~4-6 days. Dependencies: v2.18 (DAPP_REGISTER, shipped), v2.19 (DAPP_CALL, shipped); v2.24 DAPP_KEY_ROTATE (§11.7.1) adjacent but independent. No new cryptographic, consensus, or gossip primitives — strictly extends the validator admission + apply paths with a per-DApp token-bucket state machine seeded from the registry.

#### Problem statement

§9's economic model bounds DApp-spam via a chain-wide fee floor (`block_subsidy / 64` per `DAPP_CALL`) and §8's Mode A/B/C node operators rely on off-chain rate limits per identity. Neither addresses the **per-DApp** dimension: a DApp serving payment-receipt notifications at sub-second cadence is operationally indistinguishable, at the chain layer, from an adversary flooding a victim DApp at sub-second cadence. The §9 fee floor scales attacker cost linearly with traffic but does not give the DApp operator a way to **declare its expected throughput on-chain** so validators can enforce a per-DApp call-rate ceiling at admission time.

This matters because:

1. **Asymmetric attack economics.** A DApp accepting `DAPP_CALL` from anon senders has no on-chain mechanism to assert "I expect ≤ R calls/block." An adversary willing to pay R × `block_subsidy / 64` per block can flood the DApp with garbage payloads. The DApp's off-chain ACL (§9 closing paragraph) can drop them at endpoint level, but the chain has already paid for storage + gossip + state-root contribution for every call — the cost falls on every validator + every full node, not just the targeted DApp.
2. **Honest-DApp resource planning is impossible.** Without a declared per-DApp cap, a DApp operator running Mode B/C cannot guarantee their node has enough capacity to handle their own DAPP_CALL stream — they must size for unbounded volume. The Mode-D (sharded DApp) workaround per §8 helps amortize but does not bound per-shard worst case.
3. **Fair-share across DApps is implicit, not enforced.** The chain serializes `DAPP_CALL` txs by block + intra-block index; a popular DApp's calls naturally crowd out a less-popular DApp's calls under mempool pressure (S-008 admission). The fee market provides a partial answer (popular DApps can be served by users paying higher fees), but the fee market does not give a DApp operator a way to **bound** its own ingress.
4. **L2 / oracle / DSSO patterns need predictability.** The L2 zk-VM and DSSO RP patterns documented in §1 publish authenticated batch commitments at known cadences (every N blocks, or every M seconds). A per-DApp declared throughput on-chain lets light clients and other DApps reason about expected emit rates without out-of-band coordination.

The v2.28 per-DApp rate limiting flow resolves this by extending `DAPP_REGISTER` with an optional rate-limit declaration block (max calls per window + window size + burst capacity + over-cap policy), seeding a per-DApp token-bucket state machine on `apply_transactions`, and enforcing the bucket at validator admission and apply time. The state machine is a deterministic function of the chain's block height and the DApp's declared parameters; no new gossip required; the bucket state itself is reconstructible from block history (so it does not need separate state-root commitment beyond the registry entry itself).

#### Mechanism sketch

Extend `DAppEntry` with a rate-limit policy block. Senders submitting a `DAPP_CALL` to a rate-limited DApp must pass a per-DApp admission check: the validator computes the DApp's available tokens at the target block's height, and admits the call iff at least 1 token is available. Excess calls are subject to the policy: reject-at-validator (default), reject-at-apply-with-fee-retained, or defer-to-next-window. The token bucket refills deterministically every N blocks per the DApp's declared rate.

Data structures:

```cpp
struct DAppRateLimit {
    uint8_t  policy;             // 0 = unlimited (default; v2.18 entries materialize as this)
                                 // 1 = reject_at_validator (best UX; senders see "rate-exceeded" at submit)
                                 // 2 = reject_at_apply (fee retained; spam-burns the attacker)
                                 // 3 = defer (call queued logically; apply at first refill block)
    uint32_t calls_per_window;   // capacity (e.g., 64 calls per window)
    uint32_t window_blocks;      // window size in blocks (e.g., 16 blocks ≈ ~8s on regional profile)
    uint32_t burst_capacity;     // max tokens accumulated above steady-state (e.g., 256)
    uint8_t  scope;              // 0 = per-DApp aggregate (all senders share bucket)
                                 // 1 = per-(DApp, sender) (each sender has their own bucket)
                                 // 2 = per-(DApp, topic) (each topic has its own bucket)
};

struct DAppEntry {
    // ...existing fields (service_pubkey, endpoint_url, topics, retention, metadata,
    //    registered_at, active_from, inactive_from)...
    // ...v2.24 fields (key_history, current_version, rotation_pubkey)...
    DAppRateLimit rate_limit;    // optional; policy=0 means unlimited (default)
};
```

The token bucket itself is **not** persisted in `dapp_registry_`. Instead, the validator + apply path compute the available-tokens-at-height-h via a pure function:

```cpp
uint64_t available_tokens(DAppRateLimit policy, uint64_t calls_consumed, uint64_t h) {
    if (policy.policy == 0) return UINT64_MAX;  // unlimited
    uint64_t windows_elapsed = (h - dapp.registered_at) / policy.window_blocks;
    uint64_t total_capacity = windows_elapsed * policy.calls_per_window;
    if (total_capacity > policy.burst_capacity)
        total_capacity = ((windows_elapsed - 1) * policy.calls_per_window) + policy.burst_capacity;
    return total_capacity > calls_consumed ? total_capacity - calls_consumed : 0;
}
```

Where `calls_consumed` is the count of admitted `DAPP_CALL` txs targeting this DApp (or this DApp + sender, or this DApp + topic, per scope) since `dapp.registered_at`, derived deterministically from the block stream. Validators maintain a small per-DApp counter map (the `c:` namespace already exists in state-root for chain counters; extend with `c:dapp_calls:` for per-DApp counts) so the available-tokens function is O(1) per check.

This formulation is **leaky-bucket-equivalent** with explicit window granularity: a DApp with policy `(64 calls / 16 blocks, burst 256)` admits up to 64 calls in any single block (the full window allocation), up to 256 calls within any 4 consecutive windows (the burst cap), and steady-state 4 calls/block average over many windows. Operators tuning their DApp pick parameters matching their expected legitimate load + safety margin.

#### Wire-format changes

**Extension to `DAPP_REGISTER` payload** (extends §3.1):

After the existing `metadata` field, append an optional rate-limit declaration block:

```
... existing payload through metadata ...
[has_rate_limit: u8]         # 0 = absent (policy = unlimited); 1 = present
if has_rate_limit == 1 {
    [policy: u8]             # 0/1/2/3 per DAppRateLimit::policy
    [calls_per_window: u32 LE]
    [window_blocks: u32 LE]
    [burst_capacity: u32 LE]
    [scope: u8]              # 0/1/2 per DAppRateLimit::scope
}
```

Constraints:

- `policy != 0` requires `calls_per_window ≥ 1`, `window_blocks ≥ DAPP_RATE_MIN_WINDOW_BLOCKS` (suggested 4), `burst_capacity ≥ calls_per_window`, `burst_capacity ≤ DAPP_RATE_BURST_MAX` (suggested 65536).
- A v2.18-style DAPP_REGISTER payload (no rate-limit block) decodes to `has_rate_limit = 0` → `policy = 0` (unlimited). Backward-compat: byte-identical encoding for entries that never opt in.
- A subsequent DAPP_REGISTER on the same domain can update the rate-limit block; the new policy takes effect from the apply height. Tightening (lower capacity / shorter window) is permitted; loosening (higher capacity) is also permitted. The chain does not require monotonicity — operators have full operational flexibility.
- `policy=3` (defer) requires `window_blocks ≤ DAPP_RATE_DEFER_MAX_WINDOW_BLOCKS` (suggested 64) to bound mempool retention of deferred calls.

**State-commitment encoding** (extends §4 `d:` namespace canonical serialization):

Append, AFTER the v2.24 extended suffix (if present):

```
... existing fields through v2.24 key_history ...
|| u8(has_rate_limit)
|| (if has_rate_limit: u8(policy) || u32_be(calls_per_window) || u32_be(window_blocks)
                       || u32_be(burst_capacity) || u8(scope))
```

Conditionally serialized like the v2.24 suffix: a v2.18/v2.24 entry with no rate-limit MAY omit the suffix entirely (`has_rate_limit = 0` and no policy bytes). This preserves byte-identical state-root for non-rate-limited DApps, mirroring the v2.24 conditional-suffix convention.

**New `c:` namespace key for call counters** (`include/determ/chain/chain.hpp` chain counters map):

```
"c:dapp_calls:" + domain                        → u64_be(calls_consumed_since_registered_at)        # scope=0
"c:dapp_calls:" + domain + ":sender:" + addr    → u64_be(calls_consumed_by_sender)                  # scope=1
"c:dapp_calls:" + domain + ":topic:"  + topic   → u64_be(calls_consumed_for_topic)                  # scope=2
```

These counters are derived state — every `DAPP_CALL` apply increments the appropriate counter, every `DAPP_REGISTER` create initializes them to zero, every `DAPP_REGISTER` deactivate freezes them. The `c:` namespace is already part of the state-root (per PROTOCOL.md §4.1.1), so light clients verify counters via the existing `state_proof("c", "dapp_calls:" + domain)` path with no new RPC required.

**RPC extension `dapp_info(domain)`** returns the rate-limit policy + `available_tokens_at_current_height` + `tokens_consumed_in_current_window` so wallet UX can surface "this DApp is at 80% capacity for the current window" warnings.

**RPC new `dapp_rate_status(domain[, sender, topic])`** returns just the counter + availability snapshot — lighter than `dapp_info` for high-frequency UI polling.

#### Apply-path changes

Touch list (files in `src/chain/`, `src/node/`, `include/determ/`):

| File | Function | Change |
|---|---|---|
| `include/determ/chain/dapp.hpp` | `DAppEntry`, new `DAppRateLimit` struct | Add `rate_limit` field |
| `src/chain/transaction.cpp` | `binary_codec::encode/decode_tx` (DAPP_REGISTER payload) | Round-trip the conditional rate-limit suffix; preserve v2.18 byte-identical default |
| `src/chain/chain.cpp` | `apply_transactions` switch case for `DAPP_REGISTER` | Decode + store rate-limit; initialize `c:dapp_calls:` counter to 0 on create |
| `src/chain/chain.cpp` | `apply_transactions` switch case for `DAPP_CALL` (chain.cpp:1133-1224) | Before debit/credit: compute `available_tokens(...)`; if 0, dispatch per policy (policy=2 retains fee + drops call; policy=3 defers to mempool re-attempt; policy=1 should have been rejected at validator already, but apply double-checks); if ≥ 1, increment counter and proceed |
| `src/chain/chain.cpp` | `build_state_leaves` `d:` branch | Extend `canonical_serialize(DAppEntry)` to append conditional rate-limit suffix per §11.7.3 wire format |
| `src/chain/chain.cpp` | `build_state_leaves` `c:` branch | Include the new `c:dapp_calls:` keys when emitting chain-counter leaves |
| `src/chain/chain.cpp` | `serialize_state` / `restore_from_snapshot` | Round-trip the extended `DAppEntry` rate-limit field + the new `c:dapp_calls:` counters (closes S-037 forward for the extended schema) |
| `src/node/validator.cpp` | `validate_tx` switch case for `DAPP_CALL` | Add per-DApp admission check: compute `available_tokens(...)` against the validator's local view of `c:dapp_calls:`; if 0 and policy=1, reject with diagnostic `"DApp rate-limit exceeded; retry after window refill at height H_next"` |
| `src/node/node.cpp` | `rpc_dapp_info` | Return rate-limit policy + current available tokens + window position |
| `src/node/node.cpp` | new `rpc_dapp_rate_status` | Light-weight counter + availability snapshot |
| `tools/test_dapp_rate_limit.sh` | new | Regression: unlimited (policy=0); reject-at-validator (policy=1); reject-at-apply (policy=2); defer (policy=3); per-DApp scope; per-sender scope; per-topic scope; burst capacity; window refill; policy update mid-stream |

The validator-side admission check is the critical safety gate: a malicious sender could try to overrun the chain by submitting a burst of `DAPP_CALL`s within the mempool window before any apply takes effect. Validators maintain a transient "pending mempool admit count" per DApp (mirroring the existing S-008 mempool admission pattern) so the bucket is checked against admitted-mempool + applied-on-chain, not just applied-on-chain. This prevents a mempool-amplification attack where the validator admits 64 calls but only 1 actually applies after the bucket is full.

Producer-side: when assembling a block, the producer applies the same admission check at block-pack time (before adding a tx to `b.transactions`). This ensures all admitted txs at apply time pass the bucket check; no "tx fell out of mempool but landed in block" race.

The apply-path counter update is in the standard chain.cpp:1133-1224 DAPP_CALL apply branch; the increment is committed atomically with the debit/credit/nonce-advance, so the state-root reflects the post-apply counter.

#### Backward-compat story

This is a **soft-fork** addition under the v2.18/v2.19 substrate: no existing tx becomes invalid, no existing state_root computation changes for entries that never opt into rate-limiting. Coexistence:

- v2.19 / v2.24 nodes (which do not understand the rate-limit payload extension) decode a v2.28 DAPP_REGISTER with rate-limit declaration and treat the extra trailing bytes as unknown — depending on `binary_codec` strictness, either rejected (good, falls under the activation-height pin) or silently ignored (bad, causes state-root divergence). v2.28 must therefore roll out as a coordinated migration with a `genesis_params.dapp_rate_limit_active_from` height pin; pre-activation, the chain MUST reject any DAPP_REGISTER payload with a non-empty rate-limit suffix at validator admission.
- v2.18/v2.19/v2.24 entries (no rate-limit) materialize transparently as `rate_limit.policy = 0` (unlimited). Their state-root contribution is unchanged.
- The `c:dapp_calls:` counter additions are new keys; chains with no DApps in rate-limit policies generate zero such keys and produce byte-identical state-root contributions from the `c:` namespace.
- The behavior tightening "v2.18 implicit unlimited becomes v2.28 explicit policy-0" is purely a default; no operator action required for existing DApps.

The activation pattern parallels v2.24 DAPP_KEY_ROTATE (`genesis_params.dapp_key_rotate_active_from`), v2.27 cross-shard DAPP_CALL (`genesis_params.cross_shard_dapp_call_active_from`), A11 threshold randomness, and S-033 state_root activation.

#### Threat model

| Attack | v2.28 defense | New surface introduced |
|---|---|---|
| **Spam: attacker floods a single DApp with DAPP_CALLs to exhaust its off-chain processing capacity** | Per-DApp token bucket caps admissions at the validator + producer layer. Excess calls dropped at admission (policy=1) or apply (policy=2). Even an attacker willing to pay the §9 fee floor cannot get more than `burst_capacity` calls applied within `burst_capacity / calls_per_window` windows. The DApp's off-chain processor sees a bounded ingress rate matching its declared capacity. | None new — the §9 fee model still applies on top. The combined effect is "per-byte spam cost AND per-call capacity ceiling," tighter than either alone. |
| **Mempool amplification: attacker submits 10× the bucket capacity, banking on the validator admitting all and only the bucket-sized subset applying** | Validator tracks pending-mempool + applied-on-chain per DApp; mempool admission consumes a token. Bucket-full mempool admission rejects. The S-008 mempool bound and the v2.28 rate bucket compose: an attacker cannot inflate mempool with rejected-at-apply calls because validator drops them at admission. | The validator-side per-DApp pending count is new state. Bounded at O(num_dapps × max_pending_per_dapp); under the §9 stake floor, num_dapps is itself bounded (Sybil-equivalent threat). |
| **Cross-shard rate-limit bypass** | A cross-shard DAPP_CALL (per §11.7.2) is admitted on the source shard but applied on the destination. The destination's apply-path computes the bucket against the destination's local `c:dapp_calls:` counter. Cross-shard DAPP_CALLs increment the destination's counter on apply, identically to same-shard DAPP_CALLs. Attacker cannot bypass by routing through another shard. | The source-shard validator does NOT enforce the destination-shard rate limit (it cannot — the source's view of the destination's counter is lagged by S-016 receipt-soak latency). This means an attacker on shard A can submit `burst_capacity + N` cross-shard DAPP_CALLs targeting a DApp on shard B; the destination apply drops the excess. The source-shard fee is retained either way, so attacker still pays §9 floor. Acceptable per §11.7.2 Option B2 (trust-on-emit, validate-on-arrival). |
| **Honest DApp temporarily over-capacity (legitimate burst)** | `burst_capacity` parameter explicitly allows N-window-equivalent bursts. Operators size `burst_capacity` for realistic peak load. Policy=3 (defer) allows the chain to queue excess calls until the next refill, smoothing genuine burst patterns without forcing the operator to over-provision. | Policy=3 adds a "deferred calls" mempool retention surface; bounded by `window_blocks ≤ DAPP_RATE_DEFER_MAX_WINDOW_BLOCKS` per the validator constraint. Mempool eviction respects this — deferred calls compete for the bounded mempool space alongside regular txs. |
| **Operator misconfiguration: caps set too tight, locking out honest users** | Operator can re-issue DAPP_REGISTER with relaxed parameters at any time. Single-block remediation (next block applies new policy). UX: `dapp_rate_status` RPC + wallet warnings surface the throttling before users blame the chain. | None — this is operator-side ergonomics, not a protocol vulnerability. |
| **Counter-state bloat under scope=1 (per-sender)** | Per-(DApp, sender) buckets create one counter entry per (DApp, sender) pair. Worst case under sustained traffic: O(num_dapps × num_active_senders). The `c:dapp_calls:` namespace is part of state-root; bloat impacts every node. Mitigation: scope=1 is opt-in (default is scope=0); operators choosing scope=1 internalize the storage cost via the §9 DAPP_MIN_STAKE bond. | Yes: scope=1 raises state-storage cost per DApp roughly linearly with active sender count. Bounded in practice by chain-wide identity registration cost (S-010 / S-011 economic floor). Genesis-pinned `DAPP_RATE_PER_SENDER_MAX_BUCKETS` (suggested 65536 per DApp) limits worst case; on overflow, oldest-touched buckets evict. |
| **Scope=2 (per-topic) abuse: DApp registers many topics to give each its own bucket** | `topic_count ≤ 32` per §3.1 already caps topics per DApp. Combined with the DAPP_MIN_STAKE floor, the worst-case per-DApp scope=2 storage is 32 × counter_size = 1 KB — negligible. | None |
| **Light-client trust** | Counters live in the `c:` namespace already covered by state-root + state_proof RPC. Light clients verify rate-limit state via the same mechanism as any other counter. Operators cannot lie about historical call counts because the historical state-roots commit to the counter at each block. | None new |
| **Rate-limit declaration as a side-channel** | An operator could declare unusual rate-limit parameters as a signal (e.g., setting `calls_per_window = 0xDEADBEEF` as a sentinel). The chain validates ranges + clamps but does not interpret. Side-channel risk is operator-self-imposed; no protocol surface. | None |

The relevant cross-references in the existing threat-model docs: `proofs/Safety.md` L-1.3 (state-root inclusion of the new counter keys), `proofs/Liveness.md` L-4 (DAPP_CALLs cannot be censored arbitrarily — the rate bucket caps the operator's own self-throttling but does not give third parties a censorship handle), `SECURITY.md` §S-008 (mempool admission interaction).

#### Effort estimate

| Sub-component | Effort | Notes |
|---|---|---|
| `DAppRateLimit` struct + `DAppEntry` extension | 0.5 day | Mechanical |
| Encoder/decoder + payload conditional-suffix | 0.5 day | Mirrors v2.24 conditional-suffix pattern |
| `apply_transactions` DAPP_REGISTER extension (decode + store + init counters) | 0.5 day | New decode branch + counter initialization |
| `apply_transactions` DAPP_CALL extension (bucket check + counter increment) | 1 day | The available_tokens computation + four policy branches |
| `validate_tx` per-DApp admission check + producer-side block-pack check | 1 day | Pending-mempool count tracking; matches S-008 pattern |
| `build_state_leaves` `d:` branch extension (rate-limit conditional suffix) | 0.5 day | Preserves byte-identical state-root for non-opt-in entries |
| `build_state_leaves` `c:` branch extension (per-DApp counter keys) | 0.5 day | New key prefix in the existing chain-counter namespace |
| `serialize_state` / `restore_from_snapshot` round-trip | 0.5 day | Forward-closes S-037 for the extended schema |
| `rpc_dapp_info` extension + new `rpc_dapp_rate_status` | 0.5 day | JSON additions; mechanical |
| CLI: `determ dapp-register --rate-limit "policy=1,calls=64,window=16,burst=256,scope=0"` | 0.5 day | Wallet ergonomic |
| Regression: `tools/test_dapp_rate_limit.sh` (4 policies × 3 scopes × burst/refill scenarios) | 1.5 days | Twelve scenarios; matches v2.18 / v2.19 / v2.24 test-coverage depth |
| Migration coordination: genesis_params field + activation-height gate + documentation | 0.5 day | Same shape as v2.24 / v2.27 / A11 / S-033 activation pins |
| **Total** | **~4-6 engineering days** | Single-developer estimate; +1 day if `dapp_subscribe` (Phase 7.4 streaming) needs interop testing with deferred-policy events |

#### Dependencies

- **v2.18 DAPP_REGISTER** — shipped. Required for the registry substrate that carries the rate-limit declaration.
- **v2.19 DAPP_CALL** — shipped. Required for the call-counter increment site.
- **v2.2 state_proof RPC** — shipped. Required for light-client verification of rate-limit policy + counters via the `d:` and `c:` namespaces.
- **S-033 state_root** — shipped. Required for cross-validator agreement on counter state.
- **S-037 snapshot serialize/restore gap** — open. v2.28 should close S-037 forward for the extended `DAppEntry` schema as part of its own implementation; ideally S-037 closes first as an independent patch.
- **v2.24 DAPP_KEY_ROTATE (§11.7.1)** — adjacent, independent. v2.24 and v2.28 both extend `DAppEntry` with conditional suffixes; ordering: either can ship first, but the second ships its conditional suffix AFTER the first's in the canonical serialization to preserve compositional byte-identity.
- **v2.27 cross-shard DAPP_CALL (§11.7.2)** — adjacent, independent. v2.28's destination-shard bucket enforcement applies to v2.27 cross-shard arrivals without coordination; the source shard does not need to know the destination's bucket state.
- **v2.10 threshold randomness** — not required (bucket refill is deterministic from block height).
- **v2.14 OPAQUE** — not required.
- **v2.20 streaming `dapp_subscribe`** — not required for v2.28 itself, but policy=3 (defer) interacts with streaming subscribers: deferred calls emit to subscribers only at their actual apply height. Subscribers see a delay between submit and emit equal to the defer window; v2.20 should surface this in the subscription event metadata.

No new cryptographic primitives. No new consensus primitives. No new gossip primitives.

#### Cross-references

- §3.1 `DAPP_REGISTER` byte layout — extended here with conditional rate-limit suffix
- §3.2 `DAPP_CALL` — admission path extended with bucket check before debit/credit
- §4 `dapp_registry_` state-commitment via `d:` namespace — extended here with conditional suffix matching v2.24 convention
- §6 RPC surface — `dapp_info` extended; new `dapp_rate_status` RPC
- §7 client wallet integration — `dapp-call` CLI surfaces rate-limit-exceeded diagnostics
- §8 DApp node operation modes — Mode B/C operators can size hardware against declared rate
- §9 economic model — fee floor and per-DApp rate cap compose multiplicatively (cost × capacity = total attacker spend ceiling)
- §10 privacy + off-chain channels — rate-limited DApps can declare conservative on-chain caps and route bulk traffic through §10's direct-to-DApp pattern
- §11.7.1 DAPP_KEY_ROTATE — adjacent design; both extend `DAppEntry` with conditional suffixes
- §11.7.2 cross-shard DAPP_CALL — destination-shard buckets enforce against arriving cross-shard receipts
- §12 Q8 "Determ node bandwidth cost of carrying DApp messages" — v2.28 is the formal answer to the deferred-monitoring recommendation in Q8
- `V2-DESIGN.md` Theme 7 — formal spec for the deferred per-DApp rate-limit item
- `proofs/Safety.md` L-1.3 — state-root inclusion of the new counter keys
- `proofs/Liveness.md` L-4 — rate-limit caps operator self-throttling but is not a third-party censorship surface
- `PROTOCOL.md` §4.1.1 — `d:` and `c:` namespace canonical serialization; both extended here
- `SECURITY.md` §S-008 — mempool admission interaction (per-DApp pending-mempool tracking mirrors S-008 pattern)
- `SECURITY.md` §S-037 — forward-closes for the extended `DAppEntry` + new `c:dapp_calls:` keys
- `src/chain/chain.cpp` `apply_transactions`, `build_state_leaves` — touch sites for DAPP_REGISTER decode, DAPP_CALL bucket check, `d:` and `c:` namespace leaf emission
- `src/node/validator.cpp` `validate_tx` — touch site for per-DApp admission check
- `src/node/producer.cpp` `produce` — touch site for block-pack admission re-check
- `tools/test_dapp_rate_limit.sh` — new regression mirroring `test_dapp_register.sh` + `test_dapp_call.sh` patterns
- v2.18 / v2.19 in-process determ subcommands — pattern for `test-dapp-rate-limit`

#### Open questions deferred to implementation

- **Q1: Per-sender bucket eviction order.** With scope=1, the per-(DApp, sender) buckets can accumulate up to `DAPP_RATE_PER_SENDER_MAX_BUCKETS` entries. On overflow, what eviction policy? Options: (a) LRU by last-call-height (deterministic but requires extra state); (b) oldest-first by sender-registration order (simpler, may evict active senders); (c) hash-based pseudo-random (simplest, may evict active senders). Recommended: option (a), LRU; pays for the extra state with the most useful eviction semantics. Deferred to implementation.
- **Q2: Defer policy mempool retention.** Policy=3 (defer) requires the validator to retain rate-limited DAPP_CALLs in the mempool until the next refill window. How does this interact with the general S-008 mempool eviction? Options: (a) deferred calls live in a separate per-DApp queue, not subject to S-008 eviction; (b) deferred calls compete for S-008 mempool budget normally, may be evicted under pressure; (c) hybrid — deferred calls have a "reserved" slice of mempool capacity. Recommended: option (b), simplest and aligned with §12 Q8's "treat DAPP_CALL as regular tx". Deferred to implementation.
- **Q3: Rate limit changes mid-stream.** When a DApp updates its rate-limit policy via DAPP_REGISTER, do the existing counters reset? Options: (a) counters persist unchanged (operator-friendly: tightening cannot be retroactively gamed by submitting calls before the update); (b) counters reset to 0 on policy change (sender-friendly: a tightening operator can re-baseline). Recommended: option (a), persist. A tightening operator's intent is to reduce capacity going forward; resetting would let them effectively "re-grant" capacity by alternating tighten/loosen. Deferred to implementation.
- **Q4: Cross-shard arrival counter attribution.** A v2.27 cross-shard DAPP_CALL arriving at the destination shard at height H_dst counts against the destination's bucket. Should the counter timestamp be the source-shard's H_src (when the call was emitted) or H_dst (when it was applied)? Options: (a) H_dst — simpler, matches local apply semantics; (b) H_src — preserves the call's "logical time" but breaks the simple `(h - registered_at) / window_blocks` formula. Recommended: option (a). The CROSS_SHARD_RECEIPT_LATENCY soak window means H_dst is typically H_src + 3-5 blocks, a bounded skew. Deferred to implementation.
- **Q5: Policy=2 (reject-at-apply-with-fee-retained) UX.** Is policy=2 useful in practice, or does it amount to "fee burn for spam absorption"? The spam-absorption interpretation suggests policy=2 is the right choice for high-value DApps that want to charge attackers max-rate even when dropping their calls. The fee-burn interpretation suggests policy=1 (reject-at-validator) gives better UX without losing security. Recommended: ship both; let operators choose. Monitor real-world usage at v2.28+1 to see if one dominates.
- **Q6: Genesis preset for `DAPP_RATE_*` constants.** What are sensible defaults for `DAPP_RATE_MIN_WINDOW_BLOCKS`, `DAPP_RATE_BURST_MAX`, `DAPP_RATE_DEFER_MAX_WINDOW_BLOCKS`, `DAPP_RATE_PER_SENDER_MAX_BUCKETS`? The §11.7.3 text suggests 4 / 65536 / 64 / 65536 respectively. These should be tuned with the regional/global/cluster profile presets per `params.hpp` so the rate-limit semantics scale with the chain's block cadence. Deferred to genesis-config review during v2.28 implementation.

---

### 11.7.4 — DApp message-bus indexing + pub-sub backend: from polling to true streaming

**Tracking slot:** v2.29 (Theme 7 — DApp message-bus). Effort: ~6-8 days. Dependencies: v2.18 (DAPP_REGISTER, shipped), v2.19 (DAPP_CALL, shipped), v2.20 polling `dapp_messages` (shipped). No new cryptographic, consensus, or gossip primitives — strictly extends the indexer + RPC layers with a per-DApp+topic message index, a retention policy state machine, and a per-subscriber streaming socket with bounded queue + backpressure.

#### Problem statement

Phase 7.4 shipped only the polling subset: `dapp_messages(domain, from_height, to_height, topic)` returns up to 256 events per page, and clients re-poll periodically. The full design intent — `dapp_subscribe(domain, topic?)` streaming finalized DAPP_CALL events to a long-lived RPC socket — remains open. Beyond the missing streaming RPC, three deeper substrate gaps emerge once a chain accumulates non-trivial DApp traffic:

1. **No backend index.** Today's `dapp_messages` implementation scans the block stream linearly from `from_height` to `to_height`, filtering by `tx.to == domain` and (optionally) topic. At low volume this is acceptable; at any non-trivial scale (say, 100 DApps × 16 calls/block × 86400 blocks/day ≈ 138M calls/day) the linear scan becomes O(blocks × txs/block) per query, which is unsustainable for full-history retrospection. A DApp validator-node booting fresh and needing to replay its message history pays O(total chain volume) instead of O(its own DApp volume).
2. **No retention policy state machine.** §3.1's `retention: u8` field (0 = full, 1 = pruneable after K blocks) is currently a no-op — the field exists in `DAppEntry` and contributes to the state-root, but no apply-path or storage-layer code consumes it. A DApp that opts into pruning has no way to actually free the storage; full nodes carry every DAPP_CALL ciphertext forever. This contradicts the §3.1 contract and §10's pointer-pattern recommendation for large payloads (the pointer pattern is moot if the chain keeps the pointer references forever anyway).
3. **No structured backpressure on streaming.** The §6 `dapp_subscribe` thumbnail mentions "bounded per-subscriber queue with disconnect-on-overflow" but does not specify queue depth, drop policy, gap-recovery, or subscriber resync semantics. Without these, a streaming RPC is either trivially unsafe (unbounded queue grows until OOM) or trivially unusable (every subscriber gets disconnected under any traffic burst).

This matters because:

- **L2 / zk-VM and DSSO patterns** (§1) are predicated on the chain providing a reliable, queryable message bus. An L2 batch-commitment indexer needs to replay every batch DAPP_CALL since genesis; a DSSO RP needs to filter every challenge/response pair targeting it.
- **Federation Coordinator DApps** (§14) emit governance + identity-linking DAPP_CALLs that must remain queryable for federation audit purposes. Cross-deployment manifest hash verification depends on the DApp's message history being recoverable.
- **The §11.7.4 polling-only substrate** is acceptable for early-stage DApps with sparse traffic but is the limiting factor preventing graduation to high-throughput production use.

The v2.29 message-bus flow resolves this by: (a) standing up a per-DApp+topic LSM-style index keyed by `(domain, topic, height, intra_block_index)` with optional in-memory bloom filters for fast existence checks; (b) implementing the §3.1 retention policy as a height-windowed pruner that walks the index + block bodies + state_root contribution; (c) shipping the streaming `dapp_subscribe` RPC with explicit backpressure, gap detection, and resync-from-height semantics.

#### Mechanism sketch

**(a) Per-DApp+topic message index.** A persistent index on disk (one file per DApp, LSM-tree organized by `(topic, height, intra_block_index)`), maintained by an indexer process running alongside the chain. The indexer subscribes to the existing per-block hook (the same hook that fires after `enqueue_save` per Phase 2C). For each block finalized, the indexer:

1. Iterates `b.transactions` filtering `tx.type == DAPP_CALL`.
2. For each matching tx, computes the index key `(tx.to, topic, b.index, tx_index)` and writes a 32-byte entry: `(tx_hash[16], offset_into_block_body[8], ciphertext_size[4], flags[4])`. The ciphertext stays in the block body on disk; the index just points at it.
3. Optionally bumps an in-memory bloom filter `(domain, topic_byte_prefix) → bloom32` so existence queries hit the bloom first and skip the disk seek on misses.
4. Commits the index update atomically with the chain.save tip update — index-tip-height invariant: `index_tip >= chain_tip - 1` (one-block lag tolerated for crash recovery).

The indexer is **derived state**: it is reconstructible from the block stream alone, does NOT contribute to the state-root (no new namespace key), and can be rebuilt by a node operator without consensus interaction. A snapshot bootstrap (`SNAPSHOT_RESPONSE` per §11 of PROTOCOL.md) does not need to include the indexer state; the receiver rebuilds the index from the block stream as it catches up. This is the cleanest separation: the chain commits to message ORDER + CONTENT (block bodies + tx_root + state_root); the index is just a node-local performance optimization.

**(b) Retention policy state machine.** The §3.1 `retention: u8` field gains real semantics:

- `retention = 0` (full, default): block bodies for DAPP_CALL txs are retained indefinitely. Same as today.
- `retention = 1` (pruneable after K blocks): block bodies for DAPP_CALL txs targeting this DApp are eligible for pruning K blocks after their inclusion. The chain MUST retain the block header + tx_root + state_root + the tx's hash (in `applied_inbound_receipts_` for cross-shard, in `tx_root` Merkle leaf for same-shard) so the inclusion proof remains verifiable; only the ciphertext bytes are reclaimed. K is chain-default `DAPP_RETENTION_PRUNE_BLOCKS` (suggested 50000 ≈ ~3 days on regional profile), genesis-pinned, governance-mutable per Q2.
- `retention = 2` (operator-pinned-window): operator declares a retention window `W` blocks at DAPP_REGISTER time. The chain prunes ciphertext W blocks after inclusion. W is clamped to `[DAPP_RETENTION_MIN_BLOCKS, DAPP_RETENTION_MAX_BLOCKS]` (suggested 100 / 10_000_000).
- `retention = 3` (rolling-cap): operator declares a maximum total stored bytes for this DApp's history. When the cap is reached, oldest ciphertexts are pruned first. Cap clamped to `[DAPP_RETENTION_CAP_MIN_BYTES, DAPP_RETENTION_CAP_MAX_BYTES]` (suggested 1 MB / 100 GB). This is the "S3-class object-store" model — most useful for high-volume DApps that need a bounded operational footprint.

Pruning runs as an async background worker (mirrors the existing `enqueue_save` worker pattern; no consensus path interaction). The worker:

1. Iterates `dapp_registry_` entries with `retention != 0`.
2. For each pruneable DApp, walks the per-DApp index for entries past the retention threshold.
3. For each eligible entry, locates the ciphertext in the block body, overwrites it with a deterministic sentinel `b"\xFF\xFF\xFF\xFF" + sha256(original)[:28]` (32 bytes), and marks the index entry's flags `PRUNED = 0x01`.
4. The sentinel preserves block-body byte-length invariants (no block-hash recomputation needed; the block-hash is computed over `block_digest` which already excludes ciphertext content per §4.1 — see PROTOCOL.md). The block's `tx_root` Merkle leaf is computed over the original ciphertext hash, which is preserved in the sentinel's hash suffix; inclusion proofs verify against the original hash.
5. `dapp_messages` returning a pruned entry omits the ciphertext field and sets `"pruned": true`; light clients see "this DApp call was included at height H but its content has been pruned per the retention policy."

The retention policy itself is committed via the `d:` namespace state-root (the existing v2.18 encoding already includes `retention`). A DApp operator changing retention via DAPP_REGISTER update applies prospectively — already-pruned ciphertexts cannot be un-pruned, but the new policy takes effect from the update's apply height.

**(c) Streaming `dapp_subscribe` RPC with backpressure.** The streaming RPC connects to the same HMAC-RPC-authenticated socket as other RPCs (per S-001), subscribes to one or more (domain, topic?) pairs, and receives newline-JSON events as blocks finalize. Wire shape:

```
// client → server
{"jsonrpc":"2.0","method":"dapp_subscribe","params":{
    "domain":"foo.example",
    "topic":null,                       // null = all topics
    "from_height": 12345,               // optional; null = "from current tip"
    "include_pruned": false             // omit events whose ciphertext has been pruned
},"id":42}

// server → client (one line per event)
{"jsonrpc":"2.0","id":42,"result":{"event":"dapp_call","block_index":12346,"intra_block_index":3,
    "tx_hash":"...","from":"alice.example","to":"foo.example","topic":"orders",
    "amount":100,"ciphertext":"<hex>","source_shard":2}}
{"jsonrpc":"2.0","id":42,"result":{"event":"resync_marker","up_to_height":12345}}
{"jsonrpc":"2.0","id":42,"result":{"event":"backpressure_dropped","first_lost":12500,"count":42}}
```

Backpressure: each subscription owns a bounded per-subscriber queue of depth `DAPP_SUBSCRIBE_QUEUE_DEPTH` (suggested 1024 events) on the server side. When the queue fills (subscriber is slow), the server's options:

- **Drop-oldest mode (default).** Server drops events from the front of the queue and emits a single `backpressure_dropped` event summarizing the gap when the queue drains. Subscriber knows it missed events and can rebind via `dapp_messages` for the lost range.
- **Disconnect mode (opt-in via subscription parameter `on_full: "disconnect"`).** Server closes the connection. Subscriber reconnects with `from_height = last_received + 1`.
- **Pause mode (opt-in via `on_full: "pause"`).** Server pauses sending; subscriber's TCP receive window naturally throttles. Only safe if the subscriber will eventually catch up; risk is server-side queue accumulation if subscriber is permanently slow.

The `from_height` parameter enables **gap-recovery**: a subscriber that missed events (server restart, network blip, backpressure-drop) reconnects specifying `from_height = last_known_good_height + 1`. The server serves the indexed range first (replaying historical events), then transitions to live streaming when caught up. A `resync_marker` event marks the boundary.

Per-subscription rate-limit: a single RPC connection MUST NOT subscribe to more than `DAPP_SUBSCRIBE_MAX_PER_CONN` (suggested 32) DApp+topic pairs. Aggregate subscriber count is bounded by the RPC layer's existing connection cap (per S-014 per-peer-IP token bucket).

#### Wire-format changes

**No on-chain wire changes.** The §3.1 DAPP_REGISTER and §3.2 DAPP_CALL byte layouts are unchanged. The indexer is derived state; retention semantics are an apply-path interpretation of the existing `retention: u8` field; streaming RPC is a node-local concern, not a consensus surface.

**RPC additions** (`src/node/node.cpp`):

- `dapp_subscribe(domain, topic?, from_height?, on_full?, include_pruned?)` — new long-lived streaming method.
- `dapp_messages` (existing) gains optional pagination cursor `after_token: string` returning a server-generated opaque token to enable seek-based pagination over the index, replacing the current limit-256-per-call offset-style. Backward-compat: omit `after_token` to get the v2.20 behavior.
- New `dapp_index_status(domain?)` — returns indexer health: `{index_tip, chain_tip, lag, bloom_hit_rate, prune_eligible_count}`.

**Index file format** (`<data_dir>/dapp_index/<domain>.idx`):

```
[file header: 64 bytes]
    magic:           u64_be  "DAPPIDX1"
    domain_hash:     32 B    SHA256(domain) for tamper-detection
    schema_version:  u32_be  starts at 1
    flags:           u32_be  reserved
    last_indexed_height: u64_be
    entry_count:     u64_be

[entries: 64 bytes each, sorted by (topic_hash, height_be, intra_block_index_be)]
    topic_hash:           16 B    SHA256(topic)[:16]; sentinel 0x00*16 for "no topic"
    height:               u64_be
    intra_block_index:    u32_be
    tx_hash:              16 B    first 128 bits of tx_hash (collision-tolerant for indexing)
    offset_into_block_body: u32_be
    ciphertext_size:      u32_be
    flags:                u32_be  PRUNED | CROSS_SHARD | other
    reserved:             u32_be  alignment

[bloom filter: 4 KB per (domain, topic) pair, optional]
```

Sorted-by-key layout permits O(log n) seek for `(topic, from_height)` range queries via binary search. The index is rewritten on each compaction pass (background); a small write-ahead log (`<domain>.idx.wal`) accumulates new entries since the last compaction and is merged on startup or every `DAPP_INDEX_COMPACT_INTERVAL_BLOCKS` (suggested 10000).

#### Apply-path integration

Touch list (files in `src/chain/`, `src/node/`, `include/determ/`):

| File | Function | Change |
|---|---|---|
| `include/determ/chain/dapp.hpp` | `DAppEntry` | No struct change; the `retention` field already exists |
| `src/chain/chain.cpp` | `apply_transactions` DAPP_CALL apply branch (chain.cpp:1133-1224) | No change to apply semantics; ciphertext storage remains in `b.transactions[*].payload` |
| `src/chain/chain.cpp` | `serialize_state` | No change; index is derived, not state-root committed |
| `src/node/node.cpp` | `enqueue_save` post-hook | New hook: after a block is durably saved, fire the indexer with `(b, block_offset_in_chain_file)` |
| `src/node/dapp_indexer.cpp` (new) | `DAppIndexer::on_block(Block, offset)` | Iterate `b.transactions`, append matching DAPP_CALLs to the per-DApp WAL, update in-memory bloom, periodically compact |
| `src/node/dapp_indexer.cpp` (new) | `DAppIndexer::query(domain, topic?, from_height, to_height, limit, after_token?)` | Bloom-check existence; if present, binary-search the index; return up to `limit` results + next `after_token` |
| `src/node/dapp_indexer.cpp` (new) | `DAppIndexer::run_pruner()` | Async background worker; walks pruneable DApps, applies retention policy, overwrites ciphertext with sentinel, marks index entry `PRUNED` |
| `src/node/node.cpp` | `rpc_dapp_messages` | Replace linear-scan with `DAppIndexer::query()`; preserve v2.20 response shape; add `after_token` cursor support |
| `src/node/node.cpp` | new `rpc_dapp_subscribe` | Long-lived RPC method; allocates per-subscriber queue; subscribes to the per-block hook; serves historical-then-live transitions; honors backpressure policy |
| `src/node/node.cpp` | new `rpc_dapp_index_status` | Returns indexer health JSON |
| `include/determ/chain/params.hpp` | constants | Add `DAPP_RETENTION_PRUNE_BLOCKS`, `DAPP_RETENTION_MIN_BLOCKS`, `DAPP_RETENTION_MAX_BLOCKS`, `DAPP_RETENTION_CAP_MIN_BYTES`, `DAPP_RETENTION_CAP_MAX_BYTES`, `DAPP_SUBSCRIBE_QUEUE_DEPTH`, `DAPP_SUBSCRIBE_MAX_PER_CONN`, `DAPP_INDEX_COMPACT_INTERVAL_BLOCKS` |
| `tools/test_dapp_index.sh` | new | Regression: indexer correctness, bloom-filter false-positive bound, compaction idempotence, crash-recovery from WAL |
| `tools/test_dapp_subscribe.sh` | new | Regression: streaming delivery, backpressure-drop, gap-recovery via `from_height`, pause-mode, disconnect-mode |
| `tools/test_dapp_retention.sh` | new | Regression: retention=1/2/3 prune semantics, sentinel hash preservation, inclusion-proof preservation post-prune |

The indexer is implemented as a separate `.cpp` file behind a `DAppIndexer` class. The chain layer is unchanged at the apply path — the indexer only consumes the existing post-save block hook. This preserves the cleanest possible separation: a node operator could disable the indexer entirely (and fall back to the v2.20 linear scan) without affecting consensus.

#### Backward-compat story

This is a **soft, node-local addition** under the v2.18/v2.19/v2.20 substrate: no consensus change, no wire change, no state-root change. Coexistence:

- v2.20 nodes (without the indexer) continue to serve `dapp_messages` via linear scan. Their responses are byte-identical to v2.29 nodes for the same query when both nodes have all the requested history. v2.29 nodes are simply faster.
- The retention policy is the one **breaking** change: a chain that activates retention pruning at height `genesis_params.dapp_retention_active_from` MUST coordinate this — v2.20 nodes that don't prune will diverge from v2.29 nodes that do, because the v2.20 block bodies retain the original ciphertext while v2.29 block bodies have the sentinel. **Critical:** the sentinel approach was chosen specifically so that the BLOCK HASH does not change (block_digest excludes ciphertext content per §4.1 / PROTOCOL.md), so the v2.20 vs v2.29 divergence is in block-body bytes-on-disk only, not in consensus state. A v2.20 node fetching a snapshot from a v2.29 node receives the sentinel-overwritten ciphertext; queries against pruned entries return `"pruned": true` on both versions. **This relies on the §4.1 block_digest invariant holding rigorously** — if any future protocol change adds ciphertext bytes to the digest, this design must be revised.
- Coordination: an activation-height pin (`genesis_params.dapp_retention_active_from`) ensures all nodes prune on the same schedule. Pre-activation, `retention != 0` declarations in DAPP_REGISTER are accepted but the prune worker is dormant.
- Streaming `dapp_subscribe` is purely additive; v2.20 clients ignore the new RPC method.

The activation pattern parallels v2.24 / v2.27 / v2.28 / A11 / S-033 activation pins.

#### Threat model

| Attack | v2.29 defense | New surface introduced |
|---|---|---|
| **Indexer-corruption attack on a single node** | The indexer is derived state. A node operator who detects corruption (`dapp_index_status` reports inconsistent `index_tip` vs `chain_tip`) can wipe `<data_dir>/dapp_index/` and rebuild from the block stream. No consensus impact; no neighbor-node impact. | None — indexer is derived state. |
| **Light-client trust on pruned messages** | The block's `tx_root` Merkle leaf is computed over `SHA256(tx)` which includes the original ciphertext. Post-prune, the sentinel's hash suffix preserves the original SHA256's first 28 bytes; a light client verifying inclusion via tx_root can compare against the sentinel-stored hash. The first 4 bytes of the sentinel (`0xFFFFFFFF`) are a magic prefix signaling "this is a pruned ciphertext" so an honest decoder distinguishes pruned from corrupted. | Light clients learn an additional rule: ciphertext starting with `0xFFFFFFFF` is pruned-content sentinel, not real ciphertext. Documented in PROTOCOL.md §11 retention extension. |
| **Subscriber DoS: malicious subscriber holds the streaming socket open without reading** | Bounded per-subscriber queue (default 1024 events). Drop-oldest policy reclaims memory automatically. Disconnect-mode opt-in for operators who prefer hard cuts. The S-014 per-peer-IP token bucket caps connection establishment rate so an attacker cannot rotate connections to keep many slow-reader queues alive. | Yes: per-subscriber queue is new server-side state. Bounded by `DAPP_SUBSCRIBE_QUEUE_DEPTH × max_subscribers`. Worst case ~1024 × 1024 events × ~200 B each = ~200 MB across all subscribers, acceptable for a production full node. |
| **Indexer-state-bloat attack: attacker creates many DApps + topics to maximize index file count + bloom filter memory** | Indexer state is bounded by `(num_dapps × num_topics_per_dapp)` which is itself bounded by `DAPP_MIN_STAKE` (§9 Sybil floor) and `topic_count ≤ 32` per DApp (§3.1). Worst case: `DAPP_MAX_REGISTRY_SIZE × 32` index files. At reasonable parameters (say 65536 DApps × 32 topics × 4 KB bloom each) the bloom filter aggregate is ~8 GB, manageable but non-trivial; full nodes opting out of bloom filters fall back to disk seek. | Yes: aggregate bloom-filter memory grows linearly with chain-wide DApp + topic count. A node operator can disable bloom filters globally (`Config::dapp_indexer_bloom_enabled = false`) trading query latency for memory. |
| **Replay-old-ciphertext after prune** | The sentinel's hash suffix commits to the original SHA256. A third party who has the original ciphertext stored off-chain can re-publish it; verifiers compare its SHA256 to the sentinel's hash suffix and confirm it matches the originally-included ciphertext. This is consistent with the §10 "the chain is permanent ciphertext storage" caveat — pruning frees the chain's local copy but does NOT make the ciphertext truly unrecoverable. | None new — pruning is a node-local storage reclaim, not a confidentiality primitive. |
| **Retention-policy abuse: operator declares `retention=3` cap=1 MB to keep their own history minimal but spams enormous individual payloads** | The per-call MAX_DAPP_CALL_PAYLOAD (§3.1, 16 KB suggested) caps individual payloads. The combined effect is that a DApp with cap=1 MB and 16 KB per call retains at most ~64 calls, rotating older ones out. This is operator-side policy; not a third-party abuse vector. | None |
| **Subscriber gap-recovery race** | A subscriber reconnects with `from_height = last_received + 1`. The server serves the indexed range from `from_height` to `current_tip`, then transitions to live. During the historical replay, new live events queue behind. The `resync_marker` event marks the transition. A subscriber that crashed mid-replay can re-reconnect with the same `from_height`; replay is idempotent. | None — gap recovery is deterministic from the indexed history. |
| **Pruned-content-claims-malicious-content scenario** | A user who included a DAPP_CALL with payload P that was later pruned cannot deny inclusion (the tx_hash + tx_root Merkle leaf prove inclusion). They CAN claim "the content was different" because only the sentinel hash is recoverable. The chain's audit-trail commitment is therefore preserved at the hash level but loses content-level commitment for pruned items. Operators choosing `retention != 0` accept this tradeoff. | This is a deliberate tradeoff in the §3.1 retention contract; users should understand that opting into a pruning DApp means their post-prune-window content claims are hash-only. UX surface: wallet warns "this DApp prunes messages after X blocks" at DAPP_CALL submit time. |
| **Backpressure-drop event injection by adversarial subscriber** | The `backpressure_dropped` event is server-generated; subscribers cannot forge it. A subscriber receiving a `backpressure_dropped` event whose `count > 0` knows it missed events and can `dapp_messages` for the lost range to recover. | None |

The relevant cross-references in the existing threat-model docs: `proofs/Safety.md` L-1.3 (state-root is preserved regardless of retention pruning because retention only touches block bodies, not the state-root commitment), `proofs/CrossShardReceipts.md` T-5 (cross-shard DAPP_CALL inclusion proofs survive pruning because the source-block tx_root is preserved), `SECURITY.md` §S-001 (HMAC-RPC auth covers the new streaming socket), §S-014 (per-peer-IP rate limit covers new connections), §S-008 (mempool admission unchanged).
### 11.7.5 — DApp economic primitives: staking-bound registration + on-chain fee-share

**Tracking slot:** v2.30 (Theme 7 — DApp economics). Effort: ~6-8 days. Dependencies: v2.18 (DAPP_REGISTER, shipped), v2.19 (DAPP_CALL, shipped); v2.24 (DAPP_KEY_ROTATE, spec'd §11.7.1) provides the slashing event surface this section operationalizes. No new cryptographic primitives. Genesis-pinned activation height required.

#### Problem statement

§9 lays out the v2.18 / v2.19 baseline economics: `DAPP_REGISTER` requires the owning domain to hold `DAPP_MIN_STAKE` (≥ 10× normal MIN_STAKE), `DAPP_CALL` pays a regular `tx.fee` to validators, and DApp operators set their own pricing off-chain. Three substantive gaps remain:

1. **The "stake bond" is currently a passive eligibility check, not a bond.** Today's path: a DApp operator's owning domain has stake ≥ `DAPP_MIN_STAKE` at the time of `DAPP_REGISTER`; nothing locks that stake to the registration. The operator can `UNSTAKE` immediately after registering, drop below the floor, and continue operating until the next call inspects the threshold. §9 acknowledges this gap implicitly ("slashable on misbehavior — see below") but defers actual bond semantics.
2. **No on-chain fee-share between subscriber-paid DApp calls and the DApp operator.** A common DApp business model: subscribers pre-pay a periodic subscription (e.g., per-month flat fee), in exchange the DApp accepts their `DAPP_CALL`s without per-call billing. v2.19's `tx.amount`-as-payment pattern handles per-call payment cleanly, but the **subscription** pattern requires either off-chain accounting (which forfeits the chain's audit trail) or a chain-of-`COMPOSABLE_BATCH` workaround. A native primitive is missing.
3. **Refundable graceful deregistration is undocumented.** §9 mentions DApp-side stake as "skin in the game" but never specifies whether deregistering returns the bond. v2.18's `op=1` deactivation merely sets `inactive_from`; the stake remains locked indefinitely (or worse, freed only when the operator runs a separate `UNSTAKE`, with no enforced cooldown).

This problem matters because: (a) any DApp ecosystem with non-trivial economics will see operators wanting to declare their bond commitment explicitly (the same way bond-and-bail is explicit in user-identity REGISTER); (b) subscription DApps are a strict superset of per-call DApps in commercial deployment patterns (CBDC RP, oracle subscriptions, B2B settlement); (c) the §11.7.1 emergency-revoke event has no concrete slashing target without an explicit bond.

The v2.30 design pins all three: bond is locked on `DAPP_REGISTER`, fee-share is declared per-DApp at registration and applied at apply-time, deregistration releases the bond after a cooldown.

#### Mechanism sketch

**Bond locking.** `DAPP_REGISTER` `op=0` (create) gains a `bond_amount` field. On apply, the chain debits `bond_amount` from the owning domain's spendable balance into a per-DApp `dapp_bond_locked_` field. The `Stake` ledger separately holds the `DAPP_MIN_STAKE` eligibility check (unchanged from v2.18); the new `bond_amount` is in **addition to** the stake and is operationally distinct (the bond is **slashable** per §9's slashable conditions and §11.7.1 emergency-revoke; the stake remains a generic identity primitive).

**Fee-share declaration.** `DAPP_REGISTER` gains a `subscription_policy` substructure declaring (a) flat-rate model parameters (per-block period, per-period fee, max subscribers), or (b) per-call model parameters (per-call min/max amount), or (c) hybrid. Subscribers explicitly subscribe via a new `DAPP_SUBSCRIBE` tx that locks `n × period_fee` from the subscriber's balance and credits the DApp operator's account at every period boundary (the chain runs the credit as part of `apply_block_finalization`, the same hook that already runs equivocation-slash payouts).

**Refundable graceful deregister.** `DAPP_REGISTER` `op=1` (deactivate) now sets `inactive_from = current_height + GRACE_PERIOD` AND `bond_unlock_at = inactive_from + DAPP_BOND_UNLOCK_COOLDOWN_BLOCKS`. The bond becomes withdrawable via a separate `DAPP_BOND_WITHDRAW` tx at any height ≥ `bond_unlock_at`. If any open subscriber refund is owed at deactivation, the chain auto-credits subscribers their remaining `subscription_balance` at `inactive_from` from the bond (the bond is the secondary insurance behind the operator's balance for refunds).

#### Wire-format changes

**Extension to `DAPP_REGISTER` payload** (§3.1) — appended after the existing `metadata` field:

```
... existing fields through metadata ...
[bond_amount: u64 LE]               # additional bond (≥ DAPP_MIN_BOND); 0 = bond-less (pre-v2.30 compat)
[subscription_policy_kind: u8]      # 0 = none (per-call only), 1 = flat, 2 = hybrid
[if kind == 1 or 2:                 # flat-fee parameters
  [period_blocks: u32 LE]           # period length (e.g., 21600 ~ 1 day at 4s block time)
  [period_fee: u64 LE]              # fee per period per subscriber
  [max_subscribers: u32 LE]         # 0 = unlimited
  [min_periods: u8]                 # minimum subscription commitment (anti-churn; 0 = no min)
]
[if kind == 0 or 2:                 # per-call parameters
  [per_call_min: u64 LE]            # minimum tx.amount accepted on DAPP_CALL (0 = no floor)
  [per_call_max: u64 LE]            # maximum tx.amount accepted on DAPP_CALL (0 = no cap)
]
[fee_share_validator_bp: u16 LE]    # basis-points of DAPP_CALL.fee credited to producer (default 10000 = 100%);
                                    # remainder credited to dapp_operator_balance as protocol-distributed share.
                                    # Range: [0, 10000]. NOT a tax — this is the operator's voluntary cut to keep
                                    # the producer subsidy at par. Capped genesis-side: fee_share_validator_bp ≥ MIN_FEE_BP (suggested 5000)
```

**New `DAPP_SUBSCRIBE` tx type** (extends §3 enum):

```cpp
enum class TxType : uint8_t {
    ...existing 0..11 (incl. DAPP_KEY_ROTATE = 11 from §11.7.1)...,
    DAPP_SUBSCRIBE   = 12,   // open / extend / cancel a subscription
    DAPP_BOND_WITHDRAW = 13, // withdraw bond after deregister cooldown
};
```

**`DAPP_SUBSCRIBE` payload:**

```
[op: u8]                  # 0 = subscribe, 1 = extend (top up), 2 = cancel (graceful)
[dapp_domain_len: u8]
[dapp_domain: utf8]       # target DApp domain (must be a current DAPP_REGISTER)
[periods: u32 LE]         # number of periods to subscribe/extend (≥ DApp's min_periods on op=0)
[subscriber_pubkey: 32B]  # the subscriber identity (== tx.from in v2.30; reserved for delegation in v2.30.1)
```

**`DAPP_BOND_WITHDRAW` payload:**

```
[dapp_domain_len: u8]
[dapp_domain: utf8]       # must equal tx.from (only owning domain may withdraw its bond)
[amount: u64 LE]          # ≤ remaining unlocked bond balance; 0 = withdraw all
```

**State-commitment encoding** (extends §4 `d:` namespace canonical serialization, appended after the §11.7.1 `key_history` suffix when present):

```
... existing canonical_serialize(DAppEntry) including §11.7.1 suffix ...
|| u64_be(bond_amount)
|| u64_be(bond_unlock_at)
|| u64_be(subscription_policy_kind)
|| u64_be(period_blocks) || u64_be(period_fee) || u64_be(max_subscribers) || u64_be(min_periods)
|| u64_be(per_call_min) || u64_be(per_call_max) || u64_be(fee_share_validator_bp)
|| u64_be(active_subscriber_count)
```

Conditional-serialization rule (mirrors §11.7.1): the extension MAY be omitted if `bond_amount == 0 && subscription_policy_kind == 0 && fee_share_validator_bp == 10000 && active_subscriber_count == 0`. Pre-v2.30 entries default to this state, preserving state_root byte-for-byte across the activation height.

Subscribers are committed via a NEW state-Merkle namespace `"u:"` (subscription map): `"u:" + dapp_domain || subscriber_pubkey → SHA-256(canonical_serialize(SubscriberEntry))` where `SubscriberEntry = {periods_remaining, subscription_started_at, next_credit_at, periods_paid}`. This keeps the per-DApp entry size O(1) regardless of subscriber count; subscribers are individual leaves.

#### Apply-path changes

| File | Function | Change |
|---|---|---|
| `include/determ/chain/transaction.hpp` | `TxType` enum | Add `DAPP_SUBSCRIBE = 12`, `DAPP_BOND_WITHDRAW = 13` |
| `include/determ/chain/dapp.hpp` | `DAppEntry`, new `SubscriberEntry`, new `SubscriptionPolicy` struct | Add `bond_amount`, `bond_unlock_at`, `subscription_policy`, `active_subscriber_count` |
| `src/chain/transaction.cpp` | `binary_codec::encode/decode_tx` | Add `DAPP_SUBSCRIBE` + `DAPP_BOND_WITHDRAW` payload cases; extend `DAPP_REGISTER` decoder for new tail fields |
| `src/chain/chain.cpp` | `apply_transactions` switch — `DAPP_REGISTER` case | Debit `bond_amount` from sender's spendable balance, write to `dapp_registry_[from].bond_amount`. Validate `bond_amount ≥ DAPP_MIN_BOND` (genesis-pinned). Validate `fee_share_validator_bp ≥ MIN_FEE_BP` |
| `src/chain/chain.cpp` | `apply_transactions` switch — `DAPP_REGISTER op=1` case | Set `inactive_from = h + GRACE_PERIOD` and `bond_unlock_at = inactive_from + DAPP_BOND_UNLOCK_COOLDOWN_BLOCKS`. Trigger subscriber refunds if `subscription_policy.kind != 0` (credit each subscriber `periods_remaining × period_fee` from the bond; if bond insufficient, prorate) |
| `src/chain/chain.cpp` | `apply_transactions` switch — `DAPP_CALL` case | If recipient DApp has `subscription_policy.kind ∈ {1, 2}` AND sender has an active subscription (`subscribers_[dapp][sender].periods_remaining > 0`), accept the call with no `tx.amount` requirement. Else fall through to the existing per-call flow (with `per_call_min`/`per_call_max` enforcement). Validator-fee credit: `floor(fee × fee_share_validator_bp / 10000)` to producer; remainder to `accounts_[dapp].balance` |
| `src/chain/chain.cpp` | new switch case — `DAPP_SUBSCRIBE` | Validate target DApp, validate `periods ≥ min_periods`, debit `periods × period_fee` from sender, insert/update `subscribers_[dapp][sender]`. Increment `dapp_registry_[dapp].active_subscriber_count`. Reject if `active_subscriber_count + 1 > max_subscribers` |
| `src/chain/chain.cpp` | new switch case — `DAPP_BOND_WITHDRAW` | Validate `tx.from == dapp_domain`, validate `h ≥ bond_unlock_at`, validate `amount ≤ dapp_registry_[dapp].bond_amount`. Credit sender's balance, debit bond |
| `src/chain/chain.cpp` | new hook in `apply_block_finalization` | At each block finalize, iterate `subscribers_` map (keyed by `next_credit_at == h`): credit `period_fee` to `accounts_[dapp].balance` for each active subscriber whose `next_credit_at == h`, decrement `periods_remaining`. Bounded O(N_subs_due_this_block); use the same indexing pattern as per-block subsidy distribution |
| `src/chain/chain.cpp` | `build_state_leaves` | Add `u:` namespace for `subscribers_`; extend `d:` namespace canonical serializer for the conditional bond/policy tail |
| `src/chain/chain.cpp` | `serialize_state` / `restore_from_snapshot` | Round-trip `subscribers_` and the extended `DAppEntry` fields. Forward-closes S-037 (and pairs with §11.7.1's similar requirement for `key_history`) |
| `src/node/validator.cpp` | `validate_tx_shape` | Reject `DAPP_REGISTER` where `bond_amount > tx.from.balance` at admission time. Reject `DAPP_SUBSCRIBE` to inactive DApp |
| `src/node/node.cpp` | `rpc_dapp_info` | Include `bond_amount`, `bond_unlock_at`, `subscription_policy`, `active_subscriber_count`, `fee_share_validator_bp` in JSON response |
| `src/node/node.cpp` | new `rpc_dapp_subscriptions(domain)` | Return paginated subscriber list with `periods_remaining` per subscriber (RPC for DApp operator monitoring) |
| `tools/test_dapp_economics.sh` | new | Regression: bond lock on register; bond refund on deregister; subscription credit cadence; per-call min/max enforcement; refund-from-bond on emergency deactivate |

The new hook in `apply_block_finalization` is the most novel piece — it's the first per-block scheduled operation that operates over a map keyed by `next_credit_at`. This is a standard "due-this-block" pattern; the bounded-O(N_due) cost is OK because `N_due ≤ DAPP_MAX_REGISTRY_SIZE × max_subscribers_per_dapp` (genesis-pinned). For an over-pessimistic upper bound: 10K DApps × 10K subscribers each due in a single block = 100M operations. The mitigation is the per-DApp `next_credit_at` cadence being inherently staggered (different DApps register at different heights), so amortized per-block cost is O(N_dapps).

#### Backward-compat story

**Soft-fork under v2.18 substrate** — but with a height-pinned activation per the §11.7.1 / A11 / S-033 pattern. Coexistence:

- v2.18 nodes (do not understand `DAPP_SUBSCRIBE`, `DAPP_BOND_WITHDRAW`, or the extended `DAPP_REGISTER` tail) treat the new tx types as unknown and reject the containing block. **Breaking** consensus change; v2.30 must roll out as a coordinated migration with a `genesis_params.dapp_economics_active_from` height pin.
- Until that height, the chain MUST reject `DAPP_SUBSCRIBE` / `DAPP_BOND_WITHDRAW` AND MUST treat the `DAPP_REGISTER` extended tail as malformed (decoder bounded to the v2.18 length).
- After activation: existing v2.18 `DApp` entries materialize transparently as `bond_amount = 0, subscription_policy.kind = 0, fee_share_validator_bp = 10000, active_subscriber_count = 0`. The conditional-serialization rule keeps their state_root contribution unchanged.
- Existing DApps MAY opt-in to bond + subscription post-activation by issuing a `DAPP_REGISTER` `op=0` update with the new fields populated. The `bond_amount` debit lands at the update height; subscriptions accept new subscribers from that point.

#### Threat model

| Attack | v2.30 defense | New surface introduced |
|---|---|---|
| **Economic griefing — operator deregisters mid-subscription period, walks with subscriber funds** | Subscriber refund is auto-credited from the operator's bond at deactivation (apply_transactions §`DAPP_REGISTER op=1` case). Refund amount = `periods_remaining × period_fee` per subscriber. If bond insufficient (operator's bond was already drained), refunds prorate from the available bond; the residual loss is slashable against the operator's separate stake per §9. | Operator MAY set `bond_amount` arbitrarily low (e.g., bond=0 with hybrid `subscription_policy.kind=2`). Mitigation: validator rejects `DAPP_REGISTER` where `subscription_policy.kind != 0 && bond_amount < DAPP_MIN_BOND_PER_SUBSCRIPTION = period_fee × MIN_BOND_COVERAGE_MULTIPLIER × max_subscribers` (recommended `MIN_BOND_COVERAGE_MULTIPLIER = 4`, i.e., enough bond to cover 4× the worst-case all-subscribers-cancel scenario). Genesis-pinned. |
| **Stake-stealing — adversary observes a DApp's UNSTAKE then races to send DAPP_CALL when the operator falls below the stake floor** | `DAPP_MIN_STAKE` is checked at apply-time of every `DAPP_REGISTER op=0` (existing v2.18 behavior); bond is an ADDITIONAL `bond_amount` that the operator cannot reduce by UNSTAKE (it's debited from spendable, not from stake). So the operator can UNSTAKE freely without affecting the bond. Adversary cannot drain the bond unless they're the owning domain. | Adversary acquires the operator's owning-domain key → can drain bond via `DAPP_BOND_WITHDRAW`. Same threat as drain-via-TRANSFER (already accepted in v2.18). Mitigation: high-stakes operators use the §11.7.1 `rotation_pubkey` model and keep the owning-domain key cold. The `bond_unlock_at` cooldown gives the operator detection time — a withdraw attempt during the cooldown window is rejected; only post-cooldown withdraws succeed, giving a multi-block window for the operator to issue an emergency-revoke `DAPP_KEY_ROTATE` and recover. |
| **Free-rider — subscriber opens minimum subscription, makes maximum DAPP_CALLs in the period, cancels before the next period** | Subscribers commit `periods × period_fee` upfront on `DAPP_SUBSCRIBE`; cancellation does NOT refund. The DApp operator collected the period_fee at subscription time. The DApp's volume is bounded only by its own DAPP_CALL admission policy. | Cancellation as op=2 is graceful (subscriber stops receiving credit but DApp keeps already-paid fees). An "abusive" subscriber rapidly makes calls in the first block of a period — the DApp must enforce its own per-block per-subscriber call limit (orthogonal to chain rate-limiting per §11.7.3). The chain's only commitment is fee collection, not call-rate enforcement per subscription. |
| **Bond griefing — flood `DAPP_REGISTER` updates with high bond_amounts to lock operator capital** | `DAPP_REGISTER op=0` updates do NOT change the bond (operator chooses bond at create; updates preserve existing bond). To change bond, operator submits two txs: `DAPP_BOND_WITHDRAW` (partial) THEN `DAPP_REGISTER op=0` with the new bond. So bond-griefing requires two consecutive tx slots and the bond debit is from the operator's own balance — self-griefing. | None — same authorization as any owner-controlled tx. |
| **Subscription squatting — subscriber subscribes to a DApp they don't intend to use, hoping to deny others (under max_subscribers cap)** | `DAPP_SUBSCRIBE` debits `periods × period_fee` immediately. Squatting costs real funds, and the squatter forfeits those funds (no refund on cancel). For small `max_subscribers` (e.g., 100-subscriber exclusive DApp), squatting attack cost = `period_fee × min_periods × max_subscribers`. Operator can set `min_periods` to make squatting expensive (recommended for exclusive DApps). | Operator could collude with subscribers to squat (artificial scarcity). Same surface as any free-market subscription system; not a protocol concern. |
| **Subscribers map state bloat** | Per-DApp `max_subscribers` cap (operator-set, validator-enforced). Per-chain global cap `DAPP_GLOBAL_MAX_SUBSCRIBERS = 10M` enforced via `active_subscriber_count` summed across all DApps in `dapp_registry_`. Auto-pruned at subscription-expiry (when `periods_remaining → 0` the `SubscriberEntry` is erased from `subscribers_`). | The `u:` namespace adds a state-Merkle namespace; light-client proofs of subscription status now require `state_proof("u:", dapp || subscriber)`. Acceptable extension; v2.2 light-client RPC already handles arbitrary namespaces. |
| **Fee-share parameter manipulation** | `fee_share_validator_bp ≥ MIN_FEE_BP` floor (genesis-pinned, suggested 5000 = 50%) prevents operators from setting the validator share too low (which would otherwise undermine producer economics). Operators MAY freely give MORE than the floor to validators; the floor is a minimum. | Operators MAY set `fee_share_validator_bp = MIN_FEE_BP` to keep the maximum DApp share. This is by design — DApps can configure their economic relationship with validators within the bounded floor. |
| **DApp operator stake misalignment with bond** | The bond and the v2.18 `DAPP_MIN_STAKE` are independent. An operator with bond=0 still meets the stake floor (and can register). The bond is **operator's voluntary commitment** to fee-share / subscription users; it's only mandatory if `subscription_policy.kind != 0` (validator-enforced). | Per-call DApps (no subscriptions) have no bond requirement, matching v2.18 behavior. The bond is opt-in, mandatory only for subscription DApps. |

The cross-references in existing threat-model docs: `proofs/AccountStateInvariants.md` for the bond + balance invariant (bond is a non-spendable balance shard; the operator's `accounts_[dapp].balance + dapp_bond_locked_[dapp] = total operator-controlled funds`), `proofs/EquivocationSlashing.md` for the bond-as-slash-target (analogous to validator stake), `SECURITY.md` §S-007 for overflow checks (`bond_amount + balance + stake` overflow on register).

#### Effort estimate

| Sub-component | Effort | Notes |
|---|---|---|
| `DAppIndexer` class + file format + WAL | 2 days | Disk format, compaction, crash-recovery |
| Per-block hook integration in `enqueue_save` | 0.5 day | Mechanical; mirrors existing chain.save flow |
| Bloom filter + binary-search query path | 1 day | Standard bloom-32 implementation; sorted-key binary search |
| Retention policy state machine + async pruner | 1.5 days | Iterate DApps, walk index, sentinel-overwrite ciphertext, mark PRUNED |
| `rpc_dapp_messages` cutover from linear-scan to indexer | 0.5 day | Preserve v2.20 response shape; add `after_token` cursor |
| `rpc_dapp_subscribe` streaming with backpressure | 1.5 days | Long-lived socket, bounded queue, three drop policies, gap recovery |
| `rpc_dapp_index_status` + monitoring hooks | 0.5 day | Health JSON; integration with existing metrics |
| Genesis-params + activation-height for retention | 0.5 day | Same shape as v2.24 / v2.27 / v2.28 / A11 / S-033 pins |
| Regressions: `test_dapp_index.sh`, `test_dapp_subscribe.sh`, `test_dapp_retention.sh` | 2 days | Three full scripts covering correctness + crash recovery + retention semantics + streaming backpressure |
| **Total** | **~6-8 engineering days** | Single-developer estimate; +1 day if integration with §11.7.3 deferred-policy events needs joint subscribe testing |

#### Dependencies

- **v2.18 DAPP_REGISTER** — shipped. Required for `retention` field semantics.
- **v2.19 DAPP_CALL** — shipped. Required for the message stream the indexer consumes.
- **v2.20 polling `dapp_messages`** — shipped. v2.29 cutover preserves response shape + adds cursor.
- **Phase 2C lock-free reader path** — shipped. Required for `rpc_dapp_index_status` to query `dapp_registry_` without blocking apply.
- **§4.1 block_digest invariant** — shipped, MUST hold. Pruning relies on ciphertext bytes being absent from block_digest so the block hash is preserved post-prune. Any future protocol change adding ciphertext to the digest requires revising this design.
- **S-014 per-peer-IP token bucket** — shipped. Caps streaming-connection establishment rate.
- **S-033 state_root + S-038 producer-side wiring** — shipped. v2.29 does NOT extend state_root; retention pruning is local-storage-only.
- **§11.7.1 DAPP_KEY_ROTATE, §11.7.2 cross-shard, §11.7.3 rate-limit** — adjacent, all independent. v2.29 can ship in any order relative to these; the indexer's per-block hook is policy-agnostic.
- **v2.10 threshold randomness** — not required.
- **v2.14 OPAQUE** — not required.

No new cryptographic primitives. No new consensus primitives. No new gossip primitives.

#### Cross-references

- §3.1 `DAPP_REGISTER` `retention: u8` field — v2.29 implements the field's semantics for the first time (v2.18 reserved the field; v2.29 wires it to the pruner)
- §3.2 `DAPP_CALL` payload — unchanged; v2.29 is purely indexer/RPC/retention infrastructure
- §6 RPC surface — `dapp_subscribe` upgraded from "pending" to "specified"; `dapp_messages` gains `after_token` cursor; new `dapp_index_status`
- §10 off-chain large payloads (pointer pattern) — v2.29 makes the pointer pattern operationally meaningful by allowing the on-chain pointer to be pruned per retention policy
- §11 Phase 7.4 — v2.29 IS the formal spec for Phase 7.4's "streaming subscription pending" subset
- §11.7.1 DAPP_KEY_ROTATE — orthogonal; rotation is control plane, indexer is data plane
- §11.7.2 cross-shard DAPP_CALL — v2.29's per-DApp index handles cross-shard arrivals via the `source_shard` field already in `dapp_messages`
- §11.7.3 per-DApp rate-limit — orthogonal; rate-limit caps admission, indexer indexes whatever is admitted
- §12 Q8 "Determ node bandwidth cost of carrying DApp messages" — v2.29 retention pruning is part of the answer (along with §11.7.3 rate-limiting)
- `V2-DESIGN.md` Theme 7 — formal spec for Phase 7.4 streaming + the deferred message-bus indexing item
- `proofs/Safety.md` L-1.3 — state-root preserved across retention pruning (pruning touches block bodies only, not state-root inputs)
- `proofs/CrossShardReceipts.md` T-5 — cross-shard inclusion proofs survive pruning
- `PROTOCOL.md` §4.1 block_digest invariant — load-bearing for the post-prune block-hash preservation
- `PROTOCOL.md` §11 snapshot field set — v2.29 indexer is derived state, NOT in snapshot (rebuilt at boot)
- `SECURITY.md` §S-001 HMAC-RPC — covers the new streaming socket
- `SECURITY.md` §S-014 per-peer-IP token bucket — covers new connection establishment
- `src/node/node.cpp` `enqueue_save` post-hook — touch site for the indexer subscription
- `src/node/dapp_indexer.cpp` — new file; class + file format + WAL + bloom + pruner
- `tools/test_dapp_index.sh`, `test_dapp_subscribe.sh`, `test_dapp_retention.sh` — new regressions

#### Open questions deferred to implementation

- **Q1: Bloom filter sizing per-(domain, topic) vs per-domain.** Per-(domain, topic) bloom (4 KB each) gives faster topic-specific queries; per-domain bloom (4 KB total) saves memory but costs an extra index seek for topic-misses. Recommended: per-(domain, topic) for high-volume DApps, per-domain for low-volume. Operators tune via `Config::dapp_indexer_bloom_granularity` (default: per-domain; auto-promote to per-(domain, topic) at >100K calls per DApp). Deferred to implementation.
- **Q2: Retention-policy governance-mutability.** `DAPP_RETENTION_PRUNE_BLOCKS` and the cap constants are tuning knobs. Genesis-pinned (simpler) or governance-mutable via PARAM_CHANGE (more flexible)? Per §12 Q2 precedent (DAPP_CALL payload cap is recommended governance-mutable), recommended: governance-mutable. Deferred to genesis-config review.
- **Q3: Subscriber checkpointing.** Should the server periodically emit "checkpoint" events letting subscribers persist last-good-height to disk and resume after crashes? Or is it the subscriber's responsibility to track? Recommended: subscriber-tracked (simpler protocol); server emits a checkpoint event every N blocks (suggested 1024) as a convenience. Deferred to implementation.
- **Q4: Cross-shard synthetic DAPP_CALL indexing (interaction with §11.7.2).** A cross-shard DAPP_CALL arriving at the destination shard materializes as a synthetic event. The destination's indexer SHOULD index these alongside same-shard DAPP_CALLs (with `source_shard != my_shard`). The source shard's indexer SHOULD ALSO index the outbound DAPP_CALL (it's still in the source block's `b.transactions`) for source-shard audit purposes. Both indexer paths are derived state; both rebuild from block stream. Recommended: index on both sides. Deferred to implementation.
- **Q5: Compaction storm risk.** If multiple DApps' indexes hit the `DAPP_INDEX_COMPACT_INTERVAL_BLOCKS` boundary simultaneously, compaction storms could spike disk I/O. Mitigation: stagger compaction via a per-DApp hash-based offset (compact at `(block_index + hash(domain) mod interval) % interval == 0`). Recommended: stagger. Deferred to implementation.
- **Q6: Subscriber authentication on the streaming socket.** The HMAC-RPC auth (S-001) is per-request; a long-lived streaming socket needs a different auth model (one-time auth at subscribe, or periodic re-auth). Recommended: one-time auth at subscribe; the existing RPC connection's HMAC handshake covers the subscription's authority; subsequent events on the same socket inherit it. Deferred to implementation.
- **Q7: Retention activation height vs already-existing DApps.** When `genesis_params.dapp_retention_active_from` activates, existing DApps with `retention != 0` declared pre-activation should be pruneable. But should their already-included calls (from before activation) be retroactively pruned, or only calls from `activation_height` onwards? Recommended: prospective only — calls from before `activation_height` are retained regardless of declared retention. Avoids retroactive surprise for early DApp users. Deferred to genesis-config review.
| Enum + payload struct extensions (`DAPP_REGISTER` tail, `DAPP_SUBSCRIBE`, `DAPP_BOND_WITHDRAW`) | 1 day | Mechanical; mirrors §11.7.1 shape |
| Encoder/decoder + payload validation (including the conditional-tail rule) | 1 day | Bond-related range checks, fee_share floor enforcement, subscription_policy validation |
| `apply_transactions` switch cases (`DAPP_SUBSCRIBE`, `DAPP_BOND_WITHDRAW`) | 1 day | Bond debit / refund, subscription map insert/erase |
| `apply_block_finalization` per-block credit hook | 1 day | New per-block scheduled operation; performance-test the staggered cadence under 10K-DApp / 10K-subscriber-each scenarios |
| `DAPP_REGISTER op=1` refund-on-deactivate logic | 0.5 day | Iterate subscribers for this DApp, credit each refund, debit bond |
| `build_state_leaves` extension (`u:` namespace + `d:` tail extension) | 1 day | Preserves v2.18 state_root byte-for-byte for non-economic DApps |
| `serialize_state` / `restore_from_snapshot` round-trip (subscribers + extended `DAppEntry`) | 0.5 day | S-037 forward-closure |
| `rpc_dapp_info` extension + new `rpc_dapp_subscriptions` | 0.5 day | JSON additions; mechanical |
| CLI: `determ dapp-subscribe`, `determ dapp-bond-withdraw`, `determ dapp-register` extended flags | 0.5 day | Wallet ergonomic |
| Regression: `tools/test_dapp_economics.sh` (bond lock, refund, subscription cadence, free-rider, bond griefing, fee-share split) | 1.5 days | Six scenarios |
| Migration coordination: `genesis_params.dapp_economics_active_from` + activation-height gate + documentation | 0.5 day | Same shape as the §11.7.1 / A11 / S-033 activation pin |
| **Total** | **~6-8 engineering days** | Single-developer estimate; +1-2 days if performance test reveals the per-block credit-hook cost needs optimization |

#### Dependencies

- **v2.18 DAPP_REGISTER** — shipped. Required.
- **v2.19 DAPP_CALL** — shipped. Required; per-call fee-share path is the v2.30 extension's primary apply site.
- **v2.24 DAPP_KEY_ROTATE** (§11.7.1) — spec'd. Optional but **strongly recommended**; the §11.7.1 emergency-revoke event is the natural slashing trigger that v2.30 operationalizes. Shipping order: v2.30 can ship before v2.24 (bond + fee-share works standalone); v2.24's slashing path becomes more meaningful when bond is present.
- **v2.2 state_proof RPC** — shipped. Required for `u:` namespace light-client proofs.
- **S-037** — open. v2.30 implementation MUST round-trip `subscribers_` + extended `DAppEntry` in snapshot serialize/restore or it inherits S-037's symptom (state_root mismatch on snapshot restore for any DApp that exercised economic primitives). Recommended: ship S-037 fix BEFORE v2.30 activation, so the new substrate doesn't ship with a known latent bug.
- **v2.4 COMPOSABLE_BATCH** — shipped. Recommended for the `DAPP_REGISTER op=1` + immediate `DAPP_BOND_WITHDRAW` atomic deregister-and-withdraw flow (legal AFTER bond_unlock_at, atomic ergonomic).
- **v2.10 threshold randomness** — not required.
- **v2.14 OPAQUE** — not required.

No new cryptographic primitives. No new consensus primitives. No new gossip primitives. Strictly extends `dapp_registry_` and adds a new `subscribers_` map (both in `Chain`).

#### Cross-references

- §3.1 `DAPP_REGISTER` payload — extended with bond + subscription_policy + fee_share_validator_bp tail
- §3.2 `DAPP_CALL` apply path — extended with subscription-bypass-of-amount-requirement + producer fee-share split
- §4 `dapp_registry_` state-commitment via `d:` namespace — extended with conditional tail; new `u:` namespace for subscribers
- §6 RPC surface — `rpc_dapp_info` extended; new `rpc_dapp_subscriptions(domain)`
- §9 Economic model — v2.30 supersedes the v2.18 sketch with concrete bond + fee-share + refund primitives. §9's "DApp operators charge their users... per-DAPP_CALL via tx.amount field" remains valid; v2.30 adds the subscription model alongside. §9's "no DApp slashing — just stake-as-bond" is updated: bond IS slashable (via §11.7.1 emergency-revoke + the bond-deficit-on-refund mechanism above)
- §11.7.1 `DAPP_KEY_ROTATE` — slashing event surface this section operationalizes
- §11.7.2 cross-shard DAPP_CALL — fee-share split applies to cross-shard receipts the same way (producer share to source-shard producer, DApp share to destination-shard DApp; cross-shard receipt extended one u64 for the split-deferred fee)
- §11.7.3 per-DApp rate limit — orthogonal; rate-limit caps admission, economic primitives cap pricing
- §11.7.4 message-bus indexing — orthogonal; indexer indexes whatever subscribers paid for
- §12 Q4 (anon DApp calls) — anonymous subscribers MAY subscribe via anon `tx.from`; the `subscribers_[dapp][anon_addr]` entry tracks an unknown identity. Economic primitives are agnostic to identity model
- `V2-DESIGN.md` Theme 7 — formal spec for the deferred "DApp economic primitives" item
- `proofs/AccountStateInvariants.md` — bond + balance invariant (bond is non-spendable; total operator-controlled funds = balance + stake + bond)
- `proofs/Safety.md` L-1.3 — state-root inclusion of `subscribers_` map
- `SECURITY.md` §S-007 — overflow checks on `bond_amount + balance + stake` at register
- `SECURITY.md` §S-037 — forward-closes the snapshot-serialize/restore gap for the extended schema
- `PROTOCOL.md` §4.1.1 — `d:` namespace canonical serialization extended; new `u:` namespace added
- `src/chain/chain.cpp` `build_state_leaves`, `apply_transactions`, `apply_block_finalization` — touch sites
- `tools/test_dapp_register.sh` + `tools/test_dapp_call.sh` — sibling regression patterns; `tools/test_dapp_economics.sh` mirrors their shape

#### Open questions deferred to implementation

- **Q1: Subscription billing model — period-boundary credit (chosen) vs continuous accrual.** Period-boundary is simpler (credit at `next_credit_at == h`); continuous accrual gives finer-grained refunds at mid-period cancellation but adds per-block per-subscriber computation. Chosen: period-boundary. Refunds at cancellation are zero (per-period commitment); refunds at operator-side deactivation are `periods_remaining × period_fee`. Deferred: revisit if a use case demands mid-period refunds (e.g., regulated payments where consumer refund rights override).
- **Q2: Fee-share precision — basis points (chosen) vs floating-point.** Basis points (u16 in [0, 10000]) give 0.01% granularity; floating-point invites consensus-divergence risks (different rounding across platforms). Chosen: basis points. The arithmetic `floor(fee × bp / 10000)` is deterministic.
- **Q3: Bond denomination — native token (chosen) vs separate bond token.** Same native token as TRANSFER / fees keeps the economic substrate uniform; a separate bond token would require new genesis primitives. Chosen: native token. Operators can convert via market mechanisms if they wish.
- **Q4: Multi-DApp subscriptions per subscriber.** A subscriber MAY subscribe to multiple DApps; each generates a separate `subscribers_[dapp_i][subscriber]` entry. No protocol-level limit on per-subscriber subscription count. Deferred: revisit if state-bloat from subscription-heavy users becomes an issue (current cap is per-DApp `max_subscribers`, not per-subscriber `max_dapps_subscribed`).
- **Q5: Subscription delegation.** v2.30 reserves `subscriber_pubkey` as a separate field from `tx.from` to allow future delegation (e.g., a corporate domain pays for an employee's individual subscription). v2.30.0 enforces `subscriber_pubkey == tx.from`. v2.30.1 will relax this. Deferred to v2.30.1.
- **Q6: Activation height vs already-existing DApps.** v2.18 entries default to `bond_amount = 0, subscription_policy.kind = 0`. Per the §11.7.4 Q7 precedent, prospective-only is recommended: existing pre-activation DApps remain bond-less unless they explicitly opt in via a `DAPP_REGISTER op=0` update. Deferred to genesis-config review.
- **Q7: Bond reduction without full withdraw.** Operator MAY want to reduce bond from B to B' < B without deregistering. Current spec requires `DAPP_BOND_WITHDRAW` (cooldown-gated) + new `DAPP_REGISTER` (re-register with B'). A `DAPP_BOND_ADJUST` tx (op=0 increase, op=1 decrease-with-cooldown) would be cleaner. Deferred: ship without; revisit if operators report friction.
- **Q8: Auditable subscription cancellation reason.** Like §11.7.1 `reason` field, `DAPP_SUBSCRIBE op=2` (cancel) could carry an optional `reason: utf8` field for off-chain compliance / analytics. Not safety-critical. Deferred to v2.30.1.

---

## 12. Open design questions

### Q1: Should DApp domains share namespace with user domains?

**Option A:** Yes — DApp `dapp.example` and user `alice.example` are the same namespace. Pro: simple, reuses REGISTER. Con: namespace squatting confusion.
**Option B:** No — DApps in `dapp.*` namespace, users in `user.*`. Pro: clearer separation. Con: protocol-level namespace dictate.

**Recommendation:** Option A. The DApp's REGISTER + DAPP_REGISTER combo distinguishes via the existence of a registry entry. UX clients can label.

### Q2: Should DAPP_CALL payload size cap be genesis-pinned or governance-mutable?

**Genesis-pinned:** simpler. Hard limit set forever.
**Governance-mutable (via PARAM_CHANGE):** flexibility but adds governance surface.

**Recommendation:** Governance-mutable. Cap is a chain-economics tuning knob, same category as MIN_STAKE.

### Q3: Should the chain enforce DApp topic-routing rules, or treat topics as informational?

**Enforce:** validator rejects DAPP_CALL with `topic` not in DApp's registered set. Pro: clean contract. Con: DApps can't add new topics without re-registering.
**Informational:** chain records topic, DApp filters off-chain.

**Recommendation:** Enforce. Re-registering is cheap (just a new DAPP_REGISTER tx) and the contract is stronger.

### Q4: Anonymous DApp calls?

If `tx.from` is an anon (bearer) address, the DApp can't tie the call to a registered identity. Is this allowed?

**Recommendation:** allow by default; let DApps opt out via a registry flag `accept_anon: bool`. Anon DApp calls are valuable for privacy-preserving DApps (anonymous oracles, anon polling, etc.).

### Q5: Reply-routing — how does a DApp know where to reply?

**Option A:** Reply via `DAPP_CALL` from the DApp's domain back to the user's domain. Standard on-chain reply.
**Option B:** Reply off-chain via a callback URL the user includes in the encrypted payload.

**Recommendation:** Both. Option A is the trustless default; Option B is the optional fast path for off-chain channels.

### Q6: How does a DApp prove "I saw this call" or "I processed this call"?

For audit / compliance, a DApp may want to commit to processing decisions on-chain. A `DAPP_ACK` or signed-response tx pattern.

**Recommendation:** v2.X.0 doesn't address this. DApps can post their own ack txs as `DAPP_CALL` from the DApp back to the user; convention not protocol.

### Q7: Migration / DApp deprecation strategy

When a DApp goes offline, what happens to pending DAPP_CALL txs in the gossip mempool?

**Recommendation:** validator rejects DAPP_CALL where `tx.to`'s DApp entry has `inactive_from <= current_height`. Pending txs in mempool are dropped at validation. Clients see a "DApp inactive" error on submit.

### Q8: Determ node bandwidth cost of carrying DApp messages

A high-volume DApp could saturate gossip with `DAPP_CALL` txs. Even with the min-fee floor, sustained legitimate volume might dwarf payment txs.

**Recommendation:** track and monitor. If problematic, introduce a per-DApp gossip-priority lane (low-priority DAPP_CALL evicts first under mempool pressure). Not a v2.X.0 concern.

---

## 13. Closure / cross-references

This design extends Determ to support an application ecosystem WITHOUT becoming a programmable platform. The chain stays in its lane (payments + identity); DApps live alongside (off-chain logic anchored to on-chain identity + messaging).

**Builds on:**
- [v2.4 `COMPOSABLE_BATCH`](../include/determ/chain/block.hpp) — atomic payment-plus-message bundling
- [v2.2 state_proof RPC](../src/node/node.cpp) — DApp registration verification for light clients
- v2.1 state Merkle root — DApp registry committed in `state_root`
- Existing REGISTER + identity stack — DApp identities are just registered domains
- Phase 2A/2B/2C lock-free reader path — DApp queries don't block apply

**Does NOT require:**
- Smart contracts (no on-chain DApp execution)
- New consensus primitives (regular block consensus suffices)
- New cryptographic primitives (Ed25519 + libsodium sealed-box are existing)
- Protocol breaking changes (just two new tx-type slots and a new state field)

**Estimated total cost (Phases 7.1 through 7.4):** 8-10 days focused work. Phase 7.5+ is ecosystem-driven and uncapped.

---

## 14. Cross-deployment federation DApp (canonical pattern, v3-deferred ecosystem deliverable)

Federation across multiple Determ deployments — shared identity, federated DSSO, cross-deployment audit, federation governance — is **delivered as a Theme-7 DApp**, not as a protocol feature. The substrate primitives shipped in v2 + Theme 9 + Phase D are sufficient; no protocol-level changes are required.

**Status: v3-deferred ecosystem deliverable.** Not on the Determ team's protocol roadmap. Documented here as a canonical pattern so that operator consortiums have a reference design when commercial demand surfaces (regulated-vertical multi-jurisdiction deployments, CBDC federations, industry consortium payment rails). Estimated effort: ~1.5-2 months operator-side per federation. Multiple federation DApps can coexist with different governance, audit, and identity-linking policies — the protocol substrate doesn't constrain federation policy.

**Why v3-deferred rather than current scope:**
- No documented commercial partnership currently demands it
- Building federations before real deployment partnerships exist risks designing for hypothetical use cases
- DApp-layer position lets each consortium tailor the federation to their specific regulatory / operational needs
- Protocol substrate is ready *today* (v2.18 + v2.19 + v2.23 + v2.25 + v2.26 already shipped or spec-resolved); consortiums can build whenever their commercial timing aligns

### 14.1 Motivation

A Determ deployment is an island by default — its own genesis, its own chain_id, its own committee, its own identity registry, its own DSSO scope. v2.23 cross-chain bridge enables value transfer between Determ deployments, but identity remains per-deployment. Several commercial patterns need more:

- **Per-jurisdiction regulated deployments interoperating.** UK-licensed gambling Determ + Malta-licensed Determ + Singapore-licensed Determ — federated for player KYC + cross-jurisdiction settlement, separate for jurisdictional compliance.
- **National CBDC federations.** Multiple country-level CBDCs federated for cross-border identity verification, separate for monetary policy.
- **Industry consortium payment rails.** Banks A, B, C each run their own Determ deployment with own customer data + audit relationships, federated for inter-bank settlement.
- **Multi-region single-organization deployment.** One organization running deployments in EU / US / APAC for data-residency compliance, federated for unified customer experience.

The shared structural concern: **users registered on deployment A want to be recognizable on deployment B** without trusting any single party.

### 14.2 Pattern

Each federation member deployment registers a **Federation Coordinator DApp** via v2.18 DAPP_REGISTER. The DApp's identity (`service_pubkey` + `endpoint_url`) is published on its host chain. Across federation members, the DApps coordinate via DAPP_CALL messages + v2.23 bridge primitives.

**On-chain state (per deployment):**

```
FederationCoordinator (DApp identity) {
  service_pubkey: Ed25519                 // registered via v2.18 DAPP_REGISTER
  endpoint_url:   string                  // off-chain coordination endpoint
  manifest_hash:  Hash                    // current federation manifest digest
}
```

**Off-chain state (held by each deployment's Federation Coordinator DApp):**

```
FederationManifest {
  members: [
    {
      chain_id:           string
      deployment_genesis: Hash             // chain identity anchor
      coordinator_dapp:   PubKey           // DApp identity on that chain
      bridge_endpoint:    string           // v2.23 bridge endpoint
      auditor_pubkeys:    [PubKey ...]     // federation-scope auditor(s)
    },
    ...
  ],
  admission_quorum:   u32                  // K-of-N for new member admission
  governance_version: u64                  // monotonic version
}
```

The manifest is published off-chain (e.g., via IPFS, HTTP, or distributed via DAPP_CALL gossip) and its hash is committed on each member chain via the Federation Coordinator's published `manifest_hash` field. Members verify manifest authenticity by:
1. Fetching the manifest from any source
2. Computing its hash
3. Comparing against `manifest_hash` published by the local Federation Coordinator

### 14.3 Operations

**Member admission (federation governance):**

1. Prospective new member submits `PROPOSE_MEMBER` via DAPP_CALL to each existing Federation Coordinator
2. Existing members verify the prospective member's chain (genesis hash matches claimed deployment, coordinator DApp registered) via v2.23 light-client proof against the prospective member's chain
3. Existing members each submit `VOTE_MEMBER` co-signing approval
4. When K-of-N approval threshold reached, each member's Federation Coordinator updates the manifest and publishes the new `manifest_hash` on-chain

**Identity linking (user-facing):**

1. User registers normally on deployment A (gets on-chain anon or registered identity per v1.x REGISTER tx)
2. User wants their identity recognized on deployment B
3. User submits a `LINK_IDENTITY` DAPP_CALL on deployment B's Federation Coordinator, including a v2.23 light-client proof that the user is registered on deployment A at height H
4. Federation Coordinator on deployment B verifies the proof against deployment A's committee-signed header (via the bridge's light-client mesh)
5. On verification, deployment B's Federation Coordinator publishes a linked-identity record on its chain (via DAPP_CALL emitting a state change in the DApp's off-chain database, with a hash committed on-chain)

**Federated DSSO assertion:**

1. User authenticates via T-OPAQUE on deployment A (per v2.25 DSSO)
2. Determ A's K-of-K committee issues a deployment-A-scope assertion
3. The Federation Coordinator DApp on A submits the assertion to other federation members via DAPP_CALL
4. Each receiving Federation Coordinator co-signs at federation scope (DApp's service_pubkey signs over the assertion + federation manifest hash)
5. Relying parties on any federation member verify the federation-scope assertion against the local Federation Coordinator's published service_pubkey

**Cross-deployment audit:**

1. Federation members co-decide on auditor pubkey(s) at manifest level
2. Each member chain updates its v2.24 `audit_view_master_pk` field for federation-scope accounts to delegate to the federation auditor
3. Auditor's view-key reads audit data across all federation members via per-deployment v2.24 audit-mode RPC
4. Coordination logic (which auditor reads which deployment, when, for what purpose) is DApp policy, not protocol enforcement

### 14.4 What's protocol-supported vs DApp-supported

| Capability | Protocol-enforced | DApp-enforced |
|---|---|---|
| Cross-deployment value transfer | ✅ v2.23 bridge with light-client proofs | — |
| Cross-deployment identity claims | Proof verification via v2.23 | Federation coordinator decides which claims are accepted |
| Federation-scope DSSO assertions | DApp service_pubkey signature | Federation coordinator co-signing logic |
| Cross-deployment audit disclosure | v2.24 per-account `audit_view_master_pk` | Federation-level auditor designation |
| Member admission/removal | — | Federation coordinator K-of-N voting |
| Federation manifest | Hash committed on-chain via DApp registration | Off-chain replication + verification |
| Dispute resolution | — | DApp governance logic |

### 14.5 What this pattern does NOT deliver

**Validator portability.** Validators staked on deployment A cannot serve deployment B's committee selection. Slashing economics are per-chain by design (mutual-distrust isolation between deployments). A federation DApp can signal which validators are federation-active (informational metadata), but the actual committee-eligible set remains per-chain. This is the one federation capability that would require protocol-level cross-deployment slashing economics — which break the mutual-distrust isolation between deployments and have no documented commercial use case demanding them.

**Atomic cross-federation governance.** Federation manifest updates require K-of-N coordination across member chains; this happens via DAPP_CALL + manifest re-publication. A member chain that doesn't update its manifest hash promptly creates a temporary inconsistency. DApp-layer resolution (e.g., "members must update within N blocks or lose federation-active status") suffices for most cases; protocol-level atomicity isn't structurally available without breaking per-deployment autonomy.

**Forced compliance.** Federation members can publish federation policies (audit cadence, KYC requirements, etc.) in the manifest, but enforcement is DApp-layer trust — relying parties verify against the manifest; bad members can be voted out. Cryptographic enforcement is limited to what v2.22/v2.24 already provide (auditor view-key disclosure).

These limitations are acceptable for documented commercial use cases. Federations form among parties who already have off-chain legal relationships (regulatory licensing, consortium agreements, multi-org governance); DApp-layer trust composes with those existing relationships.

### 14.6 Estimated implementation cost

| Sub-component | Effort (operator/consortium side) |
|---|---|
| Federation Coordinator DApp (service code, manifest management) | 2-3 weeks |
| Federation governance logic (admission, voting, removal) | 1-2 weeks |
| Identity-linking flow | 1 week |
| Federation-scope DSSO assertion logic | 1 week |
| Cross-deployment audit coordination | 1 week |
| Testing + integration | 1-2 weeks |

**Total: ~1.5-2 months** per federation, operator-side (each consortium builds their own Federation Coordinator DApp tailored to their use case). The Determ protocol provides the substrate; the consortium provides the policy.

Multiple federation DApps can exist concurrently — a gambling federation, a CBDC federation, a B2B-payment federation could each run independently with different governance, audit rules, and identity-linking semantics. The protocol doesn't pick winners.

### 14.7 Composition with other Theme-7 patterns

A Federation Coordinator DApp can compose with:
- **Direct-to-DApp delivery (§10):** federation-coordinator-to-coordinator messages ride libsodium sealed-box for confidentiality
- **zk-VM L2 (§1, §10):** an L2 deployed across multiple federation members can use the federation as its identity layer
- **Theme 9 DSSO:** federation extends DSSO from per-deployment to per-federation scope
- **Cross-shard DApp calls (§10):** within a single federation member, cross-shard DApp routing works as documented; federation-coordinator DApp can span shards via existing mechanisms

These compositions are off-the-shelf — no special protocol awareness required.

### 14.8 Cross-references

- `V2-DESIGN.md` "Recommended sequencing → What is explicitly NOT in this sequencing" — explicit deferral statement: federation is DApp-layer, not protocol
- `V2-DESIGN.md` v2.18 / v2.19 / v2.23 / v2.25 / v2.26 — substrate primitives the Federation Coordinator builds on
- `plan.md` — federation is not on the protocol roadmap; it's tracked here as an ecosystem-product pattern

---

*End of document.*
