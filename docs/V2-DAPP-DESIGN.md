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

Where `canonical_serialize` is:
```
service_pubkey || u64_be(registered_at) || u64_be(active_from) || u64_be(inactive_from)
  || u64_be(endpoint_url.size()) || endpoint_url
  || u64_be(topics.size()) || (each: u64_be(topic.size()) || topic)
  || u8(retention)
  || u64_be(metadata.size()) || metadata
```

Light clients prove DApp registration via `state_proof` RPC (just shipped, reuses the existing primitive).

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

Cross-shard adds latency (1-2 blocks on destination) but is otherwise identical to in-shard.

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

Phased shipping plan, each phase is a single bounded commit:

### Phase 7.1 — `DAPP_REGISTER` tx + on-chain DApp registry (~2 days)

- New `TxType::DAPP_REGISTER` + `DAppEntry` struct + `dapp_registry_` member on Chain
- Wire-format encode/decode helpers
- Validator: shape check + REGISTER-precondition + stake check
- Apply path: insert/update/deactivate
- Integration with `build_state_leaves` (new `"d:"` namespace leaf)
- Phase 2A/2B lazy-snapshot integration
- New RPC: `dapp_info(domain)`, `dapp_list()`
- Regression: in-process CLI test (`determ test-dapp-register`)

### Phase 7.2 — `DAPP_CALL` tx + payload routing (~2 days)

- New `TxType::DAPP_CALL` + payload encoding
- Validator: must-resolve-to-active-DApp + payload size cap + topic match
- Apply path: amount credit (TRANSFER-like) + nonce advance
- Anti-spam: chain-wide `DAPP_CALL` min-fee
- New RPC: `dapp_messages(domain, from_height, to_height, topic)` — paginated retrospective query
- Regression: in-process CLI test (`determ test-dapp-call`)
- Wallet CLI: `determ dapp-call`, `determ dapp-info`

### Phase 7.3 — Lock-free DApp reader path (~1 day)

- Extend `CommittedStateBundle` to include `dapp_registry_`
- `dapp_info_lockfree` accessor on Chain
- Rewire `dapp_info` RPC to use the lock-free path
- ~30 LOC, mechanical

### Phase 7.4 — Streaming subscription RPC (~3 days)

- `dapp_subscribe(domain, topic?)` — newline-JSON streaming over the RPC socket
- Node-side: a per-block hook fires after `enqueue_save`; subscribers' filters check `tx.to == domain` for each DAPP_CALL in the new block
- Backpressure: bounded per-subscriber queue with disconnect-on-overflow
- Regression test: spawn 1 DApp-style subscriber, submit a `DAPP_CALL`, verify the event is delivered within K blocks

### Phase 7.5 — DApp SDK + reference implementation (~1 week, ecosystem)

Out of scope for the chain. Reference DApp written as a small process that:
- Connects to Determ full node via RPC
- Calls `dapp_subscribe`
- Implements a sample app (suggested: public bulletin board)
- Documents the SDK pattern in `docs/DAPP-SDK.md`

### Phase 7.6 — Cross-shard DApp routing (~3 days, depends on regional-sharding completion)

- DAPP_CALL across shards via inbound-receipt path
- Beacon-side relay extension to carry payload bytes (currently relays only amount + receipt)
- Block-size accounting (large DAPP_CALL payloads → block size cap consideration)

### Phase 7.7+ (deferred)

- `DAPP_REPLY` distinct tx type
- DApp slashing (proof-of-misbehavior tx types)
- DApp upgrade flows (versioned service_pubkey rotation with grace period)
- DApp permission groups (on-chain ACL list separate from DApp registry)

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

*End of document.*
