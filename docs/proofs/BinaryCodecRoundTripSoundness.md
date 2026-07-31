# BinaryCodecRoundTripSoundness — binary-only envelope-magic + round-trip + bounds-safety

This document formalizes the soundness of the A3 / S8 binary wire codec at `src/net/binary_codec.cpp` and its driver at `src/net/messages.cpp` (`Message::serialize_binary` / `Message::deserialize`). The wire is **binary-only** (D2, DECISION-LOG 2026-07-28): the legacy JSON envelope encoder (`Message::serialize`, wire-version 0) and the per-pair HELLO version negotiation were deleted pre-genesis, and every body on the wire is the `0xB1` binary envelope. Where `S022WireFormatCaps.md` + `S022WireFormatCapsCompleteness.md` bound the *size* of an accepted message and `WireFormatBackwardCompat.md` proves the *hash-stability* of optional field additions, this document proves the *decode correctness* surface that sits between the two: that the envelope-magic check is a total, deterministic predicate on at most the first two body bytes, that every reachable encoder output satisfies it, and that every body failing it is rejected fail-closed with the specific `"not a binary envelope"` throw (T-1); that the encode/decode pair is a round-trip identity on the wire-relevant projection of *every* `MsgType` — HELLO via its fixed binary frame, the five request/status control types (`GET_CHAIN`, `STATUS_REQUEST`, `STATUS_RESPONSE`, `SNAPSHOT_REQUEST`, `HEADERS_REQUEST`) via the D2-inc6a fixed frames (`ad595bb`), and the `TRANSACTION` projection including the optional `pq_auth` section (T-2); that every read in `decode_binary` / `decode_tx_frame` / `decode_hello_frame` and in the five D2-inc6a `decode_*_frame` request/status decoders is bounds-checked before the access it guards so an adversarial truncated/oversized body throws rather than reads out of bounds (T-3); and that `Message::deserialize` is therefore total — every byte string either decodes to a structurally-valid `Message` or raises a `std::exception` that the `Peer::read_body` catch handler at `src/net/peer.cpp:89-109` absorbs by closing the connection (WIRE-3) (T-4).

The proof is structural — there are no cryptographic assumptions on the codec itself (the codec moves bytes; the cryptography lives in the payloads it carries and is bound by the signing-bytes primitives that `WireFormatBackwardCompat.md` covers). The contribution over the existing wire-format proof corpus is the *decoder-correctness* layer: the size proofs assume the deserializer returns a `msg.type` value; this proof establishes that the deserializer cannot be steered into undefined behavior, that the envelope-magic dispatch is deterministic and fail-closed, and that the single shipped format round-trips every field a downstream consumer reads.

**Companion documents.** `S022WireFormatCaps.md` (parent size-cap closure — its T-3 assumes `Message::deserialize` returns a `msg.type`; T-4 here discharges the "deserialize is total" precondition that T-3 leans on, and its T-6 records the WIRE-3 close-on-parse-error disposition this proof's T-4 composes with); `S022WireFormatCapsCompleteness.md` (the cap-table exhaustion proof — its T-1 step 4 notes the decoder casts an out-of-enum type byte to `MsgType`; T-1 here shows the cast is the *only* type-byte interpretation and is bounds-safe); `WireFormatBackwardCompat.md` (the zero-skip hash-stability theorem — orthogonal: that proof covers the signing-bytes pre-image, this one covers the gossip envelope around it); `Preliminaries.md` §3 (network model underlying the `Peer` framing assumption); `JsonValidationSoundness.md` (S-018 — governs the `json_require` diagnostics in the per-type payload `from_json` consumers *downstream* of the codec; its former object here, the JSON-envelope branch of `Message::deserialize`, was deleted with D2); `S002-Mempool-Sig-Verify.md` (the amount/fee/nonce decode-fix whose round-trip property T-2 generalizes); `docs/SECURITY.md` §S-022 / §S-002 / §S-018 for the audit-trail. (`tla/HelloHandshake.tla` modeled the deleted `min(ours, theirs)` wire-version negotiation and is historical — the negotiation state machine no longer exists in the code; the spec is being retired/reduced in a parallel edit.)

---

## 1. Theorem statements

**Setup.** Let a *body* `B ∈ {0,1}^{8n}` (0 ≤ n ≤ kMaxFrameBytes) denote the framing-stripped payload that `Peer::read_body` hands to `Message::deserialize` (`src/net/messages.cpp:82`). The framing layer (a 4-byte big-endian length prefix, `src/net/peer.cpp:40-60` read side) is outside the codec; `serialize_binary` re-prepends it (`messages.cpp:124-130`) and `read_body` strips it, so the codec operates purely on `B`.

Let:

- `enc_B : Message → {0,1}^*` be the binary envelope serializer, `encode_binary` (`binary_codec.cpp:582`). It emits `[0xB1][0x01][type][0x00] || payload_frame`, so `enc_B(m)[0] = 0xB1` and `enc_B(m)[1] = 0x01`. It is total over every `MsgType` — HELLO via its fixed frame (`binary_codec.cpp:587-590`), the five request/status types via the D2-inc6a dispatch switch (`binary_codec.cpp:598-612`); the only throws are on pathological inputs (a string field > 255 bytes in `put_lp_str`, a payload or `pq_auth` exceeding the u32 length field), none reachable from a structurally-valid `Message`. There is no other wire encoder: the JSON envelope serializer `enc_J` (`Message::serialize`) is **deleted** (D2), and `Peer::send` calls `serialize_binary()` unconditionally (`peer.cpp:114-124`).
- `dec : {0,1}^* → Message ∪ {⊥}` be `Message::deserialize`, where `⊥` denotes "raised a `std::exception`".
- `det : {0,1}^* → {true, false}` be the envelope-magic predicate `is_binary_envelope` (`binary_codec.cpp:574-578`), with `det(B) = true ⟺ (|B| ≥ 4 ∧ B[0] = 0xB1 ∧ B[1] = 0x01)`.

Let `π : Message → WireFields` be the *wire-relevant projection* — the tuple of fields any downstream consumer reads off a decoded `Message`. For a `TRANSACTION`, `π` is `(from, to, amount, fee, nonce, payload, type, sig, hash, pq_auth)` (every field `chain::Transaction::from_json` / `to_json` round-trips; `pq_auth` joined the projection with the §3.21 / D2-inc1 optional trailing section — pre-inc1 the binary frame silently dropped it). For a `HELLO`, `π` is the five named fields `(domain, port, role, shard_id, wire_version)` as read through the tolerant `.value()` accessors that both `encode_hello_frame` and `GossipNet::handle_message`'s HELLO case use (`binary_codec.cpp:267-276`, `gossip.cpp:177-189`).

For each of the five D2-inc6a request/status types (`ad595bb`) `π` is likewise **the struct's field tuple, not the payload JSON value** — the frame carries exactly the fields the builders in `messages.hpp` set and the `GossipNet::handle_message` cases read, and nothing else can travel:

| Type (wire value) | `π` | Frame bytes after the envelope header |
|---|---|:---:|
| `GET_CHAIN` (5) | `(from: u64, count: u16)` | 10 |
| `STATUS_REQUEST` (7) | `()` — the empty tuple; the type byte *is* the message | 0 |
| `STATUS_RESPONSE` (8) | `(height: u64, genesis: string)` | 9..73 |
| `SNAPSHOT_REQUEST` (15) | `(headers: u32)` | 4 |
| `HEADERS_REQUEST` (17) | `(from: u64, count: u32)` | 12 |

Encoder side `binary_codec.cpp:315-394`; builders `messages.hpp:372-374, 381-383, 401-413`; consumer reads `gossip.cpp:265-313`.

For each of the four D2-inc6b consensus-chatter types (`e845b44`) `π` is likewise the struct's field tuple. These are the four control messages whose field sets are **unconditional** — no emission gates, no unbounded collections — which is what made them convertible as one increment (`CONTRIB` is deliberately excluded: it has two conditional field blocks and four unbounded hash lists that need explicit caps, so it gets its own increment):

| Type (wire value) | `π` | Frame bytes after the envelope header |
|---|---|:---:|
| `BLOCK_SIG` (3) | `(block_index: u64, signer: string, delay_output: 32 B, dh_secret: 32 B, ed_sig: 64 B)` | 137 + \|signer\| |
| `ABORT_CLAIM` (9) | `(block_index: u64, round: u8, prev_hash: 32 B, ed_sig: 64 B, missing_creator: string, claimer: string)` | 109 + \|missing_creator\| + \|claimer\| |
| `ABORT_EVENT` (10) | `(block_index: u64, prev_hash: 32 B, event: (round: u8, aborting_node: string, timestamp: i64, event_hash: 32 B, claims: AbortClaim[]))` | 82 + \|aborting_node\| + \|claims blob\| |
| `EQUIVOCATION_EVIDENCE` (11) | `(equivocator: string, block_index: u64, digest_a: 32 B, sig_a: 64 B, digest_b: 32 B, sig_b: 64 B, shard_id: u32, beacon_anchor_height: u64)` | 213 + \|equivocator\| |

Encoder side `binary_codec.cpp:441-557`; builders `messages.hpp:328-330, 334-336, 337-347, 348-350`; layout comment `binary_codec.cpp:115-140`. For every remaining type — the **8** that still carry a length-prefixed JSON payload inside the envelope (`BLOCK`, `CONTRIB`, `CHAIN_RESPONSE`, `BEACON_HEADER`, `SHARD_TIP`, `CROSS_SHARD_RECEIPT_BUNDLE`, `SNAPSHOT_RESPONSE`, `HEADERS_RESPONSE`) — `π` is the full `payload` JSON value.

**Theorem T-1 (Envelope-Magic Totality and Fail-Closed Coverage).** `det` is a total, deterministic function of `|B|` and at most the first two body bytes. Every reachable encoder output satisfies it:

$$
\forall m \in \mathrm{dom}(enc_B):\ det(enc_B(m)) = \mathrm{true},
$$

and every body failing it is rejected by `Message::deserialize` with the specific throw whose message contains `"not a binary envelope"` (`messages.cpp:83-87`), *before any payload work*. There is no second accepted format: the set of bodies `dec` will attempt to decode is exactly `{B : |B| ≥ 4 ∧ B[0] = 0xB1 ∧ B[1] = 0x01}`. In particular a legacy JSON-envelope body (first byte `'{'` = `0x7B ≠ 0xB1`) lands in this throw — the deleted wire-version-0 path cannot be silently re-entered.

**Theorem T-2 (Round-Trip Identity on the Wire Projection).** For every `Message m` whose payload is a structurally-valid instance of its type:

$$
\pi(dec(enc_B(m))) = \pi(m).
$$

Five cases. For the `TRANSACTION` fixed-frame path this is exact field equality across `(from, to, amount, fee, nonce, payload, type, sig, hash, pq_auth)`: the S-002 fix (`src/chain/block.cpp:209-211`) reads amount/fee/nonce from the fixed slots the encoder wrote (`src/chain/block.cpp:160-163`), and the D2-inc1 `pq_auth` section is emitted iff non-empty (`src/chain/block.cpp:194-199`) and decoded fail-closed (`src/chain/block.cpp:244-254`) — a frame ending at the hash decodes with `pq_auth` empty, matching the encoder's omit-when-empty convention, so the empty case round-trips too. For `HELLO` it is exact equality on the five named fields through the fixed binary frame (`encode_hello_frame` / `decode_hello_frame`, `binary_codec.cpp:267-299`) — the decoder rebuilds the payload with all five keys explicit, so a payload that omitted a field round-trips to that field's documented default, which is `π`-equal under the tolerant read. For the five D2-inc6a request/status frames it is exact equality on the field tuples tabulated in §1 (`binary_codec.cpp:315-394`, guards and properties in §3.6, agreement in L-7) — and, because each of the five builders emits exactly the keys its frame carries, the stronger *whole-payload* identity `dec(enc_B(m)).payload == m.payload` holds for every builder-shaped message, which is what test-binary-codec leg 4b asserts. For the four D2-inc6b consensus-chatter frames it is exact equality on the field tuples tabulated in §1 (`binary_codec.cpp:441-557`, guards and properties in §3.7, agreement in L-8) — and again the stronger whole-payload identity holds for builder-shaped messages, which is what leg 4c asserts. For the length-prefixed-JSON path (the remaining 8 types) it is exact JSON-value equality, since `enc_B` embeds `m.payload.dump()` verbatim (`binary_codec.cpp:616-621`) and `dec` re-parses it (`binary_codec.cpp:682-696`).

**Theorem T-2b (Encoding Canonicality on the Fixed-Frame Path).** For each of the eleven fixed-frame types, the map `enc_B` restricted to that type is *injective on the wire*: distinct byte strings never decode to the same `Message`, and each `Message` has exactly one accepted encoding. Concretely, for every fixed-frame body `B` accepted by `dec`, `enc_B(dec(B)) = B`. The mechanism is exact consumption — every fixed-frame decoder either guards with a strict `len` equality or ends with an `off == len` check, so a body that is one byte long or one byte short of its canonical encoding is rejected rather than accepted-and-normalized. This is the property the D2 migration exists to establish (DECISION-LOG D2: canonical binary only), and it is the one that a *one-sided* length check silently destroys while leaving round-trip (T-2) intact — see Finding F-4 and L-9.

*(The former corollary that the binary and JSON paths are observationally equivalent is retired with its premise: `enc_J` no longer exists, so there is no second path to be equivalent to.)*

**Theorem T-3 (Bounds-Safety of the Decode Path).** For every body `B` (adversarial or honest), `decode_binary(B)` and its eleven fixed-frame sub-calls — `decode_tx_frame`, `decode_hello_frame`, the five D2-inc6a request/status decoders, and the four D2-inc6b chatter decoders (`decode_abort_claim_frame`, `decode_block_sig_frame`, `decode_equivocation_frame`, `decode_abort_event_frame`) — perform no out-of-bounds read: every indexed access `data[i]` / `data + i` and every `memcpy` is preceded on all reachable control-flow paths by a length guard that throws `std::runtime_error` when the required bytes are not present. Formally, for each read of `k` bytes at offset `off`, the code establishes `off + k ≤ len` before the read, or throws. This covers the D2-inc1 `pq_auth` section reads, the D2-inc2 HELLO frame reads, the D2-inc6a request/status frame reads, and the D2-inc6b chatter frame reads (guard inventory in §3.4–§3.7). Two of the four chatter decoders delegate their tail to `chain::decode_abort_claims`, whose own guards are proved in `AbortDigestCanonicalizationSoundness.md`; T-3 here is closed *modulo* that delegation, which is stated as an explicit composition step rather than re-proved. The decoder therefore has no undefined behavior on any input in `{0,1}^*`.

**Theorem T-4 (Totality of `Message::deserialize`).** `dec` is total over `{0,1}^*` in the sense that for every body `B`, `dec(B)` either returns a `Message` with a well-defined `type ∈ MsgType` (any byte value, per the `static_cast<MsgType>` at `binary_codec.cpp:632` / `messages.cpp:106`) and a `payload` value, or raises a `std::exception`. `dec` is binary-only: a body failing `det` — including a `'{'`-leading legacy JSON envelope — raises the T-1 throw; a body passing `det` then faces the WIRE-1 pre-decode per-type size cap (`messages.cpp:106-114`), which throws before any payload work if `|B| > max_message_bytes(B[2])`; only then does `decode_binary` run. The theorem's *form* is unchanged by D2-inc6a/inc6b, but its dispatch surface is not: `decode_binary` now routes **eleven** types to fixed frames (HELLO, TRANSACTION, the five request/status types, and the four consensus-chatter types, via the switch at `binary_codec.cpp:659-680`) and only the remaining **8** to the length-prefixed-JSON tail, so totality must hold on eleven fixed-frame decoders plus the JSON tail rather than two plus the tail. There is no input on which `dec` reads out of bounds, loops without termination, or returns an uninitialized value. Composed with the `Peer::read_body` `try`/`catch` at `src/net/peer.cpp:71-109`, every decode failure — the T-1 magic reject and all decode throws alike — is caught, logged, and **closes the connection** (WIRE-3, `peer.cpp:107`), and every decode success is additionally gated by the post-decode S-022 per-type cap (`peer.cpp:80-87`) before dispatch.

---

## 2. Background

### 2.1 The binary-only wire surface

Determ peers exchange `Message` values over TCP. The transport (`Peer`) frames each body with a 4-byte big-endian length prefix (`src/net/peer.cpp:40-60` read side; `messages.cpp:124-130` write side). Inside that frame the *body* is exactly one format:

- **Binary envelope v1 (the only wire format — D2).** `Message::serialize_binary` → `encode_binary` emits a 4-byte header `[0xB1][0x01][type][0x00]` followed by a per-type payload. The body always begins with `0xB1 0x01`. Every `MsgType` encodes — HELLO travels as a fixed binary frame like everything else (`binary_codec.cpp:86-98` layout comment), since D2-inc6a (`ad595bb`) so do the five request/status control types (`binary_codec.cpp:100-113`), and since D2-inc6b (`e845b44`) so do the four consensus-chatter types (`binary_codec.cpp:115-140`). Eleven of the 19 types are now true fixed frames; the other 8 carry a length-prefixed JSON payload inside the same envelope.

The legacy JSON envelope (wire-version 0, body leading with `'{'`) and the per-pair `min(ours, theirs)` HELLO negotiation were deleted pre-genesis with D2. What remains of versioning is an **advertisement**: `kWireVersionBinary = 1` is the single shipped constant (`messages.hpp:84-89`), and HELLO carries a `wire_version` u8 field that nothing reads today (`gossip.cpp:185-187`) — it is the additive post-genesis upgrade escape hatch (a future v2 peer advertises 2, keeps *sending* v1 frames, and upgrades only after reading the peer's advertised max; no-migrations discipline).

The receive path (`Message::deserialize`, `messages.cpp:82-116`) checks `is_binary_envelope(B)` and *rejects* any body failing it — there is no fallback parser. The body still tells the receiver what it is (self-describing magic + in-the-clear type byte at offset 2), but the answer is now binary-or-throw, not binary-or-JSON.

### 2.2 Why a decode-correctness proof is needed alongside the size-cap proofs

`S022WireFormatCaps.md` T-3 reasons about the state *after* `Message::deserialize` returns a `msg` value — it gates `on_msg_` on `body_buf_.size() > max_message_bytes(msg.type)`. That argument silently assumes `Message::deserialize` *returns* (rather than reading out of bounds, or being steered to a type byte it can't interpret). The size proof explicitly defers this: its §6.2 finding-register lists "deserialize-time bugs that crash the receiver before the cap is checked" as out of scope. This document discharges that assumption:

1. The decoder casts the type byte with `static_cast<MsgType>(data[2])` — any of the 256 byte values is a valid (possibly out-of-enum) `MsgType`, so the type read never throws and never reads OOB (T-1, T-3).
2. Every length-prefixed and fixed-slot read inside `decode_binary` and its eleven fixed-frame decoders is guarded (T-3), so a truncated or maliciously-short body throws `std::runtime_error` rather than reading past `data + len`.
3. Both outcomes (return-or-throw) are handled at the peer layer (T-4), so the deserializer is safe to feed arbitrary peer bytes.

Two later hardening layers now sit *inside* `dec` and are part of its totality surface: the WIRE-1 pre-decode per-type cap (`messages.cpp:88-114` — the type is readable in the clear at offset 2, so the S-022 ceiling is applied before any payload work) and the WIRE-2 structural ceiling (`json_structural_precheck`, `messages.cpp:18-76`, invoked at `binary_codec.cpp:694` on the length-prefixed JSON payloads that the 8 non-fixed-frame types still carry inside the binary envelope — it survives the D2 envelope strip and **survives D2-inc6a and D2-inc6b**, because those 8 types still reach `nlohmann::json::parse`; it retires only when every payload becomes a true binary frame). Both are throw-on-violation, i.e. more instances of the T-4 return-or-throw contract; their DoS soundness is proved in `S022WireFormatCaps.md`, not here.

Without T-3, the S-022 cap argument has a gap: an attacker who can make `Message::deserialize` read OOB defeats the cap before it is consulted. T-3 closes the gap.

### 2.3 Send-side encoding is unconditional (context, not the proof object)

There is no send-side format choice. `Peer::send` calls `msg.serialize_binary()` unconditionally (`peer.cpp:114-124`); the old silent catch-all JSON fallback is deliberately not reproduced — an encode failure is a local bug and must surface loudly at the call site, never mask itself as legacy traffic (the comment at `peer.cpp:115-118` pins this intent). `encode_binary` accepts every `MsgType` including HELLO (`binary_codec.cpp:307-317`), so there is no special-cased first message: the HELLO that opens every connection is the same `0xB1` envelope as everything after it. The per-peer `wire_version_` member, the `kWireVersionLegacy` / `kWireVersionMax` constants, and the HELLO-receipt negotiation in `gossip.cpp` are all deleted; the receiver's HELLO case tags the peer's identity fields and marks the handshake done, nothing more (`gossip.cpp:177-189`).

---

## 3. Implementation citation

### 3.1 Envelope-magic check (`is_binary_envelope`)

`src/net/binary_codec.cpp:561-578`:

```cpp
constexpr uint8_t kBinaryMagic   = 0xB1;
constexpr uint8_t kBinaryVersion = 0x01;
// ...
bool is_binary_envelope(const uint8_t* data, size_t len) {
    return len >= 4
        && data[0] == kBinaryMagic
        && data[1] == kBinaryVersion;
}
```

The `len >= 4` short-circuit guards `data[0]` and `data[1]` — `is_binary_envelope` is itself bounds-safe (it never reads `data[0]` on an empty body).

### 3.2 The deserialize gate (`Message::deserialize`)

`src/net/messages.cpp:82-116`:

```cpp
Message Message::deserialize(const uint8_t* data, size_t len) {
    if (!is_binary_envelope(data, len)) {
        throw std::runtime_error(
            "wire: body is not a binary envelope (magic 0xB1) — the legacy "
            "JSON envelope was removed pre-genesis (D2 binary-only wire)");
    }
    // S-022 PRE-DECODE cap (WIRE-1). [...]
    const MsgType btype = static_cast<MsgType>(data[2]);
    if (len > max_message_bytes(btype)) {
        throw std::runtime_error(
            "S-022: binary envelope (...) exceeds its per-type cap (...)");
    }
    return decode_binary(data, len);
}
```

Total-or-throw in three stages: the T-1 magic reject (`messages.cpp:83-87`, the specific `"not a binary envelope"` string that the D2 negative gate pins), the WIRE-1 pre-decode per-type cap (`messages.cpp:106-114` — strictly accept-narrowing, the same cap `Peer::read_body` re-applies post-decode), then `decode_binary` (§3.3–§3.5). There is no JSON branch; `nlohmann::json::parse` is never reached from a non-`0xB1` body.

### 3.3 The binary envelope decoder (`decode_binary`)

`src/net/binary_codec.cpp:626-697`:

```cpp
Message decode_binary(const uint8_t* data, size_t len) {
    if (len < 4 || data[0] != kBinaryMagic)
        throw std::runtime_error("binary_codec: not a binary envelope");
    if (data[1] != kBinaryVersion)
        throw std::runtime_error("binary_codec: unsupported binary version");
    Message m;
    m.type = static_cast<MsgType>(data[2]);
    if (data[3] != 0x00)
        throw std::runtime_error("binary_codec: reserved envelope byte non-zero");
    const uint8_t* body = data + 4;
    size_t body_len = len - 4;

    if (m.type == MsgType::HELLO) {
        m.payload = decode_hello_frame(body, body_len);
        return m;
    }
    if (m.type == MsgType::TRANSACTION) {
        chain::Transaction tx = decode_tx_frame(body, body_len);
        m.payload = tx.to_json();
        return m;
    }
    // D2-inc6a: fixed-layout request/status frames.
    switch (m.type) {
    case MsgType::GET_CHAIN:
        m.payload = decode_get_chain_frame(body, body_len);        return m;
    case MsgType::STATUS_REQUEST:
        m.payload = decode_status_request_frame(body, body_len);   return m;
    case MsgType::STATUS_RESPONSE:
        m.payload = decode_status_response_frame(body, body_len);  return m;
    case MsgType::SNAPSHOT_REQUEST:
        m.payload = decode_snapshot_request_frame(body, body_len); return m;
    case MsgType::HEADERS_REQUEST:
        m.payload = decode_headers_request_frame(body, body_len);  return m;
    default: break;
    }
    if (body_len < 4)
        throw std::runtime_error("binary_codec: truncated payload header");
    uint32_t plen = le_get_u32(body);
    if (4 + static_cast<size_t>(plen) > body_len)
        throw std::runtime_error("binary_codec: truncated payload body");
    json_structural_precheck(body + 4, plen);   // S-022 / WIRE-2
    m.payload = nlohmann::json::parse(body + 4, body + 4 + plen);
    return m;
}
```

Every read is guarded: `len < 4` guards `data[0..3]` (including the reserved-byte check at `binary_codec.cpp:642-643` — non-zero is rejected fail-closed, matching the independent light/wallet conformance decoders; see `ReservedDiscriminatorAudit.md` §6); the `body_len < 4` guard precedes `le_get_u32(body)` (which reads `body[0..3]`); and `4 + plen > body_len` guards the `body + 4 .. body + 4 + plen` window for both the WIRE-2 pre-scan and the parse. The D2-inc6a `switch` at `binary_codec.cpp:659-680` is a pure *dispatch* — it performs no read of its own; each arm's guards are inventoried in §3.6, and its `default: break;` falls through to the length-prefixed-JSON tail, so no type loses a decoder. The cast `static_cast<MsgType>(data[2])` accepts any byte (per `S022WireFormatCapsCompleteness.md` T-1 step 4, an out-of-enum byte simply hits the default size tier) and — since the five new arms match only their own enum values — an out-of-enum byte still lands in the JSON tail exactly as before. The magic/version re-checks at `binary_codec.cpp:627-630` are defense-in-depth for direct callers (tests, tools); from `Message::deserialize` the T-1 gate has already established them.

### 3.4 The transaction fixed-frame decoder (`decode_tx_frame`)

`src/chain/block.cpp:202-256`. The tx frame codec moved to `chain::Transaction::encode_frame` / `decode_frame` in `src/chain/block.cpp` in d2-inc4 so the COMPOSABLE_BATCH validator/apply share it; `binary_codec.cpp`'s `encode_tx_frame` / `decode_tx_frame` are now thin delegating wrappers (`src/net/binary_codec.cpp:257-263`) and the byte layout is unchanged. The tx-frame reject strings dropped the `"binary_codec: "` prefix with the move (now `"tx frame ..."` / `"tx frame: ..."`); the pinned substrings are unchanged. The guards, in source order:

| Guard (line) | Protects |
|---|---|
| `if (len < 128 + 1 + 2) throw` (204-205) | the fixed-slot reads at offsets 32, 40, 48, 56 (amount/fee/nonce/reserved, read at 209-212) and the trailer `type` + `payload_len` reads at offsets 128, 129-130 (read at 219-220) |
| `if (reserved != 0) throw` (213-214) | determinism invariant — rejects a non-canonical frame whose reserved u64 is non-zero |
| `payload_len <= 32` branch (222-223) | reads `data + 96 .. 96 + payload_len`, which is ≤ 128 ≤ `len` by the line-204 guard |
| `if (off + overflow > len) throw` (226-227) | the overflow-payload `data + off .. off + overflow` read |
| `get_lp_str` internal guards (140, 142) | the `from` / `to` length-prefixed string reads at 234-235 (`off + 1 > len` for the length byte, `off + n > len` for the body) |
| `if (off + 64 + 32 > len) throw` (236-237) | the `memcpy` of the 64-byte sig and 32-byte hash (238-239) |
| `if (off + 4 > len) throw` (245-246) | the `pq_auth` section header `le_get_u32(data + off)` (247) — reached only when `off != len`, i.e. bytes remain after the hash |
| `if (pq_len == 0) throw` (248-249) | canonicality — the encoder omits the section when `pq_auth` is empty, so a zero-length section has no legitimate producer and is rejected (`"empty pq_auth section"`) |
| `if (pq_len != len - off) throw` (250-251) | exact consumption — the section must end the frame precisely (`"pq_auth length mismatch"`); this equality *is* the bounds guard for the `tx.pq_auth.assign(data + off, data + off + pq_len)` read at 252, whose window ends exactly at `data + len` |

The encoder side (`Transaction::encode_frame`, `src/chain/block.cpp:150-200`) writes exactly the layout the decoder reads, with `put_padded` (`src/chain/block.cpp:125-129`) right-padding short `from`/`to`/`payload` to their 32-byte slots and the trailer carrying the authoritative variable-length `from`/`to`/`sig`/`hash`. `put_lp_str` (`src/chain/block.cpp:132-137`) throws if a string exceeds 255 bytes, the symmetric bound to `get_lp_str`'s u8 length read. The `pq_auth` section (`src/chain/block.cpp:194-199`) is appended **only when `tx.pq_auth` is non-empty** — `[u32 LE len][bytes]`, with a u32-overflow guard at 195-196 — so every non-PQ frame is byte-identical to the pre-§3.21 layout (the layout comment at `binary_codec.cpp:69-77` pins the convention).

### 3.5 The HELLO fixed-frame codec (`encode_hello_frame` / `decode_hello_frame`)

`src/net/binary_codec.cpp:267-299` (layout comment at 86-98). The frame after the 4-byte envelope header is `[u8 domain_len][domain][u16 LE port][u8 role][u32 LE shard_id][u8 wire_version]`:

```cpp
void encode_hello_frame(std::vector<uint8_t>& out, const Message& m) {
    const std::string domain = m.payload.value("domain", std::string{});
    put_lp_str(out, domain);
    le_put_u16(out, m.payload.value("port", uint16_t{0}));
    out.push_back(m.payload.value("role", uint8_t{0}));
    le_put_u32(out, m.payload.value("shard_id", uint32_t{0}));
    out.push_back(m.payload.value("wire_version", uint8_t{kWireVersionBinary}));
}

nlohmann::json decode_hello_frame(const uint8_t* data, size_t len) {
    size_t off = 0;
    std::string domain = get_lp_str(data, len, off);
    if (off + 2 + 1 + 4 + 1 > len)
        throw std::runtime_error("binary_codec: truncated HELLO frame");
    // ... port / role / shard_id / wire_version reads ...
    if (off != len)
        throw std::runtime_error("binary_codec: HELLO frame trailing bytes");
    // ... rebuild the five-field payload ...
}
```

Guard inventory: `get_lp_str`'s two internal guards (`binary_codec.cpp:241, 217`) cover the domain read; the single combined guard at `binary_codec.cpp:281-282` establishes `off + 8 ≤ len` before the four fixed-width reads at 257-260 (2 + 1 + 4 + 1 = 8 bytes); and the exact-consumption check at 264-265 rejects trailing bytes fail-closed (`"HELLO frame trailing bytes"`) — a future *additive* field must arrive behind a bumped `wire_version` advertisement, never as silent padding. The two specific reject strings (`"truncated HELLO frame"`, `"HELLO frame trailing bytes"`) are pinned by test-binary-codec leg 1b.

### 3.6 The request/status fixed frames (D2-inc6a, `ad595bb`)

`src/net/binary_codec.cpp:301-394` (layout comment at 100-113; encode dispatch at 409-417, decode dispatch at 464-476). Five control message types moved from a length-prefixed JSON payload to a true fixed binary frame. All five carry **no signature and no consensus commitment**, so the change is observationally inert on the consensus path: no digest, signing pre-image, or accept rule reads these bytes — only the gossip handlers in `GossipNet::handle_message` (`gossip.cpp:265-313`) do.

```cpp
nlohmann::json decode_get_chain_frame(const uint8_t* data, size_t len) {
    if (len != 8 + 2)
        throw std::runtime_error("binary_codec: bad GET_CHAIN frame length");
    // from = le_get_u64(data); count = le_get_u16(data + 8);
}

nlohmann::json decode_status_request_frame(const uint8_t*, size_t len) {
    if (len != 0)
        throw std::runtime_error("binary_codec: STATUS_REQUEST frame not empty");
    return nlohmann::json::object();
}

nlohmann::json decode_status_response_frame(const uint8_t* data, size_t len) {
    if (len < 8 + 1)
        throw std::runtime_error("binary_codec: truncated STATUS_RESPONSE frame");
    size_t off = 0;
    uint64_t height = le_get_u64(data); off += 8;
    std::string genesis = get_lp_str(data, len, off);
    if (off != len)
        throw std::runtime_error("binary_codec: STATUS_RESPONSE frame trailing bytes");
    if (!genesis.empty() && genesis.size() != 64)
        throw std::runtime_error("binary_codec: STATUS_RESPONSE genesis length "
                                 "must be 0 or 64");
    // ...
}
```

**Guard inventory (T-3 rows).**

| Decoder (lines) | Guard (line) | Protects |
|---|---|---|
| `decode_get_chain_frame` (320-327) | `if (len != 8 + 2) throw` (321-322) | `le_get_u64(data)` (324) and `le_get_u16(data + 8)` (325) — an equality, so it is simultaneously the bounds guard and the exact-consumption check |
| `decode_status_request_frame` (333-337) | `if (len != 0) throw` (334-335) | nothing is read; the guard exists purely to reject a non-empty frame (`"STATUS_REQUEST frame not empty"`) |
| `decode_status_response_frame` (350-368) | `if (len < 8 + 1) throw` (351-352) | `le_get_u64(data)` (354) and the `get_lp_str` length byte at offset 8 |
| | `get_lp_str` internal guards (215, 217) | the `genesis` length byte and its body (355) |
| | `if (off != len) throw` (356-357) | exact consumption (`"STATUS_RESPONSE frame trailing bytes"`) |
| | `if (!genesis.empty() && genesis.size() != 64) throw` (361-363) | the `{0, 64}` accept-narrowing (`"STATUS_RESPONSE genesis length must be 0 or 64"`) |
| `decode_snapshot_request_frame` (374-380) | `if (len != 4) throw` (375-376) | `le_get_u32(data)` (378) |
| `decode_headers_request_frame` (387-394) | `if (len != 8 + 4) throw` (388-389) | `le_get_u64(data)` (391) and `le_get_u32(data + 8)` (392) |

Four of the five decoders guard with a *strict equality* on `len`, which is stronger than the `off + k ≤ len` form T-3 requires: it is the bounds guard and the exact-consumption check in one expression, so neither a short nor a padded frame can be accepted. `STATUS_RESPONSE` is the one variable-length frame and therefore carries the guard trio (lower bound → `get_lp_str` → exact consumption) plus the narrowing below.

**Property P-1 (`STATUS_RESPONSE.genesis` is length-prefixed by *correctness*, not by style).** `genesis` is the 64-char hex of the responder's genesis block hash — or the **empty string** when the responder's chain is empty, and the consumer branches on exactly that emptiness: `Node::on_status_response` skips the different-genesis rejection when `genesis_hash.empty()` (`src/node/node.cpp:3180`). A fixed 32-byte (or 64-char) slot has no way to represent "I do not have a genesis yet"; the natural encoding would be all-zeros, which the consumer would then compare against its own hash, find unequal, and treat as **wrong genesis** — silently excluding an honest bootstrapping peer from sync. The length prefix preserves the empty case exactly and is therefore load-bearing for liveness, not a byte-layout preference. `encode_status_response_frame` (`binary_codec.cpp:339-348`) records the same argument in-source, and test-binary-codec leg 4b round-trips `make_status_response(0, "")` explicitly.

*Accept-narrowing.* The decode then rejects any `genesis` whose length is neither 0 nor 64 (`binary_codec.cpp:361-363`). A conforming responder emits only those two lengths, so this costs no legitimate message while bounding what an attacker-supplied string can pin to at most 64 bytes; it is strictly accept-narrowing relative to the pre-inc6a JSON payload, which accepted a string of any length up to the 1 MB tier cap. The light client's independent `decode-wire` mirror applies the same `{0, 64}` narrowing on its own re-implementation of the layout (`light/main.cpp:8898-8915`), so daemon and light agree on frame validity — the asymmetry class `ReservedDiscriminatorAudit.md` §6 found is not reintroduced.

**Property P-2 (`make_status_request` emits an object, so encode→decode is a fixed point).** `decode_status_request_frame` materialises `nlohmann::json::object()` from a zero-length frame. Pre-inc6a the builder returned `{MsgType::STATUS_REQUEST, {}}`, and a brace-init `{}` value-initialises an `nlohmann::json` to **null**, not to an empty object — so `dec(enc_B(m)).payload` would have been `{}` while `m.payload` was `null`, i.e. encode→decode would not have been the identity on the payload even though `π` (the empty tuple) was preserved. The builder was normalized to `nlohmann::json::object()` (`include/determ/net/messages.hpp:404-410`) so the whole-payload identity holds too; leg 4b's `rt(make_status_request(), ...)` asserts `back.payload == m.payload` and would red on a revert.

**Property P-3 (`GET_CHAIN.count` is u16 and `HEADERS_REQUEST.count` is u32 — deliberately not unified).** The two widths mirror the handler signatures they feed: `on_get_chain` takes a `uint16_t` count (`gossip.cpp:290-294`) and `on_headers_request` a `uint32_t` count (`gossip.cpp:277-284`). Widening `GET_CHAIN.count` to u32 would put a value on the wire that the handler cannot represent, reintroducing a silent truncation at the dispatch boundary; narrowing `HEADERS_REQUEST.count` would drop values the light-client header-sync handler legitimately accepts. The asymmetry is recorded in-source at `binary_codec.cpp:112-113` and `284-287` so a later "cleanup" does not unify them by reflex.

### 3.7 The consensus-chatter fixed frames (D2-inc6b, `e845b44`)

`src/net/binary_codec.cpp:396-557` (layout comment at 115-140; encode dispatch at 606-611, decode dispatch at 671-680). Four control message types moved from a length-prefixed JSON payload to a typed binary frame. Unlike the five inc6a types, three of these four *do* travel alongside consensus material — a `BLOCK_SIG` carries an Ed25519 signature, an `ABORT_CLAIM` carries a signed claim, an `EQUIVOCATION_EVIDENCE` carries two signatures over two digests. The change is nonetheless **signature-transparent**, which is the property that makes it observationally inert:

**Property P-4 (signature transparency).** No signature carried by these frames is computed over the frame. `make_abort_claim_message`, `make_contrib_commitment` and `node::compute_block_digest` each hash a *binary field tuple* built directly from the struct fields, never a serialization of the container; the equivocation digests are block digests produced the same way. Therefore replacing the container changes no signing pre-image, no digest, and no block hash, and no accept rule observes the swap. The proof obligation this creates is exactly T-2 (every field the verifier reads must survive the round trip) and nothing more — if `π` is preserved, the recomputed pre-image is bit-identical.

**Property P-5 (`ABORT_CLAIM` reuses the stored-claim codec, so gossip and storage cannot drift).** `encode_abort_claim_frame` (`binary_codec.cpp:441-445`) does not define a claim layout. It calls `chain::encode_abort_claims({claim})` — the *same* function that serializes the claim list carried inside a block — and `decode_abort_claim_frame` (`binary_codec.cpp:447-454`) calls `chain::decode_abort_claims` and then asserts the count is exactly one, throwing `"binary_codec: ABORT_CLAIM must carry exactly one claim"` otherwise. This is the S-044 one-shared-helper discipline applied to a container: a gossiped claim and the block-stored claim are the same bytes produced by the same code, so no future edit can make one accept what the other rejects. The count assertion is what keeps the encoding canonical — the shared blob is count-prefixed, so without it a two-claim blob would be a second valid encoding of a one-claim message, violating T-2b.

**Property P-6 (a fixed 32-byte `dh_secret` slot is *equivalent to*, not a widening of, the JSON rule).** On the JSON path `BLOCK_SIG.dh_secret` was absent-means-zero: S-009 treats a legacy or withheld reveal as the all-zero hash. A fixed 32-byte slot carrying zeros therefore encodes exactly the same value set with exactly one representation per value, whereas an optional section would admit two encodings of "zero" (omitted, or present-and-zero) and reopen the canonicality question T-2b closes. The slot additionally removes an S-018 asymmetry the JSON path carried: `dh_secret` was the one hex field read *without* `json_require_hex`, so a wrong-length value threw an anonymous `"hex length mismatch"` rather than a field-named diagnostic.

**Property P-7 (the claims blob must be LAST in `ABORT_EVENT`).** `chain::decode_abort_claims` is exact-consuming over the whole buffer it is handed — it throws `"abort claims: trailing bytes after last claim"` on any residue. It therefore cannot be embedded mid-frame without an explicit length prefix. `encode_abort_event_frame` places it last (`binary_codec.cpp:526-529`) and `decode_abort_event_frame` hands it `data + off .. data + len` (`binary_codec.cpp:549-550`), so the sub-codec's own exact consumption *is* the frame's exact-consumption check. This is the same structural rule the transaction frame's optional `pq_auth` tail obeys, and it is why no length prefix is spent on the blob.

**Guard inventory (T-3 rows).**

| Decoder (lines) | Guard (line) | Protects |
|---|---|---|
| `decode_abort_claim_frame` (447-454) | delegated to `chain::decode_abort_claims` | all reads; the sub-codec is exact-consuming and carries its own count/length guards (`AbortDigestCanonicalizationSoundness.md`) |
| | `if (claims.size() != 1) throw` (451-452) | canonicality — the count-prefixed blob must carry exactly one claim |
| `decode_block_sig_frame` (470-482) | `if (len < 8) throw` (473) | `le_get_u64(data)` (474) |
| | `get_lp_str` internal guards (241, 243) | the `signer` length byte and its body (475) |
| | `if (off + 32 + 32 + 64 != len) throw` (476-477) | the three fixed-width copies at 478-480 — an equality, so it is simultaneously the bounds guard and the exact-consumption check |
| `decode_equivocation_frame` (496-510) | `get_lp_str` internal guards (241, 243) | the `equivocator` length byte and its body (499) |
| | `if (off + 8 + 32 + 64 + 32 + 64 + 4 + 8 != len) throw` (500-501) | every read at 502-508; likewise an equality, hence bounds + exact consumption in one |
| `decode_abort_event_frame` (532-557) | `if (len < 8 + 32) throw` (534) | `le_get_u64(data)` (535) and the `prev_hash` copy (537) |
| | `if (off + 1 > len) throw` (540) | the `round` byte (541) |
| | `get_lp_str` internal guards (241, 243) | the `aborting_node` length byte and its body (542) |
| | `if (off + 8 + 32 > len) throw` (543-544) | `le_get_u64` (545) and the `event_hash` copy (546) |
| | delegated to `chain::decode_abort_claims` (549-550) | the claims tail, including its exact consumption (P-7) |

Two of the four decoders guard with a strict equality on `len` (the T-3-stronger form: bounds and exact consumption in one expression). `ABORT_CLAIM` and `ABORT_EVENT` instead inherit exact consumption from the shared claim-list codec's own trailing-bytes check, which is why P-7's "blob last" placement is load-bearing rather than stylistic.

**Property P-9 (the claim-list `reserve` is clamped, so the u16 count is not an allocation lever).** `ABORT_CLAIM` and `ABORT_EVENT` both delegate to `chain::decode_abort_claims`, whose element count is a **u16** read straight off the wire — the layout alone admits 65,535 claims, far more than any frame in the 1 MB tier could carry. The decoder does **not** size its vector from that count: it reserves `min(count, 64)` (`src/chain/block.cpp:374`) and then grows only as claims are actually parsed, throwing `"abort claims: truncated claim N"` the moment the declared count outruns the bytes present. Peak allocation is therefore O(bytes received), not O(declared count) — the attacker gets no amplification from the prefix. This is the WIRE-1 lesson applied correctly (*a cap that runs after the work is not a cap*): the clamp precedes the loop rather than trusting the count.

*Residual, stated rather than implied.* The clamp is load-bearing but **not gated by a measured allocation leg** — a mutant changing `reserve(count <= 64 ? count : 64)` to `reserve(count)` would still round-trip, still reject every malformed frame with the same strings, and still pass every leg in the tree, while a 1 MB `ABORT_EVENT` declaring 65,535 claims would provoke a ~11 MB reservation before the first truncation throw. That is a bounded ~11× amplification, not the 51.9× WIRE-1 class, which is why it is recorded here as a named residual rather than treated as an open finding. Closing it requires an allocation-counting leg of the kind WIRE-1/WIRE-2 use, not another structural assertion.

**Property P-8 (negative timestamps are bit-exact, not clamped).** `chain::AbortEvent::timestamp` is `int64_t` and the frame carries it through a u64 slot via `static_cast<uint64_t>` on encode and `static_cast<int64_t>` on decode (`binary_codec.cpp:524`, `545`). Under the project's C++20 setting both conversions are well-defined and mutually inverse over the whole `int64_t` range, so a negative timestamp round-trips bit-exactly. This is asserted behaviourally (leg 4c) rather than left to the reader, because a plausible "cleaner" encoding — a u32 slot, or a clamp at zero — would silently corrupt the field, and the field is inside the abort-event hash pre-image.

---

## 4. Lemmas and proofs

### Lemma L-1 (every reachable encoder output begins `0xB1 0x01`)

`enc_B(m)` (`binary_codec.cpp:309-333`) calls `put_envelope_header` (`binary_codec.cpp:291-296`) first on every path, pushing `kBinaryMagic = 0xB1` then `kBinaryVersion = 0x01` as the first two bytes, then `type` and the reserved `0x00`. Every branch (HELLO fixed frame, TRANSACTION fixed frame, length-prefixed JSON) appends after the header. Hence `enc_B(m)[0] = 0xB1`, `enc_B(m)[1] = 0x01`, and `|enc_B(m)| ≥ 4`. There is no other reachable wire encoder: `Peer::send` (`peer.cpp:119`) is the only wire write path and calls `serialize_binary()`, which defers to `encode_binary` (`messages.cpp:122-123`). □

### Lemma L-2 (`det` reads at most two bytes and is deterministic)

`is_binary_envelope` (§3.1) is a pure function of `len` and `data[0..1]`, evaluated left-to-right with `&&` short-circuit: if `len < 4` it returns `false` without reading `data`; otherwise it reads exactly `data[0]` and `data[1]`. It has no global state and no side effects, so it is deterministic. □

### Lemma L-3 (every read in `decode_binary` and its eleven frame decoders is guarded)

By the guard inventory in §3.3 (the `len < 4` envelope-header guard covering the type and reserved bytes, the `body_len < 4` guard preceding `le_get_u32`, and the `4 + plen > body_len` window guard covering both the WIRE-2 scan and the parse), §3.4 (the line-204 fixed-slot/trailer guard, the overflow guard, the two `get_lp_str` internal guards, the sig/hash `memcpy` guard, and the three `pq_auth` guards — header, non-empty, exact-consumption, the last doubling as the bounds guard for the section-body read), §3.5 (the `get_lp_str` guards for the domain, the combined `off + 8 ≤ len` guard for the four fixed-width fields, and the exact-consumption check), and §3.6 (the four strict-equality `len` guards of `GET_CHAIN` / `STATUS_REQUEST` / `SNAPSHOT_REQUEST` / `HEADERS_REQUEST`, and `STATUS_RESPONSE`'s lower-bound guard + `get_lp_str` guards + exact-consumption check + `{0, 64}` narrowing). Each guard is a `throw std::runtime_error(...)` executed *before* the access it protects on every control-flow path that reaches the access. The only reads not behind an explicit per-read guard are the tx-frame fixed-slot reads at offsets 32/40/48/56/96/128/129, all covered by the single line-204 precondition `len ≥ 131`. No path reaches a `data[i]`, `memcpy`, or `assign` with `i ≥ len` or `i + k > len`. □

### Lemma L-4 (encoder/decoder slot agreement for `TRANSACTION`, `pq_auth` included)

`encode_tx_frame` writes, in order: `from` padded to 32 B (offset 0), `amount`/`fee`/`nonce`/`reserved=0` as LE u64s (offsets 32/40/48/56), `to` padded to 32 B (offset 64), `payload` first-32 padded (offset 96), then the trailer `type` (offset 128), `payload_len` (offset 129), payload-overflow if any, `lp_str(from)`, `lp_str(to)`, `sig` (64 B), `hash` (32 B), and — iff `tx.pq_auth` is non-empty — the `[u32 LE len][bytes]` `pq_auth` section (`src/chain/block.cpp:194-199`). `decode_frame` reads `amount`/`fee`/`nonce` from offsets 32/40/48 (`src/chain/block.cpp:209-211`), checks `reserved == 0` at offset 56, reads `type` at 128 and `payload_len` at 129, reconstructs `payload` from the fixed slot (≤ 32 B case) or fixed slot + overflow (> 32 B case), reads `from`/`to`/`sig`/`hash` from the trailer, and then (`src/chain/block.cpp:244-254`) reads the `pq_auth` section iff bytes remain — a frame ending exactly at the hash decodes with `pq_auth` empty, mirroring the encoder's omit-when-empty rule, and the zero-length-section reject keeps the encoding *canonical* (no two distinct byte strings decode to the same tx). The authoritative `from`/`to` come from the trailer `lp_str` values (the 32-byte fixed slots are padding-lossy and not read back as identifiers). Every encoded field has a matching decode read at the same offset. □

### Lemma L-5 (length-prefixed-JSON path is verbatim)

For `m.type` outside the eleven fixed-frame types (i.e. the 8 length-prefixed-JSON types), `enc_B` computes `s = m.payload.dump()`, writes `le_u32(|s|)` then `s` verbatim (`binary_codec.cpp:616-621`). `decode_binary` reads `plen = le_get_u32(body)`, verifies `4 + plen ≤ body_len`, runs the WIRE-2 structural pre-scan, and parses `body + 4 .. body + 4 + plen` as JSON (`binary_codec.cpp:682-696`). The pre-scan never rejects a document within the shipped ceilings that `dump()` of a legitimate payload produces (`S022WireFormatCaps.md` sizing argument), and `nlohmann::json::parse(dump(v)) == v` for any JSON value `v` (round-trip property of the JSON library on its own output), so `dec(enc_B(m)).payload == m.payload`. □

### Lemma L-6 (encoder/decoder field agreement for `HELLO`)

`encode_hello_frame` (`binary_codec.cpp:267-276`) writes `lp_str(domain)`, `port` (u16 LE), `role` (u8), `shard_id` (u32 LE), `wire_version` (u8), reading each from the payload via `.value()` with the documented default. `decode_hello_frame` (`binary_codec.cpp:278-299`) reads the same five fields at the same offsets in the same order and rebuilds a payload with all five keys explicit. For a payload carrying all five fields (the `make_hello` shape, `messages.hpp:302-321`), decode returns them exactly; for a payload omitting a field, the encoder writes the default and the decoder returns it explicitly — equal under the tolerant `.value()` read that defines `π(HELLO)`. The exact-consumption check makes the frame boundary unambiguous, so no field read can absorb bytes of another. □

### Lemma L-7 (encoder/decoder field agreement for the five request/status frames)

Each of the five encoders writes exactly the fields its decoder reads, at the same offsets, in the same order, with the same widths (§1 table; `binary_codec.cpp:315-394`):

| Type | Encoder writes (line) | Decoder reads (line) |
|---|---|---|
| `GET_CHAIN` | `le_u64(from)`, `le_u16(count)` (316-317) | `le_get_u64(data)`, `le_get_u16(data + 8)` (324-325) |
| `STATUS_REQUEST` | nothing (329-331) | nothing; asserts `len == 0` (334-336) |
| `STATUS_RESPONSE` | `le_u64(height)`, `lp_str(genesis)` (340-347) | `le_get_u64(data)`, `get_lp_str` (354-355) |
| `SNAPSHOT_REQUEST` | `le_u32(headers)` (371) | `le_get_u32(data)` (378) |
| `HEADERS_REQUEST` | `le_u64(from)`, `le_u32(count)` (383-384) | `le_get_u64(data)`, `le_get_u32(data + 8)` (391-392) |

Each encoder reads its source values from the payload via `.value()` with the same default the corresponding `messages.hpp` builder and `GossipNet::handle_message` case use, and each decoder rebuilds a payload with exactly those keys explicit. Hence for a payload carrying all of its type's fields — the builder shape (`messages.hpp:372-374, 381-383, 401-413`) — decode returns them exactly, and `dec(enc_B(m)).payload == m.payload` as JSON values; for a payload omitting a field, the encoder writes the default and the decoder returns it explicitly, which is `π`-equal under the tolerant `.value()` read that defines `π` for these types. Two boundary details make the agreement total rather than approximate:

- **Field-width agreement is exact in both directions.** `count` is u16 for `GET_CHAIN` and u32 for `HEADERS_REQUEST` on *both* sides (P-3), so no value representable by a builder is truncated by the encoder, and no value the decoder produces exceeds what the handler signature accepts.
- **The empty `genesis` is a distinguishable value, not a sentinel.** `put_lp_str("")` emits the single byte `0x00` and `get_lp_str` returns `""` — distinct from any 64-char hex string, so P-1's consumer branch survives the round trip. The `{0, 64}` narrowing rejects only lengths no conforming encoder produces, hence it never rejects an `enc_B` output and does not weaken this lemma.

The exact-consumption checks (a strict `len` equality for four of the frames, `off != len` for `STATUS_RESPONSE`) make each frame boundary unambiguous, so no field read can absorb bytes of another and no encoding is non-canonical. □

### Lemma L-8 (encoder/decoder field agreement for the four consensus-chatter frames)

Each of the four encoders writes exactly the fields its decoder reads, at the same offsets, in the same order, with the same widths (§1 table; `binary_codec.cpp:441-557`):

| Type | Encoder writes (line) | Decoder reads (line) |
|---|---|---|
| `ABORT_CLAIM` | `chain::encode_abort_claims({claim})` (443) | `chain::decode_abort_claims`, then `size() == 1` (448-452) |
| `BLOCK_SIG` | `le_u64(block_index)`, `lp_str(signer)`, `delay_output`, `dh_secret`, `ed_sig` (458-467) | same five, same order (474-480) |
| `EQUIVOCATION_EVIDENCE` | `lp_str(equivocator)`, `le_u64(block_index)`, `digest_a`, `sig_a`, `digest_b`, `sig_b`, `le_u32(shard_id)`, `le_u64(beacon_anchor_height)` (486-493) | same eight, same order (499-508) |
| `ABORT_EVENT` | `le_u64(block_index)`, `prev_hash`, `round`, `lp_str(aborting_node)`, `le_u64(timestamp)`, `event_hash`, claims blob (515-529) | same seven, same order (535-550) |

Three boundary details make the agreement total rather than approximate:

- **`ABORT_CLAIM` agreement is inherited, not restated.** Both directions call the shared `chain::encode_abort_claims` / `decode_abort_claims` pair, whose own round-trip identity is proved in `AbortDigestCanonicalizationSoundness.md`. The only claim this lemma adds is the count restriction (P-5): `encode` always writes count 1, `decode` accepts only count 1, so the restriction is respected by every reachable encoder output and is therefore not an accept-narrowing on honest traffic.
- **The all-zero `dh_secret` is a value, not an absence.** `put`/`get` of the fixed 32-byte slot round-trips `Hash{}` to `Hash{}`; the decoder's `to_json()` renders it as 64 `'0'` characters, which is exactly what the JSON path's absent-means-zero rule produced downstream (P-6). So the S-009 legacy reveal survives the container change unchanged.
- **`timestamp` is bit-exact across the signed/unsigned boundary** (P-8), so `π`'s `int64_t` component is preserved over the whole range, not merely over non-negative values.

Hence for a builder-shaped `m` (`messages.hpp:328-330, 334-336, 337-347, 348-350`), decode returns every field exactly, and `dec(enc_B(m)).payload == m.payload`. □

### Lemma L-9 (every fixed frame is exact-consuming, in both directions)

For each of the eleven fixed-frame decoders, define `L(m)` as the length of that type's canonical encoding of `m`. Each decoder rejects every body of length `≠ L(m)`:

- Seven decoders (`GET_CHAIN`, `STATUS_REQUEST`, `SNAPSHOT_REQUEST`, `HEADERS_REQUEST`, `BLOCK_SIG`, `EQUIVOCATION_EVIDENCE`, and — after its lp_str — the fixed tail of each) guard with a **strict equality** on `len`. An equality rejects the short body and the padded body with one expression; there is no direction it leaves open.
- `HELLO` and `STATUS_RESPONSE` are variable-length and therefore carry the guard *trio*: a lower bound, the `get_lp_str` internal guards, then an `off != len` exact-consumption check.
- `ABORT_CLAIM` and `ABORT_EVENT` delegate their tail to `chain::decode_abort_claims`, which is itself exact-consuming (`"abort claims: trailing bytes after last claim"`), and P-7 places the blob last so that the sub-codec's check *is* the frame's check.
- `TRANSACTION` ends either exactly at the hash (no `pq_auth`) or with a section whose declared length must equal the remaining bytes exactly (`"pq_auth length mismatch"`).

Composing: a body accepted by a fixed-frame decoder has length exactly `L(m)` and its bytes are, field by field, what `enc_B` would write for the decoded `m` (L-4, L-6, L-7, L-8). Hence `enc_B(dec(B)) = B`, which is T-2b.

**The lemma's fragility is the point.** The equality form is what carries the "both directions" content; relaxing any `len != N` to `len < N` or `len > N` preserves T-2 (honest messages still round-trip) and preserves T-3 (the surviving one-sided guard still bounds every read) while destroying T-2b — the decoder would accept a padded body and normalize it away, giving every message a second, third, … encoding. Because that failure is invisible to a round-trip test *and* to a bounds test, L-9 is gated by a dedicated exhaustive sweep rather than by the per-frame legs; see §6 and Finding F-4. □

### Proof of T-1

Totality and determinism of `det` are L-2. Coverage: by L-1, every reachable `enc_B` output has first two bytes `0xB1 0x01` and length ≥ 4, so `det(enc_B(m)) = true` for all `m ∈ dom(enc_B)`. Fail-closed rejection: `Message::deserialize` (`messages.cpp:82-87`) has a single entry check — `if (!is_binary_envelope(data, len)) throw` — whose exception message contains the string `"not a binary envelope"`; no other parse is attempted on the failing branch, so every body with `|B| < 4`, `B[0] ≠ 0xB1`, or `B[1] ≠ 0x01` is rejected before any payload work. A legacy JSON envelope begins with `'{'` = `0x7B ≠ 0xB1` and therefore lands in this throw; the D2 negative gate (test-binary-codec leg 5) pins exactly this — a *well-formed* legacy envelope rejected with the specific string, so a mutant that re-admits a JSON parse path goes red. □

### Proof of T-2

By T-1, `det(enc_B(m)) = true`; for a structurally-valid `m`, `|enc_B(m)| ≤ max_message_bytes(m.type)` (the S-022 sizing argument — legitimate messages sit far below their tier), so the WIRE-1 cap passes and `dec(enc_B(m)) = decode_binary(enc_B(m))`. Five cases, jointly exhaustive over the 19 declared types and over any out-of-enum type byte (which falls in the last case):

- `m.type = HELLO`: by L-6, `decode_hello_frame` returns the five named fields the encoder wrote, so `π(dec(enc_B(m))) = π(m)`.
- `m.type = TRANSACTION`: by L-4, every field the encoder wrote is read back at the matching offset; the S-002 fix (`src/chain/block.cpp:209-211`) supplies amount/fee/nonce from the fixed slots, the trailer supplies `from`/`to`/`payload`/`sig`/`hash`, and the D2-inc1 section supplies `pq_auth` (empty iff the encoder omitted it iff `m`'s tx had it empty). `decode_binary` then sets `m.payload = tx.to_json()`. Since `chain::Transaction::from_json ∘ to_json` is the identity on the projected fields — including `pq_auth`, whose JSON encoding follows the same omit-when-empty convention — `π(dec(enc_B(m))) = π(m)`.
- `m.type ∈ {GET_CHAIN, STATUS_REQUEST, STATUS_RESPONSE, SNAPSHOT_REQUEST, HEADERS_REQUEST}`: the encode switch (`binary_codec.cpp:598-612`) and the decode switch (`binary_codec.cpp:659-680`) select the same arm for the same type byte — the type byte is written by `put_envelope_header` from `m.type` and read back at offset 2 unchanged (L-1) — so encoder and decoder never disagree on which frame layout applies. By L-7 that arm's encoder/decoder pair agrees field-for-field, so `π(dec(enc_B(m))) = π(m)`; and for a builder-shaped `m` the stronger `dec(enc_B(m)).payload == m.payload` holds (P-2 is what makes this true for `STATUS_REQUEST`, whose payload would otherwise be `null` on one side and `{}` on the other).
- `m.type ∈ {BLOCK_SIG, ABORT_CLAIM, ABORT_EVENT, EQUIVOCATION_EVIDENCE}`: the encode switch (`binary_codec.cpp:606-611`) and the decode switch (`binary_codec.cpp:671-680`) select the same arm for the same type byte, and by L-8 that arm's encoder/decoder pair agrees field-for-field, so `π(dec(enc_B(m))) = π(m)`; for a builder-shaped `m` the whole-payload identity holds too (leg 4c). By P-4 this is the *only* obligation the swap creates: the signatures these frames carry are computed over binary field tuples, so preserving `π` preserves every verification pre-image bit-for-bit.
- `m.type` in the remaining 8 types: by L-5, `dec(enc_B(m)).payload == m.payload`, and `π` for these types is the whole payload, so `π(dec(enc_B(m))) = π(m)`. □

### Proof of T-3

By L-3, every indexed read, `memcpy`, and range `assign` in `decode_binary`, `decode_tx_frame`, `decode_hello_frame` and the five request/status decoders is preceded on all reachable paths by a length guard that throws when the required `off + k ≤ len` condition fails — including the three added surfaces: the `pq_auth` section (header guard, then the exact-consumption equality `pq_len == len − off` which pins the section-body window to end exactly at `data + len`), the HELLO frame (the `get_lp_str` guards plus the combined 8-byte fixed-field guard), the five D2-inc6a frames (four strict `len` equalities, which are simultaneously bounds and exact-consumption guards, plus `STATUS_RESPONSE`'s `len ≥ 9` lower bound → `get_lp_str` guards → `off != len` consumption check → `{0, 64}` narrowing), and the four D2-inc6b chatter frames (§3.7's inventory: two strict `len` equalities, `ABORT_EVENT`'s four-stage lower-bound chain, and the two delegations to `chain::decode_abort_claims`). The helpers `le_get_u16` / `le_get_u32` / `le_get_u64` read fixed widths (2/4/8 bytes) from a pointer the caller has already bounds-checked; `get_lp_str` carries its own two guards. The encoder's `put_lp_str` enforces the ≤ 255 bound that `get_lp_str`'s u8 length field can represent, so a round-tripped honest frame never trips the decode guards, while an adversarial frame either satisfies every guard (and decodes to a structurally-valid value) or trips one (and throws). No path performs an access with `off + k > len`. Hence the decode path has no out-of-bounds read and no undefined behavior on any input. □

### Proof of T-4

`dec` (`messages.cpp:82-116`) is a straight-line composition of three throw-or-continue stages. *Stage 1 (T-1 gate):* a body failing `det` raises the `"not a binary envelope"` throw — this is where every `'{'`-leading legacy JSON body now lands; no JSON parser exists on any path of `dec`. *Stage 2 (WIRE-1):* the pre-decode per-type cap either throws or continues; `data[2]` is safe to read because stage 1 established `len ≥ 4`. *Stage 3:* `decode_binary` either returns a `Message` (with `type = static_cast<MsgType>(data[2])`, defined for all 256 byte values, and a `payload` set from `decode_hello_frame`, `tx.to_json()`, one of the five request/status frame decoders, one of the four consensus-chatter frame decoders, or a parsed JSON window) or throws — by T-3 it never reads OOB, every internal failure is a `throw std::runtime_error`, the WIRE-2 pre-scan throws on ceiling violation, and `nlohmann::json::parse` of the payload window throws `parse_error` (a `std::exception` subclass) on malformed JSON. The D2-inc6a/inc6b dispatch does not add a failure mode of its own: it is a `switch` on a value already materialised at stage 2, every arm is a single call followed by `return`, and its `default: break;` falls through to the pre-existing length-prefixed-JSON tail — so the case analysis remains exhaustive over all 256 type-byte values with no unreachable-return path. All stages terminate (no loops in `decode_binary`; `decode_tx_frame` / `decode_hello_frame` / the five request/status decoders have only straight-line code plus the fixed-iteration helper loops in `le_get_*` / `put_*`; the WIRE-2 scan is a single bounded pass; `nlohmann` parsing terminates on finite input). Therefore `dec` is total in the return-or-throw sense.

Composed with `Peer::read_body` (`src/net/peer.cpp:62-112`):

```cpp
try {
    auto msg = Message::deserialize(self->body_buf_.data(), self->body_buf_.size());
    if (self->body_buf_.size() > max_message_bytes(msg.type)) { /* close */ }
    if (self->on_msg_) self->on_msg_(self, msg);
} catch (std::exception& e) {
    std::cerr << "[peer] message parse error from " << self->address_ << ...;
    if (self->on_close_) self->on_close_(self);   // WIRE-3
    return;
}
self->read_header();
```

every `dec` throw is caught, logged, and **closes the connection** (`peer.cpp:107` — the loop does NOT iterate to `read_header`), and every `dec` success is gated by the post-decode S-022 cap (`peer.cpp:80-87`) before `on_msg_` dispatch. So `dec`'s totality lifts to "every peer body is safely processed": decoded-and-capped, or dropped-and-disconnected.

**⚠ CORRECTED (round-12 hostile-wire audit, wf_c277c6d1).** An earlier revision of this passage read *"connection stays open; the loop iterates to `read_header`"* and concluded "dropped-and-logged". That was accurate at the time and is why T-4 here discharged the totality precondition — but the disposition it described was itself the defect: re-arming after a parse failure made every pre-auth parse cost infinitely repeatable at zero cost to the sender. **`dec`'s totality is unchanged** (it still throws rather than returning garbage, which is all this theorem needs); only the connection disposition after a throw changed. See `S022WireFormatCaps.md` T-6. □

---

## 5. Adversary model + notable findings

### 5.1 Adversary model

The codec defends against an adversary who controls the bytes of a body `B` delivered to `Message::deserialize` (a connected peer sending arbitrary frames within the `kMaxFrameBytes` framing ceiling — including the very first frame on a connection, since HELLO is now ordinary binary traffic):

**(a) Truncated binary frame.** Adversary sends `0xB1 0x01 <type> 0x00` followed by fewer bytes than the type's payload requires. **Defended (T-3 + T-4).** Every short read trips a length guard (`len < 128+1+2` for TRANSACTION, the `get_lp_str` + combined-fixed-field guards for HELLO, the strict `len` equalities / `len ≥ 9` lower bound for the five request/status frames, `body_len < 4` / `4+plen > body_len` for the length-prefixed-JSON types, the sig/hash and `pq_auth` guards) and throws; the peer logs and closes (WIRE-3).

**(b) Out-of-enum type byte.** Adversary sends `0xB1 0x01 0xFF 0x00 ...`. **Defended (T-1 + S-022 completeness T-1 step 4).** `static_cast<MsgType>(0xFF)` is a valid (out-of-enum) `MsgType`; the WIRE-1 pre-decode cap defaults it to the tight 1 MB tier, and the length-prefixed-JSON decode path handles it (it matches none of the eleven fixed-frame arms, so the dispatch `switch` falls through on `default`). No OOB, no UB.

**(c) Non-canonical reserved field.** Adversary sets the tx-frame reserved u64 (offset 56) non-zero, or the envelope reserved byte (offset 3) non-zero. **Defended (both fail-closed).** The tx-frame reserved field is checked (`src/chain/block.cpp:213-214` throws), and — since the Finding F-1 closure — the envelope reserved byte is checked too (`binary_codec.cpp:642-643` throws `"reserved envelope byte non-zero"`), matching the independent light/wallet conformance decoders. The envelope is strictly canonical: two distinct envelope byte strings never decode to the same `Message` via reserved-byte malleability.

**(d) Format-confusion / legacy-format smuggling.** Adversary sends a JSON body (or any non-`0xB1` bytes) hoping to reach a parser. **Defended (T-1).** There is no second format: any body failing the magic check — including a well-formed legacy wire-version-0 JSON envelope — is rejected with the `"not a binary envelope"` throw before any parse. The deleted JSON path cannot be re-entered from the wire; test-binary-codec leg 5 pins this with a mutant-sensitive negative vector.

**(e) Oversized length-prefix in the length-prefixed-JSON path.** Adversary sets `plen` to a huge value to provoke a large allocation. **Defended (T-3 + S-022).** `decode_binary` rejects `4 + plen > body_len` *before* parsing; `body_len` is bounded by the WIRE-1 pre-decode per-type cap (`messages.cpp:106-114`) which fires before `decode_binary` runs, and the WIRE-2 structural ceiling (`binary_codec.cpp:694`) bounds the DOM the parse can build. See `S022WireFormatCaps.md` for the measured amplification bounds. D2-inc6a and D2-inc6b *narrow* this surface — nine types that previously reached `nlohmann::json::parse` no longer can — but do not close it: the 8 remaining types still do, and the type byte at offset 2 is attacker-chosen, so WIRE-2 stays load-bearing.

**(f) `pq_auth` section abuse.** Adversary appends bytes after a TRANSACTION frame's hash: trailing garbage, a zero-length section, a short body, or extra bytes after a valid section. **Defended (T-3 + L-4 canonicality).** The section decode is fail-closed: `"truncated pq_auth header"`, `"empty pq_auth section"`, and `"pq_auth length mismatch"` cover all four shapes (test-tx-binary-codec leg 10 pins each string). A frame ending exactly at the hash is the unique encoding of a non-PQ tx.

**(g) HELLO frame padding/truncation.** Adversary pads a HELLO with trailing bytes (hoping a future field is silently absorbed) or truncates it. **Defended (T-3 + §3.5).** `"truncated HELLO frame"` / `"HELLO frame trailing bytes"` reject both fail-closed; an additive HELLO field can only ship behind a bumped `wire_version` advertisement.

**(h) Request/status frame padding, truncation, or an over-long `genesis`.** Adversary pads a `GET_CHAIN` / `SNAPSHOT_REQUEST` / `HEADERS_REQUEST` frame, sends a non-empty `STATUS_REQUEST`, truncates any of them, or answers a status probe with a `genesis` string of arbitrary length. **Defended (T-3 + §3.6).** The four strict `len` equalities reject padding and truncation with the specific strings `"bad GET_CHAIN frame length"`, `"STATUS_REQUEST frame not empty"`, `"bad SNAPSHOT_REQUEST frame length"`, `"bad HEADERS_REQUEST frame length"`; `STATUS_RESPONSE` rejects a short frame (`"truncated STATUS_RESPONSE frame"`), a padded one (`"STATUS_RESPONSE frame trailing bytes"`), and any `genesis` length outside `{0, 64}` (`"STATUS_RESPONSE genesis length must be 0 or 64"`). The last is a genuine accept-*narrowing* over the pre-inc6a JSON payload, which admitted a `genesis` string of any length up to the 1 MB tier cap. Test-binary-codec leg 4b pins four of these behaviourally by their specific string — padded `GET_CHAIN`, non-empty `STATUS_REQUEST`, truncated `HEADERS_REQUEST`, and the out-of-`{0, 64}` `genesis` — and disabling the `{0, 64}` narrowing is the mutant that reddens the leg. The remaining strings (`"bad SNAPSHOT_REQUEST frame length"`, `"truncated STATUS_RESPONSE frame"`, `"STATUS_RESPONSE frame trailing bytes"`) rest on the §3.6 structural argument, not on a dedicated negative leg. Note the frames carry **no signature and no consensus commitment**, so none of these shapes was ever a consensus-safety surface — the win is a smaller pre-auth parse surface and an unambiguous frame boundary, not a closed accept-widening hole.

**(i) Consensus-chatter frame padding, truncation, or a non-canonical claim count.** Adversary pads or truncates a `BLOCK_SIG` / `EQUIVOCATION_EVIDENCE` / `ABORT_CLAIM` / `ABORT_EVENT` frame, or sends an `ABORT_CLAIM` whose count-prefixed blob carries zero or two claims. **Defended (T-3 + T-2b + §3.7).** The two strict `len` equalities reject padding and truncation with `"bad BLOCK_SIG frame length"` / `"bad EQUIVOCATION_EVIDENCE frame length"`; `ABORT_EVENT`'s lower-bound chain rejects each truncation stage by name; and both claim-carrying frames inherit `"abort claims: trailing bytes after last claim"` from the shared sub-codec (P-7). A blob with a count other than one is rejected with `"binary_codec: ABORT_CLAIM must carry exactly one claim"` (P-5) — without which a two-claim blob would be a second valid encoding of a one-claim message. Unlike the inc6a five, these frames *do* carry signatures — but by P-4 the signatures are over binary field tuples, not over the frame, so a malformed frame is rejected by the codec before any verification and a well-formed one produces a bit-identical pre-image. No accept rule widened.

The codec does *not* defend against (and is not designed to defend against):

- Semantic validity of the decoded payload (e.g., a syntactically-valid but economically-invalid `Transaction`, or an unverified `pq_auth` blob — the codec carries it; `verify_pq_transaction` judges it). That is the apply/admission layer's job (`NonceMonotonicity.md`, `FeeAccounting.md`, S-002 signature verification). The codec guarantees a *structurally* well-formed `Message`, not a *semantically* admissible one.
- Compression bombs / parser DoS inside `nlohmann::json::parse` beyond the WIRE-1 + WIRE-2 ceilings. Bounded and *measured* in `S022WireFormatCaps.md` (T-5 work bound, F-6 residual); mitigation-not-elimination is documented there, not re-litigated here.

### 5.2 Notable findings

**Finding F-1 (Envelope reserved byte at offset 3 — RESOLVED).** As originally recorded here, `put_envelope_header` wrote `0x00` but `decode_binary` ignored the byte on decode — a benign wire malleability, flagged with a ~2 LOC mitigation. That mitigation has since shipped: `decode_binary` now rejects `data[3] != 0x00` fail-closed (`binary_codec.cpp:642-643`), closing the S-043-class validation asymmetry `ReservedDiscriminatorAudit.md` §6 found (the daemon silently ignored the byte while the light/wallet conformance decoders rejected it, so a mixed fleet disagreed on frame validity). Gated: test-binary-codec leg 6b (tampered reserved byte throws; zero-reserved control still decodes). The envelope is now strictly canonical — see §5.1(c).

**Finding F-4 (One-sided length legs left canonicality ungated — RESOLVED).** Found by the falsify-on-mutant pass on D2-inc6b. Each fixed frame had a negative leg, but each probed only **one** direction: `GET_CHAIN` and `BLOCK_SIG` were tested padded, `HEADERS_REQUEST` and `EQUIVOCATION_EVIDENCE` truncated, and `SNAPSHOT_REQUEST` neither. Relaxing an exact `len != N` guard to a one-sided `len > N` therefore left **every gate in the tree green** — `test-binary-codec`, `test-binary-codec-roundtrip-exhaustive`, `test-wire-caps-discriminator`, `test-consensus-msgs`, `test-wire-types`, `test-equivocation-evidence` — while the decoder silently accepted trailing bytes and normalized them away. That is a live violation of T-2b: every message would have acquired an unbounded family of accepted encodings, which is precisely what the D2 migration exists to eliminate. **Why the existing gates could not see it:** the mutant preserves T-2 (honest messages still round-trip) and preserves T-3 (the surviving one-sided guard still bounds every read), and those are the two properties the legs asserted. Canonicality is a third property and needed its own leg. **Closure:** a table-driven exact-length sweep over all eleven fixed-layout frames (§6, leg 4d), asserting for each that the body plus one trailing byte and the body minus one byte are both rejected by that frame's specific string, plus a control leg that the unmodified body decodes so the rejection legs cannot pass vacuously. Mutant-verified in both directions: `EQUIVOCATION_EVIDENCE` `!=`→`>` and `SNAPSHOT_REQUEST` `!=`→`<` each redden the sweep and nothing else. **Generalization worth carrying forward:** an exactness check is a *conjunction* of two accept-narrowings, and a leg that exercises one conjunct is not a gate on the conjunction. The sweep's table is also the completeness statement — a future fixed frame absent from it has no exactness gate.

**Finding F-2 (Binary `TRANSACTION` frame carries `from`/`to` twice).** The fixed-slot pubkey area (offsets 0..31, 64..95) and the trailer `lp_str(from)` / `lp_str(to)` both encode the address strings. The decoder reads the *trailer* values as authoritative and treats the fixed slots as padding-lossy (`src/chain/block.cpp:151-153` comment; trailer `from`/`to` reads at 234-235). The module comment (`binary_codec.cpp:79-84`) flags this as intentional transitional redundancy: the 4×256-bit frame predates the domain-string account model, and the trailer exists so the frame round-trips real transactions until identity migrates to raw pubkeys (R3+). **Severity:** None (correctness-neutral; a bandwidth inefficiency of ≤ ~64 redundant bytes per tx). **Status:** documented design wrinkle, not a defect. The S-002 fix preserved the property that the *numeric* fields (amount/fee/nonce) live only in the fixed slots, so there is no double-encoding ambiguity for the consensus-bound numeric fields.

**Finding F-3 (No dedicated negative test — RESOLVED).** The negative surface this finding asked for now exists across the shipped gates: test-binary-codec legs 7-8 (garbage bytes, truncated envelope header), leg 1b (truncated/padded HELLO frames with the specific reject strings), leg 4b (the four D2-inc6a request/status rejects, each by specific string), leg 5 (the D2 legacy-envelope reject), leg 6b (reserved-byte tamper), and test-tx-binary-codec leg 10 (all three `pq_auth` fail-closed reject strings, plus append-after-section, each asserted by *specific string* rather than bare throw — the SECOND-register discipline). T-3's guard inventory is therefore behaviorally pinned, not only structurally argued — with the §3.6 residual named in §5.1(h): three of the request/status reject strings have no dedicated leg.

**Finding F-4 (Endianness coupling to host).** The binary envelope, tx frame, HELLO frame and the five request/status frames use little-endian for all multi-byte integers (`binary_codec.cpp:165-170` rationale), matching x86_64/ARM64 host endianness. The `le_put_*` / `le_get_*` helpers (`binary_codec.cpp:191-223`; the moved tx-frame codec carries its own copies at `src/chain/block.cpp:90-122`) implement LE explicitly via shifts, so the codec is *byte-order-correct on any host* (the explicit shift-based pack/unpack does not depend on host endianness — it always emits/reads little-endian regardless of the machine). The "matches host endianness" comment refers to a micro-optimization opportunity (no byte-swap on LE hosts), not a correctness dependency. **Severity:** None (the explicit shifts make the codec portable). Noted to forestall a misreading of the comment as a portability bug.

Of the four findings, F-1 and F-3 are closed with shipped, gated code; F-2 and F-4 remain documented non-defects. None invalidates T-1 through T-4.

---

## 6. Test-suite citation

| Test | Source | Coverage |
|---|---|---|
| `tools/test_binary_codec.sh` (via `determ test-binary-codec`, `src/main.cpp:10137`) | In-process wire-codec unit test (rewritten for the D2 binary-only wire) | Binary HELLO round-trip through the fixed frame (leg 1) + the truncated/trailing HELLO rejects pinning `"truncated HELLO frame"` / `"HELLO frame trailing bytes"` (leg 1b — T-2 HELLO case, T-3 §3.5 guards); STATUS_REQUEST and TRANSACTION round-trips (legs 2-3, `src/main.cpp:10209-10239`) and the length-prefixed-JSON round-trip via CONTRIB (leg 6); the builder-shaped STATUS_RESPONSE round-trip through its fixed frame (leg 4, `src/main.cpp:10243-10261`); **the D2-inc6a request/status legs (leg 4b, `src/main.cpp:10263-10308`)** — see the row below; the **D2 negative leg** — a *well-formed* legacy JSON envelope rejected with the specific `"not a binary envelope"` string, so a mutant re-admitting a JSON parse path goes red (leg 5 — T-1); reserved-envelope-byte reject + zero-reserved control (leg 6b — §5.1(c), F-1 closure); garbage/truncated-header rejects (legs 7-8 — T-3/T-4); WIRE-1 pre-decode cap ordering (leg 8b); the WIRE-2 structural-ceiling legs rebuilt as **binary-envelope vectors** (legs 8d+ — the hostile payloads now travel inside `0xB1` frames, matching the only wire that exists — driven on `CHAIN_RESPONSE` / `CONTRIB` / `SNAPSHOT_RESPONSE`, all three still lp-JSON types after D2-inc6a, so the legs remain live); the S-022 cap-table golden vectors. |
| ↳ **leg 4b** (`src/main.cpp:10263-10308`) — the D2-inc6a gate | 5 round-trip legs + 4 fail-closed reject-string legs | **Round-trip (T-2, L-7, P-2):** `make_get_chain(42, 7)`, `make_status_request()` (the zero-length frame — asserts `back.payload == m.payload`, which is exactly what P-2's `nlohmann::json::object()` normalization makes true), `make_status_response(0, "")` (**the empty-genesis case an empty chain legitimately answers with — P-1**), `make_snapshot_request(99)`, `make_headers_request(5, 256)`; each asserts type *and* payload equality, i.e. the whole-payload identity, not merely `π`-equality. **Fail-closed (T-3, §3.6, §5.1(h)):** a padded `GET_CHAIN` → `"bad GET_CHAIN frame length"`; a one-byte `STATUS_REQUEST` → `"STATUS_REQUEST frame not empty"`; a truncated `HEADERS_REQUEST` → `"bad HEADERS_REQUEST frame length"`; `make_status_response(1, "abc")` → `"genesis length"`. Each asserts the SPECIFIC substring, not a bare throw. **Mutant that reddens it:** deleting the `{0, 64}` narrowing at `binary_codec.cpp:361-363` — the fourth reject stops firing while all five round-trips stay green, so this leg is the sole behavioural pin on the *daemon-side* narrowing (the light mirror re-implements the rule independently and is gated separately, so a daemon-side mutant does not red it). |
| ↳ **leg 4c** — the D2-inc6b gate | 4 round-trip legs + 2 fidelity legs + 4 fail-closed reject-string legs | **Round-trip (T-2, L-8):** `make_abort_claim`, `make_block_sig`, `make_equivocation_evidence`, `make_abort_event`, each asserting type *and* whole-payload equality. **Fidelity:** a **negative** `ABORT_EVENT.timestamp` round-trips bit-exactly (P-8 — a u32 slot or a clamp would corrupt a field that is inside the abort-event hash pre-image); an all-zero `BLOCK_SIG.dh_secret` is preserved as 64 `'0'` characters (P-6 — the S-009 legacy/absent reveal must not become a different value). **Fail-closed (T-3, §3.7):** a padded `BLOCK_SIG` → `"bad BLOCK_SIG frame length"`; a truncated `EQUIVOCATION_EVIDENCE` → `"bad EQUIVOCATION_EVIDENCE frame length"`; a two-claim `ABORT_CLAIM` → `"exactly one claim"` (P-5, the canonicality pin); a trailing byte on `ABORT_EVENT` → `"trailing bytes after last claim"` (P-7, the delegated exact consumption). Each asserts the SPECIFIC substring. **Mutant-verified:** relaxing `claims.size() != 1` to `claims.empty()` reds the two-claim leg alone; truncating the timestamp to 32 bits reds the negative-timestamp leg alone. |
| ↳ **leg 4d** — the exact-length sweep (T-2b, L-9, F-4) | 11 control legs + 11 padded legs + 10 truncated legs (`STATUS_REQUEST` is zero-length, so it has no truncated case) | A table over **all eleven** fixed-layout frames. For each: a control assertion that the unmodified body decodes (so the rejection legs cannot pass vacuously), then `body + 0x00` and `body − 1 byte`, each required to throw with that frame's specific string. Three frames end in a length-prefixed string (`STATUS_RESPONSE.genesis`, and the claim's trailing `claimer` inside `ABORT_CLAIM` / `ABORT_EVENT`), so their truncated case is caught by the `lp_str` bound before the frame-level check and names that mechanism instead. **This leg exists because the per-frame legs above could not see the F-4 mutant class**: a one-sided length guard preserves both round-trip (T-2) and bounds-safety (T-3), so only a two-directional sweep pins canonicality. **Mutants that redden it:** `EQUIVOCATION_EVIDENCE` `!=`→`>`, `SNAPSHOT_REQUEST` `!=`→`<` — each reds exactly its own row and nothing else in the tree. The `cases.size() == 11` assertion is the completeness pin: a new fixed frame added without a table row reds the leg. |
| `tools/test_tx_binary_codec.sh` (via `determ test-tx-binary-codec`, `src/main.cpp:23023`) | Transaction fixed-frame codec suite | Legs 1-8: the S-002 fixed-slot round-trip (amount/fee/nonce), trailer authority, hash invariance. Leg 9 (D2-inc1): `pq_auth` round-trips through the frame at realistic ML-DSA scale, the section is exactly `[u32 len][bytes]`, and a non-PQ tx emits **no** section (byte-identity with the pre-§3.21 layout) — T-2's extended `π`. Leg 10: fail-closed decode pinning each specific reject string — `"truncated pq_auth header"`, `"empty pq_auth section"`, `"pq_auth length mismatch"` (short body *and* byte-appended-after-section) — T-3's §3.4 `pq_auth` guard rows. Mutant-verified: reverting the encoder's `pq_auth` section reds leg 9. |
| `tools/test_binary_codec_roundtrip_exhaustive.sh` (via `determ test-binary-codec-roundtrip-exhaustive`, `src/main.cpp:10712`) | Exhaustive per-MsgType roundtrip | Walks every `MsgType` — HELLO and the five request/status types now included via their fixed binary frames — through `encode_binary` → `decode_binary`, asserting type + payload preservation, the four envelope header bytes (`0xB1`, `0x01`, type, `0x00` reserved), and tamper-loud-fail on payload byte flips. Each of the five is driven from its builder (`src/main.cpp:10957-11013`), and `STATUS_RESPONSE` is run **twice** — a 64-char genesis and the empty-genesis empty-chain shape — so P-1's branch is covered on the exhaustive path as well. The truncated-payload leg was re-based onto `CONTRIB` (`src/main.cpp:11043-11068`) because `STATUS_RESPONSE` no longer carries a length-prefixed JSON payload to truncate. Direct evidence for T-2 across the full type surface; indirect evidence for T-1 and L-1. |
| `tools/test_hello_handshake_determinism.sh` (via `determ test-hello-handshake-determinism`, `src/main.cpp:56930`) | HELLO determinism suite | All 7 scenarios run on the **binary frame** (replay determinism, round-trip, cross-instance, field-binding, boundary values); pins that the encoded HELLO body starts with `0xB1` (D2 — the old "HELLO is always JSON" contract is inverted). Mutant-verified: an encoder that drops `shard_id` from the frame reds the field-binding legs. Composes with §2.3 (the send path has no version selection to get wrong). |
| `tools/test_protocol_version_pinning.sh` (via `determ test-protocol-version-pinning`, `src/main.cpp:52197`) | PROTOCOL.md §16 version-contract pinning | §8 pins the `wire_version` **advertisement** surviving the HELLO binary round-trip; §9 is *inverted* from its pre-D2 form — it now pins that `encode_binary(HELLO)` **succeeds** with type byte 0 (the old §9 pinned the throw; this leg is the tombstone of the HELLO JSON carve-out). Its envelope-magic fixture (§3, `src/main.cpp:52239-52245`) is now builder-shaped (`make_status_response(100, <64 chars>)`) because the invented shape it previously used cannot survive the D2-inc6a frame. |
| `tools/test_wire_caps_discriminator.sh` (via `determ test-wire-caps-discriminator`, `src/main.cpp:57280`) | Framing/cap layering + discriminator contract (was `test_wire_negotiation.sh`; its section (A) — the `min(ours, theirs)` negotiation arithmetic — died with the negotiation and is deleted) | Section (B): every per-type cap ≤ `kMaxFrameBytes`, the three tiers strictly ordered, unmapped types fail closed at 1 MB. Section (C): discriminator-byte preservation for **every** MsgType — HELLO and the five request/status types included — the type byte at offset 2 survives encode → decode independent of payload (the receive-side dispatch key, T-1/T-4's `static_cast` surface). The five frames are driven from an *empty object* payload here (`src/main.cpp:57392-57432`), so this leg additionally witnesses L-7's default-valued encode path. |
| `tools/test_light_decode_wire.sh` (via `determ-light decode-wire`) | Independent light-client conformance decoder | The light binary re-implements the published layout from scratch — including the five D2-inc6a frames under `payload_kind="req_frame"` (`light/main.cpp:8881-8928`) with the same `{0, 64}` genesis narrowing (`light/main.cpp:8914-8917`), and the four D2-inc6b frames under `payload_kind="chatter_frame"` (`light/main.cpp:8929-8996`) with the same `count == 1` `ABORT_CLAIM` restriction and its own exact-consumption check. *Scope note:* the suite drives it with **hand-crafted byte vectors** built from the published spec (`tools/test_light_decode_wire.sh:122-138`), not with daemon-produced artifacts — so it pins the *light* decoder against the spec and the daemon's `{0, 64}` rule is not gated from here. Its value to §3.6 is that a second, independently-written decoder agrees on the frame contract, so a daemon/light disagreement of the `ReservedDiscriminatorAudit.md` §6 class is visible on any real artifact an operator cross-reads. |

The roundtrip-exhaustive test is the primary operational backstop for T-2; the negative legs across test-binary-codec (legs 1b, 4b, 5-8) and test-tx-binary-codec pin T-1, T-3, and the F-1/F-3 closures behaviorally; T-1 and T-3 additionally rest on the short structural arguments grounded in the §3 source citation. The S-002 regression (per `S002-Mempool-Sig-Verify.md`) is the historical witness that the `TRANSACTION` round-trip *was* broken (amount/fee/nonce dropped) and is now fixed — the D2-inc1 `pq_auth` closure is the same story one layer out (the frame silently dropped `pq_auth` until the section shipped, and leg 9 is the gate that keeps it carried) — and P-2 is the third instance of the pattern at a smaller scale: a `null`-vs-`{}` payload mismatch that the pre-inc6a JSON path hid and the fixed frame forced into the open.

---

## 7. Status

**Shipped (analytic).** This document formalizes the decode-correctness surface of the shipped D2 binary-only wire codec; it introduces no code changes. The codec (`src/net/binary_codec.cpp`) and its driver (`src/net/messages.cpp`) shipped under A3 / S8 and were made the *sole* wire format by D2 (commits `b29d422` d2-inc1: the `pq_auth` TRANSACTION section; `ce31c6f` d2-inc2: JSON envelope + negotiation deletion, binary HELLO frame; `ad595bb` d2-inc6a: fixed binary frames for the five request/status control types, §3.6). The S-002 closure (`docs/SECURITY.md` §S-002) fixed the `TRANSACTION` round-trip that T-2 states as a theorem; the S-018 closure (`JsonValidationSoundness.md`) now governs payload-level `from_json` diagnostics downstream of the codec (its former object here, the deserialize JSON branch, is deleted).

D2-inc6a is **observationally inert on the consensus path**: the five types carry no signature and no consensus commitment, no digest or signing pre-image reads their bytes, and no accept rule consumes them — the change is confined to the codec and its two independent mirrors (light `decode-wire`, and the daemon-side gates).

D2-inc6b (`e845b44`) is inert for a *different and weaker* reason, which is worth stating precisely rather than borrowing inc6a's argument. Three of its four types **do** travel alongside consensus material — a `BLOCK_SIG` carries an Ed25519 signature, an `ABORT_CLAIM` a signed claim, an `EQUIVOCATION_EVIDENCE` two signatures over two block digests. Inertness rests on P-4 (signature transparency): every one of those signatures is computed over a binary field tuple built from the struct, never over the container, so replacing the container changes no signing pre-image, no digest and no block hash. The obligation this creates is exactly T-2 and nothing more. `ABORT_CLAIM` additionally reuses the *stored-claim* codec verbatim (P-5), so the gossiped and block-carried encodings cannot diverge by construction.

What the two increments move is the *proof* surface: eleven of the 19 types are now true fixed frames, so the T-2 case analysis has five cases instead of three, T-3's guard inventory has §3.6's and §3.7's rows, and a new theorem T-2b (encoding canonicality) states the property the migration is actually for — gated by L-9's sweep after F-4 showed the per-frame legs could not see it. WIRE-2 does **not** retire: the remaining 8 types still carry length-prefixed JSON payloads through `nlohmann::json::parse`, so `json_structural_precheck` stays load-bearing until the D2 tail.

Implementation surfaces:

- `src/net/binary_codec.cpp:561-578` — magic/version constants + `put_envelope_header` + `is_binary_envelope` (T-1, L-1, L-2).
- `src/net/binary_codec.cpp:582-622` — `encode_binary` (`enc_B`; T-2 encode side, every MsgType — HELLO at 587-590, the five request/status frames via the switch at 598-604, the four consensus-chatter frames at 606-611, the length-prefixed-JSON tail at 616-621).
- `src/net/binary_codec.cpp:626-697` — `decode_binary` (T-2 decode side, T-3 envelope guards incl. the reserved-byte reject at 642-643, the fixed-frame dispatch switch at 659-680, L-3, L-5; WIRE-2 pre-scan at 694).
- `src/chain/block.cpp:150-256` — `chain::Transaction::encode_frame` / `decode_frame` (T-2 TRANSACTION path, T-3 frame guards, L-4; S-002 fix at 209-211; `pq_auth` section encode 194-199 / decode 244-254). Moved from `binary_codec.cpp` in d2-inc4 so the COMPOSABLE_BATCH validator/apply share it; `binary_codec.cpp:257-263` delegates.
- `src/net/binary_codec.cpp:267-299` — `encode_hello_frame` / `decode_hello_frame` (T-2 HELLO path, T-3 §3.5 guards, L-6).
- `src/net/binary_codec.cpp:301-394` — the five D2-inc6a request/status frame codecs (T-2 request/status case, T-3 §3.6 guards, L-7, P-1/P-2/P-3); layout comment at 100-113.
- `src/net/messages.cpp:82-116` — the binary-only `Message::deserialize` (T-1 magic gate at 83-87, WIRE-1 pre-decode cap at 106-114, T-4 totality).
- `src/net/messages.cpp:18-76, 122-132` — `json_structural_precheck` (WIRE-2) + `Message::serialize_binary` (framing).
- `include/determ/net/messages.hpp:372-374, 381-383, 401-413` — the five request/status builders; `make_status_request` at 404-410 carries P-2's `nlohmann::json::object()` normalization.
- `src/net/peer.cpp:62-112, 114-124` — `Peer::read_body` `try`/`catch` + post-decode S-022 cap + WIRE-3 close (T-4 composition); `Peer::send` unconditional `serialize_binary` (§2.3).
- `light/main.cpp:8881-8928` — the independent light-client mirror of the five request/status frames (`payload_kind="req_frame"`), same `{0, 64}` genesis narrowing at 8914-8917.
- `light/main.cpp:8929-8996` — the independent light mirror of the four consensus-chatter frames (`payload_kind="chatter_frame"`), with its own `take` / `take_lp` / `take_claims` bounds helpers, the same `count == 1` `ABORT_CLAIM` restriction, and its own `off != body_len` trailing-byte check — so daemon and light agree on frame validity for all eleven fixed frames.

This proof discharges the "deserialize is total / does not read OOB" precondition that `S022WireFormatCaps.md` T-3 assumes, completing the decode-side companion to the size-cap and backward-compat proofs.

---

## 8. References

### Implementation references

- `src/net/binary_codec.cpp:165-247` — endianness rationale + `le_put_*` / `le_get_*` / `put_padded` / `put_lp_str` / `get_lp_str` byte helpers (F-4; the guarded `get_lp_str` at 240-247 per L-3; the moved tx-frame codec carries its own copies at `src/chain/block.cpp:90-146`).
- `src/chain/block.cpp:150-256` — `chain::Transaction::encode_frame` / `decode_frame` (L-4; T-3 frame-guard inventory; S-002 amount/fee/nonce fix at 209-211; `pq_auth` section 194-199 / 244-254). Moved from `binary_codec.cpp` in d2-inc4 (COMPOSABLE_BATCH validator/apply share it); `binary_codec.cpp:257-263` delegates.
- `src/net/binary_codec.cpp:267-299` — `encode_hello_frame` / `decode_hello_frame` (L-6; T-3 HELLO guards; layout comment at 86-98).
- `src/net/binary_codec.cpp:301-394` — the five request/status frame codecs, D2-inc6a (L-7; T-3 §3.6 guards; P-1 at 339-348 + 361-363, P-3 at 310-313; layout comment at 100-113).
- `src/net/binary_codec.cpp:561-578` — magic/version constants + `put_envelope_header` + `is_binary_envelope` (L-1, L-2, T-1).
- `src/net/binary_codec.cpp:582-697` — `encode_binary` / `decode_binary` (T-2, T-3, L-5; the two fixed-frame dispatch switches 598-611 / 659-680; reserved-byte reject 642-643; WIRE-2 pre-scan 694).
- `src/net/messages.cpp:18-76` — `json_structural_precheck` (WIRE-2, survives D2, D2-inc6a *and* D2-inc6b for the 8 types that still carry length-prefixed JSON payloads).
- `src/net/messages.cpp:82-132` — `Message::deserialize` (`dec`) + `Message::serialize_binary` (T-1 gate, WIRE-1 cap, T-4 totality; framing).
- `include/determ/net/messages.hpp:84-89` — `kWireVersionBinary` (the single shipped version; advertisement-only, §2.1).
- `include/determ/net/messages.hpp:91-170` — `kMaxFrameBytes` + `max_message_bytes` (the S-022 surfaces T-4 composes with; all five D2-inc6a types **and** all four D2-inc6b types remain in the 1 MB default tier — inc6b changes no cap value).
- `src/net/binary_codec.cpp:396-557` — the four D2-inc6b consensus-chatter frame codecs (T-2 chatter case, T-2b, T-3 §3.7 guards, L-8, L-9, P-4..P-8); layout comment at 115-140.
- `src/chain/block.cpp:352-396` — `chain::encode_abort_claims` / `decode_abort_claims`, the shared claim-list codec `ABORT_CLAIM` and `ABORT_EVENT` delegate to (P-5, P-7; its own round-trip and exact-consumption proof is `AbortDigestCanonicalizationSoundness.md`).
- `include/determ/net/messages.hpp:328-330, 334-336, 337-347, 348-350` — `make_block_sig` / `make_abort_claim` / `make_abort_event` / `make_equivocation_evidence` (the builder shapes π uses for the four chatter frames).
- `include/determ/net/messages.hpp:271-300` — WIRE-2 ceilings, `Message` struct, codec declarations.
- `include/determ/net/messages.hpp:302-321` — `make_hello` (the five-field HELLO shape; π(HELLO) per §1).
- `include/determ/net/messages.hpp:372-374, 381-383, 401-413` — `make_snapshot_request` / `make_headers_request` / `make_get_chain` / `make_status_request` / `make_status_response` (the builder shapes π uses for the five frames; P-2's object normalization at 404-410).
- `src/net/peer.cpp:40-124` — `Peer::read_header` framing + `read_body` deserialize + cap + WIRE-3 `try`/`catch` (T-4 composition) + `Peer::send` (unconditional binary, §2.3).
- `src/net/gossip.cpp:177-189` — the HELLO receive case: identity tagging only; `wire_version` is read by nothing (advertisement, §2.1).
- `src/net/gossip.cpp:265-313` — the five request/status receive cases (`SNAPSHOT_REQUEST`, `HEADERS_REQUEST`, `GET_CHAIN`, `STATUS_REQUEST`, `STATUS_RESPONSE`): the consumer reads that fix π and the u16/u32 handler widths of P-3.
- `src/node/node.cpp:3167-3191` — `Node::on_status_response`: the `!genesis_hash.empty() && genesis_hash != ours` branch at 3180 that P-1's length-prefixed `genesis` exists to preserve.
- `light/main.cpp:8881-8928, 8929-8996` — the independent light `decode-wire` mirrors of the five request/status frames (`payload_kind="req_frame"`; `{0, 64}` genesis narrowing at 8914-8917) and the four consensus-chatter frames (`payload_kind="chatter_frame"`); spec commentary at 8557-8561.

### Cross-references to companion proofs

- `docs/proofs/S022WireFormatCaps.md` — parent size-cap closure; its T-3 assumes `Message::deserialize` returns `msg.type`, which T-4 here discharges; its T-5 work-bound and T-6 (WIRE-3 disposition) cover the DoS layer this proof only composes with.
- `docs/proofs/S022WireFormatCapsCompleteness.md` — cap-table exhaustion; its T-1 step 4 (out-of-enum type byte → default tier) pairs with T-1 here (the `static_cast<MsgType>` is the sole, bounds-safe type interpretation).
- `docs/proofs/WireFormatBackwardCompat.md` — zero-skip hash-stability of optional signing-bytes fields; orthogonal layer (signing-bytes pre-image vs gossip envelope) — the two together cover the full wire surface a peer sees.
- `docs/proofs/S002-Mempool-Sig-Verify.md` — the amount/fee/nonce decode fix; the historical witness for T-2's TRANSACTION-path exactness.
- `docs/proofs/JsonValidationSoundness.md` — S-018 closure; governs the `json_require` diagnostics in per-type payload `from_json` consumers downstream of the codec (the JSON-envelope branch of `Message::deserialize` it formerly governed was deleted with D2).
- `docs/proofs/Preliminaries.md` §3 — network model underlying the `Peer` framing assumption that strips the length prefix before `dec` sees the body.
- `docs/proofs/ReservedDiscriminatorAudit.md` §6 — the daemon/light/wallet reserved-byte validation asymmetry whose closure §5.1(c) and F-1 record.

### Documentation references

- `docs/SECURITY.md` §S-002 (binary codec amount/fee/nonce fix), §S-018 (payload JSON validation), §S-022 (per-type size cap + WIRE-1/2/3).
- `docs/PROTOCOL.md` §9.2 — wire-type table + body-cap column (the type surface this codec decodes); §16 — the version contract test-protocol-version-pinning gates.
- `docs/proofs/DECISION-LOG.md` 2026-07-28 (D2) — the binary-only-wire decision this codec implements.

### External references

- C++ ISO/IEC 14882:2017 §7.2.1 [expr.static.cast] / §10.2 [dcl.enum] — `static_cast<MsgType>(byte)` is well-defined for any value in the underlying `uint8_t` range (T-1, T-4: the type-byte cast never invokes UB).
- nlohmann/json — `parse` throws `nlohmann::json::parse_error` (a `std::exception` subclass) on malformed input (T-4); `parse(dump(v)) == v` round-trip identity on the library's own output (L-5). *(Scoped to the length-prefixed JSON payloads still carried inside the binary envelope — 8 types after D2-inc6b; retires with them at the D2 tail.)*
