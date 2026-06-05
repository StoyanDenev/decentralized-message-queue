# BinaryCodecRoundTripSoundness — A3 binary-envelope format-detect + round-trip + bounds-safety

This document formalizes the soundness of the A3 / S8 binary wire codec at `src/net/binary_codec.cpp` and its driver at `src/net/messages.cpp` (`Message::serialize` / `serialize_binary` / `deserialize`). Where `S022WireFormatCaps.md` + `S022WireFormatCapsCompleteness.md` bound the *size* of an accepted message and `WireFormatBackwardCompat.md` proves the *hash-stability* of optional field additions, this document proves the *decode correctness* surface that sits between the two: that the read path's self-describing first-byte discriminator partitions the body-space without collision (T-1), that the encode/decode pair is a round-trip identity on the wire-relevant projection of every non-HELLO `MsgType` (T-2), that every read in `decode_binary` / `decode_tx_frame` is bounds-checked before the access it guards so an adversarial truncated/oversized body throws rather than reads out of bounds (T-3), and that `Message::deserialize` is therefore total — every byte string either decodes to a structurally-valid `Message` or raises a `std::exception` that the `Peer::read_body` catch handler at `src/net/peer.cpp:98-101` absorbs (T-4).

The proof is structural — there are no cryptographic assumptions on the codec itself (the codec moves bytes; the cryptography lives in the payloads it carries and is bound by the signing-bytes primitives that `WireFormatBackwardCompat.md` covers). The contribution over the existing wire-format proof corpus is the *decoder-correctness* layer: the size proofs assume the deserializer returns a `msg.type` value; this proof establishes that the deserializer cannot be steered into undefined behavior, that the format-detect dispatch is deterministic, and that the binary path is observably equivalent to the JSON path on the fields the rest of the system reads.

**Companion documents.** `S022WireFormatCaps.md` (parent size-cap closure — its T-3 assumes `Message::deserialize` returns a `msg.type`; T-4 here discharges the "deserialize is total" precondition that T-3 leans on); `S022WireFormatCapsCompleteness.md` (the cap-table exhaustion proof — its T-1 step 4 notes the decoder casts an out-of-enum type byte to `MsgType`; T-1 here shows the cast is the *only* type-byte interpretation and is bounds-safe); `WireFormatBackwardCompat.md` (the zero-skip hash-stability theorem — orthogonal: that proof covers the signing-bytes pre-image, this one covers the gossip envelope around it); `Preliminaries.md` §3 (network model underlying the `Peer` framing assumption); `tla/HelloHandshake.tla` (the wire-version negotiation state machine whose `min(ours, theirs)` outcome this proof's §2.3 references for the send-side version selection); `JsonValidationSoundness.md` (S-018 — the JSON-envelope `json_require` diagnostics that `Message::deserialize`'s JSON branch shares); `S002-Mempool-Sig-Verify.md` (the amount/fee/nonce decode-fix whose round-trip property T-2 generalizes); `docs/SECURITY.md` §S-022 / §S-002 / §S-018 for the audit-trail.

---

## 1. Theorem statements

**Setup.** Let a *body* `B ∈ {0,1}^{8n}` (0 ≤ n ≤ kMaxFrameBytes) denote the framing-stripped payload that `Peer::read_body` hands to `Message::deserialize` (`src/net/messages.cpp:33`). The framing layer (a 4-byte big-endian length prefix, `src/net/peer.cpp:58-67`) is outside the codec; both `serialize` and `serialize_binary` re-prepend it (`messages.cpp:17-24`, `messages.cpp:63-70`) and `read_body` strips it, so the codec operates purely on `B`.

Let:

- `enc_J : Message → {0,1}^*` be the JSON envelope serializer, `Message::serialize` (`messages.cpp:11`). It emits `{"type": <u8>, "payload": <json>}` via `nlohmann::json::dump`, so `enc_J(m)[0] = '{' = 0x7B`.
- `enc_B : Message → {0,1}^*` be the binary envelope serializer, `encode_binary` (`binary_codec.cpp:329`). It emits `[0xB1][0x01][type][0x00] || payload_frame`, so `enc_B(m)[0] = 0xB1` and `enc_B(m)[1] = 0x01`. `enc_B` is a partial function: undefined (throws) on `m.type == HELLO`.
- `dec : {0,1}^* → Message ∪ {⊥}` be `Message::deserialize`, where `⊥` denotes "raised a `std::exception`".
- `det : {0,1}^* → {JSON, BINARY}` be the format-detect predicate `is_binary_envelope` (`binary_codec.cpp:319`), with `det(B) = BINARY ⟺ (|B| ≥ 4 ∧ B[0] = 0xB1 ∧ B[1] = 0x01)`.

Let `π : Message → WireFields` be the *wire-relevant projection* — the tuple of fields any downstream consumer reads off a decoded `Message`. For a `TRANSACTION`, `π` is `(from, to, amount, fee, nonce, payload, type, sig, hash)` (every field `chain::Transaction::from_json` / `to_json` round-trips). For every other non-HELLO type, `π` is the full `payload` JSON value.

**Theorem T-1 (Format-Detect Determinism and Non-Collision).** `det` is a total, deterministic function of at most the first two body bytes, and it partitions the reachable encoder outputs without collision:

$$
\forall m \in \mathrm{dom}(enc_J):\ det(enc_J(m)) = \mathrm{JSON}, \qquad
\forall m \in \mathrm{dom}(enc_B):\ det(enc_B(m)) = \mathrm{BINARY},
$$

and the two reachable images are disjoint because `enc_J(m)[0] = 0x7B ≠ 0xB1 = enc_B(m')[0]` for all `m, m'`. Consequently the read path never misclassifies a self-produced JSON body as binary or vice versa, and a v1-capable peer correctly parses a JSON body from a v0 peer (mixed-version receive) by inspecting only `B[0..1]`.

**Theorem T-2 (Round-Trip Identity on the Wire Projection).** For every `Message m` with `m.type ≠ HELLO` whose payload is a structurally-valid instance of its type:

$$
\pi(dec(enc_B(m))) = \pi(m) \qquad\text{and}\qquad \pi(dec(enc_J(m))) = \pi(m).
$$

In particular the binary and JSON paths are *observationally equivalent*: `π(dec(enc_B(m))) = π(dec(enc_J(m)))`. For the `TRANSACTION` fixed-frame path this is exact field equality across `(from, to, amount, fee, nonce, payload, type, sig, hash)` (the S-002 fix at `binary_codec.cpp:266-269` is the load-bearing line — it reads amount/fee/nonce from the fixed slots the encoder wrote at `binary_codec.cpp:219-221`). For the length-prefixed-JSON fallback path (every other non-`TRANSACTION` type) it is exact JSON-value equality, since `enc_B` embeds `m.payload.dump()` verbatim (`binary_codec.cpp:345-349`) and `dec` re-parses it (`binary_codec.cpp:377`).

**Theorem T-3 (Bounds-Safety of the Decode Path).** For every body `B` (adversarial or honest), `decode_binary(B)` and its `decode_tx_frame` sub-call perform no out-of-bounds read: every indexed access `data[i]` / `data + i` and every `memcpy` is preceded on all reachable control-flow paths by a length guard that throws `std::runtime_error` when the required bytes are not present. Formally, for each read of `k` bytes at offset `off`, the code establishes `off + k ≤ len` before the read, or throws. The decoder therefore has no undefined behavior on any input in `{0,1}^*`.

**Theorem T-4 (Totality of `Message::deserialize`).** `dec` is total over `{0,1}^*` in the sense that for every body `B`, `dec(B)` either returns a `Message` with a well-defined `type ∈ MsgType` (any byte value, per the `static_cast<MsgType>` at `binary_codec.cpp:361` / `messages.cpp:44`) and a `payload` value, or raises a `std::exception`. There is no input on which `dec` reads out of bounds, loops without termination, or returns an uninitialized value. Composed with the `Peer::read_body` `try`/`catch` at `src/net/peer.cpp:81-101`, every decode failure is converted to a logged-and-dropped message (connection stays open; the read loop iterates), and every decode success is gated by the S-022 per-type size cap (`peer.cpp:88-96`) before dispatch.

---

## 2. Background

### 2.1 The two-format wire surface

Determ peers exchange `Message` values over TCP. The transport (`Peer`) frames each body with a 4-byte big-endian length prefix (`src/net/peer.cpp:58-67` read side; `messages.cpp:19-22` / `messages.cpp:65-68` write side). Inside that frame the *body* is one of two self-describing formats, chosen at send time by the per-peer negotiated `wire_version` but recognized at receive time purely by the body's leading bytes:

- **Wire-version 0 (legacy JSON).** `Message::serialize` emits `{"type": t, "payload": p}` as UTF-8 JSON. The body always begins with `'{'` (`0x7B`). This is the default and the only format pre-A3 peers understand.
- **Wire-version 1 (binary envelope).** `Message::serialize_binary` → `encode_binary` emits a 4-byte header `[0xB1][0x01][type][0x00]` followed by a per-type payload. The body always begins with `0xB1 0x01`.

The receive path (`Message::deserialize`, `messages.cpp:33`) is version-agnostic: it calls `is_binary_envelope(B)` and dispatches to `decode_binary` or the JSON parser. This is what lets a connection carry a JSON HELLO (always JSON, pre-negotiation) and then upgrade to binary for subsequent traffic without the receiver tracking a per-message version — the body tells the receiver what it is.

### 2.2 Why a decode-correctness proof is needed alongside the size-cap proofs

`S022WireFormatCaps.md` T-3 reasons about the state *after* `Message::deserialize` returns a `msg` value — it gates `on_msg_` on `body_buf_.size() > max_message_bytes(msg.type)`. That argument silently assumes `Message::deserialize` *returns* (rather than reading out of bounds, or being steered to a type byte it can't interpret). The size proof explicitly defers this: its §6.2 finding-register lists "deserialize-time bugs that crash the receiver before the cap is checked" as out of scope, governed by S-018. This document discharges that assumption for the binary path specifically:

1. The binary decoder casts the type byte with `static_cast<MsgType>(data[2])` — any of the 256 byte values is a valid (possibly out-of-enum) `MsgType`, so the type read never throws and never reads OOB (T-1, T-3).
2. Every length-prefixed and fixed-slot read inside `decode_binary` / `decode_tx_frame` is guarded (T-3), so a truncated or maliciously-short body throws `std::runtime_error` rather than reading past `data + len`.
3. Both outcomes (return-or-throw) are handled at the peer layer (T-4), so the deserializer is safe to feed arbitrary peer bytes.

Without this, the S-022 cap argument has a gap: an attacker who can make `Message::deserialize` read OOB defeats the cap before it is consulted. T-3 closes the gap.

### 2.3 Send-side version selection (context, not the proof object)

The send-side choice between `enc_J` and `enc_B` is governed by the per-peer `wire_version` field, set to `min(our_max, their_max)` on HELLO receipt (`binary_codec.cpp:19-26` module comment; the negotiation state machine is modeled in `tla/HelloHandshake.tla`). HELLO itself is *always* JSON — `encode_binary` throws on `m.type == HELLO` (`binary_codec.cpp:330-331`), and `Peer`'s send path special-cases it. The proof object here is the *receive* path, which is version-agnostic by T-1; the send-side negotiation is relevant only insofar as it guarantees a v0-only peer is never sent a binary body (it advertises `wire_version = 0`, the sender takes `min(·, 0) = 0`, and emits JSON). That guarantee is a property of the HELLO state machine, not of the codec, so it is cited rather than re-proved here.

---

## 3. Implementation citation

### 3.1 Format-detect (`is_binary_envelope`)

`src/net/binary_codec.cpp:306-323`:

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

The `len >= 4` short-circuit guards `data[0]` and `data[1]` — `is_binary_envelope` is itself bounds-safe (it never reads `data[0]` on an empty body). The JSON envelope, by contrast, always begins with `'{'` because `nlohmann::json::dump` of an object opens with `{` — and `0x7B ≠ 0xB1`.

### 3.2 The deserialize dispatch (`Message::deserialize`)

`src/net/messages.cpp:33-53`:

```cpp
Message Message::deserialize(const uint8_t* data, size_t len) {
    if (is_binary_envelope(data, len)) {
        return decode_binary(data, len);
    }
    nlohmann::json envelope = nlohmann::json::parse(data, data + len);
    Message m;
    m.type    = static_cast<MsgType>(json_require<uint8_t>(envelope, "type"));
    if (!envelope.contains("payload")) {
        throw std::runtime_error(
            "S-018: gossip envelope missing required 'payload' field ...");
    }
    m.payload = envelope["payload"];
    return m;
}
```

Both branches are total-or-throw: `decode_binary` is analyzed in §3.3–§3.4; `nlohmann::json::parse` throws `nlohmann::json::parse_error` (a `std::exception` subclass) on malformed JSON, and `json_require` / the explicit `contains` check throw on a missing field (S-018).

### 3.3 The binary envelope decoder (`decode_binary`)

`src/net/binary_codec.cpp:355-379`:

```cpp
Message decode_binary(const uint8_t* data, size_t len) {
    if (len < 4 || data[0] != kBinaryMagic)
        throw std::runtime_error("binary_codec: not a binary envelope");
    if (data[1] != kBinaryVersion)
        throw std::runtime_error("binary_codec: unsupported binary version");
    Message m;
    m.type = static_cast<MsgType>(data[2]);
    const uint8_t* body = data + 4;
    size_t body_len = len - 4;

    if (m.type == MsgType::TRANSACTION) {
        chain::Transaction tx = decode_tx_frame(body, body_len);
        m.payload = tx.to_json();
        return m;
    }
    if (body_len < 4)
        throw std::runtime_error("binary_codec: truncated payload header");
    uint32_t plen = le_get_u32(body);
    if (4 + static_cast<size_t>(plen) > body_len)
        throw std::runtime_error("binary_codec: truncated payload body");
    m.payload = nlohmann::json::parse(body + 4, body + 4 + plen);
    return m;
}
```

Every read is guarded: `len < 4` guards `data[0..2]`; the `body_len < 4` guard precedes `le_get_u32(body)` (which reads `body[0..3]`); and `4 + plen > body_len` guards the `body + 4 .. body + 4 + plen` parse window. The cast `static_cast<MsgType>(data[2])` accepts any byte (per `S022WireFormatCapsCompleteness.md` T-1 step 4, an out-of-enum byte simply hits the default size tier later).

### 3.4 The transaction fixed-frame decoder (`decode_tx_frame`)

`src/net/binary_codec.cpp:252-302`. The guards, in source order:

| Guard (line) | Protects |
|---|---|
| `if (len < 128 + 1 + 2) throw` (254) | the fixed-slot reads at offsets 32, 40, 48, 56 (amount/fee/nonce/reserved) and the trailer `type` + `payload_len` reads at offsets 128, 129 |
| `if (reserved != 0) throw` (270) | determinism invariant — rejects a non-canonical frame whose reserved u64 is non-zero |
| `payload_len <= 32` branch (282) | reads `data + 96 .. 96 + payload_len`, which is ≤ 128 ≤ `len` by the line-254 guard |
| `if (off + overflow > len) throw` (287) | the overflow-payload `data + off .. off + overflow` read |
| `get_lp_str` internal guards (195-202) | the `from` / `to` length-prefixed string reads (`off + 1 > len` for the length byte, `off + n > len` for the body) |
| `if (off + 64 + 32 > len) throw` (297) | the `memcpy` of the 64-byte sig and 32-byte hash |

The encoder side (`encode_tx_frame`, `binary_codec.cpp:206-250`) writes exactly the layout the decoder reads, with `put_padded` (`binary_codec.cpp:181-185`) right-padding short `from`/`to`/`payload` to their 32-byte slots and the trailer carrying the authoritative variable-length `from`/`to`/`sig`/`hash`. `put_lp_str` (`binary_codec.cpp:188-193`) throws if a string exceeds 255 bytes, the symmetric bound to `get_lp_str`'s u8 length read.

---

## 4. Lemmas and proofs

### Lemma L-1 (JSON bodies begin with `0x7B`, binary bodies with `0xB1 0x01`)

`enc_J(m)` (`messages.cpp:11-25`) sets `envelope["type"]` and `envelope["payload"]`, then `envelope.dump()`. `nlohmann::json::dump` of a non-empty object emits the bytes `{"..."` beginning with `{` = `0x7B`. The body is `s` with no leading framing (the 4-byte length prefix is prepended *after* `s` in the returned vector, but `read_body` strips it before calling `deserialize`, so the body `B` seen by `dec` is exactly `s`). Hence `enc_J(m)[0] = 0x7B`.

`enc_B(m)` (`binary_codec.cpp:329-351`) calls `put_envelope_header` (`binary_codec.cpp:309-314`), pushing `kBinaryMagic = 0xB1` then `kBinaryVersion = 0x01` as the first two bytes. Hence `enc_B(m)[0] = 0xB1` and `enc_B(m)[1] = 0x01`. □

### Lemma L-2 (`det` reads at most two bytes and is deterministic)

`is_binary_envelope` (§3.1) is a pure function of `len` and `data[0..1]`, evaluated left-to-right with `&&` short-circuit: if `len < 4` it returns `false` without reading `data`; otherwise it reads exactly `data[0]` and `data[1]`. It has no global state and no side effects, so it is deterministic. □

### Lemma L-3 (every `decode_binary` / `decode_tx_frame` read is guarded)

By the guard inventory in §3.3 (three guards covering the type read, the `le_get_u32` header read, and the JSON-window read) and §3.4 (the line-254 fixed-slot/trailer guard, the overflow guard, the two `get_lp_str` internal guards, and the sig/hash `memcpy` guard). Each guard is a `throw std::runtime_error(...)` executed *before* the access it protects on every control-flow path that reaches the access. The only reads not behind an explicit per-read guard are the fixed-slot reads at offsets 32/40/48/56/96/128/129, all of which are covered by the single line-254 precondition `len ≥ 131`. No path reaches a `data[i]` or `memcpy` with `i ≥ len` or `i + k > len`. □

### Lemma L-4 (encoder/decoder slot agreement for `TRANSACTION`)

`encode_tx_frame` writes, in order: `from` padded to 32 B (offset 0), `amount`/`fee`/`nonce`/`reserved=0` as LE u64s (offsets 32/40/48/56), `to` padded to 32 B (offset 64), `payload` first-32 padded (offset 96), then the trailer `type` (offset 128), `payload_len` (offset 129), payload-overflow if any, `lp_str(from)`, `lp_str(to)`, `sig` (64 B), `hash` (32 B). `decode_tx_frame` reads `amount`/`fee`/`nonce` from offsets 32/40/48 (`binary_codec.cpp:266-268`), checks `reserved == 0` at offset 56, reads `type` at 128 and `payload_len` at 129, reconstructs `payload` from the fixed slot (≤ 32 B case) or fixed slot + overflow (> 32 B case), and reads `from`/`to`/`sig`/`hash` from the trailer. The authoritative `from`/`to` come from the trailer `lp_str` values (the 32-byte fixed slots are padding-lossy and not read back as identifiers). Every encoded field has a matching decode read at the same offset. □

### Lemma L-5 (length-prefixed-JSON fallback is verbatim)

For `m.type ∉ {HELLO, TRANSACTION}`, `enc_B` computes `s = m.payload.dump()`, writes `le_u32(|s|)` then `s` verbatim (`binary_codec.cpp:345-349`). `decode_binary` reads `plen = le_get_u32(body)`, verifies `4 + plen ≤ body_len`, and parses `body + 4 .. body + 4 + plen` as JSON (`binary_codec.cpp:374-377`). Because `nlohmann::json::parse(dump(v)) == v` for any JSON value `v` (round-trip property of the JSON library on its own output), `dec(enc_B(m)).payload == m.payload`. □

### Proof of T-1

By L-1, every reachable `enc_J` output has first byte `0x7B` and every reachable `enc_B` output has first two bytes `0xB1 0x01`. By L-2, `det` classifies a body as `BINARY` iff its first two bytes are `0xB1 0x01`. Therefore `det(enc_B(m)) = BINARY` for all `m ∈ dom(enc_B)`, and `det(enc_J(m)) = JSON` for all `m` (its first byte `0x7B ≠ 0xB1` fails the magic check). The two reachable images are disjoint on byte 0 (`0x7B ≠ 0xB1`), so no JSON body is ever misread as binary and no binary body is ever misread as JSON. Mixed-version receive is correct: the receiver inspects only `B[0..1]`, which is set by the *encoder that produced the body*, independent of the receiver's negotiated version. □

### Proof of T-2

*Binary path.* By T-1, `det(enc_B(m)) = BINARY`, so `dec(enc_B(m)) = decode_binary(enc_B(m))`. Two cases:

- `m.type = TRANSACTION`: by L-4, every field the encoder wrote is read back at the matching offset; the S-002 fix (`binary_codec.cpp:266-269`) supplies amount/fee/nonce from the fixed slots, and the trailer supplies `from`/`to`/`payload`/`sig`/`hash`. `decode_binary` then sets `m.payload = tx.to_json()`. Since `chain::Transaction::from_json ∘ to_json` is the identity on the projected fields (the JSON encoding of a `Transaction` is lossless on `π`), `π(dec(enc_B(m))) = π(m)`.
- `m.type ∉ {HELLO, TRANSACTION}`: by L-5, `dec(enc_B(m)).payload == m.payload`, and `π` for these types is the whole payload, so `π(dec(enc_B(m))) = π(m)`.

*JSON path.* `enc_J(m)` emits `{"type": t, "payload": p}`; `dec` parses it, reads `type` via `json_require<uint8_t>` (recovering `t`) and `payload` via `envelope["payload"]` (recovering `p` exactly, since `nlohmann::json::parse(dump(·))` is identity). Hence `dec(enc_J(m)).type = m.type` and `dec(enc_J(m)).payload = m.payload`, giving `π(dec(enc_J(m))) = π(m)`. (For `TRANSACTION` the JSON `payload` is the `to_json()` of the tx, so `π` agrees with the binary path's `to_json()` value.)

Observational equivalence `π(dec(enc_B(m))) = π(dec(enc_J(m))) = π(m)` follows by transitivity. □

### Proof of T-3

By L-3, every indexed read and every `memcpy` in `decode_binary` and `decode_tx_frame` is preceded on all reachable paths by a length guard that throws when the required `off + k ≤ len` condition fails. The helper `le_get_u32` / `le_get_u64` / `le_get_u16` read fixed widths (4/8/2 bytes) from a pointer the caller has already bounds-checked; `get_lp_str` carries its own two guards. The encoder's `put_lp_str` enforces the ≤ 255 bound that `get_lp_str`'s u8 length field can represent, so a round-tripped honest frame never trips the decode guards, while an adversarial frame either satisfies every guard (and decodes to a structurally-valid tx) or trips one (and throws). No path performs an access with `off + k > len`. Hence the decode path has no out-of-bounds read and no undefined behavior on any input. □

### Proof of T-4

`dec` (`messages.cpp:33`) has exactly two branches. *Binary branch:* `decode_binary` either returns a `Message` (with `type = static_cast<MsgType>(data[2])`, defined for all 256 byte values, and a `payload` set from `tx.to_json()` or a parsed JSON window) or throws — by T-3 it never reads OOB, and every internal failure is a `throw std::runtime_error`; `nlohmann::json::parse` of the payload window throws `parse_error` on malformed JSON. *JSON branch:* `nlohmann::json::parse` throws on malformed input; `json_require` / the `contains` check throw on a missing `type`/`payload`; otherwise it returns a `Message`. Both branches terminate (no loops in `decode_binary`; `decode_tx_frame` has only straight-line code plus the two fixed-iteration helper loops in `le_get_*`/`put_*`; `nlohmann` parsing terminates on finite input). Therefore `dec` is total in the return-or-throw sense.

Composed with `Peer::read_body` (`src/net/peer.cpp:81-101`):

```cpp
try {
    auto msg = Message::deserialize(self->body_buf_.data(), self->body_buf_.size());
    if (self->body_buf_.size() > max_message_bytes(msg.type)) { /* close */ }
    if (self->on_msg_) self->on_msg_(self, msg);
} catch (std::exception& e) {
    std::cerr << "[peer] message parse error from " << self->address_ << ...;
}
self->read_header();
```

every `dec` throw is caught and logged (connection stays open; the loop iterates to `read_header`), and every `dec` success is gated by the S-022 cap before `on_msg_` dispatch. So `dec`'s totality lifts to "every peer body is safely processed": decoded-and-capped, or dropped-and-logged. □

---

## 5. Adversary model + notable findings

### 5.1 Adversary model

The codec defends against an adversary who controls the bytes of a body `B` delivered to `Message::deserialize` (a connected peer, post-HELLO, sending arbitrary frames within the `kMaxFrameBytes` framing ceiling):

**(a) Truncated binary frame.** Adversary sends `0xB1 0x01 <type> 0x00` followed by fewer bytes than the type's payload requires. **Defended (T-3 + T-4).** Every short read trips a length guard (`len < 128+1+2` for TRANSACTION, `body_len < 4` / `4+plen > body_len` for the JSON fallback, `get_lp_str` guards, sig/hash guard) and throws; the peer logs and drops.

**(b) Out-of-enum type byte.** Adversary sends `0xB1 0x01 0xFF 0x00 ...`. **Defended (T-1 + S-022 completeness T-1 step 4).** `static_cast<MsgType>(0xFF)` is a valid (out-of-enum) `MsgType`; the JSON-fallback decode path handles it (it is `≠ TRANSACTION`), and the per-type size cap defaults to 1 MB. No OOB, no UB.

**(c) Non-canonical reserved field.** Adversary sets the tx-frame reserved u64 (offset 56) non-zero, or the envelope reserved byte (offset 3) non-zero. **Partially defended.** The tx-frame reserved field is *checked* (`binary_codec.cpp:270-271` throws), enforcing canonicality. The envelope reserved byte (offset 3) is *ignored* on decode (`binary_codec.cpp:362` comment "data[3] reserved — ignored"); see Finding F-1.

**(d) Format-confusion.** Adversary crafts a body that is ambiguously JSON-or-binary. **Defended (T-1).** Impossible: `det` keys on byte 0 (`0x7B` vs `0xB1`), which are distinct; a JSON object never starts with `0xB1` and a binary envelope never starts with `0x7B`.

**(e) Oversized length-prefix in the JSON fallback.** Adversary sets `plen` to a huge value to provoke a large allocation. **Defended (T-3 + S-022).** `decode_binary` rejects `4 + plen > body_len` *before* parsing, and `body_len ≤ kMaxFrameBytes` by the framing layer; the per-type cap further bounds the accepted size.

The codec does *not* defend against (and is not designed to defend against):

- Semantic validity of the decoded payload (e.g., a syntactically-valid but economically-invalid `Transaction`). That is the apply-layer's job (`NonceMonotonicity.md`, `FeeAccounting.md`, S-002 signature verification). The codec guarantees a *structurally* well-formed `Message`, not a *semantically* admissible one.
- Compression bombs / parser DoS inside `nlohmann::json::parse`. Bounded by the S-022 size cap (the parse window is ≤ `max_message_bytes(type)`); parse cost is `O(window)`. See `S022WireFormatCaps.md` T-5 for the work bound.

### 5.2 Notable findings

**Finding F-1 (Envelope reserved byte at offset 3 is not validated on decode).** `put_envelope_header` writes `0x00` for the reserved byte (`binary_codec.cpp:313`), and `decode_binary` explicitly ignores it (`binary_codec.cpp:362`). By contrast, the *tx-frame* reserved u64 (offset 56) *is* validated (`binary_codec.cpp:270-271`). The asymmetry means two binary envelopes that differ only in `data[3]` decode to the same `Message` — a benign malleability: the byte is not bound by any signature (the payload's own signing-bytes are computed over the decoded fields, not the envelope), so an attacker flipping `data[3]` produces a frame that decodes identically and carries no semantic effect. **Severity:** Very Low (wire malleability with no soundness or amplification consequence — the decoded `Message` is identical, and the size cap + payload signature are unaffected). **Recommended mitigation (optional, defense-in-depth):** mirror the tx-frame discipline by rejecting `data[3] != 0` in `decode_binary`, eliminating the malleability surface and making the envelope strictly canonical. Effort: ~2 LOC. This is a chip-task candidate.

**Finding F-2 (Binary `TRANSACTION` frame carries `from`/`to` twice).** The fixed-slot pubkey area (offsets 0..31, 64..95) and the trailer `lp_str(from)` / `lp_str(to)` both encode the address strings. The decoder reads the *trailer* values as authoritative and treats the fixed slots as padding-lossy (`binary_codec.cpp:276` comment). The module comment (`binary_codec.cpp:84-90`) flags this as intentional transitional redundancy: the 4×256-bit frame predates the domain-string account model, and the trailer exists so the frame round-trips real transactions until identity migrates to raw pubkeys (R3+). **Severity:** None (correctness-neutral; a bandwidth inefficiency of ≤ ~64 redundant bytes per tx). **Status:** documented design wrinkle, not a defect. The S-002 fix preserved the property that the *numeric* fields (amount/fee/nonce) live only in the fixed slots, so there is no double-encoding ambiguity for the consensus-bound numeric fields.

**Finding F-3 (No dedicated round-trip regression for the binary path on `main`).** `tools/test_binary_codec.sh` + `tools/test_binary_codec_roundtrip_exhaustive.sh` exercise the per-MsgType encode→decode loop, and `S002-Mempool-Sig-Verify.md` records the amount/fee/nonce round-trip fix. T-2's exact-field-equality claim for the `TRANSACTION` fixed-frame path is the load-bearing case; the exhaustive roundtrip test covers it indirectly (it walks every non-HELLO type with a representative payload). A *negative* test — feeding `decode_binary` a deliberately-truncated frame and asserting it throws rather than reads OOB (the T-3 surface) — would tighten coverage of the bounds-safety claim. **Severity:** Low (test-coverage completeness, not a soundness gap — T-3 is established by the §3.4 guard inventory + §4 L-3). **Recommended:** a fuzz-style negative test injecting truncated/oversized bodies. Chip-task candidate.

**Finding F-4 (Endianness coupling to host).** The binary envelope and tx frame use little-endian for all multi-byte integers (`binary_codec.cpp:120-125` rationale), matching x86_64/ARM64 host endianness. The `le_put_*` / `le_get_*` helpers (`binary_codec.cpp:146-178`) implement LE explicitly via shifts, so the codec is *byte-order-correct on any host* (the explicit shift-based pack/unpack does not depend on host endianness — it always emits/reads little-endian regardless of the machine). The "matches host endianness" comment refers to a micro-optimization opportunity (no byte-swap on LE hosts), not a correctness dependency. **Severity:** None (the explicit shifts make the codec portable). Noted to forestall a misreading of the comment as a portability bug.

These four findings are advisory; none invalidates T-1 through T-4. F-1 (envelope-reserved malleability) and F-3 (negative round-trip test) are the two with a small remediation path and are surfaced as chip-task candidates.

---

## 6. Test-suite citation

| Test | Source | Coverage |
|---|---|---|
| `tools/test_binary_codec_roundtrip_exhaustive.sh` (via `determ test-binary-codec-roundtrip-exhaustive`) | `src/main.cpp` exhaustive per-MsgType roundtrip | Walks every non-HELLO `MsgType` (1..18) with a representative payload through `encode_binary` → `decode_binary`, asserting structural equality of the decoded `Message`. Direct evidence for T-2 (round-trip identity) across the full type surface; indirect evidence for T-1 (every roundtripped body is correctly format-detected). |
| `tools/test_binary_codec.sh` | High-level binary-codec smoke test | Exercises the envelope header + a `TRANSACTION` frame + at least one JSON-fallback type. Pins L-1 (binary bodies begin `0xB1 0x01`) and L-4 (tx-frame slot agreement) behaviorally. |
| `tools/test_hello_handshake_determinism.sh` (via `determ test-hello-handshake-determinism`) | `src/main.cpp` HELLO determinism suite | Pins that HELLO serializes deterministically as JSON (the `enc_B(HELLO)` throw is never taken on the send path). Composes with §2.3's send-side version-selection argument. |
| Truncation/OOB negative test (deferred — F-3) | n/a | A test feeding `decode_binary` truncated frames (short tx frame, `plen` past `body_len`, oversize `lp_str` length byte) and asserting `std::runtime_error` rather than a crash would directly exercise the T-3 guard inventory. The detection logic is structurally short (the §3.4 guard set) and runs on every body-read; the absence of a dedicated negative test reflects test-coverage scope, not a soundness gap. |

The roundtrip-exhaustive test is the primary operational backstop for T-2; T-1 and T-3 are short structural arguments grounded in the §3 source citation. The S-002 regression (per `S002-Mempool-Sig-Verify.md`) is the historical witness that the `TRANSACTION` round-trip *was* broken (amount/fee/nonce dropped) and is now fixed — T-2's exactness claim for the numeric fields is precisely the property that fix restored.

---

## 7. Status

**Shipped (analytic).** This document formalizes the decode-correctness surface of the already-shipped A3 / S8 binary codec; it introduces no code changes. The codec (`src/net/binary_codec.cpp`), its driver (`src/net/messages.cpp`), and the format-detect dispatch were shipped under A3 / S8; the S-002 closure (`docs/SECURITY.md` §S-002) fixed the `TRANSACTION` round-trip that T-2 now states as a theorem; the S-018 closure (`JsonValidationSoundness.md`) governs the JSON-branch diagnostics in `Message::deserialize`.

Implementation surfaces:

- `src/net/binary_codec.cpp:319-323` — `is_binary_envelope` format-detect (T-1).
- `src/net/binary_codec.cpp:329-351` — `encode_binary` (`enc_B`; T-2 encode side, L-1).
- `src/net/binary_codec.cpp:355-379` — `decode_binary` (T-2 decode side, T-3 envelope guards, L-3, L-5).
- `src/net/binary_codec.cpp:206-302` — `encode_tx_frame` / `decode_tx_frame` (T-2 TRANSACTION path, T-3 frame guards, L-4; S-002 fix at 266-269).
- `src/net/messages.cpp:11-71` — `Message::serialize` / `deserialize` / `serialize_binary` (the dispatch and JSON path; T-1 dispatch, T-4 totality).
- `src/net/peer.cpp:81-101` — `Peer::read_body` `try`/`catch` + S-022 cap gate (T-4 composition).

This proof discharges the "deserialize is total / does not read OOB" precondition that `S022WireFormatCaps.md` T-3 assumes, completing the decode-side companion to the size-cap and backward-compat proofs.

---

## 8. References

### Implementation references

- `src/net/binary_codec.cpp:120-185` — endianness rationale + `le_put_*` / `le_get_*` / `put_padded` / `put_lp_str` / `get_lp_str` byte helpers (F-4; the guarded `get_lp_str` per L-3).
- `src/net/binary_codec.cpp:206-302` — `encode_tx_frame` / `decode_tx_frame` (L-4; T-3 frame-guard inventory; S-002 amount/fee/nonce fix at 266-269).
- `src/net/binary_codec.cpp:306-323` — magic/version constants + `put_envelope_header` + `is_binary_envelope` (L-1, L-2, T-1; F-1 reserved byte).
- `src/net/binary_codec.cpp:329-379` — `encode_binary` / `decode_binary` (T-2, T-3, L-5).
- `src/net/messages.cpp:11-71` — `Message::serialize` (`enc_J`), `Message::deserialize` (`dec`), `Message::serialize_binary` (T-1 dispatch, T-4 totality).
- `include/determ/net/messages.hpp:84-92` — `kWireVersionLegacy` / `kWireVersionBinary` / `kWireVersionMax` (§2.3 send-side negotiation context).
- `include/determ/net/messages.hpp:154-179` — `Message` struct + `encode_binary` / `decode_binary` / `is_binary_envelope` declarations.
- `src/net/peer.cpp:50-101` — `Peer::read_header` framing + `read_body` deserialize + cap + `try`/`catch` (T-4 composition).

### Cross-references to companion proofs

- `docs/proofs/S022WireFormatCaps.md` — parent size-cap closure; its T-3 assumes `Message::deserialize` returns `msg.type`, which T-4 here discharges; its T-5 work-bound consumes the parse-window bound this proof's §5.1(e) references.
- `docs/proofs/S022WireFormatCapsCompleteness.md` — cap-table exhaustion; its T-1 step 4 (out-of-enum type byte → default tier) pairs with T-1 here (the `static_cast<MsgType>` is the sole, bounds-safe type interpretation).
- `docs/proofs/WireFormatBackwardCompat.md` — zero-skip hash-stability of optional signing-bytes fields; orthogonal layer (signing-bytes pre-image vs gossip envelope) — the two together cover the full wire surface a peer sees.
- `docs/proofs/S002-Mempool-Sig-Verify.md` — the amount/fee/nonce decode fix; the historical witness for T-2's TRANSACTION-path exactness.
- `docs/proofs/JsonValidationSoundness.md` — S-018 closure; governs the `json_require` / missing-`payload` diagnostics in `Message::deserialize`'s JSON branch (T-4 JSON-branch throws).
- `docs/proofs/Preliminaries.md` §3 — network model underlying the `Peer` framing assumption that strips the length prefix before `dec` sees the body.
- `docs/proofs/tla/HelloHandshake.tla` — the `min(ours, theirs)` wire-version negotiation state machine referenced in §2.3.

### Documentation references

- `docs/SECURITY.md` §S-002 (binary codec amount/fee/nonce fix), §S-018 (JSON envelope validation), §S-022 (per-type size cap).
- `docs/PROTOCOL.md` §9.2 — wire-type table + body-cap column (the type surface this codec decodes).
- `docs/README.md` §12.2 — wire-format "shipped" narrative (binary codec + version negotiation).

### External references

- C++ ISO/IEC 14882:2017 §7.2.1 [expr.static.cast] / §10.2 [dcl.enum] — `static_cast<MsgType>(byte)` is well-defined for any value in the underlying `uint8_t` range (T-1, T-4: the type-byte cast never invokes UB).
- nlohmann/json — `parse` throws `nlohmann::json::parse_error` (a `std::exception` subclass) on malformed input (T-4 JSON-branch); `parse(dump(v)) == v` round-trip identity on the library's own output (L-5).
