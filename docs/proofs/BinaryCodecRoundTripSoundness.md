# BinaryCodecRoundTripSoundness — binary-only envelope-magic + round-trip + bounds-safety

This document formalizes the soundness of the A3 / S8 binary wire codec at `src/net/binary_codec.cpp` and its driver at `src/net/messages.cpp` (`Message::serialize_binary` / `Message::deserialize`). The wire is **binary-only** (D2, DECISION-LOG 2026-07-28): the legacy JSON envelope encoder (`Message::serialize`, wire-version 0) and the per-pair HELLO version negotiation were deleted pre-genesis, and every body on the wire is the `0xB1` binary envelope. Where `S022WireFormatCaps.md` + `S022WireFormatCapsCompleteness.md` bound the *size* of an accepted message and `WireFormatBackwardCompat.md` proves the *hash-stability* of optional field additions, this document proves the *decode correctness* surface that sits between the two: that the envelope-magic check is a total, deterministic predicate on at most the first two body bytes, that every reachable encoder output satisfies it, and that every body failing it is rejected fail-closed with the specific `"not a binary envelope"` throw (T-1); that the encode/decode pair is a round-trip identity on the wire-relevant projection of *every* `MsgType` — HELLO now included via its fixed binary frame, and the `TRANSACTION` projection now including the optional `pq_auth` section (T-2); that every read in `decode_binary` / `decode_tx_frame` / `decode_hello_frame` is bounds-checked before the access it guards so an adversarial truncated/oversized body throws rather than reads out of bounds (T-3); and that `Message::deserialize` is therefore total — every byte string either decodes to a structurally-valid `Message` or raises a `std::exception` that the `Peer::read_body` catch handler at `src/net/peer.cpp:89-109` absorbs by closing the connection (WIRE-3) (T-4).

The proof is structural — there are no cryptographic assumptions on the codec itself (the codec moves bytes; the cryptography lives in the payloads it carries and is bound by the signing-bytes primitives that `WireFormatBackwardCompat.md` covers). The contribution over the existing wire-format proof corpus is the *decoder-correctness* layer: the size proofs assume the deserializer returns a `msg.type` value; this proof establishes that the deserializer cannot be steered into undefined behavior, that the envelope-magic dispatch is deterministic and fail-closed, and that the single shipped format round-trips every field a downstream consumer reads.

**Companion documents.** `S022WireFormatCaps.md` (parent size-cap closure — its T-3 assumes `Message::deserialize` returns a `msg.type`; T-4 here discharges the "deserialize is total" precondition that T-3 leans on, and its T-6 records the WIRE-3 close-on-parse-error disposition this proof's T-4 composes with); `S022WireFormatCapsCompleteness.md` (the cap-table exhaustion proof — its T-1 step 4 notes the decoder casts an out-of-enum type byte to `MsgType`; T-1 here shows the cast is the *only* type-byte interpretation and is bounds-safe); `WireFormatBackwardCompat.md` (the zero-skip hash-stability theorem — orthogonal: that proof covers the signing-bytes pre-image, this one covers the gossip envelope around it); `Preliminaries.md` §3 (network model underlying the `Peer` framing assumption); `JsonValidationSoundness.md` (S-018 — governs the `json_require` diagnostics in the per-type payload `from_json` consumers *downstream* of the codec; its former object here, the JSON-envelope branch of `Message::deserialize`, was deleted with D2); `S002-Mempool-Sig-Verify.md` (the amount/fee/nonce decode-fix whose round-trip property T-2 generalizes); `docs/SECURITY.md` §S-022 / §S-002 / §S-018 for the audit-trail. (`tla/HelloHandshake.tla` modeled the deleted `min(ours, theirs)` wire-version negotiation and is historical — the negotiation state machine no longer exists in the code; the spec is being retired/reduced in a parallel edit.)

---

## 1. Theorem statements

**Setup.** Let a *body* `B ∈ {0,1}^{8n}` (0 ≤ n ≤ kMaxFrameBytes) denote the framing-stripped payload that `Peer::read_body` hands to `Message::deserialize` (`src/net/messages.cpp:82`). The framing layer (a 4-byte big-endian length prefix, `src/net/peer.cpp:40-60` read side) is outside the codec; `serialize_binary` re-prepends it (`messages.cpp:124-130`) and `read_body` strips it, so the codec operates purely on `B`.

Let:

- `enc_B : Message → {0,1}^*` be the binary envelope serializer, `encode_binary` (`binary_codec.cpp:396`). It emits `[0xB1][0x01][type][0x00] || payload_frame`, so `enc_B(m)[0] = 0xB1` and `enc_B(m)[1] = 0x01`. It is total over every `MsgType` — HELLO included, via its fixed frame (`binary_codec.cpp:401-404`); the only throws are on pathological inputs (a string field > 255 bytes in `put_lp_str`, a payload or `pq_auth` exceeding the u32 length field), none reachable from a structurally-valid `Message`. There is no other wire encoder: the JSON envelope serializer `enc_J` (`Message::serialize`) is **deleted** (D2), and `Peer::send` calls `serialize_binary()` unconditionally (`peer.cpp:114-124`).
- `dec : {0,1}^* → Message ∪ {⊥}` be `Message::deserialize`, where `⊥` denotes "raised a `std::exception`".
- `det : {0,1}^* → {true, false}` be the envelope-magic predicate `is_binary_envelope` (`binary_codec.cpp:388-392`), with `det(B) = true ⟺ (|B| ≥ 4 ∧ B[0] = 0xB1 ∧ B[1] = 0x01)`.

Let `π : Message → WireFields` be the *wire-relevant projection* — the tuple of fields any downstream consumer reads off a decoded `Message`. For a `TRANSACTION`, `π` is `(from, to, amount, fee, nonce, payload, type, sig, hash, pq_auth)` (every field `chain::Transaction::from_json` / `to_json` round-trips; `pq_auth` joined the projection with the §3.21 / D2-inc1 optional trailing section — pre-inc1 the binary frame silently dropped it). For a `HELLO`, `π` is the five named fields `(domain, port, role, shard_id, wire_version)` as read through the tolerant `.value()` accessors that both `encode_hello_frame` and `GossipNet::handle_message`'s HELLO case use (`binary_codec.cpp:339-348`, `gossip.cpp:177-189`). For every other type, `π` is the full `payload` JSON value.

**Theorem T-1 (Envelope-Magic Totality and Fail-Closed Coverage).** `det` is a total, deterministic function of `|B|` and at most the first two body bytes. Every reachable encoder output satisfies it:

$$
\forall m \in \mathrm{dom}(enc_B):\ det(enc_B(m)) = \mathrm{true},
$$

and every body failing it is rejected by `Message::deserialize` with the specific throw whose message contains `"not a binary envelope"` (`messages.cpp:83-87`), *before any payload work*. There is no second accepted format: the set of bodies `dec` will attempt to decode is exactly `{B : |B| ≥ 4 ∧ B[0] = 0xB1 ∧ B[1] = 0x01}`. In particular a legacy JSON-envelope body (first byte `'{'` = `0x7B ≠ 0xB1`) lands in this throw — the deleted wire-version-0 path cannot be silently re-entered.

**Theorem T-2 (Round-Trip Identity on the Wire Projection).** For every `Message m` whose payload is a structurally-valid instance of its type:

$$
\pi(dec(enc_B(m))) = \pi(m).
$$

Three cases. For the `TRANSACTION` fixed-frame path this is exact field equality across `(from, to, amount, fee, nonce, payload, type, sig, hash, pq_auth)`: the S-002 fix (`binary_codec.cpp:281-283`) reads amount/fee/nonce from the fixed slots the encoder wrote (`binary_codec.cpp:223-226`), and the D2-inc1 `pq_auth` section is emitted iff non-empty (`binary_codec.cpp:259-264`) and decoded fail-closed (`binary_codec.cpp:323-333`) — a frame ending at the hash decodes with `pq_auth` empty, matching the encoder's omit-when-empty convention, so the empty case round-trips too. For `HELLO` it is exact equality on the five named fields through the fixed binary frame (`encode_hello_frame` / `decode_hello_frame`, `binary_codec.cpp:339-371`) — the decoder rebuilds the payload with all five keys explicit, so a payload that omitted a field round-trips to that field's documented default, which is `π`-equal under the tolerant read. For the length-prefixed-JSON path (every other type) it is exact JSON-value equality, since `enc_B` embeds `m.payload.dump()` verbatim (`binary_codec.cpp:412-419`) and `dec` re-parses it (`binary_codec.cpp:456-470`).

*(The former corollary that the binary and JSON paths are observationally equivalent is retired with its premise: `enc_J` no longer exists, so there is no second path to be equivalent to.)*

**Theorem T-3 (Bounds-Safety of the Decode Path).** For every body `B` (adversarial or honest), `decode_binary(B)` and its `decode_tx_frame` / `decode_hello_frame` sub-calls perform no out-of-bounds read: every indexed access `data[i]` / `data + i` and every `memcpy` is preceded on all reachable control-flow paths by a length guard that throws `std::runtime_error` when the required bytes are not present. Formally, for each read of `k` bytes at offset `off`, the code establishes `off + k ≤ len` before the read, or throws. This covers the D2-inc1 `pq_auth` section reads and the D2-inc2 HELLO frame reads (guard inventory in §3.4–§3.5). The decoder therefore has no undefined behavior on any input in `{0,1}^*`.

**Theorem T-4 (Totality of `Message::deserialize`).** `dec` is total over `{0,1}^*` in the sense that for every body `B`, `dec(B)` either returns a `Message` with a well-defined `type ∈ MsgType` (any byte value, per the `static_cast<MsgType>` at `binary_codec.cpp:430` / `messages.cpp:106`) and a `payload` value, or raises a `std::exception`. `dec` is binary-only: a body failing `det` — including a `'{'`-leading legacy JSON envelope — raises the T-1 throw; a body passing `det` then faces the WIRE-1 pre-decode per-type size cap (`messages.cpp:106-114`), which throws before any payload work if `|B| > max_message_bytes(B[2])`; only then does `decode_binary` run. There is no input on which `dec` reads out of bounds, loops without termination, or returns an uninitialized value. Composed with the `Peer::read_body` `try`/`catch` at `src/net/peer.cpp:71-109`, every decode failure — the T-1 magic reject and all decode throws alike — is caught, logged, and **closes the connection** (WIRE-3, `peer.cpp:107`), and every decode success is additionally gated by the post-decode S-022 per-type cap (`peer.cpp:80-87`) before dispatch.

---

## 2. Background

### 2.1 The binary-only wire surface

Determ peers exchange `Message` values over TCP. The transport (`Peer`) frames each body with a 4-byte big-endian length prefix (`src/net/peer.cpp:40-60` read side; `messages.cpp:124-130` write side). Inside that frame the *body* is exactly one format:

- **Binary envelope v1 (the only wire format — D2).** `Message::serialize_binary` → `encode_binary` emits a 4-byte header `[0xB1][0x01][type][0x00]` followed by a per-type payload. The body always begins with `0xB1 0x01`. Every `MsgType` encodes — HELLO travels as a fixed binary frame like everything else (`binary_codec.cpp:86-98` layout comment).

The legacy JSON envelope (wire-version 0, body leading with `'{'`) and the per-pair `min(ours, theirs)` HELLO negotiation were deleted pre-genesis with D2. What remains of versioning is an **advertisement**: `kWireVersionBinary = 1` is the single shipped constant (`messages.hpp:84-89`), and HELLO carries a `wire_version` u8 field that nothing reads today (`gossip.cpp:185-187`) — it is the additive post-genesis upgrade escape hatch (a future v2 peer advertises 2, keeps *sending* v1 frames, and upgrades only after reading the peer's advertised max; no-migrations discipline).

The receive path (`Message::deserialize`, `messages.cpp:82-116`) checks `is_binary_envelope(B)` and *rejects* any body failing it — there is no fallback parser. The body still tells the receiver what it is (self-describing magic + in-the-clear type byte at offset 2), but the answer is now binary-or-throw, not binary-or-JSON.

### 2.2 Why a decode-correctness proof is needed alongside the size-cap proofs

`S022WireFormatCaps.md` T-3 reasons about the state *after* `Message::deserialize` returns a `msg` value — it gates `on_msg_` on `body_buf_.size() > max_message_bytes(msg.type)`. That argument silently assumes `Message::deserialize` *returns* (rather than reading out of bounds, or being steered to a type byte it can't interpret). The size proof explicitly defers this: its §6.2 finding-register lists "deserialize-time bugs that crash the receiver before the cap is checked" as out of scope. This document discharges that assumption:

1. The decoder casts the type byte with `static_cast<MsgType>(data[2])` — any of the 256 byte values is a valid (possibly out-of-enum) `MsgType`, so the type read never throws and never reads OOB (T-1, T-3).
2. Every length-prefixed and fixed-slot read inside `decode_binary` / `decode_tx_frame` / `decode_hello_frame` is guarded (T-3), so a truncated or maliciously-short body throws `std::runtime_error` rather than reading past `data + len`.
3. Both outcomes (return-or-throw) are handled at the peer layer (T-4), so the deserializer is safe to feed arbitrary peer bytes.

Two later hardening layers now sit *inside* `dec` and are part of its totality surface: the WIRE-1 pre-decode per-type cap (`messages.cpp:88-114` — the type is readable in the clear at offset 2, so the S-022 ceiling is applied before any payload work) and the WIRE-2 structural ceiling (`json_structural_precheck`, `messages.cpp:18-76`, invoked at `binary_codec.cpp:468` on the length-prefixed JSON payloads that the non-HELLO/non-TRANSACTION types still carry inside the binary envelope — it survives the D2 envelope strip and retires only when every payload becomes a true binary frame). Both are throw-on-violation, i.e. more instances of the T-4 return-or-throw contract; their DoS soundness is proved in `S022WireFormatCaps.md`, not here.

Without T-3, the S-022 cap argument has a gap: an attacker who can make `Message::deserialize` read OOB defeats the cap before it is consulted. T-3 closes the gap.

### 2.3 Send-side encoding is unconditional (context, not the proof object)

There is no send-side format choice. `Peer::send` calls `msg.serialize_binary()` unconditionally (`peer.cpp:114-124`); the old silent catch-all JSON fallback is deliberately not reproduced — an encode failure is a local bug and must surface loudly at the call site, never mask itself as legacy traffic (the comment at `peer.cpp:115-118` pins this intent). `encode_binary` accepts every `MsgType` including HELLO (`binary_codec.cpp:394-404`), so there is no special-cased first message: the HELLO that opens every connection is the same `0xB1` envelope as everything after it. The per-peer `wire_version_` member, the `kWireVersionLegacy` / `kWireVersionMax` constants, and the HELLO-receipt negotiation in `gossip.cpp` are all deleted; the receiver's HELLO case tags the peer's identity fields and marks the handshake done, nothing more (`gossip.cpp:177-189`).

---

## 3. Implementation citation

### 3.1 Envelope-magic check (`is_binary_envelope`)

`src/net/binary_codec.cpp:375-392`:

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

`src/net/binary_codec.cpp:424-471`:

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

Every read is guarded: `len < 4` guards `data[0..3]` (including the reserved-byte check at `binary_codec.cpp:440-441` — non-zero is rejected fail-closed, matching the independent light/wallet conformance decoders; see `ReservedDiscriminatorAudit.md` §6); the `body_len < 4` guard precedes `le_get_u32(body)` (which reads `body[0..3]`); and `4 + plen > body_len` guards the `body + 4 .. body + 4 + plen` window for both the WIRE-2 pre-scan and the parse. The cast `static_cast<MsgType>(data[2])` accepts any byte (per `S022WireFormatCapsCompleteness.md` T-1 step 4, an out-of-enum byte simply hits the default size tier). The magic/version re-checks at `binary_codec.cpp:425-428` are defense-in-depth for direct callers (tests, tools); from `Message::deserialize` the T-1 gate has already established them.

### 3.4 The transaction fixed-frame decoder (`decode_tx_frame`)

`src/net/binary_codec.cpp:267-335`. The guards, in source order:

| Guard (line) | Protects |
|---|---|
| `if (len < 128 + 1 + 2) throw` (269-270) | the fixed-slot reads at offsets 32, 40, 48, 56 (amount/fee/nonce/reserved, read at 281-284) and the trailer `type` + `payload_len` reads at offsets 128, 129-130 (read at 294-295) |
| `if (reserved != 0) throw` (285-286) | determinism invariant — rejects a non-canonical frame whose reserved u64 is non-zero |
| `payload_len <= 32` branch (297-299) | reads `data + 96 .. 96 + payload_len`, which is ≤ 128 ≤ `len` by the line-269 guard |
| `if (off + overflow > len) throw` (302-303) | the overflow-payload `data + off .. off + overflow` read |
| `get_lp_str` internal guards (200, 202) | the `from` / `to` length-prefixed string reads at 310-311 (`off + 1 > len` for the length byte, `off + n > len` for the body) |
| `if (off + 64 + 32 > len) throw` (312-313) | the `memcpy` of the 64-byte sig and 32-byte hash (314-315) |
| `if (off + 4 > len) throw` (324-325) | the `pq_auth` section header `le_get_u32(data + off)` (326) — reached only when `off != len`, i.e. bytes remain after the hash |
| `if (pq_len == 0) throw` (327-328) | canonicality — the encoder omits the section when `pq_auth` is empty, so a zero-length section has no legitimate producer and is rejected (`"empty pq_auth section"`) |
| `if (pq_len != len - off) throw` (329-330) | exact consumption — the section must end the frame precisely (`"pq_auth length mismatch"`); this equality *is* the bounds guard for the `tx.pq_auth.assign(data + off, data + off + pq_len)` read at 331, whose window ends exactly at `data + len` |

The encoder side (`encode_tx_frame`, `binary_codec.cpp:210-265`) writes exactly the layout the decoder reads, with `put_padded` (`binary_codec.cpp:185-189`) right-padding short `from`/`to`/`payload` to their 32-byte slots and the trailer carrying the authoritative variable-length `from`/`to`/`sig`/`hash`. `put_lp_str` (`binary_codec.cpp:192-197`) throws if a string exceeds 255 bytes, the symmetric bound to `get_lp_str`'s u8 length read. The `pq_auth` section (`binary_codec.cpp:259-264`) is appended **only when `tx.pq_auth` is non-empty** — `[u32 LE len][bytes]`, with a u32-overflow guard at 260-261 — so every non-PQ frame is byte-identical to the pre-§3.21 layout (the layout comment at `binary_codec.cpp:69-77` pins the convention).

### 3.5 The HELLO fixed-frame codec (`encode_hello_frame` / `decode_hello_frame`)

`src/net/binary_codec.cpp:339-371` (layout comment at 86-98). The frame after the 4-byte envelope header is `[u8 domain_len][domain][u16 LE port][u8 role][u32 LE shard_id][u8 wire_version]`:

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

Guard inventory: `get_lp_str`'s two internal guards cover the domain read; the single combined guard at `binary_codec.cpp:353-354` establishes `off + 8 ≤ len` before the four fixed-width reads at 355-358 (2 + 1 + 4 + 1 = 8 bytes); and the exact-consumption check at 362-363 rejects trailing bytes fail-closed (`"HELLO frame trailing bytes"`) — a future *additive* field must arrive behind a bumped `wire_version` advertisement, never as silent padding. The two specific reject strings (`"truncated HELLO frame"`, `"HELLO frame trailing bytes"`) are pinned by test-binary-codec leg 1b.

---

## 4. Lemmas and proofs

### Lemma L-1 (every reachable encoder output begins `0xB1 0x01`)

`enc_B(m)` (`binary_codec.cpp:396-420`) calls `put_envelope_header` (`binary_codec.cpp:378-383`) first on every path, pushing `kBinaryMagic = 0xB1` then `kBinaryVersion = 0x01` as the first two bytes, then `type` and the reserved `0x00`. Every branch (HELLO fixed frame, TRANSACTION fixed frame, length-prefixed JSON) appends after the header. Hence `enc_B(m)[0] = 0xB1`, `enc_B(m)[1] = 0x01`, and `|enc_B(m)| ≥ 4`. There is no other reachable wire encoder: `Peer::send` (`peer.cpp:119`) is the only wire write path and calls `serialize_binary()`, which defers to `encode_binary` (`messages.cpp:122-123`). □

### Lemma L-2 (`det` reads at most two bytes and is deterministic)

`is_binary_envelope` (§3.1) is a pure function of `len` and `data[0..1]`, evaluated left-to-right with `&&` short-circuit: if `len < 4` it returns `false` without reading `data`; otherwise it reads exactly `data[0]` and `data[1]`. It has no global state and no side effects, so it is deterministic. □

### Lemma L-3 (every `decode_binary` / `decode_tx_frame` / `decode_hello_frame` read is guarded)

By the guard inventory in §3.3 (the `len < 4` envelope-header guard covering the type and reserved bytes, the `body_len < 4` guard preceding `le_get_u32`, and the `4 + plen > body_len` window guard covering both the WIRE-2 scan and the parse), §3.4 (the line-269 fixed-slot/trailer guard, the overflow guard, the two `get_lp_str` internal guards, the sig/hash `memcpy` guard, and the three `pq_auth` guards — header, non-empty, exact-consumption, the last doubling as the bounds guard for the section-body read), and §3.5 (the `get_lp_str` guards for the domain, the combined `off + 8 ≤ len` guard for the four fixed-width fields, and the exact-consumption check). Each guard is a `throw std::runtime_error(...)` executed *before* the access it protects on every control-flow path that reaches the access. The only reads not behind an explicit per-read guard are the tx-frame fixed-slot reads at offsets 32/40/48/56/96/128/129, all covered by the single line-269 precondition `len ≥ 131`. No path reaches a `data[i]`, `memcpy`, or `assign` with `i ≥ len` or `i + k > len`. □

### Lemma L-4 (encoder/decoder slot agreement for `TRANSACTION`, `pq_auth` included)

`encode_tx_frame` writes, in order: `from` padded to 32 B (offset 0), `amount`/`fee`/`nonce`/`reserved=0` as LE u64s (offsets 32/40/48/56), `to` padded to 32 B (offset 64), `payload` first-32 padded (offset 96), then the trailer `type` (offset 128), `payload_len` (offset 129), payload-overflow if any, `lp_str(from)`, `lp_str(to)`, `sig` (64 B), `hash` (32 B), and — iff `tx.pq_auth` is non-empty — the `[u32 LE len][bytes]` `pq_auth` section (`binary_codec.cpp:259-264`). `decode_tx_frame` reads `amount`/`fee`/`nonce` from offsets 32/40/48 (`binary_codec.cpp:281-283`), checks `reserved == 0` at offset 56, reads `type` at 128 and `payload_len` at 129, reconstructs `payload` from the fixed slot (≤ 32 B case) or fixed slot + overflow (> 32 B case), reads `from`/`to`/`sig`/`hash` from the trailer, and then (`binary_codec.cpp:323-333`) reads the `pq_auth` section iff bytes remain — a frame ending exactly at the hash decodes with `pq_auth` empty, mirroring the encoder's omit-when-empty rule, and the zero-length-section reject keeps the encoding *canonical* (no two distinct byte strings decode to the same tx). The authoritative `from`/`to` come from the trailer `lp_str` values (the 32-byte fixed slots are padding-lossy and not read back as identifiers). Every encoded field has a matching decode read at the same offset. □

### Lemma L-5 (length-prefixed-JSON path is verbatim)

For `m.type ∉ {HELLO, TRANSACTION}`, `enc_B` computes `s = m.payload.dump()`, writes `le_u32(|s|)` then `s` verbatim (`binary_codec.cpp:412-419`). `decode_binary` reads `plen = le_get_u32(body)`, verifies `4 + plen ≤ body_len`, runs the WIRE-2 structural pre-scan, and parses `body + 4 .. body + 4 + plen` as JSON (`binary_codec.cpp:456-470`). The pre-scan never rejects a document within the shipped ceilings that `dump()` of a legitimate payload produces (`S022WireFormatCaps.md` sizing argument), and `nlohmann::json::parse(dump(v)) == v` for any JSON value `v` (round-trip property of the JSON library on its own output), so `dec(enc_B(m)).payload == m.payload`. □

### Lemma L-6 (encoder/decoder field agreement for `HELLO`)

`encode_hello_frame` (`binary_codec.cpp:339-348`) writes `lp_str(domain)`, `port` (u16 LE), `role` (u8), `shard_id` (u32 LE), `wire_version` (u8), reading each from the payload via `.value()` with the documented default. `decode_hello_frame` (`binary_codec.cpp:350-371`) reads the same five fields at the same offsets in the same order and rebuilds a payload with all five keys explicit. For a payload carrying all five fields (the `make_hello` shape, `messages.hpp:302-321`), decode returns them exactly; for a payload omitting a field, the encoder writes the default and the decoder returns it explicitly — equal under the tolerant `.value()` read that defines `π(HELLO)`. The exact-consumption check makes the frame boundary unambiguous, so no field read can absorb bytes of another. □

### Proof of T-1

Totality and determinism of `det` are L-2. Coverage: by L-1, every reachable `enc_B` output has first two bytes `0xB1 0x01` and length ≥ 4, so `det(enc_B(m)) = true` for all `m ∈ dom(enc_B)`. Fail-closed rejection: `Message::deserialize` (`messages.cpp:82-87`) has a single entry check — `if (!is_binary_envelope(data, len)) throw` — whose exception message contains the string `"not a binary envelope"`; no other parse is attempted on the failing branch, so every body with `|B| < 4`, `B[0] ≠ 0xB1`, or `B[1] ≠ 0x01` is rejected before any payload work. A legacy JSON envelope begins with `'{'` = `0x7B ≠ 0xB1` and therefore lands in this throw; the D2 negative gate (test-binary-codec leg 5) pins exactly this — a *well-formed* legacy envelope rejected with the specific string, so a mutant that re-admits a JSON parse path goes red. □

### Proof of T-2

By T-1, `det(enc_B(m)) = true`; for a structurally-valid `m`, `|enc_B(m)| ≤ max_message_bytes(m.type)` (the S-022 sizing argument — legitimate messages sit far below their tier), so the WIRE-1 cap passes and `dec(enc_B(m)) = decode_binary(enc_B(m))`. Three cases:

- `m.type = HELLO`: by L-6, `decode_hello_frame` returns the five named fields the encoder wrote, so `π(dec(enc_B(m))) = π(m)`.
- `m.type = TRANSACTION`: by L-4, every field the encoder wrote is read back at the matching offset; the S-002 fix (`binary_codec.cpp:281-283`) supplies amount/fee/nonce from the fixed slots, the trailer supplies `from`/`to`/`payload`/`sig`/`hash`, and the D2-inc1 section supplies `pq_auth` (empty iff the encoder omitted it iff `m`'s tx had it empty). `decode_binary` then sets `m.payload = tx.to_json()`. Since `chain::Transaction::from_json ∘ to_json` is the identity on the projected fields — including `pq_auth`, whose JSON encoding follows the same omit-when-empty convention — `π(dec(enc_B(m))) = π(m)`.
- `m.type ∉ {HELLO, TRANSACTION}`: by L-5, `dec(enc_B(m)).payload == m.payload`, and `π` for these types is the whole payload, so `π(dec(enc_B(m))) = π(m)`. □

### Proof of T-3

By L-3, every indexed read, `memcpy`, and range `assign` in `decode_binary`, `decode_tx_frame`, and `decode_hello_frame` is preceded on all reachable paths by a length guard that throws when the required `off + k ≤ len` condition fails — including the two new surfaces: the `pq_auth` section (header guard, then the exact-consumption equality `pq_len == len − off` which pins the section-body window to end exactly at `data + len`) and the HELLO frame (the `get_lp_str` guards plus the combined 8-byte fixed-field guard). The helpers `le_get_u16` / `le_get_u32` / `le_get_u64` read fixed widths (2/4/8 bytes) from a pointer the caller has already bounds-checked; `get_lp_str` carries its own two guards. The encoder's `put_lp_str` enforces the ≤ 255 bound that `get_lp_str`'s u8 length field can represent, so a round-tripped honest frame never trips the decode guards, while an adversarial frame either satisfies every guard (and decodes to a structurally-valid value) or trips one (and throws). No path performs an access with `off + k > len`. Hence the decode path has no out-of-bounds read and no undefined behavior on any input. □

### Proof of T-4

`dec` (`messages.cpp:82-116`) is a straight-line composition of three throw-or-continue stages. *Stage 1 (T-1 gate):* a body failing `det` raises the `"not a binary envelope"` throw — this is where every `'{'`-leading legacy JSON body now lands; no JSON parser exists on any path of `dec`. *Stage 2 (WIRE-1):* the pre-decode per-type cap either throws or continues; `data[2]` is safe to read because stage 1 established `len ≥ 4`. *Stage 3:* `decode_binary` either returns a `Message` (with `type = static_cast<MsgType>(data[2])`, defined for all 256 byte values, and a `payload` set from `decode_hello_frame`, `tx.to_json()`, or a parsed JSON window) or throws — by T-3 it never reads OOB, every internal failure is a `throw std::runtime_error`, the WIRE-2 pre-scan throws on ceiling violation, and `nlohmann::json::parse` of the payload window throws `parse_error` (a `std::exception` subclass) on malformed JSON. All stages terminate (no loops in `decode_binary`; `decode_tx_frame` / `decode_hello_frame` have only straight-line code plus the fixed-iteration helper loops in `le_get_*` / `put_*`; the WIRE-2 scan is a single bounded pass; `nlohmann` parsing terminates on finite input). Therefore `dec` is total in the return-or-throw sense.

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

**(a) Truncated binary frame.** Adversary sends `0xB1 0x01 <type> 0x00` followed by fewer bytes than the type's payload requires. **Defended (T-3 + T-4).** Every short read trips a length guard (`len < 128+1+2` for TRANSACTION, the `get_lp_str` + combined-fixed-field guards for HELLO, `body_len < 4` / `4+plen > body_len` for the length-prefixed-JSON types, the sig/hash and `pq_auth` guards) and throws; the peer logs and closes (WIRE-3).

**(b) Out-of-enum type byte.** Adversary sends `0xB1 0x01 0xFF 0x00 ...`. **Defended (T-1 + S-022 completeness T-1 step 4).** `static_cast<MsgType>(0xFF)` is a valid (out-of-enum) `MsgType`; the WIRE-1 pre-decode cap defaults it to the tight 1 MB tier, and the length-prefixed-JSON decode path handles it (it is `∉ {HELLO, TRANSACTION}`). No OOB, no UB.

**(c) Non-canonical reserved field.** Adversary sets the tx-frame reserved u64 (offset 56) non-zero, or the envelope reserved byte (offset 3) non-zero. **Defended (both fail-closed).** The tx-frame reserved field is checked (`binary_codec.cpp:285-286` throws), and — since the Finding F-1 closure — the envelope reserved byte is checked too (`binary_codec.cpp:440-441` throws `"reserved envelope byte non-zero"`), matching the independent light/wallet conformance decoders. The envelope is strictly canonical: two distinct envelope byte strings never decode to the same `Message` via reserved-byte malleability.

**(d) Format-confusion / legacy-format smuggling.** Adversary sends a JSON body (or any non-`0xB1` bytes) hoping to reach a parser. **Defended (T-1).** There is no second format: any body failing the magic check — including a well-formed legacy wire-version-0 JSON envelope — is rejected with the `"not a binary envelope"` throw before any parse. The deleted JSON path cannot be re-entered from the wire; test-binary-codec leg 5 pins this with a mutant-sensitive negative vector.

**(e) Oversized length-prefix in the length-prefixed-JSON path.** Adversary sets `plen` to a huge value to provoke a large allocation. **Defended (T-3 + S-022).** `decode_binary` rejects `4 + plen > body_len` *before* parsing; `body_len` is bounded by the WIRE-1 pre-decode per-type cap (`messages.cpp:106-114`) which fires before `decode_binary` runs, and the WIRE-2 structural ceiling (`binary_codec.cpp:468`) bounds the DOM the parse can build. See `S022WireFormatCaps.md` for the measured amplification bounds.

**(f) `pq_auth` section abuse.** Adversary appends bytes after a TRANSACTION frame's hash: trailing garbage, a zero-length section, a short body, or extra bytes after a valid section. **Defended (T-3 + L-4 canonicality).** The section decode is fail-closed: `"truncated pq_auth header"`, `"empty pq_auth section"`, and `"pq_auth length mismatch"` cover all four shapes (test-tx-binary-codec leg 10 pins each string). A frame ending exactly at the hash is the unique encoding of a non-PQ tx.

**(g) HELLO frame padding/truncation.** Adversary pads a HELLO with trailing bytes (hoping a future field is silently absorbed) or truncates it. **Defended (T-3 + §3.5).** `"truncated HELLO frame"` / `"HELLO frame trailing bytes"` reject both fail-closed; an additive HELLO field can only ship behind a bumped `wire_version` advertisement.

The codec does *not* defend against (and is not designed to defend against):

- Semantic validity of the decoded payload (e.g., a syntactically-valid but economically-invalid `Transaction`, or an unverified `pq_auth` blob — the codec carries it; `verify_pq_transaction` judges it). That is the apply/admission layer's job (`NonceMonotonicity.md`, `FeeAccounting.md`, S-002 signature verification). The codec guarantees a *structurally* well-formed `Message`, not a *semantically* admissible one.
- Compression bombs / parser DoS inside `nlohmann::json::parse` beyond the WIRE-1 + WIRE-2 ceilings. Bounded and *measured* in `S022WireFormatCaps.md` (T-5 work bound, F-6 residual); mitigation-not-elimination is documented there, not re-litigated here.

### 5.2 Notable findings

**Finding F-1 (Envelope reserved byte at offset 3 — RESOLVED).** As originally recorded here, `put_envelope_header` wrote `0x00` but `decode_binary` ignored the byte on decode — a benign wire malleability, flagged with a ~2 LOC mitigation. That mitigation has since shipped: `decode_binary` now rejects `data[3] != 0x00` fail-closed (`binary_codec.cpp:440-441`), closing the S-043-class validation asymmetry `ReservedDiscriminatorAudit.md` §6 found (the daemon silently ignored the byte while the light/wallet conformance decoders rejected it, so a mixed fleet disagreed on frame validity). Gated: test-binary-codec leg 6b (tampered reserved byte throws; zero-reserved control still decodes). The envelope is now strictly canonical — see §5.1(c).

**Finding F-2 (Binary `TRANSACTION` frame carries `from`/`to` twice).** The fixed-slot pubkey area (offsets 0..31, 64..95) and the trailer `lp_str(from)` / `lp_str(to)` both encode the address strings. The decoder reads the *trailer* values as authoritative and treats the fixed slots as padding-lossy (`binary_codec.cpp:288-291` comment). The module comment (`binary_codec.cpp:79-84`) flags this as intentional transitional redundancy: the 4×256-bit frame predates the domain-string account model, and the trailer exists so the frame round-trips real transactions until identity migrates to raw pubkeys (R3+). **Severity:** None (correctness-neutral; a bandwidth inefficiency of ≤ ~64 redundant bytes per tx). **Status:** documented design wrinkle, not a defect. The S-002 fix preserved the property that the *numeric* fields (amount/fee/nonce) live only in the fixed slots, so there is no double-encoding ambiguity for the consensus-bound numeric fields.

**Finding F-3 (No dedicated negative test — RESOLVED).** The negative surface this finding asked for now exists across the shipped gates: test-binary-codec legs 7-8 (garbage bytes, truncated envelope header), leg 1b (truncated/padded HELLO frames with the specific reject strings), leg 5 (the D2 legacy-envelope reject), leg 6b (reserved-byte tamper), and test-tx-binary-codec leg 10 (all three `pq_auth` fail-closed reject strings, plus append-after-section, each asserted by *specific string* rather than bare throw — the SECOND-register discipline). T-3's guard inventory is therefore behaviorally pinned, not only structurally argued.

**Finding F-4 (Endianness coupling to host).** The binary envelope, tx frame, and HELLO frame use little-endian for all multi-byte integers (`binary_codec.cpp:124-129` rationale), matching x86_64/ARM64 host endianness. The `le_put_*` / `le_get_*` helpers (`binary_codec.cpp:150-182`) implement LE explicitly via shifts, so the codec is *byte-order-correct on any host* (the explicit shift-based pack/unpack does not depend on host endianness — it always emits/reads little-endian regardless of the machine). The "matches host endianness" comment refers to a micro-optimization opportunity (no byte-swap on LE hosts), not a correctness dependency. **Severity:** None (the explicit shifts make the codec portable). Noted to forestall a misreading of the comment as a portability bug.

Of the four findings, F-1 and F-3 are closed with shipped, gated code; F-2 and F-4 remain documented non-defects. None invalidates T-1 through T-4.

---

## 6. Test-suite citation

| Test | Source | Coverage |
|---|---|---|
| `tools/test_binary_codec.sh` (via `determ test-binary-codec`, `src/main.cpp:10138`) | In-process wire-codec unit test (rewritten for the D2 binary-only wire) | Binary HELLO round-trip through the fixed frame (leg 1) + the truncated/trailing HELLO rejects pinning `"truncated HELLO frame"` / `"HELLO frame trailing bytes"` (leg 1b — T-2 HELLO case, T-3 §3.5 guards); TRANSACTION and length-prefixed-JSON round-trips (legs 2-4, 6); the **D2 negative leg** — a *well-formed* legacy JSON envelope rejected with the specific `"not a binary envelope"` string, so a mutant re-admitting a JSON parse path goes red (leg 5 — T-1); reserved-envelope-byte reject + zero-reserved control (leg 6b — §5.1(c), F-1 closure); garbage/truncated-header rejects (legs 7-8 — T-3/T-4); WIRE-1 pre-decode cap ordering (leg 8b); the WIRE-2 structural-ceiling legs rebuilt as **binary-envelope vectors** (legs 8d+ — the hostile payloads now travel inside `0xB1` frames, matching the only wire that exists); the S-022 cap-table golden vectors. |
| `tools/test_tx_binary_codec.sh` (via `determ test-tx-binary-codec`, `src/main.cpp:22940`) | Transaction fixed-frame codec suite | Legs 1-8: the S-002 fixed-slot round-trip (amount/fee/nonce), trailer authority, hash invariance. Leg 9 (D2-inc1): `pq_auth` round-trips through the frame at realistic ML-DSA scale, the section is exactly `[u32 len][bytes]`, and a non-PQ tx emits **no** section (byte-identity with the pre-§3.21 layout) — T-2's extended `π`. Leg 10: fail-closed decode pinning each specific reject string — `"truncated pq_auth header"`, `"empty pq_auth section"`, `"pq_auth length mismatch"` (short body *and* byte-appended-after-section) — T-3's §3.4 `pq_auth` guard rows. Mutant-verified: reverting the encoder's `pq_auth` section reds leg 9. |
| `tools/test_binary_codec_roundtrip_exhaustive.sh` (via `determ test-binary-codec-roundtrip-exhaustive`, `src/main.cpp:10661`) | Exhaustive per-MsgType roundtrip | Walks every `MsgType` — HELLO now included via its fixed binary frame — through `encode_binary` → `decode_binary`, asserting type + payload preservation, the four envelope header bytes (`0xB1`, `0x01`, type, `0x00` reserved), and tamper-loud-fail on payload byte flips. Direct evidence for T-2 across the full type surface; indirect evidence for T-1 and L-1. |
| `tools/test_hello_handshake_determinism.sh` (via `determ test-hello-handshake-determinism`, `src/main.cpp:56777`) | HELLO determinism suite | All 7 scenarios run on the **binary frame** (replay determinism, round-trip, cross-instance, field-binding, boundary values); pins that the encoded HELLO body starts with `0xB1` (D2 — the old "HELLO is always JSON" contract is inverted). Mutant-verified: an encoder that drops `shard_id` from the frame reds the field-binding legs. Composes with §2.3 (the send path has no version selection to get wrong). |
| `tools/test_protocol_version_pinning.sh` (via `determ test-protocol-version-pinning`, `src/main.cpp:52045`) | PROTOCOL.md §16 version-contract pinning | §8 pins the `wire_version` **advertisement** surviving the HELLO binary round-trip; §9 is *inverted* from its pre-D2 form — it now pins that `encode_binary(HELLO)` **succeeds** with type byte 0 (the old §9 pinned the throw; this leg is the tombstone of the HELLO JSON carve-out). |
| `tools/test_wire_caps_discriminator.sh` (via `determ test-wire-caps-discriminator`, `src/main.cpp:57127`) | Framing/cap layering + discriminator contract (was `test_wire_negotiation.sh`; its section (A) — the `min(ours, theirs)` negotiation arithmetic — died with the negotiation and is deleted) | Section (B): every per-type cap ≤ `kMaxFrameBytes`, the three tiers strictly ordered, unmapped types fail closed at 1 MB. Section (C): discriminator-byte preservation for **every** MsgType — HELLO included since D2 gave it a binary frame — the type byte at offset 2 survives encode → decode independent of payload (the receive-side dispatch key, T-1/T-4's `static_cast` surface). |

The roundtrip-exhaustive test is the primary operational backstop for T-2; the negative legs across test-binary-codec and test-tx-binary-codec pin T-1, T-3, and the F-1/F-3 closures behaviorally; T-1 and T-3 additionally rest on the short structural arguments grounded in the §3 source citation. The S-002 regression (per `S002-Mempool-Sig-Verify.md`) is the historical witness that the `TRANSACTION` round-trip *was* broken (amount/fee/nonce dropped) and is now fixed — and the D2-inc1 `pq_auth` closure is the same story one layer out: the frame silently dropped `pq_auth` until the section shipped, and leg 9 is the gate that keeps it carried.

---

## 7. Status

**Shipped (analytic).** This document formalizes the decode-correctness surface of the shipped D2 binary-only wire codec; it introduces no code changes. The codec (`src/net/binary_codec.cpp`) and its driver (`src/net/messages.cpp`) shipped under A3 / S8 and were made the *sole* wire format by D2 (commits `b29d422` d2-inc1: the `pq_auth` TRANSACTION section; `ce31c6f` d2-inc2: JSON envelope + negotiation deletion, binary HELLO frame). The S-002 closure (`docs/SECURITY.md` §S-002) fixed the `TRANSACTION` round-trip that T-2 states as a theorem; the S-018 closure (`JsonValidationSoundness.md`) now governs payload-level `from_json` diagnostics downstream of the codec (its former object here, the deserialize JSON branch, is deleted).

Implementation surfaces:

- `src/net/binary_codec.cpp:375-392` — magic/version constants + `put_envelope_header` + `is_binary_envelope` (T-1, L-1, L-2).
- `src/net/binary_codec.cpp:396-420` — `encode_binary` (`enc_B`; T-2 encode side, every MsgType including HELLO).
- `src/net/binary_codec.cpp:424-471` — `decode_binary` (T-2 decode side, T-3 envelope guards incl. the reserved-byte reject at 440-441, L-3, L-5; WIRE-2 pre-scan at 468).
- `src/net/binary_codec.cpp:210-335` — `encode_tx_frame` / `decode_tx_frame` (T-2 TRANSACTION path, T-3 frame guards, L-4; S-002 fix at 281-283; `pq_auth` section encode 259-264 / decode 323-333).
- `src/net/binary_codec.cpp:339-371` — `encode_hello_frame` / `decode_hello_frame` (T-2 HELLO path, T-3 §3.5 guards, L-6).
- `src/net/messages.cpp:82-116` — the binary-only `Message::deserialize` (T-1 magic gate at 83-87, WIRE-1 pre-decode cap at 106-114, T-4 totality).
- `src/net/messages.cpp:18-76, 122-132` — `json_structural_precheck` (WIRE-2) + `Message::serialize_binary` (framing).
- `src/net/peer.cpp:62-112, 114-124` — `Peer::read_body` `try`/`catch` + post-decode S-022 cap + WIRE-3 close (T-4 composition); `Peer::send` unconditional `serialize_binary` (§2.3).

This proof discharges the "deserialize is total / does not read OOB" precondition that `S022WireFormatCaps.md` T-3 assumes, completing the decode-side companion to the size-cap and backward-compat proofs.

---

## 8. References

### Implementation references

- `src/net/binary_codec.cpp:124-206` — endianness rationale + `le_put_*` / `le_get_*` / `put_padded` / `put_lp_str` / `get_lp_str` byte helpers (F-4; the guarded `get_lp_str` per L-3).
- `src/net/binary_codec.cpp:210-335` — `encode_tx_frame` / `decode_tx_frame` (L-4; T-3 frame-guard inventory; S-002 amount/fee/nonce fix at 281-283; `pq_auth` section 259-264 / 323-333).
- `src/net/binary_codec.cpp:339-371` — `encode_hello_frame` / `decode_hello_frame` (L-6; T-3 HELLO guards; layout comment at 86-98).
- `src/net/binary_codec.cpp:375-392` — magic/version constants + `put_envelope_header` + `is_binary_envelope` (L-1, L-2, T-1).
- `src/net/binary_codec.cpp:396-471` — `encode_binary` / `decode_binary` (T-2, T-3, L-5; reserved-byte reject 440-441; WIRE-2 pre-scan 468).
- `src/net/messages.cpp:18-76` — `json_structural_precheck` (WIRE-2, survives D2 for the length-prefixed JSON payloads).
- `src/net/messages.cpp:82-132` — `Message::deserialize` (`dec`) + `Message::serialize_binary` (T-1 gate, WIRE-1 cap, T-4 totality; framing).
- `include/determ/net/messages.hpp:84-89` — `kWireVersionBinary` (the single shipped version; advertisement-only, §2.1).
- `include/determ/net/messages.hpp:91-170` — `kMaxFrameBytes` + `max_message_bytes` (the S-022 surfaces T-4 composes with).
- `include/determ/net/messages.hpp:271-300` — WIRE-2 ceilings, `Message` struct, codec declarations.
- `include/determ/net/messages.hpp:302-321` — `make_hello` (the five-field HELLO shape; π(HELLO) per §1).
- `src/net/peer.cpp:40-124` — `Peer::read_header` framing + `read_body` deserialize + cap + WIRE-3 `try`/`catch` (T-4 composition) + `Peer::send` (unconditional binary, §2.3).
- `src/net/gossip.cpp:177-189` — the HELLO receive case: identity tagging only; `wire_version` is read by nothing (advertisement, §2.1).

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
- nlohmann/json — `parse` throws `nlohmann::json::parse_error` (a `std::exception` subclass) on malformed input (T-4); `parse(dump(v)) == v` round-trip identity on the library's own output (L-5). *(Scoped to the length-prefixed JSON payloads still carried inside the binary envelope; retires with them at the D2 tail.)*
