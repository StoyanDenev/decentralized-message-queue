// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/net/messages.hpp>
#include <stdexcept>
#include <utility>   // std::move — explicit, not via a transitive include
                     // (libstdc++ is stricter than MSVC's STL here, and the
                     //  WSL2/GCC arm is the project's cross-toolchain gate)

namespace determ::net {

// S-022 / WIRE-2: allocation-free structural pre-scan. Survives the D2
// envelope strip because decode_binary still carries length-prefixed JSON
// payloads for the non-HELLO/non-TRANSACTION types; it retires only when
// every payload is a true binary frame. See the ceiling
// commentary in messages.hpp for the threat model, the sizing rationale and
// the soundness argument. Aborts at the offending byte so a hostile body
// costs only the bytes scanned before the ceiling trips.
void json_structural_precheck(const uint8_t* data, size_t len) {
    size_t depth = 0;
    size_t nodes = 0;
    bool   in_string = false;
    bool   escaped   = false;

    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = data[i];
        if (in_string) {
            // Structural bytes inside a string literal are DATA, not
            // structure. Track the escape state so a trailing backslash
            // cannot smuggle the closing quote past us.
            if (escaped)        escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"')  in_string = false;
            continue;
        }
        switch (c) {
        case '"':
            in_string = true;
            break;
        case '[':
        case '{':
            if (++depth > kMaxJsonDepth) {
                throw std::runtime_error(
                    "S-022/WIRE-2: JSON nesting depth exceeds "
                    + std::to_string(kMaxJsonDepth)
                    + " at byte offset " + std::to_string(i)
                    + " — rejected before parse");
            }
            if (++nodes > kMaxJsonNodes) {
                throw std::runtime_error(
                    "S-022/WIRE-2: JSON node count exceeds "
                    + std::to_string(kMaxJsonNodes)
                    + " at byte offset " + std::to_string(i)
                    + " — rejected before parse");
            }
            break;
        case ']':
        case '}':
            // Underflow (a close with no matching open) is left to the
            // parser: this scan is a ceiling, not a validator, and must
            // never be the thing that decides well-formedness.
            if (depth > 0) --depth;
            break;
        case ',':
            if (++nodes > kMaxJsonNodes) {
                throw std::runtime_error(
                    "S-022/WIRE-2: JSON node count exceeds "
                    + std::to_string(kMaxJsonNodes)
                    + " at byte offset " + std::to_string(i)
                    + " — rejected before parse");
            }
            break;
        default:
            break;
        }
    }
}

// Binary-only deserializer (D2). Every body on the wire is the 0xB1 binary
// envelope; anything else — including the deleted legacy JSON envelope
// ('{' 0x7B, wire-version 0) — is rejected fail-closed, and WIRE-3 in
// Peer::read_body converts the throw into a connection close.
Message Message::deserialize(const uint8_t* data, size_t len) {
    if (!is_binary_envelope(data, len)) {
        throw std::runtime_error(
            "wire: body is not a binary envelope (magic 0xB1) — the legacy "
            "JSON envelope was removed pre-genesis (D2 binary-only wire)");
    }
    // S-022 PRE-DECODE cap (WIRE-1). `Peer::read_body` applies
    // max_message_bytes only AFTER this function returns, so without this
    // check a hostile peer's 16 MB frame is fully DECODED (decode_binary
    // reaches nlohmann::json::parse over the whole length-prefixed payload,
    // binary_codec.cpp) before the type-aware ceiling is ever consulted —
    // i.e. the framing ceiling IS usable as an amplification vector, which
    // the messages.hpp cap commentary asserts it is not.
    //
    // The binary envelope carries its type in the clear at offset 2
    // (magic, version, TYPE, reserved), so the cap is knowable before any
    // payload work. This mirrors the rule the light client already ships
    // on the same wire format (light/main.cpp: read buf[2], look up the
    // S-022 cap, reject before decoding) — same rule, two binaries.
    //
    // Strictly ACCEPT-NARROWING: any frame rejected here would have been
    // rejected by Peer::read_body's identical cap moments later, so no
    // legitimate message is affected — only the work done before the
    // rejection changes.
    const MsgType btype = static_cast<MsgType>(data[2]);
    if (len > max_message_bytes(btype)) {
        throw std::runtime_error(
            "S-022: binary envelope (" + std::to_string(len)
            + " bytes) exceeds its per-type cap ("
            + std::to_string(max_message_bytes(btype)) + ") for msg type "
            + std::to_string(static_cast<int>(btype))
            + " — rejected before payload decode");
    }
    return decode_binary(data, len);
}

// Binary envelope serializer — the only wire encoder (D2). Wraps the binary
// body in the [u32 length, big-endian] transport-layer framing (unchanged by
// the format migration). Defers to encode_binary in binary_codec.cpp for the
// body; every MsgType including HELLO encodes.
std::vector<uint8_t> Message::serialize_binary() const {
    std::vector<uint8_t> body = encode_binary(*this);
    uint32_t len = static_cast<uint32_t>(body.size());
    std::vector<uint8_t> out(4 + body.size());
    out[0] = (len >> 24) & 0xFF;
    out[1] = (len >> 16) & 0xFF;
    out[2] = (len >>  8) & 0xFF;
    out[3] =  len        & 0xFF;
    std::copy(body.begin(), body.end(), out.begin() + 4);
    return out;
}

} // namespace determ::net
