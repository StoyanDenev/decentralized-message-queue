// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/net/messages.hpp>
#include <determ/util/json_validate.hpp>
#include <stdexcept>
#include <utility>   // std::move — explicit, not via a transitive include
                     // (libstdc++ is stricter than MSVC's STL here, and the
                     //  WSL2/GCC arm is the project's cross-toolchain gate)

namespace determ::net {

using determ::util::json_require;

std::vector<uint8_t> Message::serialize() const {
    nlohmann::json envelope;
    envelope["type"]    = static_cast<uint8_t>(type);
    envelope["payload"] = payload;
    std::string s = envelope.dump();

    uint32_t len = static_cast<uint32_t>(s.size());
    std::vector<uint8_t> out(4 + s.size());
    out[0] = (len >> 24) & 0xFF;
    out[1] = (len >> 16) & 0xFF;
    out[2] = (len >> 8)  & 0xFF;
    out[3] =  len        & 0xFF;
    std::copy(s.begin(), s.end(), out.begin() + 4);
    return out;
}

// S-022 / WIRE-2: allocation-free structural pre-scan. See the ceiling
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

// Format-detecting deserializer (A3 / S8). Reads the body's first byte:
// the binary envelope is identified by its magic byte (0xB1) + version,
// while the legacy JSON envelope always starts with '{' (0x7B). This lets
// the receive path stay agnostic of the negotiated wire-version — a peer
// can mix-and-match in flight (e.g., HELLO arrives as JSON even when the
// connection is later upgraded to v1).
Message Message::deserialize(const uint8_t* data, size_t len) {
    if (is_binary_envelope(data, len)) {
        // S-022 PRE-DECODE cap. `Peer::read_body` applies max_message_bytes
        // only AFTER this function returns, so without this check a hostile
        // peer's 16 MB frame is fully DECODED (decode_binary reaches
        // nlohmann::json::parse over the whole length-prefixed payload,
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
    // S-022 / WIRE-2: the legacy JSON envelope cannot be byte-capped below
    // kMaxFrameBytes (16 MB) — its type is only readable AFTER the parse, and
    // SNAPSHOT_RESPONSE / CHAIN_RESPONSE legitimately arrive here at that size
    // whenever the peer's negotiated wire_version is 0 (the default until a
    // HELLO is processed; Peer::send). Bound the DOM instead, pre-parse.
    json_structural_precheck(data, len);
    nlohmann::json envelope = nlohmann::json::parse(data, data + len);
    // S-018: the gossip envelope is the outermost wire-format consumer
    // — every peer-supplied JSON message lands here. Field-name
    // diagnostics let the operator triage a malformed peer's traffic
    // without resorting to packet capture + nlohmann stack-trace
    // archaeology.
    Message m;
    m.type    = static_cast<MsgType>(json_require<uint8_t>(envelope, "type"));
    if (!envelope.contains("payload")) {
        throw std::runtime_error(
            "S-018: gossip envelope missing required 'payload' field "
            "(msg type "
            + std::to_string(static_cast<int>(m.type)) + ")");
    }
    // Resource: MOVE the payload subtree out of the envelope rather than
    // deep-copying it. `envelope` is a local that dies on the next line, so
    // the copy served no purpose — but it doubled peak heap at exactly the
    // worst moment, with BOTH the parsed envelope and its clone alive.
    //
    // This is the round-12 audit's measured "cheapest unrealised win": the
    // deep copy accounted for ~40% of peak on the hostile-input path (the
    // measured envelope case was 12.7 MB wire -> 525 MB DOM, 41.4x, versus
    // 482 MB / 25.5x for the same payload without the envelope copy). Since
    // this runs pre-authentication on peer-supplied bytes (Peer::read_body ->
    // Message::deserialize), halving the live set here directly shrinks what
    // an unauthenticated peer can pin per frame.
    //
    // SEMANTICS-PRESERVING by construction: `contains("payload")` was checked
    // above so `operator[]` cannot insert, and the moved-from subtree belongs
    // to a local about to be destroyed. `m.payload` is bit-identical to what
    // the copy produced — which is why the existing round-trip gates
    // (test-binary-codec / test-wire-types / test-consensus-msgs, all of
    // which assert payload equality after a serialize->deserialize cycle)
    // pin this change and there is no separate behaviour to falsify.
    m.payload = std::move(envelope["payload"]);
    return m;
}

// A3 / S8: binary envelope serializer. Wraps the binary body in the same
// [u32 length, big-endian] transport-layer framing that the JSON path uses
// (the framing wrapper itself is unchanged across wire-versions; only the
// body format differs). Defers to encode_binary in binary_codec.cpp for
// the body. HELLO is rejected there — HELLOs are always JSON because they
// happen pre-negotiation.
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
