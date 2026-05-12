// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/net/messages.hpp>
#include <stdexcept>

namespace determ::net {

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

// Format-detecting deserializer (A3 / S8). Reads the body's first byte:
// the binary envelope is identified by its magic byte (0xB1) + version,
// while the legacy JSON envelope always starts with '{' (0x7B). This lets
// the receive path stay agnostic of the negotiated wire-version — a peer
// can mix-and-match in flight (e.g., HELLO arrives as JSON even when the
// connection is later upgraded to v1).
Message Message::deserialize(const uint8_t* data, size_t len) {
    if (is_binary_envelope(data, len)) {
        return decode_binary(data, len);
    }
    nlohmann::json envelope = nlohmann::json::parse(data, data + len);
    Message m;
    m.type    = static_cast<MsgType>(envelope["type"].get<uint8_t>());
    m.payload = envelope["payload"];
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
