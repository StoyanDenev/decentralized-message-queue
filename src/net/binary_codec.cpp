// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// ─── Binary wire codec — A3 / S8 ─────────────────────────────────────────────
//
// Plan reference: plan.md, "Active: Mode selectors + economic / UX primitives",
// section "A3 — Binary wire codec / S8".
//
// PURPOSE
//   The single, mandatory wire codec for inter-peer messages (D2,
//   DECISION-LOG 2026-07-28: the p2p envelope is binary-only). The legacy
//   JSON envelope (wire-version 0) and the per-pair HELLO version
//   negotiation were removed pre-genesis; every body on the wire is the
//   0xB1 binary envelope below. HELLO still CARRIES a `wire_version` u8
//   advertisement — with a single shipped version it decides nothing, but
//   it is the additive post-genesis upgrade escape hatch (no-migrations:
//   a future v2 peer advertises 2, keeps SENDING v1 frames, and upgrades
//   only after reading the peer's advertised max).
//
// FRAMING (compatible with the existing transport layer)
//   The transport layer in `Peer` already prepends a [u32 length, big-endian]
//   length header to every body it sends. We keep that wrapper unchanged.
//   Inside it, every body starts with the envelope magic 0xB1; anything
//   else is rejected fail-closed by Message::deserialize (WIRE-3 closes
//   the connection on the resulting parse error).
//
// BINARY ENVELOPE v1 LAYOUT
//   offset  size  field
//   0       1     magic    = 0xB1
//   1       1     version  = 0x01
//   2       1     msg_type = MsgType (uint8_t)
//   3       1     reserved = 0x00 (must be zero on encode AND decode —
//                 non-zero is rejected fail-closed, matching the light/wallet
//                 conformance decoders; see decode_binary)
//   4       N     payload (per msg_type)
//
// PAYLOAD: TRANSACTION (4×256-bit fixed frame, plan §A3 mechanism)
//   The TRANSACTION payload is the canonical fixed-layout 1024-bit frame
//   the plan describes. Total transaction frame size = 128 bytes (1024 bits).
//
//     offset  size  field            description
//     0       32    sender_pubkey    raw bytes of `from` (PubKey-derived,
//                                      decoded from address; if `from`
//                                      is shorter, right-padded with 0x00)
//     32      32    amount_block     [amount: u64 LE][fee: u64 LE]
//                                      [nonce: u64 LE][reserved: u64 LE]
//     64      32    recipient_pubkey raw bytes of `to` (same encoding rule
//                                      as sender_pubkey)
//     96      32    payload          tx.payload, right-padded with 0x00 if
//                                      shorter than 32 bytes (plan A4 caps
//                                      payload at 32 bytes for TRANSFER;
//                                      REGISTER uses up to 33 bytes via
//                                      length-prefixed extension).
//
//   Trailer (after the 128-byte frame, length-prefixed because they are
//   independent of the 1024-bit core frame):
//     128     1     type             tx.type (TxType: u8)
//     129     2     payload_len      u16 LE — actual payload byte length
//                                      (0..32 normally; up to 33 to support
//                                      REGISTER's [pubkey][region_len][region])
//     131     P     payload_overflow if payload_len > 32, the bytes above 32
//                                      live here (covers REGISTER's region
//                                      field of up to 256 bytes per the
//                                      single u8 length prefix). For
//                                      payload_len <= 32, P = 0.
//     ...     8     from_len + from  u8 len followed by `from` bytes (utf8)
//     ...     8     to_len + to      u8 len followed by `to` bytes (utf8)
//     ...     64    sig              Ed25519 signature
//     ...     32    hash             SHA-256
//     ...     4+Q   pq_auth          OPTIONAL §3.21 DPQ1 authenticator:
//                                      [u32 LE len][len bytes]. Emitted ONLY
//                                      when tx.pq_auth is non-empty (mirrors
//                                      the to_json convention), so every
//                                      non-PQ frame is byte-identical to the
//                                      pre-§3.21 layout. Decode is fail-closed:
//                                      the section must consume the frame
//                                      exactly, and a zero-length section is
//                                      rejected (canonical encoding is unique).
//
//   We encode the address strings (`from`, `to`) verbatim alongside the
//   pubkey bytes for now — current code uses domain strings (e.g. utf-8
//   names) as account identifiers, not raw pubkeys, so the 4×256-bit frame
//   alone is not yet sufficient to round-trip a real Transaction. Future
//   work: once R3+ migrates account identity to raw pubkeys, the trailer
//   can be eliminated.
//
// PAYLOAD: HELLO (fixed binary frame, D2)
//   HELLO is the first frame on every connection and travels binary like
//   everything else (the JSON pre-negotiation carve-out died with the JSON
//   envelope). Layout after the 4-byte envelope header — fail-closed, the
//   frame must be consumed EXACTLY (no trailing bytes):
//
//     offset  size  field
//     0       1     domain_len: u8
//     1       D     domain bytes (utf8, verbatim)
//     1+D     2     port: u16 LE
//     3+D     1     role: u8 (ChainRole)
//     4+D     4     shard_id: u32 LE
//     8+D     1     wire_version: u8 (advertised max — see module comment)
//
// PAYLOAD: ALL OTHER MSGTYPES
//   For BLOCK, CONTRIB, BLOCK_SIG, ABORT_CLAIM, ABORT_EVENT,
//   EQUIVOCATION_EVIDENCE, BEACON_HEADER, SHARD_TIP,
//   CROSS_SHARD_RECEIPT_BUNDLE, GET_CHAIN, CHAIN_RESPONSE,
//   STATUS_REQUEST, STATUS_RESPONSE, SNAPSHOT_REQUEST, SNAPSHOT_RESPONSE:
//
//   v1 falls back to a *length-prefixed JSON payload* inside the binary
//   envelope:
//
//     offset  size  field
//     4       4     json_len: u32 LE
//     8       N     json_bytes (the per-type JSON payload, no envelope)
//
//   This is a deliberate scope decision: the plan calls for fixed-layout
//   encodings of every type, but BLOCK alone has a dozen length-prefixed
//   nested arrays (creator_tx_lists, creator_ed_sigs, creator_dh_inputs,
//   creator_dh_secrets, equivocation_events, cross_shard_receipts, ...).
//   Implementing all of them in one pass is high-blast-radius and is
//   tracked as follow-up. The wrapper still buys us:
//     • Self-describing format byte for clean version detection.
//     • A stable extension point — future PRs can switch individual
//       msg_types from "JSON inside binary frame" to true binary
//       layouts without touching peers, gossip, or the dispatcher.
//
// ENDIANNESS
//   All multi-byte integers in the binary envelope and the transaction
//   frame are LITTLE-ENDIAN. Choice rationale: matches host endianness on
//   x86_64 and ARM64 (the deployment targets), avoids byte-swap on the
//   hot path. The transport-layer length prefix (managed by Peer) remains
//   big-endian — that's outside the scope of this codec and not changed.
//
// DETERMINISM
//   • All reserved bytes are explicitly zeroed on encode.
//   • String fields are encoded verbatim (no normalization), matching
//     what the JSON path round-trips.
//   • from/to/payload that fall short of their fixed slot are
//     right-padded with 0x00. Length info in the trailer disambiguates.
//
// ─────────────────────────────────────────────────────────────────────────────

#include <determ/net/messages.hpp>
#include <cstring>
#include <stdexcept>

namespace determ::net {

namespace {

// ─── byte-pack helpers (explicit little-endian) ──────────────────────────────

inline void le_put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

inline void le_put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

inline void le_put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

inline uint16_t le_get_u16(const uint8_t* p) {
    return  static_cast<uint16_t>(p[0])
         | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t le_get_u32(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) <<  8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t le_get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

// Append `n` bytes of `src` (right-padded with 0x00 if shorter than n).
inline void put_padded(std::vector<uint8_t>& out, const uint8_t* src, size_t src_len, size_t n) {
    size_t take = src_len < n ? src_len : n;
    out.insert(out.end(), src, src + take);
    out.insert(out.end(), n - take, 0x00);
}

// Append a u8-length-prefixed string (length capped at 255).
inline void put_lp_str(std::vector<uint8_t>& out, const std::string& s) {
    size_t n = s.size();
    if (n > 255) throw std::runtime_error("binary_codec: string > 255 bytes");
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), s.begin(), s.end());
}

inline std::string get_lp_str(const uint8_t* data, size_t len, size_t& off) {
    if (off + 1 > len) throw std::runtime_error("binary_codec: truncated lp_str header");
    uint8_t n = data[off++];
    if (off + n > len) throw std::runtime_error("binary_codec: truncated lp_str body");
    std::string s(reinterpret_cast<const char*>(data + off), n);
    off += n;
    return s;
}

// ─── transaction frame (4×256-bit + trailer) ─────────────────────────────────
//
// D2: the frame codec MOVED to the chain layer
// (chain::Transaction::encode_frame / decode_frame, src/chain/block.cpp) so
// the COMPOSABLE_BATCH validator accept rule and apply path share the ONE
// codec without a chain→net dependency. The byte layout documented above is
// unchanged; these wrappers keep the wire dispatch below readable.

inline void encode_tx_frame(std::vector<uint8_t>& out, const chain::Transaction& tx) {
    tx.encode_frame(out);
}

inline chain::Transaction decode_tx_frame(const uint8_t* data, size_t len) {
    return chain::Transaction::decode_frame(data, len);
}

// ─── HELLO frame (fixed layout, D2 binary-only wire) ─────────────────────────

void encode_hello_frame(std::vector<uint8_t>& out, const Message& m) {
    // Field set + defaults mirror make_hello (messages.hpp) and the tolerant
    // reads in GossipNet::handle_message's HELLO case.
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
    uint16_t port         = le_get_u16(data + off); off += 2;
    uint8_t  role         = data[off++];
    uint32_t shard_id     = le_get_u32(data + off); off += 4;
    uint8_t  wire_version = data[off++];
    // Fail-closed: the frame must be consumed exactly. Trailing bytes mean a
    // non-conforming encoder; a future ADDITIVE field arrives behind a bumped
    // wire_version advertisement, never as silent padding.
    if (off != len)
        throw std::runtime_error("binary_codec: HELLO frame trailing bytes");
    nlohmann::json j;
    j["domain"]       = domain;
    j["port"]         = port;
    j["role"]         = role;
    j["shard_id"]     = shard_id;
    j["wire_version"] = wire_version;
    return j;
}

// ─── envelope ────────────────────────────────────────────────────────────────

constexpr uint8_t kBinaryMagic   = 0xB1;
constexpr uint8_t kBinaryVersion = 0x01;

void put_envelope_header(std::vector<uint8_t>& out, MsgType t) {
    out.push_back(kBinaryMagic);
    out.push_back(kBinaryVersion);
    out.push_back(static_cast<uint8_t>(t));
    out.push_back(0x00);                       // reserved — must be zero
}

} // namespace

// Detect whether a body should be parsed as the binary envelope.
bool is_binary_envelope(const uint8_t* data, size_t len) {
    return len >= 4
        && data[0] == kBinaryMagic
        && data[1] == kBinaryVersion;
}

// Encode a Message in binary (v1) envelope form. Every MsgType encodes —
// the wire is binary-only (D2); HELLO uses its fixed frame.
std::vector<uint8_t> encode_binary(const Message& m) {
    std::vector<uint8_t> out;
    out.reserve(64);
    put_envelope_header(out, m.type);

    if (m.type == MsgType::HELLO) {
        encode_hello_frame(out, m);
        return out;
    }

    if (m.type == MsgType::TRANSACTION) {
        chain::Transaction tx = chain::Transaction::from_json(m.payload);
        encode_tx_frame(out, tx);
        return out;
    }

    // All other types: length-prefixed JSON inside the binary envelope.
    // Tracked as follow-up: replace per-type with true fixed-layout frames.
    std::string s = m.payload.dump();
    if (s.size() > 0xFFFFFFFFu)
        throw std::runtime_error("binary_codec: payload exceeds u32 length");
    le_put_u32(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

// Decode a Message from a binary (v1) envelope. Caller has already
// established (via is_binary_envelope) that the body is binary.
Message decode_binary(const uint8_t* data, size_t len) {
    if (len < 4 || data[0] != kBinaryMagic)
        throw std::runtime_error("binary_codec: not a binary envelope");
    if (data[1] != kBinaryVersion)
        throw std::runtime_error("binary_codec: unsupported binary version");
    Message m;
    m.type = static_cast<MsgType>(data[2]);
    // data[3] reserved — MUST be zero, fail-closed. A non-zero byte means the
    // frame was not produced by a conforming encoder (put_envelope_header
    // always writes 0x00). Rejecting matches the independent light/wallet
    // conformance decoders and closes the S-043-class validation asymmetry
    // ReservedDiscriminatorAudit.md §6 found (pre-2026-07-09 the daemon
    // silently ignored the byte while light/wallet rejected it, so a mixed
    // fleet disagreed on frame validity). Keeps the byte genuinely reserved:
    // a future use can only activate behind a version bump, never by a stray
    // writer that older daemons would have silently tolerated.
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
    // S-022 / WIRE-2: bound the DOM before parsing. The pre-decode per-type
    // cap in Message::deserialize (WIRE-1) reads the type from offset 2 —
    // which is ATTACKER-CHOSEN. A hostile frame claiming SNAPSHOT_RESPONSE
    // (16) or CHAIN_RESPONSE (6) buys the full 16 MB ceiling and lands here,
    // where an unbounded json::parse reproduces the exact amplification
    // WIRE-1 was meant to remove (measured ~52x heap on a 16 MB body of '[').
    // The structural ceiling is what actually closes it, on both wire formats.
    json_structural_precheck(body + 4, plen);
    m.payload = nlohmann::json::parse(body + 4, body + 4 + plen);
    return m;
}

} // namespace determ::net
