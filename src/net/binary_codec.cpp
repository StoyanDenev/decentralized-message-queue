// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
// ─── Binary wire codec — A3 / S8 ─────────────────────────────────────────────
//
// Plan reference: plan.md, "Active: Mode selectors + economic / UX primitives",
// section "A3 — Binary wire codec / S8".
//
// PURPOSE
//   Provide a compact, deterministic binary alternative to the JSON-over-TCP
//   path used for inter-peer messages. JSON path is retained as default
//   (wire-version 0). Binary is opt-in (wire-version 1), negotiated per-pair
//   via the HELLO handshake.
//
// WIRE-FORMAT NEGOTIATION
//   1. Connection opens. Both sides immediately send a HELLO. HELLO is
//      ALWAYS encoded as JSON (so v0-only legacy peers can parse it).
//      HELLO carries a `wire_version: u8` field listing the highest
//      version the sender supports.
//   2. On HELLO receipt, each side records the peer's advertised version
//      and sets `peer.wire_version = min(our_max, their_max)`.
//      Pre-HELLO default is 0. A peer that omits the field is treated as
//      v0 (legacy JSON-only).
//   3. After HELLO has been received, every subsequent outbound message
//      is encoded according to peer.wire_version. The receive side is
//      version-agnostic: it dispatches on the first byte of the body
//      (see "FRAMING" below).
//
// FRAMING (compatible with the existing transport layer)
//   The transport layer in `Peer` already prepends a [u32 length, big-endian]
//   length header to every body it sends. We keep that wrapper unchanged
//   so the binary path is a drop-in body replacement.
//
//   The body itself is now self-describing by its first byte:
//
//     '{' (0x7B)  →  legacy JSON envelope (wire-version 0).
//     0xB1        →  binary envelope, version 1.
//
//   This makes the body format orthogonal to the negotiated version on
//   the read path — a v1-capable peer can still receive a JSON body
//   from a v0 peer without confusion. The negotiated version only
//   controls what we *send*.
//
// BINARY ENVELOPE v1 LAYOUT
//   offset  size  field
//   0       1     magic    = 0xB1
//   1       1     version  = 0x01
//   2       1     msg_type = MsgType (uint8_t)
//   3       1     reserved = 0x00 (must be zero on encode; ignored on decode)
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
//
//   We encode the address strings (`from`, `to`) verbatim alongside the
//   pubkey bytes for now — current code uses domain strings (e.g. utf-8
//   names) as account identifiers, not raw pubkeys, so the 4×256-bit frame
//   alone is not yet sufficient to round-trip a real Transaction. Future
//   work: once R3+ migrates account identity to raw pubkeys, the trailer
//   can be eliminated.
//
// PAYLOAD: HELLO
//   HELLO is NEVER encoded with this codec. Always JSON. See module-level
//   comment.
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

#include <unchained/net/messages.hpp>
#include <cstring>
#include <stdexcept>

namespace unchained::net {

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

void encode_tx_frame(std::vector<uint8_t>& out, const chain::Transaction& tx) {
    // sender_pubkey slot — 32 bytes, derived from tx.from. tx.from is the
    // string-form account identifier (typically a domain string, e.g.
    // "alice.det"); we stuff its bytes into the slot for now and rely on
    // the trailer's `from_len + from` to reconstruct it. Plan note: when
    // identity becomes raw-pubkey first-class, this slot becomes the
    // canonical address.
    put_padded(out,
        reinterpret_cast<const uint8_t*>(tx.from.data()),
        tx.from.size(),
        32);

    // amount block: 32 bytes total — [amount LE][fee LE][nonce LE][reserved LE]
    le_put_u64(out, tx.amount);
    le_put_u64(out, tx.fee);
    le_put_u64(out, tx.nonce);
    le_put_u64(out, 0);             // reserved — must be zero (deterministic)

    // recipient_pubkey slot
    put_padded(out,
        reinterpret_cast<const uint8_t*>(tx.to.data()),
        tx.to.size(),
        32);

    // payload slot — first 32 bytes of tx.payload (right-padded if shorter)
    put_padded(out,
        tx.payload.data(),
        tx.payload.size(),
        32);

    // trailer
    out.push_back(static_cast<uint8_t>(tx.type));
    uint16_t payload_len = static_cast<uint16_t>(
        tx.payload.size() > 0xFFFF ? 0xFFFF : tx.payload.size());
    le_put_u16(out, payload_len);
    if (tx.payload.size() > 32) {
        size_t overflow = tx.payload.size() - 32;
        out.insert(out.end(),
            tx.payload.begin() + 32, tx.payload.begin() + 32 + overflow);
    }
    put_lp_str(out, tx.from);
    put_lp_str(out, tx.to);
    out.insert(out.end(), tx.sig.begin(),  tx.sig.end());
    out.insert(out.end(), tx.hash.begin(), tx.hash.end());
}

chain::Transaction decode_tx_frame(const uint8_t* data, size_t len) {
    chain::Transaction tx;
    if (len < 128 + 1 + 2)
        throw std::runtime_error("binary_codec: tx frame too short");

    // Read the canonical numeric fields from the fixed-slot area (where
    // encode_tx_frame writes them). Prior to this read, the decoder was
    // dropping amount/fee/nonce on the binary-wire path — the trailer
    // doesn't carry them, so a binary round-trip produced a tx with
    // zero values for these fields. That bug stayed latent because
    // (a) the JSON wire path was often negotiated in practice, and
    // (b) admission-side sig verification (S-002) wasn't wired, so the
    // corrupted txs entered mempool and were filtered later. Closing
    // S-002 forced this fix. See docs/proofs/S002-Mempool-Sig-Verify.md.
    tx.amount = le_get_u64(data + 32);
    tx.fee    = le_get_u64(data + 40);
    tx.nonce  = le_get_u64(data + 48);
    uint64_t reserved = le_get_u64(data + 56);
    if (reserved != 0)
        throw std::runtime_error("binary_codec: reserved field non-zero");

    // Trailer starts at offset 128 — type, payload_len, overflow, etc.
    // The 4×32-byte fixed-slot area (offsets 0..127) carries the numeric
    // fields above plus pubkey + recipient slots whose authoritative
    // values still come from the trailer's length-prefixed strings.
    size_t off = 128;

    tx.type = static_cast<chain::TxType>(data[off++]);
    uint16_t payload_len = le_get_u16(data + off); off += 2;

    if (payload_len <= 32) {
        // payload lives entirely in the fixed slot at offset 96..96+payload_len
        tx.payload.assign(data + 96, data + 96 + payload_len);
    } else {
        size_t overflow = payload_len - 32;
        if (off + overflow > len)
            throw std::runtime_error("binary_codec: truncated payload overflow");
        tx.payload.reserve(payload_len);
        tx.payload.insert(tx.payload.end(), data + 96, data + 128);
        tx.payload.insert(tx.payload.end(), data + off, data + off + overflow);
        off += overflow;
    }

    tx.from = get_lp_str(data, len, off);
    tx.to   = get_lp_str(data, len, off);
    if (off + 64 + 32 > len)
        throw std::runtime_error("binary_codec: truncated sig/hash");
    std::memcpy(tx.sig.data(),  data + off, 64); off += 64;
    std::memcpy(tx.hash.data(), data + off, 32); off += 32;
    return tx;
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

// Encode a Message in binary (v1) envelope form.
//
// HELLO is rejected here — callers must serialize HELLO via JSON regardless
// of negotiated wire-version (see module-level comment).
std::vector<uint8_t> encode_binary(const Message& m) {
    if (m.type == MsgType::HELLO)
        throw std::runtime_error("binary_codec: HELLO must be sent as JSON");

    std::vector<uint8_t> out;
    out.reserve(64);
    put_envelope_header(out, m.type);

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
    // data[3] reserved — ignored.
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

} // namespace unchained::net
