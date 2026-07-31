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
// PAYLOAD: REQUEST / STATUS FRAMES (fixed layout, D2-inc6a)
//   The five small control messages that carry no signature and no consensus
//   commitment. Each is fail-closed with EXACT consumption:
//
//     GET_CHAIN        [from: u64 LE][count: u16 LE]                  10 B
//     STATUS_REQUEST   (no fields)                                     0 B
//     STATUS_RESPONSE  [height: u64 LE][genesis_len: u8][genesis]     9..73 B
//                        genesis_len is 0 (empty chain) or 64 (hex of the
//                        genesis block hash) — nothing else is accepted.
//     SNAPSHOT_REQUEST [headers: u32 LE]                                4 B
//     HEADERS_REQUEST  [from: u64 LE][count: u32 LE]                   12 B
//
//   GET_CHAIN's count is u16 and HEADERS_REQUEST's is u32 — deliberately not
//   unified; the two handler signatures differ.
//
// PAYLOAD: CONSENSUS-CHATTER FRAMES (fixed layout, D2-inc6b)
//   The four control messages with UNCONDITIONAL field sets. All are
//   signature-transparent: the sigs bind binary field hashes
//   (make_abort_claim_message / compute_block_digest / the inline digests),
//   never a serialization. Fail-closed, consumed exactly:
//
//     ABORT_CLAIM      the shared chain::encode_abort_claims blob carrying
//                      EXACTLY one claim — the same six-field layout the
//                      in-block claim list uses, so the gossiped claim and
//                      the stored claim cannot drift.
//     BLOCK_SIG        [block_index: u64 LE][signer: u8 len + utf8]
//                      [delay_output: 32 B][dh_secret: 32 B][ed_sig: 64 B]
//                        dh_secret's all-zero value is the S-009
//                        legacy/absent reveal — a fixed slot is exactly the
//                        JSON path's absent-means-zero rule.
//     EQUIVOCATION_EVIDENCE
//                      [equivocator: u8 len + utf8][block_index: u64 LE]
//                      [digest_a: 32][sig_a: 64][digest_b: 32][sig_b: 64]
//                      [shard_id: u32 LE][beacon_anchor_height: u64 LE]
//     ABORT_EVENT      [block_index: u64 LE][prev_hash: 32 B]   (envelope)
//                      [round: u8][aborting_node: u8 len + utf8]
//                      [timestamp: i64 as u64 LE][event_hash: 32 B]
//                      [claims: chain::encode_abort_claims blob]  (LAST —
//                        the blob is count-prefixed and self-delimiting, and
//                        being last is what makes exact consumption
//                        decidable)
//
// PAYLOAD: ALL OTHER MSGTYPES
//   For BLOCK, CONTRIB, BEACON_HEADER, SHARD_TIP,
//   CROSS_SHARD_RECEIPT_BUNDLE, CHAIN_RESPONSE, SNAPSHOT_RESPONSE,
//   HEADERS_RESPONSE:
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

// ─── request / status frames (fixed layout, D2-inc6a) ────────────────────────
//
// The five small fixed-shape control messages that carry NO signature and NO
// consensus commitment: GET_CHAIN, STATUS_REQUEST, STATUS_RESPONSE,
// SNAPSHOT_REQUEST, HEADERS_REQUEST. Each frame is fail-closed with
// EXACT-consumption semantics (the HELLO discipline): a conforming encoder
// produces exactly these bytes, so trailing or missing bytes are a
// non-conforming peer and WIRE-3 closes the connection.
//
// Field widths mirror the builders in messages.hpp and the reads in
// GossipNet::handle_message. Note GET_CHAIN's count is u16 while
// HEADERS_REQUEST's is u32 — deliberately NOT unified, because the two
// handler signatures differ (on_get_chain takes uint16_t).

void encode_get_chain_frame(std::vector<uint8_t>& out, const Message& m) {
    le_put_u64(out, m.payload.value("from",  uint64_t{0}));
    le_put_u16(out, m.payload.value("count", uint16_t{64}));
}

nlohmann::json decode_get_chain_frame(const uint8_t* data, size_t len) {
    if (len != 8 + 2)
        throw std::runtime_error("binary_codec: bad GET_CHAIN frame length");
    nlohmann::json j;
    j["from"]  = le_get_u64(data);
    j["count"] = le_get_u16(data + 8);
    return j;
}

void encode_status_request_frame(std::vector<uint8_t>&, const Message&) {
    // No fields — the request is the message. Zero-length payload.
}

nlohmann::json decode_status_request_frame(const uint8_t*, size_t len) {
    if (len != 0)
        throw std::runtime_error("binary_codec: STATUS_REQUEST frame not empty");
    return nlohmann::json::object();
}

void encode_status_response_frame(std::vector<uint8_t>& out, const Message& m) {
    le_put_u64(out, m.payload.value("height", uint64_t{0}));
    // `genesis` is the hex of the genesis block hash — 64 chars — or EMPTY
    // when the responder's chain is empty, and the consumer branches on that
    // emptiness (`!genesis.empty() && genesis != ours`). A fixed 32-byte slot
    // would encode "unknown" as 64 zeros and silently turn it into "wrong
    // genesis", excluding an honest bootstrapping peer from sync — so the
    // field is length-prefixed and the empty case is preserved exactly.
    put_lp_str(out, m.payload.value("genesis", std::string{}));
}

nlohmann::json decode_status_response_frame(const uint8_t* data, size_t len) {
    if (len < 8 + 1)
        throw std::runtime_error("binary_codec: truncated STATUS_RESPONSE frame");
    size_t off = 0;
    uint64_t height = le_get_u64(data); off += 8;
    std::string genesis = get_lp_str(data, len, off);
    if (off != len)
        throw std::runtime_error("binary_codec: STATUS_RESPONSE frame trailing bytes");
    // A conforming responder emits exactly 0 (empty chain) or 64 (hex of a
    // 32-byte hash) characters. Narrowing to those bounds the string a peer
    // can pin and costs no legitimate message.
    if (!genesis.empty() && genesis.size() != 64)
        throw std::runtime_error("binary_codec: STATUS_RESPONSE genesis length "
                                 "must be 0 or 64");
    nlohmann::json j;
    j["height"]  = height;
    j["genesis"] = genesis;
    return j;
}

void encode_snapshot_request_frame(std::vector<uint8_t>& out, const Message& m) {
    le_put_u32(out, m.payload.value("headers", uint32_t{16}));
}

nlohmann::json decode_snapshot_request_frame(const uint8_t* data, size_t len) {
    if (len != 4)
        throw std::runtime_error("binary_codec: bad SNAPSHOT_REQUEST frame length");
    nlohmann::json j;
    j["headers"] = le_get_u32(data);
    return j;
}

void encode_headers_request_frame(std::vector<uint8_t>& out, const Message& m) {
    le_put_u64(out, m.payload.value("from",  uint64_t{0}));
    le_put_u32(out, m.payload.value("count", uint32_t{16}));
}

nlohmann::json decode_headers_request_frame(const uint8_t* data, size_t len) {
    if (len != 8 + 4)
        throw std::runtime_error("binary_codec: bad HEADERS_REQUEST frame length");
    nlohmann::json j;
    j["from"]  = le_get_u64(data);
    j["count"] = le_get_u32(data + 8);
    return j;
}

// ─── consensus-chatter frames (fixed layout, D2-inc6b) ───────────────────────
//
// The four control messages whose field sets are UNCONDITIONAL — no emit
// gates, no unbounded collections. (CONTRIB is deliberately excluded: it has
// two conditional field blocks and four unbounded hash lists that need
// explicit caps, so it gets its own increment.)
//
// SIGNATURE-TRANSPARENT by construction: every signature these carry binds a
// binary field hash that never touched the JSON container —
// make_abort_claim_message (ABORT_CLAIM, and the claims inside ABORT_EVENT),
// compute_block_digest (BLOCK_SIG), and for EQUIVOCATION_EVIDENCE the two
// inline sigs verify against digests carried in the message itself. So no
// signature verification outcome can change; only the container does.
//
// Each frame is fail-closed with EXACT consumption. The decoders rebuild the
// same payload DOM the builders produce, so every gossip handler and every
// downstream consumer is untouched by the swap.

// Convert between the gossip claim (node::AbortClaimMsg) and the chain-layer
// claim (chain::AbortClaim). The two carry the SAME six consensus-bound
// fields; sharing chain::encode_abort_claims for both the in-block list and
// the gossiped single claim is what keeps their byte layouts from drifting
// (the S-044 one-shared-helper discipline).
chain::AbortClaim to_chain_claim(const node::AbortClaimMsg& m) {
    chain::AbortClaim c;
    c.block_index     = m.block_index;
    c.round           = m.round;
    c.prev_hash       = m.prev_hash;
    c.missing_creator = m.missing_creator;
    c.claimer         = m.claimer;
    c.ed_sig          = m.ed_sig;
    return c;
}

nlohmann::json from_chain_claim(const chain::AbortClaim& c) {
    node::AbortClaimMsg m;
    m.block_index     = c.block_index;
    m.round           = c.round;
    m.prev_hash       = c.prev_hash;
    m.missing_creator = c.missing_creator;
    m.claimer         = c.claimer;
    m.ed_sig          = c.ed_sig;
    return m.to_json();
}

void encode_abort_claim_frame(std::vector<uint8_t>& out, const Message& m) {
    auto claim = to_chain_claim(node::AbortClaimMsg::from_json(m.payload));
    auto enc = chain::encode_abort_claims({claim});
    out.insert(out.end(), enc.begin(), enc.end());
}

nlohmann::json decode_abort_claim_frame(const uint8_t* data, size_t len) {
    auto claims = chain::decode_abort_claims(std::vector<uint8_t>(data, data + len));
    // The shared codec is count-prefixed; a gossiped ABORT_CLAIM carries
    // exactly one. Rejecting any other count keeps the encoding canonical.
    if (claims.size() != 1)
        throw std::runtime_error("binary_codec: ABORT_CLAIM must carry exactly one claim");
    return from_chain_claim(claims[0]);
}

void encode_block_sig_frame(std::vector<uint8_t>& out, const Message& m) {
    node::BlockSigMsg s = node::BlockSigMsg::from_json(m.payload);
    le_put_u64(out, s.block_index);
    put_lp_str(out, s.signer);
    out.insert(out.end(), s.delay_output.begin(), s.delay_output.end());
    // S-009: dh_secret is all-zero on a legacy/absent reveal. A fixed 32-byte
    // slot is exactly equivalent to the JSON path's absent-means-zero rule,
    // and it removes that path's S-018 asymmetry (dh_secret was the one hex
    // field read WITHOUT json_require_hex, so a wrong-length value threw an
    // anonymous "hex length mismatch" instead of a field-named diagnostic).
    out.insert(out.end(), s.dh_secret.begin(), s.dh_secret.end());
    out.insert(out.end(), s.ed_sig.begin(), s.ed_sig.end());
}

nlohmann::json decode_block_sig_frame(const uint8_t* data, size_t len) {
    node::BlockSigMsg s;
    size_t off = 0;
    if (len < 8) throw std::runtime_error("binary_codec: truncated BLOCK_SIG frame");
    s.block_index = le_get_u64(data); off += 8;
    s.signer = get_lp_str(data, len, off);
    if (off + 32 + 32 + 64 != len)
        throw std::runtime_error("binary_codec: bad BLOCK_SIG frame length");
    std::copy(data + off, data + off + 32, s.delay_output.begin()); off += 32;
    std::copy(data + off, data + off + 32, s.dh_secret.begin());    off += 32;
    std::copy(data + off, data + off + 64, s.ed_sig.begin());
    return s.to_json();
}

void encode_equivocation_frame(std::vector<uint8_t>& out, const Message& m) {
    chain::EquivocationEvent e = chain::EquivocationEvent::from_json(m.payload);
    put_lp_str(out, e.equivocator);
    le_put_u64(out, e.block_index);
    out.insert(out.end(), e.digest_a.begin(), e.digest_a.end());
    out.insert(out.end(), e.sig_a.begin(),    e.sig_a.end());
    out.insert(out.end(), e.digest_b.begin(), e.digest_b.end());
    out.insert(out.end(), e.sig_b.begin(),    e.sig_b.end());
    le_put_u32(out, e.shard_id);
    le_put_u64(out, e.beacon_anchor_height);
}

nlohmann::json decode_equivocation_frame(const uint8_t* data, size_t len) {
    chain::EquivocationEvent e;
    size_t off = 0;
    e.equivocator = get_lp_str(data, len, off);
    if (off + 8 + 32 + 64 + 32 + 64 + 4 + 8 != len)
        throw std::runtime_error("binary_codec: bad EQUIVOCATION_EVIDENCE frame length");
    e.block_index = le_get_u64(data + off); off += 8;
    std::copy(data + off, data + off + 32, e.digest_a.begin()); off += 32;
    std::copy(data + off, data + off + 64, e.sig_a.begin());    off += 64;
    std::copy(data + off, data + off + 32, e.digest_b.begin()); off += 32;
    std::copy(data + off, data + off + 64, e.sig_b.begin());    off += 64;
    e.shard_id             = le_get_u32(data + off); off += 4;
    e.beacon_anchor_height = le_get_u64(data + off);
    return e.to_json();
}

void encode_abort_event_frame(std::vector<uint8_t>& out, const Message& m) {
    // Envelope (block_index + prev_hash) then the event. Neither is covered
    // by any signature — the claims inside carry their own.
    le_put_u64(out, m.payload.value("block_index", uint64_t{0}));
    Hash prev = from_hex_arr<32>(
        m.payload.value("prev_hash", std::string(64, '0')));
    out.insert(out.end(), prev.begin(), prev.end());

    chain::AbortEvent e = chain::AbortEvent::from_json(m.payload.at("event"));
    out.push_back(e.round);
    put_lp_str(out, e.aborting_node);
    // int64 timestamp round-trips bit-exactly through the u64 slot.
    le_put_u64(out, static_cast<uint64_t>(e.timestamp));
    out.insert(out.end(), e.event_hash.begin(), e.event_hash.end());
    // Claims LAST: the shared codec is self-delimiting via its own count
    // prefix, and being last is what makes exact consumption decidable.
    auto enc = chain::encode_abort_claims(e.claims);
    out.insert(out.end(), enc.begin(), enc.end());
}

nlohmann::json decode_abort_event_frame(const uint8_t* data, size_t len) {
    size_t off = 0;
    if (len < 8 + 32) throw std::runtime_error("binary_codec: truncated ABORT_EVENT frame");
    uint64_t block_index = le_get_u64(data); off += 8;
    Hash prev{};
    std::copy(data + off, data + off + 32, prev.begin()); off += 32;

    chain::AbortEvent e;
    if (off + 1 > len) throw std::runtime_error("binary_codec: truncated ABORT_EVENT event");
    e.round = data[off++];
    e.aborting_node = get_lp_str(data, len, off);
    if (off + 8 + 32 > len)
        throw std::runtime_error("binary_codec: truncated ABORT_EVENT event fields");
    e.timestamp = static_cast<int64_t>(le_get_u64(data + off)); off += 8;
    std::copy(data + off, data + off + 32, e.event_hash.begin()); off += 32;
    // decode_abort_claims is itself exact-consuming over the tail, so a
    // trailing byte after the claim list is rejected there.
    e.claims = chain::decode_abort_claims(
        std::vector<uint8_t>(data + off, data + len));

    nlohmann::json j;
    j["block_index"] = block_index;
    j["prev_hash"]   = to_hex(prev);
    j["event"]       = e.to_json();
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

    // D2-inc6a: true fixed-layout frames for the request/status types.
    switch (m.type) {
    case MsgType::GET_CHAIN:        encode_get_chain_frame(out, m);        return out;
    case MsgType::STATUS_REQUEST:   encode_status_request_frame(out, m);   return out;
    case MsgType::STATUS_RESPONSE:  encode_status_response_frame(out, m);  return out;
    case MsgType::SNAPSHOT_REQUEST: encode_snapshot_request_frame(out, m); return out;
    case MsgType::HEADERS_REQUEST:  encode_headers_request_frame(out, m);  return out;
    // D2-inc6b: unconditional consensus-chatter frames.
    case MsgType::ABORT_CLAIM:      encode_abort_claim_frame(out, m);      return out;
    case MsgType::BLOCK_SIG:        encode_block_sig_frame(out, m);        return out;
    case MsgType::EQUIVOCATION_EVIDENCE:
                                    encode_equivocation_frame(out, m);     return out;
    case MsgType::ABORT_EVENT:      encode_abort_event_frame(out, m);      return out;
    default: break;
    }

    // Remaining types: length-prefixed JSON inside the binary envelope.
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
    // D2-inc6b: unconditional consensus-chatter frames.
    case MsgType::ABORT_CLAIM:
        m.payload = decode_abort_claim_frame(body, body_len);      return m;
    case MsgType::BLOCK_SIG:
        m.payload = decode_block_sig_frame(body, body_len);        return m;
    case MsgType::EQUIVOCATION_EVIDENCE:
        m.payload = decode_equivocation_frame(body, body_len);     return m;
    case MsgType::ABORT_EVENT:
        m.payload = decode_abort_event_frame(body, body_len);      return m;
    default: break;
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
