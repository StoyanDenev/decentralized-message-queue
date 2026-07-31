// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <determ/node/producer.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <stdexcept>

namespace determ::net {

enum class MsgType : uint8_t {
    HELLO            = 0,
    BLOCK            = 1,
    TRANSACTION      = 2,
    BLOCK_SIG        = 3,    // Phase 2: signed block digest + VDF output
    CONTRIB          = 4,    // Phase 1: TxCommit + DhInput + Ed25519 sig
    GET_CHAIN        = 5,
    CHAIN_RESPONSE   = 6,
    STATUS_REQUEST   = 7,
    STATUS_RESPONSE  = 8,
    ABORT_CLAIM      = 9,
    // rev.8 follow-on: a node that forms a K-1 abort-claim quorum locally
    // broadcasts the assembled AbortEvent (which carries the signed claims
    // inline) so peers that missed individual claims can adopt it and
    // advance their abort generation in lock-step. Without this, peers
    // that see only their own claim stay stuck waiting for a second claim
    // that never re-broadcasts.
    ABORT_EVENT      = 10,
    // rev.8 follow-on: a node that detects equivocation (a BFT proposer
    // signed two different block_digests at the same height) gossips the
    // assembled EquivocationEvent so peers can slash the equivocator on
    // the next finalized block. Evidence is verifiable independently:
    // both Ed25519 sigs over distinct digests by the same registered key.
    EQUIVOCATION_EVIDENCE = 11,
    // rev.9 B2c.1: beacon nodes broadcast their newly-applied blocks to
    // shard nodes so each shard can independently maintain a verified
    // light header chain of the beacon. From this header chain shards
    // derive their own validator pool + committee under zero-trust
    // (no claim from the beacon is implicitly trusted; each shard
    // verifies the beacon block's K-of-K signatures against the pool
    // it derives from prior verified blocks). Bootstrapping starts
    // from the pinned beacon genesis hash in shard config.
    BEACON_HEADER         = 12,
    // rev.9 B2c.3: shard nodes broadcast their newly-applied blocks to
    // beacon nodes so the beacon can independently verify the shard's
    // committee K-of-K (or BFT) signatures and track the shard's tip.
    // The block travels with its shard_id context (the block itself
    // doesn't carry shard_id; the message envelope does).
    SHARD_TIP             = 13,
    // rev.9 B3.3: a shard node that produced a block carrying outbound
    // cross_shard_receipts gossips a bundle so destination shards can
    // pick up receipts addressed to them. Beacon nodes act as relays —
    // they don't apply receipts, just re-broadcast bundles to their
    // shard peers (the natural shard-A → beacon → shard-B path). The
    // bundle carries the full source block so destination shards can
    // independently verify the source's K-of-K signatures (Stage B3.4)
    // before crediting any receipt.
    CROSS_SHARD_RECEIPT_BUNDLE = 14,
    // rev.9 B6.basic: snapshot fetch over the network. A peer (typically
    // a fresh node bootstrapping) sends SNAPSHOT_REQUEST; any peer
    // willing to serve responds with SNAPSHOT_RESPONSE carrying the
    // serialized state (Chain::serialize_state). The receiver then
    // calls Chain::restore_from_snapshot to install state directly,
    // skipping per-block replay. Allowed across roles — any node with
    // chain state can serve.
    SNAPSHOT_REQUEST  = 15,
    SNAPSHOT_RESPONSE = 16,
    // v2.2 light-client header-sync. A light client peers with full
    // nodes via the gossip layer (no RPC binding) and requests a
    // slice of recent headers. The full node replies with a
    // HEADERS_RESPONSE carrying the same {headers, from, count,
    // height} shape that Node::rpc_headers returns — each header is
    // the Block JSON minus the heavy collections (transactions /
    // cross_shard_receipts / inbound_receipts / initial_state) plus
    // an explicit `block_hash` field for prev_hash chain
    // verification. Allowed across roles — any node with chain
    // state can serve.
    HEADERS_REQUEST   = 17,
    HEADERS_RESPONSE  = 18,
};

// A3 / S8: per-pair wire-version negotiation.
//   v0 = JSON-over-TCP (legacy, default).
//   v1 = binary envelope (see src/net/binary_codec.cpp for layout).
// Highest version this build understands. HELLO advertises this; both sides
// negotiate down to min(ours, theirs). Default per-peer until HELLO arrives
// is kWireVersionLegacy (0) so we stay compatible with pre-A3 peers.
inline constexpr uint8_t kWireVersionLegacy  = 0;
inline constexpr uint8_t kWireVersionBinary  = 1;
inline constexpr uint8_t kWireVersionMax     = kWireVersionBinary;

// S-022: wire-level framing ceiling. The peer layer reads this many bytes
// max before deserialization (drops the connection otherwise). After
// deserialize, the per-message-type cap (max_message_bytes) is applied —
// only SNAPSHOT_RESPONSE and CHAIN_RESPONSE actually need the 16 MB
// ceiling; everything else is bounded much tighter at the type-aware
// layer.
//
// ⚠ ORDERING CAVEAT (round-12 hostile-wire audit, wf_c277c6d1). This
// commentary previously concluded "so a flooder cannot use the framing
// ceiling as an attack vector" — that did NOT hold, because Peer::read_body
// applies max_message_bytes only AFTER Message::deserialize has already
// decoded the body. A hostile peer's 16 MB frame was therefore fully parsed
// before the type-aware ceiling was consulted (measured: ~52x heap
// amplification and multi-second CPU on the JSON path).
//   * BINARY envelopes carry a PRE-DECODE cap in Message::deserialize — the
//     type is readable in the clear at offset 2, so the ceiling is applied
//     before any payload work (the rule the light client already shipped on
//     this wire format). Gated by WIRE-1 in test-binary-codec.
//   * That cap alone did NOT close the binary path: the type at offset 2 is
//     ATTACKER-CHOSEN, so a hostile frame claiming SNAPSHOT_RESPONSE (16) or
//     CHAIN_RESPONSE (6) buys the full 16 MB ceiling and reaches the same
//     unbounded DOM expansion in decode_binary's payload parse. The
//     per-type cap narrows the vector to the two 16 MB types; it does not
//     remove it.
//   * The legacy JSON-envelope path parses before the type is known (the
//     type lives inside the document), so its byte ceiling is necessarily
//     kMaxFrameBytes — and it cannot be tightened, because those same two
//     16 MB types legitimately travel as JSON (Peer::send falls back to the
//     JSON encoding whenever the peer's negotiated wire_version is 0, which
//     is the DEFAULT until a HELLO is processed).
//   Both paths are therefore bounded by the STRUCTURAL ceiling below
//   (kMaxJsonDepth / kMaxJsonNodes, WIRE-2), applied pre-parse in each. Read
//   that block for what remains un-eliminated.
inline constexpr size_t kMaxFrameBytes = 16 * 1024 * 1024;

// S-022: per-message-type body-size cap, applied AFTER `Message::deserialize`
// in `Peer::read_body`. Messages that exceed their type-specific cap are
// dropped and the peer connection closed (same disposition as the framing-
// layer overflow), since an oversize message indicates either a peer-side
// bug or an active flooding attempt.
//
// Caps mirror the audit's guidance + the natural ceiling each message type
// carries by design:
//
//   * 1 MB for the consensus chatter (CONTRIB / BLOCK_SIG / ABORT_CLAIM /
//     ABORT_EVENT / EQUIVOCATION_EVIDENCE / HELLO / STATUS_*) — every one
//     of these is a small, fixed-shape struct + a handful of sigs and
//     hashes. Real traffic is well under 64 KB; 1 MB leaves 16× headroom.
//   * 4 MB for BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE
//     — bounded by tx-set × tx-size per block. Mainnet blocks at the
//     present TRANSFER_PAYLOAD_MAX = 128 cap top out near 2 MB even at
//     thousands of txs; the 4 MB ceiling absorbs future growth and the
//     occasional fat block with many receipts.
//   * 16 MB for SNAPSHOT_RESPONSE / CHAIN_RESPONSE — these are the only
//     legitimate large-payload channels; bootstrap state can be MBs.
//   * GET_CHAIN / SNAPSHOT_REQUEST are small request envelopes; 1 MB cap.
inline constexpr size_t max_message_bytes(MsgType type) {
    switch (type) {
    case MsgType::SNAPSHOT_RESPONSE:
    case MsgType::CHAIN_RESPONSE:
        return 16 * 1024 * 1024;        // 16 MB

    case MsgType::BLOCK:
    case MsgType::BEACON_HEADER:
    case MsgType::SHARD_TIP:
    case MsgType::CROSS_SHARD_RECEIPT_BUNDLE:
    case MsgType::HEADERS_RESPONSE:
        // 4 MB matches BLOCK because a HEADERS_RESPONSE carries
        // server-capped 256 headers max (rpc_headers's
        // HEADERS_PAGE_MAX), each header is bounded by the same
        // committee + sig + commit structure as a Block minus the
        // heavy collections (transactions / receipts /
        // initial_state). At 256 headers × ~16 KB each ≤ 4 MB.
        return 4  * 1024 * 1024;        // 4 MB

    // Everything else (consensus chatter, requests, status, tx, hello).
    // HEADERS_REQUEST is a tiny {from, count} envelope — same 1 MB
    // default applies. Default branch keeps the cap tight even if
    // new MsgType variants get added without explicit categorisation
    // — better to be too strict and catch a regression in review
    // than to let a new unbounded type slip through unchecked.
    default:
        return 1  * 1024 * 1024;        // 1 MB
    }
}

// S-022 / WIRE-2: pre-parse STRUCTURAL ceiling for every attacker-supplied
// JSON document on the wire path (round-12 hostile-wire audit, wf_c277c6d1).
//
// WHY A BYTE CAP IS NOT ENOUGH. The per-type byte cap above bounds the INPUT,
// not the DOM the parser builds from it. A 16 MB body of '[' was MEASURED at
// ~831 MB peak heap (51.9x), 33.5M allocations and ~4.3-4.8 s CPU on a SINGLE
// connection, pre-auth. And the byte cap cannot be tightened past 16 MB,
// because SNAPSHOT_RESPONSE / CHAIN_RESPONSE legitimately reach it (see the
// JSON-reachability note below).
//
// ⚠ THE DOM COST MODEL IS NOT "16 BYTES PER VALUE". An earlier draft of this
// block said nlohmann materialises "one ~16-byte node per value plus a
// container allocation". `sizeof(nlohmann::json)` is indeed 16 — but the
// default `object_t` is `std::map` (third_party/nlohmann/json.hpp), so every
// '{' costs a map allocation PLUS one red-black-tree node per entry: ~144 B
// per single-entry object, not ~16 B. Measured on the shipped ceilings
// (g++ -O2, counting global operator new):
//
//   shape                                wire      DOM     factor
//   flat scalars   [0,0,...]            3.8 MB    48 MB     12.6x
//   objects        [{"":0},...]        13.4 MB   276 MB     20.7x
//   depth-63 object chain              18.9 MB   482 MB     25.5x
//   objects + envelope (payload copy)  12.7 MB   525 MB     41.4x
//
// The last row includes `m.payload = envelope["payload"]` in
// Message::deserialize, which deep-copies while the envelope is still alive.
//
// For calibration, the DENSEST LEGITIMATE 16 MB snapshot measures 1,597,828
// units and 129.9 MB of DOM (8.1x) — i.e. a legitimate large message is ALREADY
// an 8x expansion. That is the number that makes the residual irreducible: no
// ceiling admitting 1.6M legitimate units can bound an attacker below ~200 MB.
//
// The ceiling therefore bounds the DOM directly, in a single allocation-free
// pass over the raw bytes BEFORE the parser runs:
//
//   * kMaxJsonDepth  — nesting depth. Kills the pathological case outright:
//     the 16 MB '[' flood aborts after reading 65 bytes.
//     Its LOAD-BEARING justification is not heap, though — it is a CRASH.
//     nlohmann 3.11.3 parses iteratively and its destructor is stack-safe
//     (MEASURED: a depth-3,900,000 document parses and destroys cleanly, and
//     uses only 3.9M nodes, so the node ceiling alone would have admitted it).
//     But `serializer::dump()` RECURSES, and Message::serialize() calls
//     `envelope.dump()` — so a node that accepted a deep document and re-emitted
//     it would die of stack exhaustion on the SEND path. MEASURED on an 8 MB
//     stack (g++ -O2): depth 50,000 dumps fine, depth 200,000 SEGFAULTS. A cap
//     of 64 sits ~1000x below that threshold and 8x above the deepest
//     legitimate document, so it forecloses the crash with wide margin on both
//     sides. ⚠ Do NOT relax this ceiling on the reasoning that the node ceiling
//     already bounds the '[' flood — it does, but it does not bound dump().
//   * kMaxJsonNodes  — a proxy for the node count (container opens + commas).
//     Bounds the shapes depth alone misses: one flat array of 8M integers, or
//     millions of sibling empty containers.
//     ⚠ It is NOT "within ~2x and conservative" (an earlier draft claimed
//     this). It errs in the UNSAFE direction on objects: `{"":0}` is 1 unit but
//     costs ~144 B, so measured cost per unit ranges 72 B (shallow objects) to
//     126 B (depth-63 chains) against ~24 B for flat scalars. Charging ':' as
//     well was evaluated and REJECTED: it raises the densest legitimate
//     snapshot from 1.60M to 2.80M units (headroom 2.5x -> 1.4x, too tight to
//     be safe) while only moving the attacker's best from 276 MB to 195 MB.
//
// SIZING. The deepest LEGITIMATE envelope is CHAIN_RESPONSE at depth 8
// (envelope -> {"blocks":[...]} -> blocks[] -> Block -> shard_tip_witnesses[]
// -> witness Block -> creator_tx_lists[] -> inner list); witness Blocks are
// parsed with allow_witnesses=false, so Block nesting cannot recurse further.
// 64 leaves 8x headroom.
//
// For kMaxJsonNodes the binding case is the DENSEST legitimate envelope, which
// is a snapshot at the 16 MB ceiling. Worst-case density comes from the
// smallest repeating record the snapshot schema can emit — an account entry
// with a 1-char domain and single-digit values, which nlohmann dumps with
// sorted keys as `{"balance":0,"domain":"a","next_nonce":0}` = 41 bytes, plus
// 1 byte for the array separator. That record costs 4 counter units (1 brace +
// 2 inner commas + 1 array comma), so the ceiling density is
//   16 MB / 42 bytes  x  4 units  ~=  1.6M units.
// 4M therefore leaves ~2.5x headroom over a snapshot no real deployment would
// produce (real domains are longer and balances larger, both of which lower
// the density). Mirrors the headroom style of the byte caps above (1 MB over
// ~64 KB of real traffic). ⚠ If a denser repeating record is ever added to
// serialize_state, re-run this arithmetic — it is the whole basis for 4M.
//
// SOUNDNESS. The scan tracks JSON string state (quote + backslash escape), so
// structural bytes INSIDE strings are not counted. For any input that parses
// successfully the string boundaries are unambiguous left-to-right, hence the
// counts are exact and no valid document is ever rejected by miscounting. For
// input that does not parse, the scan may be inaccurate — but the parse
// rejects it anyway, so the composition stays fail-closed either way.
//
// ⚠ THIS IS MITIGATION, NOT ELIMINATION. Within the ceilings a 16 MB frame
// still reaches a MEASURED 482 MB (25.5x), or 525 MB (41.4x) counting the
// payload copy — against 831 MB (51.9x) unmitigated and 130 MB (8.1x) for the
// densest LEGITIMATE message. So the ceiling buys roughly 1.7-2x over the
// unmitigated worst case and leaves the attacker ~3.7x a legitimate sender —
// it removes the UNBOUNDED cases (16.7M containers, arbitrary depth), which is
// its real job, not the constant factor. Closing that fully needs the JSON path
// itself capped at the 1 MB chatter ceiling, which is a PROTOCOL decision (it
// would break snapshot/chain sync to any wire_version-0 peer, and inside the
// pre-HELLO window on every connection) — see F-6 in
// docs/proofs/S022WireFormatCaps.md §6.2 for the options and the send-path
// evidence, and §2.3 for the structural argument.
inline constexpr size_t kMaxJsonDepth = 64;
inline constexpr size_t kMaxJsonNodes = 4000000;

// Throws std::runtime_error if `data[0..len)` exceeds either ceiling above.
// Allocation-free, single pass, safe on arbitrary (including non-JSON) bytes.
// Aborts at the offending byte, so a hostile body costs O(bytes scanned before
// the ceiling trips), not O(len).
void json_structural_precheck(const uint8_t* data, size_t len);

struct Message {
    MsgType        type{MsgType::HELLO};
    nlohmann::json payload;

    // Serialize using the JSON envelope (legacy / wire-version 0). Kept as
    // the default to preserve byte-for-byte compatibility with older peers.
    std::vector<uint8_t> serialize() const;

    // Serialize using the binary envelope (wire-version 1). HELLO is
    // rejected — HELLOs are always JSON because they happen pre-negotiation.
    std::vector<uint8_t> serialize_binary() const;

    // Format-detecting deserializer: reads the body's first byte and
    // dispatches to the JSON or binary path as appropriate. This is what
    // the read side calls — it does not require pre-knowledge of the
    // peer's wire-version.
    static Message       deserialize(const uint8_t* data, size_t len);
};

// Format-detection helper exported for tests / diagnostics. True iff the
// body starts with the binary envelope magic byte + version.
bool is_binary_envelope(const uint8_t* data, size_t len);

// Codec primitives — implemented in binary_codec.cpp.
std::vector<uint8_t> encode_binary(const Message& m);
Message              decode_binary(const uint8_t* data, size_t len);

inline Message make_hello(const std::string& domain, uint16_t port,
                            determ::ChainRole role = determ::ChainRole::SINGLE,
                            ShardId shard_id = 0,
                            uint8_t wire_version = kWireVersionMax) {
    // rev.9 B2c.5: HELLO carries the sender's chain identity so peers can
    // tag connections and apply role-based message filtering. Older
    // peers without role/shard_id fields default to SINGLE / 0 (matches
    // the rev.7/8 behavior — single-chain everyone is SINGLE).
    //
    // A3 / S8: HELLO additionally carries `wire_version` — the highest
    // wire format the sender understands. Each side negotiates down to
    // min(ours, theirs) on receipt. Pre-A3 peers omit the field; the
    // receiver defaults their version to 0 (legacy JSON) in that case.
    return {MsgType::HELLO, {
        {"domain",       domain},
        {"port",         port},
        {"role",         static_cast<uint8_t>(role)},
        {"shard_id",     shard_id},
        {"wire_version", wire_version}
    }};
}
inline Message make_block(const chain::Block& b) {
    return {MsgType::BLOCK, b.to_json()};
}
inline Message make_transaction(const chain::Transaction& tx) {
    return {MsgType::TRANSACTION, tx.to_json()};
}
inline Message make_block_sig(const node::BlockSigMsg& s) {
    return {MsgType::BLOCK_SIG, s.to_json()};
}
inline Message make_contrib(const node::ContribMsg& c) {
    return {MsgType::CONTRIB, c.to_json()};
}
inline Message make_abort_claim(const node::AbortClaimMsg& a) {
    return {MsgType::ABORT_CLAIM, a.to_json()};
}
inline Message make_abort_event(const chain::AbortEvent& e, uint64_t block_index,
                                  const Hash& prev_hash) {
    // The AbortEvent itself doesn't know which height/prev_hash it belongs
    // to (those come from the round context). Wrap it with that context
    // so a receiver can verify the claims inside still bind to its view.
    return {MsgType::ABORT_EVENT, {
        {"block_index", block_index},
        {"prev_hash",   to_hex(prev_hash)},
        {"event",       e.to_json()}
    }};
}
inline Message make_equivocation_evidence(const chain::EquivocationEvent& ev) {
    return {MsgType::EQUIVOCATION_EVIDENCE, ev.to_json()};
}
inline Message make_beacon_header(const chain::Block& b) {
    // Beacon blocks travel as full Block JSON. Shards verify K-of-K sigs
    // and use cumulative_rand + applied tx state to derive validator pool.
    // (We send full Block rather than a stripped-down "header" because
    // shards derive validator-pool deltas from REGISTER/STAKE txs in the
    // beacon block — those need to be present.)
    return {MsgType::BEACON_HEADER, b.to_json()};
}
inline Message make_shard_tip(ShardId shard_id, const chain::Block& tip) {
    // Shard tip wrapped with its shard_id so the beacon can dispatch
    // committee derivation correctly. The envelope `shard_id` is the
    // DISPATCH key (which region's committee to select); as of D3.5e-6 the
    // block ALSO carries a K-of-K-signed `source_shard_id` (tip.to_json emits
    // it under the eligible_count gate), and on_shard_tip rejects any tip whose
    // signed source_shard_id != this envelope shard_id — closing same-region
    // cross-shard tip replay.
    return {MsgType::SHARD_TIP, {
        {"shard_id", shard_id},
        {"tip",      tip.to_json()}
    }};
}
inline Message make_snapshot_request(uint32_t header_count = 16) {
    return {MsgType::SNAPSHOT_REQUEST, {{"headers", header_count}}};
}
inline Message make_snapshot_response(const nlohmann::json& snapshot) {
    return {MsgType::SNAPSHOT_RESPONSE, snapshot};
}
// v2.2 light-client header-sync over gossip. Request a slice of
// headers starting at `from` (inclusive); server responds with up to
// `count` headers (bounded by HEADERS_PAGE_MAX = 256 server-side).
inline Message make_headers_request(uint64_t from_index = 0, uint32_t count = 16) {
    return {MsgType::HEADERS_REQUEST, {{"from", from_index}, {"count", count}}};
}
// v2.2 HEADERS_RESPONSE wraps the same {headers, from, count, height}
// shape that Node::rpc_headers produces. The caller passes the RPC
// result through unchanged — same JSON over gossip vs RPC.
inline Message make_headers_response(const nlohmann::json& headers_envelope) {
    return {MsgType::HEADERS_RESPONSE, headers_envelope};
}
inline Message make_cross_shard_receipt_bundle(ShardId src_shard,
                                                  const chain::Block& src_block) {
    // Carry the FULL source block so destination shards can verify
    // K-of-K sigs against the source committee they derive themselves.
    // Receipts live inside src_block.cross_shard_receipts; recipients
    // filter on dst_shard == my_shard_id.
    return {MsgType::CROSS_SHARD_RECEIPT_BUNDLE, {
        {"src_shard", src_shard},
        {"src_block", src_block.to_json()}
    }};
}
inline Message make_get_chain(uint64_t from_index = 0, uint16_t count = 64) {
    return {MsgType::GET_CHAIN, {{"from", from_index}, {"count", count}}};
}
inline Message make_status_request() {
    return {MsgType::STATUS_REQUEST, {}};
}
inline Message make_status_response(uint64_t height, const std::string& genesis_hash) {
    return {MsgType::STATUS_RESPONSE, {{"height", height}, {"genesis", genesis_hash}}};
}

} // namespace determ::net
