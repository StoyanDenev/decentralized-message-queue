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
    // committee derivation correctly. Block itself doesn't carry shard_id.
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
