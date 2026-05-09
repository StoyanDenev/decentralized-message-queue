#pragma once
#include <dhcoin/chain/block.hpp>
#include <dhcoin/node/producer.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <stdexcept>

namespace dhcoin::net {

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
};

struct Message {
    MsgType        type{MsgType::HELLO};
    nlohmann::json payload;

    std::vector<uint8_t> serialize() const;
    static Message       deserialize(const uint8_t* data, size_t len);
};

inline Message make_hello(const std::string& domain, uint16_t port) {
    return {MsgType::HELLO, {{"domain", domain}, {"port", port}}};
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
inline Message make_get_chain(uint64_t from_index = 0, uint16_t count = 64) {
    return {MsgType::GET_CHAIN, {{"from", from_index}, {"count", count}}};
}
inline Message make_status_request() {
    return {MsgType::STATUS_REQUEST, {}};
}
inline Message make_status_response(uint64_t height, const std::string& genesis_hash) {
    return {MsgType::STATUS_RESPONSE, {{"height", height}, {"genesis", genesis_hash}}};
}

} // namespace dhcoin::net
