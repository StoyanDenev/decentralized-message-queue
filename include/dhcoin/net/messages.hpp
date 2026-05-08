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
