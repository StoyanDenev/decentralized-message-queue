#pragma once
#include <dhcoin/types.hpp>
#include <dhcoin/crypto/keys.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace dhcoin::chain {

enum class TxType : uint8_t {
    TRANSFER   = 0,
    REGISTER   = 1,
    DEREGISTER = 2,
    STAKE      = 3,
    UNSTAKE    = 4,
};

struct Transaction {
    TxType               type{TxType::TRANSFER};
    std::string          from;
    std::string          to;
    uint64_t             amount{0};
    uint64_t             fee{0};
    uint64_t             nonce{0};
    std::vector<uint8_t> payload;
    Signature            sig{};
    Hash                 hash{};

    std::vector<uint8_t> signing_bytes() const;
    Hash                 compute_hash() const;

    nlohmann::json       to_json() const;
    static Transaction   from_json(const nlohmann::json& j);
};

// Forward declaration — full struct lives in node/producer.hpp.
} // namespace dhcoin::chain
namespace dhcoin::node { struct AbortClaimMsg; }
namespace dhcoin::chain {

struct AbortEvent {
    uint8_t     round{0};
    std::string aborting_node;
    int64_t     timestamp{0};
    Hash        event_hash{};

    // S7: each AbortEvent carries the M-1 signed AbortClaimMsgs that
    // authorized it. Encoded inline as JSON so block.cpp doesn't need to
    // include node/producer.hpp.
    nlohmann::json claims_json;

    nlohmann::json    to_json() const;
    static AbortEvent from_json(const nlohmann::json& j);
};

// Carried only by block 0 (genesis). Populates account_state, stake_table, and
// registrants_ at chain construction.
struct GenesisAlloc {
    std::string domain;
    PubKey      ed_pub{};
    uint64_t    balance{0};
    uint64_t    stake{0};

    nlohmann::json     to_json() const;
    static GenesisAlloc from_json(const nlohmann::json& j);
};

// Block produced by the K-committee via the 2-phase + delay-hash protocol:
//
//   Phase 1 (TxCommit + DhInput): each committee member signs (tx_hashes,
//     dh_input) with Ed25519. Union of tx_hashes lists is canonical.
//     Combined dh_inputs plus prev_hash + tx_root form the delay seed.
//
//   Local delay: every node computes R = delay_hash(seed, T) on a worker
//     thread. T iterations of SHA-256 — sequential by construction; an
//     attacker can't grind candidate seeds during the Phase 1 window.
//
//   Phase 2 (BlockSig): each committee member publishes delay_output and
//     an Ed25519 signature over block_digest. K parallel sigs authenticate
//     the block.
//
// Block fields:
//   - tx_root: canonical commitment to the tx set
//   - creator_tx_lists / creator_ed_sigs / creator_dh_inputs: per-committee
//                        Phase-1 evidence
//   - delay_seed / delay_output: sequential delay binding randomness to seed
//   - creator_block_sigs: K Ed25519 sigs over block_digest
struct Block {
    uint64_t                 index{0};
    Hash                     prev_hash{};
    int64_t                  timestamp{0};
    std::vector<Transaction> transactions;          // canonical (from, nonce, hash) order

    std::vector<std::string>          creators;            // K domain names, selection order
    std::vector<std::vector<Hash>>    creator_tx_lists;    // K (Phase 1 tx_hashes lists)
    std::vector<Signature>            creator_ed_sigs;     // K (Phase 1 Ed25519 over commit)
    std::vector<Hash>                 creator_dh_inputs;   // K (Phase 1 DH contributions)

    Hash                     tx_root{};
    Hash                     delay_seed{};
    Hash                     delay_output{};
    std::vector<Signature>   creator_block_sigs;            // K (Phase 2 Ed25519 over block_digest)

    Hash                     cumulative_rand{};
    std::vector<AbortEvent>  abort_events;

    // Populated only at index 0 (genesis). Encodes the initial accounts /
    // stakes / registry that seed the chain. Invalid for any other block.
    std::vector<GenesisAlloc> initial_state;

    std::vector<uint8_t> signing_bytes() const;
    Hash                 compute_hash() const;

    nlohmann::json to_json() const;
    static Block   from_json(const nlohmann::json& j);
};

} // namespace dhcoin::chain
