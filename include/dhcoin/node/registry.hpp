#pragma once
#include <dhcoin/types.hpp>
#include <dhcoin/chain/chain.hpp>
#include <string>
#include <vector>
#include <optional>

namespace dhcoin::node {

// A REGISTER tx in block N activates at block N + 1..DELAY_WINDOW (random).
// A DEREGISTER tx in block N takes effect at block N + 1..DELAY_WINDOW (random).
// Symmetric delays prevent attackers from precisely timing pool-size shifts.
static constexpr uint64_t REGISTRATION_DELAY_WINDOW = 10;

// Abort punishment: exponential suspension from creator selection.
// Suspension length = BASE * 2^(abort_count - 1), capped at MAX.
static constexpr uint64_t BASE_SUSPENSION_BLOCKS = 10;
static constexpr uint64_t MAX_SUSPENSION_BLOCKS  = 10'000;
static constexpr uint64_t MAX_ABORT_EXPONENT     = 10;   // 2^10 = 1024

struct NodeEntry {
    std::string domain;
    PubKey      pubkey{};      // Ed25519 — for tx and consensus sig verification
    uint64_t    registered_at{0};
    uint64_t    active_from{0};
};

class NodeRegistry {
public:
    NodeRegistry() = default;

    // Nodes sorted by domain (deterministic ordering for creator selection).
    std::vector<NodeEntry>   sorted_nodes() const;
    std::optional<NodeEntry> find(const std::string& domain) const;
    size_t                   size() const { return nodes_.size(); }
    bool                     contains(const std::string& domain) const;

    // Build the eligible set as of `at_index`. Reads chain.registrants() and
    // chain.stakes() incrementally maintained by Chain::apply_transactions.
    // A domain is eligible iff:
    //   - active_from <= at_index < inactive_from
    //   - stake >= MIN_STAKE
    //   - not currently abort-suspended
    static NodeRegistry build_from_chain(const chain::Chain& chain, uint64_t at_index);

private:
    std::vector<NodeEntry> nodes_; // kept sorted by domain
};

} // namespace dhcoin::node
