// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/types.hpp>
#include <determ/chain/chain.hpp>
#include <string>
#include <vector>
#include <optional>

namespace determ::node {

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
    // rev.9 R1: validator's self-declared region tag, mirrored from
    // RegistryEntry.region. Empty = no region claim. Used by
    // eligible_in_region() to filter the pool for region-pinned shards.
    std::string region{};
};

class NodeRegistry {
public:
    NodeRegistry() = default;

    // Nodes sorted by domain (deterministic ordering for creator selection).
    std::vector<NodeEntry>   sorted_nodes() const;
    std::optional<NodeEntry> find(const std::string& domain) const;
    size_t                   size() const { return nodes_.size(); }
    bool                     contains(const std::string& domain) const;

    // rev.9 R1: region-filtered eligible pool. When `region` is empty,
    // returns the full pool (sorted_nodes() identity — preserves the
    // pre-R1 backward-compat path). When `region` is non-empty, returns
    // only entries whose declared region exactly matches. The filter is
    // a strict equality on the already-normalized strings; both sides
    // are tolower+charset-validated at parse boundaries.
    std::vector<NodeEntry>   eligible_in_region(const std::string& region) const;

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

} // namespace determ::node
