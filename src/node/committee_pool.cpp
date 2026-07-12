// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/committee_pool.hpp>

namespace determ::node {

bool committee_pin_active(const chain::Chain& chain, EpochIndex epoch) {
    return chain.shard_count() > 1
        && epoch >= 1
        && chain.committee_checkpoints().count(epoch) > 0;
}

std::vector<NodeEntry> select_committee_pool(const chain::Chain& chain,
                                             const NodeRegistry& present_head,
                                             EpochIndex epoch,
                                             const std::string& region) {
    if (!committee_pin_active(chain, epoch))
        return present_head.eligible_in_region(region);

    // Pinned path: region-filter the frozen members. Mirror
    // NodeRegistry::eligible_in_region (registry.cpp:86-95) EXACTLY: empty region
    // takes all; a non-empty region keeps strict equality matches. Members are
    // stored domain-sorted (freeze_epoch_committee iterates the registrants_
    // ordered map), matching build_from_chain's domain-sorted insert order, so
    // the emitted pool has the SAME order the present-head path would — a
    // requirement for select_m_creators to pick identical indices.
    const auto& members = chain.committee_checkpoints().at(epoch).members;
    std::vector<NodeEntry> out;
    out.reserve(members.size());
    for (const auto& m : members) {
        if (!region.empty() && m.region != region) continue;
        NodeEntry e;
        e.domain = m.domain;
        e.pubkey = m.ed_pub;
        e.region = m.region;
        // registered_at / active_from left 0 — never read on selection paths
        // (consumers read only .domain, plus .pubkey/.region for identity).
        out.push_back(std::move(e));
    }
    return out;
}

std::optional<PubKey> resolve_committee_member_pubkey(const chain::Chain& chain,
                                                      const NodeRegistry& present_head,
                                                      EpochIndex epoch,
                                                      const std::string& domain) {
    if (committee_pin_active(chain, epoch)) {
        const auto& members = chain.committee_checkpoints().at(epoch).members;
        for (const auto& m : members)
            if (m.domain == domain) return m.ed_pub;
        // frozen-first: absent from the frozen set → present-head fallback below
        // (covers a non-committee / cross-epoch slashing target).
    }
    if (auto e = present_head.find(domain)) return e->pubkey;
    return std::nullopt;
}

bool committee_member_registered(const chain::Chain& chain,
                                 const NodeRegistry& present_head,
                                 EpochIndex epoch,
                                 const std::string& domain) {
    if (committee_pin_active(chain, epoch)) {
        const auto& members = chain.committee_checkpoints().at(epoch).members;
        for (const auto& m : members)
            if (m.domain == domain) return true;
        // frozen-first, then present-head fallback.
    }
    return present_head.contains(domain);
}

} // namespace determ::node
