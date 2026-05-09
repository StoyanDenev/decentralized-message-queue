#include <dhcoin/node/registry.hpp>
#include <dhcoin/chain/block.hpp>
#include <dhcoin/chain/params.hpp>
#include <algorithm>
#include <map>

namespace dhcoin::node {

std::vector<NodeEntry> NodeRegistry::sorted_nodes() const {
    return nodes_;
}

std::optional<NodeEntry> NodeRegistry::find(const std::string& domain) const {
    for (auto& e : nodes_)
        if (e.domain == domain) return e;
    return std::nullopt;
}

bool NodeRegistry::contains(const std::string& domain) const {
    return find(domain).has_value();
}

NodeRegistry NodeRegistry::build_from_chain(const chain::Chain& chain, uint64_t at_index) {
    // Suspension table: count aborts and find each domain's last abort block.
    // Only Phase 1 (CONTRIB) aborts count toward suspension. Phase 2 (BLOCK_SIG)
    // aborts can fire on healthy creators under timing skew (a slow signature
    // arrival looks like absence to the timer), so using them inflates false
    // positives and can drop the eligible pool below K. Phase 1 absence is the
    // reliable signal that a creator is actually unresponsive.
    struct AbortRecord { uint64_t count{0}; uint64_t last_block{0}; };
    std::map<std::string, AbortRecord> abort_records;
    for (uint64_t i = 0; i < at_index && i < chain.height(); ++i) {
        for (auto& ae : chain.at(i).abort_events) {
            if (ae.round != 1) continue;
            auto& ar = abort_records[ae.aborting_node];
            ar.count++;
            ar.last_block = i;
        }
    }
    auto is_suspended = [&](const std::string& domain) -> bool {
        auto it = abort_records.find(domain);
        if (it == abort_records.end()) return false;
        auto& ar = it->second;
        uint64_t exp = std::min(ar.count - 1, MAX_ABORT_EXPONENT);
        uint64_t len = std::min(BASE_SUSPENSION_BLOCKS * (uint64_t(1) << exp),
                                 MAX_SUSPENSION_BLOCKS);
        return at_index <= ar.last_block + len;
    };

    // rev.8 follow-on: per-chain min_stake (default 1000 for
    // STAKE_INCLUSION, 0 for DOMAIN_INCLUSION). Skip the stake gate
    // entirely when 0 — any registered+active+non-suspended domain is
    // eligible.
    uint64_t threshold = chain.min_stake();

    NodeRegistry reg;
    for (auto& [domain, r] : chain.registrants()) {
        if (r.active_from > at_index)            continue;
        if (at_index >= r.inactive_from)         continue;
        if (threshold > 0 && chain.stake(domain) < threshold) continue;
        if (is_suspended(domain))                continue;

        NodeEntry e;
        e.domain        = domain;
        e.pubkey        = r.ed_pub;
        e.registered_at = r.registered_at;
        e.active_from   = r.active_from;

        auto it = std::lower_bound(reg.nodes_.begin(), reg.nodes_.end(), e,
            [](const NodeEntry& a, const NodeEntry& b) { return a.domain < b.domain; });
        reg.nodes_.insert(it, e);
    }
    return reg;
}

} // namespace dhcoin::node
