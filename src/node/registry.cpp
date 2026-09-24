// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/registry.hpp>
#include <determ/chain/block.hpp>
#include <determ/chain/eligibility_floor.hpp>
#include <determ/chain/params.hpp>
#include <algorithm>
#include <map>

namespace determ::node {

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
    // S-032 closure: read the Phase-1 abort accumulator from Chain's
    // incrementally-maintained cache instead of walking the chain log on
    // every call. The cache is kept current by apply_transactions; this
    // function becomes O(|registrants|) instead of O(height × txs/block).
    //
    // Semantics preserved: build_from_chain still returns "the registry
    // as of at_index" — the cache reflects all applied blocks (i.e., the
    // current head). Call sites that pass at_index = chain.height() get
    // identical results to the pre-S-032 walk. Call sites that pass
    // a slightly-future at_index (e.g., validating a block being received
    // at b.index = chain.height() + 1) also get identical results
    // because the loop's `i < chain.height()` bound previously prevented
    // those out-of-bounds reads.
    //
    // Only Phase-1 (round=1) aborts feed suspension; the cache mirrors
    // that filter (apply_transactions only increments on round==1).
    // The eligibility predicate + suspension formula live in ONE shared
    // definition (eligibility_floor.hpp) also consumed by
    // Chain::freeze_epoch_committee — the S-051 hard precondition that
    // replaced the two formerly byte-identical predicate copies.
    const auto& abort_records = chain.abort_records();

    // rev.8 follow-on: per-chain min_stake (default 1000 for
    // STAKE_INCLUSION, 0 for DOMAIN_INCLUSION). Skip the stake gate
    // entirely when 0 — any registered+active+non-suspended domain is
    // eligible.
    uint64_t threshold = chain.min_stake();
    auto stake_of = [&](const std::string& d) { return chain.stake(d); };

    // S-051 Option B partial floor: when fewer than K domains pass the
    // full filter, `lifted` names the suspended-but-otherwise-eligible
    // domains (ascending count/last_block/domain) re-admitted to bring
    // the pool to exactly K. Empty in every healthy state and whenever
    // the chain carries no K pin (k_block_sigs() == 0 on tool paths).
    const auto lifted = chain::eligibility_floor_lifted(
        chain.registrants(), abort_records, stake_of, threshold, at_index,
        chain.k_block_sigs());

    NodeRegistry reg;
    for (auto& [domain, r] : chain.registrants()) {
        if (!chain::domain_eligible(domain, r, abort_records, stake_of,
                                    threshold, at_index)
            && lifted.count(domain) == 0)
            continue;

        NodeEntry e;
        e.domain        = domain;
        e.pubkey        = r.ed_pub;
        e.registered_at = r.registered_at;
        e.active_from   = r.active_from;
        e.region        = r.region; // rev.9 R1

        auto it = std::lower_bound(reg.nodes_.begin(), reg.nodes_.end(), e,
            [](const NodeEntry& a, const NodeEntry& b) { return a.domain < b.domain; });
        reg.nodes_.insert(it, e);
    }
    return reg;
}

// rev.9 R1: region-filtered eligible pool.
//   region == "" → full pool (backward-compat path; behavior identical to
//                  sorted_nodes()). All pre-R1 callers see no change.
//   region != "" → strict equality on the (already-normalized) region tag.
// The pool is already sorted by domain (build_from_chain inserts in order),
// so the returned subset preserves deterministic creator-selection ordering.
std::vector<NodeEntry> NodeRegistry::eligible_in_region(
    const std::string& region) const {
    if (region.empty()) return nodes_;
    std::vector<NodeEntry> out;
    out.reserve(nodes_.size());
    for (auto& e : nodes_) {
        if (e.region == region) out.push_back(e);
    }
    return out;
}

} // namespace determ::node
