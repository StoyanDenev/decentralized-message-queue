// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// S-051 "eligibility floor" — Option B (partial floor, fill to K), owner
// decision 2026-07-17 (EligibilityFloorDesign.md §3-B / §4 recommendation
// accepted, including both §4 sub-recommendations: fill target = K, lift
// order = ascending (count, last_block, domain)). ONE chain-visible shared
// implementation — the §4 hard precondition — called by BOTH consensus
// surfaces that filter the eligible pool:
//   - NodeRegistry::build_from_chain (node selection + the validator's
//     registry input — src/node/registry.cpp)
//   - Chain::freeze_epoch_committee  (D3.3b frozen `cc:` checkpoints —
//     src/chain/chain.cpp)
// Collapsing the two formerly byte-identical predicate copies into these
// functions removes the drift vector the freeze-site comment warned about
// (design requirement R2; the params.hpp shared-formula precedent). The
// light client is NOT a mirror: it verifies committee signatures against
// the block's own committee and hash-binds `b:` leaves — it never
// re-derives the eligible pool.
//
// FLOOR SEMANTICS (Option B). At `at_index` with committee size `k`: when
// FEWER than `k` domains pass the full four-predicate filter
// (registered-active-window + stake + NOT-suspended), suspensions are
// LIFTED one domain at a time over the suspended-but-otherwise-base-
// eligible candidates, in the total order
//     ascending (abort_record.count, abort_record.last_block, domain)
// — lowest abort count first (least chronic offender), then least-
// recently-suspended, then the unique domain string as tiebreak — taking
// only enough domains to bring the pool to exactly k. This makes the
// S-051 permanent halt (suspension-pool exhaustion: no committee forms,
// no round runs, the S-050 valve is unreachable, block-indexed
// suspensions never expire) unreachable whenever >= k domains are
// base-eligible, while a chronic offender returns LAST — the deterrence
// semantics of the suspension mechanism survive (the §3-A jailbreak is
// blunted to its minimum width).
//
// PURITY (R1): every input is committed chain state — registrants, stakes,
// abort_records, at_index, k (genesis-pinned k_block_sigs, carried on
// Chain like epoch_blocks_). The sort keys come from abort_records_ + the
// domain string; the order is total (domains unique), so every node lifts
// the identical subset. No wall clock, no local view.
// DORMANCY / byte-neutrality: the lift set is EMPTY whenever >= k domains
// are eligible, so every healthy state filters byte-identically to
// pre-S-051; k == 0 (unwired tool paths) disables the floor outright.
// The abort-record WRITE path is untouched (R4) — no state-root change on
// any existing history.
#pragma once
#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <determ/chain/params.hpp>

namespace determ::chain {

// The S-032 suspension formula (count-exponential window, block-index
// expiry) — hoisted VERBATIM from the two former per-surface copies.
template <class AbortMap>
inline bool suspension_active(const AbortMap& abort_records,
                              const std::string& domain,
                              uint64_t at_index) {
    auto it = abort_records.find(domain);
    if (it == abort_records.end()) return false;
    const auto& ar = it->second;
    uint64_t exp = std::min(ar.count - 1, MAX_ABORT_EXPONENT);
    uint64_t len = std::min(BASE_SUSPENSION_BLOCKS * (uint64_t(1) << exp),
                            MAX_SUSPENSION_BLOCKS);
    return at_index <= ar.last_block + len;
}

// The full four-predicate eligibility check for one registrant record `r`
// (any type exposing .active_from / .inactive_from). A domain the floor
// lifted is admitted by the caller via the lifted set, NOT by weakening
// this predicate — see eligibility_floor_lifted.
template <class Reg, class AbortMap, class StakeFn>
inline bool domain_eligible(const std::string& domain, const Reg& r,
                            const AbortMap& abort_records,
                            StakeFn&& stake_of, uint64_t min_stake,
                            uint64_t at_index) {
    if (r.active_from > at_index)                      return false;
    if (at_index >= r.inactive_from)                   return false;
    if (min_stake > 0 && stake_of(domain) < min_stake) return false;
    if (suspension_active(abort_records, domain, at_index)) return false;
    return true;
}

// The Option-B floor: the (possibly empty) set of domains whose
// suspensions are LIFTED at at_index. Two passes over committed state:
//   1. count the fully-eligible pool and collect the suspended-but-
//      otherwise-base-eligible candidates with their (count, last_block)
//      sort keys;
//   2. if the pool is short of k, sort the candidates ascending
//      (count, last_block, domain) and lift exactly the first
//      k - |eligible| of them (all of them when even that cannot reach k
//      — the pool stays short and committee formation still gates on
//      avail < k downstream, unchanged).
// Callers admit a domain when `domain_eligible(...) || lifted.count(d)`;
// every lifted domain already passed the three base predicates by
// construction. Empty whenever |eligible| >= k or k == 0.
template <class RegMap, class AbortMap, class StakeFn>
inline std::set<std::string> eligibility_floor_lifted(
    const RegMap& registrants, const AbortMap& abort_records,
    StakeFn&& stake_of, uint64_t min_stake, uint64_t at_index, uint32_t k) {
    std::set<std::string> lifted;
    if (k == 0) return lifted;
    uint64_t eligible = 0;
    // (count, last_block, domain) — std::tuple's lexicographic ascending
    // order IS the §3-B lift order.
    std::vector<std::tuple<uint64_t, uint64_t, std::string>> cand;
    for (const auto& [domain, r] : registrants) {
        if (r.active_from > at_index)                      continue;
        if (at_index >= r.inactive_from)                   continue;
        if (min_stake > 0 && stake_of(domain) < min_stake) continue;
        if (suspension_active(abort_records, domain, at_index)) {
            const auto& ar = abort_records.find(domain)->second;
            cand.emplace_back(ar.count, ar.last_block, domain);
        } else {
            ++eligible;
        }
    }
    if (eligible >= k) return lifted;
    std::sort(cand.begin(), cand.end());
    const uint64_t need = k - eligible;
    for (uint64_t i = 0; i < need && i < cand.size(); ++i)
        lifted.insert(std::get<2>(cand[i]));
    return lifted;
}

} // namespace determ::chain
