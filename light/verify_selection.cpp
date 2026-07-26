// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-selection pure core. See verify_selection.hpp for the
// trust model. Composes d5_draw (the ratified lowest-hash sortition) with the
// first-open-wins + ordering verifier defences. No new crypto.

#include "verify_selection.hpp"
#include <determ/dapp/d5draw.h>
#include <set>

namespace determ::light {

SelectionResult verify_selection_core(
    const std::vector<uint8_t>& domain,
    const std::vector<uint8_t>& case_id,
    const uint8_t seed32[32],
    const std::vector<D5RosterOp>&   roster_ops,
    const std::vector<D5CaseOpenAt>& case_opens,
    const D5ResultAt& result,
    const std::vector<uint8_t>& queried_member) {

    SelectionResult res;
    res.multiple_case_opens = (case_opens.size() > 1);

    if (case_opens.empty()) { res.detail = "no case-open for case_id"; return res; }

    // ── first-open-wins: the canonical case-open is the one at the SMALLEST
    //    block height. A compromised authority that pre-commits several draws and
    //    publishes only a favorable one is defeated — we always re-derive under
    //    the FIRST, so a favorable-but-later result won't match. >1 = EVIDENCE. ──
    size_t first = 0;
    for (size_t i = 1; i < case_opens.size(); i++)
        if (case_opens[i].height < case_opens[first].height) first = i;
    const D5CaseOpenAt& co = case_opens[first];

    // ── ordering: h_o < draw_height < h_s (anti-grinding + no post-hoc). ──
    if (!(co.height < co.draw_height)) {
        res.detail = "case-open height (" + std::to_string(co.height)
                   + ") not before draw_height (" + std::to_string(co.draw_height)
                   + ") — post-hoc roster"; return res; }
    if (!(result.height > co.draw_height)) {
        res.detail = "result height (" + std::to_string(result.height)
                   + ") not after draw_height (" + std::to_string(co.draw_height) + ")"; return res; }
    if (result.draw_height != co.draw_height) {
        res.detail = "result references a different draw_height than the canonical case-open"; return res; }

    // ── materialize the eligible roster (fold the block-ordered add/remove stream). ──
    std::set<std::vector<uint8_t>> elig;
    for (const auto& op : roster_ops) {
        if (op.op == D5_ROSTER_ADD)         for (auto& id : op.ids) elig.insert(id);
        else if (op.op == D5_ROSTER_REMOVE) for (auto& id : op.ids) elig.erase(id);
    }
    res.eligible_count = elig.size();
    if (elig.empty()) { res.detail = "empty eligible roster"; return res; }

    // ── re-run d5_draw over the materialized roster + the authenticated seed,
    //    under the CANONICAL (first) case-open's params. ──
    std::vector<std::vector<uint8_t>> ids(elig.begin(), elig.end());
    std::vector<const uint8_t*> idp; std::vector<size_t> idl;
    for (auto& id : ids) { idp.push_back(id.data()); idl.push_back(id.size()); }
    size_t want = (size_t)co.n_primary + co.m_alternate;
    std::vector<size_t> outi(want ? want : 1);
    size_t oc = 0;
    int rc = d5_draw(seed32, domain.data(), domain.size(), case_id.data(), case_id.size(),
                     co.draw_height, co.roster_cutoff_height, co.draw_algo_version,
                     idp.data(), idl.data(), ids.size(),
                     co.n_primary, co.m_alternate, outi.data(), &oc);
    if (rc != 0) { res.detail = "d5_draw failed over the materialized roster (bad params?)"; return res; }

    // ── compare the re-derived selection to the PUBLISHED result (ordered). ──
    if (oc != result.selected_ids.size()) {
        res.detail = "published result count (" + std::to_string(result.selected_ids.size())
                   + ") != canonical draw count (" + std::to_string(oc) + ")"; return res; }
    for (size_t k = 0; k < oc; k++) {
        if (ids[outi[k]] != result.selected_ids[k]) {
            res.detail = "published result != canonical draw at rank " + std::to_string(k)
                       + " (first-open-wins re-derivation mismatch)"; return res; }
    }

    // ── verdict for the queried member. ──
    if (queried_member.empty()) {
        res.verdict = SelectionVerdict::SELECTED;   // result verified; no member queried
        res.detail  = "result verified against the canonical draw";
        return res;
    }
    bool sel = false;
    for (size_t k = 0; k < oc; k++) if (ids[outi[k]] == queried_member) { sel = true; break; }
    res.verdict = sel ? SelectionVerdict::SELECTED : SelectionVerdict::NOT_SELECTED;
    return res;
}

} // namespace determ::light
