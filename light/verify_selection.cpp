// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-selection pure core. See verify_selection.hpp for the
// trust model. Composes d5_draw (the ratified lowest-hash sortition) with the
// first-open-wins + ordering verifier defences. No new crypto.

#include "verify_selection.hpp"
#include "trustless_read.hpp"   // anchor_genesis, verify_chain_to_head
#include "verify_rand.hpp"      // verify_rand_from_blocks (S-042 seed binding)
#include "verify.hpp"           // to_hex / from_hex_arr
#include <determ/dapp/d5draw.h>
#include <determ/types.hpp>
#include <cstring>
#include <set>

namespace determ::light {

// TxType::DAPP_CALL (include/determ/chain/block.hpp:180). Hardcoded to avoid
// pulling the consensus block header into the light-verifier module.
static constexpr int D5_DAPP_CALL_TX_TYPE = 10;

static std::vector<uint8_t> d5_unhex(const std::string& s) {
    std::vector<uint8_t> v;
    v.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        v.push_back((uint8_t)std::stoi(s.substr(i, 2), nullptr, 16));
    return v;
}

int collect_d5_streams(
    const std::vector<nlohmann::json>& blocks,
    const std::string& domain,
    const std::vector<uint8_t>& case_id,
    std::vector<D5RosterOp>&   out_roster,
    std::vector<D5CaseOpenAt>& out_case_opens,
    std::vector<D5ResultAt>&   out_results) {

    out_roster.clear(); out_case_opens.clear(); out_results.clear();

    for (const auto& blk : blocks) {
        uint64_t height = blk.value("index", (uint64_t)0);
        if (!blk.contains("transactions") || !blk["transactions"].is_array()) continue;
        for (const auto& tx : blk["transactions"]) {
            if (tx.value("type", -1) != D5_DAPP_CALL_TX_TYPE) continue;
            if (tx.value("to", std::string()) != domain) continue;

            // Parse the DAPP_CALL envelope (block.hpp:150-157):
            //   [topic_len u8][topic][ciphertext_len u32 LE][ciphertext]
            std::vector<uint8_t> payload = d5_unhex(tx.value("payload", std::string()));
            size_t off = 0;
            if (payload.size() < 1) continue;
            uint8_t tlen = payload[off++];
            if (off + (size_t)tlen + 4 > payload.size()) continue;
            std::string topic((const char*)&payload[off], tlen); off += tlen;
            uint32_t clen = (uint32_t)payload[off]
                          | ((uint32_t)payload[off + 1] << 8)
                          | ((uint32_t)payload[off + 2] << 16)
                          | ((uint32_t)payload[off + 3] << 24);
            off += 4;
            if (off + (size_t)clen != payload.size()) continue;   // strict: cipher_len == remaining
            const uint8_t* ct = clen ? &payload[off] : (const uint8_t*)"";
            size_t ctlen = clen;

            if (topic == "roster") {
                uint8_t op = 0;
                std::vector<const uint8_t*> ids(D5_MAX_ROSTER);
                std::vector<uint16_t> idl(D5_MAX_ROSTER);
                uint16_t cnt = 0;
                if (d5_roster_decode(ct, ctlen, &op, ids.data(), idl.data(),
                                     (uint16_t)D5_MAX_ROSTER, &cnt) != 0) continue;
                D5RosterOp rop; rop.op = op; rop.height = height;
                for (uint16_t i = 0; i < cnt; i++)
                    rop.ids.push_back(std::vector<uint8_t>(ids[i], ids[i] + idl[i]));
                out_roster.push_back(std::move(rop));
            } else if (topic == "case-open") {
                d5_case_open co;
                if (d5_case_open_decode(ct, ctlen, &co) != 0) continue;
                if (co.case_id_len != case_id.size()
                    || memcmp(co.case_id, case_id.data(), case_id.size()) != 0) continue;
                D5CaseOpenAt coa;
                coa.height               = height;
                coa.roster_cutoff_height = co.roster_cutoff_height;
                coa.draw_height          = co.draw_height;
                coa.n_primary            = co.n_primary;
                coa.m_alternate          = co.m_alternate;
                coa.draw_algo_version    = co.draw_algo_version;
                out_case_opens.push_back(coa);
            } else if (topic == "result") {
                d5_result_hdr r;
                std::vector<const uint8_t*> sid(D5_MAX_ROSTER);
                std::vector<uint16_t> sl(D5_MAX_ROSTER);
                uint32_t sc = 0;
                if (d5_result_decode(ct, ctlen, &r, sid.data(), sl.data(),
                                     (uint32_t)D5_MAX_ROSTER, &sc) != 0) continue;
                if (r.case_id_len != case_id.size()
                    || memcmp(r.case_id, case_id.data(), case_id.size()) != 0) continue;
                D5ResultAt ra; ra.height = height; ra.draw_height = r.draw_height;
                for (uint32_t i = 0; i < sc; i++)
                    ra.selected_ids.push_back(std::vector<uint8_t>(sid[i], sid[i] + sl[i]));
                out_results.push_back(std::move(ra));
            }
        }
    }
    return 0;
}

std::vector<D5RosterOp> filter_roster_to_cutoff(
    const std::vector<D5RosterOp>& ops, uint64_t cutoff) {
    // Keep only the ops that landed at height <= cutoff, in input order. A
    // member added AFTER the canonical case-open's roster_cutoff_height is not
    // eligible for that draw; folding the un-filtered stream would admit it and
    // re-derive over the wrong roster (a false SELECTED for a post-cutoff id).
    std::vector<D5RosterOp> out;
    out.reserve(ops.size());
    for (const auto& op : ops)
        if (op.height <= cutoff) out.push_back(op);
    return out;
}

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

    // ── ordering: h_r <= h_o < draw_height < h_s (anti-grinding + no post-hoc). ──
    if (!(co.height < co.draw_height)) {
        res.detail = "case-open height (" + std::to_string(co.height)
                   + ") not before draw_height (" + std::to_string(co.draw_height)
                   + ") — post-hoc roster"; return res; }
    // roster cutoff must NOT be after the case-open (SPEC §9 ordering h_r <= h_o).
    // The roster is frozen no later than the case-open, so no id can be added on
    // knowledge of cumulative_rand[H]. A case-open declaring a cutoff AFTER its own
    // block height lets a compromised authority observe the beacon at H, then ADD a
    // winning member before the (late) cutoff h_r — filter_roster_to_cutoff would
    // admit it and the core would re-derive a rigged-but-matching draw (false
    // SELECTED). This is the R2 anti-grinding leg; without it the freeze is toothless.
    if (!(co.roster_cutoff_height <= co.height)) {
        res.detail = "roster_cutoff_height (" + std::to_string(co.roster_cutoff_height)
                   + ") is after case-open height (" + std::to_string(co.height)
                   + ") — SPEC h_r<=h_o anti-grinding ordering violated (post-commit roster)";
        return res; }
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

SelectionResult verify_selection_at(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain,
    const std::vector<uint8_t>& case_id,
    const std::vector<uint8_t>& queried_member,
    size_t expected_k,
    bool bft_enabled) {

    SelectionResult res;  // default verdict UNVERIFIABLE

    // ── 1. Anchor genesis (the operator's own pin; throws on mismatch). ──
    std::string genesis_hash = anchor_genesis(rpc, genesis);

    // ── 2. Committee-authenticate the FULL chain to the head, collecting every
    //       tx-bearing full body. The collector's block_hash pin makes the set
    //       COMPLETE + authentic (SPEC §11 3a) — a truncatable dapp hint cannot
    //       hide a DAPP_CALL. ──
    std::vector<nlohmann::json> full_blocks;
    verify_chain_to_head(rpc, committee_seed, genesis_hash,
                         /*track_registry=*/false, expected_k, bft_enabled,
                         &full_blocks);

    // ── 3. Collect the streams once to find the canonical case-open's
    //       draw_height — the height the beacon seed must be authenticated at. ──
    std::vector<D5RosterOp>   roster;
    std::vector<D5CaseOpenAt> case_opens;
    std::vector<D5ResultAt>   results;
    collect_d5_streams(full_blocks, domain, case_id, roster, case_opens, results);
    if (case_opens.empty()) {
        res.detail = "no case-open for case_id on the authenticated chain";
        return res;
    }
    size_t first = 0;
    for (size_t i = 1; i < case_opens.size(); i++)
        if (case_opens[i].height < case_opens[first].height) first = i;
    const D5CaseOpenAt& co = case_opens[first];

    // ── 4. Authenticate the beacon seed cumulative_rand[draw_height] via the
    //       S-042 successor binding (verify_rand_from_blocks). Any shortfall =
    //       UNVERIFIABLE, never a guessed seed. ──
    nlohmann::json bh  = rpc.call("block", {{"index", co.draw_height}});
    nlohmann::json bh1 = rpc.call("block", {{"index", co.draw_height + 1}});
    if (bh.is_null() || bh1.is_null()) {
        res.detail = "draw_height " + std::to_string(co.draw_height)
                   + " has no committee-signed successor yet — seed unauthenticated";
        return res;
    }
    RandResult rr = verify_rand_from_blocks(bh, bh1, committee_seed,
                                            co.draw_height, expected_k, bft_enabled);
    if (rr.verdict != RandVerdict::VERIFIED) {
        res.detail = "beacon seed at draw_height " + std::to_string(co.draw_height)
                   + " UNVERIFIABLE: " + rr.detail;
        return res;
    }
    Hash seed = from_hex_arr<32>(rr.cumulative_rand_hex);

    // ── 5. With the committee-authenticated blocks + authenticated seed in hand,
    //       the rest is the daemon-free pipeline (collect → canonical → filter →
    //       pick → core), shared with the offline citizen path. ──
    return verify_selection_from_blocks(full_blocks, domain, case_id, seed.data(),
                                        queried_member);
}

SelectionResult verify_selection_from_blocks(
    const std::vector<nlohmann::json>& blocks,
    const std::string& domain,
    const std::vector<uint8_t>& case_id,
    const uint8_t seed32[32],
    const std::vector<uint8_t>& queried_member) {

    SelectionResult res;   // default verdict UNVERIFIABLE

    std::vector<D5RosterOp>   roster;
    std::vector<D5CaseOpenAt> case_opens;
    std::vector<D5ResultAt>   results;
    collect_d5_streams(blocks, domain, case_id, roster, case_opens, results);

    if (case_opens.empty()) {
        res.detail = "no case-open for case_id in the supplied blocks";
        return res;
    }
    res.multiple_case_opens = (case_opens.size() > 1);

    // first-open-wins: the canonical case-open is the one at the SMALLEST height.
    size_t first = 0;
    for (size_t i = 1; i < case_opens.size(); i++)
        if (case_opens[i].height < case_opens[first].height) first = i;
    const D5CaseOpenAt& co = case_opens[first];

    // Materialize the eligible roster as of the canonical cutoff.
    std::vector<D5RosterOp> elig_ops =
        filter_roster_to_cutoff(roster, co.roster_cutoff_height);

    // Pick the published result at the canonical draw_height (min height wins).
    const D5ResultAt* chosen = nullptr;
    for (const auto& r : results) {
        if (r.draw_height != co.draw_height) continue;
        if (!chosen || r.height < chosen->height) chosen = &r;
    }
    if (!chosen) {
        res.detail = "no published result references the canonical draw_height "
                   + std::to_string(co.draw_height);
        return res;
    }

    // Pure core: re-derive d5_draw over (seed, eligible roster) under the
    // canonical case-open, compare to the published result, decide the member.
    std::vector<uint8_t> domain_bytes(domain.begin(), domain.end());
    SelectionResult core = verify_selection_core(
        domain_bytes, case_id, seed32, elig_ops, case_opens, *chosen,
        queried_member);
    core.multiple_case_opens = res.multiple_case_opens || core.multiple_case_opens;
    return core;
}

} // namespace determ::light
