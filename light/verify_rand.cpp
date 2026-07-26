// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-rand implementation. See verify_rand.hpp for the
// S-042 successor-binding trust model. Composes verify_block_sigs + the
// block_hash recompute — no new crypto.

#include "verify_rand.hpp"
#include "verify.hpp"
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;

// Build a JSON committee shape verify_block_sigs consumes from the in-memory
// (domain -> pubkey) seed. (Same helper shape as verify_tx_inclusion.cpp.)
static json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

RandResult verify_rand_from_blocks(
    const nlohmann::json& block_h_json,
    const nlohmann::json& block_h1_json,
    const std::map<std::string, PubKey>& committee_seed,
    uint64_t    height,
    size_t      expected_k,
    bool        bft_enabled) {

    RandResult res;
    res.height = height;

    // ── 1. Parse both headers ──
    determ::chain::Block bh, bh1;
    try { bh = determ::chain::Block::from_json(pad_stripped_header(block_h_json)); }
    catch (const std::exception& e) {
        res.detail = std::string("malformed block[H] body: ") + e.what(); return res; }
    try { bh1 = determ::chain::Block::from_json(pad_stripped_header(block_h1_json)); }
    catch (const std::exception& e) {
        res.detail = std::string("malformed block[H+1] body: ") + e.what(); return res; }

    // ── 2. Index binding: a hostile daemon must not relabel a committee-signed
    //      (block, successor) pair from OTHER heights as the queried (H, H+1). ──
    if (bh.index != height) {
        res.detail = "block index binding failed: block[H].index="
                   + std::to_string(bh.index) + " != requested height="
                   + std::to_string(height);
        return res;
    }
    if (bh1.index != height + 1) {
        res.detail = "successor index binding failed: block[H+1].index="
                   + std::to_string(bh1.index) + " != H+1="
                   + std::to_string(height + 1);
        return res;
    }

    // ── 3. S-042 SUCCESSOR BINDING (the load-bearing gate) ──
    //      block_hash[H] = SHA256(signing_bytes(block[H])) INCLUDES
    //      cumulative_rand[H]. The committee-signed successor commits it as
    //      prev_hash. Recompute block_hash[H] from the SERVED header and require
    //      it equal block[H+1].prev_hash. A swapped cumulative_rand[H] changes
    //      block_hash[H] → mismatch → UNVERIFIABLE. Checked before the sig step
    //      so it is offline-falsifiable; VERIFIED still requires BOTH.
    std::string bh_hash   = to_hex(bh.compute_hash());
    std::string succ_prev = to_hex(bh1.prev_hash);
    res.block_hash_hex = bh_hash;
    if (succ_prev != bh_hash) {
        res.detail = "successor prev_hash binding failed: block[H+1].prev_hash="
                   + succ_prev + " != recomputed block_hash[H]=" + bh_hash;
        return res;
    }

    // ── 4. Committee-sig verify on block[H+1] (MD first, BFT fallback), with
    //      the LV-1/LV-2 committee-size mode-eligibility floor. ──
    json committee_json = build_committee_json(committee_seed);
    VerifyResult vr = verify_block_sigs(block_h1_json, committee_json,
                                        /*bft_mode=*/false, expected_k, bft_enabled);
    if (!vr.ok) {
        VerifyResult vb = verify_block_sigs(block_h1_json, committee_json,
                                            /*bft_mode=*/true, expected_k, bft_enabled);
        if (!vb.ok) {
            res.detail = "committee-sig verification failed on block[H+1]: " + vr.detail;
            return res;
        }
        vr = vb;
    }
    res.committee_verified = true;
    res.sigs_verified      = vr.count;
    res.committee_size     = bh1.creators.size();

    // ── 5. VERIFIED: cumulative_rand[H] is committee-authenticated. ──
    res.verdict             = RandVerdict::VERIFIED;
    res.cumulative_rand_hex = to_hex(bh.cumulative_rand);
    return res;
}

RandResult verify_rand_at(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    uint64_t    height,
    size_t      expected_k,
    bool        bft_enabled) {
    (void)genesis;
    // block[H+1] is the committee-signed successor whose prev_hash authenticates
    // cumulative_rand[H]; both must exist. A null reply means the height is
    // beyond the daemon's head — for H+1 that means the head has no signed
    // successor yet (the beacon at the tip is not yet authenticated).
    json bh = rpc.call("block", {{"index", height}});
    if (bh.is_null())
        throw std::runtime_error("block " + std::to_string(height)
            + " is out of range (>= daemon's chain height)");
    json bh1 = rpc.call("block", {{"index", height + 1}});
    if (bh1.is_null())
        throw std::runtime_error("successor block " + std::to_string(height + 1)
            + " does not exist yet — cumulative_rand[" + std::to_string(height)
            + "] has no committee-signed successor to authenticate it");
    return verify_rand_from_blocks(bh, bh1, committee_seed, height, expected_k, bft_enabled);
}

} // namespace determ::light
