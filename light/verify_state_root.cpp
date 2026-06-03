// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-state-root implementation.
//
// Per-height anchor primitive: bind header[H] to the pinned genesis via
// an unbroken prev_hash chain walk, verify H's committee sigs, and report
// the committee-attested state_root at H. See verify_state_root.hpp for
// the full trust-model rationale (and the contrast with verify-state-proof,
// which verifies a Merkle PROOF against a GIVEN root rather than the root
// itself).
//
// REUSE: every verification step delegates to verify.cpp
// (verify_headers / verify_block_sigs). This file adds NO new crypto / no
// new Merkle / no new sig logic — it sequences the existing primitives for
// a single height and packages the result. The bounded prev_hash walk
// mirrors verify_chain_to_head's page loop (trustless_read.cpp) and the
// account-history IncrementalChainWalker, restricted to [0, H] because
// this is a one-shot command.

#include "verify_state_root.hpp"
#include "verify.hpp"

#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace determ::light {

using nlohmann::json;

namespace {

// Build the committee shape verify_block_sigs consumes from the in-memory
// (domain -> pubkey) seed (mirrors the helper in trustless_read.cpp /
// account_history.cpp — kept local so this file doesn't widen the shared
// surface).
json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

// Walk the prev_hash chain from the pinned genesis up through `target_idx`
// (inclusive), genesis-anchored on the first page and prev-anchor threaded
// on every page after. Reuses verify_headers per page (no new chain
// logic). On any break throws std::runtime_error with a page-bearing
// diagnostic. This is the bounded [0, H] single-pass walk the one-shot
// command needs: after it returns, every index in [0, target_idx] has been
// bound to the pinned genesis by an unbroken prev_hash chain, so a forged
// "header at H with a fabricated state_root" must ALSO chain to genesis AND
// (via the separate verify_block_sigs below) carry committee sigs.
void walk_chain_to(RpcClient& rpc, const std::string& genesis_hash_hex,
                   uint64_t target_idx) {
    constexpr uint32_t PAGE = 256;
    std::string prev_anchor;       // empty until the first page is verified
    uint64_t next_from = 0;        // lowest index not yet verified (frontier)
    while (next_from <= target_idx) {
        uint32_t want = static_cast<uint32_t>(
            std::min<uint64_t>(PAGE, target_idx + 1 - next_from));
        auto page = rpc.call("headers",
            {{"from", next_from}, {"count", want}});
        if (!page.contains("headers") || !page["headers"].is_array()
            || page["headers"].empty()) {
            throw std::runtime_error(
                "verify-state-root: daemon returned empty header page at from="
                + std::to_string(next_from)
                + " while chaining to index " + std::to_string(target_idx));
        }
        // First page (frontier still at 0) is genesis-anchored; every page
        // after threads the prior page's last verified block_hash.
        VerifyResult vh = (next_from == 0)
            ? verify_headers(page, genesis_hash_hex, "")
            : verify_headers(page, "", prev_anchor);
        if (!vh.ok) {
            throw std::runtime_error(
                "verify-state-root: prev_hash chain verification failed at "
                "page from=" + std::to_string(next_from) + ": " + vh.detail);
        }
        if (vh.count == 0) {
            // Defensive: a verified-but-empty page would not advance the
            // frontier and could spin the while-loop. Treat a daemon that
            // returns zero verifiable headers as a fault.
            throw std::runtime_error(
                "verify-state-root: header page at from="
                + std::to_string(next_from) + " verified zero headers");
        }
        prev_anchor = vh.block_hash_hex;
        next_from  += vh.count;
    }
}

} // namespace

StateRootResult verify_state_root_at(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex,
    uint64_t    height) {

    StateRootResult res;
    res.height = height;

    // ── 1. Probe head height; reject a height beyond the chain head ──────
    // The `headers` reply carries `height` (the daemon's block COUNT). The
    // head BLOCK index is height - 1. A request beyond that is a clean
    // handled error (ok=false), not a throw — the caller exits non-zero
    // with a clear diagnostic rather than a stack trace.
    auto probe = rpc.call("headers", {{"from", 0}, {"count", 1}});
    if (!probe.contains("height")) {
        res.detail = "daemon's headers reply missing 'height' field";
        return res;
    }
    uint64_t head_height = probe["height"].get<uint64_t>();
    if (head_height == 0) {
        res.detail = "chain has produced no blocks yet (height=0) — "
                     "no state_root to verify";
        return res;
    }
    uint64_t head_index = head_height - 1;
    if (height > head_index) {
        res.detail = "--height=" + std::to_string(height)
                   + " is beyond chain head (highest block index is "
                   + std::to_string(head_index) + ", height="
                   + std::to_string(head_height)
                   + ") — refusing to report a state_root the daemon "
                     "cannot serve";
        return res;
    }

    // ── 2. Bind header[H] to genesis via a bounded prev_hash chain walk ──
    // Genesis-anchored on the first page, prev-anchor threaded after. A
    // chain break / empty page throws (transport-class fault).
    walk_chain_to(rpc, genesis_hash_hex, height);

    // ── 3. Fetch header[H] ───────────────────────────────────────────────
    auto page = rpc.call("headers", {{"from", height}, {"count", 1}});
    if (!page.contains("headers") || !page["headers"].is_array()
        || page["headers"].empty()) {
        throw std::runtime_error(
            "verify-state-root: daemon returned no header at index "
            + std::to_string(height));
    }
    auto& h = page["headers"][0];
    res.block_hash_hex = h.value("block_hash", std::string{});

    // ── 4. Anchor header[H] + extract its state_root ─────────────────────
    if (height == 0) {
        // Genesis carries NO committee sigs by construction (it is the
        // deterministic GenesisConfig->Block transform). It is already
        // pinned by the genesis-hash anchor the caller performed AND by the
        // first-page genesis-anchored verify_headers in walk_chain_to
        // above (which checks block 0's block_hash == genesis_hash_hex).
        // Report its state_root directly; committee_size / sigs_verified
        // stay 0. Mirrors verify_chain_to_head / account-history /
        // verify-tx-inclusion's index-0 handling.
        res.committee_verified = true;
        res.committee_size = 0;
        res.sigs_verified = 0;
    } else {
        json committee_json = build_committee_json(committee_seed);
        auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
        if (!vbs.ok) {
            // BFT-mode fallback: a BFT-escalated block has up to
            // K - ceil(2K/3) sentinel-zero slots. Retry once at the BFT
            // threshold and accept if it passes (identical to
            // verify_chain_to_head / verify_header_state_root_at).
            vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
        }
        if (!vbs.ok) {
            // Committee sigs do NOT verify. Fail closed: report ok=false
            // and NEVER surface a state_root the committee didn't sign.
            res.committee_verified = false;
            res.detail = "committee-sig verification FAILED for header at "
                         "index " + std::to_string(height) + ": " + vbs.detail
                       + " — refusing to report a state_root that is not "
                         "committee-attested";
            return res;
        }
        res.committee_verified = true;
        res.sigs_verified = vbs.count;
        // committee_size = |creators| of header[H]. verify_block_sigs
        // surfaces the verified-sig count but not the committee size, so
        // read creators[] from the (now committee-attested) header. The
        // sigs were verified over light_compute_block_digest(h), which
        // binds creators[], so this length is itself committee-attested.
        if (h.contains("creators") && h["creators"].is_array()) {
            res.committee_size = h["creators"].size();
        }
    }

    // state_root field on the verified header. Empty on a pre-S-033 chain
    // (the header carries no state_root); flag that distinctly so the
    // caller can report "(not populated)" instead of a bogus empty root.
    std::string sr = h.value("state_root", std::string{});
    if (!sr.empty()) {
        res.state_root_hex = sr;
        res.state_root_present = true;
    }

    res.ok = true;
    return res;
}

} // namespace determ::light
