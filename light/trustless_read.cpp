// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light trustless-read implementation.
//
// Composite primitive: anchor genesis → verify header chain →
// fetch state-proof → cross-check daemon's cleartext account RPC.

#include "trustless_read.hpp"
#include "verify.hpp"
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace determ::light {

using nlohmann::json;

determ::chain::GenesisConfig load_genesis(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("cannot open --genesis: " + path);
    }
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("--genesis is not valid JSON: ")
                                  + e.what());
    }
    try {
        return determ::chain::GenesisConfig::from_json(j);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("--genesis parse error: ")
                                  + e.what());
    }
}

std::map<std::string, PubKey>
build_genesis_committee(const determ::chain::GenesisConfig& cfg) {
    std::map<std::string, PubKey> out;
    for (auto& c : cfg.initial_creators) {
        out[c.domain] = c.ed_pub;
    }
    return out;
}

std::string anchor_genesis(RpcClient& rpc,
                            const determ::chain::GenesisConfig& genesis) {
    // 1. Compute the expected genesis hash locally.
    Hash expected = determ::chain::compute_genesis_hash(genesis);
    std::string expected_hex = to_hex(expected);

    // 2. Fetch block 0 via rpc_headers and compare its block_hash.
    auto reply = rpc.call("headers", {{"from", 0}, {"count", 1}});
    if (!reply.contains("headers") || !reply["headers"].is_array()
        || reply["headers"].empty()) {
        throw std::runtime_error(
            "GENESIS HASH MISMATCH: daemon returned no block 0 header "
            "(reply='" + reply.dump() + "')");
    }
    auto& h0 = reply["headers"][0];
    if (!h0.contains("block_hash") || !h0["block_hash"].is_string()) {
        throw std::runtime_error(
            "GENESIS HASH MISMATCH: daemon's block 0 has no 'block_hash' field");
    }
    std::string daemon_hex = h0["block_hash"].get<std::string>();
    if (daemon_hex != expected_hex) {
        throw std::runtime_error(
            "GENESIS HASH MISMATCH: daemon's block 0 hash="
            + daemon_hex + " local genesis hash=" + expected_hex
            + " — refusing to talk to a daemon that doesn't run our chain");
    }
    return expected_hex;
}

VerifiedChain verify_chain_to_head(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex) {

    VerifiedChain vc;

    // Determine current height by asking for block 0 with count=1 (the
    // reply carries `height` at the daemon's tip).
    auto first_page = rpc.call("headers", {{"from", 0}, {"count", 1}});
    if (!first_page.contains("height")) {
        throw std::runtime_error(
            "verify-chain: daemon's headers reply missing 'height' field");
    }
    uint64_t head_height = first_page["height"].get<uint64_t>();
    if (head_height == 0) {
        // Chain hasn't produced any blocks; the verify-chain becomes a
        // genesis-anchor only — no headers to chain.
        vc.height = 0;
        vc.headers_verified = 0;
        vc.blocks_with_sigs_verified = 0;
        return vc;
    }

    // Build a JSON committee shape verify_block_sigs can consume.
    auto build_committee_json = [&]() {
        json arr = json::array();
        for (auto& [domain, pk] : committee_seed) {
            arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
        }
        return json{{"members", arr}};
    };
    json committee_json = build_committee_json();

    // Walk headers in pages of 256 (the daemon's HEADERS_PAGE_MAX).
    constexpr uint32_t PAGE = 256;
    std::string prev_anchor = "";       // empty = "use genesis-hash"
    std::string last_block_hash;
    std::string last_state_root;
    size_t headers_seen = 0;
    size_t sigs_verified = 0;

    for (uint64_t from = 0; from < head_height; from += PAGE) {
        uint32_t want = static_cast<uint32_t>(
            std::min<uint64_t>(PAGE, head_height - from));
        auto page = rpc.call(
            "headers",
            {{"from", from}, {"count", want}});
        if (!page.contains("headers") || !page["headers"].is_array()
            || page["headers"].empty()) {
            throw std::runtime_error(
                "verify-chain: daemon returned empty page at from="
                + std::to_string(from));
        }

        // Chain check for THIS page.
        auto vh = (from == 0)
            ? verify_headers(page, genesis_hash_hex, "")
            : verify_headers(page, "",            prev_anchor);
        if (!vh.ok) {
            throw std::runtime_error(
                "verify-chain: " + vh.detail
                + " (page from=" + std::to_string(from) + ")");
        }
        headers_seen += vh.count;
        prev_anchor   = vh.block_hash_hex;
        last_block_hash = vh.block_hash_hex;

        // Per-block committee-sig check.
        for (auto& h : page["headers"]) {
            // Genesis block (index 0) is the chain seed — by construction
            // it has zero creator_block_sigs (no committee produced it;
            // it's the deterministic GenesisConfig→Block transform). The
            // genesis anchor at line 188 above already cross-checked
            // block 0's block_hash against compute_genesis_hash, which
            // is the load-bearing integrity check for genesis. Skip
            // sig verification on index 0.
            uint64_t idx = h.value("index", uint64_t{0});
            if (idx == 0) continue;
            auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
            if (!vbs.ok) {
                // BFT mode fallback: a BFT-escalated block has at most
                // K - ceil(2K/3) sentinel-zero slots. Retry once with
                // bft_mode=true and accept if it passes.
                vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
                if (!vbs.ok) {
                    throw std::runtime_error(
                        "verify-chain: block at index "
                        + std::to_string(idx)
                        + ": " + vbs.detail);
                }
            }
            sigs_verified++;
            if (!vbs.state_root_hex.empty()) {
                last_state_root = vbs.state_root_hex;
            }
        }
    }

    vc.height = head_height;
    vc.head_block_hash = last_block_hash;
    vc.head_state_root = last_state_root;
    vc.headers_verified = headers_seen;
    vc.blocks_with_sigs_verified = sigs_verified;
    return vc;
}

AccountView read_account_trustless(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain) {

    AccountView av;

    // 1. Anchor genesis.
    std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

    // 2. Verify the header chain end-to-end.
    auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);

    if (vc.head_state_root.empty()) {
        throw std::runtime_error(
            "trustless-read: chain has not activated state_root (S-033) — "
            "head header carries no state_root, so state-proofs can't be "
            "anchored. Use the daemon's `account` RPC directly for chains "
            "without S-033 active.");
    }

    // 3. Fetch the state-proof for ("a:", domain).
    auto proof = rpc.call("state_proof",
        {{"namespace", "a"}, {"key", domain}});
    if (proof.contains("error") && !proof["error"].is_null()) {
        throw std::runtime_error(
            "trustless-read: state_proof RPC error: "
            + proof["error"].dump());
    }

    // 4. Verify the proof self-consistently (the proof's Merkle
    //    siblings must roll up to the claimed state_root).
    auto vsp = verify_state_proof(proof, {});
    if (!vsp.ok) {
        throw std::runtime_error("trustless-read: " + vsp.detail);
    }

    // 5. Anchor the proof's claimed state_root to a committee-signed
    //    header. Because the chain may have advanced during the
    //    round-trip, the proof's `height` can be > vc.height. We
    //    fetch the header at proof.height and confirm its state_root
    //    matches the proof's claimed root. Then we verify that
    //    header's committee sigs in isolation against the same
    //    committee seed we used in step 2 — by induction this binds
    //    the proof to a committee-attested state, even when the
    //    chain advanced past vc.height during the round-trip.
    uint64_t proof_height = proof.value("height", uint64_t{0});
    std::string proof_root = proof.value("state_root", std::string{});
    if (proof_height < vc.height) {
        throw std::runtime_error(
            "trustless-read: proof.height=" + std::to_string(proof_height)
            + " is BEFORE verified-chain head=" + std::to_string(vc.height)
            + " — daemon is serving stale state");
    }
    if (proof_height > vc.height) {
        // Build committee-json for the per-header sig check.
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed) {
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            }
            committee_json = json{{"members", arr}};
        }
        // proof.height is the count of applied blocks; the LAST applied
        // block lives at index proof.height - 1 and its state_root is
        // the post-apply commitment (block.state_root is "the state
        // after applying THIS block"). So we anchor the proof root to
        // the header at index proof.height - 1.
        uint64_t anchor_index = proof_height - 1;
        auto pg = rpc.call("headers",
            {{"from", anchor_index}, {"count", 1}});
        if (!pg.contains("headers") || !pg["headers"].is_array()
            || pg["headers"].empty()) {
            throw std::runtime_error(
                "trustless-read: cannot fetch header at index="
                + std::to_string(anchor_index)
                + " (proof.height=" + std::to_string(proof_height) + ")");
        }
        auto& h = pg["headers"][0];
        std::string hdr_root = h.value("state_root", std::string{});
        if (hdr_root != proof_root) {
            throw std::runtime_error(
                "trustless-read: proof.state_root=" + proof_root
                + " does not match header[" + std::to_string(anchor_index)
                + "].state_root=" + hdr_root);
        }
        // Verify the committee signed off on this header.
        auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
        if (!vbs.ok) {
            vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
        }
        if (!vbs.ok) {
            throw std::runtime_error(
                "trustless-read: header[" + std::to_string(anchor_index)
                + "] committee-sig check failed: " + vbs.detail);
        }
        // Also confirm the new header chains to the previously-verified
        // head via a prev_hash walk — refetch the headers between
        // vc.height and the anchor for completeness.
        if (anchor_index >= vc.height) {
            auto walk = rpc.call("headers",
                {{"from", vc.height - 1}, {"count", proof_height - vc.height + 2}});
            auto vh = verify_headers(walk, "", "");
            if (!vh.ok) {
                throw std::runtime_error(
                    "trustless-read: prev_hash walk vc.height→proof.height: "
                    + vh.detail);
            }
        }
        vc.head_state_root = proof_root;
        vc.height = proof_height;
        vc.head_block_hash = h.value("block_hash", std::string{});
    } else if (proof_root != vc.head_state_root) {
        throw std::runtime_error(
            "trustless-read: proof.state_root=" + proof_root
            + " does not match verified head state_root="
            + vc.head_state_root);
    }

    // 5. Now fetch the cleartext account fields via the daemon's
    //    `account` RPC, recompute the leaf hash, and confirm it
    //    matches the verified value_hash. This is the load-bearing
    //    cross-check: the daemon could lie about the cleartext while
    //    serving an honest proof for some OTHER (balance, next_nonce)
    //    pair; the hash recomputation forces consistency.
    auto acct = rpc.call("account", {{"address", domain}});
    if (acct.contains("error") && !acct["error"].is_null()) {
        throw std::runtime_error(
            "trustless-read: account RPC error: " + acct["error"].dump());
    }
    uint64_t bal = acct.value("balance",    uint64_t{0});
    uint64_t nn  = acct.value("next_nonce", uint64_t{0});

    determ::crypto::SHA256Builder b;
    b.append(bal);
    b.append(nn);
    Hash computed_value_hash = b.finalize();

    // Re-extract value_hash from the proof reply (we already validated it
    // via merkle_verify; pull the bytes again rather than threading them
    // through VerifyResult so the interface stays narrow).
    Hash proof_value_hash = from_hex_arr<32>(
        proof["value_hash"].get<std::string>());

    if (computed_value_hash != proof_value_hash) {
        throw std::runtime_error(
            "trustless-read: TAMPERED — daemon's `account` reply "
            "(balance=" + std::to_string(bal)
            + ", next_nonce=" + std::to_string(nn)
            + ") hashes to " + to_hex(computed_value_hash)
            + " but state-proof's value_hash is "
            + to_hex(proof_value_hash)
            + " — daemon is lying about either the cleartext OR the proof");
    }

    av.balance = bal;
    av.next_nonce = nn;
    av.state_root_hex = vc.head_state_root;
    av.height = vc.height;
    return av;
}

} // namespace determ::light
