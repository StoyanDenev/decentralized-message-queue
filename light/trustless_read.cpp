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

namespace {

// Ask the daemon for its current tip height (the `headers` reply carries the
// tip's block-count in `height`). Throws if the field is missing.
uint64_t fetch_head_height(RpcClient& rpc) {
    auto first_page = rpc.call("headers", {{"from", 0}, {"count", 1}});
    if (!first_page.contains("height")) {
        throw std::runtime_error(
            "verify-chain: daemon's headers reply missing 'height' field");
    }
    return first_page["height"].get<uint64_t>();
}

// Shared page-walk: committee-verify blocks [start_from, head_height) with
// prev_hash continuity. For start_from==0 the first page is genesis-anchored via
// genesis_hash_hex; for start_from>0 the first page's first header must have
// prev_hash == initial_prev_anchor (the previously-verified anchor block_hash).
// This is the single verified core shared by verify_chain_to_head (start_from=0)
// and verify_chain_from_anchor (start_from=anchor_height) — the per-block logic
// is byte-identical between the two so the resume path inherits the exact T-L2
// guarantee of the from-genesis walk.
VerifiedChain verify_chain_walk(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex,
    uint64_t start_from,
    const std::string& initial_prev_anchor,
    uint64_t head_height) {

    VerifiedChain vc;

    // Build a JSON committee shape verify_block_sigs can consume.
    json committee_arr = json::array();
    for (auto& [domain, pk] : committee_seed) {
        committee_arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    json committee_json = json{{"members", committee_arr}};

    // Walk headers in pages of 256 (the daemon's HEADERS_PAGE_MAX).
    constexpr uint32_t PAGE = 256;
    std::string prev_anchor = initial_prev_anchor;  // "" = use genesis-hash
    std::string last_block_hash = initial_prev_anchor;
    std::string last_state_root;
    size_t headers_seen = 0;
    size_t sigs_verified = 0;

    for (uint64_t from = start_from; from < head_height; from += PAGE) {
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

        // Index-contiguity gate (the paired resume-soundness defense): the page
        // MUST be exactly the indices [from, from+count) in order. This rejects a
        // malicious daemon that returns a header claiming index 0 inside a resume
        // suffix to divert verify_headers into its genesis branch and dodge the
        // anchor + committee-sig checks; it also rejects index gaps. For the
        // genesis walk (from==0) it is the natural 0,1,2,... invariant.
        for (size_t i = 0; i < page["headers"].size(); ++i) {
            uint64_t got = page["headers"][i].value("index", ~uint64_t{0});
            uint64_t exp = from + static_cast<uint64_t>(i);
            if (got != exp) {
                throw std::runtime_error(
                    "verify-chain: non-contiguous header index in page from="
                    + std::to_string(from) + " — expected index "
                    + std::to_string(exp) + ", got " + std::to_string(got));
            }
        }

        // Chain check for THIS page. Index-0 (genesis) page uses the genesis
        // anchor; every other page (including the resume suffix's first page)
        // must chain onto the running prev_anchor — which on the FIRST resume
        // page is the persisted, previously-verified anchor block_hash.
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
            // genesis anchor already cross-checked block 0's block_hash
            // against compute_genesis_hash, which is the load-bearing
            // integrity check for genesis. Skip sig verification on index 0.
            uint64_t idx = h.value("index", uint64_t{0});
            // Skip the sig check ONLY for the genuine genesis block — i.e. index
            // 0 reached on the from-genesis walk's first page (from == 0). The
            // index-contiguity gate above already guarantees idx==0 ⟺ from==0,
            // but gating on `from` here makes the suffix walk's never-skip
            // property explicit and independent of that gate (defense in depth).
            if (idx == 0 && from == 0) continue;
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

    // Walked-count gate: we must have verified EXACTLY the [start_from,
    // head_height) range — no short page silently truncated the walk while we
    // still report head_height as the verified tip. (Catches a daemon serving a
    // short FINAL page; non-final short pages already break prev_hash continuity.
    // Also hardens the from-genesis verify_chain_to_head, which shares this walk.)
    if (headers_seen != head_height - start_from) {
        throw std::runtime_error(
            "verify-chain: walked " + std::to_string(headers_seen)
            + " headers but expected " + std::to_string(head_height - start_from)
            + " for range [" + std::to_string(start_from) + ", "
            + std::to_string(head_height) + ") — daemon served a short page");
    }

    vc.height = head_height;
    vc.head_block_hash = last_block_hash;
    vc.head_state_root = last_state_root;
    vc.headers_verified = headers_seen;
    vc.blocks_with_sigs_verified = sigs_verified;
    return vc;
}

}  // namespace

VerifiedChain verify_chain_to_head(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex) {

    uint64_t head_height = fetch_head_height(rpc);
    if (head_height == 0) {
        // Chain hasn't produced any blocks; the verify-chain becomes a
        // genesis-anchor only — no headers to chain.
        return VerifiedChain{};  // all-zero / empty
    }
    return verify_chain_walk(rpc, committee_seed, genesis_hash_hex,
                             /*start_from=*/0, /*initial_prev_anchor=*/"",
                             head_height);
}

ResumeResult verify_chain_from_anchor(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    uint64_t anchor_height,
    const std::string& anchor_block_hash) {

    ResumeResult rr;
    uint64_t head_height = fetch_head_height(rpc);
    if (head_height <= anchor_height) {
        // Daemon is not strictly ahead of the anchor (lagging head, exactly at
        // the anchor, or a rollback): there is no suffix to verify and we cannot
        // confirm the anchor from above. Signal the caller to fall back to a
        // full verify_chain_to_head — never silently claim a resume succeeded.
        rr.resumed = false;
        return rr;
    }
    // Verify ONLY the suffix [anchor_height, head_height). The first suffix
    // block (index anchor_height) must chain onto anchor_block_hash; if it does
    // not, verify_chain_walk throws (a fork/rollback below the anchor surfaces
    // as a hard error rather than a silent from-genesis re-verification).
    rr.vc = verify_chain_walk(rpc, committee_seed, /*genesis_hash_hex=*/"",
                              /*start_from=*/anchor_height,
                              /*initial_prev_anchor=*/anchor_block_hash,
                              head_height);
    rr.resumed = true;
    return rr;
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
