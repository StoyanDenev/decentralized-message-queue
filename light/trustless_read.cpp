// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light trustless-read implementation.
//
// Composite primitive: anchor genesis → verify header chain →
// fetch state-proof → cross-check daemon's cleartext account RPC.

#include "trustless_read.hpp"
#include "verify.hpp"
#include "persist.hpp"          // anchored_head's LSP-6 resume path
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <thread>
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

AnchoredHead anchored_head(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    bool resume,
    const std::string& state_path) {

    AnchoredHead out;
    // Always anchor genesis first (fail-closed if the daemon's block 0 doesn't
    // hash to the LOCAL compute_genesis_hash). This is the operator's own pin.
    out.genesis_hash_hex = anchor_genesis(rpc, genesis);

    if (resume) {
        const std::string sp = state_path.empty() ? default_state_path() : state_path;
        if (light_state_exists(sp)) {
            // Load under a fallback guard: a CORRUPT cache is an optimization
            // fault, not a security fault → fall back to a full verify.
            LightState st;
            bool anchor_loaded = false;
            try { st = load_light_state(sp); anchor_loaded = true; }
            catch (const std::exception& e) {
                out.note = "(--resume: cached anchor is corrupt (" + std::string(e.what())
                         + ") — full verify)";
            }
            if (anchor_loaded) {
                if (st.genesis_hash == out.genesis_hash_hex && st.head_height > 0) {
                    // NOT guarded: a suffix that does not chain onto the anchor
                    // (a fork/rollback below it) THROWS — a hard error, never a
                    // silent from-genesis re-verify that would mask the fork.
                    auto rr = verify_chain_from_anchor(
                        rpc, committee_seed, st.head_height, st.head_block_hash);
                    if (rr.resumed) {
                        out.vc = rr.vc;
                        out.resumed = true;
                        out.note = "RESUMED from cached anchor at height "
                                 + std::to_string(st.head_height)
                                 + " (verified " + std::to_string(rr.vc.headers_verified)
                                 + " suffix headers)";
                        return out;
                    }
                    out.note = "(--resume: daemon not ahead of cached anchor at height "
                             + std::to_string(st.head_height) + " — full verify)";
                } else {
                    out.note = "(--resume: cached anchor is for a different chain or empty "
                               "— genesis re-pin failed; full verify)";
                }
            }
        } else {
            out.note = "(--resume: no cached anchor at " + sp + " — full verify)";
        }
    }

    // Full from-genesis verify (the default, and every fallback path above).
    out.vc = verify_chain_to_head(rpc, committee_seed, out.genesis_hash_hex);
    return out;
}

std::string committee_bound_state_root(RpcClient& rpc,
                                       const json& committee_json,
                                       uint64_t anchor_index,
                                       uint64_t max_wait_seconds) {
    // 1. Fetch the FULL block at anchor_index (NOT the stripped header).
    //    The full body carries the heavy fields signing_bytes needs, so
    //    block_hash = compute_hash() is recomputable locally — the
    //    stripped `headers` RPC cannot give us this.
    json full = rpc.call("block", {{"index", anchor_index}});
    if (full.is_null()) {
        throw std::runtime_error(
            "full block " + std::to_string(anchor_index)
            + " out of range — cannot bind its state_root");
    }
    if (full.contains("error") && !full["error"].is_null()) {
        throw std::runtime_error(
            "full block " + std::to_string(anchor_index)
            + " RPC error: " + full["error"].dump());
    }

    // 2. Parse + recompute block_hash from the full body.
    determ::chain::Block b;
    try {
        b = determ::chain::Block::from_json(full);
    } catch (const std::exception& e) {
        throw std::runtime_error(
            "malformed full block " + std::to_string(anchor_index)
            + ": " + e.what());
    }
    Hash recomputed = b.compute_hash();

    // 3. Fetch the committee-signed SUCCESSOR header (index anchor+1). Its
    //    digest binds prev_hash, so its committee sigs transitively commit
    //    the anchor's block_hash — and hence the anchor's state_root.
    uint64_t succ = anchor_index + 1;
    auto succ_present = [](const json& p) {
        return p.contains("headers") && p["headers"].is_array()
            && !p["headers"].empty();
    };
    auto pg = rpc.call("headers", {{"from", succ}, {"count", 1}});
    // HOLD-AND-WAIT (S-042 head-read fix). When the anchor IS the chain head its
    // successor does not exist yet, so the binding cannot complete. The caller
    // has ALREADY captured the proof for this anchor and the anchor block is
    // immutable + retained, so we wait for the next block to be produced and
    // then bind the HELD proof — we never re-fetch the proof (which would race a
    // state change). Poll up to max_wait_seconds (1s between attempts). With
    // max_wait_seconds == 0 this loop does not run and the head case fails closed
    // immediately, exactly as before.
    for (uint64_t waited = 0; waited < max_wait_seconds && !succ_present(pg);
         ++waited) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        pg = rpc.call("headers", {{"from", succ}, {"count", 1}});
    }
    if (!succ_present(pg)) {
        throw std::runtime_error(
            "state_root at index " + std::to_string(anchor_index)
            + " has NO committee-signed successor yet (it is the chain head)"
            + (max_wait_seconds > 0
                   ? " after waiting " + std::to_string(max_wait_seconds)
                         + "s for the next block"
                   : "")
            + " — refusing to report an unbound head state_root"
            + (max_wait_seconds > 0
                   ? ""
                   : "; pass --wait <seconds> to block for the next block, or "
                     "retry once the chain advances one block"));
    }
    auto& succ_hdr = pg["headers"][0];
    if (succ_hdr.value("index", ~uint64_t{0}) != succ) {
        throw std::runtime_error(
            "daemon returned wrong index for successor header");
    }

    // 4. Verify the successor's committee sigs (MD first, BFT fallback).
    auto vbs = verify_block_sigs(succ_hdr, committee_json, /*bft=*/false);
    if (!vbs.ok) vbs = verify_block_sigs(succ_hdr, committee_json, /*bft=*/true);
    if (!vbs.ok) {
        throw std::runtime_error(
            "successor header " + std::to_string(succ)
            + " committee-sig check failed: " + vbs.detail);
    }

    // 5. THE load-bearing binding: the committee-signed successor's
    //    prev_hash MUST equal the recomputed anchor block_hash. A daemon
    //    that swapped the anchor's state_root FIELD (which is inside
    //    signing_bytes → block_hash) produces a recomputed block_hash that
    //    no longer matches the prev_hash the committee signed over.
    std::string succ_prev = succ_hdr.value("prev_hash", std::string{});
    std::string recomputed_hex = to_hex(recomputed);
    if (succ_prev != recomputed_hex) {
        throw std::runtime_error(
            "SECURITY — successor(" + std::to_string(succ)
            + ").prev_hash=" + succ_prev
            + " != recomputed block_hash(" + std::to_string(anchor_index)
            + ")=" + recomputed_hex
            + " — the daemon forged the block body (e.g. a swapped "
              "state_root); the committee never signed this state");
    }

    // 6. Bound. Report the anchor's state_root (empty if zero/unpopulated).
    Hash zero{};
    return (b.state_root != zero) ? to_hex(b.state_root) : std::string{};
}

AccountView read_account_trustless(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain,
    bool resume,
    const std::string& state_path,
    uint64_t max_wait_seconds) {

    AccountView av;

    // 1+2. Anchor genesis + verify the header chain to the head — full from
    //      genesis, or (resume) only the suffix above a cached anchor. anchored_head
    //      is the single source of truth for that decision (with resume=false this
    //      is byte-identical to anchor_genesis + verify_chain_to_head).
    auto ah = anchored_head(rpc, committee_seed, genesis, resume, state_path);
    std::string genesis_hash_hex = ah.genesis_hash_hex;
    VerifiedChain vc = ah.vc;  // mutable: the race-window logic below advances it

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

    // 3a. Bind the proof to THIS domain's key. verify_state_proof (step 4)
    //     Merkle-verifies whatever key_bytes the daemon SUPPLIES — it does
    //     not know which key we asked for — so without this check a
    //     Byzantine daemon could serve a valid proof for SOME OTHER `a:`
    //     leaf and lie consistently in the `account` cleartext (step 5's
    //     hash-bind compares the cleartext against the SERVED leaf, not
    //     this domain's), attributing an arbitrary committed
    //     (balance, next_nonce) to `domain` — e.g. forging a whale's
    //     balance onto an empty account (the F-6 forge class,
    //     NegativeVerdictSoundness.md; the same gap was fixed in
    //     read_stake_trustless and verify-abort-record).
    //     proof.key_bytes MUST equal the locally-computed canonical key
    //     ("a:" || domain), byte-for-byte.
    {
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + domain.size());
        local_key.push_back('a'); local_key.push_back(':');
        local_key.insert(local_key.end(), domain.begin(), domain.end());
        std::string proof_key_hex = proof.value("key_bytes", std::string{});
        std::string local_key_hex = to_hex(local_key.data(), local_key.size());
        if (proof_key_hex != local_key_hex) {
            throw std::runtime_error(
                "trustless-read: proof.key_bytes=" + proof_key_hex
                + " does not match the canonical a: key " + local_key_hex
                + " — daemon served a proof for a different leaf");
        }
    }

    // 4. Verify the proof self-consistently (the proof's Merkle
    //    siblings must roll up to the claimed state_root).
    auto vsp = verify_state_proof(proof, {});
    if (!vsp.ok) {
        throw std::runtime_error("trustless-read: " + vsp.detail);
    }

    // 5. Anchor the proof's claimed state_root to a COMMITTEE-BOUND root.
    //    The committee signs compute_block_digest, which EXCLUDES
    //    state_root — so the daemon's state_root FIELD on any header is
    //    NOT directly committee-attested and can be swapped after signing.
    //    committee_bound_state_root() fetches the FULL anchor block,
    //    recomputes its block_hash, and binds it to the committee-signed
    //    SUCCESSOR header via successor.prev_hash == recomputed block_hash
    //    (the successor's digest DOES bind prev_hash). This transitively
    //    commits the anchor's state_root. Requesting the exact head index
    //    fails closed inside the helper (no signed successor yet) — by
    //    design: we never report an unbound head state_root.
    //
    //    proof.height is the count of applied blocks; the LAST applied
    //    block lives at index proof.height - 1 and its state_root is the
    //    post-apply commitment (block.state_root is "the state after
    //    applying THIS block"). So the anchor index is proof.height - 1.
    uint64_t proof_height = proof.value("height", uint64_t{0});
    std::string proof_root = proof.value("state_root", std::string{});
    if (proof_height < vc.height) {
        throw std::runtime_error(
            "trustless-read: proof.height=" + std::to_string(proof_height)
            + " is BEFORE verified-chain head=" + std::to_string(vc.height)
            + " — daemon is serving stale state");
    }

    // Build the committee-json shape verify_block_sigs consumes — once.
    json committee_json;
    {
        json arr = json::array();
        for (auto& [domain_, pk] : committee_seed) {
            arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
        }
        committee_json = json{{"members", arr}};
    }

    uint64_t anchor_index = proof_height - 1;
    std::string attested =
        committee_bound_state_root(rpc, committee_json, anchor_index,
                                   max_wait_seconds);
    if (attested != proof_root) {
        throw std::runtime_error(
            "trustless-read: SECURITY — committee-attested state_root at "
            "index " + std::to_string(anchor_index) + " = " + attested
            + " does NOT match proof.state_root = " + proof_root
            + " — daemon served a proof against an unattested root");
    }
    vc.head_state_root = attested;
    vc.height = proof_height;

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
