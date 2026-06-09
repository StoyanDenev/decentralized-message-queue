// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light account-history implementation. See account_history.hpp
// for the trust model + the head-only-state-proof RPC constraint.
//
// Flow:
//   1. Load + parse genesis JSON; build the genesis-seeded committee.
//   2. Open RPC; anchor genesis (fail-closed on mismatch).
//   3. Probe head height; validate the [from, to] range / step.
//   4. ONCE: read_account_trustless at the head — this Merkle-verifies
//      (balance, next_nonce) against the committee-signed head state_root
//      and cross-checks the daemon's cleartext (the load-bearing proof).
//   5. For each sampled height h in {from, from+step, …, <=to}:
//        a. Fetch header[h] via rpc_headers.
//        b. Advance the incremental prev_hash chain walk to h. Because the
//           sampled heights increase monotonically, the chain from genesis
//           is verified ONCE across the whole range (each header fetched at
//           most once for the chain check), reusing verify_headers — not
//           re-walked from index 0 per sample.
//        c. Verify header[h]'s committee sigs (reusing verify_block_sigs;
//           MD mode with BFT fallback, matching verify_chain_to_head).
//        d. Record (h, state_root_h). Balance/nonce are Merkle-verified
//           only when h is the head row; otherwise they carry the
//           head-anchored verified values, annotated with the proof
//           height.
//   6. Print the trajectory table (or a JSON array with --json).
//
// REUSE: every verification step delegates to verify.cpp /
// trustless_read.cpp. This file adds NO new crypto / no new Merkle
// logic — it only sequences the existing primitives across a height
// range and formats the result.

#include "account_history.hpp"
#include "rpc_client.hpp"
#include "trustless_read.hpp"
#include "verify.hpp"

#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace determ::light {

using nlohmann::json;

namespace {

// Build the committee shape verify_block_sigs consumes (mirrors the
// helper in watch.cpp / export.cpp — kept local to avoid changing the
// shared trustless_read surface).
json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

// First 16 hex chars for the table's state_root column; "(none)" for an
// empty root (pre-S-033 chain) so a missing value is visually distinct.
std::string short_root(const std::string& full_hex) {
    if (full_hex.empty()) return "(none)";
    if (full_hex.size() <= 16) return full_hex;
    return full_hex.substr(0, 16);
}

// One verified sample. Populated from a committee-verified header at a
// given index; balance/nonce are filled by the head Merkle-read.
struct HistoryRow {
    uint64_t    height{0};            // block index of the sample
    uint64_t    balance{0};
    uint64_t    next_nonce{0};
    std::string state_root_hex;       // committee-verified root at `height`
    bool        balance_merkle_verified{false};
    uint64_t    balance_proven_at_height{0};
};

// Return the COMMITTEE-BOUND state_root committed by the block at index
// `idx`. Throws (with a height-bearing diagnostic) on any soundness
// failure.
//
// SOUNDNESS: the committee signs compute_block_digest, which EXCLUDES
// state_root. The daemon's state_root FIELD on a stripped header is NOT
// committee-attested and can be swapped after signing, so we do NOT
// trust it. For idx >= 1 we route through committee_bound_state_root,
// which fetches the FULL block at idx, recomputes its block_hash,
// verifies the SUCCESSOR header's committee sigs, and requires
// successor.prev_hash == recomputed hash — transitively binding the
// returned state_root. NOTE: this fails closed at the chain HEAD (no
// committee-signed successor exists yet); account-history must sample
// indices that have a signed successor.
//
// Genesis (idx == 0) is the single special-case: it has zero
// creator_block_sigs by construction and was already pinned by
// anchor_genesis, and in a 1-block chain it has no committee-signed
// successor to bind through. Genesis is pinned by the genesis-hash
// anchor, so we read its state_root FIELD directly (genesis blocks carry
// the post-genesis-apply commitment when S-033 is active).
std::string verify_header_state_root_at(RpcClient& rpc,
                                        const json& committee_json,
                                        uint64_t idx,
                                        uint64_t max_wait_seconds = 0) {
    if (idx == 0) {
        auto page = rpc.call("headers", {{"from", idx}, {"count", 1}});
        if (!page.contains("headers") || !page["headers"].is_array()
            || page["headers"].empty()) {
            throw std::runtime_error(
                "account-history: daemon returned no header at index "
                + std::to_string(idx));
        }
        // Genesis is pinned by the genesis-hash anchor (anchor_genesis);
        // it has no committee-signed successor in a 1-block chain.
        return page["headers"][0].value("state_root", std::string{});
    }
    return committee_bound_state_root(rpc, committee_json, idx,
                                      max_wait_seconds);
}

// Incrementally verifies the prev_hash chain from the pinned genesis,
// advancing a monotonic frontier. account-history samples STRICTLY
// INCREASING heights ({from, from+step, …}), so the chain from genesis is
// walked exactly ONCE across the whole range — each header is fetched at
// most once for the chain check — instead of re-walking [0, h] for every
// sample (which was O(N·H) header fetches for N samples over a range up
// to H). The last verified block_hash is carried as the prev-anchor
// between advances, exactly as verify_chain_to_head threads it across
// pages in trustless_read.cpp.
//
// Invariant preserved (identical to the prior per-sample re-walk): after
// advance_to(h) returns, every block index in [0, h] has been bound to
// the pinned genesis by an unbroken prev_hash chain — genesis-anchored on
// the first page, prev_anchor-threaded on every page after. So a forged
// "header at height h with a fabricated state_root" is still detectable:
// it would have to chain to genesis AND (via the separate per-height
// verify_header_state_root_at below) carry K-of-K committee sigs.
class IncrementalChainWalker {
public:
    IncrementalChainWalker(RpcClient& rpc, std::string genesis_hash_hex)
        : rpc_(rpc), genesis_hash_hex_(std::move(genesis_hash_hex)) {}

    // Verify the prev_hash chain up through block index `target_idx`
    // (inclusive). No-op when target_idx is already behind the frontier,
    // so repeated / non-advancing calls are safe (account-history only
    // ever advances, but the guard keeps the helper order-robust).
    void advance_to(uint64_t target_idx) {
        constexpr uint32_t PAGE = 256;
        while (next_from_ <= target_idx) {
            uint32_t want = static_cast<uint32_t>(
                std::min<uint64_t>(PAGE, target_idx + 1 - next_from_));
            auto page = rpc_.call("headers",
                {{"from", next_from_}, {"count", want}});
            if (!page.contains("headers") || !page["headers"].is_array()
                || page["headers"].empty()) {
                throw std::runtime_error(
                    "account-history: empty header page at from="
                    + std::to_string(next_from_)
                    + " while chaining to index "
                    + std::to_string(target_idx));
            }
            // First page (frontier still at 0) is genesis-anchored; every
            // page after threads the prior page's last verified block_hash.
            VerifyResult vh = (next_from_ == 0)
                ? verify_headers(page, genesis_hash_hex_, "")
                : verify_headers(page, "", prev_anchor_);
            if (!vh.ok) {
                throw std::runtime_error(
                    "account-history: prev_hash chain verification failed at "
                    "page from=" + std::to_string(next_from_) + ": "
                    + vh.detail);
            }
            if (vh.count == 0) {
                // Defensive: a verified-but-empty page would not advance
                // the frontier and could spin the while-loop. Treat a
                // daemon that returns zero verifiable headers as a fault.
                throw std::runtime_error(
                    "account-history: header page at from="
                    + std::to_string(next_from_)
                    + " verified zero headers");
            }
            prev_anchor_ = vh.block_hash_hex;
            next_from_  += vh.count;   // frontier = lowest unverified index
        }
    }

private:
    RpcClient&  rpc_;
    std::string genesis_hash_hex_;
    std::string prev_anchor_;     // empty until the first page is verified
    uint64_t    next_from_{0};    // lowest index not yet verified (frontier)
};

} // namespace

int run_account_history(const AccountHistoryOptions& opts) {
    try {
        // 1. Load genesis + build committee.
        auto genesis = load_genesis(opts.genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        json committee_json = build_committee_json(committee_seed);

        // Validate range / step before touching the daemon (cheap, clear
        // diagnostics for operator typos).
        if (opts.step == 0) {
            std::cerr << "account-history: --step must be >= 1\n";
            return 1;
        }
        if (opts.to < opts.from) {
            std::cerr << "account-history: --to (" << opts.to
                      << ") must be >= --from (" << opts.from << ")\n";
            return 1;
        }

        // 2. Open RPC; anchor genesis (fail-closed on mismatch).
        RpcClient rpc(opts.rpc_port);
        if (!rpc.open()) {
            std::cerr << "account-history: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // 3. Probe head height; validate the requested range fits the
        //    chain. Headers live at indices [0, head_height); the head
        //    BLOCK index is head_height - 1.
        auto probe = rpc.call("headers", {{"from", 0}, {"count", 1}});
        if (!probe.contains("height")) {
            std::cerr << "account-history: daemon's headers reply missing "
                         "'height' field\n";
            return 1;
        }
        uint64_t head_height = probe["height"].get<uint64_t>();
        if (head_height == 0) {
            std::cerr << "account-history: chain has produced no blocks yet "
                         "(height=0) — nothing to sample\n";
            return 1;
        }
        uint64_t head_index = head_height - 1;
        if (opts.to > head_index) {
            std::cerr << "account-history: --to=" << opts.to
                      << " is beyond chain head (highest block index is "
                      << head_index << ", height=" << head_height
                      << ") — refusing to sample a height the daemon "
                         "cannot serve\n";
            return 1;
        }

        std::string canon_domain = normalize_anon_address(opts.domain);

        // 4. ONE full trustless head-read. This Merkle-verifies
        //    (balance, next_nonce) at the head against the committee-
        //    signed head state_root, and hash-cross-checks the daemon's
        //    cleartext `account` reply. read_account_trustless re-anchors
        //    genesis + re-verifies the chain internally; that is the
        //    load-bearing proof for the trajectory's balance/nonce.
        AccountView head_view = read_account_trustless(
            rpc, committee_seed, genesis, canon_domain,
            /*resume=*/false, /*state_path=*/"", opts.wait_seconds);

        // 5. Walk the sampled heights. For each h: chain to genesis +
        //    committee-verify header[h] -> trustless state_root_h.
        //    The prev_hash chain is verified by a SINGLE incremental pass
        //    (IncrementalChainWalker): because sampled heights increase
        //    monotonically, advancing the frontier from one sample to the
        //    next fetches each header at most once for the chain check,
        //    instead of re-walking [0, h] from genesis on every sample.
        IncrementalChainWalker chain_walker(rpc, genesis_hash_hex);
        std::vector<HistoryRow> rows;
        for (uint64_t h = opts.from; h <= opts.to; h += opts.step) {
            HistoryRow row;
            row.height = h;

            // Bind h to genesis via an unbroken prev_hash chain, advancing
            // the incremental frontier from the previous sample up to h.
            chain_walker.advance_to(h);

            // Committee-verify the header at h -> its state_root.
            row.state_root_hex =
                verify_header_state_root_at(rpc, committee_json, h,
                                            opts.wait_seconds);

            // Balance/nonce: the daemon serves a Merkle state-proof only
            // at the head (no height param on state_proof/account RPCs).
            // The head-read above gives a Merkle-verified value anchored
            // at head_view.height. A row whose height matches that proof
            // height is fully Merkle-verified; others carry the head-
            // anchored verified value, annotated with the proof height.
            row.balance = head_view.balance;
            row.next_nonce = head_view.next_nonce;
            row.balance_proven_at_height = head_view.height;
            // head_view.height is a block COUNT (== head_index + 1 in the
            // common case; can be larger if the chain advanced during the
            // head-read's round-trip). The row is Merkle-anchored when its
            // block index + 1 equals that count.
            row.balance_merkle_verified =
                (h + 1 == head_view.height);

            rows.push_back(std::move(row));

            // Guard against uint64 wrap: if `h + step` would overflow,
            // stop after this sample (the for-loop's `h += opts.step`
            // would otherwise wrap below opts.to and loop forever).
            if (opts.step > (UINT64_MAX - h)) break;
        }

        // 6. Emit.
        if (opts.json_out) {
            json history = json::array();
            for (auto& r : rows) {
                history.push_back({
                    {"height",                   r.height},
                    {"balance",                  r.balance},
                    {"next_nonce",               r.next_nonce},
                    {"state_root",               r.state_root_hex},
                    {"balance_merkle_verified",  r.balance_merkle_verified},
                    {"balance_proven_at_height", r.balance_proven_at_height},
                });
            }
            json out = {
                {"domain",      canon_domain},
                {"head_height", head_height},
                {"from",        opts.from},
                {"to",          opts.to},
                {"step",        opts.step},
                {"history",     std::move(history)},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "account-history: " << canon_domain
                      << " (head_height=" << head_height
                      << ", genesis pinned " << short_root(genesis_hash_hex)
                      << ")\n";
            std::cout << "  each row's state_root is read from a "
                         "committee-verified header at that height;\n"
                      << "  balance/next_nonce are Merkle-verified at the "
                         "head (state_proof is head-only).\n\n";
            std::cout << "  "
                      << std::left << std::setw(10) << "height"
                      << std::setw(14) << "balance"
                      << std::setw(12) << "next_nonce"
                      << std::setw(18) << "state_root"
                      << "verified\n";
            std::cout << "  "
                      << std::string(10 + 14 + 12 + 18 + 8, '-') << "\n";
            for (auto& r : rows) {
                std::cout << "  "
                          << std::left << std::setw(10) << r.height
                          << std::setw(14) << r.balance
                          << std::setw(12) << r.next_nonce
                          << std::setw(18) << short_root(r.state_root_hex)
                          << (r.balance_merkle_verified
                                  ? "merkle(head)"
                                  : "committee")
                          << "\n";
            }
            std::cout << "\n  " << rows.size()
                      << " sample(s) verified.\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "account-history: " << e.what() << "\n";
        return 1;
    }
}

} // namespace determ::light
