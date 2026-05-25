// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light `watch-head` implementation. See watch.hpp for the
// trust model + output contract.
//
// Loop shape:
//   1. Anchor genesis ONCE at startup. Fail-closed on mismatch.
//   2. Build the genesis-seeded committee map.
//   3. For each tick (1..count or until SIGINT):
//        a. Fetch the head header (rpc_headers from=H-1 count=1 where
//           H = current daemon height from a 1-header probe).
//        b. Verify K-of-K committee sigs against the genesis committee
//           (fallback to BFT mode like verify_chain_to_head does).
//        c. Print one structured line:
//             TICK <i>: height=<H> head_hash=<short> state_root=<short>
//                       committee_size=<K> sigs_valid=<yes|no>
//        d. Sleep --interval seconds (skipped on the last tick).
//
// SIGINT handling: a static std::atomic<bool> `stop_requested` is
// flipped by the signal handler. The loop checks it between ticks and
// before each sleep; the sleep itself is broken into 1-second steps so
// SIGINT is honored promptly even with --interval 60.

#include "watch.hpp"
#include "rpc_client.hpp"
#include "trustless_read.hpp"
#include "verify.hpp"

#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <thread>

namespace determ::light {

using nlohmann::json;

namespace {

// Global stop flag flipped by SIGINT handler. Single-binary scope —
// the watch-head subcommand owns it for the duration of run_watch_head.
std::atomic<bool> stop_requested{false};

extern "C" void watch_sigint_handler(int /*sig*/) {
    stop_requested.store(true);
}

// Sleep for `secs` seconds but check stop_requested every second so
// SIGINT exits promptly even with --interval 60. Returns true if the
// full duration elapsed; false if stop_requested fired during the wait.
bool interruptible_sleep(uint64_t secs) {
    for (uint64_t i = 0; i < secs; ++i) {
        if (stop_requested.load()) return false;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return !stop_requested.load();
}

// Build the JSON committee shape verify_block_sigs consumes.
json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

// Short-form hash (first 16 hex chars) for the per-tick line. Empty
// inputs map to "(none)" so missing state_root on pre-S-033 chains
// is visually distinct from a populated value.
std::string short_hash(const std::string& full_hex) {
    if (full_hex.empty()) return "(none)";
    if (full_hex.size() <= 16) return full_hex;
    return full_hex.substr(0, 16);
}

// One tick: fetch the head header, verify committee sigs, print one
// line, return true if the tick "succeeded" enough to call this a
// live observation (RPC + verify both worked). On RPC failure or
// malformed head we print a WARN line and return false — the operator
// gets visibility but the loop continues.
struct TickResult {
    bool       ok{false};         // RPC reached + header parsed
    bool       sigs_valid{false}; // committee sigs validated
    uint64_t   height{0};
};

TickResult do_one_tick(RpcClient& rpc,
                       const json& committee_json,
                       uint64_t tick_index) {
    TickResult tr;
    try {
        // 1. Probe daemon height via a 1-header fetch.
        auto first = rpc.call("headers", {{"from", 0}, {"count", 1}});
        if (!first.contains("height")) {
            std::cout << "TICK " << tick_index
                      << ": WARN — daemon's headers reply missing 'height'\n";
            return tr;
        }
        uint64_t head_height = first["height"].get<uint64_t>();
        if (head_height == 0) {
            // Pre-block chain — print a structured but vacuous line.
            std::cout << "TICK " << tick_index
                      << ": height=0 head_hash=(none) state_root=(none) "
                         "committee_size=0 sigs_valid=n/a\n";
            tr.ok = true;
            return tr;
        }

        // 2. Fetch the head header (index = head_height - 1).
        uint64_t head_index = head_height - 1;
        auto page = rpc.call("headers",
            {{"from", head_index}, {"count", 1}});
        if (!page.contains("headers") || !page["headers"].is_array()
            || page["headers"].empty()) {
            std::cout << "TICK " << tick_index
                      << ": WARN — daemon returned empty page at from="
                      << head_index << "\n";
            return tr;
        }
        auto& h = page["headers"][0];

        std::string head_hash = h.value("block_hash", std::string{});
        std::string state_root = h.value("state_root", std::string{});

        // 3. Verify committee sigs. Genesis (index 0) has no committee
        //    — by construction it's the deterministic GenesisConfig→Block
        //    seed; we anchored its block_hash against compute_genesis_hash
        //    at startup. For any non-genesis head, run the K-of-K check
        //    (with BFT fallback like verify_chain_to_head).
        bool sigs_ok = false;
        size_t committee_size = 0;
        if (head_index == 0) {
            // Head IS genesis. Anchor already validated block_hash at
            // startup; report committee_size from genesis seed for the
            // operator's sanity (the column shouldn't be empty).
            committee_size = committee_json.value("members", json::array()).size();
            sigs_ok = true;
        } else {
            auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
            if (!vbs.ok) {
                // Try BFT-mode fallback (same logic as verify_chain_to_head).
                vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
            }
            // Pull committee_size out of the header's `creators` array
            // (this is the K the block was actually produced with — may
            // diverge from genesis if mid-chain REGISTERs occurred,
            // though scoped-out per trustless_read.cpp's comment).
            if (h.contains("creators") && h["creators"].is_array()) {
                committee_size = h["creators"].size();
            }
            sigs_ok = vbs.ok;
        }

        // 4. Emit the structured line.
        std::cout << "TICK " << tick_index
                  << ": height=" << head_height
                  << " head_hash=" << short_hash(head_hash)
                  << " state_root=" << short_hash(state_root)
                  << " committee_size=" << committee_size
                  << " sigs_valid=" << (sigs_ok ? "yes" : "no")
                  << "\n";

        if (!sigs_ok) {
            std::cout << "  WARN: committee sig verification FAILED at "
                         "height " << head_height << " — daemon may be "
                         "serving an unverified block (continuing to poll)\n";
        }

        tr.ok = true;
        tr.sigs_valid = sigs_ok;
        tr.height = head_height;
        return tr;

    } catch (const std::exception& e) {
        // Transient RPC / parse failure on a non-first tick: print
        // WARN line and let the loop continue. Operator wants visibility.
        std::cout << "TICK " << tick_index
                  << ": WARN — " << e.what() << " (continuing to poll)\n";
        return tr;
    }
}

} // namespace

int run_watch_head(const WatchOptions& opts) {
    // 1. Load genesis + build committee seed.
    determ::chain::GenesisConfig genesis;
    try {
        genesis = load_genesis(opts.genesis_path);
    } catch (const std::exception& e) {
        std::cerr << "watch-head: " << e.what() << "\n";
        return 1;
    }
    auto committee_seed = build_genesis_committee(genesis);
    json committee_json = build_committee_json(committee_seed);

    // 2. Open RPC + anchor genesis at startup (fail-closed).
    RpcClient rpc(opts.rpc_port);
    if (!rpc.open()) {
        std::cerr << "watch-head: " << rpc.last_error() << "\n";
        return 1;
    }
    std::string genesis_hash_hex;
    try {
        genesis_hash_hex = anchor_genesis(rpc, genesis);
    } catch (const std::exception& e) {
        std::cerr << "watch-head: " << e.what() << "\n";
        return 1;
    }
    std::cout << "watch-head: genesis anchored (hash="
              << short_hash(genesis_hash_hex)
              << ", interval=" << opts.interval_secs << "s, count="
              << (opts.count == 0 ? std::string("unbounded") :
                                    std::to_string(opts.count))
              << ")\n";

    // 3. Install SIGINT handler (preserves prior handler restoration
    //    on exit — the binary terminates anyway, so we don't bother
    //    saving/restoring; the handler fires once and flips a flag).
    std::signal(SIGINT, &watch_sigint_handler);

    // 4. Loop. `count == 0` => unbounded until SIGINT.
    uint64_t i = 1;
    while (!stop_requested.load()) {
        do_one_tick(rpc, committee_json, i);

        // Exit if --count reached.
        if (opts.count != 0 && i >= opts.count) {
            break;
        }

        // Sleep before next tick (interruptible).
        if (!interruptible_sleep(opts.interval_secs)) {
            break;
        }
        ++i;
    }

    if (stop_requested.load()) {
        std::cout << "watch-head: SIGINT received — exiting after "
                  << i << " tick(s)\n";
    } else {
        std::cout << "watch-head: completed " << i
                  << " tick(s) (--count limit reached)\n";
    }
    return 0;
}

} // namespace determ::light
