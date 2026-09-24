// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light export-headers implementation.
//
// Flow:
//   1. Load + parse genesis JSON; build the genesis-seeded committee.
//   2. Open the RPC client; anchor genesis (compute_genesis_hash locally
//      and cross-check daemon's block 0).
//   3. Probe head height via rpc_headers(0, 1).
//   4. Validate the requested range [from, from+count) lies within
//      [0, head_height]. Reject wrong-range with diagnostic.
//   5. Page through rpc_headers in chunks of 256 (the daemon's
//      HEADERS_PAGE_MAX). For each page, run verify_headers to enforce
//      prev_hash continuity.
//   6. For each header, run verify_block_sigs against the genesis
//      committee (MD mode; fall back to BFT mode if MD fails). Genesis
//      (index 0) skips sig verification — it has no committee — but
//      genesis_hash binding above is the load-bearing anchor.
//   7. Optionally strip creator_block_sigs (default — smaller archive)
//      or preserve them (--include-committee-sigs).
//   8. Write the assembled archive envelope to --out as compact JSON.
//
// Trust model: every header committed to the archive was verified at
// export time. The exit code is the auditor's first-line check. The
// archive itself is self-verifying: re-running `determ-light
// verify-headers --in <archive>` re-checks the prev_hash chain off-line
// without needing the daemon.

#include "export.hpp"
#include "rpc_client.hpp"
#include "trustless_read.hpp"
#include "verify.hpp"

#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace determ::light {

using nlohmann::json;

namespace {

// Build the committee shape verify_block_sigs consumes.
json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

// Verify a single header's committee sigs. Genesis (index 0) skips
// sig verification — by construction it has zero creator_block_sigs;
// the genesis-hash anchor (caller-level) is the integrity check.
// Returns true if (a) it's genesis, OR (b) sigs verify in MD mode,
// OR (c) sigs verify in BFT mode.
bool verify_header_sigs(const json& header, const json& committee_json) {
    uint64_t idx = header.value("index", uint64_t{0});
    if (idx == 0) {
        // Genesis: no committee sigs by construction.
        return true;
    }
    auto vbs = verify_block_sigs(header, committee_json, /*bft=*/false);
    if (vbs.ok) return true;
    vbs = verify_block_sigs(header, committee_json, /*bft=*/true);
    return vbs.ok;
}

} // namespace

int run_export_headers(const ExportOptions& opts) {
    try {
        // 1. Load genesis + build committee.
        auto genesis = load_genesis(opts.genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        json committee_json = build_committee_json(committee_seed);

        // 2. Open RPC; anchor genesis.
        RpcClient rpc(opts.rpc_port);
        if (!rpc.open()) {
            std::cerr << "export-headers: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // 3. Probe head height.
        auto probe = rpc.call("headers", {{"from", 0}, {"count", 1}});
        if (!probe.contains("height")) {
            std::cerr << "export-headers: daemon's headers reply missing "
                         "'height' field\n";
            return 1;
        }
        uint64_t head_height = probe["height"].get<uint64_t>();

        // 4. Range validation. The daemon's chain holds indices
        //    [0, head_height); requested range is [from, from+count).
        if (opts.count == 0) {
            std::cerr << "export-headers: --count must be > 0\n";
            return 1;
        }
        if (opts.from >= head_height) {
            std::cerr << "export-headers: --from=" << opts.from
                      << " is at or beyond head (height=" << head_height
                      << "); chain has no header at that index\n";
            return 1;
        }
        if (opts.from + opts.count > head_height) {
            std::cerr << "export-headers: requested range ["
                      << opts.from << ", " << (opts.from + opts.count)
                      << ") extends past chain head (height="
                      << head_height << ")\n";
            return 1;
        }

        // 5. Page through rpc_headers, verifying prev_hash continuity
        //    per page AND committee sigs per header.
        constexpr uint32_t PAGE = 256;
        std::vector<json> all_headers;
        all_headers.reserve(opts.count);
        std::string prev_anchor;   // empty on the first page (uses genesis)

        for (uint64_t cursor = opts.from;
             cursor < opts.from + opts.count;
             cursor += PAGE) {
            uint32_t want = static_cast<uint32_t>(
                std::min<uint64_t>(PAGE, opts.from + opts.count - cursor));
            auto page = rpc.call("headers",
                {{"from", cursor}, {"count", want}});
            if (!page.contains("headers") || !page["headers"].is_array()
                || page["headers"].empty()) {
                std::cerr << "export-headers: daemon returned empty page "
                             "at from=" << cursor << "\n";
                return 1;
            }

            // prev_hash chain check for THIS page. When cursor == 0,
            // anchor to genesis-hash; otherwise to the prior page's
            // last block_hash.
            VerifyResult vh = (cursor == 0)
                ? verify_headers(page, genesis_hash_hex, "")
                : verify_headers(page, "", prev_anchor);
            if (!vh.ok) {
                std::cerr << "export-headers: prev_hash chain verification "
                             "failed at page from=" << cursor
                          << ": " << vh.detail << "\n";
                return 1;
            }
            prev_anchor = vh.block_hash_hex;

            // 6. Per-header committee-sig check + collect.
            for (auto& h : page["headers"]) {
                bool sigs_ok = verify_header_sigs(h, committee_json);
                if (!sigs_ok) {
                    uint64_t idx = h.value("index", uint64_t{0});
                    std::cerr << "export-headers: committee-sig verification "
                                 "failed for header at index " << idx
                              << "\n";
                    return 1;
                }

                // 7. Optionally strip creator_block_sigs for compact
                //    archives. The default mode preserves everything
                //    else needed by verify_headers --in <archive>.
                json hdr_copy = h;
                if (!opts.include_committee_sigs) {
                    hdr_copy.erase("creator_block_sigs");
                }
                all_headers.push_back(std::move(hdr_copy));
            }
        }

        // Sanity: page-walk should have collected exactly opts.count
        // headers spanning [opts.from, opts.from + opts.count).
        if (all_headers.size() != opts.count) {
            std::cerr << "export-headers: assembled " << all_headers.size()
                      << " header(s) but requested " << opts.count
                      << " — daemon paging behavior is inconsistent\n";
            return 1;
        }

        // 8. Build the archive envelope and write it.
        //
        // Each record carries (a) the index for quick lookup, (b) the
        // header_json (possibly minus creator_block_sigs), and (c) the
        // verified_committee_sigs flag asserting the sigs verified
        // here at export time. For genesis (index 0) the flag is
        // `true` (no committee, anchored via genesis_hash) — this is
        // honest because genesis IS the chain identity.
        json records = json::array();
        for (auto& hdr : all_headers) {
            uint64_t idx = hdr.value("index", uint64_t{0});
            records.push_back({
                {"index",                   idx},
                {"header_json",             std::move(hdr)},
                {"verified_committee_sigs", true},
            });
        }

        json archive = {
            {"exported_at_height", head_height},
            {"from",               opts.from},
            {"count",              opts.count},
            {"genesis_hash",       genesis_hash_hex},
            {"headers",            std::move(records)},
        };

        std::ofstream f(opts.out_path);
        if (!f) {
            std::cerr << "export-headers: cannot open --out for write: "
                      << opts.out_path << "\n";
            return 1;
        }
        f << archive.dump() << "\n";
        if (!f) {
            std::cerr << "export-headers: write failed on --out: "
                      << opts.out_path << "\n";
            return 1;
        }

        std::cout << "OK\n"
                  << "  exported_at_height: " << head_height << "\n"
                  << "  range:              [" << opts.from
                  << ", " << (opts.from + opts.count) << ")\n"
                  << "  headers:            " << all_headers.size() << "\n"
                  << "  genesis_hash:       " << genesis_hash_hex << "\n"
                  << "  include_sigs:       "
                  << (opts.include_committee_sigs ? "yes" : "no") << "\n"
                  << "  out:                " << opts.out_path << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "export-headers: " << e.what() << "\n";
        return 1;
    }
}

} // namespace determ::light
