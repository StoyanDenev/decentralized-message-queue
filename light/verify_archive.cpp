// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-archive implementation.
//
// Flow (all OFFLINE — no RpcClient, no network):
//   1. Load + parse the archive JSON; validate the envelope schema
//      (genesis_hash string + non-empty headers array of records).
//   2. Load --genesis, compute_genesis_hash() locally, and assert it
//      equals archive.genesis_hash (case-insensitive). This is the
//      chain-identity anchor — a wrong genesis file is REFUSED here
//      before any further work. Equivalent to anchor_genesis() but
//      with NO daemon to cross-check: the archive's stored genesis_hash
//      stands in for the daemon's block-0 hash.
//   3. prev_hash continuity: unwrap each record's header_json into an
//      rpc_headers-shaped envelope ({headers:[...]}) and run the shared
//      verify_headers primitive. When the archive starts at index 0 the
//      genesis-hash anchor is also enforced on header[0].block_hash;
//      when it starts at from>0 the first header's prev_hash links to a
//      block NOT in the archive, so only INTERNAL continuity is checked
//      (the first link is unanchored — reported in the summary).
//   4. Committee sigs: for every non-genesis record, re-verify the
//      committee Ed25519 sigs via verify_block_sigs (MD mode, BFT
//      fallback) against the genesis-seeded committee. Genesis (index 0)
//      has no committee sigs by construction — skipped, same as
//      export-headers / verify_chain_to_head; the genesis-hash anchor
//      (step 2) is its integrity binding. Sig handling depends on
//      whether the archive retained creator_block_sigs:
//        * archive WITH sigs  → re-verify (always).
//        * archive WITHOUT sigs + --require-sigs → FAIL with a clear
//          "archive has no committee sigs" diagnostic.
//        * archive WITHOUT sigs, no --require-sigs → skip sig check
//          (prev_hash chain + genesis anchor still ran).
//   5. Print a one-line summary.
//
// Reuse: load_genesis / build_genesis_committee (trustless_read.cpp),
// compute_genesis_hash (chain/genesis), verify_headers / verify_block_sigs
// (verify.cpp). NOTHING here re-implements those primitives.

#include "verify_archive.hpp"
#include "trustless_read.hpp"
#include "verify.hpp"

#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace determ::light {

using nlohmann::json;

namespace {

// Build the committee shape verify_block_sigs consumes from the
// genesis-seeded (domain → pubkey) map. Mirror of the helper in
// export.cpp / trustless_read.cpp — kept local so verify_archive doesn't
// reach into another translation unit's anonymous namespace.
json build_committee_json(const std::map<std::string, PubKey>& seed) {
    json arr = json::array();
    for (auto& [domain, pk] : seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Does this header_json carry a non-empty creator_block_sigs array?
// export-headers preserves it only under --include-committee-sigs;
// otherwise it strips the field. A present-but-empty array (e.g. genesis)
// counts as "no sigs" for the purpose of this probe.
bool header_has_committee_sigs(const json& header_json) {
    auto it = header_json.find("creator_block_sigs");
    return it != header_json.end() && it->is_array() && !it->empty();
}

} // namespace

int run_verify_archive(const VerifyArchiveOptions& opts) {
    try {
        // ── 1. Load + parse the archive JSON. ──────────────────────────
        std::ifstream f(opts.in_path);
        if (!f) {
            std::cerr << "verify-archive: cannot open --in: "
                      << opts.in_path << "\n";
            return 1;
        }
        json archive;
        try {
            f >> archive;
        } catch (const std::exception& e) {
            std::cerr << "verify-archive: --in is not valid JSON: "
                      << e.what() << "\n";
            return 1;
        }
        if (!archive.is_object()) {
            std::cerr << "verify-archive: archive root is not a JSON object\n";
            return 1;
        }
        if (!archive.contains("genesis_hash")
            || !archive["genesis_hash"].is_string()) {
            std::cerr << "verify-archive: archive missing 'genesis_hash' "
                         "string field — not an export-headers archive\n";
            return 1;
        }
        if (!archive.contains("headers") || !archive["headers"].is_array()) {
            std::cerr << "verify-archive: archive missing 'headers' array — "
                         "not an export-headers archive\n";
            return 1;
        }
        auto& records = archive["headers"];
        if (records.empty()) {
            std::cerr << "verify-archive: archive 'headers' array is empty — "
                         "nothing to verify\n";
            return 1;
        }
        std::string archive_ghash = archive["genesis_hash"].get<std::string>();

        // ── 2. Genesis anchor: compute_genesis_hash(--genesis) must
        //       equal archive.genesis_hash. No daemon — the archive's
        //       stored hash stands in for block 0. ─────────────────────
        auto genesis = load_genesis(opts.genesis_path);   // throws → caught
        Hash local_ghash = determ::chain::compute_genesis_hash(genesis);
        std::string local_ghash_hex = to_hex(local_ghash);

        if (to_lower(archive_ghash) != to_lower(local_ghash_hex)) {
            std::cerr << "verify-archive: GENESIS HASH MISMATCH — archive "
                         "genesis_hash=" << archive_ghash
                      << " but compute_genesis_hash(--genesis)="
                      << local_ghash_hex
                      << " — this archive was NOT captured from the chain "
                         "described by --genesis; refusing\n";
            return 1;
        }

        // ── 3. Unwrap records into an rpc_headers-shaped envelope and
        //       run the shared prev_hash-chain verifier. ───────────────
        json envelope;
        envelope["headers"] = json::array();
        for (size_t i = 0; i < records.size(); ++i) {
            auto& rec = records[i];
            if (!rec.is_object() || !rec.contains("header_json")) {
                std::cerr << "verify-archive: archive record " << i
                          << " missing 'header_json' field\n";
                return 1;
            }
            envelope["headers"].push_back(rec["header_json"]);
        }

        // first_index decides the anchor: at index 0 the genesis-hash
        // anchor binds header[0].block_hash; at from>0 the first link is
        // unanchored (prev_hash points outside the archive) and only
        // internal continuity is verified. verify_headers handles BOTH:
        // passing genesis_hash with a first_index==0 slice enforces the
        // genesis block_hash; passing prev_hash_hex="" with a from>0
        // slice skips the (absent) prior-block check.
        uint64_t first_index =
            envelope["headers"][0].value("index", uint64_t{0});
        bool genesis_anchored = (first_index == 0);

        VerifyResult vh = genesis_anchored
            ? verify_headers(envelope, local_ghash_hex, "")
            : verify_headers(envelope, "", "");
        if (!vh.ok) {
            std::cerr << "verify-archive: prev_hash chain verification "
                         "failed: " << vh.detail << "\n";
            return 1;
        }

        // ── 4. Committee-sig re-verification (per non-genesis header). ──
        // Probe whether the archive retained creator_block_sigs on any
        // non-genesis header.
        bool archive_has_sigs = false;
        for (auto& rec : records) {
            uint64_t idx = rec.value("index", uint64_t{0});
            if (idx == 0) continue;
            if (header_has_committee_sigs(rec["header_json"])) {
                archive_has_sigs = true;
                break;
            }
        }

        // Count non-genesis headers (the candidates for a sig check).
        size_t non_genesis = 0;
        for (auto& rec : records) {
            if (rec.value("index", uint64_t{0}) != 0) non_genesis++;
        }

        bool did_sig_check = false;
        size_t sig_sets_valid = 0;

        if (!archive_has_sigs) {
            if (opts.require_sigs && non_genesis > 0) {
                std::cerr << "verify-archive: archive has no committee sigs "
                             "(exported WITHOUT --include-committee-sigs) but "
                             "--require-sigs was set — cannot re-verify "
                             "committee signatures from a sigs-stripped "
                             "archive\n";
                return 1;
            }
            // No sigs + not required → skip the sig check. (If the archive
            // is genesis-only, non_genesis==0 and there is nothing to
            // check regardless.)
        } else {
            // Re-verify every non-genesis header's committee sigs.
            json committee_json =
                build_committee_json(build_genesis_committee(genesis));
            did_sig_check = true;

            for (auto& rec : records) {
                uint64_t idx = rec.value("index", uint64_t{0});
                if (idx == 0) {
                    // Genesis: no committee sigs by construction; the
                    // genesis-hash anchor (step 2) is its binding.
                    continue;
                }
                const json& hdr = rec["header_json"];
                if (!header_has_committee_sigs(hdr)) {
                    // The archive carried sigs on SOME header but not this
                    // one — a tampered / inconsistent archive. Fail loudly
                    // at the offending index.
                    std::cerr << "verify-archive: record at index " << idx
                              << " is missing creator_block_sigs while other "
                                 "records in the archive retain them — "
                                 "inconsistent archive\n";
                    return 1;
                }
                VerifyResult vbs =
                    verify_block_sigs(hdr, committee_json, /*bft=*/false);
                if (!vbs.ok) {
                    // BFT-mode fallback (sentinel-zero slots tolerated).
                    vbs = verify_block_sigs(hdr, committee_json, /*bft=*/true);
                }
                if (!vbs.ok) {
                    std::cerr << "verify-archive: committee-sig verification "
                                 "FAILED for header at index " << idx
                              << ": " << vbs.detail << "\n";
                    return 1;
                }
                sig_sets_valid++;
            }
        }

        // ── 5. Summary. ─────────────────────────────────────────────────
        std::cout << "OK: " << vh.count
                  << " headers verified (genesis "
                  << (genesis_anchored ? "anchored" : "UNANCHORED first link "
                                                      "(archive from>0)")
                  << ", prev_hash chain intact, ";
        if (did_sig_check) {
            std::cout << sig_sets_valid << " committee-sig sets valid)";
        } else if (non_genesis == 0) {
            std::cout << "genesis-only archive — no committee sigs to check)";
        } else {
            std::cout << "committee-sig check skipped — archive exported "
                         "without --include-committee-sigs)";
        }
        std::cout << "\n";

        // Informational detail block (mirrors export-headers' style).
        std::cout << "  in:                 " << opts.in_path << "\n"
                  << "  genesis_hash:       " << local_ghash_hex << "\n"
                  << "  range:              [" << archive.value("from", uint64_t{0})
                  << ", " << (archive.value("from", uint64_t{0})
                             + archive.value("count", uint64_t{0})) << ")\n"
                  << "  exported_at_height: "
                  << archive.value("exported_at_height", uint64_t{0}) << "\n"
                  << "  head_block_hash:    " << vh.block_hash_hex << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-archive: " << e.what() << "\n";
        return 1;
    }
}

} // namespace determ::light
