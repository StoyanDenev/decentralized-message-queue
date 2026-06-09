// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light state-proof bundle — implementation.
//
// See verify_state_bundle.hpp for the schema, the soundness argument, and the
// flow summary. This file implements:
//
//   run_export_state_bundle(opts)  — ONLINE producer (needs a daemon). Builds
//       the bundle and re-verifies the committee->state_root binding via the
//       EXISTING committee_bound_state_root helper BEFORE writing, so only a
//       sound bundle is ever produced.
//
//   verify_state_bundle(opts)      — OFFLINE verifier (NO RpcClient). Mirrors
//       committee_bound_state_root reading from the bundle bytes: recompute the
//       anchor block_hash, verify the committee-signed successor, require
//       successor.prev_hash == recomputed anchor block_hash (THE binding),
//       require the anchor's state_root == the proof root, Merkle-verify the
//       proof against the BOUND root, and (ns=="a") recompute value_hash.
//
// Reuse only — nothing here re-implements a Merkle / sig / hash / digest
// primitive. It composes:
//   * load_genesis / build_genesis_committee / committee_bound_state_root
//     (trustless_read.cpp),
//   * compute_genesis_hash (chain/genesis),
//   * verify_block_sigs / verify_state_proof (verify.cpp),
//   * Block::from_json / Block::compute_hash (chain/block).

#include "verify_state_bundle.hpp"
#include "rpc_client.hpp"
#include "trustless_read.hpp"
#include "verify.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/sha256.hpp>
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

namespace determ::light {

using nlohmann::json;

namespace {

constexpr const char* kSchema = "determ-light-state-bundle/1";

// Build the {members:[...]} committee shape verify_block_sigs consumes from the
// genesis-seeded (domain -> pubkey) map. Mirror of the local helper in
// export.cpp / verify_archive.cpp — kept here so this TU doesn't reach into
// another translation unit's anonymous namespace.
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

} // namespace

// ─────────────────────────── EXPORT (online) ────────────────────────────────

int run_export_state_bundle(const ExportStateBundleOptions& opts) {
    try {
        // 1. Load genesis + build committee; open RPC; pin the chain identity.
        auto genesis        = load_genesis(opts.genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        json committee_json = build_committee_json(committee_seed);

        // The genesis_hash baked into the bundle is the operator's own pin
        // (compute_genesis_hash) — anchor_genesis below also cross-checks it
        // against the daemon's block 0, failing closed on a wrong chain.
        Hash ghash        = determ::chain::compute_genesis_hash(genesis);
        std::string ghash_hex = to_hex(ghash);

        RpcClient rpc(opts.rpc_port);
        if (!rpc.open()) {
            std::cerr << "export-state-bundle: " << rpc.last_error() << "\n";
            return 1;
        }
        // Fail-closed if the daemon's block 0 doesn't hash to OUR genesis.
        anchor_genesis(rpc, genesis);  // throws on mismatch (caught below)

        // 2. Fetch the state-proof for (namespace, key).
        auto proof = rpc.call("state_proof",
            {{"namespace", opts.ns}, {"key", opts.key}});
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::cerr << "export-state-bundle: state_proof RPC error: "
                      << proof["error"].dump() << "\n";
            return 1;
        }
        uint64_t proof_height = proof.value("height", uint64_t{0});
        std::string proof_root = proof.value("state_root", std::string{});
        if (proof_height == 0) {
            std::cerr << "export-state-bundle: proof.height==0 — chain has no "
                         "applied block carrying a state_root to anchor\n";
            return 1;
        }
        uint64_t anchor_index = proof_height - 1;

        // 3. Fetch the FULL anchor block body (so block_hash is recomputable
        //    offline — the stripped `headers` RPC could not give us this).
        auto anchor_block = rpc.call("block", {{"index", anchor_index}});
        if (anchor_block.is_null()
            || (anchor_block.contains("error")
                && !anchor_block["error"].is_null())) {
            std::cerr << "export-state-bundle: cannot fetch full anchor block "
                      << anchor_index << "\n";
            return 1;
        }

        // 4. Fetch the committee-signed SUCCESSOR header (anchor_index+1).
        uint64_t succ = anchor_index + 1;
        auto pg = rpc.call("headers", {{"from", succ}, {"count", 1}});
        if (!pg.contains("headers") || !pg["headers"].is_array()
            || pg["headers"].empty()) {
            std::cerr << "export-state-bundle: state at the chain head has no "
                         "committee-signed successor yet (anchor index "
                      << anchor_index << " is the head) — retry once the chain "
                         "advances one block\n";
            return 1;
        }
        json successor_header = pg["headers"][0];

        // 5. VERIFY THE BINDING BEFORE WRITING. Reuse the ONLINE helper so the
        //    export side never duplicates committee_bound_state_root's logic.
        //    A bundle is written only if the committee-bound root for
        //    anchor_index equals the proof's claimed root.
        std::string attested =
            committee_bound_state_root(rpc, committee_json, anchor_index);
        if (attested != proof_root) {
            std::cerr << "export-state-bundle: SECURITY — committee-bound "
                         "state_root at index " << anchor_index << " = "
                      << attested << " does NOT match proof.state_root = "
                      << proof_root << " — refusing to write an unsound bundle\n";
            return 1;
        }

        // 6. Assemble the bundle envelope.
        json bundle = {
            {"schema",           kSchema},
            {"genesis_hash",     ghash_hex},
            {"namespace",        opts.ns},
            {"key",              opts.key},
            {"anchor_index",     anchor_index},
            {"anchor_block",     anchor_block},
            {"successor_header", successor_header},
            {"state_proof",      proof},
        };

        // 6b. For ns=="a", also store the account cleartext so the offline
        //     verifier can recompute + match value_hash.
        if (opts.ns == "a") {
            auto acct = rpc.call("account", {{"address", opts.key}});
            if (acct.contains("error") && !acct["error"].is_null()) {
                std::cerr << "export-state-bundle: account RPC error: "
                          << acct["error"].dump() << "\n";
                return 1;
            }
            bundle["account_cleartext"] = {
                {"balance",    acct.value("balance",    uint64_t{0})},
                {"next_nonce", acct.value("next_nonce", uint64_t{0})},
            };
        }

        // 7. Write the bundle to --out.
        std::ofstream f(opts.out_path);
        if (!f) {
            std::cerr << "export-state-bundle: cannot open --out for write: "
                      << opts.out_path << "\n";
            return 1;
        }
        f << bundle.dump() << "\n";
        if (!f) {
            std::cerr << "export-state-bundle: write failed on --out: "
                      << opts.out_path << "\n";
            return 1;
        }

        std::cout << "OK: state-proof bundle written (committee-bound)\n"
                  << "  namespace:    " << opts.ns << "\n"
                  << "  key:          " << opts.key << "\n"
                  << "  anchor_index: " << anchor_index << "\n"
                  << "  state_root:   " << proof_root << "\n"
                  << "  out:          " << opts.out_path << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "export-state-bundle: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────────── VERIFY (offline) ───────────────────────────────

namespace {

// Print a structured UNVERIFIABLE result (exit 3 at the call site). Keeps the
// JSON / text reporting in one place so every refusal path is uniform.
void emit_unverifiable(bool json_out, const std::string& reason) {
    if (json_out) {
        std::cout << json{{"verdict", "UNVERIFIABLE"},
                          {"reason",  reason}}.dump() << "\n";
    } else {
        std::cout << "UNVERIFIABLE\n  reason: " << reason << "\n";
    }
}

} // namespace

int verify_state_bundle(const VerifyStateBundleOptions& opts) {
    // ── 1. Load + parse the bundle JSON; validate the envelope schema. ──────
    json bundle;
    {
        std::ifstream f(opts.in_path);
        if (!f) {
            std::cerr << "verify-state-bundle: cannot open --in: "
                      << opts.in_path << "\n";
            return 1;  // IO error
        }
        try {
            f >> bundle;
        } catch (const std::exception& e) {
            emit_unverifiable(opts.json_out,
                std::string("--in is not valid JSON: ") + e.what());
            return 3;
        }
    }

    if (!bundle.is_object()) {
        emit_unverifiable(opts.json_out, "bundle root is not a JSON object");
        return 3;
    }
    // Schema discriminator.
    if (bundle.value("schema", std::string{}) != kSchema) {
        emit_unverifiable(opts.json_out,
            std::string("missing/unknown schema (expected '") + kSchema + "')");
        return 3;
    }
    // Required envelope fields + shapes.
    {
        std::string gh = bundle.value("genesis_hash", std::string{});
        if (gh.size() != 64) {
            emit_unverifiable(opts.json_out,
                "genesis_hash missing or not 64-hex");
            return 3;
        }
    }
    if (!bundle.contains("anchor_block") || !bundle["anchor_block"].is_object()) {
        emit_unverifiable(opts.json_out, "anchor_block missing or not an object");
        return 3;
    }
    if (!bundle.contains("successor_header")
        || !bundle["successor_header"].is_object()) {
        emit_unverifiable(opts.json_out,
            "successor_header missing or not an object");
        return 3;
    }
    if (!bundle.contains("state_proof") || !bundle["state_proof"].is_object()) {
        emit_unverifiable(opts.json_out, "state_proof missing or not an object");
        return 3;
    }

    std::string bundle_ghash = bundle["genesis_hash"].get<std::string>();
    std::string ns  = bundle.value("namespace", std::string{});
    std::string key = bundle.value("key", std::string{});
    uint64_t anchor_index = bundle.value("anchor_index", uint64_t{0});
    const json& successor_header = bundle["successor_header"];
    const json& state_proof      = bundle["state_proof"];

    try {
        // ── 1b. BIND the displayed namespace/key to the PROVEN leaf (fail-fast,
        //        before the crypto gates — it is a pure structural check and is
        //        order-independent). The Merkle proof selects its leaf by
        //        state_proof.key_bytes; the human-readable (namespace,key) is
        //        merely echoed in the VERIFIED output. Without this an attacker
        //        exports an HONEST bundle for key "bob" and edits ONLY
        //        bundle["key"]->"alice": every binding leg still passes (bob's
        //        real leaf + value), but the verifier would report
        //        (alice, bob's balance) — a pair the committee never attested.
        //        Defence: reconstruct the canonical key_bytes from the DISPLAYED
        //        (ns,key) — byte-identical to the daemon's rpc_state_proof
        //        encoding (src/node/node.cpp:3389-3432) + build_state_leaves
        //        (src/chain/chain.cpp) — and require it == state_proof.key_bytes.
        {
            std::vector<uint8_t> expect_key;
            if (ns == "a" || ns == "s" || ns == "r" || ns == "d" || ns == "b" || ns == "k") {
                // simple-key namespaces: "<ns>:" + key (raw string bytes)
                expect_key.push_back(static_cast<uint8_t>(ns[0]));
                expect_key.push_back(':');
                expect_key.insert(expect_key.end(), key.begin(), key.end());
            } else if (ns == "c") {
                // counters: "k:" + "c:" + name (const-leaf naming)
                std::string composite = "c:" + key;
                expect_key.push_back('k');
                expect_key.push_back(':');
                expect_key.insert(expect_key.end(), composite.begin(), composite.end());
            } else if (ns == "i" || ns == "m" || ns == "p") {
                // composite namespaces: key is the hex of the binary body, with
                // an exact width (i=8+32, m=4, p=8+4) so a malformed key can't
                // alias a different leaf.
                std::vector<uint8_t> body;
                try {
                    body = from_hex(key);
                } catch (const std::exception&) {
                    emit_unverifiable(opts.json_out,
                        "composite-namespace key is not valid hex: " + key);
                    return 3;
                }
                size_t want = (ns == "i") ? (8 + 32) : (ns == "m") ? 4u : (8 + 4);
                if (body.size() != want) {
                    emit_unverifiable(opts.json_out,
                        "composite-namespace key wrong length for ns=" + ns
                        + " (expected " + std::to_string(want) + " bytes, got "
                        + std::to_string(body.size()) + ")");
                    return 3;
                }
                expect_key.push_back(static_cast<uint8_t>(ns[0]));
                expect_key.push_back(':');
                expect_key.insert(expect_key.end(), body.begin(), body.end());
            } else {
                emit_unverifiable(opts.json_out,
                    "unsupported namespace '" + ns + "' (use a|s|r|d|b|k|c|i|m|p)");
                return 3;
            }
            std::string expect_key_hex = to_hex(expect_key.data(), expect_key.size());
            std::string proof_key_hex  = state_proof.value("key_bytes", std::string{});
            if (to_lower(proof_key_hex) != to_lower(expect_key_hex)) {
                emit_unverifiable(opts.json_out,
                    "SECURITY: state_proof.key_bytes does not encode the displayed "
                    "namespace/key — the bundle proves a DIFFERENT leaf than it claims. "
                    "displayed (ns=" + ns + ", key=" + key + ") encodes to "
                    + expect_key_hex + " but state_proof.key_bytes=" + proof_key_hex);
                return 3;
            }
        }

        // ── 2. CHAIN-IDENTITY PIN (the SOLE trust anchor). ──────────────────
        // compute_genesis_hash(--genesis) must equal bundle.genesis_hash. This
        // is the one leg that uses compute_genesis_hash (known Windows edge),
        // so it is the SKIP leg on this box; the binding legs below do NOT use
        // it. load_genesis throws on a bad path -> caught -> exit 1 (IO/args).
        auto genesis = load_genesis(opts.genesis_path);
        Hash local_ghash = determ::chain::compute_genesis_hash(genesis);
        std::string local_ghash_hex = to_hex(local_ghash);
        if (to_lower(bundle_ghash) != to_lower(local_ghash_hex)) {
            emit_unverifiable(opts.json_out,
                "GENESIS HASH MISMATCH — bundle.genesis_hash=" + bundle_ghash
                + " but compute_genesis_hash(--genesis)=" + local_ghash_hex
                + " — this bundle was NOT captured from the chain described by "
                  "--genesis; refusing");
            return 3;
        }

        // ── 3. Genesis-seeded committee (mid-chain REGISTER rotation is out of
        //       scope, mirroring trustless_read.hpp). ──────────────────────
        json committee_json =
            build_committee_json(build_genesis_committee(genesis));

        // ── 4. Recompute the anchor block_hash from the FULL body. ──────────
        determ::chain::Block anchor;
        try {
            anchor = determ::chain::Block::from_json(bundle["anchor_block"]);
        } catch (const std::exception& e) {
            emit_unverifiable(opts.json_out,
                std::string("malformed anchor_block: ") + e.what());
            return 3;
        }
        Hash recomputed = anchor.compute_hash();
        std::string recomputed_hex = to_hex(recomputed);

        // ── 5. Verify the SUCCESSOR header's committee sigs (MD, BFT fallback).
        auto vbs = verify_block_sigs(successor_header, committee_json,
                                     /*bft=*/false);
        if (!vbs.ok) {
            vbs = verify_block_sigs(successor_header, committee_json,
                                    /*bft=*/true);
        }
        if (!vbs.ok) {
            emit_unverifiable(opts.json_out,
                "successor committee-sig check failed: " + vbs.detail);
            return 3;
        }

        // ── 6. THE BINDING: successor.prev_hash == recomputed anchor block_hash.
        //       A daemon that swapped the anchor's state_root FIELD (which is
        //       inside signing_bytes -> block_hash) produces a recomputed
        //       block_hash that no longer matches the prev_hash the committee
        //       signed over.
        std::string succ_prev =
            successor_header.value("prev_hash", std::string{});
        if (succ_prev != recomputed_hex) {
            emit_unverifiable(opts.json_out,
                "SECURITY: successor prev_hash != recomputed anchor block_hash "
                "— bundle forged (e.g. swapped anchor state_root). "
                "successor.prev_hash=" + succ_prev
                + " recomputed=" + recomputed_hex);
            return 3;
        }

        // ── 7. The proof is anchored at the BOUND block: its claimed root must
        //       equal the anchor's state_root. ──────────────────────────────
        Hash zero{};
        if (anchor.state_root == zero) {
            emit_unverifiable(opts.json_out,
                "anchor block carries a zero/unpopulated state_root (pre-S-033 "
                "block) — nothing to anchor a state-proof against");
            return 3;
        }
        std::string anchor_root_hex = to_hex(anchor.state_root);
        std::string proof_root = state_proof.value("state_root", std::string{});
        if (to_lower(proof_root) != to_lower(anchor_root_hex)) {
            emit_unverifiable(opts.json_out,
                "state_proof.state_root=" + proof_root
                + " != bound anchor.state_root=" + anchor_root_hex);
            return 3;
        }

        // ── 8. Merkle-verify the proof against the BOUND root (NOT the proof's
        //       self-claimed root). ─────────────────────────────────────────
        auto vsp = verify_state_proof(state_proof, anchor_root_hex);
        if (!vsp.ok) {
            emit_unverifiable(opts.json_out,
                "state-proof Merkle verification failed: " + vsp.detail);
            return 3;
        }

        // ── 9. ns=="a" + account_cleartext present: recompute value_hash and
        //       match the proof's value_hash (mirror read_account_trustless). ─
        uint64_t balance = 0, next_nonce = 0;
        bool have_cleartext = false;
        if (ns == "a" && bundle.contains("account_cleartext")
            && bundle["account_cleartext"].is_object()) {
            have_cleartext = true;
            const json& ac = bundle["account_cleartext"];
            balance    = ac.value("balance",    uint64_t{0});
            next_nonce = ac.value("next_nonce", uint64_t{0});

            determ::crypto::SHA256Builder b;
            b.append(balance);
            b.append(next_nonce);
            Hash computed_vh = b.finalize();

            Hash proof_vh;
            try {
                proof_vh = from_hex_arr<32>(
                    state_proof.at("value_hash").get<std::string>());
            } catch (const std::exception& e) {
                emit_unverifiable(opts.json_out,
                    std::string("state_proof.value_hash malformed: ")
                    + e.what());
                return 3;
            }
            if (computed_vh != proof_vh) {
                emit_unverifiable(opts.json_out,
                    "account_cleartext (balance=" + std::to_string(balance)
                    + ", next_nonce=" + std::to_string(next_nonce)
                    + ") hashes to " + to_hex(computed_vh)
                    + " but state-proof value_hash is " + to_hex(proof_vh)
                    + " — cleartext does not match the committed leaf");
                return 3;
            }
        }

        // ── 10. SUCCESS. ────────────────────────────────────────────────────
        if (opts.json_out) {
            json out = {
                {"verdict",      "VERIFIED"},
                {"namespace",    ns},
                {"key",          key},
                {"anchor_index", anchor_index},
                {"state_root",   anchor_root_hex},
                {"value_hash",   state_proof.value("value_hash", std::string{})},
            };
            if (have_cleartext) {
                out["balance"]    = balance;
                out["next_nonce"] = next_nonce;
            }
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "VERIFIED\n"
                      << "  genesis pin:  matches (" << local_ghash_hex << ")\n"
                      << "  namespace:    " << ns << "\n"
                      << "  key:          " << key << "\n"
                      << "  anchor_index: " << anchor_index << "\n"
                      << "  state_root:   " << anchor_root_hex << "\n"
                      << "  value_hash:   "
                      << state_proof.value("value_hash", std::string{}) << "\n";
            if (have_cleartext) {
                std::cout << "  balance:      " << balance << "\n"
                          << "  next_nonce:   " << next_nonce << "\n";
            }
            std::cout << "  binding:      successor(" << (anchor_index + 1)
                      << ").prev_hash == recomputed anchor block_hash "
                         "(committee-signed)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        // load_genesis / unexpected throws — treat as args/IO unless clearly a
        // tamper. load_genesis failures are the args/IO class -> exit 1.
        std::cerr << "verify-state-bundle: " << e.what() << "\n";
        return 1;
    }
}

} // namespace determ::light
