// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verifier implementation.
//
// Ports the chain-of-hashes + committee-sig + merkle-proof primitives
// from src/main.cpp's `cmd_verify_headers` (line 1814),
// `cmd_verify_block_sigs` (line 1613), and the `verify-state-proof`
// handler (around line 5471). The factoring is cleaner here because
// the light-client treats verification as a structured returns-result
// (VerifyResult) — the original CLI handlers stream diagnostics to
// stderr and return process exit codes; this rewrite separates the
// "did it verify" from the "how to report it" concerns so composite
// commands can chain verifications without re-parsing.

#include "verify.hpp"
#include <determ/crypto/keys.hpp>
#include <determ/crypto/merkle.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/util/json_validate.hpp>
#include <determ/types.hpp>
#include <determ/chain/block.hpp>
#include <set>
#include <vector>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;
using determ::util::json_require;
using determ::util::json_require_hex;
using determ::util::json_require_array;

namespace {

// ── F2 digest helpers — byte-exact re-implementations of producer.cpp's
//    {hash_cross_shard_receipt, hash_equivocation_event, hash_abort_event,
//    compute_view_root} (src/node/producer.cpp:322-382). The light client does
//    NOT link producer.cpp (deliberate minimal footprint, see CMakeLists.txt's
//    explicit reuse list), so these four are duplicated here and pinned
//    BYTE-FOR-BYTE against the originals by tools/test_block_digest_xbinary_
//    parity.sh. The DTM-F2-* domain tags + field order + append static-types
//    MUST match producer.cpp exactly, or an F2 block's committee signature will
//    not verify. Field order / casts copied verbatim from producer.cpp. ───────
using determ::crypto::SHA256Builder;

Hash hash_cross_shard_receipt(const determ::chain::CrossShardReceipt& r) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-RCPT-v1"));
    b.append(static_cast<uint64_t>(r.src_shard));
    b.append(static_cast<uint64_t>(r.dst_shard));
    b.append(r.src_block_index);
    b.append(r.src_block_hash);
    b.append(r.tx_hash);
    b.append(r.from);
    b.append(r.to);
    b.append(r.amount);
    b.append(r.fee);
    b.append(r.nonce);
    return b.finalize();
}

Hash hash_equivocation_event(const determ::chain::EquivocationEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-EQ-v1"));
    b.append(e.equivocator);
    b.append(e.block_index);
    b.append(e.digest_a);
    b.append(e.sig_a.data(), e.sig_a.size());
    b.append(e.digest_b);
    b.append(e.sig_b.data(), e.sig_b.size());
    b.append(static_cast<uint64_t>(e.shard_id));
    b.append(e.beacon_anchor_height);
    return b.finalize();
}

Hash hash_abort_event(const determ::chain::AbortEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-ABORT-v1"));
    b.append(e.round);
    b.append(e.aborting_node);
    b.append(static_cast<uint64_t>(e.timestamp));
    b.append(e.event_hash);
    b.append(e.claims_json.dump());
    return b.finalize();
}

Hash compute_view_root(const std::vector<Hash>& items) {
    std::set<Hash> u(items.begin(), items.end());
    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

}  // namespace

// COPY OF producer.cpp::compute_block_digest (src/node/producer.cpp:619-731) — keep in sync.
//
// Computes the digest the K-of-K committee signs in Phase 2. The light
// client must recompute this byte-for-byte to verify each committee
// member's Ed25519 signature against compute_block_digest(block). The
// upstream source lives at src/node/producer.cpp:619-704; if the
// upstream byte-order or field set ever changes, mirror it here. The
// tools/test_block_digest_xbinary_parity.sh guard pins the two append
// sequences EQUAL token-for-token.
//
// FULL PARITY (F-7): this is now a byte-for-byte mirror of the node's
// compute_block_digest — it binds EVERY field the node does, including the
// three conditional F2 view roots (inbound_receipts / equivocation_events /
// abort_events) and the merged-block tail (partner_subset_hash, timestamp).
// All appends are gated on the SAME data-driven conditions as the node, so:
//   * fed an rpc_headers-STRIPPED header (heavy F2 collections removed,
//     view roots zero), every F2 gate is false → the digest collapses to the
//     v1 core, byte-identical to a non-F2 header. Header-only sync of non-F2
//     blocks is unchanged.
//   * fed a FULL block (the walk re-fetches the full body for any header whose
//     stripped digest fails to verify — trustless_read.cpp::verify_chain_walk's
//     F2 fallback), the collections are populated → the light client binds the
//     same inbound/eq/abort roots the committee signed and VERIFIES the
//     cross-shard / reconciled block (previously this fail-closed: F-7).
// (transactions / cross_shard_receipts / initial_state / state_root are not in
// the digest at all.) If the upstream byte-order or field set ever changes,
// mirror it here.
Hash light_compute_block_digest(const determ::chain::Block& b) {
    determ::crypto::SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    // v2.7 F2 / S-016 + S-030-D2 (F-7): bind the three F2 sets EXACTLY as the
    // node's compute_block_digest does (producer.cpp:632-672). All three gates
    // are data-driven and identical to the node's: on a STRIPPED header these
    // collections are empty / view roots zero, so every gate is false and the
    // digest stays byte-identical to the v1 core; on a FULL block (re-fetched by
    // the walk's F2 fallback) they are populated and the light client binds the
    // same roots the committee signed — so it now verifies cross-shard /
    // reconciled blocks rather than fail-closing on them. Field order matches
    // the node: inbound, eq, abort, partner_subset_hash, timestamp.
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        ikeys.reserve(b.inbound_receipts.size());
        for (auto& r : b.inbound_receipts) ikeys.push_back(hash_cross_shard_receipt(r));
        h.append(compute_view_root(ikeys));
    }
    auto any_nonzero = [](const std::vector<Hash>& v) {
        Hash z{};
        for (auto& r : v) if (r != z) return true;
        return false;
    };
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        ekeys.reserve(b.equivocation_events.size());
        for (auto& e : b.equivocation_events) ekeys.push_back(hash_equivocation_event(e));
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        akeys.reserve(b.abort_events.size());
        for (auto& a : b.abort_events) akeys.push_back(hash_abort_event(a));
        h.append(compute_view_root(akeys));
    }
    // S-030-D2 (partner_subset_hash dimension): bind when non-zero, exactly
    // mirroring producer.cpp::compute_block_digest's trailing conditional
    // append. Deterministic field that survives the header strip, so this
    // keeps the light digest byte-identical to the node's for merged blocks
    // (and byte-identical to the v1 digest for every non-merged header).
    Hash zero{};
    if (b.partner_subset_hash != zero) {
        h.append(b.partner_subset_hash);
    }
    // S-030-D2 (timestamp dimension): bind the canonical block timestamp when
    // the header carries per-creator proposer times (a reconciled block) —
    // again mirroring producer.cpp::compute_block_digest. creator_proposer_times
    // survives the rpc_headers strip (it is not one of the four stripped heavy
    // collections), so the light client has both it AND b.timestamp and binds
    // the same value the committee signed. A header where a daemon tampered the
    // timestamp post-signing then fails the sig check (the digest no longer
    // matches the K signatures). Empty (legacy header) appends nothing → v1
    // digest. Field order matches the node: ..., partner_subset_hash, timestamp.
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    // A6 / §7.5.1: bind signature_form when non-zero, exactly mirroring
    // producer.cpp::compute_block_digest's trailing conditional append. The
    // scalar survives the rpc_headers strip, so light and node digest the
    // identical value; form-0 (every v1.1 block) appends nothing → v1
    // digest. Field order matches the node: ..., partner_subset_hash,
    // timestamp, signature_form.
    if (b.signature_form != 0) {
        h.append(static_cast<uint8_t>(b.signature_form));
    }
    // D3.4 / S-036: bind the source shard's eligible_count when non-zero,
    // exactly mirroring producer.cpp::compute_block_digest's trailing append.
    // The u32 count survives the rpc_headers strip, so light and node digest
    // the identical value (widened to u64 to match the node's canonical field
    // encoding); zero (every SINGLE/CURRENT/BEACON block) appends nothing → v1
    // digest. Field order matches the node: ..., signature_form, eligible_count.
    if (b.eligible_count != 0) {
        h.append(static_cast<uint64_t>(b.eligible_count));
    }
    return h.finalize();
}

nlohmann::json pad_stripped_header(nlohmann::json h) {
    if (!h.contains("transactions"))         h["transactions"]         = json::array();
    if (!h.contains("cross_shard_receipts")) h["cross_shard_receipts"] = json::array();
    if (!h.contains("inbound_receipts"))     h["inbound_receipts"]     = json::array();
    if (!h.contains("initial_state"))        h["initial_state"]        = json::array();
    return h;
}

std::map<std::string, PubKey>
parse_committee(const nlohmann::json& committee_json) {
    nlohmann::json members;
    if (committee_json.is_array()) {
        members = committee_json;
    } else if (committee_json.is_object()
               && committee_json.contains("members")
               && committee_json["members"].is_array()) {
        members = committee_json["members"];
    } else {
        throw std::runtime_error(
            "committee file must be a JSON array or "
            "an object with a 'members' array");
    }
    std::map<std::string, PubKey> pubkey_of;
    for (auto& m : members) {
        std::string domain = m.value("domain", std::string{});
        std::string ed_hex = m.value("ed_pub", std::string{});
        if (domain.empty() || ed_hex.empty()) continue;
        if (ed_hex.size() != 64) {
            throw std::runtime_error(
                "committee member '" + domain
                + "' has malformed ed_pub (expected 64 hex chars, got "
                + std::to_string(ed_hex.size()) + ")");
        }
        pubkey_of[domain] = from_hex_arr<32>(ed_hex);
    }
    if (pubkey_of.empty()) {
        throw std::runtime_error("committee file has no valid members");
    }
    return pubkey_of;
}

VerifyResult verify_headers(const nlohmann::json& headers_json,
                             const std::string& genesis_hash_hex,
                             const std::string& prev_hash_hex) {
    VerifyResult r;

    if (!headers_json.contains("headers") || !headers_json["headers"].is_array()) {
        r.detail = "input missing 'headers' array (expected rpc_headers reply)";
        return r;
    }
    auto& headers = headers_json["headers"];
    if (headers.empty()) {
        r.ok = true;
        r.detail = "empty headers slice, nothing to verify";
        return r;
    }

    auto h_get = [](const json& h, const char* field,
                    size_t expected_chars) -> std::string {
        if (!h.contains(field) || !h[field].is_string()) {
            throw std::runtime_error(
                std::string("header missing '") + field + "' field");
        }
        std::string s = h[field].get<std::string>();
        if (s.size() != expected_chars) {
            throw std::runtime_error(
                std::string("header '") + field
                + "' has wrong length: expected "
                + std::to_string(expected_chars) + " chars, got "
                + std::to_string(s.size()));
        }
        return s;
    };

    try {
        uint64_t first_index = headers[0].value("index", uint64_t{0});
        std::string first_prev = h_get(headers[0], "prev_hash", 64);

        if (first_index == 0) {
            // RESUME-SOUNDNESS GATE: if the caller supplied a mid-chain anchor
            // (prev_hash_hex non-empty), a header claiming genesis (index 0) is
            // illegal — reject it. Without this, a malicious daemon serving a
            // resume suffix could set index=0 to divert into this binding-free
            // genesis branch (when genesis_hash_hex is empty) and thereby dodge
            // BOTH the anchor prev_hash check below AND the caller's per-block
            // committee-sig check (which skips index 0). See the index-contiguity
            // gate in trustless_read.cpp::verify_chain_walk for the paired defense.
            if (!prev_hash_hex.empty()) {
                r.detail = "FAIL: header claims genesis (index 0) but a mid-chain "
                           "prev_hash anchor was supplied — refusing to treat a "
                           "suffix header as genesis";
                return r;
            }
            std::string zero64(64, '0');
            if (first_prev != zero64) {
                r.detail = "FAIL: genesis header (index 0) has non-zero prev_hash: "
                         + first_prev;
                return r;
            }
            if (!genesis_hash_hex.empty()) {
                std::string gh = h_get(headers[0], "block_hash", 64);
                if (gh != genesis_hash_hex) {
                    r.detail = "FAIL: genesis block_hash mismatch — "
                               "header reports " + gh
                             + ", supplied genesis-hash " + genesis_hash_hex;
                    return r;
                }
            }
        } else if (!prev_hash_hex.empty()) {
            if (first_prev != prev_hash_hex) {
                r.detail = "FAIL: first header's prev_hash doesn't match supplied "
                           "--prev-hash (header prev_hash=" + first_prev
                         + ", --prev-hash=" + prev_hash_hex + ")";
                return r;
            }
        }

        // Walk consecutive header pairs and verify prev_hash chain.
        for (size_t i = 1; i < headers.size(); ++i) {
            std::string prev = h_get(headers[i], "prev_hash", 64);
            std::string prior_hash = h_get(headers[i - 1], "block_hash", 64);
            if (prev != prior_hash) {
                r.detail = "FAIL: prev_hash chain break at header "
                         + std::to_string(i) + " (index "
                         + std::to_string(headers[i].value("index", uint64_t{0}))
                         + "): prev_hash=" + prev
                         + ", prior block_hash=" + prior_hash;
                return r;
            }
        }

        r.ok = true;
        r.count = headers.size();
        r.block_hash_hex = h_get(headers.back(), "block_hash", 64);
        return r;
    } catch (std::exception& e) {
        r.detail = std::string("verify-headers: ") + e.what();
        return r;
    }
}

VerifyResult verify_block_sigs(const nlohmann::json& header_in,
                                const nlohmann::json& committee_json,
                                bool bft_mode) {
    VerifyResult r;

    // Accept either an rpc_headers envelope or a single header object.
    nlohmann::json header_json = header_in;
    if (header_json.contains("headers") && header_json["headers"].is_array()) {
        if (header_json["headers"].empty()) {
            r.detail = "header file has empty 'headers' array";
            return r;
        }
        header_json = header_json["headers"][0];
    }

    header_json = pad_stripped_header(std::move(header_json));

    determ::chain::Block b;
    try {
        b = determ::chain::Block::from_json(header_json);
    } catch (const std::exception& e) {
        r.detail = std::string("malformed header: ") + e.what();
        return r;
    }

    std::map<std::string, PubKey> pubkey_of;
    try {
        pubkey_of = parse_committee(committee_json);
    } catch (const std::exception& e) {
        r.detail = e.what();
        return r;
    }

    for (auto& d : b.creators) {
        if (pubkey_of.find(d) == pubkey_of.end()) {
            r.detail = "FAIL: creator '" + d
                     + "' is not in the supplied committee";
            return r;
        }
    }
    if (b.creator_block_sigs.size() != b.creators.size()) {
        r.detail = "FAIL: creator_block_sigs.size ("
                 + std::to_string(b.creator_block_sigs.size())
                 + ") != creators.size ("
                 + std::to_string(b.creators.size()) + ")";
        return r;
    }

    Hash digest = light_compute_block_digest(b);

    Signature zero_sig{};
    size_t valid = 0;
    for (size_t i = 0; i < b.creators.size(); ++i) {
        const auto& sig = b.creator_block_sigs[i];
        if (sig == zero_sig) {
            if (!bft_mode) {
                r.detail = "FAIL: creator[" + std::to_string(i) + "] '"
                         + b.creators[i]
                         + "' has sentinel-zero signature in MD mode";
                return r;
            }
            continue;
        }
        const auto& pk = pubkey_of.at(b.creators[i]);
        if (determ::crypto::verify(pk, digest.data(), digest.size(), sig)) {
            valid++;
        } else {
            r.detail = "FAIL: creator[" + std::to_string(i) + "] '"
                     + b.creators[i]
                     + "' signature does NOT verify against block_digest";
            return r;
        }
    }

    size_t required = bft_mode
        ? (2 * b.creators.size() + 2) / 3
        : b.creators.size();

    if (valid < required) {
        r.detail = "FAIL: only " + std::to_string(valid)
                 + " sigs verify (required " + std::to_string(required)
                 + " of " + std::to_string(b.creators.size()) + ")";
        return r;
    }

    r.ok = true;
    r.count = valid;
    r.digest_hex = to_hex(digest);
    Hash zero_hash{};
    if (b.state_root != zero_hash) {
        r.state_root_hex = to_hex(b.state_root);
    }
    return r;
}

VerifyResult verify_state_proof(const nlohmann::json& proof_json,
                                  const std::string& expected_root_hex) {
    VerifyResult r;

    if (proof_json.contains("error") && !proof_json["error"].is_null()) {
        r.detail = "RPC error in proof: " + proof_json["error"].dump();
        return r;
    }

    Hash claimed_root;
    std::vector<uint8_t> key_bytes;
    Hash value_hash;
    size_t target_index = 0;
    size_t leaf_count = 0;
    std::vector<Hash> proof_sibs;

    try {
        claimed_root = from_hex_arr<32>(
            json_require_hex(proof_json, "state_root", 64));
        std::string kb_hex = json_require<std::string>(proof_json, "key_bytes");
        key_bytes = from_hex(kb_hex);
        value_hash = from_hex_arr<32>(
            json_require_hex(proof_json, "value_hash", 64));
        target_index = json_require<size_t>(proof_json, "target_index");
        leaf_count   = json_require<size_t>(proof_json, "leaf_count");
        for (auto& h : json_require_array(proof_json, "proof")) {
            proof_sibs.push_back(from_hex_arr<32>(h.get<std::string>()));
        }
    } catch (const std::exception& e) {
        r.detail = std::string("malformed proof: ") + e.what();
        return r;
    }

    Hash verify_root = claimed_root;
    if (!expected_root_hex.empty()) {
        if (expected_root_hex.size() != 64) {
            r.detail = "--state-root must be 64 hex chars (32 bytes), got "
                     + std::to_string(expected_root_hex.size());
            return r;
        }
        try {
            verify_root = from_hex_arr<32>(expected_root_hex);
        } catch (const std::exception& e) {
            r.detail = std::string("--state-root parse error: ") + e.what();
            return r;
        }
    }

    bool ok = determ::crypto::merkle_verify(
        verify_root, key_bytes, value_hash,
        target_index, leaf_count, proof_sibs);
    if (!ok) {
        r.detail = "FAIL: merkle_verify rejected the proof (verify_root="
                 + to_hex(verify_root).substr(0, 16) + "..., target_index="
                 + std::to_string(target_index) + ", leaf_count="
                 + std::to_string(leaf_count) + ", sibs="
                 + std::to_string(proof_sibs.size()) + ")";
        return r;
    }

    r.ok = true;
    r.count = proof_sibs.size();
    r.state_root_hex = to_hex(verify_root);
    return r;
}

} // namespace determ::light
