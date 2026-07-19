// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// Canonical serialization of an abort event's claims array for the CONSENSUS
// DIGEST (hash_abort_event → the K-of-K-signed block digest).
//
// WHY THIS EXISTS
// ---------------
// hash_abort_event() SHA-256s the abort event's `claims_json` into the block
// digest (src/node/producer.cpp, mirrored byte-for-byte in light/verify.cpp).
// AbortEvent::from_json (src/chain/block.cpp) stores `claims_json` VERBATIM
// from peer JSON — and nlohmann keeps UNKNOWN object members. Per-claim
// validation (AbortClaimMsg::from_json → check_abort_certs / on_abort_event)
// reads only the six named fields and ignores extras; the per-claim Ed25519
// signature (make_abort_claim_message) covers only
// block_index‖round‖prev_hash‖missing_creator — NOT the JSON. So a legitimate
// abort claimant (or the producer) could inject an arbitrary extra member
// (e.g. `"z":0.1`) into an otherwise-valid claim and it would ride the signed
// digest as non-semantic, attacker-controlled bytes.
//
// This helper rebuilds each claim from ONLY the six consensus-bound fields, in
// nlohmann's sorted-key dump order, stripping any unknown members before the
// hash. The digest then binds only semantic content.
//
// BYTE-NEUTRAL for honest chains: an honest claim already has exactly those six
// keys (as produced by AbortClaimMsg::to_json), so the rebuilt object dumps
// byte-identically to the original — the digest of every honest abort block is
// UNCHANGED (no fork, no golden migration). Only a claim carrying injected
// members produces different (now-canonical) bytes.
//
// ONE SHARED HELPER (S-043 discipline): BOTH the daemon (producer.cpp) and the
// light-client mirror (light/verify.cpp) call this exact function, so their
// digests cannot drift on a canonicalization detail (a hand-mirrored copy
// could). It depends on nothing but nlohmann, so both binaries can include it.
//
// FALLBACK: if any claim cannot be canonicalized (not an object, or missing a
// required key — a MALFORMED claim that per-claim validation rejects before any
// such block is accepted), fall back to the verbatim dump, preserving the prior
// behavior exactly and never throwing on the digest path.
//
// The equivocation_events dimension needs no analogue: hash_equivocation_event
// hashes the typed EquivocationEvent struct fields directly (never a verbatim
// claims_json.dump()), so it has no unknown-member exposure.

#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace determ::chain {

// Lowercase the ASCII hex letters A-F of a hex string, so an upper/mixed-case
// hex value (which validation accepts case-insensitively via from_hex, and the
// per-claim signature covers as decoded BYTES, not as the string) canonicalizes
// to one form. Byte-neutral for honest claims (already lowercase from to_hex).
inline std::string lower_hex_ascii(std::string s) {
    for (char& ch : s)
        if (ch >= 'A' && ch <= 'F') ch = static_cast<char>(ch - 'A' + 'a');
    return s;
}

// The six consensus-bound abort-claim fields, matching AbortClaimMsg::to_json
// (src/node/producer.cpp). Kept here so the daemon and the light client rebuild
// the identical key set.
//
// Each field is re-derived through its TYPED parse rather than copied verbatim.
// This matters for consensus: nlohmann's get<uint64_t>() on a number_float
// TRUNCATES without throwing (exactly like json_require, so validation also
// accepts it), so a verbatim copy of `"block_index":10.9` would leave the
// attacker-chosen ".9" (or a float-encoded `10.0`, `1e1`, ...) in the hashed
// bytes — a numeric-VALUE channel equivalent to the unknown-MEMBER one. Parsing
// to uint64/uint8 and re-emitting collapses every encoding of the same integer
// to one canonical form; lowercasing the two hex fields does the same for hex
// case. So the digest binds only semantic content. Strings that are semantic
// identifiers (missing_creator, claimer) are copied verbatim — they are NOT
// hex and are case-sensitive account names.
//
// BYTE-NEUTRAL for honest claims: an honest block_index/round is already an
// integer json (get<uintN> round-trips to the identical bytes), honest hex is
// already lowercase, and honest strings are unchanged — so canonical == verbatim
// and every honest abort block's digest is UNCHANGED.
inline std::string canonical_abort_claims_dump(const nlohmann::json& claims) {
    if (!claims.is_array()) return claims.dump();
    try {
        nlohmann::json canon = nlohmann::json::array();
        for (const auto& cj : claims) {
            if (!cj.is_object()) throw std::runtime_error("abort claim not an object");
            nlohmann::json c;
            // Integers re-derived through the typed parse (collapses float/other
            // encodings of the same value); a non-number throws → the same
            // fallback per-claim validation would reject on.
            c["block_index"]     = cj.at("block_index").get<uint64_t>();
            c["round"]           = cj.at("round").get<uint8_t>();
            // Hex fields: typed string + lowercase (canonicalize hex case).
            c["prev_hash"]       = lower_hex_ascii(cj.at("prev_hash").get<std::string>());
            c["ed_sig"]          = lower_hex_ascii(cj.at("ed_sig").get<std::string>());
            // Semantic identifiers: verbatim (case-sensitive, not hex).
            c["missing_creator"] = cj.at("missing_creator").get<std::string>();
            c["claimer"]         = cj.at("claimer").get<std::string>();
            canon.push_back(std::move(c));
        }
        return canon.dump();
    } catch (...) {
        // Malformed claim (rejected upstream by per-claim validation): preserve
        // the prior verbatim bytes so this never changes an accepted block's
        // digest nor throws on the hash path.
        return claims.dump();
    }
}

}  // namespace determ::chain
