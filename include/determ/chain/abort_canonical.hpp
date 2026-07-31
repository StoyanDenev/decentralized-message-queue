// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// Canonical form of an abort event's claims array. Applied at BOTH ends of the
// claim's life: on INGEST (AbortEvent::from_json stores the canonical rebuild)
// and on the CONSENSUS DIGEST (hash_abort_event → the K-of-K-signed digest).
//
// WHY THIS EXISTS
// ---------------
// hash_abort_event() SHA-256s the abort event's `claims_json` into the block
// digest (src/node/producer.cpp, mirrored byte-for-byte in light/verify.cpp).
// nlohmann keeps UNKNOWN object members, and per-claim validation
// (AbortClaimMsg::from_json → check_abort_certs / on_abort_event) reads only
// the six named fields and ignores extras; the per-claim Ed25519 signature
// (make_abort_claim_message) covers only
// block_index‖round‖prev_hash‖missing_creator — NOT the JSON. Block::
// signing_bytes appends only `ae.event_hash`. So a legitimate abort claimant
// (or the producer) could inject an arbitrary extra member (e.g. `"z":0.1`)
// into an otherwise-valid claim, and honest validators would sign the block
// with those non-semantic, attacker-controlled bytes riding inside it.
//
// This helper rebuilds each claim from ONLY the six consensus-bound fields, in
// nlohmann's sorted-key dump order, stripping any unknown members. The digest
// then binds only semantic content.
//
// WHY IT ALSO RUNS ON INGEST (F-10, round-13 hostile-wire audit)
// -------------------------------------------------------------
// Canonicalizing the DIGEST alone left the injected bytes in the stored block
// body, which `to_json` re-emits verbatim. Because `claims_json` was
// schema-free, an injected member could nest arbitrarily deep — and the WIRE-2
// structural ceiling (net/messages.hpp kMaxJsonDepth) is ENVELOPE-RELATIVE:
// the same claim object sits at depth 5 under ABORT_EVENT, 6 under BLOCK and 8
// under CHAIN_RESPONSE. A claim nested L ∈ {57,58} levels deep was therefore
// ACCEPTED on every ingest path and REJECTED on every serve path, so a block
// carrying it committed fleet-wide but could never be re-served — and WIRE-3
// turned that from a dropped frame into a disconnect loop. No new node could
// sync past that height. (The band is exactly 2 wide at ANY cap value, so
// retuning the cap does not remove it; and dropping the depth ceiling trades
// the wedge for the dump() recursion crash — see S022WireFormatCaps.md §2.3.)
//
// Storing the canonical rebuild closes the entire unknown-member channel at
// its source: the stored claim is six scalars, so it contributes ZERO nesting
// and no injected content survives to be re-served. Depth is now a property of
// the SCHEMA again, which is what the ceiling was sized against.
//
// CONSENSUS-BYTE-NEUTRAL FOR EVERY INPUT, not just honest ones. The digest
// path applies this same function, and it is IDEMPOTENT (canon∘canon = canon:
// the ints re-read to themselves, lower_hex_ascii is a no-op on lowercase, the
// strings are copied, and nlohmann's object_t is std::map so key order is
// sorted regardless of insertion order). So for a claim that canonicalizes,
// hashing the stored canonical form == hashing the canonical form of the
// verbatim peer bytes; and for one that does NOT, ingest keeps the verbatim
// bytes and the digest is unchanged by construction. Every block's hash is
// therefore identical before and after this change — no fork, no golden
// migration, and no accept/reject decision moves.
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
// FALLBACK — keep the verbatim value; do NOT reject. If any claim cannot be
// canonicalized, this returns the input unchanged, so it never throws on the
// digest path and never moves an accept/reject decision.
//
// That is SOUND rather than a hole, because canonicalization is strictly
// WEAKER than per-claim validation, so nothing that survives validation can
// land in the fallback. Field for field: this reads `at(k).get<T>()` while
// AbortClaimMsg::from_json reads `json_require<T>(j,k)` — which is
// `contains(k)` + the identical `at(k).get<T>()` — and for the two hex fields
// validation ALSO enforces the exact hex length. A non-object claim, or a
// non-array `claims`, is rejected by the array/shape checks in
// check_abort_certs and Node::on_abort_event. Hence: canonicalization throws
// ⟹ validation throws ⟹ no such block is ever accepted, so the fallback
// cannot be used to smuggle un-stripped bytes into a committed block. The
// gate `test-abort-claims-canonical` pins that implication directly.
//
// Rejecting instead would be strictly worse: from_json throwing is a parse
// failure, and under WIRE-3 a parse failure now CLOSES THE PEER — turning a
// malformed gossiped claim into a disconnect, an availability regression for
// no security gain.
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
//
// Returns the canonical VALUE. `canonical_abort_claims_dump` (the digest form)
// is defined in terms of this one, so the bytes the digest commits to and the
// bytes AbortEvent::from_json stores can never drift apart — the S-043 "one
// shared helper per consensus formula" rule applied across the two call sites.
inline nlohmann::json canonical_abort_claims(const nlohmann::json& claims) {
    if (!claims.is_array()) return claims;
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
        return canon;
    } catch (...) {
        // Malformed claim (rejected upstream by per-claim validation): preserve
        // the verbatim value so this never changes an accepted block's digest
        // nor throws on the hash path. See the FALLBACK note above for why no
        // validation-surviving claim can reach here.
        return claims;
    }
}

// Digest form: the canonical value's dump. This is what hash_abort_event()
// SHA-256s, in the daemon AND in the light-client mirror (light/verify.cpp).
//
// Cost note (this splitting is not free on one path, so it is stated rather
// than glossed): on the HONEST path `canon` is constructed straight into the
// return slot and dumped from there, so this is the same work the single
// function did before the split. Only the FALLBACK arm — reached exclusively by
// a malformed claim, which validation then rejects — now copies the input where
// it previously dumped it in place. That copy is bounded by the WIRE-2 DOM
// ceiling and leads to immediate rejection, so it is an error-path constant, not
// a new amplification path.
inline std::string canonical_abort_claims_dump(const nlohmann::json& claims) {
    return canonical_abort_claims(claims).dump();
}

}  // namespace determ::chain
