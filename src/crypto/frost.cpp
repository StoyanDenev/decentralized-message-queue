//
// FROST-Ed25519 threshold signature primitives (v2.10 Phase A SCAFFOLDING).
//
// As of this commit: function signatures from `include/determ/crypto/frost.hpp`
// are declared so dependent code (DKG ceremony in Phase B, threshold-sig
// integration in Phase D) can be drafted against them. The implementations
// throw `std::logic_error("v2.10 Phase A not yet implemented: <fn>")` until
// the RFC 9591 logic is ported onto libsodium.
//
// Each placeholder is intentionally a runtime throw rather than a compile
// error so callers can be drafted + reviewed before the cryptographic
// primitives are wired. Once Phase A ships proper, only this file changes;
// no downstream consumer's signature changes.
//
// === Phase A implementation work order (deferred) ===
//
//   1. H1 sub-hash (rho): `H1(...) = SHA-512(domain_separator || ...)` mod L
//   2. H2 sub-hash (challenge): `H2(R || group_pubkey || message)` mod L
//   3. H3, H4, H5 sub-hashes per RFC 9591 §6.6
//   4. Polynomial evaluation in `F_L` (scalar arithmetic via crypto_core_ed25519_*)
//   5. Multi-scalar multiplication (`crypto_scalarmult_ed25519`)
//   6. Lagrange interpolation in `F_L`
//   7. Round 1 commitment computation
//   8. Round 2 share computation
//   9. PoP Schnorr signature
//  10. Sign Round 1 nonce generation
//  11. Sign Round 2 partial-sig computation
//  12. Aggregation
//  13. Verify (delegate to crypto_sign_verify_detached over canonical R||z)
//
// Estimated total: 2-3 days for an experienced FROST implementer; this
// file's "scaffolding-only" form lets the rest of the v2.10 work (DKG
// ceremony state machine, epoch-boundary orchestration, wire-format
// extensions) be drafted in parallel with the primitives once they land.

#include <determ/crypto/frost.hpp>
#include <determ/crypto/keys.hpp>

namespace determ::crypto::frost {

[[noreturn]] static void unimplemented(const char* fn) {
    throw std::logic_error(
        std::string("v2.10 Phase A not yet implemented: ") + fn +
        " (see docs/proofs/F2-V210-IMPLEMENTATION-PLAN.md Phase A)");
}

KeygenRound1Output frost_keygen_round1(Identifier /*self_id*/,
                                         uint16_t /*t*/, uint16_t /*n*/) {
    unimplemented("frost_keygen_round1");
}

KeygenRound2Output frost_keygen_round2(
    const KeygenRound1Output& /*round1_output*/,
    Identifier /*self_id*/, uint16_t /*n*/) {
    unimplemented("frost_keygen_round2");
}

LocalShare frost_keygen_finalize(
    Identifier /*self_id*/, uint16_t /*t*/, uint16_t /*n*/,
    const KeygenRound1Output& /*my_round1*/,
    const KeygenRound2Output& /*my_round2*/,
    const std::vector<std::pair<Identifier, KeygenRound1Output>>& /*peer_round1s*/,
    const std::vector<std::pair<Identifier, KeygenRound2Output>>& /*peer_round2s*/) {
    unimplemented("frost_keygen_finalize");
}

SignRound1Output frost_sign_round1(const LocalShare& /*my_share*/) {
    unimplemented("frost_sign_round1");
}

Scalar frost_sign_round2(const LocalShare& /*my_share*/,
                          const SignRound1Output& /*my_round1*/,
                          const CommitmentMap& /*all_commitments*/,
                          const std::vector<uint8_t>& /*message*/) {
    unimplemented("frost_sign_round2");
}

FrostSig frost_aggregate(
    const CommitmentMap& /*commitments*/,
    const std::vector<std::pair<Identifier, Scalar>>& /*partial_sigs*/,
    const std::vector<uint8_t>& /*message*/,
    const Point& /*group_pubkey*/) {
    unimplemented("frost_aggregate");
}

// v2.10 Phase A — first FROST primitive shipped end-to-end.
//
// frost_verify is the easy primitive to ship first: an aggregated FROST
// signature is structurally a standard Ed25519 (R || z) signature over
// `message` under `group_pubkey`. RFC 9591 §3 defines aggregation such
// that the result verifies via the standard Ed25519 verify equation;
// FROST adds nothing on top of that for the verify path. So this
// delegates directly to the existing `determ::crypto::verify` (which
// itself wraps OpenSSL's EVP_PKEY_ED25519 verify per src/crypto/keys.cpp).
//
// Shipping this first means downstream consumers of v2.10 (block-validation
// path; FA3 proof regression; threshold-rand integration in Phase D) can
// be drafted against a working verify endpoint while the more complex
// primitives (DKG ceremony, sign-round1/round2, aggregate) wait for their
// proper Phase A implementation.
bool frost_verify(const FrostSig& sig,
                   const Point& group_pubkey,
                   const std::vector<uint8_t>& message) {
    // FROST signature layout matches Ed25519: 32-byte R || 32-byte z.
    // Group pubkey is the Ed25519 compressed-point form (32 bytes).
    // Just adapt the array types and delegate.
    Signature ed_sig;
    static_assert(sizeof(FrostSig) == sizeof(Signature),
                  "FROST sig must be 64 bytes (Ed25519 R||z)");
    for (size_t i = 0; i < sig.size(); ++i) ed_sig[i] = sig[i];

    PubKey ed_pub;
    static_assert(sizeof(Point) == sizeof(PubKey),
                  "FROST point must be 32 bytes (Ed25519 compressed)");
    for (size_t i = 0; i < group_pubkey.size(); ++i) ed_pub[i] = group_pubkey[i];

    return determ::crypto::verify(ed_pub, message.data(), message.size(), ed_sig);
}

} // namespace determ::crypto::frost
