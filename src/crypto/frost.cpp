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

bool frost_verify(const FrostSig& /*sig*/,
                   const Point& /*group_pubkey*/,
                   const std::vector<uint8_t>& /*message*/) {
    unimplemented("frost_verify");
}

} // namespace determ::crypto::frost
