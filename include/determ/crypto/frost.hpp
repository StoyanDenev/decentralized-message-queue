#pragma once
//
// FROST-Ed25519 threshold signature primitives (v2.10 Phase A).
//
// Per `docs/proofs/v2.10-DKG-SPEC.md`, v2.10 replaces the v1 commit-reveal
// `creator_dh_secrets` with a per-committee-member FROST partial signature
// over the beacon seed; any t-of-K partials aggregate into the same
// canonical signature R, defeating the residual selective-abort attack
// from S-006 (one withholding adversary cannot bias randomness; the
// other K-t members' partials suffice).
//
// This header declares the FROST-Ed25519 API per RFC 9591 (May 2024).
// The reference is `zcash/frost-ed25519`; the implementation lives in
// `src/crypto/frost.cpp` and uses the already-vendored libsodium
// (`crypto_core_ed25519_*`, `crypto_scalarmult_ed25519_*`,
// `crypto_hash_sha512` for the H1..H5 sub-hashes per RFC 9591 §6.6).
//
// === Status ===
//
// As of this commit: PHASE A SCAFFOLDING ONLY. The function signatures
// are declared so dependent code (DKG ceremony in Phase B, threshold-sig
// integration in Phase D) can be drafted against them. The implementations
// throw `std::logic_error("v2.10 Phase A not yet implemented")` until the
// RFC 9591 logic is ported. This preserves build-clean while making the
// API contract visible.
//
// Activation of v2.10 across the chain is gated on
// `GenesisConfig::v2_10_active_from_height` — until that height is
// reached, the validator/producer use the v1 commit-reveal path; from
// that height on, they switch to the FROST path (after Phase D ships).
//
// === RFC 9591 §3 mapping ===
//
//   Identifier     uint16_t (1..K)              — share index (FROST i)
//   Scalar         std::array<uint8_t, 32>     — Ed25519 scalar (mod L)
//   Point          std::array<uint8_t, 32>     — Ed25519 compressed point
//   Signature      std::array<uint8_t, 64>     — Ed25519 (R || z) sig
//
// === Phase B (DKG ceremony) consumers ===
//
//   frost_keygen_round1() — Round 1 commitment broadcast
//   frost_keygen_round2() — Round 2 encrypted share distribution
//   frost_keygen_finalize() — local share + group pubkey computation
//
// === Phase D (threshold-sig) consumers ===
//
//   frost_sign_round1() — generates per-signer hiding/binding nonce pair
//   frost_sign_round2() — produces this signer's partial sig
//   frost_aggregate()  — aggregates t partials into the canonical sig

#include <determ/types.hpp>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace determ::crypto::frost {

using Identifier = uint16_t;
using Scalar     = std::array<uint8_t, 32>;
using Point      = std::array<uint8_t, 32>;
using FrostSig   = std::array<uint8_t, 64>;  // distinct from `Signature` in
                                              // types.hpp — same bytes,
                                              // different domain meaning

// ─── Phase B: DKG ceremony ────────────────────────────────────────────────
//
// Trustless distributed key generation. Each committee member runs Round 1
// + Round 2 + Finalize across the epoch boundary; the result is a per-
// member secret share + a shared group public key.
//
// Per RFC 9591 §6.6 + v2.10-DKG-SPEC.md, the FROST DKG uses a 2-round
// protocol: Round 1 broadcasts polynomial commitments + a proof of
// possession (PoP) for each commitment; Round 2 sends each peer their
// encrypted share via the existing gossip envelope.

struct KeygenRound1Output {
    // Public commitments: polynomial coefficients × G (one per (threshold)
    // coefficient). Other members verify against these via the PoP.
    std::vector<Point> commitments;
    // Proof of possession: Schnorr signature over the constant-term
    // commitment under H6 challenge. Defeats rogue-key attacks.
    FrostSig pop_sig;
    // Random nonce held by this member through round 2.
    Scalar private_seed;
};

// Round 1: each member generates their polynomial + commits to it.
//
// `t` = threshold (typically ceil(2K/3) per docs/proofs/Safety.md).
// `n` = total committee size at this epoch.
// `self_id` = this member's identifier (1..n; never 0).
//
// Throws on invalid t/n (e.g., t > n, t < 1) or invalid self_id.
KeygenRound1Output frost_keygen_round1(Identifier self_id,
                                         uint16_t t, uint16_t n);

struct KeygenRound2Output {
    // Per-peer encrypted shares: shares[peer_id - 1] is this member's
    // share contribution to `peer_id`. Length = n - 1 (self excluded).
    std::vector<std::pair<Identifier, Scalar>> peer_shares;
};

// Round 2: compute per-peer shares from this member's polynomial.
// `round1_output` is the Round 1 state from this member's own call.
KeygenRound2Output frost_keygen_round2(
    const KeygenRound1Output& round1_output,
    Identifier self_id, uint16_t n);

struct LocalShare {
    Identifier my_id;
    Scalar     secret_share;
    Point      group_pubkey;
    std::vector<Point> verification_shares;  // V_i for i in 1..n
};

// Finalize: combine this member's own share with all peers' round-2 shares
// addressed to this member. Output is this member's long-term FROST state.
//
// `peer_round2_outputs[i]` is the Round 2 output from peer i (i in 1..n,
// excluding self_id). Each entry's `peer_shares` should contain a pair
// keyed by `self_id`; that's this member's share contribution from peer i.
LocalShare frost_keygen_finalize(
    Identifier self_id, uint16_t t, uint16_t n,
    const KeygenRound1Output& my_round1,
    const KeygenRound2Output& my_round2,
    const std::vector<std::pair<Identifier, KeygenRound1Output>>& peer_round1s,
    const std::vector<std::pair<Identifier, KeygenRound2Output>>& peer_round2s);

// ─── Phase D: threshold signing ───────────────────────────────────────────
//
// Per RFC 9591 §5.1, FROST signing is a 2-round protocol.
//
// Round 1: each signer commits to a nonce pair (hiding, binding).
// Round 2: each signer produces a partial signature using the committed
// nonces + the canonical challenge derived from the round-1 commitments.

struct SignRound1Output {
    Point hiding_commitment;
    Point binding_commitment;
    Scalar hiding_nonce;    // kept private — held only by this signer
    Scalar binding_nonce;   // kept private — held only by this signer
};

// Round 1: generate this signer's nonce pair.
SignRound1Output frost_sign_round1(const LocalShare& my_share);

struct CommitmentMap {
    // Per-signer (hiding, binding) commitments. Round-2 input.
    std::vector<std::tuple<Identifier, Point, Point>> entries;
};

// Round 2: produce this signer's partial signature.
//
// `message` = the beacon seed || height bytes (or whatever the deployment
// wants signed — for v2.10 randomness, this is `SHA-256(beacon_seed ||
// height_le)` per the spec).
Scalar frost_sign_round2(const LocalShare& my_share,
                          const SignRound1Output& my_round1,
                          const CommitmentMap& all_commitments,
                          const std::vector<uint8_t>& message);

// Aggregate t partial signatures into the canonical (R, z) signature.
// Returns the canonical FROST signature. Any t-of-K partials produce the
// SAME R — that's the central property defeating selective-abort.
FrostSig frost_aggregate(const CommitmentMap& commitments,
                          const std::vector<std::pair<Identifier, Scalar>>& partial_sigs,
                          const std::vector<uint8_t>& message,
                          const Point& group_pubkey);

// Verify a FROST signature against the group pubkey (standard Ed25519
// verify — FROST aggregates produce a valid Ed25519 sig over `message`
// against `group_pubkey`).
bool frost_verify(const FrostSig& sig,
                   const Point& group_pubkey,
                   const std::vector<uint8_t>& message);

} // namespace determ::crypto::frost
