// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// determ::pqauth — the DPQ1 post-quantum transaction-authentication envelope
// (CRYPTO-C99-SPEC §3.21). Binds a transaction's canonical message (the chain's
// Transaction::signing_bytes) to an ML-DSA (FIPS 204) signature, optionally in
// HYBRID with Ed25519 so an attacker must break BOTH primitives. Built on the
// already-ACVP/RFC-pinned determ::c99 wrappers; adds only the byte layout + a
// domain-separation context. The wire layout is frozen by tools/vectors/pqauth.json
// (dual-oracle: this C++ + tools/verify_pqauth.py, both matched to the same bytes).
//
// This is a LIBRARY + TOOLING primitive. The consensus accept-rule that admits a
// DPQ1-authenticated transaction is a separate, owner-gated step.
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace determ::pqauth {

// DPQ1 envelope schemes. Low nibble selects the ML-DSA parameter set; the 0x10
// bit marks a HYBRID envelope that additionally carries an Ed25519 pk + sig.
enum class Scheme : uint8_t {
    MLDSA44        = 0x01,
    MLDSA65        = 0x02,
    MLDSA87        = 0x03,
    HYBRID_MLDSA44 = 0x11,
    HYBRID_MLDSA65 = 0x12,
    HYBRID_MLDSA87 = 0x13,
};

struct VerifyResult {
    bool                 ok     = false;  // every present signature verified
    uint8_t              scheme = 0;      // parsed scheme byte (0 if parse failed)
    bool                 hybrid = false;
    std::vector<uint8_t> pq_pk;           // recovered ML-DSA public key (empty on failure)
    std::vector<uint8_t> ed_pk;           // recovered Ed25519 public key (empty unless hybrid && ok)
};

// Serialize a DPQ1 envelope binding `message` (the tx canonical signing_bytes).
// Deterministic. `mldsa_seed` is the 32-byte ML-DSA KeyGen seed; `ed_seed` is
// required iff `scheme` is a HYBRID_*. Throws std::invalid_argument on a bad
// scheme or a missing hybrid ed_seed.
std::vector<uint8_t> sign(Scheme scheme,
                          std::span<const uint8_t> message,
                          std::span<const uint8_t, 32> mldsa_seed,
                          std::optional<std::span<const uint8_t, 32>> ed_seed = std::nullopt);

// Verify a DPQ1 envelope against `message`. Memory-safe and fail-closed on ANY
// malformed envelope (bad magic, unknown/invalid scheme, wrong field lengths,
// truncation, trailing bytes). Never throws — the envelope is attacker-controlled.
VerifyResult verify(std::span<const uint8_t> envelope,
                    std::span<const uint8_t> message) noexcept;

// The domain-separation context bound into the ML-DSA message ("determ-pqtx-v1").
std::span<const uint8_t> context() noexcept;

} // namespace determ::pqauth
