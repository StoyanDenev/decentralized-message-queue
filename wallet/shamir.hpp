#pragma once
// A2 Phase 1: Shamir's Secret Sharing over GF(2^8).
//
// Split an arbitrary byte sequence into N shares such that any T of them
// reconstruct the original, but any T-1 or fewer reveal nothing about it.
// Each byte of the secret is split independently over GF(2^8) using the
// AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
//
// Share format on the wire:
//   share[0] = x-coordinate (1..255, distinct per share)
//   share[1..] = polynomial evaluations at x for each secret byte
//
// Threshold reconstruction uses Lagrange interpolation evaluated at x = 0.
// All operations are constant-time relative to share content (the
// polynomial-eval inner loop is data-independent).
//
// This module is OPAQUE-independent. The OPAQUE layer (Phase 2) wraps
// each share in an AEAD envelope guarded by the user's recovery
// password + a per-guardian OPRF key. Recovery: T successful AKE
// handshakes yield T unwrapped shares, fed back through combine().

#include <cstdint>
#include <vector>
#include <optional>

namespace determ::wallet::shamir {

// One share = (x-coordinate, evaluations). x must be non-zero and
// distinct across all shares in a split.
struct Share {
    uint8_t              x{0};
    std::vector<uint8_t> y;       // y[i] = p_i(x) for each secret byte i
};

// Split secret into n shares with threshold t. n in [t, 255], t in
// [1, n]. Returns the n shares with distinct x coordinates 1..n.
// Throws std::invalid_argument on invalid parameters.
std::vector<Share> split(const std::vector<uint8_t>& secret,
                          uint8_t threshold,
                          uint8_t share_count);

// Reconstruct the secret from any t-or-more shares. Returns std::nullopt
// when shares are inconsistent (duplicate x, mismatched y sizes, empty).
// The reconstruction trusts the caller to provide >=t valid shares;
// fewer shares produce a garbage result indistinguishable from a
// different secret (information-theoretic security property of SSS).
std::optional<std::vector<uint8_t>>
combine(const std::vector<Share>& shares);

} // namespace determ::wallet::shamir
