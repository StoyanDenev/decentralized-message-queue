#pragma once
// A2 Phase 4: smoke-test surface for the libsodium primitives that
// libopaque (Phase 5) will compose into the OPAQUE registration + AKE.
//
// These wrappers are NOT OPAQUE. They expose the libsodium routines
// directly so Phase 4 can prove the build is wired correctly (ristretto255
// + Argon2id available, link succeeds, smoke test passes). Phase 5
// drops libopaque on top and the wallet's recovery flow swaps the
// PBKDF2 key derivation for the OPAQUE AKE session key.
//
// Why these specific routines: the OPAQUE RFC 9497 OPRF construction
// is:
//   blind:   y = H(password) · r       (ristretto255 scalar mult)
//   server:  z = y · k                 (ristretto255 scalar mult; k = server key)
//   unblind: out = z / r               (ristretto255 inversion)
// Followed by:
//   stretch: Argon2id(out, salt) → uniform key material
//   AKE:     HMAC-SHA-256 / HKDF over the above
// libsodium covers all three primitive families; the smoke test below
// exercises the two non-trivial ones (ristretto255 scalar arithmetic +
// Argon2id).

#include <cstdint>
#include <vector>
#include <optional>

namespace determ::wallet::primitives {

// libsodium initialization. Must be called once before any other
// routine in this header. Returns true on success. Threadsafe.
bool init_libsodium();

// One-time setup: 64 bytes of CSPRNG output. Used as a self-test
// that the random source is available.
std::vector<uint8_t> random_bytes(size_t n);

// Generate a uniformly-random ristretto255 scalar (32 bytes). Caller
// must have called init_libsodium() first.
std::vector<uint8_t> ristretto255_scalar_random();

// Compute y = H_to_curve(message) · scalar on ristretto255. Returns
// 32 bytes (the resulting point) or empty vector on failure. This is
// the "blind" step of the OPAQUE OPRF.
std::vector<uint8_t> ristretto255_point_blind(const std::vector<uint8_t>& message,
                                                  const std::vector<uint8_t>& scalar);

// Argon2id password stretching. Returns out_len bytes of derived key.
// opslimit / memlimit follow libsodium conventions:
//   opslimit=3, memlimit=64MiB matches the OPAQUE paper's
//   recommendation floor for high-value secrets.
std::vector<uint8_t> argon2id(const std::vector<uint8_t>& password,
                                const std::vector<uint8_t>& salt,
                                size_t out_len,
                                uint64_t opslimit = 3,
                                size_t   memlimit = 64ull * 1024 * 1024);

} // namespace determ::wallet::primitives
