/* Determ C99-native X25519 (RFC 7748) — Curve25519 Diffie-Hellman.
 *
 * The DH companion to the libsodium-free C99 Ed25519 signature primitive
 * (CRYPTO-C99-SPEC §3.3). Same curve (Curve25519, p = 2^255-19), same
 * TweetNaCl-derived constant-time field/ladder provenance as
 * `src/crypto/ed25519/ed25519.c`, so the two share an auditable lineage and
 * neither re-links libsodium.
 *
 * Constant-time: the Montgomery ladder runs all 255 steps with a `sel25519`
 * conditional swap masked by the secret scalar bit — no secret-dependent branch
 * or memory index. The clamped scalar copy and all field intermediates are
 * zeroized before return.
 *
 * Validated two ways by `determ test-x25519-c99`: (1) byte-equal vs OpenSSL
 * `EVP_PKEY_X25519` (public-key derivation + ECDH `EVP_PKEY_derive`) over a
 * fuzzed scalar/point grid — the §Q9 cross-validation gate — and (2) the
 * canonical RFC 7748 §6.1 known-answer vectors (Alice/Bob keypairs + shared
 * secret). Additive: not yet wired into any call site.
 */
#ifndef DETERM_CRYPTO_X25519_H
#define DETERM_CRYPTO_X25519_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* X25519 scalar multiplication: out = X25519(scalar, point), where `scalar` is
 * clamped per RFC 7748 §5 (bits cleared/set internally — pass the raw 32-byte
 * secret) and `point` is the 32-byte little-endian u-coordinate. Returns 0 on
 * success, or -1 if the result is the all-zero low-order point — RFC 7748's
 * "contributory" check, matching OpenSSL `EVP_PKEY_derive` rejecting a shared
 * secret produced from a small-order peer key. */
int determ_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/* out = X25519(scalar, basepoint{9}) — the Curve25519 public key for the private
 * scalar. Returns 0 (a clamped scalar times the base point is never low-order). */
int determ_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_X25519_H */
