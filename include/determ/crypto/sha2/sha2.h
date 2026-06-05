/* Determ C99-native SHA-2 (FIPS 180-4).
 *
 * First vendored primitive of the libsodium-free C99 crypto stack
 * (CRYPTO-C99-SPEC.md Section 3.1). One-shot SHA-256 / SHA-512, written in
 * portable C99 with no external dependency, consumable from C99 and from C++
 * (extern "C"). SHA-2 is the foundation the rest of the stack builds on:
 * RFC 8032 Ed25519 uses SHA-512, and the FROST H1..H5 challenge hashes
 * (RFC 9591) are SHA-512-based, so this unblocks the v2.10 work.
 *
 * Correctness is gated two independent ways by `determ test-sha2-c99`:
 *   (1) byte-equal cross-validation against the daemon's current backend
 *       (OpenSSL) over every message length across the block + padding
 *       boundaries (the CRYPTO-C99-SPEC Section Q9 cross-validation gate), and
 *   (2) the canonical NIST FIPS 180-4 known-answer vectors.
 *
 * No secret-dependent control flow or memory access: a public hash has no
 * timing side channel to protect, so this is the safest primitive to vendor
 * first.
 */
#ifndef DETERM_CRYPTO_SHA2_H
#define DETERM_CRYPTO_SHA2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_SHA256_DIGEST_LEN 32u
#define DETERM_SHA512_DIGEST_LEN 64u

/* One-shot SHA-256. `out` must point to at least 32 bytes. */
void determ_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* One-shot SHA-512. `out` must point to at least 64 bytes. */
void determ_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_SHA2_H */
