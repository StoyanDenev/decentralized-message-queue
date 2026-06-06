/* Determ C99-native ChaCha20 stream cipher (RFC 8439 Section 2.4).
 *
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.4, the
 * ChaCha20-Poly1305 AEAD family). This file is the cipher; Poly1305 + the AEAD
 * combiner land alongside it. ChaCha20 is an ARX cipher — no S-boxes, no lookup
 * tables, no secret-dependent branches or memory access — so it is constant-time
 * by construction (the property AES-GCM's GHASH makes hard, per the spec).
 *
 * Validated byte-equal against OpenSSL EVP_chacha20 by `determ test-chacha20-c99`.
 */
#ifndef DETERM_CRYPTO_CHACHA20_H
#define DETERM_CRYPTO_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 8439 ChaCha20: 256-bit key, 32-bit block counter, 96-bit nonce. XORs the
 * keystream (starting at block `counter`) with `in` into `out` (`out` may alias
 * `in`). ChaCha20 is its own inverse, so the same call decrypts. */
void determ_chacha20(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12],
                     const uint8_t *in, size_t len, uint8_t *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_CHACHA20_H */
