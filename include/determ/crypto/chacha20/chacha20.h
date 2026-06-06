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

/* Poly1305 one-time authenticator (RFC 8439 §2.5). `key` = r(16) || s(16); the
 * 16-byte tag is written to `tag`. Each key MUST be used for at most one message. */
void determ_poly1305(const uint8_t key[32], const uint8_t *msg, size_t msglen,
                     uint8_t tag[16]);

/* ChaCha20-Poly1305 AEAD (RFC 8439 §2.8). key=32, nonce=12, tag=16. encrypt writes
 * `ptlen` ciphertext bytes to `ct` + the tag. decrypt verifies the tag with a
 * constant-time compare and returns 0 on success (writing `ctlen` plaintext bytes
 * to `pt`) or -1 on authentication failure (and writes nothing). */
void determ_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *pt, size_t ptlen,
                                      uint8_t *ct, uint8_t tag[16]);
int  determ_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t tag[16], uint8_t *pt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_CHACHA20_H */
