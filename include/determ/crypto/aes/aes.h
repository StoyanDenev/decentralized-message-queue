/* Determ C99-native AES-256 (FIPS-197) — the block cipher underlying AES-256-GCM
 * (CRYPTO-C99-SPEC.md Section 3.5), the AEAD the wallet keyfile envelope (S-004)
 * uses. This file is the block cipher (encrypt direction, which is all GCM needs)
 * plus the AES-256-GCM AEAD declared below.
 *
 * CONSTANT-TIME: this implementation has no key-dependent table lookup or branch.
 * SubBytes / SubWord are computed arithmetically — the GF(2^8) multiplicative
 * inverse via a fixed x^254 addition chain over a branchless field multiply, then
 * the FIPS-197 affine map — so there is no cache-timing channel from the S-box.
 * GHASH (in aes_gcm.c) is likewise branchless bit-serial. The canonical FIPS-197
 * S-box table is retained ONLY as a validation oracle: `determ_aes256_sbox_selftest`
 * exhaustively asserts the computed S-box equals the table over all 256 inputs.
 * (The arithmetic S-box trades throughput for the CT guarantee; a bitsliced /
 * AES-NI S-box would be faster but is a perf optimization, not a security gate —
 * the keyfile-envelope (S-004) use is one-shot.) Correctness is gated byte-equal
 * against OpenSSL + the FIPS-197 KAT by `determ test-aes-c99`.
 */
#ifndef DETERM_CRYPTO_AES_H
#define DETERM_CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Expanded AES-256 key schedule: 15 round keys x 16 bytes. */
typedef struct { uint8_t rk[240]; } determ_aes256_ctx;

void determ_aes256_init(determ_aes256_ctx *ctx, const uint8_t key[32]);
void determ_aes256_encrypt_block(const determ_aes256_ctx *ctx,
                                 const uint8_t in[16], uint8_t out[16]);

/* Build-time validation hook: returns 1 iff the constant-time arithmetic S-box
 * is byte-identical to the canonical FIPS-197 table over all 256 inputs, else 0.
 * Exercised exhaustively by `determ test-aes-c99`. */
int determ_aes256_sbox_selftest(void);

/* AES-256-GCM AEAD (NIST SP 800-38D), 96-bit IV, 16-byte tag. encrypt writes
 * `ptlen` ciphertext bytes to `ct` + the tag; decrypt verifies the tag with a
 * constant-time compare and returns 0 on success (writing `ctlen` plaintext bytes
 * to `pt`) or -1 on authentication failure. Constant-time end to end: GHASH is
 * branchless and the AES S-box is computed arithmetically (see the note above). */
void determ_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t *pt, size_t ptlen,
                               uint8_t *ct, uint8_t tag[16]);
int  determ_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t *ct, size_t ctlen,
                               const uint8_t tag[16], uint8_t *pt);

/* Arbitrary-IV-length variants (SP 800-38D §7.1: ivlen != 12 derives the
 * pre-counter block via J0 = GHASH_H(IV || pad || [ivlen*8]_64); ivlen == 12
 * is the same fast path as the fixed-IV entry points above, which are now
 * thin wrappers over these). Returns 0 on success; -1 on ivlen == 0
 * (encrypt) or ivlen == 0 / authentication failure (decrypt). */
int  determ_aes256_gcm_encrypt_iv(const uint8_t key[32],
                                  const uint8_t *iv, size_t ivlen,
                                  const uint8_t *aad, size_t aadlen,
                                  const uint8_t *pt, size_t ptlen,
                                  uint8_t *ct, uint8_t tag[16]);
int  determ_aes256_gcm_decrypt_iv(const uint8_t key[32],
                                  const uint8_t *iv, size_t ivlen,
                                  const uint8_t *aad, size_t aadlen,
                                  const uint8_t *ct, size_t ctlen,
                                  const uint8_t tag[16], uint8_t *pt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_AES_H */
