/* Determ C99-native AES-256 (FIPS-197) — the block cipher underlying AES-256-GCM
 * (CRYPTO-C99-SPEC.md Section 3.5), the AEAD the wallet keyfile envelope (S-004)
 * uses. This file is the block cipher (encrypt direction, which is all GCM needs);
 * GHASH + the GCM mode land alongside it.
 *
 * !!! CONSTANT-TIME CAVEAT !!!  This implementation uses a table-based S-box and
 * is therefore NOT constant-time (vulnerable to cache-timing analysis of the key-
 * dependent table lookups). That is acceptable for this ADDITIVE, validated module
 * — it is not yet wired into any call site — but it MUST be replaced with a
 * constant-time S-box (bitsliced / Boyar-Peralta circuit) or hardware AES-NI, or
 * BearSSL's constant-time AES vendored, per CRYPTO-C99-SPEC Section 3.5, BEFORE it
 * replaces the OpenSSL AES at the keyfile-envelope call site. Correctness here is
 * gated byte-equal against OpenSSL + the FIPS-197 KAT by `determ test-aes-c99`.
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_AES_H */
