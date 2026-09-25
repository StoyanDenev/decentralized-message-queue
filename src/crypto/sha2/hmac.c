/* Determ C99-native HMAC-SHA-256 / HMAC-SHA-512 (RFC 2104, FIPS 198-1).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.1),
 * built on the C99 SHA-2 in this directory. Validated byte-equal against the
 * OpenSSL backend + RFC 4231 KATs by `determ-cryptotest test-sha2-c99`.
 * Both stream the message through the hash: no heap, no failure path. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <string.h>

void determ_hmac_sha256_init(determ_hmac_sha256_ctx *ctx,
                             const uint8_t *key, size_t keylen) {
    uint8_t k0[64];                 /* the key padded (or hashed) to one block */
    uint8_t pad[64];
    size_t i;

    memset(k0, 0, sizeof k0);
    if (keylen > sizeof k0) determ_sha256(key, keylen, k0);  /* k0[32..63] stay zero */
    else if (keylen) memcpy(k0, key, keylen);

    for (i = 0; i < sizeof pad; i++) pad[i] = (uint8_t)(k0[i] ^ 0x36u);
    determ_sha256_init(&ctx->inner);
    determ_sha256_update(&ctx->inner, pad, sizeof pad);
    for (i = 0; i < sizeof pad; i++) pad[i] = (uint8_t)(k0[i] ^ 0x5cu);
    determ_sha256_init(&ctx->outer);
    determ_sha256_update(&ctx->outer, pad, sizeof pad);

    determ_secure_zero(k0, sizeof k0);
    determ_secure_zero(pad, sizeof pad);
}

void determ_hmac_sha256_update(determ_hmac_sha256_ctx *ctx,
                               const uint8_t *data, size_t len) {
    determ_sha256_update(&ctx->inner, data, len);
}

void determ_hmac_sha256_final(determ_hmac_sha256_ctx *ctx, uint8_t out[32]) {
    uint8_t inner[32];
    determ_sha256_final(&ctx->inner, inner);          /* wipes ctx->inner */
    determ_sha256_update(&ctx->outer, inner, sizeof inner);
    determ_sha256_final(&ctx->outer, out);            /* wipes ctx->outer */
    determ_secure_zero(inner, sizeof inner);
}

int determ_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    determ_hmac_sha256_ctx ctx;
    determ_hmac_sha256_init(&ctx, key, keylen);
    determ_hmac_sha256_update(&ctx, msg, msglen);
    determ_hmac_sha256_final(&ctx, out);
    return 0;
}

int determ_hmac_sha512(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[64]) {
    uint8_t k0[128];                /* the key padded (or hashed) to one block */
    uint8_t pad[128];
    uint8_t inner[64];
    determ_sha512_ctx ctx;
    size_t i;

    memset(k0, 0, sizeof k0);
    if (keylen > sizeof k0) determ_sha512(key, keylen, k0);  /* k0[64..127] stay zero */
    else if (keylen) memcpy(k0, key, keylen);

    /* inner = SHA-512( (k0 ^ ipad) || msg ) */
    for (i = 0; i < sizeof pad; i++) pad[i] = (uint8_t)(k0[i] ^ 0x36u);
    determ_sha512_init(&ctx);
    determ_sha512_update(&ctx, pad, sizeof pad);
    determ_sha512_update(&ctx, msg, msglen);
    determ_sha512_final(&ctx, inner);               /* wipes ctx */

    /* out = SHA-512( (k0 ^ opad) || inner ) */
    for (i = 0; i < sizeof pad; i++) pad[i] = (uint8_t)(k0[i] ^ 0x5cu);
    determ_sha512_init(&ctx);
    determ_sha512_update(&ctx, pad, sizeof pad);
    determ_sha512_update(&ctx, inner, sizeof inner);
    determ_sha512_final(&ctx, out);                 /* wipes ctx */

    determ_secure_zero(k0, sizeof k0);
    determ_secure_zero(pad, sizeof pad);
    determ_secure_zero(inner, sizeof inner);
    return 0;
}
