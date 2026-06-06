/* Determ C99-native AES-256-GCM AEAD (NIST SP 800-38D), 96-bit IV.
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.5).
 * Composes the C99 AES-256 block cipher in this directory with a GHASH over
 * GF(2^128). Validated byte-equal against OpenSSL EVP_aes_256_gcm + a decrypt
 * round-trip + tamper rejection by `determ test-aes-c99`.
 *
 * This AEAD is constant-time end to end: GHASH below is BRANCHLESS (the mask +
 * reduction use no secret-dependent branch), and the AES S-box (aes_core.c) is
 * computed arithmetically with no key-dependent table lookup. There is no
 * remaining cache-timing channel gating use at a secret-key call site. */
#include "determ/crypto/aes/aes.h"
#include <string.h>

/* X = X * H over GF(2^128) (NIST SP 800-38D, MSB-first bit order, R=0xe1...). */
static void ghash_mul(uint8_t X[16], const uint8_t H[16]) {
    uint8_t Z[16];
    uint8_t V[16];
    int i, j;
    memset(Z, 0, 16);
    memcpy(V, H, 16);
    for (i = 0; i < 128; i++) {
        uint8_t xbit = (uint8_t)((X[i >> 3] >> (7 - (i & 7))) & 1);
        uint8_t mask = (uint8_t)(0u - xbit);          /* 0x00 or 0xff */
        uint8_t lsb;
        for (j = 0; j < 16; j++) Z[j] ^= (uint8_t)(V[j] & mask);
        lsb = (uint8_t)(V[15] & 1);
        for (j = 15; j > 0; j--) V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
        V[0] >>= 1;
        V[0] ^= (uint8_t)(0xe1u & (uint8_t)(0u - lsb)); /* branchless reduction */
    }
    memcpy(X, Z, 16);
}

/* Absorb `data` (16-byte blocks, final block zero-padded) into the GHASH state X. */
static void ghash_update(uint8_t X[16], const uint8_t H[16],
                         const uint8_t *data, size_t len) {
    size_t i = 0;
    int j;
    while (i + 16 <= len) {
        for (j = 0; j < 16; j++) X[j] ^= data[i + j];
        ghash_mul(X, H);
        i += 16;
    }
    if (i < len) {
        uint8_t blk[16];
        size_t rem = len - i;
        memset(blk, 0, 16);
        memcpy(blk, data + i, rem);
        for (j = 0; j < 16; j++) X[j] ^= blk[j];
        ghash_mul(X, H);
    }
}

static void put_u64_be(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static void inc32(uint8_t ctr[16]) {
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
                 ((uint32_t)ctr[14] << 8) | (uint32_t)ctr[15];
    c++;
    ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
    ctr[14] = (uint8_t)(c >> 8);  ctr[15] = (uint8_t)c;
}

/* GHASH(H, AAD, C) ^ E(J0)  ->  tag (the authentication tag for the AEAD). */
static void gcm_tag(const determ_aes256_ctx *ctx, const uint8_t H[16], const uint8_t J0[16],
                    const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t ctlen,
                    uint8_t tag[16]) {
    uint8_t X[16];
    uint8_t lenblk[16];
    uint8_t ej0[16];
    int j;
    memset(X, 0, 16);
    ghash_update(X, H, aad, aadlen);
    ghash_update(X, H, ct, ctlen);
    put_u64_be(lenblk,     (uint64_t)aadlen * 8u);
    put_u64_be(lenblk + 8, (uint64_t)ctlen  * 8u);
    for (j = 0; j < 16; j++) X[j] ^= lenblk[j];
    ghash_mul(X, H);
    determ_aes256_encrypt_block(ctx, J0, ej0);
    for (j = 0; j < 16; j++) tag[j] = (uint8_t)(X[j] ^ ej0[j]);
}

/* GCTR keystream over `in` -> `out`, counter starting at inc32(J0). */
static void gcm_crypt(const determ_aes256_ctx *ctx, const uint8_t J0[16],
                      const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t ctr[16];
    uint8_t ks[16];
    size_t done = 0;
    memcpy(ctr, J0, 16);
    while (done < len) {
        size_t take = (len - done < 16) ? (len - done) : 16;
        size_t j;
        inc32(ctr);
        determ_aes256_encrypt_block(ctx, ctr, ks);
        for (j = 0; j < take; j++) out[done + j] = (uint8_t)(in[done + j] ^ ks[j]);
        done += take;
    }
}

static int ct_eq16(const uint8_t *a, const uint8_t *b) {
    uint8_t r = 0;
    int i;
    for (i = 0; i < 16; i++) r |= (uint8_t)(a[i] ^ b[i]);
    return r == 0 ? 0 : -1;
}

void determ_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t *pt, size_t ptlen,
                               uint8_t *ct, uint8_t tag[16]) {
    determ_aes256_ctx ctx;
    uint8_t H[16];
    uint8_t J0[16];
    determ_aes256_init(&ctx, key);
    memset(H, 0, 16);
    determ_aes256_encrypt_block(&ctx, H, H);          /* H = E_K(0^128) */
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;    /* J0 = IV || 0^31 || 1 */
    gcm_crypt(&ctx, J0, pt, ptlen, ct);
    gcm_tag(&ctx, H, J0, aad, aadlen, ct, ptlen, tag);
}

int determ_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                              const uint8_t *aad, size_t aadlen,
                              const uint8_t *ct, size_t ctlen,
                              const uint8_t tag[16], uint8_t *pt) {
    determ_aes256_ctx ctx;
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t expect[16];
    determ_aes256_init(&ctx, key);
    memset(H, 0, 16);
    determ_aes256_encrypt_block(&ctx, H, H);
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    gcm_tag(&ctx, H, J0, aad, aadlen, ct, ctlen, expect);
    if (ct_eq16(expect, tag) != 0) return -1;          /* authentication failure */
    gcm_crypt(&ctx, J0, ct, ctlen, pt);
    return 0;
}
