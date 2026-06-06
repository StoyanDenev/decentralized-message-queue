/* Determ C99-native ChaCha20 (RFC 8439 Section 2.3-2.4).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.4).
 * Validated byte-equal against OpenSSL EVP_chacha20 by `determ test-chacha20-c99`. */
#include "determ/crypto/chacha20/chacha20.h"
#include "determ/crypto/secure_zero.h"

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

/* ChaCha20 quarter-round on four words of the working state array `x`. */
#define QR(x, a, b, c, d)                                  \
    do {                                                   \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7);  \
    } while (0)

static void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {           /* 20 rounds = 10 column + diagonal pairs */
        QR(x, 0, 4, 8, 12);  QR(x, 1, 5, 9, 13);  QR(x, 2, 6, 10, 14); QR(x, 3, 7, 11, 15);
        QR(x, 0, 5, 10, 15); QR(x, 1, 6, 11, 12); QR(x, 2, 7, 8, 13);  QR(x, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[i * 4]     = (uint8_t)v;
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
    determ_secure_zero(x, sizeof x);   /* x holds the key words (4..11) + state */
}

void determ_chacha20(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12],
                     const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t st[16];
    uint8_t block[64];
    size_t done = 0;
    int i;

    /* "expand 32-byte k" */
    st[0] = 0x61707865u; st[1] = 0x3320646eu;
    st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (i = 0; i < 8; i++) st[4 + i] = load32_le(key + 4 * i);
    st[12] = counter;
    for (i = 0; i < 3; i++) st[13 + i] = load32_le(nonce + 4 * i);

    while (done < len) {
        size_t take = (len - done < 64) ? (len - done) : 64;
        size_t j;
        chacha20_block(st, block);
        for (j = 0; j < take; j++) out[done + j] = (uint8_t)(in[done + j] ^ block[j]);
        done += take;
        st[12]++;               /* next block counter */
    }
    /* st[4..11] holds the 256-bit key; block holds the last keystream block. */
    determ_secure_zero(st, sizeof st);
    determ_secure_zero(block, sizeof block);
}
