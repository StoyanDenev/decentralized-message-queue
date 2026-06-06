/* Determ C99-native SHA-256 (FIPS 180-4 Section 6.2).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.1).
 * Validated against the daemon's OpenSSL backend + NIST KATs by
 * `determ test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <string.h>

static uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

/* SHA-256 round constants: first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes (FIPS 180-4 Section 4.2.2). */
static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_block(uint32_t h[8], const uint8_t p[64]) {
    uint32_t w[64];
    unsigned i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    {
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    /* w holds key-derived material when the caller (HMAC/PBKDF2) feeds a secret
     * inner block; scrub it so it does not linger in the reclaimed stack frame. */
    determ_secure_zero(w, sizeof w);
}

void determ_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = (uint64_t)len * 8u;
    size_t full = len / 64u;
    size_t rem;
    size_t padlen;
    uint8_t tail[128];
    size_t i;   /* size_t (not unsigned): the block loop counts up to `full`,
                 * which is a size_t — an `unsigned` counter would wrap before
                 * reaching `full` for inputs >= 256 GiB and never terminate. */

    for (i = 0; i < full; i++) sha256_block(h, data + i * 64u);

    rem = len - full * 64u;
    if (rem) memcpy(tail, data + full * 64u, rem);
    tail[rem] = 0x80u;
    padlen = (rem < 56u) ? 64u : 128u;
    memset(tail + rem + 1u, 0, padlen - rem - 1u - 8u);
    for (i = 0; i < 8u; i++)
        tail[padlen - 1u - i] = (uint8_t)(bitlen >> (8u * i));
    sha256_block(h, tail);
    if (padlen == 128u) sha256_block(h, tail + 64u);

    for (i = 0; i < 8u; i++) {
        out[i * 4u]      = (uint8_t)(h[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(h[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(h[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)(h[i]);
    }
    /* tail holds up to the final 127 input bytes (key-derived for keyed callers). */
    determ_secure_zero(tail, sizeof tail);
}
