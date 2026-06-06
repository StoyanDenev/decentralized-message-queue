/* Determ C99-native Poly1305 one-time authenticator (RFC 8439 Section 2.5).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.4).
 *
 * This is the canonical 5 x 26-bit-limb arithmetic (the "poly1305-donna-32"
 * structure): the field 2^130-5 lands on a clean 5*26 = 130-bit boundary, which
 * is why this representation is used. The carry propagation, the partial-block
 * 0x01 handling, and the final constant-time conditional subtraction of 2^130-5
 * are the parts that must be exact; correctness is gated byte-equal against the
 * OpenSSL backend (via the AEAD) + the RFC 8439 2.5.2 KAT in `determ test-chacha20-c99`.
 *
 * No secret-dependent branches or table indexing: the final reduction selects h
 * vs h-p with a constant-time mask, so this is constant-time. */
#include "determ/crypto/chacha20/chacha20.h"

static uint32_t u8to32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void u32to8(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Absorb one 16-byte block into the 5-limb accumulator h, then h = (h * r) mod p.
 * `hibit` is 1<<24 for a full block (the implicit 2^128 bit) and 0 for the final
 * partial block (whose 0x01 byte is already placed in `blk`). */
static void poly1305_absorb(uint32_t h[5],
                            uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4,
                            uint32_t s1, uint32_t s2, uint32_t s3, uint32_t s4,
                            const uint8_t blk[16], uint32_t hibit) {
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    h0 += (u8to32(blk +  0)     ) & 0x3ffffff;
    h1 += (u8to32(blk +  3) >> 2) & 0x3ffffff;
    h2 += (u8to32(blk +  6) >> 4) & 0x3ffffff;
    h3 += (u8to32(blk +  9) >> 6) & 0x3ffffff;
    h4 += (u8to32(blk + 12) >> 8) | hibit;

    d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
}

void determ_poly1305(const uint8_t key[32], const uint8_t *m, size_t bytes, uint8_t tag[16]) {
    uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4;
    uint32_t pad0, pad1, pad2, pad3;
    uint32_t h[5] = {0, 0, 0, 0, 0};
    uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
    uint64_t f;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff, split into 26-bit limbs. */
    r0 = (u8to32(key +  0)     ) & 0x3ffffff;
    r1 = (u8to32(key +  3) >> 2) & 0x3ffff03;
    r2 = (u8to32(key +  6) >> 4) & 0x3ffc0ff;
    r3 = (u8to32(key +  9) >> 6) & 0x3f03fff;
    r4 = (u8to32(key + 12) >> 8) & 0x00fffff;
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
    pad0 = u8to32(key + 16); pad1 = u8to32(key + 20);
    pad2 = u8to32(key + 24); pad3 = u8to32(key + 28);

    while (bytes >= 16) {
        poly1305_absorb(h, r0, r1, r2, r3, r4, s1, s2, s3, s4, m, 1u << 24);
        m += 16; bytes -= 16;
    }
    if (bytes) {
        uint8_t buf[16];
        size_t i;
        for (i = 0; i < bytes; i++) buf[i] = m[i];
        buf[bytes] = 1;
        for (i = bytes + 1; i < 16; i++) buf[i] = 0;
        poly1305_absorb(h, r0, r1, r2, r3, r4, s1, s2, s3, s4, buf, 0u);
    }

    /* Fully carry h. */
    h0 = h[0]; h1 = h[1]; h2 = h[2]; h3 = h[3]; h4 = h[4];
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* g = h + 5 - 2^130 (i.e. h - p); pick g if there was no borrow (h >= p). */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1;                 /* 0 if h < p (use h), all-ones if h >= p (use g) */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Repack the 5 x 26-bit limbs into 4 x 32-bit words. */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + s) mod 2^128, little-endian. */
    f = (uint64_t)h0 + pad0;            h0 = (uint32_t)f;
    f = (uint64_t)h1 + pad1 + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + pad2 + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + pad3 + (f >> 32); h3 = (uint32_t)f;

    u32to8(tag +  0, h0);
    u32to8(tag +  4, h1);
    u32to8(tag +  8, h2);
    u32to8(tag + 12, h3);
}
