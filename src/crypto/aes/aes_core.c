/* Determ C99-native AES-256 block cipher, encrypt direction (FIPS-197).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.5).
 * CONSTANT-TIME S-box: SubBytes / SubWord are computed arithmetically (a
 * branchless GF(2^8) inverse via a fixed x^254 addition chain + the affine
 * map), so there is no key-dependent table lookup and therefore no cache-
 * timing channel. The canonical FIPS-197 table is retained only as a build-
 * time validation oracle (`determ_aes256_sbox_selftest`, driven exhaustively
 * by `determ test-aes-c99`). Correctness is gated byte-equal against OpenSSL +
 * the FIPS-197 KAT by `determ test-aes-c99`. */
#include "determ/crypto/aes/aes.h"
#include <string.h>

/* FIPS-197 Figure 7 substitution box — kept ONLY as the reference oracle that
 * the constant-time `aes_sbox_ct` is exhaustively validated against; it is not
 * indexed by the cipher itself (that would reintroduce the cache-timing leak). */
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* Constant-time field multiply over GF(2^8) mod 0x11b (the AES polynomial).
 * Branchless: a fixed 8 iterations with mask-selected partial-product XOR and
 * mask-selected reduction — no secret-dependent branch or memory access. */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        p ^= (uint8_t)(a & (uint8_t)(0u - (uint8_t)(b & 1)));   /* p ^= a if b0 set */
        {
            uint8_t hi = (uint8_t)(0u - (uint8_t)((a >> 7) & 1)); /* 0xff if MSB set */
            a = (uint8_t)(a << 1);
            a ^= (uint8_t)(0x1b & hi);                          /* reduce mod 0x11b */
        }
        b = (uint8_t)(b >> 1);
    }
    return p;
}

/* Multiplicative inverse in GF(2^8) as x^254 (= x^-1 for x != 0; maps 0 -> 0,
 * matching the AES S-box convention), via a fixed square-and-multiply addition
 * chain — value-independent, hence constant-time. */
static uint8_t gf_inv(uint8_t x) {
    uint8_t x2   = gf_mul(x, x);       /* x^2   */
    uint8_t x4   = gf_mul(x2, x2);     /* x^4   */
    uint8_t x8   = gf_mul(x4, x4);     /* x^8   */
    uint8_t x16  = gf_mul(x8, x8);     /* x^16  */
    uint8_t x32  = gf_mul(x16, x16);   /* x^32  */
    uint8_t x64  = gf_mul(x32, x32);   /* x^64  */
    uint8_t x128 = gf_mul(x64, x64);   /* x^128 */
    uint8_t r = gf_mul(x128, x64);     /* x^192 */
    r = gf_mul(r, x32);                /* x^224 */
    r = gf_mul(r, x16);                /* x^240 */
    r = gf_mul(r, x8);                 /* x^248 */
    r = gf_mul(r, x4);                 /* x^252 */
    r = gf_mul(r, x2);                 /* x^254 */
    return r;
}

static uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((uint8_t)(x << n) | (uint8_t)(x >> (8 - n)));
}

/* AES S-box computed constant-time: the GF(2^8) inverse followed by the
 * FIPS-197 affine map  s = b ^ (b<<<1) ^ (b<<<2) ^ (b<<<3) ^ (b<<<4) ^ 0x63.
 * No key-dependent table index, so it is not a cache-timing target. */
static uint8_t aes_sbox_ct(uint8_t x) {
    uint8_t b = gf_inv(x);
    return (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63);
}

/* Build-time validation hook: exhaustively assert the constant-time S-box is
 * byte-identical to the canonical FIPS-197 table over all 256 inputs. Returns
 * 1 on full match, 0 otherwise. Driven by `determ test-aes-c99`. */
int determ_aes256_sbox_selftest(void) {
    int i;
    for (i = 0; i < 256; i++)
        if (aes_sbox_ct((uint8_t)i) != SBOX[i]) return 0;
    return 1;
}

void determ_aes256_init(determ_aes256_ctx *ctx, const uint8_t key[32]) {
    uint8_t *rk = ctx->rk;
    uint8_t rcon = 0x01;
    int i;
    memcpy(rk, key, 32);                       /* first two round keys = the key */
    for (i = 32; i < 240; i += 4) {
        uint8_t t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];
        if ((i % 32) == 0) {
            /* RotWord -> SubWord -> XOR Rcon */
            uint8_t a = t0;
            t0 = (uint8_t)(aes_sbox_ct(t1) ^ rcon);
            t1 = aes_sbox_ct(t2);
            t2 = aes_sbox_ct(t3);
            t3 = aes_sbox_ct(a);
            rcon = xtime(rcon);
        } else if ((i % 32) == 16) {
            /* AES-256: an extra SubWord on the middle word */
            t0 = aes_sbox_ct(t0); t1 = aes_sbox_ct(t1);
            t2 = aes_sbox_ct(t2); t3 = aes_sbox_ct(t3);
        }
        rk[i + 0] = (uint8_t)(rk[i - 32] ^ t0);
        rk[i + 1] = (uint8_t)(rk[i - 31] ^ t1);
        rk[i + 2] = (uint8_t)(rk[i - 30] ^ t2);
        rk[i + 3] = (uint8_t)(rk[i - 29] ^ t3);
    }
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t;
    /* state is column-major: byte (row r, col c) = s[r + 4*c]; rotate row r left by r */
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;        /* row 1 <<< 1 */
    t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t; /* row 2 <<< 2 */
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;        /* row 3 <<< 3 */
}

static void mix_columns(uint8_t s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t *col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);          /* 2a0 ^ 3a1 ^ a2 ^ a3 */
        col[1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);          /* a0 ^ 2a1 ^ 3a2 ^ a3 */
        col[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));          /* a0 ^ a1 ^ 2a2 ^ 3a3 */
        col[3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));          /* 3a0 ^ a1 ^ a2 ^ 2a3 */
    }
}

void determ_aes256_encrypt_block(const determ_aes256_ctx *ctx,
                                 const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int round, i;
    memcpy(s, in, 16);
    for (i = 0; i < 16; i++) s[i] ^= ctx->rk[i];        /* AddRoundKey (round 0) */
    for (round = 1; round < 14; round++) {
        for (i = 0; i < 16; i++) s[i] = aes_sbox_ct(s[i]); /* SubBytes (constant-time) */
        shift_rows(s);
        mix_columns(s);
        for (i = 0; i < 16; i++) s[i] ^= ctx->rk[round * 16 + i];
    }
    for (i = 0; i < 16; i++) s[i] = aes_sbox_ct(s[i]);   /* final round (no MixColumns) */
    shift_rows(s);
    for (i = 0; i < 16; i++) s[i] ^= ctx->rk[14 * 16 + i];
    memcpy(out, s, 16);
}
