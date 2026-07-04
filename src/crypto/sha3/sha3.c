/* Determ C99-native SHA-3 / SHAKE (NIST FIPS 202) on Keccak-f[1600].
 * Canonical reference construction; no external dependency.
 * See include/determ/crypto/sha3/sha3.h. */
#include <determ/crypto/sha3/sha3.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/* Keccak-f[1600] permutation: 24 rounds of theta, rho+pi, chi, iota. */
static void keccakf(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };
    static const int ROTC[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    static const int PILN[24] = {
        10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1
    };
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < 24; r++) {
        /* Theta */
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        /* Rho + Pi */
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = PILN[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, ROTC[i]);
            t = bc[0];
        }
        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        /* Iota */
        st[0] ^= RC[r];
    }
}

/* XOR one byte into the little-endian lane-packed state at byte offset `off`. */
static void state_xor_byte(uint64_t s[25], size_t off, uint8_t b) {
    s[off >> 3] ^= (uint64_t)b << (8u * (off & 7u));
}

/* Extract one byte from the little-endian lane-packed state at byte offset `off`. */
static uint8_t state_get_byte(const uint64_t s[25], size_t off) {
    return (uint8_t)(s[off >> 3] >> (8u * (off & 7u)));
}

void determ_keccak_init(determ_keccak_ctx* ctx, size_t rate, uint8_t dsbyte) {
    memset(ctx->s, 0, sizeof ctx->s);
    ctx->rate = rate;
    ctx->pos = 0;
    ctx->dsbyte = dsbyte;
    ctx->squeezing = 0;
}

void determ_keccak_absorb(determ_keccak_ctx* ctx, const uint8_t* in, size_t inlen) {
    size_t i;
    for (i = 0; i < inlen; i++) {
        state_xor_byte(ctx->s, ctx->pos, in[i]);
        if (++ctx->pos == ctx->rate) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void determ_keccak_finalize(determ_keccak_ctx* ctx) {
    if (ctx->squeezing) return;
    /* pad10*1: pad-start byte at current position, 0x80 at the last rate byte. */
    state_xor_byte(ctx->s, ctx->pos, ctx->dsbyte);
    state_xor_byte(ctx->s, ctx->rate - 1, 0x80u);
    keccakf(ctx->s);
    ctx->pos = 0;
    ctx->squeezing = 1;
}

void determ_keccak_squeeze(determ_keccak_ctx* ctx, uint8_t* out, size_t outlen) {
    size_t i;
    if (!ctx->squeezing)
        determ_keccak_finalize(ctx);
    for (i = 0; i < outlen; i++) {
        if (ctx->pos == ctx->rate) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
        out[i] = state_get_byte(ctx->s, ctx->pos);
        ctx->pos++;
    }
}

void determ_shake128_init(determ_keccak_ctx* ctx) {
    determ_keccak_init(ctx, DETERM_SHAKE128_RATE, DETERM_SHAKE_DOMAIN);
}
void determ_shake256_init(determ_keccak_ctx* ctx) {
    determ_keccak_init(ctx, DETERM_SHAKE256_RATE, DETERM_SHAKE_DOMAIN);
}

static void sha3_oneshot(size_t rate, uint8_t* out, size_t outlen,
                         const uint8_t* in, size_t inlen) {
    determ_keccak_ctx ctx;
    determ_keccak_init(&ctx, rate, DETERM_SHA3_DOMAIN);
    determ_keccak_absorb(&ctx, in, inlen);
    determ_keccak_squeeze(&ctx, out, outlen);
    determ_secure_zero(&ctx, sizeof ctx);
}

void determ_sha3_256(uint8_t out[32], const uint8_t* in, size_t inlen) {
    sha3_oneshot(DETERM_SHA3_256_RATE, out, 32, in, inlen);
}
void determ_sha3_512(uint8_t out[64], const uint8_t* in, size_t inlen) {
    sha3_oneshot(DETERM_SHA3_512_RATE, out, 64, in, inlen);
}

void determ_shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    determ_keccak_ctx ctx;
    determ_shake128_init(&ctx);
    determ_keccak_absorb(&ctx, in, inlen);
    determ_keccak_squeeze(&ctx, out, outlen);
    determ_secure_zero(&ctx, sizeof ctx);
}
void determ_shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    determ_keccak_ctx ctx;
    determ_shake256_init(&ctx);
    determ_keccak_absorb(&ctx, in, inlen);
    determ_keccak_squeeze(&ctx, out, outlen);
    determ_secure_zero(&ctx, sizeof ctx);
}
