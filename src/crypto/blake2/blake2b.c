/* Determ C99-native BLAKE2b (RFC 7693). Canonical reference construction; no
 * libsodium. See include/determ/crypto/blake2/blake2b.h. */
#include <determ/crypto/blake2/blake2b.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t SIGMA[12][16] = {
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    { 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    { 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    {  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    {  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    {  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    { 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    { 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    {  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    { 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

static uint64_t load64(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)| ((uint64_t)p[5] << 40)| ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}
static void store64(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; } }
static uint64_t rotr64(uint64_t w, unsigned c) { return (w >> c) | (w << (64 - c)); }

#define G(r,i,a,b,c,d) \
    do { \
        a = a + b + m[SIGMA[r][2*i]];   d = rotr64(d ^ a, 32); \
        c = c + d;                      b = rotr64(b ^ c, 24); \
        a = a + b + m[SIGMA[r][2*i+1]]; d = rotr64(d ^ a, 16); \
        c = c + d;                      b = rotr64(b ^ c, 63); \
    } while (0)

static void compress(determ_blake2b_ctx *ctx, const uint8_t block[128]) {
    uint64_t m[16], v[16]; int i, r;
    for (i = 0; i < 16; i++) m[i] = load64(block + 8 * i);
    for (i = 0; i < 8; i++)  v[i] = ctx->h[i];
    for (i = 0; i < 8; i++)  v[8 + i] = IV[i];
    v[12] ^= ctx->t[0]; v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0]; v[15] ^= ctx->f[1];
    for (r = 0; r < 12; r++) {
        G(r,0, v[0],v[4],v[8], v[12]);
        G(r,1, v[1],v[5],v[9], v[13]);
        G(r,2, v[2],v[6],v[10],v[14]);
        G(r,3, v[3],v[7],v[11],v[15]);
        G(r,4, v[0],v[5],v[10],v[15]);
        G(r,5, v[1],v[6],v[11],v[12]);
        G(r,6, v[2],v[7],v[8], v[13]);
        G(r,7, v[3],v[4],v[9], v[14]);
    }
    for (i = 0; i < 8; i++) ctx->h[i] ^= v[i] ^ v[8 + i];
}

static void increment_counter(determ_blake2b_ctx *ctx, uint64_t inc) {
    ctx->t[0] += inc;
    if (ctx->t[0] < inc) ctx->t[1]++;
}

int determ_blake2b_init(determ_blake2b_ctx *ctx, size_t outlen,
                        const uint8_t *key, size_t keylen) {
    int i;
    if (outlen == 0 || outlen > 64 || keylen > 64) return -1;
    memset(ctx, 0, sizeof *ctx);
    for (i = 0; i < 8; i++) ctx->h[i] = IV[i];
    /* param block low word: digest_length | key_length<<8 | fanout=1<<16 | depth=1<<24 */
    ctx->h[0] ^= 0x01010000ULL ^ ((uint64_t)keylen << 8) ^ (uint64_t)outlen;
    ctx->outlen = outlen;
    ctx->buflen = 0;
    if (keylen > 0) {
        uint8_t block[128];
        memset(block, 0, sizeof block);
        memcpy(block, key, keylen);
        determ_blake2b_update(ctx, block, 128);   /* key is its own full first block */
        determ_secure_zero(block, sizeof block);
    }
    return 0;
}

void determ_blake2b_update(determ_blake2b_ctx *ctx, const uint8_t *in, size_t inlen) {
    size_t left, fill;
    if (inlen == 0) return;
    left = ctx->buflen;
    fill = DETERM_BLAKE2B_BLOCKBYTES - left;
    if (inlen > fill) {
        ctx->buflen = 0;
        memcpy(ctx->buf + left, in, fill);
        increment_counter(ctx, DETERM_BLAKE2B_BLOCKBYTES);
        compress(ctx, ctx->buf);
        in += fill; inlen -= fill;
        while (inlen > DETERM_BLAKE2B_BLOCKBYTES) {
            increment_counter(ctx, DETERM_BLAKE2B_BLOCKBYTES);
            compress(ctx, in);
            in += DETERM_BLAKE2B_BLOCKBYTES; inlen -= DETERM_BLAKE2B_BLOCKBYTES;
        }
    }
    memcpy(ctx->buf + ctx->buflen, in, inlen);
    ctx->buflen += inlen;
}

void determ_blake2b_final(determ_blake2b_ctx *ctx, uint8_t *out) {
    uint8_t buffer[64]; int i;
    increment_counter(ctx, ctx->buflen);
    ctx->f[0] = (uint64_t)-1;                                  /* last-block flag */
    memset(ctx->buf + ctx->buflen, 0, DETERM_BLAKE2B_BLOCKBYTES - ctx->buflen);
    compress(ctx, ctx->buf);
    for (i = 0; i < 8; i++) store64(buffer + 8 * i, ctx->h[i]);
    memcpy(out, buffer, ctx->outlen);
    determ_secure_zero(buffer, sizeof buffer);
    determ_secure_zero(ctx, sizeof *ctx);
}

int determ_blake2b(uint8_t *out, size_t outlen,
                   const uint8_t *key, size_t keylen,
                   const uint8_t *in, size_t inlen) {
    determ_blake2b_ctx ctx;
    if (determ_blake2b_init(&ctx, outlen, key, keylen) != 0) return -1;
    determ_blake2b_update(&ctx, in, inlen);
    determ_blake2b_final(&ctx, out);
    return 0;
}
