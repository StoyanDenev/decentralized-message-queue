/* Determ C99 finite-field Pedersen commitment over the RFC 3526 MODP-3072
 * prime-order subgroup — CRYPTO-C99-SPEC.md §3.20 increment 1. See ffgroup.h.
 *
 * Ported from tools/verify_ff_pedersen.py (python-prove-first); the byte-exact
 * commitment KAT vs that Python (which uses native bignums) is the §3.13 dual-oracle
 * gate (ff_pedersen.json). Portable C99: 32-bit-limb CIOS Montgomery multiplication
 * (Koç–Acar–Kaliski), no __int128 / intrinsics. NOT constant-time (owner-gated). */
#include "determ/crypto/ff/ffgroup.h"
#include "ff_params.h"                 /* GENERATED (same dir): P, Q, R2, H, NPRIME */
#include "determ/crypto/sha2/sha2.h"   /* determ_sha256 — hash-to-group (inc.2) */

#include <string.h>

#define S DETERM_FF_LIMBS              /* 96 */

static const uint32_t ONE_LIMB[96] = { 1, 0 };     /* rest zero-initialised */
static const uint32_t G_LIMB[96]   = { 4, 0 };     /* g = 4 */

/* big-endian 384 bytes -> 96 little-endian uint32 limbs, and back. */
static void be_load(uint32_t out[96], const uint8_t b[384]) {
    for (int i = 0; i < 96; i++) {
        const uint8_t *p = b + 4 * (95 - i);
        out[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
               | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
    }
}
static void be_store(uint8_t b[384], const uint32_t in[96]) {
    for (int i = 0; i < 96; i++) {
        uint8_t *p = b + 4 * (95 - i);
        p[0] = (uint8_t)(in[i] >> 24); p[1] = (uint8_t)(in[i] >> 16);
        p[2] = (uint8_t)(in[i] >> 8);  p[3] = (uint8_t)in[i];
    }
}

/* a >= b over 96 little-endian limbs (unsigned). */
static int ff_ge(const uint32_t a[96], const uint32_t b[96]) {
    for (int i = 95; i >= 0; i--)
        if (a[i] != b[i]) return a[i] > b[i];
    return 1;                           /* equal => a >= b */
}
static int ff_is_zero(const uint32_t a[96]) {
    uint32_t x = 0; for (int i = 0; i < 96; i++) x |= a[i];
    return x == 0;
}
static int ff_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* A Montgomery context: the modulus (96 limbs), R^2 mod modulus, and -modulus^{-1} mod
 * 2^32. Group ELEMENTS live mod p (CTX_P); the scalar/exponent field lives mod q
 * (CTX_Q — §3.20 inc.3, the subgroup order). One CIOS routine, two moduli. */
typedef struct { const uint32_t *M; const uint32_t *R2; uint32_t nprime; } ff_ctx;
static const ff_ctx CTX_P = { DETERM_FF_P, DETERM_FF_R2,  DETERM_FF_NPRIME };
static const ff_ctx CTX_Q = { DETERM_FF_Q, DETERM_FF_QR2, DETERM_FF_QNPRIME };

/* out = a * b * R^{-1} mod M  (CIOS Montgomery, R = 2^3072). a, b < M => out < M. */
static void montmul_c(uint32_t out[96], const uint32_t a[96], const uint32_t b[96],
                      const ff_ctx *c) {
    const uint32_t *M = c->M;
    uint32_t t[98];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < S; i++) {
        uint32_t bi = b[i];
        uint64_t C = 0;
        for (int j = 0; j < S; j++) {   /* t = t + a * b[i] */
            uint64_t x = (uint64_t)t[j] + (uint64_t)a[j] * bi + C;
            t[j] = (uint32_t)x; C = x >> 32;
        }
        uint64_t x = (uint64_t)t[S] + C;
        t[S] = (uint32_t)x; t[S + 1] = (uint32_t)(x >> 32);

        uint32_t m = (uint32_t)((uint64_t)t[0] * c->nprime);     /* mod 2^32 */
        C = ((uint64_t)t[0] + (uint64_t)m * M[0]) >> 32;         /* low limb -> 0 */
        for (int j = 1; j < S; j++) {   /* t = (t + m * M) / 2^32 */
            uint64_t y = (uint64_t)t[j] + (uint64_t)m * M[j] + C;
            t[j - 1] = (uint32_t)y; C = y >> 32;
        }
        uint64_t y = (uint64_t)t[S] + C;
        t[S - 1] = (uint32_t)y;
        t[S] = (uint32_t)((uint64_t)t[S + 1] + (y >> 32));
    }
    /* t (limbs 0..S, < 2M) : conditionally subtract M once. */
    uint32_t tmp[96];
    uint64_t br = 0;
    for (int j = 0; j < S; j++) {
        uint64_t d = (uint64_t)t[j] - (uint64_t)M[j] - br;
        tmp[j] = (uint32_t)d; br = (d >> 32) & 1;
    }
    if (t[S] != 0 || br == 0) memcpy(out, tmp, S * 4);   /* t >= M => use t - M */
    else                       memcpy(out, t, S * 4);
}

static void to_mont_c(uint32_t out[96], const uint32_t a[96], const ff_ctx *c)   { montmul_c(out, a, c->R2, c); }
static void from_mont_c(uint32_t out[96], const uint32_t a[96], const ff_ctx *c) { montmul_c(out, a, ONE_LIMB, c); }

/* out = base^exp mod M (both normal domain, exp any 3072-bit). */
static void modexp_c(uint32_t out[96], const uint32_t base[96], const uint32_t exp[96],
                     const ff_ctx *c) {
    uint32_t bm[96], res[96];
    to_mont_c(bm, base, c);
    to_mont_c(res, ONE_LIMB, c);        /* mont(1) = R mod M */
    for (int limb = 95; limb >= 0; limb--) {
        uint32_t e = exp[limb];
        for (int bit = 31; bit >= 0; bit--) {
            montmul_c(res, res, res, c);
            if ((e >> bit) & 1u) montmul_c(res, res, bm, c);
        }
    }
    from_mont_c(out, res, c);
}

/* out = a * b mod M (normal domain). */
static void modmul_normal_c(uint32_t out[96], const uint32_t a[96], const uint32_t b[96],
                            const ff_ctx *c) {
    uint32_t am[96];
    to_mont_c(am, a, c);
    montmul_c(out, am, b, c);           /* (a*R)*b*R^{-1} = a*b */
}

/* mod-p convenience wrappers — byte-identical to the pre-inc.3 fixed-modulus routines
 * (the ff_pedersen.json / bp corpora are the byte-identity guard). */
static void montmul(uint32_t out[96], const uint32_t a[96], const uint32_t b[96])       { montmul_c(out, a, b, &CTX_P); }
static void modexp(uint32_t out[96], const uint32_t base[96], const uint32_t exp[96])   { modexp_c(out, base, exp, &CTX_P); }
static void modmul_normal(uint32_t out[96], const uint32_t a[96], const uint32_t b[96]) { modmul_normal_c(out, a, b, &CTX_P); }

int determ_ff_pedersen_generator_h(uint8_t out[DETERM_FF_ELEM_BYTES]) {
    be_store(out, DETERM_FF_H);
    return 0;
}

int determ_ff_pedersen_commit(uint8_t out[DETERM_FF_ELEM_BYTES],
                              const uint8_t v[DETERM_FF_ELEM_BYTES],
                              const uint8_t r[DETERM_FF_ELEM_BYTES]) {
    uint32_t vl[96], rl[96], gv[96], hr[96], c[96];
    be_load(vl, v); be_load(rl, r);
    if (ff_ge(vl, DETERM_FF_Q)) return -1;                     /* v >= q */
    if (ff_is_zero(rl) || ff_ge(rl, DETERM_FF_Q)) return -1;   /* r == 0 or r >= q */
    modexp(gv, G_LIMB, vl);
    modexp(hr, DETERM_FF_H, rl);
    modmul_normal(c, gv, hr);
    be_store(out, c);
    return 0;
}

int determ_ff_pedersen_verify(const uint8_t commitment[DETERM_FF_ELEM_BYTES],
                              const uint8_t v[DETERM_FF_ELEM_BYTES],
                              const uint8_t r[DETERM_FF_ELEM_BYTES]) {
    uint8_t c[DETERM_FF_ELEM_BYTES];
    if (determ_ff_pedersen_commit(c, v, r) != 0) return -1;
    return ff_bytes_eq(c, commitment, DETERM_FF_ELEM_BYTES) ? 0 : -1;
}

int determ_ff_pedersen_add(uint8_t out[DETERM_FF_ELEM_BYTES],
                           const uint8_t c1[DETERM_FF_ELEM_BYTES],
                           const uint8_t c2[DETERM_FF_ELEM_BYTES]) {
    uint32_t a[96], b[96], c[96];
    be_load(a, c1); be_load(b, c2);
    if (ff_ge(a, DETERM_FF_P) || ff_ge(b, DETERM_FF_P)) return -1;   /* not reduced */
    modmul_normal(c, a, b);
    be_store(out, c);
    return 0;
}

/* ── §3.20 increment 2: vector-commitment generators + vector commit + MSM ──── */

static int ff_is_one(const uint32_t a[96]) {
    if (a[0] != 1) return 0;
    uint32_t x = 0; for (int i = 1; i < 96; i++) x |= a[i];
    return x == 0;
}

/* acc <<= 1 across 96 limbs; returns the bit shifted out of the top (bit 3072). */
static uint32_t ff_shl1(uint32_t a[96]) {
    uint32_t carry = 0;
    for (int i = 0; i < 96; i++) {
        uint32_t nc = a[i] >> 31;
        a[i] = (a[i] << 1) | carry;
        carry = nc;
    }
    return carry;
}

/* acc -= M (unconditionally; caller guarantees acc >= M). */
static void ff_sub_mod(uint32_t a[96], const uint32_t M[96]) {
    uint32_t tmp[96];
    uint64_t br = 0;
    for (int j = 0; j < S; j++) {
        uint64_t d = (uint64_t)a[j] - (uint64_t)M[j] - br;
        tmp[j] = (uint32_t)d; br = (d >> 32) & 1;
    }
    memcpy(a, tmp, S * 4);
}

/* acc = int(material[0..mlen), big-endian) mod M, via bit-Horner (MSB-first). Each step
 * doubles acc (< 2M) and adds one message bit, then one conditional subtract of M keeps
 * acc < M — byte-identical to Python's int.from_bytes(material,"big") % M. Used with p
 * (hash-to-group) and with q (hash-to-scalar / scalar_reduce, §3.20 inc.3). */
static void ff_mod_reduce_wide(uint32_t acc[96], const uint8_t *material, size_t mlen,
                               const uint32_t M[96]) {
    memset(acc, 0, S * 4);
    for (size_t k = 0; k < mlen; k++) {
        uint8_t byte = material[k];
        for (int bit = 7; bit >= 0; bit--) {
            uint32_t carry = ff_shl1(acc);       /* acc = 2*acc, capturing bit 3072 */
            acc[0] |= (uint32_t)((byte >> bit) & 1u);
            if (carry || ff_ge(acc, M)) ff_sub_mod(acc, M);
        }
    }
}

/* Hash-to-group: 13 SHA-256 blocks of (prefix || counter) -> 416 bytes -> reduce
 * mod p -> SQUARE into the order-q QR subgroup G_q. out is normal-domain < p, != 0,1.
 * Returns 0, or -1 on the negligible degenerate square (out in {0,1}). */
static int ff_hash_to_group(uint32_t out[96], const uint8_t *prefix, size_t plen) {
    uint8_t material[416];
    uint8_t blk[64];
    memcpy(blk, prefix, plen);                   /* plen <= 40 for our DSTs */
    for (int i = 0; i < 13; i++) {
        blk[plen] = (uint8_t)i;
        determ_sha256(blk, plen + 1, material + 32 * i);
    }
    uint32_t hs[96];
    ff_mod_reduce_wide(hs, material, 416, DETERM_FF_P);
    modmul_normal(out, hs, hs);                  /* out = hs^2 mod p, order q */
    if (ff_is_zero(out) || ff_is_one(out)) return -1;
    return 0;
}

static const uint8_t FF_VG_DST[] = "DETERM-FF-PEDERSEN-VEC-G-MODP3072-v1";
static const uint8_t FF_VH_DST[] = "DETERM-FF-PEDERSEN-VEC-H-MODP3072-v1";

/* limbs-out generator (internal): out = gen(index, which), normal-domain < p. */
static int ff_gen_limbs(uint32_t out[96], uint32_t index, uint8_t which) {
    const uint8_t *dst; size_t dl;
    if (which == 0)      { dst = FF_VG_DST; dl = sizeof(FF_VG_DST) - 1; }
    else if (which == 1) { dst = FF_VH_DST; dl = sizeof(FF_VH_DST) - 1; }
    else return -1;
    uint8_t prefix[64];
    memcpy(prefix, dst, dl);
    prefix[dl + 0] = (uint8_t)(index >> 24); prefix[dl + 1] = (uint8_t)(index >> 16);
    prefix[dl + 2] = (uint8_t)(index >> 8);  prefix[dl + 3] = (uint8_t)index;
    return ff_hash_to_group(out, prefix, dl + 4);
}

int determ_ff_gen(uint8_t out[DETERM_FF_ELEM_BYTES], uint32_t index, uint8_t which) {
    uint32_t g[96];
    if (ff_gen_limbs(g, index, which) != 0) return -1;
    be_store(out, g);
    return 0;
}

int determ_ff_vector_commit(uint8_t out[DETERM_FF_ELEM_BYTES],
                            const uint8_t *a, const uint8_t *b,
                            size_t n, const uint8_t r[DETERM_FF_ELEM_BYTES]) {
    uint32_t rl[96], acc[96], sl[96], gen[96], term[96];
    be_load(rl, r);
    if (ff_is_zero(rl) || ff_ge(rl, DETERM_FF_Q)) return -1;         /* r == 0 or r >= q */
    modexp(acc, DETERM_FF_H, rl);                                    /* acc = h^r */
    for (size_t i = 0; i < n; i++) {
        be_load(sl, a + i * DETERM_FF_ELEM_BYTES);                   /* a_i * G_i */
        if (ff_ge(sl, DETERM_FF_Q)) return -1;
        if (!ff_is_zero(sl)) {
            if (ff_gen_limbs(gen, (uint32_t)i, 0) != 0) return -1;
            modexp(term, gen, sl);
            modmul_normal(acc, acc, term);
        }
        be_load(sl, b + i * DETERM_FF_ELEM_BYTES);                   /* b_i * H_i */
        if (ff_ge(sl, DETERM_FF_Q)) return -1;
        if (!ff_is_zero(sl)) {
            if (ff_gen_limbs(gen, (uint32_t)i, 1) != 0) return -1;
            modexp(term, gen, sl);
            modmul_normal(acc, acc, term);
        }
    }
    be_store(out, acc);
    return 0;
}

int determ_ff_msm(uint8_t out[DETERM_FF_ELEM_BYTES],
                  const uint8_t *scalars, const uint8_t *points, size_t n) {
    uint32_t acc[96], sl[96], pl[96], term[96];
    memset(acc, 0, sizeof(acc)); acc[0] = 1;                         /* identity = 1 */
    for (size_t i = 0; i < n; i++) {
        be_load(sl, scalars + i * DETERM_FF_ELEM_BYTES);
        if (ff_ge(sl, DETERM_FF_Q)) return -1;                       /* scalar >= q */
        if (ff_is_zero(sl)) continue;                                /* skip before reading the point */
        be_load(pl, points + i * DETERM_FF_ELEM_BYTES);
        if (ff_is_zero(pl) || ff_ge(pl, DETERM_FF_P)) return -1;     /* point 0 or >= p */
        modexp(term, pl, sl);
        modmul_normal(acc, acc, term);
    }
    be_store(out, acc);
    return 0;
}

/* ── §3.20 increment 3: scalar field arithmetic mod q (the subgroup order) ──── */

int determ_ff_scalar_reduce(uint8_t out[DETERM_FF_ELEM_BYTES],
                            const uint8_t in[DETERM_FF_ELEM_BYTES]) {
    uint32_t r[96];
    ff_mod_reduce_wide(r, in, DETERM_FF_ELEM_BYTES, DETERM_FF_Q);   /* in mod q */
    be_store(out, r);
    return 0;
}

int determ_ff_scalar_add(uint8_t out[DETERM_FF_ELEM_BYTES],
                         const uint8_t a[DETERM_FF_ELEM_BYTES],
                         const uint8_t b[DETERM_FF_ELEM_BYTES]) {
    uint32_t al[96], bl[96], s[96];
    be_load(al, a); be_load(bl, b);
    if (ff_ge(al, DETERM_FF_Q) || ff_ge(bl, DETERM_FF_Q)) return -1;   /* not reduced */
    uint64_t carry = 0;
    for (int i = 0; i < S; i++) { uint64_t x = (uint64_t)al[i] + bl[i] + carry; s[i] = (uint32_t)x; carry = x >> 32; }
    if (carry || ff_ge(s, DETERM_FF_Q)) ff_sub_mod(s, DETERM_FF_Q);   /* a+b < 2q -> one subtract */
    be_store(out, s);
    return 0;
}

int determ_ff_scalar_mul(uint8_t out[DETERM_FF_ELEM_BYTES],
                         const uint8_t a[DETERM_FF_ELEM_BYTES],
                         const uint8_t b[DETERM_FF_ELEM_BYTES]) {
    uint32_t al[96], bl[96], r[96];
    be_load(al, a); be_load(bl, b);
    if (ff_ge(al, DETERM_FF_Q) || ff_ge(bl, DETERM_FF_Q)) return -1;   /* not reduced */
    modmul_normal_c(r, al, bl, &CTX_Q);                               /* a*b mod q */
    be_store(out, r);
    return 0;
}

int determ_ff_scalar_sub(uint8_t out[DETERM_FF_ELEM_BYTES],
                         const uint8_t a[DETERM_FF_ELEM_BYTES],
                         const uint8_t b[DETERM_FF_ELEM_BYTES]) {
    uint32_t al[96], bl[96], negb[96], s[96];
    be_load(al, a); be_load(bl, b);
    if (ff_ge(al, DETERM_FF_Q) || ff_ge(bl, DETERM_FF_Q)) return -1;   /* not reduced */
    if (ff_is_zero(bl)) { be_store(out, al); return 0; }              /* a - 0 = a */
    uint64_t br = 0;                                                  /* negb = q - b, in (0,q) */
    for (int j = 0; j < S; j++) { uint64_t d = (uint64_t)DETERM_FF_Q[j] - bl[j] - br; negb[j] = (uint32_t)d; br = (d >> 32) & 1; }
    uint64_t carry = 0;                                              /* s = (a + negb) mod q */
    for (int i = 0; i < S; i++) { uint64_t x = (uint64_t)al[i] + negb[i] + carry; s[i] = (uint32_t)x; carry = x >> 32; }
    if (carry || ff_ge(s, DETERM_FF_Q)) ff_sub_mod(s, DETERM_FF_Q);
    be_store(out, s);
    return 0;
}

int determ_ff_scalar_inv(uint8_t out[DETERM_FF_ELEM_BYTES],
                         const uint8_t a[DETERM_FF_ELEM_BYTES]) {
    uint32_t al[96], qm2[96], r[96], two[96];
    be_load(al, a);
    if (ff_is_zero(al) || ff_ge(al, DETERM_FF_Q)) return -1;           /* 0 or >= q */
    memset(two, 0, sizeof(two)); two[0] = 2;                          /* qm2 = q - 2 */
    uint64_t br = 0;
    for (int j = 0; j < S; j++) { uint64_t d = (uint64_t)DETERM_FF_Q[j] - two[j] - br; qm2[j] = (uint32_t)d; br = (d >> 32) & 1; }
    modexp_c(r, al, qm2, &CTX_Q);                                     /* a^{q-2} mod q */
    be_store(out, r);
    return 0;
}

int determ_ff_hash_to_scalar(uint8_t out[DETERM_FF_ELEM_BYTES],
                             const uint8_t *msg, size_t mlen,
                             const uint8_t *dst, size_t dstlen) {
    uint8_t material[416];
    for (int i = 0; i < 13; i++) {                                   /* 13 blocks -> 416 B > q */
        determ_sha256_ctx ctx;
        determ_sha256_init(&ctx);
        determ_sha256_update(&ctx, dst, dstlen);
        determ_sha256_update(&ctx, msg, mlen);
        uint8_t cb = (uint8_t)i;
        determ_sha256_update(&ctx, &cb, 1);
        determ_sha256_final(&ctx, material + 32 * i);
    }
    uint32_t r[96];
    ff_mod_reduce_wide(r, material, 416, DETERM_FF_Q);               /* mod q */
    if (ff_is_zero(r)) return -1;                                    /* zero scalar unusable */
    be_store(out, r);
    return 0;
}
