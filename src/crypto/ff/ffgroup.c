/* Determ C99 finite-field Pedersen commitment over the RFC 3526 MODP-3072
 * prime-order subgroup — CRYPTO-C99-SPEC.md §3.20 increment 1. See ffgroup.h.
 *
 * Ported from tools/verify_ff_pedersen.py (python-prove-first); the byte-exact
 * commitment KAT vs that Python (which uses native bignums) is the §3.13 dual-oracle
 * gate (ff_pedersen.json). Portable C99: 32-bit-limb CIOS Montgomery multiplication
 * (Koç–Acar–Kaliski), no __int128 / intrinsics. NOT constant-time (owner-gated). */
#include "determ/crypto/ff/ffgroup.h"
#include "ff_params.h"                 /* GENERATED (same dir): P, Q, R2, H, NPRIME */

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

/* out = a * b * R^{-1} mod p  (CIOS Montgomery, R = 2^3072). a, b < p => out < p. */
static void montmul(uint32_t out[96], const uint32_t a[96], const uint32_t b[96]) {
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

        uint32_t m = (uint32_t)((uint64_t)t[0] * DETERM_FF_NPRIME);   /* mod 2^32 */
        C = ((uint64_t)t[0] + (uint64_t)m * DETERM_FF_P[0]) >> 32;    /* low limb -> 0 */
        for (int j = 1; j < S; j++) {   /* t = (t + m * p) / 2^32 */
            uint64_t y = (uint64_t)t[j] + (uint64_t)m * DETERM_FF_P[j] + C;
            t[j - 1] = (uint32_t)y; C = y >> 32;
        }
        uint64_t y = (uint64_t)t[S] + C;
        t[S - 1] = (uint32_t)y;
        t[S] = (uint32_t)((uint64_t)t[S + 1] + (y >> 32));
    }
    /* t (limbs 0..S, < 2p) : conditionally subtract p once. */
    uint32_t tmp[96];
    uint64_t br = 0;
    for (int j = 0; j < S; j++) {
        uint64_t d = (uint64_t)t[j] - (uint64_t)DETERM_FF_P[j] - br;
        tmp[j] = (uint32_t)d; br = (d >> 32) & 1;
    }
    if (t[S] != 0 || br == 0) memcpy(out, tmp, S * 4);   /* t >= p => use t - p */
    else                       memcpy(out, t, S * 4);
}

static void to_mont(uint32_t out[96], const uint32_t a[96]) { montmul(out, a, DETERM_FF_R2); }
static void from_mont(uint32_t out[96], const uint32_t a[96]) { montmul(out, a, ONE_LIMB); }

/* out = base^exp mod p (both normal domain, exp < q). */
static void modexp(uint32_t out[96], const uint32_t base[96], const uint32_t exp[96]) {
    uint32_t bm[96], res[96];
    to_mont(bm, base);
    to_mont(res, ONE_LIMB);             /* mont(1) = R mod p */
    for (int limb = 95; limb >= 0; limb--) {
        uint32_t e = exp[limb];
        for (int bit = 31; bit >= 0; bit--) {
            montmul(res, res, res);
            if ((e >> bit) & 1u) montmul(res, res, bm);
        }
    }
    from_mont(out, res);
}

/* out = a * b mod p (normal domain). */
static void modmul_normal(uint32_t out[96], const uint32_t a[96], const uint32_t b[96]) {
    uint32_t am[96];
    to_mont(am, a);
    montmul(out, am, b);                /* (a*R)*b*R^{-1} = a*b */
}

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
