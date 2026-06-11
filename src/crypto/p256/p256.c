/* Determ C99-native NIST P-256 (CRYPTO-C99-SPEC.md §3.8c). See p256.h for the
 * construction overview and the wire conventions.
 *
 * Layout: 8x32-bit little-endian limbs internally; big-endian byte I/O (SEC1).
 * Field elements live in the Montgomery domain between to_mont/from_mont.
 * p ≡ -1 (mod 2^32)  =>  n0' = -p^{-1} mod 2^32 = 1, so the CIOS reduction
 * step's m is simply the low limb of the accumulator.
 *
 * Constant-time discipline (ConstantTimeInventory.md conventions): no
 * secret-dependent branch or index. The scalar ladder is double-and-add-
 * always over the RCB complete addition formula with a mask-select cswap per
 * bit; field add/sub/mul use branchless carry/borrow masks. Branches exist
 * only on PUBLIC data (encodings, validity outcomes, the one-time init flag).
 */
#include "determ/crypto/p256/p256.h"
#include "determ/crypto/secure_zero.h"

#include <string.h>

typedef uint32_t fe[8];   /* little-endian limbs */

/* ── curve constants (big-endian byte form; the canonical source is FIPS
 *    186-5 D.2.3 — asserted byte-equal vs OpenSSL EC_GROUP by the test
 *    before anything else, which is what makes them trustworthy here) ── */
static const uint8_t P_BE[32] = {
    0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff };
static const uint8_t N_BE[32] = {
    0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad, 0xa7,0x17,0x9e,0x84, 0xf3,0xb9,0xca,0xc2, 0xfc,0x63,0x25,0x51 };
static const uint8_t B_BE[32] = {
    0x5a,0xc6,0x35,0xd8, 0xaa,0x3a,0x93,0xe7, 0xb3,0xeb,0xbd,0x55, 0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0, 0xcc,0x53,0xb0,0xf6, 0x3b,0xce,0x3c,0x3e, 0x27,0xd2,0x60,0x4b };
static const uint8_t GX_BE[32] = {
    0x6b,0x17,0xd1,0xf2, 0xe1,0x2c,0x42,0x47, 0xf8,0xbc,0xe6,0xe5, 0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81, 0x2d,0xeb,0x33,0xa0, 0xf4,0xa1,0x39,0x45, 0xd8,0x98,0xc2,0x96 };
static const uint8_t GY_BE[32] = {
    0x4f,0xe3,0x42,0xe2, 0xfe,0x1a,0x7f,0x9b, 0x8e,0xe7,0xeb,0x4a, 0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57, 0x6b,0x31,0x5e,0xce, 0xcb,0xb6,0x40,0x68, 0x37,0xbf,0x51,0xf5 };

static void be_to_fe(fe r, const uint8_t in[32]) {
    int i;
    for (i = 0; i < 8; i++)
        r[i] = ((uint32_t)in[31-4*i]) | ((uint32_t)in[30-4*i] << 8)
             | ((uint32_t)in[29-4*i] << 16) | ((uint32_t)in[28-4*i] << 24);
}
static void fe_to_be(uint8_t out[32], const fe a) {
    int i;
    for (i = 0; i < 8; i++) {
        out[31-4*i] = (uint8_t)(a[i]);
        out[30-4*i] = (uint8_t)(a[i] >> 8);
        out[29-4*i] = (uint8_t)(a[i] >> 16);
        out[28-4*i] = (uint8_t)(a[i] >> 24);
    }
}

/* ── field arithmetic mod p ─────────────────────────────────────────────── */

static uint32_t P[8];     /* p as limbs (filled by init from P_BE) */

/* r = a + b mod p (a, b < p). Branchless: keep the 33rd carry bit, subtract p,
 * select pre/post-subtraction by mask(carry | no-borrow). */
static void fe_add(fe r, const fe a, const fe b) {
    uint32_t t[8], s[8];
    uint64_t c = 0, brw = 0;
    int i;
    for (i = 0; i < 8; i++) { c += (uint64_t)a[i] + b[i]; t[i] = (uint32_t)c; c >>= 32; }
    for (i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)t[i] - P[i] - brw;
        s[i] = (uint32_t)d; brw = (d >> 63) & 1;
    }
    /* use the subtracted form iff (sum carried out) OR (no borrow): sum >= p */
    {
        uint32_t use_s = (uint32_t)0 - (uint32_t)((c | (1 - brw)) & 1);
        for (i = 0; i < 8; i++) r[i] = (s[i] & use_s) | (t[i] & ~use_s);
    }
}

/* r = a - b mod p (a, b < p). Branchless add-p-on-borrow. */
static void fe_sub(fe r, const fe a, const fe b) {
    uint32_t t[8];
    uint64_t brw = 0, c = 0;
    uint32_t mask;
    int i;
    for (i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - brw;
        t[i] = (uint32_t)d; brw = (d >> 63) & 1;
    }
    mask = (uint32_t)0 - (uint32_t)brw;
    for (i = 0; i < 8; i++) {
        c += (uint64_t)t[i] + (P[i] & mask);
        r[i] = (uint32_t)c; c >>= 32;
    }
}

/* Montgomery multiplication: r = a*b*R^{-1} mod p, R = 2^256. CIOS with
 * n0' = 1 (p ≡ -1 mod 2^32). Accumulator t has 8+2 limbs. */
static void fe_mont_mul(fe r, const fe a, const fe b) {
    uint32_t t[10];
    int i, j;
    memset(t, 0, sizeof t);
    for (i = 0; i < 8; i++) {
        uint64_t c = 0;
        uint32_t m;
        for (j = 0; j < 8; j++) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (uint32_t)c; c >>= 32;
        }
        c += t[8]; t[8] = (uint32_t)c; t[9] = (uint32_t)(c >> 32);
        m = t[0];                                  /* m = t0 * n0' = t0 * 1 */
        c = (uint64_t)t[0] + (uint64_t)m * P[0];   /* low limb annihilates  */
        c >>= 32;
        for (j = 1; j < 8; j++) {
            c += (uint64_t)t[j] + (uint64_t)m * P[j];
            t[j-1] = (uint32_t)c; c >>= 32;
        }
        c += t[8]; t[7] = (uint32_t)c; c >>= 32;
        t[8] = t[9] + (uint32_t)c;
        t[9] = 0;
    }
    /* t (9 limbs, t[8] in {0,1}) < 2p: one branchless conditional subtract. */
    {
        uint32_t s[8], use_s;
        uint64_t brw = 0;
        for (i = 0; i < 8; i++) {
            uint64_t d = (uint64_t)t[i] - P[i] - brw;
            s[i] = (uint32_t)d; brw = (d >> 63) & 1;
        }
        use_s = (uint32_t)0 - (uint32_t)((t[8] | (1 - (uint32_t)brw)) & 1);
        for (i = 0; i < 8; i++) r[i] = (s[i] & use_s) | (t[i] & ~use_s);
    }
}

static void fe_mont_sqr(fe r, const fe a) { fe_mont_mul(r, a, a); }

/* branchless conditional swap (the ladder's only secret-driven operation) */
static void fe_cswap(fe a, fe b, uint32_t swap) {
    uint32_t mask = (uint32_t)0 - swap, d;
    int i;
    for (i = 0; i < 8; i++) { d = (a[i] ^ b[i]) & mask; a[i] ^= d; b[i] ^= d; }
}

/* ── one-time derived constants (PUBLIC; computed, not transcribed) ─────── */
static fe R2;              /* R^2 mod p, for to_mont */
static fe ONE_M;           /* 1 in Montgomery form (= R mod p) */
static fe B_M, B3_M;       /* curve b and 3b, Montgomery form */
static fe GX_M, GY_M;      /* generator affine coords, Montgomery form */
static int p256_ready = 0; /* public one-time flag */

static void to_mont(fe r, const fe a)   { fe_mont_mul(r, a, R2); }
static void from_mont(fe r, const fe a) { fe one = {1,0,0,0,0,0,0,0}; fe_mont_mul(r, a, one); }

static void p256_init(void) {
    fe gx, gy, b;
    int i;
    if (p256_ready) return;
    be_to_fe(P, P_BE);
    /* R mod p = 2^256 - p (valid since p < 2^256 < 2p): compute as 0 - p
     * using the borrow-free identity limbs(2^256 - p) = ~p + 1. */
    {
        uint64_t c = 1;
        for (i = 0; i < 8; i++) { c += (uint64_t)(~P[i]); ONE_M[i] = (uint32_t)c; c >>= 32; }
    }
    /* R^2 mod p by 256 modular doublings of R mod p. */
    memcpy(R2, ONE_M, sizeof(fe));
    for (i = 0; i < 256; i++) fe_add(R2, R2, R2);
    be_to_fe(b, B_BE);   to_mont(B_M, b);
    fe_add(B3_M, B_M, B_M); fe_add(B3_M, B3_M, B_M);
    be_to_fe(gx, GX_BE); to_mont(GX_M, gx);
    be_to_fe(gy, GY_BE); to_mont(GY_M, gy);
    p256_ready = 1;
}

/* a^(p-2) mod p (Montgomery domain): inversion via Fermat. The exponent is
 * the PUBLIC constant p-2, so iterating its fixed bits is data-independent. */
static void fe_inv(fe r, const fe a) {
    uint8_t e[32];
    fe acc;
    int i, bit;
    /* e = p - 2, big-endian (p ends ...ffffffff, so just subtract 2 in the
     * last byte: 0xff -> 0xfd, no borrow). */
    memcpy(e, P_BE, 32); e[31] = 0xfd;
    memcpy(acc, ONE_M, sizeof(fe));
    for (i = 0; i < 32; i++)
        for (bit = 7; bit >= 0; bit--) {
            fe_mont_sqr(acc, acc);
            if ((e[i] >> bit) & 1) fe_mont_mul(acc, acc, a);  /* public bit */
        }
    memcpy(r, acc, sizeof(fe));
}

/* ── points: projective (X:Y:Z), Montgomery-domain coordinates ──────────── */
typedef struct { fe X, Y, Z; } pt;

static void pt_set_infinity(pt* p) {
    memset(p->X, 0, sizeof(fe));
    memcpy(p->Y, ONE_M, sizeof(fe));
    memset(p->Z, 0, sizeof(fe));
}

/* Complete addition, a = -3 (Renes-Costello-Batina 2016, algorithm 4).
 * Handles P+Q, P+P and P+O uniformly — no exceptional cases, which is what
 * lets the ladder below run the same instruction sequence for every bit. */
static void pt_add(pt* o, const pt* p, const pt* q) {
    fe t0, t1, t2, t3, t4, X3, Y3, Z3;
    fe_mont_mul(t0, p->X, q->X);
    fe_mont_mul(t1, p->Y, q->Y);
    fe_mont_mul(t2, p->Z, q->Z);
    fe_add(t3, p->X, p->Y);
    fe_add(t4, q->X, q->Y);
    fe_mont_mul(t3, t3, t4);
    fe_add(t4, t0, t1);
    fe_sub(t3, t3, t4);
    fe_add(t4, p->Y, p->Z);
    fe_add(X3, q->Y, q->Z);
    fe_mont_mul(t4, t4, X3);
    fe_add(X3, t1, t2);
    fe_sub(t4, t4, X3);
    fe_add(X3, p->X, p->Z);
    fe_add(Y3, q->X, q->Z);
    fe_mont_mul(X3, X3, Y3);
    fe_add(Y3, t0, t2);
    fe_sub(Y3, X3, Y3);
    fe_mont_mul(Z3, B_M, t2);
    fe_sub(X3, Y3, Z3);
    fe_add(Z3, X3, X3);
    fe_add(X3, X3, Z3);
    fe_sub(Z3, t1, X3);
    fe_add(X3, t1, X3);
    fe_mont_mul(Y3, B_M, Y3);
    fe_add(t1, t2, t2);
    fe_add(t2, t1, t2);
    fe_sub(Y3, Y3, t2);
    fe_sub(Y3, Y3, t0);
    fe_add(t1, Y3, Y3);
    fe_add(Y3, t1, Y3);
    fe_add(t1, t0, t0);
    fe_add(t0, t1, t0);
    fe_sub(t0, t0, t2);
    fe_mont_mul(t1, t4, Y3);
    fe_mont_mul(t2, t0, Y3);
    fe_mont_mul(Y3, X3, Z3);
    fe_add(Y3, Y3, t2);
    fe_mont_mul(X3, t3, X3);
    fe_sub(X3, X3, t1);
    fe_mont_mul(Z3, t4, Z3);
    fe_mont_mul(t1, t3, t0);
    fe_add(Z3, Z3, t1);
    memcpy(o->X, X3, sizeof(fe)); memcpy(o->Y, Y3, sizeof(fe)); memcpy(o->Z, Z3, sizeof(fe));
}

static void pt_cswap(pt* a, pt* b, uint32_t swap) {
    fe_cswap(a->X, b->X, swap);
    fe_cswap(a->Y, b->Y, swap);
    fe_cswap(a->Z, b->Z, swap);
}

/* acc = [scalar] base — double-and-add-always: per bit one complete
 * doubling (add with itself), one complete add, two cswaps keyed on the
 * secret bit. Uniform sequence; the complete formulas absorb O cleanly. */
static void pt_scalar_mul(pt* acc, const uint8_t scalar_be[32], const pt* base) {
    pt tmp;
    int i, bit;
    pt_set_infinity(acc);
    for (i = 0; i < 32; i++)
        for (bit = 7; bit >= 0; bit--) {
            uint32_t b = (uint32_t)((scalar_be[i] >> bit) & 1);
            pt_add(acc, acc, acc);
            pt_add(&tmp, acc, base);
            pt_cswap(acc, &tmp, b);
        }
    determ_secure_zero(&tmp, sizeof tmp);
}

/* ── encode / decode / checks (public data — plain branches) ────────────── */

/* big-endian compare: returns 1 iff a < b */
static int be_lt(const uint8_t a[32], const uint8_t b[32]) {
    int i;
    for (i = 0; i < 32; i++) {
        if (a[i] < b[i]) return 1;
        if (a[i] > b[i]) return 0;
    }
    return 0;
}
static int be_is_zero(const uint8_t a[32]) {
    uint32_t r = 0; int i;
    for (i = 0; i < 32; i++) r |= a[i];
    return r == 0;
}

static int scalar_ok(const uint8_t s[32]) {
    return !be_is_zero(s) && be_lt(s, N_BE);
}

/* y^2 == x^3 - 3x + b  (inputs Montgomery-domain affine) */
static int on_curve_m(const fe xm, const fe ym) {
    fe l, r, t;
    uint32_t diff = 0; int i;
    fe_mont_sqr(l, ym);
    fe_mont_sqr(t, xm); fe_mont_mul(t, t, xm);     /* x^3 */
    fe_sub(r, t, xm); fe_sub(r, r, xm); fe_sub(r, r, xm);  /* -3x */
    fe_add(r, r, B_M);
    for (i = 0; i < 8; i++) diff |= l[i] ^ r[i];
    return diff == 0;
}

static int decode_point(pt* p, const uint8_t in[65]) {
    fe x, y;
    if (in[0] != 0x04) return -1;
    if (!be_lt(in + 1, P_BE) || !be_lt(in + 33, P_BE)) return -1;
    be_to_fe(x, in + 1);  to_mont(p->X, x);
    be_to_fe(y, in + 33); to_mont(p->Y, y);
    if (!on_curve_m(p->X, p->Y)) return -1;
    memcpy(p->Z, ONE_M, sizeof(fe));
    return 0;
}

static int encode_point(uint8_t out[65], const pt* p) {
    fe zi, xm, ym, x, y;
    uint32_t znz = 0; int i;
    for (i = 0; i < 8; i++) znz |= p->Z[i];
    if (znz == 0) return -1;                      /* point at infinity */
    fe_inv(zi, p->Z);
    fe_mont_mul(xm, p->X, zi);
    fe_mont_mul(ym, p->Y, zi);
    from_mont(x, xm); from_mont(y, ym);
    out[0] = 0x04;
    fe_to_be(out + 1, x);
    fe_to_be(out + 33, y);
    return 0;
}

/* ── public API ─────────────────────────────────────────────────────────── */

int determ_p256_base_mul(uint8_t out[65], const uint8_t scalar_be[32]) {
    pt g, r;
    int rc;
    p256_init();
    if (!scalar_ok(scalar_be)) return -1;
    memcpy(g.X, GX_M, sizeof(fe));
    memcpy(g.Y, GY_M, sizeof(fe));
    memcpy(g.Z, ONE_M, sizeof(fe));
    pt_scalar_mul(&r, scalar_be, &g);
    rc = encode_point(out, &r);
    determ_secure_zero(&r, sizeof r);
    return rc;
}

int determ_p256_point_mul(uint8_t out[65], const uint8_t scalar_be[32],
                          const uint8_t point[65]) {
    pt p, r;
    int rc;
    p256_init();
    if (!scalar_ok(scalar_be)) return -1;
    if (decode_point(&p, point) != 0) return -1;
    pt_scalar_mul(&r, scalar_be, &p);
    rc = encode_point(out, &r);
    determ_secure_zero(&r, sizeof r);
    return rc;
}

int determ_p256_point_check(const uint8_t point[65]) {
    pt p;
    p256_init();
    return decode_point(&p, point) == 0 ? 0 : -1;
}

void determ_p256_params(uint8_t p_be[32], uint8_t n_be[32], uint8_t b_be[32],
                        uint8_t gx_be[32], uint8_t gy_be[32]) {
    memcpy(p_be, P_BE, 32);
    memcpy(n_be, N_BE, 32);
    memcpy(b_be, B_BE, 32);
    memcpy(gx_be, GX_BE, 32);
    memcpy(gy_be, GY_BE, 32);
}
