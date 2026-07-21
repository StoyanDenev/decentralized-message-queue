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
#include "determ/crypto/sha2/sha2.h"   /* expand_message_xmd (RFC 9380 §5.3.1) */
#include "determ/crypto/ct.h"             /* DLEQ challenge compare (RFC 9497) */

#include <stdlib.h>
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
/* Constant-time big-endian a < b: no early return (P256-CT-1). Reached via
 * scalar_ok on SECRET scalars (blind / sk / ECDH scalar), so the original
 * first-differing-byte short-circuit leaked the scalar's leading-byte
 * structure. Branchless byte-wise borrow chain (LSB-first): a < b iff the
 * full subtraction borrows out; running time depends only on the fixed
 * length. Mirrors ed25519's sc_lt_L borrow-chain discipline. */
static int be_lt(const uint8_t a[32], const uint8_t b[32]) {
    uint32_t borrow = 0;
    int i;
    for (i = 31; i >= 0; i--) {
        uint32_t d = (uint32_t)a[i] - (uint32_t)b[i] - borrow;
        borrow = (d >> 8) & 1u;      /* set iff a[i] - b[i] - borrow < 0 */
    }
    return (int)borrow;              /* a < b iff the final borrow is set */
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

/* ═══ §3.9b OPRF groundwork: mod-n scalar field + RFC 9380 hash-to-curve ═══ */

/* ── generic Montgomery mod n (the group order) ──────────────────────────
 * Unlike p, n mod 2^32 is not -1, so n0' = -n^{-1} mod 2^32 is derived at
 * runtime by Newton iteration (x_{k+1} = x_k(2 - n·x_k) doubles correct
 * bits; 5 steps from x=1 give all 32). R mod n = 2^256 - n (valid since
 * n < 2^256 < 2n) and R² mod n by 256 modular doublings — same
 * no-transcribed-wide-constants policy as the field layer. */
static uint32_t Nl[8];          /* n as limbs */
static uint32_t N0I;            /* -n^{-1} mod 2^32 */
static fe R2N, ONE_N;           /* R² mod n; R mod n (= 1 in Montgomery) */
static int sc_ready = 0;

static void sc_add_raw(fe r, const fe a, const fe b) {   /* mod n */
    uint32_t t[8], s[8];
    uint64_t c = 0, brw = 0;
    int i;
    for (i = 0; i < 8; i++) { c += (uint64_t)a[i] + b[i]; t[i] = (uint32_t)c; c >>= 32; }
    for (i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)t[i] - Nl[i] - brw;
        s[i] = (uint32_t)d; brw = (d >> 63) & 1;
    }
    {
        uint32_t use_s = (uint32_t)0 - (uint32_t)((c | (1 - brw)) & 1);
        for (i = 0; i < 8; i++) r[i] = (s[i] & use_s) | (t[i] & ~use_s);
    }
}

static void sc_mont_mul(fe r, const fe a, const fe b) {  /* CIOS mod n */
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
        m = t[0] * N0I;
        c = (uint64_t)t[0] + (uint64_t)m * Nl[0];
        c >>= 32;
        for (j = 1; j < 8; j++) {
            c += (uint64_t)t[j] + (uint64_t)m * Nl[j];
            t[j-1] = (uint32_t)c; c >>= 32;
        }
        c += t[8]; t[7] = (uint32_t)c; c >>= 32;
        t[8] = t[9] + (uint32_t)c;
        t[9] = 0;
    }
    {
        uint32_t s[8], use_s;
        uint64_t brw = 0;
        for (i = 0; i < 8; i++) {
            uint64_t d = (uint64_t)t[i] - Nl[i] - brw;
            s[i] = (uint32_t)d; brw = (d >> 63) & 1;
        }
        use_s = (uint32_t)0 - (uint32_t)((t[8] | (1 - (uint32_t)brw)) & 1);
        for (i = 0; i < 8; i++) r[i] = (s[i] & use_s) | (t[i] & ~use_s);
    }
}

static void sc_init(void) {
    int i;
    uint32_t x;
    if (sc_ready) return;
    be_to_fe(Nl, N_BE);
    x = 1;                                   /* Newton: invert n mod 2^32 */
    for (i = 0; i < 5; i++) x *= 2u - Nl[0] * x;
    N0I = (uint32_t)0 - x;                   /* -n^{-1} mod 2^32 */
    {
        uint64_t c = 1;                      /* R mod n = ~n + 1 */
        for (i = 0; i < 8; i++) { c += (uint64_t)(~Nl[i]); ONE_N[i] = (uint32_t)c; c >>= 32; }
    }
    memcpy(R2N, ONE_N, sizeof(fe));
    for (i = 0; i < 256; i++) sc_add_raw(R2N, R2N, R2N);
    sc_ready = 1;
}

int determ_p256_scalar_mul_mod_n(uint8_t r[32], const uint8_t a[32],
                                 const uint8_t b[32]) {
    fe am, bm, rm, t;
    fe one = {1,0,0,0,0,0,0,0};
    sc_init();
    if (!be_lt(a, N_BE) || !be_lt(b, N_BE)) return -1;
    be_to_fe(t, a); sc_mont_mul(am, t, R2N);
    be_to_fe(t, b); sc_mont_mul(bm, t, R2N);
    sc_mont_mul(rm, am, bm);
    sc_mont_mul(t, rm, one);
    fe_to_be(r, t);
    return 0;
}

int determ_p256_scalar_inv_mod_n(uint8_t r[32], const uint8_t a[32]) {
    fe am, acc, t;
    fe one = {1,0,0,0,0,0,0,0};
    uint8_t e[32];
    int i, bit;
    sc_init();
    if (be_is_zero(a) || !be_lt(a, N_BE)) return -1;
    be_to_fe(t, a); sc_mont_mul(am, t, R2N);
    /* exponent n - 2 (n ends 0x51 — no borrow); n prime => Fermat. */
    memcpy(e, N_BE, 32); e[31] -= 2;
    memcpy(acc, ONE_N, sizeof(fe));
    for (i = 0; i < 32; i++)
        for (bit = 7; bit >= 0; bit--) {
            sc_mont_mul(acc, acc, acc);
            if ((e[i] >> bit) & 1) sc_mont_mul(acc, acc, am);  /* public bit */
        }
    sc_mont_mul(t, acc, one);
    fe_to_be(r, t);
    determ_secure_zero(am, sizeof am); determ_secure_zero(acc, sizeof acc);
    determ_secure_zero(t, sizeof t);   /* transiently held a and a^-1 (audit §3.3 Info) */
    return 0;
}

/* sc_sub_raw is defined later (SSWU field-helper section); forward-declare it
 * so the exposed additive ops below can be grouped with the other scalar
 * publics rather than moved past its definition. */
static void sc_sub_raw(fe r, const fe a, const fe b);

/* r = a + b mod n. Exposes the raw (non-Montgomery) sc_add over the group
 * order n — the additive-group op the DSSO threshold-OPRF Lagrange combine
 * needs (v2.25-DSSO-DAPP-SPEC §4/§9 G1: Shamir deal + Lagrange-at-0 over Z_n).
 * be_to_fe yields the raw integer limbs sc_add_raw operates on (mul_mod_n only
 * uses Montgomery because multiplication does; addition does not). Inputs
 * big-endian, both < n; -1 otherwise. Public-validity outcome. */
int determ_p256_scalar_add_mod_n(uint8_t r[32], const uint8_t a[32],
                                 const uint8_t b[32]) {
    fe af, bf, rf;
    sc_init();
    if (!be_lt(a, N_BE) || !be_lt(b, N_BE)) return -1;
    be_to_fe(af, a);
    be_to_fe(bf, b);
    sc_add_raw(rf, af, bf);
    fe_to_be(r, rf);
    return 0;
}

/* r = a - b mod n (companion to add; the Lagrange denominator x_j - x_i).
 * Same raw-fe path. Inputs big-endian, both < n; -1 otherwise. */
int determ_p256_scalar_sub_mod_n(uint8_t r[32], const uint8_t a[32],
                                 const uint8_t b[32]) {
    fe af, bf, rf;
    sc_init();
    if (!be_lt(a, N_BE) || !be_lt(b, N_BE)) return -1;
    be_to_fe(af, a);
    be_to_fe(bf, b);
    sc_sub_raw(rf, af, bf);
    fe_to_be(r, rf);
    return 0;
}

/* ── field helpers for SSWU (public fixed exponents, derived at runtime) ── */

/* big-endian helpers over 32-byte exponents */
static void be_shr1(uint8_t a[32]) {
    int i;
    uint8_t carry = 0;
    for (i = 0; i < 32; i++) {
        uint8_t nc = a[i] & 1;
        a[i] = (uint8_t)((a[i] >> 1) | (carry << 7));
        carry = nc;
    }
}

static void fe_pow_pub(fe r, const fe a, const uint8_t e_be[32]) {
    fe acc;
    int i, bit;
    memcpy(acc, ONE_M, sizeof(fe));
    for (i = 0; i < 32; i++)
        for (bit = 7; bit >= 0; bit--) {
            fe_mont_sqr(acc, acc);
            if ((e_be[i] >> bit) & 1) fe_mont_mul(acc, acc, a);  /* public bit */
        }
    memcpy(r, acc, sizeof(fe));
}

/* sqrt(a) = a^((p+1)/4) — valid since p ≡ 3 (mod 4). Caller guarantees a is
 * square (SSWU selects the square branch first). */
static void fe_sqrt(fe r, const fe a) {
    uint8_t e[32];
    int i;
    memcpy(e, P_BE, 32);
    for (i = 31; i >= 0; i--) { if (++e[i] != 0) break; }   /* p + 1 */
    be_shr1(e); be_shr1(e);                                  /* / 4 */
    fe_pow_pub(r, a, e);
}

/* Legendre: returns all-ones mask iff a is a nonzero square (a^((p-1)/2) == 1);
 * zero treated by the caller. Branchless aggregate compare. */
static uint32_t fe_is_square_mask(const fe a) {
    uint8_t e[32];
    fe t;
    uint32_t diff = 0;
    int i;
    memcpy(e, P_BE, 32); e[31] -= 1;   /* p ends 0xff — no borrow */
    be_shr1(e);                         /* (p-1)/2 */
    fe_pow_pub(t, a, e);
    for (i = 0; i < 8; i++) diff |= t[i] ^ ONE_M[i];
    /* diff == 0 -> square. Collapse branchlessly. */
    return (uint32_t)0 - (uint32_t)(1u & (((uint64_t)diff - 1u) >> 63));
}

static void fe_cmov(fe r, const fe a, uint32_t mask) {  /* r = mask ? a : r */
    int i;
    for (i = 0; i < 8; i++) r[i] = (a[i] & mask) | (r[i] & ~mask);
}

static uint32_t fe_is_zero_mask(const fe a) {
    uint32_t d = 0; int i;
    for (i = 0; i < 8; i++) d |= a[i];
    return (uint32_t)0 - (uint32_t)(1u & (((uint64_t)d - 1u) >> 63));
}

/* sgn0(a) (m = 1): the parity of the canonical representative. */
static uint32_t fe_sgn0(const fe a_m) {
    fe t;
    from_mont(t, a_m);
    return t[0] & 1u;
}

/* ── expand_message_xmd with SHA-256 (RFC 9380 §5.3.1) ─────────────────── */

int determ_p256_expand_message_xmd(uint8_t* out, size_t outlen,
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t* dst, size_t dstlen) {
    /* b_in_bytes = 32, s_in_bytes (r_in_bytes) = 64 for SHA-256. */
    size_t ell = (outlen + 31) / 32;
    uint8_t b0[32], bi[32];
    size_t off, i, done;
    if (outlen == 0 || ell > 255 || outlen > 65535 || dstlen > 255) return -1;

    /* b0 = H(Z_pad(64) || msg || I2OSP(outlen,2) || 0x00 || DST || len(DST)).
     * msg can be arbitrarily long — hash incrementally? determ_sha256 is
     * one-shot, so assemble in two passes: hash Z_pad+msg prefix via a
     * stack buffer only when small... msg length is unbounded; allocate. */
    {
        size_t pre_len = 64 + msglen + 2 + 1 + dstlen + 1;
        uint8_t small[512];
        uint8_t* buf = pre_len <= sizeof small ? small : (uint8_t*)0;
        uint8_t* heap = 0;
        if (!buf) {
            heap = (uint8_t*)malloc(pre_len);
            if (!heap) return -1;
            buf = heap;
        }
        memset(buf, 0, 64);
        if (msglen) memcpy(buf + 64, msg, msglen);
        off = 64 + msglen;
        buf[off++] = (uint8_t)(outlen >> 8);
        buf[off++] = (uint8_t)(outlen);
        buf[off++] = 0x00;
        if (dstlen) memcpy(buf + off, dst, dstlen);
        off += dstlen;
        buf[off++] = (uint8_t)dstlen;
        determ_sha256(buf, off, b0);
        if (heap) { determ_secure_zero(heap, pre_len); free(heap); }
        else determ_secure_zero(small, sizeof small);
    }

    /* b1 = H(b0 || 0x01 || DST_prime); bi = H((b0 ^ b_{i-1}) || i || DST_prime) */
    done = 0;
    memcpy(bi, b0, 32);                 /* seed for the xor chain */
    for (i = 1; i <= ell; i++) {
        uint8_t in[32 + 1 + 255 + 1];
        size_t inlen = 0, k;
        if (i == 1) memcpy(in, b0, 32);
        else for (k = 0; k < 32; k++) in[k] = (uint8_t)(b0[k] ^ bi[k]);
        inlen = 32;
        in[inlen++] = (uint8_t)i;
        if (dstlen) memcpy(in + inlen, dst, dstlen);
        inlen += dstlen;
        in[inlen++] = (uint8_t)dstlen;
        determ_sha256(in, inlen, bi);
        {
            size_t take = outlen - done < 32 ? outlen - done : 32;
            memcpy(out + done, bi, take);
            done += take;
        }
    }
    determ_secure_zero(b0, sizeof b0);
    determ_secure_zero(bi, sizeof bi);
    return 0;
}

/* ── hash_to_field (m = 1, L = 48, count = 2) + simplified SSWU ─────────── */

/* 48 big-endian bytes -> field element mod p: val = hi(16B)·2^256 + lo(32B);
 * hi·2^256 mod p == to_mont(hi)'s VALUE (mont_mul(hi, R²) = hi·R); add the
 * conditionally-reduced lo. Output in the PLAIN domain. */
static void fe_from_be48(fe r, const uint8_t in[48]) {
    uint8_t hi_be[32], lo_be[32];
    fe hi, lo, hiR;
    memset(hi_be, 0, 16); memcpy(hi_be + 16, in, 16);
    memcpy(lo_be, in + 16, 32);
    be_to_fe(hi, hi_be);
    fe_mont_mul(hiR, hi, R2);            /* = hi·R mod p (plain value) */
    be_to_fe(lo, lo_be);
    /* reduce lo < 2^256 < 2p with one branchless conditional subtract */
    {
        uint32_t s[8], use_s; uint64_t brw = 0; int i;
        for (i = 0; i < 8; i++) {
            uint64_t d = (uint64_t)lo[i] - P[i] - brw;
            s[i] = (uint32_t)d; brw = (d >> 63) & 1;
        }
        use_s = (uint32_t)0 - (uint32_t)(1 - (uint32_t)brw);
        for (i = 0; i < 8; i++) lo[i] = (s[i] & use_s) | (lo[i] & ~use_s);
    }
    fe_add(r, hiR, lo);
}

/* Simplified SSWU (RFC 9380 §6.6.2) for y² = x³ + A x + B, A = -3, Z = -10.
 * Input/output in the Montgomery domain; constant-time (mask selects — the
 * OPRF input behind u may be a user secret). */
static void sswu_map(fe x_out, fe y_out, const fe u) {
    static fe Z_M, C1_M, C2_M, A_M;          /* derived once (public) */
    static int sswu_ready = 0;
    fe tv1, tv2, x1, gx1, x2, gx2, y1, y2, u2, t;
    uint32_t e1, e2, sgn_mask;
    if (!sswu_ready) {
        fe zero, ten, a_plain, za, inv_t;
        memset(zero, 0, sizeof(fe));
        memset(ten, 0, sizeof(fe)); ten[0] = 10;
        be_to_fe(a_plain, P_BE);             /* p ≡ 0; A = p - 3 below */
        memset(a_plain, 0, sizeof(fe)); a_plain[0] = 3;
        fe_sub(t, zero, a_plain); to_mont(A_M, t);          /* A = -3 */
        fe_sub(t, zero, ten);     to_mont(Z_M, t);          /* Z = -10 */
        /* C1 = -B/A ; C2 = B/(Z·A) (Montgomery domain throughout) */
        fe_inv(inv_t, A_M);
        fe_mont_mul(t, B_M, inv_t);
        memset(zero, 0, sizeof(fe));         /* 0 is the same in any domain */
        fe_sub(C1_M, zero, t);                              /* -B/A */
        fe_mont_mul(za, Z_M, A_M);
        fe_inv(inv_t, za);
        fe_mont_mul(C2_M, B_M, inv_t);                      /* B/(Z·A) */
        sswu_ready = 1;
    }
    /* tv1 = inv0(Z²u⁴ + Zu²) */
    fe_mont_sqr(u2, u);
    fe_mont_mul(tv1, Z_M, u2);               /* Z u² */
    fe_mont_sqr(tv2, tv1);                   /* Z² u⁴ */
    fe_add(tv2, tv2, tv1);
    fe_inv(t, tv2);                          /* inv0: 0 -> 0 */
    /* x1 = C1 · (1 + tv1');  tv1' == 0  =>  x1 = C2 */
    fe_add(x1, ONE_M, t);
    fe_mont_mul(x1, C1_M, x1);
    e1 = fe_is_zero_mask(tv2);
    fe_cmov(x1, C2_M, e1);
    /* gx1 = x1³ + A x1 + B */
    fe_mont_sqr(gx1, x1); fe_mont_mul(gx1, gx1, x1);
    fe_mont_mul(t, A_M, x1); fe_add(gx1, gx1, t); fe_add(gx1, gx1, B_M);
    /* x2 = Z u² x1 ; gx2 = x2³ + A x2 + B */
    fe_mont_mul(x2, tv1, x1);
    fe_mont_sqr(gx2, x2); fe_mont_mul(gx2, gx2, x2);
    fe_mont_mul(t, A_M, x2); fe_add(gx2, gx2, t); fe_add(gx2, gx2, B_M);
    /* select the square branch */
    e2 = fe_is_square_mask(gx1);
    memcpy(x_out, x2, sizeof(fe));  fe_cmov(x_out, x1, e2);
    memcpy(t, gx2, sizeof(fe));     fe_cmov(t, gx1, e2);
    fe_sqrt(y1, t);
    /* fix sign: sgn0(y) must equal sgn0(u) */
    {
        fe zero;
        memset(zero, 0, sizeof(fe));
        fe_sub(y2, zero, y1);
        sgn_mask = (uint32_t)0 - (fe_sgn0(y1) ^ fe_sgn0(u));
        memcpy(y_out, y1, sizeof(fe));
        fe_cmov(y_out, y2, sgn_mask);
    }
}

/* 48 big-endian bytes -> scalar mod n (the order-field analogue of
 * fe_from_be48: hi·2^256 mod n == sc_mont_mul(hi, R²(n))'s value). */
static void sc_from_be48(fe r, const uint8_t in[48]) {
    uint8_t hi_be[32], lo_be[32];
    fe hi, lo, hiR;
    memset(hi_be, 0, 16); memcpy(hi_be + 16, in, 16);
    memcpy(lo_be, in + 16, 32);
    be_to_fe(hi, hi_be);
    sc_mont_mul(hiR, hi, R2N);
    be_to_fe(lo, lo_be);
    {
        uint32_t s[8], use_s; uint64_t brw = 0; int i;
        for (i = 0; i < 8; i++) {
            uint64_t d = (uint64_t)lo[i] - Nl[i] - brw;
            s[i] = (uint32_t)d; brw = (d >> 63) & 1;
        }
        use_s = (uint32_t)0 - (uint32_t)(1 - (uint32_t)brw);
        for (i = 0; i < 8; i++) lo[i] = (s[i] & use_s) | (lo[i] & ~use_s);
    }
    sc_add_raw(r, hiR, lo);
}

int determ_p256_hash_to_scalar(uint8_t out[32],
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* dst, size_t dstlen) {
    uint8_t uniform[48];
    fe s;
    sc_init();
    if (determ_p256_expand_message_xmd(uniform, 48, msg, msglen, dst, dstlen) != 0)
        return -1;
    sc_from_be48(s, uniform);
    fe_to_be(out, s);
    determ_secure_zero(uniform, sizeof uniform);
    determ_secure_zero(s, sizeof s);
    return 0;
}

int determ_p256_point_add(uint8_t out[65], const uint8_t p[65],
                          const uint8_t q[65]) {
    pt a, b, r;
    p256_init();
    if (decode_point(&a, p) != 0 || decode_point(&b, q) != 0) return -1;
    pt_add(&r, &a, &b);
    return encode_point(out, &r);     /* infinity (P + -P) -> -1 */
}

int determ_p256_msm_ct(uint8_t out33[33], const uint8_t *scalars,
                       const uint8_t *points33, size_t n) {
    /* Constant-time Σ s_i·P_i — the CT Bulletproofs multi-scalar multiplication. NO
     * zero-scalar skip: a `continue` on s_i == 0 would leak WHICH secret scalars are zero
     * (in the range prover, the bits of a committed value). The accumulation runs in the
     * internal pt (projective) domain so the identity O needs no special-casing —
     * pt_scalar_mul(0,P) = O and the RCB-complete pt_add absorbs O — hence every term
     * folds uniformly (constant-time in the scalars). scalars: n×32 big-endian (< n_order;
     * 0 allowed); points33: n×33 SEC1 compressed. Returns 0 (compressed sum -> out33),
     * 1 (the sum is the identity; out33 untouched), or -1 (a scalar >= n_order or a point
     * that fails to decode — public-validity gates). Byte-identical to the old
     * encoded-domain accumulation (the pedersen/bp_* corpora are the guard). */
    pt acc, P, term;
    uint8_t p65[65], enc65[65];
    int rc = 0;
    p256_init();
    pt_set_infinity(&acc);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *si = scalars + i * 32;
        if (!be_lt(si, N_BE)) { rc = -1; goto done; }              /* scalar >= n (0 allowed) */
        if (determ_p256_point_decompress(p65, points33 + i * 33) != 0) { rc = -1; goto done; }
        if (decode_point(&P, p65) != 0) { rc = -1; goto done; }
        pt_scalar_mul(&term, si, &P);                              /* CT ladder; s_i == 0 -> O */
        pt_add(&acc, &acc, &term);                                 /* acc + O = acc */
    }
    if (encode_point(enc65, &acc) != 0) { rc = 1; goto done; }     /* the whole sum is O */
    rc = determ_p256_point_compress(out33, enc65);
done:
    determ_secure_zero(&acc, sizeof acc);
    determ_secure_zero(&P, sizeof P);
    determ_secure_zero(&term, sizeof term);
    return rc;
}

int determ_p256_hash_to_curve(uint8_t out[65],
                              const uint8_t* msg, size_t msglen,
                              const uint8_t* dst, size_t dstlen) {
    uint8_t uniform[96];
    fe u0p, u1p, u0, u1;
    pt q0, q1, r;
    int rc;
    p256_init();
    if (determ_p256_expand_message_xmd(uniform, 96, msg, msglen, dst, dstlen) != 0)
        return -1;
    fe_from_be48(u0p, uniform);          /* plain domain */
    fe_from_be48(u1p, uniform + 48);
    to_mont(u0, u0p); to_mont(u1, u1p);
    sswu_map(q0.X, q0.Y, u0); memcpy(q0.Z, ONE_M, sizeof(fe));
    sswu_map(q1.X, q1.Y, u1); memcpy(q1.Z, ONE_M, sizeof(fe));
    pt_add(&r, &q0, &q1);                /* complete add; clear_cofactor = id (h=1) */
    rc = encode_point(out, &r);          /* infinity (prob ~2^-256) -> -1 */
    determ_secure_zero(uniform, sizeof uniform);
    determ_secure_zero(&q0, sizeof q0); determ_secure_zero(&q1, sizeof q1);
    determ_secure_zero(&r, sizeof r);
    return rc;
}

/* ═══ SEC1 compressed encoding + the RFC 9497 OPRF(P-256, SHA-256) layer ═══ */

int determ_p256_point_compress(uint8_t out33[33], const uint8_t in65[65]) {
    pt p;
    p256_init();
    if (decode_point(&p, in65) != 0) return -1;
    out33[0] = (uint8_t)(0x02 | (in65[64] & 1));   /* parity of canonical Y */
    memcpy(out33 + 1, in65 + 1, 32);
    return 0;
}

int determ_p256_point_decompress(uint8_t out65[65], const uint8_t in33[33]) {
    fe x, xm, gx, t, y, ym;
    uint8_t y_be[32];
    p256_init();
    if (in33[0] != 0x02 && in33[0] != 0x03) return -1;
    if (!be_lt(in33 + 1, P_BE)) return -1;
    be_to_fe(x, in33 + 1);
    to_mont(xm, x);
    /* gx = x^3 - 3x + b (Montgomery) */
    fe_mont_sqr(gx, xm); fe_mont_mul(gx, gx, xm);
    fe_sub(gx, gx, xm); fe_sub(gx, gx, xm); fe_sub(gx, gx, xm);
    fe_add(gx, gx, B_M);
    fe_sqrt(ym, gx);
    /* sqrt is only valid for residues — verify y^2 == gx (rejects
     * non-square right-hand sides; also covers gx == 0 trivially). */
    fe_mont_sqr(t, ym);
    {
        uint32_t diff = 0; int i;
        for (i = 0; i < 8; i++) diff |= t[i] ^ gx[i];
        if (diff != 0) return -1;
    }
    from_mont(y, ym);
    fe_to_be(y_be, y);
    if ((y_be[31] & 1) != (in33[0] & 1)) {            /* wrong parity: y = p - y */
        fe zero;
        memset(zero, 0, sizeof(fe));
        fe_sub(ym, zero, ym);
        from_mont(y, ym);
        fe_to_be(y_be, y);
    }
    out65[0] = 0x04;
    memcpy(out65 + 1, in33 + 1, 32);
    memcpy(out65 + 33, y_be, 32);
    return 0;
}

/* contextString = "OPRFV1-" || I2OSP(mode,1) || "-P256-SHA256" (RFC 9497
 * §3.1). 20 bytes; the mode is a RAW byte between ASCII hyphens. */
#define OPRF_CTX_LEN 20
static void oprf_context(uint8_t ctx[OPRF_CTX_LEN], uint8_t mode) {
    memcpy(ctx, "OPRFV1-", 7);
    ctx[7] = mode;
    memcpy(ctx + 8, "-P256-SHA256", 12);
}

/* DST = prefix || contextString into the caller buffer; returns the length. */
static size_t oprf_dst(uint8_t* out, const char* prefix, uint8_t mode) {
    size_t n = strlen(prefix);
    memcpy(out, prefix, n);
    oprf_context(out + n, mode);
    return n + OPRF_CTX_LEN;
}

/* sc: r = a - b mod n (branchless; mirrors fe_sub over Nl). */
static void sc_sub_raw(fe r, const fe a, const fe b) {
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
        c += (uint64_t)t[i] + (Nl[i] & mask);
        r[i] = (uint32_t)c; c >>= 32;
    }
}

/* internal: compressed bytes -> pt; pt -> compressed bytes. */
static int oprf_load33(pt* p, const uint8_t in33[33]) {
    uint8_t u65[65];
    if (determ_p256_point_decompress(u65, in33) != 0) return -1;
    return decode_point(p, u65);
}
static int oprf_store33(uint8_t out33[33], const pt* p) {
    uint8_t u65[65];
    if (encode_point(u65, p) != 0) return -1;
    out33[0] = (uint8_t)(0x02 | (u65[64] & 1));
    memcpy(out33 + 1, u65 + 1, 32);
    return 0;
}

int determ_p256_oprf_derive_key(uint8_t sk[32],
                                const uint8_t* seed, size_t seedlen,
                                const uint8_t* info, size_t infolen,
                                uint8_t mode) {
    /* §3.2.1: deriveInput = seed || I2OSP(len(info),2) || info; counter loop
     * with DST = "DeriveKeyPair" || contextString (NO hyphen — RFC quirk). */
    uint8_t dst[13 + OPRF_CTX_LEN];
    size_t dstlen = oprf_dst(dst, "DeriveKeyPair", mode);
    uint8_t stackbuf[256];
    uint8_t* buf;
    uint8_t* heap = 0;
    size_t base = seedlen + 2 + infolen;
    int counter;
    int rc = -1;
    if (base + 1 <= sizeof stackbuf) buf = stackbuf;
    else { heap = (uint8_t*)malloc(base + 1); if (!heap) return -1; buf = heap; }
    if (seedlen) memcpy(buf, seed, seedlen);
    buf[seedlen] = (uint8_t)(infolen >> 8);
    buf[seedlen + 1] = (uint8_t)infolen;
    if (infolen) memcpy(buf + seedlen + 2, info, infolen);
    for (counter = 0; counter <= 255; counter++) {
        buf[base] = (uint8_t)counter;
        if (determ_p256_hash_to_scalar(sk, buf, base + 1, dst, dstlen) != 0) break;
        if (!be_is_zero(sk)) { rc = 0; break; }
    }
    if (heap) { determ_secure_zero(heap, base + 1); free(heap); }
    else determ_secure_zero(stackbuf, sizeof stackbuf);
    return rc;
}

int determ_p256_oprf_blind(uint8_t blinded33[33],
                           const uint8_t* input, size_t inputlen,
                           const uint8_t blind[32], uint8_t mode) {
    uint8_t dst[12 + OPRF_CTX_LEN];
    size_t dstlen = oprf_dst(dst, "HashToGroup-", mode);
    uint8_t elem65[65];
    pt p, r;
    int rc;
    p256_init();
    if (!scalar_ok(blind)) return -1;
    if (determ_p256_hash_to_curve(elem65, input, inputlen, dst, dstlen) != 0)
        return -1;                                /* identity -> error (§3.3.1) */
    if (decode_point(&p, elem65) != 0) return -1;
    pt_scalar_mul(&r, blind, &p);
    rc = oprf_store33(blinded33, &r);
    determ_secure_zero(&r, sizeof r);
    return rc;
}

int determ_p256_oprf_evaluate(uint8_t eval33[33], const uint8_t sk[32],
                              const uint8_t blinded33[33]) {
    pt p, r;
    int rc;
    p256_init();
    if (!scalar_ok(sk)) return -1;
    if (oprf_load33(&p, blinded33) != 0) return -1;
    pt_scalar_mul(&r, sk, &p);
    rc = oprf_store33(eval33, &r);
    determ_secure_zero(&r, sizeof r);
    return rc;
}

int determ_p256_oprf_finalize(uint8_t out[32],
                              const uint8_t* input, size_t inputlen,
                              const uint8_t blind[32],
                              const uint8_t eval33[33]) {
    uint8_t inv[32], n33[33];
    pt p, r;
    uint8_t stackbuf[512];
    uint8_t* buf;
    uint8_t* heap = 0;
    size_t total = 2 + inputlen + 2 + 33 + 8, off = 0;
    int rc = -1;
    /* inv = blind^-1 is the client's secret material; a malicious server can
     * drive the eval-decode reject below to leave it on the stack, so all
     * exit paths scrub via the cleanup label (audit §3.1 Low / §3.2 Info). */
    p256_init();
    if (determ_p256_scalar_inv_mod_n(inv, blind) != 0) return -1;   /* inv unset */
    if (oprf_load33(&p, eval33) != 0) goto cleanup;
    pt_scalar_mul(&r, inv, &p);
    if (oprf_store33(n33, &r) != 0) goto cleanup;
    determ_secure_zero(&r, sizeof r);
    if (total <= sizeof stackbuf) buf = stackbuf;
    else { heap = (uint8_t*)malloc(total); if (!heap) goto cleanup; buf = heap; }
    buf[off++] = (uint8_t)(inputlen >> 8);
    buf[off++] = (uint8_t)inputlen;
    if (inputlen) { memcpy(buf + off, input, inputlen); off += inputlen; }
    buf[off++] = 0x00; buf[off++] = 0x21;         /* len(unblindedElement) = 33 */
    memcpy(buf + off, n33, 33); off += 33;
    memcpy(buf + off, "Finalize", 8); off += 8;
    determ_sha256(buf, off, out);
    if (heap) { determ_secure_zero(heap, total); free(heap); }
    else determ_secure_zero(stackbuf, sizeof stackbuf);
    rc = 0;
cleanup:
    determ_secure_zero(inv, sizeof inv);
    determ_secure_zero(n33, sizeof n33);
    determ_secure_zero(&p, sizeof p);
    return rc;
}

/* ComputeComposites, m = 1 (§2.2.1): seed = Hash(len2(Bm) || Bm ||
 * len2(seedDST) || seedDST); di = HashToScalar(len2(seed) || seed ||
 * I2OSP(0,2) || len2(Ci) || Ci || len2(Di) || Di || "Composite").
 * M = di*C; fast side Z = k*M, verify side Z = di*D. */
static int oprf_composites(uint8_t di[32],
                           const uint8_t pk33[33],
                           const uint8_t c33[33], const uint8_t d33[33],
                           uint8_t mode) {
    uint8_t seed_dst[5 + OPRF_CTX_LEN];
    size_t seed_dstlen = oprf_dst(seed_dst, "Seed-", mode);
    uint8_t seed[32];
    uint8_t st[2 + 33 + 2 + 5 + OPRF_CTX_LEN];
    size_t off = 0;
    uint8_t ct[2 + 32 + 2 + 2 + 33 + 2 + 33 + 9];
    size_t coff = 0;
    uint8_t h2s_dst[13 + OPRF_CTX_LEN];
    size_t h2s_dstlen = oprf_dst(h2s_dst, "HashToScalar-", mode);
    st[off++] = 0x00; st[off++] = 0x21;
    memcpy(st + off, pk33, 33); off += 33;
    st[off++] = (uint8_t)(seed_dstlen >> 8); st[off++] = (uint8_t)seed_dstlen;
    memcpy(st + off, seed_dst, seed_dstlen); off += seed_dstlen;
    determ_sha256(st, off, seed);
    ct[coff++] = 0x00; ct[coff++] = 0x20;         /* len(seed) = 32 */
    memcpy(ct + coff, seed, 32); coff += 32;
    ct[coff++] = 0x00; ct[coff++] = 0x00;         /* i = 0 */
    ct[coff++] = 0x00; ct[coff++] = 0x21;
    memcpy(ct + coff, c33, 33); coff += 33;
    ct[coff++] = 0x00; ct[coff++] = 0x21;
    memcpy(ct + coff, d33, 33); coff += 33;
    memcpy(ct + coff, "Composite", 9); coff += 9;
    return determ_p256_hash_to_scalar(di, ct, coff, h2s_dst, h2s_dstlen);
}

/* challenge c = HashToScalar(len2 each of Bm, M, Z, t2, t3 || "Challenge") */
static int oprf_challenge(uint8_t c[32], const uint8_t pk33[33],
                          const uint8_t m33[33], const uint8_t z33[33],
                          const uint8_t t2_33[33], const uint8_t t3_33[33],
                          uint8_t mode) {
    uint8_t h2s_dst[13 + OPRF_CTX_LEN];
    size_t h2s_dstlen = oprf_dst(h2s_dst, "HashToScalar-", mode);
    uint8_t tr[5 * 35 + 9];
    size_t off = 0;
    const uint8_t* elems[5];
    int i;
    elems[0] = pk33; elems[1] = m33; elems[2] = z33;
    elems[3] = t2_33; elems[4] = t3_33;
    for (i = 0; i < 5; i++) {
        tr[off++] = 0x00; tr[off++] = 0x21;
        memcpy(tr + off, elems[i], 33); off += 33;
    }
    memcpy(tr + off, "Challenge", 9); off += 9;
    return determ_p256_hash_to_scalar(c, tr, off, h2s_dst, h2s_dstlen);
}

int determ_p256_voprf_prove(uint8_t proof[64], const uint8_t sk[32],
                            const uint8_t pk33[33],
                            const uint8_t blinded33[33],
                            const uint8_t eval33[33],
                            const uint8_t r[32], uint8_t mode) {
    uint8_t di[32], m33[33], z33[33], t2_33[33], t3_33[33], c[32];
    pt C, M, Z, T;
    fe rfe, cm, km, ck, sfe;
    fe one = {1,0,0,0,0,0,0,0};
    p256_init(); sc_init();
    if (!scalar_ok(sk) || !scalar_ok(r)) return -1;
    if (oprf_load33(&C, blinded33) != 0) return -1;
    if (oprf_composites(di, pk33, blinded33, eval33, mode) != 0) return -1;
    pt_scalar_mul(&M, di, &C);                    /* M = di * C */
    if (oprf_store33(m33, &M) != 0) return -1;
    pt_scalar_mul(&Z, sk, &M);                    /* fast side: Z = k * M */
    if (oprf_store33(z33, &Z) != 0) return -1;
    {                                             /* t2 = r*G ; t3 = r*M */
        pt G_;
        memcpy(G_.X, GX_M, sizeof(fe)); memcpy(G_.Y, GY_M, sizeof(fe));
        memcpy(G_.Z, ONE_M, sizeof(fe));
        pt_scalar_mul(&T, r, &G_);
        if (oprf_store33(t2_33, &T) != 0) return -1;
        pt_scalar_mul(&T, r, &M);
        if (oprf_store33(t3_33, &T) != 0) return -1;
    }
    if (oprf_challenge(c, pk33, m33, z33, t2_33, t3_33, mode) != 0) return -1;
    /* s = r - c*k mod n (plain-domain in/out through the mod-n Montgomery) */
    be_to_fe(rfe, r);
    be_to_fe(cm, c);  sc_mont_mul(cm, cm, R2N);
    be_to_fe(km, sk); sc_mont_mul(km, km, R2N);
    sc_mont_mul(ck, cm, km);
    sc_mont_mul(ck, ck, one);                     /* back to plain */
    sc_sub_raw(sfe, rfe, ck);
    memcpy(proof, c, 32);
    fe_to_be(proof + 32, sfe);
    determ_secure_zero(&T, sizeof T);
    determ_secure_zero(km, sizeof km); determ_secure_zero(ck, sizeof ck);
    determ_secure_zero(rfe, sizeof rfe); determ_secure_zero(sfe, sizeof sfe);
    return 0;
}

int determ_p256_voprf_verify(const uint8_t pk33[33],
                             const uint8_t blinded33[33],
                             const uint8_t eval33[33],
                             const uint8_t proof[64], uint8_t mode) {
    uint8_t di[32], m33[33], z33[33], t2_33[33], t3_33[33], c2[32];
    uint8_t sA65[65], cB65[65], t2_65[65], sM65[65], cZ65[65], t3_65[65];
    uint8_t pk65[65], m65[65], z65[65];
    pt C, D, M, Z;
    const uint8_t* c = proof;
    const uint8_t* s = proof + 32;
    p256_init(); sc_init();
    if (!be_lt(c, N_BE) || !be_lt(s, N_BE)) return -1;
    if (be_is_zero(c) || be_is_zero(s)) return -1;   /* base/point_mul reject 0 */
    if (oprf_load33(&C, blinded33) != 0 || oprf_load33(&D, eval33) != 0) return -1;
    if (oprf_composites(di, pk33, blinded33, eval33, mode) != 0) return -1;
    pt_scalar_mul(&M, di, &C);                    /* M = di * C */
    pt_scalar_mul(&Z, di, &D);                    /* verify side: Z = di * D */
    if (oprf_store33(m33, &M) != 0 || oprf_store33(z33, &Z) != 0) return -1;
    /* t2 = s*G + c*B ; t3 = s*M + c*Z — public data; the exported API works */
    if (determ_p256_point_decompress(pk65, pk33) != 0) return -1;
    if (encode_point(m65, &M) != 0 || encode_point(z65, &Z) != 0) return -1;
    if (determ_p256_base_mul(sA65, s) != 0) return -1;
    if (determ_p256_point_mul(cB65, c, pk65) != 0) return -1;
    if (determ_p256_point_add(t2_65, sA65, cB65) != 0) return -1;
    if (determ_p256_point_mul(sM65, s, m65) != 0) return -1;
    if (determ_p256_point_mul(cZ65, c, z65) != 0) return -1;
    if (determ_p256_point_add(t3_65, sM65, cZ65) != 0) return -1;
    if (determ_p256_point_compress(t2_33, t2_65) != 0) return -1;
    if (determ_p256_point_compress(t3_33, t3_65) != 0) return -1;
    if (oprf_challenge(c2, pk33, m33, z33, t2_33, t3_33, mode) != 0) return -1;
    return determ_ct_memcmp(c2, c, 32) == 0 ? 0 : -1;
}
