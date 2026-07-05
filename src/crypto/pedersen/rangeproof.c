/* Determ C99 Bulletproofs single-value range proof over NIST P-256 —
 * CRYPTO-C99-SPEC.md §3.19 increment 5. See rangeproof.h for the statement/contract.
 * Ported from the independent Python reference tools/verify_bp_rangeproof.py after
 * that reference's t0-oracle + round-trip + tamper + out-of-range self-tests passed
 * (python-prove-first). Pure composition over the §3.19 inc.1-4 pedersen/IPA
 * primitives and the §3.8c P-256 point/scalar ops; the only new scalar arithmetic
 * is the modular add/sub below. */
#include "determ/crypto/pedersen/rangeproof.h"
#include "determ/crypto/pedersen/ipa.h"
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"

#include <string.h>

#define RP_MAXN DETERM_RANGEPROOF_MAX_BITS      /* 64 */
#define U_INDEX 0xFFFFFFFFu

/* proof layout offsets (see rangeproof.h): A|S|T1|T2|taux|mu|that|ipa */
#define RP_A 0
#define RP_S 33
#define RP_T1 66
#define RP_T2 99
#define RP_TAUX 132
#define RP_MU 164
#define RP_THAT 196
#define RP_HDR 228                              /* == RP_THAT + 32 */

/* The P-256 group order n (big-endian). */
static const uint8_t ORDER_N[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
static const uint8_t SC_ONE[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
static const uint8_t SC_ZERO[32] = {0};

/* r = (a + b) mod n, all 32-byte big-endian, a,b < n. One conditional subtract of
 * n (a+b < 2n). Data-dependent subtract branch — owner-gated CT-hardening step. */
static void sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t sum[33], np[33], diff[33];
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned s = (unsigned)a[i] + b[i] + carry;
        sum[i + 1] = (uint8_t)s; carry = s >> 8;
    }
    sum[0] = (uint8_t)carry;
    np[0] = 0; memcpy(np + 1, ORDER_N, 32);
    int borrow = 0;
    for (int i = 32; i >= 0; i--) {
        int d = (int)sum[i] - np[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        diff[i] = (uint8_t)d;
    }
    memcpy(r, (borrow ? sum : diff) + 1, 32);
}

/* r = (a - b) mod n, for a,b < n. a - b == a + (n - b) mod n. */
static void sc_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t nz = 0;
    for (int i = 0; i < 32; i++) nz |= b[i];
    if (nz == 0) { memcpy(r, a, 32); return; }   /* n - 0 would be >= n; a - 0 = a */
    uint8_t negb[32]; int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)ORDER_N[i] - b[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        negb[i] = (uint8_t)d;                    /* n - b, in (0, n) */
    }
    sc_add(r, a, negb);
}

static int sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    return determ_p256_scalar_mul_mod_n(r, a, b);
}

/* r = <a, b> mod n over m 32-byte scalars. -1 if a scalar is out of range. */
static int rp_inner(uint8_t r[32], const uint8_t *a, const uint8_t *b, size_t m) {
    uint8_t acc[32] = {0}, prod[32];
    for (size_t i = 0; i < m; i++) {
        if (sc_mul(prod, a + i * 32, b + i * 32) != 0) return -1;
        sc_add(acc, acc, prod);
    }
    memcpy(r, acc, 32);
    return 0;
}

static void u64_to_scalar(uint8_t out[32], uint64_t x) {
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(x >> (8 * i));
}

/* out[i*32] = x^i mod n for i in [0,m). */
static int sc_powers(uint8_t *out, const uint8_t x[32], size_t m) {
    if (m == 0) return 0;
    memcpy(out, SC_ONE, 32);
    for (size_t i = 1; i < m; i++)
        if (sc_mul(out + i * 32, out + (i - 1) * 32, x) != 0) return -1;
    return 0;
}

/* out33 = compress(pedersen_gen(index, which)). */
static int gen_c(uint8_t out33[33], uint32_t index, uint8_t which) {
    uint8_t p65[65];
    if (determ_pedersen_gen(p65, index, which) != 0) return -1;
    return determ_p256_point_compress(out33, p65);
}

/* g = the P-256 base point (compressed) = compress(1*G). */
static int base_g(uint8_t out33[33]) {
    uint8_t p65[65];
    if (determ_p256_base_mul(p65, SC_ONE) != 0) return -1;
    return determ_p256_point_compress(out33, p65);
}

/* h = the Pedersen scalar generator H (compressed). */
static int ped_h(uint8_t out33[33]) {
    uint8_t p65[65];
    if (determ_pedersen_generator_h(p65) != 0) return -1;
    return determ_p256_point_compress(out33, p65);
}

/* -1 if n is not a supported power of two in [1, RP_MAXN], else the fold-round
 * count log2(n). */
static int rp_rounds(size_t n) {
    if (n < 1 || n > RP_MAXN) return -1;
    int r = 0; size_t m = n;
    while (m > 1) { if (m & 1) return -1; m >>= 1; r++; }
    return r;
}

size_t determ_rangeproof_proof_len(size_t n) {
    if (rp_rounds(n) < 0) return 0;
    return RP_HDR + determ_ipa_proof_len(n);
}

/* ── the deterministic Fiat-Shamir transcript ─────────────────────────────── */
typedef struct { uint8_t buf[512]; size_t len; } rp_tr;

static void rtr_init(rp_tr *t, const uint8_t V33[33], size_t n) {
    static const char LABEL[] = "DETERM-BP-RANGE-v1";
    t->len = sizeof(LABEL) - 1;
    memcpy(t->buf, LABEL, t->len);
    memcpy(t->buf + t->len, V33, 33); t->len += 33;
    uint32_t nn = (uint32_t)n;
    t->buf[t->len++] = (uint8_t)(nn >> 24); t->buf[t->len++] = (uint8_t)(nn >> 16);
    t->buf[t->len++] = (uint8_t)(nn >> 8);  t->buf[t->len++] = (uint8_t)nn;
}
static void rtr_absorb(rp_tr *t, const uint8_t pt33[33]) {
    memcpy(t->buf + t->len, pt33, 33); t->len += 33;
}
static int rtr_challenge(rp_tr *t, uint8_t out32[32]) {
    static const char CDST[] = "DETERM-BP-RANGE-v1-challenge";
    if (determ_p256_hash_to_scalar(out32, t->buf, t->len,
                                   (const uint8_t *)CDST, sizeof(CDST) - 1) != 0) return -1;
    uint8_t z = 0; for (int i = 0; i < 32; i++) z |= out32[i];
    if (z == 0) return -1;
    memcpy(t->buf + t->len, out32, 32); t->len += 32;
    return 0;
}

/* out33 = the msm; returns -1 on error OR the (fail-closed) identity result. */
static int msm_nonid(uint8_t out33[33], const uint8_t *scal, const uint8_t *pts, size_t cnt) {
    return determ_pedersen_msm(out33, scal, pts, cnt) == 0 ? 0 : -1;
}

int determ_rangeproof_prove(uint8_t V_out[33], uint8_t *proof,
                            uint64_t v, const uint8_t gamma[32],
                            const uint8_t alpha[32], const uint8_t rho[32],
                            const uint8_t tau1[32], const uint8_t tau2[32],
                            const uint8_t *sL, const uint8_t *sR, size_t n) {
    if (rp_rounds(n) < 0) return -1;

    uint8_t g[33], h[33], gv[RP_MAXN * 33], hv[RP_MAXN * 33], u[33];
    if (base_g(g) != 0 || ped_h(h) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        if (gen_c(gv + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(hv + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;

    /* a_L = bits of v; a_R = a_L - 1 mod n */
    uint8_t aL[RP_MAXN * 32], aR[RP_MAXN * 32];
    for (size_t i = 0; i < n; i++) {
        memset(aL + i * 32, 0, 32);
        aL[i * 32 + 31] = (uint8_t)((v >> i) & 1);
        sc_sub(aR + i * 32, aL + i * 32, SC_ONE);
    }

    /* V = v*g + gamma*h */
    uint8_t vscal[32], sc2[2 * 32], pt2[2 * 33];
    u64_to_scalar(vscal, v);
    memcpy(sc2, vscal, 32); memcpy(sc2 + 32, gamma, 32);
    memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
    if (msm_nonid(V_out, sc2, pt2, 2) != 0) return -1;

    /* A = alpha*h + <aL,gv> + <aR,hv> ;  S = rho*h + <sL,gv> + <sR,hv> */
    uint8_t scal[(2 * RP_MAXN + 1) * 32], pts[(2 * RP_MAXN + 1) * 33];
    uint8_t A[33], S[33];
    memcpy(scal, alpha, 32);
    for (size_t i = 0; i < n; i++) { memcpy(scal + (1 + i) * 32, aL + i * 32, 32);
                                     memcpy(scal + (1 + n + i) * 32, aR + i * 32, 32); }
    memcpy(pts, h, 33);
    for (size_t i = 0; i < n; i++) { memcpy(pts + (1 + i) * 33, gv + i * 33, 33);
                                     memcpy(pts + (1 + n + i) * 33, hv + i * 33, 33); }
    if (msm_nonid(A, scal, pts, 2 * n + 1) != 0) return -1;
    memcpy(scal, rho, 32);
    for (size_t i = 0; i < n; i++) { memcpy(scal + (1 + i) * 32, sL + i * 32, 32);
                                     memcpy(scal + (1 + n + i) * 32, sR + i * 32, 32); }
    if (msm_nonid(S, scal, pts, 2 * n + 1) != 0) return -1;

    rp_tr tr; rtr_init(&tr, V_out, n);
    rtr_absorb(&tr, A); rtr_absorb(&tr, S);
    uint8_t y[32], z[32];
    if (rtr_challenge(&tr, y) != 0) return -1;
    if (rtr_challenge(&tr, z) != 0) return -1;

    uint8_t yn[RP_MAXN * 32], twon[RP_MAXN * 32], z2[32];
    if (sc_powers(yn, y, n) != 0) return -1;
    for (size_t i = 0; i < n; i++) u64_to_scalar(twon + i * 32, (uint64_t)1 << i);
    if (sc_mul(z2, z, z) != 0) return -1;

    /* l0 = aL - z*1 ; r0 = yn o (aR + z*1) + z^2*2^n ; r1 = yn o sR */
    uint8_t l0[RP_MAXN * 32], r0[RP_MAXN * 32], r1[RP_MAXN * 32];
    for (size_t i = 0; i < n; i++) {
        sc_sub(l0 + i * 32, aL + i * 32, z);
        uint8_t t[32], t2[32];
        sc_add(t, aR + i * 32, z);
        if (sc_mul(t, yn + i * 32, t) != 0) return -1;         /* yn*(aR+z) */
        if (sc_mul(t2, z2, twon + i * 32) != 0) return -1;     /* z^2*2^i */
        sc_add(r0 + i * 32, t, t2);
        if (sc_mul(r1 + i * 32, yn + i * 32, sR + i * 32) != 0) return -1;
    }

    /* t1 = <sL,r0> + <l0,r1> ; t2 = <sL,r1> ; T1 = t1*g + tau1*h ; T2 = t2*g + tau2*h */
    uint8_t t1[32], t2[32], ta[32], tb[32], T1[33], T2[33];
    if (rp_inner(ta, sL, r0, n) != 0 || rp_inner(tb, l0, r1, n) != 0) return -1;
    sc_add(t1, ta, tb);
    if (rp_inner(t2, sL, r1, n) != 0) return -1;
    memcpy(sc2, t1, 32); memcpy(sc2 + 32, tau1, 32);
    memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
    if (msm_nonid(T1, sc2, pt2, 2) != 0) return -1;
    memcpy(sc2, t2, 32); memcpy(sc2 + 32, tau2, 32);
    if (msm_nonid(T2, sc2, pt2, 2) != 0) return -1;

    rtr_absorb(&tr, T1); rtr_absorb(&tr, T2);
    uint8_t x[32];
    if (rtr_challenge(&tr, x) != 0) return -1;

    /* l = l0 + sL*x ; r = r0 + r1*x ; that = <l,r> */
    uint8_t l[RP_MAXN * 32], r[RP_MAXN * 32], that[32];
    for (size_t i = 0; i < n; i++) {
        uint8_t t[32];
        if (sc_mul(t, sL + i * 32, x) != 0) return -1;
        sc_add(l + i * 32, l0 + i * 32, t);
        if (sc_mul(t, r1 + i * 32, x) != 0) return -1;
        sc_add(r + i * 32, r0 + i * 32, t);
    }
    if (rp_inner(that, l, r, n) != 0) return -1;

    /* taux = tau2*x^2 + tau1*x + z^2*gamma ; mu = alpha + rho*x */
    uint8_t x2[32], taux[32], mu[32], ta2[32], tb2[32], tc2[32];
    if (sc_mul(x2, x, x) != 0) return -1;
    if (sc_mul(ta2, tau2, x2) != 0) return -1;
    if (sc_mul(tb2, tau1, x) != 0) return -1;
    if (sc_mul(tc2, z2, gamma) != 0) return -1;
    sc_add(taux, tb2, tc2); sc_add(taux, ta2, taux);
    if (sc_mul(ta2, rho, x) != 0) return -1;
    sc_add(mu, alpha, ta2);

    /* h'_i = y^-i * h_i ; P_ipa = <l,gv> + <r,h'v> + that*u */
    uint8_t yinv[32], yinvn[RP_MAXN * 32], hprime[RP_MAXN * 33];
    if (determ_p256_scalar_inv_mod_n(yinv, y) != 0) return -1;
    if (sc_powers(yinvn, yinv, n) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t P[65], T[65];
        if (determ_p256_point_decompress(P, hv + i * 33) != 0) return -1;
        if (determ_p256_point_mul(T, yinvn + i * 32, P) != 0) return -1;
        if (determ_p256_point_compress(hprime + i * 33, T) != 0) return -1;
    }
    uint8_t P_ipa[33];
    for (size_t i = 0; i < n; i++) { memcpy(scal + i * 32, l + i * 32, 32);
                                     memcpy(scal + (n + i) * 32, r + i * 32, 32); }
    memcpy(scal + 2 * n * 32, that, 32);
    for (size_t i = 0; i < n; i++) { memcpy(pts + i * 33, gv + i * 33, 33);
                                     memcpy(pts + (n + i) * 33, hprime + i * 33, 33); }
    memcpy(pts + 2 * n * 33, u, 33);
    if (msm_nonid(P_ipa, scal, pts, 2 * n + 1) != 0) return -1;

    if (determ_ipa_prove_gens(proof + RP_HDR, l, r, gv, hprime, u, P_ipa, n) != 0) return -1;

    memcpy(proof + RP_A, A, 33);   memcpy(proof + RP_S, S, 33);
    memcpy(proof + RP_T1, T1, 33); memcpy(proof + RP_T2, T2, 33);
    memcpy(proof + RP_TAUX, taux, 32); memcpy(proof + RP_MU, mu, 32);
    memcpy(proof + RP_THAT, that, 32);
    return 0;
}

int determ_rangeproof_verify(const uint8_t V33[33], const uint8_t *proof, size_t n) {
    if (rp_rounds(n) < 0) return -1;

    uint8_t g[33], h[33], gv[RP_MAXN * 33], hv[RP_MAXN * 33], u[33];
    if (base_g(g) != 0 || ped_h(h) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        if (gen_c(gv + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(hv + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;

    const uint8_t *A = proof + RP_A, *S = proof + RP_S;
    const uint8_t *T1 = proof + RP_T1, *T2 = proof + RP_T2;
    const uint8_t *taux = proof + RP_TAUX, *mu = proof + RP_MU, *that = proof + RP_THAT;
    const uint8_t *ipa = proof + RP_HDR;

    rp_tr tr; rtr_init(&tr, V33, n);
    rtr_absorb(&tr, A); rtr_absorb(&tr, S);
    uint8_t y[32], z[32];
    if (rtr_challenge(&tr, y) != 0) return -1;
    if (rtr_challenge(&tr, z) != 0) return -1;
    rtr_absorb(&tr, T1); rtr_absorb(&tr, T2);
    uint8_t x[32];
    if (rtr_challenge(&tr, x) != 0) return -1;

    uint8_t yn[RP_MAXN * 32], twon[RP_MAXN * 32], z2[32], x2[32];
    if (sc_powers(yn, y, n) != 0) return -1;
    for (size_t i = 0; i < n; i++) u64_to_scalar(twon + i * 32, (uint64_t)1 << i);
    if (sc_mul(z2, z, z) != 0) return -1;
    if (sc_mul(x2, x, x) != 0) return -1;

    /* Check 1: that*g + taux*h == z^2*V + delta(y,z)*g + x*T1 + x^2*T2 */
    uint8_t sum_y[32] = {0}, sum_2[32] = {0}, delta[32], ta[32], tb[32];
    for (size_t i = 0; i < n; i++) { sc_add(sum_y, sum_y, yn + i * 32);
                                     sc_add(sum_2, sum_2, twon + i * 32); }
    sc_sub(ta, z, z2);                          /* z - z^2 */
    if (sc_mul(ta, ta, sum_y) != 0) return -1;  /* (z - z^2)*<1,y^n> */
    if (sc_mul(tb, z2, z) != 0) return -1;       /* z^3 */
    if (sc_mul(tb, tb, sum_2) != 0) return -1;   /* z^3*<1,2^n> */
    sc_sub(delta, ta, tb);

    uint8_t lhs[33], rhs[33];
    uint8_t sc2[2 * 32], pt2[2 * 33], sc4[4 * 32], pt4[4 * 33];
    memcpy(sc2, that, 32); memcpy(sc2 + 32, taux, 32);
    memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
    if (msm_nonid(lhs, sc2, pt2, 2) != 0) return -1;
    memcpy(sc4, z2, 32); memcpy(sc4 + 32, delta, 32);
    memcpy(sc4 + 64, x, 32); memcpy(sc4 + 96, x2, 32);
    memcpy(pt4, V33, 33); memcpy(pt4 + 33, g, 33);
    memcpy(pt4 + 66, T1, 33); memcpy(pt4 + 99, T2, 33);
    if (msm_nonid(rhs, sc4, pt4, 4) != 0) return -1;
    if (memcmp(lhs, rhs, 33) != 0) return -1;

    /* Check 2: reconstruct P = A + x*S - z*<1,gv> + <z*yn + z^2*2^n, h'v> - mu*h,
     * then verify the IPA binds <l,r> = that over (gv, h'v, u). */
    uint8_t yinv[32], yinvn[RP_MAXN * 32], hprime[RP_MAXN * 33];
    if (determ_p256_scalar_inv_mod_n(yinv, y) != 0) return -1;
    if (sc_powers(yinvn, yinv, n) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t P[65], T[65];
        if (determ_p256_point_decompress(P, hv + i * 33) != 0) return -1;
        if (determ_p256_point_mul(T, yinvn + i * 32, P) != 0) return -1;
        if (determ_p256_point_compress(hprime + i * 33, T) != 0) return -1;
    }
    uint8_t negz[32], negmu[32];
    sc_sub(negz, SC_ZERO, z);
    sc_sub(negmu, SC_ZERO, mu);
    uint8_t scal[(2 * RP_MAXN + 3) * 32], pts[(2 * RP_MAXN + 3) * 33];
    memcpy(scal, SC_ONE, 32); memcpy(scal + 32, x, 32);
    for (size_t i = 0; i < n; i++) memcpy(scal + (2 + i) * 32, negz, 32);
    for (size_t i = 0; i < n; i++) {
        uint8_t t[32], t2[32];
        if (sc_mul(t, z, yn + i * 32) != 0) return -1;        /* z*y^i */
        if (sc_mul(t2, z2, twon + i * 32) != 0) return -1;    /* z^2*2^i */
        sc_add(scal + (2 + n + i) * 32, t, t2);
    }
    memcpy(scal + (2 + 2 * n) * 32, negmu, 32);
    memcpy(pts, A, 33); memcpy(pts + 33, S, 33);
    for (size_t i = 0; i < n; i++) { memcpy(pts + (2 + i) * 33, gv + i * 33, 33);
                                     memcpy(pts + (2 + n + i) * 33, hprime + i * 33, 33); }
    memcpy(pts + (2 + 2 * n) * 33, h, 33);
    uint8_t P[33];
    if (msm_nonid(P, scal, pts, 2 * n + 3) != 0) return -1;

    /* P_ipa = P + that*u */
    uint8_t P_ipa[33];
    memcpy(sc2, SC_ONE, 32); memcpy(sc2 + 32, that, 32);
    memcpy(pt2, P, 33); memcpy(pt2 + 33, u, 33);
    if (msm_nonid(P_ipa, sc2, pt2, 2) != 0) return -1;

    return determ_ipa_verify_gens(P_ipa, ipa, gv, hprime, u, n);
}

/* ── §3.19 increment 6: the AGGREGATED range proof (m values, one proof) ──────
 * Ported from tools/verify_bp_agg_rangeproof.py (python-prove-first). Reuses every
 * file-static helper above; the aggregated vectors are m*n wide (<= DETERM_IPA_MAX_N).
 * Value j's 2^n slot is scaled by z^(2+j); m=1 reduces to the single-value proof. */
#define MN_MAX DETERM_IPA_MAX_N                 /* 256: max aggregated bit-width m*n */

/* -1 if (m,n) invalid, else log2(m*n). Requires n in [1,64], m>=1, m*n a power of
 * two in [1, MN_MAX]. */
static int agg_rounds(size_t m, size_t n) {
    if (m < 1 || n < 1 || n > RP_MAXN) return -1;
    size_t nm = m * n;
    if (nm < 1 || nm > MN_MAX) return -1;
    int r = 0; size_t t = nm;
    while (t > 1) { if (t & 1) return -1; t >>= 1; r++; }
    return r;
}

size_t determ_agg_rangeproof_proof_len(size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return 0;
    return RP_HDR + determ_ipa_proof_len(m * n);
}

/* aggregated Fiat-Shamir transcript: label ‖ m(4BE) ‖ n(4BE) ‖ V_0..V_{m-1} */
typedef struct { uint8_t buf[9600]; size_t len; } agg_tr;   /* m<=256 => V bytes <= 8448 */
static void atr_init(agg_tr *t, const uint8_t *Vs, size_t m, size_t n) {
    static const char LABEL[] = "DETERM-BP-AGGRANGE-v1";
    t->len = sizeof(LABEL) - 1;
    memcpy(t->buf, LABEL, t->len);
    uint32_t mm = (uint32_t)m, nn = (uint32_t)n;
    t->buf[t->len++] = (uint8_t)(mm >> 24); t->buf[t->len++] = (uint8_t)(mm >> 16);
    t->buf[t->len++] = (uint8_t)(mm >> 8);  t->buf[t->len++] = (uint8_t)mm;
    t->buf[t->len++] = (uint8_t)(nn >> 24); t->buf[t->len++] = (uint8_t)(nn >> 16);
    t->buf[t->len++] = (uint8_t)(nn >> 8);  t->buf[t->len++] = (uint8_t)nn;
    for (size_t j = 0; j < m; j++) { memcpy(t->buf + t->len, Vs + j * 33, 33); t->len += 33; }
}
static void atr_absorb(agg_tr *t, const uint8_t pt33[33]) {
    memcpy(t->buf + t->len, pt33, 33); t->len += 33;
}
static int atr_challenge(agg_tr *t, uint8_t out32[32]) {
    static const char CDST[] = "DETERM-BP-AGGRANGE-v1-challenge";
    if (determ_p256_hash_to_scalar(out32, t->buf, t->len,
                                   (const uint8_t *)CDST, sizeof(CDST) - 1) != 0) return -1;
    uint8_t z = 0; for (int i = 0; i < 32; i++) z |= out32[i];
    if (z == 0) return -1;
    memcpy(t->buf + t->len, out32, 32); t->len += 32;
    return 0;
}

int determ_agg_rangeproof_prove(uint8_t *V_out, uint8_t *proof,
                                const uint64_t *v, const uint8_t *gamma,
                                const uint8_t alpha[32], const uint8_t rho[32],
                                const uint8_t tau1[32], const uint8_t tau2[32],
                                const uint8_t *sL, const uint8_t *sR,
                                size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return -1;
    size_t nm = m * n;

    uint8_t g[33], h[33], u[33], gv[MN_MAX * 33], hv[MN_MAX * 33];
    if (base_g(g) != 0 || ped_h(h) != 0) return -1;
    for (size_t i = 0; i < nm; i++) {
        if (gen_c(gv + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(hv + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;

    uint8_t sc2[2 * 32], pt2[2 * 33];
    for (size_t j = 0; j < m; j++) {              /* V_j = v_j*g + gamma_j*h */
        uint8_t vscal[32];
        u64_to_scalar(vscal, v[j]);
        memcpy(sc2, vscal, 32); memcpy(sc2 + 32, gamma + j * 32, 32);
        memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
        if (msm_nonid(V_out + j * 33, sc2, pt2, 2) != 0) return -1;
    }

    uint8_t aL[MN_MAX * 32], aR[MN_MAX * 32];
    for (size_t j = 0; j < m; j++) for (size_t k = 0; k < n; k++) {
        size_t i = j * n + k;
        memset(aL + i * 32, 0, 32);
        aL[i * 32 + 31] = (uint8_t)((v[j] >> k) & 1);
        sc_sub(aR + i * 32, aL + i * 32, SC_ONE);
    }

    uint8_t scal[(2 * MN_MAX + 3) * 32], pts[(2 * MN_MAX + 3) * 33];
    uint8_t A[33], S[33];
    memcpy(scal, alpha, 32);
    for (size_t i = 0; i < nm; i++) { memcpy(scal + (1 + i) * 32, aL + i * 32, 32);
                                      memcpy(scal + (1 + nm + i) * 32, aR + i * 32, 32); }
    memcpy(pts, h, 33);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + (1 + i) * 33, gv + i * 33, 33);
                                      memcpy(pts + (1 + nm + i) * 33, hv + i * 33, 33); }
    if (msm_nonid(A, scal, pts, 2 * nm + 1) != 0) return -1;
    memcpy(scal, rho, 32);
    for (size_t i = 0; i < nm; i++) { memcpy(scal + (1 + i) * 32, sL + i * 32, 32);
                                      memcpy(scal + (1 + nm + i) * 32, sR + i * 32, 32); }
    if (msm_nonid(S, scal, pts, 2 * nm + 1) != 0) return -1;

    agg_tr tr; atr_init(&tr, V_out, m, n);
    atr_absorb(&tr, A); atr_absorb(&tr, S);
    uint8_t y[32], z[32];
    if (atr_challenge(&tr, y) != 0) return -1;
    if (atr_challenge(&tr, z) != 0) return -1;

    uint8_t yn[MN_MAX * 32], twon[RP_MAXN * 32], z2[32];
    if (sc_powers(yn, y, nm) != 0) return -1;
    for (size_t k = 0; k < n; k++) u64_to_scalar(twon + k * 32, (uint64_t)1 << k);
    if (sc_mul(z2, z, z) != 0) return -1;

    /* zslot[j*n+k] = z^(2+j) * 2^k */
    uint8_t zslot[MN_MAX * 32], zpow[32]; memcpy(zpow, z2, 32);
    for (size_t j = 0; j < m; j++) {
        for (size_t k = 0; k < n; k++)
            if (sc_mul(zslot + (j * n + k) * 32, zpow, twon + k * 32) != 0) return -1;
        if (j + 1 < m && sc_mul(zpow, zpow, z) != 0) return -1;
    }

    uint8_t l0[MN_MAX * 32], r0[MN_MAX * 32], r1[MN_MAX * 32];
    for (size_t i = 0; i < nm; i++) {
        sc_sub(l0 + i * 32, aL + i * 32, z);
        uint8_t t[32];
        sc_add(t, aR + i * 32, z);
        if (sc_mul(t, yn + i * 32, t) != 0) return -1;
        sc_add(r0 + i * 32, t, zslot + i * 32);
        if (sc_mul(r1 + i * 32, yn + i * 32, sR + i * 32) != 0) return -1;
    }

    uint8_t t1[32], t2[32], ta[32], tb[32], T1[33], T2[33];
    if (rp_inner(ta, sL, r0, nm) != 0 || rp_inner(tb, l0, r1, nm) != 0) return -1;
    sc_add(t1, ta, tb);
    if (rp_inner(t2, sL, r1, nm) != 0) return -1;
    memcpy(sc2, t1, 32); memcpy(sc2 + 32, tau1, 32);
    memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
    if (msm_nonid(T1, sc2, pt2, 2) != 0) return -1;
    memcpy(sc2, t2, 32); memcpy(sc2 + 32, tau2, 32);
    if (msm_nonid(T2, sc2, pt2, 2) != 0) return -1;

    atr_absorb(&tr, T1); atr_absorb(&tr, T2);
    uint8_t x[32];
    if (atr_challenge(&tr, x) != 0) return -1;

    uint8_t l[MN_MAX * 32], r[MN_MAX * 32], that[32];
    for (size_t i = 0; i < nm; i++) {
        uint8_t t[32];
        if (sc_mul(t, sL + i * 32, x) != 0) return -1;
        sc_add(l + i * 32, l0 + i * 32, t);
        if (sc_mul(t, r1 + i * 32, x) != 0) return -1;
        sc_add(r + i * 32, r0 + i * 32, t);
    }
    if (rp_inner(that, l, r, nm) != 0) return -1;

    /* taux = tau2*x^2 + tau1*x + sum_j z^(2+j)*gamma_j ; mu = alpha + rho*x */
    uint8_t x2[32], taux[32], mu[32], tmp[32];
    if (sc_mul(x2, x, x) != 0) return -1;
    if (sc_mul(taux, tau2, x2) != 0) return -1;
    if (sc_mul(tmp, tau1, x) != 0) return -1;
    sc_add(taux, taux, tmp);
    memcpy(zpow, z2, 32);
    for (size_t j = 0; j < m; j++) {
        if (sc_mul(tmp, zpow, gamma + j * 32) != 0) return -1;
        sc_add(taux, taux, tmp);
        if (j + 1 < m && sc_mul(zpow, zpow, z) != 0) return -1;
    }
    if (sc_mul(tmp, rho, x) != 0) return -1;
    sc_add(mu, alpha, tmp);

    uint8_t yinv[32], yinvn[MN_MAX * 32], hprime[MN_MAX * 33];
    if (determ_p256_scalar_inv_mod_n(yinv, y) != 0) return -1;
    if (sc_powers(yinvn, yinv, nm) != 0) return -1;
    for (size_t i = 0; i < nm; i++) {
        uint8_t P[65], T[65];
        if (determ_p256_point_decompress(P, hv + i * 33) != 0) return -1;
        if (determ_p256_point_mul(T, yinvn + i * 32, P) != 0) return -1;
        if (determ_p256_point_compress(hprime + i * 33, T) != 0) return -1;
    }
    uint8_t P_ipa[33];
    for (size_t i = 0; i < nm; i++) { memcpy(scal + i * 32, l + i * 32, 32);
                                      memcpy(scal + (nm + i) * 32, r + i * 32, 32); }
    memcpy(scal + 2 * nm * 32, that, 32);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + i * 33, gv + i * 33, 33);
                                      memcpy(pts + (nm + i) * 33, hprime + i * 33, 33); }
    memcpy(pts + 2 * nm * 33, u, 33);
    if (msm_nonid(P_ipa, scal, pts, 2 * nm + 1) != 0) return -1;

    if (determ_ipa_prove_gens(proof + RP_HDR, l, r, gv, hprime, u, P_ipa, nm) != 0) return -1;

    memcpy(proof + RP_A, A, 33);   memcpy(proof + RP_S, S, 33);
    memcpy(proof + RP_T1, T1, 33); memcpy(proof + RP_T2, T2, 33);
    memcpy(proof + RP_TAUX, taux, 32); memcpy(proof + RP_MU, mu, 32);
    memcpy(proof + RP_THAT, that, 32);
    return 0;
}

int determ_agg_rangeproof_verify(const uint8_t *V, const uint8_t *proof, size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return -1;
    size_t nm = m * n;

    uint8_t g[33], h[33], u[33], gv[MN_MAX * 33], hv[MN_MAX * 33];
    if (base_g(g) != 0 || ped_h(h) != 0) return -1;
    for (size_t i = 0; i < nm; i++) {
        if (gen_c(gv + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(hv + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;

    const uint8_t *A = proof + RP_A, *S = proof + RP_S;
    const uint8_t *T1 = proof + RP_T1, *T2 = proof + RP_T2;
    const uint8_t *taux = proof + RP_TAUX, *mu = proof + RP_MU, *that = proof + RP_THAT;
    const uint8_t *ipa = proof + RP_HDR;

    agg_tr tr; atr_init(&tr, V, m, n);
    atr_absorb(&tr, A); atr_absorb(&tr, S);
    uint8_t y[32], z[32];
    if (atr_challenge(&tr, y) != 0) return -1;
    if (atr_challenge(&tr, z) != 0) return -1;
    atr_absorb(&tr, T1); atr_absorb(&tr, T2);
    uint8_t x[32];
    if (atr_challenge(&tr, x) != 0) return -1;

    uint8_t yn[MN_MAX * 32], twon[RP_MAXN * 32], z2[32], x2[32];
    if (sc_powers(yn, y, nm) != 0) return -1;
    for (size_t k = 0; k < n; k++) u64_to_scalar(twon + k * 32, (uint64_t)1 << k);
    if (sc_mul(z2, z, z) != 0) return -1;
    if (sc_mul(x2, x, x) != 0) return -1;

    /* zslot + the per-value z^(2+j) (needed for Check 1's V-side + zsum for delta) */
    uint8_t zslot[MN_MAX * 32], zpow[32]; memcpy(zpow, z2, 32);
    uint8_t vscal[MN_MAX * 32];            /* reused: holds the z^(2+j) V-side scalars (m<=256) */
    uint8_t zsum[32] = {0};                /* sum_j z^(3+j) for delta */
    for (size_t j = 0; j < m; j++) {
        memcpy(vscal + j * 32, zpow, 32);
        uint8_t t3[32];
        if (sc_mul(t3, zpow, z) != 0) return -1;   /* z^(3+j) */
        sc_add(zsum, zsum, t3);
        for (size_t k = 0; k < n; k++)
            if (sc_mul(zslot + (j * n + k) * 32, zpow, twon + k * 32) != 0) return -1;
        if (j + 1 < m && sc_mul(zpow, zpow, z) != 0) return -1;
    }

    /* delta = (z - z^2)*<1^{mn}, y^{mn}> - zsum*(2^n - 1) */
    uint8_t sum_y[32] = {0}, sum_2[32] = {0}, delta[32], ta[32], tb[32];
    for (size_t i = 0; i < nm; i++) sc_add(sum_y, sum_y, yn + i * 32);
    for (size_t k = 0; k < n; k++) sc_add(sum_2, sum_2, twon + k * 32);
    sc_sub(ta, z, z2);
    if (sc_mul(ta, ta, sum_y) != 0) return -1;
    if (sc_mul(tb, zsum, sum_2) != 0) return -1;
    sc_sub(delta, ta, tb);

    /* Check 1: that*g + taux*h == sum_j z^(2+j)*V_j + delta*g + x*T1 + x^2*T2 */
    uint8_t lhs[33], rhs[33], sc2[2 * 32], pt2[2 * 33];
    uint8_t scal[(2 * MN_MAX + 3) * 32], pts[(2 * MN_MAX + 3) * 33];
    memcpy(sc2, that, 32); memcpy(sc2 + 32, taux, 32);
    memcpy(pt2, g, 33); memcpy(pt2 + 33, h, 33);
    if (msm_nonid(lhs, sc2, pt2, 2) != 0) return -1;
    for (size_t j = 0; j < m; j++) { memcpy(scal + j * 32, vscal + j * 32, 32);
                                     memcpy(pts + j * 33, V + j * 33, 33); }
    memcpy(scal + m * 32, delta, 32); memcpy(scal + (m + 1) * 32, x, 32);
    memcpy(scal + (m + 2) * 32, x2, 32);
    memcpy(pts + m * 33, g, 33); memcpy(pts + (m + 1) * 33, T1, 33);
    memcpy(pts + (m + 2) * 33, T2, 33);
    if (msm_nonid(rhs, scal, pts, m + 3) != 0) return -1;
    if (memcmp(lhs, rhs, 33) != 0) return -1;

    /* Check 2: P = A + x*S - z*<1,gv> + <z*y^{mn} + zslot, h'> - mu*h, then IPA */
    uint8_t yinv[32], yinvn[MN_MAX * 32], hprime[MN_MAX * 33];
    if (determ_p256_scalar_inv_mod_n(yinv, y) != 0) return -1;
    if (sc_powers(yinvn, yinv, nm) != 0) return -1;
    for (size_t i = 0; i < nm; i++) {
        uint8_t P[65], T[65];
        if (determ_p256_point_decompress(P, hv + i * 33) != 0) return -1;
        if (determ_p256_point_mul(T, yinvn + i * 32, P) != 0) return -1;
        if (determ_p256_point_compress(hprime + i * 33, T) != 0) return -1;
    }
    uint8_t negz[32], negmu[32];
    sc_sub(negz, SC_ZERO, z);
    sc_sub(negmu, SC_ZERO, mu);
    memcpy(scal, SC_ONE, 32); memcpy(scal + 32, x, 32);
    for (size_t i = 0; i < nm; i++) memcpy(scal + (2 + i) * 32, negz, 32);
    for (size_t i = 0; i < nm; i++) {
        uint8_t t[32];
        if (sc_mul(t, z, yn + i * 32) != 0) return -1;
        sc_add(scal + (2 + nm + i) * 32, t, zslot + i * 32);
    }
    memcpy(scal + (2 + 2 * nm) * 32, negmu, 32);
    memcpy(pts, A, 33); memcpy(pts + 33, S, 33);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + (2 + i) * 33, gv + i * 33, 33);
                                      memcpy(pts + (2 + nm + i) * 33, hprime + i * 33, 33); }
    memcpy(pts + (2 + 2 * nm) * 33, h, 33);
    uint8_t P[33];
    if (msm_nonid(P, scal, pts, 2 * nm + 3) != 0) return -1;

    uint8_t P_ipa[33];
    memcpy(sc2, SC_ONE, 32); memcpy(sc2 + 32, that, 32);
    memcpy(pt2, P, 33); memcpy(pt2 + 33, u, 33);
    if (msm_nonid(P_ipa, sc2, pt2, 2) != 0) return -1;

    return determ_ipa_verify_gens(P_ipa, ipa, gv, hprime, u, nm);
}
