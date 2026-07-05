/* Determ C99 Bulletproofs single-value range proof over Z_p* — CRYPTO-C99-SPEC.md
 * §3.20 increment 5. See ffrangeproof.h. Ported from tools/verify_ff_rangeproof.py
 * after that reference's prove/verify + out-of-range + tamper + wrong-V self-tests
 * passed (python-prove-first). Pure composition over the §3.20 inc.1-4 group / scalar /
 * IPA primitives; the value generator is g = 4 and the blinding generator is the inc.1
 * nothing-up-my-sleeve h. Working vectors are heap-allocated (n up to 64 × 384-byte
 * elements would overflow the stack). NOT constant-time (owner-gated). */
#include "determ/crypto/ff/ffrangeproof.h"
#include "determ/crypto/ff/ffipa.h"
#include "determ/crypto/ff/ffgroup.h"

#include <string.h>
#include <stdlib.h>

#define E DETERM_FF_ELEM_BYTES              /* 384 */
#define RP_MAXN DETERM_FF_RANGEPROOF_MAX_BITS
#define U_INDEX 0xFFFFFFFFu

/* proof layout (all 384-byte fields): A|S|T1|T2|taux|mu|that|ipa */
#define RP_A   (0 * E)
#define RP_S   (1 * E)
#define RP_T1  (2 * E)
#define RP_T2  (3 * E)
#define RP_TAUX (4 * E)
#define RP_MU  (5 * E)
#define RP_THAT (6 * E)
#define RP_HDR (7 * E)

static const char RTR_LABEL[] = "DETERM-FF-BP-RANGE-v1";
static const char RTR_CDST[]  = "DETERM-FF-BP-RANGE-v1-challenge";

/* small scalar constants (384-byte big-endian). */
static void sc_one(uint8_t o[E])  { memset(o, 0, E); o[E - 1] = 1; }
static void sc_zero(uint8_t o[E]) { memset(o, 0, E); }
static void ff_u64(uint8_t o[E], uint64_t x) { memset(o, 0, E); for (int i = 0; i < 8; i++) o[E - 1 - i] = (uint8_t)(x >> (8 * i)); }
static void g_val_elem(uint8_t o[E]) { memset(o, 0, E); o[E - 1] = 4; }   /* the value generator g = 4 */

static int rp_rounds(size_t n) {
    if (n < 1 || n > RP_MAXN) return -1;
    int r = 0; size_t m = n;
    while (m > 1) { if (m & 1) return -1; m >>= 1; r++; }
    return r;
}

size_t determ_ff_rangeproof_proof_len(size_t n) {
    if (rp_rounds(n) < 0) return 0;
    return RP_HDR + determ_ff_ipa_proof_len(n);
}

/* out = <a,b> mod q over m 384-byte scalars. -1 on a bad scalar. */
static int ff_inner(uint8_t out[E], const uint8_t *a, const uint8_t *b, size_t m) {
    uint8_t acc[E], prod[E];
    memset(acc, 0, E);
    for (size_t i = 0; i < m; i++) {
        if (determ_ff_scalar_mul(prod, a + i * E, b + i * E) != 0) return -1;
        if (determ_ff_scalar_add(acc, acc, prod) != 0) return -1;
    }
    memcpy(out, acc, E);
    return 0;
}

/* out[i*E] = x^i mod q for i in [0,m). */
static int ff_powers(uint8_t *out, const uint8_t x[E], size_t m) {
    if (m == 0) return 0;
    sc_one(out);
    for (size_t i = 1; i < m; i++)
        if (determ_ff_scalar_mul(out + i * E, out + (i - 1) * E, x) != 0) return -1;
    return 0;
}

typedef struct { uint8_t buf[4096]; size_t len; } rp_tr;
static void rtr_init(rp_tr *t, const uint8_t V[E], size_t n) {
    t->len = sizeof(RTR_LABEL) - 1;
    memcpy(t->buf, RTR_LABEL, t->len);
    memcpy(t->buf + t->len, V, E); t->len += E;
    uint32_t nn = (uint32_t)n;
    t->buf[t->len++] = (uint8_t)(nn >> 24); t->buf[t->len++] = (uint8_t)(nn >> 16);
    t->buf[t->len++] = (uint8_t)(nn >> 8);  t->buf[t->len++] = (uint8_t)nn;
}
static void rtr_absorb(rp_tr *t, const uint8_t pt[E]) { memcpy(t->buf + t->len, pt, E); t->len += E; }
static int rtr_challenge(rp_tr *t, uint8_t out[E]) {
    if (determ_ff_hash_to_scalar(out, t->buf, t->len, (const uint8_t *)RTR_CDST, sizeof(RTR_CDST) - 1) != 0) return -1;
    memcpy(t->buf + t->len, out, E); t->len += E;
    return 0;
}

int determ_ff_rangeproof_prove(uint8_t V_out[E], uint8_t *proof, uint64_t v,
                               const uint8_t gamma[E], const uint8_t alpha[E], const uint8_t rho[E],
                               const uint8_t tau1[E], const uint8_t tau2[E],
                               const uint8_t *sL, const uint8_t *sR, size_t n) {
    if (rp_rounds(n) < 0) return -1;
    int rc = -1;
    uint8_t *gv = calloc(n, E), *hv = calloc(n, E), *hprime = calloc(n, E);
    uint8_t *aL = calloc(n, E), *aR = calloc(n, E), *l0 = calloc(n, E);
    uint8_t *r0 = calloc(n, E), *r1 = calloc(n, E), *l = calloc(n, E), *r = calloc(n, E);
    uint8_t *yn = calloc(n, E), *twon = calloc(n, E), *yinvn = calloc(n, E);
    uint8_t *scal = calloc(2 * n + 1, E), *pts = calloc(2 * n + 1, E);
    rp_tr *tr = malloc(sizeof(rp_tr));
    if (!gv||!hv||!hprime||!aL||!aR||!l0||!r0||!r1||!l||!r||!yn||!twon||!yinvn||!scal||!pts||!tr) goto done;

    uint8_t g_val[E], h[E], u[E], one[E];
    g_val_elem(g_val); sc_one(one);
    if (determ_ff_pedersen_generator_h(h) != 0) goto done;
    if (determ_ff_gen(u, U_INDEX, 0) != 0) goto done;
    for (size_t i = 0; i < n; i++) {
        if (determ_ff_gen(gv + i * E, (uint32_t)i, 0) != 0) goto done;
        if (determ_ff_gen(hv + i * E, (uint32_t)i, 1) != 0) goto done;
    }
    /* aL = bits of v ; aR = aL - 1 */
    for (size_t i = 0; i < n; i++) {
        memset(aL + i * E, 0, E); aL[i * E + E - 1] = (uint8_t)((v >> i) & 1);
        if (determ_ff_scalar_sub(aR + i * E, aL + i * E, one) != 0) goto done;
    }
    /* V = g^v · h^gamma */
    {
        uint8_t vscal[E], sc2[2 * E], pt2[2 * E];
        ff_u64(vscal, v);
        memcpy(sc2, vscal, E); memcpy(sc2 + E, gamma, E);
        memcpy(pt2, g_val, E); memcpy(pt2 + E, h, E);
        if (determ_ff_msm(V_out, sc2, pt2, 2) != 0) goto done;
    }
    /* A = h^alpha · Π G^aL · Π H^aR ;  S = h^rho · Π G^sL · Π H^sR */
    uint8_t A[E], S[E];
    memcpy(scal, alpha, E);
    for (size_t i = 0; i < n; i++) { memcpy(scal + (1 + i) * E, aL + i * E, E); memcpy(scal + (1 + n + i) * E, aR + i * E, E); }
    memcpy(pts, h, E);
    for (size_t i = 0; i < n; i++) { memcpy(pts + (1 + i) * E, gv + i * E, E); memcpy(pts + (1 + n + i) * E, hv + i * E, E); }
    if (determ_ff_msm(A, scal, pts, 2 * n + 1) != 0) goto done;
    memcpy(scal, rho, E);
    for (size_t i = 0; i < n; i++) { memcpy(scal + (1 + i) * E, sL + i * E, E); memcpy(scal + (1 + n + i) * E, sR + i * E, E); }
    if (determ_ff_msm(S, scal, pts, 2 * n + 1) != 0) goto done;

    rtr_init(tr, V_out, n);
    rtr_absorb(tr, A); rtr_absorb(tr, S);
    uint8_t y[E], z[E], z2[E];
    if (rtr_challenge(tr, y) != 0 || rtr_challenge(tr, z) != 0) goto done;
    if (ff_powers(yn, y, n) != 0) goto done;
    for (size_t i = 0; i < n; i++) ff_u64(twon + i * E, (uint64_t)1 << i);
    if (determ_ff_scalar_mul(z2, z, z) != 0) goto done;
    /* l0 = aL - z ; r0 = yn∘(aR+z) + z^2·2^i ; r1 = yn∘sR */
    for (size_t i = 0; i < n; i++) {
        uint8_t t[E], t2[E];
        if (determ_ff_scalar_sub(l0 + i * E, aL + i * E, z) != 0) goto done;
        if (determ_ff_scalar_add(t, aR + i * E, z) != 0) goto done;
        if (determ_ff_scalar_mul(t, yn + i * E, t) != 0) goto done;
        if (determ_ff_scalar_mul(t2, z2, twon + i * E) != 0) goto done;
        if (determ_ff_scalar_add(r0 + i * E, t, t2) != 0) goto done;
        if (determ_ff_scalar_mul(r1 + i * E, yn + i * E, sR + i * E) != 0) goto done;
    }
    /* t1 = <sL,r0> + <l0,r1> ; t2 = <sL,r1> ; T1 = g^t1·h^tau1 ; T2 = g^t2·h^tau2 */
    uint8_t t1[E], t2[E], ta[E], tb[E], T1[E], T2[E], sc2[2 * E], pt2[2 * E];
    if (ff_inner(ta, sL, r0, n) != 0 || ff_inner(tb, l0, r1, n) != 0) goto done;
    if (determ_ff_scalar_add(t1, ta, tb) != 0) goto done;
    if (ff_inner(t2, sL, r1, n) != 0) goto done;
    memcpy(pt2, g_val, E); memcpy(pt2 + E, h, E);
    memcpy(sc2, t1, E); memcpy(sc2 + E, tau1, E);
    if (determ_ff_msm(T1, sc2, pt2, 2) != 0) goto done;
    memcpy(sc2, t2, E); memcpy(sc2 + E, tau2, E);
    if (determ_ff_msm(T2, sc2, pt2, 2) != 0) goto done;

    rtr_absorb(tr, T1); rtr_absorb(tr, T2);
    uint8_t x[E], x2[E];
    if (rtr_challenge(tr, x) != 0) goto done;
    /* l = l0 + sL·x ; r = r0 + r1·x ; that = <l,r> */
    uint8_t that[E];
    for (size_t i = 0; i < n; i++) {
        uint8_t t[E];
        if (determ_ff_scalar_mul(t, sL + i * E, x) != 0) goto done;
        if (determ_ff_scalar_add(l + i * E, l0 + i * E, t) != 0) goto done;
        if (determ_ff_scalar_mul(t, r1 + i * E, x) != 0) goto done;
        if (determ_ff_scalar_add(r + i * E, r0 + i * E, t) != 0) goto done;
    }
    if (ff_inner(that, l, r, n) != 0) goto done;
    /* taux = tau2·x^2 + tau1·x + z^2·gamma ; mu = alpha + rho·x */
    uint8_t taux[E], mu[E];
    if (determ_ff_scalar_mul(x2, x, x) != 0) goto done;
    if (determ_ff_scalar_mul(ta, tau2, x2) != 0) goto done;
    if (determ_ff_scalar_mul(tb, tau1, x) != 0) goto done;
    if (determ_ff_scalar_add(taux, ta, tb) != 0) goto done;
    if (determ_ff_scalar_mul(ta, z2, gamma) != 0) goto done;
    if (determ_ff_scalar_add(taux, taux, ta) != 0) goto done;
    if (determ_ff_scalar_mul(ta, rho, x) != 0) goto done;
    if (determ_ff_scalar_add(mu, alpha, ta) != 0) goto done;
    /* h'_i = H_i^{y^-i} ; P_ipa = Π G^l · Π h'^r · u^that */
    {
        uint8_t yinv[E];
        if (determ_ff_scalar_inv(yinv, y) != 0) goto done;
        if (ff_powers(yinvn, yinv, n) != 0) goto done;
        for (size_t i = 0; i < n; i++)
            if (determ_ff_msm(hprime + i * E, yinvn + i * E, hv + i * E, 1) != 0) goto done;
    }
    uint8_t P_ipa[E];
    for (size_t i = 0; i < n; i++) { memcpy(scal + i * E, l + i * E, E); memcpy(scal + (n + i) * E, r + i * E, E); }
    memcpy(scal + 2 * n * E, that, E);
    for (size_t i = 0; i < n; i++) { memcpy(pts + i * E, gv + i * E, E); memcpy(pts + (n + i) * E, hprime + i * E, E); }
    memcpy(pts + 2 * n * E, u, E);
    if (determ_ff_msm(P_ipa, scal, pts, 2 * n + 1) != 0) goto done;
    if (determ_ff_ipa_prove_gens(proof + RP_HDR, l, r, gv, hprime, u, P_ipa, n) != 0) goto done;

    memcpy(proof + RP_A, A, E);   memcpy(proof + RP_S, S, E);
    memcpy(proof + RP_T1, T1, E); memcpy(proof + RP_T2, T2, E);
    memcpy(proof + RP_TAUX, taux, E); memcpy(proof + RP_MU, mu, E); memcpy(proof + RP_THAT, that, E);
    rc = 0;
done:
    free(gv); free(hv); free(hprime); free(aL); free(aR); free(l0); free(r0);
    free(r1); free(l); free(r); free(yn); free(twon); free(yinvn); free(scal); free(pts); free(tr);
    return rc;
}

int determ_ff_rangeproof_verify(const uint8_t V33[E], const uint8_t *proof, size_t n) {
    if (rp_rounds(n) < 0) return -1;
    int rc = -1;
    uint8_t *gv = calloc(n, E), *hv = calloc(n, E), *hprime = calloc(n, E);
    uint8_t *yn = calloc(n, E), *twon = calloc(n, E), *yinvn = calloc(n, E);
    uint8_t *scal = calloc(2 * n + 3, E), *pts = calloc(2 * n + 3, E);
    rp_tr *tr = malloc(sizeof(rp_tr));
    if (!gv||!hv||!hprime||!yn||!twon||!yinvn||!scal||!pts||!tr) goto done;

    uint8_t g_val[E], h[E], u[E], one[E], zero[E];
    g_val_elem(g_val); sc_one(one); sc_zero(zero);
    if (determ_ff_pedersen_generator_h(h) != 0) goto done;
    if (determ_ff_gen(u, U_INDEX, 0) != 0) goto done;
    for (size_t i = 0; i < n; i++) {
        if (determ_ff_gen(gv + i * E, (uint32_t)i, 0) != 0) goto done;
        if (determ_ff_gen(hv + i * E, (uint32_t)i, 1) != 0) goto done;
    }
    const uint8_t *A = proof + RP_A, *S = proof + RP_S, *T1 = proof + RP_T1, *T2 = proof + RP_T2;
    const uint8_t *taux = proof + RP_TAUX, *mu = proof + RP_MU, *that = proof + RP_THAT;
    const uint8_t *ipa = proof + RP_HDR;

    rtr_init(tr, V33, n);
    rtr_absorb(tr, A); rtr_absorb(tr, S);
    uint8_t y[E], z[E], x[E], z2[E], x2[E];
    if (rtr_challenge(tr, y) != 0 || rtr_challenge(tr, z) != 0) goto done;
    rtr_absorb(tr, T1); rtr_absorb(tr, T2);
    if (rtr_challenge(tr, x) != 0) goto done;
    if (ff_powers(yn, y, n) != 0) goto done;
    for (size_t i = 0; i < n; i++) ff_u64(twon + i * E, (uint64_t)1 << i);
    if (determ_ff_scalar_mul(z2, z, z) != 0) goto done;
    if (determ_ff_scalar_mul(x2, x, x) != 0) goto done;

    /* Check 1: g^that·h^taux == V^{z^2}·g^delta·T1^x·T2^{x^2} */
    uint8_t sum_y[E], sum_2[E], delta[E], ta[E], tb[E], lhs[E], rhs[E], sc2[2 * E], pt2[2 * E], sc4[4 * E], pt4[4 * E];
    sc_zero(sum_y); sc_zero(sum_2);
    for (size_t i = 0; i < n; i++) { if (determ_ff_scalar_add(sum_y, sum_y, yn + i * E) != 0) goto done;
                                     if (determ_ff_scalar_add(sum_2, sum_2, twon + i * E) != 0) goto done; }
    if (determ_ff_scalar_sub(ta, z, z2) != 0) goto done;
    if (determ_ff_scalar_mul(ta, ta, sum_y) != 0) goto done;      /* (z-z^2)·<1,y^n> */
    if (determ_ff_scalar_mul(tb, z2, z) != 0) goto done;
    if (determ_ff_scalar_mul(tb, tb, sum_2) != 0) goto done;      /* z^3·<1,2^n> */
    if (determ_ff_scalar_sub(delta, ta, tb) != 0) goto done;
    memcpy(sc2, that, E); memcpy(sc2 + E, taux, E);
    memcpy(pt2, g_val, E); memcpy(pt2 + E, h, E);
    if (determ_ff_msm(lhs, sc2, pt2, 2) != 0) goto done;
    memcpy(sc4, z2, E); memcpy(sc4 + E, delta, E); memcpy(sc4 + 2 * E, x, E); memcpy(sc4 + 3 * E, x2, E);
    memcpy(pt4, V33, E); memcpy(pt4 + E, g_val, E); memcpy(pt4 + 2 * E, T1, E); memcpy(pt4 + 3 * E, T2, E);
    if (determ_ff_msm(rhs, sc4, pt4, 4) != 0) goto done;
    if (memcmp(lhs, rhs, E) != 0) goto done;                      /* rc stays -1 */

    /* Check 2: P = A·S^x·ΠG^{-z}·Πh'^{z·y^i+z^2·2^i}·h^{-mu} ; P_ipa = P·u^that ; IPA */
    {
        uint8_t yinv[E];
        if (determ_ff_scalar_inv(yinv, y) != 0) goto done;
        if (ff_powers(yinvn, yinv, n) != 0) goto done;
        for (size_t i = 0; i < n; i++)
            if (determ_ff_msm(hprime + i * E, yinvn + i * E, hv + i * E, 1) != 0) goto done;
    }
    uint8_t negz[E], negmu[E];
    if (determ_ff_scalar_sub(negz, zero, z) != 0) goto done;
    if (determ_ff_scalar_sub(negmu, zero, mu) != 0) goto done;
    memcpy(scal, one, E); memcpy(scal + E, x, E);
    for (size_t i = 0; i < n; i++) memcpy(scal + (2 + i) * E, negz, E);
    for (size_t i = 0; i < n; i++) {
        uint8_t t[E], t2[E];
        if (determ_ff_scalar_mul(t, z, yn + i * E) != 0) goto done;
        if (determ_ff_scalar_mul(t2, z2, twon + i * E) != 0) goto done;
        if (determ_ff_scalar_add(scal + (2 + n + i) * E, t, t2) != 0) goto done;
    }
    memcpy(scal + (2 + 2 * n) * E, negmu, E);
    memcpy(pts, A, E); memcpy(pts + E, S, E);
    for (size_t i = 0; i < n; i++) { memcpy(pts + (2 + i) * E, gv + i * E, E); memcpy(pts + (2 + n + i) * E, hprime + i * E, E); }
    memcpy(pts + (2 + 2 * n) * E, h, E);
    uint8_t Pp[E], P_ipa[E];
    if (determ_ff_msm(Pp, scal, pts, 2 * n + 3) != 0) goto done;
    memcpy(sc2, one, E); memcpy(sc2 + E, that, E);
    memcpy(pt2, Pp, E); memcpy(pt2 + E, u, E);
    if (determ_ff_msm(P_ipa, sc2, pt2, 2) != 0) goto done;
    rc = determ_ff_ipa_verify_gens(P_ipa, ipa, gv, hprime, u, n);
done:
    free(gv); free(hv); free(hprime); free(yn); free(twon); free(yinvn); free(scal); free(pts); free(tr);
    return rc;
}

/* ── §3.20 increment 6: the AGGREGATED range proof (m values, one proof) ────────
 * Ported from tools/verify_ff_rangeproof.py (agg_prove/agg_verify), python-prove-first.
 * Reuses every file-static helper above; the aggregated vectors are m*n wide
 * (<= DETERM_FF_IPA_MAX_N). Value j's 2^n slot is scaled by z^(2+j); m=1 reduces to the
 * single-value proof. The transcript (label DETERM-FF-BP-AGGRANGE-v1) is heap-allocated
 * because the m absorbed 384-byte V_j would overflow a stack buffer. */
#define MN_MAX DETERM_FF_IPA_MAX_N            /* 256: max aggregated bit-width m*n */

static const char ATR_LABEL[] = "DETERM-FF-BP-AGGRANGE-v1";
static const char ATR_CDST[]  = "DETERM-FF-BP-AGGRANGE-v1-challenge";

/* -1 if (m,n) invalid, else log2(m*n). n in [1,64], m>=1, m*n a power of two in [1,MN_MAX]. */
static int agg_rounds(size_t m, size_t n) {
    if (m < 1 || n < 1 || n > RP_MAXN) return -1;
    size_t nm = m * n;
    if (nm < 1 || nm > MN_MAX) return -1;
    int r = 0; size_t t = nm;
    while (t > 1) { if (t & 1) return -1; t >>= 1; r++; }
    return r;
}

size_t determ_ff_agg_rangeproof_proof_len(size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return 0;
    return RP_HDR + determ_ff_ipa_proof_len(m * n);
}

static void atr_init(uint8_t *buf, size_t *len, const uint8_t *Vs, size_t m, size_t n) {
    size_t L = sizeof(ATR_LABEL) - 1;
    memcpy(buf, ATR_LABEL, L);
    uint32_t mm = (uint32_t)m, nn = (uint32_t)n;
    buf[L+0]=(uint8_t)(mm>>24); buf[L+1]=(uint8_t)(mm>>16); buf[L+2]=(uint8_t)(mm>>8); buf[L+3]=(uint8_t)mm;
    buf[L+4]=(uint8_t)(nn>>24); buf[L+5]=(uint8_t)(nn>>16); buf[L+6]=(uint8_t)(nn>>8); buf[L+7]=(uint8_t)nn;
    L += 8;
    for (size_t j = 0; j < m; j++) { memcpy(buf + L, Vs + j * E, E); L += E; }
    *len = L;
}
static void atr_absorb(uint8_t *buf, size_t *len, const uint8_t pt[E]) { memcpy(buf + *len, pt, E); *len += E; }
static int atr_challenge(uint8_t *buf, size_t *len, uint8_t out[E]) {
    if (determ_ff_hash_to_scalar(out, buf, *len, (const uint8_t *)ATR_CDST, sizeof(ATR_CDST) - 1) != 0) return -1;
    memcpy(buf + *len, out, E); *len += E;
    return 0;
}

int determ_ff_agg_rangeproof_prove(uint8_t *V_out, uint8_t *proof,
                                   const uint64_t *v, const uint8_t *gamma,
                                   const uint8_t alpha[E], const uint8_t rho[E],
                                   const uint8_t tau1[E], const uint8_t tau2[E],
                                   const uint8_t *sL, const uint8_t *sR, size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return -1;
    size_t nm = m * n;
    int rc = -1;
    uint8_t *gv = calloc(nm, E), *hv = calloc(nm, E), *hprime = calloc(nm, E);
    uint8_t *aL = calloc(nm, E), *aR = calloc(nm, E), *l0 = calloc(nm, E);
    uint8_t *r0 = calloc(nm, E), *r1 = calloc(nm, E), *l = calloc(nm, E), *r = calloc(nm, E);
    uint8_t *yn = calloc(nm, E), *zslot = calloc(nm, E), *yinvn = calloc(nm, E);
    uint8_t *twon = calloc(n, E), *scal = calloc(2 * nm + 1, E), *pts = calloc(2 * nm + 1, E);
    uint8_t *trbuf = calloc(m + 10, E);
    if (!gv||!hv||!hprime||!aL||!aR||!l0||!r0||!r1||!l||!r||!yn||!zslot||!yinvn||!twon||!scal||!pts||!trbuf) goto done;

    uint8_t g_val[E], h[E], u[E], one[E], sc2[2 * E], pt2[2 * E];
    g_val_elem(g_val); sc_one(one);
    if (determ_ff_pedersen_generator_h(h) != 0) goto done;
    if (determ_ff_gen(u, U_INDEX, 0) != 0) goto done;
    for (size_t i = 0; i < nm; i++) {
        if (determ_ff_gen(gv + i * E, (uint32_t)i, 0) != 0) goto done;
        if (determ_ff_gen(hv + i * E, (uint32_t)i, 1) != 0) goto done;
    }
    memcpy(pt2, g_val, E); memcpy(pt2 + E, h, E);
    for (size_t j = 0; j < m; j++) {                    /* V_j = g^v_j · h^gamma_j */
        uint8_t vscal[E];
        ff_u64(vscal, v[j]);
        memcpy(sc2, vscal, E); memcpy(sc2 + E, gamma + j * E, E);
        if (determ_ff_msm(V_out + j * E, sc2, pt2, 2) != 0) goto done;
    }
    for (size_t j = 0; j < m; j++) for (size_t k = 0; k < n; k++) {
        size_t i = j * n + k;
        memset(aL + i * E, 0, E); aL[i * E + E - 1] = (uint8_t)((v[j] >> k) & 1);
        if (determ_ff_scalar_sub(aR + i * E, aL + i * E, one) != 0) goto done;
    }
    /* A = h^alpha · ΠG^aL · ΠH^aR ; S = h^rho · ΠG^sL · ΠH^sR */
    uint8_t A[E], S[E];
    memcpy(scal, alpha, E);
    for (size_t i = 0; i < nm; i++) { memcpy(scal + (1 + i) * E, aL + i * E, E); memcpy(scal + (1 + nm + i) * E, aR + i * E, E); }
    memcpy(pts, h, E);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + (1 + i) * E, gv + i * E, E); memcpy(pts + (1 + nm + i) * E, hv + i * E, E); }
    if (determ_ff_msm(A, scal, pts, 2 * nm + 1) != 0) goto done;
    memcpy(scal, rho, E);
    for (size_t i = 0; i < nm; i++) { memcpy(scal + (1 + i) * E, sL + i * E, E); memcpy(scal + (1 + nm + i) * E, sR + i * E, E); }
    if (determ_ff_msm(S, scal, pts, 2 * nm + 1) != 0) goto done;

    size_t tl;
    atr_init(trbuf, &tl, V_out, m, n);
    atr_absorb(trbuf, &tl, A); atr_absorb(trbuf, &tl, S);
    uint8_t y[E], z[E], z2[E];
    if (atr_challenge(trbuf, &tl, y) != 0 || atr_challenge(trbuf, &tl, z) != 0) goto done;
    if (ff_powers(yn, y, nm) != 0) goto done;
    for (size_t k = 0; k < n; k++) ff_u64(twon + k * E, (uint64_t)1 << k);
    if (determ_ff_scalar_mul(z2, z, z) != 0) goto done;
    /* zslot[j*n+k] = z^(2+j)·2^k */
    { uint8_t zpow[E]; memcpy(zpow, z2, E);
      for (size_t j = 0; j < m; j++) {
          for (size_t k = 0; k < n; k++)
              if (determ_ff_scalar_mul(zslot + (j * n + k) * E, zpow, twon + k * E) != 0) goto done;
          if (j + 1 < m && determ_ff_scalar_mul(zpow, zpow, z) != 0) goto done;
      } }
    for (size_t i = 0; i < nm; i++) {
        uint8_t t[E];
        if (determ_ff_scalar_sub(l0 + i * E, aL + i * E, z) != 0) goto done;
        if (determ_ff_scalar_add(t, aR + i * E, z) != 0) goto done;
        if (determ_ff_scalar_mul(t, yn + i * E, t) != 0) goto done;
        if (determ_ff_scalar_add(r0 + i * E, t, zslot + i * E) != 0) goto done;
        if (determ_ff_scalar_mul(r1 + i * E, yn + i * E, sR + i * E) != 0) goto done;
    }
    uint8_t t1[E], t2[E], ta[E], tb[E], T1[E], T2[E];
    if (ff_inner(ta, sL, r0, nm) != 0 || ff_inner(tb, l0, r1, nm) != 0) goto done;
    if (determ_ff_scalar_add(t1, ta, tb) != 0) goto done;
    if (ff_inner(t2, sL, r1, nm) != 0) goto done;
    memcpy(sc2, t1, E); memcpy(sc2 + E, tau1, E);
    if (determ_ff_msm(T1, sc2, pt2, 2) != 0) goto done;
    memcpy(sc2, t2, E); memcpy(sc2 + E, tau2, E);
    if (determ_ff_msm(T2, sc2, pt2, 2) != 0) goto done;
    atr_absorb(trbuf, &tl, T1); atr_absorb(trbuf, &tl, T2);
    uint8_t x[E], x2[E], that[E];
    if (atr_challenge(trbuf, &tl, x) != 0) goto done;
    for (size_t i = 0; i < nm; i++) {
        uint8_t t[E];
        if (determ_ff_scalar_mul(t, sL + i * E, x) != 0) goto done;
        if (determ_ff_scalar_add(l + i * E, l0 + i * E, t) != 0) goto done;
        if (determ_ff_scalar_mul(t, r1 + i * E, x) != 0) goto done;
        if (determ_ff_scalar_add(r + i * E, r0 + i * E, t) != 0) goto done;
    }
    if (ff_inner(that, l, r, nm) != 0) goto done;
    /* taux = tau2·x² + tau1·x + Σ_j z^(2+j)·gamma_j ; mu = alpha + rho·x */
    uint8_t taux[E], mu[E];
    if (determ_ff_scalar_mul(x2, x, x) != 0) goto done;
    if (determ_ff_scalar_mul(ta, tau2, x2) != 0) goto done;
    if (determ_ff_scalar_mul(tb, tau1, x) != 0) goto done;
    if (determ_ff_scalar_add(taux, ta, tb) != 0) goto done;
    { uint8_t zpow[E]; memcpy(zpow, z2, E);
      for (size_t j = 0; j < m; j++) {
          if (determ_ff_scalar_mul(ta, zpow, gamma + j * E) != 0) goto done;
          if (determ_ff_scalar_add(taux, taux, ta) != 0) goto done;
          if (j + 1 < m && determ_ff_scalar_mul(zpow, zpow, z) != 0) goto done;
      } }
    if (determ_ff_scalar_mul(ta, rho, x) != 0) goto done;
    if (determ_ff_scalar_add(mu, alpha, ta) != 0) goto done;
    { uint8_t yinv[E];
      if (determ_ff_scalar_inv(yinv, y) != 0) goto done;
      if (ff_powers(yinvn, yinv, nm) != 0) goto done;
      for (size_t i = 0; i < nm; i++)
          if (determ_ff_msm(hprime + i * E, yinvn + i * E, hv + i * E, 1) != 0) goto done; }
    uint8_t P_ipa[E];
    for (size_t i = 0; i < nm; i++) { memcpy(scal + i * E, l + i * E, E); memcpy(scal + (nm + i) * E, r + i * E, E); }
    memcpy(scal + 2 * nm * E, that, E);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + i * E, gv + i * E, E); memcpy(pts + (nm + i) * E, hprime + i * E, E); }
    memcpy(pts + 2 * nm * E, u, E);
    if (determ_ff_msm(P_ipa, scal, pts, 2 * nm + 1) != 0) goto done;
    if (determ_ff_ipa_prove_gens(proof + RP_HDR, l, r, gv, hprime, u, P_ipa, nm) != 0) goto done;

    memcpy(proof + RP_A, A, E);   memcpy(proof + RP_S, S, E);
    memcpy(proof + RP_T1, T1, E); memcpy(proof + RP_T2, T2, E);
    memcpy(proof + RP_TAUX, taux, E); memcpy(proof + RP_MU, mu, E); memcpy(proof + RP_THAT, that, E);
    rc = 0;
done:
    free(gv); free(hv); free(hprime); free(aL); free(aR); free(l0); free(r0); free(r1);
    free(l); free(r); free(yn); free(zslot); free(yinvn); free(twon); free(scal); free(pts); free(trbuf);
    return rc;
}

int determ_ff_agg_rangeproof_verify(const uint8_t *V, const uint8_t *proof, size_t m, size_t n) {
    if (agg_rounds(m, n) < 0) return -1;
    size_t nm = m * n;
    int rc = -1;
    uint8_t *gv = calloc(nm, E), *hv = calloc(nm, E), *hprime = calloc(nm, E);
    uint8_t *yn = calloc(nm, E), *zslot = calloc(nm, E), *yinvn = calloc(nm, E);
    uint8_t *twon = calloc(n, E), *vscal = calloc(m, E);
    uint8_t *scal = calloc(2 * nm + 3, E), *pts = calloc(2 * nm + 3, E);
    uint8_t *trbuf = calloc(m + 10, E);
    if (!gv||!hv||!hprime||!yn||!zslot||!yinvn||!twon||!vscal||!scal||!pts||!trbuf) goto done;

    uint8_t g_val[E], h[E], u[E], one[E], zero[E];
    g_val_elem(g_val); sc_one(one); sc_zero(zero);
    if (determ_ff_pedersen_generator_h(h) != 0) goto done;
    if (determ_ff_gen(u, U_INDEX, 0) != 0) goto done;
    for (size_t i = 0; i < nm; i++) {
        if (determ_ff_gen(gv + i * E, (uint32_t)i, 0) != 0) goto done;
        if (determ_ff_gen(hv + i * E, (uint32_t)i, 1) != 0) goto done;
    }
    const uint8_t *A = proof + RP_A, *S = proof + RP_S, *T1 = proof + RP_T1, *T2 = proof + RP_T2;
    const uint8_t *taux = proof + RP_TAUX, *mu = proof + RP_MU, *that = proof + RP_THAT;
    const uint8_t *ipa = proof + RP_HDR;

    size_t tl;
    atr_init(trbuf, &tl, V, m, n);
    atr_absorb(trbuf, &tl, A); atr_absorb(trbuf, &tl, S);
    uint8_t y[E], z[E], x[E], z2[E], x2[E];
    if (atr_challenge(trbuf, &tl, y) != 0 || atr_challenge(trbuf, &tl, z) != 0) goto done;
    atr_absorb(trbuf, &tl, T1); atr_absorb(trbuf, &tl, T2);
    if (atr_challenge(trbuf, &tl, x) != 0) goto done;
    if (ff_powers(yn, y, nm) != 0) goto done;
    for (size_t k = 0; k < n; k++) ff_u64(twon + k * E, (uint64_t)1 << k);
    if (determ_ff_scalar_mul(z2, z, z) != 0) goto done;
    if (determ_ff_scalar_mul(x2, x, x) != 0) goto done;
    /* vscal[j] = z^(2+j) ; zslot[j*n+k] = z^(2+j)·2^k ; zsum = Σ_j z^(3+j) */
    uint8_t zsum[E];
    sc_zero(zsum);
    { uint8_t zpow[E], t3[E]; memcpy(zpow, z2, E);
      for (size_t j = 0; j < m; j++) {
          memcpy(vscal + j * E, zpow, E);
          if (determ_ff_scalar_mul(t3, zpow, z) != 0) goto done;
          if (determ_ff_scalar_add(zsum, zsum, t3) != 0) goto done;
          for (size_t k = 0; k < n; k++)
              if (determ_ff_scalar_mul(zslot + (j * n + k) * E, zpow, twon + k * E) != 0) goto done;
          if (j + 1 < m && determ_ff_scalar_mul(zpow, zpow, z) != 0) goto done;
      } }
    /* delta = (z - z^2)·<1^{nm},y^{nm}> - zsum·<1,2^n> */
    uint8_t sum_y[E], sum_2[E], delta[E], ta[E], tb[E];
    sc_zero(sum_y); sc_zero(sum_2);
    for (size_t i = 0; i < nm; i++) if (determ_ff_scalar_add(sum_y, sum_y, yn + i * E) != 0) goto done;
    for (size_t k = 0; k < n; k++)  if (determ_ff_scalar_add(sum_2, sum_2, twon + k * E) != 0) goto done;
    if (determ_ff_scalar_sub(ta, z, z2) != 0) goto done;
    if (determ_ff_scalar_mul(ta, ta, sum_y) != 0) goto done;
    if (determ_ff_scalar_mul(tb, zsum, sum_2) != 0) goto done;
    if (determ_ff_scalar_sub(delta, ta, tb) != 0) goto done;
    /* Check 1: g^that·h^taux == Π V_j^{z^(2+j)}·g^delta·T1^x·T2^{x^2} */
    { uint8_t lhs[E], rhs[E], sc2[2 * E], pt2[2 * E];
      memcpy(sc2, that, E); memcpy(sc2 + E, taux, E);
      memcpy(pt2, g_val, E); memcpy(pt2 + E, h, E);
      if (determ_ff_msm(lhs, sc2, pt2, 2) != 0) goto done;
      for (size_t j = 0; j < m; j++) { memcpy(scal + j * E, vscal + j * E, E); memcpy(pts + j * E, V + j * E, E); }
      memcpy(scal + m * E, delta, E); memcpy(scal + (m + 1) * E, x, E); memcpy(scal + (m + 2) * E, x2, E);
      memcpy(pts + m * E, g_val, E); memcpy(pts + (m + 1) * E, T1, E); memcpy(pts + (m + 2) * E, T2, E);
      if (determ_ff_msm(rhs, scal, pts, m + 3) != 0) goto done;
      if (memcmp(lhs, rhs, E) != 0) goto done; }
    /* Check 2: P = A·S^x·ΠG^{-z}·Πh'^{z·y^i + zslot_i}·h^{-mu} ; P_ipa = P·u^that ; IPA */
    { uint8_t yinv[E];
      if (determ_ff_scalar_inv(yinv, y) != 0) goto done;
      if (ff_powers(yinvn, yinv, nm) != 0) goto done;
      for (size_t i = 0; i < nm; i++)
          if (determ_ff_msm(hprime + i * E, yinvn + i * E, hv + i * E, 1) != 0) goto done; }
    uint8_t negz[E], negmu[E];
    if (determ_ff_scalar_sub(negz, zero, z) != 0) goto done;
    if (determ_ff_scalar_sub(negmu, zero, mu) != 0) goto done;
    memcpy(scal, one, E); memcpy(scal + E, x, E);
    for (size_t i = 0; i < nm; i++) memcpy(scal + (2 + i) * E, negz, E);
    for (size_t i = 0; i < nm; i++) {
        uint8_t t[E];
        if (determ_ff_scalar_mul(t, z, yn + i * E) != 0) goto done;
        if (determ_ff_scalar_add(scal + (2 + nm + i) * E, t, zslot + i * E) != 0) goto done;
    }
    memcpy(scal + (2 + 2 * nm) * E, negmu, E);
    memcpy(pts, A, E); memcpy(pts + E, S, E);
    for (size_t i = 0; i < nm; i++) { memcpy(pts + (2 + i) * E, gv + i * E, E); memcpy(pts + (2 + nm + i) * E, hprime + i * E, E); }
    memcpy(pts + (2 + 2 * nm) * E, h, E);
    uint8_t Pp[E], P_ipa[E], sc2[2 * E], pt2[2 * E];
    if (determ_ff_msm(Pp, scal, pts, 2 * nm + 3) != 0) goto done;
    memcpy(sc2, one, E); memcpy(sc2 + E, that, E);
    memcpy(pt2, Pp, E); memcpy(pt2 + E, u, E);
    if (determ_ff_msm(P_ipa, sc2, pt2, 2) != 0) goto done;
    rc = determ_ff_ipa_verify_gens(P_ipa, ipa, gv, hprime, u, nm);
done:
    free(gv); free(hv); free(hprime); free(yn); free(zslot); free(yinvn);
    free(twon); free(vscal); free(scal); free(pts); free(trbuf);
    return rc;
}
