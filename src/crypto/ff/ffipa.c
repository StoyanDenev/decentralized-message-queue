/* Determ C99 Bulletproofs inner-product argument over Z_p* — CRYPTO-C99-SPEC.md
 * §3.20 increment 4. See ffipa.h for the statement/contract. Ported from the
 * independent Python reference tools/verify_ff_ipa.py after that reference's
 * commit/prove/verify round-trip + soundness self-tests passed (python-prove-first).
 * Pure composition over the §3.20 group ops (determ_ff_msm / determ_ff_gen) and scalar
 * field (determ_ff_scalar_* / determ_ff_hash_to_scalar). Working vectors are heap-
 * allocated (n up to 256 × 384-byte elements would overflow the stack). NOT constant-
 * time (owner-gated). */
#include "determ/crypto/ff/ffipa.h"
#include "determ/crypto/ff/ffgroup.h"

#include <string.h>
#include <stdlib.h>

#define E DETERM_FF_ELEM_BYTES              /* 384 */

static const char TR_LABEL[] = "DETERM-FF-BP-IPA-v1";
static const char TR_CDST[]  = "DETERM-FF-BP-IPA-v1-challenge";
#define U_INDEX 0xFFFFFFFFu

/* -1 if n is not a supported power of two, else the number of fold rounds. */
static int ff_rounds(size_t n) {
    if (n < 1 || n > DETERM_FF_IPA_MAX_N) return -1;
    int r = 0; size_t m = n;
    while (m > 1) { if (m & 1) return -1; m >>= 1; r++; }
    return r;
}

size_t determ_ff_ipa_proof_len(size_t n) {
    int r = ff_rounds(n);
    return r < 0 ? 0 : (size_t)(2 * r + 2) * E;
}

/* out = <a, b> mod q over n 384-byte scalars. -1 if a scalar is out of range. */
static int ff_inner(uint8_t out[E], const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t acc[E], prod[E];
    memset(acc, 0, E);                       /* scalar 0 */
    for (size_t i = 0; i < n; i++) {
        if (determ_ff_scalar_mul(prod, a + i * E, b + i * E) != 0) return -1;
        if (determ_ff_scalar_add(acc, acc, prod) != 0) return -1;
    }
    memcpy(out, acc, E);
    return 0;
}

/* out = msm([s1,s2], [p1,p2]) — the 2-point fold used for the generator vectors. */
static int ff_fold2(uint8_t out[E], const uint8_t s1[E], const uint8_t p1[E],
                    const uint8_t s2[E], const uint8_t p2[E]) {
    uint8_t s[2 * E], p[2 * E];
    memcpy(s, s1, E); memcpy(s + E, s2, E);
    memcpy(p, p1, E); memcpy(p + E, p2, E);
    return determ_ff_msm(out, s, p, 2);
}

/* ── the deterministic Fiat-Shamir transcript ─────────────────────────────── */
/* Max length: LABEL(19) + P(384) + u(384) + n(4) + rounds*(L+R+challenge = 3*384).
 * For n=256 (8 rounds) that is 791 + 9216 = 10007 < 16384. */
typedef struct { uint8_t buf[16384]; size_t len; } ff_tr;

static void tr_init(ff_tr *t, const uint8_t P[E], const uint8_t u[E], size_t n) {
    t->len = sizeof(TR_LABEL) - 1;
    memcpy(t->buf, TR_LABEL, t->len);
    memcpy(t->buf + t->len, P, E); t->len += E;
    memcpy(t->buf + t->len, u, E); t->len += E;
    uint32_t nn = (uint32_t)n;
    t->buf[t->len++] = (uint8_t)(nn >> 24); t->buf[t->len++] = (uint8_t)(nn >> 16);
    t->buf[t->len++] = (uint8_t)(nn >> 8);  t->buf[t->len++] = (uint8_t)nn;
}
static void tr_absorb(ff_tr *t, const uint8_t pt[E]) {
    memcpy(t->buf + t->len, pt, E); t->len += E;
}
static int tr_challenge(ff_tr *t, uint8_t out[E]) {
    if (determ_ff_hash_to_scalar(out, t->buf, t->len,
                                 (const uint8_t *)TR_CDST, sizeof(TR_CDST) - 1) != 0) return -1;
    memcpy(t->buf + t->len, out, E); t->len += E;   /* absorb the challenge */
    return 0;
}

int determ_ff_ipa_commit(uint8_t out[E], const uint8_t *a, const uint8_t *b, size_t n) {
    if (ff_rounds(n) < 0) return -1;
    int rc = -1;
    uint8_t *scal = malloc((2 * n + 1) * E), *pts = malloc((2 * n + 1) * E);
    uint8_t ab[E], u[E];
    if (!scal || !pts) goto done;
    for (size_t i = 0; i < n; i++) {
        memcpy(scal + i * E, a + i * E, E);
        if (determ_ff_gen(pts + i * E, (uint32_t)i, 0) != 0) goto done;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy(scal + (n + i) * E, b + i * E, E);
        if (determ_ff_gen(pts + (n + i) * E, (uint32_t)i, 1) != 0) goto done;
    }
    if (ff_inner(ab, a, b, n) != 0) goto done;
    memcpy(scal + 2 * n * E, ab, E);
    if (determ_ff_gen(u, U_INDEX, 0) != 0) goto done;
    memcpy(pts + 2 * n * E, u, E);
    rc = determ_ff_msm(out, scal, pts, 2 * n + 1);
done:
    free(scal); free(pts);
    return rc;
}

int determ_ff_ipa_prove_gens(uint8_t *proof, const uint8_t *a_in, const uint8_t *b_in,
                             const uint8_t *g_in, const uint8_t *h_in, const uint8_t u[E],
                             const uint8_t P[E], size_t n) {
    int rounds = ff_rounds(n);
    if (rounds < 0) return -1;
    int rc = -1;
    uint8_t *a = malloc(n * E), *b = malloc(n * E), *g = malloc(n * E), *h = malloc(n * E);
    uint8_t *scal = malloc((n + 1) * E), *pts = malloc((n + 1) * E);
    ff_tr *tr = malloc(sizeof(ff_tr));
    if (!a || !b || !g || !h || !scal || !pts || !tr) goto done;
    memcpy(a, a_in, n * E); memcpy(b, b_in, n * E);
    memcpy(g, g_in, n * E); memcpy(h, h_in, n * E);
    tr_init(tr, P, u, n);
    uint8_t *Lw = proof, *Rw = proof + (size_t)rounds * E;
    size_t cur = n;
    for (int rd = 0; rd < rounds; rd++) {
        size_t m = cur / 2;
        uint8_t L[E], R[E], c[E], x[E], xinv[E];

        /* L = <aL,gR> + <bR,hL> + <aL,bR>*u */
        for (size_t i = 0; i < m; i++) memcpy(scal + i * E, a + i * E, E);            /* aL */
        for (size_t i = 0; i < m; i++) memcpy(scal + (m + i) * E, b + (m + i) * E, E); /* bR */
        if (ff_inner(c, a, b + m * E, m) != 0) goto done;
        memcpy(scal + 2 * m * E, c, E);
        for (size_t i = 0; i < m; i++) memcpy(pts + i * E, g + (m + i) * E, E);        /* gR */
        for (size_t i = 0; i < m; i++) memcpy(pts + (m + i) * E, h + i * E, E);        /* hL */
        memcpy(pts + 2 * m * E, u, E);
        if (determ_ff_msm(L, scal, pts, 2 * m + 1) != 0) goto done;

        /* R = <aR,gL> + <bL,hR> + <aR,bL>*u */
        for (size_t i = 0; i < m; i++) memcpy(scal + i * E, a + (m + i) * E, E);       /* aR */
        for (size_t i = 0; i < m; i++) memcpy(scal + (m + i) * E, b + i * E, E);       /* bL */
        if (ff_inner(c, a + m * E, b, m) != 0) goto done;
        memcpy(scal + 2 * m * E, c, E);
        for (size_t i = 0; i < m; i++) memcpy(pts + i * E, g + i * E, E);              /* gL */
        for (size_t i = 0; i < m; i++) memcpy(pts + (m + i) * E, h + (m + i) * E, E);  /* hR */
        memcpy(pts + 2 * m * E, u, E);
        if (determ_ff_msm(R, scal, pts, 2 * m + 1) != 0) goto done;

        tr_absorb(tr, L); tr_absorb(tr, R);
        if (tr_challenge(tr, x) != 0) goto done;
        if (determ_ff_scalar_inv(xinv, x) != 0) goto done;

        /* fold a,b (first m slots): a'=aL*x+aR*xinv, b'=bL*xinv+bR*x */
        for (size_t i = 0; i < m; i++) {
            uint8_t t1[E], t2[E];
            if (determ_ff_scalar_mul(t1, a + i * E, x) != 0) goto done;
            if (determ_ff_scalar_mul(t2, a + (m + i) * E, xinv) != 0) goto done;
            if (determ_ff_scalar_add(a + i * E, t1, t2) != 0) goto done;
            if (determ_ff_scalar_mul(t1, b + i * E, xinv) != 0) goto done;
            if (determ_ff_scalar_mul(t2, b + (m + i) * E, x) != 0) goto done;
            if (determ_ff_scalar_add(b + i * E, t1, t2) != 0) goto done;
        }
        /* fold g,h: g'=gL^xinv*gR^x, h'=hL^x*hR^xinv */
        for (size_t i = 0; i < m; i++) {
            uint8_t o[E];
            if (ff_fold2(o, xinv, g + i * E, x, g + (m + i) * E) != 0) goto done;
            memcpy(g + i * E, o, E);
            if (ff_fold2(o, x, h + i * E, xinv, h + (m + i) * E) != 0) goto done;
            memcpy(h + i * E, o, E);
        }
        memcpy(Lw + (size_t)rd * E, L, E);
        memcpy(Rw + (size_t)rd * E, R, E);
        cur = m;
    }
    memcpy(proof + 2 * (size_t)rounds * E, a, E);
    memcpy(proof + 2 * (size_t)rounds * E + E, b, E);
    rc = 0;
done:
    free(a); free(b); free(g); free(h); free(scal); free(pts); free(tr);
    return rc;
}

int determ_ff_ipa_verify_gens(const uint8_t P[E], const uint8_t *proof,
                              const uint8_t *g_in, const uint8_t *h_in, const uint8_t u[E],
                              size_t n) {
    int rounds = ff_rounds(n);
    if (rounds < 0) return -1;
    int rc = -1;
    uint8_t *g = malloc(n * E), *h = malloc(n * E);
    ff_tr *tr = malloc(sizeof(ff_tr));
    if (!g || !h || !tr) goto done;
    memcpy(g, g_in, n * E); memcpy(h, h_in, n * E);

    const uint8_t *Ls = proof, *Rs = proof + (size_t)rounds * E;
    const uint8_t *af = proof + 2 * (size_t)rounds * E, *bf = af + E;
    tr_init(tr, P, u, n);
    uint8_t Pp[E]; memcpy(Pp, P, E);
    size_t cur = n;
    for (int rd = 0; rd < rounds; rd++) {
        const uint8_t *L = Ls + (size_t)rd * E, *R = Rs + (size_t)rd * E;
        uint8_t x[E], xinv[E], x2[E], x2inv[E], one[E];
        tr_absorb(tr, L); tr_absorb(tr, R);
        if (tr_challenge(tr, x) != 0) goto done;
        if (determ_ff_scalar_inv(xinv, x) != 0) goto done;
        if (determ_ff_scalar_mul(x2, x, x) != 0) goto done;
        if (determ_ff_scalar_mul(x2inv, xinv, xinv) != 0) goto done;
        size_t m = cur / 2;
        for (size_t i = 0; i < m; i++) {
            uint8_t o[E];
            if (ff_fold2(o, xinv, g + i * E, x, g + (m + i) * E) != 0) goto done;
            memcpy(g + i * E, o, E);
            if (ff_fold2(o, x, h + i * E, xinv, h + (m + i) * E) != 0) goto done;
            memcpy(h + i * E, o, E);
        }
        /* Pp = L^{x^2} * Pp * R^{x^-2}  (a 3-term multi-exponentiation) */
        memset(one, 0, E); one[E - 1] = 1;
        uint8_t s3[3 * E], p3[3 * E];
        memcpy(s3, x2, E); memcpy(s3 + E, one, E); memcpy(s3 + 2 * E, x2inv, E);
        memcpy(p3, L, E);  memcpy(p3 + E, Pp, E);  memcpy(p3 + 2 * E, R, E);
        if (determ_ff_msm(Pp, s3, p3, 3) != 0) goto done;    /* rejects a malformed L/R (0/>=p) */
        cur = m;
    }
    /* final: Pp == g[0]^af * h[0]^bf * u^{af*bf} */
    {
        uint8_t ab[E], s3[3 * E], p3[3 * E], rhs[E];
        if (determ_ff_scalar_mul(ab, af, bf) != 0) goto done;   /* rejects af/bf >= q */
        memcpy(s3, af, E); memcpy(s3 + E, bf, E); memcpy(s3 + 2 * E, ab, E);
        memcpy(p3, g, E);  memcpy(p3 + E, h, E);  memcpy(p3 + 2 * E, u, E);
        if (determ_ff_msm(rhs, s3, p3, 3) != 0) goto done;
        rc = (memcmp(Pp, rhs, E) == 0) ? 0 : -1;
    }
done:
    free(g); free(h); free(tr);
    return rc;
}

/* Fixed-generator forms: build g_i=gen(i,0), h_i=gen(i,1), u=gen(0xFFFFFFFF,0). */
static int ff_build_gens(uint8_t *g, uint8_t *h, uint8_t u[E], size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (determ_ff_gen(g + i * E, (uint32_t)i, 0) != 0) return -1;
        if (determ_ff_gen(h + i * E, (uint32_t)i, 1) != 0) return -1;
    }
    return determ_ff_gen(u, U_INDEX, 0);
}

int determ_ff_ipa_prove(uint8_t *proof, const uint8_t *a, const uint8_t *b,
                        const uint8_t P[E], size_t n) {
    if (ff_rounds(n) < 0) return -1;
    int rc = -1;
    uint8_t *g = malloc(n * E), *h = malloc(n * E), u[E];
    if (!g || !h) goto done;
    if (ff_build_gens(g, h, u, n) != 0) goto done;
    rc = determ_ff_ipa_prove_gens(proof, a, b, g, h, u, P, n);
done:
    free(g); free(h);
    return rc;
}

int determ_ff_ipa_verify(const uint8_t P[E], const uint8_t *proof, size_t n) {
    if (ff_rounds(n) < 0) return -1;
    int rc = -1;
    uint8_t *g = malloc(n * E), *h = malloc(n * E), u[E];
    if (!g || !h) goto done;
    if (ff_build_gens(g, h, u, n) != 0) goto done;
    rc = determ_ff_ipa_verify_gens(P, proof, g, h, u, n);
done:
    free(g); free(h);
    return rc;
}
