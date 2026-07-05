/* Determ C99 Bulletproofs inner-product argument over NIST P-256 —
 * CRYPTO-C99-SPEC.md §3.19 increment 4. See ipa.h for the statement/contract.
 * Ported from the independent Python reference tools/verify_bp_ipa.py after that
 * reference's per-round invariant + round-trip + soundness self-tests passed
 * (python-prove-first). Pure composition over the §3.19 pedersen_gen /
 * pedersen_msm and the §3.8c P-256 point/scalar primitives. */
#include "determ/crypto/pedersen/ipa.h"
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"

#include <string.h>

/* The P-256 group order n (big-endian) — the public SEC 2 / FIPS 186 constant;
 * used only for the modular add below. Every point/scalar op that consumes it is
 * itself gated against OpenSSL (test-p256-c99). */
static const uint8_t ORDER_N[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
static const uint8_t ONE[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
#define U_INDEX 0xFFFFFFFFu

/* r = (a + b) mod n, all 32-byte big-endian, a,b < n. Since a+b < 2n a single
 * conditional subtraction of n reduces it. The subtract-or-not branch is a
 * data-dependent path (documented non-CT — the range-proof track's owner-gated
 * CT-hardening step). */
static void sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t sum[33], np[33], diff[33];
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned s = (unsigned)a[i] + b[i] + carry;
        sum[i + 1] = (uint8_t)s; carry = s >> 8;
    }
    sum[0] = (uint8_t)carry;                 /* 0 or 1 */
    np[0] = 0; memcpy(np + 1, ORDER_N, 32);
    int borrow = 0;
    for (int i = 32; i >= 0; i--) {
        int d = (int)sum[i] - np[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        diff[i] = (uint8_t)d;
    }
    memcpy(r, (borrow ? sum : diff) + 1, 32); /* borrow==0 => sum>=n => use diff */
}

/* r = <a, b> mod n over n 32-byte scalars. -1 if a scalar is out of range. */
static int inner_product(uint8_t r[32], const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t acc[32] = {0}, prod[32];
    for (size_t i = 0; i < n; i++) {
        if (determ_p256_scalar_mul_mod_n(prod, a + i * 32, b + i * 32) != 0) return -1;
        sc_add(acc, acc, prod);
    }
    memcpy(r, acc, 32);
    return 0;
}

/* out33 = compress(pedersen_gen(index, which)). */
static int gen_c(uint8_t out33[33], uint32_t index, uint8_t which) {
    uint8_t p65[65];
    if (determ_pedersen_gen(p65, index, which) != 0) return -1;
    return determ_p256_point_compress(out33, p65);
}

/* out33 = compress(s1*P1 + s2*P2). out33 may alias p1 or p2 (both are decoded
 * into locals before out is written). -1 on decode/scalar failure or the
 * (negligible) identity result. */
static int fold_point(uint8_t out33[33], const uint8_t s1[32], const uint8_t p1[33],
                      const uint8_t s2[32], const uint8_t p2[33]) {
    uint8_t P1[65], P2[65], T1[65], T2[65], S[65];
    if (determ_p256_point_decompress(P1, p1) != 0) return -1;
    if (determ_p256_point_decompress(P2, p2) != 0) return -1;
    if (determ_p256_point_mul(T1, s1, P1) != 0) return -1;
    if (determ_p256_point_mul(T2, s2, P2) != 0) return -1;
    if (determ_p256_point_add(S, T1, T2) != 0) return -1;
    return determ_p256_point_compress(out33, S);
}

/* -1 if n is not a supported power of two, else the number of fold rounds. */
static int ipa_rounds(size_t n) {
    if (n < 1 || n > DETERM_IPA_MAX_N) return -1;
    int r = 0; size_t m = n;
    while (m > 1) { if (m & 1) return -1; m >>= 1; r++; }
    return r;
}

size_t determ_ipa_proof_len(size_t n) {
    int r = ipa_rounds(n);
    return r < 0 ? 0 : (size_t)r * 66 + 64;
}

/* ── the deterministic Fiat-Shamir transcript ─────────────────────────────── */
typedef struct { uint8_t buf[1024]; size_t len; } ipa_tr;

static void tr_init(ipa_tr *t, const uint8_t P33[33], const uint8_t u33[33], size_t n) {
    static const char LABEL[] = "DETERM-BP-IPA-v1";
    t->len = sizeof(LABEL) - 1;
    memcpy(t->buf, LABEL, t->len);
    memcpy(t->buf + t->len, P33, 33); t->len += 33;
    memcpy(t->buf + t->len, u33, 33); t->len += 33;
    uint32_t nn = (uint32_t)n;
    t->buf[t->len++] = (uint8_t)(nn >> 24); t->buf[t->len++] = (uint8_t)(nn >> 16);
    t->buf[t->len++] = (uint8_t)(nn >> 8);  t->buf[t->len++] = (uint8_t)nn;
}
static void tr_absorb(ipa_tr *t, const uint8_t pt33[33]) {
    memcpy(t->buf + t->len, pt33, 33); t->len += 33;
}
static int tr_challenge(ipa_tr *t, uint8_t out32[32]) {
    static const char CDST[] = "DETERM-BP-IPA-v1-challenge";
    if (determ_p256_hash_to_scalar(out32, t->buf, t->len,
                                   (const uint8_t *)CDST, sizeof(CDST) - 1) != 0) return -1;
    uint8_t z = 0; for (int i = 0; i < 32; i++) z |= out32[i];
    if (z == 0) return -1;                    /* a zero challenge is unusable (negligible) */
    memcpy(t->buf + t->len, out32, 32); t->len += 32;
    return 0;
}

int determ_ipa_commit(uint8_t out33[33], const uint8_t *a, const uint8_t *b, size_t n) {
    if (ipa_rounds(n) < 0) return -1;
    uint8_t scal[(2 * DETERM_IPA_MAX_N + 1) * 32];
    uint8_t pts[(2 * DETERM_IPA_MAX_N + 1) * 33];
    for (size_t i = 0; i < n; i++) {
        memcpy(scal + i * 32, a + i * 32, 32);
        if (gen_c(pts + i * 33, (uint32_t)i, 0) != 0) return -1;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy(scal + (n + i) * 32, b + i * 32, 32);
        if (gen_c(pts + (n + i) * 33, (uint32_t)i, 1) != 0) return -1;
    }
    uint8_t ab[32];
    if (inner_product(ab, a, b, n) != 0) return -1;
    memcpy(scal + 2 * n * 32, ab, 32);
    if (gen_c(pts + 2 * n * 33, U_INDEX, 0) != 0) return -1;
    return determ_pedersen_msm(out33, scal, pts, 2 * n + 1) == 0 ? 0 : -1;
}

int determ_ipa_prove_gens(uint8_t *proof, const uint8_t *a_in, const uint8_t *b_in,
                          const uint8_t *g_in, const uint8_t *h_in, const uint8_t u33[33],
                          const uint8_t P33[33], size_t n) {
    int rounds = ipa_rounds(n);
    if (rounds < 0) return -1;
    uint8_t a[DETERM_IPA_MAX_N * 32], b[DETERM_IPA_MAX_N * 32];
    uint8_t g[DETERM_IPA_MAX_N * 33], h[DETERM_IPA_MAX_N * 33], u[33];
    memcpy(a, a_in, n * 32); memcpy(b, b_in, n * 32);
    memcpy(g, g_in, n * 33); memcpy(h, h_in, n * 33); memcpy(u, u33, 33);

    ipa_tr tr; tr_init(&tr, P33, u, n);
    uint8_t *Lw = proof, *Rw = proof + (size_t)rounds * 33;
    size_t cur = n;
    for (int rd = 0; rd < rounds; rd++) {
        size_t m = cur / 2;
        uint8_t scal[(DETERM_IPA_MAX_N + 1) * 32], pts[(DETERM_IPA_MAX_N + 1) * 33];
        uint8_t L[33], R[33], cL[32], cR[32], x[32], xinv[32];

        /* L = <aL,gR> + <bR,hL> + <aL,bR>*u */
        for (size_t i = 0; i < m; i++) memcpy(scal + i * 32, a + i * 32, 32);            /* aL */
        for (size_t i = 0; i < m; i++) memcpy(scal + (m + i) * 32, b + (m + i) * 32, 32); /* bR */
        if (inner_product(cL, a, b + m * 32, m) != 0) return -1;
        memcpy(scal + 2 * m * 32, cL, 32);
        for (size_t i = 0; i < m; i++) memcpy(pts + i * 33, g + (m + i) * 33, 33);        /* gR */
        for (size_t i = 0; i < m; i++) memcpy(pts + (m + i) * 33, h + i * 33, 33);        /* hL */
        memcpy(pts + 2 * m * 33, u, 33);
        if (determ_pedersen_msm(L, scal, pts, 2 * m + 1) != 0) return -1;

        /* R = <aR,gL> + <bL,hR> + <aR,bL>*u */
        for (size_t i = 0; i < m; i++) memcpy(scal + i * 32, a + (m + i) * 32, 32);       /* aR */
        for (size_t i = 0; i < m; i++) memcpy(scal + (m + i) * 32, b + i * 32, 32);       /* bL */
        if (inner_product(cR, a + m * 32, b, m) != 0) return -1;
        memcpy(scal + 2 * m * 32, cR, 32);
        for (size_t i = 0; i < m; i++) memcpy(pts + i * 33, g + i * 33, 33);              /* gL */
        for (size_t i = 0; i < m; i++) memcpy(pts + (m + i) * 33, h + (m + i) * 33, 33);  /* hR */
        memcpy(pts + 2 * m * 33, u, 33);
        if (determ_pedersen_msm(R, scal, pts, 2 * m + 1) != 0) return -1;

        tr_absorb(&tr, L); tr_absorb(&tr, R);
        if (tr_challenge(&tr, x) != 0) return -1;
        if (determ_p256_scalar_inv_mod_n(xinv, x) != 0) return -1;

        /* fold a,b (in place, first m slots): a'=aL*x+aR*xinv, b'=bL*xinv+bR*x */
        for (size_t i = 0; i < m; i++) {
            uint8_t t1[32], t2[32];
            if (determ_p256_scalar_mul_mod_n(t1, a + i * 32, x) != 0) return -1;
            if (determ_p256_scalar_mul_mod_n(t2, a + (m + i) * 32, xinv) != 0) return -1;
            sc_add(a + i * 32, t1, t2);
            if (determ_p256_scalar_mul_mod_n(t1, b + i * 32, xinv) != 0) return -1;
            if (determ_p256_scalar_mul_mod_n(t2, b + (m + i) * 32, x) != 0) return -1;
            sc_add(b + i * 32, t1, t2);
        }
        /* fold g,h (in place): g'=xinv*gL+x*gR, h'=x*hL+xinv*hR */
        for (size_t i = 0; i < m; i++) {
            if (fold_point(g + i * 33, xinv, g + i * 33, x, g + (m + i) * 33) != 0) return -1;
            if (fold_point(h + i * 33, x, h + i * 33, xinv, h + (m + i) * 33) != 0) return -1;
        }
        memcpy(Lw + (size_t)rd * 33, L, 33);
        memcpy(Rw + (size_t)rd * 33, R, 33);
        cur = m;
    }
    memcpy(proof + 2 * (size_t)rounds * 33, a, 32);
    memcpy(proof + 2 * (size_t)rounds * 33 + 32, b, 32);
    return 0;
}

/* Fixed-generator prove: build g_i=gen(i,0), h_i=gen(i,1), u=gen(0xFFFFFFFF,0)
 * then delegate to the generator-supplied core (byte-identical to the pre-refactor
 * inline path). */
int determ_ipa_prove(uint8_t *proof, const uint8_t *a, const uint8_t *b,
                     const uint8_t P33[33], size_t n) {
    if (ipa_rounds(n) < 0) return -1;
    uint8_t g[DETERM_IPA_MAX_N * 33], h[DETERM_IPA_MAX_N * 33], u[33];
    for (size_t i = 0; i < n; i++) {
        if (gen_c(g + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(h + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;
    return determ_ipa_prove_gens(proof, a, b, g, h, u, P33, n);
}

int determ_ipa_verify_gens(const uint8_t P33[33], const uint8_t *proof,
                           const uint8_t *g_in, const uint8_t *h_in, const uint8_t u33[33],
                           size_t n) {
    int rounds = ipa_rounds(n);
    if (rounds < 0) return -1;
    uint8_t g[DETERM_IPA_MAX_N * 33], h[DETERM_IPA_MAX_N * 33], u[33];
    memcpy(g, g_in, n * 33); memcpy(h, h_in, n * 33); memcpy(u, u33, 33);

    const uint8_t *Ls = proof, *Rs = proof + (size_t)rounds * 33;
    const uint8_t *af = proof + 2 * (size_t)rounds * 33, *bf = af + 32;
    ipa_tr tr; tr_init(&tr, P33, u, n);
    uint8_t Pp[33]; memcpy(Pp, P33, 33);
    size_t cur = n;
    for (int rd = 0; rd < rounds; rd++) {
        const uint8_t *L = Ls + (size_t)rd * 33, *R = Rs + (size_t)rd * 33;
        uint8_t x[32], xinv[32], x2[32], x2inv[32];
        tr_absorb(&tr, L); tr_absorb(&tr, R);
        if (tr_challenge(&tr, x) != 0) return -1;
        if (determ_p256_scalar_inv_mod_n(xinv, x) != 0) return -1;
        if (determ_p256_scalar_mul_mod_n(x2, x, x) != 0) return -1;
        if (determ_p256_scalar_mul_mod_n(x2inv, xinv, xinv) != 0) return -1;
        size_t m = cur / 2;
        for (size_t i = 0; i < m; i++) {
            if (fold_point(g + i * 33, xinv, g + i * 33, x, g + (m + i) * 33) != 0) return -1;
            if (fold_point(h + i * 33, x, h + i * 33, xinv, h + (m + i) * 33) != 0) return -1;
        }
        /* Pp = x2*L + 1*Pp + x2inv*R */
        uint8_t scal[3 * 32], pts[3 * 33];
        memcpy(scal, x2, 32); memcpy(scal + 32, ONE, 32); memcpy(scal + 64, x2inv, 32);
        memcpy(pts, L, 33); memcpy(pts + 33, Pp, 33); memcpy(pts + 66, R, 33);
        if (determ_pedersen_msm(Pp, scal, pts, 3) != 0) return -1;
        cur = m;
    }
    /* final: Pp == af*g[0] + bf*h[0] + (af*bf)*u */
    uint8_t ab[32], scal[3 * 32], pts[3 * 33], rhs[33];
    if (determ_p256_scalar_mul_mod_n(ab, af, bf) != 0) return -1;
    memcpy(scal, af, 32); memcpy(scal + 32, bf, 32); memcpy(scal + 64, ab, 32);
    memcpy(pts, g, 33); memcpy(pts + 33, h, 33); memcpy(pts + 66, u, 33);
    if (determ_pedersen_msm(rhs, scal, pts, 3) != 0) return -1;
    return memcmp(Pp, rhs, 33) == 0 ? 0 : -1;
}

/* Fixed-generator verify: build the ciphersuite generators, then delegate. */
int determ_ipa_verify(const uint8_t P33[33], const uint8_t *proof, size_t n) {
    if (ipa_rounds(n) < 0) return -1;
    uint8_t g[DETERM_IPA_MAX_N * 33], h[DETERM_IPA_MAX_N * 33], u[33];
    for (size_t i = 0; i < n; i++) {
        if (gen_c(g + i * 33, (uint32_t)i, 0) != 0) return -1;
        if (gen_c(h + i * 33, (uint32_t)i, 1) != 0) return -1;
    }
    if (gen_c(u, U_INDEX, 0) != 0) return -1;
    return determ_ipa_verify_gens(P33, proof, g, h, u, n);
}
