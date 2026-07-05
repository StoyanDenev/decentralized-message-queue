/* Determ C99 confidential-tx balance proof over NIST P-256 — CRYPTO-C99-SPEC.md §3.19
 * increment 7. See balance.h. Ported from tools/verify_p256_balance.py (python-prove-
 * first: balanced accept + unbalanced/tamper reject + fee=0 self-tests passed). Pure
 * composition over the PUBLIC §3.19 pedersen (commit/msm) + §3.8c/§3.9b P-256 APIs — no
 * point-negation primitive (point subtractions are scalar negations (n−1)/(n−fee) in the
 * exponent) and NO change to the sealed p256 core; the only local arithmetic is a 256-bit
 * add-mod-n / negate-mod-n over the exported curve order. NOT constant-time (owner-gated). */
#include "determ/crypto/pedersen/balance.h"
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"

#include <string.h>
#include <stdlib.h>

#define PT 33   /* SEC1 compressed point */
#define SC 32   /* scalar */

static const char BAL_DST[] = "DETERM-P256-BALANCE-v1-challenge";

static void get_n(uint8_t n[SC]) { uint8_t p[SC], b[SC], gx[SC], gy[SC]; determ_p256_params(p, n, b, gx, gy); }

static void sc_one(uint8_t o[SC]) { memset(o, 0, SC); o[SC - 1] = 1; }
static void sc_u64(uint8_t o[SC], uint64_t x) { memset(o, 0, SC); for (int i = 0; i < 8; i++) o[SC - 1 - i] = (uint8_t)(x >> (8 * i)); }

/* out = (n - a) mod n, for a in [0, n). a == 0 -> 0. (big-endian borrow subtract) */
static void negate_mod_n(uint8_t out[SC], const uint8_t a[SC]) {
    uint8_t n[SC]; get_n(n);
    int nz = 0; for (int i = 0; i < SC; i++) if (a[i]) { nz = 1; break; }
    if (!nz) { memset(out, 0, SC); return; }
    int borrow = 0;
    for (int i = SC - 1; i >= 0; i--) { int d = (int)n[i] - (int)a[i] - borrow; if (d < 0) { d += 256; borrow = 1; } else borrow = 0; out[i] = (uint8_t)d; }
}

/* out = (a + b) mod n, for a, b in [0, n). (256-bit add + one conditional subtract of n) */
static void add_mod_n(uint8_t out[SC], const uint8_t a[SC], const uint8_t b[SC]) {
    uint8_t n[SC], t[SC]; get_n(n);
    int carry = 0;
    for (int i = SC - 1; i >= 0; i--) { int s = (int)a[i] + (int)b[i] + carry; t[i] = (uint8_t)(s & 0xff); carry = s >> 8; }
    int ge;
    if (carry) {
        ge = 1;                       /* a+b >= 2^256 > n; and then t < n so t-n mod 2^256 == a+b-n */
    } else {
        int cmp = 0;                  /* compare t vs n: >0 if t>n, <0 if t<n, 0 if equal */
        for (int i = 0; i < SC; i++) { if (t[i] != n[i]) { cmp = (t[i] > n[i]) ? 1 : -1; break; } }
        ge = (cmp >= 0);              /* t == n -> subtract to 0 */
    }
    if (ge) { int borrow = 0; for (int i = SC - 1; i >= 0; i--) { int d = (int)t[i] - (int)n[i] - borrow; if (d < 0) { d += 256; borrow = 1; } else borrow = 0; out[i] = (uint8_t)d; } }
    else memcpy(out, t, SC);
}

static int compress_h(uint8_t h33[PT]) {
    uint8_t h65[65];
    if (determ_pedersen_generator_h(h65) != 0) return -1;
    h33[0] = (uint8_t)(0x02 | (h65[64] & 1));                 /* parity of Y (uncompressed = 04|X|Y) */
    memcpy(h33 + 1, h65 + 1, 32);
    return 0;
}

static void compress_g(uint8_t g33[PT]) {
    uint8_t p[SC], n[SC], b[SC], gx[SC], gy[SC];
    determ_p256_params(p, n, b, gx, gy);
    g33[0] = (uint8_t)(0x02 | (gy[SC - 1] & 1));              /* parity of Gy (big-endian LSB) */
    memcpy(g33 + 1, gx, 32);
}

int determ_p256_balance_excess(uint8_t E_out[PT],
                               const uint8_t *C_in, size_t n_in,
                               const uint8_t *C_out, size_t n_out, uint64_t fee) {
    int rc = -1;
    size_t cnt = n_in + n_out + 1;
    uint8_t *scal = calloc(cnt, SC), *pts = calloc(cnt, PT);
    if (!scal || !pts) goto done;
    uint8_t one[SC], negone[SC], feesc[SC], negfee[SC], g33[PT];
    sc_one(one); negate_mod_n(negone, one);                  /* n-1 (scalar -1) */
    sc_u64(feesc, fee); negate_mod_n(negfee, feesc);         /* (n-fee) mod n; fee=0 -> 0 */
    compress_g(g33);
    for (size_t j = 0; j < n_in; j++)  { memcpy(scal + j * SC, one, SC);                memcpy(pts + j * PT, C_in + j * PT, PT); }
    for (size_t k = 0; k < n_out; k++) { memcpy(scal + (n_in + k) * SC, negone, SC);    memcpy(pts + (n_in + k) * PT, C_out + k * PT, PT); }
    memcpy(scal + (n_in + n_out) * SC, negfee, SC);
    memcpy(pts + (n_in + n_out) * PT, g33, PT);
    rc = determ_pedersen_msm(E_out, scal, pts, cnt);         /* Σ C_in + Σ(n-1)*C_out + (n-fee)*G */
done:
    free(scal); free(pts);
    return rc;
}

int determ_p256_balance_prove(uint8_t proof[DETERM_P256_BALANCE_PROOF_BYTES],
                              const uint8_t E_in[PT], const uint8_t x[SC], const uint8_t k[SC]) {
    uint8_t h33[PT], T[PT], c[SC], cx[SC], s[SC], msg[2 * PT];
    if (compress_h(h33) != 0) return -1;
    if (determ_pedersen_msm(T, k, h33, 1) != 0) return -1;   /* T = k*H (rejects k>=n; k==0 -> identity -> !=0) */
    memcpy(msg, E_in, PT); memcpy(msg + PT, T, PT);
    if (determ_p256_hash_to_scalar(c, msg, 2 * PT, (const uint8_t *)BAL_DST, sizeof(BAL_DST) - 1) != 0) return -1;
    if (determ_p256_scalar_mul_mod_n(cx, c, x) != 0) return -1;   /* c*x (rejects x>=n) */
    add_mod_n(s, k, cx);                                          /* s = k + c*x mod n (k<n guaranteed by the msm above) */
    memcpy(proof, T, PT); memcpy(proof + PT, s, SC);
    return 0;
}

int determ_p256_balance_verify(const uint8_t E_in[PT], const uint8_t proof[DETERM_P256_BALANCE_PROOF_BYTES]) {
    const uint8_t *T = proof, *s = proof + PT;
    uint8_t h33[PT], c[SC], lhs[PT], rhs[PT], one[SC], msg[2 * PT], sc2[2 * SC], pt2[2 * PT];
    if (compress_h(h33) != 0) return -1;
    memcpy(msg, E_in, PT); memcpy(msg + PT, T, PT);
    if (determ_p256_hash_to_scalar(c, msg, 2 * PT, (const uint8_t *)BAL_DST, sizeof(BAL_DST) - 1) != 0) return -1;
    if (determ_pedersen_msm(lhs, s, h33, 1) != 0) return -1;      /* s*H (rejects s>=n / s==0 identity) */
    sc_one(one);
    memcpy(sc2, one, SC); memcpy(sc2 + SC, c, SC);
    memcpy(pt2, T, PT);   memcpy(pt2 + PT, E_in, PT);
    if (determ_pedersen_msm(rhs, sc2, pt2, 2) != 0) return -1;    /* T + c*E (rejects malformed T/E / identity) */
    return (memcmp(lhs, rhs, PT) == 0) ? 0 : -1;
}
