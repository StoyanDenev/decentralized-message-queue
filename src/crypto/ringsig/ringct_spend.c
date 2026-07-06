// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// RingCT spend-statement composition over NIST P-256 — CRYPTO-C99-SPEC.md §3.23c.
// See ringct_spend.h. Ported from tools/verify_ringct_spend.py (python-prove-first:
// transpose honest/wrong-amount/tamper + full CLSAG->transpose->DCT1 compose +
// reject-on-any-layer-tamper passed). The only new crypto is the commitment-
// transposition proof (a textbook Schnorr AND-proof with a shared value response);
// the spend verifier is pure composition of the shipped §3.23b CLSAG + §3.22c DCT1
// bundle verifiers. Built over the PUBLIC P-256 + pedersen (generator_h) APIs; the
// only local arithmetic is a 256-bit add-mod-n over the exported curve order. NOT
// constant-time (owner-gated).
#include "determ/crypto/ringsig/ringct_spend.h"
#include "determ/crypto/ringsig/clsag.h"
#include "determ/crypto/pedersen/ctxbundle.h"
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"

#include <string.h>

#define PT 65   /* SEC1 uncompressed point */
#define CP 33   /* SEC1 compressed point   */
#define SC 32   /* scalar                  */
#define TPLEN 162  /* transpose proof: A_H(33)|A_G(33)|sv(32)|sa(32)|sb(32) */

static const char CHAL_T[]  = "DETERM-RINGCT-TRANSPOSE-P256-challenge-v1";
static const char NONCE_T[] = "DETERM-RINGCT-TRANSPOSE-P256-nonce-v1";

static void get_n(uint8_t n[SC]) {
    uint8_t p[SC], b[SC], gx[SC], gy[SC];
    determ_p256_params(p, n, b, gx, gy);
}
static int is_zero(const uint8_t s[SC]) {
    for (int i = 0; i < SC; i++) if (s[i]) return 0;
    return 1;
}
/* a >= n ? (big-endian) */
static int sc_ge(const uint8_t a[SC], const uint8_t n[SC]) {
    for (int i = 0; i < SC; i++) if (a[i] != n[i]) return a[i] > n[i];
    return 1;
}
/* out = (a + b) mod n, for a, b in [0, n) (sum < 2n -> at most one subtraction). */
static void add_mod_n(uint8_t out[SC], const uint8_t a[SC], const uint8_t b[SC]) {
    uint8_t n[SC], t[SC];
    get_n(n);
    int carry = 0;
    for (int i = SC - 1; i >= 0; i--) { int s = (int)a[i] + (int)b[i] + carry; t[i] = (uint8_t)(s & 0xff); carry = s >> 8; }
    int ge;
    if (carry) ge = 1;
    else { int cmp = 0; for (int i = 0; i < SC; i++) { if (t[i] != n[i]) { cmp = (t[i] > n[i]) ? 1 : -1; break; } } ge = (cmp >= 0); }
    if (ge) { int bo = 0; for (int i = SC - 1; i >= 0; i--) { int d = (int)t[i] - (int)n[i] - bo; if (d < 0) { d += 256; bo = 1; } else bo = 0; out[i] = (uint8_t)d; } }
    else memcpy(out, t, SC);
}

/* c = hash_to_scalar(C_H33 ‖ C_G33 ‖ A_H33 ‖ A_G33) under CHAL_T. */
static int transpose_chal(uint8_t out[SC], const uint8_t C_H33[CP], const uint8_t C_G33[CP],
                          const uint8_t A_H33[CP], const uint8_t A_G33[CP]) {
    uint8_t buf[4 * CP];
    memcpy(buf, C_H33, CP);
    memcpy(buf + CP, C_G33, CP);
    memcpy(buf + 2 * CP, A_H33, CP);
    memcpy(buf + 3 * CP, A_G33, CP);
    return determ_p256_hash_to_scalar(out, buf, sizeof(buf),
                                      (const uint8_t *)CHAL_T, sizeof(CHAL_T) - 1);
}

/* deterministic nonce = hash_to_scalar(tag2 ‖ v ‖ a ‖ b ‖ C_H33 ‖ C_G33) under NONCE_T;
 * ==0 -> 1 (mirrors python). tag2 = "rv" / "ra" / "rb". */
static int transpose_nonce(uint8_t out[SC], const char tag2[2],
                           const uint8_t v[SC], const uint8_t a[SC], const uint8_t b[SC],
                           const uint8_t C_H33[CP], const uint8_t C_G33[CP]) {
    uint8_t buf[2 + 3 * SC + 2 * CP];
    buf[0] = (uint8_t)tag2[0];
    buf[1] = (uint8_t)tag2[1];
    memcpy(buf + 2, v, SC);
    memcpy(buf + 2 + SC, a, SC);
    memcpy(buf + 2 + 2 * SC, b, SC);
    memcpy(buf + 2 + 3 * SC, C_H33, CP);
    memcpy(buf + 2 + 3 * SC + CP, C_G33, CP);
    if (determ_p256_hash_to_scalar(out, buf, sizeof(buf),
                                   (const uint8_t *)NONCE_T, sizeof(NONCE_T) - 1) != 0) return -1;
    if (is_zero(out)) out[SC - 1] = 1;
    return 0;
}

size_t determ_commit_transpose_proof_len(void) { return TPLEN; }

int determ_commit_transpose_prove(uint8_t proof[TPLEN],
                                  uint8_t C_H_out33[CP], uint8_t C_G_out33[CP],
                                  const uint8_t v[SC], const uint8_t a[SC], const uint8_t b[SC]) {
    if (proof == 0 || C_H_out33 == 0 || C_G_out33 == 0 || v == 0 || a == 0 || b == 0) return -1;
    uint8_t H[PT];
    if (determ_pedersen_generator_h(H) != 0) return -1;

    /* C_H = v*H + a*G ; C_G = v*G + b*H. */
    uint8_t vH[PT], aG[PT], C_H[PT], vG[PT], bH[PT], C_G[PT], C_H33[CP], C_G33[CP];
    if (determ_p256_point_mul(vH, v, H) != 0) return -1;
    if (determ_p256_base_mul(aG, a) != 0) return -1;
    if (determ_p256_point_add(C_H, vH, aG) != 0) return -1;
    if (determ_p256_base_mul(vG, v) != 0) return -1;
    if (determ_p256_point_mul(bH, b, H) != 0) return -1;
    if (determ_p256_point_add(C_G, vG, bH) != 0) return -1;
    if (determ_p256_point_compress(C_H33, C_H) != 0) return -1;
    if (determ_p256_point_compress(C_G33, C_G) != 0) return -1;
    memcpy(C_H_out33, C_H33, CP);
    memcpy(C_G_out33, C_G33, CP);

    /* deterministic nonces rv, ra, rb. */
    uint8_t rv[SC], ra[SC], rb[SC];
    if (transpose_nonce(rv, "rv", v, a, b, C_H33, C_G33) != 0) return -1;
    if (transpose_nonce(ra, "ra", v, a, b, C_H33, C_G33) != 0) return -1;
    if (transpose_nonce(rb, "rb", v, a, b, C_H33, C_G33) != 0) return -1;

    /* A_H = rv*H + ra*G ; A_G = rv*G + rb*H. */
    uint8_t t1[PT], t2[PT], A_H[PT], A_G[PT], A_H33[CP], A_G33[CP];
    if (determ_p256_point_mul(t1, rv, H) != 0) return -1;
    if (determ_p256_base_mul(t2, ra) != 0) return -1;
    if (determ_p256_point_add(A_H, t1, t2) != 0) return -1;
    if (determ_p256_base_mul(t1, rv) != 0) return -1;
    if (determ_p256_point_mul(t2, rb, H) != 0) return -1;
    if (determ_p256_point_add(A_G, t1, t2) != 0) return -1;
    if (determ_p256_point_compress(A_H33, A_H) != 0) return -1;
    if (determ_p256_point_compress(A_G33, A_G) != 0) return -1;

    /* c = chal(C_H, C_G, A_H, A_G); sv = rv + c*v ; sa = ra + c*a ; sb = rb + c*b. */
    uint8_t c[SC], cx[SC], sv[SC], sa[SC], sb[SC];
    if (transpose_chal(c, C_H33, C_G33, A_H33, A_G33) != 0) return -1;
    if (determ_p256_scalar_mul_mod_n(cx, c, v) != 0) return -1;
    add_mod_n(sv, rv, cx);
    if (determ_p256_scalar_mul_mod_n(cx, c, a) != 0) return -1;
    add_mod_n(sa, ra, cx);
    if (determ_p256_scalar_mul_mod_n(cx, c, b) != 0) return -1;
    add_mod_n(sb, rb, cx);

    memcpy(proof, A_H33, CP);
    memcpy(proof + CP, A_G33, CP);
    memcpy(proof + 2 * CP, sv, SC);
    memcpy(proof + 2 * CP + SC, sa, SC);
    memcpy(proof + 2 * CP + 2 * SC, sb, SC);
    return 0;
}

int determ_commit_transpose_verify(const uint8_t C_H33[CP], const uint8_t C_G33[CP],
                                   const uint8_t proof[TPLEN]) {
    if (C_H33 == 0 || C_G33 == 0 || proof == 0) return -1;
    uint8_t H[PT];
    if (determ_pedersen_generator_h(H) != 0) return -1;

    const uint8_t *A_H33 = proof;
    const uint8_t *A_G33 = proof + CP;
    const uint8_t *sv = proof + 2 * CP;
    const uint8_t *sa = proof + 2 * CP + SC;
    const uint8_t *sb = proof + 2 * CP + 2 * SC;

    uint8_t n_ord[SC];
    get_n(n_ord);
    if (sc_ge(sv, n_ord) || sc_ge(sa, n_ord) || sc_ge(sb, n_ord)) return -1;

    uint8_t A_H[PT], A_G[PT], C_H[PT], C_G[PT];
    if (determ_p256_point_decompress(A_H, A_H33) != 0) return -1;
    if (determ_p256_point_decompress(A_G, A_G33) != 0) return -1;
    if (determ_p256_point_decompress(C_H, C_H33) != 0) return -1;
    if (determ_p256_point_decompress(C_G, C_G33) != 0) return -1;

    uint8_t c[SC];
    if (transpose_chal(c, C_H33, C_G33, A_H33, A_G33) != 0) return -1;

    /* check 1: sv*H + sa*G == A_H + c*C_H. */
    uint8_t l1a[PT], l1b[PT], lhs1[PT], r1[PT], rhs1[PT], lc[CP], rc[CP];
    if (determ_p256_point_mul(l1a, sv, H) != 0) return -1;
    if (determ_p256_base_mul(l1b, sa) != 0) return -1;
    if (determ_p256_point_add(lhs1, l1a, l1b) != 0) return -1;
    if (determ_p256_point_mul(r1, c, C_H) != 0) return -1;
    if (determ_p256_point_add(rhs1, A_H, r1) != 0) return -1;
    if (determ_p256_point_compress(lc, lhs1) != 0) return -1;
    if (determ_p256_point_compress(rc, rhs1) != 0) return -1;
    if (memcmp(lc, rc, CP) != 0) return -1;

    /* check 2: sv*G + sb*H == A_G + c*C_G. */
    uint8_t l2a[PT], l2b[PT], lhs2[PT], r2[PT], rhs2[PT];
    if (determ_p256_base_mul(l2a, sv) != 0) return -1;
    if (determ_p256_point_mul(l2b, sb, H) != 0) return -1;
    if (determ_p256_point_add(lhs2, l2a, l2b) != 0) return -1;
    if (determ_p256_point_mul(r2, c, C_G) != 0) return -1;
    if (determ_p256_point_add(rhs2, A_G, r2) != 0) return -1;
    if (determ_p256_point_compress(lc, lhs2) != 0) return -1;
    if (determ_p256_point_compress(rc, rhs2) != 0) return -1;
    if (memcmp(lc, rc, CP) != 0) return -1;

    return 0;
}

int determ_ringct_spend_verify(const uint8_t *msg, size_t msglen,
                               const uint8_t *ringP33, const uint8_t *ringC33, size_t n,
                               const uint8_t coffset_H33[CP],
                               const uint8_t I33[CP], const uint8_t D33[CP],
                               const uint8_t *clsag_sig, size_t clsag_sig_len,
                               const uint8_t transpose_proof[TPLEN],
                               const uint8_t *bundle, size_t bundle_len) {
    if (ringP33 == 0 || ringC33 == 0 || coffset_H33 == 0 || I33 == 0 || D33 == 0 ||
        clsag_sig == 0 || transpose_proof == 0 || bundle == 0) return -1;

    /* (1) CLSAG: input membership + Coffset_H commits to the real input amount. */
    if (determ_clsag_verify(msg, msglen, ringP33, ringC33, n, coffset_H33,
                            I33, D33, clsag_sig, clsag_sig_len) != 0) return -1;

    /* (2) the DCT1 bundle must be well-formed with EXACTLY one input; C_in[0] = coffset_G. */
    size_t n_in = 0, m = 0, nb = 0;
    uint64_t fee = 0;
    if (determ_ctx_bundle_header(bundle, bundle_len, &n_in, &m, &nb, &fee) != 0) return -1;
    if (n_in != 1) return -1;
    const uint8_t *coffset_G33 = bundle + 15;   /* C_in = bundle + 15 (per ctxbundle.h) */

    /* (3) the transpose bridges coffset_H (value-on-H) and coffset_G (value-on-G). */
    if (determ_commit_transpose_verify(coffset_H33, coffset_G33, transpose_proof) != 0) return -1;

    /* (4) the DCT1 bundle: range over the outputs + balance coffset_G = Σ outputs + fee. */
    if (determ_ctx_bundle_verify(bundle, bundle_len) != 0) return -1;

    return 0;
}
