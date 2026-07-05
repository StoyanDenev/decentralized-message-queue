/* Determ C99 Pedersen commitment over NIST P-256 — CRYPTO-C99-SPEC.md §3.19.
 * See pedersen.h for the construction and the binding/hiding argument. This
 * file is pure composition over the §3.8c P-256 primitives; it introduces no
 * new field/group arithmetic of its own. */
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"
#include "determ/crypto/ct.h"
#include "determ/crypto/secure_zero.h"

#include <string.h>

/* The nothing-up-my-sleeve inputs for H. The message states its purpose in
 * plain ASCII; the DST follows the RFC 9380 suite-ID convention so H lands in
 * a domain distinct from any OPRF/other hash-to-curve use of the same curve.
 * Changing either byte changes H — hence the pinned H KAT in the test. */
static const char PEDERSEN_H_MSG[] = "Determ Pedersen generator H over NIST P-256 v1";
static const char PEDERSEN_H_DST[] = "DETERM-PEDERSEN-P256_XMD:SHA-256_SSWU_RO_";

int determ_pedersen_generator_h(uint8_t out65[65]) {
    return determ_p256_hash_to_curve(
        out65,
        (const uint8_t *)PEDERSEN_H_MSG, sizeof(PEDERSEN_H_MSG) - 1,
        (const uint8_t *)PEDERSEN_H_DST, sizeof(PEDERSEN_H_DST) - 1);
}

/* 1 iff the 32-byte big-endian scalar is all zero. Reads every byte (no
 * short-circuit); the branch on the result in commit() is the one documented
 * data-dependent path (a v==0 value commitment) — see README §CT posture. */
static int scalar_is_zero(const uint8_t s[32]) {
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= s[i];
    return acc == 0;
}

/* out = (in == 0) ? 1 : in — constant-time (so base_mul/point_mul always gets a nonzero
 * scalar and never takes its zero-reject branch; the caller then folds uniformly and
 * discards the dummy term when the real scalar was zero). */
static void ct_scalar_nz(uint8_t out[32], const uint8_t in[32]) {
    uint8_t z = (uint8_t)scalar_is_zero(in);        /* 1 if in == 0 else 0 */
    uint8_t keep = (uint8_t)(z - 1);                /* 0xFF if in != 0 (keep), 0x00 if in == 0 */
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(in[i] & keep);
    out[31] |= z;                                   /* in == 0 -> out = 1 */
}

/* out[0..len) = pick ? b : a, byte-wise constant-time select (pick in {0,1}). */
static void ct_point_select(uint8_t *out, const uint8_t *a, const uint8_t *b,
                            uint8_t pick, size_t len) {
    uint8_t m = (uint8_t)(0u - pick);               /* 0xFF if pick else 0x00 */
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((b[i] & m) | (a[i] & (uint8_t)~m));
}

int determ_pedersen_commit(uint8_t out33[33],
                           const uint8_t v[32], const uint8_t r[32]) {
    uint8_t H[65], rH[65], vG[65], vGrH[65], C[65], v_nz[32];

    if (determ_pedersen_generator_h(H) != 0) return -1;

    /* r*H — rejects r == 0 or r >= n (a zero/oversized blinding factor) and any
     * malformed H (cannot happen for the fixed H, but keep the guard). */
    if (determ_p256_point_mul(rH, r, H) != 0) return -1;

    /* CONSTANT-TIME: compute v*G with a nonzero-substituted scalar (so base_mul never
     * takes its zero-reject branch), then branchlessly select r*H (v == 0) vs v*G + r*H
     * (v != 0) — no leak of whether the committed value is zero. Byte-identical to the old
     * `if (v==0) C=r*H else C=v*G+r*H` (the pedersen corpus is the guard). base_mul still
     * rejects v >= n (for v != 0, v_nz == v). The RCB point_add handles v*G == r*H; only
     * the exact-inverse case (v*G == -r*H, never for honest inputs) yields -1. */
    ct_scalar_nz(v_nz, v);
    if (determ_p256_base_mul(vG, v_nz) != 0) { determ_secure_zero(v_nz, sizeof v_nz); return -1; }
    if (determ_p256_point_add(vGrH, vG, rH) != 0) { determ_secure_zero(v_nz, sizeof v_nz); return -1; }
    ct_point_select(C, rH, vGrH, (uint8_t)(1u - (unsigned)scalar_is_zero(v)), 65);   /* pick = (v != 0), branchless */
    determ_secure_zero(v_nz, sizeof v_nz);

    return determ_p256_point_compress(out33, C);
}

int determ_pedersen_verify(const uint8_t commitment33[33],
                           const uint8_t v[32], const uint8_t r[32]) {
    uint8_t recomputed[33];
    if (determ_pedersen_commit(recomputed, v, r) != 0) return -1;
    /* Constant-time compare of the 33-byte encoding (both operands public — the
     * commitment is on the wire, the opening is being revealed — so this is
     * hygiene, not a secret-dependent gate). */
    return determ_ct_memcmp(recomputed, commitment33, 33) == 0 ? 0 : -1;
}

int determ_pedersen_add(uint8_t out33[33],
                        const uint8_t c1_33[33], const uint8_t c2_33[33]) {
    uint8_t p1[65], p2[65], sum[65];
    if (determ_p256_point_decompress(p1, c1_33) != 0) return -1;
    if (determ_p256_point_decompress(p2, c2_33) != 0) return -1;
    if (determ_p256_point_add(sum, p1, p2) != 0) return -1; /* identity -> -1 */
    return determ_p256_point_compress(out33, sum);
}

/* ── §3.19 increment 2: vector-commitment generators + vector commit ─────── */

/* Family DSTs. Distinct suite tags so G_i, H_i, and the §3.19 scalar H all land
 * in separate hash_to_curve domains — no known dlog relation among them. */
static const char PEDERSEN_VG_DST[] = "DETERM-PEDERSEN-VEC-G-P256_XMD:SHA-256_SSWU_RO_";
static const char PEDERSEN_VH_DST[] = "DETERM-PEDERSEN-VEC-H-P256_XMD:SHA-256_SSWU_RO_";

int determ_pedersen_gen(uint8_t out65[65], uint32_t index, uint8_t which) {
    const char *dst;
    size_t dstlen;
    if (which == 0)      { dst = PEDERSEN_VG_DST; dstlen = sizeof(PEDERSEN_VG_DST) - 1; }
    else if (which == 1) { dst = PEDERSEN_VH_DST; dstlen = sizeof(PEDERSEN_VH_DST) - 1; }
    else return -1;
    /* msg = the 4-byte big-endian index (fixed width so no length ambiguity). */
    uint8_t msg[4];
    msg[0] = (uint8_t)(index >> 24); msg[1] = (uint8_t)(index >> 16);
    msg[2] = (uint8_t)(index >> 8);  msg[3] = (uint8_t)(index);
    return determ_p256_hash_to_curve(out65, msg, 4, (const uint8_t *)dst, dstlen);
}

int determ_pedersen_vector_commit(uint8_t out33[33],
                                  const uint8_t *a, const uint8_t *b,
                                  size_t n, const uint8_t r[32]) {
    uint8_t H[65], acc[65], gen[65], term[65], cand[65], s_nz[32];

    /* Start the accumulator at r*H (rejects r == 0 / r >= n_order). The start is
     * non-identity and stays non-identity for honest inputs (a mid-loop identity needs an
     * adversarial exact-cancellation), so every point_add below is a valid real+real add. */
    if (determ_pedersen_generator_h(H) != 0) return -1;
    if (determ_p256_point_mul(acc, r, H) != 0) return -1;

    for (size_t i = 0; i < n; i++) {
        const uint8_t *ai = a + i * 32;
        const uint8_t *bi = b + i * 32;
        /* CONSTANT-TIME a_i*G_i: always exponentiate (nonzero-substituted scalar) + fold
         * into a candidate, then select `acc` unchanged when a_i == 0 — no leak of the
         * secret bit-vector. Byte-identical to the old zero-skip (point_mul still rejects
         * a_i >= n; for a_i != 0, s_nz == a_i). */
        if (determ_pedersen_gen(gen, (uint32_t)i, 0) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        ct_scalar_nz(s_nz, ai);
        if (determ_p256_point_mul(term, s_nz, gen) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        if (determ_p256_point_add(cand, acc, term) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        ct_point_select(acc, acc, cand, (uint8_t)(1u - (unsigned)scalar_is_zero(ai)), 65);   /* pick = (a_i != 0) */
        /* b_i * H_i (same shape). */
        if (determ_pedersen_gen(gen, (uint32_t)i, 1) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        ct_scalar_nz(s_nz, bi);
        if (determ_p256_point_mul(term, s_nz, gen) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        if (determ_p256_point_add(cand, acc, term) != 0) { determ_secure_zero(s_nz, sizeof s_nz); return -1; }
        ct_point_select(acc, acc, cand, (uint8_t)(1u - (unsigned)scalar_is_zero(bi)), 65);   /* pick = (b_i != 0) */
    }
    determ_secure_zero(s_nz, sizeof s_nz);
    return determ_p256_point_compress(out33, acc);
}

/* ── §3.19 increment 3: general multi-scalar multiplication ─────────────── */

int determ_pedersen_msm(uint8_t out33[33],
                        const uint8_t *scalars, const uint8_t *points33, size_t n) {
    /* CONSTANT-TIME: delegated to the pt-domain determ_p256_msm_ct, which folds every term
     * uniformly (pt_scalar_mul(0,P) = O, the RCB-complete pt_add absorbs O) — so it needs
     * no acc_is_identity flag and NO zero-scalar skip, and leaks nothing about which secret
     * scalars are zero. Byte-identical to the old encoded-domain accumulation (the
     * pedersen / bp_* corpora are the guard). */
    return determ_p256_msm_ct(out33, scalars, points33, n);
}
