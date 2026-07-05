/* Determ C99 Pedersen commitment over NIST P-256 — CRYPTO-C99-SPEC.md §3.19.
 * See pedersen.h for the construction and the binding/hiding argument. This
 * file is pure composition over the §3.8c P-256 primitives; it introduces no
 * new field/group arithmetic of its own. */
#include "determ/crypto/pedersen/pedersen.h"
#include "determ/crypto/p256/p256.h"
#include "determ/crypto/ct.h"

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

int determ_pedersen_commit(uint8_t out33[33],
                           const uint8_t v[32], const uint8_t r[32]) {
    uint8_t H[65], rH[65], vG[65], C[65];

    if (determ_pedersen_generator_h(H) != 0) return -1;

    /* r*H — rejects r == 0 or r >= n (a zero/oversized blinding factor) and any
     * malformed H (cannot happen for the fixed H, but keep the guard). */
    if (determ_p256_point_mul(rH, r, H) != 0) return -1;

    if (scalar_is_zero(v)) {
        /* v == 0: C = r*H directly (base_mul rejects the zero scalar). */
        memcpy(C, rH, 65);
    } else {
        /* v*G (rejects v >= n; v != 0 here), then C = v*G + r*H. The RCB
         * complete-addition formula in point_add handles v*G == r*H etc.; only
         * the exact-inverse case (v*G == -r*H) yields the identity -> -1. */
        if (determ_p256_base_mul(vG, v) != 0) return -1;
        if (determ_p256_point_add(C, vG, rH) != 0) return -1;
    }

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
    uint8_t H[65], acc[65], gen[65], term[65];

    /* Start the accumulator at r*H (rejects r == 0 / r >= n_order). Because the
     * start is non-identity, an intermediate identity can only arise if a later
     * term exactly cancels the running sum — a known-dlog / adversarial event
     * that point_add reports as -1. */
    if (determ_pedersen_generator_h(H) != 0) return -1;
    if (determ_p256_point_mul(acc, r, H) != 0) return -1;

    for (size_t i = 0; i < n; i++) {
        const uint8_t *ai = a + i * 32;
        const uint8_t *bi = b + i * 32;
        /* a_i * G_i (skip the identity term a_i == 0). */
        if (!scalar_is_zero(ai)) {
            if (determ_pedersen_gen(gen, (uint32_t)i, 0) != 0) return -1;
            if (determ_p256_point_mul(term, ai, gen) != 0) return -1;
            if (determ_p256_point_add(acc, acc, term) != 0) return -1;
        }
        /* b_i * H_i (skip the identity term b_i == 0). */
        if (!scalar_is_zero(bi)) {
            if (determ_pedersen_gen(gen, (uint32_t)i, 1) != 0) return -1;
            if (determ_p256_point_mul(term, bi, gen) != 0) return -1;
            if (determ_p256_point_add(acc, acc, term) != 0) return -1;
        }
    }
    return determ_p256_point_compress(out33, acc);
}
