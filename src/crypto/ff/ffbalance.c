/* Determ C99 confidential-tx balance proof over Z_p* — CRYPTO-C99-SPEC.md §3.20
 * increment 7. See ffbalance.h. Ported from tools/verify_ff_balance.py (python-prove-
 * first: balanced accept + unbalanced/tamper reject + fee=0 self-tests passed). Pure
 * composition over the public §3.20 inc.1-3 primitives — no new arithmetic, no group
 * inverse (inverses are scalar negations q-1 / q-fee in the exponent). NOT constant-
 * time (owner-gated). */
#include "determ/crypto/ff/ffbalance.h"
#include "determ/crypto/ff/ffgroup.h"

#include <string.h>
#include <stdlib.h>

#define E DETERM_FF_ELEM_BYTES              /* 384 */

static const char BAL_CDST[] = "DETERM-FF-BALANCE-v1-challenge";

static void sc_one(uint8_t o[E])  { memset(o, 0, E); o[E - 1] = 1; }
static void sc_zero(uint8_t o[E]) { memset(o, 0, E); }
static void sc_u64(uint8_t o[E], uint64_t x) { memset(o, 0, E); for (int i = 0; i < 8; i++) o[E - 1 - i] = (uint8_t)(x >> (8 * i)); }
static void g_val_elem(uint8_t o[E]) { memset(o, 0, E); o[E - 1] = 4; }

int determ_ff_balance_excess(uint8_t E_out[E],
                             const uint8_t *C_in, size_t n_in,
                             const uint8_t *C_out, size_t n_out, uint64_t fee) {
    int rc = -1;
    size_t cnt = n_in + n_out + 1;
    uint8_t *scal = calloc(cnt, E), *pts = calloc(cnt, E);
    if (!scal || !pts) goto done;
    uint8_t one[E], zero[E], negone[E], feesc[E], negfee[E], gval[E];
    sc_one(one); sc_zero(zero); g_val_elem(gval);
    if (determ_ff_scalar_sub(negone, zero, one) != 0) goto done;    /* q-1 (scalar -1) */
    sc_u64(feesc, fee);                                             /* fee < 2^64 < q */
    if (determ_ff_scalar_sub(negfee, zero, feesc) != 0) goto done;  /* (q-fee) mod q; fee=0 -> 0 */
    for (size_t j = 0; j < n_in; j++) { memcpy(scal + j * E, one, E); memcpy(pts + j * E, C_in + j * E, E); }
    for (size_t k = 0; k < n_out; k++) { memcpy(scal + (n_in + k) * E, negone, E); memcpy(pts + (n_in + k) * E, C_out + k * E, E); }
    memcpy(scal + (n_in + n_out) * E, negfee, E);
    memcpy(pts + (n_in + n_out) * E, gval, E);
    rc = determ_ff_msm(E_out, scal, pts, cnt);                      /* Π C_in · Π C_out^{q-1} · g^{q-fee} */
done:
    free(scal); free(pts);
    return rc;
}

int determ_ff_balance_prove(uint8_t proof[2 * E], const uint8_t E_in[E],
                            const uint8_t x[E], const uint8_t k[E]) {
    uint8_t h[E], T[E], c[E], cx[E], s[E], msg[2 * E];
    if (determ_ff_pedersen_generator_h(h) != 0) return -1;
    if (determ_ff_msm(T, k, h, 1) != 0) return -1;                 /* T = h^k (rejects k >= q) */
    memcpy(msg, E_in, E); memcpy(msg + E, T, E);
    if (determ_ff_hash_to_scalar(c, msg, 2 * E, (const uint8_t *)BAL_CDST, sizeof(BAL_CDST) - 1) != 0) return -1;
    if (determ_ff_scalar_mul(cx, c, x) != 0) return -1;            /* c*x (rejects x >= q) */
    if (determ_ff_scalar_add(s, k, cx) != 0) return -1;            /* s = k + c*x (rejects k >= q) */
    memcpy(proof, T, E); memcpy(proof + E, s, E);
    return 0;
}

int determ_ff_balance_verify(const uint8_t E_in[E], const uint8_t proof[2 * E]) {
    const uint8_t *T = proof, *s = proof + E;
    uint8_t h[E], c[E], lhs[E], rhs[E], one[E], msg[2 * E], sc2[2 * E], pt2[2 * E];
    if (determ_ff_pedersen_generator_h(h) != 0) return -1;
    memcpy(msg, E_in, E); memcpy(msg + E, T, E);
    if (determ_ff_hash_to_scalar(c, msg, 2 * E, (const uint8_t *)BAL_CDST, sizeof(BAL_CDST) - 1) != 0) return -1;
    if (determ_ff_msm(lhs, s, h, 1) != 0) return -1;               /* h^s (rejects malformed s >= q) */
    sc_one(one);
    memcpy(sc2, one, E); memcpy(sc2 + E, c, E);
    memcpy(pt2, T, E);   memcpy(pt2 + E, E_in, E);
    if (determ_ff_msm(rhs, sc2, pt2, 2) != 0) return -1;           /* T · E^c (rejects malformed T / E) */
    return (memcmp(lhs, rhs, E) == 0) ? 0 : -1;
}
