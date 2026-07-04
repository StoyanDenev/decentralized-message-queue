/* ML-DSA (FIPS 204) per-polynomial ring arithmetic in R_q = Z_q[X]/(X^256+1).
 *
 * The element-wise operations keygen/sign/verify compose over the NTT + samplers:
 * add/sub (e.g. A·s1 + s2, A·z − c·t1·2^d), reduce/caddq (bring coefficients back
 * into range / to non-negative), and pointwise Montgomery multiply (the per-poly
 * step of a matrix·vector product once both operands are in the NTT domain).
 * A `poly` is simply an int32_t[256]; the forward/inverse NTT are
 * `determ_mldsa_ntt` / `determ_mldsa_invntt_tomont` (ntt.h). Data-independent
 * (no secret-dependent branch/index). See src/crypto/mldsa/poly.c + the README.
 */
#ifndef DETERM_CRYPTO_MLDSA_POLY_H
#define DETERM_CRYPTO_MLDSA_POLY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* c = a + b, c = a - b (coefficient-wise, no reduction). c may alias a or b. */
void determ_mldsa_poly_add(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void determ_mldsa_poly_sub(int32_t c[256], const int32_t a[256], const int32_t b[256]);

/* In-place Barrett reduce to a centered near-canonical representative; and
 * conditional-add-q to the non-negative representative [0, q). */
void determ_mldsa_poly_reduce(int32_t a[256]);
void determ_mldsa_poly_caddq(int32_t a[256]);

/* c[i] = montgomery_reduce(a[i] * b[i]): the per-coefficient product in the NTT
 * domain (one operand carries an extra 2^32 Montgomery factor, which this removes). */
void determ_mldsa_poly_pointwise_montgomery(int32_t c[256], const int32_t a[256], const int32_t b[256]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_POLY_H */
