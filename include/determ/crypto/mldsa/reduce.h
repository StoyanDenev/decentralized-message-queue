/* ML-DSA (FIPS 204) modular reduction primitives over Z_q, q = 8380417.
 * Canonical Dilithium reference construction; see src/crypto/mldsa/reduce.c
 * and src/crypto/mldsa/README.md. Constant-time: no secret-dependent branch. */
#ifndef DETERM_CRYPTO_MLDSA_REDUCE_H
#define DETERM_CRYPTO_MLDSA_REDUCE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Montgomery reduction: given a with |a| < q * 2^31, returns t ≡ a * 2^{-32}
 * (mod q) with -q < t < q. This is how a product of two coefficients is brought
 * back into range (the multiplicand carrying an extra 2^32 Montgomery factor). */
int32_t determ_mldsa_montgomery_reduce(int64_t a);

/* Barrett reduction: for any int32 a, returns t ≡ a (mod q) with
 * -6283009 < t < 6283009 (a centered near-canonical representative). */
int32_t determ_mldsa_reduce32(int32_t a);

/* Conditional add q: maps a ∈ (-q, q) to its non-negative representative
 * [0, q) by adding q iff a < 0. Branchless (uses the sign bit). */
int32_t determ_mldsa_caddq(int32_t a);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_REDUCE_H */
