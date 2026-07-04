/* ML-DSA (FIPS 204) number-theoretic transform over Z_q[X]/(X^256 + 1).
 *
 * The negacyclic NTT diagonalizes polynomial multiplication in the ring: a
 * length-256 negacyclic convolution (the ring product) becomes 256 independent
 * coefficient multiplications in the NTT domain, turning an O(n^2) multiply into
 * O(n log n). ML-DSA does all of its matrix/vector polynomial arithmetic here.
 *
 * Canonical Dilithium reference construction (Cooley-Tukey forward, Gentleman-
 * Sande inverse) over the 256 precomputed twiddle factors in zetas.inc. The
 * transform is exact and data-independent (constant-time). See
 * src/crypto/mldsa/ntt.c and src/crypto/mldsa/README.md.
 */
#ifndef DETERM_CRYPTO_MLDSA_NTT_H
#define DETERM_CRYPTO_MLDSA_NTT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward NTT, in place. Input: standard-domain coefficients a[256] (may be any
 * int32 with |a[i]| bounded so intermediates stay < 2^31·q). Output: the NTT of
 * a, in the standard domain (the Montgomery factor carried by the twiddle
 * factors is removed by montgomery_reduce inside each butterfly). */
void determ_mldsa_ntt(int32_t a[256]);

/* Inverse NTT with a Montgomery factor, in place: computes 2^32 · NTT^{-1}(a).
 * Composed with the standard forward NTT it satisfies
 *   invntt_tomont(ntt(a))[i] ≡ a[i] · 2^32 (mod q),
 * and for pointwise Montgomery-multiplied spectra it yields the ring product in
 * the standard domain — see the module's KAT self-test (test-mldsa-c99). */
void determ_mldsa_invntt_tomont(int32_t a[256]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_NTT_H */
