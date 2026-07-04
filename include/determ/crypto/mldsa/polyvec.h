/* ML-DSA (FIPS 204) matrix / vector layer — the domain-separated seed expansion
 * and the vector-of-polynomials arithmetic that keygen/sign/verify are written in.
 *
 * A poly is an int32_t[256]; a poly VECTOR is a contiguous run of those, passed as
 * `int32_t v[][256]` plus a length. The k x l public matrix Â is stored row-major
 * (entry (i,j) at mat[i*l + j]). Every function here is a thin composition over the
 * already-gated primitives:
 *   - expand_a    (ExpandA):    Â[i][j] = sample_uniform(ρ ‖ j ‖ i)   — SHAKE128
 *   - expand_s    (ExpandS):    s1[i] = sample_eta(ρ' ‖ le16(i)),
 *                               s2[i] = sample_eta(ρ' ‖ le16(l+i))     — SHAKE256
 *   - expand_mask (ExpandMask): y[i]  = sample_gamma1(ρ' ‖ le16(l·κ+i))— SHAKE256
 * plus polyvec add/sub/reduce/caddq/ntt/invntt and the NTT-domain matrix·vector
 * product (t = Â·v̂, pointwise-Montgomery accumulate). Dimensions (k, l), η, and γ1
 * are RUNTIME arguments, so this one layer serves ML-DSA-44/65/87. Data-independent
 * except the samplers' inherited rejection-loop timing (see sample.h). See
 * src/crypto/mldsa/polyvec.c + the module README.
 */
#ifndef DETERM_CRYPTO_MLDSA_POLYVEC_H
#define DETERM_CRYPTO_MLDSA_POLYVEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ExpandA: build the k x l public matrix Â (NTT-domain by construction — the
 * uniform samples ARE the NTT-domain coefficients). `mat` is row-major with room
 * for k*l polys: entry (i,j) at mat[i*l + j]. `rho` is 32 bytes. k∈[1,8], l∈[1,7];
 * out-of-range dims are a no-op (the buffer is left untouched). */
void determ_mldsa_expand_a(int32_t mat[][256], const uint8_t rho[32], int k, int l);

/* ExpandS: sample the secret vectors s1 (length l) and s2 (length k), coefficients
 * in [-eta, eta]. `rhoprime` is 64 bytes; s1 gets nonces 0..l-1, s2 gets l..l+k-1
 * (2-byte little-endian). eta must be 2 or 4 (else a no-op). */
void determ_mldsa_expand_s(int32_t s1[][256], int32_t s2[][256],
                           const uint8_t rhoprime[64], int k, int l, int eta);

/* ExpandMask: sample the masking vector y (length l), coefficients in (-gamma1,
 * gamma1]. `rhoprime` is 64 bytes, `kappa` the per-round counter; the i-th nonce is
 * l*kappa + i (2-byte little-endian). gamma1 must be 2^17 or 2^19 (else a no-op). */
void determ_mldsa_expand_mask(int32_t y[][256], const uint8_t rhoprime[64],
                              int kappa, int l, int32_t gamma1);

/* Element-wise vector arithmetic over `len` polynomials (each an int32_t[256]). */
void determ_mldsa_polyvec_ntt(int32_t v[][256], int len);
void determ_mldsa_polyvec_invntt_tomont(int32_t v[][256], int len);
void determ_mldsa_polyvec_reduce(int32_t v[][256], int len);
void determ_mldsa_polyvec_caddq(int32_t v[][256], int len);
void determ_mldsa_polyvec_add(int32_t w[][256], const int32_t u[][256],
                              const int32_t v[][256], int len);
void determ_mldsa_polyvec_sub(int32_t w[][256], const int32_t u[][256],
                              const int32_t v[][256], int len);

/* NTT-domain matrix·vector product: t = Â · v̂, where `mat` is the k x l row-major
 * matrix, `v` is length l, and `t` (length k) receives t[i] = Σ_j pointwise_
 * montgomery(mat[i*l+j], v[j]). All operands are in the NTT domain; the caller
 * runs invntt_tomont on `t` afterward. `t` must not alias `mat` or `v`. */
void determ_mldsa_polyvec_matrix_pointwise(int32_t t[][256], const int32_t mat[][256],
                                           const int32_t v[][256], int k, int l);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_POLYVEC_H */
