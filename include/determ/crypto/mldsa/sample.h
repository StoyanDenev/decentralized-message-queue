/* ML-DSA (FIPS 204) rejection samplers — the FIRST consumers of the SHAKE XOF.
 *
 * These turn a SHAKE stream (CRYPTO-C99-SPEC §3.17) into ring elements, the step
 * that couples the SHA-3 module into ML-DSA:
 *   - sample_uniform  (RejNTTPoly / the per-poly core of ExpandA): SHAKE128 →
 *     coefficients uniform in [0, q), the public matrix Â.
 *   - sample_eta      (RejBoundedPoly / ExpandS): SHAKE256 → coefficients in
 *     [-η, η], the secret vectors s1, s2 (η ∈ {2, 4}, a runtime argument).
 *   - sample_in_ball  (SampleInBall): SHAKE256 → the challenge polynomial with
 *     exactly τ coefficients in {-1, +1} and the rest 0 (τ a runtime argument).
 *
 * The caller supplies the already-domain-separated seed (ExpandA builds ρ‖s‖r,
 * ExpandS builds ρ'‖nonce, etc. at the matrix/vector layer — a later increment);
 * these primitives just map seed → polynomial. Rejection sampling has a
 * data-dependent LOOP COUNT (as in the canonical Dilithium reference — NOT
 * constant-time in the number of SHAKE bytes consumed); the coefficient values
 * are computed branchlessly. See src/crypto/mldsa/sample.c and the module README.
 */
#ifndef DETERM_CRYPTO_MLDSA_SAMPLE_H
#define DETERM_CRYPTO_MLDSA_SAMPLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Uniform in [0,q): SHAKE128(seed), 3-byte → 23-bit candidate, accept if < q. */
void determ_mldsa_sample_uniform(int32_t a[256], const uint8_t* seed, size_t seedlen);

/* Bounded in [-eta,eta]: SHAKE256(seed), 4-bit candidates. eta must be 2 or 4. */
void determ_mldsa_sample_eta(int32_t a[256], const uint8_t* seed, size_t seedlen, int eta);

/* Challenge: SHAKE256(seed) → exactly `tau` coefficients in {-1,+1}, rest 0
 * (Fisher-Yates over rejection-sampled positions; the first 8 squeezed bytes are
 * the sign field). tau in [0,256]. */
void determ_mldsa_sample_in_ball(int32_t c[256], const uint8_t* seed, size_t seedlen, int tau);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_SAMPLE_H */
