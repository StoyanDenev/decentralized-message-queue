/* ML-DSA (FIPS 204) coefficient rounding + hint primitives over Z_q.
 *
 * The rounding layer that keygen and sign/verify sit on:
 *   - power2round splits a coefficient t = t1*2^D + t0 (public high part t1 goes
 *     in the public key; t0 stays secret) — used in KEY GENERATION.
 *   - decompose splits a = a1*(2*GAMMA2) + a0 into high/low parts around the
 *     GAMMA2 grid — the HighBits/LowBits of SIGNING.
 *   - make_hint / use_hint carry a 1-bit-per-coefficient hint so the verifier
 *     can recover HighBits(w) without the full low part — the signature's `h`.
 *
 * Canonical Dilithium reference construction; branchless / data-independent (the
 * arithmetic-shift sign tricks are implementation-defined, not UB — the repo's
 * UBSan discipline). gamma2 is a runtime argument so one core serves ML-DSA-44
 * (GAMMA2_88) and ML-DSA-65/87 (GAMMA2_32). See src/crypto/mldsa/rounding.c and
 * src/crypto/mldsa/README.md.
 */
#ifndef DETERM_CRYPTO_MLDSA_ROUNDING_H
#define DETERM_CRYPTO_MLDSA_ROUNDING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a = a1*2^D + a0 with -2^(D-1) < a0 <= 2^(D-1). Returns a1, writes a0. */
int32_t determ_mldsa_power2round(int32_t a, int32_t* a0);

/* a ≡ a1*(2*gamma2) + a0 (mod q) with -gamma2 <= a0 <= gamma2 and a1 in
 * [0, (q-1)/(2*gamma2)). gamma2 must be DETERM_MLDSA_GAMMA2_32 or _88.
 * Returns a1 (HighBits), writes a0 (LowBits). */
int32_t determ_mldsa_decompose(int32_t a, int32_t* a0, int32_t gamma2);

/* Hint bit: 1 iff the low part a0 (from decompose) forces a carry into the high
 * part — i.e. |a0| > gamma2, or a0 == -gamma2 with a1 != 0. */
unsigned int determ_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2);

/* Corrected high part: decompose(a).a1, adjusted by ±1 (mod the bucket count)
 * when hint != 0. Recovers HighBits(a + z) for the hint that flags a boundary. */
int32_t determ_mldsa_use_hint(int32_t a, unsigned int hint, int32_t gamma2);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_ROUNDING_H */
