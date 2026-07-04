/* ML-DSA (FIPS 204) key generation — the first TOP-LEVEL operation, assembling
 * the increment 1-6 building blocks into ML-DSA.KeyGen_internal(ξ) (Algorithm 6).
 *
 * Flow (all over the already-gated primitives):
 *   (ρ, ρ', K) ← H(ξ ‖ IntegerToBytes(k,1) ‖ IntegerToBytes(l,1), 128)   [SHAKE256]
 *   Â ← ExpandA(ρ);  (s1, s2) ← ExpandS(ρ')
 *   t ← invNTT(Â ∘ NTT(s1)) + s2;  (t1, t0) ← Power2Round(t)
 *   pk ← pkEncode(ρ, t1);  tr ← H(pk, 64);  sk ← skEncode(ρ, K, tr, s1, s2, t0)
 *
 * Deterministic in the 32-byte seed ξ (no internal RNG — the caller supplies ξ,
 * exactly as the FIPS 204 ACVP KeyGen KATs do). The dimensions (k, l) and η come
 * from the parameter set, so the same code serves ML-DSA-44/65/87. Pinned
 * byte-for-byte against the NIST ACVP internalProjection.json vectors. See
 * src/crypto/mldsa/keygen.c + the module README.
 */
#ifndef DETERM_CRYPTO_MLDSA_KEYGEN_H
#define DETERM_CRYPTO_MLDSA_KEYGEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parameter set: matrix dimensions (k rows, l columns) + the secret bound η.
 * The other ML-DSA parameters (τ, γ1, γ2, β, ω) belong to sign/verify. */
typedef struct { int k; int l; int eta; } determ_mldsa_params;

/* The three FIPS 204 parameter sets. */
extern const determ_mldsa_params DETERM_MLDSA_44;  /* k=4, l=4, η=2 */
extern const determ_mldsa_params DETERM_MLDSA_65;  /* k=6, l=5, η=4 */
extern const determ_mldsa_params DETERM_MLDSA_87;  /* k=8, l=7, η=2 */

/* Encoded key sizes for a parameter set:
 *   pk = 32 (ρ) + k·320 (t1, 10-bit SimpleBitPack)
 *   sk = 128 (ρ‖K‖tr) + (l+k)·(η-packed) + k·416 (t0, 13-bit)
 * (44: 1312/2560, 65: 1952/4032, 87: 2592/4896). */
size_t determ_mldsa_pk_bytes(const determ_mldsa_params* p);
size_t determ_mldsa_sk_bytes(const determ_mldsa_params* p);

/* ML-DSA.KeyGen_internal(seed): write the encoded public key to `pk`
 * (determ_mldsa_pk_bytes(p) bytes) and the encoded secret key to `sk`
 * (determ_mldsa_sk_bytes(p) bytes). `seed` is the 32-byte ξ. Fail-closed: a null
 * param / out-of-range (k,l,eta) leaves the buffers untouched. */
void determ_mldsa_keygen(const determ_mldsa_params* p, const uint8_t seed[32],
                         uint8_t* pk, uint8_t* sk);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_KEYGEN_H */
