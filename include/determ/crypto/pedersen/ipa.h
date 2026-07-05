/* Determ C99-native Bulletproofs inner-product argument (IPA) over NIST P-256 —
 * CRYPTO-C99-SPEC.md §3.19 increment 4. The range-proof track's log-size core:
 * a proof of knowledge of vectors a, b with
 *
 *      P = <a, g> + <b, h> + <a,b>*u
 *
 * for public generator vectors g, h, a point u, and a commitment P — of size
 * 2*log2(n) points + 2 scalars instead of the trivial 2n. Non-interactive via a
 * deterministic Fiat-Shamir transcript (SHA-256/RFC-9380 hash-to-scalar over the
 * absorbed statement + L/R messages). Built ENTIRELY on the §3.19 / §3.8c
 * primitives (pedersen_gen / pedersen_msm / p256 point+scalar ops); introduces no
 * new group arithmetic. LIBRARY PRIMITIVE — no chain call site.
 *
 * Generators are fixed by the ciphersuite (so prover and verifier agree without
 * transmitting them): g_i = pedersen_gen(i, 0), h_i = pedersen_gen(i, 1), and
 * u = pedersen_gen(0xFFFFFFFF, 0) (a nothing-up-my-sleeve point independent of
 * the g_i/h_i families). Scalars are 32-byte big-endian < n_order; points are
 * 33-byte SEC1 compressed.
 */
#ifndef DETERM_CRYPTO_IPA_H
#define DETERM_CRYPTO_IPA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest supported vector length (power of two). 256 => up to 8 fold rounds. */
#define DETERM_IPA_MAX_N 256

/* Byte length of a proof for vector length n: 66*log2(n) + 64
 * (L[log2 n] ‖ R[log2 n] ‖ a_final ‖ b_final). 0 if n is not a supported
 * power of two in [1, DETERM_IPA_MAX_N]. */
size_t determ_ipa_proof_len(size_t n);

/* The statement commitment P = <a, g> + <b, h> + <a,b>*u over the fixed
 * generators. a, b are each n consecutive 32-byte big-endian scalars (< n_order).
 * out33 = SEC1 compressed. Returns 0, or -1 on a bad n / invalid scalar / the
 * (negligible) identity result. */
int determ_ipa_commit(uint8_t out33[33],
                      const uint8_t *a, const uint8_t *b, size_t n);

/* Prove: write `determ_ipa_proof_len(n)` bytes to `proof`. a, b are the witness
 * vectors (n scalars each); P33 is the commitment (typically from
 * determ_ipa_commit). Returns 0, or -1 on a bad n / invalid input / a
 * (negligible) identity intermediate. Deterministic. */
int determ_ipa_prove(uint8_t *proof,
                     const uint8_t *a, const uint8_t *b,
                     const uint8_t P33[33], size_t n);

/* Verify: 0 iff `proof` (of length determ_ipa_proof_len(n)) is a valid IPA for
 * the commitment P33 under the fixed generators, -1 otherwise (including a
 * malformed proof / bad n). Public-data operation. */
int determ_ipa_verify(const uint8_t P33[33],
                      const uint8_t *proof, size_t n);

/* Generator-supplied variants: the same protocol, but the caller provides the
 * generator vectors g, h (each n consecutive 33-byte SEC1 compressed points) and
 * the inner-product generator u33. The fixed-generator determ_ipa_prove/_verify
 * above are exactly the special case g_i = pedersen_gen(i,0),
 * h_i = pedersen_gen(i,1), u = pedersen_gen(0xFFFFFFFF,0). The §3.19 inc.5
 * Bulletproofs range proof uses these with a y-rescaled h family (h'_i =
 * y^-i * h_i). Same contract/return codes as the fixed-generator forms. */
int determ_ipa_prove_gens(uint8_t *proof, const uint8_t *a, const uint8_t *b,
                          const uint8_t *g, const uint8_t *h, const uint8_t u33[33],
                          const uint8_t P33[33], size_t n);
int determ_ipa_verify_gens(const uint8_t P33[33], const uint8_t *proof,
                           const uint8_t *g, const uint8_t *h, const uint8_t u33[33],
                           size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_IPA_H */
