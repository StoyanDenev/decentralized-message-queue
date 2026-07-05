/* Determ C99-native Bulletproofs inner-product argument (IPA) over Z_p* —
 * CRYPTO-C99-SPEC.md §3.20 increment 4. The MODERN-profile (large-prime) mirror of
 * the §3.19 P-256 IPA (include/determ/crypto/pedersen/ipa.h). A proof of knowledge of
 * vectors a, b with the commitment
 *
 *      P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>}   (mod p, in the order-q subgroup G_q)
 *
 * of size 2·log2(n) group elements + 2 scalars instead of the trivial 2n. Non-
 * interactive via a deterministic Fiat-Shamir transcript (the §3.20 inc.3
 * hash-to-scalar mod q over the absorbed statement + L/R messages). Built ENTIRELY on
 * the §3.20 group ops (determ_ff_msm / determ_ff_gen) and scalar field
 * (determ_ff_scalar_* / determ_ff_hash_to_scalar); introduces no new arithmetic.
 * LIBRARY PRIMITIVE — no chain call site. NOT constant-time (owner-gated).
 *
 * Generators are fixed by the ciphersuite (so prover and verifier agree without
 * transmitting them): g_i = determ_ff_gen(i, 0), h_i = determ_ff_gen(i, 1), and
 * u = determ_ff_gen(0xFFFFFFFF, 0). Group elements AND scalars are 384-byte
 * (3072-bit) BIG-ENDIAN; scalars are reduced mod q.
 */
#ifndef DETERM_CRYPTO_FFIPA_H
#define DETERM_CRYPTO_FFIPA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest supported vector length (power of two). 256 => up to 8 fold rounds. */
#define DETERM_FF_IPA_MAX_N 256

/* Byte length of a proof for vector length n: (2*log2(n) + 2) * 384
 * (L[log2 n] ‖ R[log2 n] ‖ a_final ‖ b_final). 0 if n is not a supported power of
 * two in [1, DETERM_FF_IPA_MAX_N]. */
size_t determ_ff_ipa_proof_len(size_t n);

/* The statement commitment P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>} mod p over the
 * fixed generators. a, b are each n consecutive 384-byte big-endian scalars (< q).
 * out is 384-byte big-endian. Returns 0, or -1 on a bad n / invalid scalar / OOM. */
int determ_ff_ipa_commit(uint8_t out[384],
                         const uint8_t *a, const uint8_t *b, size_t n);

/* Prove: write `determ_ff_ipa_proof_len(n)` bytes to `proof`. a, b are the witness
 * vectors (n scalars each, < q); P is the commitment (typically from
 * determ_ff_ipa_commit). Returns 0, or -1 on a bad n / invalid input / OOM.
 * Deterministic. */
int determ_ff_ipa_prove(uint8_t *proof,
                        const uint8_t *a, const uint8_t *b,
                        const uint8_t P[384], size_t n);

/* Verify: 0 iff `proof` (of length determ_ff_ipa_proof_len(n)) is a valid IPA for the
 * commitment P under the fixed generators, -1 otherwise (including a malformed proof /
 * bad n / OOM). Public-data operation. */
int determ_ff_ipa_verify(const uint8_t P[384],
                         const uint8_t *proof, size_t n);

/* Generator-supplied variants: the same protocol, but the caller provides the
 * generator vectors g, h (each n consecutive 384-byte elements) and the inner-product
 * generator u. The fixed-generator forms above are the special case
 * g_i = determ_ff_gen(i,0), h_i = determ_ff_gen(i,1), u = determ_ff_gen(0xFFFFFFFF,0).
 * The §3.20 range proof (a later increment) uses these with a y-rescaled h family.
 * Same contract/return codes as the fixed-generator forms. */
int determ_ff_ipa_prove_gens(uint8_t *proof, const uint8_t *a, const uint8_t *b,
                             const uint8_t *g, const uint8_t *h, const uint8_t u[384],
                             const uint8_t P[384], size_t n);
int determ_ff_ipa_verify_gens(const uint8_t P[384], const uint8_t *proof,
                              const uint8_t *g, const uint8_t *h, const uint8_t u[384],
                              size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FFIPA_H */
