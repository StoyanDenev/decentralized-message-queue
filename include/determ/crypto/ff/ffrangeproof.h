/* Determ C99-native Bulletproofs single-value RANGE PROOF over Z_p* —
 * CRYPTO-C99-SPEC.md §3.20 increment 5. The MODERN-profile (large-prime) mirror of the
 * §3.19 P-256 range proof (include/determ/crypto/pedersen/rangeproof.h). Proves that a
 * Pedersen-committed value v lies in [0, 2^n) WITHOUT revealing v, in 2*log2(n) + O(1)
 * group elements.
 *
 * Value commitment V = g^v * h^gamma mod p (g = 4, the §3.20 inc.1 value generator;
 * h = the inc.1 nothing-up-my-sleeve blinding generator). Bit-vector commitments A, S
 * live over the inc.2 generator families G_i / H_i; the log-size compression of the
 * <l,r> = t_hat check is the inc.4 IPA over (G_i, h'_i = y^-i * H_i, u). Non-interactive
 * via a deterministic Fiat-Shamir transcript (label "DETERM-FF-BP-RANGE-v1").
 *
 * Built ENTIRELY on the §3.20 inc.1-4 primitives (group ops + scalar field + IPA).
 * LIBRARY PRIMITIVE — no chain call site. NOT constant-time (owner-gated). All group
 * elements AND scalars are 384-byte big-endian; scalars are reduced mod q.
 */
#ifndef DETERM_CRYPTO_FFRANGEPROOF_H
#define DETERM_CRYPTO_FFRANGEPROOF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest supported bit width (a value fits a uint64_t). n must additionally be a
 * power of two: {1,2,4,8,16,32,64}. (The 3072-bit modexp is ~1700x slower than the
 * P-256 range proof, so large n is expensive.) */
#define DETERM_FF_RANGEPROOF_MAX_BITS 64

/* Byte length of a range proof for bit width n:
 *   A|S|T1|T2 (4*384) + taux|mu|t_hat (3*384) + the IPA (determ_ff_ipa_proof_len(n))
 *   = 2688 + determ_ff_ipa_proof_len(n). 0 if n is not a supported power of two. */
size_t determ_ff_rangeproof_proof_len(size_t n);

/* Prove that v in [0, 2^n). Writes V = g^v * h^gamma to V_out[384] and
 * `determ_ff_rangeproof_proof_len(n)` bytes to `proof`. The prover randomness
 * (gamma, alpha, rho, tau1, tau2, sL, sR) is caller-supplied for reproducibility (a
 * real prover draws it from a CSPRNG); sL, sR are each n consecutive 384-byte scalars.
 * All 384-byte big-endian < q. Returns 0, or -1 on a bad n / invalid scalar / OOM.
 * Deterministic in the inputs. */
int determ_ff_rangeproof_prove(uint8_t V_out[384], uint8_t *proof, uint64_t v,
                               const uint8_t gamma[384], const uint8_t alpha[384],
                               const uint8_t rho[384], const uint8_t tau1[384],
                               const uint8_t tau2[384], const uint8_t *sL,
                               const uint8_t *sR, size_t n);

/* Verify: 0 iff `proof` (of length determ_ff_rangeproof_proof_len(n)) is a valid range
 * proof for the value commitment V, -1 otherwise (malformed proof / v outside [0,2^n) /
 * bad n / OOM). Public-data operation, fail-closed. */
int determ_ff_rangeproof_verify(const uint8_t V[384], const uint8_t *proof, size_t n);

/* ── §3.20 increment 6: the AGGREGATED range proof (m values, one proof) ──────
 * Proves that m committed values v_0..v_{m-1} EACH lie in [0, 2^n) in ONE proof of size
 * 2*log2(m*n)+O(1) group elements. The m bit-vectors are concatenated; value j's 2^n
 * slot is scaled by z^(2+j), so m=1 recovers the single-value proof. Transcript
 * "DETERM-FF-BP-AGGRANGE-v1". Constraints: n <= DETERM_FF_RANGEPROOF_MAX_BITS (64),
 * m >= 1, m*n a power of two <= 256. Same 384-byte big-endian wire convention. */

/* Byte length of an aggregated proof: 2688 + determ_ff_ipa_proof_len(m*n). 0 if (m,n) is
 * invalid. (The m value commitments V are a separate m*384-byte output, not in `proof`.) */
size_t determ_ff_agg_rangeproof_proof_len(size_t m, size_t n);

/* Prove that every v[j] in [0, 2^n) for j<m. Writes m compressed value commitments
 * V_j = g^{v[j]}*h^{gamma[j]} to V_out (m*384 bytes) and the proof. gamma is m
 * consecutive 384-byte scalars; sL, sR are each m*n consecutive 384-byte scalars;
 * alpha/rho/tau1/tau2 are single 384-byte scalars (caller-supplied randomness). Returns
 * 0, or -1 on bad (m,n) / invalid scalar / OOM. Deterministic. */
int determ_ff_agg_rangeproof_prove(uint8_t *V_out, uint8_t *proof,
                                   const uint64_t *v, const uint8_t *gamma,
                                   const uint8_t alpha[384], const uint8_t rho[384],
                                   const uint8_t tau1[384], const uint8_t tau2[384],
                                   const uint8_t *sL, const uint8_t *sR, size_t m, size_t n);

/* Verify: 0 iff `proof` is a valid aggregated range proof for the m value commitments V
 * (m*384 bytes), -1 otherwise (malformed / any v[j] out of range / bad (m,n) / OOM).
 * Fail-closed. A single out-of-range value in the batch rejects. */
int determ_ff_agg_rangeproof_verify(const uint8_t *V, const uint8_t *proof, size_t m, size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FFRANGEPROOF_H */
