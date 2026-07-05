/* Determ C99-native Bulletproofs single-value RANGE PROOF over NIST P-256 —
 * CRYPTO-C99-SPEC.md §3.19 increment 5. Proves that a Pedersen-committed value v
 * lies in [0, 2^n) WITHOUT revealing v, in 2*log2(n) + O(1) group elements.
 *
 * The value commitment is the §3.19 inc.1 Pedersen commitment V = v*g + gamma*h
 * (g = the P-256 base point, h = the nothing-up-my-sleeve scalar generator). The
 * bit-vector commitments A, S live over the inc.2 generator families g_i / h_i;
 * the log-size compression of the final <l, r> = t_hat check is the inc.4
 * inner-product argument, run over (g_i, h'_i = y^-i * h_i, u). Non-interactive
 * via a deterministic Fiat-Shamir transcript (label "DETERM-BP-RANGE-v1").
 *
 * Built ENTIRELY on the §3.19 inc.1-4 + §3.8c P-256 primitives; the only new
 * scalar arithmetic is a modular add/sub. LIBRARY PRIMITIVE — no chain call site.
 * Scalars are 32-byte big-endian < n_order; points are 33-byte SEC1 compressed.
 */
#ifndef DETERM_CRYPTO_RANGEPROOF_H
#define DETERM_CRYPTO_RANGEPROOF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest supported bit width (a value fits a uint64_t). n must additionally be a
 * power of two: {1,2,4,8,16,32,64}. */
#define DETERM_RANGEPROOF_MAX_BITS 64

/* Byte length of a range proof for bit width n:
 *   A|S|T1|T2 (4*33) + taux|mu|t_hat (3*32) + the IPA proof (66*log2(n)+64)
 *   = 228 + determ_ipa_proof_len(n).
 * 0 if n is not a supported power of two in [1, DETERM_RANGEPROOF_MAX_BITS]. */
size_t determ_rangeproof_proof_len(size_t n);

/* Prove that v in [0, 2^n). Writes the value commitment V = v*g + gamma*h to
 * V_out[33] and `determ_rangeproof_proof_len(n)` bytes to `proof`.
 *
 * The prover randomness is supplied by the caller for reproducibility (a real
 * prover draws these from a CSPRNG): alpha, rho blind A, S; tau1, tau2 blind the
 * polynomial commitments T1, T2; sL, sR (each n consecutive 32-byte scalars) are
 * the blinding vectors. All 32-byte big-endian < n_order.
 *
 * Returns 0, or -1 on a bad n / invalid scalar / a (negligible) identity
 * intermediate. Deterministic in (v, gamma, alpha, rho, tau1, tau2, sL, sR). */
int determ_rangeproof_prove(uint8_t V_out[33], uint8_t *proof,
                            uint64_t v, const uint8_t gamma[32],
                            const uint8_t alpha[32], const uint8_t rho[32],
                            const uint8_t tau1[32], const uint8_t tau2[32],
                            const uint8_t *sL, const uint8_t *sR, size_t n);

/* Verify: 0 iff `proof` (of length determ_rangeproof_proof_len(n)) is a valid
 * range proof for the value commitment V33, -1 otherwise (including a malformed
 * proof / a value outside [0, 2^n) / bad n). Public-data operation — fail-closed
 * on any identity intermediate or decode failure. */
int determ_rangeproof_verify(const uint8_t V33[33],
                             const uint8_t *proof, size_t n);

/* ── §3.19 increment 6: the AGGREGATED range proof ───────────────────────────
 * Proves that m committed values v_0..v_{m-1} EACH lie in [0, 2^n) in ONE proof
 * of size 2*log2(m*n)+O(1) group elements (vs. m separate proofs). The m bit-
 * vectors are concatenated; value j's 2^n slot is scaled by z^(2+j) (0-indexed),
 * so m=1 recovers the single-value proof above. The final <l,r>=t_hat check is
 * compressed by the same inc.4 IPA over the m*n-wide generators.
 *
 * Constraints: n a per-value bit width <= DETERM_RANGEPROOF_MAX_BITS (64), m >= 1,
 * and m*n a power of two <= DETERM_IPA_MAX_N (256). Same wire convention. */

/* Byte length of an aggregated proof: 228 + determ_ipa_proof_len(m*n) (the header
 * A|S|T1|T2|taux|mu|t_hat + the IPA over m*n). 0 if (m,n) is invalid. (The m value
 * commitments V are a separate m*33-byte output, not part of `proof`.) */
size_t determ_agg_rangeproof_proof_len(size_t m, size_t n);

/* Prove that every v[j] in [0, 2^n) for j<m. Writes m compressed value commitments
 * V_j = v[j]*g + gamma[j]*h to V_out (m*33 bytes) and the proof. gamma is m
 * consecutive 32-byte scalars; sL, sR are each m*n consecutive 32-byte scalars;
 * alpha/rho/tau1/tau2 are single 32-byte scalars (caller-supplied randomness, as
 * in the single-value form). Returns 0, or -1 on bad (m,n) / invalid scalar / a
 * (negligible) identity intermediate. Deterministic. */
int determ_agg_rangeproof_prove(uint8_t *V_out, uint8_t *proof,
                                const uint64_t *v, const uint8_t *gamma,
                                const uint8_t alpha[32], const uint8_t rho[32],
                                const uint8_t tau1[32], const uint8_t tau2[32],
                                const uint8_t *sL, const uint8_t *sR,
                                size_t m, size_t n);

/* Verify: 0 iff `proof` is a valid aggregated range proof for the m value
 * commitments V (m*33 bytes), -1 otherwise (malformed / any v[j] out of range /
 * bad (m,n)). Fail-closed. A single out-of-range value in the batch rejects. */
int determ_agg_rangeproof_verify(const uint8_t *V, const uint8_t *proof,
                                 size_t m, size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_RANGEPROOF_H */
