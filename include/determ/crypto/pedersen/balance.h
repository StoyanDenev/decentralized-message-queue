#ifndef DETERM_CRYPTO_PEDERSEN_BALANCE_H
#define DETERM_CRYPTO_PEDERSEN_BALANCE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CRYPTO-C99-SPEC.md §3.19 increment 7 — confidential-tx BALANCE PROOF over NIST P-256.
 * The amount-conservation half of a confidential transaction (the §3.19 inc.5/6 range proofs are the
 * no-inflation half): proves Σ v_in = Σ v_out + fee WITHOUT revealing any amount, given
 * Pedersen commitments C = v*G + r*H (G the P-256 base point / value generator, H the
 * §3.19 nothing-up-my-sleeve blinding generator).
 *
 * A transaction balances iff the excess E = Σ C_in − Σ C_out − fee*G has no G-component,
 * i.e. E = x*H for the blinding excess x = (Σ r_in − Σ r_out) mod n. The prover proves
 * knowledge of x with a Schnorr proof of discrete log base H (E = x*H); since log_G(H) is
 * unknown, E = x*H forces the G-coefficient (Σv_in − Σv_out − fee) to zero.
 *
 * Built entirely on the PUBLIC §3.19 pedersen (commit/msm) + §3.8c/§3.9b P-256
 * (params/hash_to_scalar/scalar_mul_mod_n) APIs — the two point subtractions are scalar
 * negations in the exponent (−C = (n−1)*C, −fee*G = (n−fee)*G) so the excess is one
 * multi-exponentiation, no point-negation primitive; the only local arithmetic is a
 * 256-bit add-mod-n / negate-mod-n over the exported curve order (NO change to the sealed
 * p256 core). NOT constant-time (the modexp/MSM branch on secret scalars — owner-gated). */

#define DETERM_P256_BALANCE_PROOF_BYTES 65   /* compress(T) 33 + s 32 */

/* E = Σ C_in − Σ C_out − fee*G, written SEC1-compressed to E_out[33]. C_in / C_out are
 * n_in / n_out consecutive 33-byte compressed commitments; fee is a public uint64.
 * Returns 0 (E is a non-identity point — the normal case), 1 (E is the group identity —
 * the degenerate x==0 case, which has no compressed encoding and cannot be proven), or
 * -1 (a commitment fails to decode / an internal scalar is out of range). */
int determ_p256_balance_excess(uint8_t E_out[33],
                               const uint8_t *C_in, size_t n_in,
                               const uint8_t *C_out, size_t n_out, uint64_t fee);

/* Schnorr PoK that E = x*H: T = k*H ; c = hash_to_scalar(E ‖ T) ; s = k + c*x mod n.
 * Writes DETERM_P256_BALANCE_PROOF_BYTES to proof = compress(T) ‖ s. x, k are 32-byte
 * big-endian scalars in [0, n); k must be non-zero (T = k*H must not be the identity).
 * Returns 0, or -1 (invalid scalar / decode failure / identity T). Deterministic. */
int determ_p256_balance_prove(uint8_t proof[65], const uint8_t E_in[33],
                              const uint8_t x[32], const uint8_t k[32]);

/* Verify: 0 iff s*H == T + c*E, -1 otherwise (malformed proof / E, or the equation
 * fails). Public-data operation, fail-closed. */
int determ_p256_balance_verify(const uint8_t E_in[33], const uint8_t proof[65]);

/* CRYPTO-C99-SPEC.md §3.22b — CONTEXT-BOUND balance proof. Identical to the pair
 * above EXCEPT the Fiat-Shamir challenge binds an extra 32-byte context digest:
 *   c = hash_to_scalar(E ‖ T ‖ ctx32)   (vs ‖ E ‖ T only).
 * This binds the PoK-of-blinding to a caller-chosen context so a captured proof
 * cannot be replayed against a DIFFERENT context. The shielded-pool UNSHIELD
 * spend sets ctx32 = SHA-256(from ‖ to ‖ nonce ‖ amount) so a mempool-observed
 * withdraw proof cannot be copied and redirected to another recipient (front-
 * running theft). A bound proof does NOT verify under the unbound verifier and
 * vice-versa (domain separation), and a proof bound to ctx A is rejected under
 * ctx B. Same 65-byte wire, same x/k rules, deterministic. Returns 0 / -1. */
int determ_p256_balance_prove_bound(uint8_t proof[65], const uint8_t E_in[33],
                                    const uint8_t x[32], const uint8_t k[32],
                                    const uint8_t ctx32[32]);

int determ_p256_balance_verify_bound(const uint8_t E_in[33], const uint8_t proof[65],
                                     const uint8_t ctx32[32]);

/* CRYPTO-C99-SPEC.md §3.22c helper — the BLINDING EXCESS scalar for a
 * confidential transfer's balance proof: x = (Σ r_in − Σ r_out) mod n. When the
 * amounts balance (Σ v_in = Σ v_out + fee), x IS the discrete log base H of the
 * point excess E = Σ C_in − Σ C_out − fee·G (from determ_p256_balance_excess),
 * so a confidential-tx builder computes x with this, then proves E = x·H via
 * determ_p256_balance_prove. r_in / r_out are n_in / n_out consecutive 32-byte
 * blinding scalars, each canonical in [0, n) (e.g. from determ_p256_hash_to_scalar).
 * Writes x to x_out[32]. Returns 0 (x != 0, the normal case), 1 (x == 0 — the
 * excess is zero, so E is the group identity and the tx cannot be balance-proven;
 * pick blindings so it is nonzero), or -1 on n_in == 0 / NULL r_in. This is the
 * ONLY blinding arithmetic a builder needs; it reuses balance.c's internal
 * add-mod-n / negate-mod-n and touches NO sealed core. Deterministic. */
int determ_p256_balance_blinding_excess(uint8_t x_out[32],
                                        const uint8_t *r_in,  size_t n_in,
                                        const uint8_t *r_out, size_t n_out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_PEDERSEN_BALANCE_H */
