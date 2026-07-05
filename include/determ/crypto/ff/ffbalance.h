/* Determ C99-native CONFIDENTIAL-TX BALANCE PROOF over Z_p* — CRYPTO-C99-SPEC.md §3.20
 * increment 7. The amount-conservation half of a confidential transaction (the §3.20
 * inc.5/6 range proofs are the no-inflation half): proves Σ v_in = Σ v_out + fee WITHOUT
 * revealing any amount, given Pedersen commitments C = g^v * h^r mod p (g = 4, h the
 * inc.1 nothing-up-my-sleeve generator).
 *
 * The transaction balances iff the "excess"
 *     E = Π C_in * Π C_out^{-1} * g^{-fee}   (in the order-q subgroup G_q of Z_p*)
 * has NO g-component, i.e. E = h^{r_excess}. The prover proves knowledge of that
 * blinding excess with a Schnorr proof of discrete log base h (E = h^x). Because
 * log_g(h) is unknown, E = h^x is only possible when the g-exponent
 * (Σv_in − Σv_out − fee) is zero — hence balanced. Group-element inverses are scalar
 * negations in the exponent (C^{-1} = C^{q-1} in G_q, g^{-fee} = g^{q-fee}), so the
 * excess is one multi-exponentiation — no group-inverse primitive is required.
 *
 * Built ENTIRELY on the public §3.20 inc.1-3 primitives (determ_ff_msm /
 * determ_ff_scalar_* / determ_ff_hash_to_scalar / determ_ff_pedersen_generator_h).
 * LIBRARY PRIMITIVE — no chain call site. NOT constant-time (owner-gated). All
 * commitments and scalars are 384-byte big-endian; scalars are reduced mod q.
 */
#ifndef DETERM_CRYPTO_FFBALANCE_H
#define DETERM_CRYPTO_FFBALANCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Byte length of a balance proof: T ‖ s = 2 * 384. */
#define DETERM_FF_BALANCE_PROOF_BYTES 768

/* Compute the transaction excess E = Π C_in * Π C_out^{-1} * g^{-fee} mod p, via one
 * multi-exponentiation (C_out^{-1} = C^{q-1}, g^{-fee} = g^{(q-fee) mod q}). C_in / C_out
 * are n_in / n_out consecutive 384-byte commitments in G_q; fee is a public uint64
 * (< q). out E is 384-byte big-endian. Returns 0, or -1 on a malformed commitment /
 * OOM. n_in and/or n_out may be 0 (fee-only / no-output degenerate cases). */
int determ_ff_balance_excess(uint8_t E[384],
                             const uint8_t *C_in, size_t n_in,
                             const uint8_t *C_out, size_t n_out, uint64_t fee);

/* Prove knowledge of x with E = h^x (Schnorr PoK, the balance guarantee). T = h^k ;
 * c = hash_to_scalar(E ‖ T) ; s = k + c*x mod q. Writes DETERM_FF_BALANCE_PROOF_BYTES to
 * `proof` (T ‖ s). x is the blinding excess (Σr_in − Σr_out mod q); k is the caller-
 * supplied nonce (a real prover draws it from a CSPRNG). Both 384-byte big-endian < q.
 * Returns 0, or -1 on an invalid scalar / a (negligible) zero challenge. */
int determ_ff_balance_prove(uint8_t proof[768], const uint8_t E[384],
                            const uint8_t x[384], const uint8_t k[384]);

/* Verify: 0 iff `proof` is a valid balance proof for the excess E (i.e. h^s == T * E^c),
 * -1 otherwise (malformed proof / E not a commitment to zero / a wrong opening).
 * Public-data operation, fail-closed on a malformed T / E / s. */
int determ_ff_balance_verify(const uint8_t E[384], const uint8_t proof[768]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FFBALANCE_H */
