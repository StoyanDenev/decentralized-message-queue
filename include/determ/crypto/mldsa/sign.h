/* ML-DSA (FIPS 204) signing + verification — Sign_internal (Alg 7) and
 * Verify_internal (Alg 8), the Fiat-Shamir-with-aborts top level that assembles
 * the increment 1-7 building blocks (NTT, samplers, rounding/hint, packing, the
 * matrix/vector layer, keygen's decoders).
 *
 * Sign is deterministic in (sk, M', rnd): passing a 32-byte all-zero rnd gives the
 * FIPS 204 "deterministic" variant used by the ACVP sigGen KATs (byte-reproducible);
 * a random rnd gives the "hedged" variant. Verify returns a boolean. The message
 * input M' is the already-formatted message — for the pure external interface,
 * M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M (see determ_mldsa_format_message). Pinned
 * byte-for-byte against the NIST ACVP sigGen/sigVer KATs. See
 * src/crypto/mldsa/sign.c + the module README.
 */
#ifndef DETERM_CRYPTO_MLDSA_SIGN_H
#define DETERM_CRYPTO_MLDSA_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <determ/crypto/mldsa/keygen.h>   /* determ_mldsa_params */

#ifdef __cplusplus
extern "C" {
#endif

/* Encoded signature size: λ/4 (c̃) + l·(γ1-packed z) + (ω+k) (hint).
 * (44: 2420, 65: 3309, 87: 4627.) */
size_t determ_mldsa_sig_bytes(const determ_mldsa_params* p);

/* ML-DSA.Sign_internal(sk, M', rnd): write the encoded signature to `sig`
 * (determ_mldsa_sig_bytes(p) bytes). `rnd` is 32 bytes (all-zero → deterministic
 * variant). Returns 0 on success; nonzero on bad params or if the rejection loop
 * exceeds its safety cap (never expected for a valid sk). */
int determ_mldsa_sign(const determ_mldsa_params* p, const uint8_t* sk,
                      const uint8_t* mprime, size_t mlen,
                      const uint8_t rnd[32], uint8_t* sig);

/* ML-DSA.Verify_internal(pk, M', σ): returns 1 iff σ is a valid signature of M'
 * under pk, else 0 (including malformed σ / out-of-range z / bad hint). */
int determ_mldsa_verify(const determ_mldsa_params* p, const uint8_t* pk,
                        const uint8_t* mprime, size_t mlen, const uint8_t* sig);

/* Format a message for the pure external interface (no prehash):
 * M' = IntegerToBytes(0,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ M. `out` needs
 * 2 + ctxlen + mlen bytes. Returns the written length, or 0 if ctxlen > 255. */
size_t determ_mldsa_format_message(uint8_t* out, const uint8_t* ctx, size_t ctxlen,
                                   const uint8_t* msg, size_t mlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_SIGN_H */
