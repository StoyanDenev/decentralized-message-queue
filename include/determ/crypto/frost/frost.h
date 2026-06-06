/* Determ C99-native FROST-Ed25519 (RFC 9591) — threshold Schnorr signatures whose
 * aggregate is a plain Ed25519 signature under the group public key. This is the
 * v2.10 threshold-randomness primitive (CRYPTO-C99-SPEC §3.2, v2.10-DKG-SPEC).
 * Built on the constant-time C99 Ed25519 group/scalar primitives in
 * `include/determ/crypto/ed25519/ed25519_group.h` — no libsodium.
 *
 * This header currently covers the keygen pillar (trusted-dealer Shamir split over
 * the Ed25519 scalar field + Lagrange reconstruction); the two-round threshold
 * signing + aggregation lands on the same scalar/group base. Validated by
 * `determ test-frost-c99`.
 */
#ifndef DETERM_CRYPTO_FROST_H
#define DETERM_CRYPTO_FROST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Trusted-dealer key generation. Splits the scalar `secret` into `n` shares with
 * threshold `t` via a degree-(t-1) polynomial f with f(0) = secret and non-constant
 * coefficients a_1..a_{t-1} supplied in `coeffs` ((t-1)*32 bytes, each a scalar).
 * Writes:
 *   shares    : n*32 bytes — s_i = f(i) for participant indices i = 1..n
 *   group_pk  : 32 bytes   — [secret] B (the aggregate / group public key)
 *   share_pks : n*32 bytes — [s_i] B (per-participant public keys)
 * Any t shares reconstruct `secret`; any t-1 reveal nothing (Shamir).
 * Returns 0 on success, -1 on bad parameters (t<1, n<t, or n>255). */
int determ_frost_keygen_trusted(const uint8_t secret[32], const uint8_t *coeffs,
                                int t, int n,
                                uint8_t *shares, uint8_t group_pk[32],
                                uint8_t *share_pks);

/* Lagrange-reconstruct f(0) (= the secret) from `t` shares at the 1-based
 * participant x-coordinates `xs[0..t-1]`. `shares` is t*32 bytes in the same order
 * as `xs`. Writes the 32-byte secret to `secret_out`. Returns 0 on success, -1 on
 * bad parameters (t<1, a non-positive x, or a repeated x — which is singular). */
int determ_frost_reconstruct(const int *xs, const uint8_t *shares, int t,
                             uint8_t secret_out[32]);

/* Produce a FROST threshold signature over `msg` from the `t` participating
 * signers. This is a centralized simulation of the two-round protocol: the caller
 * marshals each signer's round-1 secret nonces (`d`, `e`, t*32 bytes each, in `xs`
 * order) and secret key `shares` (t*32 bytes); the function derives the public
 * commitments [d_i]B / [e_i]B, the per-signer binding factors, the group
 * commitment R, the Ed25519-compatible challenge c = H(R ‖ group_pk ‖ msg), the
 * Lagrange-weighted signature shares z_i = d_i + e_i·rho_i + lambda_i·s_i·c, and
 * their sum z. Writes `sig` = R ‖ z (64 bytes) — a signature that VERIFIES AS A
 * PLAIN ED25519 SIGNATURE under `group_pk` (so any t-of-n quorum can jointly
 * produce a standard Ed25519 signature). Returns 0 on success, -1 on bad params /
 * an oversized message / a point-decode failure. */
int determ_frost_sign(const int *xs, const uint8_t *shares,
                      const uint8_t *d, const uint8_t *e, int t,
                      const uint8_t *msg, size_t msglen,
                      const uint8_t group_pk[32], uint8_t sig[64]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FROST_H */
