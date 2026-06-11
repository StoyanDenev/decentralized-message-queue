/* Determ C99-native NIST P-256 (secp256r1) — CRYPTO-C99-SPEC.md §3.8c.
 *
 * The FIPS-profile curve (FIPS 186-5 / SP 800-186): the `tactical` + `cluster`
 * profiles bundle FIPS-validated cryptography per spec §2 Q10, and secp256k1
 * is not on NIST's list — P-256 supplants it there (OPRF-P256 per §3.9b is
 * the downstream consumer). From-scratch implementation per published method
 * (same posture as the §3.2 gf[16] Ed25519): NO vendored third-party code.
 *
 * Construction:
 *   - Field: 8x32-bit limbs, Montgomery multiplication (CIOS). p ≡ -1 mod
 *     2^32 makes the Montgomery factor n0' = 1. R² mod p and the Montgomery
 *     forms of b / G are derived at runtime from first principles (256
 *     modular doublings of R mod p = 2^256 − p) — no hand-transcribed
 *     wide constants beyond p, n, b, Gx, Gy themselves, and THOSE are
 *     asserted byte-equal against OpenSSL's EC_GROUP by `determ
 *     test-p256-c99` before anything else runs.
 *   - Points: Renes-Costello-Batina complete addition formulas for a = -3
 *     short-Weierstrass curves (EUROCRYPT 2016, algorithm 4) in projective
 *     (X:Y:Z) — exception-free: the SAME formula handles P+Q, P+P, P+O,
 *     so the scalar ladder needs no special cases and no secret-dependent
 *     branches.
 *   - Scalar mult: double-and-add-always over the complete formulas with a
 *     branchless conditional swap per bit — uniform operation sequence
 *     regardless of scalar bits.
 *
 * Wire convention: scalars and coordinates are BIG-ENDIAN (the SEC1 / X9.62
 * convention for this curve family — unlike the little-endian curve25519
 * modules). Points are 65-byte SEC1 uncompressed: 0x04 || X || Y.
 *
 * Validated by `determ test-p256-c99`: curve-constant parity vs OpenSSL
 * EC_GROUP, base-mult byte-equality vs OpenSSL EVP_PKEY_EC over a scalar
 * grid, ECDH x-coordinate parity + DH symmetry, scalarmult commutativity,
 * on-curve accept/reject, and the scalar-validity gates. */
#ifndef DETERM_CRYPTO_P256_H
#define DETERM_CRYPTO_P256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* out = [scalar] G, SEC1 uncompressed (0x04 || X || Y, big-endian).
 * Returns 0, or -1 if the scalar is invalid (zero, or >= the group order n).
 * Constant-time in the scalar (the validity check's outcome is public). */
int determ_p256_base_mul(uint8_t out[65], const uint8_t scalar_be[32]);

/* out = [scalar] P for an attacker-supplied point (the ECDH core; the shared
 * secret is out's X coordinate, bytes out[1..32]). Returns 0, or -1 if the
 * scalar is invalid OR the point fails decode (bad prefix, coordinate >= p,
 * not on the curve) OR the result is the point at infinity. Constant-time in
 * the scalar; the point checks are on PUBLIC data. */
int determ_p256_point_mul(uint8_t out[65], const uint8_t scalar_be[32],
                          const uint8_t point[65]);

/* 0 iff `point` is a well-formed SEC1 uncompressed encoding of a point ON the
 * curve (prefix 0x04, both coordinates < p, y² = x³ − 3x + b), -1 otherwise. */
int determ_p256_point_check(const uint8_t point[65]);

/* Export the curve constants (big-endian) for cross-validation — `determ
 * test-p256-c99` asserts these byte-equal against OpenSSL's EC_GROUP, which
 * is what makes the in-source constants trustworthy. */
void determ_p256_params(uint8_t p_be[32], uint8_t n_be[32], uint8_t b_be[32],
                        uint8_t gx_be[32], uint8_t gy_be[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_P256_H */
