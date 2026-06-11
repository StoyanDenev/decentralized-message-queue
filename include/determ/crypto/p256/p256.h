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

/* ── §3.9b OPRF groundwork ──────────────────────────────────────────────────
 * Scalar-field (mod n) arithmetic — the OPRF blind/unblind core — and the
 * RFC 9380 hash-to-curve suite P256_XMD:SHA-256_SSWU_RO_ (simplified SSWU,
 * Z = -10, no isogeny — P-256 has A·B ≠ 0). Validated by `determ
 * test-p256-h2c-c99` (mod-n ops vs the OpenSSL BIGNUM oracle; h2c vs the
 * RFC 9380 appendix vectors in tools/vectors/p256_h2c.json + structural
 * on-curve/determinism/DST-sensitivity gates). */

/* r = a*b mod n (inputs big-endian, both must be < n; -1 otherwise).
 * Constant-time Montgomery arithmetic; the validity outcome is public. */
int determ_p256_scalar_mul_mod_n(uint8_t r[32], const uint8_t a[32],
                                 const uint8_t b[32]);

/* r = a^{-1} mod n via Fermat (n is prime). -1 if a == 0 or a >= n.
 * Constant-time in `a` (the exponent n-2 is a public constant). */
int determ_p256_scalar_inv_mod_n(uint8_t r[32], const uint8_t a[32]);

/* expand_message_xmd with SHA-256 (RFC 9380 §5.3.1). -1 on the RFC's
 * length/DST bounds (outlen > 8160 i.e. ell > 255, or > 65535; dstlen >
 * 255; zero outlen). Exposed for the appendix-K.1 vector gate. */
int determ_p256_expand_message_xmd(uint8_t* out, size_t outlen,
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t* dst, size_t dstlen);

/* hash_to_curve P256_XMD:SHA-256_SSWU_RO_ (RFC 9380 §3, random-oracle
 * variant): out = SEC1 uncompressed point, never the identity. The map is
 * constant-time in `msg` (an OPRF input may be a user secret); DST is
 * public. -1 only on expand_message bounds violations. */
int determ_p256_hash_to_curve(uint8_t out[65],
                              const uint8_t* msg, size_t msglen,
                              const uint8_t* dst, size_t dstlen);

/* hash_to_scalar (RFC 9380 hash_to_field with the ORDER n as the modulus;
 * m = 1, L = 48, count = 1 — the RFC 9497 HashToScalar shape). Output is a
 * canonical big-endian scalar < n. -1 only on expand_message bounds. */
int determ_p256_hash_to_scalar(uint8_t out[32],
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* dst, size_t dstlen);

/* out = P + Q (SEC1 uncompressed in/out; the RCB complete formulas, so
 * P == Q and P == -Q are handled uniformly). -1 if either input fails
 * decode or the result is the point at infinity (P + (-P)). Public-data
 * operation (DLEQ verification shapes s·A + c·B operate on public values). */
int determ_p256_point_add(uint8_t out[65], const uint8_t p[65],
                          const uint8_t q[65]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_P256_H */
