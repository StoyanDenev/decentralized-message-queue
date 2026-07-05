/* Determ C99-native Pedersen commitment over NIST P-256 — CRYPTO-C99-SPEC.md
 * §3.19. The FIRST building block of the range-proof / confidential-transaction
 * track (owner-authorized 2026-07-04, library-primitive-first, ZERO consensus
 * touch — additive, not wired into any chain call site).
 *
 * A Pedersen commitment binds a value v with a blinding factor r:
 *
 *     C = v*G + r*H   (mod the P-256 group, order n)
 *
 * where G is the standard P-256 base point and H is a SECOND generator whose
 * discrete log to G is unknown ("nothing-up-my-sleeve"). H is derived by
 * hashing a fixed public string onto the curve via the RFC 9380
 * P256_XMD:SHA-256_SSWU_RO_ map — so no party knows log_G(H), which is exactly
 * the *binding* assumption (finding v',r' with v'*G+r'*H == C would recover
 * log_G(H)). *Hiding* is information-theoretic: for a uniform r, C is uniform
 * over the group and reveals nothing about v.
 *
 * This module is built ENTIRELY on the §3.8c P-256 primitives
 * (base_mul / point_mul / point_add / hash_to_curve / compress) — each already
 * validated byte-equal vs OpenSSL EC (test-p256-c99) or the RFC 9380 vectors
 * (test-p256-h2c-c99) — so its correctness is inherited; the only new logic is
 * their composition, pinned structurally by the homomorphism + open/verify
 * gates in `determ test-pedersen-c99` and byte-frozen in
 * tools/vectors/pedersen.json (both §3.13 halves).
 *
 * Wire convention (inherited from P-256): scalars are 32-byte BIG-ENDIAN
 * (< n); commitments are 33-byte SEC1 COMPRESSED points.
 */
#ifndef DETERM_CRYPTO_PEDERSEN_H
#define DETERM_CRYPTO_PEDERSEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The second generator H (nothing-up-my-sleeve): H = hash_to_curve(FIXED_MSG,
 * FIXED_DST) via P256_XMD:SHA-256_SSWU_RO_. Deterministic, never the identity,
 * always on-curve, and H != G. out65 = SEC1 uncompressed (0x04 || X || Y).
 * Returns 0 (the fixed inputs never hit the RFC's expand-bounds errors). */
int determ_pedersen_generator_h(uint8_t out65[65]);

/* Commit: out33 = compress(v*G + r*H), SEC1 compressed (33 bytes).
 *   - v (the value) is a 32-byte big-endian scalar < n; v == 0 is allowed
 *     (commits to zero value: C = r*H).
 *   - r (the blinding factor) is a 32-byte big-endian scalar, 0 < r < n; r == 0
 *     is REJECTED (a zero blinding factor gives no hiding).
 * Returns 0, or -1 if v >= n, or r is invalid (0 or >= n), or (negligibly) the
 * result is the point at infinity (v*G == -r*H, i.e. a known log_G(H)). */
int determ_pedersen_commit(uint8_t out33[33],
                           const uint8_t v[32], const uint8_t r[32]);

/* Open/verify: 0 iff commitment33 == commit(v, r) (recomputed, then a
 * constant-time compare of the 33-byte encoding), -1 otherwise (including a
 * malformed opening or a commit failure). This is the *opening* check — the
 * committer later reveals (v, r) and anyone confirms it matches C. */
int determ_pedersen_verify(const uint8_t commitment33[33],
                           const uint8_t v[32], const uint8_t r[32]);

/* Homomorphic add: out33 = compress(decompress(c1) + decompress(c2)). By the
 * group law commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2, r1+r2) (sums taken
 * mod n). Returns 0, or -1 if either input fails to decode or the result is the
 * identity (c2 == -c1, i.e. the commitments cancel — v1+v2 ≡ 0 AND r1+r2 ≡ 0). */
int determ_pedersen_add(uint8_t out33[33],
                        const uint8_t c1_33[33], const uint8_t c2_33[33]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_PEDERSEN_H */
