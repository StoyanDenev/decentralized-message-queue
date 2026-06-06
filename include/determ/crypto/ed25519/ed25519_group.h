/* Determ C99-native Ed25519 group + scalar primitives — the low-level field/group
 * API the FROST-Ed25519 layer (src/crypto/frost/, CRYPTO-C99-SPEC §3.2 / RFC 9591)
 * builds threshold keygen and signing on. Implemented in ed25519.c (same validated
 * field/group code as determ_ed25519_sign/_verify), exposed here so FROST does not
 * re-vendor the curve.
 *
 * Scalars are 32-byte little-endian integers reduced mod L (the group order).
 * Points are 32-byte compressed Edwards encodings (the wire form). All scalar ops
 * are constant-time w.r.t. their inputs EXCEPT determ_ed25519_sc_invert, which
 * branches only on the PUBLIC constant exponent L-2 (not on the base) — the base
 * is never leaked. Point ops decode their compressed inputs and re-encode the
 * result; a decode of an off-curve / non-canonical encoding returns -1.
 */
#ifndef DETERM_CRYPTO_ED25519_GROUP_H
#define DETERM_CRYPTO_ED25519_GROUP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── scalar arithmetic mod L ─────────────────────────────────────────────── */

/* out = (a*b + c) mod L. */
void determ_ed25519_sc_muladd(uint8_t out[32], const uint8_t a[32],
                              const uint8_t b[32], const uint8_t c[32]);
/* out = a*b mod L. */
void determ_ed25519_sc_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
/* out = a+b mod L. */
void determ_ed25519_sc_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
/* out = a-b mod L. */
void determ_ed25519_sc_sub(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
/* out = (64-byte little-endian `in`) mod L — e.g. hash-to-scalar. */
void determ_ed25519_sc_reduce64(const uint8_t in[64], uint8_t out[32]);
/* out = a^-1 mod L (inv(0)=0). Branches on the public exponent only. */
void determ_ed25519_sc_invert(uint8_t out[32], const uint8_t a[32]);
/* out = (uint64) v reduced mod L (v must be < L, e.g. a small index). */
void determ_ed25519_sc_set_small(uint8_t out[32], uint64_t v);

/* ── Edwards group ops (32-byte compressed points) ───────────────────────── */

/* out = [s] B  (B = the Ed25519 base point). */
void determ_ed25519_point_basemul(uint8_t out[32], const uint8_t s[32]);
/* out = [s] P. Returns 0 on success, -1 if P does not decode to a curve point. */
int  determ_ed25519_point_mul(uint8_t out[32], const uint8_t s[32], const uint8_t p[32]);
/* out = P + Q. Returns 0 on success, -1 if P or Q does not decode. */
int  determ_ed25519_point_add(uint8_t out[32], const uint8_t p[32], const uint8_t q[32]);

/* Canonicality gates (the anti-malleability checks the Ed25519 verifier applies).
 * 1 iff canonical, else 0: a scalar s < L, or a point encoding with y < q. */
int  determ_ed25519_sc_is_canonical(const uint8_t s[32]);
int  determ_ed25519_point_is_canonical(const uint8_t p[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_ED25519_GROUP_H */
