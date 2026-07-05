/* Determ C99-native finite-field Pedersen commitment over the RFC 3526 MODP-3072
 * prime-order subgroup — CRYPTO-C99-SPEC.md §3.20 increment 1. The MODERN-profile /
 * "large primes, not curves" sibling of the §3.19 P-256 range-proof stack.
 *
 * Commitments live in the prime-order subgroup G_q of Z_p*, where p is the RFC 3526
 * group-15 safe prime (3072 bits, verified prime with q=(p-1)/2 also prime). The
 * commitment is C = g^v * h^r mod p, with g = 4 (a quadratic residue, hence an
 * order-q generator) and h a nothing-up-my-sleeve second generator (hash-to-group,
 * unknown log_g(h)). Binding reduces to the finite-field discrete log; hiding is
 * information-theoretic for uniform r.
 *
 * Portable C99: 32-bit-limb CIOS Montgomery multiplication (no __int128 / intrinsics
 * -> builds on MSVC and GCC alike). NOT constant-time (the owner-gated CT-hardening
 * step, same posture as the §3.19 range prover). LIBRARY PRIMITIVE — no chain call
 * site. All group elements and scalars are 384-byte (3072-bit) BIG-ENDIAN; scalars
 * v, r are reduced mod q (must be < q).
 */
#ifndef DETERM_CRYPTO_FFGROUP_H
#define DETERM_CRYPTO_FFGROUP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A group element or a scalar: 3072 bits = 384 bytes, big-endian. */
#define DETERM_FF_ELEM_BYTES 384

/* The nothing-up-my-sleeve second generator h (SEC1-free: raw 384-byte big-endian).
 * Deterministic, in the order-q subgroup, h != 1, h != g. Returns 0. */
int determ_ff_pedersen_generator_h(uint8_t out[DETERM_FF_ELEM_BYTES]);

/* out = g^v * h^r mod p (384-byte big-endian). v and r are 384-byte big-endian
 * scalars: v in [0, q) (v == 0 allowed), r in (0, q) (r == 0 rejected — no hiding).
 * Returns 0, or -1 if v >= q or r is 0 / >= q. */
int determ_ff_pedersen_commit(uint8_t out[DETERM_FF_ELEM_BYTES],
                              const uint8_t v[DETERM_FF_ELEM_BYTES],
                              const uint8_t r[DETERM_FF_ELEM_BYTES]);

/* Opening check: 0 iff commitment == g^v * h^r mod p, -1 otherwise (including a
 * v/r out of range). Constant-time-comparison of the 384-byte encodings. */
int determ_ff_pedersen_verify(const uint8_t commitment[DETERM_FF_ELEM_BYTES],
                              const uint8_t v[DETERM_FF_ELEM_BYTES],
                              const uint8_t r[DETERM_FF_ELEM_BYTES]);

/* Homomorphic sum: out = c1 * c2 mod p (so commit(v1,r1)*commit(v2,r2) ==
 * commit((v1+v2) mod q, (r1+r2) mod q)). c1, c2 are commitments in G_q. Returns 0,
 * or -1 if an input is not a reduced element (>= p). */
int determ_ff_pedersen_add(uint8_t out[DETERM_FF_ELEM_BYTES],
                           const uint8_t c1[DETERM_FF_ELEM_BYTES],
                           const uint8_t c2[DETERM_FF_ELEM_BYTES]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FFGROUP_H */
