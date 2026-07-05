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

/* ── §3.20 increment 2: vector-commitment generators + vector commit + MSM ────
 * The Bulletproofs-shaped building blocks over Z_p*, mirroring the §3.19 P-256
 * determ_pedersen_gen / _vector_commit / _msm. NOT constant-time (owner-gated).
 * All elements/scalars are 384-byte big-endian; exponents are reduced mod q. */

#include <stddef.h>

/* out = the `index`-th generator of family `which` (0 = "G", 1 = "H"), a 384-byte
 * big-endian order-q element. Hash-to-group: 13 SHA-256 counter blocks of
 * (family-DST || big-endian-4-byte index || counter) -> reduce mod p -> SQUARE
 * into the QR subgroup G_q. Deterministic, in G_q, != 1, and with no known dlog
 * relation to g, h, or the other family. Returns 0, or -1 on which > 1 (or the
 * negligible degenerate square). */
int determ_ff_gen(uint8_t out[DETERM_FF_ELEM_BYTES], uint32_t index, uint8_t which);

/* Vector Pedersen commitment: out = h^r * Π_{i<n} G_i^{a_i} * Π_{i<n} H_i^{b_i} mod p,
 * with G_i = gen(i,0), H_i = gen(i,1), h the §3.20 scalar generator. `a` and `b` are
 * each `n` consecutive 384-byte big-endian exponents in [0,q) (a zero exponent's term
 * is the identity and is skipped). r is the blinding exponent, 0 < r < q (r == 0
 * rejected — no hiding). Returns 0, or -1 on a bad exponent (r == 0, or any a_i/b_i
 * >= q). n == 0 yields h^r. NOTE the zero-exponent skip is a data-dependent branch —
 * a range prover over SECRET vectors needs a constant-time multi-exp (owner-gated). */
int determ_ff_vector_commit(uint8_t out[DETERM_FF_ELEM_BYTES],
                            const uint8_t *a, const uint8_t *b,
                            size_t n, const uint8_t r[DETERM_FF_ELEM_BYTES]);

/* General multi-exponentiation: out = Π_{i<n} points_i^{scalars_i} mod p (the Z_p*
 * analogue of the P-256 MSM; vector_commit is the special case over [h, G_i, H_i]).
 * `scalars` is n consecutive 384-byte big-endian exponents in [0,q) (a zero scalar's
 * term is the identity and is skipped BEFORE its point is inspected). `points` is n
 * consecutive 384-byte big-endian group elements in (0,p). The identity is the
 * element 1 (representable), so this is 2-way: 0 on success (out holds the product,
 * possibly 1; n == 0 => 1), -1 on a scalar >= q or a point that is 0 / >= p. The
 * zero-scalar skip is a data-dependent branch (same CT caveat as vector_commit). */
int determ_ff_msm(uint8_t out[DETERM_FF_ELEM_BYTES],
                  const uint8_t *scalars, const uint8_t *points, size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_FFGROUP_H */
