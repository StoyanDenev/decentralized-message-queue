/* Determ C99-native ML-DSA (Dilithium, NIST FIPS 204) — shared parameters.
 *
 * Increment 1 of the owner-authorized on-chain post-quantum SIGNATURE track:
 * the arithmetic foundation (the ring Z_q[X]/(X^256 + 1) and its NTT) that every
 * ML-DSA parameter set (ML-DSA-44/65/87) is built on. Built on the C99 SHAKE
 * (`include/determ/crypto/sha3/`, CRYPTO-C99-SPEC §3.17): ML-DSA expands its
 * public matrix A with SHAKE128 and samples secrets/masks + hashes the message
 * with SHAKE256. This module is ADDITIVE — no in-tree signature consumer yet;
 * the full keygen/sign/verify + FIPS 204 byte-level KATs are later increments.
 *
 * These constants are parameter-set-INDEPENDENT (identical for ML-DSA-44/65/87):
 * the ring degree n = 256 and the modulus q = 2^23 - 2^13 + 1 = 8380417, a prime
 * with q ≡ 1 (mod 512), so Z_q holds a primitive 512-th root of unity (ζ = 1753)
 * and the negacyclic NTT exists. See src/crypto/mldsa/README.md.
 */
#ifndef DETERM_CRYPTO_MLDSA_PARAMS_H
#define DETERM_CRYPTO_MLDSA_PARAMS_H

/* Ring degree: elements are degree-<256 polynomials mod X^256 + 1. */
#define DETERM_MLDSA_N 256

/* Prime modulus q = 2^23 - 2^13 + 1. All coefficient arithmetic is mod q. */
#define DETERM_MLDSA_Q 8380417

/* q^{-1} mod 2^32 — the Montgomery reduction constant (positive form, so that
 * a - t*q ≡ 0 (mod 2^32) is an exact division by 2^32 in montgomery_reduce). */
#define DETERM_MLDSA_QINV 58728449

/* 2^32 mod q, in the centered representative (-q/2, q/2].  R = 2^32 is the
 * Montgomery radix; a value x held as x*R mod q is "in the Montgomery domain". */
#define DETERM_MLDSA_MONT (-4186625)

/* Dropped low-order bits of the public key (FIPS 204). Not used by the NTT
 * layer; recorded here for the later packing/rounding increment. */
#define DETERM_MLDSA_D 13

#endif /* DETERM_CRYPTO_MLDSA_PARAMS_H */
