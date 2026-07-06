// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#ifndef DETERM_CRYPTO_RINGSIG_LSAG_H
#define DETERM_CRYPTO_RINGSIG_LSAG_H
// CRYPTO-C99-SPEC.md §3.23 — LSAG linkable ring signature over NIST P-256
// (input-unlinkability increment 1). The Liu-Wei-Wong 2004 Linkable Spontaneous
// Anonymous Group signature — the CryptoNote / early-Monero RingCT membership
// primitive. A signer who knows the private key x of ONE of n ring public keys
// {P_0..P_{n-1}} (each P_i = x_i*G) proves membership WITHOUT revealing which,
// and publishes a KEY IMAGE I = x*H_p(P_signer) that is DETERMINISTIC in the
// signing key — so spending the same note twice reveals the SAME image (the
// double-spend nullifier) while remaining UNLINKABLE to any particular ring
// member. H_p is the RFC 9380 P256_XMD:SHA-256_SSWU_RO_ hash-to-curve.
//
// Built entirely on the shipped §3.8c/§3.9b P-256 primitives (base_mul /
// point_mul / point_add / hash_to_curve / hash_to_scalar / compress) — it adds
// NO new hardness assumption (soundness rests on P-256 ECDLP + the ROM). This is
// a LIBRARY primitive; the shielded-pool consensus wiring (unlinkable spends +
// the on-chain nullifier set) is a separate, owner-gated step.
//
// Signing is DETERMINISTIC (RFC-6979-style nonces derived from the key + a prefix
// hash over ring‖image‖message) so its bytes are reproducible and dual-oracle-
// frozen against tools/verify_lsag.py. NOT constant-time (owner-gated).
//
// Wire: ring33 = n consecutive 33-byte SEC1-compressed pubkeys; key image = 33 B
// compressed; signature = c0(32) ‖ s_0(32) ‖ … ‖ s_{n-1}(32) = 32*(n+1) bytes.
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Signature length for a ring of n members: 32*(n+1). Returns 0 if n == 0.
size_t determ_lsag_sig_len(size_t n);

// Key image I = x * H_p(P), written SEC1-compressed to out33. P33 is the 33-byte
// compressed pubkey P = x*G. Deterministic in (x, P). Returns 0, or -1 on a
// decode / param failure.
int determ_lsag_key_image(uint8_t out33[33], const uint8_t x[32],
                          const uint8_t P33[33]);

// Sign msg as the holder of x — the private key of ring[index] (so
// ring[index] == compress(x*G)). ring33 = n consecutive 33-byte compressed
// pubkeys; index < n. Writes determ_lsag_sig_len(n) bytes to sig and the key
// image to image_out33. Deterministic. Returns 0, or -1 on bad params / index
// out of range / a ring member that fails to decode / short buffer.
int determ_lsag_sign(uint8_t *sig, size_t sig_len, uint8_t image_out33[33],
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *ring33, size_t n,
                     const uint8_t x[32], size_t index);

// Verify: returns 0 iff the ring signature closes for key image I33 over the n
// ring members and message msg, -1 otherwise (wrong length / a decode failure /
// an out-of-range scalar / non-closure). Every input is treated as fully
// attacker-controlled; fail-closed.
int determ_lsag_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t *ring33, size_t n,
                       const uint8_t I33[33], const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_RINGSIG_LSAG_H */
