// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#ifndef DETERM_CRYPTO_RINGSIG_CLSAG_H
#define DETERM_CRYPTO_RINGSIG_CLSAG_H
// CRYPTO-C99-SPEC.md §3.23b — CLSAG concise linkable ring signature over NIST
// P-256 (input-unlinkability increment 2). The Goodell-Noether-RandomRun 2019
// "Concise Linkable Spontaneous Anonymous Group" signature — Monero's current
// RingCT membership + balance primitive. It generalises the §3.23 LSAG to TWO
// key layers signed by ONE concise ring (n+1 scalars, NOT 2n):
//
//   layer 0 (spend key):  ring key P_i,  signer secret p (P_l = p*G),
//                         key image  I = p*H_p(P_l)           — the nullifier
//   layer 1 (commitment): ring key C_i,  signer secret z
//                         (C_l - Coffset = z*G), aux image  D = z*H_p(P_l)
//
// The two layers are folded by hash-derived aggregation coefficients mu_P, mu_C
// into a single ring over the aggregated keys W_i = mu_P*P_i + mu_C*(C_i-Coffset)
// with the aggregated image Wimg = mu_P*I + mu_C*D. Proving C_l - Coffset is a
// pure-G multiple (no H component) is exactly the RingCT balance statement "the
// pseudo-out Coffset commits to the SAME amount as the real input commitment";
// forgery against adversarial commitment keys is prevented by the unpredictable
// mu (the paper's core result). H_p is the RFC 9380 P256_XMD:SHA-256_SSWU_RO_
// hash-to-curve (same map as §3.19 H / §3.23 LSAG, distinct DST).
//
// Built entirely on the shipped §3.8c/§3.9b P-256 primitives (base_mul /
// point_mul / point_add / hash_to_curve / hash_to_scalar / compress) — it adds
// NO new hardness assumption (soundness rests on P-256 ECDLP + the ROM). This is
// a LIBRARY primitive; the shielded-pool consensus wiring (unlinkable RingCT
// spends + the on-chain key-image nullifier set) is a separate, owner-gated step.
//
// Signing is DETERMINISTIC (RFC-6979-style nonces bound to BOTH secrets p, z and
// a prefix hash over ringP‖ringC‖Coffset‖I‖D‖msg) so its bytes are reproducible
// and dual-oracle-frozen against tools/verify_clsag.py. NOT constant-time
// (branches on secret nonces / index — owner-gated).
//
// Wire: ringP33 / ringC33 = n consecutive 33-byte SEC1-compressed pubkeys each;
// Coffset33 = 33 B; key image I = 33 B, aux image D = 33 B; signature =
// c0(32) ‖ s_0(32) ‖ … ‖ s_{n-1}(32) = 32*(n+1) bytes.
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Signature length for a ring of n members: 32*(n+1). Returns 0 if n == 0.
size_t determ_clsag_sig_len(size_t n);

// Key images from the two signer secrets and the signer's spend pubkey:
// I = p*H_p(P_signer) (link/nullifier), D = z*H_p(P_signer) (aux). P_signer33 is
// the 33-byte compressed pubkey P_signer = p*G. Deterministic. Returns 0, or -1
// on a decode / param failure.
int determ_clsag_key_images(uint8_t I_out33[33], uint8_t D_out33[33],
                            const uint8_t p[32], const uint8_t z[32],
                            const uint8_t P_signer33[33]);

// Sign msg as the holder of (p, z): p = private key of ringP[index] (so
// ringP[index] == compress(p*G)) and z = the commitment blinding difference
// (ringC[index] - Coffset == z*G). ringP33 / ringC33 = n consecutive 33-byte
// compressed pubkeys each; index < n. Writes determ_clsag_sig_len(n) bytes to
// sig, the key image to I_out33 and the aux image to D_out33. Deterministic.
// Returns 0, or -1 on bad params / index out of range / a member that fails to
// decode / short buffer. (Does NOT itself check the z*G precondition — the caller
// supplies a consistent z; a wrong z simply yields a signature that will not
// verify.)
int determ_clsag_sign(uint8_t *sig, size_t sig_len,
                      uint8_t I_out33[33], uint8_t D_out33[33],
                      const uint8_t *msg, size_t msglen,
                      const uint8_t *ringP33, const uint8_t *ringC33, size_t n,
                      const uint8_t Coffset33[33],
                      const uint8_t p[32], const uint8_t z[32], size_t index);

// Verify: returns 0 iff the concise ring signature closes for key image I33 and
// aux image D33 over the n ring members {P_i, C_i}, pseudo-out Coffset and
// message msg; -1 otherwise (wrong length / a decode failure / an out-of-range
// scalar / non-closure). Every input is treated as fully attacker-controlled;
// fail-closed.
int determ_clsag_verify(const uint8_t *msg, size_t msglen,
                        const uint8_t *ringP33, const uint8_t *ringC33, size_t n,
                        const uint8_t Coffset33[33],
                        const uint8_t I33[33], const uint8_t D33[33],
                        const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_RINGSIG_CLSAG_H */
