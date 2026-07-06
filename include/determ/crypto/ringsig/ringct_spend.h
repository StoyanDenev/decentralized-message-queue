// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#ifndef DETERM_CRYPTO_RINGSIG_RINGCT_SPEND_H
#define DETERM_CRYPTO_RINGSIG_RINGCT_SPEND_H
// CRYPTO-C99-SPEC.md §3.23c — the LIBRARY-only RingCT SPEND-STATEMENT composition
// over NIST P-256 (input-unlinkability increment 3). It stitches the already-
// shipped privacy layers into ONE end-to-end confidential + unlinkable spend proof,
// with ZERO consensus touch:
//
//   §3.23b CLSAG   — proves the spender owns ONE of n ring notes and that the
//                    pseudo-out Coffset_H commits to the SAME amount as their real
//                    input, hiding WHICH (input-unlinkable); emits the key image I
//                    (double-spend nullifier). CLSAG commitments are the RingCT
//                    convention: amount on H, blinding on G.
//   §3.23c TRANSPOSE — the reconciliation this increment adds. CLSAG is amount-on-H;
//                    the §3.19/§3.22c range+balance stack is amount-on-G. A
//                    commitment-transposition proof (a Schnorr AND-proof with a
//                    SHARED value response) certifies a value-on-H commitment
//                    C_H = v*H + a*G and a value-on-G commitment C_G = v*G + b*H hide
//                    the SAME amount v — the bridge between the two conventions.
//   §3.22c DCT1    — the amount-on-G confidential-transfer bundle: proves Coffset_G's
//                    amount = Σ(output amounts) + fee (balance) and each output in
//                    [0, 2^n) (range).
//
// Composition: CLSAG(Coffset_H) -> TRANSPOSE(Coffset_H == Coffset_G in amount) ->
// DCT1(C_in = [Coffset_G]). The amount flows from a hidden ring member, through the
// transposed pseudo-out, to hidden in-range outputs — amounts secret, input
// unlinkable, value conserved. NAIVELY sharing Coffset across the two conventions is
// UNSOUND (the H-amount is not the G-amount); the transpose proof is exactly what
// makes it sound.
//
// The transpose proof is the ONLY new crypto (a textbook Schnorr AND-proof; no new
// hardness assumption — P-256 ECDLP + the ROM). CLSAG + DCT1 are reused verbatim.
// Deterministic; dual-oracle byte-frozen against tools/verify_ringct_spend.py. NOT
// constant-time (owner-gated).
//
// Wire (transpose proof, 162 B): A_H(33) ‖ A_G(33) ‖ sv(32) ‖ sa(32) ‖ sb(32).
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Length of a commitment-transposition proof: 162 bytes.
size_t determ_commit_transpose_proof_len(void);

// Prove that C_H = v*H + a*G (value-on-H) and C_G = v*G + b*H (value-on-G) hide the
// SAME value v. Writes the 162-byte proof and the two compressed commitments
// C_H_out33 / C_G_out33. v/a/b are 32-byte big-endian scalars < n; v must be > 0
// (a spend amount) and a,b the two blindings. Deterministic. Returns 0, or -1 on a
// bad scalar / an internal decode / identity failure.
int determ_commit_transpose_prove(uint8_t proof[162],
                                  uint8_t C_H_out33[33], uint8_t C_G_out33[33],
                                  const uint8_t v[32], const uint8_t a[32],
                                  const uint8_t b[32]);

// Verify: 0 iff `proof` certifies C_H33 (value-on-H) and C_G33 (value-on-G) hide the
// same amount, -1 otherwise (malformed proof / out-of-range response / a decode
// failure / the two Schnorr equations fail). The SHARED response sv in both
// equations is what binds the two amounts. Public-data, fail-closed.
int determ_commit_transpose_verify(const uint8_t C_H33[33], const uint8_t C_G33[33],
                                   const uint8_t proof[162]);

// Verify a full RingCT spend statement end-to-end. Returns 0 iff ALL hold:
//   (1) the CLSAG closes for (ringP, ringC, coffset_H, I, D, clsag_sig) — input
//       membership + Coffset_H commits to the real input amount + the nullifier I;
//   (2) the DCT1 `bundle` is well-formed with EXACTLY ONE input (n_in == 1), whose
//       commitment C_in[0] = coffset_G is extracted from the bundle;
//   (3) the transpose proof bridges coffset_H (value-on-H) and coffset_G (value-on-G)
//       to the same amount;
//   (4) the DCT1 bundle verifies (range over the outputs + balance coffset_G =
//       Σ outputs + fee).
// -1 on any failure. Every input is fully attacker-controlled; fail-closed. This is a
// LIBRARY verifier — it touches NO consensus state (no nullifier set, no pool); the
// unlinkable-spend CONSENSUS wiring is a separate, owner-gated step.
int determ_ringct_spend_verify(const uint8_t *msg, size_t msglen,
                               const uint8_t *ringP33, const uint8_t *ringC33, size_t n,
                               const uint8_t coffset_H33[33],
                               const uint8_t I33[33], const uint8_t D33[33],
                               const uint8_t *clsag_sig, size_t clsag_sig_len,
                               const uint8_t transpose_proof[162],
                               const uint8_t *bundle, size_t bundle_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_RINGSIG_RINGCT_SPEND_H */
