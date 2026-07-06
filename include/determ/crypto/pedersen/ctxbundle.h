// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// DCT1 confidential-transfer proof bundle over NIST P-256 (CRYPTO-C99-SPEC
// §3.22). A serialized, fail-closed-verifiable composition of the already-
// shipped §3.19 primitives — it adds NO new hardness assumption:
//   * input + output Pedersen commitments  (determ_pedersen_commit),
//   * ONE aggregated Bulletproofs range proof over the m outputs
//     (determ_agg_rangeproof_*), proving each output in [0, 2^n),
//   * a balance/excess proof (determ_p256_balance_*), proving amount
//     conservation  Sum(v_in) = Sum(v_out) + fee.
// verify == range AND balance. The output commitments C_out serve DIRECTLY as
// the aggregated range proof's value commitments V (the prover uses the SAME
// blinding, gamma_j = r_out_j), so the composition identity V_j == C_out[j] is
// enforced structurally rather than checked. The balance excess E is RECOMPUTED
// by the verifier from C_in/C_out/fee and never carried in the bundle, so it
// cannot be spoofed.
//
// Wire layout:
//   MAGIC(4)="DCT1" | n_in(1) | m(1) | n(1) | fee(8 BE)
//   | C_in[n_in*33] | C_out[m*33] | agg_rangeproof[L] | balance_proof(65)
//   where L = determ_agg_rangeproof_proof_len(m, n).
//
// This is a LIBRARY primitive. A confidential-tx CONSENSUS integration (the
// shielded-pool state model: commitment set + nullifiers) is a separate,
// owner-gated step.
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Total serialized bundle length for (n_in, m, n); 0 if the parameters are
// invalid (n_in/m in [1,255]; n a power of two <= 64; m*n <= 256).
size_t determ_ctx_bundle_len(size_t n_in, size_t m, size_t n);

// Serialize a bundle from its already-computed components. `C_out` MUST equal
// the aggregated range proof's value commitments V (caller used gamma_j =
// r_out_j). Returns 0 on success, -1 on bad params / short buffer.
int determ_ctx_bundle_serialize(uint8_t *out, size_t out_len,
                                const uint8_t *C_in, size_t n_in,
                                const uint8_t *C_out, size_t m, size_t n,
                                uint64_t fee,
                                const uint8_t *agg_rangeproof,
                                const uint8_t balance_proof[65]);

// Verify a bundle of `len` fully attacker-controlled bytes. Recomputes the
// excess E, verifies the balance proof against it, and verifies the aggregated
// range proof against C_out (= V). Fail-closed on any malformed/degenerate
// input (bad magic, invalid params, wrong length, identity excess, ...).
// Returns 0 iff the confidential transfer is valid, -1 otherwise.
int determ_ctx_bundle_verify(const uint8_t *bundle, size_t len);

#ifdef __cplusplus
}
#endif
