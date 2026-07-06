// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// determ-light — client-side production + verification of a DPQ1 post-quantum
// transaction-authentication envelope (determ::pqauth, CRYPTO-C99-SPEC §3.21).
// Binds a transaction's canonical signing_bytes (byte-for-byte the chain's
// Transaction::signing_bytes) to an ML-DSA signature, optionally HYBRID with
// Ed25519. This is CLIENT tooling; the consensus accept-rule for such a tx is a
// separate, owner-gated step.

namespace determ::light {

int cmd_pq_sign_tx(int argc, char** argv);    // build a DPQ1-authenticated tx (demonstration)
int cmd_pq_verify_tx(int argc, char** argv);  // verify a DPQ1-authenticated tx (offline)
int cmd_pq_address(int argc, char** argv);    // derive the PQ-native bearer address from a seed
int cmd_pq_transfer(int argc, char** argv);   // build a canonical, submittable PQ_TRANSFER

} // namespace determ::light
