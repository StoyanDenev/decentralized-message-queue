// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// determ-light — client-side production + verification of a DPQ1 post-quantum
// transaction-authentication envelope (determ::pqauth, CRYPTO-C99-SPEC §3.21).
// Binds a transaction's canonical signing_bytes (byte-for-byte the chain's
// Transaction::signing_bytes) to an ML-DSA signature, optionally HYBRID with
// Ed25519. This is CLIENT tooling. For a PQ_TRANSFER (the shipped PQ-native
// consensus tx) the offline verify enforces the FULL node accept-rule
// (determ::chain::verify_pq_transaction) — the ML-DSA signature AND the address
// binding make_pq_anon_address(form, pubkey) == from — because a DPQ1 envelope
// is self-certifying, so a signature check alone does not prove the tx was
// authorized by the account named in `from`.

namespace determ::light {

int cmd_pq_sign_tx(int argc, char** argv);    // build a DPQ1-authenticated tx (demonstration)
int cmd_pq_verify_tx(int argc, char** argv);  // verify a DPQ1-authenticated tx (offline)
int cmd_pq_address(int argc, char** argv);    // derive the PQ-native bearer address from a seed
int cmd_pq_transfer(int argc, char** argv);   // build a canonical, submittable PQ_TRANSFER
int cmd_selftest_pq_addr_bind(int argc, char** argv);  // falsify gate: PQ_TRANSFER key must hash to `from`

} // namespace determ::light
