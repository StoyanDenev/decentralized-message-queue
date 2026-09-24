// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>

namespace determ::chain {

// §3.21 PQ_TRANSFER authenticity — the ONE shared accept-rule helper (S-043
// discipline: a new consensus formula gets a single shared implementation that
// every verify site calls). Returns true iff `tx` is a well-formed, authentic
// PQ_TRANSFER:
//   (1) tx.type == PQ_TRANSFER;
//   (2) tx.from is a PQ-native bearer address (is_pq_anon_address);
//   (3) the DPQ1 envelope in tx.pq_auth verifies against tx.signing_bytes();
//   (4) the envelope is PQ-ONLY (no Ed25519) with scheme matching the address form;
//   (5) the envelope's ML-DSA public key EQUALS the key the address commits to
//       — this is the quantum-resistance binding (only the address's key holder
//       can produce a verifying envelope; a quantum adversary cannot substitute).
// Never throws (the tx is attacker-controlled).
bool verify_pq_transaction(const Transaction& tx) noexcept;

} // namespace determ::chain
