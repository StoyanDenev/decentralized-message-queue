// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/pq_tx_auth.hpp>
#include <determ/crypto/pqauth.hpp>
#include <determ/crypto/pq_address.hpp>

namespace determ::chain {

bool verify_pq_transaction(const Transaction& tx) noexcept {
    try {
        if (tx.type != TxType::PQ_TRANSFER)            return false;
        if (!determ::is_pq_anon_address(tx.from))      return false;
        const int form = determ::pq_anon_address_form(tx.from);   // 1 / 2 / 3
        const std::vector<uint8_t> addr_pk = determ::parse_pq_anon_pubkey(tx.from);

        const std::vector<uint8_t> sb = tx.signing_bytes();
        const determ::pqauth::VerifyResult vr = determ::pqauth::verify(tx.pq_auth, sb);
        if (!vr.ok)                                    return false;
        // A PQ-native account has NO Ed25519 in its trust path: the envelope must
        // be a PQ-ONLY scheme (0x01/0x02/0x03) whose param set matches the form.
        if (vr.hybrid)                                 return false;
        if (vr.scheme != static_cast<uint8_t>(form))   return false;
        // Quantum-resistance binding: the envelope's ML-DSA key must be exactly
        // the key the bearer address commits to — so only that key's holder can
        // authorize a spend, and a quantum adversary cannot substitute its own.
        if (vr.pq_pk != addr_pk)                       return false;
        return true;
    } catch (...) {
        return false;   // fail closed on anything unexpected
    }
}

} // namespace determ::chain
