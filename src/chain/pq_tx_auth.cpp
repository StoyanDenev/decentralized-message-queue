// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/pq_tx_auth.hpp>
#include <determ/crypto/pqauth.hpp>
#include <determ/crypto/pq_address.hpp>

namespace determ::chain {

bool verify_pq_transaction(const Transaction& tx) noexcept {
    try {
        if (tx.type != TxType::PQ_TRANSFER)            return false;
        // A5 HASH address (Option A): the address is a non-invertible commitment
        // to (form, ML-DSA pubkey), so the pubkey + form come from the CARRIED
        // envelope, and we RECOMPUTE the address to check the commitment. Shape:
        // a canonical-lowercase 66-char "0x"+64hex (S-028 — one store-key per
        // account, no case-spelling fragmentation; honest producers emit
        // lowercase via make_pq_anon_address).
        if (!determ::is_pq_anon_address(tx.from))      return false;
        if (determ::normalize_pq_anon_address(tx.from) != tx.from) return false;

        const std::vector<uint8_t> sb = tx.signing_bytes();
        const determ::pqauth::VerifyResult vr = determ::pqauth::verify(tx.pq_auth, sb);
        if (!vr.ok)                                    return false;
        // A PQ-native account has NO Ed25519 in its trust path: the envelope must
        // be a PQ-ONLY scheme (0x01/0x02/0x03), mapped to the address form byte.
        if (vr.hybrid)                                 return false;
        const uint8_t form = determ::pq_scheme_to_form(vr.scheme);
        if (form == 0)                                 return false;   // hybrid/unknown
        // Length sanity before the (throwing) recompute — belt-and-suspenders
        // with make_pq_anon_address's own check.
        if (vr.pq_pk.size() != determ::pq_form_pk_bytes(form)) return false;
        // Quantum-resistance binding: recompute the hash address from the
        // envelope's (form, ML-DSA key) and require it to equal `from`. Only the
        // holder of the key whose hash-commit is `from` can authorize a spend;
        // a quantum adversary substituting its own key changes the commitment,
        // and finding a different key that hashes to the same address is a
        // 2^256 preimage search.
        if (determ::make_pq_anon_address(form, vr.pq_pk) != tx.from) return false;
        return true;
    } catch (...) {
        return false;   // fail closed on anything unexpected
    }
}

} // namespace determ::chain
