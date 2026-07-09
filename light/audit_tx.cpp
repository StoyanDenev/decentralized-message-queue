// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light A2 audit-layer tx builders — see audit_tx.hpp. The signing
// bytes match src/chain/block.cpp::Transaction::signing_bytes byte-for-byte,
// including the trailing payload (unlike the light sign_tx path, which is
// empty-payload only). The consensus shape gates live at
// src/node/validator.cpp (ROTATE_AUDIT_KEY / LOG_AUDIT_ACCESS cases) +
// include/determ/chain/block.hpp (AUDIT_KEY_PAYLOAD_SIZE / AUDIT_LOG_PAYLOAD_SIZE).

#include "audit_tx.hpp"
#include <determ/crypto/keys.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;

namespace {

// A2 wire constants — MUST match include/determ/chain/block.hpp.
constexpr int    TX_ROTATE_AUDIT_KEY = 15;
constexpr int    TX_LOG_AUDIT_ACCESS = 16;
constexpr size_t AUDIT_KEY_PAYLOAD_SIZE = 32;
constexpr size_t AUDIT_LOG_PAYLOAD_SIZE = 8 + 32 + 32;   // epoch || auditor_pk || ctx

// Canonical signing_bytes with a trailing payload:
//   u8(type) || from || 0x00 || to || 0x00 || u64_be(amount) || u64_be(fee)
//            || u64_be(nonce) || payload
// (amount/to are 0/"" for both audit tx types; kept explicit for parity.)
std::vector<uint8_t> audit_signing_bytes(int type, const std::string& from,
                                         uint64_t fee, uint64_t nonce,
                                         const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(1 + from.size() + 2 + 24 + payload.size());
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), from.begin(), from.end());
    out.push_back(0);
    // `to` is empty for both audit tx types.
    out.push_back(0);
    auto be64 = [&](uint64_t v){ for (int i = 7; i >= 0; --i) out.push_back((v >> (i*8)) & 0xFF); };
    be64(0);      // amount
    be64(fee);
    be64(nonce);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

json sign_audit_tx(const LightKeyfile& kf, int type, uint64_t fee, uint64_t nonce,
                   const std::vector<uint8_t>& payload, const char* type_name) {
    auto sb = audit_signing_bytes(type, kf.anon_address, fee, nonce, payload);
    Signature sig = determ::crypto::sign(kf.key, sb.data(), sb.size());
    Hash tx_hash  = determ::crypto::sha256(sb.data(), sb.size());
    return json{
        {"type",      type},
        {"type_name", type_name},
        {"from",      kf.anon_address},
        {"to",        ""},
        {"amount",    0},
        {"fee",       fee},
        {"nonce",     nonce},
        {"payload",   to_hex(payload.data(), payload.size())},
        {"signature", to_hex(sig)},
        {"sig",       to_hex(sig)},
        {"hash",      to_hex(tx_hash)},
    };
}

} // namespace

json build_rotate_audit_key_tx(const LightKeyfile& kf,
                               const std::optional<std::vector<uint8_t>>& pubkey,
                               uint64_t fee, uint64_t nonce) {
    std::vector<uint8_t> payload;
    if (pubkey) {
        if (pubkey->size() != AUDIT_KEY_PAYLOAD_SIZE)
            throw std::runtime_error("rotate-audit-key: --pubkey must be 32 bytes "
                                     "(64 hex); use --clear to revoke");
        payload = *pubkey;
    }
    return sign_audit_tx(kf, TX_ROTATE_AUDIT_KEY, fee, nonce, payload, "ROTATE_AUDIT_KEY");
}

json build_log_audit_access_tx(const LightKeyfile& kf, uint64_t epoch,
                               const std::vector<uint8_t>& auditor_pk,
                               const std::vector<uint8_t>& context_hash,
                               uint64_t fee, uint64_t nonce) {
    if (auditor_pk.size() != 32)
        throw std::runtime_error("log-audit-access: --auditor must be 32 bytes (64 hex)");
    if (context_hash.size() != 32)
        throw std::runtime_error("log-audit-access: --context must be 32 bytes (64 hex)");
    std::vector<uint8_t> payload;
    payload.reserve(AUDIT_LOG_PAYLOAD_SIZE);
    for (int i = 7; i >= 0; --i) payload.push_back((epoch >> (i*8)) & 0xFF);   // u64_be
    payload.insert(payload.end(), auditor_pk.begin(),   auditor_pk.end());
    payload.insert(payload.end(), context_hash.begin(), context_hash.end());
    return sign_audit_tx(kf, TX_LOG_AUDIT_ACCESS, fee, nonce, payload, "LOG_AUDIT_ACCESS");
}

} // namespace determ::light
