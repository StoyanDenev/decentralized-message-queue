// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light tx-signing implementation. Builds canonical signing
// bytes (matching src/chain/block.cpp::Transaction::signing_bytes
// byte-for-byte) and signs via OpenSSL Ed25519.

#include "sign_tx.hpp"
#include <determ/crypto/keys.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;

LightTxType parse_tx_type(const std::string& s) {
    if (s == "TRANSFER" || s == "transfer" || s == "0") return LightTxType::TRANSFER;
    if (s == "STAKE"    || s == "stake"    || s == "3") return LightTxType::STAKE;
    if (s == "UNSTAKE"  || s == "unstake"  || s == "4") return LightTxType::UNSTAKE;
    throw std::runtime_error(
        "--type must be one of TRANSFER|STAKE|UNSTAKE (got '" + s + "')");
}

static const char* tx_type_name(LightTxType t) {
    switch (t) {
    case LightTxType::TRANSFER:   return "TRANSFER";
    case LightTxType::STAKE:      return "STAKE";
    case LightTxType::UNSTAKE:    return "UNSTAKE";
    case LightTxType::REGISTER:   return "REGISTER";
    case LightTxType::DEREGISTER: return "DEREGISTER";
    }
    return "?";
}

std::vector<uint8_t> compute_signing_bytes(LightTxType type,
                                            const std::string& from_str,
                                            const std::string& to_str,
                                            uint64_t amount,
                                            uint64_t fee,
                                            uint64_t nonce) {
    // Layout (matches src/chain/block.cpp::Transaction::signing_bytes):
    //   u8(type)
    //   from || 0x00
    //   to   || 0x00
    //   u64_be(amount)
    //   u64_be(fee)
    //   u64_be(nonce)
    //   payload   (empty for all light-client tx types)
    std::vector<uint8_t> out;
    out.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24);
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), from_str.begin(), from_str.end());
    out.push_back(0);
    out.insert(out.end(), to_str.begin(), to_str.end());
    out.push_back(0);
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
    return out;
}

nlohmann::json sign_light_tx(const LightKeyfile& kf,
                              LightTxType type,
                              const std::string& to_str,
                              uint64_t amount,
                              uint64_t fee,
                              uint64_t nonce) {

    // The chain rejects TRANSFER with amount==0 (degenerate). STAKE
    // with amount==0 is also degenerate. UNSTAKE with amount==0 is
    // similarly rejected.
    if (amount == 0) {
        throw std::runtime_error(
            "sign-tx: --amount must be > 0 (got 0; chain rejects zero-"
            "amount " + std::string(tx_type_name(type)) + ")");
    }

    // For STAKE / UNSTAKE the `to` field has no semantic meaning and
    // the chain accepts `to=""`. For TRANSFER the operator MUST supply
    // a non-empty target.
    if (type == LightTxType::TRANSFER && to_str.empty()) {
        throw std::runtime_error("sign-tx: TRANSFER requires non-empty --to");
    }

    // Build canonical signing_bytes.
    auto sb = compute_signing_bytes(type, kf.anon_address, to_str,
                                       amount, fee, nonce);

    // Ed25519 sign via the project's existing crypto::sign helper
    // (OpenSSL EVP_DigestSign with EVP_PKEY_ED25519).
    Signature sig = determ::crypto::sign(kf.key, sb.data(), sb.size());

    // Recompute the tx hash (SHA-256 over signing_bytes) — what the
    // chain stores as `hash` in Transaction::compute_hash.
    Hash tx_hash = determ::crypto::sha256(sb.data(), sb.size());

    // Emit the canonical envelope. We populate BOTH `signature` (the
    // sign-anon-tx wire shape) AND `sig` (the chain
    // Transaction::from_json wire shape) so the same envelope round-
    // trips through submit_tx without rewriting.
    json out = {
        {"type",      tx_type_name(type)},
        {"from",      kf.anon_address},
        {"to",        to_str},
        {"amount",    amount},
        {"fee",       fee},
        {"nonce",     nonce},
        {"payload",   ""},
        {"signature", to_hex(sig)},
        {"sig",       to_hex(sig)},
        {"hash",      to_hex(tx_hash)},
    };
    return out;
}

} // namespace determ::light
