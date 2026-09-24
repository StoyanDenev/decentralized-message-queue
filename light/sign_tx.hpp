// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light tx-signing primitive.
//
// Builds a canonical Determ Transaction (matching the byte-for-byte
// shape of src/chain/block.cpp::Transaction::signing_bytes), signs it
// with the keyfile's Ed25519 priv_seed via OpenSSL, and returns the
// signed envelope as JSON.
//
// Supported tx types (per the plan):
//   * TRANSFER  — from → to, amount, fee, nonce. Empty payload.
//   * STAKE     — from, amount (locked), fee, nonce. Empty payload.
//                 `to` is empty (the chain accepts `to=""` for STAKE).
//   * UNSTAKE   — from, amount (unlocked), fee, nonce. Empty payload.
//                 `to` is empty.
//
// The operator supplies the nonce (light-client mode — the operator
// has already fetched it via nonce-trustless or knows it offline).

#pragma once
#include "keyfile.hpp"
#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>

namespace determ::light {

enum class LightTxType : uint8_t {
    TRANSFER = 0,
    REGISTER = 1,
    DEREGISTER = 2,
    STAKE    = 3,
    UNSTAKE  = 4,
};

// Parse the user-facing --type flag. Accepts either upper-case
// mnemonic ("TRANSFER", "STAKE", "UNSTAKE") or the numeric form.
// Throws on unrecognized input. REGISTER / DEREGISTER are
// intentionally rejected by light-client sign-tx — those carry typed
// payloads (pubkey + region) that the light client doesn't construct;
// operators use `determ register` / `determ deregister` directly.
LightTxType parse_tx_type(const std::string& s);

// Sign the given (type, from, to, amount, fee, nonce) into the
// canonical Determ Transaction envelope JSON. Throws on any
// signing-layer failure (OpenSSL errors are exceptional).
//
// Output JSON keys:
//   type      — uppercase mnemonic ("TRANSFER" / "STAKE" / "UNSTAKE")
//   from      — keyfile's anon_address
//   to        — caller-supplied `to_str` (or "" for STAKE/UNSTAKE)
//   amount    — caller-supplied amount
//   fee       — caller-supplied fee
//   nonce     — caller-supplied nonce
//   payload   — "" (empty hex for all light-client types)
//   signature — 128-char hex (Ed25519 over signing_bytes)
//   sig       — alias for signature (wire-compat with chain
//               Transaction::from_json)
//   hash      — 64-char hex (SHA-256 of signing_bytes)
nlohmann::json sign_light_tx(const LightKeyfile& kf,
                              LightTxType type,
                              const std::string& to_str,
                              uint64_t amount,
                              uint64_t fee,
                              uint64_t nonce);

// Construct the canonical signing_bytes that Determ's chain expects
// (same byte order as src/chain/block.cpp::Transaction::signing_bytes).
// Exposed for cross-binary parity testing.
std::vector<uint8_t> compute_signing_bytes(LightTxType type,
                                            const std::string& from_str,
                                            const std::string& to_str,
                                            uint64_t amount,
                                            uint64_t fee,
                                            uint64_t nonce);

} // namespace determ::light
