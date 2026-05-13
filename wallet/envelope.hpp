// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#pragma once
// A2 Phase 2: AEAD envelope wrapping individual recovery shares.
//
// The OPAQUE-guarded recovery design (per A2 plan §"Mechanism") uses
// per-guardian envelopes whose unwrap key is derived from a successful
// OPAQUE AKE handshake with that guardian. v1.x Phase 2 lands the
// envelope format and the AEAD wrap/unwrap; Phase 3 wires libopaque
// to produce the key. A passphrase-derived key (PBKDF2-HMAC-SHA-256)
// is the Phase 2 placeholder so the envelope layer ships testable
// without libopaque on the build path yet.
//
// Wire format (canonical, little-endian where noted):
//   [magic: 4B = "DWE1"]   // unchained wallet envelope v1
//   [salt_len: u8][salt: bytes]               // PBKDF2 salt (>= 16 bytes)
//   [pbkdf2_iters: u32 LE]                    // KDF cost parameter
//   [nonce: 12B]                              // AES-GCM 96-bit nonce
//   [aad_len: u16 LE][aad: bytes]             // bound into the tag
//   [ct_len: u32 LE][ciphertext + tag: bytes] // tag is the final 16 B
//
// Key derivation (Phase 2 placeholder):
//   key = PBKDF2-HMAC-SHA-256(password, salt, iters, len=32)
//
// In Phase 3, key will be the 32-byte output of the OPAQUE AKE session
// (or HKDF-expansion thereof). Envelope format stays stable; only the
// key source changes.

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace unchained::wallet::envelope {

struct Envelope {
    std::vector<uint8_t> salt;
    uint32_t             pbkdf2_iters{0};
    std::vector<uint8_t> nonce;        // exactly 12 bytes
    std::vector<uint8_t> aad;          // bound to ciphertext via GCM tag
    std::vector<uint8_t> ciphertext;   // includes 16-byte GCM tag at the end
};

// Default PBKDF2 cost. Tuned for desktop wallet — ~200 ms on a modern
// laptop. Raise for higher-value secrets; lower not recommended.
inline constexpr uint32_t DEFAULT_PBKDF2_ITERS = 600'000;

// Salt length used for fresh envelopes. 16 bytes is plenty given the
// per-envelope nonce; longer salts add no useful entropy.
inline constexpr size_t   DEFAULT_SALT_LEN     = 16;

// Encrypt `plaintext` (a Shamir share, an identity key, etc.) under a
// passphrase-derived key. Returns the canonical envelope. AAD is
// optional binding data (guardian_id, share-index, version tag, etc.)
// — must be supplied identically at decrypt time.
Envelope encrypt(const std::vector<uint8_t>& plaintext,
                   const std::string& password,
                   const std::vector<uint8_t>& aad = {},
                   uint32_t iters = DEFAULT_PBKDF2_ITERS);

// Decrypt an envelope. Returns the plaintext on success; std::nullopt
// on AEAD tag failure (wrong password, tampered ciphertext, mismatched
// AAD, or otherwise inconsistent envelope).
std::optional<std::vector<uint8_t>>
decrypt(const Envelope& env,
          const std::string& password,
          const std::vector<uint8_t>& aad = {});

// Canonical hex encoding for CLI / interchange:
//   "<magic_hex>.<salt_hex>.<iters_hex>.<nonce_hex>.<aad_hex>.<ct_hex>"
// Dot-separated so a single shell-quoted string survives copy/paste.
std::string serialize(const Envelope& env);
std::optional<Envelope> deserialize(const std::string& blob);

} // namespace unchained::wallet::envelope
