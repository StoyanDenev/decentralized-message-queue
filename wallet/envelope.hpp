// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// A2 Phase 2: AEAD envelope wrapping individual recovery shares / keyfiles.
//
// The passphrase-derived unwrap key protects wallet secrets at rest
// (encrypted keyfiles, Shamir backup shares, cold-sign archives).
//
// Wire format is VERSIONED by a 4-byte magic prefix. Two KDF layouts
// coexist; `decrypt` / `deserialize` auto-detect from the magic, so
// every envelope ever written stays readable:
//
//   DWE1 (legacy, PBKDF2 — still read+written on request):
//     [magic "DWE1"] [salt] [pbkdf2_iters u32 LE]
//     [nonce 12B]    [aad]  [ciphertext + 16B tag]
//     key = PBKDF2-HMAC-SHA-256(password, salt, iters, len=32)
//     hex serialization: magic.salt.iters.nonce.aad.ct   (6 dot-parts)
//
//   DWE2 (default for fresh envelopes, Argon2id — memory-hard):
//     [magic "DWE2"] [salt] [t_cost u32 LE | m_cost_kib u32 LE | lanes u32 LE]
//     [nonce 12B]    [aad]  [ciphertext + 16B tag]
//     key = Argon2id(password, salt, t_cost, m_cost_kib, lanes, len=32)
//     hex serialization: magic.salt.params.nonce.aad.ct  (6 dot-parts;
//       the params slot is 12 bytes here vs 4 bytes for DWE1 — the magic
//       disambiguates which the parser expects)
//
// AEAD is AES-256-GCM (12-byte nonce, 16-byte tag appended to the
// ciphertext) in BOTH layouts; only the KDF (and the params slot)
// differ. `encrypt` defaults to DWE2/Argon2id — the R58 keyfile KDF
// hardening. The legacy PBKDF2 path is retained (encrypt_pbkdf2) for
// interop and the `envelope encrypt --iters` CLI.

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace determ::wallet::envelope {

enum class Kdf : uint8_t { PBKDF2 = 0, ARGON2ID = 1 };

struct Envelope {
    Kdf                  kdf{Kdf::PBKDF2};
    std::vector<uint8_t> salt;
    uint32_t             pbkdf2_iters{0};   // DWE1 (PBKDF2) only
    uint32_t             argon2_t{0};       // DWE2 (Argon2id) passes
    uint32_t             argon2_m_kib{0};   // DWE2 memory cost, KiB
    uint32_t             argon2_p{0};       // DWE2 parallelism / lanes
    std::vector<uint8_t> nonce;             // exactly 12 bytes
    std::vector<uint8_t> aad;               // bound to ciphertext via GCM tag
    std::vector<uint8_t> ciphertext;        // includes 16-byte GCM tag at the end
};

// Legacy PBKDF2 cost. Tuned for desktop wallet — ~200 ms on a modern
// laptop. Retained for the DWE1 interop path.
inline constexpr uint32_t DEFAULT_PBKDF2_ITERS = 600'000;

// Argon2id defaults for fresh (DWE2) envelopes. m=64 MiB, t=3, p=1 sits
// comfortably above the OWASP Argon2id floor (19 MiB / t=2) and is
// memory-hard against GPU/ASIC cracking in a way PBKDF2 is not. ~150-300
// ms on a modern desktop. libsodium maps crypto_pwhash(opslimit=t,
// memlimit=m*1024) to these, so the parameters are oracle-cross-checkable
// by `determ-wallet test-argon2id-c99`.
inline constexpr uint32_t DEFAULT_ARGON2_T_COST     = 3;
inline constexpr uint32_t DEFAULT_ARGON2_M_COST_KIB = 65'536;   // 64 MiB
inline constexpr uint32_t DEFAULT_ARGON2_LANES      = 1;

// Salt length used for fresh envelopes. 16 bytes is plenty given the
// per-envelope nonce; longer salts add no useful entropy.
inline constexpr size_t   DEFAULT_SALT_LEN     = 16;

// Encrypt `plaintext` (a Shamir share, an identity key, etc.) under a
// passphrase-derived key. Defaults to the memory-hard Argon2id KDF
// (DWE2). AAD is optional binding data (guardian_id, share-index, pubkey,
// etc.) — must be supplied identically at decrypt time.
Envelope encrypt(const std::vector<uint8_t>& plaintext,
                   const std::string& password,
                   const std::vector<uint8_t>& aad = {});

// Explicit Argon2id encrypt with caller-chosen cost parameters.
Envelope encrypt_argon2id(const std::vector<uint8_t>& plaintext,
                            const std::string& password,
                            const std::vector<uint8_t>& aad = {},
                            uint32_t t_cost     = DEFAULT_ARGON2_T_COST,
                            uint32_t m_cost_kib = DEFAULT_ARGON2_M_COST_KIB,
                            uint32_t lanes      = DEFAULT_ARGON2_LANES);

// Legacy PBKDF2 encrypt (DWE1). Retained for interop and the
// `envelope encrypt --iters` CLI; new keyfiles should prefer Argon2id.
Envelope encrypt_pbkdf2(const std::vector<uint8_t>& plaintext,
                          const std::string& password,
                          const std::vector<uint8_t>& aad = {},
                          uint32_t iters = DEFAULT_PBKDF2_ITERS);

// Decrypt an envelope. Auto-selects the KDF from env.kdf (set by
// deserialize per the magic). Returns the plaintext on success;
// std::nullopt on AEAD tag failure (wrong password, tampered ciphertext,
// mismatched AAD, or otherwise inconsistent envelope).
std::optional<std::vector<uint8_t>>
decrypt(const Envelope& env,
          const std::string& password,
          const std::vector<uint8_t>& aad = {});

// Canonical hex encoding for CLI / interchange. 6 dot-separated parts:
//   DWE1: "<magic>.<salt>.<iters>.<nonce>.<aad>.<ct>"
//   DWE2: "<magic>.<salt>.<t|m|p>.<nonce>.<aad>.<ct>"
// Dot-separated so a single shell-quoted string survives copy/paste.
std::string serialize(const Envelope& env);
std::optional<Envelope> deserialize(const std::string& blob);

} // namespace determ::wallet::envelope
