// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// A2 Phase 2: AEAD envelope wrapping individual recovery shares / keyfiles.
//
// The passphrase-derived unwrap key protects wallet secrets at rest
// (encrypted keyfiles, Shamir backup shares, cold-sign archives).
//
// Canonical at-rest form is BINARY (D2: no JSON / no structured text on
// storage paths). The container is versioned by a 4-byte magic prefix;
// two KDF layouts coexist and `decrypt` / `deserialize_bytes` auto-detect
// from the magic. Byte-exact layout (all integers little-endian; decode
// requires EXACT total length — trailing bytes reject; every bound
// refuses, never clamps):
//
//   [0..3]   magic       "DWE1" (44 57 45 31) | "DWE2" (44 57 45 32)
//   [4]      salt_len    u8, accept 8..=64 (writers emit 16)
//   [5..]    salt        salt_len bytes
//   params   DWE1: pbkdf2_iters u32 LE            (1..=MAX_PBKDF2_ITERS)
//            DWE2: t_cost u32 | m_cost_kib u32 | lanes u32
//                  (existing MAX_* caps, m >= 8*lanes, t,p >= 1)
//   nonce    12 bytes
//   aad_len  u16 LE, accept 0..=MAX_AAD_LEN
//   aad      aad_len bytes
//   ct_len   u32 LE, accept 16..=MAX_CT_LEN
//   ct       ct_len bytes (body || 16B GCM tag)
//
// KDFs: DWE1 key = PBKDF2-HMAC-SHA-256(password, salt, iters, len=32);
// DWE2 key = Argon2id(password, salt, t, m_kib, lanes, len=32). AEAD is
// AES-256-GCM (12-byte nonce, 16-byte tag appended to the ciphertext) in
// BOTH layouts; only the KDF (and the params slot) differ. `encrypt`
// defaults to DWE2/Argon2id — the R58 keyfile KDF hardening. The legacy
// PBKDF2 path is retained (encrypt_pbkdf2) for interop and the
// `envelope encrypt --iters` CLI.
//
// The legacy dot-separated hex TEXT serialization is DELETED (pre-genesis,
// no migrations): readers accept only the binary container (or its plain
// lowercase-hex view via `deserialize`, CLI/interchange only).

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

// Upper bounds on KDF cost read from an UNTRUSTED envelope. decode + decrypt
// reject (fail-closed, no KDF run) any envelope exceeding these, closing an
// unbounded-work DoS: a tampered params slot could otherwise drive the KDF for
// effectively unbounded time (one flipped byte took t_cost 3 -> 67,108,867).
// The caps sit far above every value the encrypt paths ever write (Argon2id
// always uses the fixed defaults above; PBKDF2 --iters is the sole tunable), so
// no legitimately-created envelope is ever rejected. Owner-tunable.
inline constexpr uint32_t MAX_ARGON2_T_COST     = 64;          // vs default 3
inline constexpr uint32_t MAX_ARGON2_M_COST_KIB = 1u << 20;    // 1 GiB vs 64 MiB
inline constexpr uint32_t MAX_ARGON2_LANES      = 16;          // vs default 1
inline constexpr uint32_t MAX_PBKDF2_ITERS      = 100'000'000; // ~seconds vs 600k

// Salt length used for fresh envelopes. 16 bytes is plenty given the
// per-envelope nonce; longer salts add no useful entropy.
inline constexpr size_t   DEFAULT_SALT_LEN     = 16;

// Structural bounds on the binary container, enforced by serialize_bytes
// (throw) and deserialize_bytes (nullopt). AAD is a short binding label
// (share-index, raw pubkey, guardian id); ciphertext covers every wallet
// artifact (seeds, shares, cold-sign payloads) with a 1 MiB ceiling that
// also caps decode-side allocation from hostile length fields.
inline constexpr size_t   MAX_AAD_LEN = 256;
inline constexpr uint32_t MAX_CT_LEN  = 1u << 20;   // 1 MiB, includes 16B tag

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

// Canonical binary container (the D2 at-rest form; layout in the header
// comment above). serialize_bytes throws std::invalid_argument on any
// field outside the structural bounds; deserialize_bytes returns nullopt
// unless the buffer is EXACTLY one well-formed container (trailing bytes
// reject; every length/bound refuses, never clamps).
std::vector<uint8_t> serialize_bytes(const Envelope& env);
std::optional<Envelope> deserialize_bytes(const uint8_t* data, size_t len);
std::optional<Envelope> deserialize_bytes(const std::vector<uint8_t>& bytes);

// Hex text VIEW of the canonical bytes — CLI / interchange only, never an
// at-rest authority. serialize = lowercase hex of serialize_bytes;
// deserialize = strict hex decode (even length, hex chars only — the
// legacy dot-separated form is rejected) then deserialize_bytes.
std::string serialize(const Envelope& env);
std::optional<Envelope> deserialize(const std::string& blob);

} // namespace determ::wallet::envelope
