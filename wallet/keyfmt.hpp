// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// D2 (canonical binary at rest): the wallet's plaintext / encrypted keyfile
// and backup containers. No JSON, no structured text on any storage path —
// human-readable forms are non-authoritative CLI views only.
//
// House style (d33d410 Block container): 4-byte ASCII magic, explicit
// little-endian integers, length prefixes, decode requires the EXACT total
// length (trailing bytes reject), every bound refuses — never clamps.
//
// Containers (byte-exact):
//
//   DAK1 — plaintext account/keypair file, exactly 68 bytes:
//     [0..3] "DAK1"  [4..35] pubkey 32B raw  [36..67] priv_seed 32B raw
//     Decode DERIVES the pubkey from the seed (determ_ed25519_pubkey_from_
//     seed) and requires equality — this replaces the S-028 address cross-
//     check; the address is always "0x"+hex(pubkey), derived, never stored.
//
//   DAB1 — plaintext batch, exactly 6 + 64*count bytes:
//     [0..3] "DAB1"  [4..5] count u16 LE (1..=10000)
//     count x { pubkey 32B || priv_seed 32B }   (per-record derive check)
//
//   DNK1 — encrypted node keyfile:
//     [0..3] "DNK1"  [4..35] pubkey 32B raw  [36..39] env_len u32 LE
//     [40..] envelope bytes (canonical DWE container, exactly env_len,
//            must reach EOF exactly)
//     AAD = the raw 32-byte header pubkey. Envelope plaintext = the raw
//     32-byte priv_seed (no inner JSON). Decrypt verifies
//     derived-pubkey(seed) == header pubkey.
//
//   DSS1 — Shamir shares file:
//     [0..3] "DSS1"  [4] count u8 (1..=255)  [5..8] y_len u32 LE (1..=4096)
//     count x { x u8 (1..=255, all DISTINCT) || y y_len bytes }
//
//   DBE1 — backup envelopes file:
//     [0..3] "DBE1"  [4] count u8 (1..=255)
//     count x { share_index u8 (1..=255, DISTINCT) || env_len u32 LE
//               || DWE bytes (must parse as a canonical envelope) }
//
// (DRS1, the recovery-setup container, lives in wallet/recovery.hpp.)

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace determ::wallet::keyfmt {

inline constexpr size_t   DAK1_SIZE      = 68;
inline constexpr uint16_t DAB1_MAX_COUNT = 10000;   // matches account-create-batch MAX_COUNT
inline constexpr uint32_t DSS1_MAX_Y_LEN = 4096;

struct Keypair {
    std::array<uint8_t, 32> pubkey{};
    std::array<uint8_t, 32> priv_seed{};
};

struct NodeKeyfile {
    std::array<uint8_t, 32> pubkey{};
    std::vector<uint8_t>    env_bytes;   // canonical DWE container bytes
};

struct Share {
    uint8_t              x{0};
    std::vector<uint8_t> y;
};

struct ShareEnvelope {
    uint8_t              share_index{0};
    std::vector<uint8_t> env_bytes;      // canonical DWE container bytes
};

// Encoders throw std::invalid_argument on any field outside the structural
// bounds (writers fail closed). Decoders return nullopt unless the buffer
// is EXACTLY one well-formed container.
std::vector<uint8_t> encode_dak1(const Keypair& kp);
std::optional<Keypair> decode_dak1(const uint8_t* data, size_t len);
std::optional<Keypair> decode_dak1(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> encode_dab1(const std::vector<Keypair>& recs);
std::optional<std::vector<Keypair>> decode_dab1(const uint8_t* data, size_t len);
std::optional<std::vector<Keypair>> decode_dab1(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> encode_dnk1(const std::array<uint8_t, 32>& pubkey,
                                 const std::vector<uint8_t>& env_bytes);
std::optional<NodeKeyfile> decode_dnk1(const uint8_t* data, size_t len);
std::optional<NodeKeyfile> decode_dnk1(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> encode_dss1(const std::vector<Share>& shares);
std::optional<std::vector<Share>> decode_dss1(const uint8_t* data, size_t len);
std::optional<std::vector<Share>> decode_dss1(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> encode_dbe1(const std::vector<ShareEnvelope>& envs);
std::optional<std::vector<ShareEnvelope>> decode_dbe1(const uint8_t* data, size_t len);
std::optional<std::vector<ShareEnvelope>> decode_dbe1(const std::vector<uint8_t>& bytes);

} // namespace determ::wallet::keyfmt
