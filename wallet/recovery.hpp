// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// A2 Phase 3: end-to-end create-recovery / recover composition.
//
// Composes Shamir SSS + AEAD envelope into the user-facing recovery
// primitive. Each Shamir share is wrapped in its own envelope keyed by
// a passphrase + per-guardian salt. v1.x Phase 3 ships single-actor
// recovery (user knows the passphrase, holds the envelopes in N
// distinct locations). Phase 4 replaces the passphrase + offline
// guardian model with libopaque-mediated AKE against N distinct
// guardian services.
//
// At-rest form (D2, canonical binary — the JSON document is deleted):
// the DRS1 container, byte-exact (integers LE; decode requires the EXACT
// total length; every bound refuses, never clamps):
//
//   [0..3]  "DRS1"          magic
//   [4..7]  version u32 LE  (== 1; the old "scheme" string is implied)
//   [8]     threshold u8    (>= 1)
//   [9]     share_count u8  (>= threshold)
//   [10..13] secret_len u32 LE (1..=4096)
//   [14]    checksum_len u8 (0 | 32)
//   [..]    pubkey_checksum  checksum_len bytes
//   share_count x { guardian_x u8 (1..=255, DISTINCT)
//                   || env_len u32 LE || DWE envelope bytes }
//
// On recover the checksum lets the wallet self-verify that the
// reconstructed seed regenerates the expected public key — catches
// envelope corruption that survived the AEAD tag (i.e., never, but
// defense in depth).

#include "shamir.hpp"
#include "envelope.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace determ::wallet::recovery {

struct RecoverySetup {
    uint32_t                              version{1};
    uint8_t                               threshold{0};
    uint8_t                               share_count{0};
    size_t                                secret_len{0};
    std::vector<uint8_t>                  guardian_x;       // x-coordinates 1..N
    std::vector<envelope::Envelope>       envelopes;         // size = share_count
    std::vector<uint8_t>                  pubkey_checksum;   // 32 bytes if present
};

// Build a fresh recovery setup. Splits `secret` into N shares with
// threshold T; wraps each in an envelope keyed by (password,
// per-guardian salt). guardian_id (0..N-1) is bound into each
// envelope's AAD so a share decrypted under guardian_i's salt cannot
// be replayed as guardian_j's share. The returned RecoverySetup is
// self-contained (no on-chain state).
//
// PBKDF2 directly off the password. Scheme tag "shamir-aead-passphrase".
RecoverySetup create(const std::vector<uint8_t>& secret,
                       const std::string& password,
                       uint8_t threshold,
                       uint8_t share_count,
                       const std::vector<uint8_t>& pubkey_checksum = {});

// Reconstruct the secret from a recovery setup using >= threshold
// envelopes. The caller supplies which guardian indices to attempt
// (0..share_count-1); each is decrypted via the password and the
// envelope's stored salt. Returns std::nullopt if fewer than
// `threshold` envelopes decrypt successfully OR if reconstruction
// yields a secret that fails the pubkey_checksum gate (when present).
std::optional<std::vector<uint8_t>>
recover(const RecoverySetup& setup,
          const std::string& password,
          const std::vector<uint8_t>& guardian_indices);

// Serialize / deserialize a complete RecoverySetup to/from the canonical
// binary DRS1 container (layout above). Used by the CLI's create-recovery
// / recover commands when persisting to disk or transmitting between user
// devices. to_bytes throws std::invalid_argument on out-of-bounds fields;
// from_bytes returns nullopt unless the buffer is EXACTLY one well-formed
// container (DISTINCT guardian_x enforced on decode).
std::vector<uint8_t> to_bytes(const RecoverySetup& setup);
std::optional<RecoverySetup> from_bytes(const uint8_t* data, size_t len);
std::optional<RecoverySetup> from_bytes(const std::vector<uint8_t>& bytes);

// Compute the canonical pubkey_checksum for an Ed25519 seed. SHA-256
// of the seed-derived public key. Stored in the recovery setup and
// re-verified on recovery so corrupted-but-tag-valid reconstructions
// can never silently succeed against a malformed wallet.
std::vector<uint8_t> seed_pubkey_checksum(const std::vector<uint8_t>& ed25519_seed);

} // namespace determ::wallet::recovery
