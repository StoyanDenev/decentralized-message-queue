// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
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
// File layout for a recovery setup:
//   recovery_meta.json     — wallet identity, threshold, N, scheme
//   guardian_0.env         — envelope wrapping share 0 (x=1)
//   guardian_1.env         — envelope wrapping share 1 (x=2)
//   ...
//   guardian_{N-1}.env     — envelope wrapping share N-1 (x=N)
//
// recovery_meta.json schema (canonical, used by both create + recover):
//   { "version": 1,
//     "scheme": "shamir-aead-passphrase",  // Phase 4: "shamir-aead-opaque"
//     "threshold": T,
//     "share_count": N,
//     "secret_len": SECRET_BYTES,
//     "guardian_x": [1, 2, ..., N],
//     "checksum": SHA-256(seed_pub) }   // optional public-key checksum
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

namespace unchained::wallet::recovery {

struct RecoverySetup {
    uint32_t                              version{1};
    std::string                           scheme;
    uint8_t                               threshold{0};
    uint8_t                               share_count{0};
    size_t                                secret_len{0};
    std::vector<uint8_t>                  guardian_x;       // x-coordinates 1..N
    std::vector<envelope::Envelope>       envelopes;         // size = share_count
    std::vector<uint8_t>                  pubkey_checksum;   // 32 bytes if present
    // A2 Phase 7: per-guardian OPAQUE registration records. Empty when
    // scheme == "shamir-aead-passphrase" (Phase 3 behavior).
    // Populated when scheme == "shamir-aead-opaque-*"; index i holds
    // the bytes the guardian would store from opaque_register(pw, i).
    std::vector<std::vector<uint8_t>>     opaque_records;
};

// Build a fresh recovery setup. Splits `secret` into N shares with
// threshold T; wraps each in an envelope keyed by (password,
// per-guardian salt). guardian_id (0..N-1) is bound into each
// envelope's AAD so a share decrypted under guardian_i's salt cannot
// be replayed as guardian_j's share. The returned RecoverySetup is
// self-contained (no on-chain state).
//
// Phase 3 (legacy): PBKDF2 directly off the password. Scheme tag
// "shamir-aead-passphrase".
RecoverySetup create(const std::vector<uint8_t>& secret,
                       const std::string& password,
                       uint8_t threshold,
                       uint8_t share_count,
                       const std::vector<uint8_t>& pubkey_checksum = {});

// A2 Phase 7: alternative create() that derives each envelope's
// unwrap key via the OPAQUE adapter instead of PBKDF2 directly. Per
// guardian:
//   1. opaque_adapter::register_password(pw, gid) → (record, export_key)
//   2. Treat export_key as the password input to envelope::encrypt
//      (the AEAD layer still wraps the share; the OPAQUE adapter
//      replaces the password→key derivation).
// The OPAQUE registration record for each guardian is stored in
// setup.opaque_records[i] and persisted alongside the envelope.
//
// Scheme tag: "shamir-aead-opaque-" + adapter::suite_name(). When
// Phase 6 swaps the stub for real libopaque, existing recovery
// setups created under the stub remain identifiable by their suite
// tag — the recover() path errors on suite mismatch.
RecoverySetup create_opaque(const std::vector<uint8_t>& secret,
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
//
// Dispatch: if setup.scheme starts with "shamir-aead-opaque-", routes
// through the OPAQUE adapter; otherwise uses the Phase 3 PBKDF2 path.
std::optional<std::vector<uint8_t>>
recover(const RecoverySetup& setup,
          const std::string& password,
          const std::vector<uint8_t>& guardian_indices);

// Serialize / deserialize a complete RecoverySetup to/from a single
// JSON document. Used by the CLI's create-recovery / recover commands
// when persisting to disk or transmitting between user devices.
std::string to_json(const RecoverySetup& setup);
std::optional<RecoverySetup> from_json(const std::string& blob);

// Compute the canonical pubkey_checksum for an Ed25519 seed. SHA-256
// of the seed-derived public key. Stored in the recovery setup and
// re-verified on recovery so corrupted-but-tag-valid reconstructions
// can never silently succeed against a malformed wallet.
std::vector<uint8_t> seed_pubkey_checksum(const std::vector<uint8_t>& ed25519_seed);

} // namespace unchained::wallet::recovery
