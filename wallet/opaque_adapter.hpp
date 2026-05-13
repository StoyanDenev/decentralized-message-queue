// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#pragma once
// A2 Phase 5: OPAQUE adapter interface.
//
// Defines the surface the recovery flow uses to derive per-guardian
// unwrap keys via an OPAQUE-style handshake. v1.x Phase 5 ships a STUB
// implementation using libsodium primitives (Argon2id) directly — NOT
// real OPAQUE. Phase 6 swaps the stub for libopaque + liboprf with a
// hand-rolled CMake shim integrating the actual RFC 9807-compliant
// 3-message AKE.
//
// Why split the API now: the adapter signature is the contract between
// the recovery flow and whatever crypto library implements password-
// guarded threshold key recovery. Locking it down before the vendor
// work means the recovery.cpp swap in Phase 6 is a pure
// implementation change — no API surface revision.
//
// Stub limitations (read this if you're tempted to ship with the stub):
//   * No OPRF: a compromised guardian can offline-grind the password
//     against the stored record. OPAQUE prevents this; the stub does
//     not. THIS IS THE ENTIRE POINT OF USING OPAQUE.
//   * No mutual authentication: the stub authenticates the password
//     against the record, but does not authenticate the server to the
//     client. OPAQUE provides both.
//   * No forward secrecy: the stub's "session key" is deterministic
//     from password + salt. OPAQUE's AKE produces an ephemeral key.
//
// The stub is gated behind opaque_is_stub() which returns true. Real
// libopaque integration replaces the implementation and flips this
// flag to false. The recovery flow can refuse to use the stub for
// real wallets (caller's responsibility).

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace unchained::wallet::opaque_adapter {

// True if the currently-linked OPAQUE adapter is the Phase 5 stub
// (libsodium-direct, no OPRF, no real OPAQUE). False once Phase 6
// drops in libopaque + liboprf.
bool is_stub();

// Symbolic identifier for the active OPAQUE suite. Used in the
// recovery scheme tag and in any envelope AAD. Examples:
//   "stub-argon2id-2025"       — Phase 5 placeholder
//   "opaque-3dh-ristretto-sha256" — Phase 6 (RFC 9807 P-256-compatible
//                                            but instantiated on ristretto255)
std::string suite_name();

// Per-guardian registration. Output:
//   record:      bytes the guardian stores. Treat as public — a leak
//                does NOT compromise the password under real OPAQUE.
//                Under the stub, treat as confidential (a leak DOES
//                permit offline password grind).
//   export_key:  32-byte client-side derived key. Used to encrypt the
//                Shamir share before sending the (record, sealed_share)
//                pair to the guardian.
struct RegistrationResult {
    std::vector<uint8_t> record;
    std::vector<uint8_t> export_key;
};

// Run OPAQUE registration for one guardian. Returns std::nullopt on
// crypto failure (sodium_init, Argon2id, etc.).
std::optional<RegistrationResult>
register_password(const std::string& password,
                    uint8_t guardian_id);

// Run OPAQUE authentication for one guardian. Returns the same
// export_key that register_password produced IF the password matches
// the one used at registration. Returns std::nullopt otherwise.
//
// Under real OPAQUE this is the result of a 3-message AKE between
// client and guardian (and an attacker eavesdropping the messages
// learns nothing about the password). Under the stub, the function
// re-runs Argon2id deterministically — there are no messages.
std::optional<std::vector<uint8_t>>
authenticate_password(const std::string& password,
                        const std::vector<uint8_t>& record,
                        uint8_t guardian_id);

} // namespace unchained::wallet::opaque_adapter
