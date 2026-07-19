// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light A2 audit-layer tx builders (pre-launch register A2). Builds +
// signs a canonical, SUBMITTABLE ROTATE_AUDIT_KEY (TxType 15) or
// LOG_AUDIT_ACCESS (TxType 16) transaction from the account's Ed25519 keyfile
// — the client half of the audit layer whose consensus half shipped in
// commit 268cfaa (docs/proofs/AuditLayerSoundness.md).
//
// Both are FEE-ONLY: amount == 0, to == "". The account signs its own
// signing_bytes (the ordinary anon Ed25519 path), so any anon/bearer account
// can rotate its standing audit key or post a disclosure record. Output is a
// `Transaction::from_json`-compatible envelope (a validator accepts exactly
// what these build).
#pragma once
#include "keyfile.hpp"
#include <nlohmann/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace determ::light {

// ROTATE_AUDIT_KEY: SET (32-byte audit view-master pubkey) or CLEAR (empty
// payload — revoke the standing key). Throws if pubkey is present and not
// exactly 32 bytes.
nlohmann::json build_rotate_audit_key_tx(const LightKeyfile& kf,
                                         const std::optional<std::vector<uint8_t>>& pubkey,
                                         uint64_t fee,
                                         uint64_t nonce);

// LOG_AUDIT_ACCESS: an on-chain disclosure record. epoch is a specific epoch
// number or the full-history sentinel (0xFFFF_FFFF_FFFF_FFFF); auditor_pk +
// context_hash are each exactly 32 bytes. Throws on a length mismatch.
nlohmann::json build_log_audit_access_tx(const LightKeyfile& kf,
                                         uint64_t epoch,
                                         const std::vector<uint8_t>& auditor_pk,
                                         const std::vector<uint8_t>& context_hash,
                                         uint64_t fee,
                                         uint64_t nonce);

// NC-8 §5a: REGISTER_NOTE_KEY (TxType 17) — publish/rotate/revoke the account's
// standing recipient note_pk. SET (33-byte SEC1-compressed P-256 note_pk) or
// CLEAR (empty payload — revoke). Same fee-only, account-Ed25519-signed shape
// as the audit txs, so any anon/bearer payee can publish its note key; shares
// the signing_bytes helper for byte-parity. Throws if note_pk is present and
// not exactly 33 bytes. (EncryptedNoteDeliveryDesign.md §5.5.)
nlohmann::json build_register_note_key_tx(const LightKeyfile& kf,
                                          const std::optional<std::vector<uint8_t>>& note_pk,
                                          uint64_t fee,
                                          uint64_t nonce);

} // namespace determ::light
