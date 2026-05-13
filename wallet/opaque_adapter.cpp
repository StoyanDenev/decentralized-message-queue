// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
// A2 Phase 5 STUB implementation. NOT real OPAQUE. NOT for production
// secrets. See opaque_adapter.hpp for the security caveats.
//
// What this stub does:
//   register_password(pw, gid):
//     1. Generate a fresh 16-byte salt.
//     2. record  = [version || guardian_id || salt]      (29 bytes)
//     3. export_key = Argon2id(pw, salt || gid, 32)
//
//   authenticate_password(pw, record, gid):
//     1. Parse record. Reject on version mismatch or guardian_id mismatch.
//     2. Recompute export_key = Argon2id(pw, salt || gid, 32)
//     3. Return it.
//
// The stub gives the wallet's recovery flow a working surface to call
// against while libopaque vendoring proceeds in Phase 6. The Argon2id
// parameters match what Phase 6's OPAQUE configuration will use, so
// the wall-clock cost is representative of real operation.

#include "opaque_adapter.hpp"
#include "opaque_primitives.hpp"
#include <sodium.h>
#include <cstring>

namespace unchained::wallet::opaque_adapter {

namespace {

constexpr uint8_t  STUB_VERSION = 0x01;
constexpr size_t   STUB_SALT_LEN = crypto_pwhash_SALTBYTES;  // libsodium fixes this at 16
constexpr size_t   STUB_RECORD_LEN = 1 + 1 + STUB_SALT_LEN;  // ver || gid || salt
constexpr size_t   EXPORT_KEY_LEN  = 32;
// Argon2id cost — must match what Phase 6 will use for OPAQUE so the
// recovery flow's wall-clock behavior is representative now.
constexpr uint64_t STUB_OPS_LIMIT  = 3;
constexpr size_t   STUB_MEM_LIMIT  = 64ull * 1024 * 1024;

std::vector<uint8_t> derive_export_key(const std::string& password,
                                          const std::vector<uint8_t>& salt,
                                          uint8_t guardian_id) {
    // Domain-separate by mixing guardian_id into the password input.
    // The salt is the libsodium-required 16-byte field; the gid is
    // appended to the password so two registrations with the same
    // password and salt but different guardians yield distinct keys.
    std::vector<uint8_t> pw_bytes(password.begin(), password.end());
    pw_bytes.push_back(guardian_id);
    pw_bytes.push_back(0x00);   // separator
    pw_bytes.push_back(0x00);
    pw_bytes.push_back(0x00);
    return primitives::argon2id(pw_bytes, salt, EXPORT_KEY_LEN,
                                   STUB_OPS_LIMIT, STUB_MEM_LIMIT);
}

} // namespace

bool is_stub() { return true; }

std::string suite_name() { return "stub-argon2id-v1"; }

std::optional<RegistrationResult>
register_password(const std::string& password,
                    uint8_t guardian_id) {
    if (!primitives::init_libsodium()) return std::nullopt;
    auto salt = primitives::random_bytes(STUB_SALT_LEN);
    if (salt.size() != STUB_SALT_LEN) return std::nullopt;

    auto export_key = derive_export_key(password, salt, guardian_id);
    if (export_key.size() != EXPORT_KEY_LEN) return std::nullopt;

    RegistrationResult result;
    result.record.reserve(STUB_RECORD_LEN);
    result.record.push_back(STUB_VERSION);
    result.record.push_back(guardian_id);
    result.record.insert(result.record.end(), salt.begin(), salt.end());
    result.export_key = std::move(export_key);
    return result;
}

std::optional<std::vector<uint8_t>>
authenticate_password(const std::string& password,
                        const std::vector<uint8_t>& record,
                        uint8_t guardian_id) {
    if (!primitives::init_libsodium()) return std::nullopt;
    if (record.size() != STUB_RECORD_LEN) return std::nullopt;
    if (record[0] != STUB_VERSION)        return std::nullopt;
    if (record[1] != guardian_id)         return std::nullopt;
    std::vector<uint8_t> salt(record.begin() + 2, record.end());
    auto export_key = derive_export_key(password, salt, guardian_id);
    if (export_key.size() != EXPORT_KEY_LEN) return std::nullopt;
    return export_key;
}

} // namespace unchained::wallet::opaque_adapter
