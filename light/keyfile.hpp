// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light keyfile loader.
//
// Loads a plaintext signing keyfile and produces a NodeKey ready for
// Ed25519 signing via determ::crypto::sign.
//
// Scope (per the plan): NO passphrase-encrypted keyfile support. The
// light-client binary explicitly does NOT link libsodium, so it can't
// derive AES keys via Argon2id. Operators wanting passphrase
// protection use `determ-wallet keyfile-decrypt` to materialize a
// plaintext shape, hand that to `determ-light sign-tx`, then scrub.
//
// Accepted JSON shapes (interoperable with the wallet binary):
//
//   Canonical (account-create-batch / account-export single-record):
//     {"address": "0x...", "privkey_hex": "<64 hex chars>"}
//
//   Alternate (some external tooling):
//     {"anon_address": "0x...", "ed_priv_hex": "<64 hex>",
//      "ed_pub_hex":   "<64 hex>"}    (ed_pub_hex optional cross-check)
//
// On load, the loader:
//   1. Reads the JSON
//   2. Validates the anon address is canonical lowercase 0x+64-hex (S-028)
//   3. Decodes the 32-byte Ed25519 priv_seed
//   4. Derives the pubkey from the priv_seed
//   5. Confirms make_anon_address(derived_pubkey) == keyfile.address
//   6. (If ed_pub_hex present in alternate shape) cross-checks it too

#pragma once
#include <determ/crypto/keys.hpp>
#include <string>

namespace determ::light {

struct LightKeyfile {
    std::string             anon_address;   // canonical lowercase 0x+64-hex
    determ::crypto::NodeKey key;            // (pub, priv_seed)
};

// Load + validate a plaintext keyfile. Throws std::runtime_error
// (with a clear diagnostic) on any malformed-input case.
LightKeyfile load_light_keyfile(const std::string& path);

} // namespace determ::light
