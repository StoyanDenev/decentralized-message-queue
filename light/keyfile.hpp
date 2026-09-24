// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light keyfile loader.
//
// Loads a plaintext signing keyfile and produces a NodeKey ready for
// Ed25519 signing via determ::crypto::sign.
//
// Scope (per the plan): NO passphrase-encrypted keyfile support. The
// light-client binary can't derive AES keys via Argon2id. Operators
// wanting passphrase protection use `determ-wallet keyfile-decrypt` to
// materialize a plaintext shape, hand that to `determ-light sign-tx`,
// then scrub.
//
// Accepted format (D2, canonical binary only — the JSON keyfile shapes
// are deleted pre-genesis): the DAK1 container, exactly 68 bytes:
//
//   [0..3] "DAK1"  [4..35] pubkey 32B raw  [36..67] priv_seed 32B raw
//
// On load, the loader:
//   1. Reads the raw bytes and requires the EXACT 68-byte length + magic
//   2. Derives the pubkey from the priv_seed (in-tree C99 Ed25519)
//   3. Requires derived pubkey == stored pubkey (the derive-equality
//      check; subsumes the JSON-era S-028 address cross-check)
//   4. Derives anon_address = "0x" + lowercase hex(pubkey) — never stored

#pragma once
#include <determ/crypto/keys.hpp>
#include <string>

namespace determ::light {

struct LightKeyfile {
    std::string             anon_address;   // canonical lowercase 0x+64-hex
    determ::crypto::NodeKey key;            // (pub, priv_seed)
};

// Load + validate a plaintext DAK1 keyfile. Throws std::runtime_error
// (with a clear diagnostic) on any malformed-input case.
LightKeyfile load_light_keyfile(const std::string& path);

} // namespace determ::light
