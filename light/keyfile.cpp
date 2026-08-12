// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light keyfile loader implementation. Reads the canonical binary
// DAK1 container (D2; the same 68-byte file determ-wallet account-import /
// account-export --out emit — a ~30-line mirror of wallet/keyfmt.cpp
// decode_dak1, since determ-light does not link wallet/). Pubkey
// derivation runs on the in-tree C99 Ed25519 (§3.15 swap 2026-07-03 —
// determ-light links zero OpenSSL).

#include "keyfile.hpp"
#include <determ/types.hpp>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/secure_zero.h>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace determ::light {

namespace {

constexpr size_t DAK1_SIZE = 68;

// Derive an Ed25519 pubkey from a 32-byte raw priv_seed via the C99
// RFC 8032 implementation. Matches src/crypto/keys.cpp semantics — same
// Ed25519 instantiation (PureEdDSA on Curve25519), same derivation.
PubKey derive_ed_pub(const std::array<uint8_t, 32>& priv_seed) {
    PubKey pub{};
    determ_ed25519_pubkey_from_seed(priv_seed.data(), pub.data());
    return pub;
}

} // namespace

LightKeyfile load_light_keyfile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open --keyfile: " + path);
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    if (f.bad()) {
        throw std::runtime_error("read failed on --keyfile: " + path);
    }

    // D2: canonical binary DAK1 only — exactly 68 bytes, 4-byte magic.
    // The JSON keyfile shapes are deleted pre-genesis (no migrations).
    if (bytes.size() != DAK1_SIZE || std::memcmp(bytes.data(), "DAK1", 4) != 0) {
        if (!bytes.empty()) determ_secure_zero(bytes.data(), bytes.size());
        throw std::runtime_error(
            "--keyfile is not a valid DAK1 binary keypair file (exactly "
            "68 bytes: magic 'DAK1' || pubkey 32B || priv_seed 32B; the "
            "legacy JSON keyfile shapes are no longer accepted)");
    }

    LightKeyfile out;
    std::memcpy(out.key.pub.data(),       bytes.data() + 4,  32);
    std::memcpy(out.key.priv_seed.data(), bytes.data() + 36, 32);
    determ_secure_zero(bytes.data(), bytes.size());

    // Derive-equality: the stored pubkey must equal the pubkey derived from
    // the stored seed (subsumes the JSON-era S-028 address cross-check —
    // a keyfile whose halves disagree is corrupt or tampered).
    PubKey derived = derive_ed_pub(out.key.priv_seed);
    if (derived != out.key.pub) {
        determ_secure_zero(out.key.priv_seed.data(),
                           out.key.priv_seed.size());
        throw std::runtime_error(
            "--keyfile pubkey does not match the pubkey derived from the "
            "priv seed (keyfile is corrupt or tampered)");
    }

    // anon_address = "0x" + lowercase 64-hex of pubkey (derived, never
    // stored — canonical by construction, S-028).
    out.anon_address = "0x" + to_hex(out.key.pub);
    return out;
}

} // namespace determ::light
