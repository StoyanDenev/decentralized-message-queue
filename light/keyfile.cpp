// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light keyfile loader implementation. Mirrors the parsing /
// validation logic in wallet/main.cpp::cmd_sign_anon_tx, minus the
// libsodium-specific bits (we derive the pubkey via OpenSSL Ed25519
// raw-key APIs — same primitive crypto, no Argon2 / libopaque needed).

#include "keyfile.hpp"
#include <determ/types.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace determ::light {

namespace {

bool is_anon_shape(const std::string& s) {
    if (s.size() != 66) return false;
    if (s[0] != '0' || s[1] != 'x') return false;
    for (size_t i = 2; i < s.size(); ++i) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9')
               || (c >= 'a' && c <= 'f')
               || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

bool is_canonical_anon(const std::string& s) {
    if (!is_anon_shape(s)) return false;
    for (size_t i = 2; i < s.size(); ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'F') return false;
    }
    return true;
}

// Derive an Ed25519 pubkey from a 32-byte raw priv_seed via OpenSSL
// (no libsodium). Matches src/crypto/keys.cpp::generate_node_key
// semantics — same Ed25519 instantiation (PureEdDSA on Curve25519).
PubKey derive_ed_pub(const std::array<uint8_t, 32>& priv_seed) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, priv_seed.data(), 32);
    if (!pkey) {
        throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
    }
    PubKey pub{};
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1
        || len != 32) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    EVP_PKEY_free(pkey);
    return pub;
}

} // namespace

LightKeyfile load_light_keyfile(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("cannot open --keyfile: " + path);
    }
    nlohmann::json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("--keyfile is not valid JSON: ") + e.what());
    }
    if (!j.is_object()) {
        throw std::runtime_error("--keyfile must be a JSON object");
    }

    std::string address;
    std::string priv_hex;
    std::string pub_hex_hint;

    if (j.contains("address") && j["address"].is_string()
        && j.contains("privkey_hex") && j["privkey_hex"].is_string()) {
        address  = j["address"].get<std::string>();
        priv_hex = j["privkey_hex"].get<std::string>();
    } else if (j.contains("anon_address") && j["anon_address"].is_string()
               && j.contains("ed_priv_hex") && j["ed_priv_hex"].is_string()) {
        address  = j["anon_address"].get<std::string>();
        priv_hex = j["ed_priv_hex"].get<std::string>();
        if (j.contains("ed_pub_hex") && j["ed_pub_hex"].is_string()) {
            pub_hex_hint = j["ed_pub_hex"].get<std::string>();
        }
    } else {
        throw std::runtime_error(
            "--keyfile shape error: expected either\n"
            "  {\"address\":\"0x...\",\"privkey_hex\":\"...\"}\n"
            "  or\n"
            "  {\"ed_priv_hex\":\"...\",\"ed_pub_hex\":\"...\","
            "\"anon_address\":\"0x...\"}");
    }

    if (!is_canonical_anon(address)) {
        throw std::runtime_error(
            "--keyfile address is not canonical lowercase 0x+64-hex "
            "(S-028); got '" + address + "'");
    }
    if (priv_hex.size() != 64) {
        throw std::runtime_error(
            "keyfile priv must be 64 hex chars (32-byte Ed25519 priv_seed); "
            "got length " + std::to_string(priv_hex.size()));
    }
    std::vector<uint8_t> seed_bytes;
    try {
        seed_bytes = from_hex(priv_hex);
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("keyfile priv is not valid hex: ") + e.what());
    }
    if (seed_bytes.size() != 32) {
        throw std::runtime_error(
            "keyfile priv decoded length must be 32; got "
            + std::to_string(seed_bytes.size()));
    }

    LightKeyfile out;
    std::copy(seed_bytes.begin(), seed_bytes.end(),
              out.key.priv_seed.begin());
    out.key.pub = derive_ed_pub(out.key.priv_seed);

    // anon_address = "0x" + lowercase 64-hex of pubkey.
    std::string derived = "0x" + to_hex(out.key.pub);
    if (derived != address) {
        throw std::runtime_error(
            "--keyfile address mismatch: keyfile.address=" + address
            + " derived-from-priv=" + derived
            + " (keyfile is corrupt — address must match Ed25519 pubkey "
              "of the priv seed per S-028)");
    }
    if (!pub_hex_hint.empty()) {
        std::string hint_lower = pub_hex_hint;
        for (auto& c : hint_lower) {
            if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        }
        if (hint_lower != to_hex(out.key.pub)) {
            throw std::runtime_error(
                "--keyfile ed_pub_hex mismatch: ed_pub_hex=" + pub_hex_hint
                + " derived=" + to_hex(out.key.pub));
        }
    }

    out.anon_address = address;
    return out;
}

} // namespace determ::light
