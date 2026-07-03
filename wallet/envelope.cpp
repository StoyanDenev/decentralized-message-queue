// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// 1c (2026-07-03): the envelope now runs on determ::c99 (PBKDF2-HMAC-SHA256,
// AES-256-GCM, OS entropy) instead of OpenSSL. FORMAT-COMPATIBLE byte-for-
// byte: both primitives are validated byte-equal vs OpenSSL (`determ
// test-sha2-c99` / `test-aes-c99` §Q9 gates), the nonce stays 12 bytes and
// the on-disk layout (ct || 16-byte tag, "DWE1" hex serialization) is
// untouched — every existing envelope decrypts identically.
#include "envelope.hpp"
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/aes/aes.h>
#include <determ/crypto/rng/rng.h>
#include <determ/crypto/secure_zero.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace determ::wallet::envelope {

static constexpr uint32_t MAGIC_LE = 0x31455744;   // "DWE1" little-endian
static constexpr size_t   NONCE_LEN = 12;
static constexpr size_t   TAG_LEN   = 16;
static constexpr size_t   KEY_LEN   = 32;

namespace {

std::vector<uint8_t> derive_key(const std::string& password,
                                  const std::vector<uint8_t>& salt,
                                  uint32_t iters) {
    std::vector<uint8_t> key(KEY_LEN);
    if (determ_pbkdf2_hmac_sha256(
            reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            salt.data(), salt.size(), iters, key.data(), KEY_LEN) != 0) {
        throw std::runtime_error("envelope: PBKDF2 derivation failed");
    }
    return key;
}

} // namespace

Envelope encrypt(const std::vector<uint8_t>& plaintext,
                   const std::string& password,
                   const std::vector<uint8_t>& aad,
                   uint32_t iters) {
    if (iters == 0)
        throw std::invalid_argument("envelope: iters must be > 0");

    Envelope env;
    env.salt.resize(DEFAULT_SALT_LEN);
    env.nonce.resize(NONCE_LEN);
    if (determ_rng_bytes(env.salt.data(),  env.salt.size())  != 0
        || determ_rng_bytes(env.nonce.data(), env.nonce.size()) != 0)
        throw std::runtime_error("envelope: OS entropy source failed");
    env.pbkdf2_iters = iters;
    env.aad = aad;

    auto key = derive_key(password, env.salt, iters);

    // ciphertext layout unchanged: ct-body || 16-byte tag.
    env.ciphertext.resize(plaintext.size() + TAG_LEN);
    determ_aes256_gcm_encrypt(key.data(), env.nonce.data(),
                              aad.empty() ? nullptr : aad.data(), aad.size(),
                              plaintext.empty() ? nullptr : plaintext.data(),
                              plaintext.size(),
                              env.ciphertext.data(),
                              env.ciphertext.data() + plaintext.size());
    determ_secure_zero(key.data(), key.size());
    return env;
}

std::optional<std::vector<uint8_t>>
decrypt(const Envelope& env,
          const std::string& password,
          const std::vector<uint8_t>& aad) {
    if (env.ciphertext.size() < TAG_LEN) return std::nullopt;
    if (env.nonce.size()       != NONCE_LEN) return std::nullopt;
    if (env.pbkdf2_iters       == 0) return std::nullopt;

    // The passed AAD must match the envelope's stored AAD.
    if (aad != env.aad) return std::nullopt;

    auto key = derive_key(password, env.salt, env.pbkdf2_iters);

    // Tag = the trailing 16 bytes of env.ciphertext; CT tag compare +
    // fail-closed inside determ_aes256_gcm_decrypt.
    const size_t ct_body_len = env.ciphertext.size() - TAG_LEN;
    std::vector<uint8_t> pt(ct_body_len);
    int rc = determ_aes256_gcm_decrypt(
        key.data(), env.nonce.data(),
        env.aad.empty() ? nullptr : env.aad.data(), env.aad.size(),
        ct_body_len ? env.ciphertext.data() : nullptr, ct_body_len,
        env.ciphertext.data() + ct_body_len,
        pt.data());
    determ_secure_zero(key.data(), key.size());
    if (rc != 0) return std::nullopt;
    return pt;
}

namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

std::vector<uint8_t> from_hex(const std::string& s) {
    if (s.size() % 2 != 0)
        throw std::invalid_argument("from_hex: odd length");
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(s.substr(i, 2));
        ss >> std::hex >> byte;
        if (ss.fail())
            throw std::invalid_argument("from_hex: non-hex char");
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

} // namespace

std::string serialize(const Envelope& env) {
    std::vector<uint8_t> magic_bytes(4);
    for (int i = 0; i < 4; ++i)
        magic_bytes[i] = static_cast<uint8_t>((MAGIC_LE >> (8*i)) & 0xff);
    std::vector<uint8_t> iters_bytes(4);
    for (int i = 0; i < 4; ++i)
        iters_bytes[i] = static_cast<uint8_t>((env.pbkdf2_iters >> (8*i)) & 0xff);
    std::ostringstream o;
    o << to_hex(magic_bytes) << "."
      << to_hex(env.salt)    << "."
      << to_hex(iters_bytes) << "."
      << to_hex(env.nonce)   << "."
      << to_hex(env.aad)     << "."
      << to_hex(env.ciphertext);
    return o.str();
}

std::optional<Envelope> deserialize(const std::string& blob) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : blob) {
        if (c == '.') { parts.push_back(std::move(current)); current.clear(); }
        else current.push_back(c);
    }
    parts.push_back(std::move(current));
    if (parts.size() != 6) return std::nullopt;
    try {
        auto magic_bytes = from_hex(parts[0]);
        if (magic_bytes.size() != 4) return std::nullopt;
        uint32_t magic = 0;
        for (int i = 0; i < 4; ++i)
            magic |= uint32_t(magic_bytes[i]) << (8*i);
        if (magic != MAGIC_LE) return std::nullopt;

        Envelope env;
        env.salt = from_hex(parts[1]);
        if (env.salt.size() < 8) return std::nullopt;
        auto iters_bytes = from_hex(parts[2]);
        if (iters_bytes.size() != 4) return std::nullopt;
        env.pbkdf2_iters = 0;
        for (int i = 0; i < 4; ++i)
            env.pbkdf2_iters |= uint32_t(iters_bytes[i]) << (8*i);
        env.nonce = from_hex(parts[3]);
        if (env.nonce.size() != NONCE_LEN) return std::nullopt;
        env.aad        = from_hex(parts[4]);
        env.ciphertext = from_hex(parts[5]);
        if (env.ciphertext.size() < TAG_LEN) return std::nullopt;
        return env;
    } catch (std::exception&) {
        return std::nullopt;
    }
}

} // namespace determ::wallet::envelope
