// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// 1c (2026-07-03): the envelope runs on determ::c99 (AES-256-GCM, OS
// entropy) instead of OpenSSL.
// R58 (2026-07-04): fresh envelopes default to a memory-hard Argon2id KDF
// (the DWE2 wire layout) instead of PBKDF2 (DWE1). Both layouts are read
// AND written — decrypt/deserialize auto-detect from the 4-byte magic, so
// every DWE1 envelope already on disk (keyfiles, backup shares) stays
// readable byte-for-byte. Only the KDF and its parameter slot differ; the
// AES-256-GCM AEAD (12-byte nonce, 16-byte tag appended to ciphertext) is
// identical across both.
#include "envelope.hpp"
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/aes/aes.h>
#include <determ/crypto/argon2/argon2id.h>
#include <determ/crypto/rng/rng.h>
#include <determ/crypto/secure_zero.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace determ::wallet::envelope {

static constexpr uint32_t MAGIC1_LE = 0x31455744;   // "DWE1" little-endian (PBKDF2)
static constexpr uint32_t MAGIC2_LE = 0x32455744;   // "DWE2" little-endian (Argon2id)
static constexpr size_t   NONCE_LEN = 12;
static constexpr size_t   TAG_LEN   = 16;
static constexpr size_t   KEY_LEN   = 32;

namespace {

std::vector<uint8_t> derive_key_pbkdf2(const std::string& password,
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

std::vector<uint8_t> derive_key_argon2(const std::string& password,
                                         const std::vector<uint8_t>& salt,
                                         uint32_t t_cost, uint32_t m_kib,
                                         uint32_t lanes) {
    std::vector<uint8_t> key(KEY_LEN);
    if (determ_argon2id(
            key.data(), KEY_LEN,
            password.empty() ? nullptr
                             : reinterpret_cast<const uint8_t*>(password.data()),
            password.size(),
            salt.empty() ? nullptr : salt.data(), salt.size(),
            t_cost, m_kib, lanes) != 0) {
        throw std::runtime_error("envelope: Argon2id derivation failed");
    }
    return key;
}

// The shared AEAD leg. Consumes the derived key (zeroes it) and fills
// env.ciphertext = ct-body || 16-byte tag.
void seal(Envelope& env, std::vector<uint8_t>& key,
          const std::vector<uint8_t>& plaintext,
          const std::vector<uint8_t>& aad) {
    env.ciphertext.resize(plaintext.size() + TAG_LEN);
    determ_aes256_gcm_encrypt(key.data(), env.nonce.data(),
                              aad.empty() ? nullptr : aad.data(), aad.size(),
                              plaintext.empty() ? nullptr : plaintext.data(),
                              plaintext.size(),
                              env.ciphertext.data(),
                              env.ciphertext.data() + plaintext.size());
    determ_secure_zero(key.data(), key.size());
}

void fill_salt_nonce(Envelope& env) {
    env.salt.resize(DEFAULT_SALT_LEN);
    env.nonce.resize(NONCE_LEN);
    if (determ_rng_bytes(env.salt.data(),  env.salt.size())  != 0
        || determ_rng_bytes(env.nonce.data(), env.nonce.size()) != 0)
        throw std::runtime_error("envelope: OS entropy source failed");
}

} // namespace

Envelope encrypt_argon2id(const std::vector<uint8_t>& plaintext,
                            const std::string& password,
                            const std::vector<uint8_t>& aad,
                            uint32_t t_cost, uint32_t m_cost_kib,
                            uint32_t lanes) {
    if (t_cost == 0 || lanes == 0 || m_cost_kib < 8 * lanes)
        throw std::invalid_argument("envelope: invalid Argon2id parameters");

    Envelope env;
    env.kdf          = Kdf::ARGON2ID;
    fill_salt_nonce(env);
    env.argon2_t     = t_cost;
    env.argon2_m_kib = m_cost_kib;
    env.argon2_p     = lanes;
    env.aad          = aad;

    auto key = derive_key_argon2(password, env.salt, t_cost, m_cost_kib, lanes);
    seal(env, key, plaintext, aad);
    return env;
}

Envelope encrypt_pbkdf2(const std::vector<uint8_t>& plaintext,
                          const std::string& password,
                          const std::vector<uint8_t>& aad,
                          uint32_t iters) {
    if (iters == 0)
        throw std::invalid_argument("envelope: iters must be > 0");

    Envelope env;
    env.kdf          = Kdf::PBKDF2;
    fill_salt_nonce(env);
    env.pbkdf2_iters = iters;
    env.aad          = aad;

    auto key = derive_key_pbkdf2(password, env.salt, iters);
    seal(env, key, plaintext, aad);
    return env;
}

Envelope encrypt(const std::vector<uint8_t>& plaintext,
                   const std::string& password,
                   const std::vector<uint8_t>& aad) {
    // R58 default: memory-hard Argon2id.
    return encrypt_argon2id(plaintext, password, aad);
}

std::optional<std::vector<uint8_t>>
decrypt(const Envelope& env,
          const std::string& password,
          const std::vector<uint8_t>& aad) {
    if (env.ciphertext.size() < TAG_LEN) return std::nullopt;
    if (env.nonce.size()       != NONCE_LEN) return std::nullopt;

    // The passed AAD must match the envelope's stored AAD.
    if (aad != env.aad) return std::nullopt;

    std::vector<uint8_t> key;
    if (env.kdf == Kdf::ARGON2ID) {
        if (env.argon2_t == 0 || env.argon2_p == 0
            || env.argon2_m_kib < 8 * env.argon2_p) return std::nullopt;
        key = derive_key_argon2(password, env.salt,
                                env.argon2_t, env.argon2_m_kib, env.argon2_p);
    } else {
        if (env.pbkdf2_iters == 0) return std::nullopt;
        key = derive_key_pbkdf2(password, env.salt, env.pbkdf2_iters);
    }

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

std::vector<uint8_t> u32_le(uint32_t v) {
    std::vector<uint8_t> b(4);
    for (int i = 0; i < 4; ++i) b[i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    return b;
}

uint32_t rd_u32_le(const std::vector<uint8_t>& b, size_t off) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(b[off + i]) << (8*i);
    return v;
}

} // namespace

std::string serialize(const Envelope& env) {
    const bool argon = (env.kdf == Kdf::ARGON2ID);
    std::vector<uint8_t> params;
    if (argon) {
        params = u32_le(env.argon2_t);
        auto m = u32_le(env.argon2_m_kib);
        auto p = u32_le(env.argon2_p);
        params.insert(params.end(), m.begin(), m.end());
        params.insert(params.end(), p.begin(), p.end());
    } else {
        params = u32_le(env.pbkdf2_iters);
    }
    std::ostringstream o;
    o << to_hex(u32_le(argon ? MAGIC2_LE : MAGIC1_LE)) << "."
      << to_hex(env.salt)       << "."
      << to_hex(params)         << "."
      << to_hex(env.nonce)      << "."
      << to_hex(env.aad)        << "."
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
        uint32_t magic = rd_u32_le(magic_bytes, 0);
        if (magic != MAGIC1_LE && magic != MAGIC2_LE) return std::nullopt;

        Envelope env;
        env.salt = from_hex(parts[1]);
        if (env.salt.size() < 8) return std::nullopt;

        auto params = from_hex(parts[2]);
        if (magic == MAGIC2_LE) {
            if (params.size() != 12) return std::nullopt;   // t | m | p
            env.kdf          = Kdf::ARGON2ID;
            env.argon2_t     = rd_u32_le(params, 0);
            env.argon2_m_kib = rd_u32_le(params, 4);
            env.argon2_p     = rd_u32_le(params, 8);
            if (env.argon2_t == 0 || env.argon2_p == 0
                || env.argon2_m_kib < 8 * env.argon2_p) return std::nullopt;
        } else {
            if (params.size() != 4) return std::nullopt;     // iters
            env.kdf          = Kdf::PBKDF2;
            env.pbkdf2_iters = rd_u32_le(params, 0);
            if (env.pbkdf2_iters == 0) return std::nullopt;
        }

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
