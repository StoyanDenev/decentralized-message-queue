// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include "envelope.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
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
    if (PKCS5_PBKDF2_HMAC(password.data(),
                            static_cast<int>(password.size()),
                            salt.data(), static_cast<int>(salt.size()),
                            static_cast<int>(iters),
                            EVP_sha256(),
                            static_cast<int>(KEY_LEN),
                            key.data()) != 1) {
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
    if (RAND_bytes(env.salt.data(),  static_cast<int>(env.salt.size()))  != 1
        || RAND_bytes(env.nonce.data(), static_cast<int>(env.nonce.size())) != 1)
        throw std::runtime_error("envelope: RAND_bytes failed");
    env.pbkdf2_iters = iters;
    env.aad = aad;

    auto key = derive_key(password, env.salt, iters);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("envelope: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                              nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  static_cast<int>(NONCE_LEN), nullptr) != 1
        || EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                  key.data(), env.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("envelope: EncryptInit failed");
    }

    int outlen = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &outlen,
                                 aad.data(), static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("envelope: EncryptUpdate(AAD) failed");
        }
    }

    env.ciphertext.resize(plaintext.size() + TAG_LEN);
    if (EVP_EncryptUpdate(ctx, env.ciphertext.data(), &outlen,
                             plaintext.data(),
                             static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("envelope: EncryptUpdate(pt) failed");
    }
    int ct_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, env.ciphertext.data() + ct_len, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("envelope: EncryptFinal failed");
    }
    ct_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                               static_cast<int>(TAG_LEN),
                               env.ciphertext.data() + ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("envelope: GET_TAG failed");
    }
    ct_len += static_cast<int>(TAG_LEN);
    env.ciphertext.resize(static_cast<size_t>(ct_len));

    EVP_CIPHER_CTX_free(ctx);
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

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                              nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  static_cast<int>(NONCE_LEN), nullptr) != 1
        || EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                  key.data(), env.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }

    int outlen = 0;
    if (!env.aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &outlen,
                                 env.aad.data(),
                                 static_cast<int>(env.aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
    }

    const size_t ct_body_len = env.ciphertext.size() - TAG_LEN;
    std::vector<uint8_t> pt(ct_body_len);
    if (EVP_DecryptUpdate(ctx, pt.data(), &outlen,
                             env.ciphertext.data(),
                             static_cast<int>(ct_body_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    int pt_len = outlen;

    // Tag verification — the trailing 16 bytes of env.ciphertext.
    std::vector<uint8_t> tag(env.ciphertext.end() - TAG_LEN,
                                env.ciphertext.end());
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                               static_cast<int>(TAG_LEN),
                               tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }

    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) return std::nullopt;
    pt_len += outlen;
    pt.resize(static_cast<size_t>(pt_len));
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
