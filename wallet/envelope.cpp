// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// 1c (2026-07-03): the envelope runs on determ::c99 (AES-256-GCM, OS
// entropy) instead of OpenSSL.
// R58 (2026-07-04): fresh envelopes default to a memory-hard Argon2id KDF
// (the DWE2 wire layout) instead of PBKDF2 (DWE1). Both layouts are read
// AND written — decrypt/deserialize auto-detect from the 4-byte magic.
// Only the KDF and its parameter slot differ; the AES-256-GCM AEAD
// (12-byte nonce, 16-byte tag appended to ciphertext) is identical across
// both.
// D2 (2026-08-12): the at-rest serialization is the canonical BINARY
// container (serialize_bytes/deserialize_bytes; layout in envelope.hpp).
// The legacy dot-separated hex TEXT form is deleted pre-genesis — readers
// accept only the binary bytes or their plain lowercase-hex CLI view.
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
            || env.argon2_m_kib < 8 * env.argon2_p
            || env.argon2_t     > MAX_ARGON2_T_COST       // reject unbounded-work
            || env.argon2_m_kib > MAX_ARGON2_M_COST_KIB   // KDF cost from an
            || env.argon2_p     > MAX_ARGON2_LANES)       // untrusted envelope
            return std::nullopt;
        key = derive_key_argon2(password, env.salt,
                                env.argon2_t, env.argon2_m_kib, env.argon2_p);
    } else {
        if (env.pbkdf2_iters == 0 || env.pbkdf2_iters > MAX_PBKDF2_ITERS)
            return std::nullopt;
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

// Strict nibble decode: [0-9a-fA-F] only. Returns -1 on anything else, so
// the hex VIEW rejects dots (the deleted legacy form), whitespace, and
// every other non-hex character instead of best-effort parsing.
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void put_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}

uint32_t rd_u32_le(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(p[i]) << (8 * i);
    return v;
}

} // namespace

std::vector<uint8_t> serialize_bytes(const Envelope& env) {
    // Writers fail closed: refuse to emit a container deserialize_bytes
    // would reject.
    if (env.salt.size() < 8 || env.salt.size() > 64)
        throw std::invalid_argument("envelope: salt_len outside 8..64");
    if (env.nonce.size() != NONCE_LEN)
        throw std::invalid_argument("envelope: nonce must be 12 bytes");
    if (env.aad.size() > MAX_AAD_LEN)
        throw std::invalid_argument("envelope: aad exceeds MAX_AAD_LEN");
    if (env.ciphertext.size() < TAG_LEN || env.ciphertext.size() > MAX_CT_LEN)
        throw std::invalid_argument("envelope: ciphertext outside 16..MAX_CT_LEN");

    const bool argon = (env.kdf == Kdf::ARGON2ID);
    std::vector<uint8_t> out;
    out.reserve(4 + 1 + env.salt.size() + (argon ? 12 : 4) + NONCE_LEN
                + 2 + env.aad.size() + 4 + env.ciphertext.size());
    put_u32_le(out, argon ? MAGIC2_LE : MAGIC1_LE);
    out.push_back(static_cast<uint8_t>(env.salt.size()));
    out.insert(out.end(), env.salt.begin(), env.salt.end());
    if (argon) {
        put_u32_le(out, env.argon2_t);
        put_u32_le(out, env.argon2_m_kib);
        put_u32_le(out, env.argon2_p);
    } else {
        put_u32_le(out, env.pbkdf2_iters);
    }
    out.insert(out.end(), env.nonce.begin(), env.nonce.end());
    out.push_back(static_cast<uint8_t>(env.aad.size() & 0xff));
    out.push_back(static_cast<uint8_t>((env.aad.size() >> 8) & 0xff));
    out.insert(out.end(), env.aad.begin(), env.aad.end());
    put_u32_le(out, static_cast<uint32_t>(env.ciphertext.size()));
    out.insert(out.end(), env.ciphertext.begin(), env.ciphertext.end());
    return out;
}

std::optional<Envelope> deserialize_bytes(const uint8_t* data, size_t len) {
    if (data == nullptr) return std::nullopt;
    size_t off = 0;
    auto have = [&](size_t n) { return off <= len && len - off >= n; };

    if (!have(4)) return std::nullopt;
    const uint32_t magic = rd_u32_le(data + off); off += 4;
    if (magic != MAGIC1_LE && magic != MAGIC2_LE) return std::nullopt;

    Envelope env;
    if (!have(1)) return std::nullopt;
    const size_t salt_len = data[off]; off += 1;
    if (salt_len < 8 || salt_len > 64) return std::nullopt;
    if (!have(salt_len)) return std::nullopt;
    env.salt.assign(data + off, data + off + salt_len); off += salt_len;

    if (magic == MAGIC2_LE) {
        if (!have(12)) return std::nullopt;                 // t | m | p
        env.kdf          = Kdf::ARGON2ID;
        env.argon2_t     = rd_u32_le(data + off);
        env.argon2_m_kib = rd_u32_le(data + off + 4);
        env.argon2_p     = rd_u32_le(data + off + 8);
        off += 12;
        if (env.argon2_t == 0 || env.argon2_p == 0
            || env.argon2_m_kib < 8 * env.argon2_p
            || env.argon2_t     > MAX_ARGON2_T_COST       // reject unbounded-work
            || env.argon2_m_kib > MAX_ARGON2_M_COST_KIB   // KDF cost from an
            || env.argon2_p     > MAX_ARGON2_LANES)       // untrusted envelope
            return std::nullopt;
    } else {
        if (!have(4)) return std::nullopt;                  // iters
        env.kdf          = Kdf::PBKDF2;
        env.pbkdf2_iters = rd_u32_le(data + off); off += 4;
        if (env.pbkdf2_iters == 0 || env.pbkdf2_iters > MAX_PBKDF2_ITERS)
            return std::nullopt;
    }

    if (!have(NONCE_LEN)) return std::nullopt;
    env.nonce.assign(data + off, data + off + NONCE_LEN); off += NONCE_LEN;

    if (!have(2)) return std::nullopt;
    const size_t aad_len = size_t(data[off]) | (size_t(data[off + 1]) << 8);
    off += 2;
    if (aad_len > MAX_AAD_LEN) return std::nullopt;
    if (!have(aad_len)) return std::nullopt;                // length vs body
    env.aad.assign(data + off, data + off + aad_len); off += aad_len;

    if (!have(4)) return std::nullopt;
    const uint32_t ct_len = rd_u32_le(data + off); off += 4;
    if (ct_len < TAG_LEN || ct_len > MAX_CT_LEN) return std::nullopt;
    if (!have(ct_len)) return std::nullopt;                 // length vs body
    env.ciphertext.assign(data + off, data + off + ct_len); off += ct_len;

    if (off != len) return std::nullopt;                    // exact length: trailing bytes reject
    return env;
}

std::optional<Envelope> deserialize_bytes(const std::vector<uint8_t>& bytes) {
    return deserialize_bytes(bytes.data(), bytes.size());
}

std::string serialize(const Envelope& env) {
    return to_hex(serialize_bytes(env));
}

std::optional<Envelope> deserialize(const std::string& blob) {
    // Strict hex VIEW of the canonical bytes: even length, hex chars only.
    // The legacy dot-separated form fails here ('.' is not hex).
    if (blob.empty() || blob.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> bytes;
    bytes.reserve(blob.size() / 2);
    for (size_t i = 0; i < blob.size(); i += 2) {
        const int hi = hex_nibble(blob[i]);
        const int lo = hex_nibble(blob[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return deserialize_bytes(bytes.data(), bytes.size());
}

} // namespace determ::wallet::envelope
