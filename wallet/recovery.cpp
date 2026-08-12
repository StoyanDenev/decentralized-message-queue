// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include "recovery.hpp"
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/sha2/sha2.h>
#include <cstring>
#include <stdexcept>

namespace determ::wallet::recovery {

namespace {

void put_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}

uint32_t rd_u32_le(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(p[i]) << (8 * i);
    return v;
}

// AAD binds the guardian_id + scheme tag into each envelope's tag so
// a share decrypted under guardian_i's slot cannot be substituted
// into guardian_j's slot. The version byte gates Phase 4's swap to
// the OPAQUE scheme: a v=1 envelope decrypted with a v=2 AAD will
// fail the tag check.
std::vector<uint8_t> make_aad(uint8_t guardian_id, uint32_t version) {
    std::vector<uint8_t> aad;
    aad.reserve(8);
    aad.push_back('D'); aad.push_back('W'); aad.push_back('R'); aad.push_back('1');
    aad.push_back(guardian_id);
    aad.push_back(static_cast<uint8_t>(version & 0xff));
    aad.push_back(static_cast<uint8_t>((version >> 8) & 0xff));
    aad.push_back(static_cast<uint8_t>((version >> 16) & 0xff));
    return aad;
}

} // namespace

std::vector<uint8_t> seed_pubkey_checksum(const std::vector<uint8_t>& seed) {
    if (seed.size() != 32) return {};
    uint8_t pub[32];
    determ_ed25519_pubkey_from_seed(seed.data(), pub);   // 1c: c99 backend
    std::vector<uint8_t> digest(32);
    determ_sha256(pub, 32, digest.data());
    return digest;
}

RecoverySetup create(const std::vector<uint8_t>& secret,
                       const std::string& password,
                       uint8_t threshold,
                       uint8_t share_count,
                       const std::vector<uint8_t>& pubkey_checksum) {
    if (secret.empty())
        throw std::invalid_argument("recovery: secret must be non-empty");
    auto shares = shamir::split(secret, threshold, share_count);

    RecoverySetup setup;
    setup.version         = 1;
    setup.threshold       = threshold;
    setup.share_count     = share_count;
    setup.secret_len      = secret.size();
    setup.guardian_x.reserve(share_count);
    setup.envelopes.reserve(share_count);
    setup.pubkey_checksum = pubkey_checksum;

    for (uint8_t i = 0; i < share_count; ++i) {
        setup.guardian_x.push_back(shares[i].x);
        auto aad = make_aad(i, setup.version);
        // Envelope encrypts the share's y-vector. The x-coordinate is
        // stored alongside in setup.guardian_x — not encrypted, since
        // it leaks no information about the secret (x is just an
        // index 1..N).
        auto env = envelope::encrypt(shares[i].y, password, aad);
        setup.envelopes.push_back(std::move(env));
    }
    return setup;
}

std::optional<std::vector<uint8_t>>
recover(const RecoverySetup& setup,
          const std::string& password,
          const std::vector<uint8_t>& guardian_indices) {
    if (setup.envelopes.size() != setup.share_count) return std::nullopt;
    if (setup.guardian_x.size() != setup.share_count) return std::nullopt;
    if (guardian_indices.size() < setup.threshold)   return std::nullopt;

    std::vector<shamir::Share> shares;
    shares.reserve(guardian_indices.size());
    for (uint8_t gid : guardian_indices) {
        if (gid >= setup.share_count) return std::nullopt;
        auto aad = make_aad(gid, setup.version);

        auto y_opt = envelope::decrypt(setup.envelopes[gid],
                                          password, aad);
        if (!y_opt) continue;          // wrong password or tampered slot
        shamir::Share s;
        s.x = setup.guardian_x[gid];
        s.y = std::move(*y_opt);
        shares.push_back(std::move(s));
    }
    if (shares.size() < setup.threshold) return std::nullopt;

    auto secret = shamir::combine(shares);
    if (!secret) return std::nullopt;
    if (secret->size() != setup.secret_len) return std::nullopt;

    // Optional pubkey checksum verification — when the secret is a
    // 32-byte Ed25519 seed AND the setup carries a checksum, confirm
    // the reconstruction regenerates the same public key the wallet
    // was registered under. Catches the (cryptographically impossible
    // but defense-in-depth) case where multiple envelopes' tags pass
    // yet shares reconstruct a different secret.
    if (!setup.pubkey_checksum.empty() && secret->size() == 32) {
        auto computed = seed_pubkey_checksum(*secret);
        if (computed != setup.pubkey_checksum) return std::nullopt;
    }
    return secret;
}

std::vector<uint8_t> to_bytes(const RecoverySetup& setup) {
    // Writers fail closed: refuse to emit a container from_bytes rejects.
    if (setup.version != 1)
        throw std::invalid_argument("recovery: DRS1 version must be 1");
    if (setup.threshold == 0)
        throw std::invalid_argument("recovery: threshold must be >= 1");
    if (setup.share_count < setup.threshold)
        throw std::invalid_argument("recovery: share_count < threshold");
    if (setup.secret_len == 0 || setup.secret_len > 4096)
        throw std::invalid_argument("recovery: secret_len outside 1..=4096");
    if (!setup.pubkey_checksum.empty() && setup.pubkey_checksum.size() != 32)
        throw std::invalid_argument("recovery: pubkey_checksum must be 0 or 32 bytes");
    if (setup.guardian_x.size() != setup.share_count
        || setup.envelopes.size() != setup.share_count)
        throw std::invalid_argument("recovery: guardian_x/envelopes size mismatch");

    std::vector<uint8_t> out;
    out.insert(out.end(), {'D', 'R', 'S', '1'});
    put_u32_le(out, setup.version);
    out.push_back(setup.threshold);
    out.push_back(setup.share_count);
    put_u32_le(out, static_cast<uint32_t>(setup.secret_len));
    out.push_back(static_cast<uint8_t>(setup.pubkey_checksum.size()));
    out.insert(out.end(), setup.pubkey_checksum.begin(),
               setup.pubkey_checksum.end());
    bool seen[256] = {false};
    for (uint8_t i = 0; i < setup.share_count; ++i) {
        const uint8_t x = setup.guardian_x[i];
        if (x == 0)
            throw std::invalid_argument("recovery: guardian_x must be 1..=255");
        if (seen[x])
            throw std::invalid_argument("recovery: duplicate guardian_x");
        seen[x] = true;
        auto env_bytes = envelope::serialize_bytes(setup.envelopes[i]);
        out.push_back(x);
        put_u32_le(out, static_cast<uint32_t>(env_bytes.size()));
        out.insert(out.end(), env_bytes.begin(), env_bytes.end());
    }
    return out;
}

std::optional<RecoverySetup> from_bytes(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 15) return std::nullopt;
    if (std::memcmp(data, "DRS1", 4) != 0) return std::nullopt;
    RecoverySetup s;
    s.version = rd_u32_le(data + 4);
    if (s.version != 1) return std::nullopt;
    s.threshold   = data[8];
    s.share_count = data[9];
    if (s.threshold == 0) return std::nullopt;
    if (s.share_count < s.threshold) return std::nullopt;
    const uint32_t secret_len = rd_u32_le(data + 10);
    if (secret_len == 0 || secret_len > 4096) return std::nullopt;
    s.secret_len = secret_len;
    const size_t checksum_len = data[14];
    if (checksum_len != 0 && checksum_len != 32) return std::nullopt;
    size_t off = 15;
    if (len - off < checksum_len) return std::nullopt;
    s.pubkey_checksum.assign(data + off, data + off + checksum_len);
    off += checksum_len;
    bool seen[256] = {false};
    for (size_t i = 0; i < s.share_count; ++i) {
        if (len - off < 5) return std::nullopt;           // x + env_len
        const uint8_t x = data[off]; off += 1;
        if (x == 0 || seen[x]) return std::nullopt;       // 1..=255, DISTINCT
        seen[x] = true;
        const uint32_t env_len = rd_u32_le(data + off); off += 4;
        if (env_len > len - off) return std::nullopt;     // length vs body
        auto env = envelope::deserialize_bytes(data + off, env_len);
        if (!env) return std::nullopt;
        off += env_len;
        s.guardian_x.push_back(x);
        s.envelopes.push_back(std::move(*env));
    }
    if (off != len) return std::nullopt;                  // exact length
    return s;
}

std::optional<RecoverySetup> from_bytes(const std::vector<uint8_t>& bytes) {
    return from_bytes(bytes.data(), bytes.size());
}

} // namespace determ::wallet::recovery
