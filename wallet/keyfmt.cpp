// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// D2 canonical binary keyfile / backup containers. Layouts and bounds in
// keyfmt.hpp. Every decoder is gated falsify-on-mutant by the wallet's
// `selftest-keyfile-binary` / `selftest-backup-binary` commands.
#include "keyfmt.hpp"
#include "envelope.hpp"
#include <determ/crypto/ed25519/ed25519.h>
#include <cstring>
#include <stdexcept>

namespace determ::wallet::keyfmt {

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

// The derive-equality check: the stored pubkey must equal the pubkey
// derived from the stored seed. Replaces the old JSON-era S-028 address
// cross-check — a keyfile whose halves disagree is corrupt or tampered.
bool derive_matches(const std::array<uint8_t, 32>& pubkey,
                    const std::array<uint8_t, 32>& priv_seed) {
    std::array<uint8_t, 32> derived{};
    determ_ed25519_pubkey_from_seed(priv_seed.data(), derived.data());
    return derived == pubkey;
}

} // namespace

// ── DAK1 ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> encode_dak1(const Keypair& kp) {
    if (!derive_matches(kp.pubkey, kp.priv_seed))
        throw std::invalid_argument("keyfmt: DAK1 pubkey does not match seed derivation");
    std::vector<uint8_t> out;
    out.reserve(DAK1_SIZE);
    out.insert(out.end(), {'D', 'A', 'K', '1'});
    out.insert(out.end(), kp.pubkey.begin(),    kp.pubkey.end());
    out.insert(out.end(), kp.priv_seed.begin(), kp.priv_seed.end());
    return out;
}

std::optional<Keypair> decode_dak1(const uint8_t* data, size_t len) {
    if (data == nullptr || len != DAK1_SIZE) return std::nullopt;   // exact length
    if (std::memcmp(data, "DAK1", 4) != 0) return std::nullopt;
    Keypair kp;
    std::memcpy(kp.pubkey.data(),    data + 4,  32);
    std::memcpy(kp.priv_seed.data(), data + 36, 32);
    if (!derive_matches(kp.pubkey, kp.priv_seed)) return std::nullopt;
    return kp;
}

std::optional<Keypair> decode_dak1(const std::vector<uint8_t>& bytes) {
    return decode_dak1(bytes.data(), bytes.size());
}

// ── DAB1 ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> encode_dab1(const std::vector<Keypair>& recs) {
    if (recs.empty() || recs.size() > DAB1_MAX_COUNT)
        throw std::invalid_argument("keyfmt: DAB1 count outside 1..=10000");
    std::vector<uint8_t> out;
    out.reserve(6 + 64 * recs.size());
    out.insert(out.end(), {'D', 'A', 'B', '1'});
    out.push_back(static_cast<uint8_t>(recs.size() & 0xff));
    out.push_back(static_cast<uint8_t>((recs.size() >> 8) & 0xff));
    for (const auto& kp : recs) {
        if (!derive_matches(kp.pubkey, kp.priv_seed))
            throw std::invalid_argument(
                "keyfmt: DAB1 record pubkey does not match seed derivation");
        out.insert(out.end(), kp.pubkey.begin(),    kp.pubkey.end());
        out.insert(out.end(), kp.priv_seed.begin(), kp.priv_seed.end());
    }
    return out;
}

std::optional<std::vector<Keypair>> decode_dab1(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 6) return std::nullopt;
    if (std::memcmp(data, "DAB1", 4) != 0) return std::nullopt;
    const size_t count = size_t(data[4]) | (size_t(data[5]) << 8);
    if (count == 0 || count > DAB1_MAX_COUNT) return std::nullopt;
    if (len != 6 + 64 * count) return std::nullopt;    // exact length, both directions
    std::vector<Keypair> recs;
    recs.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        Keypair kp;
        std::memcpy(kp.pubkey.data(),    data + 6 + 64 * i,      32);
        std::memcpy(kp.priv_seed.data(), data + 6 + 64 * i + 32, 32);
        if (!derive_matches(kp.pubkey, kp.priv_seed)) return std::nullopt;
        recs.push_back(kp);
    }
    return recs;
}

std::optional<std::vector<Keypair>> decode_dab1(const std::vector<uint8_t>& bytes) {
    return decode_dab1(bytes.data(), bytes.size());
}

// ── DNK1 ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> encode_dnk1(const std::array<uint8_t, 32>& pubkey,
                                 const std::vector<uint8_t>& env_bytes) {
    // The envelope bytes must themselves be one well-formed DWE container;
    // refusing here keeps every DNK1 writer fail-closed.
    if (!envelope::deserialize_bytes(env_bytes))
        throw std::invalid_argument("keyfmt: DNK1 envelope bytes are not a "
                                    "well-formed DWE container");
    std::vector<uint8_t> out;
    out.reserve(40 + env_bytes.size());
    out.insert(out.end(), {'D', 'N', 'K', '1'});
    out.insert(out.end(), pubkey.begin(), pubkey.end());
    put_u32_le(out, static_cast<uint32_t>(env_bytes.size()));
    out.insert(out.end(), env_bytes.begin(), env_bytes.end());
    return out;
}

std::optional<NodeKeyfile> decode_dnk1(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 40) return std::nullopt;
    if (std::memcmp(data, "DNK1", 4) != 0) return std::nullopt;
    NodeKeyfile nk;
    std::memcpy(nk.pubkey.data(), data + 4, 32);
    const uint32_t env_len = rd_u32_le(data + 36);
    if (uint64_t(40) + env_len != uint64_t(len)) return std::nullopt;   // exact EOF
    nk.env_bytes.assign(data + 40, data + 40 + env_len);
    // The embedded envelope must be exactly one well-formed DWE container.
    if (!envelope::deserialize_bytes(nk.env_bytes)) return std::nullopt;
    return nk;
}

std::optional<NodeKeyfile> decode_dnk1(const std::vector<uint8_t>& bytes) {
    return decode_dnk1(bytes.data(), bytes.size());
}

// ── DSS1 ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> encode_dss1(const std::vector<Share>& shares) {
    if (shares.empty() || shares.size() > 255)
        throw std::invalid_argument("keyfmt: DSS1 count outside 1..=255");
    const size_t y_len = shares.front().y.size();
    if (y_len == 0 || y_len > DSS1_MAX_Y_LEN)
        throw std::invalid_argument("keyfmt: DSS1 y_len outside 1..=4096");
    bool seen[256] = {false};
    std::vector<uint8_t> out;
    out.reserve(9 + shares.size() * (1 + y_len));
    out.insert(out.end(), {'D', 'S', 'S', '1'});
    out.push_back(static_cast<uint8_t>(shares.size()));
    put_u32_le(out, static_cast<uint32_t>(y_len));
    for (const auto& s : shares) {
        if (s.x == 0)
            throw std::invalid_argument("keyfmt: DSS1 share x must be 1..=255");
        if (seen[s.x])
            throw std::invalid_argument("keyfmt: DSS1 duplicate share x");
        seen[s.x] = true;
        if (s.y.size() != y_len)
            throw std::invalid_argument("keyfmt: DSS1 inconsistent y length");
        out.push_back(s.x);
        out.insert(out.end(), s.y.begin(), s.y.end());
    }
    return out;
}

std::optional<std::vector<Share>> decode_dss1(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 9) return std::nullopt;
    if (std::memcmp(data, "DSS1", 4) != 0) return std::nullopt;
    const size_t count = data[4];
    if (count == 0) return std::nullopt;
    const uint32_t y_len = rd_u32_le(data + 5);
    if (y_len == 0 || y_len > DSS1_MAX_Y_LEN) return std::nullopt;
    // Exact length, both directions.
    if (uint64_t(len) != uint64_t(9) + uint64_t(count) * (1 + uint64_t(y_len)))
        return std::nullopt;
    bool seen[256] = {false};
    std::vector<Share> shares;
    shares.reserve(count);
    size_t off = 9;
    for (size_t i = 0; i < count; ++i) {
        Share s;
        s.x = data[off]; off += 1;
        if (s.x == 0 || seen[s.x]) return std::nullopt;   // 1..=255, DISTINCT
        seen[s.x] = true;
        s.y.assign(data + off, data + off + y_len); off += y_len;
        shares.push_back(std::move(s));
    }
    return shares;
}

std::optional<std::vector<Share>> decode_dss1(const std::vector<uint8_t>& bytes) {
    return decode_dss1(bytes.data(), bytes.size());
}

// ── DBE1 ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> encode_dbe1(const std::vector<ShareEnvelope>& envs) {
    if (envs.empty() || envs.size() > 255)
        throw std::invalid_argument("keyfmt: DBE1 count outside 1..=255");
    bool seen[256] = {false};
    std::vector<uint8_t> out;
    out.insert(out.end(), {'D', 'B', 'E', '1'});
    out.push_back(static_cast<uint8_t>(envs.size()));
    for (const auto& e : envs) {
        if (e.share_index == 0)
            throw std::invalid_argument("keyfmt: DBE1 share_index must be 1..=255");
        if (seen[e.share_index])
            throw std::invalid_argument("keyfmt: DBE1 duplicate share_index");
        seen[e.share_index] = true;
        if (!envelope::deserialize_bytes(e.env_bytes))
            throw std::invalid_argument("keyfmt: DBE1 envelope bytes are not a "
                                        "well-formed DWE container");
        out.push_back(e.share_index);
        put_u32_le(out, static_cast<uint32_t>(e.env_bytes.size()));
        out.insert(out.end(), e.env_bytes.begin(), e.env_bytes.end());
    }
    return out;
}

std::optional<std::vector<ShareEnvelope>> decode_dbe1(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 5) return std::nullopt;
    if (std::memcmp(data, "DBE1", 4) != 0) return std::nullopt;
    const size_t count = data[4];
    if (count == 0) return std::nullopt;
    bool seen[256] = {false};
    std::vector<ShareEnvelope> envs;
    envs.reserve(count);
    size_t off = 5;
    for (size_t i = 0; i < count; ++i) {
        if (len - off < 5) return std::nullopt;           // index + env_len
        ShareEnvelope e;
        e.share_index = data[off]; off += 1;
        if (e.share_index == 0 || seen[e.share_index]) return std::nullopt;
        seen[e.share_index] = true;
        const uint32_t env_len = rd_u32_le(data + off); off += 4;
        if (env_len > len - off) return std::nullopt;     // length vs body
        e.env_bytes.assign(data + off, data + off + env_len); off += env_len;
        if (!envelope::deserialize_bytes(e.env_bytes)) return std::nullopt;
        envs.push_back(std::move(e));
    }
    if (off != len) return std::nullopt;                  // exact length: trailing bytes reject
    return envs;
}

std::optional<std::vector<ShareEnvelope>> decode_dbe1(const std::vector<uint8_t>& bytes) {
    return decode_dbe1(bytes.data(), bytes.size());
}

} // namespace determ::wallet::keyfmt
