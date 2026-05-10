#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>

namespace determ {

using Hash      = std::array<uint8_t, 32>;
using PubKey    = std::array<uint8_t, 32>;
using Signature = std::array<uint8_t, 64>;

using ShardId    = uint32_t;
using EpochIndex = uint64_t;

// Stage-B sharding role of a chain. SINGLE preserves rev.7/8 behavior (one
// chain, no shards). BEACON and SHARD are the two roles in the sharded
// architecture: beacon holds validator pool + cross-shard receipts +
// epoch transitions; shards hold per-account state and process user txs.
enum class ChainRole : uint8_t {
    SINGLE = 0,    // unsharded (default; rev.8 behavior)
    BEACON = 1,    // trust anchor in a sharded deployment
    SHARD  = 2,    // throughput layer in a sharded deployment
};

inline const char* to_string(ChainRole r) {
    switch (r) {
    case ChainRole::SINGLE: return "single";
    case ChainRole::BEACON: return "beacon";
    case ChainRole::SHARD:  return "shard";
    }
    return "?";
}

// Sharding posture for the deployment. Carried in TimingProfile so a profile
// fully specifies "what kind of deployment am I in." NONE = no sharding at all
// (single chain). CURRENT = rev.9 B0-B6 sharding without regional grouping
// or under-quorum merge. EXTENDED = regional grouping + under-quorum merge
// (R1-R7 active plan).
enum class ShardingMode : uint8_t {
    NONE     = 0,
    CURRENT  = 1,
    EXTENDED = 2,
};

inline const char* to_string(ShardingMode m) {
    switch (m) {
    case ShardingMode::NONE:     return "none";
    case ShardingMode::CURRENT:  return "current";
    case ShardingMode::EXTENDED: return "extended";
    }
    return "?";
}

inline std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    return ss.str();
}

template<size_t N>
std::string to_hex(const std::array<uint8_t, N>& a) {
    return to_hex(a.data(), N);
}

inline std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("odd hex length");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}

template<size_t N>
std::array<uint8_t, N> from_hex_arr(const std::string& hex) {
    auto v = from_hex(hex);
    if (v.size() != N) throw std::invalid_argument("hex length mismatch");
    std::array<uint8_t, N> a;
    std::copy(v.begin(), v.end(), a.begin());
    return a;
}

inline int64_t now_unix() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// ─── Two-tier identity (rev. 4 / original-spec adoption) ─────────────────────
// Anonymous account address: "0x" + 64 lowercase hex chars = full Ed25519 pubkey.
// Anyone holding the corresponding private key can spend from this address —
// including by physically transferring the key offline (bearer wallet semantics).
// Account addresses cannot register, stake, or be selected as creators; they
// only hold balance and can send/receive TRANSFER. Distinguishable from domain
// names by the unique "0x" + 64-hex shape.
inline bool is_anon_address(const std::string& s) {
    if (s.size() != 66) return false;
    if (s[0] != '0' || s[1] != 'x') return false;
    for (size_t i = 2; i < 66; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

inline PubKey parse_anon_pubkey(const std::string& addr) {
    if (!is_anon_address(addr))
        throw std::invalid_argument("not an anon address: " + addr);
    return from_hex_arr<32>(addr.substr(2));
}

inline std::string make_anon_address(const PubKey& pk) {
    return "0x" + to_hex(pk);
}

} // namespace determ
