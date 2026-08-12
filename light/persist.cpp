// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light persisted-anchor cache implementation. See persist.hpp for the
// trust model and the byte-exact DLS1 container layout (D2: canonical binary
// at rest; the JSON document is deleted). Self-contained: std streams +
// std::filesystem; no dependency on the daemon, libsodium, or asio.

#include "persist.hpp"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace determ::light {

namespace {

constexpr size_t DLS1_BASE = 81;    // magic..has_state_root (flag == 0)
constexpr size_t DLS1_FULL = 113;   // + 32-byte head_state_root (flag == 1)

// Validate a lowercase/uppercase hex string of exactly `want` chars.
bool is_hex_len(const std::string& s, size_t want) {
    if (s.size() != want) return false;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// hex -> raw 32 bytes. Caller pre-validated via is_hex_len(s, 64).
void hex32_to_bytes(const std::string& s, uint8_t out[32]) {
    for (size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>((hex_nibble(s[2 * i]) << 4)
                                      | hex_nibble(s[2 * i + 1]));
    }
}

std::string bytes32_to_hex(const uint8_t* p) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < 32; ++i) {
        out.push_back(digits[p[i] >> 4]);
        out.push_back(digits[p[i] & 0x0f]);
    }
    return out;
}

// The operator's home directory. Only consulted when DETERM_LIGHT_STATE is unset
// (default_state_path() short-circuits on the override before calling this).
std::string home_dir() {
#ifdef _WIN32
    if (const char* up = std::getenv("USERPROFILE")) return up;
    if (const char* hd = std::getenv("HOMEDRIVE")) {
        const char* hp = std::getenv("HOMEPATH");
        if (hp) return std::string(hd) + hp;
    }
#else
    if (const char* h = std::getenv("HOME")) return h;
#endif
    return ".";  // last resort: current dir
}

}  // namespace

std::string default_state_path() {
    if (const char* override_path = std::getenv("DETERM_LIGHT_STATE")) {
        if (override_path[0] != '\0') return override_path;
    }
    namespace fs = std::filesystem;
    return (fs::path(home_dir()) / ".determ-light" / "state.bin").string();
}

void save_light_state(const std::string& path, const LightState& s) {
    // Writers fail closed: refuse to emit a container load_light_state
    // would reject.
    if (s.schema_version != 1)
        throw std::runtime_error("save_light_state: schema_version must be 1");
    if (!is_hex_len(s.genesis_hash, 64))
        throw std::runtime_error("save_light_state: 'genesis_hash' must be 64 hex chars");
    if (!is_hex_len(s.head_block_hash, 64))
        throw std::runtime_error("save_light_state: 'head_block_hash' must be 64 hex chars");
    if (!s.head_state_root.empty() && !is_hex_len(s.head_state_root, 64))
        throw std::runtime_error("save_light_state: 'head_state_root' must be empty or 64 hex chars");

    namespace fs = std::filesystem;
    try {
        fs::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(p.parent_path(), ec);
            // create_directories is a no-op (ec set, but harmless) if the dir
            // already exists; a genuine failure surfaces at the open() below.
        }
    } catch (const std::exception&) {
        // fall through — the ofstream open failure is the authoritative error
    }

    const bool has_root = !s.head_state_root.empty();
    std::vector<uint8_t> out;
    out.reserve(has_root ? DLS1_FULL : DLS1_BASE);
    out.insert(out.end(), {'D', 'L', 'S', '1'});
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((s.schema_version >> (8 * i)) & 0xff));
    uint8_t buf[32];
    hex32_to_bytes(s.genesis_hash, buf);
    out.insert(out.end(), buf, buf + 32);
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((s.head_height >> (8 * i)) & 0xff));
    hex32_to_bytes(s.head_block_hash, buf);
    out.insert(out.end(), buf, buf + 32);
    out.push_back(has_root ? 1 : 0);
    if (has_root) {
        hex32_to_bytes(s.head_state_root, buf);
        out.insert(out.end(), buf, buf + 32);
    }

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("save_light_state: cannot open '" + path + "' for write");
    f.write(reinterpret_cast<const char*>(out.data()),
            static_cast<std::streamsize>(out.size()));
    if (!f) throw std::runtime_error("save_light_state: write error on '" + path + "'");
}

LightState load_light_state(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("load_light_state: cannot open '" + path + "'");
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());

    // Field-boundary diagnostics: name the field the truncation landed in.
    if (d.size() < 4 || std::memcmp(d.data(), "DLS1", 4) != 0)
        throw std::runtime_error("load_light_state: missing DLS1 magic in '" +
                                 path + "' (not a canonical binary state cache)");
    if (d.size() < 8)
        throw std::runtime_error("load_light_state: truncated at 'schema_version'");

    LightState s;
    s.schema_version = 0;
    for (int i = 0; i < 4; ++i)
        s.schema_version |= uint32_t(d[4 + i]) << (8 * i);
    if (s.schema_version != 1)
        throw std::runtime_error("load_light_state: unsupported schema_version " +
                                 std::to_string(s.schema_version) +
                                 " (this build understands 1) — clear the cache");

    if (d.size() < 40)
        throw std::runtime_error("load_light_state: truncated at 'genesis_hash'");
    s.genesis_hash = bytes32_to_hex(d.data() + 8);

    if (d.size() < 48)
        throw std::runtime_error("load_light_state: truncated at 'head_height'");
    s.head_height = 0;
    for (int i = 0; i < 8; ++i)
        s.head_height |= uint64_t(d[40 + i]) << (8 * i);

    if (d.size() < 80)
        throw std::runtime_error("load_light_state: truncated at 'head_block_hash'");
    s.head_block_hash = bytes32_to_hex(d.data() + 48);

    if (d.size() < DLS1_BASE)
        throw std::runtime_error("load_light_state: truncated at 'has_state_root'");
    const uint8_t flag = d[80];
    if (flag != 0 && flag != 1)
        throw std::runtime_error("load_light_state: 'has_state_root' flag must be 0 or 1");

    if (flag == 0) {
        if (d.size() != DLS1_BASE)
            throw std::runtime_error("load_light_state: trailing bytes after "
                                     "'has_state_root' (exact 81-byte container required)");
        s.head_state_root.clear();
    } else {
        if (d.size() < DLS1_FULL)
            throw std::runtime_error("load_light_state: truncated at 'head_state_root'");
        if (d.size() != DLS1_FULL)
            throw std::runtime_error("load_light_state: trailing bytes after "
                                     "'head_state_root' (exact 113-byte container required)");
        s.head_state_root = bytes32_to_hex(d.data() + 81);
    }
    return s;
}

bool light_state_exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(path), ec) && !ec;
}

}  // namespace determ::light
