// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light persisted-anchor cache implementation. See persist.hpp for the
// trust model. Self-contained: nlohmann::json + std streams + std::filesystem;
// no dependency on the daemon, libsodium, or asio.

#include "persist.hpp"

#include <nlohmann/json.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace determ::light {

namespace {

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
    return (fs::path(home_dir()) / ".determ-light" / "state.json").string();
}

void save_light_state(const std::string& path, const LightState& s) {
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

    nlohmann::json j;
    j["schema_version"]  = s.schema_version;
    j["genesis_hash"]    = s.genesis_hash;
    j["head_height"]     = s.head_height;
    j["head_block_hash"] = s.head_block_hash;
    j["head_state_root"] = s.head_state_root;

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("save_light_state: cannot open '" + path + "' for write");
    f << j.dump(2) << "\n";
    if (!f) throw std::runtime_error("save_light_state: write error on '" + path + "'");
}

LightState load_light_state(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("load_light_state: cannot open '" + path + "'");
    std::stringstream ss;
    ss << f.rdbuf();

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(ss.str());
    } catch (const std::exception& e) {
        throw std::runtime_error("load_light_state: malformed JSON in '" + path +
                                 "': " + e.what());
    }
    if (!j.is_object())
        throw std::runtime_error("load_light_state: top-level value is not an object");

    LightState s;
    if (!j.contains("schema_version") || !j["schema_version"].is_number_unsigned())
        throw std::runtime_error("load_light_state: missing/invalid 'schema_version'");
    s.schema_version = j["schema_version"].get<uint32_t>();
    if (s.schema_version != 1)
        throw std::runtime_error("load_light_state: unsupported schema_version " +
                                 std::to_string(s.schema_version) +
                                 " (this build understands 1) — clear the cache");

    auto req_str = [&](const char* k) -> std::string {
        if (!j.contains(k) || !j[k].is_string())
            throw std::runtime_error(std::string("load_light_state: missing/invalid '") + k + "'");
        return j[k].get<std::string>();
    };

    s.genesis_hash = req_str("genesis_hash");
    if (!is_hex_len(s.genesis_hash, 64))
        throw std::runtime_error("load_light_state: 'genesis_hash' must be 64 hex chars");

    if (!j.contains("head_height") || !j["head_height"].is_number_unsigned())
        throw std::runtime_error("load_light_state: missing/invalid 'head_height'");
    s.head_height = j["head_height"].get<uint64_t>();

    s.head_block_hash = req_str("head_block_hash");
    if (!is_hex_len(s.head_block_hash, 64))
        throw std::runtime_error("load_light_state: 'head_block_hash' must be 64 hex chars");

    s.head_state_root = req_str("head_state_root");
    if (!s.head_state_root.empty() && !is_hex_len(s.head_state_root, 64))
        throw std::runtime_error("load_light_state: 'head_state_root' must be empty or 64 hex chars");

    return s;
}

bool light_state_exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(path), ec) && !ec;
}

}  // namespace determ::light
