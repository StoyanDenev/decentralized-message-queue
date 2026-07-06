// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light PQ transaction authentication. Builds the SAME canonical
// signing_bytes as src/chain/block.cpp::Transaction::signing_bytes (via the
// shared compute_signing_bytes) and binds it with a DPQ1 envelope
// (determ::pqauth): ML-DSA (FIPS 204), optionally HYBRID with Ed25519 so an
// attacker must break BOTH. Emits the tx JSON with a `pq_auth` hex field; the
// verify side recomputes signing_bytes from the tx fields and checks the
// envelope offline. No consensus path is touched — this is client tooling.

#include "pq_sign_tx.hpp"
#include "sign_tx.hpp"                    // LightTxType, parse_tx_type, compute_signing_bytes
#include <determ/crypto/pqauth.hpp>
#include <determ/crypto/pq_address.hpp>   // make_pq_anon_address (pq-transfer / pq-address)
#include <determ/crypto.hpp>              // determ::c99::mldsa::keygen (derive the PQ pubkey)
#include <determ/crypto/sha256.hpp>       // sha256 (tx hash)
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <array>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>

namespace determ::light {
using nlohmann::json;

namespace {

pqauth::Scheme parse_pq_scheme(const std::string& s) {
    if (s == "mldsa44")  return pqauth::Scheme::MLDSA44;
    if (s == "mldsa65")  return pqauth::Scheme::MLDSA65;
    if (s == "mldsa87")  return pqauth::Scheme::MLDSA87;
    if (s == "hybrid44") return pqauth::Scheme::HYBRID_MLDSA44;
    if (s == "hybrid65") return pqauth::Scheme::HYBRID_MLDSA65;
    if (s == "hybrid87") return pqauth::Scheme::HYBRID_MLDSA87;
    throw std::runtime_error(
        "--scheme must be mldsa{44,65,87} | hybrid{44,65,87} (got '" + s + "')");
}
const char* pq_scheme_name(uint8_t s) {
    switch (s) {
        case 0x01: return "mldsa44";  case 0x02: return "mldsa65";  case 0x03: return "mldsa87";
        case 0x11: return "hybrid44"; case 0x12: return "hybrid65"; case 0x13: return "hybrid87";
    }
    return "?";
}
bool scheme_is_hybrid(pqauth::Scheme s) { return (static_cast<uint8_t>(s) & 0x10) != 0; }

determ::c99::mldsa::ParamSet scheme_paramset(pqauth::Scheme s) {
    switch (static_cast<uint8_t>(s) & 0x0f) {
        case 0x02: return determ::c99::mldsa::ParamSet::ML_DSA_65;
        case 0x03: return determ::c99::mldsa::ParamSet::ML_DSA_87;
        default:   return determ::c99::mldsa::ParamSet::ML_DSA_44;
    }
}

// Derive the PQ-native BEARER `from` address for a PQ-only scheme + seed:
// address = make_pq_anon_address(form, ML-DSA pubkey(seed)). Throws on hybrid.
std::string derive_pq_from(pqauth::Scheme scheme, const std::array<uint8_t, 32>& mseed) {
    if (scheme_is_hybrid(scheme))
        throw std::runtime_error("PQ-native address requires a PQ-only scheme (mldsa44/65/87), not hybrid");
    auto kp = determ::c99::mldsa::keygen(scheme_paramset(scheme), mseed);
    return determ::make_pq_anon_address(static_cast<uint8_t>(scheme), kp.pk);  // low nibble == form
}

uint64_t parse_u64_arg(const std::string& flag, const std::string& v) {
    if (v.empty() || v[0] == '-') throw std::runtime_error(flag + " must be a u64 (got '" + v + "')");
    try {
        size_t pos = 0;
        unsigned long long u = std::stoull(v, &pos, 10);
        if (pos != v.size()) throw std::invalid_argument("trailing");
        return static_cast<uint64_t>(u);
    } catch (...) {
        throw std::runtime_error(flag + " must be a u64 integer (got '" + v + "')");
    }
}

std::array<uint8_t, 32> parse_seed32(const std::string& flag, const std::string& hex) {
    auto v = determ::from_hex(hex);
    if (v.size() != 32)
        throw std::runtime_error(flag + " must be 32 bytes (64 hex chars); got "
                                 + std::to_string(v.size()) + " bytes");
    std::array<uint8_t, 32> a{};
    std::copy(v.begin(), v.end(), a.begin());
    return a;
}

const char* tx_type_name(LightTxType t) {
    switch (t) {
        case LightTxType::TRANSFER:   return "TRANSFER";
        case LightTxType::STAKE:      return "STAKE";
        case LightTxType::UNSTAKE:    return "UNSTAKE";
        case LightTxType::REGISTER:   return "REGISTER";
        case LightTxType::DEREGISTER: return "DEREGISTER";
    }
    return "?";
}

} // namespace

int cmd_pq_sign_tx(int argc, char** argv) {
    std::string type_str, from_str, to_str, scheme_str, mldsa_seed_hex, ed_seed_hex, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--type"       && i + 1 < argc) type_str       = argv[++i];
        else if (a == "--from"       && i + 1 < argc) from_str       = argv[++i];
        else if (a == "--to"         && i + 1 < argc) to_str         = argv[++i];
        else if (a == "--amount"     && i + 1 < argc) { amount = parse_u64_arg("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"        && i + 1 < argc) { fee    = parse_u64_arg("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"      && i + 1 < argc) { nonce  = parse_u64_arg("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--scheme"     && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed" && i + 1 < argc) mldsa_seed_hex = argv[++i];
        else if (a == "--ed-seed"    && i + 1 < argc) ed_seed_hex    = argv[++i];
        else if (a == "--out"        && i + 1 < argc) out_path       = argv[++i];
        else { std::cerr << "pq-sign-tx: unknown arg '" << a << "'\n"; return 1; }
    }
    if (type_str.empty() || from_str.empty() || scheme_str.empty() || mldsa_seed_hex.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "pq-sign-tx: --type, --from, --amount, --fee, --nonce, --scheme, "
                     "--mldsa-seed are required (--to for TRANSFER; --ed-seed for hybrid*)\n";
        return 1;
    }
    try {
        LightTxType type = parse_tx_type(type_str);
        if (type == LightTxType::TRANSFER && to_str.empty()) {
            std::cerr << "pq-sign-tx: TRANSFER requires --to\n"; return 1;
        }
        pqauth::Scheme scheme = parse_pq_scheme(scheme_str);
        const bool hybrid = scheme_is_hybrid(scheme);
        if (hybrid && ed_seed_hex.empty()) {
            std::cerr << "pq-sign-tx: hybrid scheme requires --ed-seed\n"; return 1;
        }
        auto mseed = parse_seed32("--mldsa-seed", mldsa_seed_hex);
        std::array<uint8_t, 32> eseed{};
        std::optional<std::span<const uint8_t, 32>> edopt;
        if (hybrid) { eseed = parse_seed32("--ed-seed", ed_seed_hex);
                      edopt = std::span<const uint8_t, 32>(eseed); }

        // The chain's canonical signed message — byte-for-byte block.cpp.
        auto sb  = compute_signing_bytes(type, from_str, to_str, amount, fee, nonce);
        auto env = pqauth::sign(scheme, sb, mseed, edopt);

        json out = {
            {"type",      static_cast<int>(type)},
            {"type_name", tx_type_name(type)},
            {"from",      from_str},
            {"to",        to_str},
            {"amount",    amount},
            {"fee",       fee},
            {"nonce",     nonce},
            {"payload",   ""},
            {"pq_scheme", pq_scheme_name(static_cast<uint8_t>(scheme))},
            {"pq_auth",   to_hex(env.data(), env.size())},
        };
        if (out_path.empty()) {
            std::cout << out.dump() << "\n";
        } else {
            std::ofstream f(out_path);
            if (!f) { std::cerr << "pq-sign-tx: cannot write " << out_path << "\n"; return 1; }
            f << out.dump(1) << "\n";
            std::cout << "OK: wrote DPQ1-authenticated tx (scheme=" << pq_scheme_name(static_cast<uint8_t>(scheme))
                      << ", pq_auth=" << env.size() << " bytes) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "pq-sign-tx: " << e.what() << "\n";
        return 1;
    }
}

int cmd_pq_verify_tx(int argc, char** argv) {
    std::string in_path;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--file" && i + 1 < argc) in_path = argv[++i];
        else { std::cerr << "pq-verify-tx: unknown arg '" << a << "'\n"; return 1; }
    }
    if (in_path.empty()) { std::cerr << "pq-verify-tx: --file <tx.json> is required\n"; return 1; }
    try {
        std::ifstream f(in_path);
        if (!f) { std::cerr << "pq-verify-tx: cannot read " << in_path << "\n"; return 1; }
        json tx; f >> tx;
        LightTxType type = static_cast<LightTxType>(tx.at("type").get<int>());
        std::string from = tx.at("from").get<std::string>();
        std::string to   = tx.at("to").get<std::string>();
        uint64_t amount  = tx.at("amount").get<uint64_t>();
        uint64_t fee     = tx.at("fee").get<uint64_t>();
        uint64_t nonce   = tx.at("nonce").get<uint64_t>();
        auto env         = determ::from_hex(tx.at("pq_auth").get<std::string>());

        auto sb = compute_signing_bytes(type, from, to, amount, fee, nonce);
        auto vr = pqauth::verify(env, sb);
        if (vr.ok) {
            std::cout << "VERIFIED: DPQ1 envelope (scheme=" << pq_scheme_name(vr.scheme)
                      << (vr.hybrid ? ", hybrid Ed25519+ML-DSA" : ", ML-DSA")
                      << ") binds this tx's signing_bytes\n";
            return 0;
        }
        std::cout << "INVALID: DPQ1 envelope does not verify against this tx\n";
        return 3;
    } catch (const std::exception& e) {
        std::cerr << "pq-verify-tx: " << e.what() << "\n";
        return 1;
    }
}

int cmd_pq_address(int argc, char** argv) {
    std::string scheme_str, mldsa_seed_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--scheme"     && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed" && i + 1 < argc) mldsa_seed_hex = argv[++i];
        else { std::cerr << "pq-address: unknown arg '" << a << "'\n"; return 1; }
    }
    if (scheme_str.empty() || mldsa_seed_hex.empty()) {
        std::cerr << "pq-address: --scheme {mldsa44|mldsa65|mldsa87} + --mldsa-seed <hex32> required\n";
        return 1;
    }
    try {
        pqauth::Scheme scheme = parse_pq_scheme(scheme_str);
        auto mseed = parse_seed32("--mldsa-seed", mldsa_seed_hex);
        std::cout << derive_pq_from(scheme, mseed) << "\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "pq-address: " << e.what() << "\n"; return 1; }
}

int cmd_pq_transfer(int argc, char** argv) {
    std::string to_str, scheme_str, mldsa_seed_hex, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--to"         && i + 1 < argc) to_str         = argv[++i];
        else if (a == "--amount"     && i + 1 < argc) { amount = parse_u64_arg("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"        && i + 1 < argc) { fee    = parse_u64_arg("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"      && i + 1 < argc) { nonce  = parse_u64_arg("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--scheme"     && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed" && i + 1 < argc) mldsa_seed_hex = argv[++i];
        else if (a == "--out"        && i + 1 < argc) out_path       = argv[++i];
        else { std::cerr << "pq-transfer: unknown arg '" << a << "'\n"; return 1; }
    }
    if (to_str.empty() || scheme_str.empty() || mldsa_seed_hex.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "pq-transfer: --to, --amount, --fee, --nonce, --scheme {mldsa44|65|87}, "
                     "--mldsa-seed <hex32> are required\n";
        return 1;
    }
    try {
        pqauth::Scheme scheme = parse_pq_scheme(scheme_str);
        auto mseed = parse_seed32("--mldsa-seed", mldsa_seed_hex);
        std::string from = derive_pq_from(scheme, mseed);   // PQ-native bearer address

        // Canonical PQ_TRANSFER signing_bytes (type=11; layout == src/chain/block.cpp).
        std::vector<uint8_t> sb;
        sb.push_back(11);
        sb.insert(sb.end(), from.begin(), from.end()); sb.push_back(0);
        sb.insert(sb.end(), to_str.begin(), to_str.end()); sb.push_back(0);
        for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);

        auto env = pqauth::sign(scheme, sb, mseed);           // PQ-only DPQ1 envelope
        Hash h   = determ::crypto::sha256(sb.data(), sb.size());

        // Canonical, submittable Transaction JSON (from_json-compatible: sig is a
        // 64-zero-byte placeholder — a PQ account has no Ed25519 key; pq_auth carries
        // the real authenticator).
        json out = {
            {"type",    11},
            {"from",    from},
            {"to",      to_str},
            {"amount",  amount},
            {"fee",     fee},
            {"nonce",   nonce},
            {"payload", ""},
            {"sig",     std::string(128, '0')},
            {"hash",    to_hex(h)},
            {"pq_auth", to_hex(env.data(), env.size())},
        };
        if (out_path.empty()) {
            std::cout << out.dump() << "\n";
        } else {
            std::ofstream f(out_path);
            if (!f) { std::cerr << "pq-transfer: cannot write " << out_path << "\n"; return 1; }
            f << out.dump(1) << "\n";
            std::cout << "OK: wrote submittable PQ_TRANSFER (from " << from.substr(0, 18)
                      << "... amount=" << amount << " nonce=" << nonce << ") to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) { std::cerr << "pq-transfer: " << e.what() << "\n"; return 1; }
}

} // namespace determ::light
