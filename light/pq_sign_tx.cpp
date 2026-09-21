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
#include "seed_source.hpp"                // S-110: --*-seed-from + the raw-flag warning
#include <determ/crypto/pqauth.hpp>
#include <determ/crypto/pq_address.hpp>   // make_pq_anon_address (pq-transfer / pq-address)
#include <determ/crypto.hpp>              // determ::c99::mldsa::keygen (derive the PQ pubkey)
#include <determ/crypto/sha256.hpp>       // sha256 (tx hash)
#include <determ/chain/block.hpp>         // determ::chain::Transaction / TxType (from_json)
#include <determ/chain/pq_tx_auth.hpp>    // determ::chain::verify_pq_transaction (the node rule)
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

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

// The seed-hex validator, shared by the raw `--*-seed` flags and the S-110
// `--*-seed-from` sources: EXACTLY 32 bytes / 64 hex chars, nothing else. An
// odd-length or non-hex string reaches here as a from_hex exception whose
// message ("odd hex length" / stoul's) does not name the offending flag; wrap it
// so every rejection is a named diagnostic. The accepted set is unchanged.
std::array<uint8_t, 32> parse_seed32(const std::string& flag, const std::string& hex) {
    std::vector<uint8_t> v;
    try {
        v = determ::from_hex(hex);
    } catch (const std::exception& e) {
        throw std::runtime_error(flag + " is not valid hex (" + std::string(e.what())
                                 + "); expected 64 hex chars");
    }
    if (v.size() != 32) {
        determ::light::zero_secret_bytes(v.data(), v.size());
        throw std::runtime_error(flag + " must be 32 bytes (64 hex chars); got "
                                 + std::to_string(v.size()) + " bytes");
    }
    std::array<uint8_t, 32> a{};
    std::copy(v.begin(), v.end(), a.begin());
    determ::light::zero_secret_bytes(v.data(), v.size());
    return a;
}

// resolve_seed_hex() + SeedScrub are shared with light/main.cpp's --blind-seed
// commands and live in light/seed_source.{hpp,cpp}.

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
    std::string type_str, from_str, to_str, scheme_str, out_path;
    std::string mldsa_seed_raw, mldsa_seed_src, ed_seed_raw, ed_seed_src;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--type"            && i + 1 < argc) type_str       = argv[++i];
        else if (a == "--from"            && i + 1 < argc) from_str       = argv[++i];
        else if (a == "--to"              && i + 1 < argc) to_str         = argv[++i];
        else if (a == "--amount"          && i + 1 < argc) { amount = parse_u64_arg("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"             && i + 1 < argc) { fee    = parse_u64_arg("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"           && i + 1 < argc) { nonce  = parse_u64_arg("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--scheme"          && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed"      && i + 1 < argc) mldsa_seed_raw = argv[++i];
        else if (a == "--mldsa-seed-from" && i + 1 < argc) mldsa_seed_src = argv[++i];
        else if (a == "--ed-seed"         && i + 1 < argc) ed_seed_raw    = argv[++i];
        else if (a == "--ed-seed-from"    && i + 1 < argc) ed_seed_src    = argv[++i];
        else if (a == "--out"             && i + 1 < argc) out_path       = argv[++i];
        else { std::cerr << "pq-sign-tx: unknown arg '" << a << "'\n"; return 1; }
    }
    // S-110: resolve the seeds BEFORE the required-argument check so
    // `--mldsa-seed-from` satisfies it exactly as `--mldsa-seed` does.
    std::string mldsa_seed_hex, ed_seed_hex;
    SeedScrub scrub_m, scrub_e;
    if (!resolve_seed_hex("pq-sign-tx", "--mldsa-seed", "--mldsa-seed-from",
                          mldsa_seed_raw, mldsa_seed_src, mldsa_seed_hex)) return 1;
    scrub_on_scope_exit(scrub_m, mldsa_seed_hex);
    if (!resolve_seed_hex("pq-sign-tx", "--ed-seed", "--ed-seed-from",
                          ed_seed_raw, ed_seed_src, ed_seed_hex)) return 1;
    scrub_on_scope_exit(scrub_e, ed_seed_hex);

    if (type_str.empty() || from_str.empty() || scheme_str.empty() || mldsa_seed_hex.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "pq-sign-tx: --type, --from, --amount, --fee, --nonce, --scheme, "
                     "--mldsa-seed|--mldsa-seed-from are required (--to for TRANSFER; "
                     "--ed-seed|--ed-seed-from for hybrid*)\n";
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
            std::cerr << "pq-sign-tx: hybrid scheme requires --ed-seed|--ed-seed-from\n"; return 1;
        }
        std::array<uint8_t, 32> mseed{}, eseed{};
        SeedScrub scrub_ms{mseed.data(), mseed.size()};
        SeedScrub scrub_es{eseed.data(), eseed.size()};
        // Name the flag the operator actually used in any hex diagnostic.
        const char* mflag = mldsa_seed_src.empty() ? "--mldsa-seed" : "--mldsa-seed-from";
        const char* eflag = ed_seed_src.empty()    ? "--ed-seed"    : "--ed-seed-from";
        mseed = parse_seed32(mflag, mldsa_seed_hex);
        std::optional<std::span<const uint8_t, 32>> edopt;
        if (hybrid) { eseed = parse_seed32(eflag, ed_seed_hex);
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

// Outcome of the offline verify core (exposed to the selftest below).
struct PqVerifyOutcome {
    bool        ok = false;
    bool        is_pq_transfer = false;  // type == PQ_TRANSFER (11): the consensus PQ-native tx
    bool        hybrid = false;
    uint8_t     scheme = 0;
    std::string detail;
};

// The offline verify decision, shared by cmd_pq_verify_tx + the selftest.
//
// A PQ_TRANSFER (type 11) is a CONSENSUS tx: its account `from` is a hash-commit
// to (form, ML-DSA pubkey). A DPQ1 envelope is SELF-CERTIFYING — it carries its
// own pubkey — so "the envelope's signature verifies over signing_bytes" only
// proves the CARRIED key signed, NOT that the key is the one committed to by
// `from`. Enforce the FULL node accept-rule (determ::chain::verify_pq_transaction,
// which adds the address binding make_pq_anon_address(form, pk)==from + the
// non-hybrid + normalized-address legs). Without the bind, an attacker signing a
// victim-`from` message with ITS OWN key would be reported VERIFIED here yet
// REJECTED by the node — a false authenticity assurance.
//
// For any other type this stays the generic "does this DPQ1 envelope bind these
// signing_bytes" check (pq-sign-tx demonstration txs on non-PQ-native accounts).
static PqVerifyOutcome pq_verify_tx_core(const json& tx) {
    PqVerifyOutcome r;
    const int type_int = tx.at("type").get<int>();
    if (type_int == static_cast<int>(determ::chain::TxType::PQ_TRANSFER)) {
        r.is_pq_transfer = true;
        determ::chain::Transaction t = determ::chain::Transaction::from_json(tx);
        r.ok = determ::chain::verify_pq_transaction(t);
        // Report the envelope's declared scheme for the message (best-effort).
        auto env = determ::from_hex(tx.at("pq_auth").get<std::string>());
        auto vr  = pqauth::verify(env, t.signing_bytes());
        r.scheme = vr.scheme; r.hybrid = vr.hybrid;
        r.detail = r.ok
            ? "PQ_TRANSFER authenticated: ML-DSA signature + address binding "
              "(make_pq_anon_address(form, pubkey) == from)"
            : "PQ_TRANSFER FAILS the consensus accept-rule (bad signature, "
              "hybrid/unknown scheme, non-normalized from, or the envelope's key "
              "does NOT hash to `from`)";
        return r;
    }
    // Generic (non-PQ-native) DPQ1 envelope check over the tx signing_bytes.
    LightTxType type = static_cast<LightTxType>(type_int);
    std::string from = tx.at("from").get<std::string>();
    std::string to   = tx.at("to").get<std::string>();
    uint64_t amount  = tx.at("amount").get<uint64_t>();
    uint64_t fee     = tx.at("fee").get<uint64_t>();
    uint64_t nonce   = tx.at("nonce").get<uint64_t>();
    auto env         = determ::from_hex(tx.at("pq_auth").get<std::string>());
    auto sb = compute_signing_bytes(type, from, to, amount, fee, nonce);
    auto vr = pqauth::verify(env, sb);
    r.ok = vr.ok; r.scheme = vr.scheme; r.hybrid = vr.hybrid;
    r.detail = vr.ok ? "DPQ1 envelope binds this tx's signing_bytes under the carried key"
                     : "DPQ1 envelope does not verify against this tx";
    return r;
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
        PqVerifyOutcome r = pq_verify_tx_core(tx);
        if (r.ok) {
            std::cout << "VERIFIED: " << r.detail << " (scheme=" << pq_scheme_name(r.scheme)
                      << (r.hybrid ? ", hybrid Ed25519+ML-DSA" : ", ML-DSA") << ")\n";
            return 0;
        }
        std::cout << "INVALID: " << r.detail << "\n";
        return 3;
    } catch (const std::exception& e) {
        std::cerr << "pq-verify-tx: " << e.what() << "\n";
        return 1;
    }
}

int cmd_pq_address(int argc, char** argv) {
    std::string scheme_str, mldsa_seed_raw, mldsa_seed_src;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--scheme"          && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed"      && i + 1 < argc) mldsa_seed_raw = argv[++i];
        else if (a == "--mldsa-seed-from" && i + 1 < argc) mldsa_seed_src = argv[++i];
        else { std::cerr << "pq-address: unknown arg '" << a << "'\n"; return 1; }
    }
    std::string mldsa_seed_hex;
    SeedScrub scrub_m;
    if (!resolve_seed_hex("pq-address", "--mldsa-seed", "--mldsa-seed-from",
                          mldsa_seed_raw, mldsa_seed_src, mldsa_seed_hex)) return 1;
    scrub_on_scope_exit(scrub_m, mldsa_seed_hex);
    if (scheme_str.empty() || mldsa_seed_hex.empty()) {
        std::cerr << "pq-address: --scheme {mldsa44|mldsa65|mldsa87} + "
                     "--mldsa-seed <hex32>|--mldsa-seed-from <file:path|env:NAME|prompt> required\n";
        return 1;
    }
    try {
        pqauth::Scheme scheme = parse_pq_scheme(scheme_str);
        std::array<uint8_t, 32> mseed{};
        SeedScrub scrub_ms{mseed.data(), mseed.size()};
        mseed = parse_seed32(mldsa_seed_src.empty() ? "--mldsa-seed" : "--mldsa-seed-from",
                             mldsa_seed_hex);
        std::cout << derive_pq_from(scheme, mseed) << "\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "pq-address: " << e.what() << "\n"; return 1; }
}

int cmd_pq_transfer(int argc, char** argv) {
    std::string to_str, scheme_str, out_path, mldsa_seed_raw, mldsa_seed_src, genesis_hash_hex;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    uint32_t shard_id = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--to"              && i + 1 < argc) to_str         = argv[++i];
        else if (a == "--amount"          && i + 1 < argc) { amount = parse_u64_arg("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"             && i + 1 < argc) { fee    = parse_u64_arg("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"           && i + 1 < argc) { nonce  = parse_u64_arg("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--scheme"          && i + 1 < argc) scheme_str     = argv[++i];
        else if (a == "--mldsa-seed"      && i + 1 < argc) mldsa_seed_raw = argv[++i];
        else if (a == "--mldsa-seed-from" && i + 1 < argc) mldsa_seed_src = argv[++i];
        else if (a == "--genesis-hash"    && i + 1 < argc) genesis_hash_hex = argv[++i];
        else if (a == "--shard-id"        && i + 1 < argc) shard_id       = static_cast<uint32_t>(parse_u64_arg("--shard-id", argv[++i]));
        else if (a == "--out"             && i + 1 < argc) out_path       = argv[++i];
        else { std::cerr << "pq-transfer: unknown arg '" << a << "'\n"; return 1; }
    }
    std::string mldsa_seed_hex;
    SeedScrub scrub_m;
    if (!resolve_seed_hex("pq-transfer", "--mldsa-seed", "--mldsa-seed-from",
                          mldsa_seed_raw, mldsa_seed_src, mldsa_seed_hex)) return 1;
    scrub_on_scope_exit(scrub_m, mldsa_seed_hex);
    if (to_str.empty() || scheme_str.empty() || mldsa_seed_hex.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "pq-transfer: --to, --amount, --fee, --nonce, --scheme {mldsa44|65|87}, "
                     "--mldsa-seed <hex32>|--mldsa-seed-from <file:path|env:NAME|prompt> "
                     "are required\n";
        return 1;
    }
    try {
        pqauth::Scheme scheme = parse_pq_scheme(scheme_str);
        std::array<uint8_t, 32> mseed{};
        SeedScrub scrub_ms{mseed.data(), mseed.size()};
        mseed = parse_seed32(mldsa_seed_src.empty() ? "--mldsa-seed" : "--mldsa-seed-from",
                             mldsa_seed_hex);
        std::string from = derive_pq_from(scheme, mseed);   // PQ-native bearer address

        std::array<uint8_t, 32> genesis_hash{};
        if (!genesis_hash_hex.empty()) {
            if (genesis_hash_hex.rfind("0x", 0) == 0) genesis_hash_hex = genesis_hash_hex.substr(2);
            if (genesis_hash_hex.size() == 64) {
                auto v = determ::from_hex(genesis_hash_hex);
                std::copy(v.begin(), v.end(), genesis_hash.begin());
            }
        }

        // Canonical PQ_TRANSFER signing_bytes (type=11; layout == src/chain/block.cpp, D23 / R-17 S-103).
        std::vector<uint8_t> sb;
        sb.push_back(11);
        sb.insert(sb.end(), genesis_hash.begin(), genesis_hash.end());
        for (int i = 3; i >= 0; --i) sb.push_back((shard_id >> (i * 8)) & 0xFF);
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
            {"type",         11},
            {"genesis_hash", to_hex(genesis_hash.data(), genesis_hash.size())},
            {"shard_id",     shard_id},
            {"from",         from},
            {"to",           to_str},
            {"amount",       amount},
            {"fee",          fee},
            {"nonce",        nonce},
            {"payload",      ""},
            {"sig",          std::string(128, '0')},
            {"hash",         to_hex(h)},
            {"pq_auth",      to_hex(env.data(), env.size())},
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

// Falsify-on-mutant gate for the PQ_TRANSFER address binding. A DPQ1 envelope is
// self-certifying, so an envelope-ONLY check accepts a tx signed by ANY key. The
// fix routes a PQ_TRANSFER through determ::chain::verify_pq_transaction, which
// binds the envelope's key to `from`. This selftest constructs a concrete forgery
// (attacker key B signs a victim-`from`(==H(A)) message) and proves the core now
// REJECTS it while the raw envelope check still accepts it.
int cmd_selftest_pq_addr_bind(int, char**) {
    using determ::chain::Transaction;
    using determ::chain::TxType;
    int pass = 0, fail = 0;
    auto check = [&](bool c, const char* m) {
        if (c) { std::cout << "  ok:   " << m << "\n"; pass++; }
        else   { std::cout << "  FAIL: " << m << "\n"; fail++; }
    };
    std::cout << "=== selftest-pq-addr-bind: PQ_TRANSFER envelope key must hash to `from` ===\n";
    try {
        std::array<uint8_t, 32> seedA{}, seedB{};
        seedA.fill(0xA1); seedB.fill(0xB2);
        auto kpA = determ::c99::mldsa::keygen(determ::c99::mldsa::ParamSet::ML_DSA_44, seedA);
        const uint8_t form = static_cast<uint8_t>(pqauth::Scheme::MLDSA44);   // 0x01
        std::string fromA = determ::make_pq_anon_address(form, kpA.pk);

        Transaction t;
        t.type = TxType::PQ_TRANSFER;
        t.from = fromA; t.to = "recipient_domain";
        t.amount = 5; t.fee = 1; t.nonce = 0;
        const std::vector<uint8_t> sb = t.signing_bytes();   // binds `from`==H(A)

        auto envA = pqauth::sign(pqauth::Scheme::MLDSA44, sb, seedA);   // honest: A signs
        auto envB = pqauth::sign(pqauth::Scheme::MLDSA44, sb, seedB);   // FORGERY: B signs A's msg
        Hash h = determ::crypto::sha256(sb.data(), sb.size());

        json base = {{"type", static_cast<int>(TxType::PQ_TRANSFER)}, {"from", fromA},
                     {"to", t.to}, {"amount", 5}, {"fee", 1}, {"nonce", 0},
                     {"payload", ""}, {"sig", std::string(128, '0')}, {"hash", to_hex(h)}};
        json jl = base; jl["pq_auth"] = to_hex(envA.data(), envA.size());
        json jf = base; jf["pq_auth"] = to_hex(envB.data(), envB.size());

        // The gap: the envelope-ONLY check (the old behavior) ACCEPTS the forgery,
        // because B's signature genuinely verifies under B's carried pubkey.
        check(pqauth::verify(envB, sb).ok,
              "envelope-only check verifies the FORGED envelope (B signs A's message) — the gap");
        // The fix, on the same forged bytes:
        check(pq_verify_tx_core(jl).ok,
              "legit PQ_TRANSFER (A signs, from==H(A)) -> VERIFIED");
        check(pq_verify_tx_core(jf).is_pq_transfer,
              "forged tx is routed through the PQ_TRANSFER consensus accept-rule");
        check(!pq_verify_tx_core(jf).ok,
              "FORGED PQ_TRANSFER (B signs, from==H(A)) -> INVALID (address binding catches it)");
    } catch (const std::exception& e) {
        std::cout << "  FAIL: exception: " << e.what() << "\n"; fail++;
    }
    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-pq-addr-bind\n"; return 0; }
    std::cout << "  FAIL: selftest-pq-addr-bind\n"; return 1;
}

} // namespace determ::light
