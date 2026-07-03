// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// §3.15 backend swap (2026-07-03): Ed25519 keygen/sign/verify runs on the
// in-tree C99 RFC 8032 implementation (src/crypto/ed25519/ed25519.c) instead
// of OpenSSL EVP_PKEY_ED25519. Key format is unchanged (the raw private key
// IS the 32-byte RFC 8032 seed under both backends — existing node_key.json
// files load identically) and signing is deterministic RFC 8032, proven
// byte-equal to OpenSSL over a fuzzed (seed,msg) grid + the RFC 8032 KATs
// (`determ test-ed25519-c99` / `test-ed25519-vectors`). VERIFY is the
// consensus-visible edge: the C99 verifier enforces the RFC canonicality
// gates (S < L, canonical pubkey y < q) and is deliberately STRICTER than
// OpenSSL's lenient decoder on adversarial encodings. Locked in pre-genesis
// as THE consensus signature-validity rule (DECISION-LOG.md 2026-07-03):
// honestly-generated signatures are always canonical and behave identically;
// forged non-canonical encodings that OpenSSL would tolerate are rejected.
#include <determ/crypto/keys.hpp>
#include <determ/util/json_validate.hpp>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/rng/rng.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace determ::crypto {

using json = nlohmann::json;
using determ::util::json_require_hex;
namespace fs = std::filesystem;

NodeKey generate_node_key() {
    NodeKey key;
    // Fresh 32-byte RFC 8032 seed from the OS CSPRNG. Entropy failure is
    // fatal — an all-zero/partial seed must never become a node identity.
    if (determ_rng_bytes(key.priv_seed.data(), 32) != 0)
        throw std::runtime_error("OS entropy source failed (determ_rng_bytes)");
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), key.pub.data());
    return key;
}

void save_node_key(const NodeKey& key, const std::string& path) {
    fs::create_directories(fs::path(path).parent_path());
    json j;
    j["pubkey"]    = to_hex(key.pub);
    j["priv_seed"] = to_hex(key.priv_seed);
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write key file: " + path);
    f << j.dump(2);
}

NodeKey load_node_key(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open key file: " + path);
    json j = json::parse(f);
    // S-018: name the failing field if `pubkey` or `priv_seed` is
    // missing / wrong-typed / wrong-length. Operators occasionally
    // hand-edit node_key.json (e.g., to swap keys between deployments)
    // and the prior nlohmann-internal "type must be string, but is
    // null" error didn't tell them which field they botched.
    NodeKey key;
    key.pub       = from_hex_arr<32>(json_require_hex(j, "pubkey",    64));
    key.priv_seed = from_hex_arr<32>(json_require_hex(j, "priv_seed", 64));
    return key;
}

Signature sign(const NodeKey& key, const uint8_t* data, size_t len) {
    // Re-derive the public key from the seed (matching OpenSSL EVP semantics,
    // which ignored NodeKey.pub): a hand-edited keyfile with a mismatched
    // stored pub still produces a signature valid under the SEED's pubkey.
    uint8_t pk[32];
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), pk);
    Signature sig{};
    if (determ_ed25519_sign(key.priv_seed.data(), pk, data, len, sig.data()) != 0)
        throw std::runtime_error("Ed25519 sign failed");
    return sig;
}

bool verify(const PubKey& pub, const uint8_t* data, size_t len, const Signature& sig) {
    // Strict RFC 8032 verify (S < L, canonical pubkey) — see the header
    // comment: the consensus signature-validity rule as of the §3.15 swap.
    return determ_ed25519_verify(pub.data(), data, len, sig.data()) == 0;
}

} // namespace determ::crypto
