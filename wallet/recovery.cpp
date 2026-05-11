#include "recovery.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace determ::wallet::recovery {

using nlohmann::json;

namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

std::vector<uint8_t> from_hex(const std::string& s) {
    if (s.size() % 2 != 0) throw std::invalid_argument("from_hex: odd length");
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(s.substr(i, 2));
        ss >> std::hex >> byte;
        if (ss.fail()) throw std::invalid_argument("from_hex: non-hex char");
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
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
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), 32);
    if (!pkey) return {};
    uint8_t pub[32];
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1 || pub_len != 32) {
        EVP_PKEY_free(pkey);
        return {};
    }
    EVP_PKEY_free(pkey);
    std::vector<uint8_t> digest(32);
    SHA256(pub, 32, digest.data());
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
    setup.scheme          = "shamir-aead-passphrase";
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
        auto y_opt = envelope::decrypt(setup.envelopes[gid], password, aad);
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

std::string to_json(const RecoverySetup& setup) {
    json envs = json::array();
    for (auto& env : setup.envelopes) envs.push_back(envelope::serialize(env));
    return json{
        {"version",         setup.version},
        {"scheme",          setup.scheme},
        {"threshold",       setup.threshold},
        {"share_count",     setup.share_count},
        {"secret_len",      setup.secret_len},
        {"guardian_x",      setup.guardian_x},
        {"envelopes",       envs},
        {"pubkey_checksum", to_hex(setup.pubkey_checksum)}
    }.dump(2);
}

std::optional<RecoverySetup> from_json(const std::string& blob) {
    try {
        auto j = json::parse(blob);
        RecoverySetup s;
        s.version       = j.value("version",     uint32_t{1});
        s.scheme        = j.value("scheme",      std::string{});
        s.threshold     = j.value("threshold",   uint8_t{0});
        s.share_count   = j.value("share_count", uint8_t{0});
        s.secret_len    = j.value("secret_len",  size_t{0});
        if (j.contains("guardian_x"))
            for (auto& x : j["guardian_x"]) s.guardian_x.push_back(x.get<uint8_t>());
        if (j.contains("envelopes")) {
            for (auto& es : j["envelopes"]) {
                auto env_opt = envelope::deserialize(es.get<std::string>());
                if (!env_opt) return std::nullopt;
                s.envelopes.push_back(std::move(*env_opt));
            }
        }
        std::string ck_hex = j.value("pubkey_checksum", std::string{});
        if (!ck_hex.empty()) s.pubkey_checksum = from_hex(ck_hex);
        return s;
    } catch (std::exception&) {
        return std::nullopt;
    }
}

} // namespace determ::wallet::recovery
