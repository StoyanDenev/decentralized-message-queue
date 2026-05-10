#include <determ/crypto/keys.hpp>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace determ::crypto {

using json = nlohmann::json;
namespace fs = std::filesystem;

NodeKey generate_node_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("keygen_init failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("keygen failed");
    EVP_PKEY_CTX_free(ctx);

    NodeKey key;
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &len);
    len = 32;
    EVP_PKEY_get_raw_private_key(pkey, key.priv_seed.data(), &len);
    EVP_PKEY_free(pkey);
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
    NodeKey key;
    key.pub       = from_hex_arr<32>(j["pubkey"].get<std::string>());
    key.priv_seed = from_hex_arr<32>(j["priv_seed"].get<std::string>());
    return key;
}

Signature sign(const NodeKey& key, const uint8_t* data, size_t len) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) throw std::runtime_error("Failed to create signing key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0)
        throw std::runtime_error("DigestSignInit failed");

    Signature sig{};
    size_t sig_len = 64;
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, data, len) <= 0)
        throw std::runtime_error("DigestSign failed");

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return sig;
}

bool verify(const PubKey& pub, const uint8_t* data, size_t len, const Signature& sig) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), 32);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) > 0)
        ok = (EVP_DigestVerify(ctx, sig.data(), 64, data, len) == 1);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

} // namespace determ::crypto
