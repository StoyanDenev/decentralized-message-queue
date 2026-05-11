#include "opaque_primitives.hpp"
#include <sodium.h>
#include <mutex>
#include <cstring>

namespace determ::wallet::primitives {

namespace {
std::once_flag g_init_flag;
bool           g_init_ok = false;
} // namespace

bool init_libsodium() {
    std::call_once(g_init_flag, []() {
        g_init_ok = (sodium_init() >= 0);
    });
    return g_init_ok;
}

std::vector<uint8_t> random_bytes(size_t n) {
    if (!init_libsodium()) return {};
    std::vector<uint8_t> out(n);
    randombytes_buf(out.data(), n);
    return out;
}

std::vector<uint8_t> ristretto255_scalar_random() {
    if (!init_libsodium()) return {};
    std::vector<uint8_t> s(crypto_core_ristretto255_SCALARBYTES);
    crypto_core_ristretto255_scalar_random(s.data());
    return s;
}

std::vector<uint8_t> ristretto255_point_blind(const std::vector<uint8_t>& message,
                                                  const std::vector<uint8_t>& scalar) {
    if (!init_libsodium()) return {};
    if (scalar.size() != crypto_core_ristretto255_SCALARBYTES) return {};

    // Hash message into a 64-byte uniform string, then map to a ristretto255 point.
    std::vector<uint8_t> hash(crypto_core_ristretto255_HASHBYTES);
    crypto_generichash(hash.data(), hash.size(),
                          message.data(), message.size(),
                          nullptr, 0);
    std::vector<uint8_t> point(crypto_core_ristretto255_BYTES);
    if (crypto_core_ristretto255_from_hash(point.data(), hash.data()) != 0)
        return {};

    // Compute blinded = point * scalar.
    std::vector<uint8_t> blinded(crypto_core_ristretto255_BYTES);
    if (crypto_scalarmult_ristretto255(blinded.data(), scalar.data(),
                                            point.data()) != 0)
        return {};
    return blinded;
}

std::vector<uint8_t> argon2id(const std::vector<uint8_t>& password,
                                const std::vector<uint8_t>& salt,
                                size_t out_len,
                                uint64_t opslimit,
                                size_t   memlimit) {
    if (!init_libsodium()) return {};
    if (salt.size() != crypto_pwhash_SALTBYTES) return {};
    if (out_len < crypto_pwhash_BYTES_MIN) return {};
    if (out_len > crypto_pwhash_BYTES_MAX) return {};
    std::vector<uint8_t> out(out_len);
    if (crypto_pwhash(out.data(), out.size(),
                         reinterpret_cast<const char*>(password.data()),
                         password.size(),
                         salt.data(),
                         opslimit, memlimit,
                         crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return {};
    }
    return out;
}

} // namespace determ::wallet::primitives
