// Determ C++ ergonomic wrapper over the C99 crypto layer — CRYPTO-C99-SPEC.md
// §3.11 / §2 Q5. Header-only.
//
// NAMESPACE NOTE (Q5 deviation, recorded in the spec's §3.11 status): the Q5
// sketch placed this in `determ::crypto`, but that namespace is TAKEN by the
// production OpenSSL-backed layer (include/determ/crypto/sha256.hpp,
// merkle.hpp, keys.hpp) with overlapping names and different semantics
// (`determ::crypto::sha256` returns the chain's `Hash`). Until the §3.15
// migration retires the OpenSSL layer, the C99 wrapper lives in
// `determ::c99`; at migration time it folds into `determ::crypto`.
//
// Conventions:
//   - std::span in, std::array / std::vector out.
//   - Parameter errors (a C-layer -1 on bad lengths / allocation) throw
//     std::runtime_error — they are caller bugs or resource exhaustion.
//   - AEAD authentication failure and X25519 low-order results return
//     std::nullopt — they are NORMAL adversarial-input outcomes a caller must
//     branch on, not exceptional states.
//   - No incremental/streaming state in this seed (the C layer is one-shot
//     except BLAKE2b; RAII streaming wrappers are §3.11 follow-up work).
#ifndef DETERM_CRYPTO_HPP
#define DETERM_CRYPTO_HPP

#include "determ/crypto.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace determ::c99 {

using Bytes = std::vector<uint8_t>;

namespace detail {
inline const uint8_t* ptr(std::span<const uint8_t> s) {
    return s.empty() ? nullptr : s.data();
}
inline void require(int rc, const char* what) {
    if (rc != 0) throw std::runtime_error(std::string("determ::c99: ") + what);
}
} // namespace detail

// ─── Hashing ────────────────────────────────────────────────────────────────

inline std::array<uint8_t, 32> sha256(std::span<const uint8_t> msg) {
    std::array<uint8_t, 32> out;
    determ_sha256(detail::ptr(msg), msg.size(), out.data());
    return out;
}
inline std::array<uint8_t, 64> sha512(std::span<const uint8_t> msg) {
    std::array<uint8_t, 64> out;
    determ_sha512(detail::ptr(msg), msg.size(), out.data());
    return out;
}
inline std::array<uint8_t, 32> sha256(std::string_view msg) {
    return sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
}
inline std::array<uint8_t, 64> sha512(std::string_view msg) {
    return sha512(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
}

// BLAKE2b: outlen in [1,64]; key up to 64 bytes (empty = unkeyed).
inline Bytes blake2b(size_t outlen,
                     std::span<const uint8_t> key,
                     std::span<const uint8_t> msg) {
    Bytes out(outlen);
    detail::require(determ_blake2b(out.data(), outlen,
                                   detail::ptr(key), key.size(),
                                   detail::ptr(msg), msg.size()),
                    "blake2b parameter error (outlen 1..64, keylen <= 64)");
    return out;
}

// ─── MAC + KDFs ─────────────────────────────────────────────────────────────

inline std::array<uint8_t, 32> hmac_sha256(std::span<const uint8_t> key,
                                           std::span<const uint8_t> msg) {
    std::array<uint8_t, 32> out;
    detail::require(determ_hmac_sha256(detail::ptr(key), key.size(),
                                       detail::ptr(msg), msg.size(), out.data()),
                    "hmac_sha256 failed (allocation or size overflow)");
    return out;
}
inline std::array<uint8_t, 64> hmac_sha512(std::span<const uint8_t> key,
                                           std::span<const uint8_t> msg) {
    std::array<uint8_t, 64> out;
    detail::require(determ_hmac_sha512(detail::ptr(key), key.size(),
                                       detail::ptr(msg), msg.size(), out.data()),
                    "hmac_sha512 failed (allocation or size overflow)");
    return out;
}

inline Bytes hkdf_sha256(std::span<const uint8_t> salt,
                         std::span<const uint8_t> ikm,
                         std::span<const uint8_t> info,
                         size_t outlen) {
    Bytes out(outlen);
    detail::require(determ_hkdf_sha256(detail::ptr(salt), salt.size(),
                                       detail::ptr(ikm), ikm.size(),
                                       detail::ptr(info), info.size(),
                                       out.data(), outlen),
                    "hkdf_sha256 failed (outlen > 8160 or allocation)");
    return out;
}

inline Bytes pbkdf2_hmac_sha256(std::span<const uint8_t> password,
                                std::span<const uint8_t> salt,
                                uint32_t iterations, size_t dklen) {
    Bytes out(dklen);
    detail::require(determ_pbkdf2_hmac_sha256(detail::ptr(password), password.size(),
                                              detail::ptr(salt), salt.size(),
                                              iterations, out.data(), dklen),
                    "pbkdf2_hmac_sha256 failed (iters == 0 or allocation)");
    return out;
}

inline Bytes argon2id(std::span<const uint8_t> password,
                      std::span<const uint8_t> salt,
                      uint32_t t_cost, uint32_t m_cost_kib,
                      uint32_t parallelism, size_t outlen) {
    Bytes out(outlen);
    detail::require(determ_argon2id(out.data(), outlen,
                                    detail::ptr(password), password.size(),
                                    detail::ptr(salt), salt.size(),
                                    t_cost, m_cost_kib, parallelism),
                    "argon2id failed (bad parameter or allocation)");
    return out;
}

// ─── AEADs ──────────────────────────────────────────────────────────────────
// seal -> ciphertext || 16-byte tag appended (the common wire shape).
// open -> plaintext, or std::nullopt on authentication failure (a NORMAL
// adversarial-input outcome — never an exception).

struct Sealed {
    Bytes ciphertext;                // same length as the plaintext
    std::array<uint8_t, 16> tag;
};

inline Sealed chacha20_poly1305_seal(std::span<const uint8_t, 32> key,
                                     std::span<const uint8_t, 12> nonce,
                                     std::span<const uint8_t> aad,
                                     std::span<const uint8_t> plaintext) {
    Sealed s;
    s.ciphertext.resize(plaintext.size());
    detail::require(determ_chacha20_poly1305_encrypt(
                        key.data(), nonce.data(),
                        detail::ptr(aad), aad.size(),
                        detail::ptr(plaintext), plaintext.size(),
                        s.ciphertext.empty() ? nullptr : s.ciphertext.data(),
                        s.tag.data()),
                    "chacha20_poly1305 seal failed");
    return s;
}
inline std::optional<Bytes> chacha20_poly1305_open(std::span<const uint8_t, 32> key,
                                                   std::span<const uint8_t, 12> nonce,
                                                   std::span<const uint8_t> aad,
                                                   std::span<const uint8_t> ciphertext,
                                                   std::span<const uint8_t, 16> tag) {
    Bytes pt(ciphertext.size());
    if (determ_chacha20_poly1305_decrypt(key.data(), nonce.data(),
                                         detail::ptr(aad), aad.size(),
                                         detail::ptr(ciphertext), ciphertext.size(),
                                         tag.data(),
                                         pt.empty() ? nullptr : pt.data()) != 0)
        return std::nullopt;
    return pt;
}

inline Sealed xchacha20_poly1305_seal(std::span<const uint8_t, 32> key,
                                      std::span<const uint8_t, 24> nonce,
                                      std::span<const uint8_t> aad,
                                      std::span<const uint8_t> plaintext) {
    Sealed s;
    s.ciphertext.resize(plaintext.size());
    detail::require(determ_xchacha20_poly1305_encrypt(
                        key.data(), nonce.data(),
                        detail::ptr(aad), aad.size(),
                        detail::ptr(plaintext), plaintext.size(),
                        s.ciphertext.empty() ? nullptr : s.ciphertext.data(),
                        s.tag.data()),
                    "xchacha20_poly1305 seal failed");
    return s;
}
inline std::optional<Bytes> xchacha20_poly1305_open(std::span<const uint8_t, 32> key,
                                                    std::span<const uint8_t, 24> nonce,
                                                    std::span<const uint8_t> aad,
                                                    std::span<const uint8_t> ciphertext,
                                                    std::span<const uint8_t, 16> tag) {
    Bytes pt(ciphertext.size());
    if (determ_xchacha20_poly1305_decrypt(key.data(), nonce.data(),
                                          detail::ptr(aad), aad.size(),
                                          detail::ptr(ciphertext), ciphertext.size(),
                                          tag.data(),
                                          pt.empty() ? nullptr : pt.data()) != 0)
        return std::nullopt;
    return pt;
}

inline Sealed aes256_gcm_seal(std::span<const uint8_t, 32> key,
                              std::span<const uint8_t, 12> iv,
                              std::span<const uint8_t> aad,
                              std::span<const uint8_t> plaintext) {
    Sealed s;
    s.ciphertext.resize(plaintext.size());
    determ_aes256_gcm_encrypt(key.data(), iv.data(),
                              detail::ptr(aad), aad.size(),
                              detail::ptr(plaintext), plaintext.size(),
                              s.ciphertext.empty() ? nullptr : s.ciphertext.data(),
                              s.tag.data());
    return s;
}
inline std::optional<Bytes> aes256_gcm_open(std::span<const uint8_t, 32> key,
                                            std::span<const uint8_t, 12> iv,
                                            std::span<const uint8_t> aad,
                                            std::span<const uint8_t> ciphertext,
                                            std::span<const uint8_t, 16> tag) {
    Bytes pt(ciphertext.size());
    if (determ_aes256_gcm_decrypt(key.data(), iv.data(),
                                  detail::ptr(aad), aad.size(),
                                  detail::ptr(ciphertext), ciphertext.size(),
                                  tag.data(),
                                  pt.empty() ? nullptr : pt.data()) != 0)
        return std::nullopt;
    return pt;
}

// ─── Ed25519 ────────────────────────────────────────────────────────────────

namespace ed25519 {
using Seed      = std::array<uint8_t, 32>;
using PublicKey = std::array<uint8_t, 32>;
using Signature = std::array<uint8_t, 64>;

inline PublicKey public_key(const Seed& seed) {
    PublicKey pk;
    determ_ed25519_pubkey_from_seed(seed.data(), pk.data());
    return pk;
}
inline Signature sign(const Seed& seed, const PublicKey& pk,
                      std::span<const uint8_t> msg) {
    Signature sig;
    detail::require(determ_ed25519_sign(seed.data(), pk.data(),
                                        detail::ptr(msg), msg.size(), sig.data()),
                    "ed25519 sign failed (allocation)");
    return sig;
}
// false on ANY rejection: bad sig, non-canonical y/S, off-curve pubkey.
inline bool verify(const PublicKey& pk, std::span<const uint8_t> msg,
                   const Signature& sig) {
    return determ_ed25519_verify(pk.data(), detail::ptr(msg), msg.size(),
                                 sig.data()) == 0;
}
} // namespace ed25519

// ─── X25519 ─────────────────────────────────────────────────────────────────

namespace x25519 {
using Scalar = std::array<uint8_t, 32>;
using Point  = std::array<uint8_t, 32>;

inline Point public_key(const Scalar& scalar) {
    Point out;
    // Never low-order for a clamped scalar times the base point.
    detail::require(determ_x25519_base(out.data(), scalar.data()),
                    "x25519 base mult failed");
    return out;
}
// nullopt iff the result is the all-zero low-order output (RFC 7748
// contributory check) — a NORMAL adversarial-peer outcome.
inline std::optional<Point> dh(const Scalar& scalar, const Point& peer) {
    Point out;
    if (determ_x25519(out.data(), scalar.data(), peer.data()) != 0)
        return std::nullopt;
    return out;
}
} // namespace x25519

// ─── Constant-time / hygiene (§3.10) ────────────────────────────────────────

// Constant-time equality; use for every secret-adjacent compare.
inline bool ct_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;   // lengths are public by contract
    return determ_ct_memcmp(detail::ptr(a), detail::ptr(b), a.size()) == 0;
}
inline void secure_zero(std::span<uint8_t> buf) {
    determ_secure_zero(buf.empty() ? nullptr : buf.data(), buf.size());
}

} // namespace determ::c99

#endif // DETERM_CRYPTO_HPP
