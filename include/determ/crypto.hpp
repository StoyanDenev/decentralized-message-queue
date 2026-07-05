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
#include <cstring>
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

// ─── NIST P-256 (§3.8c) + RFC 9497 OPRF-P256 (§3.9b) ───────────────────────
// Wire shapes per the C layer: scalars 32B BIG-endian; points SEC1
// uncompressed (65B, 0x04||X||Y) or compressed (33B — the OPRF element size).
// nullopt = a NORMAL adversarial-input outcome (peer-supplied point fails
// decode / infinity / DLEQ reject); throw = caller bug (invalid own scalar).

namespace p256 {
using Scalar          = std::array<uint8_t, 32>;
using Point           = std::array<uint8_t, 65>;
using CompressedPoint = std::array<uint8_t, 33>;

namespace detail2 {
// Cheap public validity check (nonzero && < n) so the wrappers can separate
// "caller bug: invalid own scalar" (throw) from "adversarial peer input"
// (nullopt) — the C layer returns one -1 for both. Public data only.
inline bool scalar_valid(const Scalar& s) {
    uint8_t pb[32], nb[32], bb[32], gx[32], gy[32];
    determ_p256_params(pb, nb, bb, gx, gy);
    bool nonzero = false;
    for (auto b : s) if (b) { nonzero = true; break; }
    return nonzero && std::memcmp(s.data(), nb, 32) < 0;
}
} // namespace detail2

inline Point base_mul(const Scalar& scalar) {
    Point out;
    detail::require(determ_p256_base_mul(out.data(), scalar.data()),
                    "p256 base_mul: invalid scalar (zero or >= n)");
    return out;
}
// ECDH core: nullopt on a bad peer point / infinity (adversarial-peer
// outcome); throws only on an invalid OWN scalar.
inline std::optional<Point> point_mul(const Scalar& scalar, const Point& peer) {
    if (!detail2::scalar_valid(scalar))
        throw std::runtime_error("determ::c99: p256 point_mul: invalid scalar");
    Point out;
    if (determ_p256_point_mul(out.data(), scalar.data(), peer.data()) != 0)
        return std::nullopt;   // bad peer point or infinity result
    return out;
}
inline bool point_check(const Point& pt) {
    return determ_p256_point_check(pt.data()) == 0;
}
inline std::optional<Point> add(const Point& a, const Point& b) {
    Point out;   // nullopt: bad encoding or P + (-P) = infinity
    if (determ_p256_point_add(out.data(), a.data(), b.data()) != 0)
        return std::nullopt;
    return out;
}
inline std::optional<CompressedPoint> compress(const Point& pt) {
    CompressedPoint out;
    if (determ_p256_point_compress(out.data(), pt.data()) != 0)
        return std::nullopt;
    return out;
}
inline std::optional<Point> decompress(const CompressedPoint& pt) {
    Point out;   // nullopt: bad prefix / x >= p / non-square RHS
    if (determ_p256_point_decompress(out.data(), pt.data()) != 0)
        return std::nullopt;
    return out;
}
inline Scalar scalar_mul_mod_n(const Scalar& a, const Scalar& b) {
    Scalar r;
    detail::require(determ_p256_scalar_mul_mod_n(r.data(), a.data(), b.data()),
                    "p256 scalar_mul_mod_n: operand >= n");
    return r;
}
inline Scalar scalar_inv_mod_n(const Scalar& a) {
    Scalar r;
    detail::require(determ_p256_scalar_inv_mod_n(r.data(), a.data()),
                    "p256 scalar_inv_mod_n: a == 0 or a >= n");
    return r;
}
inline Point hash_to_curve(std::span<const uint8_t> msg,
                           std::span<const uint8_t> dst) {
    Point out;
    detail::require(determ_p256_hash_to_curve(out.data(),
                                              detail::ptr(msg), msg.size(),
                                              detail::ptr(dst), dst.size()),
                    "p256 hash_to_curve: DST/length bounds");
    return out;
}
inline Scalar hash_to_scalar(std::span<const uint8_t> msg,
                             std::span<const uint8_t> dst) {
    Scalar out;
    detail::require(determ_p256_hash_to_scalar(out.data(),
                                               detail::ptr(msg), msg.size(),
                                               detail::ptr(dst), dst.size()),
                    "p256 hash_to_scalar: DST/length bounds");
    return out;
}
} // namespace p256

namespace oprf_p256 {
using p256::Scalar;
using p256::CompressedPoint;
using Proof = std::array<uint8_t, 64>;      // SerializeScalar(c) || (s)
constexpr uint8_t MODE_OPRF  = 0x00;
constexpr uint8_t MODE_VOPRF = 0x01;

inline Scalar derive_key(std::span<const uint8_t> seed,
                         std::span<const uint8_t> info, uint8_t mode) {
    Scalar sk;
    detail::require(determ_p256_oprf_derive_key(sk.data(),
                                                detail::ptr(seed), seed.size(),
                                                detail::ptr(info), info.size(),
                                                mode),
                    "oprf_p256 derive_key failed");
    return sk;
}
inline CompressedPoint blind(std::span<const uint8_t> input,
                             const Scalar& blind_scalar, uint8_t mode) {
    CompressedPoint out;
    detail::require(determ_p256_oprf_blind(out.data(),
                                           detail::ptr(input), input.size(),
                                           blind_scalar.data(), mode),
                    "oprf_p256 blind: invalid blind (zero or >= n)");
    return out;
}
// Server side: nullopt on a malformed client element (adversarial input);
// throws on an invalid OWN key.
inline std::optional<CompressedPoint> evaluate(const Scalar& sk,
                                               const CompressedPoint& blinded) {
    if (!p256::detail2::scalar_valid(sk))
        throw std::runtime_error("determ::c99: oprf_p256 evaluate: invalid sk");
    CompressedPoint out;
    if (determ_p256_oprf_evaluate(out.data(), sk.data(), blinded.data()) != 0)
        return std::nullopt;   // malformed client element
    return out;
}
// Client side: nullopt on a malformed server evaluation (adversarial input).
// For VOPRF run verify() FIRST — finalize does not verify.
inline std::optional<std::array<uint8_t, 32>> finalize(
        std::span<const uint8_t> input,
        const Scalar& blind_scalar,
        const CompressedPoint& eval) {
    std::array<uint8_t, 32> out;
    if (determ_p256_oprf_finalize(out.data(),
                                  detail::ptr(input), input.size(),
                                  blind_scalar.data(), eval.data()) != 0)
        return std::nullopt;
    return out;
}
inline Proof prove(const Scalar& sk, const CompressedPoint& pk,
                   const CompressedPoint& blinded, const CompressedPoint& eval,
                   const Scalar& r, uint8_t mode) {
    Proof proof;
    detail::require(determ_p256_voprf_prove(proof.data(), sk.data(), pk.data(),
                                            blinded.data(), eval.data(),
                                            r.data(), mode),
                    "oprf_p256 prove: invalid scalar/element");
    return proof;
}
inline bool verify(const CompressedPoint& pk, const CompressedPoint& blinded,
                   const CompressedPoint& eval, const Proof& proof,
                   uint8_t mode) {
    return determ_p256_voprf_verify(pk.data(), blinded.data(), eval.data(),
                                    proof.data(), mode) == 0;
}
} // namespace oprf_p256

// ─── ML-DSA / Dilithium (FIPS 204) signatures (§3.18) ───────────────────────
// The complete PQ signature scheme — KeyGen + Sign + Verify, ACVP-pinned. A
// LIBRARY PRIMITIVE; chain integration (a PQ signature option) is separately gated.
namespace mldsa {

enum class ParamSet { ML_DSA_44, ML_DSA_65, ML_DSA_87 };

inline const determ_mldsa_params& params(ParamSet ps) {
    switch (ps) {
        case ParamSet::ML_DSA_65: return DETERM_MLDSA_65;
        case ParamSet::ML_DSA_87: return DETERM_MLDSA_87;
        default:                  return DETERM_MLDSA_44;
    }
}
inline size_t pk_bytes(ParamSet ps)  { return determ_mldsa_pk_bytes(&params(ps)); }
inline size_t sk_bytes(ParamSet ps)  { return determ_mldsa_sk_bytes(&params(ps)); }
inline size_t sig_bytes(ParamSet ps) { return determ_mldsa_sig_bytes(&params(ps)); }

struct KeyPair { Bytes pk; Bytes sk; };

// KeyGen_internal(seed): deterministic in the 32-byte seed ξ.
inline KeyPair keygen(ParamSet ps, std::span<const uint8_t, 32> seed) {
    const auto& p = params(ps);
    KeyPair kp;
    kp.pk.resize(determ_mldsa_pk_bytes(&p));
    kp.sk.resize(determ_mldsa_sk_bytes(&p));
    determ_mldsa_keygen(&p, seed.data(), kp.pk.data(), kp.sk.data());
    return kp;
}

// M' for the pure external interface: 0x00 | len(ctx) | ctx | M (ctx <= 255 bytes).
inline Bytes format_message(std::span<const uint8_t> ctx, std::span<const uint8_t> msg) {
    Bytes out(2 + ctx.size() + msg.size());
    size_t n = determ_mldsa_format_message(out.data(), detail::ptr(ctx), ctx.size(),
                                           detail::ptr(msg), msg.size());
    if (n == 0) throw std::runtime_error("determ::c99: mldsa context too long (> 255 bytes)");
    out.resize(n);
    return out;
}

// Sign_internal(sk, M'): deterministic by default (rnd = 32 zero bytes); pass a
// 32-byte rnd for the hedged variant. `mprime` is the already-formatted message.
inline Bytes sign(ParamSet ps, std::span<const uint8_t> sk, std::span<const uint8_t> mprime,
                  std::optional<std::span<const uint8_t, 32>> rnd = std::nullopt) {
    const auto& p = params(ps);
    static const std::array<uint8_t, 32> ZERO{};
    const uint8_t* r = rnd ? rnd->data() : ZERO.data();
    Bytes sig(determ_mldsa_sig_bytes(&p));
    // require() throws when rc != 0; determ_mldsa_sign returns 0 on success, so
    // pass the raw rc (NOT `rc == 0`, which would be 1/true on success and throw).
    detail::require(determ_mldsa_sign(&p, detail::ptr(sk), detail::ptr(mprime), mprime.size(),
                                      r, sig.data()),
                    "mldsa sign failed (bad params / rejection cap)");
    return sig;
}

// Verify_internal(pk, M', sig): memory-safe on any sig (wrong length -> false).
inline bool verify(ParamSet ps, std::span<const uint8_t> pk, std::span<const uint8_t> mprime,
                   std::span<const uint8_t> sig) {
    const auto& p = params(ps);
    return determ_mldsa_verify(&p, detail::ptr(pk), detail::ptr(mprime), mprime.size(),
                               detail::ptr(sig), sig.size()) == 1;
}
} // namespace mldsa

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
