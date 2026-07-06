// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/pqauth.hpp>
#include <determ/crypto.hpp>              // determ::c99 (ed25519 + mldsa wrappers)
#include <determ/crypto/secure_zero.h>   // determ_secure_zero
#include <cstring>
#include <stdexcept>

namespace determ::pqauth {
namespace {

// ─── DPQ1 envelope format (v1) ───────────────────────────────────────────────
//   MAGIC(4)="DPQ1" | scheme(1) | pq_pk_len(2 BE) | pq_pk | pq_sig_len(2 BE) |
//   pq_sig | [ ed_pk(32) | ed_sig(64) ]   (the ed_* tail iff scheme & 0x10)
//
// pq_sig covers M' = 0x00 | len(CTX) | CTX | message (the ML-DSA "external"
// interface, domain-separated by CTX). ed_sig covers the RAW message, so a
// hybrid tx's Ed25519 half is verifiable by the chain's existing Ed25519 path.
constexpr uint8_t MAGIC[4] = {'D', 'P', 'Q', '1'};
constexpr char    CTX[]    = "determ-pqtx-v1";
constexpr size_t  CTXLEN   = sizeof(CTX) - 1;   // 14

using determ::c99::mldsa::ParamSet;

bool is_hybrid(uint8_t s) { return (s & 0x10) != 0; }

// scheme byte -> ML-DSA parameter set (by low nibble). false if the low nibble
// is not one of {1,2,3}.
bool scheme_paramset(uint8_t s, ParamSet& ps) {
    switch (s & 0x0f) {
        case 0x01: ps = ParamSet::ML_DSA_44; return true;
        case 0x02: ps = ParamSet::ML_DSA_65; return true;
        case 0x03: ps = ParamSet::ML_DSA_87; return true;
    }
    return false;
}

// Exactly {0x01,0x02,0x03,0x11,0x12,0x13} are valid: low nibble in {1,2,3} and
// the only high-nibble bit permitted is 0x10 (hybrid).
bool scheme_valid(uint8_t s) {
    ParamSet ps;
    if (!scheme_paramset(s, ps)) return false;
    return (s & 0xE0) == 0 && ((s & 0xF0) == 0x00 || (s & 0xF0) == 0x10);
}

std::vector<uint8_t> format_mprime(std::span<const uint8_t> message) {
    std::vector<uint8_t> mp;
    mp.reserve(2 + CTXLEN + message.size());
    mp.push_back(0x00);
    mp.push_back(static_cast<uint8_t>(CTXLEN));
    mp.insert(mp.end(), CTX, CTX + CTXLEN);
    mp.insert(mp.end(), message.begin(), message.end());
    return mp;
}

} // namespace

std::span<const uint8_t> context() noexcept {
    return {reinterpret_cast<const uint8_t*>(CTX), CTXLEN};
}

std::vector<uint8_t> sign(Scheme scheme_e, std::span<const uint8_t> message,
                          std::span<const uint8_t, 32> mldsa_seed,
                          std::optional<std::span<const uint8_t, 32>> ed_seed) {
    const uint8_t scheme = static_cast<uint8_t>(scheme_e);
    ParamSet ps;
    if (!scheme_valid(scheme) || !scheme_paramset(scheme, ps))
        throw std::invalid_argument("pqauth::sign: invalid scheme");
    const bool hybrid = is_hybrid(scheme);
    if (hybrid && !ed_seed)
        throw std::invalid_argument("pqauth::sign: hybrid scheme requires ed_seed");

    auto kp     = determ::c99::mldsa::keygen(ps, mldsa_seed);          // (pk, sk)
    auto mp     = format_mprime(message);
    auto pq_sig = determ::c99::mldsa::sign(ps, kp.sk, mp);            // deterministic
    determ_secure_zero(kp.sk.data(), kp.sk.size());                   // sk is secret

    std::vector<uint8_t> env;
    env.reserve(7 + kp.pk.size() + pq_sig.size() + (hybrid ? 96u : 0u));
    env.insert(env.end(), MAGIC, MAGIC + 4);
    env.push_back(scheme);
    env.push_back(static_cast<uint8_t>((kp.pk.size() >> 8) & 0xff));
    env.push_back(static_cast<uint8_t>(kp.pk.size() & 0xff));
    env.insert(env.end(), kp.pk.begin(), kp.pk.end());
    env.push_back(static_cast<uint8_t>((pq_sig.size() >> 8) & 0xff));
    env.push_back(static_cast<uint8_t>(pq_sig.size() & 0xff));
    env.insert(env.end(), pq_sig.begin(), pq_sig.end());
    if (hybrid) {
        std::array<uint8_t, 32> es{};
        std::copy(ed_seed->begin(), ed_seed->end(), es.begin());
        auto ed_pk  = determ::c99::ed25519::public_key(es);
        auto ed_sig = determ::c99::ed25519::sign(es, ed_pk, message);
        env.insert(env.end(), ed_pk.begin(), ed_pk.end());
        env.insert(env.end(), ed_sig.begin(), ed_sig.end());
        determ_secure_zero(es.data(), es.size());
    }
    return env;
}

VerifyResult verify(std::span<const uint8_t> env, std::span<const uint8_t> message) noexcept {
    VerifyResult r;
    try {
        size_t off = 0;
        auto need = [&](size_t n) -> bool { return off + n <= env.size(); };

        if (!need(4) || std::memcmp(env.data(), MAGIC, 4) != 0) return r;
        off += 4;
        if (!need(1)) return r;
        const uint8_t scheme = env[off++];
        if (!scheme_valid(scheme)) return r;
        ParamSet ps;
        scheme_paramset(scheme, ps);
        const bool   hybrid  = is_hybrid(scheme);
        const size_t exp_pk  = determ::c99::mldsa::pk_bytes(ps);
        const size_t exp_sig = determ::c99::mldsa::sig_bytes(ps);

        if (!need(2)) return r;
        const size_t pk_len = (static_cast<size_t>(env[off]) << 8) | env[off + 1];
        off += 2;
        if (pk_len != exp_pk || !need(pk_len)) return r;   // length must match the scheme
        std::vector<uint8_t> pq_pk(env.begin() + off, env.begin() + off + pk_len);
        off += pk_len;

        if (!need(2)) return r;
        const size_t sig_len = (static_cast<size_t>(env[off]) << 8) | env[off + 1];
        off += 2;
        if (sig_len != exp_sig || !need(sig_len)) return r;
        const std::span<const uint8_t> pq_sig = env.subspan(off, sig_len);
        off += sig_len;

        std::array<uint8_t, 32> ed_pk{};
        std::array<uint8_t, 64> ed_sig{};
        if (hybrid) {
            if (!need(96)) return r;
            std::copy(env.begin() + off, env.begin() + off + 32, ed_pk.begin());
            off += 32;
            std::copy(env.begin() + off, env.begin() + off + 64, ed_sig.begin());
            off += 64;
        }
        if (off != env.size()) return r;                   // strict: no trailing bytes

        const auto mp    = format_mprime(message);
        const bool pq_ok = determ::c99::mldsa::verify(ps, pq_pk, mp, pq_sig);
        bool ed_ok = true;
        if (hybrid) ed_ok = determ::c99::ed25519::verify(ed_pk, message, ed_sig);

        r.scheme = scheme;
        r.hybrid = hybrid;
        r.pq_pk  = std::move(pq_pk);
        r.ok     = pq_ok && ed_ok;
        if (r.ok && hybrid) r.ed_pk.assign(ed_pk.begin(), ed_pk.end());
        return r;
    } catch (...) {
        return VerifyResult{};   // fail closed on anything unexpected
    }
}

} // namespace determ::pqauth
