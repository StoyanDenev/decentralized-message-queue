// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light CTX-2 confidential on/off-ramp builders — see ct_tx.hpp. The
// 98-byte payload (C(33) || balance_proof(65)) + the signing_bytes layout match
// the consensus accept-rule (src/node/validator.cpp SHIELD/UNSHIELD cases +
// src/chain/chain.cpp apply) byte-for-byte, so a validator accepts exactly what
// this builds.

#include "ct_tx.hpp"
#include <determ/crypto/keys.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/pedersen/pedersen.h>
#include <determ/crypto/pedersen/balance.h>
#include <determ/crypto/pedersen/rangeproof.h>
#include <determ/crypto/pedersen/ctxbundle.h>
#include <determ/crypto/p256/p256.h>
#include <determ/chain/shielded.hpp>   // unshield_spend_ctx_hash (inline)
#include <determ/types.hpp>

#include <array>
#include <cstring>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;

namespace {

// TxType wire values — MUST match include/determ/chain/block.hpp.
constexpr int TX_SHIELD   = 12;
constexpr int TX_UNSHIELD = 13;
constexpr int TX_CONFIDENTIAL_TRANSFER = 14;

// DCT1 range-proof bit width. n=64 covers all u64 amounts; m*n <= 256 caps m<=4.
constexpr std::size_t CT_RANGE_BITS = 64;

// A canonical scalar < n from (dst, seed || u32_be(index)) — for the per-index
// Bulletproof randomness vectors (sL, sR).
std::array<uint8_t, 32> derive_scalar_i(const char* dst,
                                        const std::vector<uint8_t>& seed,
                                        uint32_t i) {
    std::vector<uint8_t> msg = seed;
    msg.push_back(static_cast<uint8_t>(i >> 24)); msg.push_back(static_cast<uint8_t>(i >> 16));
    msg.push_back(static_cast<uint8_t>(i >> 8));  msg.push_back(static_cast<uint8_t>(i));
    std::array<uint8_t, 32> out{};
    if (determ_p256_hash_to_scalar(out.data(), msg.data(), msg.size(),
            reinterpret_cast<const uint8_t*>(dst), std::strlen(dst)) != 0)
        throw std::runtime_error("ct: hash_to_scalar failed");
    return out;
}

// Canonical signing_bytes (== Transaction::signing_bytes; same layout the light
// sign_tx / audit_tx paths reconstruct):
//   u8(type) || from || 0x00 || to || 0x00 || u64_be(amount) || u64_be(fee)
//            || u64_be(nonce) || payload
std::vector<uint8_t> ct_signing_bytes(int type, const std::string& from,
                                      const std::string& to, uint64_t amount,
                                      uint64_t fee, uint64_t nonce,
                                      const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(1 + from.size() + to.size() + 2 + 24 + payload.size());
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), from.begin(), from.end()); out.push_back(0);
    out.insert(out.end(), to.begin(),   to.end());   out.push_back(0);
    auto be64 = [&](uint64_t v){ for (int i = 7; i >= 0; --i) out.push_back((v >> (i*8)) & 0xFF); };
    be64(amount); be64(fee); be64(nonce);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// 32-byte big-endian encoding of a u64 — a valid scalar < n (top 24 bytes zero).
std::array<uint8_t, 32> u64_scalar(uint64_t a) {
    std::array<uint8_t, 32> s{};
    for (int i = 0; i < 8; ++i) s[31 - i] = static_cast<uint8_t>((a >> (i*8)) & 0xFF);
    return s;
}

// A canonical scalar < n from (dst, msg) via P256 hash_to_scalar (RFC 9380/9497).
std::array<uint8_t, 32> derive_scalar(const char* dst, const std::vector<uint8_t>& msg) {
    std::array<uint8_t, 32> out{};
    if (determ_p256_hash_to_scalar(out.data(), msg.data(), msg.size(),
            reinterpret_cast<const uint8_t*>(dst), std::strlen(dst)) != 0)
        throw std::runtime_error("ct: hash_to_scalar failed");
    return out;
}

// Build the 98-byte payload C(33) || balance_proof(65). ctx32==nullptr → SHIELD
// (unbound proof); ctx32!=nullptr → UNSHIELD (bound to the spend context).
std::vector<uint8_t> ct_payload(uint64_t amount,
                                const std::vector<uint8_t>& blind_seed,
                                const char* nonce_dst, const uint8_t* ctx32) {
    // The note's confidentiality rests ENTIRELY on the blinding r, which is
    // derived from `blind_seed`. A reused or low-entropy seed defeats amount
    // hiding (adversarial review inc.CTX-2, MEDIUM): reusing a seed for two
    // notes gives the same r, so C1-C2 = (v1-v2)*G leaks the amount difference,
    // and a guessable seed lets an observer recompute v*G = C - r*H. Enforce a
    // high-entropy floor here; the caller is responsible for UNIQUENESS.
    if (blind_seed.size() < 32)
        throw std::runtime_error("ct: --blind-seed must be >= 32 bytes (64 hex) of "
                                 "high-entropy randomness, UNIQUE per note");
    // r = the note blinding, derived from the caller's seed (always valid,
    // nonzero w.h.p. — pedersen_commit rejects r==0 if the 2^-256 case hits).
    auto r = derive_scalar("determ-ct-note-blind-v1", blind_seed);
    auto v = u64_scalar(amount);
    std::array<uint8_t, 33> C{};
    if (determ_pedersen_commit(C.data(), v.data(), r.data()) != 0)
        throw std::runtime_error("ct: pedersen_commit failed (invalid blinding)");
    // E = C - amount*G (= r*H): one input commitment, no outputs, fee = amount —
    // exactly the excess determ_shield_verify/unshield_verify recompute. NOTE:
    // E is INDEPENDENT of the amount (E = r*H), so k below is a function of
    // (r [, ctx]) only, not of the amount.
    std::array<uint8_t, 33> E{};
    if (determ_p256_balance_excess(E.data(), C.data(), 1, nullptr, 0, amount) != 0)
        throw std::runtime_error("ct: balance excess failed (degenerate commitment)");
    // Deterministic Schnorr nonce k = hash_to_scalar(dst || r || E [|| ctx]).
    // Nonce-safety: a reuse leak needs the SAME k with a DIFFERENT Fiat-Shamir
    // challenge c. Here c is the IDENTICAL function of the same inputs — for
    // SHIELD c = H(E||T) depends only on r (so same k forces same c, i.e. the
    // same proof, no independent equation); for UNSHIELD ctx enters BOTH k's
    // preimage AND c, so any (from,to,nonce,amount) change flips k and c
    // together. Cross-type SHIELD/UNSHIELD use distinct `nonce_dst`. Hence no
    // same-k/different-c pair exists (collision 2^-256).
    std::vector<uint8_t> kmsg(r.begin(), r.end());
    kmsg.insert(kmsg.end(), E.begin(), E.end());
    if (ctx32) kmsg.insert(kmsg.end(), ctx32, ctx32 + 32);
    auto k = derive_scalar(nonce_dst, kmsg);
    std::array<uint8_t, 65> proof{};
    int rc = ctx32
        ? determ_p256_balance_prove_bound(proof.data(), E.data(), r.data(), k.data(), ctx32)
        : determ_p256_balance_prove(proof.data(), E.data(), r.data(), k.data());
    if (rc != 0) throw std::runtime_error("ct: balance prove failed");
    std::vector<uint8_t> payload;
    payload.reserve(98);
    payload.insert(payload.end(), C.begin(), C.end());
    payload.insert(payload.end(), proof.begin(), proof.end());
    return payload;   // 33 + 65 == 98
}

json sign_ct_tx(const LightKeyfile& kf, int type, const std::string& to,
                uint64_t amount, uint64_t fee, uint64_t nonce,
                const std::vector<uint8_t>& payload, const char* type_name) {
    auto sb = ct_signing_bytes(type, kf.anon_address, to, amount, fee, nonce, payload);
    Signature sig = determ::crypto::sign(kf.key, sb.data(), sb.size());
    Hash tx_hash  = determ::crypto::sha256(sb.data(), sb.size());
    return json{
        {"type",      type},
        {"type_name", type_name},
        {"from",      kf.anon_address},
        {"to",        to},
        {"amount",    amount},
        {"fee",       fee},
        {"nonce",     nonce},
        {"payload",   to_hex(payload.data(), payload.size())},
        {"signature", to_hex(sig)},
        {"sig",       to_hex(sig)},
        {"hash",      to_hex(tx_hash)},
    };
}

} // namespace

json build_shield_tx(const LightKeyfile& kf, uint64_t amount,
                     const std::vector<uint8_t>& blind_seed,
                     uint64_t fee, uint64_t nonce) {
    if (amount == 0) throw std::runtime_error("shield: --amount must be > 0");
    auto payload = ct_payload(amount, blind_seed, "determ-ct-shield-nonce-v1", nullptr);
    // SHIELD has no recipient: the note is the sender's own (to == "").
    return sign_ct_tx(kf, TX_SHIELD, "", amount, fee, nonce, payload, "SHIELD");
}

json build_unshield_tx(const LightKeyfile& kf, uint64_t amount,
                       const std::vector<uint8_t>& blind_seed,
                       const std::string& to, uint64_t fee, uint64_t nonce) {
    if (amount == 0)   throw std::runtime_error("unshield: --amount must be > 0");
    if (amount < fee)  throw std::runtime_error("unshield: --amount must cover --fee");
    if (to.empty())    throw std::runtime_error("unshield: --to is required");
    // Bind the balance proof to the spend context (front-running defense): the
    // exact digest the validator recomputes from the tx fields.
    Hash ctx = determ::chain::unshield_spend_ctx_hash(kf.anon_address, to, nonce, amount);
    auto payload = ct_payload(amount, blind_seed, "determ-ct-unshield-nonce-v1", ctx.data());
    return sign_ct_tx(kf, TX_UNSHIELD, to, amount, fee, nonce, payload, "UNSHIELD");
}

json build_confidential_transfer_tx(const LightKeyfile& kf,
                                    const std::vector<CtNote>& inputs,
                                    const std::vector<CtNote>& outputs,
                                    uint64_t fee,
                                    const std::vector<uint8_t>& nonce_seed,
                                    uint64_t tx_nonce) {
    const std::size_t n_in = inputs.size(), m = outputs.size();
    const std::size_t n = CT_RANGE_BITS;
    if (n_in < 1)   throw std::runtime_error("ct-transfer: at least one input note is required");
    if (n_in > 255) throw std::runtime_error("ct-transfer: at most 255 input notes (the DCT1 header count is a u8)");
    // m*n must be a POWER OF TWO <= 256 for the aggregated IPA — with n=64 that
    // is m in {1,2,4} (m=3 -> 192 is not a power of two). Reject m=3 up front with
    // a clear message rather than a misleading "bad (m,n)" from the range proof.
    if (m != 1 && m != 2 && m != 4)
        throw std::runtime_error("ct-transfer: outputs must be 1, 2, or 4 (m*64 must be a power of two "
                                 "<= 256; to split into 3, pad to 4 with a 0-value note)");
    if (nonce_seed.size() < 32)
        throw std::runtime_error("ct-transfer: --nonce-seed must be >= 32 bytes of high-entropy randomness, "
                                 "UNIQUE per transfer (reuse voids the range-proof zero-knowledge AND reuses "
                                 "the balance Schnorr nonce, leaking + linking amounts)");

    // Balance MUST hold (else the balance proof cannot verify): Σv_in = Σv_out + fee.
    uint64_t sum_in = 0, sum_out = 0;
    for (auto& x : inputs)  { if (sum_in  > UINT64_MAX - x.value) throw std::runtime_error("ct-transfer: input value sum overflow");  sum_in  += x.value; }
    for (auto& x : outputs) { if (sum_out > UINT64_MAX - x.value) throw std::runtime_error("ct-transfer: output value sum overflow"); sum_out += x.value; }
    if (sum_out > UINT64_MAX - fee || sum_in != sum_out + fee)
        throw std::runtime_error("ct-transfer: unbalanced (Σ inputs must equal Σ outputs + fee)");

    // Note blindings — SAME DST as build-shield, so a shielded note spends here.
    std::vector<std::array<uint8_t,32>> r_in(n_in), r_out(m);
    for (std::size_t j = 0; j < n_in; ++j) {
        if (inputs[j].blind_seed.size() < 32) throw std::runtime_error("ct-transfer: an input blind-seed is < 32 bytes");
        r_in[j] = derive_scalar("determ-ct-note-blind-v1", inputs[j].blind_seed);
    }
    for (std::size_t j = 0; j < m; ++j) {
        if (outputs[j].blind_seed.size() < 32) throw std::runtime_error("ct-transfer: an output blind-seed is < 32 bytes");
        r_out[j] = derive_scalar("determ-ct-note-blind-v1", outputs[j].blind_seed);
    }

    // Input commitments C_in = commit(v_in, r_in).
    std::vector<uint8_t> C_in(n_in * 33);
    for (std::size_t j = 0; j < n_in; ++j) {
        auto v = u64_scalar(inputs[j].value);
        if (determ_pedersen_commit(&C_in[j*33], v.data(), r_in[j].data()) != 0)
            throw std::runtime_error("ct-transfer: input commitment failed (invalid blinding)");
    }

    // ONE aggregated range proof over the m outputs; gammas = r_out so the proof's
    // value commitments V == the output commitments C_out (composition identity).
    std::vector<uint64_t> vals(m);
    std::vector<uint8_t>  gammas(m * 32);
    for (std::size_t j = 0; j < m; ++j) {
        vals[j] = outputs[j].value;
        std::memcpy(&gammas[j*32], r_out[j].data(), 32);
    }
    // Bind the Bulletproof + Schnorr randomness to THIS tx (defense-in-depth vs
    // accidental nonce_seed reuse across transfers): the effective seed mixes the
    // caller seed with the tx nonce, so two transfers that (mistakenly) reuse the
    // same nonce_seed but carry different nonces still get distinct proof nonces.
    std::vector<uint8_t> eff_seed = nonce_seed;
    for (int i = 7; i >= 0; --i) eff_seed.push_back(static_cast<uint8_t>((tx_nonce >> (i*8)) & 0xFF));
    auto alpha = derive_scalar("determ-ct-bp-alpha", eff_seed);
    auto rho   = derive_scalar("determ-ct-bp-rho",   eff_seed);
    auto tau1  = derive_scalar("determ-ct-bp-tau1",  eff_seed);
    auto tau2  = derive_scalar("determ-ct-bp-tau2",  eff_seed);
    std::vector<uint8_t> sL(m * n * 32), sR(m * n * 32);
    for (std::size_t i = 0; i < m * n; ++i) {
        auto l = derive_scalar_i("determ-ct-bp-sL", eff_seed, static_cast<uint32_t>(i));
        auto r = derive_scalar_i("determ-ct-bp-sR", eff_seed, static_cast<uint32_t>(i));
        std::memcpy(&sL[i*32], l.data(), 32);
        std::memcpy(&sR[i*32], r.data(), 32);
    }
    std::size_t agglen = determ_agg_rangeproof_proof_len(m, n);
    if (agglen == 0) throw std::runtime_error("ct-transfer: bad (m,n) for the range proof");
    std::vector<uint8_t> C_out(m * 33), agg(agglen);
    if (determ_agg_rangeproof_prove(C_out.data(), agg.data(), vals.data(), gammas.data(),
            alpha.data(), rho.data(), tau1.data(), tau2.data(),
            sL.data(), sR.data(), m, n) != 0)
        throw std::runtime_error("ct-transfer: aggregated range proof failed");

    // Balance proof: E = ΣC_in − ΣC_out − fee·G ; x = (Σr_in − Σr_out) mod n.
    std::vector<uint8_t> rin_flat(n_in * 32), rout_flat(m * 32);
    for (std::size_t j = 0; j < n_in; ++j) std::memcpy(&rin_flat[j*32],  r_in[j].data(),  32);
    for (std::size_t j = 0; j < m;    ++j) std::memcpy(&rout_flat[j*32], r_out[j].data(), 32);
    std::array<uint8_t,32> x{};
    int xr = determ_p256_balance_blinding_excess(x.data(), rin_flat.data(), n_in, rout_flat.data(), m);
    if (xr == 1) throw std::runtime_error("ct-transfer: zero blinding excess (pick different seeds)");
    if (xr != 0) throw std::runtime_error("ct-transfer: blinding excess computation failed");
    std::array<uint8_t,33> E{};
    if (determ_p256_balance_excess(E.data(), C_in.data(), n_in, C_out.data(), m, fee) != 0)
        throw std::runtime_error("ct-transfer: balance excess point failed");
    auto k = derive_scalar("determ-ct-bp-balk", eff_seed);
    std::array<uint8_t,65> bproof{};
    if (determ_p256_balance_prove(bproof.data(), E.data(), x.data(), k.data()) != 0)
        throw std::runtime_error("ct-transfer: balance proof failed");

    // Serialize the DCT1 bundle + SELF-VERIFY before emit (never ship an invalid one).
    std::size_t blen = determ_ctx_bundle_len(n_in, m, n);
    if (blen == 0) throw std::runtime_error("ct-transfer: bad bundle parameters");
    std::vector<uint8_t> bundle(blen);
    if (determ_ctx_bundle_serialize(bundle.data(), blen, C_in.data(), n_in,
            C_out.data(), m, n, fee, agg.data(), bproof.data()) != 0)
        throw std::runtime_error("ct-transfer: bundle serialize failed");
    if (determ_ctx_bundle_verify(bundle.data(), blen) != 0)
        throw std::runtime_error("ct-transfer: built bundle failed self-verify (internal error)");

    // Pool -> pool: to="" and amount=0 (both ignored by the validator/apply); the
    // PUBLIC fee must equal the bundle's fee (validator enforces tx.fee==bundle_fee).
    return sign_ct_tx(kf, TX_CONFIDENTIAL_TRANSFER, "", 0, fee, tx_nonce, bundle,
                      "CONFIDENTIAL_TRANSFER");
}

} // namespace determ::light
