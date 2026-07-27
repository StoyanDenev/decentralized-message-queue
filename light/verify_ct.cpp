// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// A3 client-side CT verification — see verify_ct.hpp for the contract and
// scope. The accept-rules here MUST stay byte-identical to the validator's
// (src/node/validator.cpp SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER cases) minus
// the note-SET checks a stateless verifier cannot run — the S-043 one-formula
// rule: the context digest comes from the SHARED unshield_spend_ctx_hash
// helper, never a local re-encode.
#include "verify_ct.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/shielded.hpp>
#include <determ/chain/ctx_enote.hpp>   // ctx_split_enotes (NC-8 region split)
#include <determ/crypto/pedersen/ctxbundle.h>

#include <set>

namespace determ::light {

using determ::chain::Transaction;
using determ::chain::TxType;

CtTxVerdict verify_ct_tx_json(const json& tx_json, size_t index) {
    CtTxVerdict v;
    v.index = index;
    Transaction tx;
    try {
        tx = Transaction::from_json(tx_json);
    } catch (const std::exception& e) {
        // Fail-closed: a tx we cannot even parse is a FAILED CT verdict, not a
        // skip — an attacker must never be able to hide a bad proof behind a
        // malformed wrapper.
        v.is_ct = true;
        v.detail = std::string("unparseable transaction: ") + e.what();
        return v;
    }
    v.type = static_cast<int>(tx.type);

    switch (tx.type) {
    case TxType::SHIELD: {
        v.is_ct = true;
        if (tx.payload.size() != 98) {
            v.detail = "SHIELD payload must be 98 bytes (C33||proof65), got "
                     + std::to_string(tx.payload.size());
            return v;
        }
        if (determ_shield_verify(tx.payload.data(), tx.payload.size(),
                                 tx.amount) != 0) {
            v.detail = "SHIELD commitment/balance proof INVALID for declared "
                       "amount " + std::to_string(tx.amount);
            return v;
        }
        v.ok = true;
        v.detail = "SHIELD proof verified (amount " + std::to_string(tx.amount) + ")";
        return v;
    }
    case TxType::UNSHIELD: {
        v.is_ct = true;
        if (tx.payload.size() != 98) {
            v.detail = "UNSHIELD payload must be 98 bytes (C33||proof65), got "
                     + std::to_string(tx.payload.size());
            return v;
        }
        if (tx.amount < tx.fee) {
            v.detail = "UNSHIELD amount does not cover the fee";
            return v;
        }
        // The context-bind IS the front-running defense — rebuild it locally
        // from the tx's own fields, never trust a carried digest.
        Hash ctx = determ::chain::unshield_spend_ctx_hash(tx.from, tx.to,
                                                          tx.nonce, tx.amount);
        if (determ_unshield_verify(tx.payload.data(), tx.payload.size(),
                                   tx.amount, ctx.data()) != 0) {
            v.detail = "UNSHIELD context-bound proof INVALID for this "
                       "(from,to,nonce,amount)";
            return v;
        }
        v.ok = true;
        v.detail = "UNSHIELD context-bound proof verified (amount "
                 + std::to_string(tx.amount) + ")";
        return v;
    }
    case TxType::CONFIDENTIAL_TRANSFER: {
        v.is_ct = true;
        // NC-8 §5: split off the OPTIONAL trailing per-output enote region BEFORE
        // the frozen bundle verifiers (which demand an EXACT length). Mirrors the
        // node validator + chain apply (determ::chain::ctx_split_enotes): STRUCTURE
        // only, ciphertext never inspected. Absent region -> bundle_len ==
        // payload.size() (byte-identical to pre-NC-8). WITHOUT this, an enote-bearing
        // CONFIDENTIAL_TRANSFER the node ACCEPTS is falsely reported FAILED.
        size_t bundle_len = 0;
        if (determ::chain::ctx_split_enotes(tx.payload.data(), tx.payload.size(),
                                            &bundle_len, nullptr) != 0) {
            v.detail = "CONFIDENTIAL_TRANSFER malformed DCT1 bundle or enote region";
            return v;
        }
        size_t n_in = 0, m = 0, nbits = 0;
        uint64_t bundle_fee = 0;
        if (determ_ctx_bundle_header(tx.payload.data(), bundle_len,
                                     &n_in, &m, &nbits, &bundle_fee) != 0) {
            v.detail = "CONFIDENTIAL_TRANSFER malformed DCT1 bundle header";
            return v;
        }
        if (tx.fee != bundle_fee) {
            v.detail = "CONFIDENTIAL_TRANSFER tx.fee != bundle public fee ("
                     + std::to_string(tx.fee) + " != "
                     + std::to_string(bundle_fee) + ")";
            return v;
        }
        if (determ_ctx_bundle_verify(tx.payload.data(), bundle_len) != 0) {
            v.detail = "CONFIDENTIAL_TRANSFER bundle proof INVALID (range/balance)";
            return v;
        }
        // Intra-bundle structural collision (input or output note listed twice)
        // would let the bundle claim/burn value the balance proof still "balances".
        // Mirrors the validator's shared-`seen` input+output check (the pool-
        // existence half is state, out of a stateless verifier's scope).
        if (ct_bundle_has_intra_collision(tx.payload.data(), n_in, m)) {
            v.detail = "CONFIDENTIAL_TRANSFER note collision (a note listed twice as "
                       "inputs, or an output equal to an input or another output)";
            return v;
        }
        v.ok = true;
        v.detail = "DCT1 range+balance verified (" + std::to_string(n_in)
                 + " in, " + std::to_string(m) + " out, fee "
                 + std::to_string(bundle_fee) + ")";
        return v;
    }
    default:
        // Not a confidential tx — nothing for THIS verifier to check. The
        // caller decides how to treat vacuity (block walk counts these).
        v.is_ct = false;
        v.ok = true;
        v.detail = "not a confidential tx";
        return v;
    }
}

CtVerifyResult verify_ct_transactions(const json& block_json) {
    CtVerifyResult r;
    if (!block_json.is_object() || !block_json.contains("transactions")
        || !block_json["transactions"].is_array())
        return r;   // no tx array => zero CT txs (r.ok() true, counts say so)
    size_t idx = 0;
    for (const auto& tj : block_json["transactions"]) {
        CtTxVerdict v = verify_ct_tx_json(tj, idx++);
        r.total_txs++;
        if (!v.is_ct) continue;
        r.ct_txs++;
        if (v.ok) r.verified++;
        else      r.failures.push_back(std::move(v));
    }
    return r;
}

bool ct_bundle_has_intra_collision(const uint8_t* bundle, size_t n_in, size_t m) {
    const uint8_t* Cin  = bundle + 15;
    const uint8_t* Cout = bundle + 15 + n_in * 33;
    static const char* H = "0123456789abcdef";
    auto keyhex = [&](const uint8_t* C) {
        std::string k; k.reserve(66);
        for (size_t b = 0; b < 33; ++b) {
            k.push_back(H[C[b] >> 4]);
            k.push_back(H[C[b] & 0xf]);
        }
        return k;
    };
    std::set<std::string> seen;   // shared across inputs + outputs (mirrors validator)
    for (size_t i = 0; i < n_in; ++i)
        if (!seen.insert(keyhex(Cin + i * 33)).second) return true;   // duplicate input
    for (size_t j = 0; j < m; ++j)
        if (!seen.insert(keyhex(Cout + j * 33)).second) return true;  // output == input/output
    return false;
}

}  // namespace determ::light
