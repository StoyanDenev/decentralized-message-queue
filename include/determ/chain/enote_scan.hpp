// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
//
// NC-8 wiring increment 3 — the enote SCAN. A read-only walk over block history
// that surfaces the per-output encrypted-note (enote) delivery ciphertexts that
// increment 2 carries on CONFIDENTIAL_TRANSFER (TxType=14) transactions, so a
// wallet can pull-and-trial-decrypt them (EN-1: a verifying AEAD tag = "mine").
//
// This is a pure reader — it changes NO state and re-runs the SAME
// ctx_split_enotes mirror the validator accept-rule and chain apply consume, so
// it only ever surfaces well-framed regions on txs consensus already accepted; a
// malformed region (which could never have been accepted into a block) is
// skipped defensively. It is PROFILE-AGNOSTIC: the ciphertext rides the tx
// payload on BOTH MODERN and FIPS chains, so the scan returns hits on either —
// the crypto profile only decides whether an `en:` STATE leaf ALSO exists
// (MODERN 2b, for light-client-provable inclusion) vs payload-only (FIPS 2a).
//
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <determ/chain/chain.hpp>       // Chain, Block, Transaction, TxType, Hash, to_hex
#include <determ/chain/ctx_enote.hpp>   // ctx_split_enotes, CtxEnote

namespace determ::chain {

// One delivered ciphertext, keyed to the confidential output note it carries.
struct EnoteHit {
    uint64_t             height;         // block height carrying the tx
    Hash                 tx_hash;        // the CONFIDENTIAL_TRANSFER tx hash
    uint8_t              output_index;   // which output note this enote delivers
    std::string          commitment_hex; // hex of that output's 33-byte commitment
    std::vector<uint8_t> enote;          // the ciphertext wire bytes (E33 || ct || tag)
};

// Scan blocks in [from, to) — clamped to [0, chain.height()) — for enote regions
// on CONFIDENTIAL_TRANSFER transactions. Returns one EnoteHit per delivered
// ciphertext, in (ascending height, tx order, ascending output_index) order.
// `cap` bounds the WORK, not just the result: the walk stops as soon as `cap`
// hits are collected (so the caller's `limit` caps materialization + the read
// lock hold, not merely the response) — default unbounded for internal/test use.
inline std::vector<EnoteHit> scan_enotes(const Chain& chain,
                                         uint64_t from, uint64_t to,
                                         std::size_t cap = SIZE_MAX) {
    std::vector<EnoteHit> hits;
    if (cap == 0) return hits;
    const uint64_t h_end = (to < chain.height()) ? to : chain.height();
    for (uint64_t h = from; h < h_end; ++h) {
        const Block& b = chain.at(h);
        for (const auto& tx : b.transactions) {
            if (tx.type != TxType::CONFIDENTIAL_TRANSFER) continue;
            const uint8_t*    p   = tx.payload.data();
            const std::size_t len = tx.payload.size();
            std::size_t           bundle_len = 0;
            std::vector<CtxEnote> es;
            if (ctx_split_enotes(p, len, &bundle_len, &es) != 0) continue; // malformed → skip
            if (es.empty()) continue;                                      // no delivery region
            // n_in/m are the DCT1 header bytes ctx_split_enotes already validated;
            // C_out[j] sits at offset 15 + n_in*33 + j*33, and every e.output_index
            // is < m (bounds-checked in ctx_split_enotes), so the slice is in-range.
            const std::size_t n_in = (len >= DCT_HDR_LEN) ? p[4] : 0;
            const uint8_t*    Cout = p + DCT_HDR_LEN + n_in * 33;
            const Hash        th   = tx.compute_hash();
            for (const auto& e : es) {
                EnoteHit hit;
                hit.height         = h;
                hit.tx_hash        = th;
                hit.output_index   = e.output_index;
                hit.commitment_hex = to_hex(Cout + std::size_t(e.output_index) * 33, 33);
                hit.enote          = e.bytes;
                hits.push_back(std::move(hit));
                if (hits.size() >= cap) return hits;   // work-bounded early-out
            }
        }
    }
    return hits;
}

} // namespace determ::chain
