// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// A3 client-side confidential-transaction verification (pre-launch register
// A3, owner 2026-07-09: "determ-light verifies range/balance proofs
// CLIENT-SIDE — a light client does not trust the committee for CT validity").
//
// Re-runs the SAME cryptographic accept-rules the validator runs, locally:
//   SHIELD (12)               — determ_shield_verify(payload, tx.amount)
//   UNSHIELD (13)             — determ_unshield_verify against the locally
//                               recomputed unshield_spend_ctx_hash(from, to,
//                               nonce, amount) — the context-bind is what makes
//                               a captured proof non-redirectable, so the light
//                               client MUST rebuild the context itself.
//   CONFIDENTIAL_TRANSFER(14) — split off the OPTIONAL trailing NC-8 enote
//                               region (ctx_split_enotes) → DCT1 header over the
//                               bundle prefix + tx.fee == bundle fee + full
//                               range/balance verify + intra-bundle collision
//                               rejection (a note listed twice — two inputs, or an
//                               output == an input or another output — claims/burns
//                               value the balance proof still "balances").
//
// SCOPE (honest limits): this is CRYPTOGRAPHIC validity only. Note-SET checks
// (input notes unspent, output notes fresh — double-spend rejection) need the
// live shielded-pool state a stateless verifier does not hold; those remain
// the daemon apply-rule's job, anchored for the light client by the
// committee-signed state_root over the cn: leaves. Composing both halves:
// CT-PROOFS here + SIGS (committee digest) + the cn: state proofs = the full
// A3 light posture.
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace determ::light {

using json = nlohmann::json;

struct CtTxVerdict {
    size_t      index{0};      // position in the containing transactions[]
    int         type{-1};      // TxType value (12/13/14 for CT types)
    bool        is_ct{false};  // was this a confidential tx at all?
    bool        ok{false};     // proof verified (only meaningful when is_ct)
    std::string detail;
};

struct CtVerifyResult {
    size_t total_txs{0};       // every tx walked
    size_t ct_txs{0};          // type 12/13/14
    size_t verified{0};        // CT txs whose proofs verified
    std::vector<CtTxVerdict> failures;   // CT txs that FAILED (empty == pass)
    bool ok() const { return failures.empty(); }
};

// Verify ONE transaction JSON (Transaction::to_json shape). Never throws:
// a malformed/unparseable tx is a FAILED verdict (fail-closed), and a non-CT
// type returns is_ct=false / ok=true ("nothing to verify" — the CALLER decides
// whether vacuity is acceptable).
CtTxVerdict verify_ct_tx_json(const json& tx_json, size_t index = 0);

// Walk block_json["transactions"] (absent/empty array => zero CT txs, ok()).
CtVerifyResult verify_ct_transactions(const json& block_json);

// Structural intra-bundle note collision (STATELESS; mirrors the node validator).
// Returns true iff any of the n_in input + m output 33-byte commitments collides:
// two equal inputs, or an output equal to an input or another output. Input
// commitments start at bundle+15, outputs at bundle+15+n_in*33. A collision lets a
// bundle claim/burn value the DCT1 balance proof still "balances", so it must be
// rejected. The pool-existence half (output note already on-chain) is STATE, out of
// a stateless verifier's scope. CALLER must have validated the bundle layout first
// (determ_ctx_bundle_verify) so the reads are in-bounds. Pure; the falsify-on-mutant
// seam (dropping the OUTPUT half re-opens the light-accepts / node-rejects widening).
bool ct_bundle_has_intra_collision(const uint8_t* bundle, size_t n_in, size_t m);

}  // namespace determ::light
