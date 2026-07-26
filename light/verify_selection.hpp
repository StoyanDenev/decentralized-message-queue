// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-selection (pure core) — the D.5 government random-selection
// SECURITY SPINE (D5-RANDOM-SELECTION-SPEC §8/§9). Given the DECODED roster /
// case-open / result message streams for a case (obtained by the caller from the
// COMMITTEE-AUTHENTICATED full-block walk — that completeness is the caller's
// gate, SPEC §11 3a) and the verify-rand-authenticated beacon seed, it decides
// whether a queried member was FAIRLY selected, and NEVER reports a false
// SELECTED. It enforces the two verifier-side defences the design's adversarial
// pass surfaced:
//   * first-open-wins (SPEC §11 3b): a compromised authority that pre-commits
//     SEVERAL case-opens for one case and publishes only a favorable draw is
//     defeated — the canonical case-open is the one at the SMALLEST block height,
//     and >1 is surfaced as permanent public EVIDENCE.
//   * ordering h_o < draw_height < h_s (SPEC §11 3c): the case-open must precede
//     the seed height (anti-grinding) and the result must follow it (no post-hoc
//     roster / result).
// It then re-runs d5_draw over the materialized roster + the authenticated seed
// under the CANONICAL case-open's params and compares to the PUBLISHED result;
// any mismatch -> UNVERIFIABLE.

#pragma once
#include "rpc_client.hpp"
#include <determ/dapp/d5codec.h>
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace determ::light {

enum class SelectionVerdict { SELECTED, NOT_SELECTED, UNVERIFIABLE };

// A decoded roster message (op + ids), in canonical block order.
struct D5RosterOp {
    uint8_t  op{0};                              // D5_ROSTER_ADD / D5_ROSTER_REMOVE
    uint64_t height{0};                          // block height it landed at (for cutoff filtering)
    std::vector<std::vector<uint8_t>> ids;       // OWNED copies (not pointers into the block JSON)
};
// A decoded case-open, tagged with the block height it landed at (h_o).
struct D5CaseOpenAt {
    uint64_t height{0};                          // h_o (block height of the case-open msg)
    uint64_t roster_cutoff_height{0};
    uint64_t draw_height{0};                     // H
    uint32_t n_primary{0};
    uint32_t m_alternate{0};
    uint8_t  draw_algo_version{0};
};
// A decoded result, tagged with the block height it landed at (h_s).
struct D5ResultAt {
    uint64_t height{0};                          // h_s
    uint64_t draw_height{0};                     // must equal the canonical case-open's H
    std::vector<std::vector<uint8_t>> selected_ids;
};

struct SelectionResult {
    SelectionVerdict verdict{SelectionVerdict::UNVERIFIABLE};
    bool   multiple_case_opens{false};           // >1 case-open for case_id = EVIDENCE
    size_t eligible_count{0};
    std::string detail;
};

// Collect the D.5 roster / case-open / result streams from a set of ALREADY-
// COMMITTEE-VERIFIED full blocks (SPEC §11 3a). The caller obtains `blocks` from
// the committee-authenticated full-block walk (verify_chain_to_head — that
// AUTHENTICATION is its job); the COMPLETENESS here comes from iterating EVERY
// DAPP_CALL tx in EVERY block, so a truncatable `dapp_messages` RPC hint cannot
// hide a message. Filters DAPP_CALL (type==10) txs where `tx.to == domain`,
// parses the `[topic][ciphertext]` envelope, and decodes the ciphertext via the
// d5codec into the typed streams (owned copies). Roster ops are domain-wide
// (tagged with height so the caller can fold up to roster_cutoff_height);
// case-opens / results are kept only when their payload's case_id matches.
// Returns 0 (always; malformed/foreign txs are skipped, not fatal).
int collect_d5_streams(
    const std::vector<nlohmann::json>& blocks,    // committee-verified full blocks, ascending height
    const std::string& domain,
    const std::vector<uint8_t>& case_id,
    std::vector<D5RosterOp>&   out_roster,
    std::vector<D5CaseOpenAt>& out_case_opens,
    std::vector<D5ResultAt>&   out_results);

// Pure verification core. `queried_member` empty = report "result verified"
// (verdict SELECTED with no membership question). NEVER a false SELECTED.
SelectionResult verify_selection_core(
    const std::vector<uint8_t>& domain,
    const std::vector<uint8_t>& case_id,
    const uint8_t seed32[32],
    const std::vector<D5RosterOp>&   roster_ops,
    const std::vector<D5CaseOpenAt>& case_opens,
    const D5ResultAt& result,
    const std::vector<uint8_t>& queried_member);

// Materialize the roster as of a `cutoff` block height: keep ONLY the ops that
// landed at height <= cutoff, in input order. The canonical case-open declares
// `roster_cutoff_height` (bound into the d5_draw ctx), so a member added AFTER
// the cutoff is NOT eligible for that draw — folding the un-filtered stream
// would admit a post-cutoff member and re-derive over the wrong roster. Pure;
// the live composite calls it before verify_selection_core. (SPEC §4/§11.)
std::vector<D5RosterOp> filter_roster_to_cutoff(
    const std::vector<D5RosterOp>& ops, uint64_t cutoff);

// Live composite (the thin CLI spine, SPEC §12 inc.5 tail). Given an UNTRUSTED
// daemon `rpc`, the genesis-seeded committee, the D.5 `domain`, a `case_id`, and
// an optional `queried_member`, it:
//   1. anchors genesis (anchor_genesis — the operator's own pin);
//   2. committee-authenticates the FULL block chain to the head AND collects
//      every tx-bearing full body (verify_chain_to_head's out-param =
//      completeness, SPEC §11 3a) — a doctored/truncated stream fails closed;
//   3. decodes the roster / case-open / result streams (collect_d5_streams);
//   4. picks the canonical (first-open-wins) case-open, filters the roster to
//      its roster_cutoff_height, and authenticates the beacon seed
//      cumulative_rand[draw_height] via the S-042 successor binding
//      (verify_rand_from_blocks); any unauthenticated input -> UNVERIFIABLE;
//   5. runs verify_selection_core (re-derives d5_draw, compares to the published
//      result, decides the queried member) — NEVER a false SELECTED.
// Throws std::runtime_error only on genesis-pin / transport failures; a
// verification shortfall is returned as verdict UNVERIFIABLE with a detail.
SelectionResult verify_selection_at(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain,
    const std::vector<uint8_t>& case_id,
    const std::vector<uint8_t>& queried_member,
    size_t expected_k = 0,
    bool bft_enabled = true);

} // namespace determ::light
