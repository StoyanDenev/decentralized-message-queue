// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-rand — trustless authentication of the commit-reveal
// beacon `cumulative_rand[H]` (the MPDH block-randomness the D.5 government
// random-selection DApp draws from; D5-RANDOM-SELECTION-SPEC §7). The named
// beacon-read gap: a DApp/citizen wants cumulative_rand[H] as a committee-
// authenticated seed, but a bare header field is a daemon CLAIM, not a proof.
//
// ─── Why this is cryptographically anchored (the S-042 successor binding) ───
//
//   The K-of-K committee signs light_compute_block_digest(block[H+1]); that
//   digest binds block[H+1].prev_hash. And prev_hash == block_hash[H] ==
//   SHA256(signing_bytes(block[H])), whose signing_bytes INCLUDE
//   cumulative_rand[H] (and delay_output[H]). Therefore a committee-signed
//   SUCCESSOR block authenticates cumulative_rand[H] transitively:
//
//     verify block[H+1]'s committee sigs  (cumulative_rand not signed directly)
//     ∧ block[H+1].prev_hash == recompute block_hash(block[H])
//     ⟹ cumulative_rand[H] is committee-authenticated.
//
//   A daemon that swaps cumulative_rand[H] changes block_hash[H], so the
//   recomputed hash no longer equals the committee-signed successor prev_hash
//   → UNVERIFIABLE. Never a false VERIFIED. (This is the same successor binding
//   that verify-state-root / account-history rely on to authenticate a root
//   at the head; here it authenticates the beacon field.)
//
// Reuses verify_block_sigs + Block::compute_hash. Adds NO new crypto.

#pragma once
#include "rpc_client.hpp"
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <map>
#include <string>

namespace determ::light {

enum class RandVerdict {
    VERIFIED,      // cumulative_rand[H] is committee-authenticated via the
                   // S-042 successor binding.
    UNVERIFIABLE,  // the index / successor-binding / committee-sig chain broke
                   // — the beacon field cannot be trusted, so we refuse YES.
};

struct RandResult {
    RandVerdict verdict{RandVerdict::UNVERIFIABLE};
    uint64_t    height{0};
    std::string cumulative_rand_hex;  // cumulative_rand[H]; trustworthy ONLY when VERIFIED
    std::string block_hash_hex;       // recomputed block_hash[H]
    bool        committee_verified{false};
    size_t      sigs_verified{0};
    size_t      committee_size{0};    // |creators| of block[H+1]
    std::string detail;               // names what broke on UNVERIFIABLE
};

// Pure, offline-testable core: given the ALREADY-FETCHED header[H] and its
// successor header[H+1] (+ the committee seed that signed H+1), authenticate
// cumulative_rand[H]. Steps (fail-closed, all required for VERIFIED):
//   1. index binding   — block[H].index==H, block[H+1].index==H+1
//   2. successor binding — block[H+1].prev_hash == recompute block_hash(block[H])
//   3. committee-sig verify on block[H+1] (verify_block_sigs; expected_k /
//      bft_enabled mirror the node's committee-size mode-eligibility gate,
//      LV-1/LV-2, so a MITM cannot downgrade the quorum to a single signer).
// `expected_k` (genesis k_block_sigs) and `bft_enabled` default to the
// permissive low-level behaviour; the anchored caller passes the genesis
// values. NEVER a false VERIFIED.
RandResult verify_rand_from_blocks(
    const nlohmann::json& block_h_json,
    const nlohmann::json& block_h1_json,
    const std::map<std::string, PubKey>& committee_seed,
    uint64_t    height,
    size_t      expected_k = 0,
    bool        bft_enabled = true);

// Live wrapper: fetch block H and H+1 via the `block` RPC and delegate to the
// pure core. `committee_seed` is the genesis-derived committee (the documented
// anchor; on a chain whose signing committee has ROTATED since genesis this is
// the genesis committee — a pre-existing determ-light limitation inherited, not
// introduced, by verify-rand). Throws std::runtime_error only on transport /
// out-of-range (H+1 beyond the head → no committee-signed successor yet →
// UNVERIFIABLE by construction: the head's beacon is not yet authenticated).
RandResult verify_rand_at(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    uint64_t    height,
    size_t      expected_k = 0,
    bool        bft_enabled = true);

} // namespace determ::light
