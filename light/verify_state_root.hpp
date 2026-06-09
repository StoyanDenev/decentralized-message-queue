// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-state-root — per-height committee-verified
// state_root anchor primitive.
//
// Use case: a user/auditor wants the committee-signed state_root at a
// specific height H as a trust anchor for an out-of-band state-proof
// check, or to confirm two independent observers agree on the
// committee-attested root at H. This is the per-height anchor primitive
// that `balance-trustless` / `account-history` use internally, exposed
// standalone for scripting.
//
// ─── Distinct from verify-state-proof ──────────────────────────────────
//
//   verify-state-proof verifies a Merkle PROOF against a GIVEN root —
//   it answers "does this leaf roll up to that root?". It does NOT tell
//   you whether the root itself is genuine.
//
//   verify-state-root verifies the ROOT ITSELF — it answers "is the
//   state_root at height H genuinely committee-signed and bound to the
//   pinned genesis?". The output root is the trusted anchor you would
//   then feed to verify-state-proof's --state-root.
//
// ─── Why this is cryptographically anchored ────────────────────────────
//
//   1. Genesis is pinned: block 0's recomputed hash must equal
//      compute_genesis_hash(genesis) (fail-closed otherwise — the same
//      anchor anchor_genesis performs).
//   2. Header[H] is bound to genesis by an unbroken prev_hash chain walk
//      from block 0 up through H (so H is not an isolated header a
//      malicious daemon could fabricate — it must descend from the
//      pinned genesis).
//   3. Header[H]'s K-of-K (MD) / ceil(2K/3) (BFT-fallback) committee
//      Ed25519 signatures over light_compute_block_digest(H) must verify
//      against the genesis-seeded committee. Those sigs bind H's
//      state_root field (verify_block_sigs surfaces it only when the
//      sigs verify).
//
// Genesis (H == 0) carries NO committee sigs by construction (it is the
// deterministic GenesisConfig->Block transform). For H == 0 the anchor
// is the genesis-hash match alone (step 1); its state_root is reported
// as committee_verified=true with sigs_verified=0, mirroring how
// account_history / verify_chain_to_head / verify_tx_inclusion treat
// index 0.
//
// A header whose sigs don't verify, or that doesn't chain to genesis, is
// reported with committee_verified=false and the caller fails closed
// (non-zero exit) — NEVER a bare daemon-reported root.
//
// REUSE: this primitive sequences the existing verifiers (anchor_genesis,
// verify_headers for the bounded prev_hash chain walk, verify_block_sigs).
// It adds NO new crypto / no new Merkle / no new sig logic.

#pragma once
#include "rpc_client.hpp"
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <map>
#include <string>

namespace determ::light {

// Result of a verify-state-root query at a single height.
struct StateRootResult {
    bool        ok{false};            // true iff the root is committee-verified
                                      // (or genesis-hash-anchored at H==0)
    uint64_t    height{0};            // the queried block index H
    std::string state_root_hex;       // committee-verified state_root at H
                                      // (may be empty on a pre-S-033 chain —
                                      // see `state_root_present`)
    bool        state_root_present{false}; // false when the verified header
                                      // carries no state_root (pre-S-033)
    std::string block_hash_hex;       // block_hash of header[H]
    bool        committee_verified{false};
    size_t      sigs_verified{0};     // 0 at genesis (no committee sigs)
    size_t      committee_size{0};    // |creators| of header[H] (0 at genesis)
    // On failure (ok == false) this names what broke: genesis-anchor
    // mismatch, prev_hash chain break, height beyond head, committee-sig
    // failure, malformed header. Empty on success.
    std::string detail;
};

// Verify and return the committee-signed state_root at height `height`.
//
// Flow:
//   1. Probe head height; require height <= head index (else ok=false,
//      detail names the head bound — clean error, no throw).
//   2. Walk the prev_hash chain from the pinned genesis up through
//      `height`, genesis-anchored on the first page and prev-anchor
//      threaded on every page after (reuses verify_headers). This binds
//      header[H] to the pinned genesis. A single bounded walk [0, H] is
//      performed (one-shot command).
//   3. Fetch header[H]. For H > 0 verify its committee sigs (MD first,
//      BFT fallback) over light_compute_block_digest(H). For H == 0
//      anchor on the genesis hash (no committee sigs by construction).
//   4. Report header[H]'s state_root, committee size, and sig count.
//
// The caller must anchor genesis (anchor_genesis) BEFORE calling this so
// the chain identity is pinned and `genesis_hash_hex` is the recomputed
// compute_genesis_hash(genesis). `committee_seed` is the genesis-derived
// committee map (domain -> ed_pub).
//
// Throws std::runtime_error only on transport / RPC-layer failures
// (connection dropped, malformed RPC envelope). Verification failures
// (sigs don't verify, chain break, height out of range) are returned as
// ok=false in the result with a populated `detail`, not thrown — so the
// caller can report a clean error and exit non-zero without a stack
// trace.
//
// `max_wait_seconds` (default 0 = no wait, behaviour unchanged) is forwarded to
// committee_bound_state_root in the H>=1 branch: when `height` is the chain head
// (no committee-signed successor yet) the helper polls up to max_wait_seconds for
// the next block, then binds the held root. Default 0 fails closed at the head
// exactly as before.
StateRootResult verify_state_root_at(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex,
    uint64_t    height,
    uint64_t    max_wait_seconds = 0);

} // namespace determ::light
