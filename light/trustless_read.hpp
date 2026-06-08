// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light trustless-read wrapper.
//
// Composite primitive used by `balance-trustless`, `nonce-trustless`,
// and the end-to-end `verify-and-submit` flow. Given (genesis JSON
// path, RPC port, account domain):
//
//   1. Anchor genesis: fetch block 0 via rpc_headers, recompute the
//      block hash, compare against compute_genesis_hash(genesis). On
//      mismatch return GENESIS_HASH_MISMATCH.
//   2. Walk the header chain from genesis to the daemon's current head
//      using rpc_headers (paginated, max 256 per page). Each page is
//      verified via verify_headers (prev_hash chain) AND
//      verify_block_sigs (K-of-K committee sigs) per block.
//   3. Fetch a state-proof for ("a:", domain) via rpc_state_proof.
//   4. Verify the state-proof against the head header's state_root.
//   5. Decode the value_hash back to (balance, next_nonce) via the
//      committed account-leaf encoding (see chain.cpp::build_state_leaves
//      "accounts_" branch).
//
// The light client maintains an in-memory committee map (domain →
// pubkey) seeded from the genesis JSON's initial_creators, then
// extended as REGISTER txs would in a full node. v1.x light-client
// scope per the plan defers full REGISTER tracking — the verify pass
// extracts each block's `creators` list from the header and demands
// every member be in the locally-known committee (seeded from genesis
// + extended by any block whose creators appear in genesis). This
// covers genesis-pinned chains; chains with mid-chain REGISTERs need
// the daemon's `creators` RPC or a future stateful sync extension.

#pragma once
#include "rpc_client.hpp"
#include "verify.hpp"
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <map>
#include <string>

namespace determ::light {

// Account state extracted from a verified state-proof.
struct AccountView {
    uint64_t balance{0};
    uint64_t next_nonce{0};
    // The head header's state_root the proof verified against.
    std::string state_root_hex;
    // The head block index this view is anchored at.
    uint64_t height{0};
};

// Load and parse a genesis JSON file. Throws std::runtime_error on
// parse failure or missing required fields.
determ::chain::GenesisConfig load_genesis(const std::string& path);

// Anchor: fetch block 0 from the daemon, recompute its block_hash, and
// compare against compute_genesis_hash(genesis). Throws on mismatch.
// Returns the genesis-hash hex for callers that want to pass it to
// verify_headers as --genesis-hash.
std::string anchor_genesis(RpcClient& rpc,
                            const determ::chain::GenesisConfig& genesis);

// Composite: walk the header chain from `from_index` to the daemon's
// current head, verifying prev_hash continuity AND K-of-K committee
// sigs per block. Returns the head's block_hash (suitable as the
// chain-tip pin) plus the head's state_root (suitable for anchoring
// state-proof verifications). Throws on any verify failure.
//
// `committee_seed` is the initial committee map (domain → pubkey),
// typically derived from the genesis JSON's initial_creators. The
// function does NOT mutate it for REGISTER/DEREGISTER (scope deferred);
// callers building against a chain with mid-chain registry changes
// should pre-populate committee_seed with every domain that has been
// registered, e.g. via the daemon's `creators` RPC.
struct VerifiedChain {
    uint64_t    height{0};        // == last-verified block's index + 1
    std::string head_block_hash;  // block_hash hex of the tip
    std::string head_state_root;  // state_root hex of the tip (may be empty
                                  // if the chain hasn't activated S-033)
    size_t      headers_verified{0};
    size_t      blocks_with_sigs_verified{0};
};

VerifiedChain verify_chain_to_head(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const std::string& genesis_hash_hex);

// LSP-6 fast-resume. Given a previously-verified anchor (anchor_height ==
// a prior VerifiedChain.height, anchor_block_hash == its head_block_hash),
// verify ONLY the suffix the daemon has added ABOVE the anchor. The first
// suffix block (index == anchor_height) must have prev_hash == anchor_block_hash
// (enforced by verify_headers' continuity gate); under SHA-256 collision
// resistance that block_hash transitively commits the entire skipped prefix
// 0..anchor_height-1, which LSP-1 already committee-verified when the anchor was
// written. The CALLER MUST have re-pinned the genesis first (the persisted
// anchor.genesis_hash == the locally-recomputed compute_genesis_hash — LSP-2);
// this function assumes that gate has passed.
//
// Returns {resumed=false} WITHOUT verifying anything when the daemon's head is
// not strictly above the anchor (nothing new, or a rollback) — the caller falls
// back to a full verify_chain_to_head. Returns {resumed=true, vc} after verifying
// the suffix (vc.height = daemon tip; vc.headers_verified /
// blocks_with_sigs_verified count ONLY the suffix). THROWS if the suffix does not
// chain onto anchor_block_hash (a fork/rollback below the anchor) — a real
// anomaly that must surface, never be silently re-verified from genesis.
struct ResumeResult {
    bool          resumed{false};
    VerifiedChain vc;
};
ResumeResult verify_chain_from_anchor(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    uint64_t anchor_height,
    const std::string& anchor_block_hash);

// The committee-verified head a read/verify composite anchors against, obtained
// either by a full from-genesis verify or — when `resume` is set and a valid,
// genesis-pinned cached anchor exists and the daemon is ahead of it — by the
// LSP-6 fast-resume suffix walk. This is the SINGLE source of truth for the
// "resume-or-full" decision: cmd_verify_chain and every composite trustless read
// route through it, so they all inherit the same (adversarially-verified) resume
// soundness + genesis re-pin + fallback rules rather than reimplementing them.
struct AnchoredHead {
    std::string   genesis_hash_hex;  // the LOCAL compute_genesis_hash recompute
    VerifiedChain vc;                // the verified head (full or resumed suffix tip)
    bool          resumed{false};    // true iff the cached anchor was usable + consumed
    std::string   note;              // "" on a plain full verify; else a resume/fallback note
};

// Always anchors genesis first (anchor_genesis). If `resume` and a valid
// genesis-pinned anchor is cached at `state_path` (empty → default_state_path())
// and the daemon's head is strictly above it, verifies ONLY the suffix above the
// anchor (verify_chain_from_anchor); otherwise — absent / corrupt / wrong-chain /
// not-ahead anchor — falls back to a full verify_chain_to_head (NEVER weaker). A
// fork below the anchor THROWS (verify_chain_from_anchor's hard error). With
// resume=false this is exactly anchor_genesis + verify_chain_to_head, so existing
// callers are byte-for-byte unaffected.
AnchoredHead anchored_head(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    bool resume,
    const std::string& state_path);

// Composite: fetch a state-proof for the "a:" + domain key, verify it
// against the head's state_root, and decode the value_hash back to
// (balance, next_nonce). The decode reproduces chain.cpp's accounts_
// leaf encoding: value_hash = SHA256(u64_be(balance) || u64_be(next_nonce)).
// Since the encoded value is the hash (not the cleartext), the light
// client also fetches the cleartext (balance, next_nonce) via the
// daemon's `account` RPC, recomputes the hash, and confirms it matches
// value_hash. If the daemon lies about the cleartext, the hash check
// fails and the function throws.
// resume / state_path (default off / default cache) route the head-anchoring
// through anchored_head; with resume=false the behavior is byte-identical to the
// original full from-genesis verify, so existing callers need no change.
AccountView read_account_trustless(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain,
    bool resume = false,
    const std::string& state_path = "");

// Helper: build the genesis committee seed map (domain → ed_pub) from
// the genesis config's initial_creators. Used by verify-chain and the
// trustless-read paths so callers don't have to duplicate the
// genesis-loading code.
std::map<std::string, PubKey>
build_genesis_committee(const determ::chain::GenesisConfig& cfg);

} // namespace determ::light
