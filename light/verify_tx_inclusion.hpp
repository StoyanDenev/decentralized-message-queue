// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-tx-inclusion — trustless tx-inclusion proof.
//
// Proves (or disproves) that a specific transaction hash H is included
// in the block at a specific height B, anchored to the block's
// committee signatures and the tx-root the committee signed over.
//
// ─── Why this is cryptographically anchored ────────────────────────────
//
// The K-of-K committee signs `compute_block_digest(block)` (see
// producer.cpp::compute_block_digest, mirrored in verify.cpp::
// light_compute_block_digest). That digest binds:
//   * tx_root              = compute_tx_root(creator_tx_lists)
//   * creator_tx_lists     = the K per-creator tx-hash lists
//
// tx_root is a SHA-256 over the SORTED, DEDUPLICATED UNION of the K
// committee members' tx-hash lists (producer.cpp::compute_tx_root). The
// canonical tx SET of a block is exactly that union (producer.cpp
// build_body resolves those hashes against the mempool to populate
// transactions[]). Therefore:
//
//   "tx H is in block B" ⟺ H ∈ union(creator_tx_lists of B)
//
// and that union is committed to (a) by tx_root and (b) directly by the
// hash-list bytes — BOTH inside the committee-signed digest. So once the
// committee sigs verify against the digest, membership of H in the
// committed hash set is a cryptographic fact, not a daemon claim. This
// is NOT a head-only limitation like state_proof — any historical block
// is verifiable because its committee sigs travel with it.
//
// The block's transactions[] BODY (full tx structs) is supplementary:
// we recompute each body tx's hash, confirm the set of body-hashes
// equals the committed hash set, and confirm compute_tx_root over the
// committed hashes reproduces block.tx_root. A daemon that tampers with
// the body (drops/adds/swaps a tx) is caught here and the result is
// reported UNVERIFIABLE — never a false INCLUDED.

#pragma once
#include "rpc_client.hpp"
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <map>
#include <string>

namespace determ::light {

// Verdict for a tx-inclusion query.
enum class InclusionVerdict {
    INCLUDED,      // H is in the committee-signed tx set of block B.
    NOT_INCLUDED,  // H is absent from a block whose tx set is committee-verified.
    UNVERIFIABLE,  // the body<->committed-hash-set binding broke (tampered
                   // daemon / inconsistent block) — membership cannot be
                   // trusted, so we refuse to answer INCLUDED/NOT_INCLUDED.
};

struct TxInclusionResult {
    InclusionVerdict verdict{InclusionVerdict::UNVERIFIABLE};
    uint64_t         height{0};
    std::string      tx_hash_hex;     // the (normalized) queried hash
    std::string      tx_root_hex;     // committee-signed + recomputed tx_root
    std::string      block_hash_hex;  // block B's block_hash
    bool             committee_verified{false};
    size_t           sigs_verified{0};
    size_t           committee_size{0};
    size_t           tx_count{0};     // |committed tx set| of block B
    // On UNVERIFIABLE this names what broke (tx_root mismatch, body/hash
    // -set divergence, malformed block, ...). On INCLUDED/NOT_INCLUDED it
    // is empty.
    std::string      detail;
};

// Composite proof. Steps:
//   1. fetch block B's full JSON via the `block` RPC.
//   2. anchor B:
//        * B == 0 (genesis): genesis carries NO committee sigs by
//          construction (it's the deterministic GenesisConfig->Block
//          transform), so we anchor on the hash instead — recompute
//          compute_genesis_hash(genesis) and require it equal block 0's
//          recomputed hash. Genesis has an empty tx set, so any H is
//          NOT_INCLUDED, anchored by that hash match.
//        * B  > 0: verify B's committee sigs over
//          light_compute_block_digest(B) (MD first, BFT fallback) —
//          establishes the committee-signed digest binding tx_root +
//          creator_tx_lists.
//   3. recompute tx_root from creator_tx_lists; require == block.tx_root.
//   4. cross-check the transactions[] body against the committed hash
//      set (every body hash is in the set AND |body| == |set|). On any
//      divergence → UNVERIFIABLE.
//   5. membership: H ∈ committed set → INCLUDED else NOT_INCLUDED.
//
// The caller must anchor genesis (anchor_genesis) BEFORE calling this so
// the chain identity is pinned; this function assumes `rpc` already
// talks to the genesis-pinned chain and focuses on the block proof.
// `genesis` is the same parsed config the caller anchored with — used
// for the height-0 hash anchor.
//
// For B > 0 the function tries MD (full K-of-K) first and only falls
// back to BFT (ceil(2K/3) with sentinel-zero slots) when MD fails,
// mirroring verify_chain_to_head.
//
// Throws std::runtime_error only on transport / RPC-layer failures
// (block not found, connection dropped). Verification failures are
// returned as UNVERIFIABLE in the result, not thrown.
TxInclusionResult verify_tx_inclusion(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    uint64_t    height,
    const std::string& tx_hash_hex);

} // namespace determ::light
