// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/types.hpp>
#include <determ/chain/chain.hpp>
#include <determ/node/registry.hpp>
#include <optional>
#include <string>

// D3.5e-7b (ShardTipMergeDesign.md §9.6 pt4): the SHARED committee-derivation +
// K-of-K signature verification + committee_sig_root computation for a source
// SHARD_TIP. Extracted VERBATIM from Node::on_shard_tip so the beacon's
// contemporaneous verdict (on_shard_tip) and the future universal fold
// re-verification gate (e-7d BlockValidator::check_shardtip_witnesses) can never
// derive a different committee or a different committee_sig_root — a drift there
// would either false-reject an honest distress record (liveness) or, worse, admit a
// fabricated one (the S-036 hole this whole layer closes).
//
// It reproduces on_shard_tip's FULL logic (both the pinned `cc:[E]` path and the
// legacy fallback rand/pool path); only the CALLER decides whether the fallback is
// acceptable: on_shard_tip allows it (bootstrap), the validator gate calls this ONLY
// when committee_pin_active(chain, shard_epoch) so its verdict is a pure function of
// COMMITTED beacon state (retroactively reconstructible, the Layer-2 closure).

namespace determ::node {

// Returns the committee_sig_root iff `tip`'s committee derives from committed state
// (frozen `cc:[shard_epoch]` region-filtered when pinned, else present-head
// fallback) AND its non-zero K-of-K signatures verify against the FROZEN ed_pubs of
// that committee; std::nullopt on any failure (diagnostics on stderr, as on_shard_tip
// did). committee_sig_root is a PURE function of (tip, region, shard_id) — the
// committee derivation gates only ACCEPTANCE, never the root value — so an honest
// beacon and any re-verifier that both accept produce the identical root.
//
//   present_head : the beacon's present-head NodeRegistry (used ONLY on the
//                  non-pinned fallback path via select_committee_pool; unread when
//                  the `cc:` checkpoint is present).
//   epoch_blocks : the genesis epoch length (for the legacy fallback anchor read).
//   region       : the source shard's committee_region (genesis-committed map).
std::optional<Hash> verify_shard_tip_committee_sig_root(
    const chain::Chain&      chain,
    const NodeRegistry&      present_head,
    EpochIndex               shard_epoch,
    uint64_t                 epoch_blocks,
    const std::string&       region,
    ShardId                  shard_id,
    size_t                   k_block_sigs,
    const chain::Block&      tip);

} // namespace determ::node
