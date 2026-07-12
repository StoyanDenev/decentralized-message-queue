// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/types.hpp>
#include <determ/chain/chain.hpp>
#include <determ/node/registry.hpp>
#include <optional>
#include <string>
#include <vector>

// D3.3b-read (ShardTipMergeDesign.md §9.4): the single shared decision point for
// committee-selection POOL + creator IDENTITY resolution, so producer
// (Node::check_if_selected) and validator (BlockValidator::check_creator_selection
// / check_abort_certs + the creator-identity sub-checks) can never derive a
// different committee — a divergence would fork state_root or halt the shard.
//
// On an EXTENDED chain (shard_count>1) inside epoch E>=1, committee membership is
// FROZEN to committee_checkpoints()[E] (D3.3b-write): the pool comes from the
// frozen members (region-filtered) and creator pubkeys/registration resolve from
// the frozen CommitteeMember.ed_pub set — so a member that deregisters / unstakes
// / abort-suspends MID-EPOCH stays a valid committee member until the next epoch
// boundary (the retroactive-reconstructibility property the S-036 closure needs;
// safety-critical equivocation is still detected + slashed immediately, and
// per-round abort exclusion + BFT escalation still guarantee progress — see
// §9.4). Epoch 0, a pruned epoch, or a SINGLE chain fall back to the present-head
// registry, byte-identical to pre-D3.3b behavior.

namespace determ::node {

// TRUE iff committee selection at `epoch` must read the frozen checkpoint rather
// than the present-head registry. Mirrors the fold gate at src/chain/chain.cpp
// EXACTLY (chain-visible shard_count(), so it is deterministic during replay).
// epoch 0 never has a checkpoint (the fold skips it), so the epoch>=1 test is
// redundant with count() today but kept to document intent + guard a future
// epoch-0 fold.
bool committee_pin_active(const chain::Chain& chain, EpochIndex epoch);

// The eligible committee POOL for `epoch`, region-filtered. On the pinned path:
// the frozen members with region rule mirroring NodeRegistry::eligible_in_region
// EXACTLY (empty region => all; else strict m.region==region; order-preserving —
// the frozen members are already domain-sorted, matching build_from_chain's
// insert order, so select_m_creators indices are identical). Off the pinned path:
// present_head.eligible_in_region(region), byte-identical to today. The returned
// NodeEntry carries only domain/pubkey/region from the frozen member; the
// registered_at/active_from fields are 0 and are never read on selection paths.
std::vector<NodeEntry> select_committee_pool(const chain::Chain& chain,
                                             const NodeRegistry& present_head,
                                             EpochIndex epoch,
                                             const std::string& region);

// Resolve a creator/committee member's Ed25519 pubkey. FROZEN-FIRST: on the
// pinned path, a domain present in the frozen set resolves to its frozen ed_pub
// (so a mid-epoch-drifted member still verifies on the key it was selected with);
// a domain ABSENT from the frozen set falls back to the present-head registry
// (so a non-committee equivocator is still slashable). Off the pinned path:
// present-head only. nullopt = unknown at both.
std::optional<PubKey> resolve_committee_member_pubkey(const chain::Chain& chain,
                                                      const NodeRegistry& present_head,
                                                      EpochIndex epoch,
                                                      const std::string& domain);

// TRUE iff `domain` is a committee member for `epoch`. FROZEN-FIRST with
// present-head fallback (same rationale as resolve_committee_member_pubkey).
bool committee_member_registered(const chain::Chain& chain,
                                 const NodeRegistry& present_head,
                                 EpochIndex epoch,
                                 const std::string& domain);

} // namespace determ::node
