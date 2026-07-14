// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/shardtip_verify.hpp>
#include <determ/node/committee_pool.hpp>   // committee_pin_active / select_committee_pool
#include <determ/node/producer.hpp>          // compute_block_digest / compute_view_root
#include <determ/chain/params.hpp>           // bft_committee_size
#include <determ/crypto/random.hpp>          // epoch_committee_seed / select_m_creators
#include <determ/crypto/sha256.hpp>          // SHA256Builder
#include <determ/crypto/keys.hpp>            // crypto::verify
#include <iostream>
#include <map>
#include <set>
#include <vector>

namespace determ::node {

std::optional<Hash> verify_shard_tip_committee_sig_root(
    const chain::Chain&      chain,
    const NodeRegistry&      present_head,
    EpochIndex               shard_epoch,
    uint64_t                 epoch_blocks,
    const std::string&       region,
    ShardId                  shard_id,
    size_t                   k_block_sigs,
    bool                     bft_enabled,
    const chain::Block&      tip) {

    // MODE-ELIGIBILITY GATE (VERBATIM from on_shard_tip node.cpp — the gate the
    // caller ran there before this function existed; folded IN so no caller can
    // drop it). A BFT-declared tip lowers expected_k to bft_committee_size (ceil
    // 2K/3), so a chain that has NOT enabled per-height BFT escalation must reject a
    // consensus_mode==BFT tip outright — otherwise a Byzantine beacon could carry a
    // fabricated-distress source tip signed by only ceil(2K/3) of the frozen source
    // committee and it would pass the K-of-K verify at a reduced bar (S-036 reopened
    // at a 2K/3 collusion threshold). e-7d adversarial-review HIGH finding.
    if (tip.consensus_mode == chain::ConsensusMode::BFT && !bft_enabled) {
        std::cerr << "[node] shard tip: BFT consensus_mode but bft not enabled — "
                     "rejected (no reduced-quorum source attestation)\n";
        return std::nullopt;
    }

    // ── beacon epoch rand (VERBATIM from on_shard_tip) ──────────────────────────
    Hash beacon_rand;
    if (committee_pin_active(chain, shard_epoch)) {
        // D3.5e-4: FROZEN cc:[shard_epoch] leaf value — self-contained committed
        // state (what the auditor CLI re-derives from). Provably ==
        // chain.at(shard_epoch*epoch_blocks-1).cumulative_rand by the fold
        // construction, but robust if the anchor block is pruned within the ring.
        beacon_rand = chain.committee_checkpoints().at(shard_epoch).epoch_rand;
    } else {
        // Legacy block-anchored read (epoch 0 / not-yet-folded / CURRENT).
        uint64_t beacon_anchor_height =
            shard_epoch * (epoch_blocks ? epoch_blocks : 1);
        if (beacon_anchor_height == 0 || beacon_anchor_height > chain.height()) {
            beacon_rand = chain.empty() ? Hash{} : chain.head().cumulative_rand;
        } else {
            beacon_rand = chain.at(beacon_anchor_height - 1).cumulative_rand;
        }
    }

    // ── committee POOL — frozen cc: (region-filtered) when pinned, else present-head
    auto pool_nodes = select_committee_pool(chain, present_head, shard_epoch, region);

    std::set<std::string> excluded;
    for (auto& ae : tip.abort_events) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail;
    for (auto& nd : pool_nodes) {
        if (!excluded.count(nd.domain)) avail.push_back(nd.domain);
    }

    size_t k_full = k_block_sigs;
    size_t k_bft  = chain::bft_committee_size(k_full);
    size_t expected_k = (tip.consensus_mode == chain::ConsensusMode::BFT) ? k_bft : k_full;
    if (avail.size() < expected_k) {
        std::cerr << "[node] shard tip: insufficient pool to derive committee for shard="
                  << shard_id << "\n";
        return std::nullopt;
    }
    if (tip.creators.size() != expected_k) {
        std::cerr << "[node] shard tip: creators size (" << tip.creators.size()
                  << ") != expected_k (" << expected_k << ")\n";
        return std::nullopt;
    }

    Hash rand = crypto::epoch_committee_seed(beacon_rand, shard_id);
    for (auto& ae : tip.abort_events) {
        rand = crypto::SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
    }
    auto indices = crypto::select_m_creators(rand, avail.size(), expected_k);
    for (size_t i = 0; i < expected_k; ++i) {
        if (avail[indices[i]] != tip.creators[i]) {
            std::cerr << "[node] shard tip: creators[" << i << "] mismatch ('"
                      << tip.creators[i] << "' vs derived '"
                      << avail[indices[i]] << "')\n";
            return std::nullopt;
        }
    }

    // ── K-of-K signature verification — FROZEN-ONLY pubkeys (D3.5e-4) ────────────
    std::map<std::string, PubKey> frozen_pub;
    for (auto& nd : pool_nodes) frozen_pub[nd.domain] = nd.pubkey;

    if (tip.creator_block_sigs.size() != tip.creators.size()) return std::nullopt;
    Hash digest = compute_block_digest(tip);
    Signature zero_sig{};
    size_t signed_count = 0;
    for (size_t i = 0; i < tip.creators.size(); ++i) {
        if (tip.creator_block_sigs[i] == zero_sig) continue;
        auto pit = frozen_pub.find(tip.creators[i]);
        if (pit == frozen_pub.end()) return std::nullopt;   // not a frozen committee member
        if (!crypto::verify(pit->second, digest.data(), digest.size(),
                              tip.creator_block_sigs[i])) {
            std::cerr << "[node] shard tip: invalid sig from " << tip.creators[i] << "\n";
            return std::nullopt;
        }
        ++signed_count;
    }
    size_t required = (tip.consensus_mode == chain::ConsensusMode::BFT) ? k_bft : k_full;
    if (signed_count < required) {
        std::cerr << "[node] shard tip: insufficient sigs (" << signed_count
                  << "/" << required << ")\n";
        return std::nullopt;
    }

    // ── committee_sig_root (VERBATIM) — commitment to the ACTUAL verified sig SET.
    // A PURE function of (tip, region, shard_id): every honest verifier that accepts
    // builds the byte-identical root (the anti-wedge / re-verifiable invariant).
    std::vector<Hash> sig_hashes;
    for (const auto& s : tip.creator_block_sigs) {
        if (s == zero_sig) continue;
        crypto::SHA256Builder sb;
        sb.append(s.data(), s.size());
        sig_hashes.push_back(sb.finalize());
    }
    Hash sig_set_root = compute_view_root(sig_hashes);

    crypto::SHA256Builder cb;
    cb.append(std::string("determ-shardtip-v1"));         // domain tag (§3.3)
    cb.append(static_cast<uint64_t>(shard_id));            // source_shard_id
    cb.append(static_cast<uint64_t>(tip.index));           // height
    cb.append(static_cast<uint64_t>(tip.eligible_count));  // D3.4 source-signed count
    cb.append(static_cast<uint64_t>(region.size()));
    cb.append(region);                                     // region (may be "")
    cb.append(digest);                                     // == compute_block_digest(tip)
    cb.append(sig_set_root);                               // commitment to the K-of-K sigs
    return cb.finalize();
}

} // namespace determ::node
