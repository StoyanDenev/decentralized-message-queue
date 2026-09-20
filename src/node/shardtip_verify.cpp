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

std::optional<size_t> verify_committee_sigs(
    const std::map<std::string, PubKey>& member_pub,
    const std::vector<std::string>&      creators,
    const std::vector<Signature>&        creator_block_sigs,
    const Hash&                          digest,
    size_t                               required_k,
    const std::string&                   diag_ctx) {
    if (creators.empty()) {
        std::cerr << "[node] " << diag_ctx << ": empty committee rejected\n";
        return std::nullopt;
    }
    if (creator_block_sigs.size() != creators.size()) {
        std::cerr << "[node] " << diag_ctx << ": creator_block_sigs size mismatch\n";
        return std::nullopt;
    }
    Signature zero_sig{};
    size_t signed_count = 0;
    for (size_t i = 0; i < creators.size(); ++i) {
        if (creator_block_sigs[i] == zero_sig) continue;
        auto pit = member_pub.find(creators[i]);
        if (pit == member_pub.end()) {
            std::cerr << "[node] " << diag_ctx << ": creator '" << creators[i]
                      << "' not in committee pool\n";
            return std::nullopt;
        }
        if (!crypto::verify(pit->second, digest.data(), digest.size(),
                              creator_block_sigs[i])) {
            std::cerr << "[node] " << diag_ctx << ": invalid sig from "
                      << creators[i] << "\n";
            return std::nullopt;
        }
        ++signed_count;
    }
    if (signed_count < required_k) {
        std::cerr << "[node] " << diag_ctx << ": insufficient sigs ("
                  << signed_count << "/" << required_k << ")\n";
        return std::nullopt;
    }
    return signed_count;
}

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
        } else if (chain.has_block(beacon_anchor_height - 1)) {
            beacon_rand = chain.at(beacon_anchor_height - 1).cumulative_rand;
        } else {
            beacon_rand = chain.empty() ? Hash{} : chain.head().cumulative_rand;
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
    // S-074: the tip's abort events must carry their CANONICAL identity —
    // the same rule the source shard's validators enforce — so a K-colluding
    // source committee cannot present a chosen hash that seats a committee of
    // its choosing here while its own chain rejects the block. Re-derived from
    // the committee seed and the tip height; no parent tip is needed.
    for (size_t i = 0; i < tip.abort_events.size(); ++i) {
        const auto& ae = tip.abort_events[i];
        const chain::AbortEvent* prev = (i == 0) ? nullptr : &tip.abort_events[i - 1];
        if (ae.event_hash != chain::canonical_abort_event_hash(ae, prev, rand, tip.index)) {
            std::cerr << "[node] shard tip: abort_event[" << i
                      << "] event_hash not canonical (S-074): shard=" << shard_id
                      << " block=" << tip.index << "\n";
            return std::nullopt;
        }
    }
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

    Hash digest = compute_block_digest(tip);
    size_t required = (tip.consensus_mode == chain::ConsensusMode::BFT) ? k_bft : k_full;
    // DECISION-LOG 2026-07-31 Hole 2: the shared committee-signature core —
    // verdict-identical extraction of the loop that lived here (the empty-floor
    // arm is unreachable on this path: creators.size()==expected_k>=1 was
    // enforced above).
    if (!verify_committee_sigs(frozen_pub, tip.creators, tip.creator_block_sigs,
                               digest, required, "shard tip"))
        return std::nullopt;
    Signature zero_sig{};   // the sig-set-root loop below skips zero sentinels

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
