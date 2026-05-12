// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <determ/chain/chain.hpp>
#include <determ/node/registry.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace determ::node {

class BlockValidator {
public:
    BlockValidator() = default;

    struct Result {
        bool        ok{false};
        std::string error;
    };

    // K = committee size per round (genesis-pinned). When K = M_pool every
    // registered creator is on every committee (strong mode). When K < M_pool,
    // the committee rotates through the eligible pool (hybrid mode; v2
    // delivers the M_pool−K silent tolerance).
    void set_k_block_sigs(uint32_t K) { k_block_sigs_ = K; }
    void set_m_pool(uint32_t M)       { m_pool_ = M; }

    // rev.8 per-height BFT escalation. When `bft_enabled_` is true, validator
    // accepts BFT-mode blocks if their abort count satisfies the threshold.
    void set_bft_enabled(bool en)             { bft_enabled_ = en; }
    void set_bft_escalation_threshold(uint32_t t) { bft_escalation_threshold_ = t; }

    // rev.9 (B1): epoch-relative committee derivation parameters.
    void set_epoch_blocks(uint32_t e) { epoch_blocks_ = e; }
    void set_shard_id(ShardId s)      { shard_id_ = s; }

    // rev.9 R2: this chain's committee_region (mirrored from genesis).
    // Empty = global pool — check_creator_selection / check_abort_certs
    // see the full registry pool (pre-R2 behavior). Non-empty restricts
    // the eligible pool via NodeRegistry::eligible_in_region(region_).
    void set_committee_region(const std::string& r) { committee_region_ = r; }

    // A6: deployment-wide sharding mode (mirrored from the operator's
    // selected TimingProfile). Drives mode-incompatible-tx gates in
    // check_transactions:
    //   NONE     — REGISTER with non-empty region rejected; only
    //              SINGLE chain_role accepted at startup; MERGE_EVENT
    //              (R7, not yet defined) rejected.
    //   CURRENT  — REGISTER region tolerated but ignored (pre-R1
    //              backward compat); MERGE_EVENT rejected.
    //   EXTENDED — REGISTER region accepted (R1); MERGE_EVENT accepted
    //              (R7 will install the apply path).
    void set_sharding_mode(ShardingMode m) { sharding_mode_ = m; }

    // A5: governance mode mirrored from genesis. 0 = uncontrolled
    // (PARAM_CHANGE rejected outright); 1 = governed (PARAM_CHANGE
    // validated against keyholder set + threshold over a whitelisted
    // parameter name set).
    void set_governance_mode(uint8_t m)            { governance_mode_ = m; }
    void set_param_keyholders(std::vector<PubKey> ks) {
        param_keyholders_ = std::move(ks);
    }
    void set_param_threshold(uint32_t t)           { param_threshold_ = t; }

    // rev.9 B2c.2-full: when the validator runs on a SHARD chain, the
    // committee-selection rand must come from the BEACON's chain, not the
    // shard's own. The Node installs this provider so the validator can
    // resolve the cumulative_rand of the beacon block at the requested
    // epoch_start_height. Returning nullopt means "no beacon header
    // available at that height yet" — the validator falls back to the
    // local chain (early-bootstrap path; shard registry mirrors beacon at
    // genesis, so behavior is identical until headers begin to land).
    using EpochRandProvider =
        std::function<std::optional<Hash>(uint64_t epoch_start_height)>;
    void set_external_epoch_rand_provider(EpochRandProvider p) {
        external_epoch_rand_ = std::move(p);
    }

    Result validate(const chain::Block& b,
                    const chain::Chain& chain,
                    const NodeRegistry& registry) const;

private:
    Result check_prev_hash(const chain::Block& b, const chain::Chain& chain) const;
    Result check_creators_registered(const chain::Block& b, const NodeRegistry& registry) const;
    Result check_creator_selection(const chain::Block& b, const NodeRegistry& registry,
                                   const chain::Chain& chain) const;
    Result check_creator_tx_commitments(const chain::Block& b, const NodeRegistry& registry) const;
    Result check_creator_dh_secrets(const chain::Block& b, const NodeRegistry& registry) const;
    Result check_delay(const chain::Block& b) const;
    Result check_block_sigs(const chain::Block& b, const NodeRegistry& registry,
                             const chain::Chain& chain) const;
    Result check_abort_certs(const chain::Block& b, const chain::Chain& chain,
                              const NodeRegistry& registry) const;
    Result check_equivocation_events(const chain::Block& b,
                                       const NodeRegistry& registry) const;
    // rev.9 B3.2: cross_shard_receipts must match the cross-shard
    // subset of transactions[] in order, with consistent fields.
    // SINGLE chains expect an empty receipts list.
    Result check_cross_shard_receipts(const chain::Block& b,
                                        const chain::Chain& chain) const;
    // rev.9 B3.4: inbound_receipts (this block credits them) shape +
    // dedup checks. Each entry must have dst_shard == this chain's
    // shard_id, src_shard != this chain's shard_id, tx_hash unique
    // within the block, and not previously applied. SINGLE / BEACON
    // chains expect an empty list.
    Result check_inbound_receipts(const chain::Block& b,
                                    const chain::Chain& chain) const;
    Result check_cumulative_rand(const chain::Block& b, const chain::Chain& chain) const;
    Result check_transactions(const chain::Block& b, const chain::Chain& chain,
                               const NodeRegistry& registry) const;
    Result check_timestamp(const chain::Block& b) const;

    // Resolve the rand source at `epoch_start_height` for committee
    // selection. Consults the external provider first; on miss, falls
    // back to chain.at(epoch_start - 1).cumulative_rand or chain.head()
    // if epoch_start sits outside the chain.
    Hash resolve_epoch_rand(uint64_t epoch_start,
                              const chain::Chain& chain) const;

    uint32_t k_block_sigs_{0};
    uint32_t m_pool_{0};
    bool     bft_enabled_{true};
    uint32_t bft_escalation_threshold_{5};
    uint32_t epoch_blocks_{1000};
    ShardId  shard_id_{0};
    // rev.9 R2: committee region pin for this chain (empty = global).
    std::string committee_region_{};
    // A6: sharding mode mirrored from the operator's selected
    // TimingProfile. Default CURRENT preserves legacy behavior for any
    // call site that constructs BlockValidator without an explicit setter.
    ShardingMode sharding_mode_{ShardingMode::CURRENT};
    // A5: governance state mirrored from genesis.
    uint8_t      governance_mode_{0};
    std::vector<PubKey> param_keyholders_{};
    uint32_t     param_threshold_{0};
    EpochRandProvider external_epoch_rand_{};
};

} // namespace determ::node
