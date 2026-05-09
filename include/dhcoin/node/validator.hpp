#pragma once
#include <dhcoin/chain/block.hpp>
#include <dhcoin/chain/chain.hpp>
#include <dhcoin/node/registry.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace dhcoin::node {

class BlockValidator {
public:
    BlockValidator() = default;

    struct Result {
        bool        ok{false};
        std::string error;
    };

    // delay_T is the iteration count the chain agreed on (genesis-pinned per
    // profile). The validator must reject blocks that don't carry an output
    // matching this T.
    void set_delay_T(uint64_t T) { delay_T_ = T; }

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

    uint64_t delay_T_{0};
    uint32_t k_block_sigs_{0};
    uint32_t m_pool_{0};
    bool     bft_enabled_{true};
    uint32_t bft_escalation_threshold_{5};
    uint32_t epoch_blocks_{1000};
    ShardId  shard_id_{0};
    EpochRandProvider external_epoch_rand_{};
};

} // namespace dhcoin::node
