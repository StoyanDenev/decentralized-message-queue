#pragma once
#include <dhcoin/chain/block.hpp>
#include <dhcoin/chain/chain.hpp>
#include <dhcoin/node/registry.hpp>
#include <cstdint>
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
    Result check_block_sigs(const chain::Block& b, const NodeRegistry& registry) const;
    Result check_abort_certs(const chain::Block& b, const chain::Chain& chain,
                              const NodeRegistry& registry) const;
    Result check_cumulative_rand(const chain::Block& b, const chain::Chain& chain) const;
    Result check_transactions(const chain::Block& b, const chain::Chain& chain,
                               const NodeRegistry& registry) const;
    Result check_timestamp(const chain::Block& b) const;

    uint64_t delay_T_{0};
    uint32_t k_block_sigs_{0};
    uint32_t m_pool_{0};
};

} // namespace dhcoin::node
