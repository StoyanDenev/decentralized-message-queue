#pragma once
#include <dhcoin/chain/block.hpp>
#include <string>
#include <vector>

namespace dhcoin::chain {

// ─── Genesis configuration ──────────────────────────────────────────────────
// A GenesisConfig fully specifies a chain's initial state. Operators distribute
// the JSON form before bootstrap; everyone confirms the derived genesis hash
// before they will run nodes against it.

struct GenesisCreator {
    std::string domain;
    PubKey      ed_pub{};         // Ed25519 pubkey
    uint64_t    initial_stake{0}; // staked at genesis; counts toward MIN_STAKE
};

struct GenesisAllocation {
    std::string domain;
    uint64_t    balance{0};
};

struct GenesisConfig {
    std::string                     chain_id;
    uint32_t                        m_creators{3};
    // Rev. 3 dual-mode: K = M = strong BFT (full unanimity); K < M = weak
    // BFT (Phase 2 K-of-M threshold). Phase 1 unanimity unchanged across
    // modes — censorship resistance is identical.
    // Constraint: 1 <= k_block_sigs <= m_creators. Default = m_creators (strong).
    uint32_t                        k_block_sigs{3};
    // Rev. 4: per-block reward minted to creators alongside fees ("page reward"
    // from the original DHCoin spec). Genesis-pinned. 0 = no subsidy (fees only).
    uint64_t                        block_subsidy{0};

    // Rev. 8 per-height BFT escalation. When `bft_enabled` is true, after
    // `bft_escalation_threshold` consecutive Phase-1 aborts at the same
    // height, the next round escalates from MD K-of-K to BFT ceil(2K/3) +
    // designated proposer. False = MD-only (rev.7 behavior; chain may halt
    // on persistent silent committee member, by design).
    bool                            bft_enabled{true};
    uint32_t                        bft_escalation_threshold{5};

    // Rev. 9 sharding role. SINGLE preserves rev.8 behavior (one chain,
    // no shards). BEACON / SHARD are the two roles in the sharded
    // architecture; they're parsed and stored at this level so a single
    // genesis JSON can describe either an unsharded chain or one chain
    // within a sharded deployment.
    ChainRole                       chain_role{ChainRole::SINGLE};
    ShardId                         shard_id{0};                    // 0 for SINGLE/BEACON
    uint32_t                        initial_shard_count{1};         // 1 = unsharded
    uint32_t                        epoch_blocks{1000};             // E (Stage B1)
    Hash                            shard_address_salt{};           // CSPRNG-generated at build time

    std::vector<GenesisCreator>     initial_creators;
    std::vector<GenesisAllocation>  initial_balances;

    nlohmann::json       to_json() const;
    static GenesisConfig from_json(const nlohmann::json& j);
    static GenesisConfig load(const std::string& path);
    void                 save(const std::string& path) const;
};

// Build the canonical genesis block from a config.
Block make_genesis_block(const GenesisConfig& cfg);

// Deterministic hash of the genesis configuration. Operators pin this in their
// node config; the node refuses to start against a chain whose block 0 hash
// disagrees.
Hash compute_genesis_hash(const GenesisConfig& cfg);

// Legacy zeros-genesis: kept for tests / no-config fallback.
Block make_genesis(const std::string& seed = "dhcoin-genesis-2026");

} // namespace dhcoin::chain
