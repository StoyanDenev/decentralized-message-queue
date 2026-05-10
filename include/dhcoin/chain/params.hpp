#pragma once
#include <cstddef>
#include <cstdint>
#include "dhcoin/types.hpp"

namespace dhcoin::chain {

using ChainRole    = ::dhcoin::ChainRole;
using ShardingMode = ::dhcoin::ShardingMode;

// ─── L1 (Identity) parameters ───────────────────────────────────────────────
// Chain-wide constants. A domain is eligible for creator selection only while
// stake_table[domain].locked >= MIN_STAKE.

inline constexpr uint64_t MIN_STAKE     = 1000;
inline constexpr uint64_t UNSTAKE_DELAY = 1000;   // blocks past inactive_from before stake unlocks

// REGISTER tx payload: just the Ed25519 pubkey (32 B). The tx's own Ed25519
// signature serves as proof-of-possession of the registered key.
inline constexpr size_t REGISTER_PAYLOAD_SIZE = 32;

// rev.8 economic disincentive on abort suspension. Deducted from the
// validator's stake at the moment an AbortEvent for this domain is baked
// into a finalized block. Required for BFT-mode safety claims (BFT
// safety conditional on f<N/3 + slashing). 100 suspensions exits a
// minimally-staked validator (10 * 100 = 1000 = MIN_STAKE).
inline constexpr uint64_t SUSPENSION_SLASH = 10;

// ─── L4 (Consensus) timing profiles ─────────────────────────────────────────
// Operators pick a profile at init. Each profile fully specifies timing,
// committee size, chain role, and sharding mode — there is no CLI override
// for role or mode. Pick a different profile to change them.

struct TimingProfile {
    uint32_t     tx_commit_ms;
    uint32_t     block_sig_ms;
    uint32_t     abort_claim_ms;
    uint32_t     m_creators;
    uint32_t     k_block_sigs;
    ChainRole    chain_role;
    ShardingMode sharding_mode;
};

inline constexpr TimingProfile PROFILE_CLUSTER {
    50, 50, 25, 3, 3, ChainRole::BEACON, ShardingMode::CURRENT
};
inline constexpr TimingProfile PROFILE_WEB {
    200, 200, 100, 3, 2, ChainRole::SHARD, ShardingMode::EXTENDED
};
inline constexpr TimingProfile PROFILE_REGIONAL {
    300, 300, 150, 5, 4, ChainRole::SHARD, ShardingMode::CURRENT
};
inline constexpr TimingProfile PROFILE_GLOBAL {
    600, 600, 300, 7, 5, ChainRole::BEACON, ShardingMode::EXTENDED
};

// Tactical profile — Layer-1 swarm coordination for unmanned mobile units
// (drones, robots) operating within radio range. ~40 ms typical block
// finality (20 + 20). K=M=3 strong: maximum mutual distrust, no BFT
// downgrade tolerance for safety-relevant decisions. SHARD + EXTENDED:
// regional grouping by physical proximity; under-quorum merge folds units
// that fly out of range into the neighboring cluster automatically.
inline constexpr TimingProfile PROFILE_TACTICAL {
    20, 20, 10, 3, 3, ChainRole::SHARD, ShardingMode::EXTENDED
};

// Test profiles — sub-30ms rounds for fast CI execution. Timer values pulled
// out as named constants so they can be tuned in one place if a loaded test
// runner triggers spurious aborts.
inline constexpr uint32_t TEST_TX_COMMIT_MS   = 5;
inline constexpr uint32_t TEST_BLOCK_SIG_MS   = 5;
inline constexpr uint32_t TEST_ABORT_CLAIM_MS = 3;

inline constexpr TimingProfile PROFILE_CLUSTER_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SINGLE, ShardingMode::NONE
};
inline constexpr TimingProfile PROFILE_WEB_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED
};
inline constexpr TimingProfile PROFILE_REGIONAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::CURRENT
};
inline constexpr TimingProfile PROFILE_GLOBAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED
};
inline constexpr TimingProfile PROFILE_TACTICAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED
};

} // namespace dhcoin::chain
