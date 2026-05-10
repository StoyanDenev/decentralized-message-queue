#pragma once
#include <cstddef>
#include <cstdint>
#include "determ/types.hpp"

namespace determ::chain {

using ChainRole    = ::determ::ChainRole;
using ShardingMode = ::determ::ShardingMode;

// ─── L1 (Identity) parameters ───────────────────────────────────────────────
// Chain-wide constants. A domain is eligible for creator selection only while
// stake_table[domain].locked >= MIN_STAKE.

inline constexpr uint64_t MIN_STAKE     = 1000;
inline constexpr uint64_t UNSTAKE_DELAY = 1000;   // blocks past inactive_from before stake unlocks

// REGISTER tx payload (rev.9 R1):
//   [pubkey: 32B][region_len: u8][region: utf8 bytes]
// Legacy payload (just the 32-B pubkey) is wire-compatible — region_len
// defaults to 0 (empty region = global pool) and the trailing bytes
// are absent. The tx's own Ed25519 signature serves as proof-of-
// possession of the registered key, and binds the region into the tx
// hash via Transaction::signing_bytes() (which already includes the
// full payload).
inline constexpr size_t REGISTER_PAYLOAD_PUBKEY_SIZE = 32;
inline constexpr size_t REGISTER_REGION_MAX          = 32;
// Minimum payload size: pubkey only (legacy / empty-region). Maximum:
// pubkey + region_len byte + 32 region bytes.
inline constexpr size_t REGISTER_PAYLOAD_MIN_SIZE = REGISTER_PAYLOAD_PUBKEY_SIZE;
inline constexpr size_t REGISTER_PAYLOAD_MAX_SIZE = REGISTER_PAYLOAD_PUBKEY_SIZE + 1
                                                       + REGISTER_REGION_MAX;
// Backward-compat alias — pre-R1 callers used REGISTER_PAYLOAD_SIZE for
// the fixed 32-byte pubkey-only payload. Still valid as an exact size
// for region-less REGISTER txs.
inline constexpr size_t REGISTER_PAYLOAD_SIZE = REGISTER_PAYLOAD_PUBKEY_SIZE;

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

// Test profiles — sub-30ms rounds for fast CI execution. Each `*_test`
// profile mirrors its production counterpart's (chain_role, sharding_mode,
// M, K) posture exactly. The only difference is the round-timer triple, so
// CI exercises the same code paths a production deployment would.
//
// Test-runner tunable: if a loaded CI host triggers spurious aborts on
// these timers, bump TEST_*_MS in this file (one-place change) rather
// than per-test overrides.
inline constexpr uint32_t TEST_TX_COMMIT_MS   = 5;
inline constexpr uint32_t TEST_BLOCK_SIG_MS   = 5;
inline constexpr uint32_t TEST_ABORT_CLAIM_MS = 3;

// SINGLE+NONE single-chain test profile. Used by tests that deploy one
// chain (no beacon/shard split). No production counterpart — single-chain
// deployments are inherently a degenerate of the sharding model — but
// having a dedicated test profile keeps the single-chain regression suite
// independent of any sharding wiring.
inline constexpr TimingProfile PROFILE_SINGLE_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SINGLE, ShardingMode::NONE
};

// `cluster_test` mirrors prod `cluster`: BEACON + CURRENT, M=K=3 strong.
inline constexpr TimingProfile PROFILE_CLUSTER_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::BEACON, ShardingMode::CURRENT
};
// `web_test` mirrors prod `web`: SHARD + EXTENDED, M=3 K=2 hybrid.
inline constexpr TimingProfile PROFILE_WEB_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 2,
    ChainRole::SHARD, ShardingMode::EXTENDED
};
// `regional_test` mirrors prod `regional`: SHARD + CURRENT, M=5 K=4 hybrid.
inline constexpr TimingProfile PROFILE_REGIONAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 5, 4,
    ChainRole::SHARD, ShardingMode::CURRENT
};
// `global_test` mirrors prod `global`: BEACON + EXTENDED, M=7 K=5 hybrid.
inline constexpr TimingProfile PROFILE_GLOBAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 7, 5,
    ChainRole::BEACON, ShardingMode::EXTENDED
};
// `tactical_test` mirrors prod `tactical`: SHARD + EXTENDED, M=K=3 strong.
inline constexpr TimingProfile PROFILE_TACTICAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED
};

} // namespace determ::chain
