// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <string>
#include <vector>

namespace determ::chain {

// rev.8 follow-on: validator inclusion policy. Both modes preserve the
// same decentralization property — K-of-K mutual veto + union tx_root
// means a single honest validator in the registry, anywhere, eventually
// gets selected and unions any censored tx into a block. Censorship
// requires unanimous collusion of EVERY validator that ever rotates onto
// any committee, which is structurally impossible without 100% adversary
// capture of the registry.
//
// The two modes differ only in HOW validators are admitted to the
// registry (Sybil-resistance mechanism + disincentive medium):
//
//   STAKE_INCLUSION  — admission via locking min_stake. Sybil cost =
//                      capital lock-up. Disincentive on misbehavior =
//                      stake forfeit (suspension slash + equivocation
//                      forfeit).
//
//   DOMAIN_INCLUSION — admission via registering with a domain name
//                      (e.g., a DNS name like validator1.example.com).
//                      min_stake = 0. Sybil cost = domain registration.
//                      Disincentive on misbehavior = registry
//                      deregistration (lose all future block rewards;
//                      re-entry costs a fresh registration).
//
// Both modes use the same K-of-K consensus, BFT escalation, delay-hash
// randomness, and equivocation detection. Choice is purely about which
// Sybil/disincentive medium suits the deployment.
enum class InclusionModel : uint8_t {
    STAKE_INCLUSION  = 0,
    DOMAIN_INCLUSION = 1,
};

inline const char* to_string(InclusionModel m) {
    switch (m) {
    case InclusionModel::STAKE_INCLUSION:  return "stake-inclusion";
    case InclusionModel::DOMAIN_INCLUSION: return "domain-inclusion";
    }
    return "?";
}

// ─── Genesis configuration ──────────────────────────────────────────────────
// A GenesisConfig fully specifies a chain's initial state. Operators distribute
// the JSON form before bootstrap; everyone confirms the derived genesis hash
// before they will run nodes against it.

struct GenesisCreator {
    std::string domain;
    PubKey      ed_pub{};         // Ed25519 pubkey
    uint64_t    initial_stake{0}; // staked at genesis; counts toward MIN_STAKE
    // rev.9 R1: optional region tag, declared at genesis for the initial
    // creator set (mirrors what later REGISTER txs carry). Empty string =
    // global pool (backward-compat: existing genesis files unchanged).
    // Normalized to lowercase ASCII; charset [a-z0-9-_], max 32 bytes.
    std::string region{};
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
    // from the original Determ spec). Genesis-pinned. 0 = no subsidy (fees only).
    uint64_t                        block_subsidy{0};
    // E4: optional cap on total cumulative subsidy ever paid. 0 (default)
    // preserves the historical perpetual-subsidy behavior — chain mints
    // `block_subsidy` per block forever. Non-zero installs a finite
    // self-terminating subsidy fund: once cumulative paid subsidy reaches
    // this value, subsequent blocks distribute only transaction fees.
    // Pairs with A1 unitary-balance invariant — accumulated_subsidy_
    // tracks the actually-paid amount, so the invariant holds across
    // the exhaustion transition.
    uint64_t                        subsidy_pool_initial{0};
    // E3: subsidy distribution mode.
    //   FLAT     (0, default): each block pays `block_subsidy` evenly across
    //                          creators. Steady, predictable, current behavior.
    //   LOTTERY  (1): each block draws from a two-point distribution seeded by
    //                 the block's `cumulative_rand`. Probability `1/M` of paying
    //                 `block_subsidy * M`, otherwise 0. Expected value per block
    //                 equals FLAT subsidy — total issuance schedule unchanged.
    //                 M = `lottery_jackpot_multiplier` (must be >= 2).
    // Pairs cleanly with E4 finite subsidy fund: lottery payouts still cap at
    // remaining pool; once drained, lottery silently stops paying.
    uint8_t                         subsidy_mode{0};                 // 0=FLAT, 1=LOTTERY
    uint32_t                        lottery_jackpot_multiplier{0};   // required when LOTTERY, ignored when FLAT
    // E1: optional Negative Entry Fee (NEF). When > 0, a pseudo-account at
    // the all-zero anon address (0x0000…0000) is credited with this balance
    // at genesis. On each REGISTER tx applied, half the current pool balance
    // is transferred from the pool to the new registrant — bootstrap-time
    // reward for early registrants. Pool drains geometrically (halves per
    // registration), asymptotes to 0. Pool exhaustion does NOT block
    // future REGISTERs; NEF just degrades to 0. 0 (default) preserves
    // historical behavior (no pool, no NEF). The pool counts toward A1's
    // genesis_total_; NEF is a balance transfer (pool -> new domain),
    // not a mint, so the unitary invariant holds trivially.
    uint64_t                        zeroth_pool_initial{0};

    // Rev. 8 per-height BFT escalation. When `bft_enabled` is true, after
    // `bft_escalation_threshold` consecutive Phase-1 aborts at the same
    // height, the next round escalates from MD K-of-K to BFT ceil(2K/3) +
    // designated proposer. False = MD-only (rev.7 behavior; chain may halt
    // on persistent silent committee member, by design).
    bool                            bft_enabled{true};
    uint32_t                        bft_escalation_threshold{5};

    // Rev. 8 follow-on: validator inclusion policy. Default is
    // STAKE_INCLUSION (preserves rev.7/8 stake-based behavior).
    // DOMAIN_INCLUSION chains pin min_stake = 0 (no stake gate);
    // equivocation still deregisters the validator regardless of mode.
    InclusionModel                  inclusion_model{InclusionModel::STAKE_INCLUSION};
    // Min stake threshold for validator eligibility. Default 1000 for
    // STAKE_INCLUSION; DOMAIN_INCLUSION chains pin this to 0.
    // Genesis-pinned (mutable post-genesis only via A5 PARAM_CHANGE).
    uint64_t                        min_stake{1000};

    // A5 Phase 3: economic policy fields promoted from static constants
    // in params.hpp to genesis-pinned, governance-mutable parameters.
    // Defaults preserve pre-A5 behavior. Backward-compat: pre-Phase-3
    // genesis files omit these and pick up the defaults silently;
    // genesis-hash mix only includes them when they differ from the
    // default so existing chain identities remain stable.
    uint64_t                        suspension_slash{10};
    uint64_t                        unstake_delay{1000};

    // R4: under-quorum merge thresholds. Backward-compat: pre-R4 genesis
    // files omit these and pick up defaults silently. Genesis-hash mix
    // skips them when they equal defaults.
    //   merge_threshold_blocks: consecutive beacon-blocks of
    //     eligible_in_region(S) < 2K + no SHARD_TIP_S before MERGE_BEGIN
    //     fires (~2.5 min on the web profile at default).
    //   revert_threshold_blocks: 2:1 hysteresis on the way back. Default
    //     200 (~5 min). Higher than merge threshold to bias toward
    //     stability — once merged, do not flap.
    //   merge_grace_blocks: gap between block.height and the BEGIN's
    //     effective_height. Lets shard committees observe the upcoming
    //     transition before it takes effect.
    uint32_t                        merge_threshold_blocks{100};
    uint32_t                        revert_threshold_blocks{200};
    uint32_t                        merge_grace_blocks{10};

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

    // rev.9 R1: per-shard committee region pin. Empty = global pool
    // (backward-compat — existing deployments hash-stable). Non-empty
    // restricts this chain's K-committee selection to validators
    // tagged with the same region. Normalized to lowercase ASCII;
    // charset [a-z0-9-_], max 32 bytes. Mixed into compute_genesis_hash
    // so two shards differing only in committee_region have distinct
    // genesis hashes.
    std::string                     committee_region{};

    // A5: governance mode. 0 = uncontrolled (consensus constants are
    // genesis-pinned and immutable forever; current behavior — preserves
    // byte-identical hashes for existing genesis files). 1 = governed
    // (N-of-N keyholder multisig may emit PARAM_CHANGE txs to mutate a
    // whitelisted parameter set mid-chain).
    //
    // Under governed mode, `param_keyholders` lists the deployment's
    // founder Ed25519 pubkeys (set at genesis-build time, immutable
    // except via PARAM_CHANGE referencing `param_keyholders` itself).
    // `param_threshold` is the signature count required to ratify a
    // PARAM_CHANGE; default = param_keyholders.size() (N-of-N).
    //
    // Whitelist of mutable parameter names (validator-enforced; off-list
    // names rejected even with full N-of-N): `tx_commit_ms`,
    // `block_sig_ms`, `abort_claim_ms`, `bft_escalation_threshold`,
    // `SUSPENSION_SLASH`, `MIN_STAKE`, `UNSTAKE_DELAY`,
    // `param_keyholders`, `param_threshold`. Off-list parameters
    // (committee size K, consensus mode, sharding mode, chain identity,
    // crypto primitives) require a new genesis = new chain.
    uint8_t                         governance_mode{0};
    std::vector<PubKey>             param_keyholders;
    uint32_t                        param_threshold{0};

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
Block make_genesis(const std::string& seed = "determ-genesis-2026");

} // namespace determ::chain
