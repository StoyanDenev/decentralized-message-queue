#pragma once
#include <cstdint>

namespace dhcoin::chain {

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
// Operators pick a profile at init (cluster / web / regional / global). All
// timers are local; consensus correctness depends on K-of-K quorum +
// commit-reveal randomness (rev.9 S-009), not on clock alignment.

struct TimingProfile {
    uint32_t tx_commit_ms;
    uint32_t block_sig_ms;
    uint32_t abort_claim_ms;
    // M_pool and K committee size, picked at genesis init. Strong (K = M)
    // preferred for tightly-paired LANs; hybrid (K < M) is a v2 deliverable.
    uint32_t m_creators;
    uint32_t k_block_sigs;
};

inline constexpr TimingProfile PROFILE_CLUSTER  {  50,  50,  25, 3, 3 };  // strong
inline constexpr TimingProfile PROFILE_WEB      { 200, 200, 100, 3, 2 };  // hybrid (default)
inline constexpr TimingProfile PROFILE_REGIONAL { 300, 300, 150, 5, 4 };  // hybrid
inline constexpr TimingProfile PROFILE_GLOBAL   { 600, 600, 300, 7, 5 };  // hybrid

} // namespace dhcoin::chain
