// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
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

// A5 Phase 3: MIN_STAKE / UNSTAKE_DELAY / SUSPENSION_SLASH are promoted
// to per-Chain instance state (Chain::min_stake_, Chain::unstake_delay_,
// Chain::suspension_slash_) so the governance whitelist can mutate them
// via PARAM_CHANGE. These constants remain as build-time defaults; the
// genesis loader uses them when the corresponding field is absent.
inline constexpr uint64_t MIN_STAKE     = 1000;
inline constexpr uint64_t UNSTAKE_DELAY = 1000;   // blocks past inactive_from before stake unlocks

// Abort-punishment suspension parameters. A Phase-1 (round==1) abort
// suspends a domain from creator selection for BASE * 2^(count-1) blocks,
// capped at MAX_SUSPENSION_BLOCKS with the exponent capped at
// MAX_ABORT_EXPONENT. Defined here (chain-visible) rather than in
// node/registry.hpp so that BOTH the node-side selection filter
// (NodeRegistry::build_from_chain) and any chain-layer consumer
// (Chain::freeze_epoch_committee, D3.3b) read one authoritative
// definition — a divergence between the live filter and a frozen
// committee checkpoint would be a state_root fork. node/registry.hpp
// re-exports these into determ::node via `using` for source compatibility.
inline constexpr uint64_t BASE_SUSPENSION_BLOCKS = 10;
inline constexpr uint64_t MAX_SUSPENSION_BLOCKS  = 10'000;
inline constexpr uint64_t MAX_ABORT_EXPONENT     = 10;   // 2^10 = 1024

// E1: Zeroth pool pseudo-account address. Anon-style format (0x + 64 hex
// chars), but encodes an all-zero pubkey — a low-order point on
// curve25519 that has no usable Ed25519 private key. Any tx claiming
// `from == ZEROTH_ADDRESS` must produce a valid Ed25519 sig over an
// all-zero pubkey, which is computationally infeasible; the validator
// rejects such txs as an explicit guard regardless.
inline constexpr const char* ZEROTH_ADDRESS =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

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

// A4 TRANSFER payload cap. Optional, application-defined bytes carried
// on TRANSFER for memos, off-chain pointers, fixed-prefix tags, CBOR
// blobs, etc. Empty payload (the historical default) stays byte-identical
// on the wire. Cap is enforced by the validator.
inline constexpr size_t TRANSFER_PAYLOAD_MAX = 128;

// rev.8 economic disincentive on abort suspension. Deducted from the
// validator's stake at the moment an AbortEvent for this domain is baked
// into a finalized block. Required for BFT-mode safety claims (BFT
// safety conditional on f<N/3 + slashing). 100 suspensions exits a
// minimally-staked validator (10 * 100 = 1000 = MIN_STAKE).
inline constexpr uint64_t SUSPENSION_SLASH = 10;

// ─── L4 (Consensus) timing profiles ─────────────────────────────────────────
// Operators pick a profile at init. Each profile fully specifies timing,
// committee size, chain role, sharding mode, AND cryptographic posture —
// there is no CLI override for role or mode or crypto. Pick a different
// profile to change them.

// Cryptographic stack selection. Bundled into the timing profile because
// deployment scenarios that demand FIPS-compliant cryptography (military,
// CBDC, government, regulated healthcare) tend to also demand specific
// timing characteristics (typically tactical-grade or regional-grade).
// Bundling crypto with timing reflects this real-world alignment rather
// than exposing two orthogonal selection axes.
//
// NOTE (crypto is a POSTURE, not a code switch — see the TimingProfile note
// below, DECISION-LOG 2026-07-03): the one binary contains all algorithms; the
// profile documents the intended algorithm PREFERENCE, and real FIPS 140
// compliance is a deployment property (a pluggable CMVP-validated module).
//
//   MODERN: cryptographically-strongest defaults — XChaCha20-Poly1305 AEAD,
//           Argon2id passphrase KDF, Ed25519 signatures, X25519 KX. Confidential
//           transactions ride the profile-agnostic P-256 shielded pool (§3.22) —
//           the same wired backend FIPS uses; MODERN adds NO separate ZK curve
//           (secp256k1 never built; a big-prime Z_p* backend was considered and
//           removed 2026-07-07). The DSSO DApp's T-OPRF rides the same
//           profile-agnostic P-256 stack (threshold-OPAQUE, t-of-n RFC 9497 VOPRF —
//           docs/proofs/v2.25-DSSO-DAPP-SPEC.md; X25519 is share-envelope
//           transport only). Faster + safer with random nonces; not FIPS-validated.
//           Default for non-FIPS deployments.
//
//   FIPS:   FIPS-ALIGNED posture — AES-256-GCM AEAD (FIPS 197 + SP 800-38D),
//           PBKDF2-HMAC-SHA-256 passphrase KDF (SP 800-132; substantially weaker
//           than Argon2id), NIST P-256 for prime-order needs. Confidential
//           transactions (Pedersen + Bulletproofs over P-256, §3.19 / the §3.22
//           shielded pool) AND input-unlinkability ring signatures (§3.23) ARE
//           available and are built on FIPS-approved primitives (P-256 + SHA-256)
//           — but the ZK CONSTRUCTIONS themselves are NOT FIPS-validated
//           ALGORITHMS (NIST has no approved range-proof / ring-signature
//           standard), so a deployment requiring per-operation CMVP validation
//           treats them as out-of-module. P-256 OPRF for T-OPAQUE. Required for
//           military/defense/government/regulated-healthcare deployments.
//           Mandated for tactical profile.
enum class CryptoProfile : uint8_t {
    MODERN = 0,
    FIPS   = 1,
};

inline const char* to_string(CryptoProfile cp) {
    switch (cp) {
        case CryptoProfile::MODERN: return "MODERN";
        case CryptoProfile::FIPS:   return "FIPS";
    }
    return "UNKNOWN";
}

// ─── Consensus committee-size helpers (SHARED producer/validator formulas) ──
// These must be computed identically on the producer (Node::check_if_selected)
// and validator (BlockValidator::check_creator_selection / check_abort_certs)
// sides — an asymmetry between the two is the S-043 class of total-outage bug.
// Defining them once here is the guard against that.
//
// bft_committee_size: the escalated committee size k_bft = ceil(2K/3), used when
// the abort-adjusted pool cannot staff a full K-of-K committee.
inline constexpr size_t bft_committee_size(size_t k_block_sigs) {
    return (2 * k_block_sigs + 2) / 3;   // ceil(2K/3)
}

// abort_claim_quorum: the number of distinct AbortClaim signatures required to
// form an AbortEvent against a missing committee member. S-044 fix (F-a,
// AbortCascadeLiveness.md §4.1): floor of 2. For K>=3 this equals K-1 (no
// change); for K=2 it makes the quorum UNSATISFIABLE (only one eligible claimer
// exists against a given missing member, since claimer != missing_creator), so
// no single-claim abort event can form — eliminating the K=2 wedge-by-cascade
// in favour of a crash-stop halt-by-single-death. committee_size==0 yields 0
// (degenerate; caller guards). The producer, gossip-adoption, and validator
// paths all route through this one definition.
inline constexpr size_t abort_claim_quorum(size_t committee_size) {
    if (committee_size == 0) return 0;
    size_t k_minus_1 = committee_size - 1;
    return k_minus_1 < 2 ? 2 : k_minus_1;   // max(2, K-1)
}

struct TimingProfile {
    uint32_t      tx_commit_ms;
    uint32_t      block_sig_ms;
    uint32_t      abort_claim_ms;
    uint32_t      m_creators;
    uint32_t      k_block_sigs;
    ChainRole     chain_role;
    ShardingMode  sharding_mode;
    // Documented ALGORITHM POSTURE of the deployment archetype (MODERN =
    // XChaCha20-Poly1305/Argon2id preference; FIPS = AES-256-GCM/PBKDF2/
    // P-256, FIPS-approved algorithms only). One binary serves both
    // postures (DECISION-LOG.md 2026-07-03: the former DETERM_CRYPTO
    // build tri-state was removed — it linked identical code and could
    // not confer FIPS 140 compliance). Actual FIPS 140 compliance is a
    // DEPLOYMENT property: a FIPS deployment pairs this posture with a
    // pluggable CMVP-validated crypto module (future provider interface);
    // algorithm selection alone does not confer compliance.
    CryptoProfile crypto_profile;
};

// Cluster profile — in-house enterprise / financial services / regulated
// single-cluster deployments. BEACON + CURRENT (no sharding; one chain),
// K=M=3 strong (full mutual distrust within a consortium of validators),
// 50ms blocks (responsive but not tactical-grade). Typical use cases:
// in-house bank settlement, single-organization permissioned chain, small
// regulated consortium, single-org CBDC component.
//
// FIPS crypto profile mandated: financial services + banking + regulated-
// healthcare deployments require FIPS 140-2/3 compliant cryptography. NH4
// military-grade certification path and NH6 NIS 2 / NIST CSF / HIPAA
// regulatory compliance both require FIPS-validated primitives.
// Trade-offs of FIPS that operators accept by choosing cluster:
//   - PBKDF2 instead of Argon2id (weaker passphrase hashing — operators
//     mitigate by enforcing strong-password policy or hardware-protected keys)
//   - NIST P-256 ECDH for KX (vs the MODERN profile's X25519); confidential-tx is P-256 in both
//   - Confidential-tx ZK (P-256 range proofs / ring signatures) is FIPS-ALIGNED
//     (built on P-256 + SHA-256) but NOT a FIPS-validated ALGORITHM — a deployment
//     needing per-op CMVP validation treats it as out-of-module
//   - AES-256-GCM instead of XChaCha20-Poly1305 (FIPS-validated AEAD)
//
// Non-FIPS commercial single-cluster deployments (small commercial
// consortium without regulatory requirement) should use `web` profile
// (200ms blocks, SHARD+EXTENDED, MODERN crypto) — sharding is fine for
// single-region single-cluster commercial use; confidential transactions
// available.
inline constexpr TimingProfile PROFILE_CLUSTER {
    50, 50, 25, 3, 3, ChainRole::BEACON, ShardingMode::CURRENT,
    CryptoProfile::FIPS
};
// Web profile — internet-facing / commercial hybrid. SHARD + EXTENDED,
// MODERN crypto, 200 ms blocks. M=4 K=3 hybrid (weak, K<M): a 4-validator
// pool signing 3-of-4, so ONE straggling/dead member still forms a full
// K-of-K MD committee from the remaining 3 (MD margin M-K = 1) — the common
// single-fault case runs in strong mutual-distrust mode, not a degraded BFT
// fallback. S-044/S-045 fix (AbortCascadeLiveness.md, 2026): the historical
// M=3 K=2 default was the exposed configuration — K=2 wedged under ordinary
// timing skew (single-claim abort quorum) and M=K=3 froze escalation on one
// dead node. M=4 K=3 clears both: K>=3 disarms the S-044 cascade and the F-a
// claim floor, and MD margin 1 means single faults never depend on escalation.
inline constexpr TimingProfile PROFILE_WEB {
    200, 200, 100, 4, 3, ChainRole::SHARD, ShardingMode::EXTENDED,
    CryptoProfile::MODERN
};
inline constexpr TimingProfile PROFILE_REGIONAL {
    300, 300, 150, 5, 4, ChainRole::SHARD, ShardingMode::CURRENT,
    CryptoProfile::MODERN
};
inline constexpr TimingProfile PROFILE_GLOBAL {
    600, 600, 300, 7, 5, ChainRole::BEACON, ShardingMode::EXTENDED,
    CryptoProfile::MODERN
};

// Tactical profile — Layer-1 swarm coordination for unmanned mobile units
// (drones, robots) operating within radio range. ~40 ms typical block
// finality (20 + 20). K=M=3 strong: maximum mutual distrust, no BFT
// downgrade tolerance for safety-relevant decisions. SHARD + EXTENDED:
// regional grouping by physical proximity; under-quorum merge folds units
// that fly out of range into the neighboring cluster automatically.
//
// FIPS crypto profile mandated: tactical deployments are military / defense /
// embedded systems where FIPS 140-2/3 compliance is non-negotiable. NH4
// military-grade certification path requires FIPS-validated cryptography.
// Trade-offs of FIPS that operators accept by choosing tactical:
//   - PBKDF2 instead of Argon2id (significantly weaker passphrase hashing —
//     not a primary concern in tactical where keys are pre-provisioned)
//   - NIST P-256 ECDH for KX (vs the MODERN profile's X25519); confidential-tx is P-256 in both
//   - Confidential-tx ZK (P-256 range proofs / ring signatures) is FIPS-ALIGNED
//     (built on P-256 + SHA-256) but NOT a FIPS-validated ALGORITHM — a deployment
//     needing per-op CMVP validation treats it as out-of-module
//   - AES-256-GCM instead of XChaCha20-Poly1305 (FIPS-validated AEAD)
//
// Non-regulated "tactical-shape" deployments (commercial drones, industrial
// robots without FIPS requirement) that want sub-50ms blocks but not FIPS
// crypto have no direct profile — both fast profiles (tactical, cluster)
// bundle FIPS. Use `regional` (~150ms, MODERN) and accept the latency cost,
// or use a custom genesis with tactical/cluster timing + MODERN crypto
// override (advanced path, bypasses the bundling invariant).
inline constexpr TimingProfile PROFILE_TACTICAL {
    20, 20, 10, 3, 3, ChainRole::SHARD, ShardingMode::EXTENDED,
    CryptoProfile::FIPS
};

// Test profiles — sub-30ms rounds for fast CI execution. Each `*_test`
// profile mirrors its production counterpart's (chain_role, sharding_mode,
// M, K, crypto_profile) posture exactly. The only difference is the
// round-timer triple, so CI exercises the same code paths a production
// deployment would.
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
    ChainRole::SINGLE, ShardingMode::NONE,
    CryptoProfile::MODERN
};

// `cluster_test` mirrors prod `cluster`: BEACON + CURRENT, M=K=3 strong,
// CryptoProfile::FIPS (same FIPS bundling as production cluster — in-house
// enterprise / financial services / regulated deployments).
inline constexpr TimingProfile PROFILE_CLUSTER_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::BEACON, ShardingMode::CURRENT,
    CryptoProfile::FIPS
};
// `web_test` mirrors prod `web`: SHARD + EXTENDED, M=4 K=3 hybrid (S-044/S-045).
inline constexpr TimingProfile PROFILE_WEB_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 4, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED,
    CryptoProfile::MODERN
};
// `regional_test` mirrors prod `regional`: SHARD + CURRENT, M=5 K=4 hybrid.
inline constexpr TimingProfile PROFILE_REGIONAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 5, 4,
    ChainRole::SHARD, ShardingMode::CURRENT,
    CryptoProfile::MODERN
};
// `global_test` mirrors prod `global`: BEACON + EXTENDED, M=7 K=5 hybrid.
inline constexpr TimingProfile PROFILE_GLOBAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 7, 5,
    ChainRole::BEACON, ShardingMode::EXTENDED,
    CryptoProfile::MODERN
};
// `tactical_test` mirrors prod `tactical`: SHARD + EXTENDED, M=K=3 strong,
// CryptoProfile::FIPS (same FIPS bundling as production tactical).
inline constexpr TimingProfile PROFILE_TACTICAL_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 3,
    ChainRole::SHARD, ShardingMode::EXTENDED,
    CryptoProfile::FIPS
};

} // namespace determ::chain
