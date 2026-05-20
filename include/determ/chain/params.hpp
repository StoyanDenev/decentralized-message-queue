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
//   MODERN: cryptographically-strongest defaults — XChaCha20-Poly1305 AEAD,
//           Argon2id passphrase KDF, secp256k1 + Bulletproofs for confidential
//           transactions, secp256k1 OPRF for T-OPAQUE. Faster + safer with
//           random nonces; not FIPS-validated. Default for non-FIPS deployments.
//
//   FIPS:   FIPS 140-2/3 compliant — AES-256-GCM AEAD (FIPS 197 + SP 800-38D),
//           PBKDF2-HMAC-SHA-256 passphrase KDF (SP 800-132; substantially weaker
//           than Argon2id), NIST P-256 for prime-order needs (no FIPS-validated
//           Bulletproofs → CONFIDENTIAL TRANSACTIONS UNAVAILABLE in FIPS profile),
//           P-256 OPRF for T-OPAQUE. Required for military/defense/government/
//           regulated-healthcare deployments. Mandated for tactical profile.
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

struct TimingProfile {
    uint32_t      tx_commit_ms;
    uint32_t      block_sig_ms;
    uint32_t      abort_claim_ms;
    uint32_t      m_creators;
    uint32_t      k_block_sigs;
    ChainRole     chain_role;
    ShardingMode  sharding_mode;
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
//   - NIST P-256 instead of secp256k1 (different curve family)
//   - NO CONFIDENTIAL TRANSACTIONS (no FIPS-validated range proofs)
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
inline constexpr TimingProfile PROFILE_WEB {
    200, 200, 100, 3, 2, ChainRole::SHARD, ShardingMode::EXTENDED,
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
//   - NIST P-256 instead of secp256k1 (different curve family)
//   - NO CONFIDENTIAL TRANSACTIONS (no FIPS-validated range proofs)
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
// `web_test` mirrors prod `web`: SHARD + EXTENDED, M=3 K=2 hybrid.
inline constexpr TimingProfile PROFILE_WEB_TEST {
    TEST_TX_COMMIT_MS, TEST_BLOCK_SIG_MS, TEST_ABORT_CLAIM_MS, 3, 2,
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
