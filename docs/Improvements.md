# Optimized Architecture (C99) — Post-v1.0 design candidates

This document outlines the C99 struct definitions for a set of architectural optimizations targeting a post-v1.0 chain. Each item is **deferred** (not in v1.0 scope) and is classified individually against the no-migrations constraint per `docs/proofs/Improvements.md` §6.1.

## Key Optimizations Included:
1. **BLS Signature Aggregation:** Replaces linear `K * 64` byte Ed25519 signatures with a single, constant `96-byte` aggregated BLS12-381 signature.
2. **Quorum Liveness — OPTIONAL (opt-in per-deployment):** Adds a `2F+1`-of-K BFT-threshold finalization mode alongside (NOT replacing) the existing K-of-K unanimous mode. Selected per-deployment at genesis (a new `Config::finalization_mode` knob: `{unanimous_k, bft_quorum_2f1}`); the block header's `quorum_bitset` is only consumed when `bft_quorum_2f1` is the active mode. K-of-K unanimity remains the default for mutual-distrust deployments where any abort-rate signal is more valuable than the bandwidth saving (validators have to consciously opt into a weaker liveness model). See `docs/proofs/Improvements.md` §7.2 for the optionality rationale and the relationship to the existing v1.0 BFT-escalation gate (4-gate trigger per S-025).
3. **Data Deduplication:** `deduplicated_tx_root` replaces redundant `creator_tx_lists` arrays.
4. **Bandwidth Reduction:** Phase 1 uses an IBLT (Invertible Bloom Lookup Table) or Minisketch payload instead of raw 32-byte hash arrays.

**Status.** All four optimizations are **Breaking** classifications under the project's no-migrations constraint — they cannot ship post-v1.0-mainnet without one of the §6.1 escape valves (security hard-fork, new protocol version, or alternate chain). Item 2 (Quorum Liveness) is the only entry that can ship as `additive-via-opt-in` because the legacy K-of-K finalization path remains the codepath default; new deployments choose `bft_quorum_2f1` at genesis but existing chains are unaffected.

**Spec status.** The C99 structs below are *design candidates*; implementation is not scheduled. The four items are tracked individually as forward-looking entries in `docs/proofs/Improvements.md` §7.

---

## C99 Data Structures

```c
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HASH_SIZE 32
#define BLS_SIG_SIZE 96
#define BLS_PUBKEY_SIZE 48
#define MAX_COMMITTEE_SIZE 128

// Common Types
typedef struct {
    uint8_t bytes[HASH_SIZE];
} Hash32;

typedef struct {
    uint8_t bytes[BLS_SIG_SIZE];
} BLSSignature;

typedef struct {
    uint8_t bytes[BLS_PUBKEY_SIZE];
} BLSPublicKey;

// -----------------------------------------------------------------------------
// Phase 1: Contribution Message (Gossip)
// Instead of broadcasting full transaction lists, we use an IBLT or Minisketch 
// sketch for bandwidth-efficient mempool reconciliation.
// -----------------------------------------------------------------------------
typedef struct {
    uint64_t view_number;
    uint32_t validator_id;
    
    // IBLT / Minisketch payload for bandwidth reduction
    // This allows peers to sync missing transactions with minimal overhead.
    uint8_t* sketch_payload; 
    size_t sketch_size;
    
    // Signature over the view and sketch
    BLSSignature sig;
} Phase1_ContribMsg;

// -----------------------------------------------------------------------------
// Phase 2: Block Signature Message (Commit)
// -----------------------------------------------------------------------------
typedef struct {
    uint64_t view_number;
    uint32_t validator_id;
    Hash32 block_digest;
    
    // Individual BLS signature share to be aggregated by the block proposer
    BLSSignature sig_share;
} Phase2_BlockSigMsg;

// -----------------------------------------------------------------------------
// Optimized Block Header
// -----------------------------------------------------------------------------
typedef struct {
    uint64_t block_height;
    uint64_t view_number;
    Hash32 prev_block_hash;
    
    // The root of the globally deduplicated and lexicographically sorted 
    // transactions submitted by the quorum in Phase 1.
    Hash32 deduplicated_tx_root;
    
    // State tree root (e.g., for nonces, account balances, routing tables)
    Hash32 state_root;
    
    // Bitset representing which validators participated in this block's quorum.
    // Used ONLY when the deployment's finalization_mode == bft_quorum_2f1.
    // For finalization_mode == unanimous_k (the v1.0 default), this field
    // is fixed to all-1s (every committee bit set) for byte-stable encoding
    // and the BFT-threshold check at validate-time short-circuits to the
    // K-of-K equality check the v1.0 codepath already performs.
    // e.g., if max committee = 128, we need 16 bytes (128 bits).
    // Protocol requires at least 2F+1 bits set to '1' for validity (bft_quorum_2f1 mode).
    uint8_t quorum_bitset[MAX_COMMITTEE_SIZE / 8];
    
    // A single aggregated BLS signature.
    // In unanimous_k mode: aggregates K-of-K (all committee members).
    // In bft_quorum_2f1 mode: aggregates the 2F+1 subset indicated by quorum_bitset.
    // Constant 96 bytes regardless of committee size in either mode.
    BLSSignature aggregate_sig;
    
} BlockHeader;