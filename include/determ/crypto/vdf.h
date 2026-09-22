/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Experimental repeated-work evaluator (AES/SHA-256, fixed 64 KiB arena).
 * Verification repeats the computation. No succinct proof, sequential-hardness
 * reduction, ASIC-resistance claim or minimum wall-clock duration is provided.
 * All evaluation state is caller-provided; the evaluator allocates no heap.
 */

#ifndef DETERMINISTIC_CRYPTO_VDF_H
#define DETERMINISTIC_CRYPTO_VDF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VDF_OUTPUT_LEN          32U
#define VDF_BLOCK_SIZE          16U
#define VDF_ARENA_BLOCKS        4096U
#define VDF_ARENA_SIZE          (VDF_ARENA_BLOCKS * VDF_BLOCK_SIZE) /* 64 KB */
#define VDF_DEFAULT_TARGET_SEC  3.0
#define VDF_MIN_ITERATIONS      1000ULL
#define VDF_MAX_ITERATIONS      1000000000ULL

/*
 * BASE_VDF_ITERATIONS:
 * Default experiment work parameter, not a hardware-independent time bound.
 */
#define BASE_VDF_ITERATIONS     2500000ULL

/*
 * Evaluation state; alignment attributes are compiler-specific.
 */
#if defined(__GNUC__) || defined(__clang__)
#define VDF_ALIGNED(x) __attribute__((aligned(x)))
#define VDF_PACKED     __attribute__((packed))
#else
#define VDF_ALIGNED(x)
#define VDF_PACKED
#endif

typedef struct VDF_ALIGNED(64) {
    uint8_t  state[VDF_OUTPUT_LEN];
    uint8_t  arena[VDF_ARENA_SIZE];
    uint64_t iterations;
    uint64_t elapsed_ns;
} vdf_context_t;

/*
 * In-memory output/work record. Packing does not define wire byte order;
 * do not serialize this native uint64_t by copying the struct.
 */
typedef struct VDF_PACKED {
    uint8_t  output[VDF_OUTPUT_LEN];
    uint64_t iterations;
} vdf_proof_t;

/*
 * Compiler memory barriers where supported; not a hardware-security primitive
 */
#if defined(__GNUC__) || defined(__clang__)
#define VDF_MEMORY_BARRIER() __asm__ __volatile__("" ::: "memory")
#define VDF_VOLATILE_BARRIER(var) __asm__ __volatile__("" : "+m"(var) : : "memory")
#else
#define VDF_MEMORY_BARRIER()
#define VDF_VOLATILE_BARRIER(var) ((void)(var))
#endif

/*
 * VDF Engine API:
 * Zero heap allocation. All operations use the caller-provided vdf_context_t.
 */

/*
 * Initialize and seed the VDF engine.
 * Expands the input seed/payload through iterative AES-256 into the memory arena.
 */
int vdf_init(vdf_context_t *ctx, const uint8_t *seed, size_t seed_len, uint64_t iterations);

/*
 * Execute the experimental evaluation loop for the configured iteration count.
 * Its source-level dependency does not establish a cryptographic delay bound.
 */
int vdf_evaluate(vdf_context_t *ctx, uint8_t output[VDF_OUTPUT_LEN]);

/*
 * Verify that a claimed VDF output matches the seed and iteration count.
 * Returns 1 when reevaluation matches, 0 on mismatch or error. This does not
 * authenticate a peer or establish freshness/context binding.
 */
int vdf_verify(vdf_context_t *ctx, const uint8_t *seed, size_t seed_len,
               uint64_t iterations, const uint8_t claimed_output[VDF_OUTPUT_LEN]);

#if defined(DETERM_DSF_ENABLED)
/*
 * DSF Testing Shim:
 * Bypasses memory-hard VDF loop during simulations, instantly producing a
 * deterministic mock hash and advancing the virtual clock by target_vdf_ms.
 */
void determ_dsf_set_vdf_bypass(bool enabled, uint64_t target_vdf_ms);
bool determ_dsf_get_vdf_bypass(uint64_t *out_target_vdf_ms);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CRYPTO_VDF_H */
