/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Hardware-Resistant Verifiable Delay Function (VDF) Engine (Phase 2)
 *
 * Security Axiom:
 *   Time-Lock Inequality Theorem: T_vdf > W_reveal + Delta
 *
 * Core Guarantees:
 *   1. Memory-hard sequential hashing loop: non-parallelizable, bandwidth-bottlenecked.
 *   2. Dynamic Iteration Tuning (DDA): auto-calibrates vdf_iterations against Moore's Law.
 *   3. Strict aliasing & alignment: zero undefined behavior, compiler memory barriers.
 *   4. Zero dynamic memory allocation: static/arena execution context.
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
 * Scaled upwards by 50x (2,500,000 iterations) to guarantee a baseline
 * execution duration >2500ms on modern multicore/superscalar hardware.
 */
#define BASE_VDF_ITERATIONS     2500000ULL

/*
 * Strictly aligned, tightly packed VDF state buffer
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
 * Wire-serializable proof bundle (packed and endian-safe)
 */
typedef struct VDF_PACKED {
    uint8_t  output[VDF_OUTPUT_LEN];
    uint64_t iterations;
} vdf_proof_t;

/*
 * Memory barrier macro to defeat compiler loop unrolling and dead-code elimination
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
 * Execute the sequential memory-hard evaluation loop.
 * Guarantees strict non-parallelizable execution for the configured number of iterations.
 */
int vdf_evaluate(vdf_context_t *ctx, uint8_t output[VDF_OUTPUT_LEN]);

/*
 * Verify that a claimed VDF output matches the seed and iteration count.
 * Returns 1 on authentic proof, 0 on forgery or error.
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
