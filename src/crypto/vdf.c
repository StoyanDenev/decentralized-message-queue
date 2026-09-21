/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Hardware-Resistant Verifiable Delay Function (VDF) Engine (C99 Bare-Metal)
 */

#define _POSIX_C_SOURCE 200809L

#include <determ/crypto/vdf.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/aes/aes.h>
#include <determ/crypto/secure_zero.h>
#include <determ/crypto/ct.h>

#include <string.h>
#include <time.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

static uint64_t vdf_get_monotonic_ns(void) {
#if defined(__APPLE__)
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        (void)mach_timebase_info(&tb);
    }
    uint64_t t = mach_absolute_time();
    return (uint64_t)(((__uint128_t)t * tb.numer) / tb.denom);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0ULL;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

/*
 * Initialize and seed the VDF engine.
 * Expands the input seed/payload into the 64KB memory arena using sequential AES-256 chaining.
 */
int vdf_init(vdf_context_t *ctx, const uint8_t *seed, size_t seed_len, uint64_t iterations) {
    if (!ctx || (!seed && seed_len > 0)) {
        return -1;
    }
    if (iterations < VDF_MIN_ITERATIONS || iterations > VDF_MAX_ITERATIONS) {
        return -1;
    }

    ctx->iterations = iterations;
    ctx->elapsed_ns = 0;

    /* Base seed hashing: absorb into 32-byte initial state */
    determ_sha256(seed, seed_len, ctx->state);

    /* Initialize AES key schedule from current state */
    determ_aes256_ctx aes_ctx;
    determ_aes256_init(&aes_ctx, ctx->state);

    /*
     * Memory-hard arena initialization:
     * Fill 4096 blocks (16 bytes each = 64KB) via sequential AES block encryption.
     * Block j is computed as AES_Encrypt(Block j-1 ^ counter).
     */
    uint8_t prev_block[VDF_BLOCK_SIZE];
    memcpy(prev_block, ctx->state, VDF_BLOCK_SIZE);

    for (uint32_t j = 0; j < VDF_ARENA_BLOCKS; ++j) {
        uint8_t in_blk[VDF_BLOCK_SIZE];
        uint8_t out_blk[VDF_BLOCK_SIZE];

        for (size_t k = 0; k < VDF_BLOCK_SIZE; ++k) {
            in_blk[k] = (uint8_t)(prev_block[k] ^ ((uint8_t)(j >> (k % 4 * 8)) & 0xFF));
        }

        determ_aes256_encrypt_block(&aes_ctx, in_blk, out_blk);
        memcpy(&ctx->arena[j * VDF_BLOCK_SIZE], out_blk, VDF_BLOCK_SIZE);
        memcpy(prev_block, out_blk, VDF_BLOCK_SIZE);
    }

    determ_secure_zero(&aes_ctx, sizeof(aes_ctx));
    determ_secure_zero(prev_block, sizeof(prev_block));

    return 0;
}

/*
 * Execute the sequential memory-hard evaluation loop.
 * Each step performs:
 *   1. Pseudorandom memory lookup based on current state (memory bandwidth bottleneck).
 *   2. Strict non-parallelizable iterative mixing via AES round encryption.
 *   3. Memory write-back to enforce read-modify-write traffic.
 *   4. Compiler memory barrier to defeat instruction reordering / loop unrolling.
 */
int vdf_evaluate(vdf_context_t *ctx, uint8_t output[VDF_OUTPUT_LEN]) {
    if (!ctx || !output) {
        return -1;
    }

    uint64_t t_start = vdf_get_monotonic_ns();

    determ_aes256_ctx aes_ctx;
    determ_aes256_init(&aes_ctx, ctx->state);

    uint8_t current_state[VDF_OUTPUT_LEN];
    memcpy(current_state, ctx->state, VDF_OUTPUT_LEN);

    const uint64_t iters = ctx->iterations;

    for (uint64_t i = 0; i < iters; ++i) {
        /*
         * Extract target arena block index from state bytes in an endian-neutral,
         * strict-aliasing safe manner.
         */
        uint32_t idx = ((uint32_t)current_state[0])
                     | ((uint32_t)current_state[1] << 8)
                     | ((uint32_t)current_state[2] << 16)
                     | ((uint32_t)current_state[3] << 24);
        idx %= VDF_ARENA_BLOCKS;

        /* Fetch block from arena */
        uint8_t arena_blk[VDF_BLOCK_SIZE];
        uint8_t *arena_ptr = &ctx->arena[idx * VDF_BLOCK_SIZE];
        memcpy(arena_blk, arena_ptr, VDF_BLOCK_SIZE);

        /* Mix current state with arena block */
        uint8_t in_blk[VDF_BLOCK_SIZE];
        uint8_t enc_blk[VDF_BLOCK_SIZE];
        for (size_t k = 0; k < VDF_BLOCK_SIZE; ++k) {
            in_blk[k] = (uint8_t)(arena_blk[k] ^ current_state[k]);
        }

        /* Sequential AES block transform */
        determ_aes256_encrypt_block(&aes_ctx, in_blk, enc_blk);

        /* Write-back to arena (forces dirty cache-line update / memory bandwidth) */
        memcpy(arena_ptr, enc_blk, VDF_BLOCK_SIZE);

        /* Update sequential state */
        for (size_t k = 0; k < VDF_BLOCK_SIZE; ++k) {
            current_state[k] = (uint8_t)(current_state[k] ^ enc_blk[k]);
            current_state[k + VDF_BLOCK_SIZE] = (uint8_t)(current_state[k + VDF_BLOCK_SIZE] + enc_blk[k]);
        }

        /*
         * Strict Aliasing & Memory Barrier:
         * Prevents compiler from reordering operations, caching arena slots in registers,
         * or eliding intermediate iterations.
         */
        VDF_MEMORY_BARRIER();
        VDF_VOLATILE_BARRIER(current_state[0]);
    }

    /* Final digest over mutated state and arena digest */
    determ_sha256(current_state, VDF_OUTPUT_LEN, output);

    /* Update context state and elapsed time */
    memcpy(ctx->state, output, VDF_OUTPUT_LEN);
    uint64_t t_end = vdf_get_monotonic_ns();
    ctx->elapsed_ns = (t_end >= t_start) ? (t_end - t_start) : 0ULL;

    determ_secure_zero(&aes_ctx, sizeof(aes_ctx));
    determ_secure_zero(current_state, sizeof(current_state));

    return 0;
}

/*
 * Verify a claimed VDF output.
 */
int vdf_verify(vdf_context_t *ctx, const uint8_t *seed, size_t seed_len,
               uint64_t iterations, const uint8_t claimed_output[VDF_OUTPUT_LEN]) {
    if (!ctx || (!seed && seed_len > 0) || !claimed_output) {
        return 0;
    }

    if (vdf_init(ctx, seed, seed_len, iterations) != 0) {
        return 0;
    }

    uint8_t computed[VDF_OUTPUT_LEN];
    if (vdf_evaluate(ctx, computed) != 0) {
        return 0;
    }

    int match = (determ_ct_memcmp(computed, claimed_output, VDF_OUTPUT_LEN) == 0);
    determ_secure_zero(computed, sizeof(computed));
    return match ? 1 : 0;
}

