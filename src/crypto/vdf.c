/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Experimental repeated-work evaluator (C99): AES-256 over a 64 KiB arena and
 * SHA-256, verified only by re-evaluation. No sequential-hardness,
 * memory-hardness or ASIC-resistance claim is made (see vdf.h).
 */

#define _POSIX_C_SOURCE 200809L

#include "determ/time/clock.h"
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

#ifndef BASE_VDF_ITERATIONS
#define BASE_VDF_ITERATIONS 2500000ULL
#endif

#if defined(DETERM_DSF_ENABLED)
static bool s_dsf_vdf_bypass_enabled = false;
static uint64_t s_dsf_vdf_target_ms = 3000ULL;

void determ_dsf_set_vdf_bypass(bool enabled, uint64_t target_vdf_ms) {
    s_dsf_vdf_bypass_enabled = enabled;
    s_dsf_vdf_target_ms = target_vdf_ms;
}

bool determ_dsf_get_vdf_bypass(uint64_t *out_target_vdf_ms) {
    if (out_target_vdf_ms) {
        *out_target_vdf_ms = s_dsf_vdf_target_ms;
    }
    return s_dsf_vdf_bypass_enabled;
}
#endif

static uint64_t vdf_get_monotonic_ns(void) {
    return determ_clock_now_ns();
}

/*
 * Initialize and seed the evaluator.
 * Expands the input seed/payload into the 64 KiB arena by chained AES-256.
 */
int vdf_init(vdf_context_t *ctx, const uint8_t *seed, size_t seed_len, uint64_t iterations) {
    if (!ctx || (!seed && seed_len > 0)) {
        return -1;
    }
    if (iterations == 0) {
        iterations = BASE_VDF_ITERATIONS;
    }
    if (iterations < VDF_MIN_ITERATIONS || iterations > VDF_MAX_ITERATIONS) {
        return -1;
    }

    ctx->iterations = iterations;
    ctx->elapsed_ns = 0;

    /* Base seed hashing: absorb into 32-byte initial state */
    determ_sha256(seed, seed_len, ctx->state);

#if defined(DETERM_DSF_ENABLED)
    if (s_dsf_vdf_bypass_enabled) {
        return 0;
    }
#endif

    /* Initialize AES key schedule from current state */
    determ_aes256_ctx aes_ctx;
    determ_aes256_init(&aes_ctx, ctx->state);

    /*
     * Arena initialization: fill 4096 blocks of 16 bytes (64 KiB), where
     * block j = AES_Encrypt(block j-1 ^ counter j).
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
 * Run the configured number of iterations. Each iteration reads the arena
 * block selected by the state, XORs it with the state, AES-256-encrypts it,
 * writes the result back to the arena and folds it into the state. The output
 * is SHA-256 of the final 32-byte state. The data dependency between
 * iterations is a source-level property only; it is not a proven sequential
 * or memory bound.
 */
int vdf_evaluate(vdf_context_t *ctx, uint8_t output[VDF_OUTPUT_LEN]) {
    if (!ctx || !output) {
        return -1;
    }

#if defined(DETERM_DSF_ENABLED)
    if (s_dsf_vdf_bypass_enabled) {
        determ_sha256_ctx sha;
        determ_sha256_init(&sha);
        determ_sha256_update(&sha, ctx->state, VDF_OUTPUT_LEN);
        determ_sha256_update(&sha, (const uint8_t *)&ctx->iterations, sizeof(ctx->iterations));
        determ_sha256_final(&sha, output);

        ctx->elapsed_ns = s_dsf_vdf_target_ms * 1000000ULL;
        determ_dsf_clock_advance_ms(s_dsf_vdf_target_ms);
        return 0;
    }
#endif

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

        /* Write the block back to the arena */
        memcpy(arena_ptr, enc_blk, VDF_BLOCK_SIZE);

        /* Update sequential state */
        for (size_t k = 0; k < VDF_BLOCK_SIZE; ++k) {
            current_state[k] = (uint8_t)(current_state[k] ^ enc_blk[k]);
            current_state[k + VDF_BLOCK_SIZE] = (uint8_t)(current_state[k + VDF_BLOCK_SIZE] + enc_blk[k]);
        }

        /*
         * Compiler barriers (GCC/Clang only): keep the compiler from folding
         * iterations away. Not a hardware or security property.
         */
        VDF_MEMORY_BARRIER();
        VDF_VOLATILE_BARRIER(current_state[0]);
    }

    /* Output = SHA-256 of the final state; the arena is not hashed. */
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
#if defined(DETERM_DSF_ENABLED)
    if (s_dsf_vdf_bypass_enabled) {
        determ_sha256_ctx sha;
        determ_sha256_init(&sha);
        determ_sha256_update(&sha, ctx->state, VDF_OUTPUT_LEN);
        determ_sha256_update(&sha, (const uint8_t *)&ctx->iterations, sizeof(ctx->iterations));
        determ_sha256_final(&sha, computed);

        int match = (determ_ct_memcmp(computed, claimed_output, VDF_OUTPUT_LEN) == 0);
        determ_secure_zero(computed, sizeof(computed));
        return match ? 1 : 0;
    }
#endif
    if (vdf_evaluate(ctx, computed) != 0) {
        return 0;
    }

    int match = (determ_ct_memcmp(computed, claimed_output, VDF_OUTPUT_LEN) == 0);
    determ_secure_zero(computed, sizeof(computed));
    return match ? 1 : 0;
}
