/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Dynamic Difficulty Adjustment (DDA) Engine for K=2 VDF Duel.
 *
 * Security Axiom:
 *   Time-Lock Inequality Theorem: T_vdf > W_reveal + Delta
 *
 * Enforces Enforced Blindness against ASIC hardware acceleration and
 * hash-rate manipulation through a strictly dampened deterministic sliding window.
 */

#ifndef DETERMINISTIC_CONSENSUS_DDA_H
#define DETERMINISTIC_CONSENSUS_DDA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TARGET_VDF_MS           3000U  /* 3000ms target execution time strictly enforced */
#define DDA_WINDOW_SIZE         10U    /* 10-block sliding window */
#define DDA_MAX_ADJUST_PERCENT  5U     /* Strict 5% max adjustment per block (dampening) */
#define DDA_MIN_ITERATIONS      1000ULL
#define DDA_MAX_ITERATIONS      1000000000ULL

/*
 * Sliding Window State Tracker:
 * Pre-allocated static ring buffer tracking elapsed milliseconds of local VDF evaluations.
 */
typedef struct {
    uint32_t block_times_ms[DDA_WINDOW_SIZE];
    uint64_t block_timestamps[DDA_WINDOW_SIZE];
    size_t   count;                /* Number of recorded blocks in window (<= DDA_WINDOW_SIZE) */
    size_t   head;                 /* Ring buffer write head */
    uint64_t current_iterations;   /* Currently calibrated iteration parameter */
} dda_tracker_t;

/*
 * Big-Endian Consensus Block Header with VDF iterations:
 * Wire size: 8 + 8 + 8 + 32 + 32 + 32 = 120 bytes.
 */
#define CONSENSUS_BLOCK_HEADER_SIZE 120U

typedef struct {
    uint64_t block_index;
    uint64_t timestamp_ms;
    uint64_t vdf_iterations;      /* DDA calibrated iteration parameter */
    uint8_t  prev_hash[32];
    uint8_t  merkle_root[32];
    uint8_t  vdf_output[32];
} consensus_block_header_t;

/*
 * Initialize the DDA tracker with genesis/initial iterations.
 */
void dda_init(dda_tracker_t *tracker, uint64_t initial_iterations);

/*
 * Record pure local hardware VDF execution time (elapsed ms).
 * Ignores network latency by tracking only the pure local evaluation phase.
 */
void dda_record_vdf_time(dda_tracker_t *tracker, uint32_t elapsed_ms);

/*
 * Compute the moving average execution time over the sliding window.
 * Returns TARGET_VDF_MS if tracker has no recorded samples.
 */
uint32_t calculate_average_vdf_time(const dda_tracker_t *tracker);

/*
 * Core calibration algorithm:
 * Adjusts current_iterations based on average_time compared to TARGET_VDF_MS.
 * If measured_time < 3000ms, aggressively scales iterations upwards (iterations += iterations / 2).
 * Enforces strict 5% max change per block (dampening) when above target, and sanity clamps.
 */
uint64_t calibrate_vdf_iterations(uint64_t current_iterations, uint32_t average_time_ms);

/*
 * Get the next expected block iterations from the tracker state.
 */
uint64_t dda_get_next_iterations(const dda_tracker_t *tracker);

/*
 * Advance tracker state for a newly finalized block.
 */
void dda_commit_block(dda_tracker_t *tracker, uint32_t elapsed_ms);

/*
 * Block Verification Logic:
 * Asserts that a received block's claimed vdf_iterations exactly matches
 * the local deterministic DDA calculation. Returns true if valid, false if rejected.
 */
bool dda_verify_block_iterations(const dda_tracker_t *tracker, uint64_t block_iterations);

/*
 * Big-Endian Wire Codec for Consensus Block Header:
 * Serializes block_index, timestamp_ms, and vdf_iterations in Big-Endian format.
 */
int consensus_block_header_encode(uint8_t *out_buf, size_t buf_cap,
                                  const consensus_block_header_t *header,
                                  size_t *out_written);

int consensus_block_header_decode(const uint8_t *data, size_t len,
                                  consensus_block_header_t *header);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CONSENSUS_DDA_H */
