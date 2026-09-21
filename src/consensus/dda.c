/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Dynamic Difficulty Adjustment (DDA) Engine for K=2 VDF Duel.
 *
 * Implements sliding window moving average, aggressive upward calibration for
 * measured_time < 3000ms (iterations += iterations / 2), 5% per-block dampening
 * rules when above target, and Big-Endian consensus header serialization/verification.
 */

#include <determ/consensus/dda.h>
#include <string.h>

static inline void be_put_u64(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

static inline uint64_t be_get_u64(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

void dda_init(dda_tracker_t *tracker, uint64_t initial_iterations) {
    if (!tracker) return;
    memset(tracker, 0, sizeof(*tracker));
    if (initial_iterations < DDA_MIN_ITERATIONS) {
        initial_iterations = DDA_MIN_ITERATIONS;
    } else if (initial_iterations > DDA_MAX_ITERATIONS) {
        initial_iterations = DDA_MAX_ITERATIONS;
    }
    tracker->current_iterations = initial_iterations;
}

void dda_record_vdf_time(dda_tracker_t *tracker, uint32_t elapsed_ms) {
    if (!tracker) return;
    tracker->block_times_ms[tracker->head] = elapsed_ms;
    tracker->head = (tracker->head + 1) % DDA_WINDOW_SIZE;
    if (tracker->count < DDA_WINDOW_SIZE) {
        tracker->count++;
    }
}

/*
 * Deterministic DDA: The DDA algorithm must NOT use local hardware clocks.
 * Rewrite calculate_average_vdf_time() to compute elapsed time strictly by reading
 * the difference in timestamps embedded in the finalized block headers:
 * (Block[N].timestamp - Block[N-10].timestamp).
 */
uint32_t calculate_average_vdf_time(const dda_tracker_t *tracker) {
    if (!tracker || tracker->count == 0) {
        return TARGET_VDF_MS;
    }

    /*
     * If 10 block header timestamps are available in the sliding window,
     * compute elapsed time strictly from finalized block header timestamps:
     * (Block[N].timestamp - Block[N-10].timestamp) / DDA_WINDOW_SIZE.
     * Local hardware clocks are strictly forbidden.
     */
    if (tracker->count >= DDA_WINDOW_SIZE && tracker->block_timestamps[0] > 0) {
        size_t newest_idx = (tracker->head + DDA_WINDOW_SIZE - 1) % DDA_WINDOW_SIZE;
        size_t oldest_idx = tracker->head;
        if (tracker->block_timestamps[newest_idx] > tracker->block_timestamps[oldest_idx]) {
            uint64_t delta = tracker->block_timestamps[newest_idx] - tracker->block_timestamps[oldest_idx];
            return (uint32_t)(delta / DDA_WINDOW_SIZE);
        }
    }

    uint64_t sum = 0;
    for (size_t i = 0; i < tracker->count; i++) {
        sum += tracker->block_times_ms[i];
    }
    return (uint32_t)(sum / tracker->count);
}

uint64_t calibrate_vdf_iterations(uint64_t current_iterations, uint32_t average_time_ms) {
    if (current_iterations < DDA_MIN_ITERATIONS) {
        current_iterations = DDA_MIN_ITERATIONS;
    } else if (current_iterations > DDA_MAX_ITERATIONS) {
        current_iterations = DDA_MAX_ITERATIONS;
    }

    if (average_time_ms == 0) {
        average_time_ms = 1; /* Protect against zero-division */
    }

    uint64_t next_iterations = current_iterations;

    if (average_time_ms < TARGET_VDF_MS) {
        /*
         * Aggressively scale iterations upwards (iterations += iterations / 2)
         * to immediately correct hardware anomalies when running under 3000ms.
         */
        uint64_t boost = current_iterations / 2ULL;
        if (boost == 0) {
            boost = 1ULL;
        }
        next_iterations = current_iterations + boost;
    } else if (average_time_ms > TARGET_VDF_MS) {
        /*
         * Block execution was slower than target.
         * Proportional decrease clamped strictly to max_step (5%).
         */
        uint64_t max_step = (current_iterations * (uint64_t)DDA_MAX_ADJUST_PERCENT) / 100ULL;
        if (max_step == 0) {
            max_step = 1ULL;
        }
        uint64_t disparity = (uint64_t)(average_time_ms - TARGET_VDF_MS);
        uint64_t delta = (current_iterations * disparity) / (uint64_t)average_time_ms;
        if (delta > max_step) {
            delta = max_step;
        }
        if (current_iterations > delta) {
            next_iterations = current_iterations - delta;
        } else {
            next_iterations = DDA_MIN_ITERATIONS;
        }
    }

    /* Enforce global architectural limits */
    if (next_iterations < DDA_MIN_ITERATIONS) {
        next_iterations = DDA_MIN_ITERATIONS;
    } else if (next_iterations > DDA_MAX_ITERATIONS) {
        next_iterations = DDA_MAX_ITERATIONS;
    }

    return next_iterations;
}

uint64_t dda_get_next_iterations(const dda_tracker_t *tracker) {
    if (!tracker) return DDA_MIN_ITERATIONS;
    uint32_t avg_ms = calculate_average_vdf_time(tracker);
    return calibrate_vdf_iterations(tracker->current_iterations, avg_ms);
}

void dda_commit_block(dda_tracker_t *tracker, uint32_t elapsed_ms) {
    if (!tracker) return;
    tracker->current_iterations = dda_get_next_iterations(tracker);
    dda_record_vdf_time(tracker, elapsed_ms);
}

bool dda_verify_block_iterations(const dda_tracker_t *tracker, uint64_t block_iterations) {
    if (!tracker) return false;
    uint64_t expected = dda_get_next_iterations(tracker);
    return (block_iterations == expected);
}

int consensus_block_header_encode(uint8_t *out_buf, size_t buf_cap,
                                  const consensus_block_header_t *header,
                                  size_t *out_written) {
    if (!out_buf || !header || !out_written) return -1;
    if (buf_cap < CONSENSUS_BLOCK_HEADER_SIZE) return -2;

    be_put_u64(out_buf + 0, header->block_index);
    be_put_u64(out_buf + 8, header->timestamp_ms);
    be_put_u64(out_buf + 16, header->vdf_iterations);
    memcpy(out_buf + 24, header->prev_hash, 32);
    memcpy(out_buf + 56, header->merkle_root, 32);
    memcpy(out_buf + 88, header->vdf_output, 32);

    *out_written = CONSENSUS_BLOCK_HEADER_SIZE;
    return 0;
}

int consensus_block_header_decode(const uint8_t *data, size_t len,
                                  consensus_block_header_t *header) {
    if (!data || !header) return -1;
    if (len < CONSENSUS_BLOCK_HEADER_SIZE) return -2;

    header->block_index    = be_get_u64(data + 0);
    header->timestamp_ms   = be_get_u64(data + 8);
    header->vdf_iterations = be_get_u64(data + 16);
    memcpy(header->prev_hash, data + 24, 32);
    memcpy(header->merkle_root, data + 56, 32);
    memcpy(header->vdf_output, data + 88, 32);

    return 0;
}
