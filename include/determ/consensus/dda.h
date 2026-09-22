/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Experimental deterministic difficulty arithmetic over supplied timestamps.
 * This helper does not authenticate timestamps, validate blocks or VDFs, or
 * enforce a wall-clock target. It is not connected to block admission.
 */

#ifndef DETERMINISTIC_CONSENSUS_DDA_H
#define DETERMINISTIC_CONSENSUS_DDA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TARGET_VDF_MS           3000U  /* Calibration target for timestamp intervals */
#define DDA_WINDOW_SIZE         10U    /* Number of timestamp intervals in the window */
#define DDA_TIMESTAMP_CAPACITY  (DDA_WINDOW_SIZE + 1U)
#define DDA_MAX_ADJUST_PERCENT  5U     /* Maximum downward adjustment per step */
#define DDA_MIN_ITERATIONS      1000ULL
#define DDA_MAX_ITERATIONS      1000000000ULL

/*
 * Sliding Window State Tracker:
 * Pre-allocated ring of caller-supplied timestamps in milliseconds.
 */
typedef struct {
    uint64_t block_timestamps[DDA_TIMESTAMP_CAPACITY];
    size_t   count;                /* Timestamp count (<= DDA_TIMESTAMP_CAPACITY) */
    size_t   head;                 /* Ring buffer write head */
    uint64_t current_iterations;   /* Currently calibrated iteration parameter */
} dda_tracker_t;

/*
 * Experimental header codec with VDF iterations (not a block acceptance rule):
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
 * Compute floor((newest timestamp - oldest timestamp) / interval count).
 * Returns TARGET_VDF_MS below two timestamps; saturates at UINT32_MAX.
 * A zero timestamp is a valid anchor, not an empty-entry sentinel.
 */
uint32_t calculate_average_vdf_time(const dda_tracker_t *tracker);

/*
 * Core calibration algorithm:
 * Adjusts current_iterations based on average_time compared to TARGET_VDF_MS.
 * Below the target, increases iterations by 50%; above the target, decreases
 * proportionally by at most 5%. Clamps the result to the configured limits.
 * These arithmetic rules do not establish resistance to timestamp manipulation.
 */
uint64_t calibrate_vdf_iterations(uint64_t current_iterations, uint32_t average_time_ms);

/*
 * Get the next expected block iterations from the tracker state.
 */
uint64_t dda_get_next_iterations(const dda_tracker_t *tracker);

/*
 * Atomically append a timestamp and iteration count. Rejects non-increasing
 * timestamps and work unequal to dda_get_next_iterations(predecessor state).
 * Failure leaves the initialized tracker byte-for-byte unchanged.
 *
 * The caller must supply contiguous validated history from one branch and
 * restore/replay this tracker on reorganization. This helper does not establish
 * timestamp honesty, parent linkage, VDF validity or consensus finality.
 */
bool dda_commit_block(dda_tracker_t *tracker, uint64_t timestamp_ms,
                      uint64_t iterations);

/*
 * Compare work against this tracker's next expected value only.
 * This is not full block verification.
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
