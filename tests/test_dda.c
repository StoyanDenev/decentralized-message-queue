/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: Dynamic Difficulty Adjustment (DDA) Engine
 * Verifies moving average window, aggressive upward calibration for measured_time < 3000ms,
 * 5% dampening when above target, Big-Endian serialization, and consensus rejection.
 */

#include <determ/consensus/dda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_PASS(name) printf("  [PASS] %s\n", name)

/*
 * 1. Test Sliding Window and Moving Average Ring Buffer
 */
static void test_sliding_window_average(void) {
    dda_tracker_t tracker;
    dda_init(&tracker, 50000);

    /* Empty tracker defaults to TARGET_VDF_MS (3000ms) */
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);

    /* Record 4 samples: 2000, 2200, 2400, 2600 -> sum=9200 / 4 = 2300 */
    dda_record_vdf_time(&tracker, 2000);
    dda_record_vdf_time(&tracker, 2200);
    dda_record_vdf_time(&tracker, 2400);
    dda_record_vdf_time(&tracker, 2600);
    TEST_ASSERT(tracker.count == 4);
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 2300);

    /* Fill remaining 6 slots with 3000 -> 9200 + 18000 = 27200 / 10 = 2720 */
    for (int i = 0; i < 6; i++) {
        dda_record_vdf_time(&tracker, 3000);
    }
    TEST_ASSERT(tracker.count == 10);
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 2720);

    /* Test ring buffer wraparound: overwrite first slot (2000) with 4000 */
    dda_record_vdf_time(&tracker, 4000);
    TEST_ASSERT(tracker.count == 10);
    /* 27200 - 2000 + 4000 = 29200 / 10 = 2920 */
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 2920);

    TEST_PASS("test_sliding_window_average");
}

/*
 * 2. Test Aggressive Upward Calibration on Blocks < 3000ms
 */
static void test_asic_resistance_aggressive_scaling(void) {
    dda_tracker_t tracker;
    const uint64_t initial_iters = 100000ULL;
    dda_init(&tracker, initial_iters);

    printf("  [DDA Simulation] Initial baseline: %llu iterations (Target: %u ms)\n",
           (unsigned long long)tracker.current_iterations, TARGET_VDF_MS);

    /* Seed the tracker with a baseline 1500ms sample (< 3000ms target) */
    dda_record_vdf_time(&tracker, 1500);

    /* Aggressive scaling: iterations += iterations / 2 (+50% boost) */
    uint64_t next_iters = dda_get_next_iterations(&tracker);
    TEST_ASSERT(next_iters == initial_iters + initial_iters / 2ULL);
    TEST_ASSERT(next_iters == 150000ULL);

    dda_commit_block(&tracker, 1500);
    TEST_ASSERT(tracker.current_iterations == 150000ULL);

    /* Slower than target: 4000ms (> 3000ms) -> dampening 5% decrease */
    for (int i = 0; i < 10; i++) {
        dda_record_vdf_time(&tracker, 4000);
    }
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 4000);
    uint64_t next_slow = dda_get_next_iterations(&tracker);
    uint64_t max_step = (150000ULL * DDA_MAX_ADJUST_PERCENT) / 100ULL;
    TEST_ASSERT(next_slow == 150000ULL - max_step);

    /* Now simulate reaching target equilibrium: block time returns to 3000ms */
    for (int i = 0; i < 10; i++) {
        dda_record_vdf_time(&tracker, 3000);
    }
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 3000);
    uint64_t stabilized_iters = dda_get_next_iterations(&tracker);
    TEST_ASSERT(stabilized_iters == tracker.current_iterations);

    TEST_PASS("test_asic_resistance_aggressive_scaling");
}

/*
 * 3. Test Dampening Rule Under Extreme Attacks & Sanity Clamps
 */
static void test_dampening_rules_bounds(void) {
    const uint64_t iters = 200000ULL;

    /* Extreme ASIC speedup: 1ms block time -> aggressive +50% scaling */
    uint64_t next_high = calibrate_vdf_iterations(iters, 1);
    TEST_ASSERT(next_high == iters + iters / 2ULL);

    /* Extreme network slowdown: 30,000ms block time -> 5% decrease */
    uint64_t next_low = calibrate_vdf_iterations(iters, 30000);
    uint64_t max_decrease = (iters * DDA_MAX_ADJUST_PERCENT) / 100ULL;
    TEST_ASSERT(next_low == iters - max_decrease);

    /* Architectural minimum clamping */
    uint64_t at_min = calibrate_vdf_iterations(DDA_MIN_ITERATIONS, 30000);
    TEST_ASSERT(at_min >= DDA_MIN_ITERATIONS);

    /* Architectural maximum clamping */
    uint64_t at_max = calibrate_vdf_iterations(DDA_MAX_ITERATIONS, 100);
    TEST_ASSERT(at_max <= DDA_MAX_ITERATIONS);

    TEST_PASS("test_dampening_rules_bounds");
}

/*
 * 4. Test Big-Endian Consensus Header Serialization & Deserialization
 */
static void test_header_serialization(void) {
    consensus_block_header_t hdr;
    hdr.block_index = 42ULL;
    hdr.timestamp_ms = 1774000000000ULL;
    hdr.vdf_iterations = 105000ULL;
    memset(hdr.prev_hash, 0xAA, 32);
    memset(hdr.merkle_root, 0xBB, 32);
    memset(hdr.vdf_output, 0xCC, 32);

    uint8_t wire_buf[256];
    size_t written = 0;
    TEST_ASSERT(consensus_block_header_encode(wire_buf, sizeof(wire_buf), &hdr, &written) == 0);
    TEST_ASSERT(written == CONSENSUS_BLOCK_HEADER_SIZE);

    /* Verify Big-Endian wire encoding of vdf_iterations (offset 16) */
    uint64_t be_iters = ((uint64_t)wire_buf[16] << 56) |
                        ((uint64_t)wire_buf[17] << 48) |
                        ((uint64_t)wire_buf[18] << 40) |
                        ((uint64_t)wire_buf[19] << 32) |
                        ((uint64_t)wire_buf[20] << 24) |
                        ((uint64_t)wire_buf[21] << 16) |
                        ((uint64_t)wire_buf[22] << 8)  |
                        ((uint64_t)wire_buf[23]);
    TEST_ASSERT(be_iters == 105000ULL);

    /* Decode and compare */
    consensus_block_header_t decoded;
    TEST_ASSERT(consensus_block_header_decode(wire_buf, written, &decoded) == 0);
    TEST_ASSERT(decoded.block_index == hdr.block_index);
    TEST_ASSERT(decoded.timestamp_ms == hdr.timestamp_ms);
    TEST_ASSERT(decoded.vdf_iterations == hdr.vdf_iterations);
    TEST_ASSERT(memcmp(decoded.prev_hash, hdr.prev_hash, 32) == 0);
    TEST_ASSERT(memcmp(decoded.merkle_root, hdr.merkle_root, 32) == 0);
    TEST_ASSERT(memcmp(decoded.vdf_output, hdr.vdf_output, 32) == 0);

    TEST_PASS("test_header_serialization");
}

/*
 * 5. Test Consensus Rejection of Manipulated Block Iterations
 */
static void test_consensus_rejection(void) {
    dda_tracker_t local_tracker;
    dda_init(&local_tracker, 100000ULL);
    dda_record_vdf_time(&local_tracker, 1500);

    /* Node deterministically computes the only valid next iteration count: +50% boost = 150,000 */
    uint64_t expected_iters = dda_get_next_iterations(&local_tracker);
    TEST_ASSERT(expected_iters == 150000ULL);

    /* Honest Aggregator proposes matching iterations -> ACCEPTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, expected_iters) == true);

    /* Malicious Aggregator tries to understate difficulty (bypass DDA) -> REJECTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, 100000ULL) == false);

    /* Malicious Aggregator tries to artificially inflate difficulty -> REJECTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, 160000ULL) == false);

    TEST_PASS("test_consensus_rejection");
}

int main(void) {
    printf("=== Starting C99 Dynamic Difficulty Adjustment (DDA) Test Suite ===\n");
    test_sliding_window_average();
    test_asic_resistance_aggressive_scaling();
    test_dampening_rules_bounds();
    test_header_serialization();
    test_consensus_rejection();
    printf("=== All C99 DDA Tests Passed Successfully ===\n");
    return 0;
}
