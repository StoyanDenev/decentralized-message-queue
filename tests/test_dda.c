/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: Dynamic Difficulty Adjustment (DDA) & ASIC Resistance
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

    /* Empty tracker defaults to TARGET_VDF_MS */
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);

    /* Record 4 samples: 4000, 4200, 4400, 4600 -> sum=17200 / 4 = 4300 */
    dda_record_vdf_time(&tracker, 4000);
    dda_record_vdf_time(&tracker, 4200);
    dda_record_vdf_time(&tracker, 4400);
    dda_record_vdf_time(&tracker, 4600);
    TEST_ASSERT(tracker.count == 4);
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 4300);

    /* Fill remaining 6 slots with 5000 -> 17200 + 30000 = 47200 / 10 = 4720 */
    for (int i = 0; i < 6; i++) {
        dda_record_vdf_time(&tracker, 5000);
    }
    TEST_ASSERT(tracker.count == 10);
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 4720);

    /* Test ring buffer wraparound: overwrite first slot (4000) with 6000 */
    dda_record_vdf_time(&tracker, 6000);
    TEST_ASSERT(tracker.count == 10);
    /* 47200 - 4000 + 6000 = 49200 / 10 = 4920 */
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 4920);

    TEST_PASS("test_sliding_window_average");
}

/*
 * 2. Test ASIC Resistance: Incremental Scaling on 3000ms Blocks
 * Verifies that when simulated block times drop to 3000ms (below 5000ms target),
 * the DDA algorithm incrementally ratchets up vdf_iterations by exactly 5% per block.
 */
static void test_asic_resistance_incremental_scaling(void) {
    dda_tracker_t tracker;
    const uint64_t initial_iters = 100000ULL;
    dda_init(&tracker, initial_iters);

    printf("  [DDA Simulation] Initial baseline: %llu iterations (Target: %u ms)\n",
           (unsigned long long)tracker.current_iterations, TARGET_VDF_MS);

    /* Seed the tracker with a baseline 3000ms sample to indicate incoming fast blocks */
    dda_record_vdf_time(&tracker, 3000);

    /*
     * Simulate an adversary deploying ASICs: block execution times collapse to 3000ms.
     * With a 3000ms time, the disparity is 2000ms (a 66.7% shortfall).
     * The dampening rule must strictly clamp the per-block increase to 5.0%.
     */
    uint64_t prev_iters = initial_iters;
    for (int block = 1; block <= 10; block++) {
        /* Next block expected iterations */
        uint64_t next_iters = dda_get_next_iterations(&tracker);

        /* Verify 5% maximum dampening clamp */
        uint64_t max_allowed_step = (prev_iters * DDA_MAX_ADJUST_PERCENT) / 100ULL;
        uint64_t actual_increase = next_iters - prev_iters;

        TEST_ASSERT(next_iters > prev_iters);
        TEST_ASSERT(actual_increase <= max_allowed_step);
        /* Since 66.7% > 5%, it must hit exactly the 5% ceiling */
        TEST_ASSERT(actual_increase == max_allowed_step);

        /* Commit the block with simulated 3000ms execution time */
        dda_commit_block(&tracker, 3000);

        printf("  [DDA Simulation] Block #%d: time=3000ms -> iterations scaled %llu -> %llu (+%.2f%%)\n",
               block, (unsigned long long)prev_iters, (unsigned long long)tracker.current_iterations,
               ((double)actual_increase / (double)prev_iters) * 100.0);

        prev_iters = tracker.current_iterations;
    }

    /*
     * After 10 blocks of 5% compounded growth:
     * 100,000 * (1.05)^10 ≈ 162,889 iterations
     */
    TEST_ASSERT(tracker.current_iterations > 160000ULL);
    TEST_ASSERT(tracker.current_iterations < 165000ULL);

    /* Now simulate reaching target equilibrium: block time returns to 5000ms */
    for (int i = 0; i < 10; i++) {
        dda_record_vdf_time(&tracker, 5000);
    }
    TEST_ASSERT(calculate_average_vdf_time(&tracker) == 5000);
    uint64_t stabilized_iters = dda_get_next_iterations(&tracker);
    /* At exact 5000ms target, iterations remain stable with 0% delta */
    TEST_ASSERT(stabilized_iters == tracker.current_iterations);

    TEST_PASS("test_asic_resistance_incremental_scaling");
}

/*
 * 3. Test Dampening Rule Under Extreme Attacks & Sanity Clamps
 */
static void test_dampening_rules_bounds(void) {
    const uint64_t iters = 200000ULL;

    /* Extreme ASIC speedup: 1ms block time */
    uint64_t next_high = calibrate_vdf_iterations(iters, 1);
    uint64_t max_increase = (iters * DDA_MAX_ADJUST_PERCENT) / 100ULL;
    TEST_ASSERT(next_high == iters + max_increase);

    /* Extreme network slowdown: 30,000ms block time */
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
    dda_record_vdf_time(&local_tracker, 3000);

    /* Node deterministically computes the only valid next iteration count */
    uint64_t expected_iters = dda_get_next_iterations(&local_tracker);
    TEST_ASSERT(expected_iters == 105000ULL);

    /* Honest Aggregator proposes matching iterations -> ACCEPTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, expected_iters) == true);

    /* Malicious Aggregator tries to understate difficulty (bypass DDA) -> REJECTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, 100000ULL) == false);

    /* Malicious Aggregator tries to artificially inflate difficulty -> REJECTED */
    TEST_ASSERT(dda_verify_block_iterations(&local_tracker, 110000ULL) == false);

    TEST_PASS("test_consensus_rejection");
}

int main(void) {
    printf("=== Starting C99 Dynamic Difficulty Adjustment (DDA) Test Suite ===\n");
    test_sliding_window_average();
    test_asic_resistance_incremental_scaling();
    test_dampening_rules_bounds();
    test_header_serialization();
    test_consensus_rejection();
    printf("=== All C99 DDA Tests Passed Successfully ===\n");
    return 0;
}
