/* SPDX-License-Identifier: Apache-2.0
 * Tests the isolated timestamp arithmetic helper, not production consensus,
 * timestamp authenticity, VDF security, or resistance to faster hardware.
 */
#include <determ/consensus/dda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s at line %d\n", #cond, __LINE__); \
        exit(1); \
    } \
} while (0)

static void append_expected(dda_tracker_t *tracker, uint64_t timestamp) {
    CHECK(dda_commit_block(tracker, timestamp, dda_get_next_iterations(tracker)));
}

static void reject_unchanged(dda_tracker_t *tracker, uint64_t timestamp, uint64_t work) {
    dda_tracker_t before;
    memcpy(&before, tracker, sizeof(before));
    CHECK(!dda_commit_block(tracker, timestamp, work));
    CHECK(memcmp(tracker, &before, sizeof(*tracker)) == 0);
}

static void test_timestamp_window(void) {
    dda_tracker_t tracker;
    size_t i;
    dda_init(&tracker, 50000);
    CHECK(tracker.count == 0);
    CHECK(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);

    /* Zero is a valid first timestamp, but contributes no interval. */
    CHECK(dda_commit_block(&tracker, 0, 50000));
    CHECK(tracker.count == 1);
    CHECK(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);
    CHECK(dda_get_next_iterations(&tracker) == 50000);

    /* Four intervals: 2000, 2200, 2400, 2600; average 2300. */
    append_expected(&tracker, 2000);
    append_expected(&tracker, 4200);
    append_expected(&tracker, 6600);
    append_expected(&tracker, 9200);
    CHECK(tracker.count == 5);
    CHECK(calculate_average_vdf_time(&tracker) == 2300);
    for (i = 1; i <= 6; ++i) {
        append_expected(&tracker, 9200 + 3000 * i);
    }
    CHECK(tracker.count == DDA_WINDOW_SIZE + 1);
    CHECK(calculate_average_vdf_time(&tracker) == 2720);

    /* Eleven timestamps represent ten intervals; discard the 2000ms
     * interval and append 4000ms, yielding 29200/10 = 2920. */
    append_expected(&tracker, 31200);
    CHECK(tracker.count == DDA_WINDOW_SIZE + 1);
    CHECK(calculate_average_vdf_time(&tracker) == 2920);

    /* Repeated wraparound must not mistake ten timestamps for ten intervals. */
    dda_init(&tracker, 50000);
    for (i = 0; i < 50; ++i) {
        CHECK(dda_commit_block(&tracker, 3000 * i, 50000));
        CHECK(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);
        CHECK(dda_get_next_iterations(&tracker) == 50000);
    }
}

static void test_atomic_admission(void) {
    dda_tracker_t tracker;
    dda_init(&tracker, 100000);
    reject_unchanged(&tracker, 0, 0);
    reject_unchanged(&tracker, 0, 100001);
    CHECK(dda_commit_block(&tracker, 1000, 100000));
    CHECK(dda_commit_block(&tracker, 2500, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == 1500);
    CHECK(dda_get_next_iterations(&tracker) == 150000);
    CHECK(dda_verify_block_iterations(&tracker, 150000));
    CHECK(!dda_verify_block_iterations(&tracker, 100000));
    reject_unchanged(&tracker, 2500, 150000);
    reject_unchanged(&tracker, 2499, 150000);
    reject_unchanged(&tracker, 4000, 100000);
    reject_unchanged(&tracker, 4000, 150001);
    reject_unchanged(&tracker, 4000, UINT64_MAX);

    /* The incoming timestamp must not influence its own expected work. */
    CHECK(dda_commit_block(&tracker, 1000000, 150000));
    CHECK(tracker.current_iterations == 150000);
    CHECK(calculate_average_vdf_time(&tracker) == 499500);
    CHECK(dda_get_next_iterations(&tracker) == 142500);
    reject_unchanged(&tracker, 1000000, 142500);
    CHECK(!dda_commit_block(NULL, 0, 100000));
    CHECK(!dda_verify_block_iterations(NULL, 100000));
}

static void test_large_timestamps_and_replay(void) {
    dda_tracker_t tracker, replay;
    uint64_t timestamp;
    dda_init(&tracker, 100000);
    CHECK(dda_commit_block(&tracker, 0, 100000));
    CHECK(dda_commit_block(&tracker, UINT64_MAX, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == UINT32_MAX);
    CHECK(dda_get_next_iterations(&tracker) == 95000);
    reject_unchanged(&tracker, UINT64_MAX, 95000);

    dda_init(&tracker, 100000);
    CHECK(dda_commit_block(&tracker, UINT64_MAX - 3000, 100000));
    CHECK(dda_commit_block(&tracker, UINT64_MAX, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == TARGET_VDF_MS);

    dda_init(&tracker, 100000);
    CHECK(dda_commit_block(&tracker, 0, 100000));
    CHECK(dda_commit_block(&tracker, UINT32_MAX, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == UINT32_MAX);

    /* Values just beyond uint32_t must not wrap to a short/zero interval and
     * reverse the direction of calibration. UINT64_MAX alone has low bits
     * UINT32_MAX, so it cannot distinguish saturation from truncation. */
    dda_init(&tracker, 100000);
    CHECK(dda_commit_block(&tracker, 0, 100000));
    CHECK(dda_commit_block(&tracker, (uint64_t)UINT32_MAX + 1, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == UINT32_MAX);
    CHECK(dda_get_next_iterations(&tracker) == 95000);
    dda_init(&tracker, 100000);
    CHECK(dda_commit_block(&tracker, 0, 100000));
    CHECK(dda_commit_block(&tracker, (uint64_t)UINT32_MAX + 43, 100000));
    CHECK(calculate_average_vdf_time(&tracker) == UINT32_MAX);
    CHECK(dda_get_next_iterations(&tracker) == 95000);

    /* Same caller-supplied history produces identical state; local elapsed
     * times are absent from the API. This is not a branch-validation test. */
    dda_init(&tracker, 100000);
    dda_init(&replay, 100000);
    for (timestamp = 0; timestamp < 100000; timestamp += 3301) {
        uint64_t expected = dda_get_next_iterations(&tracker);
        CHECK(dda_commit_block(&tracker, timestamp, expected));
        CHECK(dda_commit_block(&replay, timestamp, expected));
        CHECK(memcmp(&tracker, &replay, sizeof(tracker)) == 0);
    }
}

static void test_calibration_limits(void) {
    dda_tracker_t tracker;
    CHECK(calibrate_vdf_iterations(200000, 1) == 300000);
    CHECK(calibrate_vdf_iterations(200000, 30000) == 190000);
    CHECK(calibrate_vdf_iterations(200000, 3000) == 200000);
    CHECK(calibrate_vdf_iterations(200000, 3001) == 199934);
    CHECK(calibrate_vdf_iterations(DDA_MIN_ITERATIONS, UINT32_MAX) == DDA_MIN_ITERATIONS);
    CHECK(calibrate_vdf_iterations(DDA_MAX_ITERATIONS, 1) == DDA_MAX_ITERATIONS);
    CHECK(calibrate_vdf_iterations(0, 3000) == DDA_MIN_ITERATIONS);
    CHECK(calibrate_vdf_iterations(UINT64_MAX, 3000) == DDA_MAX_ITERATIONS);
    dda_init(&tracker, 0);
    CHECK(tracker.current_iterations == DDA_MIN_ITERATIONS);
    dda_init(&tracker, UINT64_MAX);
    CHECK(tracker.current_iterations == DDA_MAX_ITERATIONS);
}

static void test_header_codec(void) {
    consensus_block_header_t header, decoded;
    uint8_t bytes[CONSENSUS_BLOCK_HEADER_SIZE + 1];
    size_t written = 0;
    memset(&header, 0, sizeof(header));
    header.block_index = 42;
    header.timestamp_ms = 1774000000000ULL;
    header.vdf_iterations = 105000;
    memset(header.prev_hash, 0xAA, 32);
    memset(header.merkle_root, 0xBB, 32);
    memset(header.vdf_output, 0xCC, 32);
    CHECK(consensus_block_header_encode(bytes, sizeof(bytes), &header, &written) == 0);
    CHECK(written == CONSENSUS_BLOCK_HEADER_SIZE);
    CHECK(bytes[16] == 0 && bytes[17] == 0 && bytes[18] == 0 && bytes[19] == 0);
    CHECK(bytes[20] == 0 && bytes[21] == 1 && bytes[22] == 0x9A && bytes[23] == 0x28);
    CHECK(consensus_block_header_decode(bytes, written, &decoded) == 0);
    CHECK(decoded.block_index == header.block_index);
    CHECK(decoded.timestamp_ms == header.timestamp_ms);
    CHECK(decoded.vdf_iterations == header.vdf_iterations);
    CHECK(memcmp(decoded.prev_hash, header.prev_hash, 32) == 0);
    CHECK(memcmp(decoded.merkle_root, header.merkle_root, 32) == 0);
    CHECK(memcmp(decoded.vdf_output, header.vdf_output, 32) == 0);
    CHECK(consensus_block_header_encode(bytes, CONSENSUS_BLOCK_HEADER_SIZE - 1, &header, &written) != 0);
    CHECK(consensus_block_header_decode(bytes, CONSENSUS_BLOCK_HEADER_SIZE - 1, &decoded) != 0);
    bytes[CONSENSUS_BLOCK_HEADER_SIZE] = 0;
    CHECK(consensus_block_header_decode(bytes, CONSENSUS_BLOCK_HEADER_SIZE + 1, &decoded) != 0);
}

int main(void) {
    test_timestamp_window();
    test_atomic_admission();
    test_large_timestamps_and_replay();
    test_calibration_limits();
    test_header_codec();
    puts("PASS: isolated deterministic timestamp DDA and header codec");
    return 0;
}
