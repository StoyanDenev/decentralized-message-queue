/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Windows QPC Nanoseconds Scaled Arithmetic Overflow Test.
 * Asserts that deterministically passing ticks = 1844674407300ULL
 * into the QPC conversion routine uses split division to return
 * accurate nanoseconds without overflowing uint64_t to 29.
 */

#include "test_harness.h"
#include <determ/time/clock.h>

static void test_qpc_clock_overflow_prevention(void) {
    printf("[TEST] Windows QPC Scaled Arithmetic Overflow Prevention...\n");

    /*
     * Auditor Test Vector:
     * ticks = 1844674407300ULL
     * freq  = 636094620784634138ULL
     *
     * Unsafe:
     * (ticks * 1000000000ULL) % 2^64 = 18446744002754390016ULL
     * 18446744002754390016ULL / 636094620784634138ULL == 29ULL (Catastrophic overflow truncation)
     *
     * Safe Split Division:
     * (ticks / freq) * 1B + ((ticks % freq) * 1B) / freq == 2900ULL (Mathematically exact)
     */
    uint64_t ticks = 1844674407300ULL;
    uint64_t freq = 636094620784634138ULL;

    uint64_t ns = determ_qpc_to_ns(ticks, freq);

    printf("  Input ticks: %llu, freq: %llu\n", (unsigned long long)ticks, (unsigned long long)freq);
    printf("  Result ns:   %llu\n", (unsigned long long)ns);

    /* HARD ASSERTION: Must NOT overflow to 29 */
    TEST_ASSERT(ns != 29ULL);
    TEST_ASSERT(ns == 2900ULL);

    /* Test Standard 10MHz QPC Frequency on Windows */
    uint64_t qpc_10mhz = 10000000ULL;
    uint64_t ns_10mhz = determ_qpc_to_ns(ticks, qpc_10mhz);
    TEST_ASSERT(ns_10mhz == 184467440730000ULL);

    printf("  -> PASS: Windows QPC conversion verified safe against uint64_t overflow.\n");
}

int main(void) {
    test_harness_init("test_qpc_clock_overflow");
    test_qpc_clock_overflow_prevention();
    test_harness_finish("test_qpc_clock_overflow");
    return 0;
}
