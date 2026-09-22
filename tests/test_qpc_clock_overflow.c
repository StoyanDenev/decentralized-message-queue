/* SPDX-License-Identifier: Apache-2.0
 * Portable QPC arithmetic regression; no simulated clock or transport.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <determ/time/clock.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s at line %d\n", #cond, __LINE__); \
        exit(1); \
    } \
} while (0)

static void test_reference_vectors(void) {
    /* Expected values were calculated with arbitrary-precision integer
     * arithmetic: min(UINT64_MAX, floor(ticks * 1000000000 / frequency)).
     * Includes overflow in the fractional product and in both parts of
     * the final result, rounding, zero, and UINT64_MAX frequencies.
     */
    static const struct { uint64_t ticks, frequency, expected; } cases[] = {
        { 0ULL, 0ULL, 0ULL },
        { 1ULL, 0ULL, 0ULL },
        { UINT64_MAX, 0ULL, 0ULL },
        { 0ULL, UINT64_MAX, 0ULL },
        { 1ULL, 3ULL, 333333333ULL },
        { 2ULL, 3ULL, 666666666ULL },
        { 3ULL, 3ULL, 1000000000ULL },
        { 1ULL, UINT64_MAX, 0ULL },
        { UINT64_MAX - 1, UINT64_MAX, 999999999ULL },
        { UINT64_MAX, UINT64_MAX, 1000000000ULL },
        { UINT64_MAX, 1ULL, UINT64_MAX },
        { 18446744073ULL, 1ULL, 18446744073000000000ULL },
        { 18446744074ULL, 1ULL, UINT64_MAX },
        { UINT64_MAX, 1000000000ULL, UINT64_MAX },
        { UINT64_MAX - 1, 1000000000ULL, UINT64_MAX - 1 },
        { UINT64_MAX, 1000000001ULL, 18446744055262807559ULL },
        { 18446744055553255925ULL, 999999999ULL, UINT64_MAX },
        { 1844674407300ULL, 636094620784634138ULL, 2900ULL },
        { 1844674407300ULL, 10000000ULL, 184467440730000ULL },
        { UINT64_MAX, 9223372036854775808ULL, 1999999999ULL },
        { 9223372036854775809ULL, UINT64_MAX, 500000000ULL },
        { UINT64_MAX - 1, 9223372036854775809ULL, 1999999999ULL }
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CHECK(determ_qpc_to_ns(cases[i].ticks, cases[i].frequency) == cases[i].expected);
    }
}

static void test_bounded_product_oracle(void) {
    uint64_t ticks, frequency;
    /* Independent direct-product oracle in the range where it cannot
     * overflow. Exercises fractional rounding without copying the helper.
     */
    for (ticks = 0; ticks <= 128; ++ticks) {
        for (frequency = 1; frequency <= 128; ++frequency) {
            CHECK(determ_qpc_to_ns(ticks, frequency) == ticks * 1000000000ULL / frequency);
        }
    }
    for (ticks = UINT64_MAX / 1000000000ULL - 32;
         ticks <= UINT64_MAX / 1000000000ULL; ++ticks) {
        for (frequency = 1; frequency <= 128; ++frequency) {
            CHECK(determ_qpc_to_ns(ticks, frequency) == ticks * 1000000000ULL / frequency);
        }
    }
}

int main(void) {
    test_reference_vectors();
    test_bounded_product_oracle();
    puts("PASS: portable QPC scaled conversion");
    return 0;
}
