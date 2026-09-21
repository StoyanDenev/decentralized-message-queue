/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ Clock Injection Seam (Pure C99).
 * Provides zero-cost monotonic time fetching for production builds and
 * virtual, deterministic time progression for DSF test builds.
 */

#ifndef DETERMINISTIC_TIME_CLOCK_H
#define DETERMINISTIC_TIME_CLOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(DETERM_DSF_ENABLED)

/*
 * DSF Virtual Clock API
 */
uint64_t determ_clock_now_ns(void);
uint64_t determ_clock_now_ms(void);

void     determ_dsf_clock_set_ns(uint64_t ns);
void     determ_dsf_clock_advance_ns(uint64_t delta_ns);
void     determ_dsf_clock_advance_ms(uint64_t delta_ms);
void     determ_dsf_clock_reset(void);

#define determ_clock_now() determ_clock_now_ns()

#else

/*
 * Production Zero-Cost Monotonic Clock
 */
#if defined(__APPLE__)
#include <mach/mach_time.h>
static inline uint64_t determ_clock_now_ns(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        (void)mach_timebase_info(&tb);
    }
    uint64_t t = mach_absolute_time();
    return (uint64_t)(((__uint128_t)t * tb.numer) / tb.denom);
}
#else
#include <time.h>
static inline uint64_t determ_clock_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0ULL;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}
#endif

static inline uint64_t determ_clock_now_ms(void) {
    return determ_clock_now_ns() / 1000000ULL;
}

#define determ_clock_now() determ_clock_now_ns()

#endif /* DETERM_DSF_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_TIME_CLOCK_H */
