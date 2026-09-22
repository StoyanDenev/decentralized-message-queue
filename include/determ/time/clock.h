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

/*
 * Portable scaled conversion: floor(ticks * 1e9 / freq), saturated at
 * UINT64_MAX. An unavailable frequency (zero) returns zero.
 * The intermediate product need not fit in uint64_t.
 */
static inline uint64_t determ_qpc_to_ns(uint64_t ticks, uint64_t freq) {
    if (freq == 0ULL) {
        return 0ULL;
    }
    const uint64_t scale = 1000000000ULL;
    const uint64_t whole = ticks / freq;
    const uint64_t fraction_ticks = ticks % freq;
    uint64_t quotient = 0;
    uint64_t remainder = 0;
    uint64_t ns;
    uint32_t bit;

    if (whole > UINT64_MAX / scale) {
        return UINT64_MAX;
    }
    ns = whole * scale;

    /* Long multiplication with division after each bit of scale. For each
     * processed prefix p: quotient=floor(fraction_ticks*p/freq), and
     * remainder=(fraction_ticks*p)%freq. Subtraction guards implement
     * modular addition without overflowing, even when freq=UINT64_MAX.
     * quotient is always less than scale (1e9).
     */
    for (bit = 1U << 29; bit != 0; bit >>= 1) {
        quotient *= 2;
        if (remainder >= freq - remainder) {
            remainder -= freq - remainder;
            quotient++;
        } else {
            remainder += remainder;
        }
        if ((scale & bit) != 0) {
            if (remainder >= freq - fraction_ticks) {
                remainder -= freq - fraction_ticks;
                quotient++;
            } else {
                remainder += fraction_ticks;
            }
        }
    }
    if (quotient > UINT64_MAX - ns) {
        return UINT64_MAX;
    }
    return ns + quotient;
}

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
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static inline uint64_t determ_clock_now_ns(void) {
    static LARGE_INTEGER freq;
    static int init = 0;
    if (!init) {
        QueryPerformanceFrequency(&freq);
        init = 1;
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    uint64_t ticks = counter.QuadPart;
    uint64_t f = freq.QuadPart;
    return determ_qpc_to_ns(ticks, f);
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
