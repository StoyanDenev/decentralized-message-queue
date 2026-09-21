/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ Clock Injection Seam Implementation (Pure C99).
 */

#include "determ/time/clock.h"

#if defined(DETERM_DSF_ENABLED)

static uint64_t s_virtual_clock_ns = 1000000000ULL; /* Start at 1.0s to prevent 0-edge anomalies */

uint64_t determ_clock_now_ns(void) {
    return s_virtual_clock_ns;
}

uint64_t determ_clock_now_ms(void) {
    return s_virtual_clock_ns / 1000000ULL;
}

void determ_dsf_clock_set_ns(uint64_t ns) {
    s_virtual_clock_ns = ns;
}

void determ_dsf_clock_advance_ns(uint64_t delta_ns) {
    s_virtual_clock_ns += delta_ns;
}

void determ_dsf_clock_advance_ms(uint64_t delta_ms) {
    s_virtual_clock_ns += (delta_ms * 1000000ULL);
}

void determ_dsf_clock_reset(void) {
    s_virtual_clock_ns = 1000000000ULL;
}

#else

/* Production symbol export if needed */
typedef int determ_clock_c_unused_t;

#endif
