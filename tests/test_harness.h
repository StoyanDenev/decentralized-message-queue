/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Lightweight, dependency-free C99 native test harness utilizing standard assert.h.
 * Activates Deterministic Simulation Framework (DSF) seams: Virtual Clock and
 * Virtual Transport.
 */

#ifndef DETERMINISTIC_TEST_HARNESS_H
#define DETERMINISTIC_TEST_HARNESS_H

#ifndef DETERM_DSF_ENABLED
#define DETERM_DSF_ENABLED 1
#endif

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "dsf_seams.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        assert(cond); \
        abort(); \
    } \
} while (0)

#define TEST_CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s at %s:%d)\n", msg, #cond, __FILE__, __LINE__); \
        assert(cond); \
        abort(); \
    } \
} while (0)

static inline void test_harness_init(const char *suite_name) {
    printf("=================================================================\n");
    printf("Running C99 DSF Test Suite: %s\n", suite_name);
    printf("=================================================================\n");
    dsf_reset_seams();
}

static inline void test_harness_finish(const char *suite_name) {
    printf("=================================================================\n");
    printf("PASS: %s completed successfully.\n", suite_name);
    printf("=================================================================\n");
}

#endif /* DETERMINISTIC_TEST_HARNESS_H */
