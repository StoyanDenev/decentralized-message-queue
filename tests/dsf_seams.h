/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Native Deterministic Simulation Framework (DSF) Seams.
 *
 * Provides:
 *   1. Clock Injection Seam: determ_clock_now() preprocessor macro mapping
 *      to hardware monotonic time in production builds, and to a virtual,
 *      manually incremented test clock in DSF builds (-DDETERM_DSF_ENABLED).
 *      Allows instant 1999ms / 2001ms fast-forwarding without sleeping the CPU thread.
 *   2. Virtual Transport Seam: Socket readiness abstraction for epoll/kqueue/IOCP.
 *      Enables simulated EWOULDBLOCK and simulated recv() byte dropping to test
 *      the 1-of-2 straggler fallback deterministically.
 */

#ifndef DETERMINISTIC_TESTS_DSF_SEAMS_H
#define DETERMINISTIC_TESTS_DSF_SEAMS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "determ/time/clock.h"
#include "determ/net/virtual_transport.h"
#include "determ/crypto/vdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ── 1. Clock Injection Seam ─────────────────────────────────────────────────
 * determ_clock_now() macro returns monotonic time in nanoseconds.
 * In production: maps directly to clock_gettime(CLOCK_MONOTONIC) / mach_absolute_time().
 * Under -DDETERM_DSF_ENABLED: maps to virtual test clock advanced manually.
 */
#define determ_clock_now() determ_clock_now_ns()

/*
 * ── 2. Virtual Transport Seam Abstractions ──────────────────────────────────
 */
#if defined(DETERM_DSF_ENABLED)

/* Socket readiness event codes */
#define DSF_EV_READ   NET_EV_READ
#define DSF_EV_WRITE  NET_EV_WRITE
#define DSF_EV_ERROR  NET_EV_ERROR

/*
 * Set simulated socket readiness in virtual multiplexer (epoll/kqueue/IOCP)
 */
static inline void dsf_set_socket_ready(int fd, uint32_t flags, void *user_data) {
    determ_dsf_mark_ready(fd, flags, user_data);
}

/*
 * Inject simulated EWOULDBLOCK condition on receive operations
 */
static inline void dsf_inject_ewouldblock(bool enable) {
    determ_dsf_inject_ewouldblock_rx(enable);
}

/*
 * Force simulated recv() to drop a specified count of incoming bytes
 */
static inline void dsf_inject_drop_bytes(size_t byte_count) {
    determ_dsf_inject_drop_bytes(byte_count);
}

/*
 * Fast-forward virtual clock by milliseconds
 */
static inline void dsf_fast_forward_ms(uint64_t ms) {
    determ_dsf_clock_advance_ms(ms);
}

/*
 * Reset all virtual transport and clock faults
 */
static inline void dsf_reset_seams(void) {
    determ_dsf_clock_reset();
    determ_dsf_transport_reset();
}

#else

/* Production fallbacks (no simulation overhead) */
#define dsf_set_socket_ready(fd, flags, user_data) ((void)0)
#define dsf_inject_ewouldblock(enable)             ((void)0)
#define dsf_inject_drop_bytes(byte_count)          ((void)0)
#define dsf_fast_forward_ms(ms)                    ((void)0)
#define dsf_reset_seams()                          ((void)0)

#endif /* DETERM_DSF_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_TESTS_DSF_SEAMS_H */
