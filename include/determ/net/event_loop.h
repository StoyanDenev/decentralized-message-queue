/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Non-Blocking Event Loop.
 * Dual-backend:
 *   - macOS / BSD: kqueue (<sys/event.h>)
 *   - Linux:       epoll  (<sys/epoll.h>)
 * Other platforms compile to an unsupported stub: add/mod/del succeed without
 * registering anything and poll reports no events.
 *
 * Readiness is level-triggered on both backends, whether an fd was registered
 * by add() or changed by mod(): an fd is reported by every poll while it stays
 * readable/writable, so a handler may consume part of what is available.
 * mod() sets the complete interest set; interest it omits is removed.
 *
 * Strictly zero dynamic memory allocations.
 */

#ifndef DETERMINISTIC_NET_EVENT_LOOP_H
#define DETERMINISTIC_NET_EVENT_LOOP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NET_MAX_EVENTS_PER_POLL 64

typedef enum {
    NET_EV_READ  = (1 << 0),
    NET_EV_WRITE = (1 << 1),
    NET_EV_ERROR = (1 << 2),
    NET_EV_EOF   = (1 << 3)
} net_event_flags_t;

typedef struct {
    int fd;
    uint32_t flags; /* Bitmask of net_event_flags_t */
    void *user_data;
} net_event_t;

typedef struct {
    int poll_fd; /* kqueue or epoll file descriptor */
    bool running;
} net_event_loop_t;

/*
 * Initialize the event loop. Returns 0 on success, negative error code on failure.
 */
int net_event_loop_init(net_event_loop_t *loop);

/*
 * Register an FD with the event loop.
 */
int net_event_loop_add(net_event_loop_t *loop, int fd, uint32_t events, void *user_data);

/*
 * Replace the registered interest set for an FD (NET_EV_READ | NET_EV_WRITE).
 */
int net_event_loop_mod(net_event_loop_t *loop, int fd, uint32_t events, void *user_data);

/*
 * Remove an FD from the event loop.
 */
int net_event_loop_del(net_event_loop_t *loop, int fd);

/*
 * Poll for ready events with a millisecond timeout.
 * timeout_ms = -1 blocks indefinitely; 0 returns immediately.
 * Returns count of ready events, 0 on timeout, negative on error.
 */
int net_event_loop_poll(net_event_loop_t *loop, int timeout_ms,
                        net_event_t *out_events, int max_events);

/*
 * Stop the event loop.
 */
void net_event_loop_stop(net_event_loop_t *loop);

/*
 * Close event loop descriptors and clean up.
 */
void net_event_loop_close(net_event_loop_t *loop);

/*
 * Socket Utility Helpers (pure POSIX <sys/socket.h> <fcntl.h>)
 */
int net_socket_set_nonblocking(int fd);
int net_socket_set_reuseaddr(int fd);
int net_socket_set_nodelay(int fd);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_NET_EVENT_LOOP_H */
