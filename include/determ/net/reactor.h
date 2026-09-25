/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Hosted C99 Native Event Loop Reactor.
 * Single-threaded I/O multiplexer over net_event_loop_t: epoll on Linux,
 * kqueue on macOS/BSD. Other platforms get the event loop's unsupported stub,
 * which registers nothing and reports no events.
 *
 *   - Strictly zero dynamic memory allocation (a fixed table of
 *     REACTOR_MAX_SOCKETS slots).
 *   - Non-blocking I/O: accept and read handlers run until EWOULDBLOCK/EAGAIN,
 *     the write handler until its queue is empty or the socket would block.
 *   - Not thread-safe; callbacks run on the caller's thread inside
 *     reactor_step().
 */

#ifndef DETERMINISTIC_NET_REACTOR_H
#define DETERMINISTIC_NET_REACTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "determ/net/event_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REACTOR_MAX_SOCKETS     128U
#define REACTOR_BUFFER_CAPACITY 4096U

typedef enum {
    REACTOR_SLOT_UNUSED = 0,
    REACTOR_SLOT_LISTENER,
    REACTOR_SLOT_CONNECTED,
    REACTOR_SLOT_CONNECTING
} reactor_slot_state_t;

typedef void (*reactor_read_fn)(int fd, const uint8_t *data, size_t len, void *user_data);
typedef void (*reactor_write_fn)(int fd, void *user_data);
typedef void (*reactor_accept_fn)(int listener_fd, int client_fd, void *user_data);
typedef void (*reactor_close_fn)(int fd, void *user_data);
typedef void (*reactor_error_fn)(int fd, int err, void *user_data);

typedef struct {
    int                  fd;
    uintptr_t            registration; /* captured event identity; meaningful only while state != REACTOR_SLOT_UNUSED */
    reactor_slot_state_t state;
    uint32_t             registered_events; /* NET_EV_READ | NET_EV_WRITE */

    uint8_t              rx_buf[REACTOR_BUFFER_CAPACITY];
    size_t               rx_len;

    uint8_t              tx_buf[REACTOR_BUFFER_CAPACITY];
    size_t               tx_len;

    reactor_read_fn      on_read;
    reactor_write_fn     on_write;
    reactor_accept_fn    on_accept;
    reactor_close_fn     on_close;
    reactor_error_fn     on_error;
    void                *user_data;
} reactor_socket_t;

typedef struct {
    net_event_loop_t  loop;
    reactor_socket_t  slots[REACTOR_MAX_SOCKETS];
    size_t            active_count;
    uintptr_t         next_generation; /* never wraps: at UINTPTR_MAX >> 8 new registrations are refused */
    bool              running;
} reactor_t;

/*
 * Initialize the reactor and its underlying OS multiplexer (kqueue / epoll) in
 * fresh or previously destroyed storage (never a live reactor).
 * Returns 0 on success, negative error code on failure.
 *
 * Ownership: one thread owns every reactor and peer mesh in the process. The
 * nested-dispatch guard is a single module-wide flag, so using a reactor from a
 * second thread is unsupported, not merely unsynchronized. That owner serializes
 * all calls and does not modify slot/cursor fields directly.
 * Initialization, stepping and running of any reactor from inside a callback are
 * refused and leave the supplied storage unchanged (on fresh zero-filled storage
 * such a refusal establishes no descriptor sentinels: do not close it then).
 * Outside callbacks, a failed init leaves descriptor sentinels safe to close.
 * Registrations draw from a generation counter that is refused rather than
 * wrapped at UINTPTR_MAX >> 8 (2^24 - 1 registrations on a 32-bit host).
 */
int reactor_init(reactor_t *reactor);

/*
 * Start listening on a TCP port with non-blocking accept.
 * Returns listener fd on success, negative error code on failure.
 */
int reactor_listen(reactor_t *reactor,
                   uint16_t port,
                   reactor_accept_fn on_accept,
                   void *user_data);

/*
 * Register an existing connected socket descriptor with the reactor.
 * Sets the socket to non-blocking mode and registers read interest.
 * Returns 0 on success, negative error code on failure.
 */
int reactor_register_client(reactor_t *reactor,
                            int client_fd,
                            reactor_read_fn on_read,
                            reactor_close_fn on_close,
                            void *user_data);

/*
 * Send data over a registered socket.
 * If socket would block (EAGAIN/EWOULDBLOCK), remaining bytes are queued
 * in the static tx_buf and write readiness is monitored.
 * Requests above REACTOR_BUFFER_CAPACITY are rejected before any write.
 * Returns bytes accepted/sent, or -1 on error.
 */
int reactor_send(reactor_t *reactor, int fd, const void *data, size_t len);

/*
 * Execute a single iteration of the event multiplexer.
 * timeout_ms: milliseconds to block (0 = immediate non-blocking poll, -1 = block).
 * Returns number of handled events, 0 on timeout, negative on error.
 */
int reactor_step(reactor_t *reactor, int timeout_ms);

/*
 * Run the event loop until stopped.
 */
void reactor_run(reactor_t *reactor);

/*
 * Signal the event loop to stop.
 */
void reactor_stop(reactor_t *reactor);

/*
 * Retire a registered socket before invoking on_close; callbacks may register
 * a replacement. RX pointers are borrowed and remain valid only until callback
 * return or an operation that closes/reuses their slot, whichever happens first.
 * Close a registered socket and free its static slot.
 */
void reactor_close_fd(reactor_t *reactor, int fd);

/*
 * Tear down the reactor and close all open sockets.
 */
void reactor_destroy(reactor_t *reactor);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_NET_REACTOR_H */
