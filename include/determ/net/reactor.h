/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Native Event Loop Reactor.
 * Single-threaded I/O multiplexer using native OS interfaces (kqueue / epoll / select).
 *
 * Guarantees:
 *   - Strictly zero dynamic memory allocation (connections[MAX_CONNECTIONS]).
 *   - Non-blocking I/O handling with graceful EWOULDBLOCK/EAGAIN quiescence.
 *   - Monotonic timer integration: 2000ms epoch buzzer halting network ingestion
 *     and transitioning consensus state machine to VDF_EVALUATION.
 */

#ifndef DETERMINISTIC_NET_REACTOR_H
#define DETERMINISTIC_NET_REACTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "determ/net/event_loop.h"
#include "determ/consensus/duel_state.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CONNECTIONS         128U
#define REACTOR_MAX_SOCKETS     MAX_CONNECTIONS
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

struct connection_state {
    int                  fd;
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
};

typedef struct connection_state reactor_socket_t;
typedef struct connection_state connection_state_t;

typedef struct {
    net_event_loop_t         loop;
    struct connection_state *slots;
    size_t                   active_count;
    bool                     running;
    bool                     ingestion_halted;
    duel_state_machine_t    *consensus_sm;
    uint64_t                 epoch_start_ns;
} reactor_t;

/*
 * Initialize the reactor and its underlying OS multiplexer (kqueue / epoll / select).
 * Allocates zero dynamic memory; uses static connections arena.
 * Returns 0 on success, negative error code on failure.
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
 * Returns bytes accepted/sent, or -1 on error.
 */
int reactor_send(reactor_t *reactor, int fd, const void *data, size_t len);

/*
 * Execute a single iteration of the event multiplexer.
 * timeout_ms: milliseconds to block (0 = non-blocking poll, -1 = block indefinitely).
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
 * Bind consensus state machine and epoch start time to reactor.
 */
void reactor_bind_consensus(reactor_t *reactor, duel_state_machine_t *sm, uint64_t epoch_start_ns);

/*
 * Run a single consensus epoch event loop.
 * Integrates determ_clock_now() monotonic timer. When clock hits exactly 2000ms
 * from epoch start, instantly halts network ingestion, triggers REVEAL_WINDOW buzzer,
 * and transitions state machine to VDF_EVALUATION.
 * Returns 0 on success, negative on error.
 */
int reactor_run_epoch(reactor_t *reactor, duel_state_machine_t *sm, uint64_t epoch_start_ns);

/*
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
