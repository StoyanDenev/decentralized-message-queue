/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Native Event Loop Reactor.
 * Single-threaded I/O multiplexer using native OS interfaces:
 *   #if defined(__linux__) -> epoll
 *   #elif defined(__APPLE__) -> kqueue
 *   #elif defined(_WIN32) -> select()
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <determ/net/reactor.h>
#include <determ/time/clock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define close(s) closesocket(s)
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define EINTR WSAEINTR
#define errno WSAGetLastError()
typedef int socklen_t;
typedef int ssize_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#endif

/*
 * Static memory arena for socket connection states: strictly zero malloc()
 */
static struct connection_state connections[MAX_CONNECTIONS];

static struct connection_state* allocate_slot(reactor_t *reactor) {
    if (!reactor || !reactor->slots) return NULL;
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        if (reactor->slots[i].state == REACTOR_SLOT_UNUSED) {
            reactor->slots[i].state = REACTOR_SLOT_CONNECTING;
            reactor->slots[i].fd = -1;
            reactor->slots[i].rx_len = 0;
            reactor->slots[i].tx_len = 0;
            reactor->slots[i].on_read = NULL;
            reactor->slots[i].on_write = NULL;
            reactor->slots[i].on_accept = NULL;
            reactor->slots[i].on_close = NULL;
            reactor->slots[i].on_error = NULL;
            reactor->slots[i].user_data = NULL;
            reactor->active_count++;
            return &reactor->slots[i];
        }
    }
    return NULL;
}

static struct connection_state* find_slot_by_fd(reactor_t *reactor, int fd) {
    if (!reactor || !reactor->slots || fd < 0) return NULL;
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        if (reactor->slots[i].state != REACTOR_SLOT_UNUSED && reactor->slots[i].fd == fd) {
            return &reactor->slots[i];
        }
    }
    return NULL;
}

int reactor_init(reactor_t *reactor) {
    if (!reactor) return -1;
    memset(reactor, 0, sizeof(*reactor));
    memset(connections, 0, sizeof(connections));
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        connections[i].fd = -1;
        connections[i].state = REACTOR_SLOT_UNUSED;
    }
    reactor->slots = connections;
    reactor->active_count = 0;
    reactor->running = false;
    reactor->ingestion_halted = false;
    reactor->consensus_sm = NULL;
    reactor->epoch_start_ns = 0;

    return net_event_loop_init(&reactor->loop);
}

void reactor_bind_consensus(reactor_t *reactor, duel_state_machine_t *sm, uint64_t epoch_start_ns) {
    if (!reactor) return;
    reactor->consensus_sm = sm;
    reactor->epoch_start_ns = epoch_start_ns;
    reactor->ingestion_halted = false;
}

int reactor_listen(reactor_t *reactor,
                   uint16_t port,
                   reactor_accept_fn on_accept,
                   void *user_data) {
    if (!reactor) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (net_socket_set_reuseaddr(fd) != 0 ||
        net_socket_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 128) != 0) {
        close(fd);
        return -1;
    }

    struct connection_state *slot = allocate_slot(reactor);
    if (!slot) {
        close(fd);
        return -1;
    }

    slot->fd = fd;
    slot->state = REACTOR_SLOT_LISTENER;
    slot->on_accept = on_accept;
    slot->user_data = user_data;
    slot->registered_events = NET_EV_READ;

    if (net_event_loop_add(&reactor->loop, fd, NET_EV_READ, slot) != 0) {
        close(fd);
        slot->state = REACTOR_SLOT_UNUSED;
        reactor->active_count--;
        return -1;
    }

    return fd;
}

int reactor_register_client(reactor_t *reactor,
                            int client_fd,
                            reactor_read_fn on_read,
                            reactor_close_fn on_close,
                            void *user_data) {
    if (!reactor || client_fd < 0) return -1;

    if (net_socket_set_nonblocking(client_fd) != 0 ||
        net_socket_set_nodelay(client_fd) != 0) {
        return -1;
    }

    struct connection_state *slot = allocate_slot(reactor);
    if (!slot) return -1;

    slot->fd = client_fd;
    slot->state = REACTOR_SLOT_CONNECTED;
    slot->on_read = on_read;
    slot->on_close = on_close;
    slot->user_data = user_data;
    slot->registered_events = NET_EV_READ;

    if (net_event_loop_add(&reactor->loop, client_fd, NET_EV_READ, slot) != 0) {
        slot->state = REACTOR_SLOT_UNUSED;
        reactor->active_count--;
        return -1;
    }

    return 0;
}

int reactor_send(reactor_t *reactor, int fd, const void *data, size_t len) {
    if (!reactor || fd < 0 || !data || len == 0) return -1;

    struct connection_state *slot = find_slot_by_fd(reactor, fd);
    if (!slot || slot->state != REACTOR_SLOT_CONNECTED) return -1;

    /* If tx_buf already has pending data, append to buffer */
    if (slot->tx_len > 0) {
        if (slot->tx_len + len > REACTOR_BUFFER_CAPACITY) {
            return -1; /* Buffer overflow */
        }
        memcpy(&slot->tx_buf[slot->tx_len], data, len);
        slot->tx_len += len;
        return (int)len;
    }

    /* Direct non-blocking write */
    ssize_t written = send(fd, (const char *)data, len, 0);
    if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (len > REACTOR_BUFFER_CAPACITY) return -1;
            memcpy(slot->tx_buf, data, len);
            slot->tx_len = len;

            slot->registered_events |= NET_EV_WRITE;
            net_event_loop_mod(&reactor->loop, fd, slot->registered_events, slot);
            return (int)len;
        }
        return -1;
    }

    /* Partial write handling */
    if ((size_t)written < len) {
        size_t rem = len - (size_t)written;
        if (rem > REACTOR_BUFFER_CAPACITY) return -1;
        memcpy(slot->tx_buf, (const uint8_t*)data + written, rem);
        slot->tx_len = rem;

        slot->registered_events |= NET_EV_WRITE;
        net_event_loop_mod(&reactor->loop, fd, slot->registered_events, slot);
    }

    return (int)len;
}

static void handle_listener_read(reactor_t *reactor, struct connection_state *slot) {
    if (!reactor || reactor->ingestion_halted) return;

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(slot->fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) continue;
            break;
        }

        if (reactor->ingestion_halted) {
            close(client_fd);
            break;
        }

        if (slot->on_accept) {
            slot->on_accept(slot->fd, client_fd, slot->user_data);
        } else {
            close(client_fd);
        }
    }
}

static void handle_client_read(reactor_t *reactor, struct connection_state *slot) {
    if (!reactor || reactor->ingestion_halted) return;

    while (1) {
        ssize_t n = recv(slot->fd, (char *)slot->rx_buf, sizeof(slot->rx_buf), 0);
        if (n > 0) {
            if (slot->on_read) {
                slot->on_read(slot->fd, slot->rx_buf, (size_t)n, slot->user_data);
            }
        } else if (n == 0) {
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) continue;
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        }
    }
}

static void handle_client_write(reactor_t *reactor, struct connection_state *slot) {
    if (slot->tx_len == 0) {
        slot->registered_events &= ~NET_EV_WRITE;
        net_event_loop_mod(&reactor->loop, slot->fd, slot->registered_events, slot);
        return;
    }

    while (slot->tx_len > 0) {
        ssize_t n = send(slot->fd, (const char *)slot->tx_buf, slot->tx_len, 0);
        if (n > 0) {
            if ((size_t)n >= slot->tx_len) {
                slot->tx_len = 0;
                slot->registered_events &= ~NET_EV_WRITE;
                net_event_loop_mod(&reactor->loop, slot->fd, slot->registered_events, slot);
                if (slot->on_write) {
                    slot->on_write(slot->fd, slot->user_data);
                }
                break;
            } else {
                size_t rem = slot->tx_len - (size_t)n;
                memmove(slot->tx_buf, slot->tx_buf + n, rem);
                slot->tx_len = rem;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) continue;
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        }
    }
}

int reactor_step(reactor_t *reactor, int timeout_ms) {
    if (!reactor) return -1;

    net_event_t events[NET_MAX_EVENTS_PER_POLL];
    int nev = net_event_loop_poll(&reactor->loop, timeout_ms, events, NET_MAX_EVENTS_PER_POLL);
    if (nev <= 0) return nev;

    for (int i = 0; i < nev; i++) {
        struct connection_state *slot = (struct connection_state *)events[i].user_data;
        if (!slot || slot->state == REACTOR_SLOT_UNUSED) continue;

        if (events[i].flags & (NET_EV_ERROR | NET_EV_EOF)) {
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            continue;
        }

        if (events[i].flags & NET_EV_READ) {
            if (slot->state == REACTOR_SLOT_LISTENER) {
                handle_listener_read(reactor, slot);
            } else if (slot->state == REACTOR_SLOT_CONNECTED) {
                handle_client_read(reactor, slot);
            }
        }

        if (slot->state == REACTOR_SLOT_CONNECTED && (events[i].flags & NET_EV_WRITE)) {
            handle_client_write(reactor, slot);
        }
    }

    return nev;
}

int reactor_run_epoch(reactor_t *reactor, duel_state_machine_t *sm, uint64_t epoch_start_ns) {
    if (!reactor) return -1;
    reactor->running = true;
    reactor->ingestion_halted = false;
    reactor->consensus_sm = sm;
    reactor->epoch_start_ns = epoch_start_ns;

    while (1) {
        uint64_t now = determ_clock_now();
        uint64_t elapsed_ns = (now >= epoch_start_ns) ? (now - epoch_start_ns) : 0;

        /*
         * Monotonic Timer Integration:
         * When clock hits exactly 2000ms (2,000,000,000 ns) from epoch start:
         * 1. Instantly halt network ingestion
         * 2. Trigger REVEAL_WINDOW buzzer
         * 3. Transition state machine to VDF_EVALUATION (or ABORTED)
         */
        if (elapsed_ns >= 2000000000ULL) {
            reactor->ingestion_halted = true;
            if (sm) {
                duel_state_poll_buzzer(sm);
            }
            break;
        }

        uint64_t remaining_ns = 2000000000ULL - elapsed_ns;
        int slice_ms = (int)(remaining_ns / 1000000ULL);
        if (slice_ms <= 0) slice_ms = 0;
        else if (slice_ms > 10) slice_ms = 10;

        int nev = reactor_step(reactor, slice_ms);
        if (nev < 0 && errno != EINTR) {
            break;
        }

        if (sm && (sm->state == DUEL_STATE_VDF_EVALUATION ||
                   sm->state == DUEL_STATE_ABORTED ||
                   sm->state == DUEL_STATE_COMPLETED)) {
            break;
        }

        if (!reactor->running) {
            break;
        }
    }

    return 0;
}

void reactor_run(reactor_t *reactor) {
    if (!reactor) return;
    reactor->running = true;
    while (reactor->running) {
        if (reactor->consensus_sm && reactor->epoch_start_ns > 0) {
            uint64_t now = determ_clock_now();
            uint64_t elapsed_ns = (now >= reactor->epoch_start_ns) ? (now - reactor->epoch_start_ns) : 0;
            if (elapsed_ns >= 2000000000ULL) {
                reactor->ingestion_halted = true;
                duel_state_poll_buzzer(reactor->consensus_sm);
                break;
            }
        }
        reactor_step(reactor, 10);
    }
}

void reactor_stop(reactor_t *reactor) {
    if (reactor) {
        reactor->running = false;
    }
}

void reactor_close_fd(reactor_t *reactor, int fd) {
    if (!reactor || fd < 0) return;

    struct connection_state *slot = find_slot_by_fd(reactor, fd);
    if (!slot) return;

    net_event_loop_del(&reactor->loop, fd);
    close(fd);

    if (slot->on_close) {
        slot->on_close(fd, slot->user_data);
    }

    slot->state = REACTOR_SLOT_UNUSED;
    slot->fd = -1;
    slot->registered_events = 0;
    slot->rx_len = 0;
    slot->tx_len = 0;
    if (reactor->active_count > 0) {
        reactor->active_count--;
    }
}

void reactor_destroy(reactor_t *reactor) {
    if (!reactor) return;
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        if (reactor->slots[i].state != REACTOR_SLOT_UNUSED && reactor->slots[i].fd >= 0) {
            net_event_loop_del(&reactor->loop, reactor->slots[i].fd);
            close(reactor->slots[i].fd);
            reactor->slots[i].state = REACTOR_SLOT_UNUSED;
            reactor->slots[i].fd = -1;
        }
    }
    reactor->active_count = 0;
    net_event_loop_close(&reactor->loop);
}
