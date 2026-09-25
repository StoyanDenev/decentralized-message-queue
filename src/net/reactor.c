/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Hosted C99 Native Event Loop Reactor Implementation.
 * Single-threaded I/O multiplexer over net_event_loop_t (epoll / kqueue; see
 * reactor.h for other platforms).
 *
 * Zero dynamic memory allocations.
 */

#include "determ/net/reactor.h"

#if defined(__linux__)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#elif defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
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
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include <string.h>
#include <stdio.h>

/* The OS stores this immutable numeric cookie, never a pointer to reusable
 * slot state. Eight low bits encode index+1 (zero is not a registration).
 * Qualified Linux/macOS host ABIs preserve uintptr_t cookies through opaque
 * user_data. This integer/pointer round trip is a platform contract, not a
 * portable-C99 theorem; a future freestanding backend must preserve tokens. */
#define REACTOR_COOKIE_BITS 8U
#define REACTOR_COOKIE_MASK ((uintptr_t)255U)
typedef char reactor_cookie_index_fits[(REACTOR_MAX_SOCKETS < 255U) ? 1 : -1];
static bool reactor_dispatching;

static reactor_socket_t *find_registration(reactor_t *reactor, uintptr_t cookie) {
    uintptr_t encoded = cookie & REACTOR_COOKIE_MASK;
    if (encoded == 0 || encoded > REACTOR_MAX_SOCKETS) return NULL;
    reactor_socket_t *slot = &reactor->slots[encoded - 1U];
    return slot->state != REACTOR_SLOT_UNUSED && slot->registration == cookie ? slot : NULL;
}

static int reactor_prepare_socket(int fd) {
#ifdef SO_NOSIGPIPE
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) != 0) return -1;
#elif !defined(MSG_NOSIGNAL)
    (void)fd;
    return -1; /* No qualified per-socket/per-send SIGPIPE suppression. */
#endif
    return net_socket_set_nonblocking(fd) != 0 || net_socket_set_nodelay(fd) != 0 ? -1 : 0;
}

static ssize_t reactor_socket_send(int fd, const void *data, size_t len) {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    return send(fd, (const char *)data, len, flags);
}

static reactor_socket_t* find_slot_by_fd(reactor_t *reactor, int fd) {
    if (!reactor || fd < 0) return NULL;
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        if (reactor->slots[i].state != REACTOR_SLOT_UNUSED && reactor->slots[i].fd == fd) {
            return &reactor->slots[i];
        }
    }
    return NULL;
}

static reactor_socket_t* allocate_slot(reactor_t *reactor) {
    if (!reactor || reactor->next_generation == (UINTPTR_MAX >> REACTOR_COOKIE_BITS)) return NULL;
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        if (reactor->slots[i].state == REACTOR_SLOT_UNUSED) {
            memset(&reactor->slots[i], 0, sizeof(reactor_socket_t));
            reactor->slots[i].fd = -1;
            reactor->next_generation++;
            reactor->slots[i].registration = (reactor->next_generation << REACTOR_COOKIE_BITS) | (i + 1U);
            reactor->active_count++;
            return &reactor->slots[i];
        }
    }
    return NULL;
}

int reactor_init(reactor_t *reactor) {
    if (!reactor || reactor_dispatching) return -1;
    memset(reactor, 0, sizeof(*reactor));
    reactor->loop.poll_fd = -1;
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        reactor->slots[i].fd = -1;
        reactor->slots[i].state = REACTOR_SLOT_UNUSED;
    }
    if (net_event_loop_init(&reactor->loop) != 0) return -1;
    reactor->active_count = 0;
    reactor->running = false;
    return 0;
}

int reactor_listen(reactor_t *reactor,
                   uint16_t port,
                   reactor_accept_fn on_accept,
                   void *user_data) {
    if (!reactor || !on_accept || reactor->loop.poll_fd < 0 ||
        reactor->active_count >= REACTOR_MAX_SOCKETS ||
        reactor->next_generation == (UINTPTR_MAX >> REACTOR_COOKIE_BITS)) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (net_socket_set_nonblocking(fd) != 0 ||
        net_socket_set_reuseaddr(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 128) != 0) {
        close(fd);
        return -1;
    }

    reactor_socket_t *slot = allocate_slot(reactor);
    if (!slot) {
        close(fd);
        return -1;
    }

    slot->fd = fd;
    slot->state = REACTOR_SLOT_LISTENER;
    slot->on_accept = on_accept;
    slot->user_data = user_data;
    slot->registered_events = NET_EV_READ;

    if (net_event_loop_add(&reactor->loop, fd, NET_EV_READ, (void *)slot->registration) != 0) {
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
    if (!reactor || client_fd < 0 || reactor->loop.poll_fd < 0 ||
        reactor->active_count >= REACTOR_MAX_SOCKETS ||
        reactor->next_generation == (UINTPTR_MAX >> REACTOR_COOKIE_BITS)) return -1;

    if (find_slot_by_fd(reactor, client_fd) || reactor_prepare_socket(client_fd) != 0) {
        return -1;
    }

    reactor_socket_t *slot = allocate_slot(reactor);
    if (!slot) return -1;

    slot->fd = client_fd;
    slot->state = REACTOR_SLOT_CONNECTED;
    slot->on_read = on_read;
    slot->on_close = on_close;
    slot->user_data = user_data;
    slot->registered_events = NET_EV_READ;

    if (net_event_loop_add(&reactor->loop, client_fd, NET_EV_READ, (void *)slot->registration) != 0) {
        slot->state = REACTOR_SLOT_UNUSED;
        reactor->active_count--;
        return -1;
    }

    return 0;
}

int reactor_send(reactor_t *reactor, int fd, const void *data, size_t len) {
    if (!reactor || fd < 0 || !data || len == 0 || len > REACTOR_BUFFER_CAPACITY) return -1;

    reactor_socket_t *slot = find_slot_by_fd(reactor, fd);
    if (!slot || slot->state != REACTOR_SLOT_CONNECTED) return -1;

    /* If tx_buf already has pending data, append to buffer */
    if (slot->tx_len > 0) {
        if (slot->tx_len > REACTOR_BUFFER_CAPACITY || len > REACTOR_BUFFER_CAPACITY - slot->tx_len) {
            return -1; /* Buffer overflow */
        }
        memcpy(&slot->tx_buf[slot->tx_len], data, len);
        slot->tx_len += len;
        return (int)len;
    }

    /* Otherwise, attempt direct non-blocking write */
    ssize_t written = reactor_socket_send(fd, data, len);
    if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer is full; queue entire message in static tx_buf */
            if (len > REACTOR_BUFFER_CAPACITY) return -1;
            memcpy(slot->tx_buf, data, len);
            slot->tx_len = len;

            /* Register write interest */
            slot->registered_events |= NET_EV_WRITE;
            net_event_loop_mod(&reactor->loop, fd, slot->registered_events, (void *)slot->registration);
            return (int)len;
        }
        return -1;
    }

    /* If partial write occurred, buffer remainder */
    if ((size_t)written < len) {
        size_t rem = len - (size_t)written;
        if (rem > REACTOR_BUFFER_CAPACITY) return -1;
        memcpy(slot->tx_buf, (const uint8_t*)data + written, rem);
        slot->tx_len = rem;

        slot->registered_events |= NET_EV_WRITE;
        net_event_loop_mod(&reactor->loop, fd, slot->registered_events, (void *)slot->registration);
    }

    return (int)len;
}

static void handle_listener_read(reactor_t *reactor, reactor_socket_t *slot) {
    uintptr_t registration = slot->registration;
    while (find_registration(reactor, registration) == slot) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(slot->fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Graceful sleep: drained all incoming connections */
                break;
            }
            if (errno == EINTR) continue;
            break;
        }

        if (slot->on_accept) {
            slot->on_accept(slot->fd, client_fd, slot->user_data);
        } else {
            close(client_fd);
        }
    }
}

static void handle_client_read(reactor_t *reactor, reactor_socket_t *slot) {
    uintptr_t registration = slot->registration;
    while (find_registration(reactor, registration) == slot) {
        ssize_t n = recv(slot->fd, (char *)slot->rx_buf, sizeof(slot->rx_buf), 0);
        if (n > 0) {
            if (slot->on_read) {
                slot->on_read(slot->fd, slot->rx_buf, (size_t)n, slot->user_data);
            }
        } else if (n == 0) {
            /* Client disconnected */
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Non-blocking socket drained: gracefully quiesce to sleep */
                break;
            }
            if (errno == EINTR) continue;
            /* Read error */
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        }
    }
}

static void handle_client_write(reactor_t *reactor, reactor_socket_t *slot) {
    if (slot->tx_len == 0) {
        /* No data pending, unregister write interest */
        slot->registered_events &= ~NET_EV_WRITE;
        net_event_loop_mod(&reactor->loop, slot->fd, slot->registered_events, (void *)slot->registration);
        return;
    }

    while (slot->tx_len > 0) {
        ssize_t n = reactor_socket_send(slot->fd, slot->tx_buf, slot->tx_len);
        if (n > 0) {
            if ((size_t)n >= slot->tx_len) {
                slot->tx_len = 0;
                slot->registered_events &= ~NET_EV_WRITE;
                net_event_loop_mod(&reactor->loop, slot->fd, slot->registered_events, (void *)slot->registration);
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
                /* Cannot write more now; wait for next write notification */
                break;
            }
            if (errno == EINTR) continue;
            /* Write error */
            int fd = slot->fd;
            reactor_close_fd(reactor, fd);
            break;
        }
    }
}

int reactor_step(reactor_t *reactor, int timeout_ms) {
    if (!reactor || reactor_dispatching) return -1;

    net_event_t events[NET_MAX_EVENTS_PER_POLL];
    int nev = net_event_loop_poll(&reactor->loop, timeout_ms, events, NET_MAX_EVENTS_PER_POLL);
    if (nev <= 0) return nev;

    reactor_dispatching = true;
    for (int i = 0; i < nev; i++) {
        uintptr_t registration = (uintptr_t)events[i].user_data;
        reactor_socket_t *slot = find_registration(reactor, registration);
        if (!slot) continue;

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

        /* Check if slot is still active after read before doing write */
        if (find_registration(reactor, registration) == slot &&
            slot->state == REACTOR_SLOT_CONNECTED && (events[i].flags & NET_EV_WRITE)) {
            handle_client_write(reactor, slot);
        }
    }

    reactor_dispatching = false;
    return nev;
}

void reactor_run(reactor_t *reactor) {
    if (!reactor || reactor_dispatching || reactor->loop.poll_fd < 0) return;
    reactor->running = true;
    while (reactor->running) {
        reactor_step(reactor, 100);
    }
}

void reactor_stop(reactor_t *reactor) {
    if (reactor) {
        reactor->running = false;
    }
}

void reactor_close_fd(reactor_t *reactor, int fd) {
    if (!reactor || fd < 0) return;

    reactor_socket_t *slot = find_slot_by_fd(reactor, fd);
    if (!slot) return;

    net_event_loop_del(&reactor->loop, fd);
    close(fd);

    /* Retire before calling user code: recursive close is a no-op, and a
     * replacement may safely reuse this slot/descriptor. Never touch the slot
     * again after the callback has started. */
    reactor_close_fn on_close = slot->on_close;
    void *user_data = slot->user_data;
    memset(slot, 0, sizeof(*slot));
    slot->fd = -1;
    if (reactor->active_count > 0) reactor->active_count--;
    if (on_close) {
        bool previous_dispatch = reactor_dispatching;
        reactor_dispatching = true;
        on_close(fd, user_data);
        reactor_dispatching = previous_dispatch;
    }
}

void reactor_destroy(reactor_t *reactor) {
    if (!reactor) return;
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        if (reactor->slots[i].state != REACTOR_SLOT_UNUSED && reactor->slots[i].fd >= 0) {
            net_event_loop_del(&reactor->loop, reactor->slots[i].fd);
            close(reactor->slots[i].fd);
            reactor->slots[i].state = REACTOR_SLOT_UNUSED;
            reactor->slots[i].fd = -1;
        }
    }
    reactor->active_count = 0;
    reactor->running = false;
    net_event_loop_close(&reactor->loop);
}
