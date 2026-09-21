/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Native Event Loop Reactor Implementation.
 * Single-threaded I/O multiplexer using native OS interfaces (kqueue / epoll / winsock).
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
    if (!reactor) return NULL;
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        if (reactor->slots[i].state == REACTOR_SLOT_UNUSED) {
            memset(&reactor->slots[i], 0, sizeof(reactor_socket_t));
            reactor->slots[i].fd = -1;
            reactor->active_count++;
            return &reactor->slots[i];
        }
    }
    return NULL;
}

int reactor_init(reactor_t *reactor) {
    if (!reactor) return -1;
    memset(reactor, 0, sizeof(*reactor));
    if (net_event_loop_init(&reactor->loop) != 0) {
        return -1;
    }
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        reactor->slots[i].fd = -1;
        reactor->slots[i].state = REACTOR_SLOT_UNUSED;
    }
    reactor->active_count = 0;
    reactor->running = false;
    return 0;
}

int reactor_listen(reactor_t *reactor,
                   uint16_t port,
                   reactor_accept_fn on_accept,
                   void *user_data) {
    if (!reactor || !on_accept) return -1;

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

    reactor_socket_t *slot = allocate_slot(reactor);
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

    reactor_socket_t *slot = find_slot_by_fd(reactor, fd);
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

    /* Otherwise, attempt direct non-blocking write */
    ssize_t written = send(fd, (const char *)data, len, 0);
    if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer is full; queue entire message in static tx_buf */
            if (len > REACTOR_BUFFER_CAPACITY) return -1;
            memcpy(slot->tx_buf, data, len);
            slot->tx_len = len;

            /* Register write interest */
            slot->registered_events |= NET_EV_WRITE;
            net_event_loop_mod(&reactor->loop, fd, slot->registered_events, slot);
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
        net_event_loop_mod(&reactor->loop, fd, slot->registered_events, slot);
    }

    return (int)len;
}

static void handle_listener_read(reactor_t *reactor, reactor_socket_t *slot) {
    (void)reactor;
    while (1) {
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
    while (1) {
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
    if (!reactor) return -1;

    net_event_t events[NET_MAX_EVENTS_PER_POLL];
    int nev = net_event_loop_poll(&reactor->loop, timeout_ms, events, NET_MAX_EVENTS_PER_POLL);
    if (nev <= 0) return nev;

    for (int i = 0; i < nev; i++) {
        reactor_socket_t *slot = (reactor_socket_t *)events[i].user_data;
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

        /* Check if slot is still active after read before doing write */
        if (slot->state == REACTOR_SLOT_CONNECTED && (events[i].flags & NET_EV_WRITE)) {
            handle_client_write(reactor, slot);
        }
    }

    return nev;
}

void reactor_run(reactor_t *reactor) {
    if (!reactor) return;
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
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
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
