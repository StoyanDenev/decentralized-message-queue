/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Virtual Transport & Socket Readiness Implementation.
 */

#include "determ/net/virtual_transport.h"

#if defined(DETERM_DSF_ENABLED)

#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/socket.h>
#include <errno.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define ENOBUFS WSAENOBUFS
#define errno WSAGetLastError()
typedef int ssize_t;
#else
#include <sys/socket.h>
#include <errno.h>
#endif

#define MAX_VIRTUAL_SLOTS 8

typedef struct {
    int      fd;
    uint8_t  rx_buf[DSF_VIRTUAL_BUF_SIZE];
    size_t   rx_head;
    size_t   rx_tail;

    uint8_t  tx_buf[DSF_VIRTUAL_BUF_SIZE];
    size_t   tx_len;

    uint32_t ready_flags;
    void    *user_data;
    bool     active;
} virtual_slot_t;

static virtual_slot_t s_slots[MAX_VIRTUAL_SLOTS];
static bool s_ewouldblock_rx = false;
static bool s_ewouldblock_tx = false;
static size_t s_drop_bytes_remaining = 0;

static virtual_slot_t* get_or_create_slot(int fd) {
    for (size_t i = 0; i < MAX_VIRTUAL_SLOTS; i++) {
        if (s_slots[i].active && s_slots[i].fd == fd) {
            return &s_slots[i];
        }
    }
    for (size_t i = 0; i < MAX_VIRTUAL_SLOTS; i++) {
        if (!s_slots[i].active) {
            memset(&s_slots[i], 0, sizeof(virtual_slot_t));
            s_slots[i].fd = fd;
            s_slots[i].active = true;
            return &s_slots[i];
        }
    }
    return NULL;
}

void determ_dsf_transport_init(void) {
    memset(s_slots, 0, sizeof(s_slots));
    s_ewouldblock_rx = false;
    s_ewouldblock_tx = false;
    s_drop_bytes_remaining = 0;
}

void determ_dsf_transport_reset(void) {
    determ_dsf_transport_init();
}

void determ_dsf_inject_ewouldblock_rx(bool enable) {
    s_ewouldblock_rx = enable;
}

void determ_dsf_inject_ewouldblock_tx(bool enable) {
    s_ewouldblock_tx = enable;
}

void determ_dsf_inject_drop_bytes(size_t byte_count) {
    s_drop_bytes_remaining += byte_count;
}

void determ_dsf_queue_rx(int fd, const uint8_t *data, size_t len) {
    if (!data || len == 0) return;
    virtual_slot_t *slot = get_or_create_slot(fd);
    if (!slot) return;

    if (slot->rx_tail + len <= DSF_VIRTUAL_BUF_SIZE) {
        memcpy(&slot->rx_buf[slot->rx_tail], data, len);
        slot->rx_tail += len;
    }
    slot->ready_flags |= NET_EV_READ;
}

size_t determ_dsf_read_tx(int fd, uint8_t *out_data, size_t max_len) {
    if (!out_data || max_len == 0) return 0;
    virtual_slot_t *slot = get_or_create_slot(fd);
    if (!slot || slot->tx_len == 0) return 0;

    size_t to_read = (slot->tx_len < max_len) ? slot->tx_len : max_len;
    memcpy(out_data, slot->tx_buf, to_read);
    size_t rem = slot->tx_len - to_read;
    if (rem > 0) {
        memmove(slot->tx_buf, slot->tx_buf + to_read, rem);
    }
    slot->tx_len = rem;
    return to_read;
}

void determ_dsf_mark_ready(int fd, uint32_t flags, void *user_data) {
    virtual_slot_t *slot = get_or_create_slot(fd);
    if (slot) {
        slot->ready_flags |= flags;
        if (user_data) {
            slot->user_data = user_data;
        }
    }
}

int determ_dsf_poll_hook(net_event_loop_t *loop, net_event_t *out_events, int max_events) {
    (void)loop;
    if (!out_events || max_events <= 0) return -1;

    int count = 0;
    for (size_t i = 0; i < MAX_VIRTUAL_SLOTS && count < max_events; i++) {
        if (s_slots[i].active && s_slots[i].ready_flags != 0) {
            out_events[count].fd = s_slots[i].fd;
            out_events[count].flags = s_slots[i].ready_flags;
            out_events[count].user_data = s_slots[i].user_data;
            s_slots[i].ready_flags = 0; /* Clear on poll */
            count++;
        }
    }
    return count;
}

ssize_t determ_net_recv(int fd, void *buf, size_t len, int flags) {
    if (s_ewouldblock_rx) {
        errno = EWOULDBLOCK;
        return -1;
    }

    virtual_slot_t *slot = NULL;
    for (size_t i = 0; i < MAX_VIRTUAL_SLOTS; i++) {
        if (s_slots[i].active && s_slots[i].fd == fd) {
            slot = &s_slots[i];
            break;
        }
    }

    if (slot && slot->rx_tail > slot->rx_head) {
        size_t available = slot->rx_tail - slot->rx_head;

        /* Check for simulated byte drops */
        if (s_drop_bytes_remaining > 0) {
            size_t drop = (available < s_drop_bytes_remaining) ? available : s_drop_bytes_remaining;
            slot->rx_head += drop;
            s_drop_bytes_remaining -= drop;
            available -= drop;
            if (available == 0) {
                slot->rx_head = 0;
                slot->rx_tail = 0;
                errno = EAGAIN;
                return -1;
            }
        }

        size_t to_copy = (available < len) ? available : len;
        memcpy(buf, &slot->rx_buf[slot->rx_head], to_copy);
        slot->rx_head += to_copy;

        if (slot->rx_head == slot->rx_tail) {
            slot->rx_head = 0;
            slot->rx_tail = 0;
        }
        return (ssize_t)to_copy;
    }

    /* If no virtual buffer queued for this fd, fall back to native recv */
    return recv(fd, (char *)buf, len, flags);
}

ssize_t determ_net_send(int fd, const void *buf, size_t len, int flags) {
    if (s_ewouldblock_tx) {
        errno = EWOULDBLOCK;
        return -1;
    }

    virtual_slot_t *slot = NULL;
    for (size_t i = 0; i < MAX_VIRTUAL_SLOTS; i++) {
        if (s_slots[i].active && s_slots[i].fd == fd) {
            slot = &s_slots[i];
            break;
        }
    }

    if (slot) {
        if (slot->tx_len + len <= DSF_VIRTUAL_BUF_SIZE) {
            memcpy(&slot->tx_buf[slot->tx_len], buf, len);
            slot->tx_len += len;
            return (ssize_t)len;
        }
        errno = ENOBUFS;
        return -1;
    }

    return send(fd, (const char *)buf, len, flags);
}

#else

typedef int determ_virtual_transport_c_unused_t;

#endif
