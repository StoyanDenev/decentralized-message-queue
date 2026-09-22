/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Virtual Transport & Socket Readiness Seam.
 * Enables deterministic network fault injection (EWOULDBLOCK, dropped bytes,
 * simulated queues, and multiplexer overrides) for DSF test builds.
 */

#ifndef DETERMINISTIC_NET_VIRTUAL_TRANSPORT_H
#define DETERMINISTIC_NET_VIRTUAL_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#if defined(_WIN32)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif
#include "determ/net/event_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(DETERM_DSF_ENABLED)

#define DSF_VIRTUAL_BUF_SIZE 65536U

/*
 * Virtual Transport Fault & Queue API
 */
void    determ_dsf_transport_init(void);
void    determ_dsf_transport_reset(void);

void    determ_dsf_inject_ewouldblock_rx(bool enable);
void    determ_dsf_inject_ewouldblock_tx(bool enable);
void    determ_dsf_inject_drop_bytes(size_t byte_count);

/* Queue incoming bytes to be read by determ_net_recv() */
void    determ_dsf_queue_rx(int fd, const uint8_t *data, size_t len);

/* Retrieve bytes transmitted via determ_net_send() */
size_t  determ_dsf_read_tx(int fd, uint8_t *out_data, size_t max_len);

/* Mark virtual FD readiness for event loop multiplexer */
void    determ_dsf_mark_ready(int fd, uint32_t flags, void *user_data);
int     determ_dsf_poll_hook(net_event_loop_t *loop, net_event_t *out_events, int max_events);

/* Seam I/O functions */
ssize_t determ_net_recv(int fd, void *buf, size_t len, int flags);
ssize_t determ_net_send(int fd, const void *buf, size_t len, int flags);

#else

/* Production zero-cost pass-throughs */
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#define determ_net_recv(fd, buf, len, flags) recv((fd), (buf), (len), (flags))
#define determ_net_send(fd, buf, len, flags) send((fd), (buf), (len), (flags))

#endif /* DETERM_DSF_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_NET_VIRTUAL_TRANSPORT_H */
