/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Non-Blocking HTTP/1.1 JSON-RPC Server Transport.
 * Zero-allocation, zero third-party dependencies (no libcurl, no libevent).
 */

#ifndef DETERMINISTIC_RPC_HTTP_RPC_SERVER_H
#define DETERMINISTIC_RPC_HTTP_RPC_SERVER_H

#include <determ/rpc/json_rpc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_RPC_MAX_CLIENTS 16
#define HTTP_RPC_BUF_SIZE 16384

typedef enum {
    HTTP_CLIENT_INACTIVE = 0,
    HTTP_CLIENT_READING,
    HTTP_CLIENT_SENDING,
    HTTP_CLIENT_CLOSING
} http_client_state_t;

typedef struct {
    int                 fd;
    http_client_state_t state;
    uint8_t             rx_buf[HTTP_RPC_BUF_SIZE];
    size_t              rx_len;
    uint8_t             tx_buf[HTTP_RPC_BUF_SIZE];
    size_t              tx_len;
    size_t              tx_sent;
} http_client_t;

typedef struct {
    uint16_t      port;
    const char   *bind_ip; /* Defaults to "127.0.0.1" if NULL */
    rpc_context_t rpc_ctx;
} http_rpc_config_t;

typedef struct {
    int               server_fd;
    uint16_t          port;
    rpc_context_t     rpc_ctx;
    http_client_t     clients[HTTP_RPC_MAX_CLIENTS];
} http_rpc_server_t;

/*
 * Initialize the HTTP RPC server.
 * Returns 0 on success, negative error code on failure.
 */
int http_rpc_server_init(http_rpc_server_t *server, const http_rpc_config_t *config);

/*
 * Start listening on the configured port.
 * Returns 0 on success, negative error code on failure.
 */
int http_rpc_server_start(http_rpc_server_t *server);

/*
 * Drive non-blocking I/O across server listener and active client connections.
 * Accepts pending connections, reads HTTP requests, dispatches JSON-RPC calls,
 * and flushes HTTP responses.
 * timeout_ms: milliseconds to wait in poll (0 for immediate return).
 * Returns number of active clients serviced, or negative on error.
 */
int http_rpc_server_poll(http_rpc_server_t *server, int timeout_ms);

/*
 * Update the active RPC context (e.g. state machine, store, peer mesh).
 */
void http_rpc_server_set_context(http_rpc_server_t *server, const rpc_context_t *ctx);

/*
 * Gracefully close server listener and all client connections.
 */
void http_rpc_server_close(http_rpc_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_RPC_HTTP_RPC_SERVER_H */
