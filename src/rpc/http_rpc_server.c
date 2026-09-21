/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Non-Blocking HTTP/1.1 JSON-RPC Server Transport.
 * Zero dynamic memory allocations (zero malloc/free).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <determ/rpc/http_rpc_server.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_client(http_client_t *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->state = HTTP_CLIENT_INACTIVE;
    c->rx_len = 0;
    c->tx_len = 0;
    c->tx_sent = 0;
}

int http_rpc_server_init(http_rpc_server_t *server, const http_rpc_config_t *config) {
    if (!server || !config) return -1;
    memset(server, 0, sizeof(*server));
    server->server_fd = -1;
    server->port = config->port;
    server->rpc_ctx = config->rpc_ctx;

    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; i++) {
        server->clients[i].fd = -1;
        server->clients[i].state = HTTP_CLIENT_INACTIVE;
    }
    return 0;
}

int http_rpc_server_start(http_rpc_server_t *server) {
    if (!server) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 32) != 0) {
        close(fd);
        return -1;
    }

    server->server_fd = fd;
    return 0;
}

void http_rpc_server_set_context(http_rpc_server_t *server, const rpc_context_t *ctx) {
    if (server && ctx) {
        server->rpc_ctx = *ctx;
    }
}

static void send_http_error(http_client_t *c, int status_code, const char *status_text, const char *msg) {
    size_t body_len = msg ? strlen(msg) : 0;
    int written = snprintf((char *)c->tx_buf, sizeof(c->tx_buf),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %zu\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "%s",
                           status_code, status_text, body_len, msg ? msg : "");
    if (written > 0 && (size_t)written < sizeof(c->tx_buf)) {
        c->tx_len = (size_t)written;
        c->tx_sent = 0;
        c->state = HTTP_CLIENT_SENDING;
    } else {
        close_client(c);
    }
}

static void handle_client_request(http_rpc_server_t *server, http_client_t *c) {
    /* Check for end of HTTP headers: "\r\n\r\n" */
    char *hdr_end = strstr((char *)c->rx_buf, "\r\n\r\n");
    if (!hdr_end) {
        /* Still reading headers */
        if (c->rx_len >= HTTP_RPC_BUF_SIZE - 1) {
            send_http_error(c, 413, "Payload Too Large", "Header size exceeded");
        }
        return;
    }

    size_t header_len = (size_t)(hdr_end + 4 - (char *)c->rx_buf);

    /* 1. CORS Preflight OPTIONS */
    if (strncasecmp((char *)c->rx_buf, "OPTIONS ", 8) == 0) {
        int written = snprintf((char *)c->tx_buf, sizeof(c->tx_buf),
                               "HTTP/1.1 204 No Content\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
                               "Access-Control-Allow-Headers: Content-Type\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n"
                               "\r\n");
        if (written > 0 && (size_t)written < sizeof(c->tx_buf)) {
            c->tx_len = (size_t)written;
            c->tx_sent = 0;
            c->state = HTTP_CLIENT_SENDING;
        } else {
            close_client(c);
        }
        return;
    }

    /* 2. Healthcheck GET */
    if (strncasecmp((char *)c->rx_buf, "GET ", 4) == 0) {
        static const char health_body[] = "{\"status\":\"OK\",\"node\":\"determ-c99\"}\n";
        size_t h_len = sizeof(health_body) - 1;
        int written = snprintf((char *)c->tx_buf, sizeof(c->tx_buf),
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: close\r\n"
                               "\r\n"
                               "%s",
                               h_len, health_body);
        if (written > 0 && (size_t)written < sizeof(c->tx_buf)) {
            c->tx_len = (size_t)written;
            c->tx_sent = 0;
            c->state = HTTP_CLIENT_SENDING;
        } else {
            close_client(c);
        }
        return;
    }

    /* 3. JSON-RPC POST */
    if (strncasecmp((char *)c->rx_buf, "POST ", 5) != 0) {
        send_http_error(c, 405, "Method Not Allowed", "Only POST, GET, OPTIONS supported");
        return;
    }

    /* Parse Content-Length */
    char *cl_pos = strcasestr((char *)c->rx_buf, "Content-Length:");
    size_t content_len = 0;
    if (cl_pos && cl_pos < hdr_end) {
        content_len = (size_t)strtoul(cl_pos + 15, NULL, 10);
    }

    if (content_len == 0) {
        send_http_error(c, 400, "Bad Request", "Missing or zero Content-Length");
        return;
    }

    if (header_len + content_len > HTTP_RPC_BUF_SIZE) {
        send_http_error(c, 413, "Payload Too Large", "Body exceeds 16KB buffer");
        return;
    }

    /* Verify if entire body has arrived */
    if (c->rx_len < header_len + content_len) {
        /* Still waiting for remainder of body */
        return;
    }

    /* Dispatch JSON-RPC */
    const char *req_body = (const char *)c->rx_buf + header_len;
    char rpc_out[RPC_MAX_RESPONSE_LEN];
    int rpc_len = rpc_dispatch_context(req_body, content_len, &server->rpc_ctx, rpc_out, sizeof(rpc_out));

    if (rpc_len < 0) {
        send_http_error(c, 500, "Internal Server Error", "JSON-RPC dispatch failed");
        return;
    }

    /* Wrap in HTTP/1.1 200 OK Response */
    int written = snprintf((char *)c->tx_buf, sizeof(c->tx_buf),
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Content-Length: %d\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "%s",
                           rpc_len, rpc_out);

    if (written > 0 && (size_t)written < sizeof(c->tx_buf)) {
        c->tx_len = (size_t)written;
        c->tx_sent = 0;
        c->state = HTTP_CLIENT_SENDING;
    } else {
        close_client(c);
    }
}

int http_rpc_server_poll(http_rpc_server_t *server, int timeout_ms) {
    if (!server || server->server_fd < 0) return -1;

    struct pollfd fds[1 + HTTP_RPC_MAX_CLIENTS];
    int poll_count = 0;

    /* Index 0: Server listening socket */
    fds[0].fd = server->server_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    poll_count = 1;

    int client_map[1 + HTTP_RPC_MAX_CLIENTS];
    client_map[0] = -1;

    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; i++) {
        if (server->clients[i].state != HTTP_CLIENT_INACTIVE && server->clients[i].fd >= 0) {
            fds[poll_count].fd = server->clients[i].fd;
            fds[poll_count].events = (server->clients[i].state == HTTP_CLIENT_SENDING) ? POLLOUT : POLLIN;
            fds[poll_count].revents = 0;
            client_map[poll_count] = (int)i;
            poll_count++;
        }
    }

    int ret = poll(fds, (nfds_t)poll_count, timeout_ms);
    if (ret <= 0) return ret;

    /* Check new connections */
    if (fds[0].revents & POLLIN) {
        while (1) {
            struct sockaddr_in c_addr;
            socklen_t c_len = sizeof(c_addr);
            int c_fd = accept(server->server_fd, (struct sockaddr *)&c_addr, &c_len);
            if (c_fd < 0) break;

            (void)set_nonblocking(c_fd);

            /* Find free client slot */
            int slot = -1;
            for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; i++) {
                if (server->clients[i].state == HTTP_CLIENT_INACTIVE) {
                    slot = (int)i;
                    break;
                }
            }

            if (slot >= 0) {
                server->clients[slot].fd = c_fd;
                server->clients[slot].state = HTTP_CLIENT_READING;
                server->clients[slot].rx_len = 0;
                server->clients[slot].tx_len = 0;
                server->clients[slot].tx_sent = 0;
            } else {
                /* Server saturated: 503 Service Unavailable */
                static const char sat_resp[] =
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                (void)write(c_fd, sat_resp, sizeof(sat_resp) - 1);
                close(c_fd);
            }
        }
    }

    /* Process client sockets */
    int active_serviced = 0;
    for (int p = 1; p < poll_count; p++) {
        int idx = client_map[p];
        if (idx < 0) continue;
        http_client_t *c = &server->clients[idx];

        if (fds[p].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            close_client(c);
            continue;
        }

        /* Reading incoming request */
        if ((fds[p].revents & POLLIN) && c->state == HTTP_CLIENT_READING) {
            size_t space = sizeof(c->rx_buf) - 1 - c->rx_len;
            if (space > 0) {
                ssize_t n = read(c->fd, c->rx_buf + c->rx_len, space);
                if (n > 0) {
                    c->rx_len += (size_t)n;
                    c->rx_buf[c->rx_len] = '\0';
                    handle_client_request(server, c);
                    active_serviced++;
                } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    close_client(c);
                }
            } else {
                send_http_error(c, 413, "Payload Too Large", "Buffer limit reached");
            }
        }

        /* Flushing outgoing response */
        if ((fds[p].revents & POLLOUT) && c->state == HTTP_CLIENT_SENDING) {
            size_t remaining = c->tx_len - c->tx_sent;
            if (remaining > 0) {
                ssize_t n = write(c->fd, c->tx_buf + c->tx_sent, remaining);
                if (n > 0) {
                    c->tx_sent += (size_t)n;
                    if (c->tx_sent >= c->tx_len) {
                        /* Request finished, close connection */
                        close_client(c);
                    }
                    active_serviced++;
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close_client(c);
                }
            } else {
                close_client(c);
            }
        }
    }

    return active_serviced;
}

void http_rpc_server_close(http_rpc_server_t *server) {
    if (!server) return;
    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; i++) {
        close_client(&server->clients[i]);
    }
    if (server->server_fd >= 0) {
        close(server->server_fd);
        server->server_fd = -1;
    }
}
