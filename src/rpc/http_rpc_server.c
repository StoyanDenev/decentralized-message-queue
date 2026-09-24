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
    /* Before any failure return: close() after a failed init must not see fd 0. */
    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; i++) {
        server->clients[i].fd = -1;
        server->clients[i].state = HTTP_CLIENT_INACTIVE;
    }
    server->port = config->port;
    server->rpc_ctx = config->rpc_ctx;
    {
        /* Loopback unless the caller names an address explicitly. */
        struct in_addr bind_addr;
        const char *ip = config->bind_ip ? config->bind_ip : "127.0.0.1";
        if (inet_pton(AF_INET, ip, &bind_addr) != 1) return -1;
        server->bind_addr_be = (uint32_t)bind_addr.s_addr;
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
    addr.sin_addr.s_addr = server->bind_addr_be;

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

static int http_field_is(const uint8_t *name, size_t len, const char *expected) {
    if (len != strlen(expected)) return 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = name[i];
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + ('a' - 'A'));
        if (c != (uint8_t)expected[i]) return 0;
    }
    return 1;
}

/* POST framing only. Scan complete CRLF header lines, excluding the request
 * line and body. The receive buffer reserves one byte for its trailing NUL.
 * Return the HTTP error status or zero, without publishing a partial length.
 */
static int http_content_length(const uint8_t *data, size_t header_len, size_t *out) {
    size_t pos = 0, value = 0;
    int seen = 0;
    if (header_len > HTTP_RPC_BUF_SIZE - 1) return 413;
    const size_t limit = (HTTP_RPC_BUF_SIZE - 1) - header_len;
    while (pos + 1 < header_len && !(data[pos] == '\r' && data[pos + 1] == '\n')) ++pos;
    if (pos + 1 >= header_len) return 400;
    pos += 2; /* Skip the request line. */
    while (pos + 1 < header_len) {
        size_t end = pos, colon;
        while (end + 1 < header_len && !(data[end] == '\r' && data[end + 1] == '\n')) ++end;
        if (end + 1 >= header_len) return 400;
        if (end == pos) {
            if (end + 2 != header_len || !seen || value == 0) return 400;
            *out = value;
            return 0;
        }
        colon = pos;
        while (colon < end && data[colon] != ':') ++colon;
        if (colon == pos || colon == end) return 400;
        if (http_field_is(data + pos, colon - pos, "transfer-encoding")) return 400;
        if (http_field_is(data + pos, colon - pos, "content-length")) {
            size_t start = colon + 1, stop = end;
            if (seen) return 400;
            seen = 1;
            while (start < stop && (data[start] == ' ' || data[start] == '\t')) ++start;
            while (stop > start && (data[stop - 1] == ' ' || data[stop - 1] == '\t')) --stop;
            if (start == stop) return 400;
            for (size_t i = start; i < stop; ++i) {
                if (data[i] < '0' || data[i] > '9') return 400;
                size_t digit = (size_t)(data[i] - '0');
                if (value > limit / 10 || (value == limit / 10 && digit > limit % 10)) return 413;
                value = value * 10 + digit;
            }
        }
        pos = end + 2;
    }
    return 400;
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

    /* 1. Healthcheck GET */
    if (strncasecmp((char *)c->rx_buf, "GET ", 4) == 0) {
        static const char health_body[] = "{\"status\":\"OK\",\"node\":\"determ-c99\"}\n";
        size_t h_len = sizeof(health_body) - 1;
        int written = snprintf((char *)c->tx_buf, sizeof(c->tx_buf),
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
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

    /* 2. JSON-RPC POST */
    if (strncasecmp((char *)c->rx_buf, "POST ", 5) != 0) {
        send_http_error(c, 405, "Method Not Allowed", "Only POST and GET supported");
        return;
    }

    size_t content_len = 0;
    int framing = http_content_length(c->rx_buf, header_len, &content_len);
    if (framing == 413) {
        send_http_error(c, 413, "Payload Too Large", "Body exceeds 16KB buffer");
        return;
    }
    if (framing != 0) {
        send_http_error(c, 400, "Bad Request", "Invalid Content-Length or unsupported transfer encoding");
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
                /* Best effort: the connection is closed either way. */
                if (write(c_fd, sat_resp, sizeof(sat_resp) - 1) < 0) { /* ignored */ }
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
