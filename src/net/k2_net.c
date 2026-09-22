/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Experimental unauthenticated two-party computation over POSIX sockets.
 *
 * Implements raw non-blocking POSIX socket communication between
 * the Aggregator and Contributor. This is not block admission or consensus.
 *
 * Strictly zero dynamic memory allocations (no malloc/free).
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "determ/net/virtual_transport.h"
#include <determ/net/k2_net.h>
#include <determ/crypto/secure_zero.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/time/clock.h>

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

/* Big-Endian Serialization Utilities */
static inline void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static inline void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

int k2_net_encode_frame(k2_msg_type_t type, const uint8_t *payload, uint32_t payload_len,
                        uint8_t *out_buf, size_t out_max, size_t *out_len) {
    if (!out_buf || !out_len) {
        return -1;
    }
    if (payload_len > DUEL_MAX_PAYLOAD_SIZE || (!payload && payload_len != 0)) return -1;
    size_t total = (size_t)K2_NET_HEADER_LEN + payload_len;
    if (total > out_max) {
        return -1;
    }

    write_be32(out_buf, K2_NET_MAGIC);
    write_be16(out_buf + 4, (uint16_t)type);
    write_be16(out_buf + 6, 0); /* Reserved */
    write_be32(out_buf + 8, payload_len);

    if (payload && payload_len > 0) {
        memcpy(out_buf + K2_NET_HEADER_LEN, payload, payload_len);
    }
    *out_len = total;
    return 0;
}

int k2_net_parse_header(const uint8_t *buf, size_t len, k2_net_header_t *out_hdr) {
    if (!buf || !out_hdr || len < K2_NET_HEADER_LEN) {
        return -1;
    }
    out_hdr->magic = read_be32(buf);
    if (out_hdr->magic != K2_NET_MAGIC) {
        return -2; /* Bad magic */
    }
    out_hdr->msg_type = read_be16(buf + 4);
    out_hdr->reserved = read_be16(buf + 6);
    out_hdr->payload_len = read_be32(buf + 8);
    if (out_hdr->reserved != 0) return -3;
    if (out_hdr->payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return -3; /* Payload exceeds limit */
    }
    return 0;
}

static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    uint64_t start = determ_clock_now_ns();
    while (sent < len) {
        int flags = 0;
        if (determ_clock_now_ns() - start >= DUEL_REVEAL_WINDOW_NS) return -1;
#ifdef MSG_NOSIGNAL
        flags = MSG_NOSIGNAL;
#endif
        ssize_t n = determ_net_send(fd, data + sent, len - sent, flags);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 100000L; /* 100 microseconds */
                nanosleep(&ts, NULL);
                continue;
            }
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void close_peer(k2_aggregator_t *agg) {
    if (agg->peer.fd >= 0) {
        net_event_loop_del(&agg->loop, agg->peer.fd);
        close(agg->peer.fd);
    }
    memset(&agg->peer, 0, sizeof(agg->peer));
    agg->peer.fd = -1;
}
static int fail_attempt(k2_aggregator_t *agg, int status) {
    close_peer(agg);
    agg->duel_sm.state = DUEL_STATE_ABORTED;
    agg->duel_sm.terminal_status = (duel_status_t)status;
    agg->duel_sm.reveal_buffer_locked = true;
    agg->duel_sm.vdf_input_len = 0;
    agg->duel_completed = false;
    return status;
}
static int bounded_poll_ms(uint64_t start, uint64_t duration, int requested) {
    uint64_t elapsed = determ_clock_now_ns() - start;
    int remaining = elapsed >= duration ? 0 : (int)((duration - elapsed + 999999ULL) / 1000000ULL);
    return requested < 0 || requested > remaining ? remaining : requested;
}

static void suppress_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int value = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));
#else
    (void)fd;
#endif
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Aggregator Implementation
 * ───────────────────────────────────────────────────────────────────────────── */

int k2_aggregator_init(k2_aggregator_t *agg, uint16_t port) {
    if (!agg) return -1;
    memset(agg, 0, sizeof(*agg));
    agg->listen_fd = -1;
    agg->peer.fd = -1;
    agg->port = port;

    if (duel_state_init(&agg->duel_sm) != DUEL_SUCCESS) {
        return -1;
    }
    if (net_event_loop_init(&agg->loop) != 0) {
        return -1;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        net_event_loop_close(&agg->loop);
        return -1;
    }

    net_socket_set_reuseaddr(s);
    if (net_socket_set_nonblocking(s) != 0) {
        close(s);
        net_event_loop_close(&agg->loop);
        return -1;
    }
    net_socket_set_nodelay(s);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        net_event_loop_close(&agg->loop);
        return -1;
    }

    if (listen(s, 16) < 0) {
        close(s);
        net_event_loop_close(&agg->loop);
        return -1;
    }

    agg->listen_fd = s;
    if (net_event_loop_add(&agg->loop, s, NET_EV_READ, (void *)(intptr_t)1) != 0) {
        close(s);
        net_event_loop_close(&agg->loop);
        return -1;
    }

    return 0;
}

int k2_aggregator_start_duel(k2_aggregator_t *agg, const uint8_t *agg_reveal, uint32_t agg_len) {
    if (!agg || !agg_reveal || agg_len == 0 || agg_len > DUEL_MAX_PAYLOAD_SIZE) return -1;

    duel_status_t st = duel_state_start_commitment_phase(&agg->duel_sm);
    if (st != DUEL_SUCCESS) return -1;

    close_peer(agg); /* A restart never reuses bytes from the previous connection. */
    agg->duel_completed = false;
    memset(agg->latest_vdf_output, 0, sizeof(agg->latest_vdf_output));
    memcpy(agg->agg_reveal, agg_reveal, agg_len);
    agg->agg_reveal_len = agg_len;
    uint8_t commitment[32];
    determ_sha256(agg_reveal, agg_len, commitment);
    return duel_submit_aggregator_commit(&agg->duel_sm, commitment) == DUEL_SUCCESS ? 0 : -1;
}

int k2_aggregator_poll(k2_aggregator_t *agg, int timeout_ms) {
    if (!agg || agg->listen_fd < 0) return -1;

    if (agg->duel_sm.state == DUEL_STATE_ABORTED)
        return fail_attempt(agg, agg->duel_sm.terminal_status);
    int status = duel_state_poll_commit_timeout(&agg->duel_sm);
    if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
    status = duel_state_poll_buzzer(&agg->duel_sm);
    if (status != DUEL_SUCCESS) return fail_attempt(agg, status);

    /* Fixed-cost local experiment; DDA is not a network accept rule here. */
    if (agg->duel_sm.state == DUEL_STATE_VDF_EVALUATION && !agg->duel_completed) {
        if (vdf_init(&agg->vdf_ctx, agg->duel_sm.vdf_input_buffer,
                     agg->duel_sm.vdf_input_len, K2_EXPERIMENT_ITERATIONS) != 0 ||
            vdf_evaluate(&agg->vdf_ctx, agg->latest_vdf_output) != 0)
            return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
        if (agg->peer.connected && agg->peer.fd >= 0) {
            uint8_t frame[K2_NET_HEADER_LEN + VDF_OUTPUT_LEN];
            size_t len = 0;
            if (k2_net_encode_frame(K2_MSG_BLOCK_RESULT, agg->latest_vdf_output,
                                   VDF_OUTPUT_LEN, frame, sizeof(frame), &len) != 0 ||
                send_all(agg->peer.fd, frame, len) != 0)
                return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
        }
        agg->duel_completed = true;
        agg->duel_sm.state = DUEL_STATE_COMPLETED;
        return 1;
    }
    if (agg->duel_completed) return 1;

    uint64_t duration = agg->duel_sm.state == DUEL_STATE_COMMITMENT_PHASE ?
                        DUEL_COMMIT_TIMEOUT_NS : DUEL_REVEAL_WINDOW_NS;
    timeout_ms = bounded_poll_ms(agg->duel_sm.epoch_start_time, duration, timeout_ms);
    net_event_t evs[NET_MAX_EVENTS_PER_POLL];
    int n = net_event_loop_poll(&agg->loop, timeout_ms, evs, NET_MAX_EVENTS_PER_POLL);
    if (n < 0) return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
    if (n == 0) {
        status = duel_state_poll_commit_timeout(&agg->duel_sm);
        if (status == DUEL_SUCCESS) status = duel_state_poll_buzzer(&agg->duel_sm);
        return status == DUEL_SUCCESS ? 0 : fail_attempt(agg, status);
    }

    for (int i = 0; i < n; ++i) {
        /* Both kqueue and epoll preserve user_data; epoll does not return fd. */
        int fd = evs[i].user_data == (void *)(intptr_t)1 ? agg->listen_fd :
                 evs[i].user_data == (void *)(intptr_t)2 ? agg->peer.fd : -1;
        uint32_t flags = evs[i].flags;

        if (fd == agg->listen_fd) {
            /* Drain the listener because epoll subscriptions are edge triggered. */
            for (;;) {
                status = duel_state_poll_commit_timeout(&agg->duel_sm);
                if (status == DUEL_SUCCESS) status = duel_state_poll_buzzer(&agg->duel_sm);
                if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int cfd = accept(agg->listen_fd, (struct sockaddr *)&client_addr, &client_len);
                if (cfd < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
                }
                if (agg->peer.connected || agg->duel_sm.state != DUEL_STATE_COMMITMENT_PHASE) {
                    close(cfd);
                    continue;
                }
                if (net_socket_set_nonblocking(cfd) != 0) {
                    close(cfd);
                    return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
                }
                net_socket_set_nodelay(cfd);
                suppress_sigpipe(cfd);
                agg->peer.fd = cfd;
                agg->peer.connected = true;
                agg->peer.rx_cursor = 0;
                agg->peer.expected_total_len = 0;
                if (net_event_loop_add(&agg->loop, cfd, NET_EV_READ, (void *)(intptr_t)2) != 0)
                    return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
            }
        } else if (fd == agg->peer.fd) {
            if (flags & (NET_EV_ERROR | NET_EV_EOF)) {
                return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
            }

            if (flags & NET_EV_READ) {
                /* Parse/free the bounded arena between reads, until EAGAIN. */
                for (;;) {
                    status = duel_state_poll_commit_timeout(&agg->duel_sm);
                    if (status == DUEL_SUCCESS) status = duel_state_poll_buzzer(&agg->duel_sm);
                    if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                    if (agg->duel_sm.state == DUEL_STATE_VDF_EVALUATION) break;
                    ssize_t rc = determ_net_recv(agg->peer.fd,
                                      agg->peer.rx_buf + agg->peer.rx_cursor,
                                      sizeof(agg->peer.rx_buf) - agg->peer.rx_cursor, 0);
                    if (rc <= 0) {
                        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;
                        }
                        if (rc < 0 && errno == EINTR) continue;
                        return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
                    }

                    agg->peer.rx_cursor += (size_t)rc;

                    /* Parse frames in non-blocking receive buffer */
                    while (agg->peer.rx_cursor >= K2_NET_HEADER_LEN) {
                        k2_net_header_t hdr;
                        if (k2_net_parse_header(agg->peer.rx_buf, agg->peer.rx_cursor, &hdr) != 0) {
                            return fail_attempt(agg, DUEL_ERR_INVALID_ARGUMENT);
                        }

                        size_t frame_total = (size_t)K2_NET_HEADER_LEN + hdr.payload_len;
                        if (agg->peer.rx_cursor < frame_total) {
                            /* Incomplete frame: wait for remaining bytes */
                            break;
                        }

                        const uint8_t *payload = agg->peer.rx_buf + K2_NET_HEADER_LEN;

                        if (hdr.msg_type == K2_MSG_COMMITMENT && hdr.payload_len == 32) {
                            status = duel_submit_contributor_commit(&agg->duel_sm, payload);
                            if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                            status = duel_state_start_reveal_window(&agg->duel_sm);
                            if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                            status = duel_submit_aggregator_reveal(&agg->duel_sm, agg->agg_reveal, agg->agg_reveal_len);
                            if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                            uint8_t frame[K2_NET_HEADER_LEN];
                            size_t len = 0;
                            if (k2_net_encode_frame(K2_MSG_REVEAL_WINDOW, NULL, 0, frame, sizeof(frame), &len) != 0 ||
                                send_all(agg->peer.fd, frame, len) != 0)
                                return fail_attempt(agg, DUEL_ERR_INVALID_STATE);
                        } else if (hdr.msg_type == K2_MSG_REVEAL_PAYLOAD && hdr.payload_len != 0) {
                            status = duel_submit_contributor_reveal(&agg->duel_sm, payload, hdr.payload_len, true);
                            if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                            status = duel_state_poll_buzzer(&agg->duel_sm);
                            if (status != DUEL_SUCCESS) return fail_attempt(agg, status);
                        } else {
                            return fail_attempt(agg, DUEL_ERR_INVALID_ARGUMENT);
                        }

                        /* Shift remaining bytes in buffer */
                        size_t rem = agg->peer.rx_cursor - frame_total;
                        if (rem > 0) {
                            memmove(agg->peer.rx_buf, agg->peer.rx_buf + frame_total, rem);
                        }
                        agg->peer.rx_cursor = rem;
                    }
                }
            }
        }
    }

    return 0;
}

void k2_aggregator_close(k2_aggregator_t *agg) {
    if (!agg) return;
    if (agg->peer.connected && agg->peer.fd >= 0) {
        net_event_loop_del(&agg->loop, agg->peer.fd);
        close(agg->peer.fd);
        agg->peer.connected = false;
        agg->peer.fd = -1;
    }
    if (agg->listen_fd >= 0) {
        net_event_loop_del(&agg->loop, agg->listen_fd);
        close(agg->listen_fd);
        agg->listen_fd = -1;
    }
    net_event_loop_close(&agg->loop);
    determ_secure_zero(agg, sizeof(*agg));
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Contributor Implementation
 * ───────────────────────────────────────────────────────────────────────────── */

int k2_contributor_init(k2_contributor_t *cont) {
    if (!cont) return -1;
    memset(cont, 0, sizeof(*cont));
    cont->conn.fd = -1;
    return net_event_loop_init(&cont->loop);
}

int k2_contributor_connect(k2_contributor_t *cont, const char *ip_addr, uint16_t port) {
    if (!cont || !ip_addr) return -1;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    net_socket_set_reuseaddr(s);
    net_socket_set_nodelay(s);
    suppress_sigpipe(s);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) <= 0) {
        close(s);
        return -1;
    }

    if (net_socket_set_nonblocking(s) != 0) { close(s); return -1; }
    uint64_t connect_start = determ_clock_now_ns();
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) { close(s); return -1; }
        struct pollfd pfd;
        pfd.fd = s;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        for (;;) {
            int wait_ms = bounded_poll_ms(connect_start, DUEL_COMMIT_TIMEOUT_NS, -1);
            if (wait_ms == 0) { close(s); return -1; }
            int ready = poll(&pfd, 1, wait_ms);
            if (ready < 0 && errno == EINTR) continue;
            int error = 0;
            socklen_t error_len = sizeof(error);
            if (ready <= 0 || getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
                close(s);
                return -1;
            }
            break;
        }
    }

    cont->conn.fd = s;
    cont->conn.connected = true;
    cont->conn.rx_cursor = 0;
    if (net_event_loop_add(&cont->loop, s, NET_EV_READ, (void *)(intptr_t)1) != 0) {
        close(s);
        cont->conn.fd = -1;
        cont->conn.connected = false;
        return -1;
    }
    return 0;
}

int k2_contributor_send_commitment(k2_contributor_t *cont, const uint8_t commitment[32]) {
    if (!cont || !cont->conn.connected || cont->conn.fd < 0 || !commitment) {
        return -1;
    }
    memcpy(cont->commitment, commitment, 32);
    cont->attempt_start_ns = determ_clock_now_ns();
    cont->attempt_started = true;
    cont->result_received = false;
    cont->reveal_window_seen = false;

    uint8_t frame[K2_NET_HEADER_LEN + 32];
    size_t flen = 0;
    if (k2_net_encode_frame(K2_MSG_COMMITMENT, commitment, 32, frame, sizeof(frame), &flen) != 0) {
        return -1;
    }
    return send_all(cont->conn.fd, frame, flen);
}

int k2_contributor_send_reveal(k2_contributor_t *cont, const uint8_t *reveal, uint32_t reveal_len) {
    if (!cont || !cont->conn.connected || cont->conn.fd < 0 || !reveal || reveal_len == 0) {
        return -1;
    }
    if (reveal_len > DUEL_MAX_PAYLOAD_SIZE) {
        return -1;
    }
    memcpy(cont->reveal_payload, reveal, reveal_len);
    cont->reveal_payload_len = reveal_len;

    uint8_t frame[K2_NET_MAX_FRAME_LEN];
    size_t flen = 0;
    if (k2_net_encode_frame(K2_MSG_REVEAL_PAYLOAD, reveal, reveal_len, frame, sizeof(frame), &flen) != 0) {
        return -1;
    }
    return send_all(cont->conn.fd, frame, flen);
}

static int fail_contributor(k2_contributor_t *cont) {
    if (cont->conn.fd >= 0) {
        net_event_loop_del(&cont->loop, cont->conn.fd);
        close(cont->conn.fd);
    }
    cont->conn.fd = -1;
    cont->conn.connected = false;
    return -1;
}
int k2_contributor_poll(k2_contributor_t *cont, int timeout_ms) {
    if (!cont) return -1;
    if (cont->result_received) return 1;
    if (!cont->conn.connected || cont->conn.fd < 0) return -1;
    if (!cont->attempt_started) return fail_contributor(cont);
    if (determ_clock_now_ns() - cont->attempt_start_ns >= K2_RESPONSE_TIMEOUT_NS)
        return fail_contributor(cont);
    timeout_ms = bounded_poll_ms(cont->attempt_start_ns, K2_RESPONSE_TIMEOUT_NS, timeout_ms);
    net_event_t evs[NET_MAX_EVENTS_PER_POLL];
    int n = net_event_loop_poll(&cont->loop, timeout_ms, evs, NET_MAX_EVENTS_PER_POLL);
    if (n < 0) return fail_contributor(cont);
    if (n == 0) {
        if (determ_clock_now_ns() - cont->attempt_start_ns >= K2_RESPONSE_TIMEOUT_NS)
            return fail_contributor(cont);
        return 0;
    }
    for (int i = 0; i < n; ++i) {
        if (evs[i].user_data != (void *)(intptr_t)1) continue;
        uint32_t flags = evs[i].flags;
        /* READ|EOF can carry the final complete frame followed by FIN. */
        if (flags & (NET_EV_READ | NET_EV_EOF)) {
            for (;;) {
                if (determ_clock_now_ns() - cont->attempt_start_ns >= K2_RESPONSE_TIMEOUT_NS)
                    return fail_contributor(cont);
                ssize_t rc = determ_net_recv(cont->conn.fd, cont->conn.rx_buf + cont->conn.rx_cursor,
                                            sizeof(cont->conn.rx_buf) - cont->conn.rx_cursor, 0);
                if (rc <= 0) {
                    if (rc < 0 && errno == EINTR) continue;
                    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                    return fail_contributor(cont);
                }
                cont->conn.rx_cursor += (size_t)rc;
                while (cont->conn.rx_cursor >= K2_NET_HEADER_LEN) {
                    k2_net_header_t hdr;
                    if (k2_net_parse_header(cont->conn.rx_buf, cont->conn.rx_cursor, &hdr) != 0)
                        return fail_contributor(cont);
                    size_t total = (size_t)K2_NET_HEADER_LEN + hdr.payload_len;
                    if (cont->conn.rx_cursor < total) break;
                    const uint8_t *payload = cont->conn.rx_buf + K2_NET_HEADER_LEN;
                    if (hdr.msg_type == K2_MSG_REVEAL_WINDOW && hdr.payload_len == 0 && !cont->reveal_window_seen) {
                        cont->reveal_window_seen = true;
                        if (cont->reveal_payload_len > 0 &&
                            k2_contributor_send_reveal(cont, cont->reveal_payload, cont->reveal_payload_len) != 0)
                            return fail_contributor(cont);
                    } else if (hdr.msg_type == K2_MSG_BLOCK_RESULT && hdr.payload_len == VDF_OUTPUT_LEN && cont->reveal_window_seen) {
                        memcpy(cont->block_result, payload, VDF_OUTPUT_LEN);
                        cont->result_received = true;
                        return 1; /* Peer output only; no chain/block validation claim. */
                    } else {
                        return fail_contributor(cont);
                    }
                    size_t remaining = cont->conn.rx_cursor - total;
                    memmove(cont->conn.rx_buf, cont->conn.rx_buf + total, remaining);
                    cont->conn.rx_cursor = remaining;
                }
            }
        }
        if (flags & (NET_EV_ERROR | NET_EV_EOF)) return fail_contributor(cont);
    }
    return 0;
}

void k2_contributor_close(k2_contributor_t *cont) {
    if (!cont) return;
    if (cont->conn.connected && cont->conn.fd >= 0) {
        net_event_loop_del(&cont->loop, cont->conn.fd);
        close(cont->conn.fd);
        cont->conn.connected = false;
        cont->conn.fd = -1;
    }
    net_event_loop_close(&cont->loop);
    determ_secure_zero(cont, sizeof(*cont));
}
