/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * K=2 Fast-Block VDF Duel Networking Layer (Pure C99 Bare-Metal).
 *
 * Implements raw non-blocking POSIX socket communication between
 * the Aggregator and Contributor nodes under the Monotonic Time-Lock Model.
 *
 * Strictly zero dynamic memory allocations (no malloc/free).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <determ/net/k2_net.h>
#include <determ/crypto/secure_zero.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
    if (out_hdr->payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return -3; /* Payload exceeds limit */
    }
    return 0;
}

static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Non-blocking socket busy: spin brief delay */
                usleep(100);
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
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
    net_socket_set_nonblocking(s);
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

    memcpy(agg->agg_reveal, agg_reveal, agg_len);
    agg->agg_reveal_len = agg_len;
    return 0;
}

int k2_aggregator_poll(k2_aggregator_t *agg, int timeout_ms) {
    if (!agg || agg->listen_fd < 0) return -1;

    /* If reveal window is running, poll monotonic clock for buzzer expiration */
    if (agg->duel_sm.state == DUEL_STATE_AWAITING_REVEALS) {
        uint64_t now = duel_clock_monotonic_ns();
        uint64_t elapsed = now - agg->duel_sm.reveal_start_ns;
        if (elapsed >= DUEL_REVEAL_WINDOW_NS) {
            /* 2000ms hard buzzer reached: lock buffer and trigger fallback */
            (void)duel_state_poll_buzzer(&agg->duel_sm);
        }
    }

    /* If ready for VDF evaluation, perform ASIC-resistant VDF loop */
    if (agg->duel_sm.state == DUEL_STATE_VDF_EVALUATION && !agg->duel_completed) {
        if (vdf_init(&agg->vdf_ctx, agg->duel_sm.vdf_input_buffer,
                     agg->duel_sm.vdf_input_len, 2000) == 0) {
            if (vdf_evaluate(&agg->vdf_ctx, agg->latest_vdf_output) == 0) {
                agg->duel_completed = true;

                /* Send block result frame to peer if connected */
                if (agg->peer.connected && agg->peer.fd >= 0) {
                    uint8_t out_frame[K2_NET_HEADER_LEN + VDF_OUTPUT_LEN];
                    size_t out_len = 0;
                    if (k2_net_encode_frame(K2_MSG_BLOCK_RESULT, agg->latest_vdf_output,
                                            VDF_OUTPUT_LEN, out_frame, sizeof(out_frame), &out_len) == 0) {
                        (void)send_all(agg->peer.fd, out_frame, out_len);
                    }
                }
                return 1; /* Duel completed */
            }
        }
    }

    net_event_t evs[NET_MAX_EVENTS_PER_POLL];
    int n = net_event_loop_poll(&agg->loop, timeout_ms, evs, NET_MAX_EVENTS_PER_POLL);
    if (n <= 0) {
        return n;
    }

    for (int i = 0; i < n; ++i) {
        int fd = evs[i].fd;
        uint32_t flags = evs[i].flags;

        if (fd == agg->listen_fd) {
            /* Accept incoming Contributor connection */
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int cfd = accept(agg->listen_fd, (struct sockaddr *)&client_addr, &client_len);
            if (cfd >= 0) {
                net_socket_set_nonblocking(cfd);
                net_socket_set_nodelay(cfd);

                /* If existing peer connected, replace or drop */
                if (agg->peer.connected && agg->peer.fd >= 0) {
                    net_event_loop_del(&agg->loop, agg->peer.fd);
                    close(agg->peer.fd);
                }

                agg->peer.fd = cfd;
                agg->peer.connected = true;
                agg->peer.rx_cursor = 0;
                agg->peer.expected_total_len = 0;

                net_event_loop_add(&agg->loop, cfd, NET_EV_READ, (void *)(intptr_t)2);
            }
        } else if (fd == agg->peer.fd) {
            if (flags & (NET_EV_ERROR | NET_EV_EOF)) {
                net_event_loop_del(&agg->loop, agg->peer.fd);
                close(agg->peer.fd);
                agg->peer.connected = false;
                agg->peer.fd = -1;
                continue;
            }

            if (flags & NET_EV_READ) {
                ssize_t rc = recv(agg->peer.fd,
                                  agg->peer.rx_buf + agg->peer.rx_cursor,
                                  sizeof(agg->peer.rx_buf) - agg->peer.rx_cursor, 0);
                if (rc <= 0) {
                    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        continue;
                    }
                    net_event_loop_del(&agg->loop, agg->peer.fd);
                    close(agg->peer.fd);
                    agg->peer.connected = false;
                    agg->peer.fd = -1;
                    continue;
                }

                agg->peer.rx_cursor += (size_t)rc;

                /* Parse frames in non-blocking receive buffer */
                while (agg->peer.rx_cursor >= K2_NET_HEADER_LEN) {
                    k2_net_header_t hdr;
                    if (k2_net_parse_header(agg->peer.rx_buf, agg->peer.rx_cursor, &hdr) != 0) {
                        /* Framing error: drop stream */
                        net_event_loop_del(&agg->loop, agg->peer.fd);
                        close(agg->peer.fd);
                        agg->peer.connected = false;
                        agg->peer.fd = -1;
                        break;
                    }

                    size_t frame_total = (size_t)K2_NET_HEADER_LEN + hdr.payload_len;
                    if (agg->peer.rx_cursor < frame_total) {
                        /* Incomplete frame: wait for remaining bytes */
                        break;
                    }

                    const uint8_t *payload = agg->peer.rx_buf + K2_NET_HEADER_LEN;

                    /* Dispatch Frame */
                    if (hdr.msg_type == K2_MSG_COMMITMENT) {
                        /* Contributor commitment received: open reveal window */
                        if (agg->duel_sm.state == DUEL_STATE_COMMITMENT_PHASE) {
                            (void)duel_state_start_reveal_window(&agg->duel_sm);
                            if (agg->agg_reveal_len > 0) {
                                (void)duel_submit_aggregator_reveal(&agg->duel_sm, agg->agg_reveal, agg->agg_reveal_len);
                            }

                            /* Notify Contributor that window is open */
                            uint8_t win_frame[K2_NET_HEADER_LEN];
                            size_t win_len = 0;
                            if (k2_net_encode_frame(K2_MSG_REVEAL_WINDOW, NULL, 0,
                                                    win_frame, sizeof(win_frame), &win_len) == 0) {
                                (void)send_all(agg->peer.fd, win_frame, win_len);
                            }
                        }
                    } else if (hdr.msg_type == K2_MSG_REVEAL_PAYLOAD) {
                        /* Contributor reveal packet: enforce monotonic buzzer */
                        (void)duel_submit_contributor_reveal(&agg->duel_sm, payload, hdr.payload_len, true);
                        /* Advance buzzer poll */
                        (void)duel_state_poll_buzzer(&agg->duel_sm);
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

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) <= 0) {
        close(s);
        return -1;
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    net_socket_set_nonblocking(s);

    cont->conn.fd = s;
    cont->conn.connected = true;
    cont->conn.rx_cursor = 0;

    return net_event_loop_add(&cont->loop, s, NET_EV_READ, (void *)(intptr_t)1);
}

int k2_contributor_send_commitment(k2_contributor_t *cont, const uint8_t commitment[32]) {
    if (!cont || !cont->conn.connected || cont->conn.fd < 0 || !commitment) {
        return -1;
    }
    memcpy(cont->commitment, commitment, 32);

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

int k2_contributor_poll(k2_contributor_t *cont, int timeout_ms) {
    if (!cont || !cont->conn.connected || cont->conn.fd < 0) {
        return -1;
    }

    net_event_t evs[NET_MAX_EVENTS_PER_POLL];
    int n = net_event_loop_poll(&cont->loop, timeout_ms, evs, NET_MAX_EVENTS_PER_POLL);
    if (n <= 0) {
        return n;
    }

    for (int i = 0; i < n; ++i) {
        int fd = evs[i].fd;
        uint32_t flags = evs[i].flags;

        if (fd == cont->conn.fd) {
            if (flags & (NET_EV_ERROR | NET_EV_EOF)) {
                net_event_loop_del(&cont->loop, cont->conn.fd);
                close(cont->conn.fd);
                cont->conn.connected = false;
                cont->conn.fd = -1;
                return -1;
            }

            if (flags & NET_EV_READ) {
                ssize_t rc = recv(cont->conn.fd,
                                  cont->conn.rx_buf + cont->conn.rx_cursor,
                                  sizeof(cont->conn.rx_buf) - cont->conn.rx_cursor, 0);
                if (rc <= 0) {
                    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        continue;
                    }
                    net_event_loop_del(&cont->loop, cont->conn.fd);
                    close(cont->conn.fd);
                    cont->conn.connected = false;
                    cont->conn.fd = -1;
                    return -1;
                }

                cont->conn.rx_cursor += (size_t)rc;

                while (cont->conn.rx_cursor >= K2_NET_HEADER_LEN) {
                    k2_net_header_t hdr;
                    if (k2_net_parse_header(cont->conn.rx_buf, cont->conn.rx_cursor, &hdr) != 0) {
                        return -1;
                    }
                    size_t total = (size_t)K2_NET_HEADER_LEN + hdr.payload_len;
                    if (cont->conn.rx_cursor < total) {
                        break;
                    }

                    const uint8_t *payload = cont->conn.rx_buf + K2_NET_HEADER_LEN;

                    if (hdr.msg_type == K2_MSG_REVEAL_WINDOW) {
                        /* Aggregator signaled reveal window open */
                        if (cont->reveal_payload_len > 0) {
                            (void)k2_contributor_send_reveal(cont, cont->reveal_payload, cont->reveal_payload_len);
                        }
                    } else if (hdr.msg_type == K2_MSG_BLOCK_RESULT) {
                        if (hdr.payload_len == VDF_OUTPUT_LEN) {
                            memcpy(cont->block_result, payload, VDF_OUTPUT_LEN);
                            cont->result_received = true;
                        }
                    }

                    size_t rem = cont->conn.rx_cursor - total;
                    if (rem > 0) {
                        memmove(cont->conn.rx_buf, cont->conn.rx_buf + total, rem);
                    }
                    cont->conn.rx_cursor = rem;
                }
            }
        }
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
