/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Peer Mesh & Gossip Protocol Engine.
 */

#include <determ/net/peer_mesh.h>
#include <determ/crypto/sha2/sha2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define LISTENER_TOKEN ((void*)(uintptr_t)(-1))

static inline uint32_t be_get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static inline void be_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

bool peer_mesh_is_allowed(uint8_t msg_type, uint8_t peer_role, uint32_t peer_shard_id,
                          uint8_t our_role, uint32_t our_shard_id) {
    switch (msg_type) {
    case WIRE_MSG_HELLO:
    case WIRE_MSG_STATUS_REQUEST:
    case WIRE_MSG_STATUS_RESPONSE:
    case WIRE_MSG_EQUIVOCATION_EVIDENCE:
    case WIRE_MSG_ABORT_EVENT:
        return true;
    case WIRE_MSG_BEACON_HEADER:
        return (peer_role == CHAIN_ROLE_BEACON);
    case WIRE_MSG_SHARD_TIP:
        return (peer_role == CHAIN_ROLE_SHARD);
    case WIRE_MSG_CROSS_SHARD_RECEIPT_BUNDLE:
        return (peer_role == CHAIN_ROLE_BEACON || peer_role == CHAIN_ROLE_SHARD);
    case WIRE_MSG_SNAPSHOT_REQUEST:
    case WIRE_MSG_SNAPSHOT_RESPONSE:
    case WIRE_MSG_HEADERS_REQUEST:
    case WIRE_MSG_HEADERS_RESPONSE:
        return true;
    default:
        /* Intra-chain consensus messages */
        if (peer_role != our_role) return false;
        if (our_role == CHAIN_ROLE_SHARD && peer_shard_id != our_shard_id) return false;
        return true;
    }
}

static bool rate_limiter_consume(peer_entry_t *peer, double per_sec, double burst) {
    if (per_sec <= 0.0 || burst <= 0.0) return true;
    uint64_t now = get_time_ms();
    if (peer->last_token_update_ms == 0) {
        peer->tokens = burst;
        peer->last_token_update_ms = now;
    } else {
        double elapsed_sec = (double)(now - peer->last_token_update_ms) / 1000.0;
        peer->tokens += elapsed_sec * per_sec;
        if (peer->tokens > burst) peer->tokens = burst;
        peer->last_token_update_ms = now;
    }
    if (peer->tokens >= 1.0) {
        peer->tokens -= 1.0;
        return true;
    }
    return false;
}

int peer_mesh_init(peer_mesh_t *mesh, const peer_mesh_config_t *cfg) {
    if (!mesh || !cfg) return -1;
    memset(mesh, 0, sizeof(*mesh));
    mesh->config = *cfg;
    if (mesh->config.rate_limit_burst <= 0.0) {
        mesh->config.rate_limit_burst = 100.0;
    }
    if (mesh->config.rate_limit_per_sec <= 0.0) {
        mesh->config.rate_limit_per_sec = 50.0;
    }
    if (net_event_loop_init(&mesh->loop) != 0) {
        return -2;
    }
    mesh->listen_fd = -1;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        mesh->peers[i].fd = -1;
        mesh->peers[i].state = PEER_STATE_FREE;
    }
    mesh->running = true;
    return 0;
}

int peer_mesh_listen(peer_mesh_t *mesh, uint16_t port) {
    if (!mesh || mesh->listen_fd >= 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -2;

    if (net_socket_set_nonblocking(fd) != 0 ||
        net_socket_set_reuseaddr(fd) != 0 ||
        net_socket_set_nodelay(fd) != 0) {
        close(fd);
        return -3;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -4;
    }

    if (listen(fd, 16) != 0) {
        close(fd);
        return -5;
    }

    mesh->listen_fd = fd;
    mesh->config.listen_port = port;

    if (net_event_loop_add(&mesh->loop, fd, NET_EV_READ, LISTENER_TOKEN) != 0) {
        close(fd);
        mesh->listen_fd = -1;
        return -6;
    }

    return 0;
}

static int send_raw_frame(peer_mesh_t *mesh, int peer_idx, const uint8_t *frame, size_t frame_len) {
    peer_entry_t *peer = &mesh->peers[peer_idx];
    if (peer->state == PEER_STATE_FREE || peer->fd < 0) return -1;
    if (peer->tx_len + frame_len > PEER_MESH_TX_BUF_SIZE) return -2; /* Outbound buffer full */

    memcpy(peer->tx_buf + peer->tx_len, frame, frame_len);
    peer->tx_len += frame_len;

    /* Register for write readiness */
    net_event_loop_mod(&mesh->loop, peer->fd, NET_EV_READ | NET_EV_WRITE, (void*)(uintptr_t)peer_idx);
    return 0;
}

static int peer_mesh_send_hello(peer_mesh_t *mesh, int peer_idx) {
    uint8_t payload[256];
    size_t payload_len = 0;
    wire_hello_t hello;
    hello.domain = mesh->config.domain;
    hello.domain_len = (uint8_t)strlen(mesh->config.domain);
    hello.port = mesh->config.listen_port;
    hello.role = (uint8_t)mesh->config.role;
    hello.shard_id = mesh->config.shard_id;
    hello.wire_version = 1;

    if (wire_hello_encode(payload, sizeof(payload), &hello, &payload_len) != WIRE_CODEC_OK) {
        return -1;
    }

    uint8_t env_buf[512];
    size_t env_len = 0;
    if (wire_envelope_encode(env_buf, sizeof(env_buf), WIRE_MSG_HELLO, payload, payload_len, &env_len) != WIRE_CODEC_OK) {
        return -2;
    }

    uint8_t framed[516];
    be_put_u32(framed, (uint32_t)env_len);
    memcpy(framed + 4, env_buf, env_len);
    return send_raw_frame(mesh, peer_idx, framed, 4 + env_len);
}

int peer_mesh_connect(peer_mesh_t *mesh, const char *host, uint16_t port) {
    if (!mesh || !host) return -1;
    int slot = -1;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        if (mesh->peers[i].state == PEER_STATE_FREE) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) return -2; /* No peer slots */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -3;
    net_socket_set_nonblocking(fd);
    net_socket_set_nodelay(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -4;
    }

    peer_entry_t *peer = &mesh->peers[slot];
    memset(peer, 0, sizeof(*peer));
    peer->fd = fd;
    peer->inbound = false;
    snprintf(peer->remote_addr, sizeof(peer->remote_addr), "%s:%u", host, port);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        peer->state = PEER_STATE_HANDSHAKING;
        net_event_loop_add(&mesh->loop, fd, NET_EV_READ | NET_EV_WRITE, (void*)(uintptr_t)slot);
        peer_mesh_send_hello(mesh, slot);
    } else if (errno == EINPROGRESS) {
        peer->state = PEER_STATE_CONNECTING;
        net_event_loop_add(&mesh->loop, fd, NET_EV_READ | NET_EV_WRITE, (void*)(uintptr_t)slot);
    } else {
        close(fd);
        peer->fd = -1;
        peer->state = PEER_STATE_FREE;
        return -5;
    }

    return slot;
}

void peer_mesh_disconnect(peer_mesh_t *mesh, int peer_idx) {
    if (!mesh || peer_idx < 0 || peer_idx >= (int)PEER_MESH_MAX_PEERS) return;
    peer_entry_t *peer = &mesh->peers[peer_idx];
    if (peer->state == PEER_STATE_FREE) return;

    if (peer->fd >= 0) {
        net_event_loop_del(&mesh->loop, peer->fd);
        close(peer->fd);
        peer->fd = -1;
    }
    peer->state = PEER_STATE_FREE;
    if (mesh->config.on_disconnect) {
        mesh->config.on_disconnect(mesh, peer_idx, mesh->config.user_data);
    }
}

int peer_mesh_send_to(peer_mesh_t *mesh, int peer_idx, uint8_t msg_type, const uint8_t *payload, size_t payload_len) {
    if (!mesh || peer_idx < 0 || peer_idx >= (int)PEER_MESH_MAX_PEERS) return -1;
    peer_entry_t *peer = &mesh->peers[peer_idx];
    if (peer->state != PEER_STATE_ACTIVE && peer->state != PEER_STATE_HANDSHAKING) return -2;

    uint8_t env_buf[PEER_MESH_TX_BUF_SIZE];
    size_t env_written = 0;
    if (wire_envelope_encode(env_buf, sizeof(env_buf), msg_type, payload, payload_len, &env_written) != WIRE_CODEC_OK) {
        return -3;
    }

    uint8_t framed_hdr[4];
    be_put_u32(framed_hdr, (uint32_t)env_written);
    if (send_raw_frame(mesh, peer_idx, framed_hdr, 4) != 0) return -4;
    return send_raw_frame(mesh, peer_idx, env_buf, env_written);
}

static bool dedup_check_and_insert(peer_mesh_t *mesh, const uint8_t hash[32]) {
    for (size_t i = 0; i < mesh->dedup.count; i++) {
        if (memcmp(mesh->dedup.entries[i], hash, 32) == 0) {
            return true; /* duplicate found */
        }
    }
    /* insert */
    memcpy(mesh->dedup.entries[mesh->dedup.head], hash, 32);
    mesh->dedup.head = (mesh->dedup.head + 1) % PEER_MESH_DEDUP_CAPACITY;
    if (mesh->dedup.count < PEER_MESH_DEDUP_CAPACITY) {
        mesh->dedup.count++;
    }
    return false;
}

int peer_mesh_broadcast(peer_mesh_t *mesh, uint8_t msg_type, const uint8_t *payload, size_t payload_len) {
    if (!mesh) return -1;
    uint8_t hash[32];
    determ_sha256(payload, payload_len, hash);
    if (dedup_check_and_insert(mesh, hash)) {
        return 0; /* suppressed duplicate */
    }

    int sent_count = 0;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        peer_entry_t *peer = &mesh->peers[i];
        if (peer->state == PEER_STATE_ACTIVE && peer->hello_received) {
            if (peer_mesh_is_allowed(msg_type, peer->role, peer->shard_id,
                                     (uint8_t)mesh->config.role, mesh->config.shard_id)) {
                if (peer_mesh_send_to(mesh, (int)i, msg_type, payload, payload_len) == 0) {
                    sent_count++;
                }
            }
        }
    }
    return sent_count;
}

static void handle_inbound_connection(peer_mesh_t *mesh) {
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int cfd = accept(mesh->listen_fd, (struct sockaddr *)&caddr, &clen);
    if (cfd < 0) return;

    int slot = -1;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        if (mesh->peers[i].state == PEER_STATE_FREE) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        close(cfd);
        return;
    }

    net_socket_set_nonblocking(cfd);
    net_socket_set_nodelay(cfd);

    peer_entry_t *peer = &mesh->peers[slot];
    memset(peer, 0, sizeof(*peer));
    peer->fd = cfd;
    peer->inbound = true;
    peer->state = PEER_STATE_HANDSHAKING;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &caddr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(peer->remote_addr, sizeof(peer->remote_addr), "%s:%u", ip_str, ntohs(caddr.sin_port));

    net_event_loop_add(&mesh->loop, cfd, NET_EV_READ, (void*)(uintptr_t)slot);
    peer_mesh_send_hello(mesh, slot);
}

static void handle_peer_read(peer_mesh_t *mesh, int peer_idx) {
    peer_entry_t *peer = &mesh->peers[peer_idx];
    size_t space = PEER_MESH_RX_BUF_SIZE - peer->rx_cursor;
    if (space == 0) {
        peer_mesh_disconnect(mesh, peer_idx);
        return;
    }

    ssize_t n = read(peer->fd, peer->rx_buf + peer->rx_cursor, space);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        peer_mesh_disconnect(mesh, peer_idx);
        return;
    }
    peer->rx_cursor += (size_t)n;

    /* Frame dispatch loop */
    while (peer->rx_cursor >= 4) {
        uint32_t payload_len = be_get_u32(peer->rx_buf);
        if (payload_len > PEER_MESH_RX_BUF_SIZE - 4) {
            peer_mesh_disconnect(mesh, peer_idx);
            return;
        }
        size_t frame_total = 4 + (size_t)payload_len;
        if (peer->rx_cursor < frame_total) {
            break; /* Incomplete frame, wait for more bytes */
        }

        /* Full frame available */
        wire_envelope_t env;
        if (wire_envelope_decode(peer->rx_buf + 4, payload_len, &env) != WIRE_CODEC_OK) {
            peer_mesh_disconnect(mesh, peer_idx);
            return;
        }

        if (env.msg_type == WIRE_MSG_HELLO) {
            wire_hello_t hello;
            if (wire_hello_decode(env.payload, env.payload_len, &hello) == WIRE_CODEC_OK) {
                size_t dlen = hello.domain_len < PEER_MESH_MAX_DOMAIN_LEN - 1 ? hello.domain_len : PEER_MESH_MAX_DOMAIN_LEN - 1;
                memcpy(peer->domain, hello.domain, dlen);
                peer->domain[dlen] = '\0';
                peer->port = hello.port;
                peer->role = hello.role;
                peer->shard_id = hello.shard_id;
                peer->wire_version = hello.wire_version;
                peer->hello_received = true;
                peer->state = PEER_STATE_ACTIVE;
                if (mesh->config.on_connect) {
                    mesh->config.on_connect(mesh, peer_idx, mesh->config.user_data);
                }
            } else {
                peer_mesh_disconnect(mesh, peer_idx);
                return;
            }
        } else {
            /* Non-HELLO messages */
            if (!rate_limiter_consume(peer, mesh->config.rate_limit_per_sec, mesh->config.rate_limit_burst)) {
                /* Drop message due to rate-limit */
            } else if (!peer->hello_received) {
                /* Drop before handshake completion */
            } else if (!peer_mesh_is_allowed(env.msg_type, peer->role, peer->shard_id,
                                             (uint8_t)mesh->config.role, mesh->config.shard_id)) {
                /* Silent drop cross-chain role violation */
            } else {
                if (mesh->config.on_message) {
                    mesh->config.on_message(mesh, peer_idx, &env, mesh->config.user_data);
                }
            }
        }

        /* Shift unconsumed bytes to buffer start */
        size_t remaining = peer->rx_cursor - frame_total;
        if (remaining > 0) {
            memmove(peer->rx_buf, peer->rx_buf + frame_total, remaining);
        }
        peer->rx_cursor = remaining;
    }
}

static void handle_peer_write(peer_mesh_t *mesh, int peer_idx) {
    peer_entry_t *peer = &mesh->peers[peer_idx];

    if (peer->state == PEER_STATE_CONNECTING) {
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            peer_mesh_disconnect(mesh, peer_idx);
            return;
        }
        peer->state = PEER_STATE_HANDSHAKING;
        peer_mesh_send_hello(mesh, peer_idx);
    }

    if (peer->tx_len > peer->tx_cursor) {
        size_t to_write = peer->tx_len - peer->tx_cursor;
        ssize_t n = write(peer->fd, peer->tx_buf + peer->tx_cursor, to_write);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            peer_mesh_disconnect(mesh, peer_idx);
            return;
        }
        peer->tx_cursor += (size_t)n;
        if (peer->tx_cursor >= peer->tx_len) {
            peer->tx_cursor = 0;
            peer->tx_len = 0;
            net_event_loop_mod(&mesh->loop, peer->fd, NET_EV_READ, (void*)(uintptr_t)peer_idx);
        }
    }
}

int peer_mesh_poll(peer_mesh_t *mesh, int timeout_ms) {
    if (!mesh || !mesh->running) return -1;
    net_event_t events[NET_MAX_EVENTS_PER_POLL];
    int n = net_event_loop_poll(&mesh->loop, timeout_ms, events, NET_MAX_EVENTS_PER_POLL);
    if (n <= 0) return n;

    for (int i = 0; i < n; i++) {
        net_event_t *ev = &events[i];
        if (ev->user_data == LISTENER_TOKEN) {
            if (ev->flags & NET_EV_READ) {
                handle_inbound_connection(mesh);
            }
        } else {
            int peer_idx = (int)(uintptr_t)ev->user_data;
            if (peer_idx >= 0 && peer_idx < (int)PEER_MESH_MAX_PEERS) {
                if (ev->flags & (NET_EV_ERROR | NET_EV_EOF)) {
                    peer_mesh_disconnect(mesh, peer_idx);
                } else {
                    if (ev->flags & NET_EV_WRITE) {
                        handle_peer_write(mesh, peer_idx);
                    }
                    if (ev->flags & NET_EV_READ) {
                        handle_peer_read(mesh, peer_idx);
                    }
                }
            }
        }
    }
    return n;
}

void peer_mesh_close(peer_mesh_t *mesh) {
    if (!mesh) return;
    mesh->running = false;
    if (mesh->listen_fd >= 0) {
        net_event_loop_del(&mesh->loop, mesh->listen_fd);
        close(mesh->listen_fd);
        mesh->listen_fd = -1;
    }
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        if (mesh->peers[i].state != PEER_STATE_FREE) {
            peer_mesh_disconnect(mesh, (int)i);
        }
    }
    net_event_loop_close(&mesh->loop);
}
