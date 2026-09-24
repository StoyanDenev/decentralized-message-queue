/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: C99 Bare-Metal Peer Mesh & Gossip Engine
 */

#include <determ/net/peer_mesh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_PASS(name) printf("  [PASS] %s\n", name)

typedef struct {
    int connects;
    int disconnects;
    int messages;
    uint8_t last_msg_type;
    uint8_t last_payload[1024];
    size_t  last_payload_len;
} test_context_t;

static void on_test_connect(peer_mesh_t *mesh, int peer_idx, void *user_data) {
    (void)mesh;
    (void)peer_idx;
    test_context_t *ctx = (test_context_t *)user_data;
    ctx->connects++;
}

static void on_test_disconnect(peer_mesh_t *mesh, int peer_idx, void *user_data) {
    (void)mesh;
    (void)peer_idx;
    test_context_t *ctx = (test_context_t *)user_data;
    ctx->disconnects++;
}

static void on_test_message(peer_mesh_t *mesh, int peer_idx, const wire_envelope_t *env, void *user_data) {
    (void)mesh;
    (void)peer_idx;
    test_context_t *ctx = (test_context_t *)user_data;
    ctx->messages++;
    ctx->last_msg_type = env->msg_type;
    ctx->last_payload_len = env->payload_len < sizeof(ctx->last_payload) ? env->payload_len : sizeof(ctx->last_payload);
    memcpy(ctx->last_payload, env->payload, ctx->last_payload_len);
}

static peer_mesh_t s_mesh_a;
static peer_mesh_t s_mesh_b;

static void test_peer_mesh_handshake_and_exchange(void) {
    test_context_t ctx_a = {0};
    test_context_t ctx_b = {0};

    peer_mesh_config_t cfg_a = {
        .domain = "validator-node-a",
        .listen_port = 19842,
        .role = CHAIN_ROLE_SINGLE,
        .shard_id = 0,
        .rate_limit_per_sec = 100.0,
        .rate_limit_burst = 200.0,
        .on_connect = on_test_connect,
        .on_disconnect = on_test_disconnect,
        .on_message = on_test_message,
        .user_data = &ctx_a
    };

    peer_mesh_config_t cfg_b = {
        .domain = "validator-node-b",
        .listen_port = 19843,
        .role = CHAIN_ROLE_SINGLE,
        .shard_id = 0,
        .rate_limit_per_sec = 100.0,
        .rate_limit_burst = 200.0,
        .on_connect = on_test_connect,
        .on_disconnect = on_test_disconnect,
        .on_message = on_test_message,
        .user_data = &ctx_b
    };


    TEST_ASSERT(peer_mesh_init(&s_mesh_a, &cfg_a) == 0);
    TEST_ASSERT(peer_mesh_init(&s_mesh_b, &cfg_b) == 0);

    TEST_ASSERT(peer_mesh_listen(&s_mesh_a, 19842) == 0);

    int b_peer_idx = peer_mesh_connect(&s_mesh_b, "127.0.0.1", 19842);
    TEST_ASSERT(b_peer_idx >= 0);

    /* Drive event loops until handshake completes */
    for (int iter = 0; iter < 50; iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
        if (ctx_a.connects >= 1 && ctx_b.connects >= 1) {
            break;
        }
    }

    TEST_ASSERT(ctx_a.connects >= 1);
    TEST_ASSERT(ctx_b.connects >= 1);

    /* 1. Point-to-Point message transfer */
    const uint8_t mock_tx[] = "canonical-c99-transaction-frame-bytes";
    TEST_ASSERT(peer_mesh_send_to(&s_mesh_b, b_peer_idx, WIRE_MSG_TRANSACTION, mock_tx, sizeof(mock_tx)) == 0);

    for (int iter = 0; iter < 100; iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
        if (ctx_a.messages >= 1) break;
    }

    TEST_ASSERT(ctx_a.messages == 1);
    TEST_ASSERT(ctx_a.last_msg_type == WIRE_MSG_TRANSACTION);
    TEST_ASSERT(ctx_a.last_payload_len == sizeof(mock_tx));
    TEST_ASSERT(memcmp(ctx_a.last_payload, mock_tx, sizeof(mock_tx)) == 0);

    /* 2. Broadcast and Deduplication */
    const uint8_t mock_block[] = "deterministic-fast-block-header-payload";
    int sent = peer_mesh_broadcast(&s_mesh_a, WIRE_MSG_BLOCK, mock_block, sizeof(mock_block));
    TEST_ASSERT(sent == 1);

    for (int iter = 0; iter < 100; iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
        if (ctx_b.messages >= 1) break;
    }

    TEST_ASSERT(ctx_b.messages == 1);
    TEST_ASSERT(ctx_b.last_msg_type == WIRE_MSG_BLOCK);
    TEST_ASSERT(memcmp(ctx_b.last_payload, mock_block, sizeof(mock_block)) == 0);

    /* Second identical broadcast must be suppressed by dedup */
    int re_sent = peer_mesh_broadcast(&s_mesh_a, WIRE_MSG_BLOCK, mock_block, sizeof(mock_block));
    TEST_ASSERT(re_sent == 0); /* Suppressed duplicate */

    /* The same bytes under another message type are a different message. */
    int other_type = peer_mesh_broadcast(&s_mesh_a, WIRE_MSG_TRANSACTION, mock_block, sizeof(mock_block));
    TEST_ASSERT(other_type == 1);
    for (int iter = 0; iter < 100 && ctx_b.messages < 2; iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
    }
    TEST_ASSERT(ctx_b.messages == 2);
    TEST_ASSERT(ctx_b.last_msg_type == WIRE_MSG_TRANSACTION);
    TEST_ASSERT(peer_mesh_broadcast(&s_mesh_a, WIRE_MSG_TRANSACTION, mock_block, sizeof(mock_block)) == 0);

    peer_mesh_close(&s_mesh_a);
    peer_mesh_close(&s_mesh_b);

    TEST_PASS("test_peer_mesh_handshake_and_exchange");
}

/* Inbound non-HELLO messages spend one token each from a bucket of
 * rate_limit_burst tokens refilled at rate_limit_per_sec. */
static void test_inbound_rate_limit(void) {
    test_context_t ctx_a = {0};
    test_context_t ctx_b = {0};
    peer_mesh_config_t cfg_a = {
        .domain = "rate-limited-a",
        .listen_port = 19846,
        .role = CHAIN_ROLE_SINGLE,
        .rate_limit_per_sec = 0.01, /* one token per 100 s: no refill during the test */
        .rate_limit_burst = 2.0,
        .on_connect = on_test_connect,
        .on_disconnect = on_test_disconnect,
        .on_message = on_test_message,
        .user_data = &ctx_a
    };
    peer_mesh_config_t cfg_b = {
        .domain = "sender-b",
        .role = CHAIN_ROLE_SINGLE,
        .rate_limit_per_sec = 100.0,
        .rate_limit_burst = 200.0,
        .on_connect = on_test_connect,
        .on_disconnect = on_test_disconnect,
        .on_message = on_test_message,
        .user_data = &ctx_b
    };
    TEST_ASSERT(peer_mesh_init(&s_mesh_a, &cfg_a) == 0);
    TEST_ASSERT(peer_mesh_init(&s_mesh_b, &cfg_b) == 0);
    TEST_ASSERT(peer_mesh_listen(&s_mesh_a, 19846) == 0);
    int idx = peer_mesh_connect(&s_mesh_b, "127.0.0.1", 19846);
    TEST_ASSERT(idx >= 0);
    for (int iter = 0; iter < 50 && (ctx_a.connects < 1 || ctx_b.connects < 1); iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
    }
    TEST_ASSERT(ctx_a.connects == 1 && ctx_b.connects == 1);

    for (uint8_t i = 0; i < 5; i++)
        TEST_ASSERT(peer_mesh_send_to(&s_mesh_b, idx, WIRE_MSG_TRANSACTION, &i, 1) == 0);
    for (int iter = 0; iter < 100 && s_mesh_b.peers[idx].tx_len != 0; iter++) {
        peer_mesh_poll(&s_mesh_b, 10);
        peer_mesh_poll(&s_mesh_a, 10);
    }
    TEST_ASSERT(s_mesh_b.peers[idx].tx_len == 0); /* all five frames written */
    for (int iter = 0; iter < 10; iter++) peer_mesh_poll(&s_mesh_a, 10);

    /* The burst admits the first two; the other three are dropped, not queued. */
    TEST_ASSERT(ctx_a.messages == 2);
    TEST_ASSERT(ctx_a.last_payload_len == 1 && ctx_a.last_payload[0] == 1);
    TEST_ASSERT(ctx_a.disconnects == 0);

    peer_mesh_close(&s_mesh_a);
    peer_mesh_close(&s_mesh_b);
    TEST_PASS("test_inbound_rate_limit");
}

/* Connect B to A (listening on port) and complete the HELLO exchange. */
static int connect_pair(test_context_t *ctx_a, test_context_t *ctx_b, uint16_t port) {
    peer_mesh_config_t cfg_a = {
        .domain = "node-a", .listen_port = port, .role = CHAIN_ROLE_SINGLE,
        .rate_limit_per_sec = 100.0, .rate_limit_burst = 200.0,
        .on_connect = on_test_connect, .on_disconnect = on_test_disconnect,
        .on_message = on_test_message, .user_data = ctx_a
    };
    peer_mesh_config_t cfg_b = cfg_a;
    snprintf(cfg_b.domain, sizeof(cfg_b.domain), "node-b");
    cfg_b.listen_port = 0;
    cfg_b.user_data = ctx_b;
    TEST_ASSERT(peer_mesh_init(&s_mesh_a, &cfg_a) == 0);
    TEST_ASSERT(peer_mesh_init(&s_mesh_b, &cfg_b) == 0);
    TEST_ASSERT(peer_mesh_listen(&s_mesh_a, port) == 0);
    int idx = peer_mesh_connect(&s_mesh_b, "127.0.0.1", port);
    TEST_ASSERT(idx >= 0);
    for (int iter = 0; iter < 50 && (ctx_a->connects < 1 || ctx_b->connects < 1); iter++) {
        peer_mesh_poll(&s_mesh_a, 10);
        peer_mesh_poll(&s_mesh_b, 10);
    }
    TEST_ASSERT(ctx_a->connects == 1 && ctx_b->connects == 1);
    return idx;
}

/* A frame that does not fit the outbound buffer is refused whole: nothing of
 * it is queued, so the next frame still reaches the peer intact. */
static void test_send_frame_is_atomic(void) {
    static uint8_t large[100000];
    static uint8_t oversized[40000];
    const uint8_t small[16] = "after-refusal";
    test_context_t ctx_a = {0};
    test_context_t ctx_b = {0};
    int idx = connect_pair(&ctx_a, &ctx_b, 19847);
    memset(large, 0x5A, sizeof(large));
    memset(oversized, 0xA5, sizeof(oversized));

    TEST_ASSERT(peer_mesh_send_to(&s_mesh_b, idx, WIRE_MSG_BLOCK, large, sizeof(large)) == 0);
    const size_t queued = s_mesh_b.peers[idx].tx_len;
    TEST_ASSERT(queued == 4 + 4 + sizeof(large));
    /* Its 4-byte length header would still fit; the frame does not. */
    TEST_ASSERT(peer_mesh_send_to(&s_mesh_b, idx, WIRE_MSG_BLOCK, oversized, sizeof(oversized)) != 0);
    TEST_ASSERT(s_mesh_b.peers[idx].tx_len == queued);
    TEST_ASSERT(peer_mesh_send_to(&s_mesh_b, idx, WIRE_MSG_TRANSACTION, small, sizeof(small)) == 0);

    for (int iter = 0; iter < 200 && ctx_a.messages < 2; iter++) {
        peer_mesh_poll(&s_mesh_b, 10);
        peer_mesh_poll(&s_mesh_a, 10);
    }
    TEST_ASSERT(ctx_a.messages == 2);
    TEST_ASSERT(ctx_a.last_msg_type == WIRE_MSG_TRANSACTION);
    TEST_ASSERT(ctx_a.last_payload_len == sizeof(small));
    TEST_ASSERT(memcmp(ctx_a.last_payload, small, sizeof(small)) == 0);
    TEST_ASSERT(ctx_a.disconnects == 0);

    peer_mesh_close(&s_mesh_a);
    peer_mesh_close(&s_mesh_b);
    TEST_PASS("test_send_frame_is_atomic");
}

/* OR of the flags of every event for tag (kqueue reports one event per filter). */
static uint32_t poll_flags(net_event_loop_t *loop, int timeout_ms, void *tag) {
    net_event_t events[NET_MAX_EVENTS_PER_POLL];
    uint32_t flags = 0;
    int n = net_event_loop_poll(loop, timeout_ms, events, NET_MAX_EVENTS_PER_POLL);
    TEST_ASSERT(n >= 0);
    for (int i = 0; i < n; i++) {
        TEST_ASSERT(events[i].user_data == tag);
        flags |= events[i].flags;
    }
    return flags;
}

/* The event loop reports readiness level-triggered on both backends, from
 * add() and from mod(), and mod() removes interest it no longer requests. */
static void test_event_loop_level_triggered(void) {
    int pair[2];
    char buf[2];
    net_event_loop_t loop;
    void *tag = &loop;
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    TEST_ASSERT(net_socket_set_nonblocking(pair[0]) == 0);
    TEST_ASSERT(net_event_loop_init(&loop) == 0);
    TEST_ASSERT(net_event_loop_add(&loop, pair[0], NET_EV_READ, tag) == 0);
    TEST_ASSERT(poll_flags(&loop, 0, tag) == 0);

    TEST_ASSERT(write(pair[1], "ab", 2) == 2);
    /* Unread data is reported again by every poll, not only on arrival. */
    TEST_ASSERT(poll_flags(&loop, 100, tag) == NET_EV_READ);
    TEST_ASSERT(poll_flags(&loop, 0, tag) == NET_EV_READ);

    TEST_ASSERT(net_event_loop_mod(&loop, pair[0], NET_EV_READ | NET_EV_WRITE, tag) == 0);
    TEST_ASSERT(poll_flags(&loop, 0, tag) == (NET_EV_READ | NET_EV_WRITE));
    TEST_ASSERT(poll_flags(&loop, 0, tag) == (NET_EV_READ | NET_EV_WRITE));
    /* Dropping write interest stops write events (kqueue kept EVFILT_WRITE). */
    TEST_ASSERT(net_event_loop_mod(&loop, pair[0], NET_EV_READ, tag) == 0);
    TEST_ASSERT(poll_flags(&loop, 0, tag) == NET_EV_READ);

    TEST_ASSERT(read(pair[0], buf, sizeof(buf)) == 2);
    TEST_ASSERT(poll_flags(&loop, 0, tag) == 0);
    TEST_ASSERT(net_event_loop_del(&loop, pair[0]) == 0);
    net_event_loop_close(&loop);
    close(pair[0]);
    close(pair[1]);
    TEST_PASS("test_event_loop_level_triggered");
}

static size_t inbound_peers(const peer_mesh_t *mesh) {
    size_t count = 0;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++)
        if (mesh->peers[i].state != PEER_STATE_FREE && mesh->peers[i].inbound) count++;
    return count;
}

/* Every connection queued at the listener is accepted by one poll, not one
 * connection per readiness event. */
static void test_accept_drains_backlog(void) {
    test_context_t ctx_a = {0};
    peer_mesh_config_t cfg_a = {
        .domain = "listener-a", .listen_port = 19848, .role = CHAIN_ROLE_SINGLE,
        .rate_limit_per_sec = 100.0, .rate_limit_burst = 200.0,
        .on_connect = on_test_connect, .on_disconnect = on_test_disconnect,
        .on_message = on_test_message, .user_data = &ctx_a
    };
    struct sockaddr_in addr;
    struct timespec settle = {0, 50000000L}; /* let both handshakes reach the backlog */
    int clients[2];
    TEST_ASSERT(peer_mesh_init(&s_mesh_a, &cfg_a) == 0);
    TEST_ASSERT(peer_mesh_listen(&s_mesh_a, 19848) == 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(19848);
    TEST_ASSERT(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    for (int i = 0; i < 2; i++) {
        clients[i] = socket(AF_INET, SOCK_STREAM, 0);
        TEST_ASSERT(clients[i] >= 0);
        TEST_ASSERT(connect(clients[i], (struct sockaddr *)&addr, sizeof(addr)) == 0);
    }
    (void)nanosleep(&settle, NULL);

    TEST_ASSERT(peer_mesh_poll(&s_mesh_a, 100) > 0);
    TEST_ASSERT(inbound_peers(&s_mesh_a) == 2);

    peer_mesh_close(&s_mesh_a);
    close(clients[0]);
    close(clients[1]);
    TEST_PASS("test_accept_drains_backlog");
}

static void test_role_based_filtering(void) {
    /* Test cross-chain role-based gossip filter logic */
    /* 1. Universal messages allowed from any peer */
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_HELLO, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_STATUS_REQUEST, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_EQUIVOCATION_EVIDENCE, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_ABORT_EVENT, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_SNAPSHOT_REQUEST, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);

    /* 2. BEACON_HEADER only allowed from BEACON peers */
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_BEACON_HEADER, CHAIN_ROLE_BEACON, 0, CHAIN_ROLE_SHARD, 1) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_BEACON_HEADER, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_SHARD, 1) == false);

    /* 3. SHARD_TIP only allowed from SHARD peers */
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_SHARD_TIP, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_BEACON, 0) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_SHARD_TIP, CHAIN_ROLE_BEACON, 0, CHAIN_ROLE_BEACON, 0) == false);

    /* 4. Intra-chain consensus messages restricted to same role & shard */
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_BLOCK, CHAIN_ROLE_SHARD, 1, CHAIN_ROLE_SHARD, 1) == true);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_BLOCK, CHAIN_ROLE_SHARD, 2, CHAIN_ROLE_SHARD, 1) == false);
    TEST_ASSERT(peer_mesh_is_allowed(WIRE_MSG_TRANSACTION, CHAIN_ROLE_BEACON, 0, CHAIN_ROLE_SHARD, 1) == false);

    TEST_PASS("test_role_based_filtering");
}

int main(void) {
    printf("=== Starting C99 Peer Mesh & Gossip Engine Test Suite ===\n");
    test_role_based_filtering();
    test_peer_mesh_handshake_and_exchange();
    test_inbound_rate_limit();
    test_send_frame_is_atomic();
    test_event_loop_level_triggered();
    test_accept_drains_backlog();
    printf("=== All C99 Peer Mesh Tests Passed Successfully ===\n");
    return 0;
}
