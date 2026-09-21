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

    for (int iter = 0; iter < 20; iter++) {
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

    for (int iter = 0; iter < 20; iter++) {
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

    peer_mesh_close(&s_mesh_a);
    peer_mesh_close(&s_mesh_b);

    TEST_PASS("test_peer_mesh_handshake_and_exchange");
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
    printf("=== All C99 Peer Mesh Tests Passed Successfully ===\n");
    return 0;
}
