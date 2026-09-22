/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Verification Suite for K=2 POSIX Non-Blocking Networking & Zero-Allocation JSON-RPC.
 * Pure C99 bare-metal testing.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <determ/net/event_loop.h>
#include <determ/net/k2_net.h>
#include <determ/wire/json_token.h>
#include <determ/rpc/json_rpc.h>
#include <determ/consensus/duel_state.h>
#include <determ/crypto/vdf.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/time/clock.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

/* ── 1. Test Zero-Allocation JSON Token Parser ─────────────────────────────── */
static void test_zero_alloc_json_parser(void) {
    printf("[TEST] 1. Zero-Allocation In-Place JSON Token Parser...\n");

    const char json_doc[] =
        "{\"method\":\"get_status\",\"params\":{\"round\":42,\"active\":true},\"id\":101}";
    determ_json_tok_t tokens[32];

    int count = determ_json_parse(json_doc, strlen(json_doc), tokens, 32);
    TEST_ASSERT(count > 0);
    TEST_ASSERT(tokens[0].type == JSON_TOK_OBJECT);

    /* Test finding keys */
    const determ_json_tok_t *method_val = determ_json_find_key(json_doc, tokens, (size_t)count, &tokens[0], "method");
    TEST_ASSERT(method_val != NULL);
    TEST_ASSERT(method_val->type == JSON_TOK_STRING);
    TEST_ASSERT(determ_json_token_streq(json_doc, method_val, "get_status") == 1);

    const determ_json_tok_t *id_val = determ_json_find_key(json_doc, tokens, (size_t)count, &tokens[0], "id");
    TEST_ASSERT(id_val != NULL);
    uint64_t id_num = 0;
    TEST_ASSERT(determ_json_token_to_uint64(json_doc, id_val, &id_num) == 0);
    TEST_ASSERT(id_num == 101);

    /* Test malformed / incomplete rejection */
    const char bad_json[] = "{\"method\": \"broken";
    TEST_ASSERT(determ_json_parse(bad_json, strlen(bad_json), tokens, 32) < 0);

    printf("  -> PASS: JSON tokens extracted in-place with zero malloc().\n");
}

/* ── 2. Test In-Place RPC Dispatcher ────────────────────────────────────────── */
static void test_rpc_dispatch(void) {
    printf("[TEST] 2. In-Place JSON-RPC Dispatcher...\n");

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);

    char resp[RPC_MAX_RESPONSE_LEN];

    /* Call get_status */
    const char req_status[] = "{\"method\":\"get_status\",\"params\":{},\"id\":1}";
    int len = rpc_dispatch(req_status, strlen(req_status), &sm, resp, sizeof(resp));
    TEST_ASSERT(len > 0);
    TEST_ASSERT(strstr(resp, "\"state\":\"COMMITMENT_PHASE\"") != NULL);
    TEST_ASSERT(strstr(resp, "\"id\":1") != NULL);

    /* Call get_vdf_stats */
    const char req_vdf[] = "{\"method\":\"get_vdf_stats\",\"params\":{},\"id\":2}";
    len = rpc_dispatch(req_vdf, strlen(req_vdf), &sm, resp, sizeof(resp));
    TEST_ASSERT(len > 0);
    TEST_ASSERT(strstr(resp, "\"arena_kb\":64") != NULL);
    TEST_ASSERT(strstr(resp, "\"scope\":\"dda-helper-only\"") != NULL);
    TEST_ASSERT(strstr(resp, "\"consensus_enforced\":false") != NULL);
    sm.state = DUEL_STATE_ABORTED;
    TEST_ASSERT(rpc_dispatch(req_status, strlen(req_status), &sm, resp, sizeof(resp)) > 0);
    TEST_ASSERT(strstr(resp, "\"state\":\"ABORTED\"") != NULL);
    const char req_duel[] = "{\"method\":\"get_duel_state\",\"id\":3}";
    sm.state = DUEL_STATE_AWAITING_REVEALS;
    sm.reveal_start_ns = duel_clock_monotonic_ns();
    sm.epoch_start_time = sm.reveal_start_ns - 500000000ULL;
    TEST_ASSERT(rpc_dispatch(req_duel, strlen(req_duel), &sm, resp, sizeof(resp)) > 0);
    TEST_ASSERT(strstr(resp, "\"deadline_origin\":\"attempt_start\"") != NULL);
    const char *elapsed = strstr(resp, "\"elapsed_ms\":");
    TEST_ASSERT(elapsed != NULL && strtoull(elapsed + 13, NULL, 10) >= 500);

    /* Call non-existent method */
    const char req_unknown[] = "{\"method\":\"foobar_unknown\",\"params\":{},\"id\":3}";
    len = rpc_dispatch(req_unknown, strlen(req_unknown), &sm, resp, sizeof(resp));
    TEST_ASSERT(len > 0);
    TEST_ASSERT(strstr(resp, "\"code\":-32601") != NULL);

    printf("  -> PASS: JSON-RPC requests dispatched cleanly on stack.\n");
}

/* ── 3. Test Non-Blocking Event Loop & Wire Framing ────────────────────────── */
static void test_k2_wire_framing(void) {
    printf("[TEST] 3. K=2 Big-Endian Wire Frame Encoding/Parsing...\n");

    uint8_t payload[64];
    memset(payload, 0xAB, sizeof(payload));

    uint8_t frame_buf[128];
    size_t frame_len = 0;

    TEST_ASSERT(k2_net_encode_frame(K2_MSG_REVEAL_PAYLOAD, payload, (uint32_t)sizeof(payload),
                                    frame_buf, sizeof(frame_buf), &frame_len) == 0);
    TEST_ASSERT(frame_len == K2_NET_HEADER_LEN + sizeof(payload));

    k2_net_header_t hdr;
    TEST_ASSERT(k2_net_parse_header(frame_buf, frame_len, &hdr) == 0);
    TEST_ASSERT(hdr.magic == K2_NET_MAGIC);
    TEST_ASSERT(hdr.msg_type == K2_MSG_REVEAL_PAYLOAD);
    TEST_ASSERT(hdr.payload_len == sizeof(payload));

    /* Test corrupt magic rejection */
    frame_buf[0] = 0x00;
    TEST_ASSERT(k2_net_parse_header(frame_buf, frame_len, &hdr) == -2);

    printf("  -> PASS: Big-Endian binary wire frames validated.\n");
}

/* ── 4. Test K=2 Raw Non-Blocking POSIX Socket Duel ────────────────────────── */
static k2_aggregator_t agg;
static k2_contributor_t cont;
static const uint8_t agg_payload[] = "experimental aggregator";
static const uint8_t cont_payload[] = "experimental contributor";

static uint16_t listen_port(void) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    TEST_ASSERT(getsockname(agg.listen_fd, (struct sockaddr *)&addr, &len) == 0);
    return ntohs(addr.sin_port);
}
static void connect_contributor(bool prepare_reveal) {
    TEST_ASSERT(k2_contributor_init(&cont) == 0);
    TEST_ASSERT(k2_contributor_connect(&cont, "127.0.0.1", listen_port()) == 0);
    TEST_ASSERT(k2_aggregator_poll(&agg, 10) >= 0);
    TEST_ASSERT(agg.peer.connected);
    if (prepare_reveal) {
        memcpy(cont.reveal_payload, cont_payload, sizeof(cont_payload));
        cont.reveal_payload_len = sizeof(cont_payload);
    }
}
static void start_attempt(void) {
    TEST_ASSERT(k2_aggregator_start_duel(&agg, agg_payload, sizeof(agg_payload)) == 0);
    TEST_ASSERT(!agg.duel_completed && agg.duel_sm.aggregator_commit.present);
    TEST_ASSERT(agg.peer.fd == -1);
}
static void send_commit(bool correct) {
    uint8_t hash[32];
    determ_sha256(cont_payload, sizeof(cont_payload), hash);
    if (!correct) hash[0] ^= 1;
    TEST_ASSERT(k2_contributor_send_commitment(&cont, hash) == 0);
    TEST_ASSERT(k2_aggregator_poll(&agg, 20) == 0);
    TEST_ASSERT(agg.duel_sm.state == DUEL_STATE_AWAITING_REVEALS);
    TEST_ASSERT(agg.duel_sm.contributor_commit.present);
}
static void test_k2_raw_socket_duel(void) {
    TEST_ASSERT(k2_aggregator_init(&agg, 0) == 0);

    /* A missing commitment returns terminal failure, including repeated polls. */
    start_attempt();
    agg.duel_sm.epoch_start_time -= DUEL_COMMIT_TIMEOUT_NS - 20000000ULL;
    /* An indefinite caller timeout must still wake at the attempt deadline. */
    TEST_ASSERT(k2_aggregator_poll(&agg, -1) == ERR_EPOCH_SKIPPED_SILENCE);
    TEST_ASSERT(k2_aggregator_poll(&agg, 0) == ERR_EPOCH_SKIPPED_SILENCE);
    TEST_ASSERT(!agg.duel_completed && agg.peer.fd == -1);

    /* Explicit retry, but a reveal cannot bypass the commitment phase. */
    start_attempt();
    connect_contributor(false);
    TEST_ASSERT(k2_contributor_send_reveal(&cont, cont_payload, sizeof(cont_payload)) == 0);
    TEST_ASSERT(k2_aggregator_poll(&agg, 20) == DUEL_ERR_INVALID_STATE);
    TEST_ASSERT(agg.peer.fd == -1 && agg.duel_sm.vdf_input_len == 0);
    k2_contributor_close(&cont);

    /* A peer which never opens the reveal window cannot hold an infinite poll. */
    start_attempt();
    connect_contributor(false);
    uint8_t hash[32];
    determ_sha256(cont_payload, sizeof(cont_payload), hash);
    TEST_ASSERT(k2_contributor_send_commitment(&cont, hash) == 0);
    cont.attempt_start_ns -= K2_RESPONSE_TIMEOUT_NS - 20000000ULL;
    TEST_ASSERT(k2_contributor_poll(&cont, -1) == -1);
    TEST_ASSERT(!cont.conn.connected && cont.conn.fd == -1);
    k2_contributor_close(&cont);
    int closed_status = 0;
    for (int i = 0; i < 120 && closed_status >= 0; i++)
        closed_status = k2_aggregator_poll(&agg, 20);
    TEST_ASSERT(closed_status < 0 && agg.duel_sm.state == DUEL_STATE_ABORTED);

    /* The network must actually record and check the received commitment. */
    start_attempt();
    connect_contributor(true);
    send_commit(false);
    TEST_ASSERT(k2_contributor_poll(&cont, 20) == 0);
    TEST_ASSERT(k2_aggregator_poll(&agg, 20) == DUEL_DROPPED_INVALID_PAYLOAD);
    TEST_ASSERT(!agg.duel_completed && agg.peer.fd == -1);
    k2_contributor_close(&cont);

    /* Correct commitment with withheld reveal terminates at the total deadline. */
    start_attempt();
    connect_contributor(false);
    send_commit(true);
    TEST_ASSERT(k2_contributor_poll(&cont, 20) == 0);
    agg.duel_sm.epoch_start_time -= DUEL_REVEAL_WINDOW_NS;
    TEST_ASSERT(k2_aggregator_poll(&agg, 0) == ERR_EPOCH_SKIPPED_INCOMPLETE);
    TEST_ASSERT(agg.duel_sm.vdf_input_len == 0 && !agg.duel_completed && agg.peer.fd == -1);
    k2_contributor_close(&cont);

    /* Another explicit retry can complete; there is no hidden re-election. */
    start_attempt();
    connect_contributor(true);
    send_commit(true);
    for (int i = 0; i < 50 && !agg.duel_completed; i++) {
        TEST_ASSERT(k2_contributor_poll(&cont, 10) >= 0);
        TEST_ASSERT(k2_aggregator_poll(&agg, 10) >= 0);
    }
    TEST_ASSERT(agg.duel_completed && agg.duel_sm.state == DUEL_STATE_COMPLETED);
    TEST_ASSERT(vdf_verify(&agg.vdf_ctx, agg.duel_sm.vdf_input_buffer, agg.duel_sm.vdf_input_len,
                           K2_EXPERIMENT_ITERATIONS, agg.latest_vdf_output) == 1);
    uint8_t expected[VDF_OUTPUT_LEN];
    memcpy(expected, agg.latest_vdf_output, sizeof(expected));
    /* Match daemon lifecycle: send result then immediately close the Aggregator. */
    k2_aggregator_close(&agg);
    for (int i = 0; i < 50 && !cont.result_received; i++)
        TEST_ASSERT(k2_contributor_poll(&cont, 10) >= 0);
    TEST_ASSERT(cont.result_received && memcmp(expected, cont.block_result, sizeof(expected)) == 0);
    k2_contributor_close(&cont);
    puts("PASS: real socket commitment binding, terminal failures, explicit retry and local completion");
}

/* TCP FIN need not carry EPOLLHUP while data remains unread. A fully closed
 * local stream peer gives both native backends queued bytes plus EOF, without
 * depending on TCP segmentation or FIN/ACK scheduling. Observe that condition
 * independently, then exercise the ordinary Contributor receive path. */
static void test_buffered_result_at_eof(void) {
    static k2_contributor_t receiver;
    uint8_t expected[VDF_OUTPUT_LEN];
    uint8_t commitment[32] = {0};
    uint8_t received_commit[K2_NET_HEADER_LEN + sizeof(commitment)];
    uint8_t frames[2 * K2_NET_HEADER_LEN + VDF_OUTPUT_LEN];
    size_t window_len = 0, result_len = 0;
    memset(expected, 0xa7, sizeof(expected));
    TEST_ASSERT(k2_net_encode_frame(K2_MSG_REVEAL_WINDOW, NULL, 0,
                                   frames, sizeof(frames), &window_len) == 0);
    TEST_ASSERT(k2_net_encode_frame(K2_MSG_BLOCK_RESULT, expected, sizeof(expected),
                                   frames + window_len, sizeof(frames) - window_len,
                                   &result_len) == 0);

    /* The complete frame succeeds; the same stream missing its final byte fails. */
    for (size_t missing = 0; missing < 2; ++missing) {
        int pair[2];
        net_event_loop_t observer;
        net_event_t events[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        TEST_ASSERT(net_socket_set_nonblocking(pair[0]) == 0);
        TEST_ASSERT(net_socket_set_nonblocking(pair[1]) == 0);
        TEST_ASSERT(k2_contributor_init(&receiver) == 0);
        receiver.conn.fd = pair[0];
        receiver.conn.connected = true;
        TEST_ASSERT(net_event_loop_add(&receiver.loop, pair[0], NET_EV_READ,
                                       (void *)(intptr_t)1) == 0);
        TEST_ASSERT(net_event_loop_init(&observer) == 0);
        TEST_ASSERT(net_event_loop_add(&observer, pair[0], NET_EV_READ,
                                       (void *)(intptr_t)2) == 0);

        TEST_ASSERT(k2_contributor_send_commitment(&receiver, commitment) == 0);
        size_t drained = 0;
        while (drained < sizeof(received_commit)) {
            ssize_t count = recv(pair[1], received_commit + drained,
                                 sizeof(received_commit) - drained, 0);
            TEST_ASSERT(count > 0);
            drained += (size_t)count;
        }
        size_t sent = 0;
        size_t length = window_len + result_len - missing;
        while (sent < length) {
            ssize_t count = send(pair[1], frames + sent, length - sent, 0);
            TEST_ASSERT(count > 0);
            sent += (size_t)count;
        }
        TEST_ASSERT(close(pair[1]) == 0);

        /* Polling this separate watcher consumes neither bytes nor the
         * Contributor event loop's readiness notification. */
        TEST_ASSERT(net_event_loop_poll(&observer, 0, events, 2) == 1);
        TEST_ASSERT(events[0].user_data == (void *)(intptr_t)2);
        TEST_ASSERT((events[0].flags & (NET_EV_READ | NET_EV_EOF)) ==
                    (NET_EV_READ | NET_EV_EOF));
        net_event_loop_close(&observer);
        TEST_ASSERT(!receiver.result_received && !receiver.reveal_window_seen);
        if (missing == 0) {
            TEST_ASSERT(k2_contributor_poll(&receiver, 0) == 1);
            TEST_ASSERT(receiver.result_received && receiver.reveal_window_seen);
            TEST_ASSERT(memcmp(receiver.block_result, expected, sizeof(expected)) == 0);
        } else {
            TEST_ASSERT(k2_contributor_poll(&receiver, 0) == -1);
            TEST_ASSERT(!receiver.result_received && receiver.reveal_window_seen);
            TEST_ASSERT(!receiver.conn.connected && receiver.conn.fd == -1);
        }
        k2_contributor_close(&receiver);
    }
    puts("PASS: READ|EOF preserves a complete buffered result and rejects a truncated result");
}

/* A commitment plus a maximum reveal is larger than the receive arena.
 * No additional network input is required to drain and assemble both frames. */
static void test_coalesced_maximum_reveal(void) {
    static uint8_t reveal[DUEL_MAX_PAYLOAD_SIZE];
    static uint8_t frames[2 * K2_NET_HEADER_LEN + 32 + DUEL_MAX_PAYLOAD_SIZE];
    uint8_t hash[32];
    size_t first = 0, second = 0;
    memset(reveal, 0x5a, sizeof(reveal));
    determ_sha256(reveal, sizeof(reveal), hash);
    TEST_ASSERT(k2_aggregator_init(&agg, 0) == 0);
    start_attempt();
    connect_contributor(false);
    TEST_ASSERT(k2_net_encode_frame(K2_MSG_COMMITMENT, hash, sizeof(hash), frames, sizeof(frames), &first) == 0);
    TEST_ASSERT(k2_net_encode_frame(K2_MSG_REVEAL_PAYLOAD, reveal, sizeof(reveal), frames + first, sizeof(frames) - first, &second) == 0);
    int capacity = sizeof(frames) * 2;
    TEST_ASSERT(setsockopt(cont.conn.fd, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0);
    TEST_ASSERT(setsockopt(agg.peer.fd, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) == 0);
    size_t sent = 0;
    while (sent < first + second) {
        ssize_t amount = send(cont.conn.fd, frames + sent, first + second - sent, 0);
        TEST_ASSERT(amount > 0);
        sent += (size_t)amount;
    }
    for (int i = 0; i < 50 && !agg.duel_completed; i++)
        TEST_ASSERT(k2_aggregator_poll(&agg, 10) >= 0);
    TEST_ASSERT(agg.duel_completed && agg.duel_sm.contributor_reveal.len == sizeof(reveal));
    k2_contributor_close(&cont);
    k2_aggregator_close(&agg);
    puts("PASS: coalesced commitment and maximum-size reveal drained");
}

int main(void) {
    printf("=================================================================\n");
    printf("Running Determ Zero-Dependency C99 Networking & RPC Suite\n");
    printf("=================================================================\n");

    test_zero_alloc_json_parser();
    test_rpc_dispatch();
    test_k2_wire_framing();
    test_buffered_result_at_eof();
    test_k2_raw_socket_duel();
    test_coalesced_maximum_reveal();

    printf("=================================================================\n");
    printf("PASS: scoped parser/RPC and experimental socket checks.\n");
    printf("=================================================================\n");
    return 0;
}
