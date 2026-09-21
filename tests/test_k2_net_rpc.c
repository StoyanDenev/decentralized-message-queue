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
static void test_k2_raw_socket_duel(void) {
    printf("[TEST] 4. K=2 POSIX Non-Blocking Socket Duel (Aggregator <-> Contributor)...\n");

    uint16_t test_port = 49152 + (uint16_t)(getpid() % 10000);

    static k2_aggregator_t agg;
    static k2_contributor_t cont;

    TEST_ASSERT(k2_aggregator_init(&agg, test_port) == 0);
    TEST_ASSERT(k2_contributor_init(&cont) == 0);

    /* Setup Aggregator payload */
    const uint8_t agg_reveal[] = "aggregator-block-payload-0xAA";
    TEST_ASSERT(k2_aggregator_start_duel(&agg, agg_reveal, (uint32_t)sizeof(agg_reveal) - 1) == 0);

    /* Setup Contributor payload */
    const uint8_t cont_reveal[] = "contributor-block-payload-0xBB";
    memcpy(cont.reveal_payload, cont_reveal, sizeof(cont_reveal) - 1);
    cont.reveal_payload_len = (uint32_t)sizeof(cont_reveal) - 1;

    /* Connect Contributor */
    TEST_ASSERT(k2_contributor_connect(&cont, "127.0.0.1", test_port) == 0);

    /* Aggregator accept loop poll */
    k2_aggregator_poll(&agg, 50);

    /* Contributor sends commitment */
    uint8_t mock_commit[32];
    memset(mock_commit, 0xCC, 32);
    TEST_ASSERT(k2_contributor_send_commitment(&cont, mock_commit) == 0);

    /* Run event loop rounds until duel completes and result is propagated */
    for (int i = 0; i < 50; ++i) {
        k2_aggregator_poll(&agg, 20);
        k2_contributor_poll(&cont, 20);
        if (agg.duel_completed && cont.result_received) {
            break;
        }
        usleep(2000);
    }

    TEST_ASSERT(agg.duel_completed == true);
    TEST_ASSERT(cont.result_received == true);
    TEST_ASSERT(memcmp(agg.latest_vdf_output, cont.block_result, VDF_OUTPUT_LEN) == 0);

    k2_contributor_close(&cont);
    k2_aggregator_close(&agg);

    printf("  -> PASS: Contributor & Aggregator completed non-blocking duel over raw POSIX sockets.\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("Running Determ Zero-Dependency C99 Networking & RPC Suite\n");
    printf("=================================================================\n");

    test_zero_alloc_json_parser();
    test_rpc_dispatch();
    test_k2_wire_framing();
    test_k2_raw_socket_duel();

    printf("=================================================================\n");
    printf("ALL TESTS PASSED: Asio & nlohmann/json completely eradicated.\n");
    printf("=================================================================\n");
    return 0;
}
