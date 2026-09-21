/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: Bare-Metal C99 HTTP/1.1 JSON-RPC Server Transport
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <determ/rpc/http_rpc_server.h>
#include <determ/consensus/duel_state.h>
#include <determ/consensus/dda.h>
#include <determ/storage/block_store.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_PASS(name) printf("  [PASS] %s\n", name)

static int send_http_request(uint16_t port, const char *req, char *resp, size_t max_resp) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    size_t req_len = strlen(req);
    if (write(fd, req, req_len) != (ssize_t)req_len) {
        close(fd);
        return -1;
    }

    size_t total = 0;
    while (total < max_resp - 1) {
        ssize_t n = read(fd, resp + total, max_resp - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    resp[total] = '\0';
    close(fd);
    return (int)total;
}

/* 1. Test GET /health and OPTIONS CORS */
static void test_http_health_and_options(void) {
    uint16_t test_port = 18545;
    http_rpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = test_port;

    http_rpc_server_t server;
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) == 0);
    TEST_ASSERT(http_rpc_server_start(&server) == 0);

    /* Test GET */
    const char get_req[] = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    char resp[2048];

    /* Connect & poll */
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    TEST_ASSERT(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(client_fd, get_req, strlen(get_req)) == (ssize_t)strlen(get_req));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    ssize_t n = read(client_fd, resp, sizeof(resp) - 1);
    TEST_ASSERT(n > 0);
    resp[n] = '\0';
    close(client_fd);

    TEST_ASSERT(strstr(resp, "HTTP/1.1 200 OK") != NULL);
    TEST_ASSERT(strstr(resp, "\"status\":\"OK\"") != NULL);

    /* Test OPTIONS CORS */
    const char opt_req[] = "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(client_fd, opt_req, strlen(opt_req)) == (ssize_t)strlen(opt_req));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    n = read(client_fd, resp, sizeof(resp) - 1);
    TEST_ASSERT(n > 0);
    resp[n] = '\0';
    close(client_fd);

    TEST_ASSERT(strstr(resp, "HTTP/1.1 204 No Content") != NULL);
    TEST_ASSERT(strstr(resp, "Access-Control-Allow-Origin: *") != NULL);

    http_rpc_server_close(&server);
    TEST_PASS("test_http_health_and_options");
}

/* 2. Test JSON-RPC POST get_status & get_difficulty */
static void test_http_json_rpc_status_and_difficulty(void) {
    uint16_t test_port = 18546;

    duel_state_machine_t sm;
    duel_state_init(&sm);

    dda_tracker_t dda;
    dda_init(&dda, 125000ULL);

    http_rpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = test_port;
    cfg.rpc_ctx.sm = &sm;
    cfg.rpc_ctx.dda = &dda;
    cfg.rpc_ctx.node_version = "v1.1.0-test";

    http_rpc_server_t server;
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) == 0);
    TEST_ASSERT(http_rpc_server_start(&server) == 0);

    /* 1. Send get_status */
    const char body1[] = "{\"jsonrpc\":\"2.0\",\"method\":\"get_status\",\"id\":1}";
    char req1[512];
    snprintf(req1, sizeof(req1),
             "POST / HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             strlen(body1), body1);

    int c_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    TEST_ASSERT(connect(c_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(c_fd, req1, strlen(req1)) == (ssize_t)strlen(req1));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    char resp1[2048];
    ssize_t n = read(c_fd, resp1, sizeof(resp1) - 1);
    TEST_ASSERT(n > 0);
    resp1[n] = '\0';
    close(c_fd);

    TEST_ASSERT(strstr(resp1, "HTTP/1.1 200 OK") != NULL);
    TEST_ASSERT(strstr(resp1, "\"version\":\"v1.1.0-test\"") != NULL);
    TEST_ASSERT(strstr(resp1, "\"k_factor\":2") != NULL);

    /* 2. Send get_difficulty */
    const char body2[] = "{\"jsonrpc\":\"2.0\",\"method\":\"get_difficulty\",\"id\":2}";
    char req2[512];
    snprintf(req2, sizeof(req2),
             "POST / HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             strlen(body2), body2);

    c_fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(connect(c_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(c_fd, req2, strlen(req2)) == (ssize_t)strlen(req2));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    char resp2[2048];
    n = read(c_fd, resp2, sizeof(resp2) - 1);
    TEST_ASSERT(n > 0);
    resp2[n] = '\0';
    close(c_fd);

    TEST_ASSERT(strstr(resp2, "HTTP/1.1 200 OK") != NULL);
    TEST_ASSERT(strstr(resp2, "\"target_vdf_ms\":3000") != NULL);
    TEST_ASSERT(strstr(resp2, "\"current_iterations\":125000") != NULL);
    TEST_ASSERT(strstr(resp2, "\"max_dampening_percent\":5") != NULL);

    http_rpc_server_close(&server);
    TEST_PASS("test_http_json_rpc_status_and_difficulty");
}

/* 3. Test Block Lookup via Block Store */
static void test_http_json_rpc_block_store(void) {
    uint16_t test_port = 18547;
    const char *test_dir = "/tmp/test_http_rpc_store";
    char rm_cmd[128];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", test_dir);
    (void)system(rm_cmd);

    block_store_t store;
    TEST_ASSERT(block_store_open(&store, test_dir) == 0);

    /* Append block 0 */
    uint8_t payload[] = "c99-block-payload-data";
    uint8_t blk_hash[32];
    memset(blk_hash, 0x55, 32);
    TEST_ASSERT(block_store_append_block(&store, 0, blk_hash, payload, sizeof(payload)) == 0);

    http_rpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = test_port;
    cfg.rpc_ctx.store = &store;

    http_rpc_server_t server;
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) == 0);
    TEST_ASSERT(http_rpc_server_start(&server) == 0);

    /* Query get_block height: 0 */
    const char body[] = "{\"jsonrpc\":\"2.0\",\"method\":\"get_block\",\"params\":{\"height\":0},\"id\":42}";
    char req[512];
    snprintf(req, sizeof(req),
             "POST / HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             strlen(body), body);

    int c_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    TEST_ASSERT(connect(c_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(c_fd, req, strlen(req)) == (ssize_t)strlen(req));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    char resp[2048];
    ssize_t n = read(c_fd, resp, sizeof(resp) - 1);
    TEST_ASSERT(n > 0);
    resp[n] = '\0';
    close(c_fd);

    TEST_ASSERT(strstr(resp, "HTTP/1.1 200 OK") != NULL);
    TEST_ASSERT(strstr(resp, "\"height\":0") != NULL);
    TEST_ASSERT(strstr(resp, "\"data_hex\":") != NULL);

    http_rpc_server_close(&server);
    block_store_close(&store);
    (void)system(rm_cmd);
    TEST_PASS("test_http_json_rpc_block_store");
}

/* 4. Test Malformed and Error Handling */
static void test_http_malformed_handling(void) {
    uint16_t test_port = 18548;
    http_rpc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = test_port;

    http_rpc_server_t server;
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) == 0);
    TEST_ASSERT(http_rpc_server_start(&server) == 0);

    /* Method Not Allowed: DELETE */
    const char req1[] = "DELETE / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    int c_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    TEST_ASSERT(connect(c_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(c_fd, req1, strlen(req1)) == (ssize_t)strlen(req1));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    char resp1[1024];
    ssize_t n = read(c_fd, resp1, sizeof(resp1) - 1);
    TEST_ASSERT(n > 0);
    resp1[n] = '\0';
    close(c_fd);
    TEST_ASSERT(strstr(resp1, "HTTP/1.1 405 Method Not Allowed") != NULL);

    /* Unknown RPC method */
    const char body2[] = "{\"jsonrpc\":\"2.0\",\"method\":\"non_existent\",\"id\":99}";
    char req2[512];
    snprintf(req2, sizeof(req2),
             "POST / HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             strlen(body2), body2);

    c_fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(connect(c_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(write(c_fd, req2, strlen(req2)) == (ssize_t)strlen(req2));

    for (int iter = 0; iter < 10; iter++) {
        http_rpc_server_poll(&server, 10);
    }

    char resp2[1024];
    n = read(c_fd, resp2, sizeof(resp2) - 1);
    TEST_ASSERT(n > 0);
    resp2[n] = '\0';
    close(c_fd);
    TEST_ASSERT(strstr(resp2, "HTTP/1.1 200 OK") != NULL);
    TEST_ASSERT(strstr(resp2, "-32601") != NULL); /* Method not found */

    http_rpc_server_close(&server);
    TEST_PASS("test_http_malformed_handling");
}

int main(void) {
    (void)send_http_request;
    printf("=== Starting C99 HTTP/1.1 JSON-RPC Server Test Suite ===\n");
    test_http_health_and_options();
    test_http_json_rpc_status_and_difficulty();
    test_http_json_rpc_block_store();
    test_http_malformed_handling();
    printf("=== All C99 HTTP JSON-RPC Tests Passed Successfully ===\n");
    return 0;
}
