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
#include <errno.h>
#include <fcntl.h>
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

#ifndef DETERM_TEST_FIXTURE_DIR
#define DETERM_TEST_FIXTURE_DIR "tests/fixtures"
#endif

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

/* 1. Test GET /health, no CORS surface, loopback default bind */
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

    /* No cross-origin surface: OPTIONS is not served and no response
     * carries Access-Control-Allow-Origin (a web page must not be able to
     * drive this RPC). */
    TEST_ASSERT(strstr(resp, "Access-Control-Allow-Origin") == NULL);
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

    TEST_ASSERT(strstr(resp, "HTTP/1.1 405 Method Not Allowed") != NULL);
    TEST_ASSERT(strstr(resp, "Access-Control-Allow-Origin") == NULL);

    /* Default bind address is loopback, never the wildcard. */
    {
        struct sockaddr_in bound;
        socklen_t bound_len = sizeof(bound);
        memset(&bound, 0, sizeof(bound));
        TEST_ASSERT(getsockname(server.server_fd, (struct sockaddr *)&bound, &bound_len) == 0);
        TEST_ASSERT(bound.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    }

    http_rpc_server_close(&server);
    TEST_PASS("test_http_health_and_options");
}

/* 1b. An explicit bind address is honored; a malformed one is refused. */
static void test_http_bind_address(void) {
    http_rpc_config_t cfg;
    http_rpc_server_t server;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = 0;
    cfg.bind_ip = "not-an-ip";
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) != 0);
    {
        /* Closing after a failed init must not close descriptor 0. */
        int null_fd = open("/dev/null", O_RDONLY);
        TEST_ASSERT(null_fd >= 0);
        TEST_ASSERT(dup2(null_fd, 0) == 0);
        if (null_fd != 0) close(null_fd);
        http_rpc_server_close(&server);
        TEST_ASSERT(fcntl(0, F_GETFD) != -1);
    }
    cfg.bind_ip = "127.0.0.1";
    TEST_ASSERT(http_rpc_server_init(&server, &cfg) == 0);
    TEST_ASSERT(server.bind_addr_be == htonl(INADDR_LOOPBACK));
    TEST_PASS("test_http_bind_address");
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
    TEST_ASSERT(snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", test_dir) < (int)sizeof(rm_cmd));
    TEST_ASSERT(system(rm_cmd) == 0);

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
    TEST_ASSERT(system(rm_cmd) == 0);
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

/* Framing is tested at the receiver with an independently signed, otherwise
 * admissible pending transfer. A 400 alone must not hide an inbox side effect. */
static pending_shard_t framing_buckets[PENDING_TRANSFER_MAX_SHARDS];
static pending_transfer_pool_t framing_pool;

static void reset_framing_pool(void) {
    uint8_t zero[32] = {0};
    shard_routing_config_t routing;
    TEST_ASSERT(shard_routing_init(&routing, 1, zero) == 0);
    TEST_ASSERT(pending_transfer_init(&framing_pool, framing_buckets,
                PENDING_TRANSFER_MAX_SHARDS, &routing, zero) == 0);
}

static size_t exchange_framing(http_rpc_server_t *server, uint16_t port,
                               const char *request, size_t length, size_t split,
                               char *response, size_t capacity) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    TEST_ASSERT(fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    int flags = fcntl(fd, F_GETFL, 0);
    TEST_ASSERT(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    if (split) {
        pending_shard_t before[PENDING_TRANSFER_MAX_SHARDS];
        memcpy(before, framing_buckets, sizeof(before));
        TEST_ASSERT(split < length && write(fd, request, split) == (ssize_t)split);
        for (int i = 0; i < 10; ++i) TEST_ASSERT(http_rpc_server_poll(server, 1) >= 0);
        char byte;
        TEST_ASSERT(read(fd, &byte, 1) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
        TEST_ASSERT(memcmp(before, framing_buckets, sizeof(before)) == 0);
    }
    TEST_ASSERT(write(fd, request + split, length - split) == (ssize_t)(length - split));
    size_t total = 0;
    /* This bounded observation also tests immediate rejection of an oversized
     * declaration with no body sent. It must not wait for that impossible body. */
    for (int i = 0; i < 100 && total + 1 < capacity; ++i) {
        TEST_ASSERT(http_rpc_server_poll(server, 1) >= 0);
        ssize_t n = read(fd, response + total, capacity - total - 1);
        if (n > 0) total += (size_t)n;
        else if (n == 0 || (n < 0 && errno == ECONNRESET && total > 0)) break;
        else TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    response[total] = '\0';
    close(fd);
    return total;
}

static void framing_rejected(http_rpc_server_t *server, uint16_t port,
                              const char *request, size_t length, const char *status) {
    pending_shard_t before[PENDING_TRANSFER_MAX_SHARDS];
    pending_transfer_pool_t old_pool;
    char response[2048];
    reset_framing_pool();
    memcpy(before, framing_buckets, sizeof(before));
    memcpy(&old_pool, &framing_pool, sizeof(old_pool));
    TEST_ASSERT(exchange_framing(server, port, request, length, 0, response, sizeof(response)) > 0);
    if (!strstr(response, status)) fprintf(stderr, "framing response: %s\n", response);
    TEST_ASSERT(strstr(response, status) != NULL);
    TEST_ASSERT(memcmp(before, framing_buckets, sizeof(before)) == 0);
    TEST_ASSERT(memcmp(&old_pool, &framing_pool, sizeof(old_pool)) == 0);
}

static void test_http_bounded_post_framing(void) {
    const uint16_t port = 18549;
    http_rpc_config_t config;
    http_rpc_server_t server;
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE];
    char hex[PENDING_TRANSFER_FRAME_SIZE * 2 + 1], body[1024];
    char request[HTTP_RPC_BUF_SIZE + 1], response[2048], headers[256];
    memset(&config, 0, sizeof(config));
    reset_framing_pool();
    config.port = port;
    config.rpc_ctx.pending = &framing_pool;
    TEST_ASSERT(http_rpc_server_init(&server, &config) == 0);
    TEST_ASSERT(http_rpc_server_start(&server) == 0);
    FILE *file = fopen(DETERM_TEST_FIXTURE_DIR "/pending_transfer_default.bin", "rb");
    TEST_ASSERT(file != NULL);
    TEST_ASSERT(fread(frame, 1, sizeof(frame), file) == sizeof(frame) && fgetc(file) == EOF);
    TEST_ASSERT(fclose(file) == 0);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(frame); ++i) {
        hex[2 * i] = digits[frame[i] >> 4]; hex[2 * i + 1] = digits[frame[i] & 15];
    }
    hex[sizeof(hex) - 1] = '\0';
    int n = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":{\"frame\":\"%s\"},\"id\":7} ", hex);
    TEST_ASSERT(n > 0 && (size_t)n < sizeof(body));
    size_t body_len = (size_t)n;
    n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\nHost: localhost\r\ncOnTeNt-LeNgTh:\t%zu \t\r\n\r\n%s", body_len, body);
    TEST_ASSERT(n > 0 && (size_t)n < sizeof(request));
    /* Hold back the final declared whitespace byte after a complete JSON object.
     * There must be no early response/dispatch, even though the object is valid. */
    TEST_ASSERT(exchange_framing(&server, port, request, (size_t)n, (size_t)n - 1,
                               response, sizeof(response)) > 0);
    TEST_ASSERT(strstr(response, "HTTP/1.1 200 OK") && strstr(response, "\"status\":\"inserted\""));
    pending_transfer_snapshot_t snapshot;
    TEST_ASSERT(pending_transfer_list(&framing_pool, 0, &snapshot) == 0 && snapshot.count == 1);
    TEST_ASSERT(memcmp(snapshot.frames[0], frame, sizeof(frame)) == 0);

    /* Run this causal digit fixture before ordinary junk errors: a missing
     * digit guard must first admit the valid body, not merely change a 400 to
     * 413 on a later overflowing value. ':' is decimal digit 10 if unchecked. */
    while (body_len % 10) body[body_len++] = ' ';
    body[body_len] = '\0';
    n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\nContent-Length: %zu:\r\n\r\n%s", body_len / 10 - 1, body);
    TEST_ASSERT(n > 0 && (size_t)n < sizeof(request));
    framing_rejected(&server, port, request, (size_t)n, "HTTP/1.1 400 Bad Request");

    const char *bad_headers[] = {
        "X-Content-Length: %zu\r\n",
        "X-Note: Content-Length: %zu\r\n",
        "Content-Length: 0\r\nContent-Length: %zu\r\n",
        "Content-Length: %zu\r\nContent-Length: 1\r\n",
        "Content-Length: %zujunk\r\n",
        "Content-Length: -%zu\r\n",
        "Content-Length: +%zu\r\n",
        "Content-Length: \t\r\n",
        "Content-Length: 0\r\n",
        "Content-Length: %zu\r\nTrAnSfEr-EnCoDiNg: chunked\r\n"
    };
    for (size_t i = 0; i < sizeof(bad_headers) / sizeof(bad_headers[0]); ++i) {
        n = snprintf(headers, sizeof(headers), bad_headers[i], body_len);
        TEST_ASSERT(n > 0 && (size_t)n < sizeof(headers));
        n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\n%s\r\n%s", headers, body);
        TEST_ASSERT(n > 0 && (size_t)n < sizeof(request));
        framing_rejected(&server, port, request, (size_t)n, "HTTP/1.1 400 Bad Request");
    }
    n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999999999999999999\r\n\r\n%s", body);
    TEST_ASSERT(n > 0 && (size_t)n < sizeof(request));
    framing_rejected(&server, port, request, (size_t)n, "HTTP/1.1 413 Payload Too Large");

    /* A Content-Length-looking token in a valid JSON ID is body data, never a
     * header. Three-digit length keeps the ID/body size stable on both passes. */
    n = snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":{\"frame\":\"%s\"},\"id\":\"Content-Length: 000\"}", hex);
    TEST_ASSERT(n > 0 && n < 1000);
    body_len = (size_t)n;
    n = snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":{\"frame\":\"%s\"},\"id\":\"Content-Length: %03zu\"}", hex, body_len);
    TEST_ASSERT(n > 0 && (size_t)n == body_len);
    n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n%s", body);
    TEST_ASSERT(n > 0 && (size_t)n < sizeof(request));
    framing_rejected(&server, port, request, (size_t)n, "HTTP/1.1 400 Bad Request");

    /* Pad an ignored header, keeping the signed JSON below its own RPC bound.
     * The exact receive limit must dispatch; one extra declared byte must be
     * refused using the header alone, before waiting for any body bytes. */
    size_t usable = HTTP_RPC_BUF_SIZE - 1;
    n = snprintf(request, sizeof(request), "POST / HTTP/1.1\r\nContent-Length: %zu\r\nX-Pad: ", body_len);
    TEST_ASSERT(n > 0 && (size_t)n + 4 + body_len < usable);
    size_t prefix = (size_t)n;
    size_t padding = usable - prefix - 4 - body_len;
    memset(request + prefix, 'a', padding);
    memcpy(request + prefix + padding, "\r\n\r\n", 4);
    memcpy(request + prefix + padding + 4, body, body_len);
    reset_framing_pool();
    TEST_ASSERT(exchange_framing(&server, port, request, usable, 0, response, sizeof(response)) > 0);
    TEST_ASSERT(strstr(response, "HTTP/1.1 200 OK") && strstr(response, "\"status\":\"inserted\""));
    TEST_ASSERT(pending_transfer_list(&framing_pool, 0, &snapshot) == 0 && snapshot.count == 1);
    TEST_ASSERT(memcmp(snapshot.frames[0], frame, sizeof(frame)) == 0);
    memset(request + prefix, 'a', padding + 1);
    memcpy(request + prefix + padding + 1, "\r\n\r\n", 4);
    framing_rejected(&server, port, request, prefix + padding + 5, "HTTP/1.1 413 Payload Too Large");
    http_rpc_server_close(&server);
    TEST_PASS("test_http_bounded_post_framing");
}

int main(void) {
    (void)send_http_request;
    printf("=== Starting C99 HTTP/1.1 JSON-RPC Server Test Suite ===\n");
    test_http_health_and_options();
    test_http_bind_address();
    test_http_json_rpc_status_and_difficulty();
    test_http_json_rpc_block_store();
    test_http_malformed_handling();
    test_http_bounded_post_framing();
    printf("=== All C99 HTTP JSON-RPC Tests Passed Successfully ===\n");
    return 0;
}
