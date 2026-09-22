/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/rpc/json_rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "routing RPC check failed at line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define ZERO "0000000000000000000000000000000000000000000000000000000000000000"
#define FF "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define UPPER "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
#define METHOD "\"method\":\"get_shard_for_pubkey\""
#define VERSION "\"jsonrpc\":\"2.0\""
#define PARAMS "\"params\":{\"pubkey\":\"" ZERO "\"}"
#define VALID "{" VERSION "," METHOD "," PARAMS ",\"id\":7}"

static char response[1024];

static void dispatch(const char *request, const rpc_context_t *ctx) {
    int n = rpc_dispatch_context(request, strlen(request), ctx, response, sizeof(response));
    CHECK(n > 0 && (size_t)n == strlen(response));
}

static void fails(const char *request, const rpc_context_t *ctx) {
    dispatch(request, ctx);
    CHECK(strstr(response, "\"error\"") != NULL);
    CHECK(strstr(response, "\"result\"") == NULL);
}

int main(void) {
    uint8_t salt[32] = {0};
    shard_routing_config_t config, before, other;
    rpc_context_t ctx, ctx_before, other_ctx;
    duel_state_machine_t sm, sm_before;
    memset(&ctx, 0, sizeof(ctx));
    memset(&sm, 0, sizeof(sm));
    ctx.sm = &sm;
    CHECK(shard_routing_init(&config, 7, salt) == 0);
    ctx.routing = &config;
    memcpy(&before, &config, sizeof(config));
    memcpy(&ctx_before, &ctx, sizeof(ctx));
    memcpy(&sm_before, &sm, sizeof(sm));
    dispatch(VALID, &ctx);
    /* Oracle values are pinned independently in test_shard_routing.c. Exact
     * consumer response asserts domain, canonical address, count, salt and ID. */
    CHECK(strcmp(response, "{\"jsonrpc\":\"2.0\",\"result\":{\"scope\":\"routing-query\","
        "\"config_source\":\"local\",\"consensus_enforced\":false,"
        "\"address\":\"0x" ZERO "\",\"shard_id\":6,\"shard_count\":7,"
        "\"routing_salt\":\"" ZERO "\"},\"id\":7}\n") == 0);
    CHECK(memcmp(&before, &config, sizeof(config)) == 0);
    CHECK(memcmp(&ctx_before, &ctx, sizeof(ctx)) == 0);
    CHECK(memcmp(&sm_before, &sm, sizeof(sm)) == 0);

    CHECK(shard_routing_init(&other, 3, salt) == 0);
    other_ctx = ctx;
    other_ctx.routing = &other;
    dispatch(VALID, &other_ctx);
    CHECK(strstr(response, "\"shard_id\":2,\"shard_count\":3") != NULL);
    dispatch(VALID, &ctx);
    CHECK(strstr(response, "\"shard_id\":6,\"shard_count\":7") != NULL);
    CHECK(shard_routing_init(&other, 1, salt) == 0);
    dispatch(VALID, &other_ctx);
    CHECK(strstr(response, "\"shard_id\":0,\"shard_count\":1") != NULL);
    memset(salt, 255, sizeof(salt));
    CHECK(shard_routing_init(&other, UINT32_MAX, salt) == 0);
    dispatch("{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"" UPPER "\"},\"id\":\"q-1\"}", &other_ctx);
    CHECK(strcmp(response, "{\"jsonrpc\":\"2.0\",\"result\":{\"scope\":\"routing-query\","
        "\"config_source\":\"local\",\"consensus_enforced\":false,"
        "\"address\":\"0x" FF "\",\"shard_id\":1711102701,\"shard_count\":4294967295,"
        "\"routing_salt\":\"" FF "\"},\"id\":\"q-1\"}\n") == 0);
    dispatch("{\"id\":-12, " PARAMS ", " METHOD ", " VERSION "}", &ctx);
    CHECK(strstr(response, "\"id\":-12}") != NULL);
    dispatch("{" VERSION "," METHOD "," PARAMS "}", &ctx);
    CHECK(strstr(response, "\"id\":null}") != NULL);
    const char *method_id_orders[] = {
        "{\"id\":\"method\"," VERSION "," METHOD "," PARAMS "}",
        "{" VERSION ",\"id\":\"method\"," METHOD "," PARAMS "}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":\"method\"}"
    };
    for (size_t i = 0; i < sizeof(method_id_orders) / sizeof(method_id_orders[0]); ++i) {
        dispatch(method_id_orders[i], &ctx);
        CHECK(strstr(response, "\"shard_id\":6,\"shard_count\":7") != NULL);
        CHECK(strstr(response, "\"id\":\"method\"}") != NULL);
    }

    const char *bad[] = {
        "{" VERSION "," METHOD "}",
        "{" VERSION "," METHOD ",\"params\":{}}",
        "{" VERSION "," METHOD ",\"params\":[]}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":12}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"0x" ZERO "\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"" ZERO "0\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"short\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"g000000000000000000000000000000000000000000000000000000000000000\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"" ZERO "\",\"pubkey\":\"" FF "\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"" ZERO "\",\"shard_count\":1}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\" \"" ZERO "\"}}",
        "{" VERSION "," METHOD ",\"params\":{\"pubkey\":\"" ZERO "\",}}",
        "{" VERSION "," METHOD "," PARAMS "," PARAMS "}",
        "{" VERSION "," METHOD "," METHOD "," PARAMS "}",
        "{" VERSION "," VERSION "," METHOD "," PARAMS "}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":1,\"id\":2}",
        "{" VERSION "," METHOD "," PARAMS ",\"extra\":1}",
        "{" VERSION " " METHOD "," PARAMS "}",
        "{" VERSION "," METHOD "," PARAMS ",}",
        VALID "{}",
        "{" METHOD "," PARAMS "}",
        "{\"jsonrpc\":\"1.0\"," METHOD "," PARAMS "}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":01}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":1.2}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":true}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":{}}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":123456789012345678901}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":\"12345678901234567890123456789012345\"}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":\"x\\n\"}",
        "{" VERSION "," METHOD "," PARAMS ",\"id\":\"x\ny\"}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) fails(bad[i], &ctx);
    fails("{" VERSION "," METHOD ",\"params\":{},\"id\":7}", &ctx);
    CHECK(strstr(response, "-32602") != NULL && strstr(response, "\"id\":7}") != NULL);
    fails("{\"id\":\"bad-params\"," VERSION "," METHOD ",\"params\":[1.5e+2,true,null]}", &ctx);
    CHECK(strstr(response, "-32602") != NULL && strstr(response, "\"id\":\"bad-params\"}") != NULL);
    fails("{" VERSION "," METHOD ",\"params\":{},\"id\":7,\"id\":8}", &ctx);
    CHECK(strstr(response, "-32600") != NULL && strstr(response, "\"id\":null}") != NULL);
    char raw[sizeof(VALID)];
    memcpy(raw, VALID, sizeof(raw));
    char *key_start = strstr(raw, ZERO);
    CHECK(key_start != NULL);
    *key_start = '\0';
    CHECK(rpc_dispatch_context(raw, sizeof(raw) - 1, &ctx, response, sizeof(response)) > 0);
    CHECK(strstr(response, "\"result\"") == NULL);

    char bounded[RPC_ROUTING_MAX_REQUEST_LEN + 2];
    size_t padding = RPC_ROUTING_MAX_REQUEST_LEN - strlen(VALID);
    memset(bounded, ' ', sizeof(bounded));
    memcpy(bounded + padding, VALID, strlen(VALID));
    bounded[RPC_ROUTING_MAX_REQUEST_LEN] = '\0';
    dispatch(bounded, &ctx);
    CHECK(strstr(response, "\"result\"") != NULL);
    bounded[RPC_ROUTING_MAX_REQUEST_LEN] = ' ';
    bounded[RPC_ROUTING_MAX_REQUEST_LEN + 1] = '\0';
    fails(bounded, &ctx);

    fails(VALID, NULL);
    CHECK(strstr(response, "-32001") != NULL);
    other_ctx.routing = NULL;
    fails(VALID, &other_ctx);
    other.shard_count = 0;
    other_ctx.routing = &other;
    fails(VALID, &other_ctx);
    CHECK(rpc_dispatch(VALID, strlen(VALID), NULL, response, sizeof(response)) > 0);
    CHECK(strstr(response, "-32001") != NULL);

    dispatch(VALID, &ctx);
    size_t len = strlen(response);
    char short_response[1024];
    memset(short_response, 0x55, sizeof(short_response));
    CHECK(rpc_dispatch_context(VALID, strlen(VALID), &ctx, short_response, len + 1) == (int)len);
    CHECK(strcmp(short_response, response) == 0);
    CHECK(rpc_dispatch_context(VALID, strlen(VALID), &ctx, short_response, len) == -1);
    CHECK((unsigned char)short_response[len + 1] == 0x55);
    CHECK(rpc_dispatch_context(VALID, strlen(VALID), &ctx, short_response, 1) == -1);
    CHECK(short_response[0] == '\0');
    /* Shared early parse errors reached by unfinished routing requests must
     * also return failure rather than a would-have-written byte count. */
    const char unfinished[] = "{" VERSION "," METHOD ",\"params\":";
    CHECK(rpc_dispatch_context(unfinished, strlen(unfinished), &ctx, short_response, 1) == -1);
    CHECK(short_response[0] == '\0');
    CHECK(memcmp(&before, &config, sizeof(config)) == 0);
    CHECK(memcmp(&sm_before, &sm, sizeof(sm)) == 0);
    puts("PASS: routing RPC consumer, bounded grammar, configuration isolation");
    return 0;
}
