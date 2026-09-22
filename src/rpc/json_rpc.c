/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Zero-Allocation, In-Place C99 JSON-RPC Handler.
 * Strictly zero heap allocations (no malloc/free).
 */

#include <determ/rpc/json_rpc.h>
#include <determ/wire/parser.h>
#include <determ/wire/binary_codec.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bytes_to_hex(const uint8_t *src, size_t len, char *dst, size_t max_dst) {
    static const char hex_digits[] = "0123456789abcdef";
    if (max_dst < len * 2 + 1) return;
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hex_digits[(src[i] >> 4) & 0x0F];
        dst[i * 2 + 1] = hex_digits[src[i] & 0x0F];
    }
    dst[len * 2] = '\0';
}

static size_t count_active_peers(const peer_mesh_t *mesh) {
    if (!mesh) return 0;
    size_t count = 0;
    for (size_t i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        if (mesh->peers[i].state != PEER_STATE_FREE) {
            count++;
        }
    }
    return count;
}

int rpc_dispatch_context(const char *request_json, size_t req_len,
                         const rpc_context_t *ctx,
                         char *out_resp, size_t max_resp) {
    if (!request_json || req_len == 0 || !out_resp || max_resp == 0) {
        return -1;
    }

    determ_json_tok_t tokens[RPC_MAX_TOKENS];
    int num_tokens = determ_json_parse(request_json, req_len, tokens, RPC_MAX_TOKENS);
    if (num_tokens <= 0 || tokens[0].type != JSON_TOK_OBJECT) {
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n");
    }

    const determ_json_tok_t *method_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "method");
    const determ_json_tok_t *id_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "id");

    char id_str[32] = "null";
    if (id_tok) {
        (void)determ_json_token_to_string(request_json, id_tok, id_str, sizeof(id_str));
    }

    if (!method_tok || method_tok->type != JSON_TOK_STRING) {
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"},\"id\":%s}\n",
                        id_str);
    }

    char method[RPC_MAX_METHOD_LEN];
    if (determ_json_token_to_string(request_json, method_tok, method, sizeof(method)) != 0) {
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Method name too long\"},\"id\":%s}\n",
                        id_str);
    }

    const duel_state_machine_t *sm = ctx ? ctx->sm : NULL;
    const block_store_t *store = ctx ? ctx->store : NULL;
    const peer_mesh_t *mesh = ctx ? ctx->mesh : NULL;
    const dda_tracker_t *dda = ctx ? ctx->dda : NULL;
    const char *ver = (ctx && ctx->node_version) ? ctx->node_version : "v1.1.0-c99";

    /* 1. get_status */
    if (strcmp(method, "get_status") == 0) {
        const char *state_str = "IDLE";
        if (sm) {
            switch (sm->state) {
                case DUEL_STATE_IDLE:             state_str = "IDLE"; break;
                case DUEL_STATE_COMMITMENT_PHASE: state_str = "COMMITMENT_PHASE"; break;
                case DUEL_STATE_AWAITING_REVEALS: state_str = "AWAITING_REVEALS"; break;
                case DUEL_STATE_VDF_EVALUATION:   state_str = "VDF_EVALUATION"; break;
                case DUEL_STATE_ABORTED:          state_str = "ABORTED"; break;
                case DUEL_STATE_COMPLETED:        state_str = "COMPUTATION_COMPLETED"; break;
                default:                          state_str = "UNKNOWN"; break;
            }
        }
        bool fallback = false; /* Strict 2-of-2 local attempt; no fallback. */

        uint64_t height = 0;
        char head_hex[65] = "0000000000000000000000000000000000000000000000000000000000000000";
        if (store) {
            uint8_t head_hash[32];
            if (block_store_get_head(store, &height, head_hash) == 0) {
                bytes_to_hex(head_hash, 32, head_hex, sizeof(head_hex));
            }
        }

        size_t peers = count_active_peers(mesh);

        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{"
                        "\"version\":\"%s\","
                        "\"state\":\"%s\","
                        "\"height\":%llu,"
                        "\"head_hash\":\"%s\","
                        "\"peers\":%zu,"
                        "\"straggler_fallback\":%s,"
                        "\"k_factor\":2"
                        "},\"id\":%s}\n",
                        ver, state_str, (unsigned long long)height, head_hex,
                        peers, fallback ? "true" : "false", id_str);
    }

    /* 2. get_height */
    if (strcmp(method, "get_height") == 0) {
        uint64_t height = 0;
        char head_hex[65] = "0000000000000000000000000000000000000000000000000000000000000000";
        if (store) {
            uint8_t head_hash[32];
            if (block_store_get_head(store, &height, head_hash) == 0) {
                bytes_to_hex(head_hash, 32, head_hex, sizeof(head_hex));
            }
        }
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"height\":%llu,\"head_hash\":\"%s\"},\"id\":%s}\n",
                        (unsigned long long)height, head_hex, id_str);
    }

    /* 3. get_block */
    if (strcmp(method, "get_block") == 0) {
        const determ_json_tok_t *params_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "params");
        uint64_t target_height = 0;
        if (params_tok && params_tok->type == JSON_TOK_OBJECT) {
            const determ_json_tok_t *h_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, params_tok, "height");
            if (h_tok && h_tok->type == JSON_TOK_PRIMITIVE) {
                target_height = (uint64_t)strtoull(request_json + h_tok->start, NULL, 10);
            }
        }

        if (!store) {
            return snprintf(out_resp, max_resp,
                            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Block store unavailable\"},\"id\":%s}\n",
                            id_str);
        }

        uint8_t blk_buf[1024];
        size_t blk_size = 0;
        if (block_store_read_block(store, target_height, blk_buf, sizeof(blk_buf), &blk_size) != 0) {
            return snprintf(out_resp, max_resp,
                            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32004,\"message\":\"Block not found\"},\"id\":%s}\n",
                            id_str);
        }

        char hex_buf[2049];
        bytes_to_hex(blk_buf, blk_size > 1024 ? 1024 : blk_size, hex_buf, sizeof(hex_buf));

        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{"
                        "\"height\":%llu,"
                        "\"size\":%zu,"
                        "\"data_hex\":\"%s\""
                        "},\"id\":%s}\n",
                        (unsigned long long)target_height, blk_size, hex_buf, id_str);
    }

    /* 4. get_vdf_stats / get_difficulty */
    if (strcmp(method, "get_vdf_stats") == 0 || strcmp(method, "get_difficulty") == 0) {
        uint64_t iters = 100000ULL;
        uint32_t avg_time_ms = TARGET_VDF_MS;
        if (dda) {
            iters = dda->current_iterations;
            avg_time_ms = calculate_average_vdf_time(dda);
        }
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{"
                        "\"algorithm\":\"AES256-Round-Chained\","
                        "\"scope\":\"dda-helper-only\","
                        "\"consensus_enforced\":false,"
                        "\"arena_kb\":64,"
                        "\"target_vdf_ms\":%u,"
                        "\"current_iterations\":%llu,"
                        "\"sliding_average_ms\":%u,"
                        "\"max_dampening_percent\":%u"
                        "},\"id\":%s}\n",
                        TARGET_VDF_MS, (unsigned long long)iters, avg_time_ms,
                        DDA_MAX_ADJUST_PERCENT, id_str);
    }

    /* 5. get_peer_info */
    if (strcmp(method, "get_peer_info") == 0) {
        size_t peers = count_active_peers(mesh);
        const char *domain = mesh ? mesh->config.domain : "none";
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{"
                        "\"domain\":\"%s\","
                        "\"peer_count\":%zu"
                        "},\"id\":%s}\n",
                        domain, peers, id_str);
    }

    /* 6. get_duel_state */
    if (strcmp(method, "get_duel_state") == 0) {
        uint64_t elapsed_ms = 0;
        if (sm && sm->state != DUEL_STATE_IDLE) {
            elapsed_ms = (duel_clock_monotonic_ns() - sm->epoch_start_time) / 1000000ULL;
        }
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{"
                        "\"attempt_deadline_ms\":2000,"
                        "\"deadline_origin\":\"attempt_start\","
                        "\"consensus_enforced\":false,"
                        "\"elapsed_ms\":%llu,"
                        "\"aggregator_ready\":%s,"
                        "\"contributor_ready\":%s"
                        "},\"id\":%s}\n",
                        (unsigned long long)elapsed_ms,
                        (sm && sm->aggregator_reveal.present) ? "true" : "false",
                        (sm && sm->contributor_reveal.present) ? "true" : "false",
                        id_str);
    }

    /* Method not found */
    return snprintf(out_resp, max_resp,
                    "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n",
                    id_str);
}

int rpc_dispatch(const char *request_json, size_t req_len,
                 const duel_state_machine_t *sm,
                 char *out_resp, size_t max_resp) {
    rpc_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.sm = sm;
    return rpc_dispatch_context(request_json, req_len, &ctx, out_resp, max_resp);
}
