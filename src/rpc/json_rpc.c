/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Zero-Allocation, In-Place C99 JSON-RPC Handler.
 * Strictly zero heap allocations (no malloc/free).
 */

#include <determ/rpc/json_rpc.h>
#include <determ/wire/parser.h>

#include <stdio.h>
#include <string.h>

int rpc_dispatch(const char *request_json, size_t req_len,
                 const duel_state_machine_t *sm,
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

    /* Dispatch endpoints */
    if (strcmp(method, "get_status") == 0) {
        const char *state_str = "IDLE";
        if (sm) {
            switch (sm->state) {
                case DUEL_STATE_IDLE:                  state_str = "IDLE"; break;
                case DUEL_STATE_COMMITMENT_PHASE: state_str = "COMMITMENT_PHASE"; break;
                case DUEL_STATE_AWAITING_REVEALS:      state_str = "AWAITING_REVEALS"; break;
                case DUEL_STATE_VDF_EVALUATION:        state_str = "VDF_EVALUATION"; break;
                case DUEL_STATE_FINALIZED:        state_str = "BLOCK_PRODUCED"; break;
                default:                               state_str = "UNKNOWN"; break;
            }
        }
        bool fallback = sm ? sm->straggler_fallback_active : false;
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"state\":\"%s\",\"straggler_fallback\":%s,\"k_factor\":2},\"id\":%s}\n",
                        state_str, fallback ? "true" : "false", id_str);
    }

    if (strcmp(method, "get_duel_state") == 0) {
        uint64_t elapsed_ms = 0;
        if (sm && sm->reveal_start_ns > 0) {
            uint64_t now = duel_clock_monotonic_ns();
            if (now >= sm->reveal_start_ns) {
                elapsed_ms = (now - sm->reveal_start_ns) / 1000000ULL;
            }
        }
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"reveal_window_ms\":2000,\"elapsed_ms\":%llu,\"aggregator_ready\":%s,\"contributor_ready\":%s},\"id\":%s}\n",
                        (unsigned long long)elapsed_ms,
                        (sm && sm->aggregator_reveal.present) ? "true" : "false",
                        (sm && sm->contributor_reveal.present) ? "true" : "false",
                        id_str);
    }

    if (strcmp(method, "get_vdf_stats") == 0) {
        return snprintf(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"algorithm\":\"AES256-Round-Chained\",\"arena_kb\":64,\"target_block_time_s\":5.0},\"id\":%s}\n",
                        id_str);
    }

    /* Method not found */
    return snprintf(out_resp, max_resp,
                    "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n",
                    id_str);
}
