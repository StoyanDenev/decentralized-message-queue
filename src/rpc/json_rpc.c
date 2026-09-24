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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int rpc_error_response(char *out, size_t cap, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int written = vsnprintf(out, cap, format, args);
    va_end(args);
    return written < 0 || (size_t)written >= cap ? -1 : written;
}

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

/* This endpoint has a small, closed request grammar. The legacy tokenizer does
 * not validate JSON separators or unique keys, so it cannot authorize a routing
 * result. Parse the entire bounded request here before consulting configuration.
 */
typedef struct { const char *text; size_t len, pos; } routing_reader_t;

static void routing_space(routing_reader_t *r) {
    while (r->pos < r->len && (r->text[r->pos] == ' ' || r->text[r->pos] == '\t' ||
           r->text[r->pos] == '\r' || r->text[r->pos] == '\n')) ++r->pos;
}

static int routing_take(routing_reader_t *r, char c) {
    routing_space(r);
    if (r->pos == r->len || r->text[r->pos] != c) return -1;
    ++r->pos;
    return 0;
}

static int routing_string(routing_reader_t *r, char *out, size_t cap) {
    size_t n = 0;
    if (routing_take(r, '"') != 0) return -1;
    while (r->pos < r->len && r->text[r->pos] != '"') {
        unsigned char c = (unsigned char)r->text[r->pos++];
        if (c < 0x20 || c > 0x7e || c == '\\' || n + 1 >= cap) return -1;
        out[n++] = (char)c;
    }
    if (r->pos == r->len) return -1;
    ++r->pos;
    out[n] = '\0';
    return 0;
}

static int routing_hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Validate/skip a JSON value so an invalid params value can be reported using
 * the ID from the complete, otherwise-valid envelope. No allocation or unbounded
 * recursion. Accepted params remain the much narrower routing_params grammar.
 */
static int routing_skip_string(routing_reader_t *r) {
    if (routing_take(r, '"') != 0) return -1;
    while (r->pos < r->len) {
        unsigned char c = (unsigned char)r->text[r->pos++];
        if (c == '"') return 0;
        if (c < 0x20) return -1;
        if (c == '\\') {
            if (r->pos == r->len) return -1;
            c = (unsigned char)r->text[r->pos++];
            if (c == 'u') {
                for (unsigned i = 0; i < 4; ++i)
                    if (r->pos == r->len || routing_hex_value(r->text[r->pos++]) < 0) return -1;
            } else if (c == 0 || !strchr("\"\\/bfnrt", c)) return -1;
        }
    }
    return -1;
}

static int routing_skip_value(routing_reader_t *r, unsigned depth) {
    routing_space(r);
    if (r->pos == r->len || depth > 16) return -1;
    char c = r->text[r->pos];
    if (c == '"') return routing_skip_string(r);
    if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        ++r->pos;
        routing_space(r);
        if (r->pos < r->len && r->text[r->pos] == close) { ++r->pos; return 0; }
        for (;;) {
            if (c == '{' && (routing_skip_string(r) != 0 || routing_take(r, ':') != 0)) return -1;
            if (routing_skip_value(r, depth + 1) != 0) return -1;
            routing_space(r);
            if (r->pos < r->len && r->text[r->pos] == close) { ++r->pos; return 0; }
            if (routing_take(r, ',') != 0) return -1;
        }
    }
    const char *literal = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : NULL;
    if (literal) {
        size_t n = strlen(literal);
        if (r->len - r->pos < n || memcmp(r->text + r->pos, literal, n) != 0) return -1;
        r->pos += n;
        return 0;
    }
    if (r->text[r->pos] == '-') ++r->pos;
    if (r->pos == r->len) return -1;
    if (r->text[r->pos] == '0') ++r->pos;
    else {
        if (r->text[r->pos] < '1' || r->text[r->pos] > '9') return -1;
        do { ++r->pos; } while (r->pos < r->len && r->text[r->pos] >= '0' && r->text[r->pos] <= '9');
    }
    if (r->pos < r->len && r->text[r->pos] == '.') {
        ++r->pos;
        size_t start = r->pos;
        while (r->pos < r->len && r->text[r->pos] >= '0' && r->text[r->pos] <= '9') ++r->pos;
        if (r->pos == start) return -1;
    }
    if (r->pos < r->len && (r->text[r->pos] == 'e' || r->text[r->pos] == 'E')) {
        ++r->pos;
        if (r->pos < r->len && (r->text[r->pos] == '+' || r->text[r->pos] == '-')) ++r->pos;
        size_t start = r->pos;
        while (r->pos < r->len && r->text[r->pos] >= '0' && r->text[r->pos] <= '9') ++r->pos;
        if (r->pos == start) return -1;
    }
    return 0;
}

static int routing_params(routing_reader_t *r, uint8_t key[32]) {
    char name[7], value[65];
    if (routing_take(r, '{') != 0 || routing_string(r, name, sizeof(name)) != 0 ||
        strcmp(name, "pubkey") != 0 || routing_take(r, ':') != 0 ||
        routing_string(r, value, sizeof(value)) != 0 || strlen(value) != 64 ||
        routing_take(r, '}') != 0) return -1;
    for (size_t i = 0; i < 32; ++i) {
        int hi = routing_hex_value(value[2 * i]), lo = routing_hex_value(value[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int routing_id(routing_reader_t *r, char id[35]) {
    size_t start, len;
    routing_space(r);
    start = r->pos;
    if (start == r->len) return -1;
    if (r->text[start] == '"') {
        char value[33];
        if (routing_string(r, value, sizeof(value)) != 0) return -1;
    } else if (r->len - start >= 4 && memcmp(r->text + start, "null", 4) == 0) {
        r->pos += 4;
    } else {
        if (r->text[r->pos] == '-') ++r->pos;
        if (r->pos == r->len) return -1;
        if (r->text[r->pos] == '0') ++r->pos;
        else {
            if (r->text[r->pos] < '1' || r->text[r->pos] > '9') return -1;
            do { ++r->pos; } while (r->pos < r->len && r->text[r->pos] >= '0' && r->text[r->pos] <= '9');
        }
        if (r->pos - start > 20) return -1;
    }
    len = r->pos - start;
    memcpy(id, r->text + start, len);
    id[len] = '\0';
    return 0;
}

/* Closed envelopes shared by the routing query and opt-in pending inbox. The
 * method-specific parser still owns its request bound and exact params grammar. */
static int closed_request(const char *json, size_t len, const char *method,
                          routing_reader_t *params, char id[35]) {
    routing_reader_t r = { json, len, 0 };
    unsigned seen = 0;
    if (routing_take(&r, '{') != 0) return -32600;
    for (;;) {
        char name[8], value[RPC_MAX_METHOD_LEN];
        unsigned bit;
        if (routing_string(&r, name, sizeof(name)) != 0 || routing_take(&r, ':') != 0) return -32600;
        if (strcmp(name, "jsonrpc") == 0) bit = 1;
        else if (strcmp(name, "method") == 0) bit = 2;
        else if (strcmp(name, "params") == 0) bit = 4;
        else if (strcmp(name, "id") == 0) bit = 8;
        else return -32600;
        if (seen & bit) return -32600;
        seen |= bit;
        if (bit == 1 || bit == 2) {
            if (routing_string(&r, value, sizeof(value)) != 0 ||
                strcmp(value, bit == 1 ? "2.0" : method) != 0) return -32600;
        } else if (bit == 4) {
            size_t start = r.pos;
            if (routing_skip_value(&r, 0) != 0) return -32600;
            params->text = json;
            params->pos = start;
            params->len = r.pos;
        } else if (routing_id(&r, id) != 0) return -32600;
        routing_space(&r);
        if (r.pos < r.len && r.text[r.pos] == '}') { ++r.pos; break; }
        if (routing_take(&r, ',') != 0) return -32600;
    }
    routing_space(&r);
    if (r.pos != r.len || (seen & 3) != 3) return -32600;
    return seen & 4 ? 0 : -32602;
}

static int routing_request(const char *json, size_t len, uint8_t key[32], char id[35]) {
    routing_reader_t params;
    int error;
    if (len > RPC_ROUTING_MAX_REQUEST_LEN) return -32600;
    error = closed_request(json, len, "get_shard_for_pubkey", &params, id);
    if (error) return error;
    return routing_params(&params, key) == 0 && params.pos == params.len ? 0 : -32602;
}

static int routing_dispatch(const char *request, size_t len, const rpc_context_t *ctx,
                            char *out, size_t cap) {
    uint8_t key[32];
    uint32_t shard;
    char id[35] = "null", address[67] = "0x", salt[65];
    int error = routing_request(request, len, key, id), written;
    if (error) {
        written = snprintf(out, cap,
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Invalid routing request\"},\"id\":%s}\n", error,
            error == -32602 ? id : "null");
    } else if (!ctx || !ctx->routing ||
               shard_routing_for_pubkey(ctx->routing, key, sizeof(key), &shard) != 0) {
        written = snprintf(out, cap,
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Routing configuration unavailable\"},\"id\":%s}\n", id);
    } else {
        bytes_to_hex(key, sizeof(key), address + 2, sizeof(address) - 2);
        bytes_to_hex(ctx->routing->salt, sizeof(ctx->routing->salt), salt, sizeof(salt));
        written = snprintf(out, cap,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"scope\":\"routing-query\",\"config_source\":\"local\","
            "\"consensus_enforced\":false,\"address\":\"%s\","
            "\"shard_id\":%u,\"shard_count\":%u,\"routing_salt\":\"%s\"},\"id\":%s}\n",
            address, (unsigned)shard, (unsigned)ctx->routing->shard_count, salt, id);
    }
    return written < 0 || (size_t)written >= cap ? -1 : written;
}

static int pending_params(routing_reader_t *r, int submit,
                          uint8_t frame[PENDING_TRANSFER_FRAME_SIZE], uint32_t *shard) {
    char name[9];
    if (routing_take(r, '{') != 0 || routing_string(r, name, sizeof(name)) != 0 ||
        strcmp(name, submit ? "frame" : "shard_id") != 0 || routing_take(r, ':') != 0) return -1;
    if (submit) {
        char hex[PENDING_TRANSFER_FRAME_SIZE * 2 + 1];
        if (routing_string(r, hex, sizeof(hex)) != 0 || strlen(hex) != sizeof(hex) - 1) return -1;
        for (size_t i = 0; i < PENDING_TRANSFER_FRAME_SIZE; ++i) {
            int hi = routing_hex_value(hex[2 * i]), lo = routing_hex_value(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) return -1;
            frame[i] = (uint8_t)((hi << 4) | lo);
        }
    } else {
        uint32_t value = 0;
        size_t start;
        routing_space(r);
        start = r->pos;
        while (r->pos < r->len && r->text[r->pos] >= '0' && r->text[r->pos] <= '9') {
            uint32_t digit = (uint32_t)(r->text[r->pos++] - '0');
            if (value > (UINT32_MAX - digit) / 10) return -1;
            value = value * 10 + digit;
        }
        if (r->pos == start || (r->pos - start > 1 && r->text[start] == '0')) return -1;
        *shard = value;
    }
    return routing_take(r, '}') == 0 && r->pos == r->len ? 0 : -1;
}

static int pending_dispatch(const char *request, size_t len, const char *method,
                            const rpc_context_t *ctx, char *out, size_t cap) {
    routing_reader_t params;
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE];
    uint32_t shard = 0;
    char id[35] = "null", genesis[65], salt[65], hash[65];
    int submit = strcmp(method, "submit_pending_transfer") == 0;
    int error = len > RPC_PENDING_MAX_REQUEST_LEN ? -32600 :
                closed_request(request, len, method, &params, id);
    if (!error && pending_params(&params, submit, frame, &shard) != 0) error = -32602;
    if (error) return rpc_error_response(out, cap,
        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Invalid pending request\"},\"id\":%s}\n",
        error, error == -32602 ? id : "null");
    if (!ctx || !ctx->pending) return rpc_error_response(out, cap,
        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Pending inbox disabled\"},\"id\":%s}\n", id);
    const pending_transfer_pool_t *pool = ctx->pending;
    bytes_to_hex(pool->genesis_hash, 32, genesis, sizeof(genesis));
    bytes_to_hex(pool->routing.salt, 32, salt, sizeof(salt));
    if (submit) {
        pending_transfer_result_t result;
        /* Longest successful response is 481 bytes plus NUL: 32-character ID,
         * two 10-digit u32 fields, three 64-character hex strings and the
         * nine-character status. Preflight BEFORE the only mutating call. */
        if (cap < RPC_PENDING_SUBMIT_RESPONSE_LEN) return -1;
        pending_transfer_status_t status = pending_transfer_submit(ctx->pending, frame, sizeof(frame), &result);
        if (status < 0) return rpc_error_response(out, cap,
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32002,\"message\":\"Pending transfer rejected\",\"data\":%d},\"id\":%s}\n",
            (int)status, id);
        bytes_to_hex(result.hash, 32, hash, sizeof(hash));
        return rpc_error_response(out, cap,
            "{\"jsonrpc\":\"2.0\",\"result\":{\"scope\":\"pending-signature-and-routing\","
            "\"state_validated\":false,\"config_source\":\"local\",\"genesis_hash\":\"%s\","
            "\"routing_salt\":\"%s\",\"shard_count\":%u,\"status\":\"%s\",\"shard_id\":%u,"
            "\"pending_count\":%u,\"hash\":\"%s\"},\"id\":%s}\n", genesis, salt,
            (unsigned)pool->routing.shard_count,
            status == PENDING_TRANSFER_INSERTED ? "inserted" : status == PENDING_TRANSFER_REPLACED ? "replaced" : "duplicate",
            (unsigned)result.shard_id, (unsigned)result.pending_count, hash, id);
    }
    pending_transfer_snapshot_t snapshot;
    if (pending_transfer_list(pool, shard, &snapshot) != 0) return rpc_error_response(out, cap,
        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid shard\"},\"id\":%s}\n", id);
    int written = rpc_error_response(out, cap,
        "{\"jsonrpc\":\"2.0\",\"result\":{\"scope\":\"pending-signature-and-routing\","
        "\"state_validated\":false,\"config_source\":\"local\",\"genesis_hash\":\"%s\","
        "\"routing_salt\":\"%s\",\"shard_count\":%u,\"shard_id\":%u,\"frames\":[",
        genesis, salt, (unsigned)pool->routing.shard_count, (unsigned)shard);
    if (written < 0) return -1;
    size_t used = (size_t)written;
    for (uint32_t i = 0; i < snapshot.count; ++i) {
        char hex[PENDING_TRANSFER_FRAME_SIZE * 2 + 1];
        bytes_to_hex(snapshot.frames[i], PENDING_TRANSFER_FRAME_SIZE, hex, sizeof(hex));
        written = rpc_error_response(out + used, cap - used, "%s\"%s\"", i ? "," : "", hex);
        if (written < 0) return -1;
        used += (size_t)written;
    }
    written = rpc_error_response(out + used, cap - used, "]},\"id\":%s}\n", id);
    return written < 0 ? -1 : (int)(used + (size_t)written);
}

/* Select from actual root key/value pairs. A string value such as id:"method"
 * is not a method key. This selects the handler only; routing_request still
 * validates every separator, field and byte before returning a routing result.
 */
static const determ_json_tok_t *rpc_method_token(const char *json,
                                                const determ_json_tok_t *tokens,
                                                size_t count) {
    const determ_json_tok_t *key = NULL;
    for (size_t i = 1; i < count; ++i) {
        if (tokens[i].parent != 0) continue;
        if (!key) key = &tokens[i];
        else {
            if (key->type == JSON_TOK_STRING && determ_json_token_streq(json, key, "method"))
                return &tokens[i];
            key = NULL;
        }
    }
    return NULL;
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
        return rpc_error_response(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n");
    }

    const determ_json_tok_t *method_tok = rpc_method_token(request_json, tokens, (size_t)num_tokens);
    const determ_json_tok_t *id_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "id");

    char id_str[32] = "null";
    if (id_tok) {
        (void)determ_json_token_to_string(request_json, id_tok, id_str, sizeof(id_str));
    }

    if (!method_tok || method_tok->type != JSON_TOK_STRING) {
        return rpc_error_response(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"},\"id\":%s}\n",
                        id_str);
    }

    char method[RPC_MAX_METHOD_LEN];
    if (determ_json_token_to_string(request_json, method_tok, method, sizeof(method)) != 0) {
        return rpc_error_response(out_resp, max_resp,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Method name too long\"},\"id\":%s}\n",
                        id_str);
    }

    if (strcmp(method, "get_shard_for_pubkey") == 0)
        return routing_dispatch(request_json, req_len, ctx, out_resp, max_resp);
    if (strcmp(method, "submit_pending_transfer") == 0 || strcmp(method, "get_pending_transfers") == 0)
        return pending_dispatch(request_json, req_len, method, ctx, out_resp, max_resp);

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
