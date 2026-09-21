/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Zero-Allocation, In-Place C99 JSON-RPC Handler.
 *
 * Dispatches RPC calls strictly using in-place token parsing
 * without any dynamic memory allocations (zero malloc/free).
 */

#ifndef DETERMINISTIC_RPC_JSON_RPC_H
#define DETERMINISTIC_RPC_JSON_RPC_H

#include <determ/wire/json_token.h>
#include <determ/consensus/duel_state.h>
#include <determ/consensus/dda.h>
#include <determ/storage/block_store.h>
#include <determ/net/peer_mesh.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RPC_MAX_TOKENS 128
#define RPC_MAX_METHOD_LEN 64
#define RPC_MAX_RESPONSE_LEN 8192

/*
 * Unified node RPC dispatch context
 */
typedef struct {
    const duel_state_machine_t *sm;
    const block_store_t        *store;
    const peer_mesh_t          *mesh;
    const dda_tracker_t        *dda;
    const char                 *node_version;
} rpc_context_t;

/*
 * Dispatch with full node context.
 * Returns length of response written into out_response, or negative error.
 */
int rpc_dispatch_context(const char *request_json, size_t req_len,
                         const rpc_context_t *ctx,
                         char *out_response, size_t max_response_len);

/*
 * Backwards-compatible dispatch helper for duel state machine.
 */
int rpc_dispatch(const char *request_json, size_t req_len,
                 const duel_state_machine_t *duel_sm,
                 char *out_response, size_t max_response_len);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_RPC_JSON_RPC_H */
