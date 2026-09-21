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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RPC_MAX_TOKENS 128
#define RPC_MAX_METHOD_LEN 64
#define RPC_MAX_RESPONSE_LEN 4096

/*
 * Dispatch a JSON-RPC request string in-place and write the JSON-RPC
 * response into out_response.
 * Returns length of response written, or negative error code.
 */
int rpc_dispatch(const char *request_json, size_t req_len,
                 const duel_state_machine_t *duel_sm,
                 char *out_response, size_t max_response_len);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_RPC_JSON_RPC_H */
