/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Zero-Allocation, In-Place C99 JSON Token Parser.
 *
 * Strictly zero heap allocations (malloc/free). Parses tokens directly
 * pointing into the caller's immutable input buffer to eliminate heap latency spikes.
 */

#ifndef DETERMINISTIC_WIRE_JSON_TOKEN_H
#define DETERMINISTIC_WIRE_JSON_TOKEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JSON_TOK_UNDEFINED = 0,
    JSON_TOK_OBJECT    = 1,
    JSON_TOK_ARRAY     = 2,
    JSON_TOK_STRING    = 3,
    JSON_TOK_PRIMITIVE = 4 /* numbers, booleans, null */
} determ_json_type_t;

typedef enum {
    JSON_ERR_OK             =  0,
    JSON_ERR_NOMEM          = -1, /* Token capacity exceeded */
    JSON_ERR_INVAL          = -2, /* Malformed character or syntax */
    JSON_ERR_PART           = -3  /* Incomplete JSON string */
} determ_json_err_t;

typedef struct {
    determ_json_type_t type;
    size_t start;
    size_t end;
    int size;   /* Number of direct child items */
    int parent; /* Index of parent token (-1 if root) */
} determ_json_tok_t;

/*
 * Parse json_str in-place into tokens array.
 * Returns count of parsed tokens on success, or negative determ_json_err_t.
 */
int determ_json_parse(const char *json_str, size_t len,
                      determ_json_tok_t *tokens, size_t max_tokens);

/*
 * Find direct key token inside an object token.
 * Returns pointer to value token or NULL if not found.
 */
const determ_json_tok_t *determ_json_find_key(const char *json_str,
                                              const determ_json_tok_t *tokens,
                                              size_t num_tokens,
                                              const determ_json_tok_t *obj_tok,
                                              const char *key);

/*
 * Compare token string content against expected null-terminated string.
 * Returns 1 if identical, 0 otherwise.
 */
int determ_json_token_streq(const char *json_str, const determ_json_tok_t *tok, const char *expected);

/*
 * Extract token as null-terminated string into out_buf.
 * Returns 0 on success, -1 on truncation/overflow.
 */
int determ_json_token_to_string(const char *json_str, const determ_json_tok_t *tok,
                                char *out_buf, size_t max_out);

/*
 * Parse unsigned integer from primitive/number token.
 * Returns 0 on success, -1 on parse failure.
 */
int determ_json_token_to_uint64(const char *json_str, const determ_json_tok_t *tok, uint64_t *out_val);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_WIRE_JSON_TOKEN_H */
