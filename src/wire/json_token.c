/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Zero-Allocation, In-Place C99 JSON Token Parser.
 * Strictly zero heap allocations (no malloc/free).
 */

#include <determ/wire/json_token.h>
#include <string.h>
#include <ctype.h>

static inline determ_json_tok_t *alloc_token(determ_json_tok_t *tokens,
                                             size_t max_tokens,
                                             size_t *next_tok) {
    if (*next_tok >= max_tokens) {
        return NULL;
    }
    determ_json_tok_t *tok = &tokens[*next_tok];
    tok->start = 0;
    tok->end = 0;
    tok->size = 0;
    tok->parent = -1;
    tok->type = JSON_TOK_UNDEFINED;
    (*next_tok)++;
    return tok;
}

int determ_json_parse(const char *js, size_t len,
                      determ_json_tok_t *tokens, size_t max_tokens) {
    if (!js || len == 0 || !tokens || max_tokens == 0) {
        return JSON_ERR_INVAL;
    }

    size_t next_tok = 0;
    int super_tok = -1;

    for (size_t i = 0; i < len; ++i) {
        char c = js[i];

        switch (c) {
            case '{':
            case '[': {
                determ_json_tok_t *tok = alloc_token(tokens, max_tokens, &next_tok);
                if (!tok) return JSON_ERR_NOMEM;

                if (super_tok != -1) {
                    tokens[super_tok].size++;
                    tok->parent = super_tok;
                }
                tok->type = (c == '{' ? JSON_TOK_OBJECT : JSON_TOK_ARRAY);
                tok->start = i;
                super_tok = (int)(next_tok - 1);
                break;
            }

            case '}':
            case ']': {
                determ_json_type_t expected = (c == '}' ? JSON_TOK_OBJECT : JSON_TOK_ARRAY);
                if (super_tok == -1 || tokens[super_tok].type != expected) {
                    return JSON_ERR_INVAL;
                }
                tokens[super_tok].end = i + 1;
                super_tok = tokens[super_tok].parent;
                break;
            }

            case '\"': {
                /* Parse string */
                size_t start = i;
                i++;
                while (i < len) {
                    if (js[i] == '\"') {
                        /* Check escape */
                        size_t backslashes = 0;
                        size_t b = i;
                        while (b > start && js[b - 1] == '\\') {
                            backslashes++;
                            b--;
                        }
                        if ((backslashes % 2) == 0) {
                            break;
                        }
                    }
                    i++;
                }
                if (i >= len) {
                    return JSON_ERR_PART;
                }

                determ_json_tok_t *tok = alloc_token(tokens, max_tokens, &next_tok);
                if (!tok) return JSON_ERR_NOMEM;

                tok->type = JSON_TOK_STRING;
                tok->start = start + 1; /* Skip opening quote */
                tok->end = i;           /* Exclude closing quote */
                tok->size = 0;
                tok->parent = super_tok;
                if (super_tok != -1) {
                    tokens[super_tok].size++;
                }
                break;
            }

            case '\t':
            case '\r':
            case '\n':
            case ' ':
            case ':':
            case ',':
                break;

            default: {
                /* Primitive: numbers, booleans, null */
                size_t start = i;
                while (i < len) {
                    char ch = js[i];
                    if (ch == ',' || ch == '}' || ch == ']' ||
                        ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                        break;
                    }
                    i++;
                }

                determ_json_tok_t *tok = alloc_token(tokens, max_tokens, &next_tok);
                if (!tok) return JSON_ERR_NOMEM;

                tok->type = JSON_TOK_PRIMITIVE;
                tok->start = start;
                tok->end = i;
                tok->size = 0;
                tok->parent = super_tok;
                if (super_tok != -1) {
                    tokens[super_tok].size++;
                }
                i--; /* Rewind one to process delimiter */
                break;
            }
        }
    }

    if (super_tok != -1) {
        return JSON_ERR_PART;
    }

    return (int)next_tok;
}

const determ_json_tok_t *determ_json_find_key(const char *js,
                                              const determ_json_tok_t *tokens,
                                              size_t num_tokens,
                                              const determ_json_tok_t *obj_tok,
                                              const char *key) {
    if (!js || !tokens || !obj_tok || !key || obj_tok->type != JSON_TOK_OBJECT) {
        return NULL;
    }

    int obj_idx = (int)(obj_tok - tokens);
    for (size_t i = 0; i < num_tokens; ++i) {
        if (tokens[i].parent == obj_idx && tokens[i].type == JSON_TOK_STRING) {
            if (determ_json_token_streq(js, &tokens[i], key)) {
                /* Found matching key; its value is the immediately following token */
                if (i + 1 < num_tokens) {
                    return &tokens[i + 1];
                }
            }
        }
    }
    return NULL;
}

int determ_json_token_streq(const char *js, const determ_json_tok_t *tok, const char *expected) {
    if (!js || !tok || !expected) return 0;
    size_t tok_len = tok->end - tok->start;
    size_t exp_len = strlen(expected);
    if (tok_len != exp_len) return 0;
    return (memcmp(js + tok->start, expected, tok_len) == 0) ? 1 : 0;
}

int determ_json_token_to_string(const char *js, const determ_json_tok_t *tok,
                                char *out_buf, size_t max_out) {
    if (!js || !tok || !out_buf || max_out == 0) return -1;
    size_t tok_len = tok->end - tok->start;
    if (tok_len + 1 > max_out) return -1;
    memcpy(out_buf, js + tok->start, tok_len);
    out_buf[tok_len] = '\0';
    return 0;
}

int determ_json_token_to_uint64(const char *js, const determ_json_tok_t *tok, uint64_t *out_val) {
    if (!js || !tok || !out_val || tok->start >= tok->end) return -1;
    uint64_t val = 0;
    for (size_t i = tok->start; i < tok->end; ++i) {
        char c = js[i];
        if (c < '0' || c > '9') return -1;
        val = val * 10 + (uint64_t)(c - '0');
    }
    *out_val = val;
    return 0;
}
