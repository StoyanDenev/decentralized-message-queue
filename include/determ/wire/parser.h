/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Strict Canonicalization Wire Defenses (Phase 3: C99 Bare-Metal)
 *
 * Security Defenses:
 *   1. Surgical elimination of the NUL-byte canonicalization vulnerability ("NUL-Byte Ghost").
 *   2. Charset-gated validation for all identifier fields (from, to, domain).
 *   3. Big-endian Safe Concatenation with strict length-prefix boundary verification.
 *   4. Zero dynamic memory allocation (pure stack/arena, no malloc).
 */

#ifndef DETERMINISTIC_WIRE_PARSER_H
#define DETERMINISTIC_WIRE_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIRE_MAX_ADDR_LEN         128U
#define WIRE_MAX_DOMAIN_LEN       256U
#define WIRE_MAX_PAYLOAD_LEN      65536U
#define WIRE_MAX_VDF_BUNDLE_LEN   (WIRE_MAX_PAYLOAD_LEN * 2 + 8)

typedef enum {
    WIRE_OK                          =  0,
    ERR_INVALID_TRANSACTION_FORMAT   = -1,
    ERR_BUFFER_OVERFLOW              = -2,
    ERR_INVALID_LENGTH_PREFIX        = -3,
    ERR_CHARSET_VIOLATION            = -4,
    ERR_NUL_BYTE_INJECTION           = -5,
    ERR_INVALID_ARGUMENT             = -6
} wire_status_t;

/*
 * Canonical Transaction Deserialization Context (Zero-alloc, stack/caller allocated)
 */
typedef struct {
    uint8_t  type;
    uint8_t  from[WIRE_MAX_ADDR_LEN];
    uint16_t from_len;
    uint8_t  to[WIRE_MAX_ADDR_LEN];
    uint16_t to_len;
    uint8_t  domain[WIRE_MAX_DOMAIN_LEN];
    uint16_t domain_len;
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint8_t  payload[WIRE_MAX_PAYLOAD_LEN];
    uint32_t payload_len;
} wire_tx_t;

/*
 * Charset-Gating & NUL-Byte Ghost Defense:
 * Scans a variable-length byte slice of length `len`.
 * Rejection criteria:
 *   - Any byte == 0x00 (The NUL-Byte Ghost).
 *   - Any character outside the strict whitelist: [a-z, 0-9, '.', '-', '_'].
 * Returns WIRE_OK on success, or ERR_INVALID_TRANSACTION_FORMAT on violation.
 */
wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len);

/*
 * Strict Wire Deserialization:
 * Validates and unpacks wire bytes into wire_tx_t.
 * Prevents NUL-byte injection and buffer overflows before consensus ingress.
 */
wire_status_t wire_parse_transaction(const uint8_t *data, size_t data_len, wire_tx_t *out_tx);

/*
 * Safe Concatenation:
 * Aggregator bundles raw reveals into the canonical VDF input payload.
 * Serialization: [BE32(len_a)][reveal_a][BE32(len_b)][reveal_b]
 * Enforces strict boundary checks to eliminate buffer overflow vectors.
 */
wire_status_t wire_bundle_vdf_input(const uint8_t *reveal_a, uint32_t len_a,
                                    const uint8_t *reveal_b, uint32_t len_b,
                                    uint8_t *out_buf, size_t max_out_len,
                                    size_t *out_written_len);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_WIRE_PARSER_H */
