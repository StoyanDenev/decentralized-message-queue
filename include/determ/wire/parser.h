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


/*
 * ── Canonical Block Header Specification ─────────────────────────────────────
 * Strict Big-Endian binary encoding:
 *   1. height                   (8 bytes, uint64_t BE)
 *   2. prev_hash                (32 bytes)
 *   3. tx_root                  (32 bytes, Triple-Entry Merkle Root)
 *   4. dsso_root                (32 bytes, DSSO OPAQUE State Root)
 *   5. timestamp                (8 bytes, uint64_t BE)
 *   6. vrf_aggregator_proof     (32 bytes)
 *   7. vrf_contributor_proof    (32 bytes)
 *   8. vdf_iterations           (4 bytes, uint32_t BE)
 *   9. vdf_proof                (32 bytes)
 * Total: 212 bytes.
 */
#define WIRE_BLOCK_HEADER_LEN    212U

typedef struct {
    uint64_t height;
    uint8_t  prev_hash[32];
    uint8_t  tx_root[32];
    uint8_t  dsso_root[32];
    uint64_t timestamp;
    uint8_t  vrf_aggregator_proof[32];
    uint8_t  vrf_contributor_proof[32];
    uint32_t vdf_iterations;
    uint8_t  vdf_proof[32];
} wire_block_header_t;

/*
 * Parse canonical block header from raw bytes.
 * Returns WIRE_OK on success, or error status.
 */
wire_status_t wire_parse_block_header(const uint8_t *data, size_t data_len,
                                      wire_block_header_t *out_hdr);

/*
 * Encode canonical block header into raw Big-Endian wire bytes.
 */
wire_status_t wire_encode_block_header(const wire_block_header_t *hdr,
                                       uint8_t *out_buf, size_t max_out_len,
                                       size_t *out_written_len);

/*
 * Deterministically bind the executed Triple-Entry transactions and DSSO state changes
 * into the canonical payload digest fed into the VDF.
 */
wire_status_t wire_bind_consensus_vdf_payload(uint64_t height,
                                              const uint8_t prev_hash[32],
                                              const uint8_t tx_root[32],
                                              const uint8_t dsso_root[32],
                                              uint64_t timestamp,
                                              uint8_t out_vdf_payload[32]);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_WIRE_PARSER_H */
