/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Strict wire parsing for the C99 prototype (Phase 3: C99 Bare-Metal).
 *
 *   1. The identifier fields (from, to, domain) admit only [a-z0-9._-]; a NUL
 *      or any other byte is rejected.
 *   2. Every length prefix is bounded by its field maximum and by the remaining
 *      input, and a transaction frame must be consumed exactly.
 *   3. Big-endian [BE32 length][bytes] concatenation of the two duel reveals.
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
#ifndef MAX_BUNDLE_SIZE
#define MAX_BUNDLE_SIZE           131104
#endif
#define WIRE_MAX_VDF_BUNDLE_LEN   MAX_BUNDLE_SIZE

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
 * Identifier charset gate over `len` bytes (len 0 is accepted):
 *   - len > max_len: ERR_BUFFER_OVERFLOW.
 *   - A NUL byte or any byte outside [a-z, 0-9, '.', '-', '_']:
 *     ERR_INVALID_TRANSACTION_FORMAT.
 * Returns WIRE_OK otherwise.
 */
wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len);

/*
 * Decode [type u8][BE16 len][from][BE16 len][to][BE16 len][domain]
 * [BE64 amount][BE64 fee][BE64 nonce][BE32 len][payload] into out_tx. Each
 * length is bounded by its field maximum and the remaining input, from/to/
 * domain must pass wire_validate_charset_strict, and the input must be
 * consumed exactly. Returns WIRE_OK or ERR_INVALID_TRANSACTION_FORMAT.
 * No production path calls it (tests only).
 */
wire_status_t wire_parse_transaction(const uint8_t *data, size_t data_len, wire_tx_t *out_tx);

/*
 * Bundle the two reveals as the evaluator input:
 * [BE32(len_a)][reveal_a][BE32(len_b)][reveal_b]. Returns ERR_BUFFER_OVERFLOW
 * when a reveal exceeds WIRE_MAX_PAYLOAD_LEN or the bundle would exceed
 * max_out_len or MAX_BUNDLE_SIZE.
 */
wire_status_t wire_bundle_vdf_input(const uint8_t *reveal_a, uint32_t len_a,
                                    const uint8_t *reveal_b, uint32_t len_b,
                                    uint8_t *out_buf, size_t max_out_len,
                                    size_t *out_written_len);

/*
 * ── Canonical Block Header Specification ─────────────────────────────────────
 * Strict Big-Endian binary encoding. The codec carries every field and
 * verifies none; the field names are kept for format stability:
 *   1. height                   (8 bytes, uint64_t BE)
 *   2. prev_hash                (32 bytes)
 *   3. tx_root                  (32 bytes; ledger_compute_tx_root defines one
 *                                encoding, nothing checks this field)
 *   4. dsso_root                (32 bytes; RESERVED: no DSSO state root is
 *                                computed or verified in the C99 tree)
 *   5. timestamp                (8 bytes, uint64_t BE)
 *   6. vrf_aggregator_proof     (32 bytes; RESERVED: the C99 tree has no VRF)
 *   7. vrf_contributor_proof    (32 bytes; RESERVED: the C99 tree has no VRF)
 *   8. vdf_iterations           (4 bytes, uint32_t BE)
 *   9. vdf_proof                (32 bytes; the evaluator output, checkable only
 *                                by re-evaluation, not a succinct proof)
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
 * Parse a canonical block header. data_len must be exactly
 * WIRE_BLOCK_HEADER_LEN; shorter input or trailing bytes are rejected with
 * ERR_INVALID_TRANSACTION_FORMAT. Returns WIRE_OK on success.
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
 * out = SHA-256(BE64 height || prev_hash || tx_root || dsso_root || BE64 timestamp).
 * The inputs are hashed as given (dsso_root is the reserved field above);
 * nothing here computes or checks them. No production path calls it.
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
