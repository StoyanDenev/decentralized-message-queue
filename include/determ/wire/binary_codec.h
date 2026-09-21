/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Canonical Binary Wire & Storage Frame Codec (C99 Bare-Metal)
 *
 * Implements strict zero-allocation serialization and deserialization for:
 *   1. Canonical P2P binary envelope (0xB1, v1) across all 19 MsgTypes.
 *   2. Fixed-layout transaction framing (4x256-bit core + trailer).
 *   3. Consensus chatter frames (BLOCK_SIG, CONTRIB, ABORT_CLAIM, ABORT_EVENT, EQUIVOCATION).
 *   4. Control / sync frames (GET_CHAIN, CHAIN_RESPONSE, STATUS, SNAPSHOT, HEADERS).
 *   5. Canonical storage records: DBK1 (Block), DHF1 (Header), DMF1 (Manifest).
 *
 * Architectural Guarantees:
 *   - Zero dynamic heap allocation (malloc/free) on encode/decode paths.
 *   - Explicit Little-Endian (LE) integer encoding for multi-byte payloads.
 *   - Strict fail-closed parsing: truncated payloads, non-zero reserved bytes,
 *     and unexpected trailing bytes result in immediate failure.
 */

#ifndef DETERMINISTIC_WIRE_BINARY_CODEC_H
#define DETERMINISTIC_WIRE_BINARY_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Envelope Constants ─────────────────────────────────────────────────── */
#define WIRE_ENVELOPE_MAGIC             0xB1U
#define WIRE_ENVELOPE_VERSION           0x01U
#define WIRE_ENVELOPE_HEADER_LEN        4U

/* Wire ceilings and limits */
#define WIRE_HEADERS_PAGE_MAX           256U
#define WIRE_SNAPSHOT_HEADER_MAX        256U
#define WIRE_MIN_BLOCK_FRAME            297U
#define WIRE_MANIFEST_BYTES             44U

/* ─── Return Status Codes ────────────────────────────────────────────────── */
typedef enum {
    WIRE_CODEC_OK                       =  0,
    WIRE_CODEC_ERR_TRUNCATED            = -1,
    WIRE_CODEC_ERR_BAD_MAGIC            = -2,
    WIRE_CODEC_ERR_BAD_VERSION          = -3,
    WIRE_CODEC_ERR_BAD_MSG_TYPE         = -4,
    WIRE_CODEC_ERR_NONZERO_RESERVED     = -5,
    WIRE_CODEC_ERR_TRAILING_BYTES       = -6,
    WIRE_CODEC_ERR_BUFFER_TOO_SMALL     = -7,
    WIRE_CODEC_ERR_INVALID_FIELD        = -8,
    WIRE_CODEC_ERR_CAP_EXCEEDED         = -9,
    WIRE_CODEC_ERR_INVALID_ARG          = -10
} wire_codec_status_t;

/* ─── Canonical Wire Message Types (MsgType) ────────────────────────────── */
typedef enum {
    WIRE_MSG_HELLO                      = 0,
    WIRE_MSG_BLOCK                      = 1,
    WIRE_MSG_TRANSACTION                = 2,
    WIRE_MSG_BLOCK_SIG                  = 3,
    WIRE_MSG_CONTRIB                    = 4,
    WIRE_MSG_GET_CHAIN                  = 5,
    WIRE_MSG_CHAIN_RESPONSE             = 6,
    WIRE_MSG_STATUS_REQUEST             = 7,
    WIRE_MSG_STATUS_RESPONSE            = 8,
    WIRE_MSG_ABORT_CLAIM                = 9,
    WIRE_MSG_ABORT_EVENT                = 10,
    WIRE_MSG_EQUIVOCATION_EVIDENCE      = 11,
    WIRE_MSG_BEACON_HEADER              = 12,
    WIRE_MSG_SHARD_TIP                  = 13,
    WIRE_MSG_CROSS_SHARD_RECEIPT_BUNDLE = 14,
    WIRE_MSG_SNAPSHOT_REQUEST           = 15,
    WIRE_MSG_SNAPSHOT_RESPONSE          = 16,
    WIRE_MSG_HEADERS_REQUEST            = 17,
    WIRE_MSG_HEADERS_RESPONSE           = 18,
    WIRE_MSG_TYPE_COUNT                 = 19
} wire_msg_type_t;

/* ─── 1. Binary Envelope Header ─────────────────────────────────────────── */
typedef struct {
    uint8_t        msg_type;
    const uint8_t *payload;
    size_t         payload_len;
} wire_envelope_t;

bool wire_is_binary_envelope(const uint8_t *data, size_t len);
wire_codec_status_t wire_envelope_decode(const uint8_t *data, size_t len, wire_envelope_t *out_env);
wire_codec_status_t wire_envelope_encode(uint8_t *out_buf, size_t buf_cap,
                                        uint8_t msg_type,
                                        const uint8_t *payload, size_t payload_len,
                                        size_t *out_written);

/* ─── 2. HELLO (MsgType 0) ──────────────────────────────────────────────── */
typedef struct {
    const char *domain;
    uint8_t     domain_len;
    uint16_t    port;
    uint8_t     role;
    uint32_t    shard_id;
    uint8_t     wire_version;
} wire_hello_t;

wire_codec_status_t wire_hello_encode(uint8_t *out_buf, size_t buf_cap,
                                      const wire_hello_t *msg, size_t *out_written);
wire_codec_status_t wire_hello_decode(const uint8_t *data, size_t len,
                                      wire_hello_t *msg);

/* ─── 3. TRANSACTION Frame (MsgType 2) ──────────────────────────────────── */
/* 4x256-bit fixed frame + trailer */
typedef struct {
    uint8_t        sender_pubkey[32];
    uint64_t       amount;
    uint64_t       fee;
    uint64_t       nonce;
    uint8_t        recipient_pubkey[32];
    const uint8_t *payload;
    uint16_t       payload_len;
    uint8_t        type;
    const char    *from;
    uint8_t        from_len;
    const char    *to;
    uint8_t        to_len;
    uint8_t        sig[64];
    uint8_t        hash[32];
    uint8_t        genesis_hash[32];
    uint32_t       shard_id;
    const uint8_t *pq_auth;
    uint32_t       pq_auth_len;
} wire_transaction_t;

wire_codec_status_t wire_tx_encode(uint8_t *out_buf, size_t buf_cap,
                                   const wire_transaction_t *tx, size_t *out_written);
wire_codec_status_t wire_tx_decode(const uint8_t *data, size_t len,
                                   wire_transaction_t *tx);

/* ─── 4. BLOCK_SIG (MsgType 3) ──────────────────────────────────────────── */
typedef struct {
    uint64_t    block_index;
    const char *signer;
    uint8_t     signer_len;
    uint8_t     delay_output[32];
    uint8_t     dh_secret[32];
    uint8_t     ed_sig[64];
} wire_block_sig_t;

wire_codec_status_t wire_block_sig_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_block_sig_t *msg, size_t *out_written);
wire_codec_status_t wire_block_sig_decode(const uint8_t *data, size_t len,
                                          wire_block_sig_t *msg);

/* ─── 5. CONTRIB (MsgType 4) ────────────────────────────────────── */
typedef struct {
    uint64_t       block_index;
    const char    *signer;
    uint8_t        signer_len;
    uint8_t        prev_hash[32];
    uint64_t       aborts_gen;
    const uint8_t *tx_hashes;           /* tx_hash_count * 32 bytes */
    uint16_t       tx_hash_count;
    uint8_t        dh_input[32];
    uint8_t        view_eq_root[32];
    uint8_t        view_abort_root[32];
    uint8_t        view_inbound_root[32];
    const uint8_t *view_eq_list;        /* view_eq_count * 32 bytes */
    uint16_t       view_eq_count;
    const uint8_t *view_abort_list;     /* view_abort_count * 32 bytes */
    uint16_t       view_abort_count;
    const uint8_t *view_inbound_list;   /* view_inbound_count * 32 bytes */
    uint16_t       view_inbound_count;
    uint64_t       proposer_time;
    uint8_t        view_shardtip_root[32];
    const uint8_t *view_shardtip_list;  /* view_shardtip_count * 32 bytes */
    uint16_t       view_shardtip_count;
    uint8_t        ed_sig[64];
} wire_contrib_t;

wire_codec_status_t wire_contrib_encode(uint8_t *out_buf, size_t buf_cap,
                                        const wire_contrib_t *msg, size_t *out_written);
wire_codec_status_t wire_contrib_decode(const uint8_t *data, size_t len,
                                        wire_contrib_t *msg);

/* ─── 6. Request & Status Frames ────────────────────────────────────────── */
/* GET_CHAIN (MsgType 5) */
typedef struct {
    uint64_t from;
    uint16_t count;
} wire_get_chain_t;

wire_codec_status_t wire_get_chain_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_get_chain_t *msg, size_t *out_written);
wire_codec_status_t wire_get_chain_decode(const uint8_t *data, size_t len,
                                          wire_get_chain_t *msg);

/* STATUS_RESPONSE (MsgType 8) */
typedef struct {
    uint64_t    height;
    const char *genesis_hex;
    uint8_t     genesis_len;            /* 0 or 64 */
} wire_status_response_t;

wire_codec_status_t wire_status_response_encode(uint8_t *out_buf, size_t buf_cap,
                                                const wire_status_response_t *msg, size_t *out_written);
wire_codec_status_t wire_status_response_decode(const uint8_t *data, size_t len,
                                                wire_status_response_t *msg);

/* SNAPSHOT_REQUEST (MsgType 15) */
typedef struct {
    uint32_t headers;
} wire_snapshot_req_t;

wire_codec_status_t wire_snapshot_req_encode(uint8_t *out_buf, size_t buf_cap,
                                             const wire_snapshot_req_t *msg, size_t *out_written);
wire_codec_status_t wire_snapshot_req_decode(const uint8_t *data, size_t len,
                                             wire_snapshot_req_t *msg);

/* HEADERS_REQUEST (MsgType 17) */
typedef struct {
    uint64_t from;
    uint32_t count;
} wire_headers_req_t;

wire_codec_status_t wire_headers_req_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_headers_req_t *msg, size_t *out_written);
wire_codec_status_t wire_headers_req_decode(const uint8_t *data, size_t len,
                                            wire_headers_req_t *msg);

/* ─── 7. ABORT_CLAIM (MsgType 9) & ABORT_EVENT (MsgType 10) ─────────────── */
typedef struct {
    uint64_t    block_index;
    uint8_t     round;
    uint8_t     prev_hash[32];
    uint8_t     ed_sig[64];
    const char *missing_creator;
    uint8_t     missing_creator_len;
    const char *claimer;
    uint8_t     claimer_len;
} wire_abort_claim_t;

wire_codec_status_t wire_abort_claim_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_abort_claim_t *msg, size_t *out_written);
wire_codec_status_t wire_abort_claim_decode(const uint8_t *data, size_t len,
                                            wire_abort_claim_t *msg);

typedef struct {
    uint64_t       block_index;
    uint8_t        prev_hash[32];
    uint8_t        round;
    const char    *aborting_node;
    uint8_t        aborting_node_len;
    uint64_t       timestamp;
    uint8_t        event_hash[32];
    const uint8_t *claims_blob;
    size_t         claims_blob_len;
} wire_abort_event_t;

wire_codec_status_t wire_abort_event_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_abort_event_t *msg, size_t *out_written);
wire_codec_status_t wire_abort_event_decode(const uint8_t *data, size_t len,
                                            wire_abort_event_t *msg);

/* ─── 8. EQUIVOCATION_EVIDENCE (MsgType 11) ──────────────────────────────── */
typedef struct {
    const char *equivocator;
    uint8_t     equivocator_len;
    uint64_t    block_index;
    uint8_t     kind;                   /* 0 = BLOCK_DIGEST, 1 = CONTRIB_COMMIT */
    uint64_t    index_a;
    uint64_t    gen_a;
    uint8_t     body_root_a[32];
    uint8_t     sig_a[64];
    uint64_t    index_b;
    uint64_t    gen_b;
    uint8_t     body_root_b[32];
    uint8_t     sig_b[64];
    uint32_t    shard_id;
    uint64_t    beacon_anchor_height;
} wire_equivocation_evidence_t;

wire_codec_status_t wire_equivocation_encode(uint8_t *out_buf, size_t buf_cap,
                                             const wire_equivocation_evidence_t *msg, size_t *out_written);
wire_codec_status_t wire_equivocation_decode(const uint8_t *data, size_t len,
                                             wire_equivocation_evidence_t *msg);

/* ─── 9. Block-Carrying Payload Frames ──────────────────────────────────── */
/* SHARD_TIP (MsgType 13) */
typedef struct {
    uint32_t       shard_id;
    const uint8_t *block_frame;
    size_t         block_frame_len;
} wire_shard_tip_t;

wire_codec_status_t wire_shard_tip_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_shard_tip_t *msg, size_t *out_written);
wire_codec_status_t wire_shard_tip_decode(const uint8_t *data, size_t len,
                                          wire_shard_tip_t *msg);

/* CROSS_SHARD_RECEIPT_BUNDLE (MsgType 14) */
typedef struct {
    uint32_t       src_shard;
    const uint8_t *block_frame;
    size_t         block_frame_len;
} wire_receipt_bundle_t;

wire_codec_status_t wire_receipt_bundle_encode(uint8_t *out_buf, size_t buf_cap,
                                               const wire_receipt_bundle_t *msg, size_t *out_written);
wire_codec_status_t wire_receipt_bundle_decode(const uint8_t *data, size_t len,
                                               wire_receipt_bundle_t *msg);

/* CHAIN_RESPONSE (MsgType 6) */
typedef struct {
    uint8_t        has_more;
    uint16_t       block_count;
    const uint8_t *blocks_data;
    size_t         blocks_data_len;
} wire_chain_response_t;

wire_codec_status_t wire_chain_response_decode_header(const uint8_t *data, size_t len,
                                                     wire_chain_response_t *resp);
wire_codec_status_t wire_chain_response_next_block(const uint8_t *blocks_data, size_t total_len,
                                                  size_t *cursor,
                                                  const uint8_t **out_block_frame,
                                                  uint32_t *out_block_frame_len);

/* ─── 10. Canonical Storage & Container Records ─────────────────────────── */

/* DMF1: Fixed 44-byte manifest record */
typedef struct {
    uint64_t height;
    uint8_t  head_hash[32];
} wire_manifest_t;

wire_codec_status_t wire_manifest_encode(uint8_t *out_buf, size_t buf_cap,
                                         const wire_manifest_t *m, size_t *out_written);
wire_codec_status_t wire_manifest_decode(const uint8_t *data, size_t len,
                                         wire_manifest_t *m);

/* DBK1: Per-block storage frame wrapper */
wire_codec_status_t wire_dbk1_wrap(uint8_t *out_buf, size_t buf_cap,
                                   const uint8_t *block_frame, size_t block_frame_len,
                                   size_t *out_written);
wire_codec_status_t wire_dbk1_unwrap(const uint8_t *data, size_t len,
                                     const uint8_t **out_block_frame,
                                     size_t *out_block_frame_len);

/* DHF1: Header record for HEADERS_RESPONSE (MsgType 18) */
typedef struct {
    uint8_t        block_hash[32];
    uint32_t       frame_len;
    const uint8_t *block_frame;
} wire_header_record_t;

typedef struct {
    uint64_t       from;
    uint64_t       height;
    uint16_t       count;
    const uint8_t *headers_data;
    size_t         headers_data_len;
} wire_headers_response_t;

wire_codec_status_t wire_headers_response_decode_header(const uint8_t *data, size_t len,
                                                        wire_headers_response_t *resp);
wire_codec_status_t wire_headers_response_next_record(const uint8_t *headers_data, size_t total_len,
                                                      size_t *cursor,
                                                      wire_header_record_t *out_rec);
wire_codec_status_t wire_dhf1_record_encode(uint8_t *out_buf, size_t buf_cap,
                                            const uint8_t block_hash[32],
                                            const uint8_t *block_frame, uint32_t block_frame_len,
                                            size_t *out_written);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_WIRE_BINARY_CODEC_H */
