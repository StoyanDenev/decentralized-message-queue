/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Canonical Binary Wire & Storage Frame Codec (C99 Bare-Metal)
 */

#include <determ/wire/binary_codec.h>
#include <string.h>

/* ─── Static Endian & Helper Primitives ─────────────────────────────────── */

static inline void le_put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline uint16_t le_get_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline void le_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint32_t le_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void le_put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
    }
}

static inline uint64_t le_get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)p[i]) << (i * 8);
    }
    return v;
}

/* ─── 1. Binary Envelope Header ─────────────────────────────────────────── */

bool wire_is_binary_envelope(const uint8_t *data, size_t len) {
    if (!data || len < WIRE_ENVELOPE_HEADER_LEN) {
        return false;
    }
    return (data[0] == WIRE_ENVELOPE_MAGIC && data[1] == WIRE_ENVELOPE_VERSION);
}

wire_codec_status_t wire_envelope_decode(const uint8_t *data, size_t len, wire_envelope_t *out_env) {
    if (!data || !out_env) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    if (len < WIRE_ENVELOPE_HEADER_LEN) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }
    if (data[0] != WIRE_ENVELOPE_MAGIC) {
        return WIRE_CODEC_ERR_BAD_MAGIC;
    }
    if (data[1] != WIRE_ENVELOPE_VERSION) {
        return WIRE_CODEC_ERR_BAD_VERSION;
    }
    if (data[2] >= WIRE_MSG_TYPE_COUNT) {
        return WIRE_CODEC_ERR_BAD_MSG_TYPE;
    }
    if (data[3] != 0x00) {
        return WIRE_CODEC_ERR_NONZERO_RESERVED;
    }
    out_env->msg_type = data[2];
    out_env->payload = data + WIRE_ENVELOPE_HEADER_LEN;
    out_env->payload_len = len - WIRE_ENVELOPE_HEADER_LEN;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_envelope_encode(uint8_t *out_buf, size_t buf_cap,
                                        uint8_t msg_type,
                                        const uint8_t *payload, size_t payload_len,
                                        size_t *out_written) {
    if (!out_buf || !out_written) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    if (msg_type >= WIRE_MSG_TYPE_COUNT) {
        return WIRE_CODEC_ERR_BAD_MSG_TYPE;
    }
    if (buf_cap < WIRE_ENVELOPE_HEADER_LEN + payload_len) {
        return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    }
    out_buf[0] = WIRE_ENVELOPE_MAGIC;
    out_buf[1] = WIRE_ENVELOPE_VERSION;
    out_buf[2] = msg_type;
    out_buf[3] = 0x00; /* reserved */
    if (payload && payload_len > 0) {
        memcpy(out_buf + WIRE_ENVELOPE_HEADER_LEN, payload, payload_len);
    }
    *out_written = WIRE_ENVELOPE_HEADER_LEN + payload_len;
    return WIRE_CODEC_OK;
}

/* ─── 2. HELLO (MsgType 0) ──────────────────────────────────────────────── */

wire_codec_status_t wire_hello_encode(uint8_t *out_buf, size_t buf_cap,
                                      const wire_hello_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t required = 1 + (size_t)msg->domain_len + 2 + 1 + 4 + 1;
    if (buf_cap < required) {
        return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = 0;
    out_buf[off++] = msg->domain_len;
    if (msg->domain_len > 0 && msg->domain) {
        memcpy(out_buf + off, msg->domain, msg->domain_len);
        off += msg->domain_len;
    }
    le_put_u16(out_buf + off, msg->port);
    off += 2;
    out_buf[off++] = msg->role;
    le_put_u32(out_buf + off, msg->shard_id);
    off += 4;
    out_buf[off++] = msg->wire_version;
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_hello_decode(const uint8_t *data, size_t len,
                                      wire_hello_t *msg) {
    if (!data || !msg) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    if (len < 1) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }
    size_t off = 0;
    uint8_t dlen = data[off++];
    if (off + dlen + 2 + 1 + 4 + 1 > len) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }
    msg->domain_len = dlen;
    msg->domain = (const char *)(data + off);
    off += dlen;
    msg->port = le_get_u16(data + off);
    off += 2;
    msg->role = data[off++];
    msg->shard_id = le_get_u32(data + off);
    off += 4;
    msg->wire_version = data[off++];
    if (off != len) {
        return WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    return WIRE_CODEC_OK;
}

/* ─── 3. TRANSACTION Frame (MsgType 2) ──────────────────────────────────── */

wire_codec_status_t wire_tx_encode(uint8_t *out_buf, size_t buf_cap,
                                   const wire_transaction_t *tx, size_t *out_written) {
    if (!out_buf || !tx || !out_written) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t overflow = (tx->payload_len > 32) ? (size_t)(tx->payload_len - 32) : 0;
    size_t required = 128 + 1 + 2 + overflow + 1 + tx->from_len + 1 + tx->to_len + 64 + 32 + 32 + 4;
    if (tx->pq_auth_len > 0) {
        required += 4 + tx->pq_auth_len;
    }
    if (buf_cap < required) {
        return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    }

    /* Core 128 bytes */
    memset(out_buf, 0, 128);
    memcpy(out_buf, tx->sender_pubkey, 32);
    le_put_u64(out_buf + 32, tx->amount);
    le_put_u64(out_buf + 40, tx->fee);
    le_put_u64(out_buf + 48, tx->nonce);
    le_put_u64(out_buf + 56, 0); /* reserved = 0 */
    memcpy(out_buf + 64, tx->recipient_pubkey, 32);
    if (tx->payload && tx->payload_len > 0) {
        size_t head = tx->payload_len < 32 ? tx->payload_len : 32;
        memcpy(out_buf + 96, tx->payload, head);
    }

    /* Trailer */
    size_t off = 128;
    out_buf[off++] = tx->type;
    le_put_u16(out_buf + off, tx->payload_len);
    off += 2;

    if (overflow > 0 && tx->payload) {
        memcpy(out_buf + off, tx->payload + 32, overflow);
        off += overflow;
    }

    out_buf[off++] = tx->from_len;
    if (tx->from_len > 0 && tx->from) {
        memcpy(out_buf + off, tx->from, tx->from_len);
        off += tx->from_len;
    }

    out_buf[off++] = tx->to_len;
    if (tx->to_len > 0 && tx->to) {
        memcpy(out_buf + off, tx->to, tx->to_len);
        off += tx->to_len;
    }

    memcpy(out_buf + off, tx->sig, 64);
    off += 64;
    memcpy(out_buf + off, tx->hash, 32);
    off += 32;
    memcpy(out_buf + off, tx->genesis_hash, 32);
    off += 32;
    le_put_u32(out_buf + off, tx->shard_id);
    off += 4;

    if (tx->pq_auth_len > 0 && tx->pq_auth) {
        le_put_u32(out_buf + off, tx->pq_auth_len);
        off += 4;
        memcpy(out_buf + off, tx->pq_auth, tx->pq_auth_len);
        off += tx->pq_auth_len;
    }

    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_tx_decode(const uint8_t *data, size_t len,
                                   wire_transaction_t *tx) {
    if (!data || !tx) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    if (len < 128 + 1 + 2) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }

    memcpy(tx->sender_pubkey, data, 32);
    tx->amount = le_get_u64(data + 32);
    tx->fee    = le_get_u64(data + 40);
    tx->nonce  = le_get_u64(data + 48);
    uint64_t reserved = le_get_u64(data + 56);
    if (reserved != 0) {
        return WIRE_CODEC_ERR_NONZERO_RESERVED;
    }
    memcpy(tx->recipient_pubkey, data + 64, 32);

    size_t off = 128;
    tx->type = data[off++];
    tx->payload_len = le_get_u16(data + off);
    off += 2;

    if (tx->payload_len <= 32) {
        tx->payload = data + 96;
    } else {
        size_t overflow = tx->payload_len - 32;
        if (off + overflow > len) {
            return WIRE_CODEC_ERR_TRUNCATED;
        }
        /* Caller can inspect 32 bytes at data+96 and remainder at data+off */
        tx->payload = data + 96;
        off += overflow;
    }

    if (off >= len) return WIRE_CODEC_ERR_TRUNCATED;
    tx->from_len = data[off++];
    if (off + tx->from_len > len) return WIRE_CODEC_ERR_TRUNCATED;
    tx->from = (const char *)(data + off);
    off += tx->from_len;

    if (off >= len) return WIRE_CODEC_ERR_TRUNCATED;
    tx->to_len = data[off++];
    if (off + tx->to_len > len) return WIRE_CODEC_ERR_TRUNCATED;
    tx->to = (const char *)(data + off);
    off += tx->to_len;

    if (off + 64 + 32 + 32 + 4 > len) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }
    memcpy(tx->sig, data + off, 64);
    off += 64;
    memcpy(tx->hash, data + off, 32);
    off += 32;
    memcpy(tx->genesis_hash, data + off, 32);
    off += 32;
    tx->shard_id = le_get_u32(data + off);
    off += 4;

    tx->pq_auth = NULL;
    tx->pq_auth_len = 0;
    if (off != len) {
        if (off + 4 > len) {
            return WIRE_CODEC_ERR_TRUNCATED;
        }
        uint32_t pq_len = le_get_u32(data + off);
        off += 4;
        if (pq_len == 0 || off + pq_len != len) {
            return WIRE_CODEC_ERR_TRAILING_BYTES;
        }
        tx->pq_auth = data + off;
        tx->pq_auth_len = pq_len;
        off += pq_len;
    }

    return WIRE_CODEC_OK;
}

/* ─── 4. BLOCK_SIG (MsgType 3) ──────────────────────────────────────────── */

wire_codec_status_t wire_block_sig_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_block_sig_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t required = 8 + 1 + msg->signer_len + 32 + 32 + 64;
    if (buf_cap < required) {
        return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = 0;
    le_put_u64(out_buf + off, msg->block_index);
    off += 8;
    out_buf[off++] = msg->signer_len;
    if (msg->signer_len > 0 && msg->signer) {
        memcpy(out_buf + off, msg->signer, msg->signer_len);
        off += msg->signer_len;
    }
    memcpy(out_buf + off, msg->delay_output, 32);
    off += 32;
    memcpy(out_buf + off, msg->dh_secret, 32);
    off += 32;
    memcpy(out_buf + off, msg->ed_sig, 64);
    off += 64;
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_block_sig_decode(const uint8_t *data, size_t len,
                                          wire_block_sig_t *msg) {
    if (!data || !msg) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    if (len < 8 + 1) {
        return WIRE_CODEC_ERR_TRUNCATED;
    }
    size_t off = 0;
    msg->block_index = le_get_u64(data + off);
    off += 8;
    msg->signer_len = data[off++];
    if (off + msg->signer_len + 32 + 32 + 64 != len) {
        return (off + msg->signer_len + 32 + 32 + 64 > len) ? WIRE_CODEC_ERR_TRUNCATED
                                                             : WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    msg->signer = (const char *)(data + off);
    off += msg->signer_len;
    memcpy(msg->delay_output, data + off, 32);
    off += 32;
    memcpy(msg->dh_secret, data + off, 32);
    off += 32;
    memcpy(msg->ed_sig, data + off, 64);
    return WIRE_CODEC_OK;
}

/* ─── 5. CONTRIB (MsgType 4) ────────────────────────────────────────────── */

wire_codec_status_t wire_contrib_encode(uint8_t *out_buf, size_t buf_cap,
                                        const wire_contrib_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t required = 8 + 1 + msg->signer_len + 32 + 8 +
                      2 + (size_t)msg->tx_hash_count * 32 +
                      32 + 32 + 32 + 32 +
                      2 + (size_t)msg->view_eq_count * 32 +
                      2 + (size_t)msg->view_abort_count * 32 +
                      2 + (size_t)msg->view_inbound_count * 32 +
                      8 + 32 +
                      2 + (size_t)msg->view_shardtip_count * 32 +
                      64;
    if (buf_cap < required) {
        return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    }
    size_t off = 0;
    le_put_u64(out_buf + off, msg->block_index); off += 8;
    out_buf[off++] = msg->signer_len;
    if (msg->signer_len > 0 && msg->signer) {
        memcpy(out_buf + off, msg->signer, msg->signer_len);
        off += msg->signer_len;
    }
    memcpy(out_buf + off, msg->prev_hash, 32); off += 32;
    le_put_u64(out_buf + off, msg->aborts_gen); off += 8;

    le_put_u16(out_buf + off, msg->tx_hash_count); off += 2;
    if (msg->tx_hash_count > 0 && msg->tx_hashes) {
        memcpy(out_buf + off, msg->tx_hashes, (size_t)msg->tx_hash_count * 32);
        off += (size_t)msg->tx_hash_count * 32;
    }

    memcpy(out_buf + off, msg->dh_input, 32); off += 32;
    memcpy(out_buf + off, msg->view_eq_root, 32); off += 32;
    memcpy(out_buf + off, msg->view_abort_root, 32); off += 32;
    memcpy(out_buf + off, msg->view_inbound_root, 32); off += 32;

    le_put_u16(out_buf + off, msg->view_eq_count); off += 2;
    if (msg->view_eq_count > 0 && msg->view_eq_list) {
        memcpy(out_buf + off, msg->view_eq_list, (size_t)msg->view_eq_count * 32);
        off += (size_t)msg->view_eq_count * 32;
    }

    le_put_u16(out_buf + off, msg->view_abort_count); off += 2;
    if (msg->view_abort_count > 0 && msg->view_abort_list) {
        memcpy(out_buf + off, msg->view_abort_list, (size_t)msg->view_abort_count * 32);
        off += (size_t)msg->view_abort_count * 32;
    }

    le_put_u16(out_buf + off, msg->view_inbound_count); off += 2;
    if (msg->view_inbound_count > 0 && msg->view_inbound_list) {
        memcpy(out_buf + off, msg->view_inbound_list, (size_t)msg->view_inbound_count * 32);
        off += (size_t)msg->view_inbound_count * 32;
    }

    le_put_u64(out_buf + off, msg->proposer_time); off += 8;
    memcpy(out_buf + off, msg->view_shardtip_root, 32); off += 32;

    le_put_u16(out_buf + off, msg->view_shardtip_count); off += 2;
    if (msg->view_shardtip_count > 0 && msg->view_shardtip_list) {
        memcpy(out_buf + off, msg->view_shardtip_list, (size_t)msg->view_shardtip_count * 32);
        off += (size_t)msg->view_shardtip_count * 32;
    }

    memcpy(out_buf + off, msg->ed_sig, 64); off += 64;
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_contrib_decode(const uint8_t *data, size_t len,
                                        wire_contrib_t *msg) {
    if (!data || !msg) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t off = 0;
    if (len < 8 + 1) return WIRE_CODEC_ERR_TRUNCATED;
    msg->block_index = le_get_u64(data + off); off += 8;
    msg->signer_len = data[off++];
    if (off + msg->signer_len + 32 + 8 + 2 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->signer = (const char *)(data + off); off += msg->signer_len;

    memcpy(msg->prev_hash, data + off, 32); off += 32;
    msg->aborts_gen = le_get_u64(data + off); off += 8;

    msg->tx_hash_count = le_get_u16(data + off); off += 2;
    size_t tx_bytes = (size_t)msg->tx_hash_count * 32;
    if (off + tx_bytes + 32*4 + 2 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->tx_hashes = data + off; off += tx_bytes;

    memcpy(msg->dh_input, data + off, 32); off += 32;
    memcpy(msg->view_eq_root, data + off, 32); off += 32;
    memcpy(msg->view_abort_root, data + off, 32); off += 32;
    memcpy(msg->view_inbound_root, data + off, 32); off += 32;

    msg->view_eq_count = le_get_u16(data + off); off += 2;
    size_t eq_bytes = (size_t)msg->view_eq_count * 32;
    if (off + eq_bytes + 2 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->view_eq_list = data + off; off += eq_bytes;

    msg->view_abort_count = le_get_u16(data + off); off += 2;
    size_t ab_bytes = (size_t)msg->view_abort_count * 32;
    if (off + ab_bytes + 2 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->view_abort_list = data + off; off += ab_bytes;

    msg->view_inbound_count = le_get_u16(data + off); off += 2;
    size_t in_bytes = (size_t)msg->view_inbound_count * 32;
    if (off + in_bytes + 8 + 32 + 2 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->view_inbound_list = data + off; off += in_bytes;

    msg->proposer_time = le_get_u64(data + off); off += 8;
    memcpy(msg->view_shardtip_root, data + off, 32); off += 32;

    msg->view_shardtip_count = le_get_u16(data + off); off += 2;
    size_t st_bytes = (size_t)msg->view_shardtip_count * 32;
    if (off + st_bytes + 64 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->view_shardtip_list = data + off; off += st_bytes;

    memcpy(msg->ed_sig, data + off, 64); off += 64;
    if (off != len) return WIRE_CODEC_ERR_TRAILING_BYTES;

    return WIRE_CODEC_OK;
}

/* ─── 6. Request & Status Frames ────────────────────────────────────────── */

wire_codec_status_t wire_get_chain_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_get_chain_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 10) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u64(out_buf, msg->from);
    le_put_u16(out_buf + 8, msg->count);
    *out_written = 10;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_get_chain_decode(const uint8_t *data, size_t len,
                                          wire_get_chain_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len != 10) return (len < 10) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    msg->from = le_get_u64(data);
    msg->count = le_get_u16(data + 8);
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_status_response_encode(uint8_t *out_buf, size_t buf_cap,
                                                const wire_status_response_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (msg->genesis_len != 0 && msg->genesis_len != 64) return WIRE_CODEC_ERR_INVALID_FIELD;
    size_t required = 8 + 1 + (size_t)msg->genesis_len;
    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u64(out_buf, msg->height);
    out_buf[8] = msg->genesis_len;
    if (msg->genesis_len == 64 && msg->genesis_hex) {
        memcpy(out_buf + 9, msg->genesis_hex, 64);
    }
    *out_written = required;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_status_response_decode(const uint8_t *data, size_t len,
                                                wire_status_response_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 9) return WIRE_CODEC_ERR_TRUNCATED;
    msg->height = le_get_u64(data);
    msg->genesis_len = data[8];
    if (msg->genesis_len != 0 && msg->genesis_len != 64) return WIRE_CODEC_ERR_INVALID_FIELD;
    if (len != 9 + (size_t)msg->genesis_len) {
        return (len < 9 + (size_t)msg->genesis_len) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    msg->genesis_hex = (msg->genesis_len == 64) ? (const char *)(data + 9) : NULL;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_snapshot_req_encode(uint8_t *out_buf, size_t buf_cap,
                                             const wire_snapshot_req_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 4) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u32(out_buf, msg->headers);
    *out_written = 4;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_snapshot_req_decode(const uint8_t *data, size_t len,
                                             wire_snapshot_req_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len != 4) return (len < 4) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    msg->headers = le_get_u32(data);
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_headers_req_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_headers_req_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 12) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u64(out_buf, msg->from);
    le_put_u32(out_buf + 8, msg->count);
    *out_written = 12;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_headers_req_decode(const uint8_t *data, size_t len,
                                            wire_headers_req_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len != 12) return (len < 12) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    msg->from = le_get_u64(data);
    msg->count = le_get_u32(data + 8);
    return WIRE_CODEC_OK;
}

/* ─── 7. ABORT_CLAIM & ABORT_EVENT ───────────────────────────────────────── */

wire_codec_status_t wire_abort_claim_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_abort_claim_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    /* shared encode_abort_claims blob with count=1: u16 count (2) + fields */
    size_t required = 2 + 8 + 1 + 32 + 64 + 1 + msg->missing_creator_len + 1 + msg->claimer_len;
    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    size_t off = 0;
    le_put_u16(out_buf + off, 1); off += 2;
    le_put_u64(out_buf + off, msg->block_index); off += 8;
    out_buf[off++] = msg->round;
    memcpy(out_buf + off, msg->prev_hash, 32); off += 32;
    memcpy(out_buf + off, msg->ed_sig, 64); off += 64;
    out_buf[off++] = msg->missing_creator_len;
    if (msg->missing_creator_len > 0 && msg->missing_creator) {
        memcpy(out_buf + off, msg->missing_creator, msg->missing_creator_len);
        off += msg->missing_creator_len;
    }
    out_buf[off++] = msg->claimer_len;
    if (msg->claimer_len > 0 && msg->claimer) {
        memcpy(out_buf + off, msg->claimer, msg->claimer_len);
        off += msg->claimer_len;
    }
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_abort_claim_decode(const uint8_t *data, size_t len,
                                            wire_abort_claim_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 2 + 8 + 1 + 32 + 64 + 1) return WIRE_CODEC_ERR_TRUNCATED;
    size_t off = 0;
    uint16_t count = le_get_u16(data + off); off += 2;
    if (count != 1) return WIRE_CODEC_ERR_INVALID_FIELD;
    msg->block_index = le_get_u64(data + off); off += 8;
    msg->round = data[off++];
    memcpy(msg->prev_hash, data + off, 32); off += 32;
    memcpy(msg->ed_sig, data + off, 64); off += 64;
    msg->missing_creator_len = data[off++];
    if (off + msg->missing_creator_len + 1 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->missing_creator = (const char *)(data + off); off += msg->missing_creator_len;
    msg->claimer_len = data[off++];
    if (off + msg->claimer_len != len) {
        return (off + msg->claimer_len > len) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    msg->claimer = (const char *)(data + off);
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_abort_event_encode(uint8_t *out_buf, size_t buf_cap,
                                            const wire_abort_event_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    size_t required = 8 + 32 + 1 + 1 + msg->aborting_node_len + 8 + 32 + msg->claims_blob_len;
    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    size_t off = 0;
    le_put_u64(out_buf + off, msg->block_index); off += 8;
    memcpy(out_buf + off, msg->prev_hash, 32); off += 32;
    out_buf[off++] = msg->round;
    out_buf[off++] = msg->aborting_node_len;
    if (msg->aborting_node_len > 0 && msg->aborting_node) {
        memcpy(out_buf + off, msg->aborting_node, msg->aborting_node_len);
        off += msg->aborting_node_len;
    }
    le_put_u64(out_buf + off, msg->timestamp); off += 8;
    memcpy(out_buf + off, msg->event_hash, 32); off += 32;
    if (msg->claims_blob_len > 0 && msg->claims_blob) {
        memcpy(out_buf + off, msg->claims_blob, msg->claims_blob_len);
        off += msg->claims_blob_len;
    }
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_abort_event_decode(const uint8_t *data, size_t len,
                                            wire_abort_event_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 8 + 32 + 1 + 1) return WIRE_CODEC_ERR_TRUNCATED;
    size_t off = 0;
    msg->block_index = le_get_u64(data + off); off += 8;
    memcpy(msg->prev_hash, data + off, 32); off += 32;
    msg->round = data[off++];
    msg->aborting_node_len = data[off++];
    if (off + msg->aborting_node_len + 8 + 32 > len) return WIRE_CODEC_ERR_TRUNCATED;
    msg->aborting_node = (const char *)(data + off); off += msg->aborting_node_len;
    msg->timestamp = le_get_u64(data + off); off += 8;
    memcpy(msg->event_hash, data + off, 32); off += 32;
    msg->claims_blob = data + off;
    msg->claims_blob_len = len - off;
    return WIRE_CODEC_OK;
}

/* ─── 8. EQUIVOCATION_EVIDENCE ──────────────────────────────────────────── */

wire_codec_status_t wire_equivocation_encode(uint8_t *out_buf, size_t buf_cap,
                                             const wire_equivocation_evidence_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (msg->kind > 1) return WIRE_CODEC_ERR_INVALID_FIELD;
    size_t required = 1 + msg->equivocator_len + 8 + 1 + 8 + 8 + 32 + 64 + 8 + 8 + 32 + 64 + 4 + 8;
    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    size_t off = 0;
    out_buf[off++] = msg->equivocator_len;
    if (msg->equivocator_len > 0 && msg->equivocator) {
        memcpy(out_buf + off, msg->equivocator, msg->equivocator_len);
        off += msg->equivocator_len;
    }
    le_put_u64(out_buf + off, msg->block_index); off += 8;
    out_buf[off++] = msg->kind;
    le_put_u64(out_buf + off, msg->index_a); off += 8;
    le_put_u64(out_buf + off, msg->gen_a); off += 8;
    memcpy(out_buf + off, msg->body_root_a, 32); off += 32;
    memcpy(out_buf + off, msg->sig_a, 64); off += 64;
    le_put_u64(out_buf + off, msg->index_b); off += 8;
    le_put_u64(out_buf + off, msg->gen_b); off += 8;
    memcpy(out_buf + off, msg->body_root_b, 32); off += 32;
    memcpy(out_buf + off, msg->sig_b, 64); off += 64;
    le_put_u32(out_buf + off, msg->shard_id); off += 4;
    le_put_u64(out_buf + off, msg->beacon_anchor_height); off += 8;
    *out_written = off;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_equivocation_decode(const uint8_t *data, size_t len,
                                             wire_equivocation_evidence_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 1) return WIRE_CODEC_ERR_TRUNCATED;
    size_t off = 0;
    msg->equivocator_len = data[off++];
    /* Fixed remaining length: 8 + 1 + (8+8+32+64)*2 + 4 + 8 = 245 */
    if (off + msg->equivocator_len + 245 != len) {
        return (off + msg->equivocator_len + 245 > len) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    msg->equivocator = (const char *)(data + off); off += msg->equivocator_len;
    msg->block_index = le_get_u64(data + off); off += 8;
    msg->kind = data[off++];
    if (msg->kind > 1) return WIRE_CODEC_ERR_INVALID_FIELD;
    msg->index_a = le_get_u64(data + off); off += 8;
    msg->gen_a = le_get_u64(data + off); off += 8;
    memcpy(msg->body_root_a, data + off, 32); off += 32;
    memcpy(msg->sig_a, data + off, 64); off += 64;
    msg->index_b = le_get_u64(data + off); off += 8;
    msg->gen_b = le_get_u64(data + off); off += 8;
    memcpy(msg->body_root_b, data + off, 32); off += 32;
    memcpy(msg->sig_b, data + off, 64); off += 64;
    msg->shard_id = le_get_u32(data + off); off += 4;
    msg->beacon_anchor_height = le_get_u64(data + off);
    return WIRE_CODEC_OK;
}

/* ─── 9. Block-Carrying Payload Frames ──────────────────────────────────── */

wire_codec_status_t wire_shard_tip_encode(uint8_t *out_buf, size_t buf_cap,
                                          const wire_shard_tip_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 4 + msg->block_frame_len) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u32(out_buf, msg->shard_id);
    if (msg->block_frame_len > 0 && msg->block_frame) {
        memcpy(out_buf + 4, msg->block_frame, msg->block_frame_len);
    }
    *out_written = 4 + msg->block_frame_len;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_shard_tip_decode(const uint8_t *data, size_t len,
                                          wire_shard_tip_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 4) return WIRE_CODEC_ERR_TRUNCATED;
    msg->shard_id = le_get_u32(data);
    msg->block_frame = data + 4;
    msg->block_frame_len = len - 4;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_receipt_bundle_encode(uint8_t *out_buf, size_t buf_cap,
                                               const wire_receipt_bundle_t *msg, size_t *out_written) {
    if (!out_buf || !msg || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 4 + msg->block_frame_len) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    le_put_u32(out_buf, msg->src_shard);
    if (msg->block_frame_len > 0 && msg->block_frame) {
        memcpy(out_buf + 4, msg->block_frame, msg->block_frame_len);
    }
    *out_written = 4 + msg->block_frame_len;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_receipt_bundle_decode(const uint8_t *data, size_t len,
                                               wire_receipt_bundle_t *msg) {
    if (!data || !msg) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 4) return WIRE_CODEC_ERR_TRUNCATED;
    msg->src_shard = le_get_u32(data);
    msg->block_frame = data + 4;
    msg->block_frame_len = len - 4;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_chain_response_decode_header(const uint8_t *data, size_t len,
                                                     wire_chain_response_t *resp) {
    if (!data || !resp) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 1 + 2) return WIRE_CODEC_ERR_TRUNCATED;
    resp->has_more = data[0];
    if (resp->has_more > 1) return WIRE_CODEC_ERR_INVALID_FIELD;
    resp->block_count = le_get_u16(data + 1);
    resp->blocks_data = data + 3;
    resp->blocks_data_len = len - 3;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_chain_response_next_block(const uint8_t *blocks_data, size_t total_len,
                                                  size_t *cursor,
                                                  const uint8_t **out_block_frame,
                                                  uint32_t *out_block_frame_len) {
    if (!blocks_data || !cursor || !out_block_frame || !out_block_frame_len) {
        return WIRE_CODEC_ERR_INVALID_ARG;
    }
    size_t off = *cursor;
    if (off >= total_len) return WIRE_CODEC_ERR_TRUNCATED;
    if (off + 4 > total_len) return WIRE_CODEC_ERR_TRUNCATED;
    uint32_t flen = le_get_u32(blocks_data + off); off += 4;
    if (flen > total_len || off > total_len - flen) return WIRE_CODEC_ERR_TRUNCATED;
    *out_block_frame = blocks_data + off;
    *out_block_frame_len = flen;
    *cursor = off + flen;
    return WIRE_CODEC_OK;
}

/* ─── 10. Canonical Storage & Container Records ─────────────────────────── */

wire_codec_status_t wire_manifest_encode(uint8_t *out_buf, size_t buf_cap,
                                         const wire_manifest_t *m, size_t *out_written) {
    if (!out_buf || !m || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < WIRE_MANIFEST_BYTES) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    out_buf[0] = 'D';
    out_buf[1] = 'M';
    out_buf[2] = 'F';
    out_buf[3] = '1';
    le_put_u64(out_buf + 4, m->height);
    memcpy(out_buf + 12, m->head_hash, 32);
    *out_written = WIRE_MANIFEST_BYTES;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_manifest_decode(const uint8_t *data, size_t len,
                                         wire_manifest_t *m) {
    if (!data || !m) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len != WIRE_MANIFEST_BYTES) {
        return (len < WIRE_MANIFEST_BYTES) ? WIRE_CODEC_ERR_TRUNCATED : WIRE_CODEC_ERR_TRAILING_BYTES;
    }
    if (memcmp(data, "DMF1", 4) != 0) return WIRE_CODEC_ERR_BAD_MAGIC;
    m->height = le_get_u64(data + 4);
    memcpy(m->head_hash, data + 12, 32);
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_dbk1_wrap(uint8_t *out_buf, size_t buf_cap,
                                   const uint8_t *block_frame, size_t block_frame_len,
                                   size_t *out_written) {
    if (!out_buf || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    if (buf_cap < 4 + block_frame_len) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    out_buf[0] = 'D';
    out_buf[1] = 'B';
    out_buf[2] = 'K';
    out_buf[3] = '1';
    if (block_frame_len > 0 && block_frame) {
        memcpy(out_buf + 4, block_frame, block_frame_len);
    }
    *out_written = 4 + block_frame_len;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_dbk1_unwrap(const uint8_t *data, size_t len,
                                     const uint8_t **out_block_frame,
                                     size_t *out_block_frame_len) {
    if (!data || !out_block_frame || !out_block_frame_len) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 4) return WIRE_CODEC_ERR_TRUNCATED;
    if (memcmp(data, "DBK1", 4) != 0) return WIRE_CODEC_ERR_BAD_MAGIC;
    *out_block_frame = data + 4;
    *out_block_frame_len = len - 4;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_headers_response_decode_header(const uint8_t *data, size_t len,
                                                        wire_headers_response_t *resp) {
    if (!data || !resp) return WIRE_CODEC_ERR_INVALID_ARG;
    if (len < 8 + 8 + 2) return WIRE_CODEC_ERR_TRUNCATED;
    resp->from = le_get_u64(data);
    resp->height = le_get_u64(data + 8);
    resp->count = le_get_u16(data + 16);
    if (resp->count > WIRE_HEADERS_PAGE_MAX) return WIRE_CODEC_ERR_CAP_EXCEEDED;
    resp->headers_data = data + 18;
    resp->headers_data_len = len - 18;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_headers_response_next_record(const uint8_t *headers_data, size_t total_len,
                                                      size_t *cursor,
                                                      wire_header_record_t *out_rec) {
    if (!headers_data || !cursor || !out_rec) return WIRE_CODEC_ERR_INVALID_ARG;
    size_t off = *cursor;
    /* DHF1 record: magic 4 + block_hash 32 + frame_len 4 */
    if (off >= total_len) return WIRE_CODEC_ERR_TRUNCATED;
    if (off + 40 > total_len) return WIRE_CODEC_ERR_TRUNCATED;
    if (memcmp(headers_data + off, "DHF1", 4) != 0) return WIRE_CODEC_ERR_BAD_MAGIC;
    off += 4;
    memcpy(out_rec->block_hash, headers_data + off, 32); off += 32;
    uint32_t flen = le_get_u32(headers_data + off); off += 4;
    if (flen > total_len || off > total_len - flen) return WIRE_CODEC_ERR_TRUNCATED;
    out_rec->frame_len = flen;
    out_rec->block_frame = headers_data + off;
    *cursor = off + flen;
    return WIRE_CODEC_OK;
}

wire_codec_status_t wire_dhf1_record_encode(uint8_t *out_buf, size_t buf_cap,
                                            const uint8_t block_hash[32],
                                            const uint8_t *block_frame, uint32_t block_frame_len,
                                            size_t *out_written) {
    if (!out_buf || !block_hash || !out_written) return WIRE_CODEC_ERR_INVALID_ARG;
    size_t required = 4 + 32 + 4 + block_frame_len;
    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;
    out_buf[0] = 'D';
    out_buf[1] = 'H';
    out_buf[2] = 'F';
    out_buf[3] = '1';
    memcpy(out_buf + 4, block_hash, 32);
    le_put_u32(out_buf + 36, block_frame_len);
    if (block_frame_len > 0 && block_frame) {
        memcpy(out_buf + 40, block_frame, block_frame_len);
    }
    *out_written = required;
    return WIRE_CODEC_OK;
}
