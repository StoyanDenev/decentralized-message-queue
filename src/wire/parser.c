/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Strict Canonicalization Wire Defenses (Phase 3: C99 Bare-Metal)
 */

#include <determ/wire/parser.h>
#include <determ/crypto/sha2/sha2.h>
#include <string.h>
#include <unistd.h>

static inline uint16_t read_be16(const uint8_t *b) {
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline uint32_t read_be32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           ((uint32_t)b[3]);
}

static inline uint64_t read_be64(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) |
           ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) |
           ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  |
           ((uint64_t)b[7]);
}


static inline void write_be32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static inline void write_be64(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len) {
    if (!field && len > 0) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    if (len > max_len) {
        return ERR_BUFFER_OVERFLOW;
    }

    for (size_t i = 0; i < len; ++i) {
        uint8_t c = field[i];

        /* Surgical elimination of the NUL-Byte Ghost */
        if (c == 0x00) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }

        /* Whitelist: [a-z, 0-9, '.', '-', '_'] */
        bool is_lower = (c >= 'a' && c <= 'z');
        bool is_digit = (c >= '0' && c <= '9');
        bool is_punct = (c == '.' || c == '-' || c == '_');

        if (!is_lower && !is_digit && !is_punct) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }
    }

    return WIRE_OK;
}

wire_status_t wire_parse_transaction(const uint8_t *data, size_t data_len, wire_tx_t *out_tx) {
    if (!data || !out_tx) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    /* Minimum format: 1 (type) + 2 + 0 + 2 + 0 + 2 + 0 + 8 + 8 + 8 + 4 + 0 = 35 bytes */
    if (data_len < 35) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    memset(out_tx, 0, sizeof(*out_tx));
    size_t offset = 0;

    /* 1. Transaction type (1 byte) */
    out_tx->type = data[offset++];

    /* 2. 'from' address [2-byte BE length + bytes] */
    if (offset + 2 > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    uint16_t from_len = read_be16(&data[offset]);
    offset += 2;
    if (from_len > WIRE_MAX_ADDR_LEN || offset + from_len > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    if (from_len > 0) {
        if (wire_validate_charset_strict(&data[offset], from_len, WIRE_MAX_ADDR_LEN) != WIRE_OK) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }
        memcpy(out_tx->from, &data[offset], from_len);
        offset += from_len;
    }
    out_tx->from_len = from_len;

    /* 3. 'to' address [2-byte BE length + bytes] */
    if (offset + 2 > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    uint16_t to_len = read_be16(&data[offset]);
    offset += 2;
    if (to_len > WIRE_MAX_ADDR_LEN || offset + to_len > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    if (to_len > 0) {
        if (wire_validate_charset_strict(&data[offset], to_len, WIRE_MAX_ADDR_LEN) != WIRE_OK) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }
        memcpy(out_tx->to, &data[offset], to_len);
        offset += to_len;
    }
    out_tx->to_len = to_len;

    /* 4. 'domain' identifier [2-byte BE length + bytes] */
    if (offset + 2 > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    uint16_t domain_len = read_be16(&data[offset]);
    offset += 2;
    if (domain_len > WIRE_MAX_DOMAIN_LEN || offset + domain_len > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    if (domain_len > 0) {
        if (wire_validate_charset_strict(&data[offset], domain_len, WIRE_MAX_DOMAIN_LEN) != WIRE_OK) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }
        memcpy(out_tx->domain, &data[offset], domain_len);
        offset += domain_len;
    }
    out_tx->domain_len = domain_len;

    /* 5. Scalar values: amount(8), fee(8), nonce(8) */
    if (offset + 24 > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    out_tx->amount = read_be64(&data[offset]);
    offset += 8;
    out_tx->fee    = read_be64(&data[offset]);
    offset += 8;
    out_tx->nonce  = read_be64(&data[offset]);
    offset += 8;

    /* 6. Variable payload [4-byte BE length + bytes] */
    if (offset + 4 > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    uint32_t payload_len = read_be32(&data[offset]);
    offset += 4;
    if (payload_len > WIRE_MAX_PAYLOAD_LEN || offset + payload_len > data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }
    if (payload_len > 0) {
        memcpy(out_tx->payload, &data[offset], payload_len);
        offset += payload_len;
    }
    out_tx->payload_len = payload_len;

    /* Exact consumption check: no trailing unparsed bytes permitted */
    if (offset != data_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    return WIRE_OK;
}

wire_status_t wire_bundle_vdf_input(const uint8_t *reveal_a, uint32_t len_a,
                                    const uint8_t *reveal_b, uint32_t len_b,
                                    uint8_t *out_buf, size_t max_out_len,
                                    size_t *out_written_len) {
    if (!out_buf || !out_written_len) {
        return ERR_INVALID_ARGUMENT;
    }
    if ((!reveal_a && len_a > 0) || (!reveal_b && len_b > 0)) {
        return ERR_INVALID_ARGUMENT;
    }

    if (len_a > WIRE_MAX_PAYLOAD_LEN || len_b > WIRE_MAX_PAYLOAD_LEN) {
        return ERR_BUFFER_OVERFLOW;
    }

    size_t offset = 0;

    /* Strict check for reveal A */
    size_t parsed_length = 4 + (size_t)len_a;
    if (offset + parsed_length > 131104) {
        return ERR_BUFFER_OVERFLOW;
    }
    if (offset + parsed_length > max_out_len) {
        return ERR_BUFFER_OVERFLOW;
    }
    write_be32(&out_buf[offset], len_a);
    offset += 4;
    if (len_a > 0 && reveal_a) {
        memcpy(&out_buf[offset], reveal_a, len_a);
        offset += len_a;
    }

    /* Strict check for reveal B */
    parsed_length = 4 + (size_t)len_b;
    if (offset + parsed_length > 131104) {
        return ERR_BUFFER_OVERFLOW;
    }
    if (offset + parsed_length > max_out_len) {
        return ERR_BUFFER_OVERFLOW;
    }
    write_be32(&out_buf[offset], len_b);
    offset += 4;
    if (len_b > 0 && reveal_b) {
        memcpy(&out_buf[offset], reveal_b, len_b);
        offset += len_b;
    }

    *out_written_len = offset;
    return WIRE_OK;
}

wire_status_t wire_concat_reveals_stream(const uint8_t *reveal_a, uint32_t len_a,
                                         const uint8_t *reveal_b, uint32_t len_b,
                                         uint8_t *bundle_out, size_t max_bundle_len,
                                         size_t *out_written_len, int socket_fd) {
    if (!bundle_out || !out_written_len) {
        if (socket_fd >= 0) { close(socket_fd); }
        return ERR_INVALID_ARGUMENT;
    }

    size_t offset = 0;
    size_t parsed_length = 4 + (size_t)len_a;
    if (offset + parsed_length > 131104) {
        if (socket_fd >= 0) { close(socket_fd); }
        return ERR_BUFFER_OVERFLOW;
    }
    if (offset + parsed_length > max_bundle_len) {
        if (socket_fd >= 0) { close(socket_fd); }
        return ERR_BUFFER_OVERFLOW;
    }
    write_be32(&bundle_out[offset], len_a);
    offset += 4;
    if (len_a > 0 && reveal_a) {
        memcpy(&bundle_out[offset], reveal_a, len_a);
        offset += len_a;
    }

    parsed_length = 4 + (size_t)len_b;
    if (offset + parsed_length > 131104) {
        if (socket_fd >= 0) { close(socket_fd); }
        return ERR_BUFFER_OVERFLOW;
    }
    if (offset + parsed_length > max_bundle_len) {
        if (socket_fd >= 0) { close(socket_fd); }
        return ERR_BUFFER_OVERFLOW;
    }
    write_be32(&bundle_out[offset], len_b);
    offset += 4;
    if (len_b > 0 && reveal_b) {
        memcpy(&bundle_out[offset], reveal_b, len_b);
        offset += len_b;
    }

    *out_written_len = offset;
    return WIRE_OK;
}

wire_status_t wire_parse_block_header(const uint8_t *data, size_t data_len,
                                      wire_block_header_t *out_hdr) {
    if (!data || !out_hdr || data_len < WIRE_BLOCK_HEADER_LEN) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    size_t offset = 0;
    out_hdr->height = read_be64(&data[offset]);
    offset += 8;

    memcpy(out_hdr->prev_hash, &data[offset], 32);
    offset += 32;

    memcpy(out_hdr->tx_root, &data[offset], 32);
    offset += 32;

    memcpy(out_hdr->dsso_root, &data[offset], 32);
    offset += 32;

    out_hdr->timestamp = read_be64(&data[offset]);
    offset += 8;

    memcpy(out_hdr->vrf_aggregator_proof, &data[offset], 32);
    offset += 32;

    memcpy(out_hdr->vrf_contributor_proof, &data[offset], 32);
    offset += 32;

    out_hdr->vdf_iterations = read_be32(&data[offset]);
    offset += 4;

    memcpy(out_hdr->vdf_proof, &data[offset], 32);
    offset += 32;

    return WIRE_OK;
}

wire_status_t wire_encode_block_header(const wire_block_header_t *hdr,
                                       uint8_t *out_buf, size_t max_out_len,
                                       size_t *out_written_len) {
    if (!hdr || !out_buf || !out_written_len || max_out_len < WIRE_BLOCK_HEADER_LEN) {
        return ERR_BUFFER_OVERFLOW;
    }

    size_t offset = 0;
    write_be64(&out_buf[offset], hdr->height);
    offset += 8;

    memcpy(&out_buf[offset], hdr->prev_hash, 32);
    offset += 32;

    memcpy(&out_buf[offset], hdr->tx_root, 32);
    offset += 32;

    memcpy(&out_buf[offset], hdr->dsso_root, 32);
    offset += 32;

    write_be64(&out_buf[offset], hdr->timestamp);
    offset += 8;

    memcpy(&out_buf[offset], hdr->vrf_aggregator_proof, 32);
    offset += 32;

    memcpy(&out_buf[offset], hdr->vrf_contributor_proof, 32);
    offset += 32;

    write_be32(&out_buf[offset], hdr->vdf_iterations);
    offset += 4;

    memcpy(&out_buf[offset], hdr->vdf_proof, 32);
    offset += 32;

    *out_written_len = offset;
    return WIRE_OK;
}

wire_status_t wire_bind_consensus_vdf_payload(uint64_t height,
                                              const uint8_t prev_hash[32],
                                              const uint8_t tx_root[32],
                                              const uint8_t dsso_root[32],
                                              uint64_t timestamp,
                                              uint8_t out_vdf_payload[32]) {
    if (!prev_hash || !tx_root || !dsso_root || !out_vdf_payload) {
        return ERR_INVALID_ARGUMENT;
    }

    uint8_t staging[8 + 32 + 32 + 32 + 8];
    write_be64(&staging[0], height);
    memcpy(&staging[8], prev_hash, 32);
    memcpy(&staging[40], tx_root, 32);
    memcpy(&staging[72], dsso_root, 32);
    write_be64(&staging[104], timestamp);

    determ_sha256(staging, sizeof(staging), out_vdf_payload);
    return WIRE_OK;
}
