#include <determ/crypto/sha2/sha2.h>
/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Strict Canonicalization Wire Defenses (C99 Bare-Metal)
 */

#include <determ/wire/parser.h>
#include <string.h>

static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t read_be32(const uint8_t *p) {
    return (((uint32_t)p[0] << 24) |
            ((uint32_t)p[1] << 16) |
            ((uint32_t)p[2] << 8)  |
            ((uint32_t)p[3]));
}

static inline uint64_t read_be64(const uint8_t *p) {
    return (((uint64_t)p[0] << 56) |
            ((uint64_t)p[1] << 48) |
            ((uint64_t)p[2] << 40) |
            ((uint64_t)p[3] << 32) |
            ((uint64_t)p[4] << 24) |
            ((uint64_t)p[5] << 16) |
            ((uint64_t)p[6] << 8)  |
            ((uint64_t)p[7]));
}

static inline void write_be32(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)((val >> 24) & 0xFF);
    p[1] = (uint8_t)((val >> 16) & 0xFF);
    p[2] = (uint8_t)((val >> 8)  & 0xFF);
    p[3] = (uint8_t)(val & 0xFF);
}

wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len) {
    if (!field && len > 0) {
        return ERR_INVALID_ARGUMENT;
    }
    if (len > max_len) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    for (size_t i = 0; i < len; ++i) {
        uint8_t c = field[i];

        /*
         * The NUL-Byte Ghost Defense:
         * Reject any embedded 0x00 byte immediately before it reaches consensus.
         */
        if (c == 0x00) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }

        /* Strict alphanumeric and allowed canonical delimiters whitelist */
        bool valid = (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') ||
                     (c == '.') || (c == '-') || (c == '_');
        if (!valid) {
            return ERR_INVALID_TRANSACTION_FORMAT;
        }
    }

    return WIRE_OK;
}

wire_status_t wire_parse_transaction(const uint8_t *data, size_t data_len, wire_tx_t *out_tx) {
    if (!data || !out_tx) {
        return ERR_INVALID_ARGUMENT;
    }

    memset(out_tx, 0, sizeof(*out_tx));

    /* Minimum framing: type(1) + 3*len16(6) + 3*val64(24) + payload_len32(4) = 35 bytes */
    if (data_len < 35) {
        return ERR_INVALID_TRANSACTION_FORMAT;
    }

    size_t offset = 0;

    /* 1. Transaction Type (1 byte) */
    out_tx->type = data[offset++];

    /* 2. 'from' Address [2-byte BE length + bytes] */
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

    /* 3. 'to' Address [2-byte BE length + bytes] */
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

    /* 4. 'domain' [2-byte BE length + bytes] */
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

    /* Strict boundary check with overflow protection */
    size_t required = 4 + (size_t)len_a + 4 + (size_t)len_b;
    if (required > max_out_len) {
        return ERR_BUFFER_OVERFLOW;
    }

    size_t cursor = 0;

    /* Write BE32 length prefix + reveal A */
    write_be32(&out_buf[cursor], len_a);
    cursor += 4;
    if (len_a > 0) {
        memcpy(&out_buf[cursor], reveal_a, len_a);
        cursor += len_a;
    }

    /* Write BE32 length prefix + reveal B */
    write_be32(&out_buf[cursor], len_b);
    cursor += 4;
    if (len_b > 0) {
        memcpy(&out_buf[cursor], reveal_b, len_b);
        cursor += len_b;
    }

    *out_written_len = cursor;
    return WIRE_OK;
}


static inline void write_be64(uint8_t *p, uint64_t val) {
    p[0] = (uint8_t)((val >> 56) & 0xFF);
    p[1] = (uint8_t)((val >> 48) & 0xFF);
    p[2] = (uint8_t)((val >> 40) & 0xFF);
    p[3] = (uint8_t)((val >> 32) & 0xFF);
    p[4] = (uint8_t)((val >> 24) & 0xFF);
    p[5] = (uint8_t)((val >> 16) & 0xFF);
    p[6] = (uint8_t)((val >> 8)  & 0xFF);
    p[7] = (uint8_t)(val & 0xFF);
}

wire_status_t wire_parse_block_header(const uint8_t *data, size_t data_len,
                                      wire_block_header_t *out_hdr) {
    if (!data || !out_hdr) {
        return ERR_INVALID_ARGUMENT;
    }
    if (data_len < WIRE_BLOCK_HEADER_LEN) {
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
    if (!hdr || !out_buf || !out_written_len) {
        return ERR_INVALID_ARGUMENT;
    }
    if (max_out_len < WIRE_BLOCK_HEADER_LEN) {
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

    /* Deterministic serialization of consensus state roots: 8 + 32 + 32 + 32 + 8 = 112 bytes */
    uint8_t pre_image[112];
    size_t offset = 0;

    write_be64(&pre_image[offset], height);
    offset += 8;

    memcpy(&pre_image[offset], prev_hash, 32);
    offset += 32;

    memcpy(&pre_image[offset], tx_root, 32);
    offset += 32;

    memcpy(&pre_image[offset], dsso_root, 32);
    offset += 32;

    write_be64(&pre_image[offset], timestamp);
    offset += 8;

    determ_sha256(pre_image, sizeof(pre_image), out_vdf_payload);
    return WIRE_OK;
}
