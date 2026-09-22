/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 */
#include <determ/ledger/shard_routing.h>
#include <determ/crypto/sha2/sha2.h>
#include <string.h>

int shard_routing_init(shard_routing_config_t *out, uint32_t shard_count,
                       const uint8_t salt[32]) {
    shard_routing_config_t value;
    if (!out || !salt || shard_count == 0) return -1;
    memset(&value, 0, sizeof(value));
    value.shard_count = shard_count;
    memcpy(value.salt, salt, sizeof(value.salt));
    memcpy(out, &value, sizeof(value));
    return 0;
}

int shard_routing_for_pubkey(const shard_routing_config_t *config,
                             const uint8_t *pubkey, size_t pubkey_len,
                             uint32_t *out_shard) {
    static const char tag[] = "shard-route";
    static const char hex[] = "0123456789abcdef";
    uint8_t address[66], digest[32];
    determ_sha256_ctx hash;
    uint64_t folded = 0;
    size_t i;
    if (!config || !pubkey || !out_shard || pubkey_len != 32 || config->shard_count == 0)
        return -1;
    if (config->shard_count == 1) {
        *out_shard = 0;
        return 0;
    }
    address[0] = '0';
    address[1] = 'x';
    for (i = 0; i < 32; ++i) {
        address[2 + i * 2] = (uint8_t)hex[pubkey[i] >> 4];
        address[3 + i * 2] = (uint8_t)hex[pubkey[i] & 15];
    }
    determ_sha256_init(&hash);
    determ_sha256_update(&hash, config->salt, sizeof(config->salt));
    determ_sha256_update(&hash, (const uint8_t *)tag, sizeof(tag) - 1);
    determ_sha256_update(&hash, address, sizeof(address));
    determ_sha256_final(&hash, digest);
    for (i = 0; i < 8; ++i) folded = (folded << 8) | digest[i];
    *out_shard = (uint32_t)(folded % config->shard_count);
    return 0;
}
