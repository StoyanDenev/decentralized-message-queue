/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 * Read-only account routing under a caller-supplied fixed configuration.
 */
#ifndef DETERMINISTIC_LEDGER_SHARD_ROUTING_H
#define DETERMINISTIC_LEDGER_SHARD_ROUTING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t shard_count;
    uint8_t salt[32];
} shard_routing_config_t;

/* S must be in [1, UINT32_MAX]. No storage is allocated in proportion to S.
 * Copies the salt; caller input may subsequently change. Returns 0 on success,
 * -1 on invalid arguments. The output is unchanged on failure.
 * This configuration does not authenticate or load a chain's genesis.
 */
int shard_routing_init(shard_routing_config_t *out, uint32_t shard_count,
                       const uint8_t salt[32]);

/* Route the canonical anonymous address "0x" + lowercase hex(pubkey):
 * BE64(SHA256(salt || "shard-route" || address)[0:8]) modulo shard_count.
 * The pubkey must contain exactly 32 bytes. This maps the bytes without claiming
 * curve-key validity, ownership, eligibility, transaction admission or execution.
 * Returns 0 on success, -1 for invalid pointers/length/configuration. The shard
 * output is unchanged on failure. No input/configuration is modified.
 */
int shard_routing_for_pubkey(const shard_routing_config_t *config,
                             const uint8_t *pubkey, size_t pubkey_len,
                             uint32_t *out_shard);

#ifdef __cplusplus
}
#endif
#endif
