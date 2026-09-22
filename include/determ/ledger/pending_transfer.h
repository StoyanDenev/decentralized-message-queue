/* SPDX-License-Identifier: Apache-2.0 */
#ifndef DETERM_LEDGER_PENDING_TRANSFER_H
#define DETERM_LEDGER_PENDING_TRANSFER_H

#include <determ/ledger/shard_routing.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PENDING_TRANSFER_FRAME_SIZE 397U
#define PENDING_TRANSFER_SIGNING_SIZE 195U
#define PENDING_TRANSFER_PER_SHARD 4U
#define PENDING_TRANSFER_MAX_SHARDS 8U

typedef enum {
    PENDING_TRANSFER_INSERTED = 0,
    PENDING_TRANSFER_REPLACED = 1,
    PENDING_TRANSFER_DUPLICATE = 2,
    PENDING_TRANSFER_ERR_ARGUMENT = -1,
    PENDING_TRANSFER_ERR_FRAME = -2,
    PENDING_TRANSFER_ERR_GENESIS = -3,
    PENDING_TRANSFER_ERR_SOURCE_SHARD = -4,
    PENDING_TRANSFER_ERR_CROSS_SHARD = -5,
    PENDING_TRANSFER_ERR_HASH = -6,
    PENDING_TRANSFER_ERR_SIGNATURE = -7,
    PENDING_TRANSFER_ERR_SENDER_KEY = -8,
    PENDING_TRANSFER_ERR_NOT_PREFERRED = -9,
    PENDING_TRANSFER_ERR_CAPACITY = -10
} pending_transfer_status_t;

typedef struct {
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE];
    uint8_t sender[32];
    uint8_t hash[32];
    uint64_t nonce;
} pending_transfer_entry_t;

typedef struct {
    uint32_t shard_id;
    uint32_t count;
    pending_transfer_entry_t entries[PENDING_TRANSFER_PER_SHARD];
} pending_shard_t;

typedef struct {
    shard_routing_config_t routing;
    uint8_t genesis_hash[32];
    pending_shard_t *buckets;
    size_t bucket_capacity;
} pending_transfer_pool_t;

typedef struct {
    uint8_t hash[32];
    uint32_t shard_id;
    uint32_t pending_count;
} pending_transfer_result_t;

typedef struct {
    uint32_t count;
    uint8_t frames[PENDING_TRANSFER_PER_SHARD][PENDING_TRANSFER_FRAME_SIZE];
} pending_transfer_snapshot_t;

/* Caller owns a distinct pool object and 1..8 buckets for their entire use.
 * Input, pool/bucket storage and output objects must not overlap. The caller
 * must not modify pool metadata/configuration or buckets after initialization.
 * Operations are single-threaded; the caller serializes any concurrent access.
 * Init copies routing/genesis and empties buckets. Genesis equality is exact,
 * including zero; this does not load/authenticate a chain's genesis. Negative
 * returns leave all caller storage unchanged, including result/snapshot outputs.
 */
int pending_transfer_init(pending_transfer_pool_t *pool,
                          pending_shard_t *buckets, size_t bucket_capacity,
                          const shard_routing_config_t *routing,
                          const uint8_t genesis_hash[32]);

/* Admit only canonical payload/PQ-empty anonymous TRANSFER frames. Signature,
 * content hash, sender key, configured context and intra-shard ownership are
 * verified before any duplicate/conflict/capacity decision. The queue owns a
 * copy of the frame. Same(sender,nonce) alternatives keep the smaller data hash;
 * a valid duplicate may carry another signature and keeps the existing frame.
 * No balance, nonce readiness, affordability, execution or inclusion is asserted.
 * Consequently a signature-valid stale or unaffordable smaller-hash alternative
 * can replace another pending entry. This is an inbox preference, not the
 * state-revalidated assembly/requeue rule of a ledger or consensus engine.
 */
pending_transfer_status_t pending_transfer_submit(pending_transfer_pool_t *pool,
                                                  const uint8_t *frame, size_t len,
                                                  pending_transfer_result_t *result);

/* Read an owned snapshot in sender-byte/unsigned-nonce order. A valid shard
 * with no resident bucket returns count zero. No queue/configuration is changed.
 */
int pending_transfer_list(const pending_transfer_pool_t *pool, uint32_t shard_id,
                          pending_transfer_snapshot_t *snapshot);

#ifdef __cplusplus
}
#endif
#endif
