/* SPDX-License-Identifier: Apache-2.0
 * TEST MODEL ONLY: anchored sibling selection and bounded ledger replay.
 * Pair authorization and joint-receipt evidence are immutable model oracles.
 * No production election, DH/VDF proof, timeout authority or wire format.
 */
#ifndef DETERM_SIM_K2_RECOVERY_MODEL_H
#define DETERM_SIM_K2_RECOVERY_MODEL_H
#include <determ/ledger/state.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define K2_MODEL_CANDIDATES 8U
#define K2_MODEL_TXS 4U
#define K2_MODEL_DEPTH 4U
#define K2_MODEL_RECEIPTS 32U
#define K2_MODEL_HEADER_BYTES 136U
#define K2_MODEL_FRAME_MAX (K2_MODEL_HEADER_BYTES + 1U + K2_MODEL_TXS * 152U)
#define K2_MODEL_JOURNAL_MAX (6U + K2_MODEL_CANDIDATES * (2U + K2_MODEL_FRAME_MAX))
typedef enum {
    K2_MODEL_OK = 0, K2_MODEL_DUPLICATE = 1, K2_MODEL_PENDING = 2,
    K2_MODEL_INVALID = -1, K2_MODEL_FULL = -2, K2_MODEL_UNSUPPORTED_BRANCHING = -3,
    K2_MODEL_STALE_PREPARATION = -4
} k2_model_status_t;
typedef struct {
    uint8_t chain[32]; uint32_t shard;
    uint64_t height, round;
    uint8_t parent[32]; uint16_t creators[2];
    uint64_t variant; /* Model header variation, not a VDF output or nonce rule. */
    uint8_t tx_count;
    triple_entry_tx_t txs[K2_MODEL_TXS];
} k2_model_candidate_t;
typedef struct {
    uint8_t parent[32]; uint64_t height, round; uint16_t creators[2];
} k2_model_authority_t;
typedef struct { uint8_t tx_id[32]; uint32_t received_by; } k2_model_receipt_t;
typedef struct {
    uint8_t chain[32], anchor_id[32]; uint32_t shard;
    uint64_t anchor_height; uint16_t local_pool_count;
    ledger_state_t anchor_state;
    k2_model_authority_t authority[K2_MODEL_CANDIDATES]; size_t authority_count;
    k2_model_receipt_t receipts[K2_MODEL_RECEIPTS]; size_t receipt_count;
} k2_model_config_t;
typedef struct {
    k2_model_candidate_t candidate;
    uint8_t header[K2_MODEL_HEADER_BYTES], id[32];
    bool valid;
} k2_model_record_t;
typedef struct {
    const k2_model_config_t *config;
    uint64_t generation;
    k2_model_record_t records[K2_MODEL_CANDIDATES]; size_t record_count;
    size_t selected[K2_MODEL_DEPTH], selected_count;
    ledger_state_t state;
    triple_entry_tx_t requeue[K2_MODEL_RECEIPTS]; size_t requeue_count;
    size_t rejected_requeue_count;
} k2_model_node_t;
typedef struct {
    k2_model_node_t next, restoring;
    ledger_state_t replay;
    uint64_t base_generation;
    const k2_model_node_t *prepared_for;
    bool prepared;
} k2_model_workspace_t;
void k2_model_tx_id(const triple_entry_tx_t *, uint8_t out[32]);
void k2_model_header(const k2_model_candidate_t *, uint8_t out[K2_MODEL_HEADER_BYTES]);
void k2_model_id(const k2_model_candidate_t *, uint8_t out[32]);
/* Configuration is immutable for a node's lifetime. Reinitialization starts a
 * new lifetime and invalidates all outstanding preparations. Nodes and working
 * arenas must be disjoint. */
k2_model_status_t k2_model_init(k2_model_node_t *, const k2_model_config_t *);
/* Prepare has no visible effect; publish installs one complete history/state. */
k2_model_status_t k2_model_prepare(const k2_model_node_t *, const k2_model_candidate_t *, k2_model_workspace_t *);
k2_model_status_t k2_model_publish(k2_model_node_t *, k2_model_workspace_t *);
k2_model_status_t k2_model_receive(k2_model_node_t *, const k2_model_candidate_t *, k2_model_workspace_t *);
/* Canonical bytes for an in-memory crash/restart model, not filesystem durability.
 * Restore requires an initialized output with the same immutable configuration;
 * successful restore invalidates prior preparations for that output. */
k2_model_status_t k2_model_journal(const k2_model_node_t *, uint8_t *, size_t, size_t *);
k2_model_status_t k2_model_restore(k2_model_node_t *, const k2_model_config_t *, const uint8_t *, size_t, k2_model_workspace_t *);
#endif
