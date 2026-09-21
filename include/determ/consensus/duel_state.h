/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Monotonic K=2 State Machine (Hardware Execution Layer)
 *
 * Security Axioms & Protections:
 *   1. Strict 2-of-2 Epoch Skipping: 1-of-2 fallback is eradicated. Missing or
 *      invalid reveals trigger instant ERR_EPOCH_SKIPPED_INCOMPLETE and increment VRF.
 *   2. Commit Timeout: Contributor silence past T+1000ms triggers ERR_EPOCH_SKIPPED_SILENCE,
 *      increments VRF, and aborts.
 *   3. Decoupled Metronome: Valid 2-of-2 bundle at 2000ms buzzer immediately broadcasts
 *      Signed_Reveal_Bundle to P2P network, locking inputs before VDF execution begins.
 *   4. Gossip Veto: Asynchronous poll() every 10,000 VDF iterations detects Equivocation_Proof,
 *      instantly returning ERR_EQUIVOCATION_DETECTED and slashing the Aggregator.
 */

#ifndef DETERMINISTIC_CONSENSUS_DUEL_STATE_H
#define DETERMINISTIC_CONSENSUS_DUEL_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <determ/crypto/vdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DUEL_COMMIT_TIMEOUT_MS      1000ULL
#define DUEL_COMMIT_TIMEOUT_NS      (DUEL_COMMIT_TIMEOUT_MS * 1000000ULL)
#define DUEL_REVEAL_WINDOW_MS       2000ULL
#define DUEL_REVEAL_WINDOW_NS       (DUEL_REVEAL_WINDOW_MS * 1000000ULL)
#define DUEL_MAX_PAYLOAD_SIZE       65536U
#ifndef MAX_BUNDLE_SIZE
#define MAX_BUNDLE_SIZE             131104
#endif

typedef enum {
    DUEL_STATE_IDLE = 0,
    DUEL_STATE_COMMITMENT_PHASE,
    DUEL_STATE_AWAITING_COMMITS = DUEL_STATE_COMMITMENT_PHASE,
    DUEL_STATE_AWAITING_REVEALS,
    DUEL_STATE_REVEAL_BUFFER_LOCKED,
    DUEL_STATE_VDF_EVALUATION,
    DUEL_STATE_FINALIZED,
    DUEL_STATE_ABORTED
} duel_state_t;

typedef enum {
    DUEL_SUCCESS                     =  0,
    DUEL_ERR_INVALID_ARGUMENT        = -1,
    DUEL_ERR_INVALID_STATE           = -2,
    DUEL_ERR_PAYLOAD_TOO_LARGE       = -3,
    DUEL_ERR_ALREADY_COMMITTED       = -4,
    DUEL_ERR_ALREADY_REVEALED        = -5,
    DUEL_ERR_WINDOW_EXPIRED          = -6,
    DUEL_DROPPED_BUZZER_EXCEEDED     = -7,
    DUEL_DROPPED_BUFFER_LOCKED       = -8,
    DUEL_DROPPED_INVALID_PAYLOAD     = -9,
    ERR_EPOCH_SKIPPED_SILENCE        = -11,
    ERR_EPOCH_SKIPPED_INCOMPLETE     = -12,
    ERR_EQUIVOCATION_DETECTED        = -13
} duel_status_t;

typedef struct {
    uint8_t  data[DUEL_MAX_PAYLOAD_SIZE];
    uint32_t len;
    uint64_t arrival_timestamp_ns;
    bool     present;
    bool     valid;
} duel_reveal_entry_t;

typedef struct {
    uint8_t  hash[32];
    uint64_t arrival_timestamp_ns;
    bool     present;
} duel_commit_entry_t;

typedef struct {
    duel_state_t        state;
    uint64_t            epoch_start_time;       /* Monotonic epoch start ns */
    uint64_t            reveal_start_ns;
    uint64_t            reveal_end_ns;
    bool                reveal_buffer_locked;
    bool                straggler_fallback_active; /* strictly false under 2-of-2 */

    uint64_t            vrf_round;              /* Monotonic VRF round counter */

    duel_commit_entry_t aggregator_commit;
    duel_commit_entry_t contributor_commit;

    duel_reveal_entry_t aggregator_reveal;
    duel_reveal_entry_t contributor_reveal;

    /* Staged VDF input payload (assembled from 2-of-2 reveals) */
    uint8_t             vdf_input_buffer[MAX_BUNDLE_SIZE];
    uint32_t            vdf_input_len;

    /* PoSW Sequential Work Tracking */
    uint64_t            cumulative_vdf_iterations;

    /* Decoupled Metronome & Gossip Veto */
    int                 p2p_socket_fd;
    bool                aggregator_slashed;
    int (*push_reveal_bundle)(const uint8_t *bundle, uint32_t len, void *ctx);
    bool (*check_equivocation_proof)(int p2p_socket_fd, void *ctx);
    void               *network_ctx;
} duel_state_machine_t;

/*
 * Hardware Clock Source:
 * Returns the current monotonic time in nanoseconds.
 */
uint64_t duel_clock_monotonic_ns(void);

/*
 * State Machine Lifecycle:
 */
duel_status_t duel_state_init(duel_state_machine_t *sm);
duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm);
duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm);

/*
 * Commit Ingress & Timeout Poll:
 * In AWAITING_COMMITS, 1000ms monotonic timeout is enforced against epoch_start_time.
 * Returns ERR_EPOCH_SKIPPED_SILENCE on contributor silence.
 */
duel_status_t duel_submit_aggregator_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]);
duel_status_t duel_submit_contributor_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]);
duel_status_t duel_state_poll_commit_timeout(duel_state_machine_t *sm);

/*
 * Reveal Ingress:
 * Validates timestamp against REVEAL_WINDOW (2000ms). Packets arriving
 * after window expiration are dropped with DUEL_DROPPED_BUZZER_EXCEEDED.
 */
duel_status_t duel_submit_aggregator_reveal(duel_state_machine_t *sm,
                                            const uint8_t *payload,
                                            uint32_t payload_len);

duel_status_t duel_submit_contributor_reveal(duel_state_machine_t *sm,
                                             const uint8_t *payload,
                                             uint32_t payload_len,
                                             bool is_valid);

/*
 * Buzzer Event Loop:
 * If determ_clock_now() - epoch_start_time >= 2000ms:
 *  1. Instantly locks the reveal buffer.
 *  2. Evaluates presence and validity of BOTH reveals (Strict 2-of-2 Rule).
 *  3. If either reveal is missing or invalid: returns ERR_EPOCH_SKIPPED_INCOMPLETE,
 *     increments VRF, and aborts (zero VDF on 1-of-2).
 *  4. If both reveals present: bundles them, broadcasts Signed_Reveal_Bundle via
 *     Decoupled Metronome, and transitions to DUEL_STATE_VDF_EVALUATION.
 */
duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm);

/*
 * Decoupled Metronome & Gossip Veto VDF Execution:
 * Runs VDF evaluation, asynchronously polling incoming P2P socket every 10,000
 * iterations for an Equivocation_Proof. If detected, slashes Aggregator,
 * aborts block, and returns ERR_EQUIVOCATION_DETECTED.
 */
duel_status_t execute_vdf_loop(duel_state_machine_t *sm, vdf_context_t *ctx, uint8_t output[32]);

/*
 * Nakamoto Heaviest-Chain Fork Choice Rule (PoSW):
 * When conflicting block headers (a fork) arrive at the same height,
 * the node evaluates the sum of vdf_iterations across competing chains.
 * The branch with the highest cumulative sequential work becomes canonical tip.
 */
typedef struct {
    uint64_t height;
    uint64_t vdf_iterations;
    uint64_t cumulative_vdf_iterations;
    uint8_t  prev_hash[32];
    uint8_t  block_hash[32];
} duel_block_header_t;

int duel_resolve_fork_choice(duel_state_machine_t *sm,
                             const duel_block_header_t *chain_a, size_t count_a,
                             const duel_block_header_t *chain_b, size_t count_b,
                             const duel_block_header_t **canonical_tip);

int duel_resolve_fork_headers(duel_state_machine_t *sm,
                              const duel_block_header_t *header_a,
                              const duel_block_header_t *header_b,
                              const duel_block_header_t **canonical_tip);

void duel_state_accumulate_work(duel_state_machine_t *sm, uint64_t vdf_iterations);
uint64_t duel_state_get_cumulative_work(const duel_state_machine_t *sm);

/*
 * Inspection & Utility:
 */
const char* duel_state_name(duel_state_t state);
uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CONSENSUS_DUEL_STATE_H */
