/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Monotonic K=2 State Machine (Phase 1: Hardware Execution Layer)
 *
 * Security Axiom:
 *   Time-Lock Inequality Theorem: T_vdf > W_reveal + Delta
 *
 * Requirements:
 *   - REVEAL_WINDOW: exactly 2000ms (2,000,000,000 ns).
 *   - Monotonic Hardware Clock: clock_gettime(CLOCK_MONOTONIC) / mach_absolute_time().
 *   - Zero dynamic memory allocations (static/caller-allocated context).
 *   - Hard Buzzer: reveal packets arriving >= 2001ms (or >= 2000ms) are explicitly dropped.
 *   - 1-of-2 Straggler Fallback: on missing/invalid contributor reveal at buzzer,
 *     instant transition to VDF_EVALUATION using only aggregator payload.
 */

#ifndef DETERMINISTIC_CONSENSUS_DUEL_STATE_H
#define DETERMINISTIC_CONSENSUS_DUEL_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DUEL_REVEAL_WINDOW_MS       2000ULL
#define DUEL_REVEAL_WINDOW_NS       (DUEL_REVEAL_WINDOW_MS * 1000000ULL)
#define DUEL_MAX_PAYLOAD_SIZE       65536U

typedef enum {
    DUEL_STATE_IDLE = 0,
    DUEL_STATE_COMMITMENT_PHASE,
    DUEL_STATE_AWAITING_REVEALS,
    DUEL_STATE_REVEAL_BUFFER_LOCKED,
    DUEL_STATE_VDF_EVALUATION,
    DUEL_STATE_FINALIZED,
    DUEL_STATE_ABORTED
} duel_state_t;

typedef enum {
    DUEL_SUCCESS = 0,
    DUEL_ERR_INVALID_ARGUMENT,
    DUEL_ERR_INVALID_STATE,
    DUEL_ERR_PAYLOAD_TOO_LARGE,
    DUEL_ERR_ALREADY_COMMITTED,
    DUEL_ERR_ALREADY_REVEALED,
    DUEL_ERR_WINDOW_EXPIRED,
    DUEL_DROPPED_BUZZER_EXCEEDED,
    DUEL_DROPPED_BUFFER_LOCKED,
    DUEL_DROPPED_INVALID_PAYLOAD
} duel_status_t;

typedef struct {
    uint8_t  data[DUEL_MAX_PAYLOAD_SIZE];
    uint32_t len;
    uint64_t arrival_timestamp_ns;
    bool     present;
    bool     valid;
} duel_reveal_entry_t;

typedef struct {
    duel_state_t        state;
    uint64_t            reveal_start_ns;
    uint64_t            reveal_end_ns;
    bool                reveal_buffer_locked;
    bool                straggler_fallback_active;

    duel_reveal_entry_t aggregator_reveal;
    duel_reveal_entry_t contributor_reveal;

    /* Staged VDF input payload (assembled from 1 or 2 reveals) */
    uint8_t             vdf_input_buffer[DUEL_MAX_PAYLOAD_SIZE * 2];
    uint32_t            vdf_input_len;
} duel_state_machine_t;

/*
 * Hardware Clock Source:
 * Returns the current monotonic time in nanoseconds.
 * Immune to NTP adjustments, step corrections, and leap seconds.
 */
uint64_t duel_clock_monotonic_ns(void);

/*
 * State Machine Lifecycle:
 */
duel_status_t duel_state_init(duel_state_machine_t *sm);
duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm);
duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm);

/*
 * Reveal Ingress:
 * Aggregator and Contributor reveal submission.
 * Validates timestamp against REVEAL_WINDOW (2000ms). Packets arriving
 * after window expiration are dropped unconditionally with DUEL_DROPPED_BUZZER_EXCEEDED.
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
 * Non-blocking tick/poll function.
 * Evaluates current monotonic time. If monotonic delta >= 2000ms:
 *  1. Instantly locks the reveal buffer.
 *  2. Evaluates presence and validity of Contributor reveal.
 *  3. If missing/invalid, activates 1-of-2 Straggler Fallback (using only Aggregator payload).
 *  4. Assembles VDF input and transitions state to DUEL_STATE_VDF_EVALUATION.
 *
 * Returns DUEL_SUCCESS if transitioned or waiting, or appropriate status code.
 */
duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm);

/*
 * Inspection & Utility:
 */
const char* duel_state_name(duel_state_t state);
uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CONSENSUS_DUEL_STATE_H */
