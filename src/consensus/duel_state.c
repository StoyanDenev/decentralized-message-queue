/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Monotonic K=2 State Machine Implementation (C99 Bare-Metal)
 */

#define _POSIX_C_SOURCE 200809L

#include "duel_state.h"
#include <string.h>
#include <time.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

uint64_t duel_clock_monotonic_ns(void) {
#if defined(__APPLE__)
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        (void)mach_timebase_info(&tb);
    }
    uint64_t t = mach_absolute_time();
    /* Guard against potential overflow for long runtimes */
    return (uint64_t)(((__uint128_t)t * tb.numer) / tb.denom);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0ULL;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

duel_status_t duel_state_init(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    memset(sm, 0, sizeof(*sm));
    sm->state = DUEL_STATE_IDLE;
    return DUEL_SUCCESS;
}

duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_IDLE && sm->state != DUEL_STATE_FINALIZED) {
        return DUEL_ERR_INVALID_STATE;
    }

    memset(&sm->aggregator_reveal, 0, sizeof(sm->aggregator_reveal));
    memset(&sm->contributor_reveal, 0, sizeof(sm->contributor_reveal));
    memset(sm->vdf_input_buffer, 0, sizeof(sm->vdf_input_buffer));
    sm->vdf_input_len = 0;
    sm->reveal_buffer_locked = false;
    sm->straggler_fallback_active = false;
    sm->reveal_start_ns = 0;
    sm->reveal_end_ns = 0;

    sm->state = DUEL_STATE_COMMITMENT_PHASE;
    return DUEL_SUCCESS;
}

duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE) {
        return DUEL_ERR_INVALID_STATE;
    }

    sm->reveal_start_ns = duel_clock_monotonic_ns();
    sm->reveal_end_ns = sm->reveal_start_ns + DUEL_REVEAL_WINDOW_NS;
    sm->reveal_buffer_locked = false;
    sm->state = DUEL_STATE_AWAITING_REVEALS;

    return DUEL_SUCCESS;
}

uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm) {
    if (!sm || sm->reveal_start_ns == 0) {
        return 0ULL;
    }
    uint64_t now = duel_clock_monotonic_ns();
    if (now <= sm->reveal_start_ns) {
        return 0ULL;
    }
    return now - sm->reveal_start_ns;
}

duel_status_t duel_submit_aggregator_reveal(duel_state_machine_t *sm,
                                            const uint8_t *payload,
                                            uint32_t payload_len) {
    if (!sm || (!payload && payload_len > 0)) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_ERR_INVALID_STATE;
    }
    if (sm->reveal_buffer_locked) {
        return DUEL_DROPPED_BUFFER_LOCKED;
    }
    if (payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return DUEL_ERR_PAYLOAD_TOO_LARGE;
    }

    uint64_t now = duel_clock_monotonic_ns();
    if (now >= sm->reveal_end_ns || (now - sm->reveal_start_ns) >= DUEL_REVEAL_WINDOW_NS) {
        return DUEL_DROPPED_BUZZER_EXCEEDED;
    }

    if (sm->aggregator_reveal.present) {
        return DUEL_ERR_ALREADY_REVEALED;
    }

    if (payload_len > 0) {
        memcpy(sm->aggregator_reveal.data, payload, payload_len);
    }
    sm->aggregator_reveal.len = payload_len;
    sm->aggregator_reveal.arrival_timestamp_ns = now;
    sm->aggregator_reveal.present = true;
    sm->aggregator_reveal.valid = true;

    return DUEL_SUCCESS;
}

duel_status_t duel_submit_contributor_reveal(duel_state_machine_t *sm,
                                             const uint8_t *payload,
                                             uint32_t payload_len,
                                             bool is_valid) {
    if (!sm || (!payload && payload_len > 0)) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_ERR_INVALID_STATE;
    }
    if (sm->reveal_buffer_locked) {
        return DUEL_DROPPED_BUFFER_LOCKED;
    }

    uint64_t now = duel_clock_monotonic_ns();

    /*
     * The Buzzer Gate:
     * When monotonic delta hits 2000ms, buffer is locked and any packet
     * arriving at >= 2001ms (or >= 2000ms boundary) MUST be dropped.
     */
    if (now >= sm->reveal_end_ns || (now - sm->reveal_start_ns) >= DUEL_REVEAL_WINDOW_NS) {
        return DUEL_DROPPED_BUZZER_EXCEEDED;
    }

    if (payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return DUEL_ERR_PAYLOAD_TOO_LARGE;
    }

    if (sm->contributor_reveal.present) {
        return DUEL_ERR_ALREADY_REVEALED;
    }

    if (!is_valid) {
        /* Mark invalid but recorded within window */
        sm->contributor_reveal.arrival_timestamp_ns = now;
        sm->contributor_reveal.present = true;
        sm->contributor_reveal.valid = false;
        sm->contributor_reveal.len = 0;
        return DUEL_DROPPED_INVALID_PAYLOAD;
    }

    if (payload_len > 0) {
        memcpy(sm->contributor_reveal.data, payload, payload_len);
    }
    sm->contributor_reveal.len = payload_len;
    sm->contributor_reveal.arrival_timestamp_ns = now;
    sm->contributor_reveal.present = true;
    sm->contributor_reveal.valid = true;

    return DUEL_SUCCESS;
}

/*
 * Helper to write 32-bit big-endian integer into memory buffer
 */
static void write_be32(uint8_t *dest, uint32_t val) {
    dest[0] = (uint8_t)((val >> 24) & 0xFF);
    dest[1] = (uint8_t)((val >> 16) & 0xFF);
    dest[2] = (uint8_t)((val >> 8)  & 0xFF);
    dest[3] = (uint8_t)(val & 0xFF);
}

duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }

    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_SUCCESS;
    }

    uint64_t now = duel_clock_monotonic_ns();
    uint64_t elapsed = (now >= sm->reveal_start_ns) ? (now - sm->reveal_start_ns) : 0ULL;

    bool both_present = (sm->aggregator_reveal.present && sm->contributor_reveal.present);
    if (elapsed < DUEL_REVEAL_WINDOW_NS && !both_present) {
        /* Reveal window still active */
        return DUEL_SUCCESS;
    }

    /*
     * Buzzer fired:
     * 1. Lock reveal buffer immediately.
     */
    sm->reveal_buffer_locked = true;
    sm->state = DUEL_STATE_REVEAL_BUFFER_LOCKED;

    /*
     * 2. The 1-of-2 Straggler Fallback:
     * If contributor's reveal is missing or invalid at the buzzer, the Aggregator
     * instantly transitions to VDF_EVALUATION using only their own payload.
     * Expected physical reality; zero errors thrown.
     */
    bool contributor_accepted = sm->contributor_reveal.present && sm->contributor_reveal.valid;
    sm->straggler_fallback_active = !contributor_accepted;

    uint32_t offset = 0;

    /* Pack Aggregator Payload (Length-prefixed BE32 + Raw Bytes) */
    write_be32(&sm->vdf_input_buffer[offset], sm->aggregator_reveal.len);
    offset += 4;
    if (sm->aggregator_reveal.len > 0) {
        memcpy(&sm->vdf_input_buffer[offset], sm->aggregator_reveal.data, sm->aggregator_reveal.len);
        offset += sm->aggregator_reveal.len;
    }

    if (contributor_accepted) {
        /* Pack Contributor Payload (Length-prefixed BE32 + Raw Bytes) */
        write_be32(&sm->vdf_input_buffer[offset], sm->contributor_reveal.len);
        offset += 4;
        if (sm->contributor_reveal.len > 0) {
            memcpy(&sm->vdf_input_buffer[offset], sm->contributor_reveal.data, sm->contributor_reveal.len);
            offset += sm->contributor_reveal.len;
        }
    } else {
        /* Straggler fallback: 0-length contributor payload appended */
        write_be32(&sm->vdf_input_buffer[offset], 0);
        offset += 4;
    }

    sm->vdf_input_len = offset;

    /* Transition directly to VDF Evaluation */
    sm->state = DUEL_STATE_VDF_EVALUATION;

    return DUEL_SUCCESS;
}

const char* duel_state_name(duel_state_t state) {
    switch (state) {
        case DUEL_STATE_IDLE:                 return "IDLE";
        case DUEL_STATE_COMMITMENT_PHASE:     return "COMMITMENT_PHASE";
        case DUEL_STATE_AWAITING_REVEALS:     return "AWAITING_REVEALS";
        case DUEL_STATE_REVEAL_BUFFER_LOCKED: return "REVEAL_BUFFER_LOCKED";
        case DUEL_STATE_VDF_EVALUATION:       return "VDF_EVALUATION";
        case DUEL_STATE_FINALIZED:            return "FINALIZED";
        case DUEL_STATE_ABORTED:              return "ABORTED";
        default:                              return "UNKNOWN";
    }
}
