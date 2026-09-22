/* SPDX-License-Identifier: Apache-2.0
 * Local bounded commit/reveal computation. See the public header for its limits.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <determ/consensus/duel_state.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/wire/parser.h>
#include <determ/time/clock.h>
#include <string.h>

uint64_t duel_clock_monotonic_ns(void) { return determ_clock_now_ns(); }

/* Unsigned subtraction also handles a single monotonic counter wrap. */
static uint64_t attempt_elapsed(const duel_state_machine_t *sm) {
    return duel_clock_monotonic_ns() - sm->epoch_start_time;
}
static duel_status_t abort_attempt(duel_state_machine_t *sm, duel_status_t status) {
    sm->state = DUEL_STATE_ABORTED;
    sm->terminal_status = status;
    sm->reveal_buffer_locked = true;
    sm->vdf_input_len = 0;
    return status;
}

duel_status_t duel_state_init(duel_state_machine_t *sm) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    memset(sm, 0, sizeof(*sm));
    return DUEL_SUCCESS;
}
duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    if (sm->state != DUEL_STATE_IDLE && sm->state != DUEL_STATE_COMPLETED && sm->state != DUEL_STATE_ABORTED)
        return DUEL_ERR_INVALID_STATE;
    memset(sm, 0, sizeof(*sm));
    sm->epoch_start_time = duel_clock_monotonic_ns();
    sm->state = DUEL_STATE_COMMITMENT_PHASE;
    return DUEL_SUCCESS;
}
static duel_status_t submit_commit(duel_state_machine_t *sm, duel_commit_entry_t *entry,
                                    const uint8_t hash[32]) {
    if (!hash) return DUEL_ERR_INVALID_ARGUMENT;
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE) return DUEL_ERR_INVALID_STATE;
    if (attempt_elapsed(sm) >= DUEL_COMMIT_TIMEOUT_NS)
        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);
    if (entry->present) return DUEL_ERR_ALREADY_COMMITTED;
    memcpy(entry->hash, hash, 32);
    entry->arrival_timestamp_ns = duel_clock_monotonic_ns();
    entry->present = true;
    return DUEL_SUCCESS;
}
duel_status_t duel_submit_aggregator_commit(duel_state_machine_t *sm, const uint8_t hash[32]) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    return submit_commit(sm, &sm->aggregator_commit, hash);
}
duel_status_t duel_submit_contributor_commit(duel_state_machine_t *sm, const uint8_t hash[32]) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    return submit_commit(sm, &sm->contributor_commit, hash);
}
duel_status_t duel_state_poll_commit_timeout(duel_state_machine_t *sm) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    if (sm->state == DUEL_STATE_ABORTED) return sm->terminal_status;
    if (sm->state == DUEL_STATE_COMMITMENT_PHASE &&
        (!sm->aggregator_commit.present || !sm->contributor_commit.present) &&
        attempt_elapsed(sm) >= DUEL_COMMIT_TIMEOUT_NS)
        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);
    return DUEL_SUCCESS;
}
duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE) return DUEL_ERR_INVALID_STATE;
    if (!sm->aggregator_commit.present || !sm->contributor_commit.present)
        return DUEL_ERR_INVALID_STATE;
    if (attempt_elapsed(sm) >= DUEL_REVEAL_WINDOW_NS)
        return abort_attempt(sm, ERR_EPOCH_SKIPPED_INCOMPLETE);
    sm->reveal_start_ns = duel_clock_monotonic_ns();
    sm->state = DUEL_STATE_AWAITING_REVEALS;
    return DUEL_SUCCESS;
}
uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm) {
    if (!sm || sm->state < DUEL_STATE_AWAITING_REVEALS) return 0;
    return duel_clock_monotonic_ns() - sm->reveal_start_ns;
}
static duel_status_t submit_reveal(duel_state_machine_t *sm, duel_reveal_entry_t *entry,
                                    const duel_commit_entry_t *commit,
                                    const uint8_t *payload, uint32_t len, bool is_valid) {
    uint8_t digest[32];
    (void)digest;
    if (!payload || len == 0) return DUEL_ERR_INVALID_ARGUMENT;
    if (len > DUEL_MAX_PAYLOAD_SIZE) return DUEL_ERR_PAYLOAD_TOO_LARGE;
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) return DUEL_ERR_INVALID_STATE;
    if (sm->reveal_buffer_locked) return DUEL_DROPPED_BUFFER_LOCKED;
    if (attempt_elapsed(sm) >= DUEL_REVEAL_WINDOW_NS) return DUEL_DROPPED_BUZZER_EXCEEDED;
    if (entry->present) return DUEL_ERR_ALREADY_REVEALED;
    determ_sha256(payload, len, digest);
    if (!commit->present || !is_valid || memcmp(digest, commit->hash, 32) != 0)
        return abort_attempt(sm, DUEL_DROPPED_INVALID_PAYLOAD);
    memcpy(entry->data, payload, len);
    entry->len = len;
    entry->arrival_timestamp_ns = duel_clock_monotonic_ns();
    entry->present = true;
    entry->valid = true;
    return DUEL_SUCCESS;
}
duel_status_t duel_submit_aggregator_reveal(duel_state_machine_t *sm, const uint8_t *payload, uint32_t len) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    return submit_reveal(sm, &sm->aggregator_reveal, &sm->aggregator_commit, payload, len, true);
}
duel_status_t duel_submit_contributor_reveal(duel_state_machine_t *sm, const uint8_t *payload, uint32_t len, bool is_valid) {
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    return submit_reveal(sm, &sm->contributor_reveal, &sm->contributor_commit, payload, len, is_valid);
}
duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm) {
    size_t len = 0;
    bool complete;
    if (!sm) return DUEL_ERR_INVALID_ARGUMENT;
    if (sm->state == DUEL_STATE_ABORTED) return sm->terminal_status;
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) return DUEL_SUCCESS;
    complete = sm->aggregator_reveal.present && sm->aggregator_reveal.valid &&
               sm->contributor_reveal.present && sm->contributor_reveal.valid;
    if (!complete) {
        if (attempt_elapsed(sm) < DUEL_REVEAL_WINDOW_NS) return DUEL_SUCCESS;
        return abort_attempt(sm, ERR_EPOCH_SKIPPED_INCOMPLETE);
    }
    sm->reveal_buffer_locked = true;
    sm->state = DUEL_STATE_REVEAL_BUFFER_LOCKED;
    if (wire_bundle_vdf_input(sm->aggregator_reveal.data, sm->aggregator_reveal.len,
                             sm->contributor_reveal.data, sm->contributor_reveal.len,
                             sm->vdf_input_buffer, sizeof(sm->vdf_input_buffer), &len) != WIRE_OK)
        return abort_attempt(sm, DUEL_ERR_PAYLOAD_TOO_LARGE);
    sm->vdf_input_len = (uint32_t)len;
    sm->state = DUEL_STATE_VDF_EVALUATION;
    return DUEL_SUCCESS;
}
const char *duel_state_name(duel_state_t state) {
    switch (state) {
        case DUEL_STATE_IDLE: return "IDLE";
        case DUEL_STATE_COMMITMENT_PHASE: return "COMMITMENT_PHASE";
        case DUEL_STATE_AWAITING_REVEALS: return "AWAITING_REVEALS";
        case DUEL_STATE_REVEAL_BUFFER_LOCKED: return "REVEAL_BUFFER_LOCKED";
        case DUEL_STATE_VDF_EVALUATION: return "VDF_EVALUATION";
        case DUEL_STATE_COMPLETED: return "COMPLETED";
        case DUEL_STATE_ABORTED: return "ABORTED";
        default: return "UNKNOWN";
    }
}
