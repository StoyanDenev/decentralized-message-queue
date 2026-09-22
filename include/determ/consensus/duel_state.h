/* SPDX-License-Identifier: Apache-2.0
 * Experimental local two-party commit/reveal attempt, not a consensus protocol.
 * Commitments are SHA256(payload): no peer, chain, height, or session authentication.
 * Both commitments must arrive before T+1000ms; reveals before T+2000ms.
 * Failure terminates the attempt. Restart is an explicit caller action, not election.
 */
#ifndef DETERMINISTIC_CONSENSUS_DUEL_STATE_H
#define DETERMINISTIC_CONSENSUS_DUEL_STATE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DUEL_COMMIT_TIMEOUT_MS 1000ULL
#define DUEL_COMMIT_TIMEOUT_NS (DUEL_COMMIT_TIMEOUT_MS * 1000000ULL)
#define DUEL_REVEAL_WINDOW_MS 2000ULL
#define DUEL_REVEAL_WINDOW_NS (DUEL_REVEAL_WINDOW_MS * 1000000ULL)
#define DUEL_MAX_PAYLOAD_SIZE 65536U
#ifndef MAX_BUNDLE_SIZE
#define MAX_BUNDLE_SIZE 131104U
#endif

typedef enum {
    DUEL_STATE_IDLE = 0,
    DUEL_STATE_COMMITMENT_PHASE,
    DUEL_STATE_AWAITING_COMMITS = DUEL_STATE_COMMITMENT_PHASE,
    DUEL_STATE_AWAITING_REVEALS,
    DUEL_STATE_REVEAL_BUFFER_LOCKED,
    DUEL_STATE_VDF_EVALUATION,
    DUEL_STATE_COMPLETED, /* Computation finished; no consensus finality. */
    DUEL_STATE_ABORTED
} duel_state_t;
typedef enum {
    DUEL_SUCCESS = 0,
    DUEL_ERR_INVALID_ARGUMENT = -1,
    DUEL_ERR_INVALID_STATE = -2,
    DUEL_ERR_PAYLOAD_TOO_LARGE = -3,
    DUEL_ERR_ALREADY_COMMITTED = -4,
    DUEL_ERR_ALREADY_REVEALED = -5,
    DUEL_ERR_WINDOW_EXPIRED = -6,
    DUEL_DROPPED_BUZZER_EXCEEDED = -7,
    DUEL_DROPPED_BUFFER_LOCKED = -8,
    DUEL_DROPPED_INVALID_PAYLOAD = -9,
    /* Historical names retained; these terminate only a local attempt. */
    ERR_EPOCH_SKIPPED_SILENCE = -11,
    ERR_EPOCH_SKIPPED_INCOMPLETE = -12
} duel_status_t;
typedef struct {
    uint8_t data[DUEL_MAX_PAYLOAD_SIZE];
    uint32_t len;
    uint64_t arrival_timestamp_ns;
    bool present;
    bool valid;
} duel_reveal_entry_t;
typedef struct {
    uint8_t hash[32];
    uint64_t arrival_timestamp_ns;
    bool present;
} duel_commit_entry_t;
typedef struct {
    duel_state_t state;
    duel_status_t terminal_status;
    uint64_t epoch_start_time;
    uint64_t reveal_start_ns;
    bool reveal_buffer_locked;
    duel_commit_entry_t aggregator_commit;
    duel_commit_entry_t contributor_commit;
    duel_reveal_entry_t aggregator_reveal;
    duel_reveal_entry_t contributor_reveal;
    uint8_t vdf_input_buffer[MAX_BUNDLE_SIZE];
    uint32_t vdf_input_len;
} duel_state_machine_t;

uint64_t duel_clock_monotonic_ns(void);
duel_status_t duel_state_init(duel_state_machine_t *sm);
duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm);
duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm);
duel_status_t duel_submit_aggregator_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]);
duel_status_t duel_submit_contributor_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]);
duel_status_t duel_state_poll_commit_timeout(duel_state_machine_t *sm);
duel_status_t duel_submit_aggregator_reveal(duel_state_machine_t *sm, const uint8_t *payload, uint32_t payload_len);
/* is_valid may reject a payload; true never bypasses commitment verification. */
duel_status_t duel_submit_contributor_reveal(duel_state_machine_t *sm, const uint8_t *payload, uint32_t payload_len, bool is_valid);
duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm);
const char *duel_state_name(duel_state_t state);
uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm);
#ifdef __cplusplus
}
#endif
#endif
