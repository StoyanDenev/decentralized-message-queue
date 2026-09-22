/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/consensus/duel_state.h>
#include <determ/crypto/sha2/sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)
static const uint8_t a[] = "aggregator payload";
static const uint8_t b[] = "contributor payload";
static void commit_pair(duel_state_machine_t *sm) {
    uint8_t hash[32];
    determ_sha256(a, sizeof(a), hash);
    CHECK(duel_submit_aggregator_commit(sm, hash) == DUEL_SUCCESS);
    determ_sha256(b, sizeof(b), hash);
    CHECK(duel_submit_contributor_commit(sm, hash) == DUEL_SUCCESS);
}

#include <determ/time/clock.h>
static duel_state_machine_t sm;
static void fresh(uint64_t now) {
    determ_dsf_clock_set_ns(now);
    CHECK(duel_state_init(&sm) == DUEL_SUCCESS);
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
}
static void test_commit_boundaries(void) {
    uint8_t hash[32];
    determ_sha256(a, sizeof(a), hash);
    fresh(0);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_ERR_INVALID_STATE);
    CHECK(duel_submit_aggregator_commit(&sm, hash) == DUEL_SUCCESS);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_ERR_INVALID_STATE);
    determ_dsf_clock_set_ns(DUEL_COMMIT_TIMEOUT_NS - 1);
    CHECK(duel_state_poll_commit_timeout(&sm) == DUEL_SUCCESS);
    determ_dsf_clock_advance_ns(1);
    CHECK(duel_state_poll_commit_timeout(&sm) == ERR_EPOCH_SKIPPED_SILENCE);
    CHECK(sm.state == DUEL_STATE_ABORTED && sm.vdf_input_len == 0);
    CHECK(duel_state_poll_commit_timeout(&sm) == ERR_EPOCH_SKIPPED_SILENCE);
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    CHECK(!sm.aggregator_commit.present && !sm.contributor_commit.present);
    CHECK(!sm.aggregator_reveal.present && sm.terminal_status == DUEL_SUCCESS);
    commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    fresh(0);
    determ_dsf_clock_set_ns(DUEL_COMMIT_TIMEOUT_NS);
    CHECK(duel_submit_aggregator_commit(&sm, hash) == ERR_EPOCH_SKIPPED_SILENCE);
    fresh(0);
    determ_dsf_clock_set_ns(DUEL_COMMIT_TIMEOUT_NS);
    CHECK(duel_submit_contributor_commit(&sm, hash) == ERR_EPOCH_SKIPPED_SILENCE);
}
static void test_hash_binding(void) {
    fresh(0); commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, b, sizeof(b)) == DUEL_DROPPED_INVALID_PAYLOAD);
    CHECK(sm.state == DUEL_STATE_ABORTED && sm.vdf_input_len == 0);
    fresh(0); commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, a, sizeof(a)) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, a, sizeof(a), true) == DUEL_DROPPED_INVALID_PAYLOAD);
    CHECK(sm.state == DUEL_STATE_ABORTED && sm.vdf_input_len == 0);
    fresh(0); commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, b, sizeof(b), false) == DUEL_DROPPED_INVALID_PAYLOAD);
}
static void test_reveal_deadline(uint64_t origin) {
    uint8_t hash[32];
    fresh(origin);
    determ_sha256(a, sizeof(a), hash);
    CHECK(duel_submit_aggregator_commit(&sm, hash) == DUEL_SUCCESS);
    determ_dsf_clock_advance_ms(900);
    determ_sha256(b, sizeof(b), hash);
    CHECK(duel_submit_contributor_commit(&sm, hash) == DUEL_SUCCESS);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, a, sizeof(a)) == DUEL_SUCCESS);
    determ_dsf_clock_advance_ns(1099999999ULL);
    CHECK(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    CHECK(sm.state == DUEL_STATE_AWAITING_REVEALS);
    determ_dsf_clock_advance_ns(1);
    CHECK(duel_submit_contributor_reveal(&sm, b, sizeof(b), true) == DUEL_DROPPED_BUZZER_EXCEEDED);
    CHECK(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
    CHECK(sm.state == DUEL_STATE_ABORTED && sm.vdf_input_len == 0);
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, a, sizeof(a)) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, b, sizeof(b), true) == DUEL_SUCCESS);
    CHECK(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    CHECK(sm.state == DUEL_STATE_VDF_EVALUATION);
}
int main(void) {
    test_commit_boundaries();
    test_hash_binding();
    test_reveal_deadline(0);
    test_reveal_deadline(UINT64_MAX - 1500000000ULL);
    puts("PASS: strict local attempt deadlines, commitment binding and explicit retry");
    return 0;
}
