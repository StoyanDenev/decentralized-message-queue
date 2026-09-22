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
#include <determ/net/virtual_transport.h>
#include <determ/crypto/vdf.h>
#include <determ/consensus/dda.h>
#include <errno.h>
static duel_state_machine_t sm;
static vdf_context_t vdf;
int main(void) {
    uint8_t rx[64], output[32];
    uint64_t completed = 0, aborted = 0;
    dda_tracker_t dda;
    determ_dsf_clock_reset();
    determ_dsf_transport_init();
    determ_dsf_set_vdf_bypass(true, TARGET_VDF_MS);
    dda_init(&dda, 50000);
    for (uint64_t attempt = 1; attempt <= 10; attempt++) {
        CHECK(duel_state_init(&sm) == DUEL_SUCCESS);
        CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
        commit_pair(&sm);
        CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
        CHECK(duel_submit_aggregator_reveal(&sm, a, sizeof(a)) == DUEL_SUCCESS);
        determ_dsf_queue_rx(42, b, sizeof(b));
        CHECK(determ_net_recv(42, rx, sizeof(rx), 0) == sizeof(b));
        if (attempt % 3 == 0) {
            determ_dsf_clock_advance_ms(2000);
            CHECK(duel_submit_contributor_reveal(&sm, rx, sizeof(b), true) == DUEL_DROPPED_BUZZER_EXCEEDED);
            CHECK(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
            aborted++;
            continue;
        }
        CHECK(duel_submit_contributor_reveal(&sm, rx, sizeof(b), true) == DUEL_SUCCESS);
        CHECK(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
        uint64_t iterations = dda_get_next_iterations(&dda);
        CHECK(vdf_init(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, iterations) == 0);
        CHECK(vdf_evaluate(&vdf, output) == 0);
        CHECK(vdf.elapsed_ns == TARGET_VDF_MS * 1000000ULL);
        /* Synthetic strictly ordered timestamp history, not block admission. */
        CHECK(dda_commit_block(&dda, determ_clock_now_ms(), iterations));
        completed++;
    }
    CHECK(completed == 7 && aborted == 3);
    determ_dsf_inject_ewouldblock_rx(true);
    CHECK(determ_net_recv(42, rx, sizeof(rx), 0) == -1 && errno == EWOULDBLOCK);
    determ_dsf_inject_ewouldblock_rx(false);
    puts("PASS: DSF clock/transport and seven mock computations, three terminated attempts");
    return 0;
}
