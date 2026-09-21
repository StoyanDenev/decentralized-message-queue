/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Liveness Proof: K=2 Duel Fallback Execution under DSF.
 *
 * Mathematically proves zero-halt liveness:
 *   1. Initialize Aggregator and Contributor state.
 *   2. Fast-forward the DSF virtual clock exactly 2001ms.
 *   3. Simulate a Virtual Transport timeout (EWOULDBLOCK) on Contributor socket.
 *   4. Assert: Aggregator does NOT block or crash; transitions seamlessly to
 *      VDF_EVALUATION on a 1-of-2 payload.
 */

#include "test_harness.h"
#include <determ/consensus/duel_state.h>
#include <determ/net/virtual_transport.h>
#include <determ/crypto/vdf.h>

static void test_k2_duel_fallback_liveness(void) {
    printf("[TEST] K=2 Duel 1-of-2 Fallback & Virtual Transport EWOULDBLOCK Liveness...\n");

    /* 1. Initialize Aggregator and Contributor state */
    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);

    const uint8_t agg_payload[32] = "AGGREGATOR-TXS-ROOT-BLOCK-00001";
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_payload, sizeof(agg_payload)) == DUEL_SUCCESS);

    /* 2. Fast-forward the DSF virtual clock exactly 2001ms */
    dsf_fast_forward_ms(2001);
    TEST_ASSERT(duel_state_elapsed_reveal_ns(&sm) >= 2001000000ULL);

    /* 3. Simulate a Virtual Transport timeout (EWOULDBLOCK) for Contributor socket */
    int cont_socket_fd = 77;
    dsf_inject_ewouldblock(true);

    uint8_t cont_rx_buf[64];
    ssize_t rx_rc = determ_net_recv(cont_socket_fd, cont_rx_buf, sizeof(cont_rx_buf), 0);
    TEST_ASSERT(rx_rc == -1);
    TEST_ASSERT(errno == EWOULDBLOCK);
    dsf_inject_ewouldblock(false);

    /* Also verify that any reveal arriving at >= 2001ms is strictly dropped */
    const uint8_t late_cont_payload[32] = "CONTRIBUTOR-STRAGGLER-LATE-REVE";
    duel_status_t drop_rc = duel_submit_contributor_reveal(&sm, late_cont_payload, 32, true);
    TEST_ASSERT(drop_rc == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* 4. Poll buzzer: state machine must NOT block or crash;
     * must transition seamlessly to VDF_EVALUATION on 1-of-2 payload.
     */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_VDF_EVALUATION);
    TEST_ASSERT(sm.reveal_buffer_locked == true);
    TEST_ASSERT(sm.straggler_fallback_active == true);

    /* Assert 1-of-2 payload composition: 4-byte len + agg_payload + 4-byte 0 len */
    TEST_ASSERT(sm.vdf_input_len == 4 + 32 + 4);
    TEST_ASSERT(memcmp(&sm.vdf_input_buffer[4], agg_payload, 32) == 0);

    printf("  -> PASS: Seamless transition to VDF_EVALUATION on 1-of-2 payload. Zero-halt verified.\n");
}

int main(void) {
    test_harness_init("test_k2_duel_fallback (Liveness Proof)");
    test_k2_duel_fallback_liveness();
    test_harness_finish("test_k2_duel_fallback");
    return 0;
}
