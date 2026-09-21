/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Strict 2-of-2 Consensus Verification:
 *   1. Commit Timeout (1000ms): Contributor silence returns ERR_EPOCH_SKIPPED_SILENCE,
 *      increments VRF, and aborts.
 *   2. Strict 2-of-2 Buzzer Skipping: Missing/incomplete reveal returns
 *      ERR_EPOCH_SKIPPED_INCOMPLETE, increments VRF, and aborts (zero VDF on 1-of-2).
 *   3. Decoupled Metronome: Valid 2-of-2 bundles are pushed to P2P network before VDF.
 *   4. Gossip Veto: Double-signature detected during execute_vdf_loop returns
 *      ERR_EQUIVOCATION_DETECTED, slashes Aggregator, and aborts block.
 */

#include "test_harness.h"
#include <determ/consensus/duel_state.h>
#include <determ/net/virtual_transport.h>
#include <determ/crypto/vdf.h>
#include <sys/socket.h>
#include <unistd.h>

static bool s_mock_broadcast_called = false;
static uint32_t s_mock_broadcast_len = 0;

static int mock_push_reveal_bundle(const uint8_t *bundle, uint32_t len, void *ctx) {
    (void)bundle;
    (void)ctx;
    s_mock_broadcast_called = true;
    s_mock_broadcast_len = len;
    return 0;
}

static bool mock_check_equivocation_detected(int socket_fd, void *ctx) {
    (void)socket_fd;
    (void)ctx;
    return true;
}

static void test_commit_timeout_silence(void) {
    printf("[TEST] 1. Commit Timeout (1000ms Contributor Silence)...\n");

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_COMMITMENT_PHASE);
    TEST_ASSERT(sm.vrf_round == 0);

    const uint8_t agg_commit[32] = {0xAA};
    TEST_ASSERT(duel_submit_aggregator_commit(&sm, agg_commit) == DUEL_SUCCESS);

    /* Fast-forward DSF virtual clock past 1000ms without Contributor commit */
    dsf_fast_forward_ms(1001);

    /* Poll commit timeout: Contributor silence must trigger abort and VRF increment */
    TEST_ASSERT(duel_state_poll_commit_timeout(&sm) == ERR_EPOCH_SKIPPED_SILENCE);
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
    TEST_ASSERT(sm.vrf_round == 1);

    printf("  -> PASS: Contributor silence at T+1000ms correctly returned ERR_EPOCH_SKIPPED_SILENCE and incremented VRF.\n");
}

static void test_strict_2_of_2_buzzer_incomplete(void) {
    printf("[TEST] 2. Strict 2-of-2 Buzzer (Missing Reveal Skipping)...\n");

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);

    const uint8_t agg_commit[32] = {0x01};
    const uint8_t cont_commit[32] = {0x02};
    TEST_ASSERT(duel_submit_aggregator_commit(&sm, agg_commit) == DUEL_SUCCESS);
    TEST_ASSERT(duel_submit_contributor_commit(&sm, cont_commit) == DUEL_SUCCESS);

    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_AWAITING_REVEALS);

    const uint8_t agg_payload[] = "AGGREGATOR-TXS-ROOT-BLOCK-00001";
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_payload, sizeof(agg_payload)) == DUEL_SUCCESS);

    /* Fast-forward DSF virtual clock 2001ms (past the 2000ms buzzer) */
    dsf_fast_forward_ms(2001);

    /* Verify straggler payload arriving late is dropped */
    const uint8_t late_payload[] = "CONTRIBUTOR-LATE-REVEAL-00000001";
    TEST_ASSERT(duel_submit_contributor_reveal(&sm, late_payload, sizeof(late_payload), true) == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* Poll buzzer: Incomplete reveals must fail instantly with ERR_EPOCH_SKIPPED_INCOMPLETE */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
    TEST_ASSERT(sm.reveal_buffer_locked == true);
    TEST_ASSERT(sm.straggler_fallback_active == false);
    TEST_ASSERT(sm.vrf_round == 1);

    printf("  -> PASS: Missing contributor reveal returned ERR_EPOCH_SKIPPED_INCOMPLETE; zero 1-of-2 VDF evaluation.\n");
}

static void test_decoupled_metronome_and_gossip_veto(void) {
    printf("[TEST] 3. Decoupled Metronome Broadcast & Gossip Veto Detection...\n");

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    sm.push_reveal_bundle = mock_push_reveal_bundle;

    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);

    const uint8_t agg_payload[] = "AGGREGATOR-DUEL-PAYLOAD-ALPHA-01";
    const uint8_t cont_payload[] = "CONTRIBUTOR-DUEL-PAYLOAD-BETA-02";

    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_payload, sizeof(agg_payload) - 1) == DUEL_SUCCESS);
    TEST_ASSERT(duel_submit_contributor_reveal(&sm, cont_payload, sizeof(cont_payload) - 1, true) == DUEL_SUCCESS);

    /* Poll buzzer: Valid 2-of-2 payload triggers immediate Decoupled Metronome broadcast */
    s_mock_broadcast_called = false;
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_VDF_EVALUATION);
    TEST_ASSERT(s_mock_broadcast_called == true);
    TEST_ASSERT(s_mock_broadcast_len == 4 + 32 + 4 + 32);

    /* Setup Gossip Veto detection */
    sm.check_equivocation_proof = mock_check_equivocation_detected;

    vdf_context_t vdf_ctx;
    TEST_ASSERT(vdf_init(&vdf_ctx, sm.vdf_input_buffer, sm.vdf_input_len, 20000ULL) == 0);

    uint8_t out[32];
    duel_status_t veto_status = execute_vdf_loop(&sm, &vdf_ctx, out);

    /* Assert Gossip Veto caught equivocation and slashed Aggregator */
    TEST_ASSERT(veto_status == ERR_EQUIVOCATION_DETECTED);
    TEST_ASSERT(sm.aggregator_slashed == true);
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);

    printf("  -> PASS: Decoupled Metronome broadcast verified; Gossip Veto slashed equivocator with ERR_EQUIVOCATION_DETECTED.\n");
}

int main(void) {
    test_harness_init("test_k2_duel_fallback");
    test_commit_timeout_silence();
    test_strict_2_of_2_buzzer_incomplete();
    test_decoupled_metronome_and_gossip_veto();
    test_harness_finish("test_k2_duel_fallback");
    return 0;
}
