/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ C99 Native Test Harness: PoSW Liveness & Fork Proofs.
 * Tests strict 2-of-2 epoch skipping on reveal buzzer timeout (no halting),
 * and Heaviest-Chain branch resolution via cumulative VDF iterations.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <determ/consensus/duel_state.h>
#include <determ/consensus/branch_resolver.h>
#include <determ/consensus/dda.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/vdf.h>
#include <determ/time/clock.h>
#include <determ/net/virtual_transport.h>

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "FAILED: %s:%d: %s\n", __FILE__, __LINE__, #c); \
        abort(); \
    } \
} while (0)

/* Test 1: Liveness Proof — Virtual Transport Timeout & Strict 2-of-2 Epoch Skipping */
static void test_liveness_timeout_and_epoch_skipping(void) {
    printf("[Test 1] Running Liveness & Strict 2-of-2 Epoch Skipping Proof...\n");

    duel_state_machine_t sm;
    uint8_t agg_payload[] = "aggregator-liveness-payload-epoch-1";
    uint8_t cont_payload[] = "contributor-liveness-payload-epoch-1";
    uint8_t agg_hash[32];
    uint8_t cont_hash[32];

    determ_sha256(agg_payload, sizeof(agg_payload), agg_hash);
    determ_sha256(cont_payload, sizeof(cont_payload), cont_hash);

    determ_dsf_clock_reset();
    determ_dsf_transport_init();

    /* Epoch 1: Simulate contributor timeout during reveal phase */
    CHECK(duel_state_init(&sm) == DUEL_SUCCESS);
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_commit(&sm, agg_hash) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_commit(&sm, cont_hash) == DUEL_SUCCESS);

    /* Open reveal window at T=0 */
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, agg_payload, sizeof(agg_payload)) == DUEL_SUCCESS);

    /* Contributor experiences virtual transport timeout: advance virtual clock past 2000ms buzzer */
    determ_dsf_clock_advance_ms(2001);

    /* Late contributor reveal attempted after buzzer: dropped with DUEL_DROPPED_BUZZER_EXCEEDED */
    CHECK(duel_submit_contributor_reveal(&sm, cont_payload, sizeof(cont_payload), true) == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* Aggregator buzzer fires: assert strict 2-of-2 epoch skipping terminates attempt without halting */
    duel_status_t buzzer_status = duel_state_poll_buzzer(&sm);
    CHECK(buzzer_status == ERR_EPOCH_SKIPPED_INCOMPLETE);
    CHECK(sm.state == DUEL_STATE_ABORTED);
    CHECK(sm.terminal_status == ERR_EPOCH_SKIPPED_INCOMPLETE);

    /* Subsequent calls after abort are rejected */
    CHECK(duel_submit_contributor_reveal(&sm, cont_payload, sizeof(cont_payload), true) == DUEL_ERR_INVALID_STATE);

    /* Assert node seamlessly transitions to Epoch 2 without deadlock or state corruption */
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    CHECK(sm.state == DUEL_STATE_COMMITMENT_PHASE);
    CHECK(duel_submit_aggregator_commit(&sm, agg_hash) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_commit(&sm, cont_hash) == DUEL_SUCCESS);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, agg_payload, sizeof(agg_payload)) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, cont_payload, sizeof(cont_payload), true) == DUEL_SUCCESS);

    /* Both reveals received before buzzer: epoch succeeds */
    CHECK(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    CHECK(sm.state == DUEL_STATE_VDF_EVALUATION);

    printf("  -> Liveness & Strict 2-of-2 Epoch Skipping verified!\n");
}

/* Test 2: Heaviest-Chain Fork Choice — PoSW Branch Resolution */
static void test_heaviest_chain_branch_resolution(void) {
    printf("[Test 2] Running PoSW Heaviest-Chain Branch Resolver Proof...\n");

    posw_branch_resolver_t resolver;
    posw_block_candidate_t genesis;
    memset(&genesis, 0, sizeof(genesis));
    genesis.height = 0;
    memset(genesis.block_hash, 0x11, 32);
    genesis.cumulative_vdf_iterations = 10000;
    genesis.timestamp = 1000;

    posw_branch_resolver_init(&resolver, &genesis);
    CHECK(resolver.has_tip == true);
    CHECK(resolver.canonical_tip.height == 0);
    CHECK(resolver.canonical_tip.cumulative_vdf_iterations == 10000);

    /* Scenario: Two competing blocks produced at Height 1 (Fork duel) */
    posw_block_candidate_t block_1a;
    memset(&block_1a, 0, sizeof(block_1a));
    block_1a.height = 1;
    memcpy(block_1a.prev_hash, genesis.block_hash, 32);
    memset(block_1a.block_hash, 0xAA, 32);
    block_1a.cumulative_vdf_iterations = 10000 + 50000; /* 60,000 iterations */
    block_1a.timestamp = 2000;

    posw_block_candidate_t block_1b;
    memset(&block_1b, 0, sizeof(block_1b));
    block_1b.height = 1;
    memcpy(block_1b.prev_hash, genesis.block_hash, 32);
    memset(block_1b.block_hash, 0xBB, 32);
    block_1b.cumulative_vdf_iterations = 10000 + 75000; /* 85,000 iterations (Heavier) */
    block_1b.timestamp = 2000;

    /* Feed first block (1A) to resolver: should be adopted */
    bool adopted_1a = posw_branch_resolver_consider(&resolver, &block_1a);
    CHECK(adopted_1a == true);
    const posw_block_candidate_t *tip = posw_branch_resolver_get_tip(&resolver);
    CHECK(tip != NULL);
    CHECK(tip->height == 1);
    CHECK(tip->cumulative_vdf_iterations == 60000);
    CHECK(memcmp(tip->block_hash, block_1a.block_hash, 32) == 0);

    /* Feed competing heavier block (1B) at the same height: node MUST adopt branch 1B */
    bool adopted_1b = posw_branch_resolver_consider(&resolver, &block_1b);
    CHECK(adopted_1b == true);
    tip = posw_branch_resolver_get_tip(&resolver);
    CHECK(tip != NULL);
    CHECK(tip->height == 1);
    CHECK(tip->cumulative_vdf_iterations == 85000);
    CHECK(memcmp(tip->block_hash, block_1b.block_hash, 32) == 0);

    /* Feed a third competing block (1C) at height 1 with only 70,000 iterations: MUST BE REJECTED */
    posw_block_candidate_t block_1c;
    memset(&block_1c, 0, sizeof(block_1c));
    block_1c.height = 1;
    memcpy(block_1c.prev_hash, genesis.block_hash, 32);
    memset(block_1c.block_hash, 0xCC, 32);
    block_1c.cumulative_vdf_iterations = 70000;
    block_1c.timestamp = 2000;

    bool adopted_1c = posw_branch_resolver_consider(&resolver, &block_1c);
    CHECK(adopted_1c == false);
    tip = posw_branch_resolver_get_tip(&resolver);
    CHECK(tip != NULL);
    CHECK(tip->height == 1);
    CHECK(tip->cumulative_vdf_iterations == 85000);
    CHECK(memcmp(tip->block_hash, block_1b.block_hash, 32) == 0);

    /* Extend heavier chain to Height 2 */
    posw_block_candidate_t block_2;
    memset(&block_2, 0, sizeof(block_2));
    block_2.height = 2;
    memcpy(block_2.prev_hash, block_1b.block_hash, 32);
    memset(block_2.block_hash, 0x22, 32);
    block_2.cumulative_vdf_iterations = 85000 + 80000; /* 165,000 iterations */
    block_2.timestamp = 3000;

    bool adopted_2 = posw_branch_resolver_consider(&resolver, &block_2);
    CHECK(adopted_2 == true);
    tip = posw_branch_resolver_get_tip(&resolver);
    CHECK(tip != NULL);
    CHECK(tip->height == 2);
    CHECK(tip->cumulative_vdf_iterations == 165000);

    printf("  -> PoSW Heaviest-Chain Branch Resolution verified!\n");
}

int main(void) {
    printf("=========================================\n");
    printf("Determ C99 K=2 PoSW Test Suite\n");
    printf("=========================================\n");

    test_liveness_timeout_and_epoch_skipping();
    test_heaviest_chain_branch_resolution();

    printf("=========================================\n");
    printf("ALL PoSW TESTS PASSED SUCCESSFULLY.\n");
    printf("=========================================\n");
    return 0;
}
