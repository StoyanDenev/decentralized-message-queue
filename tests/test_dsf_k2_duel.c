/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Deterministic Simulation Framework (DSF) Test Suite: K=2 VDF Duel.
 * Validates virtual clock injection, virtual transport, strict 2-of-2 buzzer skipping,
 * and high-speed simulation bypass.
 */

#define _POSIX_C_SOURCE 200809L

#include <determ/time/clock.h>
#include <determ/net/virtual_transport.h>
#include <determ/consensus/duel_state.h>
#include <determ/consensus/dda.h>
#include <determ/crypto/vdf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
static uint64_t real_wall_clock_ns(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    return (uint64_t)(((__uint128_t)mach_absolute_time() * tb.numer) / tb.denom);
}
#else
#include <time.h>
static uint64_t real_wall_clock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}
#endif

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

/*
 * ── Test 1: Clock Injection Seam ──────────────────────────────────────────────
 */
static void test_clock_injection_seam(void) {
    printf("[TEST 1] Clock Injection Seam Verification...\n");

    determ_dsf_clock_reset();
    TEST_ASSERT(determ_clock_now_ns() == 1000000000ULL); /* t0 = 1.0s */
    TEST_ASSERT(determ_clock_now_ms() == 1000ULL);

    determ_dsf_clock_advance_ns(500000000ULL); /* +500ms */
    TEST_ASSERT(determ_clock_now_ns() == 1500000000ULL);
    TEST_ASSERT(determ_clock_now_ms() == 1500ULL);

    determ_dsf_clock_advance_ms(250ULL); /* +250ms */
    TEST_ASSERT(determ_clock_now_ns() == 1750000000ULL);
    TEST_ASSERT(determ_clock_now_ms() == 1750ULL);

    determ_dsf_clock_set_ns(5000000000ULL); /* Set to 5.0s */
    TEST_ASSERT(determ_clock_now_ns() == 5000000000ULL);
    TEST_ASSERT(determ_clock_now_ms() == 5000ULL);

    printf("  -> PASS: Virtual clock advanced deterministically without thread sleep.\n");
}

/*
 * ── Test 2: Virtual Transport & Strict 2-of-2 Buzzer Skipping ─────────────────
 */
static void test_virtual_transport_buzzer_fallback(void) {
    printf("[TEST 2] Virtual Transport & Strict 2-of-2 Buzzer Skipping...\n");

    determ_dsf_clock_reset();
    determ_dsf_transport_init();

    /* 1. Initialize Aggregator state machine */
    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    const uint8_t agg_payload[32] = "AGGREGATOR-TRANSACTIONS-ROOT-12";
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_payload, 32) == DUEL_SUCCESS);

    /* 2. Fast-forward virtual clock 2001ms (beyond the 2000ms window) */
    determ_dsf_clock_advance_ms(2001);
    TEST_ASSERT(duel_state_elapsed_reveal_ns(&sm) == 2001000000ULL);

    /* 3. Inject Contributor's payload into Virtual Transport */
    const uint8_t cont_payload[32] = "CONTRIBUTOR-LATE-REVEAL-PAYLOAD";
    int virtual_sock_fd = 42;
    determ_dsf_queue_rx(virtual_sock_fd, cont_payload, 32);

    /* Read from Virtual Transport via determ_net_recv */
    uint8_t wire_rx[64];
    ssize_t n_read = determ_net_recv(virtual_sock_fd, wire_rx, sizeof(wire_rx), 0);
    TEST_ASSERT(n_read == 32);
    TEST_ASSERT(memcmp(wire_rx, cont_payload, 32) == 0);

    /* 4. Assert Aggregator state machine strictly rejects late payload */
    duel_status_t sub_rc = duel_submit_contributor_reveal(&sm, wire_rx, (uint32_t)n_read, true);
    TEST_ASSERT(sub_rc == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* Poll buzzer: state machine must lock buffer and trigger strict 2-of-2 skip (abort epoch) */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
    TEST_ASSERT(sm.reveal_buffer_locked == true);
    TEST_ASSERT(sm.straggler_fallback_active == false);
    TEST_ASSERT(sm.vrf_round == 1);

    /* Verify virtual transport fault injection: EWOULDBLOCK */
    determ_dsf_inject_ewouldblock_rx(true);
    ssize_t eb_rc = determ_net_recv(virtual_sock_fd, wire_rx, sizeof(wire_rx), 0);
    TEST_ASSERT(eb_rc == -1 && errno == EWOULDBLOCK);
    determ_dsf_inject_ewouldblock_rx(false);

    /* Verify virtual transport fault injection: byte drop */
    determ_dsf_queue_rx(virtual_sock_fd, cont_payload, 10);
    determ_dsf_inject_drop_bytes(4);
    ssize_t drop_rc = determ_net_recv(virtual_sock_fd, wire_rx, sizeof(wire_rx), 0);
    TEST_ASSERT(drop_rc == 6); /* 10 - 4 = 6 bytes delivered */

    printf("  -> PASS: 2001ms payload rejected, strict 2-of-2 skip executed, EWOULDBLOCK & drops verified.\n");
}

/*
 * ── Test 3: VDF Simulation Bypass & Dynamic Difficulty Adjustment (DDA) ───────
 */
static void test_vdf_simulation_bypass_and_dda(void) {
    printf("[TEST 3] VDF Simulation Bypass & DDA Calibration...\n");

    determ_dsf_clock_reset();
    uint64_t clock_before = determ_clock_now_ms();

    /* Enable DSF VDF bypass for TARGET_VDF_MS (3000ms) */
    determ_dsf_set_vdf_bypass(true, TARGET_VDF_MS);

    vdf_context_t ctx;
    const uint8_t seed[32] = "TEST-SIMULATION-SEED-OPAQUE-K2";
    TEST_ASSERT(vdf_init(&ctx, seed, sizeof(seed), 100000ULL) == 0);

    uint8_t out1[VDF_OUTPUT_LEN];
    uint64_t wall_start = real_wall_clock_ns();
    int eval_rc = vdf_evaluate(&ctx, out1);
    uint64_t wall_elapsed = real_wall_clock_ns() - wall_start;

    TEST_ASSERT(eval_rc == 0);
    /* Real wall clock must be near zero (< 5ms) */
    TEST_ASSERT(wall_elapsed < 5000000ULL);

    /* Virtual clock must have advanced by exactly TARGET_VDF_MS (3000ms) */
    uint64_t clock_after = determ_clock_now_ms();
    TEST_ASSERT(clock_after - clock_before == TARGET_VDF_MS);
    TEST_ASSERT(ctx.elapsed_ns == TARGET_VDF_MS * 1000000ULL);

    /* Verify mock hash verification succeeds using separate verification context */
    vdf_context_t verify_ctx;
    TEST_ASSERT(vdf_verify(&verify_ctx, seed, sizeof(seed), 100000ULL, out1) == 1);

    /* Verify DDA integration with simulated time */
    dda_tracker_t dda;
    dda_init(&dda, 100000ULL);
    dda_record_vdf_time(&dda, (uint32_t)(ctx.elapsed_ns / 1000000ULL));
    uint32_t avg = calculate_average_vdf_time(&dda);
    TEST_ASSERT(avg == TARGET_VDF_MS);

    printf("  -> PASS: VDF bypass simulated %ums in %.2f us without CPU burn; DDA registered %ums.\n",
           TARGET_VDF_MS, (double)wall_elapsed / 1000.0, TARGET_VDF_MS);
}

/*
 * ── Test 4: Acceptance Test — 10-Block Simulated K=2 Duel (< 50ms Real Time) ──
 */
static void test_10_block_simulated_duel_benchmark(void) {
    printf("[TEST 4] Acceptance Benchmark: 10-Block Simulated K=2 Duel (< 50ms Wall-Clock)...\n");

    determ_dsf_clock_reset();
    determ_dsf_transport_init();
    determ_dsf_set_vdf_bypass(true, TARGET_VDF_MS);

    dda_tracker_t dda;
    dda_init(&dda, 50000ULL);

    uint8_t prev_hash[32] = {0};
    uint64_t wall_start_ns = real_wall_clock_ns();
    uint64_t blocks_finalized = 0;
    uint64_t epochs_skipped = 0;

    for (uint64_t block = 1; block <= 10; block++) {
        duel_state_machine_t sm;
        TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
        TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
        TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);

        uint8_t agg_data[32];
        memset(agg_data, (uint8_t)block, sizeof(agg_data));
        TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_data, sizeof(agg_data)) == DUEL_SUCCESS);

        if (block % 3 == 0) {
            /* Contributor drops / straggles: fast-forward virtual clock past buzzer */
            determ_dsf_clock_advance_ms(2001);
            TEST_ASSERT(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
            TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
            TEST_ASSERT(sm.straggler_fallback_active == false);
            epochs_skipped++;
            continue;
        } else {
            /* Contributor delivers timely reveal at +500ms */
            determ_dsf_clock_advance_ms(500);
            uint8_t cont_data[32];
            memset(cont_data, (uint8_t)(block + 0x80), sizeof(cont_data));
            TEST_ASSERT(duel_submit_contributor_reveal(&sm, cont_data, sizeof(cont_data), true) == DUEL_SUCCESS);
            /* Advance remaining window to buzzer */
            determ_dsf_clock_advance_ms(1500);
            TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
            TEST_ASSERT(sm.straggler_fallback_active == false);
        }

        TEST_ASSERT(sm.state == DUEL_STATE_VDF_EVALUATION);

        /* VDF Evaluation using simulation bypass (advances virtual clock by TARGET_VDF_MS) */
        vdf_context_t vdf;
        uint64_t iters = dda_get_next_iterations(&dda);
        TEST_ASSERT(vdf_init(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, iters) == 0);

        uint8_t vdf_out[VDF_OUTPUT_LEN];
        TEST_ASSERT(vdf_evaluate(&vdf, vdf_out) == 0);

        /* Update DDA and block chain link */
        dda_commit_block(&dda, (uint32_t)(vdf.elapsed_ns / 1000000ULL));
        memcpy(prev_hash, vdf_out, 32);
        blocks_finalized++;
    }

    uint64_t wall_elapsed_ns = real_wall_clock_ns() - wall_start_ns;
    double wall_elapsed_ms = (double)wall_elapsed_ns / 1000000.0;
    uint64_t virtual_elapsed_ms = determ_clock_now_ms() - 1000ULL;

    printf("  [Benchmark Results]\n");
    printf("  -> Total Blocks Finalized: %llu, Epochs Skipped: %llu\n",
           (unsigned long long)blocks_finalized, (unsigned long long)epochs_skipped);
    printf("  -> Simulated Virtual Time: %llu ms (%.1f seconds)\n",
           (unsigned long long)virtual_elapsed_ms, (double)virtual_elapsed_ms / 1000.0);
    printf("  -> Real Wall-Clock Time:   %.2f ms (Target: < 50.0 ms)\n", wall_elapsed_ms);

    /* HARD ACCEPTANCE CRITERION: Must execute in under 50 milliseconds */
    TEST_ASSERT(wall_elapsed_ms < 50.0);

    printf("  -> PASS: 10-block simulated duel completed in %.2f ms (< 50 ms limit)!\n", wall_elapsed_ms);
}

int main(void) {
    printf("=================================================================\n");
    printf("Running Deterministic Simulation Framework (DSF) K=2 Test Suite\n");
    printf("=================================================================\n");

    test_clock_injection_seam();
    test_virtual_transport_buzzer_fallback();
    test_vdf_simulation_bypass_and_dda();
    test_10_block_simulated_duel_benchmark();

    printf("=================================================================\n");
    printf("ALL DSF TESTS PASSED: Virtual Seams & Consensus Perfectly Aligned\n");
    printf("=================================================================\n");
    return 0;
}
