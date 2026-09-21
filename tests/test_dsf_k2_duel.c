/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Deterministic Simulation Framework (DSF) for K=2 VDF Duel Consensus.
 *
 * Verifies:
 *   1. Clock Injection Seam: deterministic time control, microsecond boundary jumps.
 *   2. Virtual Transport Seam: OS socket readiness override, EWOULDBLOCK & drop injection.
 *   3. Task 2 Test Sequence: 2001ms time jump, payload injection, strict buzzer rejection,
 *      and seamless 1-of-2 VDF fallback execution.
 *   4. VDF Simulation Bypass: instant mock hash & virtual clock advance by TARGET_VDF_MS (5000ms).
 *   5. Acceptance Test: 10-block simulated K=2 Duel in under 50ms real wall-clock time.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#include "determ/time/clock.h"
#include "determ/net/virtual_transport.h"
#include "determ/consensus/duel_state.h"
#include "determ/crypto/vdf.h"
#include "determ/consensus/dda.h"
#include "determ/net/k2_net.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

/* Helper: get real host CPU wall-clock in nanoseconds for benchmark validation */
static uint64_t real_wall_clock_ns(void) {
#if defined(__APPLE__)
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        (void)mach_timebase_info(&tb);
    }
    uint64_t t = mach_absolute_time();
    return (uint64_t)(((__uint128_t)t * tb.numer) / tb.denom);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

/*
 * ── Test 1: Clock Injection Seam & Monotonic Boundary Verification ────────────
 */
static void test_clock_injection_seam(void) {
    printf("[TEST 1] Clock Injection Seam & Reveal Window Boundary Verification...\n");

    determ_dsf_clock_reset();
    TEST_ASSERT(determ_clock_now_ns() == 1000000000ULL);

    /* Advance clock to 1000ms */
    uint64_t start_time = determ_clock_now_ns();
    TEST_ASSERT(start_time == 1000000000ULL);

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);

    /* Submit aggregator reveal */
    const uint8_t agg_data[16] = {0xAA, 0xBB};
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_data, sizeof(agg_data)) == DUEL_SUCCESS);

    /* Fast-forward virtual clock to 1999ms from reveal start (boundary - 1ms) */
    determ_dsf_clock_advance_ms(1999);
    TEST_ASSERT(duel_state_elapsed_reveal_ns(&sm) == 1999000000ULL);

    /* Contributor reveal at 1999ms MUST be accepted */
    const uint8_t cont_data[16] = {0x11, 0x22};
    TEST_ASSERT(duel_submit_contributor_reveal(&sm, cont_data, sizeof(cont_data), true) == DUEL_SUCCESS);

    printf("  -> PASS: Virtual clock advanced 1999ms instantly; payload within boundary accepted.\n");
}

/*
 * ── Test 2: Virtual Transport Seam & 2001ms Buzzer Straggler Fallback ──────────
 */
static void test_virtual_transport_buzzer_fallback(void) {
    printf("[TEST 2] Virtual Transport Seam & 2001ms Buzzer Fallback Execution...\n");

    determ_dsf_clock_reset();
    determ_dsf_transport_init();

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);

    /* 1. Simulate Aggregator and Contributor entering REVEAL_WINDOW */
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    const uint8_t agg_payload[32] = "AGGREGATOR-TRANSACTIONS-ROOT-12";
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_payload, 32) == DUEL_SUCCESS);

    /* 2. Fast-forward the virtual clock 2001ms (strictly beyond the 2000ms window) */
    determ_dsf_clock_advance_ms(2001);
    TEST_ASSERT(duel_state_elapsed_reveal_ns(&sm) == 2001000000ULL);

    /* 3. Inject the Contributor's payload into the Virtual Transport */
    const uint8_t cont_payload[32] = "CONTRIBUTOR-LATE-REVEAL-PAYLOAD";
    int virtual_sock_fd = 42;
    determ_dsf_queue_rx(virtual_sock_fd, cont_payload, 32);

    /* Read from the Virtual Transport via determ_net_recv */
    uint8_t wire_rx[64];
    ssize_t n_read = determ_net_recv(virtual_sock_fd, wire_rx, sizeof(wire_rx), 0);
    TEST_ASSERT(n_read == 32);
    TEST_ASSERT(memcmp(wire_rx, cont_payload, 32) == 0);

    /* 4. Assert Aggregator state machine strictly rejects the payload */
    duel_status_t sub_rc = duel_submit_contributor_reveal(&sm, wire_rx, (uint32_t)n_read, true);
    TEST_ASSERT(sub_rc == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* Poll buzzer: state machine must lock buffer and trigger 1-of-2 straggler fallback */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_VDF_EVALUATION);
    TEST_ASSERT(sm.reveal_buffer_locked == true);
    TEST_ASSERT(sm.straggler_fallback_active == true);

    /* Assert VDF staged input contains exclusively the Aggregator's payload (4-byte len + payload + 4-byte 0 len) */
    TEST_ASSERT(sm.vdf_input_len == 4 + 32 + 4);
    TEST_ASSERT(memcmp(&sm.vdf_input_buffer[4], agg_payload, 32) == 0);

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

    printf("  -> PASS: 2001ms payload rejected, 1-of-2 fallback executed, EWOULDBLOCK & drops verified.\n");
}

/*
 * ── Test 3: VDF Simulation Bypass & Dynamic Difficulty Adjustment (DDA) ───────
 */
static void test_vdf_simulation_bypass_and_dda(void) {
    printf("[TEST 3] VDF Simulation Bypass & DDA Calibration...\n");

    determ_dsf_clock_reset();
    uint64_t clock_before = determ_clock_now_ms();

    /* Enable DSF VDF bypass for TARGET_VDF_MS (5000ms) */
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

    /* Virtual clock must have advanced by exactly TARGET_VDF_MS (5000ms) */
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

    printf("  -> PASS: VDF bypass simulated 5000ms in %.2f us without CPU burn; DDA registered 5000ms.\n",
           (double)wall_elapsed / 1000.0);
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
            TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
            TEST_ASSERT(sm.straggler_fallback_active == true);
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

        /* VDF Evaluation using simulation bypass (advances virtual clock by 5000ms) */
        vdf_context_t vdf;
        uint64_t iters = dda_get_next_iterations(&dda);
        TEST_ASSERT(vdf_init(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, iters) == 0);

        uint8_t vdf_out[VDF_OUTPUT_LEN];
        TEST_ASSERT(vdf_evaluate(&vdf, vdf_out) == 0);

        /* Update DDA and block chain link */
        dda_commit_block(&dda, (uint32_t)(vdf.elapsed_ns / 1000000ULL));
        memcpy(prev_hash, vdf_out, 32);
    }

    uint64_t wall_elapsed_ns = real_wall_clock_ns() - wall_start_ns;
    double wall_elapsed_ms = (double)wall_elapsed_ns / 1000000.0;
    uint64_t virtual_elapsed_ms = determ_clock_now_ms() - 1000ULL;

    printf("  [Benchmark Results]\n");
    printf("  -> Total Blocks Finalized: 10\n");
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
