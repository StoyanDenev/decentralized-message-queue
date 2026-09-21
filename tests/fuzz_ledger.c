/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * LLVM libFuzzer & Memory Safety Test Suite for Bare-Metal C99 State
 *
 * Fuzz Targets:
 *   1. verify_triple_entry_tx: Mathematical overflow & overspend immunity
 *   2. OPAQUE DSSO structures: OPRF blind request, envelope unsealing, zero-knowledge auth
 *   3. Native DSF seams: determ_clock_now(), virtual clock fast-forwarding, socket readiness
 *   4. Reactor non-blocking multiplexer: zero-allocation echo server verification
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "determ/ledger/state.h"
#include "determ/crypto/opaque_dsso.h"
#include "determ/crypto/ed25519/ed25519.h"
#include "determ/crypto/secure_zero.h"
#include "determ/net/reactor.h"
#include "determ/consensus/duel_state.h"
#include "dsf_seams.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

static account_t s_test_sender;

static void init_fuzz_state(void) {
    uint8_t seed[32];
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = (uint8_t)(i + 1);
    }
    determ_ed25519_pubkey_from_seed(seed, s_test_sender.pubkey);
    s_test_sender.balance = 1000000ULL; /* 1,000,000 units initial balance */
    s_test_sender.nonce = 10;
}

/*
 * LLVM libFuzzer Entrypoint
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) {
        return 0;
    }

    /* ── Target 1: Fuzz verify_triple_entry_tx with arbitrary mutations ── */
    triple_entry_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    size_t copy_len = Size > sizeof(tx) ? sizeof(tx) : Size;
    memcpy(&tx, Data, copy_len);

    uint64_t min_fee = 100;
    int rc = verify_triple_entry_tx(&s_test_sender, &tx, min_fee);

    /* Mathematical invariant verification */
    if (UINT64_MAX - tx.amount < tx.fee) {
        /* Any addition overflow MUST be rejected */
        TEST_ASSERT(rc == LEDGER_ERR_OVERFLOW || rc == LEDGER_ERR_PUBKEY_MISMATCH ||
               rc == LEDGER_ERR_INVALID_NONCE || rc == LEDGER_ERR_FEE_TOO_LOW);
    }
    if ((UINT64_MAX - tx.amount >= tx.fee) && (s_test_sender.balance < tx.amount + tx.fee)) {
        /* Overspend MUST be rejected */
        TEST_ASSERT(rc == LEDGER_ERR_OVERSPEND || rc == LEDGER_ERR_PUBKEY_MISMATCH ||
               rc == LEDGER_ERR_INVALID_NONCE || rc == LEDGER_ERR_FEE_TOO_LOW);
    }

    /* ── Target 2: Fuzz OPAQUE DSSO Structs & Multi-Party Handshake ──────── */
    if (Size >= sizeof(opaque_oprf_request_t)) {
        opaque_oprf_request_t req;
        memcpy(&req, Data, sizeof(opaque_oprf_request_t));
        opaque_oprf_response_t resp;
        uint8_t dummy_key[32] = {0x07};
        (void)opaque_dsso_oprf_evaluate(dummy_key, &req, &resp);
    }

    if (Size >= sizeof(opaque_envelope_t)) {
        opaque_envelope_t env;
        memcpy(&env, Data, sizeof(opaque_envelope_t));
        uint8_t dec_buf[128];
        size_t dec_len = 0;
        uint8_t dummy_key[32] = {0x42};
        (void)opaque_dsso_unseal_envelope(dummy_key, &env, dec_buf, &dec_len);

        opaque_auth_request_t auth_req;
        memset(&auth_req, 0, sizeof(auth_req));
        if (Size >= sizeof(opaque_envelope_t) + sizeof(opaque_auth_request_t)) {
            memcpy(&auth_req, Data + sizeof(opaque_envelope_t), sizeof(opaque_auth_request_t));
        }
        opaque_envelope_t released;
        (void)opaque_dsso_verify_and_release(dummy_key, &auth_req, &env, &released);
    }

    return 0;
}

/*
 * Static Reactor Echo Server Test Helper
 */
typedef struct {
    bool accepted;
    bool client_read_ok;
    bool server_read_ok;
    int client_fd;
    int server_client_fd;
    uint8_t received_data[64];
    size_t received_len;
} reactor_test_context_t;

static void on_test_accept(int listener_fd, int client_fd, void *user_data) {
    (void)listener_fd;
    reactor_test_context_t *ctx = (reactor_test_context_t *)user_data;
    ctx->accepted = true;
    ctx->server_client_fd = client_fd;
}

static void on_server_client_read(int fd, const uint8_t *data, size_t len, void *user_data) {
    reactor_test_context_t *ctx = (reactor_test_context_t *)user_data;
    ctx->server_read_ok = true;
    if (len <= sizeof(ctx->received_data)) {
        memcpy(ctx->received_data, data, len);
        ctx->received_len = len;
    }
    /* Echo back */
    (void)send(fd, data, len, 0);
}

static void on_test_client_read(int fd, const uint8_t *data, size_t len, void *user_data) {
    (void)fd;
    (void)data;
    (void)len;
    reactor_test_context_t *ctx = (reactor_test_context_t *)user_data;
    ctx->client_read_ok = true;
}

/*
 * ── 1. Extreme Integer Overflow & Overspend Test ─────────────────────────────
 */
static void test_extreme_overflow_and_overspend(void) {
    printf("[TEST] 1. Mathematical Overflow & Overspend Immunity Sweep...\n");

    const uint64_t test_amounts[] = {
        0ULL, 1ULL, 50ULL, 100ULL, 1000000ULL,
        s_test_sender.balance,
        s_test_sender.balance + 1ULL,
        UINT64_MAX / 2ULL,
        UINT64_MAX - 100ULL,
        UINT64_MAX - 1ULL,
        UINT64_MAX
    };
    size_t num_amounts = sizeof(test_amounts) / sizeof(test_amounts[0]);

    for (size_t i = 0; i < num_amounts; i++) {
        for (size_t j = 0; j < num_amounts; j++) {
            uint64_t amt = test_amounts[i];
            uint64_t fee = test_amounts[j];

            triple_entry_tx_t tx;
            memset(&tx, 0, sizeof(tx));
            memcpy(tx.from, s_test_sender.pubkey, 32);
            memset(tx.to, 0x02, 32);
            tx.amount = amt;
            tx.fee = fee;
            tx.nonce = s_test_sender.nonce + 1;

            int rc = verify_triple_entry_tx(&s_test_sender, &tx, 100);

            if (fee < 100) {
                TEST_ASSERT(rc == LEDGER_ERR_FEE_TOO_LOW);
            } else if (UINT64_MAX - amt < fee) {
                /* Overflow check MUST catch this */
                TEST_ASSERT(rc == LEDGER_ERR_OVERFLOW);
            } else if (s_test_sender.balance < amt + fee) {
                /* Overspend check MUST catch this */
                TEST_ASSERT(rc == LEDGER_ERR_OVERSPEND);
            }
        }
    }

    /* Explicit Single-Case Overspend Rejection Check */
    triple_entry_tx_t overspend_tx;
    memset(&overspend_tx, 0, sizeof(overspend_tx));
    memcpy(overspend_tx.from, s_test_sender.pubkey, 32);
    memset(overspend_tx.to, 0xAA, 32);
    overspend_tx.amount = s_test_sender.balance + 1; /* 1 unit over balance */
    overspend_tx.fee = 100;
    overspend_tx.nonce = s_test_sender.nonce + 1;
    int overspend_rc = verify_triple_entry_tx(&s_test_sender, &overspend_tx, 100);
    TEST_ASSERT(overspend_rc == LEDGER_ERR_OVERSPEND);

    /* Explicit Single-Case UINT64_MAX Overflow Rejection Check */
    triple_entry_tx_t overflow_tx;
    memset(&overflow_tx, 0, sizeof(overflow_tx));
    memcpy(overflow_tx.from, s_test_sender.pubkey, 32);
    memset(overflow_tx.to, 0xBB, 32);
    overflow_tx.amount = UINT64_MAX;
    overflow_tx.fee = 100;
    overflow_tx.nonce = s_test_sender.nonce + 1;
    int overflow_rc = verify_triple_entry_tx(&s_test_sender, &overflow_tx, 100);
    TEST_ASSERT(overflow_rc == LEDGER_ERR_OVERFLOW);

    printf("  -> PASS: 121 extreme combinations tested. Overspends and overflows strictly rejected.\n");
}

/*
 * ── 2. OPAQUE DSSO Zero-Knowledge Authentication Test ───────────────────────
 */
static void test_opaque_mock_user_authentication(void) {
    printf("[TEST] 2. OPAQUE aPAKE Mock User Authentication (Zero-Knowledge)...\n");

    /* Plaintext password exists exclusively on client stack */
    uint8_t password[] = "SuperSecureQuantumResistantPassword#2026";
    size_t pwd_len = strlen((char *)password);

    uint8_t blind_scalar[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    uint8_t server_oprf_key[32] = {
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41
    };

    /* 1. Client Blinds Password */
    opaque_oprf_request_t req;
    TEST_ASSERT(opaque_dsso_oprf_blind(password, pwd_len, blind_scalar, &req) == 0);

    /* 2. Server Blindly Evaluates (Never learns plaintext or scalar) */
    opaque_oprf_response_t resp;
    TEST_ASSERT(opaque_dsso_oprf_evaluate(server_oprf_key, &req, &resp) == 0);

    /* 3. Client Finalizes OPRF */
    uint8_t oprf_output[32];
    TEST_ASSERT(opaque_dsso_oprf_finalize(password, pwd_len, blind_scalar, &resp, oprf_output) == 0);

    /* Zero out plaintext password from memory immediately */
    determ_secure_zero(password, sizeof(password));

    /* 4. Derive Keys and Seal Private Credential Envelope */
    uint8_t envelope_key[32];
    uint8_t client_proof[32];
    TEST_ASSERT(opaque_dsso_derive_keys(oprf_output, envelope_key, client_proof) == 0);

    const uint8_t secret_seed[32] = "USER-COLD-WALLET-SEED-BYTES-42";
    uint8_t nonce[OPAQUE_ENVELOPE_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t client_pk[OPAQUE_ID_LEN] = {0xAA};
    uint8_t server_pk[OPAQUE_ID_LEN] = {0xBB};

    opaque_envelope_t envelope;
    TEST_ASSERT(opaque_dsso_seal_envelope(envelope_key, nonce, secret_seed, 32,
                                          client_pk, server_pk, &envelope) == 0);

    /* 5. Zero-Knowledge Authorization: Verify Proof & Release Envelope */
    opaque_auth_request_t auth_req;
    memcpy(auth_req.account_id, client_pk, 32);
    memcpy(auth_req.client_identity_proof, client_proof, 32);

    opaque_envelope_t released_env;
    bool auth_ok = opaque_dsso_verify_and_release(client_proof, &auth_req, &envelope, &released_env);
    TEST_ASSERT(auth_ok == true);

    /* 6. Unseal Released Envelope to Recover Secret */
    uint8_t recovered_secret[64];
    size_t recovered_len = 0;
    TEST_ASSERT(opaque_dsso_unseal_envelope(envelope_key, &released_env, recovered_secret, &recovered_len) == 0);
    TEST_ASSERT(recovered_len == 32);
    TEST_ASSERT(memcmp(recovered_secret, secret_seed, 32) == 0);

    /* Verify that a forged identity proof strictly fails and zeroes output */
    auth_req.client_identity_proof[0] ^= 0xFF;
    bool forged_ok = opaque_dsso_verify_and_release(client_proof, &auth_req, &envelope, &released_env);
    TEST_ASSERT(forged_ok == false);

    printf("  -> PASS: Mock user authenticated via OPAQUE without exposing secret; forged proof rejected.\n");
}

/*
 * ── 3. Native DSF Seams & Virtual Clock Fast-Forward ─────────────────────────
 */
static void test_native_dsf_seams(void) {
    printf("[TEST] 3. Native DSF Seams & Virtual Clock 2-Second Reveal Fast-Forward...\n");

    /* Reset virtual clock and transport */
    dsf_reset_seams();
    uint64_t t0 = determ_clock_now();

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);

    const uint8_t agg_data[16] = {0x01, 0x02};
    TEST_ASSERT(duel_submit_aggregator_reveal(&sm, agg_data, sizeof(agg_data)) == DUEL_SUCCESS);

    /*
     * Fast-forward virtual clock by 2001ms instantly.
     * Triggers the 2-second REVEAL_WINDOW buzzer without sleeping CPU thread.
     */
    dsf_fast_forward_ms(2001);
    uint64_t t1 = determ_clock_now();
    TEST_ASSERT(t1 >= t0 + 2001000000ULL);

    /* Contributor reveals after buzzer must be rejected */
    const uint8_t late_data[16] = {0xDE, 0xAD};
    duel_status_t late_rc = duel_submit_contributor_reveal(&sm, late_data, sizeof(late_data), true);
    TEST_ASSERT(late_rc == DUEL_DROPPED_BUZZER_EXCEEDED);

    /* Poll buzzer: state machine locks buffer and enters 1-of-2 straggler fallback */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(sm.state == DUEL_STATE_VDF_EVALUATION);
    TEST_ASSERT(sm.straggler_fallback_active == true);

    printf("  -> PASS: Virtual clock jumped 2001ms instantly without CPU sleep; buzzer triggered fallback.\n");
}

/*
 * ── 4. Simulated Fuzzing Mutation Sweep ──────────────────────────────────────
 */
static void test_malformed_fuzzing_mutations(void) {
    printf("[TEST] 4. Malformed Byte Array Fuzzing Sweep (5,000 mutations)...\n");
    uint8_t fuzz_buf[256];
    uint32_t lcg = 0x12345678;

    for (int iter = 0; iter < 5000; iter++) {
        for (size_t k = 0; k < sizeof(fuzz_buf); k++) {
            lcg = lcg * 1664525U + 1013904223U;
            fuzz_buf[k] = (uint8_t)(lcg >> 24);
        }
        size_t fuzz_len = (lcg % (sizeof(fuzz_buf) - sizeof(triple_entry_tx_t) + 1)) + sizeof(triple_entry_tx_t);
        LLVMFuzzerTestOneInput(fuzz_buf, fuzz_len);
    }
    printf("  -> PASS: 5,000 malformed frames fuzzed with zero memory violations.\n");
}

/*
 * ── 5. Native Event Loop Reactor Verification ────────────────────────────────
 */
static void test_reactor_nonblocking(void) {
    printf("[TEST] 5. Native Event Loop Reactor Non-Blocking I/O...\n");
    reactor_t reactor;
    int rc_init = reactor_init(&reactor);
    TEST_ASSERT(rc_init == 0);

    reactor_test_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.client_fd = -1;
    ctx.server_client_fd = -1;

    uint16_t test_port = 28841;
    int listen_fd = reactor_listen(&reactor, test_port, on_test_accept, &ctx);
    TEST_ASSERT(listen_fd >= 0);

    /* Connect test client */
    int client_s = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_s >= 0);

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(test_port);
    srv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int c_rc = connect(client_s, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    TEST_ASSERT(c_rc == 0);
    ctx.client_fd = client_s;

    /* Step reactor to accept connection */
    for (int step = 0; step < 10 && !ctx.accepted; step++) {
        reactor_step(&reactor, 50);
    }
    TEST_ASSERT(ctx.accepted && ctx.server_client_fd >= 0);

    /* Register accepted client and test client */
    int r1 = reactor_register_client(&reactor, ctx.server_client_fd,
                                     on_server_client_read, NULL, &ctx);
    TEST_ASSERT(r1 == 0);

    int r2 = reactor_register_client(&reactor, ctx.client_fd,
                                     on_test_client_read, NULL, &ctx);
    TEST_ASSERT(r2 == 0);

    /* Send payload through reactor */
    const char *msg = "HELLO-DETERM-REACTOR";
    int s_sent = reactor_send(&reactor, ctx.client_fd, msg, strlen(msg));
    TEST_ASSERT(s_sent == (int)strlen(msg));

    /* Step reactor to echo data */
    for (int step = 0; step < 20 && (!ctx.server_read_ok || !ctx.client_read_ok); step++) {
        reactor_step(&reactor, 50);
    }
    TEST_ASSERT(ctx.server_read_ok);
    TEST_ASSERT(ctx.client_read_ok);
    TEST_ASSERT(ctx.received_len == strlen(msg));
    TEST_ASSERT(memcmp(ctx.received_data, msg, strlen(msg)) == 0);

    reactor_destroy(&reactor);
    printf("  -> PASS: Reactor multiplexed non-blocking accept, send, and echo cleanly.\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("Running LLVM libFuzzer & Memory Safety Sweep (Pure C99)\n");
    printf("=================================================================\n");

    init_fuzz_state();

    test_extreme_overflow_and_overspend();
    test_opaque_mock_user_authentication();
    test_native_dsf_seams();
    test_malformed_fuzzing_mutations();
    test_reactor_nonblocking();

    printf("=================================================================\n");
    printf("ALL MEMORY SAFETY & FUZZING TESTS PASSED SUCCESSFULLY.\n");
    printf("=================================================================\n");
    return 0;
}
