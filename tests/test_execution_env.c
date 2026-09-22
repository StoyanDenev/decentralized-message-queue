/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Execution Environment Verification Suite (C99 Bare-Metal Architecture):
 *   1. Native Single-Threaded Reactor (kqueue / epoll / select) with 2000ms monotonic buzzer
 *   2. Flat Triple-Entry Ledger Memory Arena (global_ledger[MAX_ACCOUNTS])
 *   3. OPAQUE DSSO Envelope Memory Arena (dsso_registry[MAX_IDENTITIES])
 */

#include "test_harness.h"
#include <determ/net/reactor.h>
#include <determ/ledger/state.h>
#include <determ/crypto/opaque_dsso.h>
#include <determ/consensus/duel_state.h>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/time/clock.h>
#include <string.h>

/*
 * Test 1: Native Single-Threaded Reactor & Monotonic 2000ms Buzzer
 */
static void test_reactor_epoch_buzzer(void) {
    printf("[TEST 1] Native Reactor & 2000ms Buzzer Ingestion Halt...\n");

    reactor_t reactor;
    TEST_ASSERT(reactor_init(&reactor) == 0);
    TEST_ASSERT(reactor.slots != NULL);
    TEST_ASSERT(reactor.ingestion_halted == false);

    duel_state_machine_t sm;
    duel_state_init(&sm);
    sm.state = DUEL_STATE_AWAITING_REVEALS;

    /* Set clock so elapsed time >= 2000ms from epoch start */
    uint64_t epoch_start = 1000000000ULL;
#if defined(DETERM_DSF_ENABLED)
    determ_dsf_clock_set_ns(epoch_start + 2000000000ULL);
#endif

    int rc = reactor_run_epoch(&reactor, &sm, epoch_start);
    TEST_ASSERT(rc == 0);

    /* Ingestion must be halted */
    TEST_ASSERT(reactor.ingestion_halted == true);

    /* State machine must have aborted due to incomplete reveals within 2000ms reveal window */
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
    TEST_ASSERT(sm.terminal_status == ERR_EPOCH_SKIPPED_INCOMPLETE);

    reactor_destroy(&reactor);
    printf("  -> PASS: Reactor halted network ingestion and triggered REVEAL_WINDOW buzzer.\n");
}

/*
 * Test 2: Flat Triple-Entry Ledger Memory Arena & verify_triple_entry_tx_payload
 */
static void test_triple_entry_ledger_arena(void) {
    printf("[TEST 2] Triple-Entry Ledger Memory Arena (global_ledger[MAX_ACCOUNTS])...\n");

    global_ledger_init();

    /* Keypair generation */
    uint8_t seed[32];
    memset(seed, 0x42, 32);
    uint8_t sender_pk[32];
    determ_ed25519_pubkey_from_seed(seed, sender_pk);

    uint64_t init_balance = 5000000ULL;
    uint64_t init_nonce = 10ULL;
    TEST_ASSERT(global_ledger_register(sender_pk, init_balance, init_nonce) == 0);

    determ_account_t *found = global_ledger_find(sender_pk);
    TEST_ASSERT(found != NULL);
    TEST_ASSERT(found->balance == init_balance);
    TEST_ASSERT(found->nonce == init_nonce);

    /* Build valid transaction */
    triple_entry_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memcpy(tx.from, sender_pk, 32);
    memset(tx.to, 0xEE, 32);
    tx.amount = 100000ULL;
    tx.fee = 500ULL;
    tx.nonce = init_nonce + 1; /* Strictly incrementing */

    uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
    triple_entry_tx_signing_bytes(&tx, signing_bytes);
    determ_ed25519_sign(seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx.sig);

    /* Test verify_triple_entry_tx_payload(payload) */
    int rc = verify_triple_entry_tx_payload((const uint8_t *)&tx);
    TEST_ASSERT(rc == LEDGER_OK);

    /* Test invalid nonce rejection */
    tx.nonce = init_nonce; /* Replay */
    triple_entry_tx_signing_bytes(&tx, signing_bytes);
    determ_ed25519_sign(seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx.sig);
    TEST_ASSERT(verify_triple_entry_tx_payload((const uint8_t *)&tx) == ERR_INVALID_NONCE);

    /* Test overspend rejection */
    tx.nonce = init_nonce + 1;
    tx.amount = init_balance + 1;
    triple_entry_tx_signing_bytes(&tx, signing_bytes);
    determ_ed25519_sign(seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx.sig);
    TEST_ASSERT(verify_triple_entry_tx_payload((const uint8_t *)&tx) == ERR_OVERSPEND);

    /* Test integer overflow rejection */
    tx.amount = UINT64_MAX;
    triple_entry_tx_signing_bytes(&tx, signing_bytes);
    determ_ed25519_sign(seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx.sig);
    TEST_ASSERT(verify_triple_entry_tx_payload((const uint8_t *)&tx) == ERR_OVERFLOW);

    printf("  -> PASS: Triple-Entry Arena verified nonces, signatures, overflows, and overspends.\n");
}

/*
 * Test 3: OPAQUE Envelope Arena & verify_opaque_handshake(client_payload)
 */
static void test_opaque_envelope_arena(void) {
    printf("[TEST 3] OPAQUE Envelope Memory Arena (dsso_registry[MAX_IDENTITIES])...\n");

    dsso_registry_clear();

    uint8_t account_id[32] = {0xAA, 0xBB, 0xCC};
    uint8_t oprf_eval_hash[32] = {0x11, 0x22, 0x33, 0x44};

    opaque_envelope_t envelope;
    memset(&envelope, 0, sizeof(envelope));
    envelope.ciphertext_len = 16;
    memset(envelope.ciphertext, 0x77, 16);

    TEST_ASSERT(dsso_registry_register(account_id, oprf_eval_hash, &envelope) == 0);

    struct dsso_envelope *found = dsso_registry_find(account_id);
    TEST_ASSERT(found != NULL);
    TEST_ASSERT(found->active == 1);
    TEST_ASSERT(memcmp(found->oprf_eval_hash, oprf_eval_hash, 32) == 0);

    /* Valid client payload: [account_id(32)] || [client_proof(32)] */
    uint8_t client_payload[64];
    memcpy(client_payload, account_id, 32);
    memcpy(client_payload + 32, oprf_eval_hash, 32);

    TEST_ASSERT(verify_opaque_handshake(client_payload) == 0);

    /* Forged proof */
    client_payload[32] ^= 0xFF;
    TEST_ASSERT(verify_opaque_handshake(client_payload) == -2);

    /* Unknown account */
    uint8_t unknown_payload[64];
    memset(unknown_payload, 0x99, 64);
    TEST_ASSERT(verify_opaque_handshake(unknown_payload) == -1);

    printf("  -> PASS: Blind OPAQUE handshake verified against static registry without exposing secrets.\n");
}

int main(void) {
    test_harness_init("test_execution_env (Reactor, Triple-Entry Arena, OPAQUE Arena)");
    test_reactor_epoch_buzzer();
    test_triple_entry_ledger_arena();
    test_opaque_envelope_arena();
    test_harness_finish("test_execution_env");
    return 0;
}
