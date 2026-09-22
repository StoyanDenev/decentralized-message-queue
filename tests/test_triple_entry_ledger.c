/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * C99 ledger validation and monetary state-transition regression checks.
 * These tests enforce local contracts, not a production consensus theorem.
 */

#include "test_harness.h"
#include <determ/ledger/state.h>
#include <determ/crypto/ed25519/ed25519.h>

static void sign_tx(triple_entry_tx_t *tx, const uint8_t seed[32]) {
    uint8_t bytes[LEDGER_TX_SIGNING_BYTES];
    triple_entry_tx_signing_bytes(tx, bytes);
    TEST_ASSERT(determ_ed25519_sign(seed, tx->from, bytes, sizeof(bytes), tx->sig) == 0);
}

static void test_self_transfer(void) {
    ledger_state_t state;
    triple_entry_tx_t tx;
    uint8_t seed[32] = {7}, key[32];
    determ_ed25519_pubkey_from_seed(seed, key);
    ledger_state_init(&state);
    TEST_ASSERT(ledger_register_account(&state, key, 100) != NULL);
    memset(&tx, 0, sizeof(tx));
    memcpy(tx.from, key, 32);
    memcpy(tx.to, key, 32);
    tx.amount = 40;
    tx.fee = 3;
    tx.nonce = 1;
    sign_tx(&tx, seed);
    TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_OK);
    TEST_ASSERT(state.account_count == 1);
    TEST_ASSERT(state.accounts[0].balance == 97);
    TEST_ASSERT(state.accounts[0].nonce == 1);
    TEST_ASSERT(state.total_fees == 3);
    TEST_ASSERT(state.accounts[0].balance + state.total_fees == 100);
    ledger_state_t before;
    memcpy(&before, &state, sizeof(before));
    TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_ERR_INVALID_NONCE);
    TEST_ASSERT(memcmp(&before, &state, sizeof(state)) == 0);

    tx.nonce = 2;
    tx.amount = 98;
    sign_tx(&tx, seed);
    TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_ERR_OVERSPEND);
    TEST_ASSERT(memcmp(&before, &state, sizeof(state)) == 0);

    /* The net balance never exceeds its original value, even at UINT64_MAX. */
    ledger_state_init(&state);
    TEST_ASSERT(ledger_register_account(&state, key, UINT64_MAX) != NULL);
    tx.amount = UINT64_MAX;
    tx.fee = 0;
    tx.nonce = 1;
    sign_tx(&tx, seed);
    TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_OK);
    TEST_ASSERT(state.accounts[0].balance == UINT64_MAX);
    TEST_ASSERT(state.accounts[0].nonce == 1);
    TEST_ASSERT(state.total_fees == 0);
}

static void test_nonce_exhaustion(void) {
    ledger_state_t state, before;
    triple_entry_tx_t tx;
    uint8_t seed[32] = {8}, key[32];
    determ_ed25519_pubkey_from_seed(seed, key);
    ledger_state_init(&state);
    account_t *sender = ledger_register_account(&state, key, 100);
    TEST_ASSERT(sender != NULL);
    sender->nonce = UINT64_MAX - 1;
    memset(&tx, 0, sizeof(tx));
    memcpy(tx.from, key, 32);
    memcpy(tx.to, key, 32);
    tx.amount = 1;
    tx.nonce = UINT64_MAX;
    sign_tx(&tx, seed);
    TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_OK);
    TEST_ASSERT(sender->nonce == UINT64_MAX);
    TEST_ASSERT(sender->balance == 100);
    memcpy(&before, &state, sizeof(before));
    const uint64_t rejected_nonces[] = {0, 1, UINT64_MAX};
    for (size_t i = 0; i < sizeof(rejected_nonces) / sizeof(rejected_nonces[0]); ++i) {
        tx.nonce = rejected_nonces[i];
        sign_tx(&tx, seed);
        TEST_ASSERT(verify_triple_entry_tx(sender, &tx, 0) == LEDGER_ERR_INVALID_NONCE);
        TEST_ASSERT(ledger_apply_tx(&state, &tx, 0) == LEDGER_ERR_INVALID_NONCE);
        TEST_ASSERT(memcmp(&before, &state, sizeof(state)) == 0);
    }
}

static void test_triple_entry_ledger_overflow_immunity(void) {
    printf("[TEST] Triple-Entry Ledger UINT64_MAX Overflow Rejection...\n");

    /* Existing prototype in-memory layouts; not allocation or wire proofs. */
    TEST_ASSERT(sizeof(account_t) == 48);
    TEST_ASSERT(sizeof(triple_entry_tx_t) == 152);

    /* Setup sender account with standard initial balance */
    account_t sender;
    memset(&sender, 0, sizeof(sender));
    uint8_t sender_seed[32] = {0x01, 0x02, 0x03, 0x04};
    determ_ed25519_pubkey_from_seed(sender_seed, sender.pubkey);
    sender.balance = 1000000ULL; /* 1M units */
    sender.nonce = 10;

    /* Construct transaction attempting to spend UINT64_MAX with fee */
    triple_entry_tx_t tx_overflow;
    memset(&tx_overflow, 0, sizeof(tx_overflow));
    memcpy(tx_overflow.from, sender.pubkey, LEDGER_PUBKEY_LEN);
    memset(tx_overflow.to, 0x42, LEDGER_PUBKEY_LEN);
    tx_overflow.amount = UINT64_MAX;
    tx_overflow.fee = 1000ULL;
    tx_overflow.nonce = sender.nonce + 1;

    /* Pass to verify_triple_entry_tx() */
    int rc_overflow = verify_triple_entry_tx(&sender, &tx_overflow, 100ULL);

    /* Assert: Returns strict integer overflow error */
    TEST_ASSERT(rc_overflow == LEDGER_ERR_OVERFLOW);
    printf("  -> PASS: verify_triple_entry_tx() strictly rejected UINT64_MAX + fee with LEDGER_ERR_OVERFLOW (%d).\n", rc_overflow);

    /* Also verify boundary overspend without fee overflow: amount = balance + 1 */
    triple_entry_tx_t tx_overspend;
    memset(&tx_overspend, 0, sizeof(tx_overspend));
    memcpy(tx_overspend.from, sender.pubkey, LEDGER_PUBKEY_LEN);
    memset(tx_overspend.to, 0x42, LEDGER_PUBKEY_LEN);
    tx_overspend.amount = sender.balance + 1;
    tx_overspend.fee = 0ULL;
    tx_overspend.nonce = sender.nonce + 1;

    int rc_overspend = verify_triple_entry_tx(&sender, &tx_overspend, 0ULL);
    TEST_ASSERT(rc_overspend == LEDGER_ERR_OVERSPEND);
    printf("  -> PASS: verify_triple_entry_tx() strictly rejected overspend with LEDGER_ERR_OVERSPEND (%d).\n", rc_overspend);

    /* Verify valid transaction succeeds */
    triple_entry_tx_t tx_valid;
    memset(&tx_valid, 0, sizeof(tx_valid));
    memcpy(tx_valid.from, sender.pubkey, LEDGER_PUBKEY_LEN);
    memset(tx_valid.to, 0x42, LEDGER_PUBKEY_LEN);
    tx_valid.amount = 5000ULL;
    tx_valid.fee = 200ULL;
    tx_valid.nonce = sender.nonce + 1;

    /* Sign valid transaction */
    uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
    triple_entry_tx_signing_bytes(&tx_valid, signing_bytes);
    determ_ed25519_sign(sender_seed, sender.pubkey, signing_bytes, sizeof(signing_bytes), tx_valid.sig);

    int rc_valid = verify_triple_entry_tx(&sender, &tx_valid, 100ULL);
    TEST_ASSERT(rc_valid == LEDGER_OK);
    printf("  -> PASS: Valid transaction verified successfully (LEDGER_OK).\n");
}

int main(void) {
    test_harness_init("test_triple_entry_ledger");
    test_triple_entry_ledger_overflow_immunity();
    test_self_transfer();
    test_nonce_exhaustion();
    test_harness_finish("test_triple_entry_ledger");
    return 0;
}
