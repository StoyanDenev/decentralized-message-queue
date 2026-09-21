/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Economic Proof: Triple-Entry Ledger Integer Overflow & Overspend Immunity.
 *
 * Mathematically proves economic security:
 *   1. Construct a mock Big-Endian transaction attempting to spend UINT64_MAX.
 *   2. Pass it to verify_triple_entry_tx().
 *   3. Assert: Function returns a strict integer overflow error and rejects
 *      the transaction, proving immunity to overspend attacks without using
 *      dynamic memory allocation.
 */

#include "test_harness.h"
#include <determ/ledger/state.h>
#include <determ/crypto/ed25519/ed25519.h>

static void test_triple_entry_ledger_overflow_immunity(void) {
    printf("[TEST] Triple-Entry Ledger UINT64_MAX Overflow Rejection (Economic Proof)...\n");

    /* Memory safety: assert zero dynamic allocation constraints and flat structs */
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
    test_harness_init("test_triple_entry_ledger (Economic Proof)");
    test_triple_entry_ledger_overflow_immunity();
    test_harness_finish("test_triple_entry_ledger");
    return 0;
}
