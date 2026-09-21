/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Flat Triple-Entry Bookkeeping Ledger Implementation
 */

#include <determ/ledger/state.h>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

static inline void write_be64(uint8_t *dest, uint64_t val) {
    dest[0] = (uint8_t)((val >> 56) & 0xFF);
    dest[1] = (uint8_t)((val >> 48) & 0xFF);
    dest[2] = (uint8_t)((val >> 40) & 0xFF);
    dest[3] = (uint8_t)((val >> 32) & 0xFF);
    dest[4] = (uint8_t)((val >> 24) & 0xFF);
    dest[5] = (uint8_t)((val >> 16) & 0xFF);
    dest[6] = (uint8_t)((val >> 8)  & 0xFF);
    dest[7] = (uint8_t)(val & 0xFF);
}

void triple_entry_tx_signing_bytes(const triple_entry_tx_t *tx,
                                   uint8_t out_signing_bytes[LEDGER_TX_SIGNING_BYTES]) {
    if (!tx || !out_signing_bytes) return;

    size_t offset = 0;
    memcpy(&out_signing_bytes[offset], tx->from, LEDGER_PUBKEY_LEN);
    offset += LEDGER_PUBKEY_LEN;

    memcpy(&out_signing_bytes[offset], tx->to, LEDGER_PUBKEY_LEN);
    offset += LEDGER_PUBKEY_LEN;

    write_be64(&out_signing_bytes[offset], tx->amount);
    offset += 8;

    write_be64(&out_signing_bytes[offset], tx->fee);
    offset += 8;

    write_be64(&out_signing_bytes[offset], tx->nonce);
}

int verify_triple_entry_tx(const account_t *sender,
                           const triple_entry_tx_t *tx,
                           uint64_t min_fee) {
    if (!sender || !tx) {
        return LEDGER_ERR_NULL_ARG;
    }

    /* 1. Public key verification: sender must match transaction 'from' */
    if (memcmp(sender->pubkey, tx->from, LEDGER_PUBKEY_LEN) != 0) {
        return LEDGER_ERR_PUBKEY_MISMATCH;
    }

    /* 2. Strictly incrementing nonce defense against replay attacks */
    if (tx->nonce != sender->nonce + 1) {
        return LEDGER_ERR_INVALID_NONCE;
    }

    /* 3. Fee validity check */
    if (tx->fee < min_fee) {
        return LEDGER_ERR_FEE_TOO_LOW;
    }

    /* 4. Integer overflow guard: amount + fee */
    if (UINT64_MAX - tx->amount < tx->fee) {
        return LEDGER_ERR_OVERFLOW;
    }

    uint64_t total_debit = tx->amount + tx->fee;

    /* 5. Overspend / integer underflow defense */
    if (sender->balance < total_debit) {
        return LEDGER_ERR_OVERSPEND;
    }

    /* 6. Ed25519 cryptographic signature verification */
    uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
    triple_entry_tx_signing_bytes(tx, signing_bytes);

    if (determ_ed25519_verify(sender->pubkey, signing_bytes, sizeof(signing_bytes), tx->sig) != 0) {
        return LEDGER_ERR_INVALID_SIG;
    }

    return LEDGER_OK;
}

void ledger_state_init(ledger_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->account_count = 0;
    state->total_fees = 0;
}

account_t* ledger_register_account(ledger_state_t *state,
                                   const uint8_t pubkey[LEDGER_PUBKEY_LEN],
                                   uint64_t initial_balance) {
    if (!state || !pubkey) return NULL;

    /* Check if account already exists */
    account_t *existing = ledger_find_account(state, pubkey);
    if (existing) {
        return existing;
    }

    /* Check arena capacity */
    if (state->account_count >= LEDGER_MAX_ACCOUNTS) {
        return NULL;
    }

    account_t *acc = &state->accounts[state->account_count++];
    memcpy(acc->pubkey, pubkey, LEDGER_PUBKEY_LEN);
    acc->balance = initial_balance;
    acc->nonce = 0;
    return acc;
}

account_t* ledger_find_account(ledger_state_t *state,
                               const uint8_t pubkey[LEDGER_PUBKEY_LEN]) {
    if (!state || !pubkey) return NULL;

    for (size_t i = 0; i < state->account_count; ++i) {
        if (memcmp(state->accounts[i].pubkey, pubkey, LEDGER_PUBKEY_LEN) == 0) {
            return &state->accounts[i];
        }
    }
    return NULL;
}

ledger_status_t ledger_apply_tx(ledger_state_t *state,
                                const triple_entry_tx_t *tx,
                                uint64_t min_fee) {
    if (!state || !tx) {
        return LEDGER_ERR_NULL_ARG;
    }

    /* Find sender */
    account_t *sender = ledger_find_account(state, tx->from);
    if (!sender) {
        return LEDGER_ERR_ACCOUNT_NOT_FOUND;
    }

    /* Verify validity of transaction */
    int rc = verify_triple_entry_tx(sender, tx, min_fee);
    if (rc != LEDGER_OK) {
        return (ledger_status_t)rc;
    }

    /* Find or register receiver */
    account_t *receiver = ledger_find_account(state, tx->to);
    if (!receiver) {
        receiver = ledger_register_account(state, tx->to, 0);
        if (!receiver) {
            return LEDGER_ERR_ARENA_FULL;
        }
    }

    /* Guard receiver balance overflow */
    if (UINT64_MAX - receiver->balance < tx->amount) {
        return LEDGER_ERR_OVERFLOW;
    }

    /* State transitions: pure stack execution, zero heap allocation */
    uint64_t total_debit = tx->amount + tx->fee;
    sender->balance -= total_debit;
    sender->nonce = tx->nonce;

    receiver->balance += tx->amount;
    state->total_fees += tx->fee;

    return LEDGER_OK;
}

int ledger_compute_tx_root(const triple_entry_tx_t *txs,
                           size_t count,
                           uint8_t out_root[32]) {
    if (!out_root) return -1;
    if (!txs || count == 0) {
        memset(out_root, 0, 32);
        return 0;
    }

    /* Pairwise tree reduction using stack memory */
    uint8_t tree[LEDGER_MAX_ACCOUNTS][32];
    size_t n = count > LEDGER_MAX_ACCOUNTS ? LEDGER_MAX_ACCOUNTS : count;

    for (size_t i = 0; i < n; ++i) {
        determ_sha256((const uint8_t *)&txs[i], sizeof(triple_entry_tx_t), tree[i]);
    }

    while (n > 1) {
        size_t next_n = 0;
        for (size_t i = 0; i < n; i += 2) {
            if (i + 1 < n) {
                uint8_t combined[64];
                memcpy(combined, tree[i], 32);
                memcpy(combined + 32, tree[i + 1], 32);
                determ_sha256(combined, 64, tree[next_n++]);
            } else {
                /* Odd element carries forward */
                memcpy(tree[next_n++], tree[i], 32);
            }
        }
        n = next_n;
    }

    memcpy(out_root, tree[0], 32);
    return 0;
}

int ledger_compute_state_root(const ledger_state_t *state,
                             uint8_t out_root[32]) {
    if (!out_root) return -1;
    if (!state || state->account_count == 0) {
        memset(out_root, 0, 32);
        return 0;
    }

    uint8_t tree[LEDGER_MAX_ACCOUNTS][32];
    size_t n = state->account_count;
    if (n > LEDGER_MAX_ACCOUNTS) n = LEDGER_MAX_ACCOUNTS;

    for (size_t i = 0; i < n; ++i) {
        determ_sha256((const uint8_t *)&state->accounts[i], sizeof(account_t), tree[i]);
    }

    while (n > 1) {
        size_t next_n = 0;
        for (size_t i = 0; i < n; i += 2) {
            if (i + 1 < n) {
                uint8_t combined[64];
                memcpy(combined, tree[i], 32);
                memcpy(combined + 32, tree[i + 1], 32);
                determ_sha256(combined, 64, tree[next_n++]);
            } else {
                memcpy(tree[next_n++], tree[i], 32);
            }
        }
        n = next_n;
    }

    memcpy(out_root, tree[0], 32);
    return 0;
}

int verify_triple_entry_tx_state(const triple_entry_tx_t *tx,
                                 const ledger_state_t *state,
                                 uint64_t min_fee) {
    if (!tx || !state) {
        return LEDGER_ERR_NULL_ARG;
    }
    const account_t *sender = NULL;
    for (size_t i = 0; i < state->account_count; i++) {
        if (memcmp(state->accounts[i].pubkey, tx->from, LEDGER_PUBKEY_LEN) == 0) {
            sender = &state->accounts[i];
            break;
        }
    }
    if (!sender) {
        return LEDGER_ERR_ACCOUNT_NOT_FOUND;
    }
    return verify_triple_entry_tx(sender, tx, min_fee);
}
