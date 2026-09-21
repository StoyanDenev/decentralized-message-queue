/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Flat Triple-Entry Bookkeeping Ledger
 *
 * Guarantees:
 *   - Zero dynamic heap memory allocation (no malloc/free).
 *   - Strictly flat, cache-conscious array structures (__attribute__((packed))).
 *   - Cryptographically enforced balance invariants: no integer overflow or underflow.
 *   - Ed25519 signature authentication on all state transitions.
 */

#ifndef DETERMINISTIC_LEDGER_STATE_H
#define DETERMINISTIC_LEDGER_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LEDGER_MAX_ACCOUNTS     1024U
#define LEDGER_PUBKEY_LEN       32U
#define LEDGER_SIG_LEN          64U
#define LEDGER_TX_SIGNING_BYTES (32U + 32U + 8U + 8U + 8U) /* 88 bytes */

#if defined(__GNUC__) || defined(__clang__)
#define LEDGER_PACKED __attribute__((packed))
#else
#define LEDGER_PACKED
#endif

/*
 * Packed C99 Account structure:
 * Contains the Ed25519 public key (32 bytes), 64-bit unsigned balance,
 * and strictly incrementing nonce. Exactly 48 bytes with zero padding.
 */
typedef struct LEDGER_PACKED {
    uint8_t  pubkey[LEDGER_PUBKEY_LEN];
    uint64_t balance;
    uint64_t nonce;
} account_t;

/*
 * Packed C99 Triple-Entry Transaction structure:
 * Entry 1: Sender debit (from, amount + fee)
 * Entry 2: Receiver credit (to, amount; fee credited to block aggregator)
 * Entry 3: Cryptographic ledger signature / receipt (sig over signing bytes)
 */
typedef struct LEDGER_PACKED {
    uint8_t  from[LEDGER_PUBKEY_LEN];
    uint8_t  to[LEDGER_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint8_t  sig[LEDGER_SIG_LEN];
} triple_entry_tx_t;

typedef enum {
    LEDGER_OK                        =  0,
    LEDGER_ERR_NULL_ARG              = -1,
    LEDGER_ERR_ACCOUNT_NOT_FOUND     = -2,
    LEDGER_ERR_OVERFLOW              = -3,
    LEDGER_ERR_OVERSPEND             = -4, /* Insufficient funds: amount + fee > balance */
    LEDGER_ERR_FEE_TOO_LOW           = -5, /* Fee below block minimum */
    LEDGER_ERR_INVALID_NONCE         = -6, /* Nonce is not strictly incrementing */
    LEDGER_ERR_INVALID_SIG           = -7, /* Ed25519 signature mismatch */
    LEDGER_ERR_ARENA_FULL            = -8, /* Static ledger account arena capacity reached */
    LEDGER_ERR_PUBKEY_MISMATCH       = -9
} ledger_status_t;

/*
 * Flat In-Memory Ledger State
 * Statically sized arena of accounts with zero heap allocation.
 */
typedef struct {
    account_t accounts[LEDGER_MAX_ACCOUNTS];
    size_t    account_count;
    uint64_t  total_fees;
} ledger_state_t;

/*
 * Serialize the 88 canonical signing bytes for a Triple-Entry Transaction:
 * [from(32)] || [to(32)] || [BE64(amount)] || [BE64(fee)] || [BE64(nonce)]
 */
void triple_entry_tx_signing_bytes(const triple_entry_tx_t *tx,
                                   uint8_t out_signing_bytes[LEDGER_TX_SIGNING_BYTES]);

/*
 * Verify a Triple-Entry Transaction against the sender's account:
 * 1. Verifies the sender pubkey matches tx->from.
 * 2. Ensures the nonce strictly increments (tx->nonce == sender->nonce + 1).
 * 3. Verifies the fee meets min_fee.
 * 4. Ensures amount + fee does not integer-overflow UINT64_MAX.
 * 5. Ensures sender->balance >= amount + fee (rejects overspend / underflow).
 * 6. Verifies the Ed25519 signature over canonical signing bytes.
 * Returns LEDGER_OK (0) on success, or appropriate error code.
 */
/*
 * Verify a Triple-Entry Transaction directly against the ledger state.
 * Finds the sender account in state and verifies the transaction.
 */
int verify_triple_entry_tx_state(const triple_entry_tx_t *tx,
                                 const ledger_state_t *state,
                                 uint64_t min_fee);

int verify_triple_entry_tx(const account_t *sender,
                           const triple_entry_tx_t *tx,
                           uint64_t min_fee);

/*
 * Initialize the ledger state in static/stack memory.
 */
void ledger_state_init(ledger_state_t *state);

/*
 * Register or update an account in the flat ledger arena.
 * Returns pointer to account_t in state, or NULL if arena is full.
 */
account_t* ledger_register_account(ledger_state_t *state,
                                   const uint8_t pubkey[LEDGER_PUBKEY_LEN],
                                   uint64_t initial_balance);

/*
 * Find an account in the flat ledger arena by pubkey.
 * Returns pointer to account_t, or NULL if not found.
 */
account_t* ledger_find_account(ledger_state_t *state,
                               const uint8_t pubkey[LEDGER_PUBKEY_LEN]);

/*
 * Apply a Triple-Entry Transaction with zero heap allocation.
 * Uses only stack variables and updates state in-place.
 */
ledger_status_t ledger_apply_tx(ledger_state_t *state,
                                const triple_entry_tx_t *tx,
                                uint64_t min_fee);

/*
 * Compute the 32-byte Merkle root of an array of Triple-Entry transactions.
 */
int ledger_compute_tx_root(const triple_entry_tx_t *txs,
                           size_t count,
                           uint8_t out_root[32]);

/*
 * Compute the 32-byte Merkle root of the flat ledger state accounts.
 */
int ledger_compute_state_root(const ledger_state_t *state,
                             uint8_t out_root[32]);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_LEDGER_STATE_H */
