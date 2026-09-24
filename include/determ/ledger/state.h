/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * In-memory single-signature transfer ledger for the C99 prototype. (Type and
 * function names keep the historical "triple_entry" prefix; the ledger keeps
 * only balances, nonces and a total_fees sink.)
 *
 *   - Zero dynamic heap memory allocation: a fixed arena of LEDGER_MAX_ACCOUNTS.
 *   - ledger_apply_tx applies a transfer only when the Ed25519 signature by
 *     `from` verifies, and rejects a wrong nonce, a fee below the minimum, an
 *     amount + fee overflow, an overspend, a total_fees overflow and a
 *     receiver-balance overflow, leaving the state unchanged (see
 *     verify_triple_entry_tx and ledger_apply_tx below).
 *   - ledger_register_account sets a balance without any signature: it is the
 *     caller's genesis/test hook, not an authenticated transition.
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

#pragma pack(push, 1)

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
 * Packed C99 transfer (in-memory layout, not a wire format): `from` pays
 * amount + fee, `to` receives amount, and the fee is added to
 * ledger_state_t.total_fees; it is credited to no account. `sig` is an
 * Ed25519 signature by `from` over triple_entry_tx_signing_bytes().
 */
typedef struct LEDGER_PACKED {
    uint8_t  from[LEDGER_PUBKEY_LEN];
    uint8_t  to[LEDGER_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint8_t  sig[LEDGER_SIG_LEN];
} triple_entry_tx_t;

#pragma pack(pop)

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
 * Serialize the 88 canonical signing bytes of a transfer:
 * [from(32)] || [to(32)] || [BE64(amount)] || [BE64(fee)] || [BE64(nonce)]
 */
void triple_entry_tx_signing_bytes(const triple_entry_tx_t *tx,
                                   uint8_t out_signing_bytes[LEDGER_TX_SIGNING_BYTES]);

/*
 * Check a transfer against the sender's account, in this order: `from` equals
 * the account key; nonce == account nonce + 1 (an account at UINT64_MAX can
 * send nothing); fee >= min_fee; amount + fee does not overflow; balance >=
 * amount + fee; Ed25519 signature over the signing bytes. Returns LEDGER_OK
 * or the ledger_status_t of the first failing check.
 */
int verify_triple_entry_tx(const account_t *sender,
                           const triple_entry_tx_t *tx,
                           uint64_t min_fee);

/*
 * verify_triple_entry_tx against the state's account for tx->from
 * (LEDGER_ERR_ACCOUNT_NOT_FOUND when there is none).
 */
int verify_triple_entry_tx_state(const triple_entry_tx_t *tx,
                                 const ledger_state_t *state,
                                 uint64_t min_fee);

/*
 * Initialize the ledger state in static/stack memory.
 */
void ledger_state_init(ledger_state_t *state);

/*
 * Register an account with initial_balance and nonce 0. An existing account
 * is returned unchanged. Returns NULL when the arena is full.
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
 * Apply a transfer in place with zero heap allocation: after the checks of
 * verify_triple_entry_tx, debit `from` by amount + fee (only the fee for a
 * self-transfer), credit `to` with amount (registering it with balance 0 when
 * absent), add the fee to total_fees (credited to no account) and set the
 * sender nonce. Fails without changing the state on any error, including a
 * total_fees or receiver-balance overflow and a full account arena.
 */
ledger_status_t ledger_apply_tx(ledger_state_t *state,
                                const triple_entry_tx_t *tx,
                                uint64_t min_fee);

/*
 * Transaction root: leaf_i = SHA-256(triple_entry_tx_signing_bytes(tx_i) ||
 * sig_i); a pairwise SHA-256 tree in array order carries an odd node up
 * unchanged; root = SHA-256(BE64(count) || tree root), the tree root being 32
 * zero bytes when count == 0. Returns -1 (out_root untouched) when
 * count > LEDGER_MAX_ACCOUNTS or txs is NULL with count > 0.
 */
int ledger_compute_tx_root(const triple_entry_tx_t *txs,
                           size_t count,
                           uint8_t out_root[32]);

/*
 * State root over the accounts in arena (registration) order:
 * leaf_i = SHA-256(pubkey || BE64(balance) || BE64(nonce)), with the tree and
 * count commitment of ledger_compute_tx_root. total_fees is not committed.
 * Returns -1 (out_root untouched) for a NULL state or
 * account_count > LEDGER_MAX_ACCOUNTS.
 */
int ledger_compute_state_root(const ledger_state_t *state,
                             uint8_t out_root[32]);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_LEDGER_STATE_H */
