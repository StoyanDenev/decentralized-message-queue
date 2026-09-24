/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Ledger input sweep and local seam checks for the C99 prototype.
 *
 * Checks:
 *   1. verify_triple_entry_tx: overflow and overspend rejection
 *   2. DSF seams: virtual clock fast-forward against the duel reveal deadline
 *   3. Input sweep: each input drives a fresh ledger through up to four
 *      transactions. The sender is always the registered key; nonce, amount,
 *      fee, recipient and signature are shaped from the input so every check
 *      of verify_triple_entry_tx is reached. Each verify and apply status must
 *      equal a reference model, and after every apply the sum of balances plus
 *      total_fees is unchanged, the sender balance only falls and the sender
 *      nonce advances by exactly one on success and not at all on failure.
 *   4. Reactor: non-blocking accept, send and echo over loopback
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
#include "determ/crypto/ed25519/ed25519.h"
#include <determ/crypto/sha2/sha2.h>
#include "determ/net/reactor.h"
#include "determ/consensus/duel_state.h"
#include "dsf_seams.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

#define FUZZ_SETUP_BYTES 8U
#define FUZZ_MAX_TXS     4U

static account_t s_test_sender;
static uint8_t s_sender_seed[32];
static const uint8_t s_receiver_key[32] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};
static ledger_state_t s_fuzz_state, s_fuzz_before;
/* Sweep coverage: how often each verify status (index -status) was reached. */
static unsigned long s_verify_seen[10];

static void init_fuzz_state(void) {
    for (size_t i = 0; i < 32; ++i) {
        s_sender_seed[i] = (uint8_t)(i + 1);
    }
    determ_ed25519_pubkey_from_seed(s_sender_seed, s_test_sender.pubkey);
    s_test_sender.balance = 1000000ULL; /* 1,000,000 units initial balance */
    s_test_sender.nonce = 10;
}

/* Sum of every balance plus total_fees, as a 128-bit (hi, lo) pair. */
static void total_value(const ledger_state_t *state, uint64_t *hi, uint64_t *lo) {
    uint64_t h = 0, l = state->total_fees;
    for (size_t i = 0; i < state->account_count; ++i) {
        uint64_t balance = state->accounts[i].balance;
        l += balance;
        if (l < balance) h++;
    }
    *hi = h;
    *lo = l;
}

/* The documented check order of verify_triple_entry_tx. */
static int expected_verify(const account_t *sender, const triple_entry_tx_t *tx,
                           uint64_t min_fee, bool signature_valid) {
    uint64_t amount = tx->amount, fee = tx->fee;
    if (memcmp(sender->pubkey, tx->from, LEDGER_PUBKEY_LEN) != 0) return LEDGER_ERR_PUBKEY_MISMATCH;
    if (sender->nonce == UINT64_MAX || tx->nonce != sender->nonce + 1) return LEDGER_ERR_INVALID_NONCE;
    if (fee < min_fee) return LEDGER_ERR_FEE_TOO_LOW;
    if (amount > UINT64_MAX - fee) return LEDGER_ERR_OVERFLOW;
    if (sender->balance < amount + fee) return LEDGER_ERR_OVERSPEND;
    return signature_valid ? LEDGER_OK : LEDGER_ERR_INVALID_SIG;
}

/* One transaction record: the bytes are copied over triple_entry_tx_t; its
 * first bytes (inside `from`, which is then replaced) select the shaping. */
static void fuzz_one_tx(ledger_state_t *state, const uint8_t *rec, uint64_t min_fee) {
    triple_entry_tx_t tx;
    const uint8_t control = rec[0];
    account_t *sender = ledger_find_account(state, s_test_sender.pubkey);
    bool signature_valid = false;
    TEST_ASSERT(sender != NULL);

    memcpy(&tx, rec, sizeof(tx));
    memcpy(tx.from, s_test_sender.pubkey, LEDGER_PUBKEY_LEN);
    if (control & 0x01) tx.nonce = sender->nonce + 1;
    if (control & 0x02) {
        tx.amount >>= (rec[1] & 63);
        tx.fee >>= (rec[2] & 63);
    }
    if (control & 0x04) memcpy(tx.to, s_test_sender.pubkey, LEDGER_PUBKEY_LEN);
    else if (control & 0x08) memcpy(tx.to, s_receiver_key, LEDGER_PUBKEY_LEN);
    /* A signature is examined only after every other check passes; sign only
     * then (signing is the sweep's dominant cost). */
    if ((control & 0x10) && expected_verify(sender, &tx, min_fee, true) == LEDGER_OK) {
        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx, signing_bytes);
        TEST_ASSERT(determ_ed25519_sign(s_sender_seed, s_test_sender.pubkey, signing_bytes,
                                        sizeof(signing_bytes), tx.sig) == 0);
        signature_valid = (control & 0x20) == 0;
        if (!signature_valid) tx.sig[rec[3] & 63] ^= (uint8_t)(1U << (rec[3] >> 6));
    }

    const int want_verify = expected_verify(sender, &tx, min_fee, signature_valid);
    const int got_verify = verify_triple_entry_tx(sender, &tx, min_fee);
    TEST_ASSERT(got_verify == want_verify);
    s_verify_seen[-got_verify]++;

    /* Apply adds the fee accumulator, arena and receiver-balance checks. */
    const account_t *receiver = ledger_find_account(state, tx.to);
    int want_apply = want_verify;
    if (want_apply == LEDGER_OK) {
        if (UINT64_MAX - state->total_fees < tx.fee) want_apply = LEDGER_ERR_OVERFLOW;
        else if (!receiver && state->account_count >= LEDGER_MAX_ACCOUNTS) want_apply = LEDGER_ERR_ARENA_FULL;
        else if (receiver && receiver != sender && UINT64_MAX - receiver->balance < tx.amount)
            want_apply = LEDGER_ERR_OVERFLOW;
    }
    const uint64_t old_nonce = sender->nonce, old_balance = sender->balance;
    const uint64_t old_receiver = receiver ? receiver->balance : 0;
    uint64_t hi_before, lo_before, hi_after, lo_after;
    total_value(state, &hi_before, &lo_before);
    memcpy(&s_fuzz_before, state, sizeof(*state));

    TEST_ASSERT((int)ledger_apply_tx(state, &tx, min_fee) == want_apply);
    total_value(state, &hi_after, &lo_after);
    TEST_ASSERT(hi_after == hi_before && lo_after == lo_before);
    sender = ledger_find_account(state, s_test_sender.pubkey);
    TEST_ASSERT(sender != NULL && sender->balance <= old_balance);
    if (want_apply != LEDGER_OK) {
        TEST_ASSERT(memcmp(&s_fuzz_before, state, sizeof(*state)) == 0);
        return;
    }
    TEST_ASSERT(sender->nonce == old_nonce + 1);
    TEST_ASSERT(state->total_fees == s_fuzz_before.total_fees + tx.fee);
    if (memcmp(tx.to, tx.from, LEDGER_PUBKEY_LEN) == 0) {
        TEST_ASSERT(sender->balance == old_balance - tx.fee);
    } else {
        const account_t *credited = ledger_find_account(state, tx.to);
        TEST_ASSERT(sender->balance == old_balance - tx.amount - tx.fee);
        TEST_ASSERT(credited != NULL && credited->balance == old_receiver + tx.amount);
        TEST_ASSERT(state->account_count == s_fuzz_before.account_count + (receiver ? 0U : 1U));
    }
}

/*
 * LLVM libFuzzer Entrypoint: FUZZ_SETUP_BYTES of setup, then up to
 * FUZZ_MAX_TXS records of sizeof(triple_entry_tx_t) bytes each.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size < FUZZ_SETUP_BYTES + sizeof(triple_entry_tx_t)) {
        return 0;
    }
    const uint8_t setup = Data[0];
    const uint64_t min_fee = Data[1];

    ledger_state_init(&s_fuzz_state);
    TEST_ASSERT(ledger_register_account(&s_fuzz_state, s_test_sender.pubkey,
                                        (setup & 0x01) ? UINT64_MAX : 1000000ULL) != NULL);
    if (setup & 0x02)
        TEST_ASSERT(ledger_register_account(&s_fuzz_state, s_receiver_key, UINT64_MAX - 1000ULL) != NULL);
    if (setup & 0x04) s_fuzz_state.total_fees = UINT64_MAX - 1000ULL;

    /* at <= Size holds throughout, so Size - at never wraps. */
    for (size_t i = 0, at = FUZZ_SETUP_BYTES;
         i < FUZZ_MAX_TXS && Size - at >= sizeof(triple_entry_tx_t);
         ++i, at += sizeof(triple_entry_tx_t)) {
        fuzz_one_tx(&s_fuzz_state, Data + at, min_fee);
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
    printf("[TEST] 1. Overflow and overspend rejection over 121 amount/fee pairs...\n");

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

    printf("  -> PASS: every overflowing or overspending pair was rejected with its status code.\n");
}

/*
 * ── 2. Native DSF Seams & Virtual Clock Fast-Forward ─────────────────────────
 */
static void test_native_dsf_seams(void) {
    printf("[TEST] 2. Virtual clock fast-forward past the 2 s reveal deadline...\n");

    /* Reset virtual clock and transport */
    dsf_reset_seams();
    uint64_t t0 = determ_clock_now();

    duel_state_machine_t sm;
    TEST_ASSERT(duel_state_init(&sm) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    const uint8_t agg_data[16] = {0x01, 0x02};
    uint8_t hash[32];
    determ_sha256(agg_data, sizeof(agg_data), hash);
    TEST_ASSERT(duel_submit_aggregator_commit(&sm, hash) == DUEL_SUCCESS);
    TEST_ASSERT(duel_submit_contributor_commit(&sm, hash) == DUEL_SUCCESS);
    TEST_ASSERT(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
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

    /* Poll buzzer: state machine locks buffer and enters strict 2-of-2 skipping */
    TEST_ASSERT(duel_state_poll_buzzer(&sm) == ERR_EPOCH_SKIPPED_INCOMPLETE);
    TEST_ASSERT(sm.state == DUEL_STATE_ABORTED);
    TEST_ASSERT(sm.vdf_input_len == 0);

    printf("  -> PASS: late reveal dropped; attempt aborted as incomplete.\n");
}

/*
 * ── 3. Simulated Fuzzing Mutation Sweep ──────────────────────────────────────
 */
static void test_malformed_fuzzing_mutations(void) {
    printf("[TEST] 3. Random ledger sweep (5000 inputs, up to %u transactions each)...\n", FUZZ_MAX_TXS);
    uint8_t fuzz_buf[FUZZ_SETUP_BYTES + FUZZ_MAX_TXS * sizeof(triple_entry_tx_t)];
    const size_t min_len = FUZZ_SETUP_BYTES + sizeof(triple_entry_tx_t);
    uint32_t lcg = 0x12345678;

    memset(s_verify_seen, 0, sizeof(s_verify_seen));
    for (int iter = 0; iter < 5000; iter++) {
        for (size_t k = 0; k < sizeof(fuzz_buf); k++) {
            lcg = lcg * 1664525U + 1013904223U;
            fuzz_buf[k] = (uint8_t)(lcg >> 24);
        }
        size_t fuzz_len = (lcg % (sizeof(fuzz_buf) - min_len + 1)) + min_len;
        LLVMFuzzerTestOneInput(fuzz_buf, fuzz_len);
    }
    /* The sweep must reach every check past the key comparison. */
    TEST_ASSERT(s_verify_seen[-LEDGER_OK] > 0);
    TEST_ASSERT(s_verify_seen[-LEDGER_ERR_INVALID_NONCE] > 0);
    TEST_ASSERT(s_verify_seen[-LEDGER_ERR_FEE_TOO_LOW] > 0);
    TEST_ASSERT(s_verify_seen[-LEDGER_ERR_OVERFLOW] > 0);
    TEST_ASSERT(s_verify_seen[-LEDGER_ERR_OVERSPEND] > 0);
    TEST_ASSERT(s_verify_seen[-LEDGER_ERR_INVALID_SIG] > 0);
    printf("  -> PASS: statuses matched the reference model; value conserved after every apply "
           "(ok %lu, nonce %lu, fee %lu, overflow %lu, overspend %lu, signature %lu).\n",
           s_verify_seen[-LEDGER_OK], s_verify_seen[-LEDGER_ERR_INVALID_NONCE],
           s_verify_seen[-LEDGER_ERR_FEE_TOO_LOW], s_verify_seen[-LEDGER_ERR_OVERFLOW],
           s_verify_seen[-LEDGER_ERR_OVERSPEND], s_verify_seen[-LEDGER_ERR_INVALID_SIG]);
}

/*
 * ── 4. Native Event Loop Reactor Verification ────────────────────────────────
 */
static void test_reactor_nonblocking(void) {
    printf("[TEST] 4. Reactor loopback accept, send and echo...\n");
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
    printf("  -> PASS: accepted, sent and received the echoed bytes.\n");
}

int main(void) {
    printf("=================================================================\n");
    printf("Running C99 ledger sweep, DSF seam and reactor checks\n");
    printf("=================================================================\n");

    init_fuzz_state();

    test_extreme_overflow_and_overspend();
    test_native_dsf_seams();
    test_malformed_fuzzing_mutations();
    test_reactor_nonblocking();

    printf("=================================================================\n");
    printf("PASS: fuzz_ledger\n");
    printf("=================================================================\n");
    return 0;
}
