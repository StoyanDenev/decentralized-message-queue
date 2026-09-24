/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Checks for:
 *   1. The in-memory C99 transfer ledger (src/ledger/state.c).
 *   2. The consensus payload digest, block header codec and VDF re-evaluation.
 *   3. A random input sweep over the same ledger and header entry points.
 */

#define _POSIX_C_SOURCE 200809L

#include <determ/ledger/state.h>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/vdf.h>
#include <determ/wire/parser.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_ASSERT(cond) do {     if (!(cond)) {         fprintf(stderr, "FATAL: Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__);         abort();     } } while (0)

/*
 * ── 1. Ledger Tests ──────────────────────────────────────────────────────────
 */
static void test_triple_entry_ledger_invariants(void) {
    printf("[TEST] 1. Ledger layout, rejection codes and one applied transfer...\n");

    /* Memory safety & packed layout validation */
    TEST_ASSERT(sizeof(account_t) == 48);
    TEST_ASSERT(sizeof(triple_entry_tx_t) == 152);

    /* Setup static ledger state */
    static ledger_state_t state;
    ledger_state_init(&state);

    /* Generate Sender Ed25519 Keypair */
    uint8_t sender_seed[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    uint8_t sender_pk[32];
    determ_ed25519_pubkey_from_seed(sender_seed, sender_pk);

    /* Generate Receiver Ed25519 Keypair */
    uint8_t receiver_seed[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
    };
    uint8_t receiver_pk[32];
    determ_ed25519_pubkey_from_seed(receiver_seed, receiver_pk);

    /* Register sender with initial balance of 1,000,000 units */
    account_t *sender_acc = ledger_register_account(&state, sender_pk, 1000000ULL);
    TEST_ASSERT(sender_acc != NULL);
    TEST_ASSERT(sender_acc->balance == 1000000ULL);
    TEST_ASSERT(sender_acc->nonce == 0);

    /* Minimum block fee */
    const uint64_t min_fee = 50ULL;

    /* ── Subtest 1: Overspend Rejection ── */
    {
        triple_entry_tx_t tx_overspend;
        memset(&tx_overspend, 0, sizeof(tx_overspend));
        memcpy(tx_overspend.from, sender_pk, 32);
        memcpy(tx_overspend.to, receiver_pk, 32);
        tx_overspend.amount = 1000000ULL; /* amount + fee = 1000050 > 1000000 balance */
        tx_overspend.fee = min_fee;
        tx_overspend.nonce = 1ULL;

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx_overspend, signing_bytes);
        int sign_rc = determ_ed25519_sign(sender_seed, sender_pk,
                                          signing_bytes, sizeof(signing_bytes),
                                          tx_overspend.sig);
        TEST_ASSERT(sign_rc == 0);

        int verify_rc = verify_triple_entry_tx(sender_acc, &tx_overspend, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_ERR_OVERSPEND);

        ledger_status_t apply_rc = ledger_apply_tx(&state, &tx_overspend, min_fee);
        TEST_ASSERT(apply_rc == LEDGER_ERR_OVERSPEND);
        /* Invariant: balance unaffected */
        TEST_ASSERT(sender_acc->balance == 1000000ULL);
    }

    /* ── Subtest 2: Integer Overflow Rejection ── */
    {
        triple_entry_tx_t tx_overflow;
        memset(&tx_overflow, 0, sizeof(tx_overflow));
        memcpy(tx_overflow.from, sender_pk, 32);
        memcpy(tx_overflow.to, receiver_pk, 32);
        tx_overflow.amount = UINT64_MAX - 10ULL;
        tx_overflow.fee = 50ULL; /* UINT64_MAX - 10 + 50 overflows */
        tx_overflow.nonce = 1ULL;

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx_overflow, signing_bytes);
        (void)determ_ed25519_sign(sender_seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx_overflow.sig);

        int verify_rc = verify_triple_entry_tx(sender_acc, &tx_overflow, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_ERR_OVERFLOW);
    }

    /* ── Subtest 3: Fee Below Minimum Rejection ── */
    {
        triple_entry_tx_t tx_low_fee;
        memset(&tx_low_fee, 0, sizeof(tx_low_fee));
        memcpy(tx_low_fee.from, sender_pk, 32);
        memcpy(tx_low_fee.to, receiver_pk, 32);
        tx_low_fee.amount = 100ULL;
        tx_low_fee.fee = min_fee - 1ULL;
        tx_low_fee.nonce = 1ULL;

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx_low_fee, signing_bytes);
        (void)determ_ed25519_sign(sender_seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx_low_fee.sig);

        int verify_rc = verify_triple_entry_tx(sender_acc, &tx_low_fee, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_ERR_FEE_TOO_LOW);
    }

    /* ── Subtest 4: Invalid Nonce Rejection ── */
    {
        triple_entry_tx_t tx_bad_nonce;
        memset(&tx_bad_nonce, 0, sizeof(tx_bad_nonce));
        memcpy(tx_bad_nonce.from, sender_pk, 32);
        memcpy(tx_bad_nonce.to, receiver_pk, 32);
        tx_bad_nonce.amount = 100ULL;
        tx_bad_nonce.fee = min_fee;
        tx_bad_nonce.nonce = 2ULL; /* sender nonce is 0, expecting 1 */

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx_bad_nonce, signing_bytes);
        (void)determ_ed25519_sign(sender_seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx_bad_nonce.sig);

        int verify_rc = verify_triple_entry_tx(sender_acc, &tx_bad_nonce, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_ERR_INVALID_NONCE);
    }

    /* ── Subtest 5: Tampered Signature Rejection ── */
    {
        triple_entry_tx_t tx_bad_sig;
        memset(&tx_bad_sig, 0, sizeof(tx_bad_sig));
        memcpy(tx_bad_sig.from, sender_pk, 32);
        memcpy(tx_bad_sig.to, receiver_pk, 32);
        tx_bad_sig.amount = 100ULL;
        tx_bad_sig.fee = min_fee;
        tx_bad_sig.nonce = 1ULL;

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&tx_bad_sig, signing_bytes);
        (void)determ_ed25519_sign(sender_seed, sender_pk, signing_bytes, sizeof(signing_bytes), tx_bad_sig.sig);
        tx_bad_sig.sig[0] ^= 0xFF; /* Tamper signature */

        int verify_rc = verify_triple_entry_tx(sender_acc, &tx_bad_sig, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_ERR_INVALID_SIG);
    }

    /* ── Subtest 6: Valid Transaction Execution (Zero-Allocation) ── */
    {
        triple_entry_tx_t valid_tx;
        memset(&valid_tx, 0, sizeof(valid_tx));
        memcpy(valid_tx.from, sender_pk, 32);
        memcpy(valid_tx.to, receiver_pk, 32);
        valid_tx.amount = 250000ULL;
        valid_tx.fee = 100ULL;
        valid_tx.nonce = 1ULL;

        uint8_t signing_bytes[LEDGER_TX_SIGNING_BYTES];
        triple_entry_tx_signing_bytes(&valid_tx, signing_bytes);
        int sign_rc = determ_ed25519_sign(sender_seed, sender_pk,
                                          signing_bytes, sizeof(signing_bytes),
                                          valid_tx.sig);
        TEST_ASSERT(sign_rc == 0);

        int verify_rc = verify_triple_entry_tx(sender_acc, &valid_tx, min_fee);
        TEST_ASSERT(verify_rc == LEDGER_OK);

        ledger_status_t apply_rc = ledger_apply_tx(&state, &valid_tx, min_fee);
        TEST_ASSERT(apply_rc == LEDGER_OK);

        /* Invariant checks */
        TEST_ASSERT(sender_acc->balance == 1000000ULL - 250000ULL - 100ULL);
        TEST_ASSERT(sender_acc->nonce == 1ULL);

        account_t *recv_acc = ledger_find_account(&state, receiver_pk);
        TEST_ASSERT(recv_acc != NULL);
        TEST_ASSERT(recv_acc->balance == 250000ULL);
        TEST_ASSERT(state.total_fees == 100ULL);

        /* Merkle roots computation */
        uint8_t tx_root[32];
        uint8_t state_root[32];
        TEST_ASSERT(ledger_compute_tx_root(&valid_tx, 1, tx_root) == 0);
        TEST_ASSERT(ledger_compute_state_root(&state, state_root) == 0);
    }

    printf("  -> PASS: overspend, overflow, low fee, bad nonce and bad signature rejected; one transfer applied.\n");
}

static void check_root_hex(const uint8_t root[32], const char *expected) {
    char hex[65];
    for (size_t i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", root[i]);
    TEST_ASSERT(strcmp(hex, expected) == 0);
}

/*
 * Expected roots were computed independently (Python hashlib) from the
 * encoding documented in state.h: account leaf SHA-256(pubkey || BE64 balance
 * || BE64 nonce), transaction leaf SHA-256(signing bytes || sig), a pairwise
 * SHA-256 tree that carries an odd node up, and
 * root = SHA-256(BE64 count || tree root, or 32 zero bytes when empty).
 */
static void test_ledger_roots(void) {
    printf("[TEST] 1b. State and transaction roots against independent vectors...\n");
    static const char empty_root[] = "2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb";
    static ledger_state_t st;
    uint8_t root[32], key[32];
    account_t *acc;

    ledger_state_init(&st);
    TEST_ASSERT(ledger_compute_state_root(&st, root) == 0);
    check_root_hex(root, empty_root);

    for (size_t i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 1);
    acc = ledger_register_account(&st, key, 1000000ULL);
    TEST_ASSERT(acc != NULL);
    acc->nonce = 7;
    TEST_ASSERT(ledger_compute_state_root(&st, root) == 0);
    check_root_hex(root, "b3ca1474858b6a6e7fddc6dde30175c9945f35b9b704a7f0c71714fd0fd421eb");

    for (size_t i = 0; i < 32; ++i) key[i] = (uint8_t)(0x21 + i);
    TEST_ASSERT(ledger_register_account(&st, key, 0x0102030405060708ULL) != NULL);
    memset(key, 0xAA, sizeof(key));
    acc = ledger_register_account(&st, key, UINT64_MAX);
    TEST_ASSERT(acc != NULL);
    acc->nonce = UINT64_MAX;
    TEST_ASSERT(ledger_compute_state_root(&st, root) == 0);
    check_root_hex(root, "15477176256bb88d1243715637139ce69f7e086a27124849375c068a151d400e");

    /* An account count beyond the arena is refused, not truncated. */
    st.account_count = LEDGER_MAX_ACCOUNTS + 1;
    TEST_ASSERT(ledger_compute_state_root(&st, root) == -1);
    TEST_ASSERT(ledger_compute_state_root(NULL, root) == -1);

    triple_entry_tx_t txs[3];
    memset(txs, 0, sizeof(txs));
    for (size_t i = 0; i < 3; ++i) {
        memset(txs[i].from, 0x11, 32);
        memset(txs[i].to, 0x22, 32);
        txs[i].amount = i + 1;
        txs[i].fee = 10 * (i + 1);
        txs[i].nonce = i + 1;
        memset(txs[i].sig, 0x30 + (int)i, 64);
    }
    TEST_ASSERT(ledger_compute_tx_root(txs, 3, root) == 0);
    check_root_hex(root, "7080ddf2d7e9533719ff868373c23adf68898a09a7fc0de4d455c2ed3bea55cf");
    TEST_ASSERT(ledger_compute_tx_root(txs, 0, root) == 0);
    check_root_hex(root, empty_root);
    TEST_ASSERT(ledger_compute_tx_root(NULL, 1, root) == -1);
    TEST_ASSERT(ledger_compute_tx_root(txs, LEDGER_MAX_ACCOUNTS + 1, root) == -1);
    printf("  -> PASS: state and transaction roots match the vectors; over-capacity counts refused.\n");
}

/*
 * ── 2. Binding Consensus Payload to VDF ───────────────────────────────────────
 */
static void test_consensus_vdf_binding(void) {
    printf("[TEST] 2. Consensus payload digest, block header round trip and VDF re-evaluation...\n");

    /* Simulated state roots */
    uint8_t tx_root[32] = {0x11};
    uint8_t dsso_root[32] = {0x22};
    uint8_t prev_hash[32] = {0x33};
    uint64_t height = 42ULL;
    uint64_t timestamp = 1774000000ULL;

    /* Bind into 32-byte canonical consensus digest */
    uint8_t vdf_payload[32];
    wire_status_t ws = wire_bind_consensus_vdf_payload(height, prev_hash, tx_root, dsso_root,
                                                       timestamp, vdf_payload);
    TEST_ASSERT(ws == WIRE_OK);

    /* Test canonical Block Header packing and unpacking */
    wire_block_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.height = height;
    memcpy(hdr.prev_hash, prev_hash, 32);
    memcpy(hdr.tx_root, tx_root, 32);
    memcpy(hdr.dsso_root, dsso_root, 32);
    hdr.timestamp = timestamp;
    memset(hdr.vrf_aggregator_proof, 0x44, 32);
    memset(hdr.vrf_contributor_proof, 0x55, 32);
    hdr.vdf_iterations = 1000;
    memset(hdr.vdf_proof, 0x66, 32);

    uint8_t hdr_wire[WIRE_BLOCK_HEADER_LEN];
    size_t hdr_len = 0;
    TEST_ASSERT(wire_encode_block_header(&hdr, hdr_wire, sizeof(hdr_wire), &hdr_len) == WIRE_OK);
    TEST_ASSERT(hdr_len == WIRE_BLOCK_HEADER_LEN);

    wire_block_header_t decoded_hdr;
    TEST_ASSERT(wire_parse_block_header(hdr_wire, hdr_len, &decoded_hdr) == WIRE_OK);
    TEST_ASSERT(decoded_hdr.height == height);
    TEST_ASSERT(memcmp(decoded_hdr.tx_root, tx_root, 32) == 0);
    TEST_ASSERT(memcmp(decoded_hdr.dsso_root, dsso_root, 32) == 0);

    /* Feed canonical payload into VDF Engine */
    static vdf_context_t vdf_ctx;
    TEST_ASSERT(vdf_init(&vdf_ctx, vdf_payload, sizeof(vdf_payload), 1000) == 0);

    uint8_t vdf_output[VDF_OUTPUT_LEN];
    TEST_ASSERT(vdf_evaluate(&vdf_ctx, vdf_output) == 0);
    TEST_ASSERT(vdf_verify(&vdf_ctx, vdf_payload, sizeof(vdf_payload), 1000, vdf_output) == 1);

    /* Tampering payload must fail VDF verification */
    vdf_payload[0] ^= 0x01;
    TEST_ASSERT(vdf_verify(&vdf_ctx, vdf_payload, sizeof(vdf_payload), 1000, vdf_output) == 0);

    printf("  -> PASS: header round trip; VDF output re-evaluated; tampered payload rejected.\n");
}

/*
 * ── 3. LibFuzzer Target Harness ──────────────────────────────────────────────
 */
static account_t s_fuzz_sender;
static ledger_state_t s_fuzz_ledger;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0) {
        return 0;
    }

    /* Target 1: Fuzz verify_triple_entry_tx with arbitrary / extreme transaction amounts */
    if (size >= sizeof(triple_entry_tx_t)) {
        triple_entry_tx_t fuzz_tx;
        memcpy(&fuzz_tx, data, sizeof(triple_entry_tx_t));

        /* Sender with extreme and boundary balances */
        memset(&s_fuzz_sender, 0, sizeof(s_fuzz_sender));
        memcpy(s_fuzz_sender.pubkey, fuzz_tx.from, 32);
        s_fuzz_sender.balance = (data[0] % 2 == 0) ? UINT64_MAX : (uint64_t)size;
        s_fuzz_sender.nonce = fuzz_tx.nonce > 0 ? fuzz_tx.nonce - 1 : 0;

        uint64_t min_fee = (uint64_t)(data[size - 1]);
        int rc_verify = verify_triple_entry_tx(&s_fuzz_sender, &fuzz_tx, min_fee);

        ledger_state_init(&s_fuzz_ledger);
        account_t *registered = ledger_register_account(&s_fuzz_ledger, s_fuzz_sender.pubkey,
                                                        s_fuzz_sender.balance);
        TEST_ASSERT(registered != NULL);
        registered->nonce = s_fuzz_sender.nonce;
        /* A one-account ledger adds no apply-only failure (the receiver is new
         * or the sender, the fee accumulator is zero): the statuses agree. */
        TEST_ASSERT((int)ledger_apply_tx(&s_fuzz_ledger, &fuzz_tx, min_fee) == rc_verify);
    }

    /* Target 2: Canonical Block Header deserialization (exact length only) */
    {
        wire_block_header_t hdr;
        wire_status_t rc_hdr = wire_parse_block_header(data, size, &hdr);
        TEST_ASSERT((rc_hdr == WIRE_OK) == (size == WIRE_BLOCK_HEADER_LEN));
    }

    return 0;
}

#ifndef LIBFUZZER_ENABLED
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=================================================================\n");
    printf("Running C99 ledger state and block header checks\n");
    printf("=================================================================\n");

    test_triple_entry_ledger_invariants();
    test_ledger_roots();
    test_consensus_vdf_binding();

    /* Simulated in-process LibFuzzer sweep */
    printf("[TEST] 3. Random input sweep (1000 inputs)...\n");
    uint8_t fuzz_buf[512];
    for (int i = 0; i < 1000; ++i) {
        size_t sz = (size_t)(rand() % sizeof(fuzz_buf));
        for (size_t j = 0; j < sz; ++j) {
            fuzz_buf[j] = (uint8_t)(rand() & 0xFF);
            if ((rand() % 8) == 0) fuzz_buf[j] = 0x00; /* Inject NUL bytes */
            if ((rand() % 8) == 1) fuzz_buf[j] = 0xFF; /* Inject UINT64_MAX bytes */
        }
        (void)LLVMFuzzerTestOneInput(fuzz_buf, sz);
    }
    printf("  -> PASS: 1000 random inputs processed.\n");

    printf("=================================================================\n");
    printf("PASS: test_ledger_state\n");
    printf("=================================================================\n");
    return 0;
}
#endif
