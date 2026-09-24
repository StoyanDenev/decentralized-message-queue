/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: C99 Bare-Metal Canonical Binary Frame Codec
 */

#include <determ/wire/binary_codec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_PASS(name) printf("  [PASS] %s\n", name)

static void test_binary_envelope(void) {
    uint8_t buf[256];
    size_t written = 0;
    const uint8_t test_payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    /* 1. Normal round-trip */
    wire_codec_status_t rc = wire_envelope_encode(buf, sizeof(buf), WIRE_MSG_TRANSACTION,
                                                 test_payload, sizeof(test_payload), &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == 4 + sizeof(test_payload));
    TEST_ASSERT(wire_is_binary_envelope(buf, written) == true);

    wire_envelope_t env;
    rc = wire_envelope_decode(buf, written, &env);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(env.msg_type == WIRE_MSG_TRANSACTION);
    TEST_ASSERT(env.payload_len == sizeof(test_payload));
    TEST_ASSERT(memcmp(env.payload, test_payload, sizeof(test_payload)) == 0);

    /* 2. Reject bad magic */
    buf[0] = 0xAA;
    TEST_ASSERT(wire_envelope_decode(buf, written, &env) == WIRE_CODEC_ERR_BAD_MAGIC);
    buf[0] = WIRE_ENVELOPE_MAGIC;

    /* 3. Reject bad version */
    buf[1] = 0x02;
    TEST_ASSERT(wire_envelope_decode(buf, written, &env) == WIRE_CODEC_ERR_BAD_VERSION);
    buf[1] = WIRE_ENVELOPE_VERSION;

    /* 4. Reject bad msg_type */
    buf[2] = WIRE_MSG_TYPE_COUNT + 1;
    TEST_ASSERT(wire_envelope_decode(buf, written, &env) == WIRE_CODEC_ERR_BAD_MSG_TYPE);
    buf[2] = WIRE_MSG_TRANSACTION;

    /* 5. Reject non-zero reserved byte */
    buf[3] = 0x01;
    TEST_ASSERT(wire_envelope_decode(buf, written, &env) == WIRE_CODEC_ERR_NONZERO_RESERVED);
    buf[3] = 0x00;

    /* 6. Reject truncated envelope header */
    TEST_ASSERT(wire_envelope_decode(buf, 3, &env) == WIRE_CODEC_ERR_TRUNCATED);

    TEST_PASS("test_binary_envelope");
}

static void test_hello_frame(void) {
    uint8_t buf[256];
    size_t written = 0;

    wire_hello_t in_msg;
    in_msg.domain = "validator-alpha.determ.net";
    in_msg.domain_len = (uint8_t)strlen(in_msg.domain);
    in_msg.port = 4848;
    in_msg.role = 2; /* Full Node */
    in_msg.shard_id = 42;
    in_msg.wire_version = 1;

    wire_codec_status_t rc = wire_hello_encode(buf, sizeof(buf), &in_msg, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);

    wire_hello_t out_msg;
    rc = wire_hello_decode(buf, written, &out_msg);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(out_msg.domain_len == in_msg.domain_len);
    TEST_ASSERT(memcmp(out_msg.domain, in_msg.domain, in_msg.domain_len) == 0);
    TEST_ASSERT(out_msg.port == in_msg.port);
    TEST_ASSERT(out_msg.role == in_msg.role);
    TEST_ASSERT(out_msg.shard_id == in_msg.shard_id);
    TEST_ASSERT(out_msg.wire_version == in_msg.wire_version);

    /* Trailing bytes rejection */
    buf[written] = 0xFF;
    rc = wire_hello_decode(buf, written + 1, &out_msg);
    TEST_ASSERT(rc == WIRE_CODEC_ERR_TRAILING_BYTES);

    TEST_PASS("test_hello_frame");
}

static void test_transaction_frame(void) {
    uint8_t buf[1024];
    size_t written = 0;

    /* Test TX with payload overflow (> 32 bytes) and optional pq_auth */
    uint8_t long_payload[64];
    for (int i = 0; i < 64; i++) long_payload[i] = (uint8_t)(i ^ 0x5A);

    uint8_t pq_sig[128];
    for (int i = 0; i < 128; i++) pq_sig[i] = (uint8_t)(i ^ 0xA5);

    wire_transaction_t in_tx;
    memset(&in_tx, 0, sizeof(in_tx));
    memset(in_tx.sender_pubkey, 0x11, 32);
    in_tx.amount = 1000000ULL;
    in_tx.fee = 500ULL;
    in_tx.nonce = 42ULL;
    memset(in_tx.recipient_pubkey, 0x22, 32);
    in_tx.payload = long_payload;
    in_tx.payload_overflow = long_payload + 32;
    in_tx.payload_len = 64;
    in_tx.type = 1;
    in_tx.from = "determ1alice";
    in_tx.from_len = (uint8_t)strlen(in_tx.from);
    in_tx.to = "determ1bob";
    in_tx.to_len = (uint8_t)strlen(in_tx.to);
    memset(in_tx.sig, 0x33, 64);
    memset(in_tx.hash, 0x44, 32);
    memset(in_tx.genesis_hash, 0x55, 32);
    in_tx.shard_id = 7;
    in_tx.pq_auth = pq_sig;
    in_tx.pq_auth_len = 128;

    wire_codec_status_t rc = wire_tx_encode(buf, sizeof(buf), &in_tx, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);

    wire_transaction_t out_tx;
    rc = wire_tx_decode(buf, written, &out_tx);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(memcmp(out_tx.sender_pubkey, in_tx.sender_pubkey, 32) == 0);
    TEST_ASSERT(out_tx.amount == in_tx.amount);
    TEST_ASSERT(out_tx.fee == in_tx.fee);
    TEST_ASSERT(out_tx.nonce == in_tx.nonce);
    TEST_ASSERT(memcmp(out_tx.recipient_pubkey, in_tx.recipient_pubkey, 32) == 0);
    TEST_ASSERT(out_tx.payload_len == in_tx.payload_len);
    TEST_ASSERT(memcmp(out_tx.payload, long_payload, 32) == 0);
    TEST_ASSERT(out_tx.payload_overflow != NULL);
    TEST_ASSERT(memcmp(out_tx.payload_overflow, long_payload + 32, 32) == 0);
    TEST_ASSERT(out_tx.type == in_tx.type);
    TEST_ASSERT(out_tx.from_len == in_tx.from_len);
    TEST_ASSERT(memcmp(out_tx.from, in_tx.from, in_tx.from_len) == 0);
    TEST_ASSERT(out_tx.to_len == in_tx.to_len);
    TEST_ASSERT(memcmp(out_tx.to, in_tx.to, in_tx.to_len) == 0);
    TEST_ASSERT(memcmp(out_tx.sig, in_tx.sig, 64) == 0);
    TEST_ASSERT(memcmp(out_tx.hash, in_tx.hash, 32) == 0);
    TEST_ASSERT(memcmp(out_tx.genesis_hash, in_tx.genesis_hash, 32) == 0);
    TEST_ASSERT(out_tx.shard_id == in_tx.shard_id);
    TEST_ASSERT(out_tx.pq_auth_len == in_tx.pq_auth_len);
    TEST_ASSERT(memcmp(out_tx.pq_auth, in_tx.pq_auth, in_tx.pq_auth_len) == 0);

    /* encode(decode(frame)) reproduces the frame, payload bytes included. */
    uint8_t again[1024];
    size_t again_len = 0;
    TEST_ASSERT(wire_tx_encode(again, sizeof(again), &out_tx, &again_len) == WIRE_CODEC_OK);
    TEST_ASSERT(again_len == written && memcmp(again, buf, written) == 0);

    /* A short payload leaves zero padding in the 32-byte slot; non-zero
     * padding is rejected. */
    in_tx.payload_len = 5;
    in_tx.pq_auth = NULL;
    in_tx.pq_auth_len = 0;
    uint8_t short_frame[1024];
    size_t short_len = 0;
    TEST_ASSERT(wire_tx_encode(short_frame, sizeof(short_frame), &in_tx, &short_len) == WIRE_CODEC_OK);
    TEST_ASSERT(wire_tx_decode(short_frame, short_len, &out_tx) == WIRE_CODEC_OK);
    TEST_ASSERT(out_tx.payload_len == 5 && memcmp(out_tx.payload, long_payload, 5) == 0);
    TEST_ASSERT(out_tx.payload_overflow == NULL);
    short_frame[96 + 5] = 0x01;
    TEST_ASSERT(wire_tx_decode(short_frame, short_len, &out_tx) == WIRE_CODEC_ERR_NONZERO_RESERVED);
    short_frame[96 + 5] = 0x00;
    short_frame[127] = 0x80;
    TEST_ASSERT(wire_tx_decode(short_frame, short_len, &out_tx) == WIRE_CODEC_ERR_NONZERO_RESERVED);
    short_frame[127] = 0x00;
    TEST_ASSERT(wire_tx_decode(short_frame, short_len, &out_tx) == WIRE_CODEC_OK);

    /* A declared overflow segment without its bytes is refused, not encoded. */
    in_tx.payload_len = 64;
    in_tx.payload_overflow = NULL;
    TEST_ASSERT(wire_tx_encode(short_frame, sizeof(short_frame), &in_tx, &short_len) == WIRE_CODEC_ERR_INVALID_ARG);

    /* Verify non-zero reserved reject */
    buf[56] = 0x01;
    rc = wire_tx_decode(buf, written, &out_tx);
    TEST_ASSERT(rc == WIRE_CODEC_ERR_NONZERO_RESERVED);

    TEST_PASS("test_transaction_frame");
}

static void test_block_sig_and_contrib(void) {
    uint8_t buf[2048];
    size_t written = 0;

    /* 1. BLOCK_SIG */
    wire_block_sig_t in_sig;
    in_sig.block_index = 12345;
    in_sig.signer = "validator-node-9";
    in_sig.signer_len = (uint8_t)strlen(in_sig.signer);
    memset(in_sig.delay_output, 0x11, 32);
    memset(in_sig.dh_secret, 0x22, 32);
    memset(in_sig.ed_sig, 0x33, 64);

    wire_codec_status_t rc = wire_block_sig_encode(buf, sizeof(buf), &in_sig, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);

    wire_block_sig_t out_sig;
    rc = wire_block_sig_decode(buf, written, &out_sig);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(out_sig.block_index == in_sig.block_index);
    TEST_ASSERT(out_sig.signer_len == in_sig.signer_len);
    TEST_ASSERT(memcmp(out_sig.signer, in_sig.signer, in_sig.signer_len) == 0);
    TEST_ASSERT(memcmp(out_sig.delay_output, in_sig.delay_output, 32) == 0);
    TEST_ASSERT(memcmp(out_sig.dh_secret, in_sig.dh_secret, 32) == 0);
    TEST_ASSERT(memcmp(out_sig.ed_sig, in_sig.ed_sig, 64) == 0);

    /* 2. CONTRIB */
    uint8_t sample_hashes[64];
    memset(sample_hashes, 0xAB, 64);

    wire_contrib_t in_contrib;
    memset(&in_contrib, 0, sizeof(in_contrib));
    in_contrib.block_index = 999;
    in_contrib.signer = "proposer-1";
    in_contrib.signer_len = (uint8_t)strlen(in_contrib.signer);
    memset(in_contrib.prev_hash, 0xCC, 32);
    in_contrib.aborts_gen = 2;
    in_contrib.tx_hashes = sample_hashes;
    in_contrib.tx_hash_count = 2;
    memset(in_contrib.dh_input, 0xDD, 32);
    memset(in_contrib.view_eq_root, 0xEE, 32);
    memset(in_contrib.view_abort_root, 0xFF, 32);
    memset(in_contrib.view_inbound_root, 0x12, 32);
    in_contrib.view_eq_list = sample_hashes;
    in_contrib.view_eq_count = 1;
    in_contrib.proposer_time = 1774000000ULL;
    memset(in_contrib.view_shardtip_root, 0x34, 32);
    memset(in_contrib.ed_sig, 0x77, 64);

    rc = wire_contrib_encode(buf, sizeof(buf), &in_contrib, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);

    wire_contrib_t out_contrib;
    rc = wire_contrib_decode(buf, written, &out_contrib);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(out_contrib.block_index == in_contrib.block_index);
    TEST_ASSERT(out_contrib.signer_len == in_contrib.signer_len);
    TEST_ASSERT(memcmp(out_contrib.signer, in_contrib.signer, in_contrib.signer_len) == 0);
    TEST_ASSERT(memcmp(out_contrib.prev_hash, in_contrib.prev_hash, 32) == 0);
    TEST_ASSERT(out_contrib.aborts_gen == in_contrib.aborts_gen);
    TEST_ASSERT(out_contrib.tx_hash_count == 2);
    TEST_ASSERT(memcmp(out_contrib.tx_hashes, sample_hashes, 64) == 0);
    TEST_ASSERT(out_contrib.proposer_time == in_contrib.proposer_time);
    TEST_ASSERT(memcmp(out_contrib.ed_sig, in_contrib.ed_sig, 64) == 0);

    TEST_PASS("test_block_sig_and_contrib");
}

static void test_storage_and_control_frames(void) {
    uint8_t buf[1024];
    size_t written = 0;

    /* 1. DMF1 Manifest */
    wire_manifest_t in_m;
    in_m.height = 4242;
    memset(in_m.head_hash, 0x88, 32);
    wire_codec_status_t rc = wire_manifest_encode(buf, sizeof(buf), &in_m, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == WIRE_MANIFEST_BYTES);

    wire_manifest_t out_m;
    rc = wire_manifest_decode(buf, written, &out_m);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(out_m.height == in_m.height);
    TEST_ASSERT(memcmp(out_m.head_hash, in_m.head_hash, 32) == 0);

    /* 2. DBK1 Block File Wrapper */
    const uint8_t mock_block_frame[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    rc = wire_dbk1_wrap(buf, sizeof(buf), mock_block_frame, sizeof(mock_block_frame), &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == 4 + sizeof(mock_block_frame));

    const uint8_t *unwrapped_block = NULL;
    size_t unwrapped_len = 0;
    rc = wire_dbk1_unwrap(buf, written, &unwrapped_block, &unwrapped_len);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(unwrapped_len == sizeof(mock_block_frame));
    TEST_ASSERT(memcmp(unwrapped_block, mock_block_frame, sizeof(mock_block_frame)) == 0);

    /* 3. DHF1 Header Record & HEADERS_RESPONSE */
    uint8_t dhf_buf[512];
    uint8_t mock_hash[32];
    memset(mock_hash, 0x77, 32);
    rc = wire_dhf1_record_encode(dhf_buf, sizeof(dhf_buf), mock_hash,
                                mock_block_frame, (uint32_t)sizeof(mock_block_frame), &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == 4 + 32 + 4 + sizeof(mock_block_frame));

    size_t cursor = 0;
    wire_header_record_t rec;
    rc = wire_headers_response_next_record(dhf_buf, written, &cursor, &rec);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(cursor == written);
    TEST_ASSERT(memcmp(rec.block_hash, mock_hash, 32) == 0);
    TEST_ASSERT(rec.frame_len == sizeof(mock_block_frame));
    TEST_ASSERT(memcmp(rec.block_frame, mock_block_frame, sizeof(mock_block_frame)) == 0);

    /* 4. GET_CHAIN and STATUS_RESPONSE */
    wire_get_chain_t gc_in = { .from = 100, .count = 32 };
    rc = wire_get_chain_encode(buf, sizeof(buf), &gc_in, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == 10);
    wire_get_chain_t gc_out;
    rc = wire_get_chain_decode(buf, written, &gc_out);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(gc_out.from == 100 && gc_out.count == 32);

    const char *genesis_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    wire_status_response_t sr_in = { .height = 500, .genesis_hex = genesis_hex, .genesis_len = 64 };
    rc = wire_status_response_encode(buf, sizeof(buf), &sr_in, &written);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(written == 9 + 64);
    wire_status_response_t sr_out;
    rc = wire_status_response_decode(buf, written, &sr_out);
    TEST_ASSERT(rc == WIRE_CODEC_OK);
    TEST_ASSERT(sr_out.height == 500 && sr_out.genesis_len == 64);
    TEST_ASSERT(memcmp(sr_out.genesis_hex, genesis_hex, 64) == 0);

    TEST_PASS("test_storage_and_control_frames");
}

int main(void) {
    printf("=== Starting C99 Binary Wire Codec Test Suite ===\n");
    test_binary_envelope();
    test_hello_frame();
    test_transaction_frame();
    test_block_sig_and_contrib();
    test_storage_and_control_frames();
    printf("=== All C99 Binary Wire Codec Tests Passed Successfully ===\n");
    return 0;
}
