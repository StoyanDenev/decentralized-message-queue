/* SPDX-License-Identifier: Apache-2.0
 * Capacity preflight gate over the actual codec source. Oversized memcpy calls
 * are intercepted so a missing guard fails an assertion, not a memory fault.
 * Ordinary test-binary-codec still executes the real copies under sanitizers.
 */
#include <determ/wire/binary_codec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #x, __FILE__, __LINE__); \
    exit(1); \
} } while (0)

static int oversized_copy;
static void *bounded_test_copy(void *dst, const void *src, size_t len) {
    if (len > 1024) { oversized_copy = 1; return dst; }
    return memcpy(dst, src, len);
}
#ifdef memcpy
#undef memcpy
#endif
#define memcpy bounded_test_copy
#include "../src/wire/binary_codec.c"
#undef memcpy

static uint8_t output[1024], before[1024];
static size_t written;
static const uint8_t byte = 7;
static const uint8_t hash[32] = {0};
static void reset_output(void) {
    memset(output, 0xa5, sizeof(output));
    memcpy(before, output, sizeof(before));
    written = 123;
    oversized_copy = 0;
}
static void rejected(wire_codec_status_t status, wire_codec_status_t expected) {
    CHECK(status == expected);
    CHECK(!oversized_copy);
    CHECK(written == 123);
    CHECK(memcmp(output, before, sizeof(output)) == 0);
}

static void test_unrepresentable_lengths(void) {
    const size_t lengths[] = { SIZE_MAX, SIZE_MAX - 3, SIZE_MAX - 40 };
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t n = lengths[i];
        reset_output();
        rejected(wire_envelope_encode(output, sizeof(output), WIRE_MSG_BLOCK,
                  &byte, n, &written), WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
        wire_abort_event_t event = {0};
        event.claims_blob = &byte; event.claims_blob_len = n;
        reset_output();
        rejected(wire_abort_event_encode(output, sizeof(output), &event, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
        wire_shard_tip_t tip = {0};
        tip.block_frame = &byte; tip.block_frame_len = n;
        reset_output();
        rejected(wire_shard_tip_encode(output, sizeof(output), &tip, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
        wire_receipt_bundle_t receipt = {0};
        receipt.block_frame = &byte; receipt.block_frame_len = n;
        reset_output();
        rejected(wire_receipt_bundle_encode(output, sizeof(output), &receipt, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
        reset_output();
        rejected(wire_dbk1_wrap(output, sizeof(output), &byte, n, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    }
    /* uint32_t promotion is a separate defect on 64-bit hosts. */
    const uint32_t u32_lengths[] = { UINT32_MAX, UINT32_MAX - 3, UINT32_MAX - 39 };
    for (size_t i = 0; i < sizeof(u32_lengths) / sizeof(u32_lengths[0]); ++i) {
        wire_transaction_t tx = {0};
        tx.pq_auth = &byte; tx.pq_auth_len = u32_lengths[i];
        reset_output();
        rejected(wire_tx_encode(output, sizeof(output), &tx, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
        reset_output();
        rejected(wire_dhf1_record_encode(output, sizeof(output), hash, &byte,
                 u32_lengths[i], &written), WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    }
    /* Pure preflight checks exercise SIZE_MAX offsets without making an invalid
     * pointer or pretending a tiny input really contains SIZE_MAX bytes. */
    CHECK(!bytes_fit(SIZE_MAX, SIZE_MAX - 2, 4));
    CHECK(!bytes_fit(SIZE_MAX, SIZE_MAX - 20, 40));
    CHECK(bytes_fit(SIZE_MAX, SIZE_MAX - 40, 40));
    CHECK(!bytes_fit(0, 4, 0));
    CHECK(bytes_fit(4, 4, 0));
}

static void test_missing_extents(void) {
    wire_hello_t hello = {0};
    hello.domain_len = 1;
    reset_output();
    rejected(wire_hello_encode(output, sizeof(output), &hello, &written), WIRE_CODEC_ERR_INVALID_ARG);
    wire_block_sig_t sig = {0};
    sig.signer_len = 1;
    reset_output();
    rejected(wire_block_sig_encode(output, sizeof(output), &sig, &written), WIRE_CODEC_ERR_INVALID_ARG);
    wire_status_response_t status = {0};
    status.genesis_len = 64;
    reset_output();
    rejected(wire_status_response_encode(output, sizeof(output), &status, &written), WIRE_CODEC_ERR_INVALID_ARG);
    wire_equivocation_evidence_t equiv = {0};
    equiv.equivocator_len = 1;
    reset_output();
    rejected(wire_equivocation_encode(output, sizeof(output), &equiv, &written), WIRE_CODEC_ERR_INVALID_ARG);
    for (unsigned field = 0; field < 6; ++field) {
        wire_contrib_t contrib = {0};
        if (field == 0) contrib.signer_len = 1;
        if (field == 1) contrib.tx_hash_count = 1;
        if (field == 2) contrib.view_eq_count = 1;
        if (field == 3) contrib.view_abort_count = 1;
        if (field == 4) contrib.view_inbound_count = 1;
        if (field == 5) contrib.view_shardtip_count = 1;
        reset_output();
        rejected(wire_contrib_encode(output, sizeof(output), &contrib, &written), WIRE_CODEC_ERR_INVALID_ARG);
    }
    for (unsigned field = 0; field < 2; ++field) {
        wire_abort_claim_t claim = {0};
        if (field == 0) claim.missing_creator_len = 1;
        else claim.claimer_len = 1;
        reset_output();
        rejected(wire_abort_claim_encode(output, sizeof(output), &claim, &written), WIRE_CODEC_ERR_INVALID_ARG);
        wire_abort_event_t event = {0};
        if (field == 0) event.aborting_node_len = 1;
        else event.claims_blob_len = 1;
        reset_output();
        rejected(wire_abort_event_encode(output, sizeof(output), &event, &written), WIRE_CODEC_ERR_INVALID_ARG);
    }
    wire_shard_tip_t tip = {0}; tip.block_frame_len = 1;
    reset_output();
    rejected(wire_shard_tip_encode(output, sizeof(output), &tip, &written), WIRE_CODEC_ERR_INVALID_ARG);
    wire_receipt_bundle_t receipt = {0}; receipt.block_frame_len = 1;
    reset_output();
    rejected(wire_receipt_bundle_encode(output, sizeof(output), &receipt, &written), WIRE_CODEC_ERR_INVALID_ARG);
    reset_output();
    rejected(wire_envelope_encode(output, sizeof(output), WIRE_MSG_BLOCK, NULL, 1, &written), WIRE_CODEC_ERR_INVALID_ARG);
    reset_output();
    rejected(wire_dbk1_wrap(output, sizeof(output), NULL, 1, &written), WIRE_CODEC_ERR_INVALID_ARG);
    reset_output();
    rejected(wire_dhf1_record_encode(output, sizeof(output), hash, NULL, 1, &written), WIRE_CODEC_ERR_INVALID_ARG);
}

static void test_boundaries_and_cursors(void) {
    for (size_t cap = 0; cap < 5; ++cap) {
        reset_output();
        rejected(wire_envelope_encode(output, cap, WIRE_MSG_BLOCK, &byte, 1, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    }
    reset_output();
    CHECK(wire_envelope_encode(output, 5, WIRE_MSG_BLOCK, &byte, 1, &written) == WIRE_CODEC_OK);
    CHECK(written == 5 && output[4] == byte && output[5] == 0xa5);
    reset_output();
    CHECK(wire_dhf1_record_encode(output, 41, hash, &byte, 1, &written) == WIRE_CODEC_OK);
    CHECK(written == 41 && output[40] == byte && output[41] == 0xa5);
    size_t cursor = 0;
    wire_header_record_t rec;
    CHECK(wire_headers_response_next_record(output, written, &cursor, &rec) == WIRE_CODEC_OK);
    CHECK(cursor == 41 && rec.frame_len == 1 && rec.block_frame[0] == byte);
    const size_t cursors[] = { 2, 3, 4, SIZE_MAX };
    const uint8_t data[4] = {0};
    for (size_t i = 0; i < sizeof(cursors) / sizeof(cursors[0]); ++i) {
        const uint8_t *block = NULL;
        uint32_t length = 17;
        cursor = cursors[i];
        CHECK(wire_chain_response_next_block(data, sizeof(data), &cursor, &block, &length) == WIRE_CODEC_ERR_TRUNCATED);
        CHECK(cursor == cursors[i] && block == NULL && length == 17);
        CHECK(wire_headers_response_next_record(data, sizeof(data), &cursor, &rec) == WIRE_CODEC_ERR_TRUNCATED);
        CHECK(cursor == cursors[i]);
    }
}


/* Exact-capacity edges of the new preflight clauses; rejected() also proves
 * that no byte of the 1024-byte backing buffer was written. */
static void test_exact_capacity_edges(void) {
    wire_transaction_t tx = {0};
    tx.pq_auth = &byte; tx.pq_auth_len = 1;          /* 265 + 4 + 1 = 270 */
    for (size_t cap = 0; cap < 270; ++cap) {
        reset_output();
        rejected(wire_tx_encode(output, cap, &tx, &written), WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    }
    reset_output();
    CHECK(wire_tx_encode(output, 270, &tx, &written) == WIRE_CODEC_OK);
    CHECK(written == 270 && output[270] == 0xa5);
    tx.pq_auth = NULL; tx.pq_auth_len = 0;           /* 265 */
    reset_output();
    rejected(wire_tx_encode(output, 264, &tx, &written), WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    for (size_t cap = 0; cap < 41; ++cap) {
        reset_output();
        rejected(wire_dhf1_record_encode(output, cap, hash, &byte, 1, &written),
                 WIRE_CODEC_ERR_BUFFER_TOO_SMALL);
    }
    /* A record whose declared frame exceeds the remaining input. */
    uint8_t rec[48]; size_t n = 0, cursor = 0; wire_header_record_t hr;
    CHECK(wire_dhf1_record_encode(rec, sizeof(rec), hash, hash, 8, &n) == WIRE_CODEC_OK && n == 48);
    for (size_t cut = 40; cut < 48; ++cut) {
        cursor = 0;
        CHECK(wire_headers_response_next_record(rec, cut, &cursor, &hr) == WIRE_CODEC_ERR_TRUNCATED && cursor == 0);
    }
    const uint8_t blocks[12] = { 8, 0, 0, 0 };
    const uint8_t *frame = NULL; uint32_t frame_len = 0;
    for (size_t cut = 4; cut < 12; ++cut) {
        cursor = 0;
        CHECK(wire_chain_response_next_block(blocks, cut, &cursor, &frame, &frame_len) == WIRE_CODEC_ERR_TRUNCATED && cursor == 0);
    }
}

int main(void) {
    test_exact_capacity_edges();
    test_unrepresentable_lengths();
    test_missing_extents();
    test_boundaries_and_cursors();
    puts("PASS: C99 codec bounds reject before output writes or oversized copies");
    return 0;
}
