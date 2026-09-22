/* SPDX-License-Identifier: Apache-2.0
 * Binary fixtures were generated independently with Node crypto.sign using
 * OpenSSL 3.5.7, not Determ's signing/codec functions. Public fixture seeds are
 * 32 copies of byte 1 (default sender), 2 (recipient/second sender), or 1..9
 * (sparse senders). Independent signing input:
 * type || genesis32 || BE32(shard) || from66 || 0 || to66 || 0 ||
 * BE64(amount) || BE64(fee) || BE64(nonce), exactly 195 bytes.
 * Frames independently use the existing C++ Transaction::encode_frame layout:
 * ASCII address-prefix slots, LE numeric fields, empty payload/PQ, length 397.
 * Default context is zero genesis/salt, S=1. Routed/sparse contexts use
 * genesis=salt=bytes 00..1f, S=7/UINT32_MAX respectively. These are local fixtures,
 * not authenticated genesis records. Amount=10, fee=1, nonce=1 unless named.
 * Identity forgery is R=B,S=1 under A=identity; the signature equation holds
 * for every message, making the separate small-order rejection essential.
 */
#include <determ/ledger/pending_transfer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DETERM_TEST_FIXTURE_DIR
#define DETERM_TEST_FIXTURE_DIR "tests/fixtures"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "pending transfer failure line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static pending_shard_t buckets[PENDING_TRANSFER_MAX_SHARDS];
static pending_transfer_pool_t pool;

static void fixture(const char *name, uint8_t frame[PENDING_TRANSFER_FRAME_SIZE]) {
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/pending_transfer_%s.bin", DETERM_TEST_FIXTURE_DIR, name);
    CHECK(n > 0 && (size_t)n < sizeof(path));
    FILE *file = fopen(path, "rb");
    if (!file) fprintf(stderr, "fixture unavailable: %s\n", path);
    CHECK(file != NULL);
    CHECK(fread(frame, 1, PENDING_TRANSFER_FRAME_SIZE, file) == PENDING_TRANSFER_FRAME_SIZE);
    CHECK(fgetc(file) == EOF && !ferror(file));
    CHECK(fclose(file) == 0);
}

static uint32_t shard_of(const uint8_t *frame) {
    return (uint32_t)frame[393] | ((uint32_t)frame[394] << 8) |
           ((uint32_t)frame[395] << 16) | ((uint32_t)frame[396] << 24);
}

static void initialize(uint32_t count, int ramp, size_t capacity) {
    shard_routing_config_t routing;
    uint8_t salt[32], genesis[32];
    for (size_t i = 0; i < 32; ++i) salt[i] = genesis[i] = ramp ? (uint8_t)i : 0;
    CHECK(shard_routing_init(&routing, count, salt) == 0);
    CHECK(pending_transfer_init(&pool, buckets, capacity, &routing, genesis) == 0);
}

static void rejected(const uint8_t *frame, size_t len, pending_transfer_status_t expected) {
    pending_shard_t old_buckets[PENDING_TRANSFER_MAX_SHARDS];
    pending_transfer_pool_t old_pool;
    pending_transfer_result_t result, old_result;
    memcpy(old_buckets, buckets, sizeof(buckets));
    memcpy(&old_pool, &pool, sizeof(pool));
    memset(&result, 0xa5, sizeof(result));
    memcpy(&old_result, &result, sizeof(result));
    pending_transfer_status_t actual = pending_transfer_submit(&pool, frame, len, &result);
    if (actual != expected) fprintf(stderr, "expected refusal %d, got %d\n", expected, actual);
    CHECK(actual == expected);
    CHECK(memcmp(old_buckets, buckets, sizeof(buckets)) == 0);
    CHECK(memcmp(&old_pool, &pool, sizeof(pool)) == 0);
    CHECK(memcmp(&old_result, &result, sizeof(result)) == 0);
}

static pending_transfer_result_t accepted(const uint8_t *frame, pending_transfer_status_t expected) {
    pending_transfer_result_t result;
    CHECK(pending_transfer_submit(&pool, frame, PENDING_TRANSFER_FRAME_SIZE, &result) == expected);
    CHECK(memcmp(result.hash, frame + 329, 32) == 0);
    CHECK(result.shard_id == shard_of(frame));
    return result;
}

static void test_owned_configuration_and_frames(void) {
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE], original[PENDING_TRANSFER_FRAME_SIZE];
    uint8_t zero[32] = {0};
    shard_routing_config_t routing;
    pending_transfer_snapshot_t snapshot;
    CHECK(shard_routing_init(&routing, 1, zero) == 0);
    CHECK(pending_transfer_init(&pool, buckets, 8, &routing, zero) == 0);
    routing.shard_count = 7;
    memset(routing.salt, 255, 32);
    memset(zero, 255, 32);
    fixture("default", frame);
    memcpy(original, frame, sizeof(frame));
    CHECK(accepted(frame, PENDING_TRANSFER_INSERTED).pending_count == 1);
    CHECK(accepted(frame, PENDING_TRANSFER_DUPLICATE).pending_count == 1);
    memset(frame, 0, sizeof(frame));
    CHECK(pending_transfer_list(&pool, 0, &snapshot) == 0 && snapshot.count == 1);
    CHECK(memcmp(snapshot.frames[0], original, sizeof(original)) == 0);
    snapshot.frames[0][0] ^= 1;
    CHECK(pending_transfer_list(&pool, 0, &snapshot) == 0 && snapshot.count == 1);
    CHECK(memcmp(snapshot.frames[0], original, sizeof(original)) == 0);
    CHECK(pool.routing.shard_count == 1 && pool.genesis_hash[0] == 0 && pool.routing.salt[0] == 0);
}

static void test_authentication_before_state(void) {
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE + 1], valid[PENDING_TRANSFER_FRAME_SIZE];
    initialize(1, 0, 8);
    fixture("default", valid);
    accepted(valid, PENDING_TRANSFER_INSERTED);
    memcpy(frame, valid, sizeof(valid));
    frame[265] ^= 1;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SIGNATURE); /* forged duplicate */
    fixture("conflict_11", frame);
    CHECK(memcmp(frame + 329, valid + 329, 32) < 0);
    frame[265] ^= 1;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SIGNATURE); /* forged preferred conflict */
    memcpy(frame, valid, sizeof(valid)); frame[329] ^= 1;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_HASH);
    memcpy(frame, valid, sizeof(valid)); memset(frame + 329, 0, 32);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_HASH); /* zero is not a wildcard */
    initialize(1, 0, 8); /* Context mutants must admit, not hit a later conflict rejection. */
    fixture("wrong_genesis", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_GENESIS); /* fresh valid signature */
    fixture("wrong_shard", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SOURCE_SHARD); /* freshly signed, outside S */
    fixture("identity", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SENDER_KEY); /* valid forged equation */
    fixture("malformed_key", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SIGNATURE);

    fixture("wrong_type", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME); /* freshly signed type 1 */
    fixture("uppercase", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME); /* freshly signed uppercase address */
    const size_t unsigned_bad_offsets[] = {0, 64, 96, 127, 56};
    for (size_t i = 0; i < sizeof(unsigned_bad_offsets) / sizeof(unsigned_bad_offsets[0]); ++i) {
        memcpy(frame, valid, sizeof(valid)); frame[unsigned_bad_offsets[i]] ^= 1;
        rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    }
    memcpy(frame, valid, sizeof(valid)); frame[129] = 1; frame[96] = 1;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    memcpy(frame, valid, sizeof(valid)); frame[131] = 65;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    memcpy(frame, valid, sizeof(valid)); frame[198] = 65;
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    memcpy(frame, valid, sizeof(valid)); frame[134] = '\0';
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    memcpy(frame, valid, sizeof(valid)); frame[201] = 'g';
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_FRAME);
    memcpy(frame, valid, sizeof(valid)); frame[sizeof(valid)] = 0;
    rejected(frame, sizeof(frame), PENDING_TRANSFER_ERR_FRAME);
    for (size_t len = 0; len < sizeof(valid); ++len)
        rejected(frame, len, PENDING_TRANSFER_ERR_FRAME);

    initialize(7, 1, 8);
    fixture("routed", frame);
    CHECK(accepted(frame, PENDING_TRANSFER_INSERTED).shard_id == 6);
    initialize(7, 1, 8); /* Isolate source ownership from the later hash preference. */
    fixture("wrong_route", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_SOURCE_SHARD); /* signed shard3, owner6 */
    fixture("cross_shard", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_CROSS_SHARD); /* signed source6,destination3 */
    initialize(1, 0, 8);
    /* Exact comparison also rejects zero transaction genesis against a configured
     * nonzero genesis, without relying on a shard or signature mismatch. */
    shard_routing_config_t routing = pool.routing;
    uint8_t genesis[32];
    for (size_t i = 0; i < 32; ++i) genesis[i] = (uint8_t)i;
    CHECK(pending_transfer_init(&pool, buckets, 8, &routing, genesis) == 0);
    fixture("default", frame);
    rejected(frame, sizeof(valid), PENDING_TRANSFER_ERR_GENESIS);
    fixture("wrong_genesis", frame);
    accepted(frame, PENDING_TRANSFER_INSERTED);
}

static void test_conflicts_capacity_and_order(void) {
    uint8_t original[PENDING_TRANSFER_FRAME_SIZE], preferred[PENDING_TRANSFER_FRAME_SIZE], middle[PENDING_TRANSFER_FRAME_SIZE];
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE];
    pending_transfer_snapshot_t forward, reverse, snapshot;
    fixture("default", original); fixture("conflict_11", preferred); fixture("conflict_12", middle);
    CHECK(memcmp(preferred + 329, middle + 329, 32) < 0 && memcmp(middle + 329, original + 329, 32) < 0);
    initialize(1, 0, 1);
    accepted(original, PENDING_TRANSFER_INSERTED);
    accepted(middle, PENDING_TRANSFER_REPLACED);
    accepted(preferred, PENDING_TRANSFER_REPLACED);
    CHECK(pending_transfer_list(&pool, 0, &forward) == 0 && forward.count == 1);
    initialize(1, 0, 1);
    accepted(preferred, PENDING_TRANSFER_INSERTED);
    rejected(middle, sizeof(middle), PENDING_TRANSFER_ERR_NOT_PREFERRED);
    rejected(original, sizeof(original), PENDING_TRANSFER_ERR_NOT_PREFERRED);
    CHECK(pending_transfer_list(&pool, 0, &reverse) == 0);
    CHECK(memcmp(&forward, &reverse, sizeof(forward)) == 0);

    initialize(1, 0, 1);
    accepted(original, PENDING_TRANSFER_INSERTED);
    const char *fill[] = {"nonce_4", "nonce_2", "nonce_3"};
    for (size_t i = 0; i < 3; ++i) { fixture(fill[i], frame); accepted(frame, PENDING_TRANSFER_INSERTED); }
    CHECK(accepted(preferred, PENDING_TRANSFER_REPLACED).pending_count == 4); /* replacement at capacity */
    CHECK(accepted(preferred, PENDING_TRANSFER_DUPLICATE).pending_count == 4);
    fixture("nonce_5", frame);
    rejected(frame, sizeof(frame), PENDING_TRANSFER_ERR_CAPACITY);
    frame[265] ^= 1;
    rejected(frame, sizeof(frame), PENDING_TRANSFER_ERR_SIGNATURE); /* full does not bypass auth */
    CHECK(pending_transfer_list(&pool, 0, &snapshot) == 0 && snapshot.count == 4);
    for (size_t i = 0; i < 4; ++i) CHECK(snapshot.frames[i][48] == i + 1);
    CHECK(memcmp(snapshot.frames[0], preferred, sizeof(preferred)) == 0);

    initialize(1, 0, 1);
    fixture("nonce_max", frame); accepted(frame, PENDING_TRANSFER_INSERTED);
    accepted(original, PENDING_TRANSFER_INSERTED);
    fixture("nonce_0", frame); accepted(frame, PENDING_TRANSFER_INSERTED);
    fixture("second_sender", frame); accepted(frame, PENDING_TRANSFER_INSERTED);
    CHECK(pending_transfer_list(&pool, 0, &snapshot) == 0 && snapshot.count == 4);
    CHECK(memcmp(snapshot.frames[0], frame, sizeof(frame)) == 0); /* sender81.. before8a.. */
    fixture("nonce_0", frame); CHECK(memcmp(snapshot.frames[1], frame, sizeof(frame)) == 0);
    CHECK(memcmp(snapshot.frames[2], original, sizeof(original)) == 0);
    fixture("nonce_max", frame); CHECK(memcmp(snapshot.frames[3], frame, sizeof(frame)) == 0);
}

static void test_sparse_shards_and_invalid_arguments(void) {
    static const uint32_t shard_ids[9] = {3029074351U,3014741129U,3478588442U,4198117546U,2300111512U,
                                         1164743518U,2229326869U,3821808314U,1342591991U};
    uint8_t frame[PENDING_TRANSFER_FRAME_SIZE];
    pending_transfer_snapshot_t snapshot, old_snapshot;
    initialize(UINT32_MAX, 1, 8);
    for (size_t i = 0; i < 9; ++i) {
        char name[32];
        CHECK(snprintf(name, sizeof(name), "sparse_%u", (unsigned)i + 1) > 0);
        fixture(name, frame);
        CHECK(shard_of(frame) == shard_ids[i]);
        if (i < 8) CHECK(accepted(frame, PENDING_TRANSFER_INSERTED).pending_count == 1);
        else rejected(frame, sizeof(frame), PENDING_TRANSFER_ERR_CAPACITY);
    }
    for (size_t i = 0; i < 8; ++i) {
        CHECK(pending_transfer_list(&pool, shard_ids[i], &snapshot) == 0 && snapshot.count == 1);
        CHECK(shard_of(snapshot.frames[0]) == shard_ids[i]);
    }
    CHECK(pending_transfer_list(&pool, shard_ids[8], &snapshot) == 0 && snapshot.count == 0);
    memset(&snapshot, 0xa5, sizeof(snapshot)); memcpy(&old_snapshot, &snapshot, sizeof(snapshot));
    CHECK(pending_transfer_list(&pool, UINT32_MAX, &snapshot) == PENDING_TRANSFER_ERR_SOURCE_SHARD);
    CHECK(memcmp(&snapshot, &old_snapshot, sizeof(snapshot)) == 0);
    CHECK(pending_transfer_list(NULL, 0, &snapshot) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(memcmp(&snapshot, &old_snapshot, sizeof(snapshot)) == 0);
    CHECK(pending_transfer_list(&pool, 0, NULL) == PENDING_TRANSFER_ERR_ARGUMENT);

    pending_transfer_pool_t disabled;
    memset(&disabled, 0, sizeof(disabled));
    pending_transfer_result_t result, old_result;
    memset(&result, 0xa5, sizeof(result)); memcpy(&old_result, &result, sizeof(result));
    CHECK(pending_transfer_submit(&disabled, frame, sizeof(frame), &result) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_submit(NULL, frame, sizeof(frame), &result) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(memcmp(&result, &old_result, sizeof(result)) == 0);
    rejected(NULL, sizeof(frame), PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_submit(&pool, frame, sizeof(frame), NULL) == PENDING_TRANSFER_ERR_ARGUMENT);

    pending_shard_t old_buckets[PENDING_TRANSFER_MAX_SHARDS];
    pending_transfer_pool_t old_pool;
    shard_routing_config_t routing = pool.routing;
    uint8_t genesis[32] = {0};
    memcpy(old_buckets, buckets, sizeof(buckets)); memcpy(&old_pool, &pool, sizeof(pool));
    CHECK(pending_transfer_init(&pool, buckets, 0, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(&pool, buckets, 9, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(&pool, buckets, SIZE_MAX, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(NULL, buckets, 8, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(&pool, NULL, 8, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(&pool, buckets, 8, NULL, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(pending_transfer_init(&pool, buckets, 8, &routing, NULL) == PENDING_TRANSFER_ERR_ARGUMENT);
    routing.shard_count = 0;
    CHECK(pending_transfer_init(&pool, buckets, 8, &routing, genesis) == PENDING_TRANSFER_ERR_ARGUMENT);
    CHECK(memcmp(old_buckets, buckets, sizeof(buckets)) == 0 && memcmp(&old_pool, &pool, sizeof(pool)) == 0);
}

int main(void) {
    test_owned_configuration_and_frames();
    test_authentication_before_state();
    test_conflicts_capacity_and_order();
    test_sparse_shards_and_invalid_arguments();
    puts("PASS: pending transfer authentication, ownership, atomic refusal and bounded shard queues");
    return 0;
}
