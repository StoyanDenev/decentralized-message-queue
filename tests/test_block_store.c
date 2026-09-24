/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Test Suite: C99 Bare-Metal Block & Manifest Storage Engine
 */

#include <determ/storage/block_store.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define TEST_PASS(name) printf("  [PASS] %s\n", name)

static void cleanup_dir(const char *dir) {
    char cmd[512];
    int n = snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (n > 0 && (size_t)n < sizeof(cmd) && system(cmd) != 0) {
        fprintf(stderr, "warning: cleanup of %s failed\n", dir);
    }
}

static void test_block_store_lifecycle(void) {
    char test_dir[] = "/tmp/determ_test_blocks_XXXXXX";
    char *d = mkdtemp(test_dir);
    TEST_ASSERT(d != NULL);

    block_store_t store;

    /* 1. Open brand new store */
    TEST_ASSERT(block_store_open(&store, test_dir) == BLOCK_STORE_OK);

    uint64_t height = 999;
    uint8_t head_hash[32];
    memset(head_hash, 0xFF, 32);
    TEST_ASSERT(block_store_get_head(&store, &height, head_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(height == 0);
    for (int i = 0; i < 32; i++) TEST_ASSERT(head_hash[i] == 0);

    /* 2. Append Genesis Block (height 0) */
    const uint8_t genesis_frame[] = "GENESIS_CANONICAL_BLOCK_FRAME_PAYLOAD";
    uint8_t genesis_hash[32];
    memset(genesis_hash, 0x11, 32);

    TEST_ASSERT(block_store_append_block(&store, 0, genesis_hash,
                                         genesis_frame, sizeof(genesis_frame)) == BLOCK_STORE_OK);

    TEST_ASSERT(block_store_get_head(&store, &height, head_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(height == 1);
    TEST_ASSERT(memcmp(head_hash, genesis_hash, 32) == 0);

    /* 3. Reject non-contiguous height append */
    uint8_t bad_hash[32];
    memset(bad_hash, 0x99, 32);
    TEST_ASSERT(block_store_append_block(&store, 5, bad_hash,
                                         genesis_frame, sizeof(genesis_frame)) == BLOCK_STORE_ERR_HEIGHT_MISMATCH);

    /* 4. Append Block 1 */
    const uint8_t block1_frame[] = "BLOCK_1_CANONICAL_TRANSACTIONS_AND_VDF_REVEAL";
    uint8_t block1_hash[32];
    memset(block1_hash, 0x22, 32);

    TEST_ASSERT(block_store_append_block(&store, 1, block1_hash,
                                         block1_frame, sizeof(block1_frame)) == BLOCK_STORE_OK);

    TEST_ASSERT(block_store_get_head(&store, &height, head_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(height == 2);
    TEST_ASSERT(memcmp(head_hash, block1_hash, 32) == 0);

    /* 5. Read back blocks */
    uint8_t read_buf[1024];
    size_t read_len = 0;

    /* Read block 0 */
    TEST_ASSERT(block_store_read_block(&store, 0, read_buf, sizeof(read_buf), &read_len) == BLOCK_STORE_OK);
    TEST_ASSERT(read_len == sizeof(genesis_frame));
    TEST_ASSERT(memcmp(read_buf, genesis_frame, sizeof(genesis_frame)) == 0);

    /* Read block 1 */
    TEST_ASSERT(block_store_read_block(&store, 1, read_buf, sizeof(read_buf), &read_len) == BLOCK_STORE_OK);
    TEST_ASSERT(read_len == sizeof(block1_frame));
    TEST_ASSERT(memcmp(read_buf, block1_frame, sizeof(block1_frame)) == 0);

    /* Non-existent block */
    TEST_ASSERT(block_store_read_block(&store, 2, read_buf, sizeof(read_buf), &read_len) == BLOCK_STORE_ERR_NOT_FOUND);

    /* Hashes of blocks appended in this session are indexed. */
    uint8_t got_hash[32];
    TEST_ASSERT(block_store_get_hash_by_height(&store, 0, got_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(memcmp(got_hash, genesis_hash, 32) == 0);
    TEST_ASSERT(block_store_get_hash_by_height(&store, 1, got_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(memcmp(got_hash, block1_hash, 32) == 0);
    TEST_ASSERT(block_store_get_hash_by_height(&store, 2, got_hash) == BLOCK_STORE_ERR_NOT_FOUND);

    /* 6. Close store and re-open to test crash-recovery & index reload */
    block_store_close(&store);

    block_store_t store2;
    TEST_ASSERT(block_store_open(&store2, test_dir) == BLOCK_STORE_OK);
    TEST_ASSERT(block_store_get_head(&store2, &height, head_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(height == 2);
    TEST_ASSERT(memcmp(head_hash, block1_hash, 32) == 0);

    /* Verify reloaded blocks */
    TEST_ASSERT(block_store_read_block(&store2, 0, read_buf, sizeof(read_buf), &read_len) == BLOCK_STORE_OK);
    TEST_ASSERT(read_len == sizeof(genesis_frame));
    TEST_ASSERT(memcmp(read_buf, genesis_frame, sizeof(genesis_frame)) == 0);

    /* Block files carry no hash: after reopening only the manifest head hash
     * is known, and no other height may report a hash. */
    memset(got_hash, 0xEE, sizeof(got_hash));
    TEST_ASSERT(block_store_get_hash_by_height(&store2, 1, got_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(memcmp(got_hash, block1_hash, 32) == 0);
    TEST_ASSERT(block_store_get_hash_by_height(&store2, 0, got_hash) == BLOCK_STORE_ERR_NOT_FOUND);

    /* A block appended after reopening is indexed with its hash. */
    const uint8_t block2_frame[] = "BLOCK_2_AFTER_REOPEN";
    uint8_t block2_hash[32];
    memset(block2_hash, 0x33, 32);
    TEST_ASSERT(block_store_append_block(&store2, 2, block2_hash,
                                         block2_frame, sizeof(block2_frame)) == BLOCK_STORE_OK);
    TEST_ASSERT(block_store_get_hash_by_height(&store2, 2, got_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(memcmp(got_hash, block2_hash, 32) == 0);
    TEST_ASSERT(block_store_get_hash_by_height(&store2, 1, got_hash) == BLOCK_STORE_OK);
    TEST_ASSERT(block_store_get_hash_by_height(&store2, 0, got_hash) == BLOCK_STORE_ERR_NOT_FOUND);

    block_store_close(&store2);

    /* 7. A block file below the manifest height without the DBK1 magic fails open */
    char bpath[512];
    snprintf(bpath, sizeof(bpath), "%s/0.blk", test_dir);
    int bfd = open(bpath, O_WRONLY);
    TEST_ASSERT(bfd >= 0);
    TEST_ASSERT(write(bfd, "X", 1) == 1);
    close(bfd);
    TEST_ASSERT(block_store_open(&store2, test_dir) == BLOCK_STORE_ERR_CORRUPT_BLOCK);
    bfd = open(bpath, O_WRONLY);
    TEST_ASSERT(bfd >= 0);
    TEST_ASSERT(write(bfd, "D", 1) == 1);
    close(bfd);
    TEST_ASSERT(block_store_open(&store2, test_dir) == BLOCK_STORE_OK);
    block_store_close(&store2);

    /* 8. Test corruption fail-closed: corrupt manifest to wrong size */
    char mpath[512];
    snprintf(mpath, sizeof(mpath), "%s/manifest.bin", test_dir);
    int mfd = open(mpath, O_WRONLY | O_TRUNC);
    TEST_ASSERT(mfd >= 0);
    TEST_ASSERT(write(mfd, "TRUNCATED", 9) == 9);
    close(mfd);

    block_store_t corrupt_store;
    TEST_ASSERT(block_store_open(&corrupt_store, test_dir) == BLOCK_STORE_ERR_CORRUPT_MANIFEST);

    cleanup_dir(test_dir);
    TEST_PASS("test_block_store_lifecycle");
}

int main(void) {
    printf("=== Starting C99 Block & Manifest Storage Test Suite ===\n");
    test_block_store_lifecycle();
    printf("=== All C99 Block Storage Tests Passed Successfully ===\n");
    return 0;
}
