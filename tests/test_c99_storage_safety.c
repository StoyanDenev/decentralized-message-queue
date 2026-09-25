/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Storage gate for ADR-006 review findings R1-01 and R1-02. It compiles the
 * real src/storage/block_store.c into this file with a stat() interceptor, so
 * a manifest stat() failure other than ENOENT can be injected on demand:
 *   R1-01: open must return BLOCK_STORE_ERR_IO and leave the manifest bytes
 *          unchanged (it used to publish a height-0 manifest over them);
 *   R1-02: append must refuse an all-zero hash before writing any file, at
 *          every height (open would then refuse the manifest it produced),
 *          and must still accept hashes that are only nearly zero.
 * Hosted POSIX evidence only; the target storage contract is separate.
 */
#include <determ/storage/block_store.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "C99-STORAGE-SAFETY ASSERTION FAILED at %s:%d: %s\n", \
            __FILE__, __LINE__, #c); exit(1); } } while (0)

static unsigned long checks;
static int fail_manifest_stat;    /* errno to inject on manifest stat() calls */
static unsigned manifest_stats;   /* manifest stat() calls seen */

/* Defined before the macro below, so this stat() is the real one. */
static int storage_test_stat(const char *path, struct stat *st) {
    static const char suffix[] = "/manifest.bin";
    size_t n = strlen(path), k = sizeof suffix - 1u;
    if (n >= k && strcmp(path + n - k, suffix) == 0) {
        ++manifest_stats;
        if (fail_manifest_stat) {
            errno = fail_manifest_stat;
            return -1;
        }
    }
    return stat(path, st);
}

/* A function-like macro: `struct stat` is untouched, calls are redirected. */
#define stat(path, buf) storage_test_stat(path, buf)
#include "../src/storage/block_store.c"
#undef stat

/* Temporary stores, removed at exit even when an assertion fails. */
static char dirs[2][BLOCK_STORE_MAX_PATH];

static void remove_stores(void) {
    char path[BLOCK_STORE_MAX_PATH];
    uint64_t h;
    size_t d;
    for (d = 0; d < 2u; ++d) {
        if (!dirs[d][0]) continue;
        for (h = 0; h < 4u; ++h)
            if (get_block_path(dirs[d], h, path, sizeof path) == 0) (void)unlink(path);
        if (snprintf(path, sizeof path, "%s/manifest.bin", dirs[d]) > 0) (void)unlink(path);
        (void)rmdir(dirs[d]);
    }
}

static const char *make_store_dir(size_t d) {
    const char *tmp = getenv("TMPDIR");
    int n = snprintf(dirs[d], sizeof dirs[d], "%s/determ_storage_safety_XXXXXX",
                     (tmp && *tmp) ? tmp : "/tmp");
    CHECK(n > 0 && (size_t)n < sizeof dirs[d] - 32u);
    CHECK(mkdtemp(dirs[d]) != NULL);
    return dirs[d];
}

static size_t read_file(const char *path, uint8_t *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    ssize_t n;
    CHECK(fd >= 0);
    n = read(fd, buf, cap);
    close(fd);
    CHECK(n >= 0);
    return (size_t)n;
}

static void manifest_of(const char *dir, uint8_t *buf, size_t *len) {
    char path[BLOCK_STORE_MAX_PATH];
    CHECK(snprintf(path, sizeof path, "%s/manifest.bin", dir) > 0);
    *len = read_file(path, buf, 64u);
    CHECK(*len == WIRE_MANIFEST_BYTES);
}

static void no_block_file(const char *dir, uint64_t height) {
    char path[BLOCK_STORE_MAX_PATH];
    struct stat st;
    CHECK(get_block_path(dir, height, path, sizeof path) == 0);
    errno = 0;
    CHECK(stat(path, &st) != 0 && errno == ENOENT);
}

static void check_head(const char *dir, uint64_t want_height, const uint8_t want[32]) {
    block_store_t store;
    uint64_t height = 0;
    uint8_t head[32];
    CHECK(block_store_open(&store, dir) == BLOCK_STORE_OK);
    CHECK(block_store_get_head(&store, &height, head) == BLOCK_STORE_OK);
    CHECK(height == want_height && memcmp(head, want, 32u) == 0);
}

/* R1-01: every stat() failure other than ENOENT is an I/O error, and the
 * durable manifest is left exactly as it was. */
static void stat_failure_tests(void) {
    const char *dir = make_store_dir(0);
    const uint8_t frame[3] = { 1, 2, 3 };
    uint8_t before[64], after[64], hash[32];
    size_t blen, alen, i;
    unsigned seen;
    int e;
    block_store_t store;

    /* A two-block store; ENOENT (the manifest really is absent) initializes. */
    CHECK(block_store_open(&store, dir) == BLOCK_STORE_OK);
    CHECK(manifest_stats == 1u);
    for (i = 0; i < 2u; ++i) {
        memset(hash, (int)(0x41u + i), sizeof hash);
        CHECK(block_store_append_block(&store, i, hash, frame, sizeof frame) == BLOCK_STORE_OK);
    }
    manifest_of(dir, before, &blen);
    for (e = 1; e < 256; ++e) {
        if (e == ENOENT) continue;
        seen = manifest_stats;
        fail_manifest_stat = e;
        CHECK(block_store_open(&store, dir) == BLOCK_STORE_ERR_IO);
        CHECK(!store.open);
        fail_manifest_stat = 0;
        CHECK(manifest_stats == seen + 1u);       /* the interceptor fired */
        manifest_of(dir, after, &alen);
        CHECK(alen == blen && memcmp(before, after, blen) == 0);
    }
    /* The untouched store still reopens at its height and head. */
    check_head(dir, 2u, hash);
}

/* R1-02: an all-zero hash is refused before the block file or the manifest
 * is written, at height 0 and above; nearly-zero hashes are ordinary. */
static void zero_hash_tests(void) {
    const char *dir = make_store_dir(1);
    const uint8_t frame[3] = { 4, 5, 6 };
    uint8_t before[64], after[64], zero[32], low[32], high[32];
    size_t blen, alen;
    block_store_t store;

    memset(zero, 0, sizeof zero);
    memset(low, 0, sizeof low);
    low[31] = 1u;                                 /* 00..01 */
    memset(high, 0, sizeof high);
    high[0] = 1u;                                 /* 01 00..00 */
    CHECK(block_store_open(&store, dir) == BLOCK_STORE_OK);
    manifest_of(dir, before, &blen);
    CHECK(block_store_append_block(&store, 0u, zero, frame, sizeof frame) == BLOCK_STORE_ERR_INVALID_ARG);
    no_block_file(dir, 0u);
    manifest_of(dir, after, &alen);
    CHECK(alen == blen && memcmp(before, after, blen) == 0);

    CHECK(block_store_append_block(&store, 0u, low, frame, sizeof frame) == BLOCK_STORE_OK);
    CHECK(block_store_append_block(&store, 1u, high, frame, sizeof frame) == BLOCK_STORE_OK);
    manifest_of(dir, before, &blen);
    CHECK(block_store_append_block(&store, 2u, zero, frame, sizeof frame) == BLOCK_STORE_ERR_INVALID_ARG);
    no_block_file(dir, 2u);
    manifest_of(dir, after, &alen);
    CHECK(alen == blen && memcmp(before, after, blen) == 0);
    check_head(dir, 2u, high);
}

int main(void) {
    CHECK(atexit(remove_stores) == 0);
    stat_failure_tests();
    zero_hash_tests();
    printf("PASS: C99 storage safety (%lu assertions)\n", checks);
    return 0;
}
