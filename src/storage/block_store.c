/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Canonical Block & Manifest Storage Engine.
 */

#include <determ/storage/block_store.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static bool is_all_zero(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) return false;
    }
    return true;
}

static int make_directory(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    return mkdir(dir, 0755);
}

/* Returns 0 on success, -1 if the path does not fit (never a truncated path). */
static int get_block_path(const char *base_dir, uint64_t height, char *out_path, size_t max_len) {
    int n = snprintf(out_path, max_len, "%s/%llu.blk", base_dir, (unsigned long long)height);
    return (n < 0 || (size_t)n >= max_len) ? -1 : 0;
}

/* Make a completed rename in dir durable. */
static int sync_directory(const char *dir) {
    int dfd = open(dir, O_RDONLY);
    if (dfd < 0) return -1;
    int rc = fsync(dfd);
    close(dfd);
    return rc;
}

static block_store_status_t write_manifest_atomic(const block_store_t *store, uint64_t height, const uint8_t head_hash[32]) {
    char tmp_path[BLOCK_STORE_MAX_PATH + 32];
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", store->manifest_path, (int)getpid());
    if (tn < 0 || (size_t)tn >= sizeof(tmp_path)) return BLOCK_STORE_ERR_INVALID_ARG;

    uint8_t mbuf[WIRE_MANIFEST_BYTES];
    size_t mlen = 0;
    wire_manifest_t m = { .height = height };
    memcpy(m.head_hash, head_hash, 32);

    if (wire_manifest_encode(mbuf, sizeof(mbuf), &m, &mlen) != WIRE_CODEC_OK || mlen != WIRE_MANIFEST_BYTES) {
        return BLOCK_STORE_ERR_CORRUPT_MANIFEST;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return BLOCK_STORE_ERR_IO;

    ssize_t n = write(fd, mbuf, mlen);
    if (n != (ssize_t)mlen) {
        close(fd);
        unlink(tmp_path);
        return BLOCK_STORE_ERR_IO;
    }

    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        return BLOCK_STORE_ERR_IO;
    }
    close(fd);

    if (rename(tmp_path, store->manifest_path) != 0) {
        unlink(tmp_path);
        return BLOCK_STORE_ERR_IO;
    }
    /* The rename is visible now; fsync the directory so it survives a crash
     * (this also persists a new block file's directory entry). */
    if (sync_directory(store->base_dir) != 0) {
        return BLOCK_STORE_ERR_IO;
    }
    return BLOCK_STORE_OK;
}

block_store_status_t block_store_open(block_store_t *store, const char *base_dir) {
    if (!store || !base_dir) return BLOCK_STORE_ERR_INVALID_ARG;
    memset(store, 0, sizeof(*store));

    size_t dlen = strlen(base_dir);
    if (dlen >= BLOCK_STORE_MAX_PATH - 32) return BLOCK_STORE_ERR_INVALID_ARG;
    memcpy(store->base_dir, base_dir, dlen + 1);

    if (make_directory(base_dir) != 0 && errno != EEXIST) {
        return BLOCK_STORE_ERR_IO;
    }

    {
        int mn = snprintf(store->manifest_path, sizeof(store->manifest_path), "%s/manifest.bin", base_dir);
        if (mn < 0 || (size_t)mn >= sizeof(store->manifest_path)) return BLOCK_STORE_ERR_INVALID_ARG;
    }

    struct stat st;
    if (stat(store->manifest_path, &st) != 0) {
        /* Manifest doesn't exist: initialize brand new store */
        uint8_t zero_hash[32] = {0};
        block_store_status_t rc = write_manifest_atomic(store, 0, zero_hash);
        if (rc != BLOCK_STORE_OK) return rc;
        store->current_height = 0;
        memset(store->head_hash, 0, 32);
        store->indexed_count = 0;
        store->open = true;
        return BLOCK_STORE_OK;
    }

    /* Existing manifest: read and validate */
    if (st.st_size != (off_t)WIRE_MANIFEST_BYTES) {
        return BLOCK_STORE_ERR_CORRUPT_MANIFEST;
    }

    int mfd = open(store->manifest_path, O_RDONLY);
    if (mfd < 0) return BLOCK_STORE_ERR_IO;

    uint8_t mbuf[WIRE_MANIFEST_BYTES];
    ssize_t n = read(mfd, mbuf, WIRE_MANIFEST_BYTES);
    close(mfd);
    if (n != (ssize_t)WIRE_MANIFEST_BYTES) return BLOCK_STORE_ERR_IO;

    wire_manifest_t m;
    if (wire_manifest_decode(mbuf, WIRE_MANIFEST_BYTES, &m) != WIRE_CODEC_OK) {
        return BLOCK_STORE_ERR_CORRUPT_MANIFEST;
    }

    bool zero_head = is_all_zero(m.head_hash, 32);
    if (m.height == 0 && !zero_head) return BLOCK_STORE_ERR_CORRUPT_MANIFEST;
    if (m.height > 0 && zero_head) return BLOCK_STORE_ERR_CORRUPT_MANIFEST;

    store->current_height = m.height;
    memcpy(store->head_hash, m.head_hash, 32);

    /* Index and validate each block file from 0 to current_height - 1 */
    char bpath[BLOCK_STORE_MAX_PATH];
    for (uint64_t h = 0; h < m.height; h++) {
        if (get_block_path(store->base_dir, h, bpath, sizeof(bpath)) != 0)
            return BLOCK_STORE_ERR_INVALID_ARG;
        struct stat bst;
        if (stat(bpath, &bst) != 0 || bst.st_size < 4) {
            return BLOCK_STORE_ERR_CORRUPT_BLOCK;
        }

        int bfd = open(bpath, O_RDONLY);
        if (bfd < 0) return BLOCK_STORE_ERR_IO;
        char magic[4];
        ssize_t mn = read(bfd, magic, 4);
        close(bfd);
        if (mn != 4 || memcmp(magic, "DBK1", 4) != 0) {
            return BLOCK_STORE_ERR_CORRUPT_BLOCK;
        }

        if (h < BLOCK_STORE_MAX_INDEX) {
            store->index[h].height = h;
            store->index[h].frame_len = (uint32_t)(bst.st_size - 4);
            /* Block files carry no hash; the manifest vouches for the head only. */
            if (h == m.height - 1) {
                memcpy(store->index[h].hash, m.head_hash, 32);
                store->index[h].hash_known = true;
            }
            store->indexed_count = h + 1;
        }
    }

    store->open = true;
    return BLOCK_STORE_OK;
}

block_store_status_t block_store_append_block(block_store_t *store,
                                              uint64_t height,
                                              const uint8_t hash[32],
                                              const uint8_t *block_frame,
                                              size_t frame_len) {
    if (!store || !store->open || !hash || !block_frame || frame_len == 0) {
        return BLOCK_STORE_ERR_INVALID_ARG;
    }
    if (height != store->current_height) {
        return BLOCK_STORE_ERR_HEIGHT_MISMATCH;
    }
    if (frame_len > BLOCK_STORE_MAX_FRAME_SIZE) {
        return BLOCK_STORE_ERR_INVALID_ARG;
    }

    char bpath[BLOCK_STORE_MAX_PATH];
    if (get_block_path(store->base_dir, height, bpath, sizeof(bpath)) != 0)
        return BLOCK_STORE_ERR_INVALID_ARG;

    int bfd = open(bpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (bfd < 0) return BLOCK_STORE_ERR_IO;

    /* Write DBK1 header */
    if (write(bfd, "DBK1", 4) != 4) {
        close(bfd);
        unlink(bpath);
        return BLOCK_STORE_ERR_IO;
    }

    if (write(bfd, block_frame, frame_len) != (ssize_t)frame_len) {
        close(bfd);
        unlink(bpath);
        return BLOCK_STORE_ERR_IO;
    }

    if (fsync(bfd) != 0) {
        close(bfd);
        unlink(bpath);
        return BLOCK_STORE_ERR_IO;
    }
    close(bfd);

    /* Atomically commit manifest. On failure the block file stays: if the
     * rename happened the manifest references it; otherwise it lies above the
     * manifest height, where open ignores it and the next append at this
     * height truncates it. */
    block_store_status_t mrc = write_manifest_atomic(store, height + 1, hash);
    if (mrc != BLOCK_STORE_OK) {
        return mrc;
    }

    /* Update in-memory state */
    if (height < BLOCK_STORE_MAX_INDEX) {
        store->index[height].height = height;
        memcpy(store->index[height].hash, hash, 32);
        store->index[height].hash_known = true;
        store->index[height].frame_len = (uint32_t)frame_len;
        if (height + 1 > store->indexed_count) {
            store->indexed_count = height + 1;
        }
    }
    store->current_height = height + 1;
    memcpy(store->head_hash, hash, 32);

    return BLOCK_STORE_OK;
}

block_store_status_t block_store_read_block(const block_store_t *store,
                                            uint64_t height,
                                            uint8_t *out_frame_buf,
                                            size_t buf_cap,
                                            size_t *out_frame_len) {
    if (!store || !store->open || !out_frame_buf || !out_frame_len) {
        return BLOCK_STORE_ERR_INVALID_ARG;
    }
    if (height >= store->current_height) {
        return BLOCK_STORE_ERR_NOT_FOUND;
    }

    char bpath[BLOCK_STORE_MAX_PATH];
    if (get_block_path(store->base_dir, height, bpath, sizeof(bpath)) != 0)
        return BLOCK_STORE_ERR_INVALID_ARG;

    struct stat st;
    if (stat(bpath, &st) != 0 || st.st_size < 4) {
        return BLOCK_STORE_ERR_CORRUPT_BLOCK;
    }

    size_t expected_frame_len = (size_t)(st.st_size - 4);
    if (buf_cap < expected_frame_len) {
        return BLOCK_STORE_ERR_BUFFER_TOO_SMALL;
    }

    int bfd = open(bpath, O_RDONLY);
    if (bfd < 0) return BLOCK_STORE_ERR_IO;

    char magic[4];
    if (read(bfd, magic, 4) != 4 || memcmp(magic, "DBK1", 4) != 0) {
        close(bfd);
        return BLOCK_STORE_ERR_CORRUPT_BLOCK;
    }

    ssize_t n = read(bfd, out_frame_buf, expected_frame_len);
    close(bfd);
    if (n != (ssize_t)expected_frame_len) {
        return BLOCK_STORE_ERR_IO;
    }

    *out_frame_len = expected_frame_len;
    return BLOCK_STORE_OK;
}

block_store_status_t block_store_get_head(const block_store_t *store,
                                          uint64_t *out_height,
                                          uint8_t out_head_hash[32]) {
    if (!store || !store->open || !out_height || !out_head_hash) {
        return BLOCK_STORE_ERR_INVALID_ARG;
    }
    *out_height = store->current_height;
    memcpy(out_head_hash, store->head_hash, 32);
    return BLOCK_STORE_OK;
}

block_store_status_t block_store_get_hash_by_height(const block_store_t *store,
                                                    uint64_t height,
                                                    uint8_t out_hash[32]) {
    if (!store || !store->open || !out_hash) return BLOCK_STORE_ERR_INVALID_ARG;
    if (height >= store->current_height || height >= store->indexed_count ||
        !store->index[height].hash_known) {
        return BLOCK_STORE_ERR_NOT_FOUND;
    }
    memcpy(out_hash, store->index[height].hash, 32);
    return BLOCK_STORE_OK;
}

void block_store_close(block_store_t *store) {
    if (!store) return;
    store->open = false;
    store->current_height = 0;
    store->indexed_count = 0;
    memset(store->head_hash, 0, sizeof(store->head_hash));
}
