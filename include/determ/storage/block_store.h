/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Canonical Block & Manifest Storage Engine.
 *
 * Guarantees:
 *   - Strictly zero dynamic memory allocation (no malloc/free).
 *   - Canonical 'DMF1' 44-byte manifest with atomic rename() + fsync() persistence.
 *   - Canonical 'DBK1' wrapped per-block file persistence (<height>.blk).
 *   - In-memory fast index table for O(1) height-to-hash lookups.
 *   - Fail-closed validation on startup: rejects hash chain breaks, index mismatches,
 *     truncated frames, and malformed container magic.
 */

#ifndef DETERMINISTIC_STORAGE_BLOCK_STORE_H
#define DETERMINISTIC_STORAGE_BLOCK_STORE_H

#include <determ/wire/binary_codec.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCK_STORE_MAX_INDEX       4096U
#define BLOCK_STORE_MAX_PATH        512U
#define BLOCK_STORE_MAX_FRAME_SIZE  (256U * 1024U) /* 256 KB max per block */

typedef enum {
    BLOCK_STORE_OK                  =  0,
    BLOCK_STORE_ERR_INVALID_ARG     = -1,
    BLOCK_STORE_ERR_IO              = -2,
    BLOCK_STORE_ERR_CORRUPT_MANIFEST= -3,
    BLOCK_STORE_ERR_CORRUPT_BLOCK   = -4,
    BLOCK_STORE_ERR_HEIGHT_MISMATCH = -5,
    BLOCK_STORE_ERR_BUFFER_TOO_SMALL= -6,
    BLOCK_STORE_ERR_INDEX_FULL      = -7,
    BLOCK_STORE_ERR_NOT_FOUND       = -8
} block_store_status_t;

typedef struct {
    uint64_t height;
    uint8_t  hash[32];
    uint32_t frame_len;
} block_index_entry_t;

typedef struct {
    char                base_dir[BLOCK_STORE_MAX_PATH];
    char                manifest_path[BLOCK_STORE_MAX_PATH];
    uint64_t            current_height;
    uint8_t             head_hash[32];
    block_index_entry_t index[BLOCK_STORE_MAX_INDEX];
    size_t              indexed_count;
    bool                open;
} block_store_t;

/*
 * Open or initialize a block store at base_dir.
 * If manifest exists, loads and validates all blocks up to current_height.
 * If not exists, creates directory and writes initial DMF1 (height 0, zero head).
 */
block_store_status_t block_store_open(block_store_t *store, const char *base_dir);

/*
 * Atomically append a new block to the store:
 * 1. Writes <base_dir>/<height>.blk with 'DBK1' header.
 * 2. fsyncs block file.
 * 3. Atomically replaces <manifest_path> with updated height and head_hash.
 * 4. Updates in-memory index.
 */
block_store_status_t block_store_append_block(block_store_t *store,
                                              uint64_t height,
                                              const uint8_t hash[32],
                                              const uint8_t *block_frame,
                                              size_t frame_len);

/*
 * Read block frame at given height into out_frame_buf.
 * Unwraps DBK1 container and returns exact raw frame.
 */
block_store_status_t block_store_read_block(const block_store_t *store,
                                            uint64_t height,
                                            uint8_t *out_frame_buf,
                                            size_t buf_cap,
                                            size_t *out_frame_len);

/*
 * Get current store height and head block hash.
 */
block_store_status_t block_store_get_head(const block_store_t *store,
                                          uint64_t *out_height,
                                          uint8_t out_head_hash[32]);

/*
 * Look up indexed block hash by height.
 */
block_store_status_t block_store_get_hash_by_height(const block_store_t *store,
                                                    uint64_t height,
                                                    uint8_t out_hash[32]);

/*
 * Close the store and clear in-memory state.
 */
void block_store_close(block_store_t *store);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_STORAGE_BLOCK_STORE_H */
