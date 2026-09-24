/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 Block & Manifest Storage for the C99 prototype.
 *
 * Layout: <base_dir>/manifest.bin (44-byte DMF1 record: height, head hash) and
 * one <base_dir>/<height>.blk per block ('DBK1' followed by the caller's frame
 * bytes). The records use the DMF1/DBK1 encodings, but this directory layout
 * is not the C++ node's <path>.blocks/ + <path>.manifest.bin store.
 *
 *   - Strictly zero dynamic memory allocation (no malloc/free).
 *   - The manifest is written to a temporary file, fsync()ed, rename()d over
 *     manifest.bin, and the directory is fsync()ed.
 *   - Block hashes are supplied by the caller and are not stored in block
 *     files. The in-memory index knows the hash of each block appended in this
 *     session (heights below BLOCK_STORE_MAX_INDEX) and, after open, only the
 *     manifest's head hash; other heights report BLOCK_STORE_ERR_NOT_FOUND.
 *   - open checks the manifest (exactly 44 bytes, DMF1 magic, zero head hash
 *     iff height 0) and that every block file below the manifest height exists
 *     with at least 4 bytes and the DBK1 magic. It does not decode frames,
 *     check hashes or chain linkage, or detect a truncated frame.
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
    bool     hash_known; /* hash is the appended or manifest head hash */
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
 * If the manifest exists, checks it and the block files below its height as
 * described above. Otherwise creates the directory if needed and writes an
 * initial DMF1 (height 0, zero head).
 */
block_store_status_t block_store_open(block_store_t *store, const char *base_dir);

/*
 * Append the block at height == current height:
 * 1. Writes <base_dir>/<height>.blk with 'DBK1' header and fsyncs it.
 * 2. Replaces the manifest with height + 1 and hash (see above).
 * 3. Updates the in-memory head and index.
 * On an error the in-memory state is unchanged. When the error is the final
 * directory fsync, the renamed manifest and its block file are already
 * visible; after an earlier manifest error the block file stays above the
 * manifest height, where open ignores it and the next append at that height
 * truncates it.
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
 * Look up a block hash by height: BLOCK_STORE_OK only for the heights whose
 * hash this store knows (see above); BLOCK_STORE_ERR_NOT_FOUND otherwise.
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
