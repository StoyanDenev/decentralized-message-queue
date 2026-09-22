/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/ledger/pending_transfer.h>
#include <determ/wire/binary_codec.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/ed25519/ed25519_group.h>
#include <string.h>

static int valid_pool(const pending_transfer_pool_t *pool) {
    return pool && pool->buckets && pool->bucket_capacity > 0 &&
           pool->bucket_capacity <= PENDING_TRANSFER_MAX_SHARDS && pool->routing.shard_count > 0;
}

int pending_transfer_init(pending_transfer_pool_t *pool,
                          pending_shard_t *buckets, size_t bucket_capacity,
                          const shard_routing_config_t *routing,
                          const uint8_t genesis_hash[32]) {
    pending_transfer_pool_t value;
    if (!pool || !buckets || !routing || !genesis_hash || routing->shard_count == 0 ||
        bucket_capacity == 0 || bucket_capacity > PENDING_TRANSFER_MAX_SHARDS)
        return PENDING_TRANSFER_ERR_ARGUMENT;
    memset(&value, 0, sizeof(value));
    memcpy(&value.routing, routing, sizeof(value.routing));
    memcpy(value.genesis_hash, genesis_hash, sizeof(value.genesis_hash));
    value.buckets = buckets;
    value.bucket_capacity = bucket_capacity;
    memset(buckets, 0, bucket_capacity * sizeof(*buckets));
    memcpy(pool, &value, sizeof(value));
    return 0;
}

static int lower_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int address_key(const char *address, uint8_t key[32]) {
    if (address[0] != '0' || address[1] != 'x') return -1;
    for (size_t i = 0; i < 32; ++i) {
        int hi = lower_hex(address[2 + 2 * i]), lo = lower_hex(address[3 + 2 * i]);
        if (hi < 0 || lo < 0) return -1;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void put_be64(uint8_t *out, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static pending_transfer_status_t authenticate(const pending_transfer_pool_t *pool,
                                               const uint8_t *frame, size_t len,
                                               pending_transfer_entry_t *entry,
                                               uint32_t *shard_id) {
    wire_transaction_t tx;
    uint8_t canonical[PENDING_TRANSFER_FRAME_SIZE], sender[32], recipient[32];
    uint8_t signing[PENDING_TRANSFER_SIGNING_SIZE], hash[32];
    uint32_t source_shard, destination_shard;
    size_t written = 0;
    memset(&tx, 0, sizeof(tx));
    if (len != PENDING_TRANSFER_FRAME_SIZE || wire_tx_decode(frame, len, &tx) != WIRE_CODEC_OK ||
        tx.type != 0 || tx.payload_len != 0 || tx.pq_auth_len != 0 || tx.from_len != 66 || tx.to_len != 66)
        return PENDING_TRANSFER_ERR_FRAME;
    if (address_key(tx.from, sender) != 0 || address_key(tx.to, recipient) != 0)
        return PENDING_TRANSFER_ERR_FRAME;
    /* Despite the C99 field names, the shipped C++ frame stores the first 32
     * ASCII address bytes in these duplicate slots, not raw Ed25519 keys. */
    if (memcmp(tx.sender_pubkey, tx.from, 32) != 0 || memcmp(tx.recipient_pubkey, tx.to, 32) != 0)
        return PENDING_TRANSFER_ERR_FRAME;
    if (wire_tx_encode(canonical, sizeof(canonical), &tx, &written) != WIRE_CODEC_OK ||
        written != len || memcmp(canonical, frame, len) != 0)
        return PENDING_TRANSFER_ERR_FRAME;
    if (memcmp(tx.genesis_hash, pool->genesis_hash, 32) != 0)
        return PENDING_TRANSFER_ERR_GENESIS;
    if (shard_routing_for_pubkey(&pool->routing, sender, sizeof(sender), &source_shard) != 0 ||
        tx.shard_id >= pool->routing.shard_count || tx.shard_id != source_shard)
        return PENDING_TRANSFER_ERR_SOURCE_SHARD;
    if (shard_routing_for_pubkey(&pool->routing, recipient, sizeof(recipient), &destination_shard) != 0 ||
        destination_shard != source_shard)
        return PENDING_TRANSFER_ERR_CROSS_SHARD;

    /* Exactly Transaction::signing_bytes for this fixed subset. The wire's
     * numeric fields are little endian; its signing preimage is big endian. */
    signing[0] = tx.type;
    memcpy(signing + 1, tx.genesis_hash, 32);
    for (size_t i = 0; i < 4; ++i) signing[33 + i] = (uint8_t)(tx.shard_id >> (24 - 8 * i));
    memcpy(signing + 37, tx.from, 66);
    signing[103] = 0;
    memcpy(signing + 104, tx.to, 66);
    signing[170] = 0;
    put_be64(signing + 171, tx.amount);
    put_be64(signing + 179, tx.fee);
    put_be64(signing + 187, tx.nonce);
    determ_sha256(signing, sizeof(signing), hash);
    if (memcmp(hash, tx.hash, sizeof(hash)) != 0) return PENDING_TRANSFER_ERR_HASH;
    if (determ_ed25519_verify(sender, signing, sizeof(signing), tx.sig) != 0)
        return PENDING_TRANSFER_ERR_SIGNATURE;
    if (determ_ed25519_point_has_small_order(sender) != 0)
        return PENDING_TRANSFER_ERR_SENDER_KEY;

    memset(entry, 0, sizeof(*entry));
    memcpy(entry->frame, frame, len);
    memcpy(entry->sender, sender, sizeof(sender));
    memcpy(entry->hash, hash, sizeof(hash));
    entry->nonce = tx.nonce;
    *shard_id = source_shard;
    return PENDING_TRANSFER_INSERTED;
}

static int entry_before(const pending_transfer_entry_t *left, const pending_transfer_entry_t *right) {
    int sender_order = memcmp(left->sender, right->sender, sizeof(left->sender));
    return sender_order < 0 || (sender_order == 0 && left->nonce < right->nonce);
}

static void set_result(pending_transfer_result_t *result, const pending_transfer_entry_t *entry,
                       uint32_t shard_id, uint32_t count) {
    pending_transfer_result_t value;
    memset(&value, 0, sizeof(value));
    memcpy(value.hash, entry->hash, sizeof(value.hash));
    value.shard_id = shard_id;
    value.pending_count = count;
    memcpy(result, &value, sizeof(value));
}

pending_transfer_status_t pending_transfer_submit(pending_transfer_pool_t *pool,
                                                  const uint8_t *frame, size_t len,
                                                  pending_transfer_result_t *result) {
    pending_transfer_entry_t candidate;
    uint32_t shard_id = 0;
    pending_shard_t *bucket = NULL, *empty = NULL;
    if (!valid_pool(pool) || !frame || !result) return PENDING_TRANSFER_ERR_ARGUMENT;
    pending_transfer_status_t status = authenticate(pool, frame, len, &candidate, &shard_id);
    if (status < 0) return status;

    /* Do not even consult duplicate/conflict/capacity state before complete
     * authentication. A forged known hash cannot displace or acknowledge data. */
    for (size_t i = 0; i < pool->bucket_capacity; ++i) {
        pending_shard_t *at = &pool->buckets[i];
        if (at->count == 0) { if (!empty) empty = at; }
        else if (at->shard_id == shard_id) { bucket = at; break; }
    }
    if (bucket) {
        for (size_t i = 0; i < bucket->count; ++i) {
            pending_transfer_entry_t *incumbent = &bucket->entries[i];
            if (incumbent->nonce != candidate.nonce || memcmp(incumbent->sender, candidate.sender, 32) != 0)
                continue;
            int order = memcmp(candidate.hash, incumbent->hash, sizeof(candidate.hash));
            if (order > 0) return PENDING_TRANSFER_ERR_NOT_PREFERRED;
            if (order < 0) memcpy(incumbent, &candidate, sizeof(candidate));
            set_result(result, &candidate, shard_id, bucket->count);
            return order < 0 ? PENDING_TRANSFER_REPLACED : PENDING_TRANSFER_DUPLICATE;
        }
        if (bucket->count == PENDING_TRANSFER_PER_SHARD) return PENDING_TRANSFER_ERR_CAPACITY;
    } else {
        if (!empty) return PENDING_TRANSFER_ERR_CAPACITY;
        bucket = empty;
        bucket->shard_id = shard_id;
    }
    size_t at = bucket->count;
    while (at > 0 && entry_before(&candidate, &bucket->entries[at - 1])) {
        memcpy(&bucket->entries[at], &bucket->entries[at - 1], sizeof(candidate));
        --at;
    }
    memcpy(&bucket->entries[at], &candidate, sizeof(candidate));
    ++bucket->count;
    set_result(result, &candidate, shard_id, bucket->count);
    return PENDING_TRANSFER_INSERTED;
}

int pending_transfer_list(const pending_transfer_pool_t *pool, uint32_t shard_id,
                          pending_transfer_snapshot_t *snapshot) {
    pending_transfer_snapshot_t value;
    if (!valid_pool(pool) || !snapshot) return PENDING_TRANSFER_ERR_ARGUMENT;
    if (shard_id >= pool->routing.shard_count) return PENDING_TRANSFER_ERR_SOURCE_SHARD;
    memset(&value, 0, sizeof(value));
    for (size_t i = 0; i < pool->bucket_capacity; ++i) {
        const pending_shard_t *bucket = &pool->buckets[i];
        if (bucket->count == 0 || bucket->shard_id != shard_id) continue;
        value.count = bucket->count;
        for (size_t j = 0; j < bucket->count; ++j)
            memcpy(value.frames[j], bucket->entries[j].frame, PENDING_TRANSFER_FRAME_SIZE);
        break;
    }
    memcpy(snapshot, &value, sizeof(value));
    return 0;
}
