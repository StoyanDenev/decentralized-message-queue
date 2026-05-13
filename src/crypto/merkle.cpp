// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/merkle.hpp>
#include <determ/crypto/sha256.hpp>
#include <algorithm>
#include <cstring>

namespace determ::crypto {

namespace {

// Big-endian u32 helper for length-prefix encoding.
void append_be_u32(SHA256Builder& b, uint32_t v) {
    uint8_t bytes[4] = {
        static_cast<uint8_t>((v >> 24) & 0xff),
        static_cast<uint8_t>((v >> 16) & 0xff),
        static_cast<uint8_t>((v >> 8)  & 0xff),
        static_cast<uint8_t>( v        & 0xff),
    };
    b.append(bytes, 4);
}

} // namespace

Hash merkle_leaf_hash(const std::vector<uint8_t>& key,
                       const Hash& value_hash) {
    SHA256Builder b;
    uint8_t prefix = 0x00;
    b.append(&prefix, 1);
    append_be_u32(b, static_cast<uint32_t>(key.size()));
    if (!key.empty()) b.append(key.data(), key.size());
    b.append(value_hash);
    return b.finalize();
}

Hash merkle_inner_hash(const Hash& left, const Hash& right) {
    SHA256Builder b;
    uint8_t prefix = 0x01;
    b.append(&prefix, 1);
    b.append(left);
    b.append(right);
    return b.finalize();
}

Hash merkle_root(const std::vector<MerkleLeaf>& leaves) {
    if (leaves.empty()) return Hash{};

    // Sort by key (lexicographic). Stable not required — keys are
    // assumed unique by caller; we don't enforce here.
    std::vector<MerkleLeaf> sorted = leaves;
    std::sort(sorted.begin(), sorted.end(),
        [](const MerkleLeaf& a, const MerkleLeaf& b) { return a.key < b.key; });

    // Hash each leaf into a row.
    std::vector<Hash> row;
    row.reserve(sorted.size());
    for (auto& l : sorted) {
        row.push_back(merkle_leaf_hash(l.key, l.value_hash));
    }

    // Walk levels until single root. At each level, duplicate the last
    // leaf to fill an odd count (standard tx-Merkle convention).
    while (row.size() > 1) {
        if (row.size() % 2 == 1) row.push_back(row.back());
        std::vector<Hash> next;
        next.reserve(row.size() / 2);
        for (size_t i = 0; i + 1 < row.size(); i += 2) {
            next.push_back(merkle_inner_hash(row[i], row[i + 1]));
        }
        row = std::move(next);
    }
    return row[0];
}

std::vector<Hash> merkle_proof(const std::vector<MerkleLeaf>& leaves,
                                  size_t target_index) {
    if (leaves.empty() || target_index >= leaves.size()) return {};

    std::vector<MerkleLeaf> sorted = leaves;
    std::sort(sorted.begin(), sorted.end(),
        [](const MerkleLeaf& a, const MerkleLeaf& b) { return a.key < b.key; });

    // Map original target_index (in the input ordering) to the sorted
    // position. The caller is responsible for knowing which sorted
    // position they want; for our typical use (querying by key), the
    // caller would call merkle_proof after binary-searching the sorted
    // leaves. Here we assume target_index is in the *sorted* ordering.
    //
    // Note: this signature differs from how some Merkle libraries
    // expose proofs. The caller passes the sorted-leaf index.

    std::vector<Hash> row;
    row.reserve(sorted.size());
    for (auto& l : sorted) row.push_back(merkle_leaf_hash(l.key, l.value_hash));

    std::vector<Hash> proof;
    size_t idx = target_index;
    while (row.size() > 1) {
        if (row.size() % 2 == 1) row.push_back(row.back());
        size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        proof.push_back(row[sibling]);
        std::vector<Hash> next;
        next.reserve(row.size() / 2);
        for (size_t i = 0; i + 1 < row.size(); i += 2) {
            next.push_back(merkle_inner_hash(row[i], row[i + 1]));
        }
        row = std::move(next);
        idx /= 2;
    }
    return proof;
}

bool merkle_verify(const Hash& root,
                     const std::vector<uint8_t>& key,
                     const Hash& value_hash,
                     size_t target_index,
                     size_t leaf_count,
                     const std::vector<Hash>& proof) {
    if (leaf_count == 0) return false;
    if (target_index >= leaf_count) return false;

    Hash current = merkle_leaf_hash(key, value_hash);
    size_t idx = target_index;
    size_t level_size = leaf_count;
    size_t proof_idx = 0;

    while (level_size > 1) {
        if (level_size % 2 == 1) level_size += 1;  // simulate duplication
        if (proof_idx >= proof.size()) return false;
        Hash sibling = proof[proof_idx++];
        if (idx % 2 == 0) {
            current = merkle_inner_hash(current, sibling);
        } else {
            current = merkle_inner_hash(sibling, current);
        }
        idx /= 2;
        level_size /= 2;
    }

    return proof_idx == proof.size() && current == root;
}

} // namespace determ::crypto
