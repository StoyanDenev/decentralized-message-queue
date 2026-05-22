// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// v2.1: deterministic Merkle tree over sorted (key, value-hash) pairs.
// The state-commitment primitive on top of which v2.2 light-client
// inclusion proofs and v2.3 trustless fast sync are built.
//
// Tree shape: balanced binary tree over the sorted-leaf array. If the
// leaf count is not a power of 2, the last leaf is duplicated to the
// next power-of-2 boundary at each level — the standard pattern
// (Bitcoin's tx tree, Cosmos's IAVL leaf padding, OpenSSL's HashTree).
// This isn't a sparse Merkle tree in the literal sense (leaf position
// is determined by sort order, not by key path), so it doesn't support
// non-membership proofs natively. Membership proofs are O(log N) sibling
// hashes and verify in O(log N) SHA-256 evaluations.
//
// A future v2 iteration can swap this for a true SMT (sparse Merkle
// tree with key-path-indexed leaves) if non-membership becomes needed
// for any protocol-level use case. The root is the same shape
// (32-byte Hash) so wire-format changes don't cascade.
//
// Determinism: sorting is by lexicographic byte order of the key. Two
// honest nodes with the same (key, value_hash) set produce byte-
// identical roots.

#include <determ/types.hpp>
#include <vector>
#include <utility>

namespace determ::crypto {

// One leaf entry. `key` is opaque bytes; the tree sorts by lexicographic
// byte order. `value_hash` is the SHA-256 of the canonical serialization
// of the value being committed. Separating key from value_hash lets the
// tree commit to arbitrary-sized values without unbounded leaf data.
struct MerkleLeaf {
    std::vector<uint8_t> key;
    Hash                 value_hash;
};

// Compute the Merkle root over the given leaves. Leaves are sorted by
// key inside this call (caller doesn't need to pre-sort, but sorting
// upfront is no slower and makes proof generation easier).
//
// Empty leaf set: returns the all-zero hash (the same value as `Hash{}`
// default-constructed). This is the convention for "no committed state."
Hash merkle_root(const std::vector<MerkleLeaf>& leaves);

// Compute an inclusion proof for the leaf at `target_index` in the
// sorted-by-key array. The proof is the sequence of sibling hashes
// going up the tree (log2 ceil of leaf count). Pair this with the
// leaf's (key, value_hash) and the root for verification.
//
// Returns empty if target_index is out of range or leaves is empty.
std::vector<Hash> merkle_proof(const std::vector<MerkleLeaf>& leaves,
                                  size_t target_index);

// Verify an inclusion proof against a committed root. Returns true iff
// the (key, value_hash) at target_index in a tree of `leaf_count`
// total leaves produces `root` when combined with the proof's sibling
// hashes.
//
// S-040 caller-trust invariant: `leaf_count` is NOT bound into the leaf
// or inner hash. Two distinct (target_index, leaf_count) pairs that
// produce the same walk-shape (same `ceil(log2(N))` level count + same
// per-level parity) will share the same proof structure. A caller that
// fetches `leaf_count` from an untrusted source and the proof from
// another untrusted source can be fooled. Concrete failure case pinned
// by `determ test-merkle-proof-tampering` scenario #8: claiming
// `leaf_count=8` for a 5-leaf tree at index 2 verifies as TRUE because
// both yield identical 3-level walks consuming the same 3 siblings.
//
// MITIGATION (operator-side): always source `leaf_count` from the
// committed snapshot header (state-proof RPC returns it from the
// daemon's canonical state — so callers verifying against a single
// trusted daemon are safe). A light-client fetching the proof from
// one untrusted source and the leaf_count from another MUST cross-
// verify both against an anchor (e.g., a committee-signed state_root
// + an attestation that includes leaf_count). See SECURITY.md §S-040
// for the threat model + structural fix path (domain-separate
// `leaf_count` into the leaf hash; breaks v1 wire compat — tracked
// for v2.x).
bool merkle_verify(const Hash& root,
                     const std::vector<uint8_t>& key,
                     const Hash& value_hash,
                     size_t target_index,
                     size_t leaf_count,
                     const std::vector<Hash>& proof);

// Hash a single leaf entry. Exposed for callers that want to verify
// without depending on the in-memory MerkleLeaf shape.
//   leaf_hash = SHA-256(0x00 || u32_be(key_len) || key || value_hash)
// The 0x00 prefix domain-separates leaf hashes from inner-node hashes
// (0x01 prefix), defeating second-preimage attacks where an attacker
// crafts a leaf that hashes identically to an inner node.
Hash merkle_leaf_hash(const std::vector<uint8_t>& key,
                       const Hash& value_hash);

// Hash an inner node combining two children. Exposed for verification.
//   inner_hash = SHA-256(0x01 || left || right)
Hash merkle_inner_hash(const Hash& left, const Hash& right);

} // namespace determ::crypto
