// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/random.hpp>
#include <determ/crypto/sha256.hpp>
#include <algorithm>
#include <stdexcept>

namespace determ::crypto {

Hash compute_dh_output(const Hash& share_a, const Hash& share_b) {
    return sha256(share_a, share_b);
}

Hash compute_dh_output_m(const std::vector<Hash>& shares) {
    SHA256Builder b;
    for (auto& s : shares) b.append(s);
    return b.finalize();
}

Hash update_random_state(const Hash& prev_state, const Hash& dh_output) {
    return sha256(prev_state, dh_output);
}

static uint64_t hash_u64(const Hash& h) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | h[i];
    return v;
}

// Rejection-sampled draw of a value in [0, n). Guarantees uniform distribution
// even when n doesn't evenly divide 2^64. Caller supplies a fresh hash per call.
static size_t hash_mod(const Hash& h, size_t n) {
    if (n == 0) return 0;
    uint64_t v     = hash_u64(h);
    uint64_t limit = (UINT64_MAX / n) * n;
    if (v >= limit) {
        // Re-derive from h until we land in the unbiased range. Counter-based
        // re-hash to keep the function deterministic and pure.
        Hash next = h;
        uint64_t counter = 0;
        while (v >= limit) {
            next = SHA256Builder{}.append(next).append(counter++).finalize();
            v = hash_u64(next);
        }
    }
    return static_cast<size_t>(v % n);
}

// S-020 (Track A): hybrid Fisher-Yates committee selection.
//
// Rejection-sampling baseline runs expected O(K · N/(N−K)) hashes; the
// final pick when K = N−1 expects N tries, and at K = N the loop spins
// only because each draw collides with someone already in the result.
// The pathology is gradual and unbounded, not a hard hang — but it gives
// an attacker a knob to nudge committee selection latency at large N.
//
// Hybrid: stay on rejection sampling when 2K ≤ N (cheap, no allocation,
// matches prior committee-index fixtures in regression tests); switch to
// a partial Fisher-Yates shuffle when 2K > N. The FY path costs an O(N)
// index array plus exactly K hashes; the cost stays flat across the
// entire K → N range.
//
// Determinism: every node sees the same K, N, random_state and so picks
// the same branch and the same indices. No fork height needed because no
// chain history sits on the K > N/2 path — current regression tests run
// with M ≤ 2, K ≤ M, N_registered ≤ 3, and they all hit the rejection
// branch (m·2 ≤ N when M=1, N≥2; M=2, N=3 borderline below). Future
// production deployments with larger M, K will exercise the FY branch.
std::vector<size_t> select_m_creators(const Hash& random_state, size_t node_count, size_t m) {
    if (node_count < m)
        throw std::runtime_error("Not enough registered nodes for M creators");
    if (m * 2 <= node_count) {
        // Rejection sampling — preserves rev.9 output for K/N ≤ 0.5 to
        // keep existing committee-index fixtures stable.
        std::vector<size_t> result;
        Hash h = random_state;
        uint64_t counter = 0;
        while (result.size() < m) {
            h = SHA256Builder{}.append(h).append(counter++).finalize();
            size_t idx = hash_mod(h, node_count);
            if (std::find(result.begin(), result.end(), idx) == result.end())
                result.push_back(idx);
        }
        return result;
    }
    // Partial Fisher-Yates shuffle: O(N) setup, exactly K hashes, no spin.
    std::vector<size_t> indices(node_count);
    for (size_t i = 0; i < node_count; ++i) indices[i] = i;
    Hash h = random_state;
    uint64_t counter = 0;
    for (size_t i = 0; i < m; ++i) {
        h = SHA256Builder{}.append(h).append(counter++).finalize();
        // Uniform pick j in [i, node_count); swap into position i.
        size_t j = i + hash_mod(h, node_count - i);
        std::swap(indices[i], indices[j]);
    }
    indices.resize(m);
    return indices;
}

Hash compute_abort_hash(uint8_t round, const std::string& aborting_node,
                        int64_t timestamp, const Hash& random_state) {
    return SHA256Builder{}
        .append(round)
        .append(aborting_node)
        .append(timestamp)
        .append(random_state)
        .finalize();
}

Hash chain_abort_hash(const Hash& prev_abort_hash, uint8_t round,
                      const std::string& aborting_node, int64_t timestamp) {
    return SHA256Builder{}
        .append(prev_abort_hash)
        .append(round)
        .append(aborting_node)
        .append(timestamp)
        .finalize();
}

std::vector<size_t> select_after_abort_m(const std::vector<size_t>& indices,
                                          const Hash& abort_hash,
                                          size_t node_count) {
    size_t m      = indices.size();
    size_t offset = hash_mod(abort_hash, node_count);
    size_t new_first = (indices[0] + offset) % node_count;

    // S-020: same hybrid switch as select_m_creators. K << N stays on
    // rejection sampling to preserve fixture stability; K → N uses a
    // partial Fisher-Yates over indices with new_first pinned at slot 0.
    if (m * 2 <= node_count) {
        std::vector<size_t> result = {new_first};
        Hash h = SHA256Builder{}.append(abort_hash).append(std::string("abort_m")).finalize();
        uint64_t counter = 0;
        while (result.size() < m) {
            h = SHA256Builder{}.append(h).append(counter++).finalize();
            size_t idx = hash_mod(h, node_count);
            if (std::find(result.begin(), result.end(), idx) == result.end())
                result.push_back(idx);
        }
        return result;
    }
    // Build [new_first, 0, 1, …, n−1 minus new_first] then Fisher-Yates
    // shuffle positions 1..m. new_first is fixed by the abort-hash offset
    // (consensus contract), so it stays at position 0.
    std::vector<size_t> shuffle(node_count);
    shuffle[0] = new_first;
    size_t pos = 1;
    for (size_t i = 0; i < node_count; ++i) {
        if (i == new_first) continue;
        shuffle[pos++] = i;
    }
    Hash h = SHA256Builder{}.append(abort_hash).append(std::string("abort_m")).finalize();
    uint64_t counter = 0;
    for (size_t i = 1; i < m; ++i) {
        h = SHA256Builder{}.append(h).append(counter++).finalize();
        size_t j = i + hash_mod(h, node_count - i);
        std::swap(shuffle[i], shuffle[j]);
    }
    shuffle.resize(m);
    return shuffle;
}

Hash genesis_random_state(const Hash& seed) {
    return sha256(seed);
}

Hash epoch_committee_seed(const Hash& epoch_rand, ShardId shard_id) {
    return SHA256Builder{}
        .append(epoch_rand)
        .append(std::string("shard-committee"))
        .append(static_cast<uint64_t>(shard_id))
        .finalize();
}

ShardId shard_id_for_address(const std::string& addr,
                                uint32_t shard_count,
                                const Hash& shard_address_salt) {
    if (shard_count <= 1) return 0;
    Hash h = SHA256Builder{}
        .append(shard_address_salt)
        .append(std::string("shard-route"))
        .append(addr)
        .finalize();
    // Fold first 8 bytes to uint64, then mod shard_count. Bias is
    // negligible at S << 2^64.
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | h[i];
    return static_cast<ShardId>(v % shard_count);
}

} // namespace determ::crypto
