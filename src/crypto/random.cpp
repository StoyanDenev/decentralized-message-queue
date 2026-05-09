#include <dhcoin/crypto/random.hpp>
#include <dhcoin/crypto/sha256.hpp>
#include <algorithm>
#include <stdexcept>

namespace dhcoin::crypto {

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

std::vector<size_t> select_m_creators(const Hash& random_state, size_t node_count, size_t m) {
    if (node_count < m)
        throw std::runtime_error("Not enough registered nodes for M creators");
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

} // namespace dhcoin::crypto
