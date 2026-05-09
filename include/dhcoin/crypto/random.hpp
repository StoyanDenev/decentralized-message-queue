#pragma once
#include <dhcoin/types.hpp>
#include <utility>
#include <string>
#include <cstdint>
#include <vector>

namespace dhcoin::crypto {

// dh_output = SHA256(share_a || share_b)
Hash compute_dh_output(const Hash& share_a, const Hash& share_b);

// Fold M DH shares: SHA256(share_0 || share_1 || ... || share_{M-1})
Hash compute_dh_output_m(const std::vector<Hash>& shares);

// random_state[n] = SHA256(random_state[n-1] || dh_output[n])
Hash update_random_state(const Hash& prev_state, const Hash& dh_output);

// Select M distinct creator indices deterministically from random_state.
// Uses rejection sampling with a counter; guaranteed to terminate when node_count >= m.
std::vector<size_t> select_m_creators(const Hash& random_state, size_t node_count, size_t m);

// Abort-dependent offset hashing (prevents cartel navigation of fallback sequence)
Hash compute_abort_hash(uint8_t round, const std::string& aborting_node,
                        int64_t timestamp, const Hash& random_state);
Hash chain_abort_hash(const Hash& prev_abort_hash, uint8_t round,
                      const std::string& aborting_node, int64_t timestamp);

// After abort: shift first index by offset derived from abort_hash, re-derive rest.
std::vector<size_t> select_after_abort_m(const std::vector<size_t>& indices,
                                          const Hash& abort_hash,
                                          size_t node_count);

Hash genesis_random_state(const Hash& seed);

// Stage B1: per-shard, per-epoch committee selection seed.
//   epoch_seed = SHA-256(epoch_rand ‖ "shard-committee" ‖ shard_id)
// epoch_rand is the chain's cumulative_rand at the block that opened the
// current epoch (block_index = epoch_index * epoch_blocks). This is
// deterministic across all nodes and stable for the duration of the epoch.
Hash epoch_committee_seed(const Hash& epoch_rand, ShardId shard_id);

// rev.9 B3: deterministic address-to-shard routing. Maps any string
// address (registered domain or anonymous bearer wallet) to one of the
// `shard_count` shards using a salted hash. Salt comes from the genesis
// (GenesisConfig::shard_address_salt) and is fixed for the chain's
// lifetime, so all nodes — beacon, every shard, every external wallet —
// agree on which shard owns which address.
//
// shard_count must be > 0. shard_count == 1 returns 0 unconditionally.
ShardId shard_id_for_address(const std::string& addr,
                                uint32_t shard_count,
                                const Hash& shard_address_salt);

} // namespace dhcoin::crypto
