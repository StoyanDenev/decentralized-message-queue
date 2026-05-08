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

} // namespace dhcoin::crypto
