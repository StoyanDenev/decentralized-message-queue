#pragma once
#include <dhcoin/types.hpp>
#include <cstdint>

namespace dhcoin::crypto {

// Sequential delay function — T iterations of SHA-256 starting from `seed`.
// The output binds the seed under provable sequentiality (SHA-256 is
// inherently sequential; arbitrary parallelism does not speed it up). This
// is exactly what selective-abort defense needs: an attacker grinding
// candidate seeds during Phase 1 must spend >= T sequential hashes per
// candidate, so with T_delay >= 2*T_phase_1 they get fewer than 1 trial.
//
// Verification reruns the same T iterations (O(T)). With SHA-NI on modern
// CPUs (~100M hashes/sec) this is ~2 ms per block at T = 200k.
//
//   compute(seed, T) -> output      O(T) sequential
//   verify (seed, T, output) -> bool O(T) sequential

Hash delay_hash_compute(const Hash& seed, uint64_t T);
bool delay_hash_verify (const Hash& seed, uint64_t T, const Hash& output);

} // namespace dhcoin::crypto
