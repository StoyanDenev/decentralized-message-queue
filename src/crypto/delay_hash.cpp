#include <dhcoin/crypto/delay_hash.hpp>
#include <dhcoin/crypto/sha256.hpp>

namespace dhcoin::crypto {

// rev.9 S-009 fix: the iterated SHA-256 delay function is removed.
// The selective-abort defense the iteration was supposed to provide
// is structurally weak (ASIC asymmetry with SHA-256 makes the wall-
// clock budget unenforceable at production scale — the threat model
// of S-009). Rather than attempt a VDF replacement, the protocol now
// relies on:
//
//   (1) Phase-1 commit-reveal binding for selective-abort defense:
//       creators commit to a fresh secret in Phase 1 (via dh_input,
//       semantically a commitment) and reveal it in Phase 2. An
//       attacker without all K secrets cannot predict block_rand;
//       SHA-256 preimage resistance does the work.
//
//   (2) BFT escalation + equivocation slashing for liveness under
//       blind-abort attacks.
//
// The function signature is kept for backward compatibility with
// existing callers (compute_delay_seed, validator checks, BlockSigMsg
// serialization). The T parameter is ignored — what was previously a
// delay-hash output is now a single SHA-256 over the seed, computed
// instantly. Phase-2 message ordering already handles the secret-
// reveal step via the existing buffered_block_sigs path.
Hash delay_hash_compute(const Hash& seed, uint64_t /*T_ignored*/) {
    return sha256(seed);
}

bool delay_hash_verify(const Hash& seed, uint64_t T, const Hash& output) {
    return delay_hash_compute(seed, T) == output;
}

} // namespace dhcoin::crypto
