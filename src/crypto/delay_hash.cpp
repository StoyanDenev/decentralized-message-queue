#include <dhcoin/crypto/delay_hash.hpp>
#include <dhcoin/crypto/sha256.hpp>

namespace dhcoin::crypto {

Hash delay_hash_compute(const Hash& seed, uint64_t T) {
    Hash cur = seed;
    for (uint64_t i = 0; i < T; ++i) {
        cur = sha256(cur);
    }
    return cur;
}

bool delay_hash_verify(const Hash& seed, uint64_t T, const Hash& output) {
    return delay_hash_compute(seed, T) == output;
}

} // namespace dhcoin::crypto
