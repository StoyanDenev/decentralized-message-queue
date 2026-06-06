/* Determ C99-native Argon2id (RFC 9106 / P-H-C reference) — the memory-hard
 * password hash, libsodium-free (CRYPTO-C99-SPEC §3.6). Built on the C99 BLAKE2b
 * (src/crypto/blake2/). The intended consumer is the passphrase-encrypted keyfile
 * KDF (today libsodium crypto_pwhash); this is the drop-in replacement.
 *
 * Explicit-parameter (raw) interface, matching the P-H-C `argon2id_hash_raw`:
 * libsodium's crypto_pwhash_argon2id maps (opslimit, memlimit) -> (t_cost=opslimit,
 * m_cost=memlimit/1024, parallelism=1, version=0x13), so determ_argon2id(t, m, 1,
 * ...) is validated byte-equal vs crypto_pwhash_argon2id(opslimit=t, memlimit=m*1024)
 * by `determ-wallet test-argon2id-c99` (the only AEAD-grade oracle is libsodium,
 * which the determ daemon does not link — so the cross-validation lives in the
 * libsodium-linked wallet binary).
 *
 * NOTE: memory-hard, so NOT constant-time in the data-dependent passes by design
 * (that is Argon2d's GPU-resistance); the Argon2id hybrid keeps the FIRST half of
 * the first pass data-INdependent (side-channel-resistant for the secret-derived
 * addressing), per RFC 9106 §3.4. Inputs flow through BLAKE2b; the block memory is
 * zeroized before free.
 */
#ifndef DETERM_CRYPTO_ARGON2ID_H
#define DETERM_CRYPTO_ARGON2ID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Argon2id v1.3. Writes `outlen` bytes (>= 4) to `out`. `t_cost` >= 1 passes,
 * `m_cost` >= 8*parallelism KiB, `parallelism` >= 1. `pwd`/`salt` may be NULL when
 * their length is 0 (salt should be >= 8 bytes per the spec; libsodium uses 16).
 * Returns 0 on success, -1 on a bad parameter or a memory-allocation failure. */
int determ_argon2id(uint8_t *out, size_t outlen,
                    const uint8_t *pwd, size_t pwdlen,
                    const uint8_t *salt, size_t saltlen,
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_ARGON2ID_H */
