/* Determ C99 OS-entropy source (CRYPTO-C99-SPEC.md §3.15).
 *
 * The one primitive the from-scratch stack cannot synthesize: fresh entropy.
 * Thin, auditable shim over the operating system's CSPRNG — BCryptGenRandom
 * (system-preferred RNG) on Windows, getrandom(2) with a /dev/urandom
 * fallback elsewhere. No userspace RNG state, no seeding logic, no fallback
 * to anything weaker: if the OS source fails, the call fails and the caller
 * must treat it as fatal (an all-zero or partial secret must never be used).
 *
 * Replaces OpenSSL RAND_bytes at the daemon's two entropy sites (the
 * per-round dh_secret commit and node keygen) as part of the §3.15
 * consensus-path migration off OpenSSL.
 */
#ifndef DETERM_CRYPTO_RNG_H
#define DETERM_CRYPTO_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fill buf[0..n) with cryptographically secure random bytes from the OS.
 * Returns 0 on success, -1 on failure (buf contents are then undefined and
 * MUST NOT be used). n == 0 is a no-op success. */
int determ_rng_bytes(uint8_t *buf, size_t n);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_RNG_H */
