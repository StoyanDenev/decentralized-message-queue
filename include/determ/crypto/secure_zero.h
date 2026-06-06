/* Determ C99-native secure zeroization — the one memory-hygiene primitive the
 * libsodium-free crypto stack (CRYPTO-C99-SPEC.md) was missing. Use it to scrub
 * secret-bearing buffers (keys, keystream, MAC r/s, GHASH subkey, AES round-key
 * schedules, KDF intermediates) before they go out of scope, so key-derived
 * material does not linger in a reclaimed stack frame or freed heap block where a
 * separate memory-disclosure bug (core dump, swap, stack reuse) could recover it.
 *
 * NOTE: this is a hygiene primitive, not a constant-time one; it has no secret-
 * dependent behavior of its own. A plain `memset` before return is subject to
 * dead-store elimination — this routine writes through a volatile indirection so
 * the compiler may not prove the stores dead and drop them. */
#ifndef DETERM_CRYPTO_SECURE_ZERO_H
#define DETERM_CRYPTO_SECURE_ZERO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Overwrite `len` bytes at `p` with zero; not elided by the optimizer. A NULL
 * `p` or zero `len` is a no-op. */
void determ_secure_zero(void *p, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_SECURE_ZERO_H */
