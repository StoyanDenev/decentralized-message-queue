/* Determ C99-native constant-time equality compare — the second of the two
 * §3.10 primitives in CRYPTO-C99-SPEC.md (the first, memory zeroization, is
 * determ_secure_zero in secure_zero.h).
 *
 * WHY: a short-circuiting memcmp returns at the first mismatching byte, so its
 * running time reveals the length of the matching prefix. When one operand is
 * secret-derived (an AEAD authentication tag, a recomputed MAC, a signature's
 * R encoding), that timing side channel lets an attacker forge the value one
 * byte at a time. determ_ct_memcmp always touches every byte and accumulates
 * differences with OR — its running time depends only on `len`, never on the
 * data.
 *
 * USAGE NOTES (CRYPTO-C99-SPEC.md §3.10 "documented usage notes"):
 *   - EQUALITY ONLY. The return value is 0 iff the buffers are byte-identical
 *     and nonzero otherwise; unlike memcmp it carries NO lexicographic order.
 *     Never use it for sorting or range checks.
 *   - Use it for every compare where at least one operand is secret or
 *     secret-derived: AEAD tag verification (ChaCha20-Poly1305, AES-256-GCM),
 *     Ed25519 signature R-encoding acceptance, MAC checks.
 *   - Also use it on public-but-crypto-adjacent equality (e.g. FROST VSS /
 *     PoP point comparisons, whose operands are publicly recomputable group
 *     elements): uniform discipline costs nothing and removes the per-site
 *     "is this operand really public?" review burden.
 *   - `len` itself is treated as public (the loop count is visible). Do not
 *     encode secrets in buffer lengths. */
#ifndef DETERM_CRYPTO_CT_H
#define DETERM_CRYPTO_CT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constant-time equality compare of `len` bytes: returns 0 iff a == b
 * byte-for-byte, -1 otherwise (treat the contract as "0 / nonzero" — the -1
 * matches libsodium's crypto_verify convention). No short-circuit, no
 * secret-dependent branch; running time depends only on `len`. NULL is
 * permitted only when len == 0 (returns 0). */
int determ_ct_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_CT_H */
