/* Determ C99-native Ed25519 (RFC 8032) — the EC prerequisite for the v2.10
 * FROST-Ed25519 threshold randomness (CRYPTO-C99-SPEC.md Section 3.2). Provides
 * the scalar/point arithmetic + sign/verify the daemon previously had only via
 * OpenSSL's opaque EVP_PKEY_ED25519, with NO libsodium dependency.
 *
 * Implementation strategy: a from-scratch, CONSTANT-TIME field/group layer in the
 * well-known gf[16] (radix-2^16) representation with a cswap-ladder scalar
 * multiplication and a branchless mod-L reduction — no key-dependent branch,
 * index, or precomputed-table lookup, so there is no cache-timing channel. (A
 * radix-2^51 / ref10 perf-optimized variant remains a future optimization, not a
 * security gate — the correctness-first posture mirrors the AES S-box.) Built on
 * the C99 SHA-512 in `src/crypto/sha2/`. Validated byte-equal against OpenSSL
 * EVP_PKEY_ED25519 + the RFC 8032 Section 7.1 known-answer vectors by
 * `determ test-ed25519-c99`.
 */
#ifndef DETERM_CRYPTO_ED25519_H
#define DETERM_CRYPTO_ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Derive the 32-byte Ed25519 public key from a 32-byte seed (the raw private
 * key), per RFC 8032 §5.1.5: pk = encode([clamp(SHA512(seed)[0:32])] * B). */
void determ_ed25519_pubkey_from_seed(const uint8_t seed[32], uint8_t pk[32]);

/* Sign `msg` (length `msglen`) under `seed` (whose public key is `pk`), writing a
 * 64-byte detached signature R||S to `sig` per RFC 8032 §5.1.6. Returns 0 on
 * success, -1 on an internal allocation failure / length overflow. Deterministic:
 * the signature is a pure function of (seed, msg). Secret intermediates are
 * zeroized before return. */
int determ_ed25519_sign(const uint8_t seed[32], const uint8_t pk[32],
                        const uint8_t *msg, size_t msglen, uint8_t sig[64]);

/* Verify the 64-byte signature `sig` over `msg` under public key `pk`, per RFC
 * 8032 §5.1.7. Returns 0 if the signature is valid, -1 otherwise (bad signature,
 * malformed public key, or internal allocation failure). Enforces the RFC
 * canonicality gates that defeat malleability: the scalar S is rejected unless
 * S < L (§5.1.7, so (R, S+L) does NOT re-verify — signatures are unique), and a
 * non-canonical public-key y >= q is rejected (§5.1.3). This is intentionally
 * STRICTER than OpenSSL's lenient ref10 decoder on adversarial inputs; honestly
 * generated keys/signatures are always canonical and behave identically. */
int determ_ed25519_verify(const uint8_t pk[32],
                          const uint8_t *msg, size_t msglen, const uint8_t sig[64]);

/* Ed25519 -> X25519 key conversions (RFC 7748 birational map), reproducing
 * libsodium's crypto_sign_ed25519_{sk,pk}_to_curve25519 byte-for-byte so a
 * wallet can reuse one Ed25519 identity for X25519 ECDH. The sk conversion
 * takes the 32-byte SEED (not libsodium's 64-byte sk — same output, since
 * libsodium hashes only the seed half). The pk conversion returns -1 on an
 * off-curve / non-canonical input. */
void determ_ed25519_seed_to_x25519_sk(const uint8_t seed[32], uint8_t x_sk[32]);
int  determ_ed25519_pk_to_x25519_pk(const uint8_t ed_pk[32], uint8_t x_pk[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_ED25519_H */
