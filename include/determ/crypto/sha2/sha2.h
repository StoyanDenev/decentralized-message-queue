/* Determ C99-native SHA-2 (FIPS 180-4).
 *
 * First vendored primitive of the libsodium-free C99 crypto stack
 * (CRYPTO-C99-SPEC.md Section 3.1). One-shot SHA-256 / SHA-512, written in
 * portable C99 with no external dependency, consumable from C99 and from C++
 * (extern "C"). SHA-2 is the foundation the rest of the stack builds on:
 * RFC 8032 Ed25519 uses SHA-512.
 *
 * Correctness is gated two independent ways by `determ test-sha2-c99`:
 *   (1) byte-equal cross-validation against the daemon's current backend
 *       (OpenSSL) over every message length across the block + padding
 *       boundaries (the CRYPTO-C99-SPEC Section Q9 cross-validation gate), and
 *   (2) the canonical NIST FIPS 180-4 known-answer vectors.
 *
 * No secret-dependent control flow or memory access: a public hash has no
 * timing side channel to protect, so this is the safest primitive to vendor
 * first.
 */
#ifndef DETERM_CRYPTO_SHA2_H
#define DETERM_CRYPTO_SHA2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_SHA256_DIGEST_LEN 32u
#define DETERM_SHA512_DIGEST_LEN 64u

/* One-shot SHA-256. `out` must point to at least 32 bytes. */
void determ_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* Incremental (streaming) SHA-256 — the init/update/final form of the same
 * FIPS 180-4 engine, exported for the daemon's SHA256Builder (§3.15: the
 * consensus path hashes blocks/state leaves incrementally; OpenSSL's
 * EVP_DigestInit/Update/Final shape is reproduced 1:1). The one-shot
 * determ_sha256 is implemented on this engine, so the CAVP + §Q9 gates that
 * validate it validate this too. determ_sha256_final zeroizes the ctx (the
 * buffer may hold secret material for keyed callers); a ctx is single-use —
 * call determ_sha256_init again to rehash. */
typedef struct {
    uint32_t h[8];      /* chaining state */
    uint64_t total;     /* total bytes absorbed */
    uint8_t  buf[64];   /* partial-block buffer */
    size_t   buflen;    /* valid bytes in buf (< 64) */
} determ_sha256_ctx;

void determ_sha256_init(determ_sha256_ctx *ctx);
void determ_sha256_update(determ_sha256_ctx *ctx, const uint8_t *data, size_t len);
void determ_sha256_final(determ_sha256_ctx *ctx, uint8_t out[32]);

/* Incremental HMAC-SHA-256 (RFC 2104) on the streaming engine above: key once,
 * absorb the message in any number of updates, finish once. No heap and no
 * failure path. `key`/`data` may be NULL when their length is 0. The ctx holds
 * key-derived state; final wipes it, and a ctx is single-use, but a copy taken
 * after init (or after any update) finishes independently: PBKDF2 keys once
 * per password that way. A ctx or copy abandoned before final still holds that
 * state: wipe it with determ_secure_zero. `out` may alias bytes already
 * absorbed. */
typedef struct {
    determ_sha256_ctx inner;   /* has absorbed K0 ^ ipad, then the message */
    determ_sha256_ctx outer;   /* has absorbed K0 ^ opad */
} determ_hmac_sha256_ctx;

void determ_hmac_sha256_init(determ_hmac_sha256_ctx *ctx,
                             const uint8_t *key, size_t keylen);
void determ_hmac_sha256_update(determ_hmac_sha256_ctx *ctx,
                               const uint8_t *data, size_t len);
void determ_hmac_sha256_final(determ_hmac_sha256_ctx *ctx, uint8_t out[32]);

/* One-shot SHA-512. `out` must point to at least 64 bytes. */
void determ_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/* HMAC (RFC 2104) keyed by SHA-256 / SHA-512. `out` = 32 / 64 bytes. `key`/`msg`
 * may be NULL when their length is 0. Secret-bearing intermediates are zeroized
 * before return. HMAC-SHA-256 is the streaming form above: it does not allocate
 * and always returns 0. HMAC-SHA-512 returns -1 on a memory-allocation failure
 * or a `block+msglen` size_t overflow (in which case `out` is left unwritten; a
 * long key never enters size arithmetic — `keylen > block` hashes the key into
 * the fixed-size k0 block), 0 otherwise. (The int return is kept for source
 * compatibility.) `out` may alias `msg`: the message is consumed before `out`
 * is written. */
int determ_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32]);
int determ_hmac_sha512(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[64]);

/* HKDF-SHA-256 (RFC 5869): extract-then-expand. `salt`/`ikm`/`info` may be NULL
 * when their length is 0 (an empty salt is HashLen zero bytes per the RFC).
 * Returns -1, with `out` untouched, only when outlen > 255 * 32 (the RFC's
 * bound); 0 otherwise. Does not allocate. Secret scratch is wiped. */
int determ_hkdf_sha256(const uint8_t *salt, size_t saltlen,
                       const uint8_t *ikm,  size_t ikmlen,
                       const uint8_t *info, size_t infolen,
                       uint8_t *out, size_t outlen);

/* PBKDF2-HMAC-SHA-256 (RFC 8018 / PKCS #5 v2.1). `pw`/`salt` may be NULL when
 * their length is 0. Returns -1, with `out` untouched, only for zero `iters` or
 * outlen > (2^32 - 1) * 32 (RFC 8018 section 5.2 step 1); 0 otherwise (outlen 0
 * included). Does not allocate. Secret scratch is wiped. */
int determ_pbkdf2_hmac_sha256(const uint8_t *pw,   size_t pwlen,
                              const uint8_t *salt, size_t saltlen,
                              uint32_t iters, uint8_t *out, size_t outlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_SHA2_H */
