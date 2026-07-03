/* Determ C99-native SHA-2 (FIPS 180-4).
 *
 * First vendored primitive of the libsodium-free C99 crypto stack
 * (CRYPTO-C99-SPEC.md Section 3.1). One-shot SHA-256 / SHA-512, written in
 * portable C99 with no external dependency, consumable from C99 and from C++
 * (extern "C"). SHA-2 is the foundation the rest of the stack builds on:
 * RFC 8032 Ed25519 uses SHA-512, and the FROST H1..H5 challenge hashes
 * (RFC 9591) are SHA-512-based, so this unblocks the v2.10 work.
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

/* One-shot SHA-512. `out` must point to at least 64 bytes. */
void determ_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/* HMAC (RFC 2104) keyed by SHA-256 / SHA-512. `out` = 32 / 64 bytes. `key`/`msg`
 * may be NULL when their length is 0. Returns 0 on success, -1 on a memory-
 * allocation failure or a `block+msglen` size_t overflow (in which case `out` is
 * left unwritten; a long key never enters size arithmetic — `keylen > block`
 * hashes the key into the fixed-size k0 block). Secret-bearing intermediates are zeroized before
 * return. (The int return is backward source-compatible: existing statement-call
 * sites that ignore it still compile and behave identically for valid inputs.) */
int determ_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32]);
int determ_hmac_sha512(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[64]);

/* HKDF-SHA-256 (RFC 5869): extract-then-expand. `salt`/`info` may be NULL when
 * their length is 0 (a NULL/zero salt is treated as HashLen zero bytes per the
 * RFC). Returns 0 on success, -1 if `outlen` exceeds 255*32 = 8160 bytes. */
int determ_hkdf_sha256(const uint8_t *salt, size_t saltlen,
                       const uint8_t *ikm,  size_t ikmlen,
                       const uint8_t *info, size_t infolen,
                       uint8_t *out, size_t outlen);

/* PBKDF2-HMAC-SHA-256 (RFC 8018 / PKCS #5 v2.1). `iters` must be >= 1. `pw`/`salt`
 * may be NULL when their length is 0. Returns 0 on success, -1 if iters == 0. */
int determ_pbkdf2_hmac_sha256(const uint8_t *pw,   size_t pwlen,
                              const uint8_t *salt, size_t saltlen,
                              uint32_t iters, uint8_t *out, size_t outlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_SHA2_H */
