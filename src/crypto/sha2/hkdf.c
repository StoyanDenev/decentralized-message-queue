/* Determ C99-native HKDF-SHA-256 (RFC 5869).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.1),
 * built on the streaming C99 HMAC in this directory, so it does not allocate.
 * Validated byte-equal against the OpenSSL backend + RFC 5869 KATs by
 * `determ-cryptotest test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <string.h>

int determ_hkdf_sha256(const uint8_t *salt, size_t saltlen,
                       const uint8_t *ikm,  size_t ikmlen,
                       const uint8_t *info, size_t infolen,
                       uint8_t *out, size_t outlen) {
    const size_t HASHLEN = 32;
    determ_hmac_sha256_ctx ctx;
    uint8_t prk[32];
    uint8_t t[32];
    size_t tlen = 0;
    size_t done = 0;
    unsigned counter = 1;

    if (outlen > 255 * HASHLEN) return -1;

    /* Extract: PRK = HMAC(salt, IKM). RFC 5869 reads an empty salt as HashLen
     * zero bytes; HMAC zero-pads a short key to the block size, so the empty
     * key is that same key. */
    determ_hmac_sha256_init(&ctx, salt, saltlen);
    determ_hmac_sha256_update(&ctx, ikm, ikmlen);
    determ_hmac_sha256_final(&ctx, prk);

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) || T(2) || ... */
    while (done < outlen) {
        uint8_t ctr = (uint8_t)counter;
        size_t take = (outlen - done < HASHLEN) ? (outlen - done) : HASHLEN;
        determ_hmac_sha256_init(&ctx, prk, HASHLEN);
        determ_hmac_sha256_update(&ctx, t, tlen);
        determ_hmac_sha256_update(&ctx, info, infolen);
        determ_hmac_sha256_update(&ctx, &ctr, 1);
        determ_hmac_sha256_final(&ctx, t);
        tlen = HASHLEN;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
    determ_secure_zero(prk, sizeof prk);   /* the pseudorandom key — derives all OKM */
    determ_secure_zero(t, sizeof t);
    return 0;
}
