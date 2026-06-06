/* Determ C99-native HKDF-SHA-256 (RFC 5869).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.1),
 * built on the C99 HMAC in this directory. Validated byte-equal against the
 * OpenSSL backend + RFC 5869 KATs by `determ test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int determ_hkdf_sha256(const uint8_t *salt, size_t saltlen,
                       const uint8_t *ikm,  size_t ikmlen,
                       const uint8_t *info, size_t infolen,
                       uint8_t *out, size_t outlen) {
    const size_t HASHLEN = 32;
    uint8_t prk[32];
    uint8_t t[32];
    uint8_t zero_salt[32];
    size_t tlen = 0;
    size_t done = 0;
    unsigned counter = 1;

    if (outlen > 255 * HASHLEN) return -1;
    /* Guard size_t overflow of n = tlen + infolen + 1 (tlen <= HASHLEN). */
    if (infolen > SIZE_MAX - (HASHLEN + 1u)) return -1;

    /* Extract: PRK = HMAC(salt, IKM). A NULL/zero salt is HashLen zero bytes. */
    if (saltlen == 0) {
        memset(zero_salt, 0, HASHLEN);
        determ_hmac_sha256(zero_salt, HASHLEN, ikm, ikmlen, prk);
    } else {
        determ_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    }

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) || T(2) || ... */
    while (done < outlen) {
        size_t n = tlen + infolen + 1;
        uint8_t *buf = (uint8_t *)malloc(n);
        size_t off = 0;
        size_t take;
        if (buf == NULL) {                       /* allocation failure: scrub + fail */
            determ_secure_zero(prk, sizeof prk);
            determ_secure_zero(t, sizeof t);
            determ_secure_zero(zero_salt, sizeof zero_salt);
            return -1;
        }
        if (tlen) { memcpy(buf, t, tlen); off += tlen; }
        if (infolen) { memcpy(buf + off, info, infolen); off += infolen; }
        buf[off] = (uint8_t)counter;
        determ_hmac_sha256(prk, HASHLEN, buf, n, t);
        determ_secure_zero(buf, n);              /* holds prior T (PRK-derived) */
        free(buf);
        tlen = HASHLEN;
        take = (outlen - done < HASHLEN) ? (outlen - done) : HASHLEN;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
    determ_secure_zero(prk, sizeof prk);         /* the pseudorandom key — derives all OKM */
    determ_secure_zero(t, sizeof t);
    determ_secure_zero(zero_salt, sizeof zero_salt);
    return 0;
}
