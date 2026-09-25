/* Determ C99-native PBKDF2-HMAC-SHA-256 (RFC 8018 / PKCS #5 v2.1).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.8b),
 * built on the C99 HMAC in this directory. This is the KDF the wallet keyfile
 * envelope (S-004) uses at rest. Validated byte-equal against OpenSSL
 * PKCS5_PBKDF2_HMAC + RFC-style KATs by `determ test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int determ_pbkdf2_hmac_sha256(const uint8_t *pw,   size_t pwlen,
                              const uint8_t *salt, size_t saltlen,
                              uint32_t iters, uint8_t *out, size_t outlen) {
    const size_t hLen = 32;
    size_t blocks;
    uint8_t U[32], T[32];
    uint8_t *msg;          /* salt || INT_32_BE(i) */
    uint32_t i;
    size_t j, k;
    int rc = -1;

    if (iters == 0) return -1;
    if (outlen == 0) return 0;
    /* RFC 8018 §5.2 step 1: reject dkLen > (2^32 - 1) * hLen ("derived key too
     * long"). Computed in 64-bit so the bound is correct on any size_t width, and
     * bounds `blocks` by UINT32_MAX. The loop below is zero-based so its final
     * increment terminates at UINT32_MAX rather than wrapping back to zero. */
    if ((uint64_t)outlen > (uint64_t)0xFFFFFFFFu * (uint64_t)hLen) return -1;
    if (saltlen > SIZE_MAX - 4u) return -1;       /* guard size_t overflow on saltlen+4 */

    blocks = outlen / hLen + (outlen % hLen != 0u); /* ceil, without addition overflow */
    msg = (uint8_t *)malloc(saltlen + 4);
    if (msg == NULL) return -1;

    for (i = 0; i < blocks; i++) {
        uint32_t block_index = i + 1u; /* 1..UINT32_MAX, never zero */
        size_t off = (size_t)i * hLen;
        size_t take = (outlen - off < hLen) ? (outlen - off) : hLen;

        /* U_1 = HMAC(pw, salt || INT_32_BE(i)) */
        if (saltlen) memcpy(msg, salt, saltlen);
        msg[saltlen]     = (uint8_t)(block_index >> 24);
        msg[saltlen + 1] = (uint8_t)(block_index >> 16);
        msg[saltlen + 2] = (uint8_t)(block_index >> 8);
        msg[saltlen + 3] = (uint8_t)(block_index);
        if (determ_hmac_sha256(pw, pwlen, msg, saltlen + 4, U) != 0) goto done;
        memcpy(T, U, hLen);

        /* T_i = U_1 ^ U_2 ^ ... ^ U_c,  U_j = HMAC(pw, U_{j-1}) */
        for (j = 1; j < iters; j++) {
            if (determ_hmac_sha256(pw, pwlen, U, hLen, U) != 0) goto done;
            for (k = 0; k < hLen; k++) T[k] = (uint8_t)(T[k] ^ U[k]);
        }
        memcpy(out + off, T, take);
    }

    rc = 0;
done:
    /* U and T are derived-key material (T == the returned key for the final
     * block); msg holds salt||counter. Scrub before the frame/heap is reclaimed. */
    determ_secure_zero(U, sizeof U);
    determ_secure_zero(T, sizeof T);
    determ_secure_zero(msg, saltlen + 4);
    free(msg);
    return rc;
}
