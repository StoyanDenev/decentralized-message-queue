/* Determ C99-native PBKDF2-HMAC-SHA-256 (RFC 8018 / PKCS #5 v2.1).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.8b),
 * built on the C99 HMAC in this directory. This is the KDF the wallet keyfile
 * envelope (S-004) uses at rest. Validated byte-equal against OpenSSL
 * PKCS5_PBKDF2_HMAC + RFC-style KATs by `determ test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
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

    if (iters == 0) return -1;
    if (outlen == 0) return 0;

    blocks = (outlen + hLen - 1) / hLen;
    msg = (uint8_t *)malloc(saltlen + 4);

    for (i = 1; i <= blocks; i++) {
        size_t off = (size_t)(i - 1) * hLen;
        size_t take = (outlen - off < hLen) ? (outlen - off) : hLen;

        /* U_1 = HMAC(pw, salt || INT_32_BE(i)) */
        if (saltlen) memcpy(msg, salt, saltlen);
        msg[saltlen]     = (uint8_t)(i >> 24);
        msg[saltlen + 1] = (uint8_t)(i >> 16);
        msg[saltlen + 2] = (uint8_t)(i >> 8);
        msg[saltlen + 3] = (uint8_t)(i);
        determ_hmac_sha256(pw, pwlen, msg, saltlen + 4, U);
        memcpy(T, U, hLen);

        /* T_i = U_1 ^ U_2 ^ ... ^ U_c,  U_j = HMAC(pw, U_{j-1}) */
        for (j = 1; j < iters; j++) {
            determ_hmac_sha256(pw, pwlen, U, hLen, U);
            for (k = 0; k < hLen; k++) T[k] = (uint8_t)(T[k] ^ U[k]);
        }
        memcpy(out + off, T, take);
    }

    free(msg);
    return 0;
}
