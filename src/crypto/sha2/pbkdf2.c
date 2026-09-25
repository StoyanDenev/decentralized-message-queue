/* Determ C99-native PBKDF2-HMAC-SHA-256 (RFC 8018 / PKCS #5 v2.1).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.8b),
 * built on the streaming C99 HMAC in this directory, so it does not allocate.
 * This is the KDF the wallet keyfile envelope (S-004) uses at rest. Validated
 * byte-equal against OpenSSL PKCS5_PBKDF2_HMAC + RFC-style KATs by
 * `determ-cryptotest test-sha2-c99`. */
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <string.h>

int determ_pbkdf2_hmac_sha256(const uint8_t *pw,   size_t pwlen,
                              const uint8_t *salt, size_t saltlen,
                              uint32_t iters, uint8_t *out, size_t outlen) {
    const size_t hLen = 32;
    determ_hmac_sha256_ctx keyed;   /* HMAC(pw, .) keyed once; each MAC finishes a copy */
    determ_hmac_sha256_ctx ctx;
    size_t blocks;
    uint8_t U[32], T[32];
    uint32_t i, j;
    size_t k;

    if (iters == 0) return -1;
    if (outlen == 0) return 0;
    /* RFC 8018 section 5.2 step 1: reject dkLen > (2^32 - 1) * hLen ("derived
     * key too long"). Computed in 64-bit so the bound is correct on any size_t
     * width, and bounds `blocks` by UINT32_MAX. The loop below is zero-based so
     * its final increment terminates at UINT32_MAX rather than wrapping. */
    if ((uint64_t)outlen > (uint64_t)0xFFFFFFFFu * (uint64_t)hLen) return -1;

    blocks = outlen / hLen + (outlen % hLen != 0u); /* ceil, without addition overflow */
    determ_hmac_sha256_init(&keyed, pw, pwlen);

    for (i = 0; i < blocks; i++) {
        uint32_t block_index = i + 1u; /* 1..UINT32_MAX, never zero */
        uint8_t be[4];
        size_t off = (size_t)i * hLen;
        size_t take = (outlen - off < hLen) ? (outlen - off) : hLen;

        /* U_1 = HMAC(pw, salt || INT_32_BE(i)) */
        be[0] = (uint8_t)(block_index >> 24);
        be[1] = (uint8_t)(block_index >> 16);
        be[2] = (uint8_t)(block_index >> 8);
        be[3] = (uint8_t)(block_index);
        ctx = keyed;
        determ_hmac_sha256_update(&ctx, salt, saltlen);
        determ_hmac_sha256_update(&ctx, be, sizeof be);
        determ_hmac_sha256_final(&ctx, U);
        memcpy(T, U, hLen);

        /* T_i = U_1 ^ U_2 ^ ... ^ U_c,  U_j = HMAC(pw, U_{j-1}) */
        for (j = 1; j < iters; j++) {
            ctx = keyed;
            determ_hmac_sha256_update(&ctx, U, hLen);
            determ_hmac_sha256_final(&ctx, U);
            for (k = 0; k < hLen; k++) T[k] = (uint8_t)(T[k] ^ U[k]);
        }
        memcpy(out + off, T, take);
    }

    /* keyed holds pw-derived chaining state; U and T are derived-key material
     * (T == the returned key for the final block). ctx is wiped by final. */
    determ_secure_zero(&keyed, sizeof keyed);
    determ_secure_zero(U, sizeof U);
    determ_secure_zero(T, sizeof T);
    return 0;
}
