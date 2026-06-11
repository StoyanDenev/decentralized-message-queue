/* Determ C99-native ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.4).
 * Composes the C99 ChaCha20 + Poly1305 in this directory. Validated byte-equal
 * against OpenSSL EVP_chacha20_poly1305 + the RFC 8439 2.8.2 KAT by
 * `determ test-chacha20-c99`. */
#include "determ/crypto/chacha20/chacha20.h"
#include "determ/crypto/secure_zero.h"
#include "determ/crypto/ct.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* poly1305_key_gen (RFC 8439 2.6): the one-time Poly1305 key is the first 32
 * bytes of the ChaCha20 keystream at block counter 0. */
static void poly1305_keygen(const uint8_t key[32], const uint8_t nonce[12], uint8_t otk[32]) {
    uint8_t z32[32];
    memset(z32, 0, 32);
    determ_chacha20(key, 0u, nonce, z32, 32, otk);   /* keystream XOR 0 = keystream */
}

static void put_u64_le(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* tag = Poly1305(otk, aad || pad16(aad) || ct || pad16(ct) || len(aad)_le64 || len(ct)_le64)
 * Returns 0 on success, -1 on a length overflow or MAC-buffer allocation failure. */
static int aead_tag(const uint8_t otk[32], const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen, uint8_t tag[16]) {
    size_t pad_a = (16 - (aadlen % 16)) % 16;
    size_t pad_c = (16 - (ctlen  % 16)) % 16;
    size_t n;
    uint8_t *mac;
    size_t off = 0;

    /* Guard size_t overflow on n = aadlen + pad_a + ctlen + pad_c + 16 (the
     * per-operand pad is < 16, so the constant overhead is < 48). On a 32-bit
     * size_t an adversarial aadlen/ctlen near SIZE_MAX would otherwise wrap n to a
     * small value, malloc a tiny buffer, and overflow it on the memcpy below. */
    if (ctlen > SIZE_MAX - 48u) return -1;
    if (aadlen > SIZE_MAX - 48u - ctlen) return -1;

    n = aadlen + pad_a + ctlen + pad_c + 16;
    mac = (uint8_t *)malloc(n > 0 ? n : 1);
    if (mac == NULL) return -1;
    if (aadlen) { memcpy(mac + off, aad, aadlen); off += aadlen; }
    memset(mac + off, 0, pad_a); off += pad_a;
    if (ctlen)  { memcpy(mac + off, ct, ctlen);  off += ctlen; }
    memset(mac + off, 0, pad_c); off += pad_c;
    put_u64_le(mac + off, (uint64_t)aadlen); off += 8;
    put_u64_le(mac + off, (uint64_t)ctlen);  off += 8;
    determ_poly1305(otk, mac, n, tag);
    free(mac);   /* mac holds only public aad/ct + lengths — no secret to scrub */
    return 0;
}

int determ_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aadlen,
                                     const uint8_t *pt, size_t ptlen,
                                     uint8_t *ct, uint8_t tag[16]) {
    uint8_t otk[32];
    int rc;
    poly1305_keygen(key, nonce, otk);
    determ_chacha20(key, 1u, nonce, pt, ptlen, ct);
    rc = aead_tag(otk, aad, aadlen, ct, ptlen, tag);
    determ_secure_zero(otk, sizeof otk);          /* the one-time Poly1305 key */
    return rc;
}

int determ_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aadlen,
                                     const uint8_t *ct, size_t ctlen,
                                     const uint8_t tag[16], uint8_t *pt) {
    uint8_t otk[32], expect[16];
    int rc;
    poly1305_keygen(key, nonce, otk);
    rc = aead_tag(otk, aad, aadlen, ct, ctlen, expect);
    if (rc != 0) {                                /* internal failure */
        determ_secure_zero(otk, sizeof otk);
        determ_secure_zero(expect, sizeof expect);
        return -1;
    }
    if (determ_ct_memcmp(expect, tag, 16) != 0) {              /* authentication failure */
        determ_secure_zero(otk, sizeof otk);
        determ_secure_zero(expect, sizeof expect);
        return -1;
    }
    determ_chacha20(key, 1u, nonce, ct, ctlen, pt);
    determ_secure_zero(otk, sizeof otk);
    determ_secure_zero(expect, sizeof expect);
    return 0;
}
