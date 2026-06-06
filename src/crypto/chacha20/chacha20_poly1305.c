/* Determ C99-native ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8).
 * Part of the libsodium-free crypto stack (CRYPTO-C99-SPEC.md Section 3.4).
 * Composes the C99 ChaCha20 + Poly1305 in this directory. Validated byte-equal
 * against OpenSSL EVP_chacha20_poly1305 + the RFC 8439 2.8.2 KAT by
 * `determ test-chacha20-c99`. */
#include "determ/crypto/chacha20/chacha20.h"
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

/* Constant-time 16-byte compare: returns 0 iff equal (no secret-dependent branch). */
static int ct_eq16(const uint8_t *a, const uint8_t *b) {
    uint8_t r = 0;
    int i;
    for (i = 0; i < 16; i++) r |= (uint8_t)(a[i] ^ b[i]);
    return r == 0 ? 0 : -1;
}

/* tag = Poly1305(otk, aad || pad16(aad) || ct || pad16(ct) || len(aad)_le64 || len(ct)_le64) */
static void aead_tag(const uint8_t otk[32], const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t ctlen, uint8_t tag[16]) {
    size_t pad_a = (16 - (aadlen % 16)) % 16;
    size_t pad_c = (16 - (ctlen  % 16)) % 16;
    size_t n = aadlen + pad_a + ctlen + pad_c + 16;
    uint8_t *mac = (uint8_t *)malloc(n > 0 ? n : 1);
    size_t off = 0;
    if (aadlen) { memcpy(mac + off, aad, aadlen); off += aadlen; }
    memset(mac + off, 0, pad_a); off += pad_a;
    if (ctlen)  { memcpy(mac + off, ct, ctlen);  off += ctlen; }
    memset(mac + off, 0, pad_c); off += pad_c;
    put_u64_le(mac + off, (uint64_t)aadlen); off += 8;
    put_u64_le(mac + off, (uint64_t)ctlen);  off += 8;
    determ_poly1305(otk, mac, n, tag);
    free(mac);
}

void determ_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *pt, size_t ptlen,
                                      uint8_t *ct, uint8_t tag[16]) {
    uint8_t otk[32];
    poly1305_keygen(key, nonce, otk);
    determ_chacha20(key, 1u, nonce, pt, ptlen, ct);
    aead_tag(otk, aad, aadlen, ct, ptlen, tag);
}

int determ_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aadlen,
                                     const uint8_t *ct, size_t ctlen,
                                     const uint8_t tag[16], uint8_t *pt) {
    uint8_t otk[32], expect[16];
    poly1305_keygen(key, nonce, otk);
    aead_tag(otk, aad, aadlen, ct, ctlen, expect);
    if (ct_eq16(expect, tag) != 0) return -1;     /* authentication failure */
    determ_chacha20(key, 1u, nonce, ct, ctlen, pt);
    return 0;
}
