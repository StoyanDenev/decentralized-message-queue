/* Determ C99-native XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) + HChaCha20.
 * Built on the C99 ChaCha20-Poly1305 (chacha20.h). No libsodium.
 * See include/determ/crypto/chacha20/xchacha20_poly1305.h. */
#include <determ/crypto/chacha20/xchacha20_poly1305.h>
#include <determ/crypto/chacha20/chacha20.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }

#define QR(a,b,c,d) do { \
    a += b; d = rotl32(d ^ a, 16); \
    c += d; b = rotl32(b ^ c, 12); \
    a += b; d = rotl32(d ^ a, 8);  \
    c += d; b = rotl32(b ^ c, 7);  \
} while (0)

void determ_hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16]) {
    uint32_t s[16]; int i;
    s[0]=0x61707865u; s[1]=0x3320646eu; s[2]=0x79622d32u; s[3]=0x6b206574u;
    for (i = 0; i < 8; i++) s[4 + i]  = ld32(key + 4 * i);
    for (i = 0; i < 4; i++) s[12 + i] = ld32(nonce + 4 * i);
    for (i = 0; i < 10; i++) {
        QR(s[0],s[4],s[8], s[12]); QR(s[1],s[5],s[9], s[13]);
        QR(s[2],s[6],s[10],s[14]); QR(s[3],s[7],s[11],s[15]);
        QR(s[0],s[5],s[10],s[15]); QR(s[1],s[6],s[11],s[12]);
        QR(s[2],s[7],s[8], s[13]); QR(s[3],s[4],s[9], s[14]);
    }
    for (i = 0; i < 4; i++) st32(out + 4 * i,      s[i]);
    for (i = 0; i < 4; i++) st32(out + 16 + 4 * i, s[12 + i]);
    determ_secure_zero(s, sizeof s);
}

/* Derive (subkey, 96-bit nonce) per the XChaCha construction:
 *   subkey = HChaCha20(key, N24[0:16]);  nonce12 = 0x00000000 || N24[16:24]. */
static void derive(const uint8_t key[32], const uint8_t nonce24[24],
                   uint8_t subkey[32], uint8_t nonce12[12]) {
    determ_hchacha20(subkey, key, nonce24);
    nonce12[0] = nonce12[1] = nonce12[2] = nonce12[3] = 0;
    memcpy(nonce12 + 4, nonce24 + 16, 8);
}

int determ_xchacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[24],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *pt, size_t ptlen,
                                      uint8_t *ct, uint8_t tag[16]) {
    uint8_t subkey[32], n12[12]; int rc;
    derive(key, nonce, subkey, n12);
    rc = determ_chacha20_poly1305_encrypt(subkey, n12, aad, aadlen, pt, ptlen, ct, tag);
    determ_secure_zero(subkey, sizeof subkey);
    return rc;
}

int determ_xchacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[24],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t tag[16], uint8_t *pt) {
    uint8_t subkey[32], n12[12]; int rc;
    derive(key, nonce, subkey, n12);
    rc = determ_chacha20_poly1305_decrypt(subkey, n12, aad, aadlen, ct, ctlen, tag, pt);
    determ_secure_zero(subkey, sizeof subkey);
    return rc;
}
