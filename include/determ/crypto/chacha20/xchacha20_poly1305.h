/* Determ C99-native XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) + HChaCha20.
 *
 * The extended-nonce (192-bit) AEAD of the ChaCha20-Poly1305 family
 * (CRYPTO-C99-SPEC §3.4): a 24-byte random nonce removes the counter/nonce
 * management burden of the 96-bit IETF construction. Defined as
 *   XChaCha20-Poly1305(key, N24, aad, pt)
 *     = ChaCha20-Poly1305-IETF( HChaCha20(key, N24[0:16]),
 *                               0x00000000 || N24[16:24], aad, pt )
 * so it is built directly on the already-OpenSSL-validated C99 ChaCha20-Poly1305
 * (src/crypto/chacha20/) plus the HChaCha20 subkey-derivation below. No libsodium.
 *
 * HChaCha20 is constant-time by construction (the ChaCha ARX permutation — no
 * S-box / table / secret-dependent branch); the derived subkey is zeroized after
 * each AEAD call. Validated by `determ test-xchacha-c99`: HChaCha20 vs the
 * draft §2.2.1 KAT, and the full AEAD byte-equal vs OpenSSL's inner
 * ChaCha20-Poly1305 over the derived (subkey, nonce) — the §Q9 gate.
 */
#ifndef DETERM_CRYPTO_XCHACHA20_POLY1305_H
#define DETERM_CRYPTO_XCHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HChaCha20 (draft §2.2): out[32] = the 256-bit subkey derived from `key[32]` and
 * the 16-byte `nonce` via the ChaCha20 permutation (no feed-forward). */
void determ_hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16]);

/* XChaCha20-Poly1305 AEAD. key=32, nonce=24, tag=16. encrypt writes `ptlen`
 * ciphertext bytes to `ct` + the tag and returns 0 (or -1 on the inner AEAD's
 * allocation/length failure). decrypt verifies the tag (constant-time) and returns
 * 0 on success (writing `ctlen` plaintext bytes to `pt`) or -1 on authentication
 * failure (writing nothing). The derived subkey is zeroized before return. */
int determ_xchacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[24],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *pt, size_t ptlen,
                                      uint8_t *ct, uint8_t tag[16]);
int determ_xchacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[24],
                                      const uint8_t *aad, size_t aadlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t tag[16], uint8_t *pt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_XCHACHA20_POLY1305_H */
