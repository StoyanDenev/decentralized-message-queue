/* NC-8 encrypted-note delivery — ephemeral-static ECIES over P-256.
 * See include/determ/crypto/enote/enote.h for the construction + rationale.
 * Composition only: P-256 ECDH (determ_p256_*) + HKDF-SHA256 (determ_hkdf_sha256)
 * + ChaCha20-Poly1305 (determ_chacha20_poly1305_*). No new primitive. */
#include <determ/crypto/enote/enote.h>
#include <determ/crypto/p256/p256.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/chacha20/chacha20.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

/* Domain-separation tag = HKDF salt. No trailing NUL is hashed. */
static const uint8_t ENOTE_DST[] = "determ-enote-v1";

/* z ‖ K‖N derivation shared by seal/open. `eph33`/`recip33` are the two
 * compressed pubkeys bound into the info string; `shared_x` is the ECDH x.
 * Writes 44 bytes (K(32)‖N(12)) into `ks`. Returns 0 / -1. */
static int enote_kdf(const uint8_t shared_x[32],
                     const uint8_t eph33[33], const uint8_t recip33[33],
                     uint8_t ks[44]) {
    uint8_t info[DETERM_ENOTE_EPH_LEN * 2]; /* E33 ‖ R33 */
    memcpy(info, eph33, DETERM_ENOTE_EPH_LEN);
    memcpy(info + DETERM_ENOTE_EPH_LEN, recip33, DETERM_ENOTE_EPH_LEN);
    return determ_hkdf_sha256(ENOTE_DST, sizeof(ENOTE_DST) - 1,
                              shared_x, 32,
                              info, sizeof(info),
                              ks, 44);
}

int determ_enote_seal(const uint8_t recipient_pub[33],
                      const uint8_t *pt, size_t ptlen,
                      const uint8_t eph_sk[32],
                      uint8_t *out, size_t *out_len) {
    if (!recipient_pub || !eph_sk || !out || !out_len) return -1;
    if (ptlen && !pt) return -1;

    uint8_t r65[65], e65[65], z65[65], e33[33], ks[44];
    int rc = -1;

    /* Validate + expand the recipient point; derive the ephemeral pubkey. */
    if (determ_p256_point_decompress(r65, recipient_pub) != 0) return -1;
    if (determ_p256_point_check(r65) != 0)                     return -1;
    if (determ_p256_base_mul(e65, eph_sk) != 0)                return -1; /* E = e·G, rejects bad e */
    if (determ_p256_point_compress(e33, e65) != 0)             return -1;

    /* ECDH: Z = e·R ; shared secret = Z.x (z65[1..33]). */
    if (determ_p256_point_mul(z65, eph_sk, r65) != 0)          goto done;
    if (enote_kdf(z65 + 1, e33, recipient_pub, ks) != 0)       goto done;

    /* out = E33 ‖ ct ‖ tag. AAD = E33 binds the ephemeral pub into the tag. */
    memcpy(out, e33, DETERM_ENOTE_EPH_LEN);
    if (determ_chacha20_poly1305_encrypt(ks, ks + 32,
                                         e33, DETERM_ENOTE_EPH_LEN,
                                         pt, ptlen,
                                         out + DETERM_ENOTE_EPH_LEN,
                                         out + DETERM_ENOTE_EPH_LEN + ptlen) != 0)
        goto done;
    *out_len = ptlen + DETERM_ENOTE_OVERHEAD;
    rc = 0;
done:
    determ_secure_zero(z65, sizeof z65);
    determ_secure_zero(ks,  sizeof ks);
    return rc;
}

int determ_enote_open(const uint8_t recipient_sk[32],
                      const uint8_t *in, size_t in_len,
                      uint8_t *pt_out, size_t *pt_len) {
    if (!recipient_sk || !in || !pt_out || !pt_len) return -1;
    if (in_len < DETERM_ENOTE_OVERHEAD)             return -1;

    const size_t ctlen = in_len - DETERM_ENOTE_OVERHEAD;
    const uint8_t *eph33 = in;
    const uint8_t *ct    = in + DETERM_ENOTE_EPH_LEN;
    const uint8_t *tag   = in + DETERM_ENOTE_EPH_LEN + ctlen;

    uint8_t e65[65], z65[65], r65[65], recip33[33], ks[44];
    int rc = -1;

    /* Recover our own compressed pubkey R33 (bound into the KDF info) and the
     * ECDH shared secret Z = r·E. */
    if (determ_p256_point_decompress(e65, eph33) != 0)   return -1; /* bad ephemeral point ⇒ not ours */
    if (determ_p256_base_mul(r65, recipient_sk) != 0)    return -1; /* R = r·G, rejects bad sk */
    if (determ_p256_point_compress(recip33, r65) != 0)   return -1;
    if (determ_p256_point_mul(z65, recipient_sk, e65) != 0) goto done;
    if (enote_kdf(z65 + 1, eph33, recip33, ks) != 0)        goto done;

    /* A verifying tag both authenticates AND signals ownership. On failure
     * decrypt writes nothing (pt_out stays untouched). */
    if (determ_chacha20_poly1305_decrypt(ks, ks + 32,
                                         eph33, DETERM_ENOTE_EPH_LEN,
                                         ct, ctlen, tag, pt_out) != 0)
        goto done;
    *pt_len = ctlen;
    rc = 0;
done:
    determ_secure_zero(z65, sizeof z65);
    determ_secure_zero(ks,  sizeof ks);
    return rc;
}
