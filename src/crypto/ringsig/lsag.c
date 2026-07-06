// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// LSAG linkable ring signature over NIST P-256 — CRYPTO-C99-SPEC.md §3.23. See
// lsag.h. Ported from tools/verify_lsag.py (python-prove-first: sign/verify +
// linkable key image + tamper/wrong-msg/wrong-image/wrong-ring reject passed).
// Pure composition over the PUBLIC §3.8c/§3.9b P-256 API (base_mul / point_mul /
// point_add / hash_to_curve / hash_to_scalar / compress) + streaming SHA-256; the
// only local arithmetic is a 256-bit sub-mod-n / compare over the exported curve
// order. NOT constant-time (branches on secret nonces/index — owner-gated).
#include "determ/crypto/ringsig/lsag.h"
#include "determ/crypto/p256/p256.h"
#include "determ/crypto/sha2/sha2.h"

#include <string.h>
#include <stdlib.h>

#define PT 65   /* SEC1 uncompressed point */
#define CP 33   /* SEC1 compressed point   */
#define SC 32   /* scalar                  */

static const char DOM[]       = "DETERM-LSAG-P256-v1";
static const char KI_DST[]    = "DETERM-LSAG-P256-keyimage-v1";
static const char CHAL_DST[]  = "DETERM-LSAG-P256-challenge-v1";
static const char NONCE_DST[] = "DETERM-LSAG-P256-nonce-v1";

static void get_n(uint8_t n[SC]) {
    uint8_t p[SC], b[SC], gx[SC], gy[SC];
    determ_p256_params(p, n, b, gx, gy);
}
static int is_zero(const uint8_t s[SC]) {
    for (int i = 0; i < SC; i++) if (s[i]) return 0;
    return 1;
}
/* a >= n ? (big-endian) */
static int sc_ge(const uint8_t a[SC], const uint8_t n[SC]) {
    for (int i = 0; i < SC; i++) if (a[i] != n[i]) return a[i] > n[i];
    return 1;
}
/* out = (a - b) mod n = a + (n - b) mod n, for a, b in [0, n). */
static void sub_mod_n(uint8_t out[SC], const uint8_t a[SC], const uint8_t b[SC]) {
    uint8_t n[SC], nb[SC], t[SC];
    get_n(n);
    int borrow = 0;
    for (int i = SC - 1; i >= 0; i--) { int d = (int)n[i] - (int)b[i] - borrow; if (d < 0) { d += 256; borrow = 1; } else borrow = 0; nb[i] = (uint8_t)d; }
    int carry = 0;
    for (int i = SC - 1; i >= 0; i--) { int s = (int)a[i] + (int)nb[i] + carry; t[i] = (uint8_t)(s & 0xff); carry = s >> 8; }
    int ge;
    if (carry) ge = 1;
    else { int cmp = 0; for (int i = 0; i < SC; i++) { if (t[i] != n[i]) { cmp = (t[i] > n[i]) ? 1 : -1; break; } } ge = (cmp >= 0); }
    if (ge) { int bo = 0; for (int i = SC - 1; i >= 0; i--) { int d = (int)t[i] - (int)n[i] - bo; if (d < 0) { d += 256; bo = 1; } else bo = 0; out[i] = (uint8_t)d; } }
    else memcpy(out, t, SC);
}

/* prefix = SHA256(DOM ‖ n_be4 ‖ ring ‖ I ‖ msg) — binds ring + image + message. */
static void lsag_prefix(uint8_t out[SC], const uint8_t *ring33, size_t n,
                        const uint8_t I33[CP], const uint8_t *msg, size_t msglen) {
    determ_sha256_ctx ctx;
    determ_sha256_init(&ctx);
    determ_sha256_update(&ctx, (const uint8_t *)DOM, sizeof(DOM) - 1);
    uint8_t nb[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    determ_sha256_update(&ctx, nb, 4);
    determ_sha256_update(&ctx, ring33, n * CP);
    determ_sha256_update(&ctx, I33, CP);
    if (msglen) determ_sha256_update(&ctx, msg, msglen);
    determ_sha256_final(&ctx, out);
}

/* c = hash_to_scalar(prefix ‖ compress(L) ‖ compress(R)). */
static int lsag_chal(uint8_t out[SC], const uint8_t pre[SC],
                     const uint8_t L65[PT], const uint8_t R65[PT]) {
    uint8_t buf[SC + CP + CP], Lc[CP], Rc[CP];
    if (determ_p256_point_compress(Lc, L65) != 0) return -1;
    if (determ_p256_point_compress(Rc, R65) != 0) return -1;
    memcpy(buf, pre, SC);
    memcpy(buf + SC, Lc, CP);
    memcpy(buf + SC + CP, Rc, CP);
    return determ_p256_hash_to_scalar(out, buf, sizeof(buf),
                                      (const uint8_t *)CHAL_DST, sizeof(CHAL_DST) - 1);
}

size_t determ_lsag_sig_len(size_t n) { return n ? SC * (n + 1) : 0; }

int determ_lsag_key_image(uint8_t out33[CP], const uint8_t x[SC], const uint8_t P33[CP]) {
    if (out33 == 0 || x == 0 || P33 == 0) return -1;
    uint8_t chk[PT], Hp[PT], I65[PT];
    if (determ_p256_point_decompress(chk, P33) != 0) return -1;   /* validate P on curve */
    if (determ_p256_hash_to_curve(Hp, P33, CP, (const uint8_t *)KI_DST, sizeof(KI_DST) - 1) != 0) return -1;
    if (determ_p256_point_mul(I65, x, Hp) != 0) return -1;
    return determ_p256_point_compress(out33, I65);
}

int determ_lsag_sign(uint8_t *sig, size_t sig_len, uint8_t image_out33[CP],
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *ring33, size_t n,
                     const uint8_t x[SC], size_t index) {
    if (sig == 0 || image_out33 == 0 || ring33 == 0 || x == 0) return -1;
    if (n == 0 || index >= n || sig_len != determ_lsag_sig_len(n)) return -1;

    int rc = -1;
    uint8_t *Hp = (uint8_t *)malloc(n * PT);
    uint8_t *c  = (uint8_t *)calloc(n, SC);
    uint8_t *s  = (uint8_t *)calloc(n, SC);
    if (Hp == 0 || c == 0 || s == 0) goto done;

    for (size_t i = 0; i < n; i++) {
        uint8_t chk[PT];
        if (determ_p256_point_decompress(chk, ring33 + i * CP) != 0) goto done;
        if (determ_p256_hash_to_curve(Hp + i * PT, ring33 + i * CP, CP,
                                      (const uint8_t *)KI_DST, sizeof(KI_DST) - 1) != 0) goto done;
    }

    uint8_t I65[PT], I33[CP];
    if (determ_p256_point_mul(I65, x, Hp + index * PT) != 0) goto done;
    if (determ_p256_point_compress(I33, I65) != 0) goto done;
    memcpy(image_out33, I33, CP);

    uint8_t pre[SC];
    lsag_prefix(pre, ring33, n, I33, msg, msglen);

    /* alpha = hash_to_scalar("alpha" ‖ x ‖ pre); alpha==0 -> 1 (mirrors python). */
    uint8_t alpha[SC];
    {
        uint8_t buf[5 + SC + SC];
        memcpy(buf, "alpha", 5);
        memcpy(buf + 5, x, SC);
        memcpy(buf + 5 + SC, pre, SC);
        if (determ_p256_hash_to_scalar(alpha, buf, sizeof(buf),
                                       (const uint8_t *)NONCE_DST, sizeof(NONCE_DST) - 1) != 0) goto done;
        if (is_zero(alpha)) alpha[SC - 1] = 1;
    }
    /* c[(index+1) mod n] = chal(pre, alpha*G, alpha*Hp[index]). */
    {
        uint8_t L[PT], R[PT];
        if (determ_p256_base_mul(L, alpha) != 0) goto done;
        if (determ_p256_point_mul(R, alpha, Hp + index * PT) != 0) goto done;
        if (lsag_chal(c + ((index + 1) % n) * SC, pre, L, R) != 0) goto done;
    }
    /* Decoy loop around the ring: pick s_i, derive the next challenge. */
    for (size_t step = 1; step < n; step++) {
        size_t i = (index + step) % n;
        uint8_t buf[1 + SC + SC + 4];
        buf[0] = 's';
        memcpy(buf + 1, x, SC);
        memcpy(buf + 1 + SC, pre, SC);
        buf[1 + 2 * SC + 0] = (uint8_t)(i >> 24);
        buf[1 + 2 * SC + 1] = (uint8_t)(i >> 16);
        buf[1 + 2 * SC + 2] = (uint8_t)(i >> 8);
        buf[1 + 2 * SC + 3] = (uint8_t)i;
        if (determ_p256_hash_to_scalar(s + i * SC, buf, sizeof(buf),
                                       (const uint8_t *)NONCE_DST, sizeof(NONCE_DST) - 1) != 0) goto done;
        if (is_zero(s + i * SC)) s[i * SC + SC - 1] = 1;

        uint8_t Pi[PT], sG[PT], cP[PT], sH[PT], cI[PT], Li[PT], Ri[PT];
        if (determ_p256_point_decompress(Pi, ring33 + i * CP) != 0) goto done;
        if (determ_p256_base_mul(sG, s + i * SC) != 0) goto done;
        if (determ_p256_point_mul(cP, c + i * SC, Pi) != 0) goto done;
        if (determ_p256_point_add(Li, sG, cP) != 0) goto done;
        if (determ_p256_point_mul(sH, s + i * SC, Hp + i * PT) != 0) goto done;
        if (determ_p256_point_mul(cI, c + i * SC, I65) != 0) goto done;
        if (determ_p256_point_add(Ri, sH, cI) != 0) goto done;
        if (lsag_chal(c + ((i + 1) % n) * SC, pre, Li, Ri) != 0) goto done;
    }
    /* Close the ring at the real index: s[index] = alpha - c[index]*x mod n. */
    {
        uint8_t cx[SC];
        if (determ_p256_scalar_mul_mod_n(cx, c + index * SC, x) != 0) goto done;
        sub_mod_n(s + index * SC, alpha, cx);
    }
    memcpy(sig, c, SC);
    for (size_t i = 0; i < n; i++) memcpy(sig + SC + i * SC, s + i * SC, SC);
    rc = 0;
done:
    free(Hp); free(c); free(s);
    return rc;
}

int determ_lsag_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t *ring33, size_t n,
                       const uint8_t I33[CP], const uint8_t *sig, size_t sig_len) {
    if (ring33 == 0 || I33 == 0 || sig == 0 || n == 0) return -1;
    if (sig_len != determ_lsag_sig_len(n)) return -1;

    int rc = -1;
    uint8_t *Hp = (uint8_t *)malloc(n * PT);
    if (Hp == 0) goto done;

    uint8_t I65[PT];
    if (determ_p256_point_decompress(I65, I33) != 0) goto done;   /* image on curve */

    uint8_t n_ord[SC];
    get_n(n_ord);
    if (is_zero(sig) || sc_ge(sig, n_ord)) goto done;             /* c0 in [1, n) */
    for (size_t i = 0; i < n; i++) {
        const uint8_t *si = sig + SC + i * SC;
        if (is_zero(si) || sc_ge(si, n_ord)) goto done;           /* s_i in [1, n) */
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t chk[PT];
        if (determ_p256_point_decompress(chk, ring33 + i * CP) != 0) goto done;
        if (determ_p256_hash_to_curve(Hp + i * PT, ring33 + i * CP, CP,
                                      (const uint8_t *)KI_DST, sizeof(KI_DST) - 1) != 0) goto done;
    }

    uint8_t pre[SC];
    lsag_prefix(pre, ring33, n, I33, msg, msglen);

    uint8_t c[SC];
    memcpy(c, sig, SC);   /* c = c0 */
    for (size_t i = 0; i < n; i++) {
        const uint8_t *si = sig + SC + i * SC;
        uint8_t Pi[PT], sG[PT], cP[PT], sH[PT], cI[PT], Li[PT], Ri[PT];
        if (determ_p256_point_decompress(Pi, ring33 + i * CP) != 0) goto done;
        if (determ_p256_base_mul(sG, si) != 0) goto done;
        if (determ_p256_point_mul(cP, c, Pi) != 0) goto done;
        if (determ_p256_point_add(Li, sG, cP) != 0) goto done;
        if (determ_p256_point_mul(sH, si, Hp + i * PT) != 0) goto done;
        if (determ_p256_point_mul(cI, c, I65) != 0) goto done;
        if (determ_p256_point_add(Ri, sH, cI) != 0) goto done;
        if (lsag_chal(c, pre, Li, Ri) != 0) goto done;   /* c = next */
    }
    rc = (memcmp(c, sig, SC) == 0) ? 0 : -1;              /* closure: recomputed c == c0 */
done:
    free(Hp);
    return rc;
}
