/* Determ C99-native ML-DSA (FIPS 204) Sign_internal (Alg 7) + Verify_internal
 * (Alg 8). Fiat-Shamir with aborts over the increment 1-7 building blocks;
 * canonical Dilithium construction, pinned byte-for-byte against the NIST ACVP
 * sigGen/sigVer KATs. See include/determ/crypto/mldsa/sign.h + the module README. */
#include <determ/crypto/mldsa/sign.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/mldsa/polyvec.h>
#include <determ/crypto/mldsa/poly.h>
#include <determ/crypto/mldsa/ntt.h>
#include <determ/crypto/mldsa/rounding.h>
#include <determ/crypto/mldsa/pack.h>
#include <determ/crypto/mldsa/sample.h>
#include <determ/crypto/sha3/sha3.h>
#include <determ/crypto/secure_zero.h>

#define N    DETERM_MLDSA_N
#define Q    DETERM_MLDSA_Q
#define D    DETERM_MLDSA_D
#define KMAX 8
#define LMAX 7
#define SIGN_MAX_ITERS 1000   /* safety cap; the loop terminates w.h.p. in a few */

static size_t eta_poly_bytes(int eta) { return (eta == 2) ? 96u : 128u; }
static size_t z_poly_bytes(int32_t g1) { return (g1 == DETERM_MLDSA_GAMMA1_17) ? 576u : 640u; }
static size_t w1_poly_bytes(int32_t g2) { return (g2 == DETERM_MLDSA_GAMMA2_88) ? 192u : 128u; }

size_t determ_mldsa_sig_bytes(const determ_mldsa_params* p) {
    if (!p) return 0;
    return (size_t)(p->lambda / 4) + (size_t)p->l * z_poly_bytes(p->gamma1)
         + (size_t)(p->omega + p->k);
}

/* Centered representative of a (mod q) in (-q/2, q/2]. */
static int32_t center(int32_t a) {
    a %= Q; if (a < 0) a += Q;
    if (a > Q / 2) a -= Q;
    return a;
}
/* HighBits(a) via decompose (a reduced to canonical [0,q) first). */
static int32_t hi(int32_t a, int32_t g2) { int32_t lo, x = a % Q; if (x < 0) x += Q; return determ_mldsa_decompose(x, &lo, g2); }
/* ||v||_inf over `len` polys, coefficients centered — returns 1 if any |coeff| >= bound. */
static int chknorm(const int32_t v[][256], int len, int32_t bound) {
    int i, c;
    for (i = 0; i < len; i++)
        for (c = 0; c < N; c++) {
            int32_t t = center(v[i][c]); if (t < 0) t = -t;
            if (t >= bound) return 1;
        }
    return 0;
}

size_t determ_mldsa_format_message(uint8_t* out, const uint8_t* ctx, size_t ctxlen,
                                   const uint8_t* msg, size_t mlen) {
    size_t i;
    if (ctxlen > 255) return 0;
    out[0] = 0x00; out[1] = (uint8_t)ctxlen;
    for (i = 0; i < ctxlen; i++) out[2 + i] = ctx[i];
    for (i = 0; i < mlen; i++) out[2 + ctxlen + i] = msg[i];
    return 2 + ctxlen + mlen;
}

/* SHAKE256(a || b || c, outlen); any of a/b/c may be empty (len 0). */
static void h3(uint8_t* out, size_t outlen,
               const uint8_t* a, size_t la, const uint8_t* b, size_t lb,
               const uint8_t* c, size_t lc) {
    determ_keccak_ctx ctx; determ_shake256_init(&ctx);
    if (la) determ_keccak_absorb(&ctx, a, la);
    if (lb) determ_keccak_absorb(&ctx, b, lb);
    if (lc) determ_keccak_absorb(&ctx, c, lc);
    determ_keccak_finalize(&ctx);
    determ_keccak_squeeze(&ctx, out, outlen);
    determ_secure_zero(&ctx, sizeof ctx);
}

int determ_mldsa_sign(const determ_mldsa_params* p, const uint8_t* sk,
                      const uint8_t* mprime, size_t mlen,
                      const uint8_t rnd[32], uint8_t* sig) {
    int k, l, eta; int32_t g1, g2; int tau, omega, beta, lam4;
    uint8_t rho[32], K[32], tr[64], mu[64], rhopp[64];
    static const uint8_t ZERO32[32] = {0};
    int32_t mat[KMAX * LMAX][256];
    int32_t s1[LMAX][256], s2[KMAX][256], t0[KMAX][256];   /* NTT'd in place */
    int32_t y[LMAX][256], yh[LMAX][256], w[KMAX][256], w1[KMAX][256];
    int32_t cp[256], ch[256], cs1[LMAX][256], cs2[KMAX][256], ct0[KMAX][256];
    int32_t z[LMAX][256], zc[LMAX][256], hint[KMAX][256], r0[KMAX][256];
    uint8_t ctil[64];
    uint8_t w1buf[KMAX * 192];
    int i, j, c, it; size_t off, epb, wpb;

    if (!p) return 1;
    k = p->k; l = p->l; eta = p->eta; g1 = p->gamma1; g2 = p->gamma2;
    tau = p->tau; omega = p->omega; beta = p->tau * p->eta; lam4 = p->lambda / 4;
    if (k < 1 || k > KMAX || l < 1 || l > LMAX) return 1;
    if (rnd == 0) rnd = ZERO32;

    /* skDecode: rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0. */
    for (c = 0; c < 32; c++) rho[c] = sk[c];
    for (c = 0; c < 32; c++) K[c]   = sk[32 + c];
    for (c = 0; c < 64; c++) tr[c]  = sk[64 + c];
    off = 128; epb = eta_poly_bytes(eta);
    for (i = 0; i < l; i++) { determ_mldsa_unpack_eta(s1[i], sk + off, eta); off += epb; }
    for (i = 0; i < k; i++) { determ_mldsa_unpack_eta(s2[i], sk + off, eta); off += epb; }
    for (i = 0; i < k; i++) { determ_mldsa_unpack_t0(t0[i], sk + off);       off += 416; }

    /* mu = H(tr ‖ M', 64);  rho'' = H(K ‖ rnd ‖ mu, 64). */
    h3(mu, 64, tr, 64, mprime, mlen, 0, 0);
    h3(rhopp, 64, K, 32, rnd, 32, mu, 64);

    /* Â = ExpandA(rho); ŝ1 = NTT(s1); ŝ2 = NTT(s2); t̂0 = NTT(t0). */
    determ_mldsa_expand_a(mat, rho, k, l);
    determ_mldsa_polyvec_ntt(s1, l);
    determ_mldsa_polyvec_ntt(s2, k);
    determ_mldsa_polyvec_ntt(t0, k);

    wpb = w1_poly_bytes(g2);
    for (it = 0; it < SIGN_MAX_ITERS; it++) {
        /* y = ExpandMask(rho'', it);  w = invNTT(Â ∘ NTT(y)). */
        determ_mldsa_expand_mask(y, rhopp, it, l, g1);
        for (i = 0; i < l; i++) { for (c = 0; c < N; c++) yh[i][c] = y[i][c]; }
        determ_mldsa_polyvec_ntt(yh, l);
        determ_mldsa_polyvec_matrix_pointwise(w, mat, yh, k, l);
        determ_mldsa_polyvec_reduce(w, k);
        determ_mldsa_polyvec_invntt_tomont(w, k);
        /* w1 = HighBits(w). */
        for (i = 0; i < k; i++) { int32_t lo; for (c = 0; c < N; c++) {
            int32_t a = w[i][c] % Q; if (a < 0) a += Q;
            w1[i][c] = determ_mldsa_decompose(a, &lo, g2); } }
        /* c̃ = H(mu ‖ w1Encode(w1)); c = SampleInBall(c̃). */
        for (i = 0; i < k; i++) determ_mldsa_pack_w1(w1buf + (size_t)i * wpb, w1[i], g2);
        h3(ctil, (size_t)lam4, mu, 64, w1buf, (size_t)k * wpb, 0, 0);
        determ_mldsa_sample_in_ball(cp, ctil, (size_t)lam4, tau);
        for (c = 0; c < N; c++) ch[c] = cp[c];
        determ_mldsa_ntt(ch);
        /* z = y + c·s1; r0 = LowBits(w - c·s2). */
        for (j = 0; j < l; j++) { determ_mldsa_poly_pointwise_montgomery(cs1[j], ch, s1[j]);
                                  determ_mldsa_invntt_tomont(cs1[j]); }
        for (j = 0; j < k; j++) { determ_mldsa_poly_pointwise_montgomery(cs2[j], ch, s2[j]);
                                  determ_mldsa_invntt_tomont(cs2[j]); }
        for (i = 0; i < l; i++) { for (c = 0; c < N; c++) z[i][c] = y[i][c] + cs1[i][c];
                                  for (c = 0; c < N; c++) zc[i][c] = center(z[i][c]); }
        for (i = 0; i < k; i++) { int32_t lo; for (c = 0; c < N; c++) {
            int32_t a = (w[i][c] - cs2[i][c]) % Q; if (a < 0) a += Q;
            determ_mldsa_decompose(a, &lo, g2); r0[i][c] = lo; } }
        /* Reject on the z / r0 norm bounds. */
        if (chknorm(zc, l, g1 - beta)) continue;
        if (chknorm(r0, k, g2 - beta)) continue;
        /* h = MakeHint(-c·t0, w - c·s2 + c·t0);  reject on ct0 norm / #hints. */
        for (j = 0; j < k; j++) { determ_mldsa_poly_pointwise_montgomery(ct0[j], ch, t0[j]);
                                  determ_mldsa_invntt_tomont(ct0[j]); }
        if (chknorm(ct0, k, g2)) continue;
        { int ones = 0;
          for (i = 0; i < k; i++) for (c = 0; c < N; c++) {
              int32_t rr = w[i][c] - cs2[i][c] + ct0[i][c];   /* r = r+z + <<ct0>> */
              int32_t rz = w[i][c] - cs2[i][c];                /* r+z = w - cs2 */
              hint[i][c] = (hi(rr, g2) != hi(rz, g2)) ? 1 : 0;
              ones += hint[i][c];
          }
          if (ones > omega) continue;
        }
        /* sigEncode(c̃, z mod± q, h). */
        for (c = 0; c < lam4; c++) sig[c] = ctil[c];
        off = (size_t)lam4;
        for (i = 0; i < l; i++) { determ_mldsa_pack_z(sig + off, zc[i], g1); off += z_poly_bytes(g1); }
        { size_t base = off; int idx = 0;
          for (c = 0; c < omega + k; c++) sig[base + c] = 0;
          for (i = 0; i < k; i++) {
              for (c = 0; c < N; c++) if (hint[i][c]) sig[base + idx++] = (uint8_t)c;
              sig[base + omega + i] = (uint8_t)idx;
          }
        }
        determ_secure_zero(s1, sizeof s1); determ_secure_zero(s2, sizeof s2);
        determ_secure_zero(t0, sizeof t0); determ_secure_zero(K, sizeof K);
        determ_secure_zero(rhopp, sizeof rhopp);
        return 0;
    }
    return 2;   /* safety cap hit — not expected */
}

int determ_mldsa_verify(const determ_mldsa_params* p, const uint8_t* pk,
                        const uint8_t* mprime, size_t mlen, const uint8_t* sig) {
    int k, l; int32_t g1, g2; int tau, omega, beta, lam4;
    uint8_t rho[32], tr[64], mu[64], ctil[64], ctil2[64];
    int32_t mat[KMAX * LMAX][256];
    int32_t t1[KMAX][256], z[LMAX][256], zh[LMAX][256], hint[KMAX][256];
    int32_t cp[256], ch[256], w[KMAX][256], w1[KMAX][256];
    uint8_t w1buf[KMAX * 192];
    int i, j, c; size_t off, wpb, zpb;

    if (!p) return 0;
    k = p->k; l = p->l; g1 = p->gamma1; g2 = p->gamma2;
    tau = p->tau; omega = p->omega; beta = p->tau * p->eta; lam4 = p->lambda / 4;
    if (k < 1 || k > KMAX || l < 1 || l > LMAX) return 0;
    zpb = z_poly_bytes(g1); wpb = w1_poly_bytes(g2);

    /* pkDecode + sigDecode. */
    for (c = 0; c < 32; c++) rho[c] = pk[c];
    for (i = 0; i < k; i++) determ_mldsa_unpack_t1(t1[i], pk + 32 + (size_t)i * 320u);
    for (c = 0; c < lam4; c++) ctil[c] = sig[c];
    off = (size_t)lam4;
    for (i = 0; i < l; i++) { determ_mldsa_unpack_z(z[i], sig + off, g1); off += zpb; }
    /* HintBitUnpack (Alg 21) with the three malformed-hint rejections. */
    { const uint8_t* hb = sig + off; int idx = 0;
      for (i = 0; i < k; i++) for (c = 0; c < N; c++) hint[i][c] = 0;
      for (i = 0; i < k; i++) {
          int end = hb[omega + i];
          if (end < idx || end > omega) return 0;
          for (j = idx; j < end; j++) {
              if (j > idx && hb[j] <= hb[j - 1]) return 0;   /* strictly increasing */
              hint[i][hb[j]] = 1;
          }
          idx = end;
      }
      for (j = idx; j < omega; j++) if (hb[j] != 0) return 0; /* trailing zero pad */
    }
    /* ||z||_inf < gamma1 - beta (reject if >=). */
    if (chknorm(z, l, g1 - beta)) return 0;

    /* mu = H(H(pk,64) ‖ M', 64). */
    h3(tr, 64, pk, determ_mldsa_pk_bytes(p), 0, 0, 0, 0);
    h3(mu, 64, tr, 64, mprime, mlen, 0, 0);
    /* c = SampleInBall(c̃). */
    determ_mldsa_sample_in_ball(cp, ctil, (size_t)lam4, tau);
    for (c = 0; c < N; c++) ch[c] = cp[c];
    determ_mldsa_ntt(ch);
    /* w'Approx = invNTT(Â ∘ NTT(z) − ĉ ∘ NTT(t1·2^d)); w1' = UseHint(h, w'Approx). */
    determ_mldsa_expand_a(mat, rho, k, l);
    for (i = 0; i < l; i++) { for (c = 0; c < N; c++) zh[i][c] = z[i][c]; }
    determ_mldsa_polyvec_ntt(zh, l);
    { int32_t t1h[KMAX][256], acc[256], tmp[256];
      for (i = 0; i < k; i++) { for (c = 0; c < N; c++) t1h[i][c] = t1[i][c] << D;
                                determ_mldsa_ntt(t1h[i]); }
      for (i = 0; i < k; i++) {
          for (c = 0; c < N; c++) acc[c] = 0;
          for (j = 0; j < l; j++) { determ_mldsa_poly_pointwise_montgomery(tmp, mat[i * l + j], zh[j]);
                                    determ_mldsa_poly_add(acc, acc, tmp); }
          determ_mldsa_poly_pointwise_montgomery(tmp, ch, t1h[i]);
          determ_mldsa_poly_sub(acc, acc, tmp);
          determ_mldsa_poly_reduce(acc);
          determ_mldsa_invntt_tomont(acc);
          for (c = 0; c < N; c++) w[i][c] = acc[c];
      }
    }
    for (i = 0; i < k; i++) { int32_t a; for (c = 0; c < N; c++) {
        a = w[i][c] % Q; if (a < 0) a += Q;
        w1[i][c] = determ_mldsa_use_hint(a, (unsigned)hint[i][c], g2); } }
    /* c̃' = H(mu ‖ w1Encode(w1')); accept iff c̃ == c̃'. */
    for (i = 0; i < k; i++) determ_mldsa_pack_w1(w1buf + (size_t)i * wpb, w1[i], g2);
    h3(ctil2, (size_t)lam4, mu, 64, w1buf, (size_t)k * wpb, 0, 0);
    for (c = 0; c < lam4; c++) if (ctil[c] != ctil2[c]) return 0;
    return 1;
}
