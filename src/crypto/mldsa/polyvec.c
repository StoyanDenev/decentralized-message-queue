/* Determ C99-native ML-DSA (FIPS 204) matrix / vector layer.
 * Canonical Dilithium reference construction (polyvec.c + poly_uniform*); a thin
 * composition over the already-gated samplers + per-poly ring ops, with the
 * dimensions (k,l), eta, and gamma1 as runtime arguments so one layer serves
 * ML-DSA-44/65/87. See include/determ/crypto/mldsa/polyvec.h + the module README. */
#include <determ/crypto/mldsa/polyvec.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/mldsa/sample.h>
#include <determ/crypto/mldsa/poly.h>
#include <determ/crypto/mldsa/ntt.h>

#define N DETERM_MLDSA_N

/* Dimension bounds — the largest parameter set is ML-DSA-87 with (k,l)=(8,7). */
#define MLDSA_KMAX 8
#define MLDSA_LMAX 7

/* Little-endian 2-byte nonce, as the reference poly_uniform_eta / _gamma1 pack it. */
static void nonce_le16(uint8_t out[2], int nonce) {
    out[0] = (uint8_t)(nonce & 0xff);
    out[1] = (uint8_t)((nonce >> 8) & 0xff);
}

void determ_mldsa_expand_a(int32_t mat[][256], const uint8_t rho[32], int k, int l) {
    uint8_t seed[34];
    int i, j, t;
    if (k < 1 || k > MLDSA_KMAX || l < 1 || l > MLDSA_LMAX) return;
    for (t = 0; t < 32; t++) seed[t] = rho[t];            /* seed[0..31] = rho */
    for (i = 0; i < k; i++) {
        for (j = 0; j < l; j++) {
            /* seed = rho || IntegerToBytes(col=j,1) || IntegerToBytes(row=i,1). */
            seed[32] = (uint8_t)j;
            seed[33] = (uint8_t)i;
            determ_mldsa_sample_uniform(mat[i * l + j], seed, 34);
        }
    }
}

void determ_mldsa_expand_s(int32_t s1[][256], int32_t s2[][256],
                           const uint8_t rhoprime[64], int k, int l, int eta) {
    uint8_t seed[66];
    int i, t;
    if (k < 1 || k > MLDSA_KMAX || l < 1 || l > MLDSA_LMAX) return;
    if (eta != 2 && eta != 4) return;
    for (t = 0; t < 64; t++) seed[t] = rhoprime[t];
    for (i = 0; i < l; i++) {          /* s1: nonces 0 .. l-1 */
        nonce_le16(seed + 64, i);
        determ_mldsa_sample_eta(s1[i], seed, 66, eta);
    }
    for (i = 0; i < k; i++) {          /* s2: nonces l .. l+k-1 */
        nonce_le16(seed + 64, l + i);
        determ_mldsa_sample_eta(s2[i], seed, 66, eta);
    }
}

void determ_mldsa_expand_mask(int32_t y[][256], const uint8_t rhoprime[64],
                              int kappa, int l, int32_t gamma1) {
    uint8_t seed[66];
    int i, t;
    if (l < 1 || l > MLDSA_LMAX) return;
    if (gamma1 != DETERM_MLDSA_GAMMA1_17 && gamma1 != DETERM_MLDSA_GAMMA1_19) return;
    for (t = 0; t < 64; t++) seed[t] = rhoprime[t];
    for (i = 0; i < l; i++) {          /* nonce = l*kappa + i */
        nonce_le16(seed + 64, l * kappa + i);
        determ_mldsa_sample_gamma1(y[i], seed, 66, gamma1);
    }
}

void determ_mldsa_polyvec_ntt(int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_ntt(v[i]);
}

void determ_mldsa_polyvec_invntt_tomont(int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_invntt_tomont(v[i]);
}

void determ_mldsa_polyvec_reduce(int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_poly_reduce(v[i]);
}

void determ_mldsa_polyvec_caddq(int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_poly_caddq(v[i]);
}

void determ_mldsa_polyvec_add(int32_t w[][256], const int32_t u[][256],
                              const int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_poly_add(w[i], u[i], v[i]);
}

void determ_mldsa_polyvec_sub(int32_t w[][256], const int32_t u[][256],
                              const int32_t v[][256], int len) {
    int i;
    for (i = 0; i < len; i++) determ_mldsa_poly_sub(w[i], u[i], v[i]);
}

void determ_mldsa_polyvec_matrix_pointwise(int32_t t[][256], const int32_t mat[][256],
                                           const int32_t v[][256], int k, int l) {
    int32_t acc[256], tmp[256];
    int i, j, c;
    for (i = 0; i < k; i++) {
        /* t[i] = Σ_j pointwise_montgomery(mat[i*l+j], v[j]) */
        determ_mldsa_poly_pointwise_montgomery(acc, mat[i * l + 0], v[0]);
        for (j = 1; j < l; j++) {
            determ_mldsa_poly_pointwise_montgomery(tmp, mat[i * l + j], v[j]);
            determ_mldsa_poly_add(acc, acc, tmp);
        }
        for (c = 0; c < N; c++) t[i][c] = acc[c];
    }
}
