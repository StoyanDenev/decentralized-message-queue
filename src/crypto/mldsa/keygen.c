/* Determ C99-native ML-DSA (FIPS 204) key generation — ML-DSA.KeyGen_internal
 * (Algorithm 6). Assembles the increment 1-6 building blocks; canonical Dilithium
 * construction, pinned byte-for-byte against the NIST ACVP KeyGen KATs. See
 * include/determ/crypto/mldsa/keygen.h + src/crypto/mldsa/README.md. */
#include <determ/crypto/mldsa/keygen.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/mldsa/polyvec.h>
#include <determ/crypto/mldsa/poly.h>
#include <determ/crypto/mldsa/ntt.h>
#include <determ/crypto/mldsa/rounding.h>
#include <determ/crypto/mldsa/pack.h>
#include <determ/crypto/sha3/sha3.h>
#include <determ/crypto/secure_zero.h>

#define N DETERM_MLDSA_N
#define KMAX 8
#define LMAX 7

/* {k, l, eta, tau, gamma1, gamma2, omega, lambda} */
const determ_mldsa_params DETERM_MLDSA_44 =
    { 4, 4, 2, 39, DETERM_MLDSA_GAMMA1_17, DETERM_MLDSA_GAMMA2_88, 80, 128 };
const determ_mldsa_params DETERM_MLDSA_65 =
    { 6, 5, 4, 49, DETERM_MLDSA_GAMMA1_19, DETERM_MLDSA_GAMMA2_32, 55, 192 };
const determ_mldsa_params DETERM_MLDSA_87 =
    { 8, 7, 2, 60, DETERM_MLDSA_GAMMA1_19, DETERM_MLDSA_GAMMA2_32, 75, 256 };

/* Per-poly eta-packed byte count: η=2 → 3 bits → 96 B; η=4 → 4 bits → 128 B. */
static size_t eta_poly_bytes(int eta) { return (eta == 2) ? 96u : 128u; }

size_t determ_mldsa_pk_bytes(const determ_mldsa_params* p) {
    if (!p) return 0;
    return 32u + (size_t)p->k * 320u;                 /* ρ + k·(t1 10-bit) */
}
size_t determ_mldsa_sk_bytes(const determ_mldsa_params* p) {
    if (!p) return 0;
    return 128u                                       /* ρ‖K‖tr (32+32+64) */
         + (size_t)(p->l + p->k) * eta_poly_bytes(p->eta)
         + (size_t)p->k * 416u;                        /* t0 13-bit */
}

void determ_mldsa_keygen(const determ_mldsa_params* p, const uint8_t seed[32],
                         uint8_t* pk, uint8_t* sk) {
    determ_keccak_ctx ctx;
    uint8_t h[128], tr[64];
    const uint8_t *rho, *rhop, *K;
    int32_t mat[KMAX * LMAX][256];
    int32_t s1[LMAX][256], s1h[LMAX][256], s2[KMAX][256];
    int32_t t[KMAX][256], t1[KMAX][256], t0[KMAX][256];
    int k, l, eta, i, c;
    size_t off, epb;

    if (!p) return;
    k = p->k; l = p->l; eta = p->eta;
    if (k < 1 || k > KMAX || l < 1 || l > LMAX || (eta != 2 && eta != 4)) return;

    /* (ρ, ρ', K) ← SHAKE256(ξ ‖ IntegerToBytes(k,1) ‖ IntegerToBytes(l,1), 128). */
    determ_shake256_init(&ctx);
    determ_keccak_absorb(&ctx, seed, 32);
    { uint8_t kl[2]; kl[0] = (uint8_t)k; kl[1] = (uint8_t)l;
      determ_keccak_absorb(&ctx, kl, 2); }
    determ_keccak_finalize(&ctx);
    determ_keccak_squeeze(&ctx, h, 128);
    rho = h; rhop = h + 32; K = h + 96;

    /* Â ← ExpandA(ρ) [NTT domain];  (s1, s2) ← ExpandS(ρ'). */
    determ_mldsa_expand_a(mat, rho, k, l);
    determ_mldsa_expand_s(s1, s2, rhop, k, l, eta);

    /* t ← invNTT(Â ∘ NTT(s1)) + s2  — NTT a COPY of s1 so the standard-domain s1
     * survives for skEncode. */
    for (i = 0; i < l; i++) for (c = 0; c < N; c++) s1h[i][c] = s1[i][c];
    determ_mldsa_polyvec_ntt(s1h, l);
    determ_mldsa_polyvec_matrix_pointwise(t, mat, s1h, k, l);
    determ_mldsa_polyvec_reduce(t, k);
    determ_mldsa_polyvec_invntt_tomont(t, k);
    determ_mldsa_polyvec_add(t, t, s2, k);
    determ_mldsa_polyvec_caddq(t, k);

    /* (t1, t0) ← Power2Round(t). */
    for (i = 0; i < k; i++)
        for (c = 0; c < N; c++) t1[i][c] = determ_mldsa_power2round(t[i][c], &t0[i][c]);

    /* pk ← pkEncode(ρ, t1). */
    for (c = 0; c < 32; c++) pk[c] = rho[c];
    for (i = 0; i < k; i++) determ_mldsa_pack_t1(pk + 32 + (size_t)i * 320u, t1[i]);

    /* tr ← SHAKE256(pk, 64). */
    determ_shake256_init(&ctx);
    determ_keccak_absorb(&ctx, pk, determ_mldsa_pk_bytes(p));
    determ_keccak_finalize(&ctx);
    determ_keccak_squeeze(&ctx, tr, 64);

    /* sk ← skEncode(ρ, K, tr, s1, s2, t0). */
    for (c = 0; c < 32; c++) sk[c] = rho[c];
    for (c = 0; c < 32; c++) sk[32 + c] = K[c];
    for (c = 0; c < 64; c++) sk[64 + c] = tr[c];
    off = 128; epb = eta_poly_bytes(eta);
    for (i = 0; i < l; i++) { determ_mldsa_pack_eta(sk + off, s1[i], eta); off += epb; }
    for (i = 0; i < k; i++) { determ_mldsa_pack_eta(sk + off, s2[i], eta); off += epb; }
    for (i = 0; i < k; i++) { determ_mldsa_pack_t0(sk + off, t0[i]); off += 416u; }

    /* Scrub secret-bearing locals. */
    determ_secure_zero(&ctx, sizeof ctx);
    determ_secure_zero(h, sizeof h);
    determ_secure_zero(s1, sizeof s1);
    determ_secure_zero(s1h, sizeof s1h);
    determ_secure_zero(s2, sizeof s2);
    determ_secure_zero(t0, sizeof t0);
}
