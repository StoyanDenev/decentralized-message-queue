/* Determ C99-native ML-DSA (FIPS 204) NTT over Z_q[X]/(X^256 + 1), q = 8380417.
 * Canonical Dilithium reference construction; no external dependency.
 * See include/determ/crypto/mldsa/ntt.h and src/crypto/mldsa/README.md. */
#include <determ/crypto/mldsa/ntt.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/mldsa/reduce.h>

/* The 256 precomputed twiddle factors zetas[i] = 2^32 · ζ^{brv8(i)} (mod q),
 * centered, ζ = 1753 a primitive 512-th root of unity. Machine-generated +
 * verified — see the file header and tools/verify_mldsa_vectors.py. */
#include "zetas.inc"

/* Forward NTT: Cooley-Tukey, decimation-in-time, over decreasing block length. */
void determ_mldsa_ntt(int32_t a[256]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < 256; start += 2 * len) {
            zeta = zetas[++k];
            for (j = start; j < start + len; j++) {
                t = determ_mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j]       = a[j] + t;
            }
        }
    }
}

/* Inverse NTT to the Montgomery domain: Gentleman-Sande, then a final scale by
 * f = 2^32 · 2^32 / 256 (mod q) so the composition with the forward NTT carries
 * exactly one Montgomery factor. */
void determ_mldsa_invntt_tomont(int32_t a[256]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978; /* mont^2 / 256 (mod q) */

    k = 256;
    for (len = 1; len < 256; len <<= 1) {
        for (start = 0; start < 256; start += 2 * len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; j++) {
                t          = a[j];
                a[j]       = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = determ_mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < 256; j++)
        a[j] = determ_mldsa_montgomery_reduce((int64_t)f * a[j]);
}
