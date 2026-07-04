/* Determ C99-native ML-DSA (FIPS 204) per-polynomial ring arithmetic.
 * Canonical Dilithium reference construction; no external dependency.
 * See include/determ/crypto/mldsa/poly.h and src/crypto/mldsa/README.md. */
#include <determ/crypto/mldsa/poly.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/mldsa/reduce.h>

#define N DETERM_MLDSA_N

void determ_mldsa_poly_add(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
    int i;
    for (i = 0; i < N; i++) c[i] = a[i] + b[i];
}

void determ_mldsa_poly_sub(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
    int i;
    for (i = 0; i < N; i++) c[i] = a[i] - b[i];
}

void determ_mldsa_poly_reduce(int32_t a[256]) {
    int i;
    for (i = 0; i < N; i++) a[i] = determ_mldsa_reduce32(a[i]);
}

void determ_mldsa_poly_caddq(int32_t a[256]) {
    int i;
    for (i = 0; i < N; i++) a[i] = determ_mldsa_caddq(a[i]);
}

void determ_mldsa_poly_pointwise_montgomery(int32_t c[256], const int32_t a[256], const int32_t b[256]) {
    int i;
    for (i = 0; i < N; i++) c[i] = determ_mldsa_montgomery_reduce((int64_t)a[i] * b[i]);
}
