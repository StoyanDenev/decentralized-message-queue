/* Determ C99-native ML-DSA (FIPS 204) coefficient rounding + hints over Z_q.
 * Canonical Dilithium reference construction; no external dependency.
 * See include/determ/crypto/mldsa/rounding.h and src/crypto/mldsa/README.md. */
#include <determ/crypto/mldsa/rounding.h>
#include <determ/crypto/mldsa/params.h>

#define Q  DETERM_MLDSA_Q
#define D  DETERM_MLDSA_D

int32_t determ_mldsa_power2round(int32_t a, int32_t* a0) {
    int32_t a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    return a1;
}

int32_t determ_mldsa_decompose(int32_t a, int32_t* a0, int32_t gamma2) {
    int32_t a1 = (a + 127) >> 7;
    if (gamma2 == DETERM_MLDSA_GAMMA2_32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else { /* DETERM_MLDSA_GAMMA2_88 */
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    *a0 = a - a1 * 2 * gamma2;
    *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
    return a1;
}

unsigned int determ_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2) {
    if (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0))
        return 1;
    return 0;
}

int32_t determ_mldsa_use_hint(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;
    a1 = determ_mldsa_decompose(a, &a0, gamma2);
    if (hint == 0)
        return a1;
    if (gamma2 == DETERM_MLDSA_GAMMA2_32) {
        return (a0 > 0) ? ((a1 + 1) & 15) : ((a1 - 1) & 15);
    } else {
        if (a0 > 0) return (a1 == 43) ? 0 : a1 + 1;
        else        return (a1 == 0) ? 43 : a1 - 1;
    }
}
