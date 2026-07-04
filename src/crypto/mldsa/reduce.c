/* Determ C99-native ML-DSA (FIPS 204) modular reduction over Z_q, q = 8380417.
 * Canonical Dilithium reference construction; no external dependency.
 * See include/determ/crypto/mldsa/reduce.h. */
#include <determ/crypto/mldsa/reduce.h>
#include <determ/crypto/mldsa/params.h>

#define Q    DETERM_MLDSA_Q
#define QINV DETERM_MLDSA_QINV

/* t ≡ a * 2^{-32} (mod q). The multiply into the low 32 bits is done unsigned
 * (no signed-overflow UB); t*Q then divides a exactly by 2^32 because
 * t ≡ a * q^{-1} (mod 2^32) ⇒ a - t*q ≡ 0 (mod 2^32). The arithmetic right
 * shift of a possibly-negative int64 is implementation-defined (arithmetic on
 * every target Determ builds for), NOT undefined behaviour — matches the repo's
 * UBSan-clean discipline. */
int32_t determ_mldsa_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((uint32_t)a * (uint32_t)QINV);
    t = (int32_t)((a - (int64_t)t * Q) >> 32);
    return t;
}

/* Barrett: t = round(a / q) via the fixed-point (a + 2^22) >> 23, then a - t*q. */
int32_t determ_mldsa_reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

/* a + (q if a < 0 else 0), branchless: (a >> 31) is all-ones for a < 0. The
 * arithmetic right shift of a negative int32 is implementation-defined, not UB. */
int32_t determ_mldsa_caddq(int32_t a) {
    a += (a >> 31) & Q;
    return a;
}
