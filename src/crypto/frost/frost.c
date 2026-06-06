/* Determ C99-native FROST-Ed25519 (RFC 9591). See frost.h.
 *
 * Keygen pillar: Shamir secret sharing over the Ed25519 scalar field (mod L) +
 * Lagrange reconstruction, on the constant-time C99 group/scalar primitives in
 * ed25519_group.h. The polynomial f(x) = secret + a_1 x + ... + a_{t-1} x^{t-1} is
 * evaluated at each participant index by Horner's method using sc_muladd; the
 * Lagrange basis L_i(0) = prod_{j!=i} x_j / (x_j - x_i) reconstructs f(0).
 * Validated by `determ test-frost-c99`. */
#include "determ/crypto/frost/frost.h"
#include "determ/crypto/ed25519/ed25519_group.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>

typedef uint8_t u8;

int determ_frost_keygen_trusted(const u8 secret[32], const u8 *coeffs,
                                int t, int n,
                                u8 *shares, u8 group_pk[32], u8 *share_pks) {
    int i, j, k;
    if (t < 1 || n < t || n > 255) return -1;

    for (i = 1; i <= n; i++) {
        u8 xi[32], acc[32];
        determ_ed25519_sc_set_small(xi, (uint64_t)i);
        /* Horner: f(x) = ((a_{t-1} x + a_{t-2}) x + ... + a_1) x + secret. */
        if (t >= 2) { for (k = 0; k < 32; k++) acc[k] = coeffs[(t - 2) * 32 + k]; }
        else        { for (k = 0; k < 32; k++) acc[k] = 0; }
        for (j = t - 3; j >= 0; j--)
            determ_ed25519_sc_muladd(acc, acc, xi, &coeffs[j * 32]);   /* acc = acc*x + a_{j+1} */
        determ_ed25519_sc_muladd(acc, acc, xi, secret);               /* acc = acc*x + secret */
        for (k = 0; k < 32; k++) shares[(i - 1) * 32 + k] = acc[k];
        determ_ed25519_point_basemul(&share_pks[(i - 1) * 32], acc);  /* [s_i] B */
        determ_secure_zero(acc, sizeof acc);
    }
    determ_ed25519_point_basemul(group_pk, secret);                   /* [secret] B */
    return 0;
}

int determ_frost_reconstruct(const int *xs, const u8 *shares, int t, u8 secret_out[32]) {
    int i, j, k;
    u8 acc[32];
    if (t < 1) return -1;
    for (k = 0; k < 32; k++) acc[k] = 0;

    for (i = 0; i < t; i++) {
        u8 xi[32], num[32], den[32], xj[32], tmp[32], lam[32];
        if (xs[i] <= 0) return -1;
        determ_ed25519_sc_set_small(xi, (uint64_t)xs[i]);
        for (k = 0; k < 32; k++) { num[k] = (k == 0) ? 1 : 0; den[k] = (k == 0) ? 1 : 0; }
        for (j = 0; j < t; j++) {
            if (j == i) continue;
            if (xs[j] == xs[i]) return -1;                 /* repeated x -> singular */
            determ_ed25519_sc_set_small(xj, (uint64_t)xs[j]);
            determ_ed25519_sc_mul(num, num, xj);           /* num *= x_j         */
            determ_ed25519_sc_sub(tmp, xj, xi);            /* x_j - x_i          */
            determ_ed25519_sc_mul(den, den, tmp);          /* den *= (x_j - x_i) */
        }
        determ_ed25519_sc_invert(tmp, den);
        determ_ed25519_sc_mul(lam, num, tmp);              /* L_i(0) = num/den   */
        determ_ed25519_sc_muladd(acc, lam, &shares[i * 32], acc);   /* acc += L_i(0) * s_i */
        determ_secure_zero(lam, sizeof lam);
    }
    for (k = 0; k < 32; k++) secret_out[k] = acc[k];
    determ_secure_zero(acc, sizeof acc);
    return 0;
}
