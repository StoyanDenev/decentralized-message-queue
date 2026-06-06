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
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;

/* 16-byte domain separator for the binding-factor hash. */
static const u8 FROST_DOMAIN_RHO[16] =
    { 'D','E','T','E','R','M','-','F','R','O','S','T','-','R','H','O' };

/* L_i(0) = prod_{j!=i} x_j / (x_j - x_i), the Lagrange coefficient for signer i
 * over the participating x-coordinate set `xs[0..t-1]`. */
static void frost_lagrange(const int *xs, int t, int i, u8 lam[32]) {
    u8 num[32], den[32], xi[32], xj[32], tmp[32];
    int j, k;
    for (k = 0; k < 32; k++) { num[k] = (k == 0) ? 1 : 0; den[k] = (k == 0) ? 1 : 0; }
    determ_ed25519_sc_set_small(xi, (uint64_t)xs[i]);
    for (j = 0; j < t; j++) {
        if (j == i) continue;
        determ_ed25519_sc_set_small(xj, (uint64_t)xs[j]);
        determ_ed25519_sc_mul(num, num, xj);
        determ_ed25519_sc_sub(tmp, xj, xi);
        determ_ed25519_sc_mul(den, den, tmp);
    }
    determ_ed25519_sc_invert(tmp, den);
    determ_ed25519_sc_mul(lam, num, tmp);
}

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

int determ_frost_sign(const int *xs, const u8 *shares,
                      const u8 *d, const u8 *e, int t,
                      const u8 *msg, size_t msglen,
                      const u8 group_pk[32], u8 sig[64]) {
    int i, k, rc = -1;
    u8 *Dc = NULL, *Ec = NULL, *rho = NULL, *rbuf = NULL, *cbuf = NULL;
    u8 R_enc[32], c[32], z[32], zi[32], t1[32], ls[32], lam[32], hbuf[64];
    size_t rsize, csize, off;

    if (t < 1) return -1;
    if (msglen > (size_t)0x10000000) return -1;          /* 256 MiB cap — beacon msgs are tiny */
    /* Validate the signer set: indices must be in [1,255] (they are hashed as a
     * u8 binding-factor tag) and pairwise distinct — a repeated x makes the
     * Lagrange denominator prod(x_j - x_i) singular, which sc_invert maps to
     * inv(0)=0, collapsing lambda_i to 0 and silently producing a WRONG signature.
     * Mirrors determ_frost_reconstruct's guards; turns that into a clean -1. */
    for (i = 0; i < t; i++) {
        if (xs[i] < 1 || xs[i] > 255) return -1;
        for (k = i + 1; k < t; k++) if (xs[k] == xs[i]) return -1;
    }

    Dc  = (u8 *)malloc((size_t)t * 32);
    Ec  = (u8 *)malloc((size_t)t * 32);
    rho = (u8 *)malloc((size_t)t * 32);
    rsize = 16 + 1 + (size_t)t * 65 + msglen;             /* DOMAIN ‖ idx ‖ list ‖ msg */
    csize = 64 + msglen;                                  /* R ‖ group_pk ‖ msg */
    rbuf = (u8 *)malloc(rsize);
    cbuf = (u8 *)malloc(csize);
    if (!Dc || !Ec || !rho || !rbuf || !cbuf) goto done;

    /* round-1 commitments D_i = [d_i] B, E_i = [e_i] B (public). */
    for (i = 0; i < t; i++) {
        determ_ed25519_point_basemul(Dc + i * 32, d + i * 32);
        determ_ed25519_point_basemul(Ec + i * 32, e + i * 32);
    }

    /* binding-factor input: DOMAIN ‖ [signer idx] ‖ commitment-list ‖ msg.
     * The list + msg are constant across signers; only byte 16 (idx) varies. */
    for (k = 0; k < 16; k++) rbuf[k] = FROST_DOMAIN_RHO[k];
    off = 17;
    for (i = 0; i < t; i++) {
        rbuf[off++] = (u8)xs[i];
        memcpy(rbuf + off, Dc + i * 32, 32); off += 32;
        memcpy(rbuf + off, Ec + i * 32, 32); off += 32;
    }
    if (msglen) memcpy(rbuf + off, msg, msglen);
    for (i = 0; i < t; i++) {
        rbuf[16] = (u8)xs[i];
        determ_sha512(rbuf, rsize, hbuf);
        determ_ed25519_sc_reduce64(hbuf, rho + i * 32);  /* rho_i */
    }

    /* group commitment R = sum_i ( D_i + [rho_i] E_i ). */
    for (i = 0; i < t; i++) {
        u8 Ti[32], Pi[32];
        if (determ_ed25519_point_mul(Ti, rho + i * 32, Ec + i * 32)) goto done;
        if (determ_ed25519_point_add(Pi, Dc + i * 32, Ti)) goto done;
        if (i == 0) { for (k = 0; k < 32; k++) R_enc[k] = Pi[k]; }
        else if (determ_ed25519_point_add(R_enc, R_enc, Pi)) goto done;
    }

    /* Ed25519-compatible challenge c = H(R ‖ group_pk ‖ msg) mod L. */
    for (k = 0; k < 32; k++) { cbuf[k] = R_enc[k]; cbuf[32 + k] = group_pk[k]; }
    if (msglen) memcpy(cbuf + 64, msg, msglen);
    determ_sha512(cbuf, csize, hbuf);
    determ_ed25519_sc_reduce64(hbuf, c);

    /* aggregate z = sum_i ( d_i + e_i·rho_i + lambda_i·s_i·c ). */
    for (k = 0; k < 32; k++) z[k] = 0;
    for (i = 0; i < t; i++) {
        frost_lagrange(xs, t, i, lam);
        determ_ed25519_sc_muladd(t1, e + i * 32, rho + i * 32, d + i * 32);  /* e_i·rho_i + d_i */
        determ_ed25519_sc_mul(ls, lam, shares + i * 32);                    /* lambda_i·s_i    */
        determ_ed25519_sc_muladd(zi, ls, c, t1);                            /* ls·c + t1 = z_i */
        determ_ed25519_sc_add(z, z, zi);
    }

    for (k = 0; k < 32; k++) { sig[k] = R_enc[k]; sig[32 + k] = z[k]; }
    rc = 0;

done:
    if (Dc)  free(Dc);
    if (Ec)  free(Ec);
    if (rho) free(rho);                                  /* binding factors are public */
    if (rbuf) free(rbuf);
    if (cbuf) free(cbuf);
    determ_secure_zero(z, 32);  determ_secure_zero(zi, 32); determ_secure_zero(t1, 32);
    determ_secure_zero(ls, 32); determ_secure_zero(lam, 32); determ_secure_zero(hbuf, 64);
    return rc;
}
