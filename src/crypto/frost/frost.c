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
#include "determ/crypto/ct.h"
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

/* Signer-set validity: indices in [1,255] (hashed as a u8 binding-factor tag) and
 * pairwise distinct (a repeated x makes the Lagrange denominator prod(x_j - x_i)
 * singular -> sc_invert(0)=0 -> a silently WRONG signature). 0 if valid, -1 if not. */
static int frost_check_signer_set(const int *xs, int t) {
    int i, k;
    if (t < 1) return -1;
    for (i = 0; i < t; i++) {
        if (xs[i] < 1 || xs[i] > 255) return -1;
        for (k = i + 1; k < t; k++) if (xs[k] == xs[i]) return -1;
    }
    return 0;
}

/* From the PUBLIC round-1 commitment lists D[],E[] (t*32 each, in xs order),
 * compute the per-signer binding factors rho[] (t*32), the group commitment R, and
 * the Ed25519-compatible challenge c = H(R ‖ group_pk ‖ msg) mod L. This is the
 * single source of truth for those values, shared by the centralized
 * determ_frost_sign and the per-signer determ_frost_sign_partial /
 * determ_frost_aggregate so they cannot diverge. Returns 0, or -1 on alloc /
 * length / point-decode failure. */
static int frost_binding_and_challenge(const int *xs, int t,
        const u8 *D, const u8 *E, const u8 *msg, size_t msglen,
        const u8 group_pk[32], u8 *rho, u8 R_enc[32], u8 c[32]) {
    int i, k, rc = -1;
    u8 *rbuf = NULL, *cbuf = NULL, hbuf[64];
    size_t rsize, csize, off;
    if (msglen > (size_t)0x10000000) return -1;              /* 256 MiB cap */
    rsize = 16 + 1 + (size_t)t * 65 + msglen;                /* DOMAIN ‖ idx ‖ list ‖ msg */
    csize = 64 + msglen;                                     /* R ‖ group_pk ‖ msg */
    rbuf = (u8 *)malloc(rsize);
    cbuf = (u8 *)malloc(csize);
    if (!rbuf || !cbuf) goto done;

    for (k = 0; k < 16; k++) rbuf[k] = FROST_DOMAIN_RHO[k];
    off = 17;
    for (i = 0; i < t; i++) {
        rbuf[off++] = (u8)xs[i];
        memcpy(rbuf + off, D + i * 32, 32); off += 32;
        memcpy(rbuf + off, E + i * 32, 32); off += 32;
    }
    if (msglen) memcpy(rbuf + off, msg, msglen);
    for (i = 0; i < t; i++) {
        rbuf[16] = (u8)xs[i];
        determ_sha512(rbuf, rsize, hbuf);
        determ_ed25519_sc_reduce64(hbuf, rho + i * 32);      /* rho_i */
    }
    for (i = 0; i < t; i++) {
        u8 Ti[32], Pi[32];
        if (determ_ed25519_point_mul(Ti, rho + i * 32, E + i * 32)) goto done;
        if (determ_ed25519_point_add(Pi, D + i * 32, Ti)) goto done;
        if (i == 0) { for (k = 0; k < 32; k++) R_enc[k] = Pi[k]; }
        else if (determ_ed25519_point_add(R_enc, R_enc, Pi)) goto done;
    }
    for (k = 0; k < 32; k++) { cbuf[k] = R_enc[k]; cbuf[32 + k] = group_pk[k]; }
    if (msglen) memcpy(cbuf + 64, msg, msglen);
    determ_sha512(cbuf, csize, hbuf);
    determ_ed25519_sc_reduce64(hbuf, c);
    rc = 0;
done:
    if (rbuf) free(rbuf);
    if (cbuf) free(cbuf);
    determ_secure_zero(hbuf, sizeof hbuf);
    return rc;
}

int determ_frost_sign(const int *xs, const u8 *shares,
                      const u8 *d, const u8 *e, int t,
                      const u8 *msg, size_t msglen,
                      const u8 group_pk[32], u8 sig[64]) {
    int i, k, rc = -1;
    u8 *Dc = NULL, *Ec = NULL, *rho = NULL;
    u8 R_enc[32], c[32], z[32], zi[32], t1[32], ls[32], lam[32];

    if (frost_check_signer_set(xs, t)) return -1;
    Dc  = (u8 *)malloc((size_t)t * 32);
    Ec  = (u8 *)malloc((size_t)t * 32);
    rho = (u8 *)malloc((size_t)t * 32);
    if (!Dc || !Ec || !rho) goto done;

    /* round-1 commitments D_i = [d_i] B, E_i = [e_i] B (public). */
    for (i = 0; i < t; i++) {
        determ_ed25519_point_basemul(Dc + i * 32, d + i * 32);
        determ_ed25519_point_basemul(Ec + i * 32, e + i * 32);
    }
    if (frost_binding_and_challenge(xs, t, Dc, Ec, msg, msglen, group_pk, rho, R_enc, c)) goto done;

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
    determ_secure_zero(z, 32);  determ_secure_zero(zi, 32); determ_secure_zero(t1, 32);
    determ_secure_zero(ls, 32); determ_secure_zero(lam, 32);
    return rc;
}

/* Per-signer round-2 partial: the signature share z_pos for the signer at position
 * `pos` in the set `xs`, given ONLY that signer's secret (share, d, e) plus the
 * PUBLIC round-1 commitment lists D[],E[] of all signers. z_pos = d_pos +
 * e_pos·rho_pos + lambda_pos·share·c. This is the distributed counterpart of the
 * inner loop of determ_frost_sign (which has every signer's secrets at once).
 * Returns 0, or -1 on bad params. */
int determ_frost_sign_partial(const int *xs, int t, int pos,
                              const u8 share[32], const u8 d_self[32], const u8 e_self[32],
                              const u8 *D, const u8 *E,
                              const u8 *msg, size_t msglen,
                              const u8 group_pk[32], u8 z_out[32]) {
    int rc = -1;
    u8 *rho = NULL;
    u8 R_enc[32], c[32], lam[32], t1[32], ls[32];
    if (frost_check_signer_set(xs, t)) return -1;
    if (pos < 0 || pos >= t) return -1;
    rho = (u8 *)malloc((size_t)t * 32);
    if (!rho) return -1;
    if (frost_binding_and_challenge(xs, t, D, E, msg, msglen, group_pk, rho, R_enc, c)) goto done;
    frost_lagrange(xs, t, pos, lam);
    determ_ed25519_sc_muladd(t1, e_self, rho + pos * 32, d_self);   /* e·rho_pos + d */
    determ_ed25519_sc_mul(ls, lam, share);                         /* lambda·share  */
    determ_ed25519_sc_muladd(z_out, ls, c, t1);                    /* ls·c + t1     */
    rc = 0;
done:
    if (rho) free(rho);
    determ_secure_zero(lam, 32); determ_secure_zero(t1, 32); determ_secure_zero(ls, 32);
    return rc;
}

/* Aggregate t partial signatures (`partials`, t*32, in xs order) into the
 * canonical signature R ‖ z, where R is recomputed from the public commitment
 * lists D[],E[] (so every aggregator gets the same R) and z = Σ partials. Returns
 * 0, or -1 on bad params. */
int determ_frost_aggregate(const int *xs, int t,
                           const u8 *D, const u8 *E, const u8 *partials,
                           const u8 *msg, size_t msglen,
                           const u8 group_pk[32], u8 sig[64]) {
    int i, k, rc = -1;
    u8 *rho = NULL;
    u8 R_enc[32], c[32], z[32];
    if (frost_check_signer_set(xs, t)) return -1;
    rho = (u8 *)malloc((size_t)t * 32);
    if (!rho) return -1;
    if (frost_binding_and_challenge(xs, t, D, E, msg, msglen, group_pk, rho, R_enc, c)) goto done;
    for (k = 0; k < 32; k++) z[k] = 0;
    for (i = 0; i < t; i++) determ_ed25519_sc_add(z, z, partials + i * 32);
    for (k = 0; k < 32; k++) { sig[k] = R_enc[k]; sig[32 + k] = z[k]; }
    rc = 0;
done:
    if (rho) free(rho);
    return rc;
}

/* ── DKG (Pedersen / Feldman VSS, RFC 9591 §6.6) ─────────────────────────── */

/* 20-byte domain for the proof-of-possession hashes (nonce/challenge separated by
 * a 1-byte tag). */
static const u8 DKG_POP_DOM[20] =
    { 'D','E','T','E','R','M','-','F','R','O','S','T','-','D','K','G','-','P','O','P' };

/* f(x) = Σ_{k=0}^{t-1} poly_k x^k, evaluated by Horner. */
static void frost_poly_eval(const u8 *poly, int t, int x, u8 out[32]) {
    u8 xs[32], acc[32]; int k;
    determ_ed25519_sc_set_small(xs, (uint64_t)x);
    for (k = 0; k < 32; k++) acc[k] = poly[(t - 1) * 32 + k];   /* highest coeff */
    for (k = t - 2; k >= 0; k--)
        determ_ed25519_sc_muladd(acc, acc, xs, &poly[k * 32]);
    for (k = 0; k < 32; k++) out[k] = acc[k];
    determ_secure_zero(acc, sizeof acc);
}

void determ_frost_dkg_share(const u8 *poly, int t, int j, u8 share_out[32]) {
    frost_poly_eval(poly, t, j, share_out);
}

int determ_frost_dkg_commit(const u8 *poly, int t, int idx,
                            u8 *commitments, u8 pop[64]) {
    int k;
    u8 A0[32], R[32], kn[32], c[32], z[32], hbuf[64], nb[54], cb[86];
    if (t < 1 || idx < 1 || idx > 255) return -1;

    for (k = 0; k < t; k++) determ_ed25519_point_basemul(&commitments[k * 32], &poly[k * 32]);
    for (k = 0; k < 32; k++) A0[k] = commitments[k];          /* [a_0] B */

    /* deterministic Schnorr nonce kn = H(DOM ‖ 0x01 ‖ idx ‖ a_0) mod L */
    memcpy(nb, DKG_POP_DOM, 20); nb[20] = 0x01; nb[21] = (u8)idx; memcpy(nb + 22, poly, 32);
    determ_sha512(nb, sizeof nb, hbuf);
    determ_ed25519_sc_reduce64(hbuf, kn);
    determ_ed25519_point_basemul(R, kn);                      /* R = [kn] B */

    /* challenge c = H(DOM ‖ 0x02 ‖ idx ‖ A_0 ‖ R) mod L */
    memcpy(cb, DKG_POP_DOM, 20); cb[20] = 0x02; cb[21] = (u8)idx;
    memcpy(cb + 22, A0, 32); memcpy(cb + 54, R, 32);
    determ_sha512(cb, sizeof cb, hbuf);
    determ_ed25519_sc_reduce64(hbuf, c);

    determ_ed25519_sc_muladd(z, c, poly, kn);                 /* z = c·a_0 + kn */
    memcpy(pop, R, 32); memcpy(pop + 32, z, 32);

    determ_secure_zero(kn, sizeof kn); determ_secure_zero(z, sizeof z);
    determ_secure_zero(nb, sizeof nb); determ_secure_zero(hbuf, sizeof hbuf);
    return 0;
}

int determ_frost_dkg_verify_pop(const u8 commitment0[32], int idx, const u8 pop[64]) {
    u8 c[32], hbuf[64], cb[86], lhs[32], rhs[32], tmp[32];
    if (idx < 1 || idx > 255) return -1;
    /* Anti-malleability: reject a non-canonical R encoding (y >= q) or a
     * non-canonical scalar z (z >= L) — without these, (R, z+L) and the ~19
     * non-canonical y-encodings of R would re-verify, breaking PoP byte-
     * uniqueness (matches the Ed25519 verifier's RFC 8032 §5.1.3/§5.1.7 gates). */
    if (!determ_ed25519_point_is_canonical(pop)) return -1;
    if (!determ_ed25519_sc_is_canonical(pop + 32)) return -1;
    memcpy(cb, DKG_POP_DOM, 20); cb[20] = 0x02; cb[21] = (u8)idx;
    memcpy(cb + 22, commitment0, 32); memcpy(cb + 54, pop, 32);   /* pop[0..31] = R */
    determ_sha512(cb, sizeof cb, hbuf);
    determ_ed25519_sc_reduce64(hbuf, c);
    determ_ed25519_point_basemul(lhs, pop + 32);                 /* [z] B */
    if (determ_ed25519_point_mul(tmp, c, commitment0)) return -1;/* [c] A_0 */
    if (determ_ed25519_point_add(rhs, pop, tmp)) return -1;      /* R + [c] A_0 */
    /* Both operands are publicly recomputable group elements; the constant-
     * time compare is uniform house discipline (ct.h), not a leak fix. */
    return determ_ct_memcmp(lhs, rhs, 32);
}

int determ_frost_dkg_verify_share(const u8 share[32], int j, const u8 *commitments, int t) {
    u8 acc[32], jpow[32], js[32], term[32], lhs[32]; int k;
    if (t < 1 || j < 1 || j > 255) return -1;
    for (k = 0; k < 32; k++) acc[k] = commitments[k];            /* j^0 · C_0 = C_0 */
    determ_ed25519_sc_set_small(jpow, 1u);
    determ_ed25519_sc_set_small(js, (uint64_t)j);
    for (k = 1; k < t; k++) {
        determ_ed25519_sc_mul(jpow, jpow, js);                   /* jpow = j^k */
        if (determ_ed25519_point_mul(term, jpow, &commitments[k * 32])) return -1;
        if (determ_ed25519_point_add(acc, acc, term)) return -1; /* acc += j^k · C_k */
    }
    determ_ed25519_point_basemul(lhs, share);                    /* [share] B */
    /* Same as verify_pop: public group elements; CT compare for uniformity. */
    return determ_ct_memcmp(lhs, acc, 32);
}

/* ── Proactive Secret Sharing refresh (Herzberg et al. 1995) ──────────────────
 * Rotates every participant's secret share WITHOUT changing the group secret
 * `s` or the group public key `[s]B`, so a "mobile" adversary who collects up to
 * t-1 shares in one epoch gains nothing once the epoch rolls over: the captured
 * shares become inconsistent with the refreshed ones. Each participant i picks a
 * RANDOM degree-(t-1) "zero-hole" polynomial δ_i with δ_i(0)=0; the refresh
 * polynomial is Δ = Σ_i δ_i, also with Δ(0)=0. Participant j's new share is
 *   s'_j = s_j + Σ_i δ_i(j) = f(j) + Δ(j) = (f+Δ)(j),
 * and (f+Δ)(0) = f(0)+0 = s — unchanged. The shares move; the secret does not. */

/* Emit the Feldman commitments C_k = [δ_k]B (t*32 bytes) for a zero-hole refresh
 * polynomial `zeropoly` (t*32 bytes, δ_0 MUST be the zero scalar). Returns 0, or
 * -1 if t<1 or the constant term is non-zero (a non-zero hole would shift the
 * group secret — forbidden). C_0 is therefore the identity point, which any peer
 * checks with determ_frost_pss_verify_commit. Shares are dealt + verified with
 * the existing determ_frost_dkg_share / _verify_share (the Feldman check is
 * identical; it simply sees C_0 = identity). */
int determ_frost_pss_commit(const u8 *zeropoly, int t, u8 *commitments) {
    int k; u8 hole = 0;
    if (t < 1) return -1;
    /* δ_0 == 0 required (zero hole). Accumulate all 32 bytes into one OR and branch
     * once on the aggregate, matching the house branchless-compare discipline (no
     * per-byte early-return timing). The checked bytes are the protocol-mandated
     * public-zero constant term, not secret material — the secret coefficients
     * δ_1..δ_{t-1} flow only through the constant-time point_basemul below. */
    for (k = 0; k < 32; k++) hole |= zeropoly[k];
    if (hole != 0) return -1;
    for (k = 0; k < t; k++)
        determ_ed25519_point_basemul(&commitments[k * 32], &zeropoly[k * 32]);
    return 0;
}

/* The zero-hole proof: confirm a peer's commitment C_0 is the identity point
 * (i.e. δ_0 = 0, so that peer cannot have shifted the group secret). Returns 0 if
 * C_0 == [0]B, -1 otherwise. This is the PSS analogue of the DKG proof-of-
 * possession — no Schnorr PoP is needed because the only fact to prove about the
 * constant term is that it is zero, which is publicly checkable from C_0 alone. */
int determ_frost_pss_verify_commit(const u8 commitment0[32]) {
    u8 zero[32], id[32]; int k;
    for (k = 0; k < 32; k++) zero[k] = 0;
    determ_ed25519_point_basemul(id, zero);                       /* identity = [0]B */
    /* C_0 is a public commitment; CT compare is uniform house discipline
     * (ConstantTimeInventory.md CTI-1 — this was the one per-byte early-
     * return compare left after the §3.10 consolidation). */
    return determ_ct_memcmp(commitment0, id, 32);
}
