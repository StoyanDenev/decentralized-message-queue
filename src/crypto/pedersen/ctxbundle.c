// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/pedersen/ctxbundle.h>
#include <determ/crypto/pedersen/rangeproof.h>
#include <determ/crypto/pedersen/balance.h>
#include <string.h>

#define DCT_HDR 15u   /* MAGIC(4) + n_in(1) + m(1) + n(1) + fee(8) */

static int n_pow2_le64(size_t n) { return n && n <= 64 && (n & (n - 1)) == 0; }

size_t determ_ctx_bundle_len(size_t n_in, size_t m, size_t n) {
    if (n_in < 1 || n_in > 255 || m < 1 || m > 255) return 0;
    if (!n_pow2_le64(n))                             return 0;
    if (m * n > 256)                                 return 0;   /* IPA max dimension */
    size_t agg = determ_agg_rangeproof_proof_len(m, n);
    if (agg == 0)                                    return 0;
    return DCT_HDR + n_in * 33 + m * 33 + agg + 65;
}

int determ_ctx_bundle_serialize(uint8_t *out, size_t out_len,
                                const uint8_t *C_in, size_t n_in,
                                const uint8_t *C_out, size_t m, size_t n,
                                uint64_t fee,
                                const uint8_t *agg_rangeproof,
                                const uint8_t balance_proof[65]) {
    size_t need = determ_ctx_bundle_len(n_in, m, n);
    if (need == 0 || out == 0 || out_len < need) return -1;
    size_t agg = determ_agg_rangeproof_proof_len(m, n);
    uint8_t *p = out;
    p[0] = 'D'; p[1] = 'C'; p[2] = 'T'; p[3] = '1'; p += 4;
    *p++ = (uint8_t)n_in; *p++ = (uint8_t)m; *p++ = (uint8_t)n;
    for (int i = 7; i >= 0; --i) *p++ = (uint8_t)((fee >> (i * 8)) & 0xFF);
    memcpy(p, C_in,  n_in * 33); p += n_in * 33;
    memcpy(p, C_out, m * 33);    p += m * 33;
    memcpy(p, agg_rangeproof, agg); p += agg;
    memcpy(p, balance_proof, 65);
    return 0;
}

int determ_ctx_bundle_verify(const uint8_t *bundle, size_t len) {
    if (bundle == 0 || len < DCT_HDR)                       return -1;
    if (bundle[0] != 'D' || bundle[1] != 'C' ||
        bundle[2] != 'T' || bundle[3] != '1')               return -1;
    size_t n_in = bundle[4], m = bundle[5], n = bundle[6];
    size_t need = determ_ctx_bundle_len(n_in, m, n);        /* validates all params */
    if (need == 0 || len != need)                           return -1;
    uint64_t fee = 0;
    for (int i = 0; i < 8; i++) fee = (fee << 8) | bundle[7 + i];

    const uint8_t *C_in   = bundle + DCT_HDR;
    const uint8_t *C_out  = C_in + n_in * 33;
    size_t         agg    = determ_agg_rangeproof_proof_len(m, n);
    const uint8_t *agg_rp = C_out + m * 33;
    const uint8_t *bal    = agg_rp + agg;

    /* Recompute the excess E = Sum(C_in) - Sum(C_out) - fee*G; a non-zero return
     * is a malformed commitment or the degenerate identity excess -> reject. */
    uint8_t E[33];
    if (determ_p256_balance_excess(E, C_in, n_in, C_out, m, fee) != 0) return -1;
    /* Balance (value conservation) AND range (each output in [0, 2^n)). C_out is
     * used directly as the range proof's value commitments V. */
    if (determ_p256_balance_verify(E, bal) != 0)                return -1;
    if (determ_agg_rangeproof_verify(C_out, agg_rp, m, n) != 0) return -1;
    return 0;
}

int determ_shield_verify(const uint8_t *payload, size_t len, uint64_t amount) {
    if (payload == 0 || len != 98) return -1;
    /* E = C - amount*G  (balance excess with C as the single input, NO outputs,
     * fee = amount). A non-zero return is a malformed commitment or the identity
     * excess (which would mean amount==0 and r==0) -> reject. */
    uint8_t E[33];
    if (determ_p256_balance_excess(E, payload, 1, 0, 0, amount) != 0) return -1;
    /* The balance proof proves E opens to zero on H, i.e. C = amount*G + r*H. */
    return determ_p256_balance_verify(E, payload + 33);
}

int determ_unshield_verify(const uint8_t *payload, size_t len, uint64_t amount,
                           const uint8_t ctx32[32]) {
    if (payload == 0 || ctx32 == 0 || len != 98) return -1;
    /* Same excess E = C - amount*G as SHIELD (C is the single input, no outputs,
     * fee = amount). A non-zero return is a malformed commitment or the identity
     * excess (amount==0 and r==0) -> reject. */
    uint8_t E[33];
    if (determ_p256_balance_excess(E, payload, 1, 0, 0, amount) != 0) return -1;
    /* Context-BOUND PoK: proves C = amount*G + r*H (knowledge of r) AND binds the
     * spend to ctx32 so a captured proof cannot be redirected. */
    return determ_p256_balance_verify_bound(E, payload + 33, ctx32);
}
