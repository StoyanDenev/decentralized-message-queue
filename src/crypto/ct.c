/* Determ C99-native constant-time equality compare (CRYPTO-C99-SPEC.md §3.10).
 * See ct.h for the usage contract.
 *
 * Accumulate XOR differences with OR across the FULL length — no early return,
 * no secret-dependent branch. The final collapse to 0 / -1 uses the standard
 * unsigned-borrow idiom (same shape as libsodium's crypto_verify family):
 * with d in [0,255], (d - 1u) underflows to 0xFFFFFFFF only when d == 0, so
 * bit 8 of the result distinguishes "all bytes equal" from "any difference"
 * with fully-defined unsigned arithmetic and no branch on the secret-derived
 * accumulator. This consolidates the per-module local helpers the C99 stack
 * accumulated (ct_eq16 in aes_gcm.c and chacha20_poly1305.c, ct_verify_32 in
 * ed25519.c) into one audited site. */
#include "determ/crypto/ct.h"

int determ_ct_memcmp(const void *a, const void *b, size_t len) {
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned int d = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        d |= (unsigned int)(pa[i] ^ pb[i]);
    }
    /* 0 iff d == 0, else -1 (matches the prior ct_eq16 / ct_verify_32
     * conventions and libsodium crypto_verify). */
    return (int)(1u & ((d - 1u) >> 8)) - 1;
}
