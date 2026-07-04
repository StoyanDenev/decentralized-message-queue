/* ML-DSA (FIPS 204) coefficient bit-packing — the polynomial ↔ byte-string codec.
 *
 * Keygen/sign/verify serialize polynomials at fixed bit widths: t1 (10 bits, the
 * public key), t0 (13 bits, the secret key), s1/s2 (η-dependent, the secret key),
 * w1 (γ2-dependent, hashed into the challenge), z (γ1-dependent, the signature).
 * All are little-endian bit-stream packings; the generic `pack_bits`/`unpack_bits`
 * below produce byte-identical output to the canonical Dilithium per-field packers
 * (verified vs the reference pack_t1), and the signed encodings are a thin
 * coefficient transform (offset/negate) layered on top.
 *
 * Pure bit manipulation — no SHAKE, no secrets held. See src/crypto/mldsa/pack.c
 * and the module README. Additive; no in-tree consumer yet.
 */
#ifndef DETERM_CRYPTO_MLDSA_PACK_H
#define DETERM_CRYPTO_MLDSA_PACK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic LSB-first bit-stream codec over `n` unsigned values of `bits` bits each
 * (1 ≤ bits ≤ 30). pack writes ceil(n*bits/8) bytes; unpack is the inverse.
 * Inputs to pack must already be in [0, 2^bits) (the value is masked defensively). */
void determ_mldsa_pack_bits(uint8_t* out, const int32_t* in, int n, int bits);
void determ_mldsa_unpack_bits(int32_t* out, const uint8_t* in, int n, int bits);

/* Public-key t1: 256 × 10-bit unsigned → 320 bytes. */
void determ_mldsa_pack_t1(uint8_t out[320], const int32_t t1[256]);
void determ_mldsa_unpack_t1(int32_t t1[256], const uint8_t in[320]);

/* Secret-key t0: 256 × 13-bit, coefficient in (-2^12, 2^12] stored as 2^12 - t0
 * → 416 bytes. */
void determ_mldsa_pack_t0(uint8_t out[416], const int32_t t0[256]);
void determ_mldsa_unpack_t0(int32_t t0[256], const uint8_t in[416]);

/* Secret vectors s1/s2: coefficient in [-η,η] stored as η - s. eta must be 2
 * (3-bit, 96 bytes) or 4 (4-bit, 128 bytes). */
void determ_mldsa_pack_eta(uint8_t* out, const int32_t s[256], int eta);
void determ_mldsa_unpack_eta(int32_t s[256], const uint8_t* in, int eta);

/* w1 (hashed into the challenge): unsigned, γ2-dependent width — 6-bit for
 * GAMMA2_88 (192 bytes), 4-bit for GAMMA2_32 (128 bytes). Pack-only. */
void determ_mldsa_pack_w1(uint8_t* out, const int32_t w1[256], int32_t gamma2);

/* Signature z: coefficient in (-γ1, γ1] stored as γ1 - z. γ1-dependent width —
 * 18-bit for GAMMA1_17 (576 bytes), 20-bit for GAMMA1_19 (640 bytes). */
void determ_mldsa_pack_z(uint8_t* out, const int32_t z[256], int32_t gamma1);
void determ_mldsa_unpack_z(int32_t z[256], const uint8_t* in, int32_t gamma1);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_MLDSA_PACK_H */
