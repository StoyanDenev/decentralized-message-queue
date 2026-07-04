/* Determ C99-native ML-DSA (FIPS 204) coefficient bit-packing.
 * Canonical Dilithium little-endian bit-stream layout; no external dependency.
 * See include/determ/crypto/mldsa/pack.h and src/crypto/mldsa/README.md. */
#include <determ/crypto/mldsa/pack.h>
#include <determ/crypto/mldsa/params.h>

#define N DETERM_MLDSA_N

/* LSB-first: value i occupies bits [i*bits, (i+1)*bits) of the byte stream, the
 * low bit of each value first. The 32-bit accumulator holds at most bits+7 ≤ 37
 * — but bits ≤ 30 and we flush at ≥ 8, so at most 7 + 30 = 37 would overflow;
 * callers use bits ≤ 20, giving ≤ 27 accumulated bits (safe in uint32). */
void determ_mldsa_pack_bits(uint8_t* out, const int32_t* in, int n, int bits) {
    uint32_t acc = 0, mask = (bits >= 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    int nbits = 0, oi = 0, i;
    for (i = 0; i < n; i++) {
        acc |= ((uint32_t)in[i] & mask) << nbits;
        nbits += bits;
        while (nbits >= 8) { out[oi++] = (uint8_t)(acc & 0xFFu); acc >>= 8; nbits -= 8; }
    }
    if (nbits) out[oi] = (uint8_t)(acc & 0xFFu);
}

void determ_mldsa_unpack_bits(int32_t* out, const uint8_t* in, int n, int bits) {
    uint32_t acc = 0, mask = (bits >= 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    int nbits = 0, bi = 0, i;
    for (i = 0; i < n; i++) {
        while (nbits < bits) { acc |= (uint32_t)in[bi++] << nbits; nbits += 8; }
        out[i] = (int32_t)(acc & mask); acc >>= bits; nbits -= bits;
    }
}

void determ_mldsa_pack_t1(uint8_t out[320], const int32_t t1[256]) {
    determ_mldsa_pack_bits(out, t1, N, 10);
}
void determ_mldsa_unpack_t1(int32_t t1[256], const uint8_t in[320]) {
    determ_mldsa_unpack_bits(t1, in, N, 10);
}

void determ_mldsa_pack_t0(uint8_t out[416], const int32_t t0[256]) {
    int32_t tmp[256]; int i;
    for (i = 0; i < N; i++) tmp[i] = (1 << (DETERM_MLDSA_D - 1)) - t0[i];
    determ_mldsa_pack_bits(out, tmp, N, 13);
}
void determ_mldsa_unpack_t0(int32_t t0[256], const uint8_t in[416]) {
    int i;
    determ_mldsa_unpack_bits(t0, in, N, 13);
    for (i = 0; i < N; i++) t0[i] = (1 << (DETERM_MLDSA_D - 1)) - t0[i];
}

void determ_mldsa_pack_eta(uint8_t* out, const int32_t s[256], int eta) {
    int32_t tmp[256]; int i, bits = (eta == 2) ? 3 : 4;
    for (i = 0; i < N; i++) tmp[i] = eta - s[i];
    determ_mldsa_pack_bits(out, tmp, N, bits);
}
void determ_mldsa_unpack_eta(int32_t s[256], const uint8_t* in, int eta) {
    int i, bits = (eta == 2) ? 3 : 4;
    determ_mldsa_unpack_bits(s, in, N, bits);
    for (i = 0; i < N; i++) s[i] = eta - s[i];
}

void determ_mldsa_pack_w1(uint8_t* out, const int32_t w1[256], int32_t gamma2) {
    int bits = (gamma2 == DETERM_MLDSA_GAMMA2_88) ? 6 : 4;
    determ_mldsa_pack_bits(out, w1, N, bits);
}

void determ_mldsa_pack_z(uint8_t* out, const int32_t z[256], int32_t gamma1) {
    int32_t tmp[256]; int i, bits = (gamma1 == DETERM_MLDSA_GAMMA1_17) ? 18 : 20;
    for (i = 0; i < N; i++) tmp[i] = gamma1 - z[i];
    determ_mldsa_pack_bits(out, tmp, N, bits);
}
void determ_mldsa_unpack_z(int32_t z[256], const uint8_t* in, int32_t gamma1) {
    int i, bits = (gamma1 == DETERM_MLDSA_GAMMA1_17) ? 18 : 20;
    determ_mldsa_unpack_bits(z, in, N, bits);
    for (i = 0; i < N; i++) z[i] = gamma1 - z[i];
}
