/* Determ C99-native ML-DSA (FIPS 204) rejection samplers on the SHAKE XOF.
 * Canonical Dilithium reference construction; the first consumers of
 * src/crypto/sha3/. See include/determ/crypto/mldsa/sample.h + the module README. */
#include <determ/crypto/mldsa/sample.h>
#include <determ/crypto/mldsa/params.h>
#include <determ/crypto/sha3/sha3.h>
#include <determ/crypto/secure_zero.h>

#define N DETERM_MLDSA_N
#define Q DETERM_MLDSA_Q

/* RejNTTPoly / SampleUniform: SHAKE128(seed), 3-byte little-endian 23-bit
 * candidate, accept if < q. The incremental squeeze handles the sponge block
 * boundary, so 3-byte reads never straddle a permutation incorrectly. */
void determ_mldsa_sample_uniform(int32_t a[256], const uint8_t* seed, size_t seedlen) {
    determ_keccak_ctx ctx;
    unsigned ctr = 0;
    uint8_t b[3];

    determ_shake128_init(&ctx);
    determ_keccak_absorb(&ctx, seed, seedlen);
    determ_keccak_finalize(&ctx);
    while (ctr < N) {
        determ_keccak_squeeze(&ctx, b, 3);
        int32_t t = (int32_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8)
                              | (((uint32_t)b[2] & 0x7Fu) << 16));
        if (t < Q) a[ctr++] = t;
    }
    determ_secure_zero(&ctx, sizeof ctx);
}

/* RejBoundedPoly / SampleEta: SHAKE256(seed), each byte gives two 4-bit
 * candidates. eta==2: accept z<15, coeff = 2 - (z mod 5). eta==4: accept z<9,
 * coeff = 4 - z. An unsupported eta yields no accepts (loop cannot fill) — the
 * caller contract requires eta in {2,4}. */
void determ_mldsa_sample_eta(int32_t a[256], const uint8_t* seed, size_t seedlen, int eta) {
    determ_keccak_ctx ctx;
    unsigned ctr = 0;
    uint8_t byte;

    determ_shake256_init(&ctx);
    determ_keccak_absorb(&ctx, seed, seedlen);
    determ_keccak_finalize(&ctx);
    while (ctr < N) {
        uint8_t z0, z1;
        determ_keccak_squeeze(&ctx, &byte, 1);
        z0 = byte & 0x0Fu;
        z1 = byte >> 4;
        if (eta == 2) {
            if (z0 < 15 && ctr < N) a[ctr++] = 2 - (int32_t)(z0 % 5u);
            if (z1 < 15 && ctr < N) a[ctr++] = 2 - (int32_t)(z1 % 5u);
        } else { /* eta == 4 */
            if (z0 < 9 && ctr < N) a[ctr++] = 4 - (int32_t)z0;
            if (z1 < 9 && ctr < N) a[ctr++] = 4 - (int32_t)z1;
        }
    }
    determ_secure_zero(&ctx, sizeof ctx);
}

/* SampleInBall: SHAKE256(seed); the first 8 squeezed bytes are the little-endian
 * sign field, then Fisher-Yates places tau signed 1s at rejection-sampled
 * positions j <= i. Output has exactly tau coefficients in {-1,+1}, rest 0. */
void determ_mldsa_sample_in_ball(int32_t c[256], const uint8_t* seed, size_t seedlen, int tau) {
    determ_keccak_ctx ctx;
    uint8_t s[8], jb;
    uint64_t signs = 0;
    int i, j;

    determ_shake256_init(&ctx);
    determ_keccak_absorb(&ctx, seed, seedlen);
    determ_keccak_finalize(&ctx);
    determ_keccak_squeeze(&ctx, s, 8);
    for (i = 0; i < 8; i++) signs |= (uint64_t)s[i] << (8 * i);

    for (i = 0; i < N; i++) c[i] = 0;
    for (i = N - tau; i < N; i++) {
        do {
            determ_keccak_squeeze(&ctx, &jb, 1);
            j = (int)jb;
        } while (j > i);
        c[i] = c[j];
        c[j] = 1 - 2 * (int32_t)(signs & 1u);
        signs >>= 1;
    }
    determ_secure_zero(&ctx, sizeof ctx);
    determ_secure_zero(s, sizeof s);
}
