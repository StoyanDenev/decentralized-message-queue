/* Determ C99-native Argon2id (RFC 9106 / P-H-C reference). libsodium-free; built on
 * the C99 BLAKE2b. See include/determ/crypto/argon2/argon2id.h. */
#include <determ/crypto/argon2/argon2id.h>
#include <determ/crypto/blake2/blake2b.h>
#include <determ/crypto/secure_zero.h>
#include <stdlib.h>
#include <string.h>

#define QWORDS 128u          /* 1024-byte block = 128 uint64 */
#define BLOCKBYTES 1024u
#define SYNC_POINTS 4u
#define ADDR_IN_BLOCK 128u   /* pseudo-random words per address block */
#define ARGON2_TYPE_ID 2u
#define ARGON2_VERSION 0x13u

typedef struct { uint64_t v[QWORDS]; } block;

static uint64_t rotr64(uint64_t w, unsigned c) { return (w >> c) | (w << (64 - c)); }
/* fBlaMka: x + y + 2 * lo32(x) * lo32(y)  (all mod 2^64). */
static uint64_t fBlaMka(uint64_t x, uint64_t y) {
    uint64_t xy = (x & 0xffffffffULL) * (y & 0xffffffffULL);
    return x + y + 2 * xy;
}

#define GB(a,b,c,d) do { \
    a = fBlaMka(a,b); d = rotr64(d ^ a, 32); \
    c = fBlaMka(c,d); b = rotr64(b ^ c, 24); \
    a = fBlaMka(a,b); d = rotr64(d ^ a, 16); \
    c = fBlaMka(c,d); b = rotr64(b ^ c, 63); \
} while (0)

/* P: the BLAKE2-round permutation over 16 uint64 (passed by pointer in v[]). */
#define P(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) do { \
    GB(v0,v4,v8, v12); GB(v1,v5,v9, v13); GB(v2,v6,v10,v14); GB(v3,v7,v11,v15); \
    GB(v0,v5,v10,v15); GB(v1,v6,v11,v12); GB(v2,v7,v8, v13); GB(v3,v4,v9, v14); \
} while (0)

static void load_block(block *dst, const uint8_t *src) {
    unsigned i;
    for (i = 0; i < QWORDS; i++) {
        const uint8_t *p = src + 8 * i;
        dst->v[i] = (uint64_t)p[0] | ((uint64_t)p[1]<<8) | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24)
                  | ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40) | ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
    }
}
static void store_block(uint8_t *dst, const block *src) {
    unsigned i, j;
    for (i = 0; i < QWORDS; i++) { uint64_t x = src->v[i]; for (j = 0; j < 8; j++) { dst[8*i+j] = (uint8_t)x; x >>= 8; } }
}

/* next = (with_xor ? next : 0) XOR R XOR P(R), where R = prev XOR ref. */
static void fill_block(const block *prev, const block *ref, block *next, int with_xor) {
    block R, Z; unsigned i;
    for (i = 0; i < QWORDS; i++) R.v[i] = prev->v[i] ^ ref->v[i];
    Z = R;
    /* row pass: 8 rows of 16 contiguous words */
    for (i = 0; i < 8; i++) {
        uint64_t *r = &Z.v[16 * i];
        P(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13],r[14],r[15]);
    }
    /* column pass: 8 columns, strided (each cell = 2 words, stride 16) */
    for (i = 0; i < 8; i++) {
        uint64_t *z = Z.v;
        P(z[2*i],     z[2*i+1],     z[2*i+16],  z[2*i+17],  z[2*i+32],  z[2*i+33],  z[2*i+48],  z[2*i+49],
          z[2*i+64],  z[2*i+65],    z[2*i+80],  z[2*i+81],  z[2*i+96],  z[2*i+97],  z[2*i+112], z[2*i+113]);
    }
    for (i = 0; i < QWORDS; i++) {
        uint64_t res = R.v[i] ^ Z.v[i];
        next->v[i] = with_xor ? (next->v[i] ^ res) : res;
    }
    determ_secure_zero(&R, sizeof R); determ_secure_zero(&Z, sizeof Z);
}

static void le32(uint8_t out[4], uint32_t v) { out[0]=(uint8_t)v; out[1]=(uint8_t)(v>>8); out[2]=(uint8_t)(v>>16); out[3]=(uint8_t)(v>>24); }

/* Argon2 variable-length hash H'^T(in) (RFC 9106 §3.3). */
static void blake2b_long(uint8_t *out, uint32_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t lenb[4]; le32(lenb, outlen);
    if (outlen <= 64) {
        determ_blake2b_ctx ctx;
        determ_blake2b_init(&ctx, outlen, NULL, 0);
        determ_blake2b_update(&ctx, lenb, 4);
        determ_blake2b_update(&ctx, in, inlen);
        determ_blake2b_final(&ctx, out);
        return;
    }
    {
        uint8_t v[64]; uint32_t produced = 0, toproduce = outlen;
        determ_blake2b_ctx ctx;
        determ_blake2b_init(&ctx, 64, NULL, 0);
        determ_blake2b_update(&ctx, lenb, 4);
        determ_blake2b_update(&ctx, in, inlen);
        determ_blake2b_final(&ctx, v);
        memcpy(out, v, 32); produced = 32; toproduce -= 32;
        while (toproduce > 64) {
            determ_blake2b(v, 64, NULL, 0, v, 64);
            memcpy(out + produced, v, 32); produced += 32; toproduce -= 32;
        }
        determ_blake2b(out + produced, toproduce, NULL, 0, v, 64);  /* final block, size toproduce */
        determ_secure_zero(v, sizeof v);
    }
}

/* index_alpha: the reference-block position within its lane (RFC 9106 §3.4). */
static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index,
                            uint32_t seg_len, uint32_t lane_len,
                            uint32_t pseudo_rand, int same_lane) {
    uint64_t area, rel, phi; uint32_t start;
    if (pass == 0) {
        if (slice == 0)        area = index - 1;
        else if (same_lane)    area = (uint64_t)slice * seg_len + index - 1;
        else                   area = (uint64_t)slice * seg_len + (index == 0 ? (uint64_t)-1 : 0);
    } else {
        if (same_lane)         area = (uint64_t)lane_len - seg_len + index - 1;
        else                   area = (uint64_t)lane_len - seg_len + (index == 0 ? (uint64_t)-1 : 0);
    }
    rel = pseudo_rand;
    rel = (rel * rel) >> 32;
    rel = area - 1 - ((area * rel) >> 32);
    if (pass != 0) start = (slice == SYNC_POINTS - 1) ? 0 : (slice + 1) * seg_len;
    else           start = 0;
    phi = ((uint64_t)start + rel) % lane_len;
    return (uint32_t)phi;
}

int determ_argon2id(uint8_t *out, size_t outlen,
                    const uint8_t *pwd, size_t pwdlen,
                    const uint8_t *salt, size_t saltlen,
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism) {
    uint8_t H0[72];               /* 64-byte H0 + 4 (block idx) + 4 (lane) appended for H' input */
    uint32_t mem, seg, lane_len, p = parallelism;
    block *B = NULL; uint8_t lenb[4]; size_t i; uint32_t pass, slice, lane;
    int rc = -1;

    /* Reject params that would silently truncate in the LE32 H0 encoding (RFC 9106
     * §3.1 length fields are 32-bit) or overflow uint32 in the segment math. The
     * p <= UINT32_MAX/8 bound makes both 8*p and p*SYNC_POINTS overflow-free.
     * (audit ARG2ID-001/-002/-003 + ARGON2ID-003/-005) */
    if (outlen < 4 || outlen > 0xffffffffULL || t_cost < 1 ||
        pwdlen > 0xffffffffULL || saltlen > 0xffffffffULL ||
        p < 1 || p > (UINT32_MAX / 8u)) return -1;
    if (m_cost < 8 * p) m_cost = 8 * p;
    seg = m_cost / (p * SYNC_POINTS);
    if (seg < 1) return -1;
    mem = seg * p * SYNC_POINTS;
    lane_len = seg * SYNC_POINTS;

    /* ---- H0 = BLAKE2b-512( params ‖ pwd ‖ salt ‖ secret(0) ‖ ad(0) ) ---- */
    {
        determ_blake2b_ctx ctx;
        determ_blake2b_init(&ctx, 64, NULL, 0);
        le32(lenb, p);            determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, (uint32_t)outlen); determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, m_cost);       determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, t_cost);       determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, ARGON2_VERSION); determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, ARGON2_TYPE_ID); determ_blake2b_update(&ctx, lenb, 4);
        le32(lenb, (uint32_t)pwdlen);  determ_blake2b_update(&ctx, lenb, 4);
        if (pwdlen)  determ_blake2b_update(&ctx, pwd, pwdlen);
        le32(lenb, (uint32_t)saltlen); determ_blake2b_update(&ctx, lenb, 4);
        if (saltlen) determ_blake2b_update(&ctx, salt, saltlen);
        le32(lenb, 0);            determ_blake2b_update(&ctx, lenb, 4);   /* secret length */
        le32(lenb, 0);            determ_blake2b_update(&ctx, lenb, 4);   /* assoc-data length */
        determ_blake2b_final(&ctx, H0);
    }

    B = (block *)malloc((size_t)mem * sizeof(block));
    if (!B) goto done;

    /* ---- initial blocks B[l][0], B[l][1] for each lane ---- */
    for (lane = 0; lane < p; lane++) {
        uint8_t blk[BLOCKBYTES];
        le32(H0 + 64, 0); le32(H0 + 68, lane);
        blake2b_long(blk, BLOCKBYTES, H0, 72);
        load_block(&B[lane * lane_len + 0], blk);
        le32(H0 + 64, 1); le32(H0 + 68, lane);
        blake2b_long(blk, BLOCKBYTES, H0, 72);
        load_block(&B[lane * lane_len + 1], blk);
        determ_secure_zero(blk, sizeof blk);
    }

    /* ---- fill memory ---- */
    for (pass = 0; pass < t_cost; pass++) {
        for (slice = 0; slice < SYNC_POINTS; slice++) {
            for (lane = 0; lane < p; lane++) {
                int data_indep = (pass == 0 && slice < SYNC_POINTS / 2);   /* Argon2id hybrid */
                block addr, input, zero;
                uint32_t start_index = 0, idx;
                if (data_indep) {
                    memset(&zero, 0, sizeof zero); memset(&input, 0, sizeof input);
                    input.v[0]=pass; input.v[1]=lane; input.v[2]=slice;
                    input.v[3]=mem;  input.v[4]=t_cost; input.v[5]=ARGON2_TYPE_ID;
                }
                if (pass == 0 && slice == 0) {
                    start_index = 2;
                    if (data_indep) { input.v[6]++; fill_block(&zero,&input,&addr,0); fill_block(&zero,&addr,&addr,0); }
                }
                for (idx = start_index; idx < seg; idx++) {
                    uint32_t cur = lane * lane_len + slice * seg + idx;
                    uint32_t prev = (cur % lane_len == 0) ? (cur + lane_len - 1) : (cur - 1);
                    uint64_t pr; uint32_t ref_lane, ref_index; int same;
                    if (data_indep) {
                        if (idx % ADDR_IN_BLOCK == 0) { input.v[6]++; fill_block(&zero,&input,&addr,0); fill_block(&zero,&addr,&addr,0); }
                        pr = addr.v[idx % ADDR_IN_BLOCK];
                    } else {
                        pr = B[prev].v[0];
                    }
                    ref_lane = (pass == 0 && slice == 0) ? lane : (uint32_t)((pr >> 32) % p);
                    same = (ref_lane == lane);
                    ref_index = index_alpha(pass, slice, idx, seg, lane_len, (uint32_t)(pr & 0xffffffffULL), same);
                    {
                        const block *refb = &B[ref_lane * lane_len + ref_index];
                        fill_block(&B[prev], refb, &B[cur], pass != 0);
                    }
                }
            }
        }
    }

    /* ---- final: XOR last column across lanes, then H'(outlen) ---- */
    {
        block final = B[lane_len - 1];      /* lane 0 last block */
        uint8_t fb[BLOCKBYTES];
        for (lane = 1; lane < p; lane++)
            for (i = 0; i < QWORDS; i++) final.v[i] ^= B[lane * lane_len + lane_len - 1].v[i];
        store_block(fb, &final);
        blake2b_long(out, (uint32_t)outlen, fb, BLOCKBYTES);
        determ_secure_zero(&final, sizeof final); determ_secure_zero(fb, sizeof fb);
    }
    rc = 0;

done:
    if (B) { determ_secure_zero(B, (size_t)mem * sizeof(block)); free(B); }
    determ_secure_zero(H0, sizeof H0);
    return rc;
}
