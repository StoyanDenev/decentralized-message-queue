/* Determ C99-native Ed25519 (RFC 8032). See ed25519.h.
 *
 * Constant-time field/group arithmetic in the gf[16] (radix-2^16) representation:
 * a cswap-ladder scalar multiplication (no secret-dependent branch or table
 * index) over a branchless GF(2^255-19) field and a branchless mod-L scalar
 * reduction. Composes the C99 SHA-512 in src/crypto/sha2/. Validated byte-equal
 * vs OpenSSL EVP_PKEY_ED25519 + RFC 8032 §7.1 KATs by `determ test-ed25519-c99`.
 *
 * The field/group algorithms follow the public-domain TweetNaCl construction
 * (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers); RFC 8032 §5.1 fixes
 * the signing/verification framing. */
#include "determ/crypto/ed25519/ed25519.h"
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t  u8;
typedef int64_t  i64;
typedef i64      gf[16];

static const gf gf0;
static const gf gf1 = {1};
/* d = -121665/121666 mod p */
static const gf D  = {0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,
                      0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203};
/* 2*d */
static const gf D2 = {0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,
                      0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406};
/* base point x */
static const gf X  = {0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,
                      0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169};
/* base point y = 4/5 */
static const gf Y  = {0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,
                      0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666};
/* sqrt(-1) mod p */
static const gf I  = {0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43,
                      0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83};

/* group order L = 2^252 + 27742317777372353535851937790883648493 (little-endian) */
static const i64 L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

static void set25519(gf r, const gf a) { int i; for (i = 0; i < 16; i++) r[i] = a[i]; }

/* Branchless carry/reduce of a field element in the gf[16] representation. */
static void car25519(gf o) {
    int i; i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

/* Constant-time conditional swap of p,q when b == 1. */
static void sel25519(gf p, gf q, int b) {
    i64 t, c = ~(b - 1);
    int i;
    for (i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

static void pack25519(u8 *o, const gf n) {
    int i, j, b; gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) { o[2 * i] = (u8)(t[i] & 0xff); o[2 * i + 1] = (u8)(t[i] >> 8); }
}

static int neq25519(const gf a, const gf b) {
    u8 c[32], d[32]; int i, r = 0;
    pack25519(c, a); pack25519(d, b);
    for (i = 0; i < 32; i++) r |= (c[i] ^ d[i]);
    return r != 0;   /* 1 if a != b */
}

static u8 par25519(const gf a) { u8 d[32]; pack25519(d, a); return d[0] & 1; }

static void unpack25519(gf o, const u8 *n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void Z(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void M(gf o, const gf a, const gf b) {
    i64 t[31]; int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

/* o = i^(2^255-21) = i^-1 mod p */
static void inv25519(gf o, const gf i) {
    gf c; int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) { S(c, c); if (a != 2 && a != 4) M(c, c, i); }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

/* o = i^((p-5)/8) = i^(2^252-3) mod p */
static void pow2523(gf o, const gf i) {
    gf c; int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) { S(c, c); if (a != 1) M(c, c, i); }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

/* Edwards point addition on extended coordinates p = (X,Y,Z,T), p += q. */
static void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t);
    A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t);
    M(c, p[3], q[3]); M(c, c, D2);
    M(d, p[2], q[2]); A(d, d, d);
    Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a);
    M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], u8 b) {
    int i;
    for (i = 0; i < 4; i++) sel25519(p[i], q[i], b);
}

static void pack(u8 *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const u8 *s) {
    int i;
    set25519(p[0], gf0); set25519(p[1], gf1);
    set25519(p[2], gf1); set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        u8 b = (u8)((s[i / 8] >> (i & 7)) & 1);
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const u8 *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

/* r[0..31] = (sum of x[0..63] as a 504-bit little-endian integer) mod L. */
static void modL(u8 *r, i64 x[64]) {
    i64 carry; int i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) { x[j] += carry - (x[31] >> 4) * L[j]; carry = x[j] >> 8; x[j] &= 255; }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) { x[i + 1] += x[i] >> 8; r[i] = (u8)(x[i] & 255); }
}

/* In-place reduce of a 64-byte little-endian value mod L -> r[0..31]. */
static void reduce(u8 *r) {
    i64 x[64]; int i;
    for (i = 0; i < 64; i++) x[i] = (i64)(uint64_t)r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    modL(r, x);
}

/* Decompress pk into -A (the negated public-key point). Returns 0 on a valid
 * point, -1 if pk does not encode a curve point. */
static int unpackneg(gf r[4], const u8 p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]); M(den, num, D); Z(num, num, r[2]); A(den, r[2], den);
    S(den2, den); S(den4, den2); M(den6, den4, den2);
    M(t, den6, num); M(t, t, den);
    pow2523(t, t);
    M(t, t, num); M(t, t, den); M(t, t, den); M(r[0], t, den);
    S(chk, r[0]); M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);
    S(chk, r[0]); M(chk, chk, den);
    if (neq25519(chk, num)) return -1;
    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

static int ct_verify_32(const u8 *x, const u8 *y) {
    u8 d = 0; int i;
    for (i = 0; i < 32; i++) d |= (u8)(x[i] ^ y[i]);
    return d == 0 ? 0 : -1;
}

/* Constant-time test that the 32-byte little-endian scalar s is canonical
 * (s < L, the group order). Returns 1 iff s < L. Computes s - L byte-wise and
 * inspects the final borrow — no data-dependent branch. RFC 8032 §5.1.7 step 1
 * requires the verifier to reject a non-canonical S (defeats (R, S+L)
 * malleability); the daemon's signer always emits canonical S via modL. */
static int sc_lt_L(const u8 s[32]) {
    unsigned int borrow = 0; int i;
    for (i = 0; i < 32; i++) {
        unsigned int d = (unsigned int)s[i] - (unsigned int)(u8)L[i] - borrow;
        borrow = (d >> 8) & 1u;   /* 1 if this byte underflowed */
    }
    return (int)borrow;           /* 1 iff s < L */
}

/* 1 iff the 32-byte little-endian point encoding p has a canonical y < q
 * (q = 2^255-19). RFC 8032 §5.1.3 rejects y >= q on decode; the field's reduced
 * canonical form (pack25519) is compared against the input's low 255 bits.
 * Branch is on PUBLIC key bytes, so it is not a constant-time concern. NOTE:
 * this is STRICTER than OpenSSL's lenient ref10 decoder, which accepts the 19
 * non-canonical y in {q..q+18}; we follow RFC 8032 to keep "one point = one
 * encoding" for any consensus / anon-address derivation over the raw bytes. */
static int point_y_is_canonical(const u8 p[32]) {
    gf y; u8 rt[32], d = 0; int i;
    unpack25519(y, p);            /* y = low 255 bits of p */
    pack25519(rt, y);             /* canonical (reduced mod q) encoding of y */
    for (i = 0; i < 31; i++) d |= (u8)(rt[i] ^ p[i]);
    d |= (u8)(rt[31] ^ (u8)(p[31] & 0x7f));   /* ignore the sign bit (p[31] bit 7) */
    return d == 0 ? 1 : 0;
}

void determ_ed25519_pubkey_from_seed(const u8 seed[32], u8 pk[32]) {
    u8 h[64]; gf p[4];
    determ_sha512(seed, 32, h);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;     /* RFC 8032 clamp */
    scalarbase(p, h);                            /* [a] B  (a = h[0..31]) */
    pack(pk, p);
    determ_secure_zero(h, sizeof h);
}

int determ_ed25519_sign(const u8 seed[32], const u8 pk[32],
                        const u8 *msg, size_t msglen, u8 sig[64]) {
    u8 h[64], a[32], rh[64], hram[64];
    gf P[4];
    i64 x[64]; int i, j;
    u8 *buf;

    if (msglen > SIZE_MAX - 64u) return -1;

    determ_sha512(seed, 32, h);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    for (i = 0; i < 32; i++) a[i] = h[i];        /* clamped scalar a */

    buf = (u8 *)malloc(64 + msglen);
    if (buf == NULL) {
        determ_secure_zero(h, sizeof h);
        determ_secure_zero(a, sizeof a);
        return -1;
    }

    /* r = reduce( SHA512( prefix || msg ) ), prefix = h[32..63] */
    for (i = 0; i < 32; i++) buf[i] = h[32 + i];
    if (msglen) memcpy(buf + 32, msg, msglen);   /* size_t-safe splice */
    determ_sha512(buf, 32 + msglen, rh);
    reduce(rh);                                  /* rh[0..31] = r */

    /* R = [r] B */
    scalarbase(P, rh);
    pack(sig, P);

    /* k = reduce( SHA512( R || pk || msg ) ) */
    for (i = 0; i < 32; i++) { buf[i] = sig[i]; buf[32 + i] = pk[i]; }
    if (msglen) memcpy(buf + 64, msg, msglen);   /* size_t-safe splice */
    determ_sha512(buf, 64 + msglen, hram);
    reduce(hram);                                /* hram[0..31] = k */

    /* S = (r + k*a) mod L */
    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) for (j = 0; j < 32; j++) x[i + j] += (i64)hram[i] * (i64)a[j];
    for (i = 0; i < 32; i++) x[i] += (i64)rh[i];
    modL(sig + 32, x);

    determ_secure_zero(h, sizeof h);
    determ_secure_zero(a, sizeof a);
    determ_secure_zero(rh, sizeof rh);
    determ_secure_zero(x, sizeof x);
    determ_secure_zero(buf, 64 + msglen);
    free(buf);
    return 0;
}

int determ_ed25519_verify(const u8 pk[32],
                          const u8 *msg, size_t msglen, const u8 sig[64]) {
    u8 hram[64], t[32];
    gf P[4], Q[4];
    int i, rc;
    u8 *buf;

    if (msglen > SIZE_MAX - 64u) return -1;
    if (!point_y_is_canonical(pk)) return -1;    /* RFC 8032 §5.1.3: reject y >= q */
    if (!sc_lt_L(sig + 32)) return -1;           /* RFC 8032 §5.1.7: reject S >= L (anti-malleability) */
    if (unpackneg(Q, pk)) return -1;             /* Q = -A */

    buf = (u8 *)malloc(64 + msglen);
    if (buf == NULL) return -1;

    for (i = 0; i < 32; i++) { buf[i] = sig[i]; buf[32 + i] = pk[i]; }
    if (msglen) memcpy(buf + 64, msg, msglen);   /* size_t-safe splice */
    determ_sha512(buf, 64 + msglen, hram);
    reduce(hram);

    scalarmult(P, Q, hram);                       /* [k](-A) */
    scalarbase(Q, sig + 32);                      /* [S] B   (reuses Q) */
    add(P, Q);                                    /* [S]B - [k]A */
    pack(t, P);

    rc = ct_verify_32(sig, t);                    /* accept iff encodes R */
    free(buf);
    return rc;
}
