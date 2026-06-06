/* Determ C99-native X25519 (RFC 7748) — Curve25519 Diffie-Hellman.
 *
 * TweetNaCl-derived (public domain, Bernstein et al.) constant-time Montgomery
 * ladder over the Curve25519 field (p = 2^255-19), the same field/ladder lineage
 * as src/crypto/ed25519/ed25519.c. No libsodium. See include/determ/crypto/x25519/x25519.h.
 */
#include <determ/crypto/x25519/x25519.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

typedef int64_t i64;
typedef i64 gf[16];

static const gf _121665 = { 0xDB41, 1 };

static void car25519(gf o) {
    int i; i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

/* constant-time conditional swap of p,q when b==1 (b in {0,1}). */
static void sel25519(gf p, gf q, int b) {
    i64 t, i, c = ~(b - 1);
    for (i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

static void pack25519(uint8_t *o, const gf n) {
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
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) { o[2 * i] = (uint8_t)(t[i] & 0xff); o[2 * i + 1] = (uint8_t)(t[i] >> 8); }
}

static void unpack25519(gf o, const uint8_t *n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fadd(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void fsub(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void fmul(gf o, const gf a, const gf b) {
    i64 i, j, t[31];
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
}

static void fsqr(gf o, const gf a) { fmul(o, a, a); }

/* o = i^-1 mod p, via the public fixed exponent p-2 (no secret-dependent branch). */
static void inv25519(gf o, const gf i) {
    gf c; int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) { fsqr(c, c); if (a != 2 && a != 4) fmul(c, c, i); }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

int determ_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t z[32]; i64 x[80], r, i; gf a, b, c, d, e, f;
    int k, allzero;

    /* RFC 7748 §5 clamping on a private copy of the scalar. */
    for (i = 0; i < 31; i++) z[i] = scalar[i];
    z[31] = (scalar[31] & 127) | 64;
    z[0] &= 248;

    unpack25519(x, point);
    for (i = 0; i < 16; i++) { b[i] = x[i]; d[i] = a[i] = c[i] = 0; }
    a[0] = d[0] = 1;

    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fsqr(d, e);
        fsqr(f, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fsqr(b, a);
        fsub(c, d, f);
        fmul(a, c, _121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fsqr(b, e);
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }
    for (i = 0; i < 16; i++) { x[i + 16] = a[i]; x[i + 32] = c[i]; x[i + 48] = b[i]; x[i + 64] = d[i]; }
    inv25519(x + 32, x + 32);
    fmul(x + 16, x + 16, x + 32);
    pack25519(out, x + 16);

    /* RFC 7748 contributory check: reject the all-zero (low-order) result. */
    allzero = 0; for (k = 0; k < 32; k++) allzero |= out[k];

    determ_secure_zero(z, sizeof z);
    determ_secure_zero(x, sizeof x);
    determ_secure_zero(a, sizeof a); determ_secure_zero(b, sizeof b);
    determ_secure_zero(c, sizeof c); determ_secure_zero(d, sizeof d);
    determ_secure_zero(e, sizeof e); determ_secure_zero(f, sizeof f);
    return allzero ? 0 : -1;
}

int determ_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    static const uint8_t base[32] = { 9 };
    /* base-point mult is never low-order for a clamped scalar; normalize to 0. */
    return determ_x25519(out, scalar, base) == 0 ? 0 : 0;
}
