/* Determ C99 crypto stack — LIVE byte-equal cross-validation against libsodium.
 *
 * The determ daemon is libsodium-free; this harness is the explicit equivalence
 * proof that the C99 primitives reproduce libsodium byte-for-byte, so a future
 * migration of the libsodium call sites (e.g. the keyfile KDF) onto the C99 stack
 * is provably behaviour-preserving. It is NOT built into any determ binary — it is
 * compiled standalone by tools/test_c99_libsodium_xval.sh, linking the build tree's
 * libsodium.a:
 *
 *   gcc -I include -I <sodium-include> tools/c99_libsodium_xval.c \
 *       src/crypto/argon2/argon2id.c src/crypto/blake2/blake2b.c \
 *       src/crypto/x25519/x25519.c src/crypto/chacha20/chacha20.c \
 *       src/crypto/chacha20/poly1305.c src/crypto/chacha20/chacha20_poly1305.c \
 *       src/crypto/chacha20/xchacha20_poly1305.c src/crypto/secure_zero.c \
 *       <build>/_deps/sodium-build/libsodium.a -lpthread -o /tmp/c99xval
 *
 * Exit 0 iff every comparison matched.
 */
#include <determ/crypto/argon2/argon2id.h>
#include <determ/crypto/blake2/blake2b.h>
#include <determ/crypto/x25519/x25519.h>
#include <determ/crypto/chacha20/xchacha20_poly1305.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int fails = 0, total = 0;
static void expect(int ok, const char *what) {
    total++;
    if (ok) { printf("  PASS: %s\n", what); }
    else    { printf("  FAIL: %s\n", what); fails++; }
}

/* deterministic filler so the run is reproducible */
static void fill(unsigned char *p, size_t n, unsigned seed) {
    size_t i; for (i = 0; i < n; i++) p[i] = (unsigned char)((i * 131u + seed * 17u + 7u) & 0xff);
}

static void test_blake2b(void) {
    /* libsodium crypto_generichash IS BLAKE2b; it restricts outlen>=16 and
     * keylen==0 or in [16,64], so compare over the overlapping domain. */
    size_t outl[] = {16, 32, 48, 64};
    size_t keyl[] = {0, 16, 32, 64};
    size_t inl[]  = {0, 1, 64, 127, 128, 200, 1000};
    int oi, ki, ii, ok = 1;
    for (oi = 0; oi < 4 && ok; oi++)
    for (ki = 0; ki < 4 && ok; ki++)
    for (ii = 0; ii < 7 && ok; ii++) {
        unsigned char in[1000], key[64], a[64], b[64];
        size_t ol = outl[oi], kl = keyl[ki], il = inl[ii];
        fill(in, il, (unsigned)(ii + 1)); fill(key, kl, (unsigned)(ki + 9));
        determ_blake2b(a, ol, kl ? key : NULL, kl, il ? in : NULL, il);
        crypto_generichash(b, ol, il ? in : NULL, il, kl ? key : NULL, kl);
        if (memcmp(a, b, ol) != 0) ok = 0;
    }
    expect(ok, "BLAKE2b C99 == libsodium crypto_generichash (outlen{16,32,48,64} x key{0,16,32,64} x len grid)");
}

static void test_x25519(void) {
    int t, okpub = 1, okdh = 1;
    for (t = 0; t < 64 && okpub && okdh; t++) {
        unsigned char a[32], b[32], pa[32], pb[32], opa[32], opb[32], ssA[32], ssB[32], oss[32];
        fill(a, 32, (unsigned)(t + 1)); fill(b, 32, (unsigned)(t + 101));
        determ_x25519_base(pa, a); determ_x25519_base(pb, b);
        crypto_scalarmult_base(opa, a); crypto_scalarmult_base(opb, b);
        if (memcmp(pa, opa, 32) || memcmp(pb, opb, 32)) { okpub = 0; break; }
        determ_x25519(ssA, a, pb); determ_x25519(ssB, b, pa);
        if (crypto_scalarmult(oss, a, pb) != 0) { okdh = 0; break; }
        if (memcmp(ssA, oss, 32) || memcmp(ssA, ssB, 32)) { okdh = 0; break; }
    }
    expect(okpub, "X25519 base-point mult C99 == libsodium crypto_scalarmult_base (64 scalars)");
    expect(okdh,  "X25519 ECDH C99 == libsodium crypto_scalarmult (64 keypairs) + DH symmetry");
}

static void test_xchacha(void) {
    size_t ptl[] = {0, 1, 16, 63, 64, 200};
    size_t adl[] = {0, 1, 16, 20};
    int pi, ai, ok = 1;
    for (pi = 0; pi < 6 && ok; pi++)
    for (ai = 0; ai < 4 && ok; ai++) {
        unsigned char key[32], n24[24], pt[200], ad[20], ct[200], tag[16], c2[216];
        unsigned long long c2len = 0;
        size_t pl = ptl[pi], al = adl[ai];
        fill(key, 32, (unsigned)(pi + 1)); fill(n24, 24, (unsigned)(ai + 5));
        fill(pt, pl, (unsigned)(pi + 9)); fill(ad, al, (unsigned)(ai + 3));
        determ_xchacha20_poly1305_encrypt(key, n24, al ? ad : NULL, al, pl ? pt : NULL, pl, ct, tag);
        crypto_aead_xchacha20poly1305_ietf_encrypt(c2, &c2len, pl ? pt : NULL, pl,
                                                   al ? ad : NULL, al, NULL, n24, key);
        /* libsodium emits ciphertext||tag (pl+16) */
        if (c2len != pl + 16) ok = 0;
        else if (pl && memcmp(ct, c2, pl) != 0) ok = 0;
        else if (memcmp(tag, c2 + pl, 16) != 0) ok = 0;
    }
    expect(ok, "XChaCha20-Poly1305 C99 == libsodium crypto_aead_xchacha20poly1305_ietf (pt x aad grid)");
}

static void test_argon2id(void) {
    unsigned t_set[] = {1, 2, 3}, m_set[] = {8, 16, 32, 64, 256};
    int ti, mi, ok = 1;
    unsigned char salt[16]; const char *pwd = "determ c99 vs libsodium xval";
    fill(salt, 16, 42);
    for (ti = 0; ti < 3 && ok; ti++)
    for (mi = 0; mi < 5 && ok; mi++) {
        unsigned char a[32], b[32];
        int r1 = determ_argon2id(a, 32, (const unsigned char *)pwd, strlen(pwd), salt, 16, t_set[ti], m_set[mi], 1);
        int r2 = crypto_pwhash_argon2id(b, 32, pwd, strlen(pwd), salt,
                                        (unsigned long long)t_set[ti], (size_t)m_set[mi] * 1024,
                                        crypto_pwhash_argon2id_ALG_ARGON2ID13);
        if (r1 != 0 || r2 != 0 || memcmp(a, b, 32) != 0) ok = 0;
    }
    expect(ok, "Argon2id C99 == libsodium crypto_pwhash_argon2id (t{1,2,3} x m{8,16,32,64,256} KiB)");
}

int main(void) {
    if (sodium_init() < 0) { printf("  FAIL: sodium_init\n"); return 2; }
    printf("=== Determ C99 crypto stack vs libsodium (live byte-equal) ===\n");
    test_blake2b();
    test_x25519();
    test_xchacha();
    test_argon2id();
    printf("\n  %s: c99-libsodium-xval %d/%d comparisons matched\n",
           fails ? "FAIL" : "PASS", total - fails, total);
    return fails ? 1 : 0;
}
