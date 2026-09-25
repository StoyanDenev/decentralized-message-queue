/* SPDX-License-Identifier: Apache-2.0
 * API-boundary gate. CMake compiles the actual affected C sources in separate
 * test objects, substituting allocator, memcpy, HMAC and tag-comparison symbols.
 * This harness uses the real libc/crypto beneath its hooks. No production fault
 * switch exists.
 * Oversized rejected lengths never reach an actual copy/allocation, including
 * in mutants: hooks fail by assertion+exit(1), never by deliberate corruption.
 * This is hosted evidence, not freestanding or whole-crypto qualification.
 */
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/p256/p256.h>
#include <determ/crypto/pedersen/balance.h>
#include <determ/crypto/argon2/argon2id.h>
#include <determ/crypto/dsso/opaque3dh.h>
#include <determ/crypto/ct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "C99-CRYPTO-BOUNDS ASSERTION FAILED at %s:%d: %s\n", \
            __FILE__, __LINE__, #c); exit(1); } } while (0)

static unsigned long checks;
static unsigned alloc_calls, free_calls, live_allocs, hmac_calls, memcpy_calls;
static unsigned fail_alloc_at, fail_hmac_at;
static int forbid_alloc, failed_hmac;

void *c99_bounds_malloc(size_t n) {
    void *p;
    ++alloc_calls;
    CHECK(!forbid_alloc);
    CHECK(n <= 65536u);
    if (alloc_calls == fail_alloc_at) return NULL;
    p = malloc(n);
    CHECK(p != NULL);
    ++live_allocs;
    return p;
}

void *c99_bounds_calloc(size_t n, size_t size) {
    void *p;
    ++alloc_calls;
    CHECK(!forbid_alloc);
    CHECK(size != 0u && n <= 65536u / size);
    if (alloc_calls == fail_alloc_at) return NULL;
    p = calloc(n, size);
    CHECK(p != NULL);
    ++live_allocs;
    return p;
}

void c99_bounds_free(void *p) {
    if (p != NULL) {
        CHECK(live_allocs != 0u);
        --live_allocs;
        ++free_calls;
    }
    free(p);
}

void *c99_bounds_memcpy(void *dst, const void *src, size_t n) {
    /* All genuine fixture buffers fit this bound. A removed length check must
     * fail here, not read a one-byte adversarial fixture for SIZE_MAX bytes. */
    CHECK(n <= 65536u);
    CHECK(!failed_hmac); /* no consumption of an unwritten HMAC output */
    ++memcpy_calls;
    return memcpy(dst, src, n);
}

int c99_bounds_hmac_sha256(const uint8_t *key, size_t keylen,
                           const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    CHECK(!failed_hmac);
    ++hmac_calls;
    if (hmac_calls == fail_hmac_at) {
        failed_hmac = 1;
        return -1; /* real HMAC failure leaves out unwritten */
    }
    return determ_hmac_sha256(key, keylen, msg, msglen, out);
}

int c99_bounds_ct_memcmp(const void *a, const void *b, size_t n) {
    CHECK(!failed_hmac); /* do not inspect an unwritten MAC in a mutant */
    return determ_ct_memcmp(a, b, n);
}

static void reset(void) {
    CHECK(live_allocs == 0u);
    alloc_calls = free_calls = hmac_calls = memcpy_calls = 0u;
    fail_alloc_at = fail_hmac_at = 0u;
    forbid_alloc = failed_hmac = 0;
}

static void sentinel(const uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) CHECK(p[i] == 0xa5u);
}

static unsigned hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    CHECK(c >= 'a' && c <= 'f');
    return (unsigned)(c - 'a') + 10u;
}

static void equals_hex(const uint8_t *p, size_t n, const char *hex) {
    size_t i;
    CHECK(strlen(hex) == n * 2u);
    for (i = 0; i < n; ++i)
        CHECK(p[i] == (uint8_t)((hex_nibble(hex[2u*i]) << 4) | hex_nibble(hex[2u*i+1u])));
}

static void kdf_tests(void) {
    uint8_t ikm[22], salt[13], info[10], out[64];
    unsigned i;
    memset(ikm, 0x0b, sizeof ikm);
    for (i = 0; i < sizeof salt; ++i) salt[i] = (uint8_t)i;
    for (i = 0; i < sizeof info; ++i) info[i] = (uint8_t)(0xf0u + i);
    reset();
    CHECK(determ_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm,
                             info, sizeof info, out, 42u) == 0);
    equals_hex(out, 42u, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    CHECK(hmac_calls == 3u && live_allocs == 0u);
    /* The copy adapter is live: a toolchain that re-enabled fortified-header
     * substitution would route copies around it and silently weaken this gate. */
    CHECK(memcpy_calls > 0u);
    /* Both extract branches and both expansion iterations fail closed. */
    for (i = 1u; i <= 3u; ++i) {
        reset(); fail_hmac_at = i; memset(out, 0xa5, sizeof out);
        CHECK(determ_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm,
                                 info, sizeof info, out, 42u) == -1);
        CHECK(hmac_calls == i && live_allocs == 0u);
        if (i <= 2u) sentinel(out, sizeof out);
        else sentinel(out + 32u, sizeof out - 32u);
    }
    reset(); fail_hmac_at = 1u; memset(out, 0xa5, sizeof out);
    CHECK(determ_hkdf_sha256(NULL, 0u, ikm, sizeof ikm, NULL, 0u, out, 32u) == -1);
    CHECK(hmac_calls == 1u && alloc_calls == 0u); sentinel(out, sizeof out);
    reset(); fail_alloc_at = 1u;
    CHECK(determ_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, out, 42u) == -1);
    CHECK(live_allocs == 0u);
    reset(); forbid_alloc = 1;
    CHECK(determ_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm, info, SIZE_MAX, out, 32u) == -1);
    CHECK(hmac_calls == 0u);

    /* RFC 7914 §11, vector 1: two blocks verify counter values 1 and 2. */
    reset();
    CHECK(determ_pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6u,
                                   (const uint8_t *)"salt", 4u, 1u, out, 64u) == 0);
    equals_hex(out, 64u, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    CHECK(hmac_calls == 2u);
    reset(); memset(out, 0xa5, sizeof out);
    CHECK(determ_pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6u,
                                   (const uint8_t *)"salt", 4u, 1u, out, 33u) == 0);
    equals_hex(out, 33u, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49");
    CHECK(hmac_calls == 2u); sentinel(out + 33u, sizeof out - 33u);
    /* Includes initial U1, subsequent Uj, and the following output block. */
    for (i = 1u; i <= 4u; ++i) {
        reset(); fail_hmac_at = i; memset(out, 0xa5, sizeof out);
        CHECK(determ_pbkdf2_hmac_sha256((const uint8_t *)"pw", 2u,
                                       salt, sizeof salt, 2u, out, sizeof out) == -1);
        CHECK(hmac_calls == i && live_allocs == 0u && free_calls == 1u);
        if (i <= 2u) sentinel(out, sizeof out);
        else sentinel(out + 32u, sizeof out - 32u);
    }
    reset(); fail_alloc_at = 1u;
    CHECK(determ_pbkdf2_hmac_sha256(ikm, sizeof ikm, salt, sizeof salt, 1u, out, 32u) == -1);
    CHECK(hmac_calls == 0u && live_allocs == 0u);
    reset(); forbid_alloc = 1;
    CHECK(determ_pbkdf2_hmac_sha256(ikm, sizeof ikm, salt, SIZE_MAX, 1u, out, 32u) == -1);
    CHECK(hmac_calls == 0u);
#if SIZE_MAX > UINT32_MAX
    CHECK(determ_pbkdf2_hmac_sha256(ikm, sizeof ikm, salt, sizeof salt, 1u,
                                   out, (size_t)UINT32_MAX * 32u + 1u) == -1);
#else
    /* No huge output is touched: inject failure in the first HMAC. A wrapped
     * ceil at outlen==SIZE_MAX would incorrectly report success without it. */
    reset(); fail_hmac_at = 1u;
    CHECK(determ_pbkdf2_hmac_sha256(ikm, sizeof ikm, salt, sizeof salt, 1u,
                                   out, SIZE_MAX) == -1);
    CHECK(hmac_calls == 1u);
#endif
}

static void preflight_tests(void) {
    uint8_t byte = 0u, out[65], scalar[32] = {0}, point[33];
    uint8_t input[600];
    unsigned i;
    memset(input, 0, sizeof input);
    scalar[31] = 1u;
    reset();
    CHECK(determ_p256_base_mul(out, scalar) == 0);
    CHECK(determ_p256_point_compress(point, out) == 0);
    reset(); forbid_alloc = 1; memset(out, 0xa5, sizeof out);
    CHECK(determ_p256_expand_message_xmd(out, 32u, &byte, SIZE_MAX, &byte, 1u) == -1);
    CHECK(determ_p256_expand_message_xmd(out, SIZE_MAX, &byte, 1u, &byte, 1u) == -1);
    CHECK(determ_p256_oprf_derive_key(out, &byte, SIZE_MAX, &byte, 0u, 0u) == -1);
    CHECK(determ_p256_oprf_derive_key(out, &byte, 0u, &byte, SIZE_MAX, 0u) == -1);
    CHECK(determ_p256_oprf_derive_key(out, &byte, SIZE_MAX - 3u, &byte, 1u, 0u) == -1);
    CHECK(determ_p256_oprf_finalize(out, &byte, SIZE_MAX, scalar, point) == -1);
    CHECK(determ_p256_balance_excess(out, point, SIZE_MAX, point, 0u, 0u) == -1);
    CHECK(determ_p256_balance_excess(out, point, 0u, point, SIZE_MAX, 0u) == -1);
    CHECK(determ_p256_balance_excess(out, point, SIZE_MAX / 33u, point, 0u, 0u) == -1);
    /* First rejected values: one less would make the preimage size wrap to a
     * small (stack) buffer followed by a huge copy. */
    CHECK(determ_p256_expand_message_xmd(out, 32u, &byte, SIZE_MAX - 68u, &byte, 1u) == -1);
    CHECK(determ_p256_oprf_finalize(out, &byte, SIZE_MAX - 44u, scalar, point) == -1);
    CHECK(alloc_calls == 0u); sentinel(out, sizeof out);
    /* RFC 9380 §5.3.1: ell = ceil(len/32) <= 255, i.e. len_in_bytes <= 8160. */
    {
        static uint8_t wide[8161];
        memset(wide, 0xa5, sizeof wide);
        CHECK(determ_p256_expand_message_xmd(wide, 8161u, &byte, 1u, &byte, 1u) == -1);
        sentinel(wide, sizeof wide);
        CHECK(determ_p256_expand_message_xmd(wide, 8160u, &byte, 1u, &byte, 1u) == 0);
        CHECK(wide[8160] == 0xa5u);
    }

    reset(); fail_alloc_at = 1u;
    CHECK(determ_p256_expand_message_xmd(out, 32u, input, sizeof input, &byte, 1u) == -1);
    CHECK(alloc_calls == 1u && live_allocs == 0u);
    reset(); fail_alloc_at = 1u;
    CHECK(determ_p256_oprf_derive_key(out, input, sizeof input, &byte, 1u, 0u) == -1);
    CHECK(alloc_calls == 1u && live_allocs == 0u);
    reset(); fail_alloc_at = 1u;
    CHECK(determ_p256_oprf_finalize(out, input, sizeof input, scalar, point) == -1);
    CHECK(alloc_calls == 1u && live_allocs == 0u);
    for (i = 1u; i <= 2u; ++i) {
        reset(); fail_alloc_at = i;
        CHECK(determ_p256_balance_excess(out, point, 1u, NULL, 0u, 0u) == -1);
        CHECK(live_allocs == 0u);
    }
    reset(); fail_alloc_at = 1u;
    CHECK(determ_argon2id(out, 32u, &byte, 1u, input, 8u, 1u, 8u, 1u) == -1);
    CHECK(alloc_calls == 1u && live_allocs == 0u);
#if SIZE_MAX <= UINT32_MAX
    reset(); forbid_alloc = 1;
    CHECK(determ_argon2id(out, 32u, &byte, 1u, input, 8u, 1u, 4194304u, 1u) == -1);
    CHECK(alloc_calls == 0u);
#else
    puts("NOTE: native 32-bit Argon2 allocation and PBKDF2 ceil boundary paths not exercised");
#endif
    /* Nonempty valid paths remain admitted; existing algorithm-vector gates
     * remain the authority for P-256/Argon2 cryptographic byte correctness. */
    reset();
    CHECK(determ_p256_expand_message_xmd(out, 32u, input, sizeof input, &byte, 1u) == 0);
    CHECK(determ_p256_oprf_derive_key(out, input, sizeof input, &byte, 1u, 0u) == 0);
    CHECK(determ_p256_oprf_finalize(out, input, sizeof input, scalar, point) == 0);
    CHECK(determ_p256_balance_excess(out, point, 1u, NULL, 0u, 0u) == 0);
    CHECK(determ_argon2id(out, 32u, &byte, 1u, input, 8u, 1u, 8u, 1u) == 0);
    CHECK(live_allocs == 0u);
}

static void opaque_tests(void) {
    determ_opaque3dh_transcript t;
    uint8_t sk_c[32] = {0}, sk_s[32] = {0}, esk_c[32] = {0}, esk_s[32] = {0};
    uint8_t pk_c[65], pk_s[65], epk_c[65], epk_s[65], got_epk[65];
    uint8_t cn[32] = {0}, sn[32] = {1};
    uint8_t key_s[32], key_c[32], smac[32], expected[32], cmac[32];
    uint8_t out_key[32], out_mac[32], out_expected[32];
    int mac_ok;
    unsigned fail_at;
    sk_c[31] = 1u; sk_s[31] = 2u; esk_c[31] = 3u; esk_s[31] = 4u;
    reset();
    CHECK(determ_p256_base_mul(pk_c, sk_c) == 0);
    CHECK(determ_p256_base_mul(pk_s, sk_s) == 0);
    CHECK(determ_p256_base_mul(epk_c, esk_c) == 0);
    CHECK(determ_p256_base_mul(epk_s, esk_s) == 0);
    memset(&t, 0, sizeof t);
    t.client_public_key = pk_c; t.server_public_key = pk_s;
    t.client_nonce = cn; t.server_nonce = sn;
    t.context = (const uint8_t *)"test"; t.context_len = 4u;
    reset();
    CHECK(determ_opaque3dh_server(&t, sk_s, esk_s, epk_c, got_epk,
                                 key_s, smac, expected) == 0);
    CHECK(memcmp(got_epk, epk_s, 65u) == 0 && hmac_calls == 7u);
    reset(); mac_ok = 0;
    CHECK(determ_opaque3dh_client(&t, sk_c, esk_c, epk_s, smac, got_epk,
                                 key_c, cmac, &mac_ok) == 0);
    CHECK(mac_ok == 1 && hmac_calls == 7u);
    CHECK(memcmp(got_epk, epk_c, 65u) == 0);
    CHECK(memcmp(key_s, key_c, 32u) == 0 && memcmp(expected, cmac, 32u) == 0);

    /* Extract, handshake, session, Km2, Km3, server-MAC and client-MAC. */
    for (fail_at = 1u; fail_at <= 7u; ++fail_at) {
        reset(); fail_hmac_at = fail_at;
        memset(got_epk, 0xa5, sizeof got_epk); memset(out_key, 0xa5, sizeof out_key);
        memset(out_mac, 0xa5, sizeof out_mac); memset(out_expected, 0xa5, sizeof out_expected);
        CHECK(determ_opaque3dh_server(&t, sk_s, esk_s, epk_c, got_epk,
                                     out_key, out_mac, out_expected) == -1);
        CHECK(hmac_calls == fail_at && live_allocs == 0u);
        sentinel(got_epk, sizeof got_epk); sentinel(out_key, sizeof out_key);
        sentinel(out_mac, sizeof out_mac); sentinel(out_expected, sizeof out_expected);
        reset(); fail_hmac_at = fail_at; mac_ok = 99;
        CHECK(determ_opaque3dh_client(&t, sk_c, esk_c, epk_s, smac, got_epk,
                                     out_key, out_mac, &mac_ok) == -1);
        CHECK(mac_ok == 0 && hmac_calls == fail_at && live_allocs == 0u);
        sentinel(got_epk, sizeof got_epk); sentinel(out_key, sizeof out_key);
        sentinel(out_mac, sizeof out_mac);
    }
    /* C2-h: a NULL-argument rejection leaves every output untouched, including
     * server_mac_ok (asserted by the C++ gate test-dsso-opaque3dh as well). */
    reset(); mac_ok = 99;
    CHECK(determ_opaque3dh_client(NULL, sk_c, esk_c, epk_s, smac, got_epk,
                                 out_key, out_mac, &mac_ok) == -1);
    CHECK(mac_ok == 99);
    {   /* The C++ gate's cases: each missing static key, transcript present. */
        determ_opaque3dh_transcript missing = t;
        missing.server_public_key = NULL; mac_ok = 7;
        memset(got_epk, 0xa5, sizeof got_epk); memset(out_key, 0xa5, sizeof out_key);
        memset(out_mac, 0xa5, sizeof out_mac);
        CHECK(determ_opaque3dh_client(&missing, sk_c, esk_c, epk_s, smac, got_epk,
                                     out_key, out_mac, &mac_ok) == -1);
        CHECK(mac_ok == 7);
        sentinel(got_epk, sizeof got_epk); sentinel(out_key, sizeof out_key);
        sentinel(out_mac, sizeof out_mac);
        missing = t; missing.client_public_key = NULL; mac_ok = 7;
        CHECK(determ_opaque3dh_client(&missing, sk_c, esk_c, epk_s, smac, got_epk,
                                     out_key, out_mac, &mac_ok) == -1);
        CHECK(mac_ok == 7);
        sentinel(got_epk, sizeof got_epk); sentinel(out_key, sizeof out_key);
        sentinel(out_mac, sizeof out_mac);
    }
    /* A mismatched tag still completes with mac_ok=0: existing API semantics. */
    reset(); smac[0] ^= 1u;
    CHECK(determ_opaque3dh_client(&t, sk_c, esk_c, epk_s, smac, got_epk,
                                 out_key, out_mac, &mac_ok) == 0);
    CHECK(mac_ok == 0);
}


/* Existing v2 frozen KAT, not regenerated from the patched C implementation.
 * Provenance: tools/verify_opaque3dh.py selftest() inputs, introduced in commit
 * cccc60c4987ecb517e59a5e5821c52c1f476ce12; expected hex was already recorded by
 * test-dsso-opaque3dh at audited baseline 6a131af3a96fa20e81d54e3d7057ac28bd1345c7.
 * This C99 gate reuses that independent oracle's fixture without the hosted
 * C++ test runner. Agreement alone would miss a transcript change on both sides.
 */
static void opaque_known_answer(void) {
    static const uint8_t context[] = "determ-dsso-test";
    static const uint8_t client_id[] = "alice@rp", server_id[] = "determ-idp";
    static const uint8_t request[] = "CRED-REQ-blob", response[] = "CRED-RESP-blob";
    static const char key_hex[] =
        "669097b27b88b05eb468d46a00c4fb9b6f06d6d6696ec3b85ea61d1456cfc880";
    static const char server_mac_hex[] =
        "5a86590c25a05a7c287eaf80ae21b3f11b7b162ec83c9f68425e95ced14381f7";
    static const char client_mac_hex[] =
        "4de728062ab9344d0691f806fabbace1227c6c24407fedeb703201f90a3f3a35";
    determ_opaque3dh_transcript t;
    uint8_t sk_c[32], sk_s[32], esk_c[32], esk_s[32], cn[32], sn[32];
    uint8_t pk_c[65], pk_s[65], epk_c[65], epk_s[65], got_epk[65];
    uint8_t key_s[32], key_c[32], smac[32], cmac[32], expected_cmac[32], cc[128];
    size_t cc_len = 0;
    int mac_ok = 0;
    memset(sk_c, 0x11, sizeof sk_c); memset(sk_s, 0x22, sizeof sk_s);
    memset(esk_c, 0x33, sizeof esk_c); memset(esk_s, 0x44, sizeof esk_s);
    memset(cn, 0x55, sizeof cn); memset(sn, 0x66, sizeof sn);
    reset();
    CHECK(determ_p256_base_mul(pk_c, sk_c) == 0);
    CHECK(determ_p256_base_mul(pk_s, sk_s) == 0);
    CHECK(determ_p256_base_mul(epk_c, esk_c) == 0);
    memset(&t, 0, sizeof t);
    t.context = context; t.context_len = sizeof context - 1u;
    t.client_identity = client_id; t.client_identity_len = sizeof client_id - 1u;
    t.server_identity = server_id; t.server_identity_len = sizeof server_id - 1u;
    t.client_public_key = pk_c; t.server_public_key = pk_s;
    t.cred_request = request; t.cred_request_len = sizeof request - 1u;
    t.cred_response = response; t.cred_response_len = sizeof response - 1u;
    t.client_nonce = cn; t.server_nonce = sn;
    CHECK(determ_opaque3dh_server(&t, sk_s, esk_s, epk_c, epk_s,
                                 key_s, smac, expected_cmac) == 0);
    CHECK(hmac_calls == 7u);
    equals_hex(key_s, sizeof key_s, key_hex);
    equals_hex(smac, sizeof smac, server_mac_hex);
    equals_hex(expected_cmac, sizeof expected_cmac, client_mac_hex);
    reset();
    CHECK(determ_opaque3dh_client(&t, sk_c, esk_c, epk_s, smac, got_epk,
                                 key_c, cmac, &mac_ok) == 0);
    CHECK(mac_ok == 1 && hmac_calls == 7u);
    CHECK(memcmp(got_epk, epk_c, sizeof epk_c) == 0);
    equals_hex(key_c, sizeof key_c, key_hex);
    equals_hex(cmac, sizeof cmac, client_mac_hex);
    CHECK(determ_opaque3dh_cleartext_credentials(&t, cc, sizeof cc, &cc_len) == 0);
    equals_hex(cc, cc_len,
        "44544d2d4453534f2d434c454152435245442d76322d"
        "03d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3"
        "020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
        "000a64657465726d2d6964700008616c696365407270");
    puts("PASS: existing independent OPAQUE v2 frozen transcript KAT");
}

int main(void) {
    kdf_tests();
    preflight_tests();
    opaque_tests();
    opaque_known_answer();
    reset();
    printf("PASS: C99 crypto bounds and failure propagation (%lu assertions)\n", checks);
    return 0;
}
