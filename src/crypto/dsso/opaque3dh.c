/* DSSO G4 OPAQUE-3DH AKE core — CRYPTO-C99-SPEC §3.26. See opaque3dh.h for the
 * construction, the transcript encoding, and the domain tags. A pure composition
 * of determ::c99 primitives: P-256 scalar mult (the 3DH), HKDF-SHA256 (built on
 * determ_hmac_sha256) with a TLS-1.3/RFC-9807 Expand-Label schedule, and streaming
 * SHA-256 over the transcript preamble. Byte-frozen against tools/verify_opaque3dh.py. */
#include <determ/crypto/dsso/opaque3dh.h>

#include <string.h>

#include <determ/crypto/p256/p256.h>       /* determ_p256_base_mul/_point_mul/_point_compress */
#include <determ/crypto/sha2/sha2.h>       /* determ_sha256(_ctx), determ_hmac_sha256          */
#include <determ/crypto/ct.h>              /* determ_ct_memcmp                                  */
#include <determ/crypto/secure_zero.h>     /* determ_secure_zero                                */

#define NH 32                              /* SHA-256 output length          */
#define CPT 33                             /* SEC1 compressed P-256 point    */
static const char LABEL_PREFIX[] = "DTM-DSSO-OPAQUE3DH-v1-"; /* 22 bytes, no NUL */
static const char PREAMBLE_TAG[] = "DTM-DSSO-OPAQUEv1-";     /* 18 bytes, no NUL */

/* i2osp(x, 2) big-endian into a 2-byte slot. */
static void put_u16(uint8_t out[2], size_t x) {
    out[0] = (uint8_t)((x >> 8) & 0xff);
    out[1] = (uint8_t)(x & 0xff);
}

/* HKDF-Expand (RFC 5869): T(0)="", T(i)=HMAC(prk, T(i-1)||info||i), out = T(1)||…
 * Bounded to our uses (info small; outlen == NH), so the T-block scratch is fixed. */
static int hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    if (info_len > 256) return -1;               /* our labels are << 256 */
    uint8_t buf[32 + 256 + 1];
    uint8_t t[32];
    size_t  have_t = 0, done = 0;
    uint8_t ctr = 1;
    while (done < out_len) {
        size_t off = 0;
        if (have_t) { memcpy(buf, t, NH); off = NH; }
        memcpy(buf + off, info, info_len); off += info_len;
        buf[off++] = ctr;
        determ_hmac_sha256(prk, NH, buf, off, t);
        have_t = 1;
        size_t take = (out_len - done < NH) ? (out_len - done) : NH;
        memcpy(out + done, t, take);
        done += take;
        ctr++;
    }
    determ_secure_zero(buf, sizeof buf);
    determ_secure_zero(t, sizeof t);
    return 0;
}

/* Expand-Label(secret, label, context, len) — the TLS-1.3/RFC-9807 label wrapper
 * with the house "DTM-DSSO-OPAQUE3DH-v1-" prefix. label/context are short. */
static int expand_label(const uint8_t secret[32],
                        const char *label, size_t label_len,
                        const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len) {
    const size_t pfx = sizeof(LABEL_PREFIX) - 1;             /* 22 */
    if (label_len > 64 || context_len > 64 || out_len > 0xffff) return -1;
    uint8_t info[2 + 1 + 22 + 64 + 1 + 64];
    size_t k = 0;
    put_u16(info + k, out_len); k += 2;
    info[k++] = (uint8_t)(pfx + label_len);
    memcpy(info + k, LABEL_PREFIX, pfx);    k += pfx;
    memcpy(info + k, label, label_len);     k += label_len;
    info[k++] = (uint8_t)context_len;
    if (context_len) { memcpy(info + k, context, context_len); k += context_len; }
    return hkdf_expand(secret, info, k, out, out_len);
}

/* Derive-Secret(secret, label, transcript_hash) = Expand-Label(secret, label,
 * SHA256(transcript), NH). The caller passes the already-computed preamble hash. */
static int derive_secret(const uint8_t secret[32],
                         const char *label, size_t label_len,
                         const uint8_t transcript_hash[32], uint8_t out[32]) {
    return expand_label(secret, label, label_len, transcript_hash, NH, out, NH);
}

/* Fail-close if any on-wire field exceeds the cap (bounds the preamble hash work). */
static int field_ok(size_t len) { return len <= DETERM_OPAQUE3DH_MAX_FIELD; }

/* Stream the transcript preamble into SHA-256 and (optionally) a trailing tail
 * (server_mac for the client_mac hash), producing SHA256(preamble [|| tail]).
 * The preamble is never materialized. Returns 0, or -1 fail-closed on a compress
 * failure (identity ephemeral) or an over-length field. */
static int hash_preamble(const determ_opaque3dh_transcript *t,
                         const uint8_t epk_c[65], const uint8_t epk_s[65],
                         const uint8_t *tail, size_t tail_len,
                         uint8_t out[32]) {
    if (!field_ok(t->context_len) || !field_ok(t->client_identity_len) ||
        !field_ok(t->server_identity_len) || !field_ok(t->cred_request_len) ||
        !field_ok(t->cred_response_len))
        return -1;

    uint8_t cepk_c[CPT], cepk_s[CPT];
    if (determ_p256_point_compress(cepk_c, epk_c) != 0) return -1;
    if (determ_p256_point_compress(cepk_s, epk_s) != 0) return -1;

    uint8_t lp[2];
    determ_sha256_ctx h;
    determ_sha256_init(&h);
    determ_sha256_update(&h, (const uint8_t *)PREAMBLE_TAG, sizeof(PREAMBLE_TAG) - 1);
    /* i2osp(|context|,2) || context */
    put_u16(lp, t->context_len); determ_sha256_update(&h, lp, 2);
    if (t->context_len) determ_sha256_update(&h, t->context, t->context_len);
    /* i2osp(|client_identity|,2) || client_identity */
    put_u16(lp, t->client_identity_len); determ_sha256_update(&h, lp, 2);
    if (t->client_identity_len) determ_sha256_update(&h, t->client_identity, t->client_identity_len);
    /* ke1 = cred_request || client_nonce(32) || compress(epk_c) */
    if (t->cred_request_len) determ_sha256_update(&h, t->cred_request, t->cred_request_len);
    determ_sha256_update(&h, t->client_nonce, DETERM_OPAQUE3DH_NONCE_LEN);
    determ_sha256_update(&h, cepk_c, CPT);
    /* i2osp(|server_identity|,2) || server_identity */
    put_u16(lp, t->server_identity_len); determ_sha256_update(&h, lp, 2);
    if (t->server_identity_len) determ_sha256_update(&h, t->server_identity, t->server_identity_len);
    /* inner_ke2 = cred_response || server_nonce(32) || compress(epk_s) */
    if (t->cred_response_len) determ_sha256_update(&h, t->cred_response, t->cred_response_len);
    determ_sha256_update(&h, t->server_nonce, DETERM_OPAQUE3DH_NONCE_LEN);
    determ_sha256_update(&h, cepk_s, CPT);
    /* optional trailing tail (server_mac) */
    if (tail_len) determ_sha256_update(&h, tail, tail_len);
    determ_sha256_final(&h, out);
    return 0;
}

/* prk = HKDF-Extract(0^32, ikm); then the four schedule outputs. Secret scratch
 * (prk, handshake_secret, Km2/Km3) is zeroed before return except session_key,
 * km2, km3 which the caller consumes. */
static int key_schedule(const uint8_t ikm[99], const uint8_t pre_hash[32],
                        uint8_t session_key[32], uint8_t km2[32], uint8_t km3[32]) {
    uint8_t prk[32];
    uint8_t zero_salt[32];
    memset(zero_salt, 0, sizeof zero_salt);
    determ_hmac_sha256(zero_salt, NH, ikm, 99, prk);       /* HKDF-Extract, empty salt */

    uint8_t handshake_secret[32];
    int rc = 0;
    rc |= derive_secret(prk, "HandshakeSecret", 15, pre_hash, handshake_secret);
    rc |= derive_secret(prk, "SessionKey", 10, pre_hash, session_key);
    rc |= expand_label(handshake_secret, "ServerMAC", 9, NULL, 0, km2, NH);
    rc |= expand_label(handshake_secret, "ClientMAC", 9, NULL, 0, km3, NH);

    determ_secure_zero(prk, sizeof prk);
    determ_secure_zero(handshake_secret, sizeof handshake_secret);
    return rc ? -1 : 0;
}

/* Compute compress(scalar·point) into a 33-byte slot. Returns 0, -1 on failure. */
static int dh_compress(uint8_t out33[33], const uint8_t scalar[32], const uint8_t point[65]) {
    uint8_t p[65];
    if (determ_p256_point_mul(p, scalar, point) != 0) { determ_secure_zero(p, sizeof p); return -1; }
    int rc = determ_p256_point_compress(out33, p);
    determ_secure_zero(p, sizeof p);
    return rc;
}

int determ_opaque3dh_server(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_s[32],  const uint8_t pk_c[65],
                            const uint8_t esk_s[32], const uint8_t epk_c[65],
                            uint8_t epk_s_out[65],
                            uint8_t session_key[32],
                            uint8_t server_mac[32],
                            uint8_t expected_client_mac[32]) {
    if (!t || !sk_s || !pk_c || !esk_s || !epk_c || !epk_s_out ||
        !session_key || !server_mac || !expected_client_mac ||
        !t->client_nonce || !t->server_nonce)
        return -1;

    uint8_t epk_s[65];
    if (determ_p256_base_mul(epk_s, esk_s) != 0) return -1;   /* epk_s = esk_s·G */

    /* 3DH (server view): dh1 = esk_s·epk_c, dh2 = sk_s·epk_c, dh3 = esk_s·pk_c */
    uint8_t ikm[99];
    int rc = 0;
    rc |= dh_compress(ikm + 0,  esk_s, epk_c);
    rc |= dh_compress(ikm + 33, sk_s,  epk_c);
    rc |= dh_compress(ikm + 66, esk_s, pk_c);
    if (rc != 0) { determ_secure_zero(ikm, sizeof ikm); return -1; }

    uint8_t pre_hash[32];
    if (hash_preamble(t, epk_c, epk_s, NULL, 0, pre_hash) != 0) {
        determ_secure_zero(ikm, sizeof ikm); return -1;
    }

    uint8_t km2[32], km3[32];
    if (key_schedule(ikm, pre_hash, session_key, km2, km3) != 0) {
        determ_secure_zero(ikm, sizeof ikm);
        determ_secure_zero(km2, sizeof km2); determ_secure_zero(km3, sizeof km3);  /* G6-5 */
        return -1;
    }
    determ_secure_zero(ikm, sizeof ikm);

    determ_hmac_sha256(km2, NH, pre_hash, NH, server_mac);    /* HMAC(Km2, SHA256(preamble)) */

    uint8_t pre_smac_hash[32];
    if (hash_preamble(t, epk_c, epk_s, server_mac, NH, pre_smac_hash) != 0) {
        determ_secure_zero(km2, sizeof km2); determ_secure_zero(km3, sizeof km3);
        return -1;
    }
    determ_hmac_sha256(km3, NH, pre_smac_hash, NH, expected_client_mac);

    memcpy(epk_s_out, epk_s, 65);
    determ_secure_zero(km2, sizeof km2);
    determ_secure_zero(km3, sizeof km3);
    return 0;
}

int determ_opaque3dh_client(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_c[32],  const uint8_t pk_s[65],
                            const uint8_t esk_c[32], const uint8_t epk_s[65],
                            const uint8_t server_mac[32],
                            uint8_t epk_c_out[65],
                            uint8_t session_key[32],
                            uint8_t client_mac[32],
                            int *server_mac_ok) {
    if (!t || !sk_c || !pk_s || !esk_c || !epk_s || !server_mac ||
        !epk_c_out || !session_key || !client_mac || !server_mac_ok ||
        !t->client_nonce || !t->server_nonce)
        return -1;
    *server_mac_ok = 0;

    uint8_t epk_c[65];
    if (determ_p256_base_mul(epk_c, esk_c) != 0) return -1;   /* epk_c = esk_c·G */

    /* 3DH (client view): dh1 = esk_c·epk_s, dh2 = esk_c·pk_s, dh3 = sk_c·epk_s */
    uint8_t ikm[99];
    int rc = 0;
    rc |= dh_compress(ikm + 0,  esk_c, epk_s);
    rc |= dh_compress(ikm + 33, esk_c, pk_s);
    rc |= dh_compress(ikm + 66, sk_c,  epk_s);
    if (rc != 0) { determ_secure_zero(ikm, sizeof ikm); return -1; }

    uint8_t pre_hash[32];
    if (hash_preamble(t, epk_c, epk_s, NULL, 0, pre_hash) != 0) {
        determ_secure_zero(ikm, sizeof ikm); return -1;
    }

    uint8_t km2[32], km3[32];
    if (key_schedule(ikm, pre_hash, session_key, km2, km3) != 0) {
        determ_secure_zero(ikm, sizeof ikm);
        determ_secure_zero(km2, sizeof km2); determ_secure_zero(km3, sizeof km3);  /* G6-5 */
        return -1;
    }
    determ_secure_zero(ikm, sizeof ikm);

    /* Verify the server MAC (constant-time), then produce the client MAC. */
    uint8_t expect_smac[32];
    determ_hmac_sha256(km2, NH, pre_hash, NH, expect_smac);
    *server_mac_ok = (determ_ct_memcmp(server_mac, expect_smac, NH) == 0) ? 1 : 0;

    uint8_t pre_smac_hash[32];
    if (hash_preamble(t, epk_c, epk_s, server_mac, NH, pre_smac_hash) != 0) {
        determ_secure_zero(km2, sizeof km2); determ_secure_zero(km3, sizeof km3);
        determ_secure_zero(expect_smac, sizeof expect_smac);  /* G6-4 */
        return -1;
    }
    determ_hmac_sha256(km3, NH, pre_smac_hash, NH, client_mac);

    memcpy(epk_c_out, epk_c, 65);
    determ_secure_zero(km2, sizeof km2);
    determ_secure_zero(km3, sizeof km3);
    determ_secure_zero(expect_smac, sizeof expect_smac);  /* G6-4: hygiene (public MAC tag) */
    return 0;
}
