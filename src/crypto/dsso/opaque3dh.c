/* DSSO G4 OPAQUE-3DH AKE core — CRYPTO-C99-SPEC §3.26. See opaque3dh.h for the
 * construction, the transcript encoding, the domain tags and the C2 trust-boundary
 * note. A pure composition of determ::c99 primitives: P-256 scalar mult (the 3DH),
 * HKDF-SHA256 (built on determ_hmac_sha256) with a TLS-1.3/RFC-9807 Expand-Label
 * schedule, and streaming SHA-256 over the transcript preamble. Byte-frozen against
 * tools/verify_opaque3dh.py. */
#include <determ/crypto/dsso/opaque3dh.h>

#include <string.h>

#include <determ/crypto/p256/p256.h>       /* determ_p256_base_mul/_point_mul/_point_compress */
#include <determ/crypto/sha2/sha2.h>       /* determ_sha256(_ctx), determ_hmac_sha256          */
#include <determ/crypto/ct.h>              /* determ_ct_memcmp                                  */
#include <determ/crypto/secure_zero.h>     /* determ_secure_zero                                */

#define NH 32                              /* SHA-256 output length          */
#define CPT 33                             /* SEC1 compressed P-256 point    */
static const char LABEL_PREFIX[] = "DTM-DSSO-OPAQUE3DH-v2-"; /* 22 bytes, no NUL */
static const char PREAMBLE_TAG[] = "DTM-DSSO-OPAQUEv2-";     /* 18 bytes, no NUL */
static const char CLEARCRED_TAG[] = "DTM-DSSO-CLEARCRED-v2-";/* 22 bytes, no NUL */

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
    int rc = -1;
    while (done < out_len) {
        size_t off = 0;
        if (have_t) { memcpy(buf, t, NH); off = NH; }
        memcpy(buf + off, info, info_len); off += info_len;
        buf[off++] = ctr;
        if (determ_hmac_sha256(prk, NH, buf, off, t) != 0) goto done;
        have_t = 1;
        size_t take = (out_len - done < NH) ? (out_len - done) : NH;
        memcpy(out + done, t, take);
        done += take;
        ctr++;
    }
    rc = 0;
done:
    determ_secure_zero(buf, sizeof buf);
    determ_secure_zero(t, sizeof t);
    return rc;
}

/* Expand-Label(secret, label, context, len) — the TLS-1.3/RFC-9807 label wrapper
 * with the house "DTM-DSSO-OPAQUE3DH-v2-" prefix. label/context are short. */
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

/* ── the CleartextCredentials emitter (RFC 9807 §4.1.1) ────────────────────────
 * ONE emitter, two sinks: a SHA-256 context (the preamble, never materialized) and
 * a caller buffer (the envelope AAD). Having a single emitter is what guarantees
 * the envelope tag and the transcript MAC commit to the identical bytes — two
 * hand-kept copies of an encoding drift, and this one is security-load-bearing. */
typedef struct {
    determ_sha256_ctx *h;      /* non-NULL -> stream into this hash            */
    uint8_t           *buf;    /* non-NULL -> write here                        */
    size_t             cap;    /* capacity of buf                               */
    size_t             len;    /* bytes emitted so far                          */
    int                ovf;    /* 1 once a write would have exceeded cap        */
} cc_sink;

static void cc_put(cc_sink *s, const uint8_t *p, size_t n) {
    if (!n) return;
    if (s->h) determ_sha256_update(s->h, p, n);
    if (s->buf) {
        if (s->len + n > s->cap) { s->ovf = 1; return; }
        memcpy(s->buf + s->len, p, n);
    }
    s->len += n;
}

/* Emit "DTM-DSSO-CLEARCRED-v2-" || compress(pk_s) || compress(pk_c)
 *      || i2osp(|sid|,2) || sid || i2osp(|cid|,2) || cid.
 * Returns 0, or -1 fail-closed (NULL static key, over-length identity, an
 * uncompressible static key, or a buffer sink overflow). */
static int cc_emit(cc_sink *s, const determ_opaque3dh_transcript *t) {
    uint8_t cpk_s[CPT], cpk_c[CPT], lp[2];
    if (!t->server_public_key || !t->client_public_key) return -1;
    if (!field_ok(t->server_identity_len) || !field_ok(t->client_identity_len)) return -1;
    if (determ_p256_point_compress(cpk_s, t->server_public_key) != 0) return -1;
    if (determ_p256_point_compress(cpk_c, t->client_public_key) != 0) return -1;

    cc_put(s, (const uint8_t *)CLEARCRED_TAG, sizeof(CLEARCRED_TAG) - 1);
    cc_put(s, cpk_s, CPT);
    cc_put(s, cpk_c, CPT);
    put_u16(lp, t->server_identity_len); cc_put(s, lp, 2);
    if (t->server_identity_len) cc_put(s, t->server_identity, t->server_identity_len);
    put_u16(lp, t->client_identity_len); cc_put(s, lp, 2);
    if (t->client_identity_len) cc_put(s, t->client_identity, t->client_identity_len);
    return s->ovf ? -1 : 0;
}

int determ_opaque3dh_cleartext_credentials(const determ_opaque3dh_transcript *t,
                                           uint8_t *out, size_t out_cap,
                                           size_t *out_len) {
    if (!t || !out || !out_len) return -1;
    cc_sink s;
    s.h = NULL; s.buf = out; s.cap = out_cap; s.len = 0; s.ovf = 0;
    if (cc_emit(&s, t) != 0) return -1;
    *out_len = s.len;
    return 0;
}

/* Stream the transcript preamble into SHA-256 and (optionally) a trailing tail
 * (server_mac for the client_mac hash), producing SHA256(preamble [|| tail]).
 * The preamble is never materialized. Returns 0, or -1 fail-closed on a compress
 * failure (identity ephemeral / bad static key) or an over-length field. */
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
    /* CleartextCredentials: both STATIC public keys + both identities (RFC 9807
     * §4.1.1). This is the C2 binding — without it a party's static key is not in
     * anything the MACs cover, and a server that does not hold sk_s impersonates
     * the IdP to a client whose pk_s it also supplied. */
    {
        cc_sink s;
        s.h = &h; s.buf = NULL; s.cap = 0; s.len = 0; s.ovf = 0;
        if (cc_emit(&s, t) != 0) return -1;
    }
    /* ke1 = cred_request || client_nonce(32) || compress(epk_c) */
    if (t->cred_request_len) determ_sha256_update(&h, t->cred_request, t->cred_request_len);
    determ_sha256_update(&h, t->client_nonce, DETERM_OPAQUE3DH_NONCE_LEN);
    determ_sha256_update(&h, cepk_c, CPT);
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
    uint8_t handshake_secret[32];
    int rc = -1;
    memset(zero_salt, 0, sizeof zero_salt);
    if (determ_hmac_sha256(zero_salt, NH, ikm, 99, prk) != 0) goto done; /* HKDF-Extract, empty salt */
    if (derive_secret(prk, "HandshakeSecret", 15, pre_hash, handshake_secret) != 0) goto done;
    if (derive_secret(prk, "SessionKey", 10, pre_hash, session_key) != 0) goto done;
    if (expand_label(handshake_secret, "ServerMAC", 9, NULL, 0, km2, NH) != 0) goto done;
    if (expand_label(handshake_secret, "ClientMAC", 9, NULL, 0, km3, NH) != 0) goto done;
    rc = 0;
done:
    determ_secure_zero(prk, sizeof prk);
    determ_secure_zero(handshake_secret, sizeof handshake_secret);
    return rc;
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
                            const uint8_t sk_s[32],
                            const uint8_t esk_s[32], const uint8_t epk_c[65],
                            uint8_t epk_s_out[65],
                            uint8_t session_key[32],
                            uint8_t server_mac[32],
                            uint8_t expected_client_mac[32]) {
    if (!t || !sk_s || !esk_s || !epk_c || !epk_s_out ||
        !session_key || !server_mac || !expected_client_mac ||
        !t->client_nonce || !t->server_nonce ||
        !t->client_public_key || !t->server_public_key)      /* C2: both required */
        return -1;

    uint8_t epk_s[65], ikm[99], pre_hash[32], pre_smac_hash[32];
    uint8_t km2[32], km3[32], key_tmp[32], smac_tmp[32], cmac_tmp[32];
    int rc = -1;
    if (determ_p256_base_mul(epk_s, esk_s) != 0) goto done;   /* epk_s = esk_s·G */

    /* All outputs remain private scratch until every fallible operation has
     * succeeded. An allocation failure inside HMAC is never a valid MAC/key.
     * 3DH (server view): dh1 = esk_s·epk_c, dh2 = sk_s·epk_c, dh3 = esk_s·pk_c.
     * pk_c is the TRANSCRIPT field, so the key the DH uses is the key the MACs
     * cover — there is no second, unbound way for a static key to enter. */
    if (dh_compress(ikm + 0,  esk_s, epk_c) != 0) goto done;
    if (dh_compress(ikm + 33, sk_s,  epk_c) != 0) goto done;
    if (dh_compress(ikm + 66, esk_s, t->client_public_key) != 0) goto done;
    if (hash_preamble(t, epk_c, epk_s, NULL, 0, pre_hash) != 0) goto done;
    if (key_schedule(ikm, pre_hash, key_tmp, km2, km3) != 0) goto done;
    if (determ_hmac_sha256(km2, NH, pre_hash, NH, smac_tmp) != 0) goto done;
    if (hash_preamble(t, epk_c, epk_s, smac_tmp, NH, pre_smac_hash) != 0) goto done;
    if (determ_hmac_sha256(km3, NH, pre_smac_hash, NH, cmac_tmp) != 0) goto done;

    memcpy(epk_s_out, epk_s, 65);
    memcpy(session_key, key_tmp, NH);
    memcpy(server_mac, smac_tmp, NH);
    memcpy(expected_client_mac, cmac_tmp, NH);
    rc = 0;
done:
    determ_secure_zero(ikm, sizeof ikm);
    determ_secure_zero(km2, sizeof km2);
    determ_secure_zero(km3, sizeof km3);
    determ_secure_zero(key_tmp, sizeof key_tmp);
    determ_secure_zero(smac_tmp, sizeof smac_tmp);
    determ_secure_zero(cmac_tmp, sizeof cmac_tmp);
    return rc;
}

int determ_opaque3dh_client(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_c[32],
                            const uint8_t esk_c[32], const uint8_t epk_s[65],
                            const uint8_t server_mac[32],
                            uint8_t epk_c_out[65],
                            uint8_t session_key[32],
                            uint8_t client_mac[32],
                            int *server_mac_ok) {
    /* C2-h: a NULL-argument rejection leaves every output untouched,
     * server_mac_ok included (the C++ gate test-dsso-opaque3dh asserts it). */
    if (!t || !sk_c || !esk_c || !epk_s || !server_mac ||
        !epk_c_out || !session_key || !client_mac || !server_mac_ok ||
        !t->client_nonce || !t->server_nonce ||
        !t->client_public_key || !t->server_public_key)      /* C2: both required */
        return -1;
    *server_mac_ok = 0;   /* every later failure leaves 0, never a stale 1 */
    uint8_t epk_c[65], ikm[99], pre_hash[32], pre_smac_hash[32];
    uint8_t km2[32], km3[32], key_tmp[32], mac_tmp[32], expect_smac[32];
    int rc = -1, mac_matches;
    if (determ_p256_base_mul(epk_c, esk_c) != 0) goto done;   /* epk_c = esk_c·G */

    /* 3DH (client view): dh1 = esk_c·epk_s, dh2 = esk_c·pk_s, dh3 = sk_c·epk_s.
     * pk_s is the TRANSCRIPT field — the key the client ANCHORED, which the MACs
     * also cover. C2: never route a peer-supplied static key here. */
    if (dh_compress(ikm + 0,  esk_c, epk_s) != 0) goto done;
    if (dh_compress(ikm + 33, esk_c, t->server_public_key) != 0) goto done;
    if (dh_compress(ikm + 66, sk_c,  epk_s) != 0) goto done;
    if (hash_preamble(t, epk_c, epk_s, NULL, 0, pre_hash) != 0) goto done;
    if (key_schedule(ikm, pre_hash, key_tmp, km2, km3) != 0) goto done;
    if (determ_hmac_sha256(km2, NH, pre_hash, NH, expect_smac) != 0) goto done;
    /* The acceptance decision, over the FULL NH bytes in constant time: 1 only if
     * the peer derived Km2, which needs sk_s for t->server_public_key AND the
     * identical transcript. It is published below, after every step succeeded. */
    mac_matches = (determ_ct_memcmp(server_mac, expect_smac, NH) == 0) ? 1 : 0;
    if (hash_preamble(t, epk_c, epk_s, server_mac, NH, pre_smac_hash) != 0) goto done;
    if (determ_hmac_sha256(km3, NH, pre_smac_hash, NH, mac_tmp) != 0) goto done;

    memcpy(epk_c_out, epk_c, 65);
    memcpy(session_key, key_tmp, NH);
    memcpy(client_mac, mac_tmp, NH);
    *server_mac_ok = mac_matches; /* publish only after the entire operation succeeds */
    rc = 0;
done:
    determ_secure_zero(ikm, sizeof ikm);
    determ_secure_zero(km2, sizeof km2);
    determ_secure_zero(km3, sizeof km3);
    determ_secure_zero(key_tmp, sizeof key_tmp);
    determ_secure_zero(mac_tmp, sizeof mac_tmp);
    determ_secure_zero(expect_smac, sizeof expect_smac);
    return rc;
}
