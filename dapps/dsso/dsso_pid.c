/* dsso_pid — the wallet-relying-party verification pipeline. See dsso_pid.h for
 * the role, the format choice and the nine rules. */
#include "dsso_pid.h"
#include "dsso_jose.h"

#include <string.h>

#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"

/* ───────────────────────────── trust anchors ────────────────────────────── */

/* ARF v2.9.0 requirement OIA_12: "a Relying Party SHALL validate the signature
 * of a PID using a trust anchor provided in a PID Provider Trusted List."
 *
 * The operative word is PROVIDED: the verifying key comes from configuration,
 * never from the token. That is why this lookup takes the token's `iss` and
 * `kid` as SELECTORS and returns a key the caller already trusted, and why the
 * header parser rejects `jwk` / `jku` / `x5u` / `x5c` outright — a token that
 * carries its own key is not asking to be verified, it is asking to choose its
 * own verifier. An issuer/kid pair that is not in the list is DSSO_E_TRUST;
 * there is no fallback, no "unknown issuer at reduced assurance", no discovery.
 *
 * This list is the repository stand-in for a Member State Trusted List. Nothing
 * here fetches, parses or validates an actual eIDAS Trusted List (ETSI TS 119
 * 612); populating the list is a deployment act and is EXTERNAL to this code. */
int dsso_trust_lookup(const dsso_trust_list *tl,
                      const uint8_t *iss, size_t iss_len,
                      const uint8_t *kid, size_t kid_len,
                      const dsso_trust_anchor **out) {
    size_t i;
    if (!tl || !tl->a || !out) return DSSO_E_ARG;
    if ((iss_len && !iss) || (kid_len && !kid)) return DSSO_E_ARG;
    for (i = 0; i < tl->n; ++i) {
        const dsso_trust_anchor *e = &tl->a[i];
        size_t el, kl;
        if (!e->iss || !e->kid) continue;
        el = strlen(e->iss);
        kl = strlen(e->kid);
        if (el != iss_len || kl != kid_len) continue;
        if (!dsso_ct_equal((const uint8_t *)e->iss, iss, el)) continue;
        if (!dsso_ct_equal((const uint8_t *)e->kid, kid, kl)) continue;
        *out = e;
        return DSSO_OK;
    }
    return DSSO_E_TRUST;
}

/* ───────────────────────────── small helpers ────────────────────────────── */

static int str_member(dsso_slice obj, const char *key,
                      uint8_t *out, size_t cap, size_t *outlen) {
    dsso_slice v;
    dsso_json_type t;
    int rc = dsso_json_member(obj, key, &v, &t);
    if (rc != DSSO_OK) return rc;
    if (t != DSSO_JSON_STRING) return DSSO_E_FORMAT;
    return dsso_json_string(v, out, cap, outlen);
}

static int int_member(dsso_slice obj, const char *key, int64_t *out) {
    dsso_slice v;
    dsso_json_type t;
    int rc = dsso_json_member(obj, key, &v, &t);
    if (rc != DSSO_OK) return rc;
    if (t != DSSO_JSON_NUMBER) return DSSO_E_FORMAT;
    return dsso_json_int(v, out);
}

static int b64_len(dsso_slice b64, uint8_t *out, size_t cap, size_t want) {
    size_t n = 0;
    if (dsso_b64url_decode(b64, out, cap, &n) != DSSO_OK) return DSSO_E_FORMAT;
    return n == want ? DSSO_OK : DSSO_E_FORMAT;
}

/* A JSON string value (span INCLUDING quotes) whose body is decoded as
 * base64url into exactly `want` bytes. */
static int b64_string_member(dsso_slice obj, const char *key,
                             uint8_t *out, size_t cap, size_t want) {
    dsso_slice v, body;
    dsso_json_type t;
    if (dsso_json_member(obj, key, &v, &t) != DSSO_OK) return DSSO_E_FORMAT;
    if (t != DSSO_JSON_STRING || v.n < 2) return DSSO_E_FORMAT;
    body.p = v.p + 1;
    body.n = v.n - 2;
    return b64_len(body, out, cap, want);
}

/* Decode + validate one compact JWT: header JSON, payload JSON, the wire
 * signing input, and the still-encoded signature segment. Every buffer is the
 * caller's.
 *
 * The signature is deliberately NOT decoded here. Its decoding is a length
 * check, and a length check must not be able to pre-empt the ALGORITHM check:
 * an `alg: none` token carries an EMPTY signature, and a verifier that rejects
 * it for being the wrong length has not actually refused `none` — swap in 64
 * bytes of anything and the same code path would have to be trusted to refuse
 * it on the algorithm. So the caller runs header_ok() first and decodes the
 * signature only afterwards. */
static int jwt_open(dsso_slice jwt,
                    uint8_t *hb, size_t hcap, dsso_slice *hdr,
                    uint8_t *pb, size_t pcap, dsso_slice *pl,
                    dsso_slice *signing_input, dsso_slice *sig_b64) {
    dsso_slice hb64, pb64, raw;
    dsso_json_type t;
    size_t n;
    int rc;

    rc = dsso_jwt_split(jwt, &hb64, &pb64, sig_b64, signing_input);
    if (rc != DSSO_OK) return rc;

    if (dsso_b64url_decode(hb64, hb, hcap, &n) != DSSO_OK) return DSSO_E_FORMAT;
    raw.p = hb; raw.n = n;
    rc = dsso_json_validate(raw, hdr, &t);
    if (rc != DSSO_OK) return rc;
    if (t != DSSO_JSON_OBJECT) return DSSO_E_FORMAT;

    if (dsso_b64url_decode(pb64, pb, pcap, &n) != DSSO_OK) return DSSO_E_FORMAT;
    raw.p = pb; raw.n = n;
    rc = dsso_json_validate(raw, pl, &t);
    if (rc != DSSO_OK) return rc;
    if (t != DSSO_JSON_OBJECT) return DSSO_E_FORMAT;

    return DSSO_OK;
}

/* A JOSE header DSSO is willing to process at all.
 *
 * `alg` must be exactly "ES256". This single test is what rejects BOTH the
 * `alg: none` family (RFC 7515 §6.1 "none", accepted by a verifier that reads
 * the algorithm out of the token) AND algorithm substitution (an issuer's
 * P-256 key re-presented as an HMAC key under `alg: HS256`, the classic
 * confusion attack) — because the algorithm is not read from the token to
 * SELECT a verifier, it is read only to be compared against the one algorithm
 * this service implements.
 *
 * Any header parameter that carries or locates key material is rejected: the
 * key comes from the trust list (OIA_12). `crit` is rejected because DSSO
 * implements no critical extension, and RFC 7515 §4.1.11 says a header it does
 * not understand must not be processed. */
static int header_ok(dsso_slice hdr, const char *want_typ) {
    static const char *FORBIDDEN[] = { "jwk", "jku", "x5u", "x5c", "x5t", "crit" };
    dsso_slice v;
    dsso_json_type t;
    size_t i;

    for (i = 0; i < sizeof FORBIDDEN / sizeof FORBIDDEN[0]; ++i)
        if (dsso_json_member(hdr, FORBIDDEN[i], &v, &t) == DSSO_OK)
            return DSSO_E_TRUST;

    if (dsso_json_member(hdr, "alg", &v, &t) != DSSO_OK) return DSSO_E_CRYPTO;
    if (t != DSSO_JSON_STRING) return DSSO_E_CRYPTO;
    if (!dsso_json_string_equals(v, "ES256")) return DSSO_E_CRYPTO;

    if (want_typ) {
        if (dsso_json_member(hdr, "typ", &v, &t) != DSSO_OK) return DSSO_E_FORMAT;
        if (t != DSSO_JSON_STRING) return DSSO_E_FORMAT;
        if (!dsso_json_string_equals(v, want_typ)) return DSSO_E_FORMAT;
    }
    return DSSO_OK;
}

/* Every byte of a presentation must be from the SD-JWT combined-format
 * alphabet: base64url, '.' and '~'. A byte outside it cannot appear in any
 * legitimate presentation, so rejecting early keeps the rest of the pipeline
 * from having to reason about, say, an embedded NUL splitting a claim name. */
static int wire_charset_ok(dsso_slice s) {
    size_t i;
    for (i = 0; i < s.n; ++i) {
        uint8_t c = s.p[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            continue;
        return DSSO_E_FORMAT;
    }
    return DSSO_OK;
}

/* ─────────────────────────── assurance (rule 9) ─────────────────────────── */

/* HOW DSSO DECIDES THE LEVEL OF A PRESENTATION.
 *
 * The credential must ASSERT its level, in the ISSUER-SIGNED payload (never in
 * a disclosure — the wallet chooses what to disclose, and a level the holder
 * can withhold or select is not evidence). DSSO reads the OIDC `acr` claim and
 * requires one of the three eIDAS level URIs of Commission Implementing
 * Regulation (EU) 2015/1502. An absent, unrecognised or non-string `acr` is
 * DSSO_E_ASSURANCE, not "unknown, proceed".
 *
 * The effective level is min(anchor.max_loa, credential.acr): the trust anchor
 * entry caps what its issuer may claim, so an issuer configured as substantial
 * cannot mint a "high" credential, and a token cannot talk its own issuer up.
 *
 * STATED LIMITATION: the ARF v2.9.0 PID Rulebook does not fix a claim name for
 * the assurance level of the credential ITSELF in the SD-JWT VC profile. `acr`
 * with the eIDAS LoA URIs is DSSO's profile choice, documented here and in
 * docs/proofs/DssoPidVerification.md. If a future rulebook fixes a different
 * carrier, this one function changes. */
static int assurance_of(dsso_slice payload, dsso_loa *out) {
    dsso_slice v;
    dsso_json_type t;
    if (dsso_json_member(payload, "acr", &v, &t) != DSSO_OK) return DSSO_E_ASSURANCE;
    if (t != DSSO_JSON_STRING) return DSSO_E_ASSURANCE;
    if (dsso_json_string_equals(v, "http://eidas.europa.eu/LoA/high"))
        { *out = DSSO_LOA_HIGH; return DSSO_OK; }
    if (dsso_json_string_equals(v, "http://eidas.europa.eu/LoA/substantial"))
        { *out = DSSO_LOA_SUBSTANTIAL; return DSSO_OK; }
    if (dsso_json_string_equals(v, "http://eidas.europa.eu/LoA/low"))
        { *out = DSSO_LOA_LOW; return DSSO_OK; }
    return DSSO_E_ASSURANCE;
}

/* ──────────────────────────── status (rule 8) ───────────────────────────── */

/* IETF Token Status List (draft-ietf-oauth-status-list). The credential carries
 *   "status": { "status_list": { "idx": <n>, "uri": "<list url>" } }
 * and the list itself is a signed JWT whose payload carries
 *   "status_list": { "bits": <1|2|4|8>, "lst": "<base64url(zlib(bitstring))>" }
 *
 * FAIL-CLOSED, in four distinct ways, all of which the gate exercises:
 *   - the fetch callback fails                      -> DSSO_E_UNAVAILABLE
 *   - the token is past its own `exp` (stale)       -> DSSO_E_UNAVAILABLE
 *   - the token's `sub` is not the list we asked for-> DSSO_E_UNAVAILABLE
 *   - the index is past the end of the bitstring    -> DSSO_E_UNAVAILABLE
 * A status that IS readable and is not 0x00 (VALID) is DSSO_E_STATUS: 0x01 is
 * INVALID (revoked), 0x02 is SUSPENDED, and any other value is an extension
 * this verifier does not understand and therefore refuses.
 *
 * The status token is verified against the SAME trust anchor list as the
 * credential: a revocation feed that anyone may sign is not a revocation feed. */
static int check_status(dsso_slice payload, const dsso_pid_policy *pol,
                        const uint8_t *cred_iss, size_t cred_iss_len) {
    uint8_t  uri[256];
    size_t   uri_len = 0;
    int64_t  idx = 0;
    dsso_slice st, sl;
    dsso_json_type t;
    int rc;

    if (dsso_json_member(payload, "status", &st, &t) != DSSO_OK || t != DSSO_JSON_OBJECT)
        return DSSO_E_FORMAT;
    if (dsso_json_member(st, "status_list", &sl, &t) != DSSO_OK || t != DSSO_JSON_OBJECT)
        return DSSO_E_FORMAT;
    if (str_member(sl, "uri", uri, sizeof uri, &uri_len) != DSSO_OK)
        return DSSO_E_FORMAT;
    if (int_member(sl, "idx", &idx) != DSSO_OK || idx < 0)
        return DSSO_E_FORMAT;

    if (!pol->fetch) return DSSO_E_UNAVAILABLE;

    {
        /* Automatic, not static: this module stays reentrant, at the price of a
         * ~40 KiB frame here (16 KiB fetched token + 16 KiB inflated bitstring
         * + 4 KiB compressed + 4 KiB payload). Every one of those is a cap from
         * dsso.h, so the frame is a compile-time constant, not a function of
         * what a wallet sent. */
        uint8_t tok[DSSO_MAX_TOKEN];
        uint8_t hb[512], pb[DSSO_MAX_FIELD];
        uint8_t bits_buf[DSSO_MAX_STATUS_BYTES];
        uint8_t comp[DSSO_MAX_FIELD];
        dsso_slice raw, hdr, pl, si, sig_b64;
        uint8_t sig[64], kid[128], iss[128], sub[256];
        size_t tok_len = 0, kid_len = 0, iss_len = 0, sub_len = 0, comp_len = 0, bits_len = 0;
        const dsso_trust_anchor *anchor = NULL;
        int64_t exp = 0, bits = 0;
        size_t byte_off, shift, need;
        unsigned value;

        if (pol->fetch(pol->fetch_ctx, uri, uri_len, tok, sizeof tok, &tok_len) != 0)
            return DSSO_E_UNAVAILABLE;
        if (tok_len == 0 || tok_len > sizeof tok) return DSSO_E_UNAVAILABLE;

        raw.p = tok; raw.n = tok_len;
        rc = jwt_open(raw, hb, sizeof hb, &hdr, pb, sizeof pb, &pl, &si, &sig_b64);
        if (rc != DSSO_OK) return DSSO_E_UNAVAILABLE;
        rc = header_ok(hdr, "statuslist+jwt");
        if (rc != DSSO_OK) return rc;
        if (b64_len(sig_b64, sig, 64, 64) != DSSO_OK) return DSSO_E_UNAVAILABLE;
        if (str_member(hdr, "kid", kid, sizeof kid, &kid_len) != DSSO_OK)
            return DSSO_E_UNAVAILABLE;
        if (str_member(pl, "iss", iss, sizeof iss, &iss_len) != DSSO_OK)
            return DSSO_E_UNAVAILABLE;
        /* ADVERSARIAL-REVIEW FINDING (malicious issuer), closed here.
         * Requiring only "signed by SOME anchor on the list" would let any
         * PID Provider on the list answer the revocation question for
         * ANOTHER provider's credential: one compromised, low-assurance
         * issuer could un-revoke every other Member State's PID by hosting
         * a status token at the named URI and signing it with its own key
         * — `sub` would match, the signature would verify, and the
         * credential would come back VALID. The status token must therefore
         * come from the CREDENTIAL'S OWN issuer. This is stricter than
         * draft-ietf-oauth-status-list, which permits a third-party status
         * provider; a deployment that needs one adds that provider under the
         * credential issuer's own identifier rather than to the list at
         * large. */
        if (iss_len != cred_iss_len || !dsso_ct_equal(iss, cred_iss, iss_len))
            return DSSO_E_TRUST;
        rc = dsso_trust_lookup(pol->trust, iss, iss_len, kid, kid_len, &anchor);
        if (rc != DSSO_OK) return rc;                       /* DSSO_E_TRUST */
        if (dsso_es256_verify(anchor->pk, si, sig) != DSSO_OK) return DSSO_E_CRYPTO;

        /* The token must be the list the credential named, or an attacker
         * answers a revocation question with a different list's answer. */
        if (str_member(pl, "sub", sub, sizeof sub, &sub_len) != DSSO_OK)
            return DSSO_E_UNAVAILABLE;
        if (sub_len != uri_len || !dsso_ct_equal(sub, uri, uri_len))
            return DSSO_E_UNAVAILABLE;

        /* Stale beyond its own `exp` is "could not be consulted", not "valid". */
        if (int_member(pl, "exp", &exp) != DSSO_OK) return DSSO_E_UNAVAILABLE;
        if (exp <= pol->now) return DSSO_E_UNAVAILABLE;

        if (dsso_json_member(pl, "status_list", &sl, &t) != DSSO_OK || t != DSSO_JSON_OBJECT)
            return DSSO_E_UNAVAILABLE;
        if (int_member(sl, "bits", &bits) != DSSO_OK) return DSSO_E_UNAVAILABLE;
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) return DSSO_E_UNAVAILABLE;
        {
            dsso_slice v, body;
            if (dsso_json_member(sl, "lst", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING || v.n < 2)
                return DSSO_E_UNAVAILABLE;
            body.p = v.p + 1; body.n = v.n - 2;
            if (dsso_b64url_decode(body, comp, sizeof comp, &comp_len) != DSSO_OK)
                return DSSO_E_UNAVAILABLE;
        }
        {
            dsso_slice z;
            z.p = comp; z.n = comp_len;
            if (dsso_inflate(z, bits_buf, sizeof bits_buf, &bits_len) != DSSO_OK)
                return DSSO_E_UNAVAILABLE;           /* bomb, truncation, bad CRC */
        }

        /* Index the bitstring: statuses are packed least-significant-bits-first
         * within each byte (draft-ietf-oauth-status-list §4.1). */
        if ((uint64_t)idx > (uint64_t)0x00FFFFFFu) return DSSO_E_UNAVAILABLE;
        byte_off = (size_t)((uint64_t)idx * (uint64_t)bits / 8u);
        shift    = (size_t)((uint64_t)idx * (uint64_t)bits % 8u);
        need     = byte_off + 1u;
        if (need > bits_len) return DSSO_E_UNAVAILABLE;   /* not covered by the list */
        value = (unsigned)((bits_buf[byte_off] >> shift) & ((1u << (unsigned)bits) - 1u));
        if (value != 0u) return DSSO_E_STATUS;            /* revoked / suspended */
    }
    return DSSO_OK;
}

/* ───────────────────────── disclosures (rule 4) ─────────────────────────── */

/* Registered JWT / SD-JWT VC names a disclosure may never introduce. A
 * disclosure is holder-selected material; letting one carry `iss` or `cnf`
 * would let the holder overwrite what the issuer signed. */
static int reserved_name(const uint8_t *n, size_t len) {
    static const char *R[] = { "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
                               "cnf", "vct", "status", "acr", "_sd", "_sd_alg",
                               "...", "alg", "kid", "typ" };
    size_t i;
    for (i = 0; i < sizeof R / sizeof R[0]; ++i) {
        size_t rl = strlen(R[i]);
        if (rl == len && memcmp(R[i], n, len) == 0) return 1;
    }
    return 0;
}

/* The disclosure salt must be at least 128 bits of base64url (22 characters) —
 * the SD-JWT requirement that makes a digest un-guessable. A short or
 * non-base64url salt lets a verifier's own `_sd` array be brute-forced back
 * into the withheld attribute values. */
static int salt_ok(dsso_slice s) {
    size_t i;
    if (s.n < 2) return 0;
    if (s.n - 2 < 22) return 0;
    for (i = 1; i + 1 < s.n; ++i) {
        uint8_t c = s.p[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') continue;
        return 0;
    }
    return 1;
}

/* ───────────────────────────── the pipeline ─────────────────────────────── */

void dsso_pid_result_scrub(dsso_pid_result *r) {
    if (!r) return;
    determ_secure_zero(r, sizeof *r);
}

int dsso_pid_claim_value(const dsso_pid_result *r, const char *name,
                         dsso_slice *out) {
    size_t i, nl;
    if (!r || !name || !out) return DSSO_E_ARG;
    nl = strlen(name);
    for (i = 0; i < r->n_claims; ++i) {
        if (r->claims[i].name_len != nl) continue;
        if (memcmp(r->claims[i].name, name, nl) != 0) continue;
        out->p = r->claims[i].value;
        out->n = r->claims[i].value_len;
        return DSSO_OK;
    }
    return DSSO_E_FORMAT;
}

int dsso_pid_subject_material(const dsso_pid_result *r,
                              uint8_t *out, size_t cap, size_t *outlen) {
    dsso_slice v;
    size_t o = 0;
    int rc;
    if (!r || !out || !outlen) return DSSO_E_ARG;
    rc = dsso_pid_claim_value(r, "personal_administrative_number", &v);
    if (rc != DSSO_OK) return DSSO_E_FORMAT;
    if (v.n < 2 || v.p[0] != '"') return DSSO_E_FORMAT;  /* must be a string */
    if (r->iss_len > 255 || v.n > 255) return DSSO_E_ARG;   /* the length prefixes */
    if (r->iss_len + v.n + 2 > cap) return DSSO_E_ARG;
    /* Length-separated so ("ab","c") and ("a","bc") cannot collide. */
    out[o++] = (uint8_t)(r->iss_len & 0xFFu);
    memcpy(out + o, r->iss, r->iss_len); o += r->iss_len;
    out[o++] = (uint8_t)(v.n & 0xFFu);
    memcpy(out + o, v.p, v.n); o += v.n;
    *outlen = o;
    return DSSO_OK;
}

/* The pipeline proper. Every failure exit is a plain `return`; the public
 * wrapper below scrubs the result, so a caller that ignores the status can
 * never read half-built claims out of it. */
static int pid_verify_inner(dsso_slice presentation, const dsso_pid_policy *pol,
                            dsso_pid_result *out) {
    /* These buffers dominate the frame; everything else is scalars. All are
     * automatic (the module is reentrant) and all are sized from the dsso.h
     * caps, so the frame is a compile-time constant. */
    uint8_t hb[1024], pb[DSSO_MAX_FIELD];
    uint8_t khb[512], kpb[1024];
    uint8_t dbuf[DSSO_MAX_FIELD];
    uint8_t sd_digest[DSSO_JSON_MAX_ELEMS][32];
    uint8_t sd_used[DSSO_JSON_MAX_ELEMS];

    dsso_slice parts[DSSO_MAX_PARTS];
    size_t     nparts = 0;
    dsso_slice hdr, pl, si, khdr, kpl, ksi, v, sd_arr, sig_b64, ksig_b64;
    dsso_json_type t;
    uint8_t sig[64], ksig[64], cnf_pk[65];
    uint8_t kid[128], iss[DSSO_PID_MAX_NAME], namebuf[DSSO_PID_MAX_NAME];
    uint8_t got[32], want[32];
    size_t  kid_len = 0, iss_len = 0, n_sd = 0, kb_off = 0;
    size_t  i, j, k;
    const dsso_trust_anchor *anchor = NULL;
    int64_t iat = 0, exp = 0, nbf = 0, kb_iat = 0;
    dsso_loa cred_loa = DSSO_LOA_NONE, eff;
    int rc;

    if (!pol->trust || !pol->rp_id || (pol->nonce_len && !pol->nonce)) return DSSO_E_ARG;
    if (presentation.n == 0 || !presentation.p) return DSSO_E_FORMAT;
    if (presentation.n > DSSO_MAX_TOKEN) return DSSO_E_FORMAT;

    /* ── rule 1: structure ───────────────────────────────────────────────── */
    rc = wire_charset_ok(presentation);
    if (rc != DSSO_OK) return rc;
    {
        size_t start = 0;
        for (i = 0; i <= presentation.n; ++i) {
            if (i == presentation.n || presentation.p[i] == '~') {
                if (nparts >= DSSO_MAX_PARTS) return DSSO_E_FORMAT;
                parts[nparts].p = presentation.p + start;
                parts[nparts].n = i - start;
                nparts++;
                if (i < presentation.n && presentation.p[i] == '~') kb_off = i + 1;
                start = i + 1;
            }
        }
    }
    if (nparts < 2) return DSSO_E_FORMAT;                   /* no `~` at all */
    if (parts[0].n == 0) return DSSO_E_FORMAT;
    if (nparts - 2 > DSSO_MAX_CLAIMS) return DSSO_E_FORMAT;  /* too many disclosures */

    rc = jwt_open(parts[0], hb, sizeof hb, &hdr, pb, sizeof pb, &pl, &si, &sig_b64);
    if (rc != DSSO_OK) return rc;

    /* ── rule 2: issuer trust (OIA_12) ───────────────────────────────────── */
    rc = header_ok(hdr, NULL);
    if (rc != DSSO_OK) return rc;
    {
        /* SD-JWT VC media type. Both the current `dc+sd-jwt` and the earlier
         * `vc+sd-jwt` are accepted; anything else is not an SD-JWT VC. */
        if (dsso_json_member(hdr, "typ", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
            return DSSO_E_FORMAT;
        if (!dsso_json_string_equals(v, "dc+sd-jwt") &&
            !dsso_json_string_equals(v, "vc+sd-jwt"))
            return DSSO_E_FORMAT;
    }
    if (str_member(hdr, "kid", kid, sizeof kid, &kid_len) != DSSO_OK)
        return DSSO_E_TRUST;
    if (str_member(pl, "iss", iss, sizeof iss, &iss_len) != DSSO_OK)
        return DSSO_E_TRUST;
    rc = dsso_trust_lookup(pol->trust, iss, iss_len, kid, kid_len, &anchor);
    if (rc != DSSO_OK) return rc;

    /* ── rule 3: signature ───────────────────────────────────────────────── */
    if (b64_len(sig_b64, sig, 64, 64) != DSSO_OK) return DSSO_E_FORMAT;
    rc = dsso_es256_verify(anchor->pk, si, sig);
    if (rc != DSSO_OK) return rc;

    /* ── rule 4: selective disclosure ────────────────────────────────────── */
    if (dsso_json_member(pl, "_sd_alg", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_FORMAT;
    if (!dsso_json_string_equals(v, "sha-256")) return DSSO_E_FORMAT;
    if (dsso_json_member(pl, "_sd", &sd_arr, &t) != DSSO_OK || t != DSSO_JSON_ARRAY)
        return DSSO_E_FORMAT;
    if (dsso_json_array_len(sd_arr, &n_sd) != DSSO_OK) return DSSO_E_FORMAT;
    if (n_sd == 0 || n_sd > DSSO_JSON_MAX_ELEMS) return DSSO_E_FORMAT;
    for (i = 0; i < n_sd; ++i) {
        dsso_slice e, body;
        if (dsso_json_element(sd_arr, i, &e, &t) != DSSO_OK || t != DSSO_JSON_STRING)
            return DSSO_E_FORMAT;
        if (e.n < 2) return DSSO_E_FORMAT;
        body.p = e.p + 1; body.n = e.n - 2;
        if (b64_len(body, sd_digest[i], 32, 32) != DSSO_OK) return DSSO_E_FORMAT;
        for (j = 0; j < i; ++j)
            if (dsso_ct_equal(sd_digest[i], sd_digest[j], 32)) return DSSO_E_FORMAT;
        sd_used[i] = 0;
    }

    for (k = 1; k + 1 < nparts; ++k) {
        dsso_slice d = parts[k], darr, el;
        size_t dn = 0, nl = 0, matched = (size_t)-1;
        if (d.n == 0) return DSSO_E_FORMAT;                 /* empty disclosure */
        determ_sha256(d.p, d.n, got);
        for (i = 0; i < n_sd; ++i) {
            if (!dsso_ct_equal(got, sd_digest[i], 32)) continue;
            /* A digest may be presented once. A second disclosure hashing to
             * the same `_sd` entry is a duplicate, not a second attribute. */
            if (sd_used[i]) return DSSO_E_FORMAT;
            sd_used[i] = 1;
            matched = i;
            break;
        }
        if (matched == (size_t)-1) return DSSO_E_FORMAT;    /* matches no digest */

        if (dsso_b64url_decode(d, dbuf, sizeof dbuf, &dn) != DSSO_OK) return DSSO_E_FORMAT;
        { dsso_slice raw; raw.p = dbuf; raw.n = dn;
          if (dsso_json_validate(raw, &darr, &t) != DSSO_OK) return DSSO_E_FORMAT; }
        if (t != DSSO_JSON_ARRAY) return DSSO_E_FORMAT;
        { size_t alen = 0;
          if (dsso_json_array_len(darr, &alen) != DSSO_OK || alen != 3) return DSSO_E_FORMAT; }

        if (dsso_json_element(darr, 0, &el, &t) != DSSO_OK || t != DSSO_JSON_STRING)
            return DSSO_E_FORMAT;
        if (!salt_ok(el)) return DSSO_E_FORMAT;

        if (dsso_json_element(darr, 1, &el, &t) != DSSO_OK || t != DSSO_JSON_STRING)
            return DSSO_E_FORMAT;
        if (dsso_json_string(el, namebuf, sizeof namebuf, &nl) != DSSO_OK)
            return DSSO_E_FORMAT;
        if (nl == 0) return DSSO_E_FORMAT;
        if (memchr(namebuf, 0, nl) != NULL) return DSSO_E_FORMAT;
        if (reserved_name(namebuf, nl)) return DSSO_E_FORMAT;
        /* An attribute the issuer already asserts in cleartext may not also
         * arrive as a disclosure: that is the "undisclosed but claimed" shape,
         * where the holder supplies a value the issuer did not digest. */
        {
            char key[DSSO_PID_MAX_NAME + 1];
            memcpy(key, namebuf, nl); key[nl] = '\0';
            if (dsso_json_member(pl, key, &v, &t) == DSSO_OK) return DSSO_E_FORMAT;
        }
        for (i = 0; i < out->n_claims; ++i)
            if (out->claims[i].name_len == nl &&
                memcmp(out->claims[i].name, namebuf, nl) == 0)
                return DSSO_E_FORMAT;                       /* same name twice */

        if (dsso_json_element(darr, 2, &el, &t) != DSSO_OK) return DSSO_E_FORMAT;
        if (el.n > DSSO_PID_MAX_VALUE) return DSSO_E_FORMAT;
        if (out->n_claims >= DSSO_MAX_CLAIMS) return DSSO_E_FORMAT;
        memcpy(out->claims[out->n_claims].name, namebuf, nl);
        out->claims[out->n_claims].name_len = nl;
        memcpy(out->claims[out->n_claims].value, el.p, el.n);
        out->claims[out->n_claims].value_len = el.n;
        out->n_claims++;
    }

    /* ── rule 5: holder binding (OIA_02) ─────────────────────────────────── */
    if (parts[nparts - 1].n == 0) return DSSO_E_BINDING;
    if (dsso_json_member(pl, "cnf", &v, &t) != DSSO_OK || t != DSSO_JSON_OBJECT)
        return DSSO_E_BINDING;
    { dsso_slice jwk;
      if (dsso_json_member(v, "jwk", &jwk, &t) != DSSO_OK || t != DSSO_JSON_OBJECT)
          return DSSO_E_BINDING;
      if (dsso_jwk_p256(jwk, cnf_pk) != DSSO_OK) return DSSO_E_BINDING; }

    rc = jwt_open(parts[nparts - 1], khb, sizeof khb, &khdr,
                  kpb, sizeof kpb, &kpl, &ksi, &ksig_b64);
    if (rc != DSSO_OK) return rc;
    rc = header_ok(khdr, "kb+jwt");
    if (rc != DSSO_OK) return (rc == DSSO_E_CRYPTO) ? DSSO_E_CRYPTO : DSSO_E_BINDING;
    if (b64_len(ksig_b64, ksig, 64, 64) != DSSO_OK) return DSSO_E_BINDING;

    /* sd_hash covers the presentation up to AND INCLUDING the final `~` — the
     * exact bytes of this issuer JWT and these disclosures. A KB-JWT lifted
     * from another presentation, or one whose disclosure set has been edited,
     * fails here. */
    determ_sha256(presentation.p, kb_off, want);
    if (b64_string_member(kpl, "sd_hash", got, 32, 32) != DSSO_OK)
        return DSSO_E_BINDING;
    if (!dsso_ct_equal(got, want, 32)) return DSSO_E_BINDING;

    /* Signed by the key the credential binds, not merely by SOME key. */
    if (dsso_es256_verify(cnf_pk, ksi, ksig) != DSSO_OK) return DSSO_E_BINDING;

    /* ── rule 6a: audience ───────────────────────────────────────────────── */
    if (dsso_json_member(kpl, "aud", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_AUDIENCE;
    if (!dsso_json_string_equals(v, pol->rp_id)) return DSSO_E_AUDIENCE;

    /* ── rule 6b: request binding ────────────────────────────────────────── */
    {
        uint8_t nb[128];
        size_t nl = 0;
        if (str_member(kpl, "nonce", nb, sizeof nb, &nl) != DSSO_OK)
            return DSSO_E_REPLAY;
        if (nl != pol->nonce_len || !dsso_ct_equal(nb, pol->nonce, nl))
            return DSSO_E_REPLAY;
    }

    /* ── rule 7: freshness ───────────────────────────────────────────────── */
    if (int_member(pl, "iat", &iat) != DSSO_OK) return DSSO_E_EXPIRED;
    if (int_member(pl, "exp", &exp) != DSSO_OK) return DSSO_E_EXPIRED;
    if (iat > pol->now + pol->max_skew) return DSSO_E_EXPIRED;
    if (exp <= pol->now - pol->max_skew) return DSSO_E_EXPIRED;
    if (exp <= iat) return DSSO_E_EXPIRED;
    if (pol->now - iat > pol->max_cred_age) return DSSO_E_EXPIRED;
    if (int_member(pl, "nbf", &nbf) == DSSO_OK && nbf > pol->now + pol->max_skew)
        return DSSO_E_EXPIRED;
    if (int_member(kpl, "iat", &kb_iat) != DSSO_OK) return DSSO_E_EXPIRED;
    if (kb_iat > pol->now + pol->max_skew) return DSSO_E_EXPIRED;
    if (pol->now - kb_iat > pol->max_pres_age) return DSSO_E_EXPIRED;

    /* ── rule 8: status ──────────────────────────────────────────────────── */
    rc = check_status(pl, pol, iss, iss_len);
    if (rc != DSSO_OK) return rc;

    /* ── rule 9: assurance ───────────────────────────────────────────────── */
    rc = assurance_of(pl, &cred_loa);
    if (rc != DSSO_OK) return rc;
    eff = (cred_loa < anchor->max_loa) ? cred_loa : anchor->max_loa;
    if ((int)eff < (int)pol->required_loa) return DSSO_E_ASSURANCE;

    if (iss_len > sizeof out->iss) return DSSO_E_FORMAT;
    memcpy(out->iss, iss, iss_len);
    out->iss_len  = iss_len;
    out->loa      = eff;
    out->cred_iat = iat;
    out->cred_exp = exp;
    return DSSO_OK;
}

int dsso_pid_verify(dsso_slice presentation, const dsso_pid_policy *pol,
                    dsso_pid_result *out) {
    int rc;
    if (!pol || !out) return DSSO_E_ARG;
    memset(out, 0, sizeof *out);
    rc = pid_verify_inner(presentation, pol, out);
    if (rc != DSSO_OK) dsso_pid_result_scrub(out);
    return rc;
}
