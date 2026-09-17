/* dsso_jose — bounded base64url / JSON / JOSE readers. See dsso_jose.h for the
 * contract and for why every reader here is written to be fuzzed. */
#include "dsso_jose.h"

#include <string.h>

#include "determ/crypto/p256/p256.h"
#include "determ/crypto/sha2/sha2.h"

/* ─────────────────────────────── base64url ──────────────────────────────── */

static int b64u_val(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;   /* '=', '+', '/', whitespace, NUL, anything else */
}

int dsso_b64url_decode(dsso_slice in, uint8_t *out, size_t cap, size_t *outlen) {
    size_t full, rem, need, i, o;

    if (!out || !outlen) return DSSO_E_ARG;
    if (in.n && !in.p) return DSSO_E_ARG;
    if (in.n > DSSO_MAX_TOKEN) return DSSO_E_FORMAT;

    rem  = in.n % 4;
    if (rem == 1) return DSSO_E_FORMAT;     /* no base64 string has this length */
    full = in.n / 4;
    need = full * 3 + (rem ? rem - 1 : 0);
    if (need > cap) return DSSO_E_ARG;

    /* Pass 1 — validate the whole input, so a failure leaves `out` untouched. */
    for (i = 0; i < in.n; ++i)
        if (b64u_val(in.p[i]) < 0) return DSSO_E_FORMAT;
    /* Canonical tail: the bits of the final group that encode nothing MUST be
     * zero. Without this, "QQ" and "QR" both decode to the single byte 0x41 and
     * a signed object has two encodings. */
    if (rem == 2 && (b64u_val(in.p[in.n - 1]) & 0x0F) != 0) return DSSO_E_FORMAT;
    if (rem == 3 && (b64u_val(in.p[in.n - 1]) & 0x03) != 0) return DSSO_E_FORMAT;

    /* Pass 2 — decode. */
    o = 0;
    for (i = 0; i + 4 <= full * 4; i += 4) {
        uint32_t v = ((uint32_t)b64u_val(in.p[i])     << 18)
                   | ((uint32_t)b64u_val(in.p[i + 1]) << 12)
                   | ((uint32_t)b64u_val(in.p[i + 2]) <<  6)
                   | ((uint32_t)b64u_val(in.p[i + 3]));
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
        out[o++] = (uint8_t)v;
    }
    if (rem == 2) {
        uint32_t v = ((uint32_t)b64u_val(in.p[i]) << 18)
                   | ((uint32_t)b64u_val(in.p[i + 1]) << 12);
        out[o++] = (uint8_t)(v >> 16);
    } else if (rem == 3) {
        uint32_t v = ((uint32_t)b64u_val(in.p[i])     << 18)
                   | ((uint32_t)b64u_val(in.p[i + 1]) << 12)
                   | ((uint32_t)b64u_val(in.p[i + 2]) <<  6);
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
    }
    *outlen = o;
    return DSSO_OK;
}

/* ───────────────────────────── JSON: strings ────────────────────────────── */

/* Streaming unescape of a JSON string BODY (the bytes between the quotes).
 * Emits UTF-8. Returns 1 and fills buf/len with 1..4 bytes, 0 at end of body,
 * or -1 on a malformed escape / raw control character. */
static int js_next(const uint8_t *s, size_t n, size_t *i, uint8_t buf[4], int *len) {
    uint32_t cp;
    int k;
    if (*i >= n) return 0;
    if (s[*i] != '\\') {
        uint8_t c = s[*i];
        if (c < 0x20) return -1;          /* raw control char — RFC 8259 §7 */
        if (c == '"') return -1;          /* an unescaped quote cannot be here */
        buf[0] = c; *len = 1; (*i)++;
        return 1;
    }
    (*i)++;
    if (*i >= n) return -1;
    switch (s[*i]) {
        case '"':  buf[0] = '"';  *len = 1; (*i)++; return 1;
        case '\\': buf[0] = '\\'; *len = 1; (*i)++; return 1;
        case '/':  buf[0] = '/';  *len = 1; (*i)++; return 1;
        case 'b':  buf[0] = 0x08; *len = 1; (*i)++; return 1;
        case 'f':  buf[0] = 0x0C; *len = 1; (*i)++; return 1;
        case 'n':  buf[0] = 0x0A; *len = 1; (*i)++; return 1;
        case 'r':  buf[0] = 0x0D; *len = 1; (*i)++; return 1;
        case 't':  buf[0] = 0x09; *len = 1; (*i)++; return 1;
        case 'u':  break;
        default:   return -1;
    }
    (*i)++;
    if (*i + 4 > n) return -1;
    cp = 0;
    for (k = 0; k < 4; ++k) {
        uint8_t c = s[*i + (size_t)k];
        uint32_t d;
        if      (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a') + 10u;
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A') + 10u;
        else return -1;
        cp = (cp << 4) | d;
    }
    *i += 4;
    if (cp >= 0xD800u && cp <= 0xDBFFu) {          /* high surrogate: need the low */
        uint32_t lo = 0;
        if (*i + 6 > n || s[*i] != '\\' || s[*i + 1] != 'u') return -1;
        *i += 2;
        for (k = 0; k < 4; ++k) {
            uint8_t c = s[*i + (size_t)k];
            uint32_t d;
            if      (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a') + 10u;
            else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A') + 10u;
            else return -1;
            lo = (lo << 4) | d;
        }
        *i += 4;
        if (lo < 0xDC00u || lo > 0xDFFFu) return -1;
        cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
    } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
        return -1;                                  /* unpaired low surrogate */
    }
    if (cp < 0x80u) { buf[0] = (uint8_t)cp; *len = 1; }
    else if (cp < 0x800u) {
        buf[0] = (uint8_t)(0xC0u | (cp >> 6));
        buf[1] = (uint8_t)(0x80u | (cp & 0x3Fu));
        *len = 2;
    } else if (cp < 0x10000u) {
        buf[0] = (uint8_t)(0xE0u | (cp >> 12));
        buf[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
        buf[2] = (uint8_t)(0x80u | (cp & 0x3Fu));
        *len = 3;
    } else {
        buf[0] = (uint8_t)(0xF0u | (cp >> 18));
        buf[1] = (uint8_t)(0x80u | ((cp >> 12) & 0x3Fu));
        buf[2] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
        buf[3] = (uint8_t)(0x80u | (cp & 0x3Fu));
        *len = 4;
    }
    return 1;
}

/* Two string BODIES compare equal after unescaping. This is what the
 * duplicate-key detector uses: a member name spelled with a backslash-u escape
 * is byte-different from the same name spelled plainly, so a detector that
 * compared RAW bytes would see two distinct keys where every JSON reader in the
 * world sees one — and the second value would silently win. */
static int js_body_equal(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    size_t ia = 0, ib = 0;
    uint8_t ba[4], bb[4];
    int la = 0, lb = 0, oa = 0, ob = 0, ra, rb;
    for (;;) {
        if (oa >= la) { ra = js_next(a, alen, &ia, ba, &la); if (ra < 0) return 0; if (ra == 0) la = 0; oa = 0; }
        if (ob >= lb) { rb = js_next(b, blen, &ib, bb, &lb); if (rb < 0) return 0; if (rb == 0) lb = 0; ob = 0; }
        if (la == 0 && lb == 0) return 1;
        if (la == 0 || lb == 0) return 0;
        if (ba[oa] != bb[ob]) return 0;
        oa++; ob++;
    }
}

/* ──────────────────────── JSON: the bounded parser ──────────────────────── */

typedef struct {
    const uint8_t *p;
    size_t         n;
    size_t         i;
    int            depth;
    int            record;                    /* 1 = validating, 0 = scanning */
    size_t         koff[DSSO_JSON_MAX_KEYS];  /* key body spans, for dup check */
    size_t         klen[DSSO_JSON_MAX_KEYS];
    uint32_t       kobj[DSSO_JSON_MAX_KEYS];  /* which object instance         */
    size_t         nkeys;
    uint32_t       next_obj;
} jp;

static void jp_ws(jp *s) {
    while (s->i < s->n) {
        uint8_t c = s->p[s->i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->i++;
        else break;
    }
}

/* Parse a string token starting at s->i (which must be '"'). On success s->i is
 * past the closing quote and *body is the span between the quotes. */
static int jp_string(jp *s, size_t *body_off, size_t *body_len) {
    size_t start;
    if (s->i >= s->n || s->p[s->i] != '"') return DSSO_E_FORMAT;
    s->i++;
    start = s->i;
    while (s->i < s->n && s->p[s->i] != '"') {
        uint8_t c = s->p[s->i];
        if (c < 0x20) return DSSO_E_FORMAT;
        if (c == '\\') {
            s->i++;
            if (s->i >= s->n) return DSSO_E_FORMAT;
            if (s->p[s->i] == 'u') {
                if (s->i + 4 >= s->n) return DSSO_E_FORMAT;
                s->i += 4;
            }
        }
        s->i++;
    }
    if (s->i >= s->n) return DSSO_E_FORMAT;
    *body_off = start;
    *body_len = s->i - start;
    s->i++;                                     /* past the closing quote */
    /* The escape grammar itself is checked by replaying the body through the
     * unescaper, so a malformed \q or a lone surrogate is caught at validate
     * time and never reaches a comparison. */
    {
        size_t k = 0; uint8_t buf[4]; int len, r;
        for (;;) {
            r = js_next(s->p + *body_off, *body_len, &k, buf, &len);
            if (r < 0) return DSSO_E_FORMAT;
            if (r == 0) break;
        }
    }
    return DSSO_OK;
}

static int jp_number(jp *s) {
    size_t start = s->i;
    if (s->i < s->n && s->p[s->i] == '-') s->i++;
    if (s->i >= s->n) return DSSO_E_FORMAT;
    if (s->p[s->i] == '0') {
        s->i++;
    } else if (s->p[s->i] >= '1' && s->p[s->i] <= '9') {
        while (s->i < s->n && s->p[s->i] >= '0' && s->p[s->i] <= '9') s->i++;
    } else {
        return DSSO_E_FORMAT;                   /* no leading '+', '.', 'N', 'I' */
    }
    if (s->i < s->n && s->p[s->i] == '.') {
        s->i++;
        if (s->i >= s->n || s->p[s->i] < '0' || s->p[s->i] > '9') return DSSO_E_FORMAT;
        while (s->i < s->n && s->p[s->i] >= '0' && s->p[s->i] <= '9') s->i++;
    }
    if (s->i < s->n && (s->p[s->i] == 'e' || s->p[s->i] == 'E')) {
        s->i++;
        if (s->i < s->n && (s->p[s->i] == '+' || s->p[s->i] == '-')) s->i++;
        if (s->i >= s->n || s->p[s->i] < '0' || s->p[s->i] > '9') return DSSO_E_FORMAT;
        while (s->i < s->n && s->p[s->i] >= '0' && s->p[s->i] <= '9') s->i++;
    }
    return s->i > start ? DSSO_OK : DSSO_E_FORMAT;
}

static int jp_lit(jp *s, const char *lit, size_t len) {
    if (s->i + len > s->n) return DSSO_E_FORMAT;
    if (memcmp(s->p + s->i, lit, len) != 0) return DSSO_E_FORMAT;
    s->i += len;
    return DSSO_OK;
}

static int jp_value(jp *s, dsso_json_type *type);

static int jp_object(jp *s) {
    uint32_t oid;
    size_t members = 0;
    if (s->i >= s->n || s->p[s->i] != '{') return DSSO_E_FORMAT;
    s->i++;
    oid = s->next_obj++;
    jp_ws(s);
    if (s->i < s->n && s->p[s->i] == '}') { s->i++; return DSSO_OK; }
    for (;;) {
        size_t koff, klen;
        dsso_json_type t;
        int rc;
        jp_ws(s);
        rc = jp_string(s, &koff, &klen);
        if (rc != DSSO_OK) return rc;
        if (s->record) {
            size_t j;
            for (j = 0; j < s->nkeys; ++j)
                if (s->kobj[j] == oid &&
                    js_body_equal(s->p + s->koff[j], s->klen[j], s->p + koff, klen))
                    return DSSO_E_FORMAT;       /* duplicate member name */
            if (s->nkeys >= DSSO_JSON_MAX_KEYS) return DSSO_E_FORMAT;
            s->koff[s->nkeys] = koff;
            s->klen[s->nkeys] = klen;
            s->kobj[s->nkeys] = oid;
            s->nkeys++;
        }
        jp_ws(s);
        if (s->i >= s->n || s->p[s->i] != ':') return DSSO_E_FORMAT;
        s->i++;
        jp_ws(s);
        rc = jp_value(s, &t);
        if (rc != DSSO_OK) return rc;
        if (++members > DSSO_JSON_MAX_ELEMS) return DSSO_E_FORMAT;
        jp_ws(s);
        if (s->i < s->n && s->p[s->i] == ',') { s->i++; continue; }
        if (s->i < s->n && s->p[s->i] == '}') { s->i++; return DSSO_OK; }
        return DSSO_E_FORMAT;
    }
}

static int jp_array(jp *s) {
    size_t elems = 0;
    if (s->i >= s->n || s->p[s->i] != '[') return DSSO_E_FORMAT;
    s->i++;
    jp_ws(s);
    if (s->i < s->n && s->p[s->i] == ']') { s->i++; return DSSO_OK; }
    for (;;) {
        dsso_json_type t;
        int rc;
        jp_ws(s);
        rc = jp_value(s, &t);
        if (rc != DSSO_OK) return rc;
        if (++elems > DSSO_JSON_MAX_ELEMS) return DSSO_E_FORMAT;
        jp_ws(s);
        if (s->i < s->n && s->p[s->i] == ',') { s->i++; continue; }
        if (s->i < s->n && s->p[s->i] == ']') { s->i++; return DSSO_OK; }
        return DSSO_E_FORMAT;
    }
}

static int jp_value(jp *s, dsso_json_type *type) {
    int rc;
    if (s->i >= s->n) return DSSO_E_FORMAT;
    if (s->depth >= DSSO_JSON_MAX_DEPTH) return DSSO_E_FORMAT;
    switch (s->p[s->i]) {
        case '{':
            s->depth++; rc = jp_object(s); s->depth--;
            *type = DSSO_JSON_OBJECT; return rc;
        case '[':
            s->depth++; rc = jp_array(s); s->depth--;
            *type = DSSO_JSON_ARRAY; return rc;
        case '"': {
            size_t o, l;
            rc = jp_string(s, &o, &l);
            *type = DSSO_JSON_STRING; return rc;
        }
        case 't': *type = DSSO_JSON_BOOL;   return jp_lit(s, "true", 4);
        case 'f': *type = DSSO_JSON_BOOL;   return jp_lit(s, "false", 5);
        case 'n': *type = DSSO_JSON_NULL;   return jp_lit(s, "null", 4);
        default:  *type = DSSO_JSON_NUMBER; return jp_number(s);
    }
}

int dsso_json_validate(dsso_slice doc, dsso_slice *root, dsso_json_type *type) {
    jp s;
    size_t start;
    dsso_json_type t;
    int rc;

    if (!root || !type) return DSSO_E_ARG;
    if (doc.n && !doc.p) return DSSO_E_ARG;
    if (doc.n == 0 || doc.n > DSSO_MAX_TOKEN) return DSSO_E_FORMAT;

    memset(&s, 0, sizeof s);
    s.p = doc.p; s.n = doc.n; s.record = 1;
    jp_ws(&s);
    start = s.i;
    rc = jp_value(&s, &t);
    if (rc != DSSO_OK) return rc;
    {
        size_t end = s.i;
        jp_ws(&s);
        if (s.i != s.n) return DSSO_E_FORMAT;   /* trailing data */
        root->p = doc.p + start;
        root->n = end - start;
    }
    *type = t;
    return DSSO_OK;
}

int dsso_json_member(dsso_slice obj, const char *key,
                     dsso_slice *out, dsso_json_type *type) {
    jp s;
    if (!key || !out || !type) return DSSO_E_ARG;
    if (obj.n == 0 || !obj.p || obj.p[0] != '{') return DSSO_E_FORMAT;
    memset(&s, 0, sizeof s);
    s.p = obj.p; s.n = obj.n; s.i = 1; s.record = 0;
    jp_ws(&s);
    if (s.i < s.n && s.p[s.i] == '}') return DSSO_E_FORMAT;
    for (;;) {
        size_t koff, klen, vstart;
        dsso_json_type t;
        int rc;
        jp_ws(&s);
        rc = jp_string(&s, &koff, &klen);
        if (rc != DSSO_OK) return rc;
        jp_ws(&s);
        if (s.i >= s.n || s.p[s.i] != ':') return DSSO_E_FORMAT;
        s.i++;
        jp_ws(&s);
        vstart = s.i;
        rc = jp_value(&s, &t);
        if (rc != DSSO_OK) return rc;
        if (js_body_equal(s.p + koff, klen, (const uint8_t *)key, strlen(key))) {
            out->p = s.p + vstart;
            out->n = s.i - vstart;
            *type  = t;
            return DSSO_OK;
        }
        jp_ws(&s);
        if (s.i < s.n && s.p[s.i] == ',') { s.i++; continue; }
        return DSSO_E_FORMAT;                   /* absent */
    }
}

static int json_array_walk(dsso_slice arr, size_t want, size_t *count,
                           dsso_slice *out, dsso_json_type *type) {
    jp s;
    size_t idx = 0;
    if (arr.n == 0 || !arr.p || arr.p[0] != '[') return DSSO_E_FORMAT;
    memset(&s, 0, sizeof s);
    s.p = arr.p; s.n = arr.n; s.i = 1; s.record = 0;
    jp_ws(&s);
    if (s.i < s.n && s.p[s.i] == ']') { if (count) *count = 0; return out ? DSSO_E_FORMAT : DSSO_OK; }
    for (;;) {
        size_t vstart;
        dsso_json_type t;
        int rc;
        jp_ws(&s);
        vstart = s.i;
        rc = jp_value(&s, &t);
        if (rc != DSSO_OK) return rc;
        if (out && idx == want) {
            out->p = s.p + vstart;
            out->n = s.i - vstart;
            *type  = t;
            return DSSO_OK;
        }
        idx++;
        jp_ws(&s);
        if (s.i < s.n && s.p[s.i] == ',') { s.i++; continue; }
        break;
    }
    if (count) *count = idx;
    return out ? DSSO_E_FORMAT : DSSO_OK;
}

int dsso_json_array_len(dsso_slice arr, size_t *n) {
    if (!n) return DSSO_E_ARG;
    return json_array_walk(arr, 0, n, NULL, NULL);
}

int dsso_json_element(dsso_slice arr, size_t idx,
                      dsso_slice *out, dsso_json_type *type) {
    if (!out || !type) return DSSO_E_ARG;
    return json_array_walk(arr, idx, NULL, out, type);
}

int dsso_json_string(dsso_slice str, uint8_t *out, size_t cap, size_t *outlen) {
    size_t i = 0, o = 0;
    uint8_t buf[4];
    int len, r, k;
    if (!out || !outlen) return DSSO_E_ARG;
    if (str.n < 2 || !str.p || str.p[0] != '"' || str.p[str.n - 1] != '"')
        return DSSO_E_FORMAT;
    for (;;) {
        r = js_next(str.p + 1, str.n - 2, &i, buf, &len);
        if (r < 0) return DSSO_E_FORMAT;
        if (r == 0) break;
        if (o + (size_t)len > cap) return DSSO_E_ARG;
        for (k = 0; k < len; ++k) out[o++] = buf[k];
    }
    *outlen = o;
    return DSSO_OK;
}

int dsso_json_string_equals(dsso_slice str, const char *lit) {
    if (str.n < 2 || !str.p || !lit) return 0;
    if (str.p[0] != '"' || str.p[str.n - 1] != '"') return 0;
    return js_body_equal(str.p + 1, str.n - 2, (const uint8_t *)lit, strlen(lit));
}

int dsso_json_int(dsso_slice num, int64_t *out) {
    size_t i = 0;
    int neg = 0;
    uint64_t v = 0;
    if (!out) return DSSO_E_ARG;
    if (num.n == 0 || !num.p) return DSSO_E_FORMAT;
    if (num.p[0] == '-') { neg = 1; i = 1; }
    if (i >= num.n) return DSSO_E_FORMAT;
    if (num.p[i] == '0' && num.n - i > 1) return DSSO_E_FORMAT;   /* leading zero */
    for (; i < num.n; ++i) {
        uint8_t c = num.p[i];
        if (c < '0' || c > '9') return DSSO_E_FORMAT;             /* '.', 'e', 'E' */
        if (v > (uint64_t)0x0CCCCCCCCCCCCCCCull) return DSSO_E_FORMAT;
        v = v * 10u + (uint64_t)(c - '0');
    }
    if (neg) {
        if (v > (uint64_t)0x8000000000000000ull) return DSSO_E_FORMAT;
        *out = (v == (uint64_t)0x8000000000000000ull)
             ? (int64_t)(-0x7FFFFFFFFFFFFFFFll - 1)
             : -(int64_t)v;
    } else {
        if (v > (uint64_t)0x7FFFFFFFFFFFFFFFull) return DSSO_E_FORMAT;
        *out = (int64_t)v;
    }
    return DSSO_OK;
}

/* ─────────────────────────────── JOSE / ES256 ───────────────────────────── */

int dsso_jwt_split(dsso_slice jwt, dsso_slice *hdr_b64, dsso_slice *pl_b64,
                   dsso_slice *sig_b64, dsso_slice *signing_input) {
    size_t d1 = 0, d2 = 0, i, dots = 0;
    if (!hdr_b64 || !pl_b64 || !sig_b64 || !signing_input) return DSSO_E_ARG;
    if (jwt.n == 0 || !jwt.p) return DSSO_E_FORMAT;
    if (jwt.n > DSSO_MAX_TOKEN) return DSSO_E_FORMAT;
    for (i = 0; i < jwt.n; ++i) {
        if (jwt.p[i] != '.') continue;
        if (dots == 0) d1 = i;
        else if (dots == 1) d2 = i;
        dots++;
        if (dots > 2) return DSSO_E_FORMAT;
    }
    if (dots != 2) return DSSO_E_FORMAT;
    if (d1 == 0) return DSSO_E_FORMAT;                  /* empty header */
    if (d2 == d1 + 1) return DSSO_E_FORMAT;             /* empty payload */
    hdr_b64->p = jwt.p;          hdr_b64->n = d1;
    pl_b64->p  = jwt.p + d1 + 1; pl_b64->n  = d2 - d1 - 1;
    sig_b64->p = jwt.p + d2 + 1; sig_b64->n = jwt.n - d2 - 1;
    /* The signing input is taken from the wire, never rebuilt: a verifier that
     * re-encodes what it parsed can check a signature over bytes that are not
     * the ones it acted on. */
    signing_input->p = jwt.p;    signing_input->n = d2;
    return DSSO_OK;
}

/* Big-endian 256-bit helpers (public-data arithmetic: r, s and the affine X of
 * the recomputed point are all public). */
static int be_is_zero(const uint8_t a[32]) {
    int i; uint8_t acc = 0;
    for (i = 0; i < 32; ++i) acc |= a[i];
    return acc == 0;
}
static int be_lt(const uint8_t a[32], const uint8_t b[32]) {
    int i;
    for (i = 0; i < 32; ++i) {
        if (a[i] < b[i]) return 1;
        if (a[i] > b[i]) return 0;
    }
    return 0;
}
static void be_sub(uint8_t a[32], const uint8_t b[32]) {
    int i; int borrow = 0;
    for (i = 31; i >= 0; --i) {
        int d = (int)a[i] - (int)b[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        a[i] = (uint8_t)d;
    }
}

int dsso_es256_verify(const uint8_t pk65[65], dsso_slice msg, const uint8_t sig[64]) {
    uint8_t p_be[32], n_be[32], b_be[32], gx[32], gy[32];
    uint8_t e[32], w[32], u1[32], u2[32], x[32];
    uint8_t g65[65], pts[66], scal[64], out33[33];
    int rc;

    if (!pk65 || !sig) return DSSO_E_ARG;
    if (msg.n && !msg.p) return DSSO_E_ARG;

    determ_p256_params(p_be, n_be, b_be, gx, gy);

    /* Canonical signature encoding. JOSE fixes the width at 2·32 bytes, which
     * removes DER's length/negative-integer ambiguity; what remains to check is
     * that both scalars are in [1, n−1]. */
    if (be_is_zero(sig) || !be_lt(sig, n_be)) return DSSO_E_FORMAT;
    if (be_is_zero(sig + 32) || !be_lt(sig + 32, n_be)) return DSSO_E_FORMAT;

    if (determ_p256_point_check(pk65) != 0) return DSSO_E_CRYPTO;

    determ_sha256(msg.p, msg.n, e);
    /* e mod n. n > 2^255 and the digest is < 2^256 < 2n, so one conditional
     * subtraction is the whole reduction. */
    if (!be_lt(e, n_be)) be_sub(e, n_be);

    if (determ_p256_scalar_inv_mod_n(w, sig + 32) != 0) return DSSO_E_CRYPTO;
    if (determ_p256_scalar_mul_mod_n(u1, e, w) != 0) return DSSO_E_CRYPTO;
    if (determ_p256_scalar_mul_mod_n(u2, sig, w) != 0) return DSSO_E_CRYPTO;

    g65[0] = 0x04;
    memcpy(g65 + 1, gx, 32);
    memcpy(g65 + 33, gy, 32);
    if (determ_p256_point_compress(pts, g65) != 0) return DSSO_E_CRYPTO;
    if (determ_p256_point_compress(pts + 33, pk65) != 0) return DSSO_E_CRYPTO;
    memcpy(scal, u1, 32);
    memcpy(scal + 32, u2, 32);

    /* R = u1·G + u2·Q. A non-zero rc is either the point at infinity (rc == 1,
     * which is a forgery attempt, not a valid signature) or a decode failure. */
    rc = determ_p256_msm_ct(out33, scal, pts, 2);
    if (rc != 0) return DSSO_E_CRYPTO;

    memcpy(x, out33 + 1, 32);                    /* affine X of R */
    if (!be_lt(x, n_be)) be_sub(x, n_be);        /* X mod n (p < 2n) */
    return dsso_ct_equal(x, sig, 32) ? DSSO_OK : DSSO_E_CRYPTO;
}

int dsso_jwk_p256(dsso_slice jwk, uint8_t out65[65]) {
    dsso_slice v;
    dsso_json_type t;
    uint8_t xb[48], yb[48], tmp[65];
    size_t xn = 0, yn = 0;

    if (!out65) return DSSO_E_ARG;
    if (dsso_json_member(jwk, "kty", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_FORMAT;
    if (!dsso_json_string_equals(v, "EC")) return DSSO_E_FORMAT;
    if (dsso_json_member(jwk, "crv", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_FORMAT;
    if (!dsso_json_string_equals(v, "P-256")) return DSSO_E_FORMAT;
    if (dsso_json_member(jwk, "x", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_FORMAT;
    if (v.n < 2) return DSSO_E_FORMAT;
    { dsso_slice b; b.p = v.p + 1; b.n = v.n - 2;
      if (dsso_b64url_decode(b, xb, sizeof xb, &xn) != DSSO_OK) return DSSO_E_FORMAT; }
    if (dsso_json_member(jwk, "y", &v, &t) != DSSO_OK || t != DSSO_JSON_STRING)
        return DSSO_E_FORMAT;
    if (v.n < 2) return DSSO_E_FORMAT;
    { dsso_slice b; b.p = v.p + 1; b.n = v.n - 2;
      if (dsso_b64url_decode(b, yb, sizeof yb, &yn) != DSSO_OK) return DSSO_E_FORMAT; }
    if (xn != 32 || yn != 32) return DSSO_E_FORMAT;   /* fixed-width per RFC 7518 */
    tmp[0] = 0x04;
    memcpy(tmp + 1, xb, 32);
    memcpy(tmp + 33, yb, 32);
    if (determ_p256_point_check(tmp) != 0) return DSSO_E_CRYPTO;
    memcpy(out65, tmp, 65);
    return DSSO_OK;
}

/* ─────────────────── bounded inflate (RFC 1950 over RFC 1951) ───────────── */

typedef struct {
    const uint8_t *in; size_t inlen; size_t inpos;
    uint32_t bitbuf; int bitcnt;
    uint8_t *out; size_t cap; size_t outpos;
} inf_st;

typedef struct { short count[16]; short symbol[288]; } inf_huff;

static int inf_bits(inf_st *s, int need, uint32_t *val) {
    uint32_t v = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) return -1;
        v |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = v >> need;
    s->bitcnt -= need;
    *val = need ? (v & ((1u << need) - 1u)) : 0u;
    return 0;
}

static int inf_construct(inf_huff *h, const short *length, int n) {
    int symbol, len, left;
    short offs[16];
    /* Fill the symbol table with -1 first. An INCOMPLETE code (the fixed
     * distance alphabet has 30 of 32 codes) can decode an unused code to a slot
     * this loop never writes; without the sentinel that slot is an
     * indeterminate value and the "is this symbol in range" test below becomes
     * a coin flip. With it, an invalid code is a hard reject. */
    for (symbol = 0; symbol < 288; ++symbol) h->symbol[symbol] = -1;
    for (len = 0; len < 16; ++len) h->count[len] = 0;
    for (symbol = 0; symbol < n; ++symbol) h->count[length[symbol]]++;
    if (h->count[0] == n) return 0;              /* no codes at all */
    left = 1;
    for (len = 1; len < 16; ++len) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;               /* over-subscribed */
    }
    offs[1] = 0;
    for (len = 1; len < 15; ++len) offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (symbol = 0; symbol < n; ++symbol)
        if (length[symbol] != 0) h->symbol[offs[length[symbol]]++] = (short)symbol;
    return left;                                 /* > 0 = incomplete code */
}

static int inf_decode(inf_st *s, const inf_huff *h, int *sym) {
    int len, code = 0, first = 0, count, index = 0;
    uint32_t b;
    for (len = 1; len <= 15; ++len) {
        if (inf_bits(s, 1, &b) != 0) return -1;
        code |= (int)b;
        count = h->count[len];
        if (code - count < first) {
            int slot = index + (code - first);
            if (slot < 0 || slot >= 288) return -1;
            *sym = h->symbol[slot];
            return *sym < 0 ? -1 : 0;            /* an unused code is invalid */
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static const short INF_LENS[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,
                                   59,67,83,99,115,131,163,195,227,258};
static const short INF_LEXT[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const short INF_DIST[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,
                                   769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const short INF_DEXT[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static int inf_codes(inf_st *s, const inf_huff *lencode, const inf_huff *distcode) {
    int sym;
    uint32_t extra;
    for (;;) {
        if (inf_decode(s, lencode, &sym) != 0) return -1;
        if (sym < 256) {
            if (s->outpos >= s->cap) return -1;      /* output ceiling */
            s->out[s->outpos++] = (uint8_t)sym;
        } else if (sym == 256) {
            return 0;
        } else {
            size_t len, dist, k;
            sym -= 257;
            if (sym >= 29) return -1;
            if (inf_bits(s, INF_LEXT[sym], &extra) != 0) return -1;
            len = (size_t)INF_LENS[sym] + (size_t)extra;
            if (inf_decode(s, distcode, &sym) != 0) return -1;
            if (sym >= 30) return -1;
            if (inf_bits(s, INF_DEXT[sym], &extra) != 0) return -1;
            dist = (size_t)INF_DIST[sym] + (size_t)extra;
            if (dist > s->outpos) return -1;         /* before the start of output */
            if (len > s->cap - s->outpos) return -1; /* output ceiling */
            for (k = 0; k < len; ++k) {
                s->out[s->outpos] = s->out[s->outpos - dist];
                s->outpos++;
            }
        }
    }
}

static int inf_stored(inf_st *s) {
    unsigned len, nlen;
    s->bitbuf = 0; s->bitcnt = 0;                    /* discard to byte boundary */
    if (s->inpos + 4 > s->inlen) return -1;
    len  = (unsigned)s->in[s->inpos] | ((unsigned)s->in[s->inpos + 1] << 8);
    nlen = (unsigned)s->in[s->inpos + 2] | ((unsigned)s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if ((len ^ 0xFFFFu) != nlen) return -1;
    if (s->inpos + len > s->inlen) return -1;
    if (len > s->cap - s->outpos) return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos  += len;
    s->outpos += len;
    return 0;
}

static int inf_fixed(inf_st *s) {
    inf_huff lencode, distcode;
    short lengths[288];
    int i;
    for (i = 0;   i < 144; ++i) lengths[i] = 8;
    for (i = 144; i < 256; ++i) lengths[i] = 9;
    for (i = 256; i < 280; ++i) lengths[i] = 7;
    for (i = 280; i < 288; ++i) lengths[i] = 8;
    inf_construct(&lencode, lengths, 288);
    for (i = 0; i < 30; ++i) lengths[i] = 5;
    inf_construct(&distcode, lengths, 30);
    return inf_codes(s, &lencode, &distcode);
}

static int inf_dynamic(inf_st *s) {
    static const short ORDER[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    inf_huff lencode, distcode;
    short lengths[288 + 30];
    uint32_t v;
    int nlen, ndist, ncode, index, err;

    if (inf_bits(s, 5, &v) != 0) return -1;
    nlen  = (int)v + 257;
    if (inf_bits(s, 5, &v) != 0) return -1;
    ndist = (int)v + 1;
    if (inf_bits(s, 4, &v) != 0) return -1;
    ncode = (int)v + 4;
    if (nlen > 286 || ndist > 30) return -1;

    for (index = 0; index < ncode; ++index) {
        if (inf_bits(s, 3, &v) != 0) return -1;
        lengths[ORDER[index]] = (short)v;
    }
    for (; index < 19; ++index) lengths[ORDER[index]] = 0;
    err = inf_construct(&lencode, lengths, 19);
    if (err != 0) return -1;                         /* must be complete */

    index = 0;
    while (index < nlen + ndist) {
        int symbol, len;
        if (inf_decode(s, &lencode, &symbol) != 0) return -1;
        if (symbol < 16) {
            lengths[index++] = (short)symbol;
        } else {
            len = 0;
            if (symbol == 16) {
                if (index == 0) return -1;
                len = lengths[index - 1];
                if (inf_bits(s, 2, &v) != 0) return -1;
                symbol = 3 + (int)v;
            } else if (symbol == 17) {
                if (inf_bits(s, 3, &v) != 0) return -1;
                symbol = 3 + (int)v;
            } else {
                if (inf_bits(s, 7, &v) != 0) return -1;
                symbol = 11 + (int)v;
            }
            if (index + symbol > nlen + ndist) return -1;
            while (symbol--) lengths[index++] = (short)len;
        }
    }
    if (lengths[256] == 0) return -1;                /* no end-of-block code */

    err = inf_construct(&lencode, lengths, nlen);
    if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1])) return -1;
    err = inf_construct(&distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1])) return -1;

    return inf_codes(s, &lencode, &distcode);
}

static uint32_t inf_adler32(const uint8_t *d, size_t n) {
    uint32_t a = 1, b = 0;
    size_t i;
    for (i = 0; i < n; ++i) {
        a = (a + d[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

int dsso_inflate(dsso_slice in, uint8_t *out, size_t cap, size_t *outlen) {
    inf_st s;
    uint32_t v, want;
    unsigned cmf, flg;
    int last;

    if (!out || !outlen) return DSSO_E_ARG;
    if (in.n && !in.p) return DSSO_E_ARG;
    if (in.n < 2 + 4) return DSSO_E_FORMAT;           /* zlib header + Adler-32 */
    if (in.n > DSSO_MAX_TOKEN) return DSSO_E_FORMAT;

    cmf = in.p[0]; flg = in.p[1];
    if ((cmf & 0x0Fu) != 8u) return DSSO_E_FORMAT;    /* not DEFLATE */
    if ((cmf >> 4) > 7u) return DSSO_E_FORMAT;        /* window > 32 KiB */
    if (((cmf << 8) | flg) % 31u != 0u) return DSSO_E_FORMAT;
    if (flg & 0x20u) return DSSO_E_FORMAT;            /* preset dictionary */

    memset(&s, 0, sizeof s);
    s.in = in.p + 2; s.inlen = in.n - 2;
    s.out = out; s.cap = cap;

    do {
        int type, rc;
        if (inf_bits(&s, 1, &v) != 0) return DSSO_E_FORMAT;
        last = (int)v;
        if (inf_bits(&s, 2, &v) != 0) return DSSO_E_FORMAT;
        type = (int)v;
        if      (type == 0) rc = inf_stored(&s);
        else if (type == 1) rc = inf_fixed(&s);
        else if (type == 2) rc = inf_dynamic(&s);
        else return DSSO_E_FORMAT;                    /* reserved block type */
        if (rc != 0) return DSSO_E_FORMAT;
    } while (!last);

    s.bitbuf = 0; s.bitcnt = 0;                       /* to the byte boundary */
    if (s.inlen - s.inpos != 4) return DSSO_E_FORMAT; /* missing or trailing data */
    want = ((uint32_t)s.in[s.inpos] << 24) | ((uint32_t)s.in[s.inpos + 1] << 16)
         | ((uint32_t)s.in[s.inpos + 2] << 8) | (uint32_t)s.in[s.inpos + 3];
    if (inf_adler32(out, s.outpos) != want) return DSSO_E_FORMAT;

    *outlen = s.outpos;
    return DSSO_OK;
}
