/* DSSO relying-party assertion — see assertion.h for the construction, the key
 * custody, and why the RP compares against an IdP-delivered reference instead of
 * against bytes the presenter chose. */
#include "assertion.h"

#include <determ/crypto/sha2/sha2.h>
#include <string.h>

/* ── Domain separation ────────────────────────────────────────────────────────
 * Three disjoint tags, each length-prefixed into its message like every other
 * field, so no encoding of one leg can ever be read as an encoding of another. */
static const char DS_CLAIM[]  = "determ-dsso/assert/claim/v1";
static const char DS_BINDER[] = "determ-dsso/assert/binder/v1";
static const char DS_TAG[]    = "determ-dsso/assert/tag/v1";
static const char DS_SUB[]    = "determ-dsso/assert/pairwise-sub/v1";

/* ── Bounded writer ───────────────────────────────────────────────────────────
 * Every append checks the remaining capacity first; on overflow the writer is
 * poisoned (`ok = 0`) and stays poisoned, so a caller only has to test once at
 * the end. No allocation anywhere. */
typedef struct { uint8_t *p; size_t cap, n; int ok; } wr;

static void wr_bytes(wr *w, const uint8_t *b, size_t n) {
    if (!w->ok) return;
    if (n > w->cap - w->n) { w->ok = 0; return; }
    if (n != 0) memcpy(w->p + w->n, b, n);
    w->n += n;
}

static void wr_u64(wr *w, uint64_t v) {
    uint8_t b[8];
    int i;
    for (i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (8 * (7 - i)));
    wr_bytes(w, b, 8);
}

/* Length-prefixed field: u64be(len) | bytes. Prefixing EVERY variable-length
 * field is what makes the encoding unambiguous — no two distinct claims can
 * share a canonical encoding, which is the property the accept rule rests on. */
static void wr_lp(wr *w, const uint8_t *b, size_t n) {
    wr_u64(w, (uint64_t)n);
    wr_bytes(w, b, n);
}

static void wr_lp_str(wr *w, const char *s) {
    wr_lp(w, (const uint8_t *)s, strlen(s));
}

/* ── canon(claim) ─────────────────────────────────────────────────────────────
 * The exact bytes both legs commit to. Fixed field order, every variable field
 * length-prefixed, the whole thing prefixed by its domain tag. Bounded by
 * DSSO_ASSERT_MAX_CANON; an input that would exceed it is a rejection, never a
 * truncation. */
static dsso_status canon_claim(const dsso_claim *c,
                               uint8_t out[DSSO_ASSERT_MAX_CANON], size_t *out_len) {
    wr w;
    if (c == NULL || out == NULL || out_len == NULL) return DSSO_E_ARG;
    if (c->iss_len > DSSO_ASSERT_MAX_ID ||
        c->aud_len > DSSO_ASSERT_MAX_ID ||
        c->sid_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;

    w.p = out; w.cap = DSSO_ASSERT_MAX_CANON; w.n = 0; w.ok = 1;
    wr_lp_str(&w, DS_CLAIM);
    wr_lp(&w, c->iss, c->iss_len);
    wr_lp(&w, c->sub, DSSO_ASSERT_SUB_LEN);
    wr_lp(&w, c->aud, c->aud_len);
    wr_lp(&w, c->sid, c->sid_len);
    wr_bytes(&w, c->nonce, DSSO_ASSERT_NONCE_LEN);
    wr_u64(&w, c->iat);
    wr_u64(&w, c->exp);
    wr_u64(&w, c->reg_epoch);
    wr_u64(&w, c->key_epoch);
    if (!w.ok) return DSSO_E_ARG;
    *out_len = w.n;
    return DSSO_OK;
}

/* binder = HMAC(sso_key, LP(DS_BINDER) | canon(claim)).
 * The inner leg of the paper's dual hash. Only a party that completed the login
 * holds `sso_key`, so only such a party can produce this value for a given
 * claim — that is the dependence the RP's accept rule ultimately rests on. */
static dsso_status derive_binder(const uint8_t sso_key[DSSO_ASSERT_KEY_LEN],
                                 const uint8_t *canon, size_t canon_len,
                                 uint8_t out[DSSO_ASSERT_BINDER_LEN]) {
    uint8_t msg[DSSO_ASSERT_MAX_CANON + 64];
    wr w;
    w.p = msg; w.cap = sizeof msg; w.n = 0; w.ok = 1;
    wr_lp_str(&w, DS_BINDER);
    wr_bytes(&w, canon, canon_len);
    if (!w.ok) return DSSO_E_ARG;
    if (determ_hmac_sha256(sso_key, DSSO_ASSERT_KEY_LEN, msg, w.n, out) != 0)
        return DSSO_E_CRYPTO;
    return DSSO_OK;
}

/* tag = HMAC(tenant_key, LP(DS_TAG) | canon(claim) | binder).
 * The outer leg. Note canon(claim) is INSIDE the message: that is what makes the
 * value the RP checks commit to every field it will act on. MAC'ing the binder
 * alone — the rule C6 records — commits to nothing the RP reads. */
static dsso_status derive_tag(const uint8_t tenant_key[DSSO_ASSERT_KEY_LEN],
                              const uint8_t *canon, size_t canon_len,
                              const uint8_t binder[DSSO_ASSERT_BINDER_LEN],
                              uint8_t out[DSSO_ASSERT_TAG_LEN]) {
    uint8_t msg[DSSO_ASSERT_MAX_CANON + 64 + DSSO_ASSERT_BINDER_LEN];
    wr w;
    w.p = msg; w.cap = sizeof msg; w.n = 0; w.ok = 1;
    wr_lp_str(&w, DS_TAG);
    wr_bytes(&w, canon, canon_len);
    wr_bytes(&w, binder, DSSO_ASSERT_BINDER_LEN);
    if (!w.ok) return DSSO_E_ARG;
    if (determ_hmac_sha256(tenant_key, DSSO_ASSERT_KEY_LEN, msg, w.n, out) != 0)
        return DSSO_E_CRYPTO;
    return DSSO_OK;
}

dsso_status dsso_assert_binder(const uint8_t sso_key[DSSO_ASSERT_KEY_LEN],
                               const dsso_claim *claim,
                               uint8_t out_binder[DSSO_ASSERT_BINDER_LEN]) {
    uint8_t canon[DSSO_ASSERT_MAX_CANON], binder[DSSO_ASSERT_BINDER_LEN];
    size_t canon_len = 0;
    dsso_status st;
    if (sso_key == NULL || claim == NULL || out_binder == NULL) return DSSO_E_ARG;
    st = canon_claim(claim, canon, &canon_len);
    if (st != DSSO_OK) return st;
    st = derive_binder(sso_key, canon, canon_len, binder);
    if (st != DSSO_OK) return st;
    memcpy(out_binder, binder, DSSO_ASSERT_BINDER_LEN);
    return DSSO_OK;
}

/* Saturating add — a retention deadline must never wrap into the past. */
static uint64_t sat_add(uint64_t a, uint64_t b) {
    return (a > (uint64_t)-1 - b) ? (uint64_t)-1 : a + b;
}

/* ── Pairwise subject ─────────────────────────────────────────────────────── */

dsso_status dsso_pairwise_subject(const uint8_t user_root[DSSO_ASSERT_KEY_LEN],
                                  const uint8_t *rp_id, size_t rp_id_len,
                                  uint64_t reg_epoch,
                                  uint8_t out_sub[DSSO_ASSERT_SUB_LEN]) {
    uint8_t msg[DSSO_ASSERT_MAX_ID + 96];
    uint8_t sub[DSSO_ASSERT_SUB_LEN];
    wr w;
    if (user_root == NULL || out_sub == NULL) return DSSO_E_ARG;
    if (rp_id == NULL && rp_id_len != 0) return DSSO_E_ARG;
    if (rp_id_len == 0 || rp_id_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;

    w.p = msg; w.cap = sizeof msg; w.n = 0; w.ok = 1;
    wr_lp_str(&w, DS_SUB);
    wr_lp(&w, rp_id, rp_id_len);
    wr_u64(&w, reg_epoch);
    if (!w.ok) return DSSO_E_ARG;
    if (determ_hmac_sha256(user_root, DSSO_ASSERT_KEY_LEN, msg, w.n, sub) != 0)
        return DSSO_E_CRYPTO;
    memcpy(out_sub, sub, DSSO_ASSERT_SUB_LEN);
    return DSSO_OK;
}

/* ── IdP side ─────────────────────────────────────────────────────────────── */

dsso_status dsso_idp_init(dsso_idp *idp) {
    if (idp == NULL) return DSSO_E_ARG;
    memset(idp, 0, sizeof *idp);
    return DSSO_OK;
}

static int binding_valid(const dsso_rp_binding *b) {
    return b != NULL && b->rp_id_len != 0 && b->rp_id_len <= DSSO_ASSERT_MAX_ID;
}

dsso_status dsso_idp_register_rp(dsso_idp *idp, const dsso_rp_binding *b) {
    size_t i;
    if (idp == NULL || !binding_valid(b)) return DSSO_E_ARG;
    for (i = 0; i < idp->rp_count; ++i) {   /* re-registration / rotation */
        if (idp->rp[i].rp_id_len == b->rp_id_len &&
            memcmp(idp->rp[i].rp_id, b->rp_id, b->rp_id_len) == 0) {
            idp->rp[i] = *b;
            return DSSO_OK;
        }
    }
    if (idp->rp_count >= DSSO_ASSERT_MAX_RPS) return DSSO_E_UNAVAILABLE;
    idp->rp[idp->rp_count++] = *b;
    return DSSO_OK;
}

static const dsso_rp_binding *idp_lookup(const dsso_idp *idp,
                                         const uint8_t *rp_id, size_t rp_id_len) {
    size_t i;
    for (i = 0; i < idp->rp_count; ++i) {
        if (idp->rp[i].rp_id_len == rp_id_len &&
            memcmp(idp->rp[i].rp_id, rp_id, rp_id_len) == 0) return &idp->rp[i];
    }
    return NULL;
}

dsso_status dsso_assert_issue(const dsso_idp *idp,
                              const uint8_t sso_key[DSSO_ASSERT_KEY_LEN],
                              const uint8_t user_root[DSSO_ASSERT_KEY_LEN],
                              const dsso_assert_request *req,
                              dsso_assertion *out,
                              uint8_t out_tag[DSSO_ASSERT_TAG_LEN]) {
    const dsso_rp_binding *rp;
    const uint8_t *aud;
    size_t aud_len, canon_len = 0;
    uint8_t canon[DSSO_ASSERT_MAX_CANON];
    uint8_t binder[DSSO_ASSERT_BINDER_LEN], tag[DSSO_ASSERT_TAG_LEN];
    dsso_claim c;
    dsso_status st;

    if (idp == NULL || sso_key == NULL || user_root == NULL ||
        req == NULL || out == NULL || out_tag == NULL) return DSSO_E_ARG;
    if (req->rp_id == NULL || req->rp_id_len == 0 ||
        req->rp_id_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (req->iss == NULL || req->iss_len == 0 ||
        req->iss_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (req->sid == NULL || req->sid_len == 0 ||
        req->sid_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (req->aud != NULL && req->aud_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (req->aud == NULL && req->aud_len != 0) return DSSO_E_ARG;
    if (req->exp <= req->iat) return DSSO_E_ARG;

    /* An unknown relying party is rejected here, at the layer that owns the
     * registry. The IdP cannot assert to someone it never registered. */
    rp = idp_lookup(idp, req->rp_id, req->rp_id_len);
    if (rp == NULL) return DSSO_E_TRUST;

    aud     = (req->aud_len != 0) ? req->aud     : req->rp_id;
    aud_len = (req->aud_len != 0) ? req->aud_len : req->rp_id_len;

    memset(&c, 0, sizeof c);
    memcpy(c.iss, req->iss, req->iss_len); c.iss_len = req->iss_len;
    memcpy(c.aud, aud, aud_len);           c.aud_len = aud_len;
    memcpy(c.sid, req->sid, req->sid_len); c.sid_len = req->sid_len;
    memcpy(c.nonce, req->nonce, DSSO_ASSERT_NONCE_LEN);
    c.iat = req->iat; c.exp = req->exp;
    c.reg_epoch = rp->reg_epoch; c.key_epoch = rp->key_epoch;

    /* The subject is DERIVED, never accepted from the caller: the IdP cannot be
     * asked to assert an arbitrary identifier, and the result is pairwise. */
    st = dsso_pairwise_subject(user_root, rp->rp_id, rp->rp_id_len,
                               rp->reg_epoch, c.sub);
    if (st != DSSO_OK) return st;

    st = canon_claim(&c, canon, &canon_len);
    if (st != DSSO_OK) return st;
    st = derive_binder(sso_key, canon, canon_len, binder);
    if (st != DSSO_OK) return st;
    st = derive_tag(rp->tenant_key, canon, canon_len, binder, tag);
    if (st != DSSO_OK) return st;

    out->claim = c;
    memcpy(out->binder, binder, DSSO_ASSERT_BINDER_LEN);
    memcpy(out_tag, tag, DSSO_ASSERT_TAG_LEN);
    return DSSO_OK;
}

/* ── RP side ──────────────────────────────────────────────────────────────── */

dsso_status dsso_rp_init(dsso_rp_verifier *v, const dsso_rp_binding *b,
                         uint64_t skew_s, uint64_t max_lifetime_s) {
    if (v == NULL || !binding_valid(b)) return DSSO_E_ARG;
    memset(v, 0, sizeof *v);
    v->self = *b;
    v->skew_s         = (skew_s         != 0) ? skew_s         : DSSO_ASSERT_DEFAULT_SKEW_S;
    v->max_lifetime_s = (max_lifetime_s != 0) ? max_lifetime_s : DSSO_ASSERT_DEFAULT_MAX_LIFETIME_S;
    return DSSO_OK;
}

/* Retention for both tables: the full bounded lifetime plus skew, measured from
 * the claim's own `iat`. For any claim that passes the clock legs this is at
 * least `exp + skew`, so an entry is dropped only once the clock alone already
 * rejects every token that could carry it. */
static uint64_t retention_deadline(const dsso_rp_verifier *v, uint64_t iat) {
    return sat_add(sat_add(iat, v->max_lifetime_s), v->skew_s);
}

dsso_status dsso_rp_deliver(dsso_rp_verifier *v,
                            const uint8_t tag[DSSO_ASSERT_TAG_LEN],
                            uint64_t claim_iat, uint64_t now) {
    size_t i, slot = (size_t)-1;
    if (v == NULL || tag == NULL) return DSSO_E_ARG;
    if (now == 0) return DSSO_E_UNAVAILABLE;      /* no usable clock: fail closed */

    for (i = 0; i < DSSO_ASSERT_REF_SLOTS; ++i) {
        if (v->ref[i].used && v->ref[i].expires_at > now &&
            dsso_ct_equal(v->ref[i].tag, tag, DSSO_ASSERT_TAG_LEN))
            return DSSO_E_REPLAY;                 /* already delivered           */
    }
    /* An empty slot first, else one whose retention has elapsed. A LIVE slot is
     * never taken: dropping a reference the IdP issued and the user has not yet
     * presented would silently void a legitimate login. */
    for (i = 0; i < DSSO_ASSERT_REF_SLOTS; ++i) {
        if (!v->ref[i].used) { slot = i; break; }
    }
    if (slot == (size_t)-1) {
        for (i = 0; i < DSSO_ASSERT_REF_SLOTS; ++i) {
            if (v->ref[i].expires_at <= now) { slot = i; break; }
        }
    }
    if (slot == (size_t)-1) return DSSO_E_UNAVAILABLE;

    memcpy(v->ref[slot].tag, tag, DSSO_ASSERT_TAG_LEN);
    v->ref[slot].expires_at = retention_deadline(v, claim_iat);
    v->ref[slot].used = 1;
    return DSSO_OK;
}

dsso_status dsso_rp_verify(dsso_rp_verifier *v, const dsso_assertion *a,
                           uint64_t now,
                           const uint8_t *expected_sid, size_t expected_sid_len,
                           uint8_t out_sub[DSSO_ASSERT_SUB_LEN]) {
    uint8_t canon[DSSO_ASSERT_MAX_CANON];
    uint8_t tag[DSSO_ASSERT_TAG_LEN];
    size_t canon_len = 0, i, slot = (size_t)-1;
    int matched = 0;
    uint64_t lifetime;
    dsso_status st;

    if (v == NULL || a == NULL || out_sub == NULL) return DSSO_E_ARG;
    if (expected_sid == NULL || expected_sid_len == 0 ||
        expected_sid_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (a->claim.iss_len == 0 || a->claim.iss_len > DSSO_ASSERT_MAX_ID ||
        a->claim.aud_len == 0 || a->claim.aud_len > DSSO_ASSERT_MAX_ID ||
        a->claim.sid_len == 0 || a->claim.sid_len > DSSO_ASSERT_MAX_ID) return DSSO_E_ARG;
    if (a->claim.exp <= a->claim.iat) return DSSO_E_ARG;
    if (now == 0) return DSSO_E_UNAVAILABLE;      /* no usable clock: fail closed */

    /* The only field read before the MAC is checked: the epochs select WHICH key
     * the verifier is entitled to verify under, so they are necessarily prior to
     * it. A rotated-out key or a previous registration is not this RP. */
    if (a->claim.key_epoch != v->self.key_epoch ||
        a->claim.reg_epoch != v->self.reg_epoch) return DSSO_E_TRUST;

    st = canon_claim(&a->claim, canon, &canon_len);
    if (st != DSSO_OK) return st;
    st = derive_tag(v->self.tenant_key, canon, canon_len, a->binder, tag);
    if (st != DSSO_OK) return st;

    /* THE ACCEPT RULE. The recomputed tag must be one the IdP delivered. The
     * presenter supplies no tag, so there is nothing presenter-chosen here for a
     * tenant_key holder to aim at: it would have to hit a value the IdP already
     * emitted, whose binder needs the login's sso_key. Constant-time compare
     * over the FULL tag — a truncated or early-exit compare is a forgery
     * oracle. The scan does not break early, so its cost does not reveal which
     * slot matched. */
    for (i = 0; i < DSSO_ASSERT_REF_SLOTS; ++i) {
        if (v->ref[i].used && v->ref[i].expires_at > now &&
            dsso_ct_equal(v->ref[i].tag, tag, DSSO_ASSERT_TAG_LEN)) matched = 1;
    }
    if (!matched) return DSSO_E_CRYPTO;

    /* A matched reference is NOT consumed. Single use is a property of the
     * claim's `nonce` and is enforced in exactly one place below; the reference
     * table is a retention cache of what the IdP issued, with the same lifetime
     * discipline. Consuming here as well would make a benign re-delivery or a
     * retried presentation indistinguishable from a replay, and would split the
     * single-use rule across two tables. */

    /* The session this verifier is completing. Binding `sid` into the MAC keeps
     * the IdP's statement about it honest; comparing it here is what stops a
     * party who influenced which `sid` was asserted from fixating someone else's
     * session with a token that is perfectly valid for its own. */
    if (a->claim.sid_len != expected_sid_len ||
        !dsso_ct_equal(a->claim.sid, expected_sid, expected_sid_len))
        return DSSO_E_BINDING;

    /* From here the claim is authenticated, so its fields may be read. Three
     * clock legs, all fail-closed, all against the RP's own policy and never the
     * issuer's: a claim dated into the future beyond the tolerated skew, a claim
     * whose window has closed, and a claim whose window is longer than this RP
     * accepts (which is what stops an issuer — or a clock slip — from minting a
     * long-lived bearer credential out of one login). */
    if (a->claim.iat > sat_add(now, v->skew_s)) return DSSO_E_EXPIRED;  /* not yet valid */
    if (a->claim.exp <= now) return DSSO_E_EXPIRED;                     /* expired       */
    lifetime = a->claim.exp - a->claim.iat;                             /* exp > iat, checked */
    if (lifetime > v->max_lifetime_s) return DSSO_E_EXPIRED;            /* over-long     */

    /* Single use. A nonce already held and still inside its retention window is
     * a replay — including a replay that arrives after some OTHER entry was
     * evicted, because eviction only ever takes expired slots. */
    for (i = 0; i < DSSO_ASSERT_NONCE_SLOTS; ++i) {
        if (v->nonce[i].used && v->nonce[i].expires_at > now &&
            dsso_ct_equal(v->nonce[i].nonce, a->claim.nonce, DSSO_ASSERT_NONCE_LEN))
            return DSSO_E_REPLAY;
    }
    for (i = 0; i < DSSO_ASSERT_NONCE_SLOTS; ++i) {
        if (!v->nonce[i].used) { slot = i; break; }
    }
    if (slot == (size_t)-1) {
        for (i = 0; i < DSSO_ASSERT_NONCE_SLOTS; ++i) {
            if (v->nonce[i].expires_at <= now) { slot = i; break; }
        }
    }
    /* Every slot live: REJECT. Accepting while unable to remember is accepting a
     * replay, so the cache being full is a fail-closed condition, not a licence
     * to forget. */
    if (slot == (size_t)-1) return DSSO_E_UNAVAILABLE;

    memcpy(v->nonce[slot].nonce, a->claim.nonce, DSSO_ASSERT_NONCE_LEN);
    v->nonce[slot].expires_at = retention_deadline(v, a->claim.iat);
    v->nonce[slot].used = 1;

    memcpy(out_sub, a->claim.sub, DSSO_ASSERT_SUB_LEN);
    return DSSO_OK;
}

size_t dsso_rp_nonce_live(const dsso_rp_verifier *v, uint64_t now) {
    size_t i, n = 0;
    if (v == NULL) return 0;
    for (i = 0; i < DSSO_ASSERT_NONCE_SLOTS; ++i)
        if (v->nonce[i].used && v->nonce[i].expires_at > now) ++n;
    return n;
}

size_t dsso_rp_ref_live(const dsso_rp_verifier *v, uint64_t now) {
    size_t i, n = 0;
    if (v == NULL) return 0;
    for (i = 0; i < DSSO_ASSERT_REF_SLOTS; ++i)
        if (v->ref[i].used && v->ref[i].expires_at > now) ++n;
    return n;
}
