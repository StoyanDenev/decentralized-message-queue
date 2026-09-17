/* dsso_bind — account binding rules. See dsso_bind.h for the three failure
 * shapes this module exists to make impossible, and for the pseudonym rationale. */
#include "dsso_bind.h"

#include <string.h>

#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/secure_zero.h"

#define PSEU_LABEL   "DSSO-PID-PSEUDONYM-v1"
#define REAUTH_LABEL "DSSO-ACCT-REAUTH-v1"

int dsso_pseudonym_derive(const uint8_t key[32],
                          const uint8_t *material, size_t material_len,
                          uint8_t out[32]) {
    uint8_t buf[sizeof PSEU_LABEL - 1 + 320];
    size_t label = sizeof PSEU_LABEL - 1;
    if (!key || !out || (material_len && !material)) return DSSO_E_ARG;
    if (material_len > sizeof buf - label) return DSSO_E_ARG;
    memcpy(buf, PSEU_LABEL, label);
    memcpy(buf + label, material, material_len);
    if (determ_hmac_sha256(key, 32, buf, label + material_len, out) != 0) {
        determ_secure_zero(buf, sizeof buf);
        return DSSO_E_CRYPTO;
    }
    determ_secure_zero(buf, sizeof buf);
    return DSSO_OK;
}

static dsso_bind_account *find_account(dsso_bind_ctx *c, const uint8_t id[32]) {
    size_t i;
    for (i = 0; i < DSSO_BIND_MAX_ACCOUNTS; ++i)
        if (c->accounts[i].in_use &&
            dsso_ct_equal(c->accounts[i].account_id, id, DSSO_BIND_ID_LEN))
            return &c->accounts[i];
    return NULL;
}

/* (i) A SESSION IS NOT AUTHORISATION.
 *
 * This is the check that makes "possession of a DSSO session alone cannot
 * authorise binding another person's identity" true. It is deliberately a
 * positive test on a proof the account holder produced — kind == FRESH, inside
 * the re-auth window, MAC under the ACCOUNT'S OWN key — and not a negative test
 * on some "is this a session?" flag, because a negative test degrades to
 * "allowed" the moment a caller forgets to set the flag. */
static int auth_ok(const dsso_bind_ctx *c, const dsso_bind_account *a,
                   const dsso_account_auth *auth, int64_t now) {
    uint8_t msg[sizeof REAUTH_LABEL - 1 + DSSO_BIND_ID_LEN + 8];
    uint8_t mac[32];
    size_t label = sizeof REAUTH_LABEL - 1, o = 0;
    int i, eq;
    uint64_t at;

    if (!auth) return DSSO_E_BINDING;
    if (auth->kind != DSSO_AUTH_FRESH) return DSSO_E_BINDING;
    if (auth->at > now) return DSSO_E_BINDING;                 /* future-dated */
    if (now - auth->at > c->reauth_max_age) return DSSO_E_EXPIRED;

    memcpy(msg, REAUTH_LABEL, label); o = label;
    memcpy(msg + o, a->account_id, DSSO_BIND_ID_LEN); o += DSSO_BIND_ID_LEN;
    at = (uint64_t)auth->at;
    for (i = 7; i >= 0; --i) msg[o++] = (uint8_t)((at >> (8 * i)) & 0xFFu);

    if (determ_hmac_sha256(a->auth_key, 32, msg, o, mac) != 0) return DSSO_E_CRYPTO;
    eq = dsso_ct_equal(mac, auth->mac, 32);
    determ_secure_zero(mac, sizeof mac);
    return eq ? DSSO_OK : DSSO_E_BINDING;
}

int dsso_bind_init(dsso_bind_ctx *c, const uint8_t pseudonym_key[32],
                   int64_t challenge_ttl, int64_t reauth_max_age) {
    if (!c || !pseudonym_key) return DSSO_E_ARG;
    if (challenge_ttl <= 0 || reauth_max_age <= 0) return DSSO_E_ARG;
    memset(c, 0, sizeof *c);
    memcpy(c->pseudonym_key, pseudonym_key, 32);
    c->challenge_ttl  = challenge_ttl;
    c->reauth_max_age = reauth_max_age;
    return DSSO_OK;
}

int dsso_bind_account_add(dsso_bind_ctx *c,
                          const uint8_t account_id[DSSO_BIND_ID_LEN],
                          const uint8_t auth_key[32]) {
    size_t i;
    if (!c || !account_id || !auth_key) return DSSO_E_ARG;
    if (find_account(c, account_id)) return DSSO_E_ARG;
    for (i = 0; i < DSSO_BIND_MAX_ACCOUNTS; ++i) {
        if (c->accounts[i].in_use) continue;
        memset(&c->accounts[i], 0, sizeof c->accounts[i]);
        memcpy(c->accounts[i].account_id, account_id, DSSO_BIND_ID_LEN);
        memcpy(c->accounts[i].auth_key, auth_key, 32);
        c->accounts[i].in_use = 1;
        return DSSO_OK;
    }
    return DSSO_E_ARG;
}

int dsso_bind_challenge_new(dsso_bind_ctx *c,
                            const uint8_t account_id[DSSO_BIND_ID_LEN],
                            const dsso_account_auth *auth,
                            dsso_bind_purpose purpose,
                            const uint8_t nonce[DSSO_BIND_NONCE_LEN],
                            int64_t now) {
    dsso_bind_account *a;
    size_t i;
    int rc;

    if (!c || !account_id || !nonce) return DSSO_E_ARG;
    if (purpose != DSSO_BIND_PURPOSE_BIND && purpose != DSSO_BIND_PURPOSE_UNBIND)
        return DSSO_E_ARG;
    a = find_account(c, account_id);
    if (!a) return DSSO_E_BINDING;

    rc = auth_ok(c, a, auth, now);
    if (rc != DSSO_OK) return rc;

    /* The nonce is the request binding the presentation must answer, so it has
     * to be transportable as a JSON string: enforce the base64url alphabet
     * rather than trusting the caller's CSPRNG plumbing. */
    for (i = 0; i < DSSO_BIND_NONCE_LEN; ++i) {
        uint8_t ch = nonce[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') continue;
        return DSSO_E_ARG;
    }

    /* A new challenge invalidates the previous one for this account. */
    memcpy(a->ch_nonce, nonce, DSSO_BIND_NONCE_LEN);
    a->ch_purpose   = purpose;
    a->ch_issued_at = now;
    a->ch_open      = 1;
    return DSSO_OK;
}

static dsso_binding_record *active_of_account(dsso_bind_ctx *c, const uint8_t id[32]) {
    size_t i;
    for (i = 0; i < DSSO_BIND_MAX_BINDINGS; ++i)
        if (c->bindings[i].in_use && c->bindings[i].active &&
            dsso_ct_equal(c->bindings[i].account_id, id, DSSO_BIND_ID_LEN))
            return &c->bindings[i];
    return NULL;
}

static dsso_binding_record *active_of_pseudonym(dsso_bind_ctx *c, const uint8_t p[32]) {
    size_t i;
    for (i = 0; i < DSSO_BIND_MAX_BINDINGS; ++i)
        if (c->bindings[i].in_use && c->bindings[i].active &&
            dsso_ct_equal(c->bindings[i].pseudonym, p, 32))
            return &c->bindings[i];
    return NULL;
}

int dsso_bind_commit(dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     dsso_slice presentation,
                     const dsso_pid_policy *base_pol,
                     int64_t now,
                     uint8_t pseudonym_out[32]) {
    dsso_bind_account *a;
    dsso_pid_policy    pol;
    dsso_pid_result    res;
    dsso_binding_record *rec, *other;
    uint8_t material[320], pseu[32];
    size_t  material_len = 0, i;
    int rc;

    if (!c || !account_id || !base_pol) return DSSO_E_ARG;
    a = find_account(c, account_id);
    if (!a) return DSSO_E_BINDING;

    /* (iii) NO REUSE — the challenge must be open, for THIS purpose, and fresh. */
    if (!a->ch_open || a->ch_purpose != DSSO_BIND_PURPOSE_BIND)
        return DSSO_E_REPLAY;
    if (now - a->ch_issued_at > c->challenge_ttl) {
        a->ch_open = 0;
        return DSSO_E_EXPIRED;
    }

    /* The nonce comes from the account's own challenge record. A caller cannot
     * verify against one challenge and commit against another. */
    pol           = *base_pol;
    pol.nonce     = a->ch_nonce;
    pol.nonce_len = DSSO_BIND_NONCE_LEN;
    pol.now       = now;

    /* Consumed the moment a presentation is offered against it, pass or fail:
     * a single-use challenge with a retry oracle is not single-use. */
    a->ch_open = 0;

    rc = dsso_pid_verify(presentation, &pol, &res);
    if (rc != DSSO_OK) { dsso_pid_result_scrub(&res); return rc; }

    rc = dsso_pid_subject_material(&res, material, sizeof material, &material_len);
    if (rc != DSSO_OK) { dsso_pid_result_scrub(&res); return rc; }
    rc = dsso_pseudonym_derive(c->pseudonym_key, material, material_len, pseu);
    /* ARF OIA_16: the raw national identifier was needed for exactly one HMAC
     * and is gone before anything else can touch it. */
    determ_secure_zero(material, sizeof material);
    if (rc != DSSO_OK) { dsso_pid_result_scrub(&res); return rc; }

    /* (ii) ONE SUBJECT, ONE ACCOUNT, AND NO SILENT SWAPS. */
    other = active_of_pseudonym(c, pseu);
    if (other && !dsso_ct_equal(other->account_id, account_id, DSSO_BIND_ID_LEN)) {
        dsso_pid_result_scrub(&res);
        determ_secure_zero(pseu, sizeof pseu);
        return DSSO_E_BINDING;                 /* subject already bound elsewhere */
    }
    rec = active_of_account(c, account_id);
    if (rec) {
        if (!dsso_ct_equal(rec->pseudonym, pseu, 32)) {
            dsso_pid_result_scrub(&res);
            determ_secure_zero(pseu, sizeof pseu);
            return DSSO_E_BINDING;             /* re-bind needs an explicit unbind */
        }
        /* Same subject, same account: a re-affirmation, not a second binding. */
        rec->bound_at = now;
        rec->loa      = res.loa;
        if (pseudonym_out) memcpy(pseudonym_out, pseu, 32);
        dsso_pid_result_scrub(&res);
        determ_secure_zero(pseu, sizeof pseu);
        return DSSO_OK;
    }

    for (i = 0; i < DSSO_BIND_MAX_BINDINGS; ++i) {
        if (c->bindings[i].in_use) continue;
        memset(&c->bindings[i], 0, sizeof c->bindings[i]);
        memcpy(c->bindings[i].account_id, account_id, DSSO_BIND_ID_LEN);
        memcpy(c->bindings[i].pseudonym, pseu, 32);
        if (res.iss_len <= sizeof c->bindings[i].iss) {
            memcpy(c->bindings[i].iss, res.iss, res.iss_len);
            c->bindings[i].iss_len = res.iss_len;
        }
        c->bindings[i].loa      = res.loa;
        c->bindings[i].bound_at = now;
        c->bindings[i].active   = 1;
        c->bindings[i].in_use   = 1;
        if (pseudonym_out) memcpy(pseudonym_out, pseu, 32);
        dsso_pid_result_scrub(&res);
        determ_secure_zero(pseu, sizeof pseu);
        return DSSO_OK;
    }
    dsso_pid_result_scrub(&res);
    determ_secure_zero(pseu, sizeof pseu);
    return DSSO_E_ARG;                          /* binding table full */
}

int dsso_bind_unbind(dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     const dsso_account_auth *auth,
                     int64_t now) {
    dsso_bind_account   *a;
    dsso_binding_record *rec;
    int rc;

    if (!c || !account_id) return DSSO_E_ARG;
    a = find_account(c, account_id);
    if (!a) return DSSO_E_BINDING;

    /* An unbind is as consequential as a bind — it is what makes re-binding
     * possible — so it takes the same fresh account authentication. */
    rc = auth_ok(c, a, auth, now);
    if (rc != DSSO_OK) return rc;

    rec = active_of_account(c, account_id);
    if (!rec) return DSSO_E_BINDING;
    rec->active = 0;
    determ_secure_zero(rec->pseudonym, sizeof rec->pseudonym);
    return DSSO_OK;
}

int dsso_bind_lookup(const dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     uint8_t pseudonym_out[32]) {
    size_t i;
    if (!c || !account_id) return DSSO_E_ARG;
    for (i = 0; i < DSSO_BIND_MAX_BINDINGS; ++i) {
        if (!c->bindings[i].in_use || !c->bindings[i].active) continue;
        if (!dsso_ct_equal(c->bindings[i].account_id, account_id, DSSO_BIND_ID_LEN))
            continue;
        if (pseudonym_out) memcpy(pseudonym_out, c->bindings[i].pseudonym, 32);
        return DSSO_OK;
    }
    return DSSO_E_BINDING;
}
