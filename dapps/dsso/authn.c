/* DSSO user authentication — see authn.h for the problem, the design and the
 * regulatory reading. This file is the mechanism. */
#include "authn.h"

#include <string.h>

#include <determ/crypto/p256/p256.h>    /* base_mul, h2c, oprf_evaluate, voprf_* */
#include <determ/crypto/sha2/sha2.h>    /* determ_sha256(_ctx), determ_hmac_sha256 */
#include <determ/crypto/secure_zero.h>  /* determ_secure_zero                     */

/* Domain separation. Every hash in this module is prefixed by exactly one of
 * these, so no output of one construction can be reinterpreted as another. */
static const char DST_CHAL[]  = "DSSO-authn-v1-challenge";
static const char DST_KNOW[]  = "DSSO-authn-v1-knowledge";
static const char DST_DEVKEY[]= "DSSO-authn-v1-device-key";
static const char DST_PNONCE[]= "DSSO-authn-v1-proof-nonce";
static const char DST_H2C[]   = "DSSO-authn-v1-possession-H2C";
static const char DST_SET[]   = "DSSO-authn-v1-server-set";
static const char DST_SID[]   = "DSSO-authn-v1-session-id";
static const char DST_AUX[]   = "DSSO-authn-v1-aux";

/* RFC 9497 mode byte: 0x01 = VOPRF, the mode whose contextString the DLEQ
 * prove/verify pair is defined over. The possession proof is a DLEQ, so it must
 * use the mode the shipped prover and verifier agree on. */
#define OPRF_MODE_VOPRF 0x01u

static const uint8_t ZERO32[32] = {0};

/* ── small helpers ─────────────────────────────────────────────────────────*/

static void put_u64be(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v >> 56); out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40); out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24); out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >>  8); out[7] = (uint8_t)(v);
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t d = 0; size_t i;
    for (i = 0; i < n; ++i) d |= p[i];
    return d == 0;
}

/* |a - b| <= w, without unsigned wrap. */
static int within(uint64_t a, uint64_t b, uint64_t w) {
    return (a >= b) ? (a - b <= w) : (b - a <= w);
}

static void sha_dst(determ_sha256_ctx *c, const char *dst) {
    uint8_t l = (uint8_t)strlen(dst);
    determ_sha256_init(c);
    determ_sha256_update(c, &l, 1);
    determ_sha256_update(c, (const uint8_t *)dst, l);
}

/* ── device-side primitives ───────────────────────────────────────────────*/

int dsso_authn_device_keygen(uint8_t sk[32], uint8_t pk[DSSO_AUTHN_PK_LEN],
                             const uint8_t seed[32]) {
    uint8_t s[32], pk65[65];
    if (!sk || !pk || !seed) return DSSO_E_ARG;
    /* The secret is a function of the DEVICE'S OWN seed and of nothing else.
     * A derivation that ignored `seed` — for instance one that hashed the
     * password, the OPRF output or the credential envelope — would make this
     * key recomputable by whoever holds that material, and a recomputable key
     * is not a possession factor. The gate pins the dependency directly. */
    if (determ_p256_hash_to_scalar(s, seed, 32, (const uint8_t *)DST_DEVKEY,
                                   strlen(DST_DEVKEY)) != 0) return DSSO_E_CRYPTO;
    if (all_zero(s, 32)) { determ_secure_zero(s, sizeof s); return DSSO_E_CRYPTO; }
    if (determ_p256_base_mul(pk65, s) != 0) {
        determ_secure_zero(s, sizeof s); return DSSO_E_CRYPTO;
    }
    if (determ_p256_point_compress(pk, pk65) != 0) {
        determ_secure_zero(s, sizeof s); return DSSO_E_CRYPTO;
    }
    memcpy(sk, s, 32);
    determ_secure_zero(s, sizeof s);
    return DSSO_OK;
}

int dsso_authn_challenge(uint8_t out[32], uint8_t purpose,
                         const uint8_t account[DSSO_AUTHN_ID_LEN],
                         const uint8_t device[DSSO_AUTHN_ID_LEN],
                         const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                         const uint8_t set_digest[DSSO_AUTHN_ID_LEN],
                         uint64_t timestamp,
                         const uint8_t bind[32], const uint8_t aux[32]) {
    determ_sha256_ctx c;
    uint8_t ts[8];
    const uint8_t ver = 1;
    if (!out || !account || !device || !nonce || !set_digest) return DSSO_E_ARG;
    if (purpose == 0) return DSSO_E_ARG;
    put_u64be(ts, timestamp);
    /* Fixed-width fields in a fixed order, under a length-prefixed DST: the
     * encoding is unambiguous, so two different tuples cannot collide. EVERY
     * field is one the verifier holds independently — the session nonce, the
     * SERVER SET the login is addressed to, the timestamp, the device, and the
     * other factor's response — which is what makes a proof for one session,
     * one server set or one purpose useless for another. */
    sha_dst(&c, DST_CHAL);
    determ_sha256_update(&c, &ver, 1);
    determ_sha256_update(&c, &purpose, 1);
    determ_sha256_update(&c, account, DSSO_AUTHN_ID_LEN);
    determ_sha256_update(&c, device, DSSO_AUTHN_ID_LEN);
    determ_sha256_update(&c, nonce, DSSO_AUTHN_ID_LEN);
    determ_sha256_update(&c, set_digest, DSSO_AUTHN_ID_LEN);
    determ_sha256_update(&c, ts, 8);
    determ_sha256_update(&c, bind ? bind : ZERO32, 32);
    determ_sha256_update(&c, aux  ? aux  : ZERO32, 32);
    determ_sha256_final(&c, out);
    return DSSO_OK;
}

int dsso_authn_knowledge_tag(uint8_t out[32],
                             const uint8_t knowledge_verifier[32],
                             uint8_t purpose,
                             const uint8_t account[DSSO_AUTHN_ID_LEN],
                             const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                             const uint8_t set_digest[DSSO_AUTHN_ID_LEN],
                             uint64_t timestamp, const uint8_t aux[32]) {
    uint8_t msg[1 + 32 + 1 + 1 + 32 + 32 + 32 + 8 + 32];
    size_t off = 0, dl = strlen(DST_KNOW);
    const uint8_t ver = 1;
    if (!out || !knowledge_verifier || !account || !nonce || !set_digest)
        return DSSO_E_ARG;
    if (purpose == 0 || dl > 32) return DSSO_E_ARG;
    msg[off++] = (uint8_t)dl;
    memcpy(msg + off, DST_KNOW, dl); off += dl;
    msg[off++] = ver; msg[off++] = purpose;
    memcpy(msg + off, account, 32);    off += 32;
    memcpy(msg + off, nonce, 32);      off += 32;
    memcpy(msg + off, set_digest, 32); off += 32;
    put_u64be(msg + off, timestamp);   off += 8;
    memcpy(msg + off, aux ? aux : ZERO32, 32); off += 32;
    /* Keyed by the server-side secret the shipped threshold-OPRF + OPAQUE-3DH
     * login co-generates; the length-prefixed DST, the version and the purpose
     * lead the message, so no tag computed here can be replayed as any other
     * construction in this module. */
    if (determ_hmac_sha256(knowledge_verifier, 32, msg, off, out) != 0)
        return DSSO_E_CRYPTO;
    return DSSO_OK;
}

/* H2C(challenge) — the group element the device's answer is taken over. */
static int chal_point(uint8_t blinded33[DSSO_AUTHN_PK_LEN],
                      const uint8_t challenge[32]) {
    uint8_t p65[65];
    if (determ_p256_hash_to_curve(p65, challenge, 32, (const uint8_t *)DST_H2C,
                                  strlen(DST_H2C)) != 0) return DSSO_E_CRYPTO;
    if (determ_p256_point_compress(blinded33, p65) != 0) return DSSO_E_CRYPTO;
    return DSSO_OK;
}

int dsso_authn_possession_sign(dsso_authn_possession *out,
                               const uint8_t sk[32],
                               const uint8_t pk[DSSO_AUTHN_PK_LEN],
                               const uint8_t device[DSSO_AUTHN_ID_LEN],
                               const uint8_t challenge[32]) {
    uint8_t blinded[DSSO_AUTHN_PK_LEN], eval[DSSO_AUTHN_PK_LEN];
    uint8_t r[32], nonce_in[64];
    int rc;
    if (!out || !sk || !pk || !device || !challenge) return DSSO_E_ARG;
    if ((rc = chal_point(blinded, challenge)) != DSSO_OK) return rc;
    if (determ_p256_oprf_evaluate(eval, sk, blinded) != 0) return DSSO_E_CRYPTO;
    /* Deterministic proof nonce (RFC 6979 in spirit): r = HashToScalar(sk ||
     * challenge). Two different challenges give two different nonces, and the
     * same challenge always gives the same proof — which is what lets the gate
     * be byte-reproducible without a CSPRNG. Reusing r across two challenges
     * would leak sk, exactly as in Schnorr/ECDSA; deriving it from both the
     * secret and the challenge makes reuse impossible. */
    memcpy(nonce_in, sk, 32);
    memcpy(nonce_in + 32, challenge, 32);
    rc = determ_p256_hash_to_scalar(r, nonce_in, sizeof nonce_in,
                                    (const uint8_t *)DST_PNONCE, strlen(DST_PNONCE));
    determ_secure_zero(nonce_in, sizeof nonce_in);
    if (rc != 0 || all_zero(r, 32)) { determ_secure_zero(r, sizeof r); return DSSO_E_CRYPTO; }
    rc = determ_p256_voprf_prove(out->proof, sk, pk, blinded, eval, r, OPRF_MODE_VOPRF);
    determ_secure_zero(r, sizeof r);
    if (rc != 0) return DSSO_E_CRYPTO;
    memcpy(out->device, device, DSSO_AUTHN_ID_LEN);
    memcpy(out->eval, eval, DSSO_AUTHN_PK_LEN);
    return DSSO_OK;
}

int dsso_authn_possession_verify(const uint8_t pk[DSSO_AUTHN_PK_LEN],
                                 const dsso_authn_possession *resp,
                                 const uint8_t challenge[32]) {
    uint8_t blinded[DSSO_AUTHN_PK_LEN];
    int rc;
    if (!pk || !resp || !challenge) return DSSO_E_ARG;
    /* The verifier rebuilds the challenge point from ITS OWN challenge bytes;
     * nothing the client sends decides what was signed. */
    if ((rc = chal_point(blinded, challenge)) != DSSO_OK) return rc;
    if (determ_p256_voprf_verify(pk, blinded, resp->eval, resp->proof,
                                 OPRF_MODE_VOPRF) != 0) return DSSO_E_CRYPTO;
    return DSSO_OK;
}

/* ── the aggregate attempt limiter ────────────────────────────────────────*/

static uint64_t win_of(const dsso_authn_cluster *c, uint64_t now) {
    return c->window_secs ? (now / c->window_secs) : 0;
}

int dsso_authn_cluster_init(dsso_authn_cluster *c, uint8_t n, uint8_t t,
                            const uint8_t *ids,
                            uint32_t cap, uint64_t window_secs,
                            uint64_t merge_max_age, uint64_t now) {
    determ_sha256_ctx h;
    uint8_t i;
    if (!c || !ids) return DSSO_E_ARG;
    if (n == 0 || n > DSSO_AUTHN_MAX_SERVERS) return DSSO_E_ARG;
    if (t == 0 || t > n) return DSSO_E_ARG;
    if (cap == 0 || window_secs == 0) return DSSO_E_ARG;
    memset(c, 0, sizeof *c);
    c->n = n; c->t = t; c->cap = cap;
    c->window_secs = window_secs; c->merge_max_age = merge_max_age;
    for (i = 0; i < n; ++i) {
        memcpy(c->srv[i].id, ids + (size_t)i * DSSO_AUTHN_ID_LEN,
               DSSO_AUTHN_ID_LEN);
        c->srv[i].index = i;
        c->srv[i].merged_at = now;
    }
    /* The server-set digest is what a possession proof is bound to, so it must
     * cover the threshold as well as the membership: moving from 3-of-5 to
     * 1-of-5 is a different set even with the same members. */
    sha_dst(&h, DST_SET);
    determ_sha256_update(&h, &n, 1);
    determ_sha256_update(&h, &t, 1);
    for (i = 0; i < n; ++i) {
        determ_sha256_update(&h, &i, 1);
        determ_sha256_update(&h, c->srv[i].id, DSSO_AUTHN_ID_LEN);
    }
    determ_sha256_final(&h, c->set_digest);
    return DSSO_OK;
}

static dsso_authn_meter *meter_find(dsso_authn_server *v,
                                    const uint8_t account[DSSO_AUTHN_ID_LEN]) {
    unsigned i;
    for (i = 0; i < DSSO_AUTHN_MAX_ACCOUNTS; ++i)
        if (v->meter[i].in_use && dsso_ct_equal(v->meter[i].account, account,
                                                DSSO_AUTHN_ID_LEN))
            return &v->meter[i];
    return NULL;
}

static dsso_authn_meter *meter_get(dsso_authn_server *v,
                                   const uint8_t account[DSSO_AUTHN_ID_LEN],
                                   uint64_t window) {
    unsigned i;
    dsso_authn_meter *m = meter_find(v, account);
    if (!m) {
        for (i = 0; i < DSSO_AUTHN_MAX_ACCOUNTS; ++i)
            if (!v->meter[i].in_use) { m = &v->meter[i]; break; }
        if (!m) return NULL;                 /* full: the caller fails CLOSED */
        memset(m, 0, sizeof *m);
        m->in_use = 1;
        memcpy(m->account, account, DSSO_AUTHN_ID_LEN);
        m->window = window;
    }
    if (m->window != window) {               /* a new window starts at zero   */
        memset(m->slot, 0, sizeof m->slot);
        m->window = window;
    }
    return m;
}

static uint32_t meter_sum(const dsso_authn_meter *m) {
    uint32_t s = 0; unsigned i;
    for (i = 0; i < DSSO_AUTHN_MAX_SERVERS; ++i) {
        if (m->slot[i] > 0xFFFFFFFFu - s) return 0xFFFFFFFFu;  /* saturate */
        s += m->slot[i];
    }
    return s;
}

/* Least upper bound of two meter states for the same account: a newer
 * (window, reset_seq) wins wholesale; at equal (window, reset_seq) the slots
 * merge per-slot maximum. Idempotent, commutative, associative — the whole
 * reason the servers need no consensus rule to agree on the count. */
static void meter_join(dsso_authn_meter *dst, const dsso_authn_meter *src) {
    unsigned i;
    if (src->window > dst->window ||
        (src->window == dst->window && src->reset_seq > dst->reset_seq)) {
        memcpy(dst->slot, src->slot, sizeof dst->slot);
        dst->window = src->window;
        dst->reset_seq = src->reset_seq;
        return;
    }
    if (src->window != dst->window || src->reset_seq != dst->reset_seq) return;
    for (i = 0; i < DSSO_AUTHN_MAX_SERVERS; ++i)
        if (src->slot[i] > dst->slot[i]) dst->slot[i] = src->slot[i];
}

void dsso_authn_cluster_gossip(dsso_authn_cluster *c, uint64_t now) {
    dsso_authn_meter u[DSSO_AUTHN_MAX_SERVERS * DSSO_AUTHN_MAX_ACCOUNTS];
    unsigned nu = 0, i, j, k;
    if (!c) return;
    memset(u, 0, sizeof u);
    /* Build the union (the CRDT's least upper bound over every view), then
     * hand the same union back to every server. One pass, order-independent —
     * the array cannot overflow because each of the n <= MAX_SERVERS views
     * holds at most MAX_ACCOUNTS meters. */
    for (i = 0; i < c->n; ++i)
        for (j = 0; j < DSSO_AUTHN_MAX_ACCOUNTS; ++j) {
            const dsso_authn_meter *m = &c->srv[i].meter[j];
            if (!m->in_use) continue;
            for (k = 0; k < nu; ++k)
                if (dsso_ct_equal(u[k].account, m->account, DSSO_AUTHN_ID_LEN)) break;
            if (k == nu) { u[nu] = *m; nu++; }
            else meter_join(&u[k], m);
        }
    for (i = 0; i < c->n; ++i) {
        for (k = 0; k < nu; ++k) {
            dsso_authn_meter *m = meter_find(&c->srv[i], u[k].account);
            if (!m) {
                for (j = 0; j < DSSO_AUTHN_MAX_ACCOUNTS; ++j)
                    if (!c->srv[i].meter[j].in_use) { m = &c->srv[i].meter[j]; break; }
                if (!m) continue;
                *m = u[k];
                continue;
            }
            meter_join(m, &u[k]);
        }
        c->srv[i].merged_at = now;
    }
}

int dsso_authn_cluster_meter(dsso_authn_cluster *c, const uint8_t *subset,
                             uint8_t k, const uint8_t account[DSSO_AUTHN_ID_LEN],
                             uint64_t now) {
    uint64_t w;
    uint8_t i, j;
    if (!c || !subset || !account) return DSSO_E_ARG;
    if (k == 0 || k > c->n) return DSSO_E_ARG;
    for (i = 0; i < k; ++i) {
        if (subset[i] >= c->n) return DSSO_E_ARG;
        for (j = 0; j < i; ++j) if (subset[j] == subset[i]) return DSSO_E_ARG;
    }
    w = win_of(c, now);
    for (i = 0; i < k; ++i) {
        dsso_authn_server *v = &c->srv[subset[i]];
        dsso_authn_meter *m;
        /* A view that has not been merged recently cannot know what the rest of
         * the set has already served for this account. Serving on it would be
         * "allow on outage" — the one thing the mission rules forbid — so the
         * server refuses instead. Partition costs the attacker service, not the
         * bound. */
        if (now > v->merged_at && now - v->merged_at > c->merge_max_age)
            return DSSO_E_UNAVAILABLE;
        m = meter_get(v, account, w);
        if (!m) return DSSO_E_UNAVAILABLE;
        /* THE AGGREGATE CAP. Compared against the SUM of every server's slot,
         * not against this server's own slot: that is the whole difference
         * between a limiter a subset-rotating attacker walks around and one
         * that bounds the total number of guesses the set will ever serve. */
        if (meter_sum(m) >= c->cap) return DSSO_E_RATELIMIT;
        if (m->slot[v->index] < 0xFFFFFFFFu) m->slot[v->index] += 1;
    }
    return DSSO_OK;
}

uint32_t dsso_authn_meter_total(const dsso_authn_cluster *c, uint8_t server_index,
                                const uint8_t account[DSSO_AUTHN_ID_LEN],
                                uint64_t now) {
    const dsso_authn_meter *m;
    if (!c || !account || server_index >= c->n) return 0;
    m = meter_find((dsso_authn_server *)&c->srv[server_index], account);
    if (!m || m->window != win_of(c, now)) return 0;
    return meter_sum(m);
}

/* A successful two-factor login clears the account's budget across the set: a
 * legitimate user who mistyped is not held hostage by their own failures. The
 * clear is a reset_seq bump, which merge prefers wholesale, so gossip carries
 * it to servers that were not in the serving subset. */
static void meter_clear(dsso_authn_cluster *c, const uint8_t *subset, uint8_t k,
                        const uint8_t account[DSSO_AUTHN_ID_LEN], uint64_t now) {
    uint64_t w = win_of(c, now), top = 0;
    uint8_t i;
    for (i = 0; i < c->n; ++i) {
        const dsso_authn_meter *m = meter_find(&c->srv[i], account);
        if (m && m->window == w && m->reset_seq > top) top = m->reset_seq;
    }
    for (i = 0; i < k; ++i) {
        dsso_authn_meter *m = meter_get(&c->srv[subset[i]], account, w);
        if (!m) continue;
        memset(m->slot, 0, sizeof m->slot);
        m->reset_seq = top + 1;
    }
}

/* ── state, accounts, sessions ────────────────────────────────────────────*/

int dsso_authn_init(dsso_authn_state *st, const uint8_t session_secret[32],
                    uint64_t session_ttl, uint64_t clock_skew) {
    if (!st || !session_secret || session_ttl == 0) return DSSO_E_ARG;
    if (all_zero(session_secret, 32)) return DSSO_E_ARG;  /* fail closed on an
                                                           * unset secret     */
    memset(st, 0, sizeof *st);
    memcpy(st->session_secret, session_secret, 32);
    st->session_ttl = session_ttl;
    st->clock_skew = clock_skew;
    return DSSO_OK;
}

/* How long a spent nonce must be remembered. A request carrying timestamp `ts`
 * is acceptable for the whole interval [ts - skew, ts + skew], and it is first
 * accepted at some `now` inside it — possibly at the very start. Remembering it
 * for only `skew` would therefore let it be forgotten while it is still inside
 * its own acceptance window, which is a replay. 2*skew + 1 covers the window's
 * full width whatever moment inside it the first use happened. */
static uint64_t nonce_retain(const dsso_authn_state *st) {
    if (st->clock_skew > ((uint64_t)-1 - 1) / 2) return (uint64_t)-1;
    return st->clock_skew * 2 + 1;
}

void dsso_authn_set_pid_verifier(dsso_authn_state *st, dsso_pid_verify_fn fn,
                                 void *ctx) {
    if (!st) return;
    st->pid_verify = fn;
    st->pid_ctx = ctx;
}

int dsso_authn_bind_server_set(dsso_authn_state *st,
                               const uint8_t set_digest[DSSO_AUTHN_ID_LEN]) {
    if (!st || !set_digest) return DSSO_E_ARG;
    if (all_zero(set_digest, DSSO_AUTHN_ID_LEN)) return DSSO_E_ARG;
    memcpy(st->set_digest, set_digest, DSSO_AUTHN_ID_LEN);
    st->set_bound = 1;
    return DSSO_OK;
}

static dsso_authn_account *acc_find(dsso_authn_state *st,
                                    const uint8_t id[DSSO_AUTHN_ID_LEN]) {
    unsigned i;
    for (i = 0; i < DSSO_AUTHN_MAX_ACCOUNTS; ++i)
        if (st->acc[i].in_use && dsso_ct_equal(st->acc[i].id, id, DSSO_AUTHN_ID_LEN))
            return &st->acc[i];
    return NULL;
}

static dsso_authn_device_rec *dev_find(dsso_authn_account *a,
                                       const uint8_t id[DSSO_AUTHN_ID_LEN]) {
    unsigned i;
    if (all_zero(id, DSSO_AUTHN_ID_LEN)) return NULL;   /* the empty slot id  */
    for (i = 0; i < DSSO_AUTHN_MAX_DEVICES; ++i)
        if (dsso_ct_equal(a->dev[i].id, id, DSSO_AUTHN_ID_LEN))
            return &a->dev[i];
    return NULL;
}

static int dev_active_count(const dsso_authn_account *a) {
    unsigned i; int n = 0;
    for (i = 0; i < DSSO_AUTHN_MAX_DEVICES; ++i) if (a->dev[i].active) n++;
    return n;
}

static void dev_deactivate_all(dsso_authn_account *a) {
    unsigned i;
    for (i = 0; i < DSSO_AUTHN_MAX_DEVICES; ++i) a->dev[i].active = 0;
}

/* Whether this account could take this device — asked BEFORE any mutation, so
 * a refused enrolment or recovery leaves the account exactly as it was. A
 * device id is never recycled: letting a revoked id come back would resurrect a
 * device an operator believes is gone. */
static int dev_admit(dsso_authn_account *a, const uint8_t id[DSSO_AUTHN_ID_LEN],
                     const uint8_t pk[DSSO_AUTHN_PK_LEN]) {
    uint8_t p65[65];
    if (!id || !pk) return DSSO_E_ARG;
    if (all_zero(id, DSSO_AUTHN_ID_LEN)) return DSSO_E_ARG;
    if (dev_find(a, id)) return DSSO_E_REPLAY;
    if (determ_p256_point_decompress(p65, pk) != 0) return DSSO_E_FORMAT;
    return DSSO_OK;
}

static int dev_add(dsso_authn_account *a, const uint8_t id[DSSO_AUTHN_ID_LEN],
                   const uint8_t pk[DSSO_AUTHN_PK_LEN], uint8_t authority,
                   uint64_t now) {
    unsigned i;
    dsso_authn_device_rec *d = dev_find(a, id);
    if (d) return DSSO_E_REPLAY;             /* a device id is enrolled once  */
    for (i = 0; i < DSSO_AUTHN_MAX_DEVICES; ++i)
        if (!a->dev[i].active && all_zero(a->dev[i].id, DSSO_AUTHN_ID_LEN)) {
            d = &a->dev[i]; break;
        }
    if (!d)                                   /* reuse a revoked slot          */
        for (i = 0; i < DSSO_AUTHN_MAX_DEVICES; ++i)
            if (!a->dev[i].active) { d = &a->dev[i]; break; }
    if (!d) return DSSO_E_UNAVAILABLE;
    memset(d, 0, sizeof *d);
    memcpy(d->id, id, DSSO_AUTHN_ID_LEN);
    memcpy(d->pk, pk, DSSO_AUTHN_PK_LEN);
    d->enrolled_at = now;
    d->authority = authority;
    d->active = 1;
    return DSSO_OK;
}

/* Every change that could make a live session more powerful than the account
 * now is bumps this. Adding a device does NOT: it takes nothing away from any
 * session that already exists, and killing every session on an addition would
 * be hostile without being safer. */
static void bump_epoch(dsso_authn_account *a) { a->auth_epoch += 1; }

static dsso_authn_session *ses_find(const dsso_authn_state *st,
                                    const uint8_t id[DSSO_AUTHN_ID_LEN]) {
    unsigned i;
    for (i = 0; i < DSSO_AUTHN_MAX_SESSIONS; ++i)
        if (st->ses[i].in_use && dsso_ct_equal(st->ses[i].id, id, DSSO_AUTHN_ID_LEN))
            return (dsso_authn_session *)&st->ses[i];
    return NULL;
}

/* Single-use values: nonces (per account) and PID presentation ids. An entry
 * older than the freshness window can be dropped because the timestamp check
 * already rejects anything that old; if nothing is droppable the caller fails
 * CLOSED rather than forgetting a nonce it may still see again. */
static int seen_take(dsso_authn_seen *arr, const uint8_t scope[DSSO_AUTHN_ID_LEN],
                     const uint8_t value[DSSO_AUTHN_ID_LEN], uint64_t now,
                     uint64_t retain) {
    unsigned i, free_i = DSSO_AUTHN_MAX_SEEN;
    for (i = 0; i < DSSO_AUTHN_MAX_SEEN; ++i) {
        if (!arr[i].in_use) { if (free_i == DSSO_AUTHN_MAX_SEEN) free_i = i; continue; }
        if (dsso_ct_equal(arr[i].scope, scope, DSSO_AUTHN_ID_LEN) &&
            dsso_ct_equal(arr[i].value, value, DSSO_AUTHN_ID_LEN))
            return DSSO_E_REPLAY;
        if (now > arr[i].seen_at && now - arr[i].seen_at > retain) {
            arr[i].in_use = 0;
            if (free_i == DSSO_AUTHN_MAX_SEEN) free_i = i;
        }
    }
    if (free_i == DSSO_AUTHN_MAX_SEEN) return DSSO_E_UNAVAILABLE;
    memset(&arr[free_i], 0, sizeof arr[free_i]);
    memcpy(arr[free_i].scope, scope, DSSO_AUTHN_ID_LEN);
    memcpy(arr[free_i].value, value, DSSO_AUTHN_ID_LEN);
    arr[free_i].seen_at = now;
    arr[free_i].in_use = 1;
    return DSSO_OK;
}

static dsso_loa state_loa(uint8_t s) {
    switch (s) {
        case DSSO_ACC_ACTIVE:          return DSSO_LOA_SUBSTANTIAL;
        case DSSO_ACC_KNOWLEDGE_ONLY:  /* fall through — one factor is LOW    */
        case DSSO_ACC_POSSESSION_ONLY: return DSSO_LOA_LOW;
        default:                       return DSSO_LOA_NONE;
    }
}

dsso_acc_state dsso_authn_account_state(const dsso_authn_state *st,
                                        const uint8_t account[DSSO_AUTHN_ID_LEN]) {
    const dsso_authn_account *a;
    if (!st || !account) return DSSO_ACC_NONE;
    a = acc_find((dsso_authn_state *)st, account);
    return a ? (dsso_acc_state)a->state : DSSO_ACC_NONE;
}

dsso_loa dsso_authn_account_loa(const dsso_authn_state *st,
                                const uint8_t account[DSSO_AUTHN_ID_LEN]) {
    return state_loa((uint8_t)dsso_authn_account_state(st, account));
}

const char *dsso_loa_name(dsso_loa l) {
    switch (l) {
        case DSSO_LOA_NONE:        return "NONE";
        case DSSO_LOA_LOW:         return "LOW";
        case DSSO_LOA_SUBSTANTIAL: return "SUBSTANTIAL";
    }
    return "UNKNOWN";
}

const char *dsso_acc_state_name(dsso_acc_state s) {
    switch (s) {
        case DSSO_ACC_NONE:            return "NONE";
        case DSSO_ACC_ACTIVE:          return "ACTIVE";
        case DSSO_ACC_KNOWLEDGE_ONLY:  return "KNOWLEDGE_ONLY";
        case DSSO_ACC_POSSESSION_ONLY: return "POSSESSION_ONLY";
        case DSSO_ACC_LOCKED:          return "LOCKED";
    }
    return "UNKNOWN";
}

/* ── enrolment ────────────────────────────────────────────────────────────*/

/* Consult the identity-proofing seam. Fails CLOSED in every direction: no
 * verifier installed, no attestation offered, a verdict that is not DSSO_OK, a
 * subject binding that is not this account's, or a presentation already used. */
static int pid_admit(dsso_authn_state *st, dsso_authn_account *a,
                     const dsso_pid_attestation *pid, uint64_t now) {
    int rc;
    if (!pid) return DSSO_E_ASSURANCE;      /* the second evidence is missing */
    if (!st->pid_verify) return DSSO_E_UNAVAILABLE;
    rc = st->pid_verify(st->pid_ctx, pid, now);
    if (rc != DSSO_OK) return rc < 0 ? rc : DSSO_E_ASSURANCE;
    if (a && !dsso_ct_equal(a->pid_subject, pid->subject_binding, DSSO_AUTHN_ID_LEN))
        return DSSO_E_BINDING;              /* someone else's identity        */
    /* Single use, and never aged out: forgetting a presentation id would make
     * a captured presentation replayable, so the cache fails CLOSED when full
     * instead (a production deployment backs this with a database). */
    return seen_take(st->pid_seen, ZERO32, pid->presentation_id, now,
                     (uint64_t)-1);
}

int dsso_authn_enrol_first(dsso_authn_state *st,
                           const uint8_t account[DSSO_AUTHN_ID_LEN],
                           const dsso_pid_attestation *pid,
                           const uint8_t device[DSSO_AUTHN_ID_LEN],
                           const uint8_t pk[DSSO_AUTHN_PK_LEN],
                           const uint8_t knowledge_verifier[32], uint64_t now) {
    dsso_authn_account *a;
    unsigned i;
    int rc;
    if (!st || !account || !device || !pk || !knowledge_verifier) return DSSO_E_ARG;
    if (all_zero(account, DSSO_AUTHN_ID_LEN) || all_zero(device, DSSO_AUTHN_ID_LEN))
        return DSSO_E_ARG;
    if (acc_find(st, account)) return DSSO_E_REPLAY;
    {   /* the enrolled point must decode: right prefix, x < p, on the curve.
         * decompress performs all three, so a junk "public key" is refused at
         * enrolment rather than at the first failed login. */
        uint8_t p65[65];
        if (determ_p256_point_decompress(p65, pk) != 0) return DSSO_E_FORMAT;
    }
    /* At FIRST enrolment the user holds no DSSO credential yet, so the only
     * thing that can authorise the binding is the identity-proofing event: the
     * PID presentation the wallet made. That is where the account's assurance
     * comes from, and it is inherited, never re-earned by a later login. */
    if (!pid) return DSSO_E_ASSURANCE;   /* guarded HERE too: the fields below
                                          * are read directly, so this must not
                                          * depend on a callee's NULL check    */
    rc = pid_admit(st, NULL, pid, now);
    if (rc != DSSO_OK) return rc;
    a = NULL;
    for (i = 0; i < DSSO_AUTHN_MAX_ACCOUNTS; ++i)
        if (!st->acc[i].in_use) { a = &st->acc[i]; break; }
    if (!a) return DSSO_E_UNAVAILABLE;
    memset(a, 0, sizeof *a);
    a->in_use = 1;
    memcpy(a->id, account, DSSO_AUTHN_ID_LEN);
    memcpy(a->pid_subject, pid->subject_binding, DSSO_AUTHN_ID_LEN);
    memcpy(a->knowledge_verifier, knowledge_verifier, 32);
    a->has_knowledge = 1;
    a->auth_epoch = 1;
    rc = dev_add(a, device, pk, 0, now);
    if (rc != DSSO_OK) { memset(a, 0, sizeof *a); return rc; }
    a->state = DSSO_ACC_ACTIVE;
    return DSSO_OK;
}

int dsso_authn_enrol_device(dsso_authn_state *st,
                            const uint8_t session[DSSO_AUTHN_ID_LEN],
                            const dsso_authn_possession *existing,
                            const uint8_t new_device[DSSO_AUTHN_ID_LEN],
                            const uint8_t new_pk[DSSO_AUTHN_PK_LEN],
                            const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                            uint64_t timestamp, uint64_t now) {
    dsso_authn_session *s;
    dsso_authn_account *a;
    dsso_authn_device_rec *d;
    determ_sha256_ctx h;
    uint8_t aux[32], chal[32];
    dsso_loa loa;
    int rc;
    const uint8_t ev = DSSO_AUTHN_P_ENROL;
    if (!st || !session || !new_device || !new_pk || !nonce) return DSSO_E_ARG;
    if (!st->set_bound) return DSSO_E_UNAVAILABLE;
    if (all_zero(new_device, DSSO_AUTHN_ID_LEN)) return DSSO_E_ARG;
    rc = dsso_authn_session_verify(st, session, now, &loa);
    if (rc != DSSO_OK) return rc;
    s = ses_find(st, session);
    if (!s) return DSSO_E_BINDING;
    /* A session that was not itself two-factor cannot mint a second factor.
     * This is the clause that stops "password alone enrols a new device", and
     * with it the collapse of the whole scheme back to one factor. */
    if (loa != DSSO_LOA_SUBSTANTIAL || !s->two_factor) return DSSO_E_ASSURANCE;
    /* And the session is not enough on its own: the CURRENT possession factor
     * must sign the new device's public key. A stolen session token therefore
     * cannot enrol either. */
    if (!existing) return DSSO_E_ASSURANCE;
    a = acc_find(st, s->account);
    if (!a || a->state != DSSO_ACC_ACTIVE) return DSSO_E_STATUS;
    rc = dev_admit(a, new_device, new_pk);
    if (rc != DSSO_OK) return rc;
    if (!within(now, timestamp, st->clock_skew)) return DSSO_E_EXPIRED;
    rc = seen_take(st->seen, a->id, nonce, now, nonce_retain(st));
    if (rc != DSSO_OK) return rc;
    d = dev_find(a, existing->device);
    if (!d || !d->active) return DSSO_E_STATUS;
    sha_dst(&h, DST_AUX);
    determ_sha256_update(&h, &ev, 1);
    determ_sha256_update(&h, new_device, DSSO_AUTHN_ID_LEN);
    determ_sha256_update(&h, new_pk, DSSO_AUTHN_PK_LEN);
    determ_sha256_final(&h, aux);
    rc = dsso_authn_challenge(chal, DSSO_AUTHN_P_ENROL, a->id, d->id, nonce,
                              st->set_digest, timestamp, s->id, aux);
    if (rc != DSSO_OK) return rc;
    rc = dsso_authn_possession_verify(d->pk, existing, chal);
    if (rc != DSSO_OK) return rc;
    /* Adding a device does not invalidate live sessions — see bump_epoch. */
    return dev_add(a, new_device, new_pk, 1, now);
}

/* ── login: the dynamic authentication ────────────────────────────────────*/

int dsso_authn_login(dsso_authn_state *st, dsso_authn_cluster *c,
                     const uint8_t *subset, uint8_t k,
                     const dsso_authn_login_req *req, uint64_t now,
                     uint8_t out_session[DSSO_AUTHN_ID_LEN], dsso_loa *out_loa) {
    dsso_authn_account *a;
    dsso_authn_device_rec *d = NULL;
    dsso_authn_session *s = NULL;
    uint8_t expect[32], chal[32], sid[32], ts[8], ep[8];
    unsigned i;
    int rc, two = 0;
    dsso_loa loa;
    if (!st || !c || !subset || !req || !out_session) return DSSO_E_ARG;
    if (k < c->t) return DSSO_E_ARG;   /* a login needs a full t-quorum       */
    /* The deployment says which server set it is; the cluster in hand must BE
     * that set. A mismatch is a substituted or misconfigured set, never a
     * login — and it is refused before anything is metered or verified. */
    if (!st->set_bound) return DSSO_E_UNAVAILABLE;
    if (!dsso_ct_equal(st->set_digest, c->set_digest, DSSO_AUTHN_ID_LEN))
        return DSSO_E_BINDING;
    a = acc_find(st, req->account);
    if (!a) return DSSO_E_STATUS;
    /* METER FIRST. An attempt costs budget whether or not any factor is right;
     * a limiter that only counted *failures after verification* would let the
     * cheap rejections (stale timestamp, replayed nonce) run free. */
    rc = dsso_authn_cluster_meter(c, subset, k, a->id, now);
    if (rc != DSSO_OK) return rc;
    if (a->state == DSSO_ACC_LOCKED || a->state == DSSO_ACC_NONE)
        return DSSO_E_STATUS;
    if (!within(now, req->timestamp, st->clock_skew)) return DSSO_E_EXPIRED;
    rc = seen_take(st->seen, a->id, req->nonce, now, nonce_retain(st));
    if (rc != DSSO_OK) return rc;       /* a replayed nonce is never a login  */

    /* WHICH FACTORS THIS ACCOUNT STILL OWES. In ACTIVE both are required, and
     * "either one alone" is refused before any verification — that refusal is
     * the whole §2.2.1 claim. A degraded account owes exactly the one factor it
     * still has, and the session it gets says so. */
    if (a->state == DSSO_ACC_ACTIVE) {
        if (!req->knowledge || !req->possession) return DSSO_E_ASSURANCE;
    } else if (a->state == DSSO_ACC_KNOWLEDGE_ONLY) {
        if (!req->knowledge || req->possession) return DSSO_E_ASSURANCE;
    } else { /* POSSESSION_ONLY */
        if (req->knowledge || !req->possession) return DSSO_E_ASSURANCE;
    }

    if (req->knowledge) {
        if (!a->has_knowledge) return DSSO_E_STATUS;
        rc = dsso_authn_knowledge_tag(expect, a->knowledge_verifier,
                                      DSSO_AUTHN_P_LOGIN, a->id, req->nonce,
                                      c->set_digest, req->timestamp, NULL);
        if (rc != DSSO_OK) return rc;
        if (!dsso_ct_equal(expect, req->knowledge->tag, 32)) return DSSO_E_CRYPTO;
    } else {
        memset(expect, 0, sizeof expect);
    }
    if (req->possession) {
        d = dev_find(a, req->possession->device);
        if (!d || !d->active) return DSSO_E_STATUS;   /* revoked device: no  */
        /* The challenge is rebuilt here, from the server's own view: the
         * account, the nonce it just claimed as fresh, THIS server set's
         * digest, the timestamp, the device, and the knowledge factor's
         * expected tag. A proof made for another session, another server set,
         * another purpose or another moment does not verify against it. */
        rc = dsso_authn_challenge(chal, DSSO_AUTHN_P_LOGIN, a->id, d->id,
                                  req->nonce, c->set_digest, req->timestamp,
                                  req->knowledge ? expect : NULL, NULL);
        if (rc != DSSO_OK) return rc;
        rc = dsso_authn_possession_verify(d->pk, req->possession, chal);
        if (rc != DSSO_OK) return rc;
    }
    two = (req->knowledge && req->possession) ? 1 : 0;
    loa = two ? DSSO_LOA_SUBSTANTIAL : DSSO_LOA_LOW;
    if (loa > state_loa(a->state)) loa = state_loa(a->state);

    /* THE SESSION ID IS A BEARER TOKEN. Every other input to it — the account,
     * the login nonce, the timestamp — is carried in the clear in the login
     * request, so hashing those alone would let anyone who saw the request
     * compute the token. It is therefore an HMAC under a SERVER-SIDE secret,
     * plus a per-issue sequence number so two issues can never collide. */
    {
        uint8_t msg[1 + 32 + 32 + 32 + 8 + 8 + 8];
        size_t off = 0, dl = strlen(DST_SID);
        uint8_t sq[8];
        put_u64be(ts, req->timestamp);
        put_u64be(ep, a->auth_epoch);
        put_u64be(sq, ++st->session_seq);
        msg[off++] = (uint8_t)dl;
        memcpy(msg + off, DST_SID, dl); off += dl;
        memcpy(msg + off, a->id, 32);      off += 32;
        memcpy(msg + off, req->nonce, 32); off += 32;
        memcpy(msg + off, ts, 8);          off += 8;
        memcpy(msg + off, ep, 8);          off += 8;
        memcpy(msg + off, sq, 8);          off += 8;
        if (determ_hmac_sha256(st->session_secret, 32, msg, off, sid) != 0)
            return DSSO_E_CRYPTO;
    }
    for (i = 0; i < DSSO_AUTHN_MAX_SESSIONS; ++i)
        if (!st->ses[i].in_use) { s = &st->ses[i]; break; }
    if (!s)                                   /* reclaim an expired slot      */
        for (i = 0; i < DSSO_AUTHN_MAX_SESSIONS; ++i)
            if (st->ses[i].expires_at <= now) { s = &st->ses[i]; break; }
    if (!s) return DSSO_E_UNAVAILABLE;
    memset(s, 0, sizeof *s);
    memcpy(s->id, sid, DSSO_AUTHN_ID_LEN);
    memcpy(s->account, a->id, DSSO_AUTHN_ID_LEN);
    if (d) memcpy(s->device, d->id, DSSO_AUTHN_ID_LEN);
    s->issued_at = now;
    s->expires_at = now + st->session_ttl;
    s->epoch = a->auth_epoch;
    s->loa = (uint8_t)loa;
    s->two_factor = (uint8_t)two;
    s->in_use = 1;
    meter_clear(c, subset, k, a->id, now);
    memcpy(out_session, sid, DSSO_AUTHN_ID_LEN);
    if (out_loa) *out_loa = loa;
    return DSSO_OK;
}

int dsso_authn_session_verify(const dsso_authn_state *st,
                              const uint8_t session[DSSO_AUTHN_ID_LEN],
                              uint64_t now, dsso_loa *out_loa) {
    const dsso_authn_session *s;
    const dsso_authn_account *a;
    dsso_loa loa;
    if (!st || !session) return DSSO_E_ARG;
    s = ses_find(st, session);
    if (!s) return DSSO_E_BINDING;
    if (now >= s->expires_at) return DSSO_E_EXPIRED;
    a = acc_find((dsso_authn_state *)st, s->account);
    if (!a) return DSSO_E_STATUS;
    /* THE REVOCATION RULE. A session is a claim about the account as it was at
     * issue; every revocation, password change and recovery bumps auth_epoch,
     * so a token minted before the change stops verifying the moment the change
     * lands — with no session table to walk and nothing to miss. */
    if (s->epoch != a->auth_epoch) return DSSO_E_STATUS;
    if (a->state == DSSO_ACC_LOCKED || a->state == DSSO_ACC_NONE)
        return DSSO_E_STATUS;
    loa = (dsso_loa)s->loa;
    if (loa > state_loa(a->state)) loa = state_loa(a->state);
    if (out_loa) *out_loa = loa;
    return DSSO_OK;
}

int dsso_authn_assertion_authorize(const dsso_authn_state *st,
                                   const uint8_t session[DSSO_AUTHN_ID_LEN],
                                   dsso_loa required, uint64_t now) {
    dsso_loa have;
    int rc = dsso_authn_session_verify(st, session, now, &have);
    if (rc != DSSO_OK) return rc;
    /* The assurance the module reports is the thing the §5 assertion layer
     * consumes: a degraded account cannot buy back a substantial assertion by
     * logging in again, because the state — not the login — decides the level. */
    if (have < required) return DSSO_E_ASSURANCE;
    return DSSO_OK;
}

/* ── revocation ───────────────────────────────────────────────────────────*/

int dsso_authn_revoke_device(dsso_authn_state *st,
                             const uint8_t session[DSSO_AUTHN_ID_LEN],
                             const dsso_authn_possession *proof,
                             const uint8_t target_device[DSSO_AUTHN_ID_LEN],
                             const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                             uint64_t timestamp, uint64_t now) {
    dsso_authn_session *s;
    dsso_authn_account *a;
    dsso_authn_device_rec *d, *tgt;
    determ_sha256_ctx h;
    uint8_t aux[32], chal[32];
    dsso_loa loa;
    int rc;
    const uint8_t ev = DSSO_AUTHN_P_REVOKE;
    if (!st || !session || !proof || !target_device || !nonce) return DSSO_E_ARG;
    if (!st->set_bound) return DSSO_E_UNAVAILABLE;
    rc = dsso_authn_session_verify(st, session, now, &loa);
    if (rc != DSSO_OK) return rc;
    s = ses_find(st, session);
    if (!s) return DSSO_E_BINDING;
    if (loa != DSSO_LOA_SUBSTANTIAL || !s->two_factor) return DSSO_E_ASSURANCE;
    a = acc_find(st, s->account);
    if (!a) return DSSO_E_STATUS;
    if (!within(now, timestamp, st->clock_skew)) return DSSO_E_EXPIRED;
    rc = seen_take(st->seen, a->id, nonce, now, nonce_retain(st));
    if (rc != DSSO_OK) return rc;
    d = dev_find(a, proof->device);
    if (!d || !d->active) return DSSO_E_STATUS;
    tgt = dev_find(a, target_device);
    if (!tgt || !tgt->active) return DSSO_E_STATUS;
    sha_dst(&h, DST_AUX);
    determ_sha256_update(&h, &ev, 1);
    determ_sha256_update(&h, target_device, DSSO_AUTHN_ID_LEN);
    determ_sha256_final(&h, aux);
    rc = dsso_authn_challenge(chal, DSSO_AUTHN_P_REVOKE, a->id, d->id, nonce,
                              st->set_digest, timestamp, s->id, aux);
    if (rc != DSSO_OK) return rc;
    rc = dsso_authn_possession_verify(d->pk, proof, chal);
    if (rc != DSSO_OK) return rc;
    tgt->active = 0;
    if (dev_active_count(a) == 0)
        a->state = a->has_knowledge ? DSSO_ACC_KNOWLEDGE_ONLY : DSSO_ACC_LOCKED;
    bump_epoch(a);       /* every live session for this account dies here     */
    return DSSO_OK;
}

/* ── the loss / recovery state machine ────────────────────────────────────*/

/* aux for a recovery event: the event byte plus whatever the transition is
 * about, so evidence gathered for one transition cannot authorise another. */
static void recover_aux(uint8_t out[32], uint8_t ev,
                        const dsso_authn_evidence *e) {
    determ_sha256_ctx h;
    sha_dst(&h, DST_AUX);
    determ_sha256_update(&h, &ev, 1);
    if (e->pid) determ_sha256_update(&h, e->pid->presentation_id, DSSO_AUTHN_ID_LEN);
    if (e->new_device) determ_sha256_update(&h, e->new_device, DSSO_AUTHN_ID_LEN);
    if (e->new_pk) determ_sha256_update(&h, e->new_pk, DSSO_AUTHN_PK_LEN);
    if (e->new_knowledge_verifier)
        determ_sha256_update(&h, e->new_knowledge_verifier, DSSO_AUTHN_ID_LEN);
    determ_sha256_final(&h, out);
}

static int check_knowledge(dsso_authn_state *st, dsso_authn_account *a,
                           const dsso_authn_evidence *e, const uint8_t aux[32]) {
    uint8_t expect[32];
    int rc;
    (void)st;
    if (!e->knowledge) return DSSO_E_ASSURANCE;
    if (!a->has_knowledge) return DSSO_E_STATUS;
    rc = dsso_authn_knowledge_tag(expect, a->knowledge_verifier,
                                  DSSO_AUTHN_P_RECOVER, a->id, e->nonce,
                                  st->set_digest, e->timestamp, aux);
    if (rc != DSSO_OK) return rc;
    if (!dsso_ct_equal(expect, e->knowledge->tag, 32)) return DSSO_E_CRYPTO;
    return DSSO_OK;
}

static int check_possession(const dsso_authn_state *st, dsso_authn_account *a,
                            const dsso_authn_evidence *e, const uint8_t aux[32]) {
    dsso_authn_device_rec *d;
    uint8_t chal[32];
    int rc;
    if (!e->possession) return DSSO_E_ASSURANCE;
    d = dev_find(a, e->possession->device);
    if (!d || !d->active) return DSSO_E_STATUS;
    rc = dsso_authn_challenge(chal, DSSO_AUTHN_P_RECOVER, a->id, d->id, e->nonce,
                              st->set_digest, e->timestamp, NULL, aux);
    if (rc != DSSO_OK) return rc;
    return dsso_authn_possession_verify(d->pk, e->possession, chal);
}

int dsso_authn_recover(dsso_authn_state *st,
                       const uint8_t account[DSSO_AUTHN_ID_LEN],
                       dsso_authn_event ev, const dsso_authn_evidence *e,
                       uint64_t now) {
    dsso_authn_account *a;
    uint8_t aux[32];
    int rc, k_rc, p_rc;
    if (!st || !account || !e) return DSSO_E_ARG;
    if (!st->set_bound) return DSSO_E_UNAVAILABLE;
    a = acc_find(st, account);
    if (!a) return DSSO_E_STATUS;
    if (!within(now, e->timestamp, st->clock_skew)) return DSSO_E_EXPIRED;
    rc = seen_take(st->seen, a->id, e->nonce, now, nonce_retain(st));
    if (rc != DSSO_OK) return rc;
    recover_aux(aux, (uint8_t)ev, e);

    switch (ev) {
    /* ── reductions. One factor's evidence is enough to TAKE AWAY capability:
     * the worst a wrong one can do is degrade an account its holder can
     * re-establish with a fresh identity proofing. ─────────────────────────*/
    case DSSO_AUTHN_EV_DEVICE_LOST:
        if (a->state != DSSO_ACC_ACTIVE) return DSSO_E_STATUS;
        rc = check_knowledge(st, a, e, aux);
        if (rc != DSSO_OK) return rc;
        dev_deactivate_all(a);
        a->state = DSSO_ACC_KNOWLEDGE_ONLY;      /* visible LOW, not hidden   */
        bump_epoch(a);
        return DSSO_OK;

    case DSSO_AUTHN_EV_PASSWORD_LOST:
        if (a->state != DSSO_ACC_ACTIVE) return DSSO_E_STATUS;
        rc = check_possession(st, a, e, aux);
        if (rc != DSSO_OK) return rc;
        a->has_knowledge = 0;
        memset(a->knowledge_verifier, 0, sizeof a->knowledge_verifier);
        a->state = DSSO_ACC_POSSESSION_ONLY;
        bump_epoch(a);
        return DSSO_OK;

    case DSSO_AUTHN_EV_BOTH_LOST:
        if (a->state == DSSO_ACC_LOCKED || a->state == DSSO_ACC_NONE)
            return DSSO_E_STATUS;
        /* The panic button. Either surviving factor authorises it, because it
         * only ever removes capability; with neither, the holder goes straight
         * to RESTORE_BOTH with a fresh PID. */
        k_rc = e->knowledge  ? check_knowledge(st, a, e, aux) : DSSO_E_ASSURANCE;
        p_rc = e->possession ? check_possession(st, a, e, aux)    : DSSO_E_ASSURANCE;
        if (k_rc != DSSO_OK && p_rc != DSSO_OK)
            return (e->knowledge && k_rc != DSSO_OK) ? k_rc : p_rc;
        dev_deactivate_all(a);
        a->has_knowledge = 0;
        memset(a->knowledge_verifier, 0, sizeof a->knowledge_verifier);
        a->state = DSSO_ACC_LOCKED;
        bump_epoch(a);
        return DSSO_OK;

    /* ── restorations. Assurance goes back UP only on TWO independent
     * evidences, and one of them is always a fresh, single-use, subject-matched
     * PID presentation. Without it the transition is refused — it does not
     * "succeed at a lower level", because a half-done restore is exactly the
     * silent single-factor account this module exists to prevent. ──────────*/
    case DSSO_AUTHN_EV_RESTORE_DEVICE:
        if (a->state != DSSO_ACC_ACTIVE && a->state != DSSO_ACC_KNOWLEDGE_ONLY)
            return DSSO_E_STATUS;
        if (!e->new_device || !e->new_pk) return DSSO_E_ARG;
        rc = dev_admit(a, e->new_device, e->new_pk);   /* before any mutation */
        if (rc != DSSO_OK) return rc;
        rc = check_knowledge(st, a, e, aux);       /* evidence 1: knowledge   */
        if (rc != DSSO_OK) return rc;
        rc = pid_admit(st, a, e->pid, now);        /* evidence 2: the PID     */
        if (rc != DSSO_OK) return rc;
        dev_deactivate_all(a);
        rc = dev_add(a, e->new_device, e->new_pk, 0, now);
        if (rc != DSSO_OK) return rc;
        a->state = DSSO_ACC_ACTIVE;
        bump_epoch(a);
        return DSSO_OK;

    case DSSO_AUTHN_EV_RESTORE_PASSWORD:
        if (a->state != DSSO_ACC_ACTIVE && a->state != DSSO_ACC_POSSESSION_ONLY)
            return DSSO_E_STATUS;
        if (!e->new_knowledge_verifier) return DSSO_E_ARG;
        rc = check_possession(st, a, e, aux);          /* evidence 1: possession  */
        if (rc != DSSO_OK) return rc;
        rc = pid_admit(st, a, e->pid, now);        /* evidence 2: the PID     */
        if (rc != DSSO_OK) return rc;
        memcpy(a->knowledge_verifier, e->new_knowledge_verifier, 32);
        a->has_knowledge = 1;
        a->state = DSSO_ACC_ACTIVE;
        bump_epoch(a);
        return DSSO_OK;

    case DSSO_AUTHN_EV_RESTORE_BOTH:
        if (!e->new_device || !e->new_pk || !e->new_knowledge_verifier)
            return DSSO_E_ARG;
        rc = dev_admit(a, e->new_device, e->new_pk);   /* before any mutation */
        if (rc != DSSO_OK) return rc;
        /* Both factors gone: the PID is the only evidence left, and it is the
         * SAME evidence that authorised the account in the first place. This
         * does not bypass the level — it re-runs enrolment under a fresh
         * proofing — but it does mean whoever can present the subject's PID can
         * take the account. That is the eIDAS trust root, stated plainly. */
        rc = pid_admit(st, a, e->pid, now);
        if (rc != DSSO_OK) return rc;
        dev_deactivate_all(a);
        rc = dev_add(a, e->new_device, e->new_pk, 0, now);
        if (rc != DSSO_OK) return rc;
        memcpy(a->knowledge_verifier, e->new_knowledge_verifier, 32);
        a->has_knowledge = 1;
        a->state = DSSO_ACC_ACTIVE;
        bump_epoch(a);
        return DSSO_OK;
    }
    return DSSO_E_ARG;
}
