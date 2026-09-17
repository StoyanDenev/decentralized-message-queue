/* `determ-dsso selftest-authn` — the falsify-on-mutant gate for the DSSO
 * authentication module.
 *
 * WHAT IT ASSERTS, and why each arm is here: the two factors are independent
 * and BOTH required (2015/1502 Annex §2.2.1); the authentication is dynamic and
 * bound to this session, this server set and this moment (§2.3.1); a new device
 * can never be enrolled by the knowledge factor alone; every recovery either
 * needs a second independent evidence or DEGRADES the account visibly; a
 * revocation kills live sessions; and the attempt limiter binds the total number
 * of guesses the server set will serve, not the number any one server serves.
 *
 * DETERMINISM. No clock is read and no randomness is drawn: `now` is a plain
 * counter, every id/seed/nonce is a labelled SHA-256 of a constant string, and
 * the possession proof is deterministic in (secret, challenge). Two runs of this
 * binary are byte-identical. */
#include <stdio.h>
#include <string.h>

#include "authn.h"

#include <determ/crypto/p256/p256.h>
#include <determ/crypto/sha2/sha2.h>

static int g_fail;
#define CHECK(cond, msg) do { \
    if (cond) printf("  PASS: %s\n", (msg)); \
    else { printf("  FAIL: %s\n", (msg)); g_fail++; } } while (0)

/* Deterministic fixture values: distinct labels give distinct 32-byte ids. */
static void mk32(uint8_t out[32], const char *label) {
    determ_sha256((const uint8_t *)label, strlen(label), out);
}

typedef struct {
    uint8_t id[DSSO_AUTHN_ID_LEN];
    uint8_t sk[32];
    uint8_t pk[DSSO_AUTHN_PK_LEN];
} tdev;

static int tdev_new(tdev *d, const char *label) {
    char buf[96];
    uint8_t seed[32];
    snprintf(buf, sizeof buf, "dsso-authn-selftest/device-id/%s", label);
    mk32(d->id, buf);
    /* The seed stands for DEVICE-LOCAL entropy: it is not the password, not the
     * OPRF output, and not anything a server stores. */
    snprintf(buf, sizeof buf, "dsso-authn-selftest/device-seed/%s", label);
    mk32(seed, buf);
    return dsso_authn_device_keygen(d->sk, d->pk, seed);
}

/* ── the PID seam, stubbed. The real verifier is a sibling track's work; this
 * models only its verdict so the state machine can be driven. ─────────────── */
typedef struct { int accept; } pid_ctx;

static int pid_stub(void *ctx, const dsso_pid_attestation *att, uint64_t now) {
    const pid_ctx *c = (const pid_ctx *)ctx;
    (void)now;
    if (!att || att->verified_at == 0) return DSSO_E_FORMAT;
    return c && c->accept ? DSSO_OK : DSSO_E_ASSURANCE;
}

static void mk_pid(dsso_pid_attestation *p, const char *subject,
                   const char *presentation, uint64_t at) {
    char buf[96];
    snprintf(buf, sizeof buf, "dsso-authn-selftest/pid-subject/%s", subject);
    mk32(p->subject_binding, buf);
    snprintf(buf, sizeof buf, "dsso-authn-selftest/pid-presentation/%s", presentation);
    mk32(p->presentation_id, buf);
    p->verified_at = at;
}

/* ── login helpers ────────────────────────────────────────────────────────── */

/* Build the client side of one login: the knowledge tag (when a verifier is
 * supplied) and the device's answer to the challenge those very bytes produce. */
static int mk_login(dsso_authn_knowledge *kn, dsso_authn_possession *po,
                    const uint8_t acct[32], const uint8_t *kv, const tdev *d,
                    const uint8_t nonce[32], const uint8_t set_digest[32],
                    uint64_t ts) {
    uint8_t chal[32];
    int rc;
    if (kv) {
        rc = dsso_authn_knowledge_tag(kn->tag, kv, DSSO_AUTHN_P_LOGIN, acct,
                                      nonce, set_digest, ts, NULL);
        if (rc != DSSO_OK) return rc;
    }
    if (d) {
        rc = dsso_authn_challenge(chal, DSSO_AUTHN_P_LOGIN, acct, d->id, nonce,
                                  set_digest, ts, kv ? kn->tag : NULL, NULL);
        if (rc != DSSO_OK) return rc;
        rc = dsso_authn_possession_sign(po, d->sk, d->pk, d->id, chal);
        if (rc != DSSO_OK) return rc;
    }
    return DSSO_OK;
}

static int login_ts(dsso_authn_state *st, dsso_authn_cluster *c,
                    const uint8_t *sub, uint8_t k, const uint8_t acct[32],
                    const uint8_t *kv, const tdev *d, const char *nonce_label,
                    uint64_t ts, uint64_t now, uint8_t out_sid[32],
                    dsso_loa *out_loa) {
    dsso_authn_knowledge kn;
    dsso_authn_possession po;
    dsso_authn_login_req req;
    uint8_t nonce[32];
    char buf[96];
    int rc;
    snprintf(buf, sizeof buf, "dsso-authn-selftest/nonce/%s", nonce_label);
    mk32(nonce, buf);
    memset(&kn, 0, sizeof kn); memset(&po, 0, sizeof po);
    rc = mk_login(&kn, &po, acct, kv, d, nonce, c->set_digest, ts);
    if (rc != DSSO_OK) return rc;
    memset(&req, 0, sizeof req);
    memcpy(req.account, acct, 32);
    memcpy(req.nonce, nonce, 32);
    req.timestamp = ts;
    req.knowledge = kv ? &kn : NULL;
    req.possession = d ? &po : NULL;
    return dsso_authn_login(st, c, sub, k, &req, now, out_sid, out_loa);
}

/* The ordinary case: the client's timestamp IS the server's clock. */
static int login(dsso_authn_state *st, dsso_authn_cluster *c,
                 const uint8_t *sub, uint8_t k, const uint8_t acct[32],
                 const uint8_t *kv, const tdev *d, const char *nonce_label,
                 uint64_t now, uint8_t out_sid[32], dsso_loa *out_loa) {
    return login_ts(st, c, sub, k, acct, kv, d, nonce_label, now, now,
                    out_sid, out_loa);
}

/* ── the module-level fixture ─────────────────────────────────────────────── */

static dsso_authn_state ST;
static dsso_authn_cluster CL;
static dsso_authn_cluster CL2;      /* a DIFFERENT server set, same members  */
static dsso_authn_state ST2;        /* the same deployment under a different
                                     * server-side session secret            */

#define T0          1700000000u
#define WINDOW      3600u
#define MERGE_AGE     60u
#define CAP           12u   /* the DEDICATED limiter fixture's cap          */
#define CAP_MAIN    4096u   /* the walk-through fixture: the limiter is not
                             * what those arms are testing, so its budget is
                             * generous enough not to mask them              */
#define SESSION_TTL  900u
#define SKEW         120u

static const uint8_t SUB012[3] = {0, 1, 2};

static void init_clusters(uint64_t now) {
    uint8_t ids[5][DSSO_AUTHN_ID_LEN];
    char buf[64];
    int i;
    for (i = 0; i < 5; ++i) {
        snprintf(buf, sizeof buf, "dsso-authn-selftest/server/%d", i);
        mk32(ids[i], buf);
    }
    dsso_authn_cluster_init(&CL, 5, 3, &ids[0][0], CAP_MAIN, WINDOW, MERGE_AGE, now);
    /* CL2 is the SAME five servers at a DIFFERENT threshold — a different
     * server set, and a possession proof bound to one must not verify in the
     * other. */
    dsso_authn_cluster_init(&CL2, 5, 4, &ids[0][0], CAP_MAIN, WINDOW, MERGE_AGE, now);
}

int dsso_selftest_authn(void);

int dsso_selftest_authn(void) {
    static const uint8_t SUB013[3] = {0, 1, 3};
    static const uint8_t ROT[10][3] = {
        {0,1,2},{0,1,3},{0,1,4},{0,2,3},{0,2,4},
        {0,3,4},{1,2,3},{1,2,4},{1,3,4},{2,3,4}
    };
    uint8_t acctA[32], acctB[32], acctC[32], acctD[32];
    uint8_t kvA[32], kvB[32], kvC[32], kvD[32], kvC2[32], kvWrong[32];
    tdev d1, d2, d3, dR, dC, dD, dN;
    dsso_pid_attestation pid;
    pid_ctx pc; pc.accept = 1;
    uint8_t sid[32], sid2[32], sidLow[32], junk[32];
    dsso_loa loa;
    uint64_t now = T0;
    int rc, i, served;

    g_fail = 0;
    mk32(acctA, "dsso-authn-selftest/account/A");
    mk32(acctB, "dsso-authn-selftest/account/B");
    mk32(acctC, "dsso-authn-selftest/account/C");
    mk32(acctD, "dsso-authn-selftest/account/D");
    /* `kv` stands for the server-side secret the shipped threshold-OPRF +
     * OPAQUE-3DH login co-generates from the password. It IS derivable from the
     * password together with t shares — that is the point. */
    mk32(kvA, "dsso-authn-selftest/kv/A");
    mk32(kvB, "dsso-authn-selftest/kv/B");
    mk32(kvC, "dsso-authn-selftest/kv/C");
    mk32(kvC2, "dsso-authn-selftest/kv/C-new");
    mk32(kvD, "dsso-authn-selftest/kv/D");
    mk32(kvWrong, "dsso-authn-selftest/kv/wrong");
    init_clusters(now);
    {   /* the deployment's server-side session secret, injected like everything
         * else in this gate so the run is reproducible */
        uint8_t ssec[32];
        mk32(ssec, "dsso-authn-selftest/session-secret");
        CHECK(dsso_authn_init(&ST, ssec, SESSION_TTL, SKEW) == DSSO_OK,
              "A0 init: the state initialises with an injected session secret");
        memset(ssec, 0, sizeof ssec);
        CHECK(dsso_authn_init(&ST, ssec, SESSION_TTL, SKEW) == DSSO_E_ARG,
              "A0b init: an unset (all-zero) session secret is REFUSED — session ids are bearer tokens");
        mk32(ssec, "dsso-authn-selftest/session-secret");
        dsso_authn_init(&ST, ssec, SESSION_TTL, SKEW);
        CHECK(dsso_authn_bind_server_set(&ST, CL.set_digest) == DSSO_OK,
              "A0c init: the deployment's server set is installed once, not passed per call");
    }

    /* ══ A. the possession factor's cryptography ═══════════════════════════ */
    printf("\n-- A. the device possession proof (P-256 DLEQ over the shipped VOPRF) --\n");
    CHECK(tdev_new(&d1, "d1") == DSSO_OK, "A1 keygen: a device key is produced from a device-local seed");
    CHECK(tdev_new(&d2, "d2") == DSSO_OK, "A1b keygen: a second device key is produced");
    /* THE INDEPENDENCE ARM. If the derivation ignored its seed, every caller
     * would compute the same "device" key — and a key anyone can recompute is
     * not a possession factor. */
    CHECK(memcmp(d1.pk, d2.pk, DSSO_AUTHN_PK_LEN) != 0,
          "A2 keygen: different device seeds give DIFFERENT keys (the seed is load-bearing)");
    {
        tdev again;
        CHECK(tdev_new(&again, "d1") == DSSO_OK && memcmp(again.pk, d1.pk, 33) == 0,
              "A3 keygen: the same seed reproduces the same key (deterministic, no RNG)");
    }
    {
        dsso_authn_possession p, p2;
        uint8_t ch1[32], ch2[32], setd[32];
        memset(setd, 0x5a, sizeof setd);
        mk32(ch1, "dsso-authn-selftest/chal/1");
        mk32(ch2, "dsso-authn-selftest/chal/2");
        CHECK(dsso_authn_possession_sign(&p, d1.sk, d1.pk, d1.id, ch1) == DSSO_OK,
              "A4 sign: the device answers a challenge");
        CHECK(dsso_authn_possession_verify(d1.pk, &p, ch1) == DSSO_OK,
              "A5 verify: the answer verifies against the enrolled public key");
        CHECK(dsso_authn_possession_sign(&p2, d1.sk, d1.pk, d1.id, ch1) == DSSO_OK &&
              memcmp(&p, &p2, sizeof p) == 0,
              "A6 sign: the proof is deterministic (reproducible gate, no nonce reuse across challenges)");
        CHECK(dsso_authn_possession_verify(d1.pk, &p, ch2) != DSSO_OK,
              "A7 verify: an answer to ANOTHER challenge is rejected (challenge binding)");
        CHECK(dsso_authn_possession_verify(d2.pk, &p, ch1) != DSSO_OK,
              "A8 verify: the answer does not verify under another device's key");
        p2 = p; p2.proof[0] ^= 0x01;
        CHECK(dsso_authn_possession_verify(d1.pk, &p2, ch1) != DSSO_OK,
              "A9 verify: a byte-flipped proof is rejected");
        p2 = p; p2.eval[5] ^= 0x01;
        CHECK(dsso_authn_possession_verify(d1.pk, &p2, ch1) != DSSO_OK,
              "A10 verify: a byte-flipped response element is rejected");
        {
            uint8_t badpk[DSSO_AUTHN_PK_LEN];
            memset(badpk, 0, sizeof badpk);
            CHECK(dsso_authn_possession_verify(badpk, &p, ch1) != DSSO_OK,
                  "A11 verify: a malformed public key is rejected, never dereferenced");
        }
        CHECK(dsso_authn_possession_verify(NULL, &p, ch1) == DSSO_E_ARG &&
              dsso_authn_possession_verify(d1.pk, NULL, ch1) == DSSO_E_ARG,
              "A12 verify: NULL arguments fail closed with DSSO_E_ARG");
        (void)setd;
    }

    /* ══ B. enrolment is authorised by the identity-proofing event ═════════ */
    printf("\n-- B. first enrolment: only the PID binding authorises it --\n");
    mk_pid(&pid, "A", "A-enrol", now);
    CHECK(dsso_authn_enrol_first(&ST, acctA, &pid, d1.id, d1.pk, kvA, now)
              == DSSO_E_UNAVAILABLE,
          "B1 enrol: with NO PID verifier installed the enrolment FAILS CLOSED (E_UNAVAILABLE)");
    dsso_authn_set_pid_verifier(&ST, pid_stub, &pc);
    CHECK(dsso_authn_enrol_first(&ST, acctA, NULL, d1.id, d1.pk, kvA, now)
              == DSSO_E_ASSURANCE,
          "B2 enrol: with no PID presentation at all the enrolment is refused");
    CHECK(dsso_authn_enrol_first(&ST, acctA, &pid, d1.id, d1.pk, kvA, now) == DSSO_OK,
          "B3 enrol: a verified PID presentation enrols the first device");
    CHECK(dsso_authn_account_state(&ST, acctA) == DSSO_ACC_ACTIVE,
          "B4 enrol: the account is ACTIVE");
    CHECK(dsso_authn_account_loa(&ST, acctA) == DSSO_LOA_SUBSTANTIAL,
          "B5 enrol: the reported assurance is SUBSTANTIAL");
    CHECK(dsso_authn_enrol_first(&ST, acctB, &pid, d2.id, d2.pk, kvB, now)
              == DSSO_E_REPLAY,
          "B6 enrol: the SAME PID presentation cannot be replayed into a second account");
    {
        dsso_pid_attestation pB;
        mk_pid(&pB, "B", "B-enrol", now);
        CHECK(dsso_authn_enrol_first(&ST, acctB, &pB, d2.id, d2.pk, kvB, now) == DSSO_OK,
              "B7 enrol: a second user enrols with their own presentation");
        mk_pid(&pB, "A", "A-enrol-2", now);
        CHECK(dsso_authn_enrol_first(&ST, acctA, &pB, d1.id, d1.pk, kvA, now)
                  == DSSO_E_REPLAY,
              "B8 enrol: an existing account cannot be re-enrolled over");
    }

    /* ══ C. the two-factor login ═══════════════════════════════════════════ */
    printf("\n-- C. login: two factors, different categories, both required --\n");
    now += 10;
    dsso_authn_cluster_gossip(&CL, now);
    CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-ok-1", now, sid, &loa) == DSSO_OK
              && loa == DSSO_LOA_SUBSTANTIAL,
          "C1 login: the honest two-factor login is ACCEPTED at SUBSTANTIAL");
    CHECK(dsso_authn_session_verify(&ST, sid, now, &loa) == DSSO_OK
              && loa == DSSO_LOA_SUBSTANTIAL,
          "C2 session: the issued session verifies at SUBSTANTIAL");
    now += 10; dsso_authn_cluster_gossip(&CL, now);
    CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, NULL, "A-pw-only", now, junk, NULL)
              == DSSO_E_ASSURANCE,
          "C3 login: PASSWORD ALONE is REJECTED (the knowledge factor is not an authentication)");
    now += 10; dsso_authn_cluster_gossip(&CL, now);
    CHECK(login(&ST, &CL, SUB012, 3, acctA, NULL, &d1, "A-dev-only", now, junk, NULL)
              == DSSO_E_ASSURANCE,
          "C4 login: DEVICE ALONE is REJECTED (possession does not stand in for knowledge)");
    now += 10; dsso_authn_cluster_gossip(&CL, now);
    CHECK(login(&ST, &CL, SUB012, 3, acctA, kvWrong, &d1, "A-badpw", now, junk, NULL)
              == DSSO_E_CRYPTO,
          "C5 login: a wrong password is rejected even with the right device");
    /* replay: the exact bytes of a completed login, presented again */
    {
        dsso_authn_knowledge kn; dsso_authn_possession po; dsso_authn_login_req req;
        uint8_t nonce[32];
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        mk32(nonce, "dsso-authn-selftest/nonce/A-replay");
        memset(&kn, 0, sizeof kn); memset(&po, 0, sizeof po);
        rc = mk_login(&kn, &po, acctA, kvA, &d1, nonce, CL.set_digest, now);
        memset(&req, 0, sizeof req);
        memcpy(req.account, acctA, 32); memcpy(req.nonce, nonce, 32);
        req.timestamp = now; req.knowledge = &kn; req.possession = &po;
        CHECK(rc == DSSO_OK &&
              dsso_authn_login(&ST, &CL, SUB012, 3, &req, now, sid2, NULL) == DSSO_OK,
              "C6 login: a fresh challenge is accepted once");
        dsso_authn_cluster_gossip(&CL, now);
        CHECK(dsso_authn_login(&ST, &CL, SUB012, 3, &req, now, junk, NULL) == DSSO_E_REPLAY,
              "C7 login: REPLAYING the same device response is REJECTED (single-use nonce)");
    }
    /* a response made for a different session nonce */
    {
        dsso_authn_knowledge kn; dsso_authn_possession po; dsso_authn_login_req req;
        uint8_t nonce_a[32], nonce_b[32];
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        mk32(nonce_a, "dsso-authn-selftest/nonce/A-sess-a");
        mk32(nonce_b, "dsso-authn-selftest/nonce/A-sess-b");
        memset(&kn, 0, sizeof kn); memset(&po, 0, sizeof po);
        rc = mk_login(&kn, &po, acctA, kvA, &d1, nonce_a, CL.set_digest, now);
        /* present it under nonce_b, with a knowledge tag recomputed for b so
         * that the ONLY thing wrong is the session the device signed */
        (void)dsso_authn_knowledge_tag(kn.tag, kvA, DSSO_AUTHN_P_LOGIN, acctA,
                                       nonce_b, CL.set_digest, now, NULL);
        memset(&req, 0, sizeof req);
        memcpy(req.account, acctA, 32); memcpy(req.nonce, nonce_b, 32);
        req.timestamp = now; req.knowledge = &kn; req.possession = &po;
        CHECK(rc == DSSO_OK &&
              dsso_authn_login(&ST, &CL, SUB012, 3, &req, now, junk, NULL) == DSSO_E_CRYPTO,
              "C8 login: a device response bound to ANOTHER SESSION is REJECTED");
    }
    /* a response made against a different server set */
    {
        dsso_authn_knowledge kn; dsso_authn_possession po; dsso_authn_login_req req;
        uint8_t nonce[32];
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        mk32(nonce, "dsso-authn-selftest/nonce/A-otherset");
        memset(&kn, 0, sizeof kn); memset(&po, 0, sizeof po);
        rc = mk_login(&kn, &po, acctA, kvA, &d1, nonce, CL2.set_digest, now);
        (void)dsso_authn_knowledge_tag(kn.tag, kvA, DSSO_AUTHN_P_LOGIN, acctA,
                                       nonce, CL.set_digest, now, NULL);
        memset(&req, 0, sizeof req);
        memcpy(req.account, acctA, 32); memcpy(req.nonce, nonce, 32);
        req.timestamp = now; req.knowledge = &kn; req.possession = &po;
        CHECK(rc == DSSO_OK &&
              dsso_authn_login(&ST, &CL, SUB012, 3, &req, now, junk, NULL) == DSSO_E_CRYPTO,
              "C9 login: a device response bound to ANOTHER SERVER SET is REJECTED");
    }
    {   /* the deployment says which server set it is; a cluster that is NOT
         * that set is refused before anything is metered or verified */
        static const uint8_t SUB0123[4] = {0, 1, 2, 3};
        now += 10; dsso_authn_cluster_gossip(&CL2, now);
        CHECK(login(&ST, &CL2, SUB0123, 4, acctA, kvA, &d1, "A-wrongcluster", now,
                    junk, NULL) == DSSO_E_BINDING,
              "C9b login: a cluster whose set digest is NOT the bound one is REFUSED (substituted server set)");
    }
    now += 10; dsso_authn_cluster_gossip(&CL, now);
    CHECK(login_ts(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-stale",
                   now - SKEW - 1, now, junk, NULL) == DSSO_E_EXPIRED,
          "C10 login: a STALE timestamp is rejected (the authentication is dynamic)");
    now += 10; dsso_authn_cluster_gossip(&CL, now);
    CHECK(login_ts(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-future",
                   now + SKEW + 1, now, junk, NULL) == DSSO_E_EXPIRED,
          "C10b login: a FUTURE-DATED timestamp is rejected too (the window is two-sided)");

    /* THE ADVERSARY OF §2.2.1: password + every server's share, no device. */
    printf("\n-- C'. the adversary holding the password AND every server share --\n");
    {
        tdev forged;
        determ_sha256_ctx h;
        uint8_t seed[32];
        /* Everything a full-quorum adversary can see: the enrolled PUBLIC key,
         * the password-derived server-side secret, and every server id. */
        determ_sha256_init(&h);
        determ_sha256_update(&h, d1.pk, DSSO_AUTHN_PK_LEN);
        determ_sha256_update(&h, kvA, 32);
        determ_sha256_update(&h, CL.set_digest, 32);
        determ_sha256_final(&h, seed);
        CHECK(dsso_authn_device_keygen(forged.sk, forged.pk, seed) == DSSO_OK &&
              memcmp(forged.pk, d1.pk, DSSO_AUTHN_PK_LEN) != 0,
              "C11 adversary: the device key is NOT recoverable from the password + everything the servers store");
        memcpy(forged.id, d1.id, DSSO_AUTHN_ID_LEN);   /* claim the real device */
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &forged, "A-forge", now, junk, NULL)
                  == DSSO_E_CRYPTO,
              "C12 adversary: that adversary CANNOT complete a login (no device key, no authentication)");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-after-forge", now, sid, &loa)
                  == DSSO_OK && loa == DSSO_LOA_SUBSTANTIAL,
              "C13 adversary: the honest holder still logs in afterwards");
    }

    /* ══ D. enrolling a second device ══════════════════════════════════════ */
    printf("\n-- D. enrolling a second device needs the session AND the current device --\n");
    {
        uint8_t nonce[32], aux[32], chal[32];
        dsso_authn_possession po;
        determ_sha256_ctx h;
        const uint8_t ev = DSSO_AUTHN_P_ENROL;
        const uint8_t dl = (uint8_t)strlen("DSSO-authn-v1-aux");
        tdev_new(&d3, "d3");
        mk32(nonce, "dsso-authn-selftest/nonce/A-enrol2");
        now += 5;
        /* password alone — an authenticated session but NO possession proof */
        CHECK(dsso_authn_enrol_device(&ST, sid, NULL, d3.id, d3.pk, nonce, now, now) == DSSO_E_ASSURANCE,
              "D1 enrol: a session WITHOUT the current possession factor cannot enrol a device");
        /* the same session, now with the current device's signature over the
         * new device's public key */
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &ev, 1);
        determ_sha256_update(&h, d3.id, DSSO_AUTHN_ID_LEN);
        determ_sha256_update(&h, d3.pk, DSSO_AUTHN_PK_LEN);
        determ_sha256_final(&h, aux);
        dsso_authn_challenge(chal, DSSO_AUTHN_P_ENROL, acctA, d1.id, nonce,
                             CL.set_digest, now, sid, aux);
        dsso_authn_possession_sign(&po, d1.sk, d1.pk, d1.id, chal);
        {   /* a LOGIN-purpose proof must not authorise an enrolment */
            dsso_authn_possession lp;
            uint8_t lchal[32];
            dsso_authn_challenge(lchal, DSSO_AUTHN_P_LOGIN, acctA, d1.id, nonce,
                                 CL.set_digest, now, sid, aux);
            dsso_authn_possession_sign(&lp, d1.sk, d1.pk, d1.id, lchal);
            CHECK(dsso_authn_enrol_device(&ST, sid, &lp, d3.id, d3.pk, nonce, now, now) == DSSO_E_CRYPTO,
                  "D2 enrol: a proof made for a LOGIN cannot authorise an enrolment (purpose binding)");
        }
        /* D2's refused attempt spent that nonce (a nonce is single use whatever
         * the verdict), so the real enrolment carries a fresh one. */
        mk32(nonce, "dsso-authn-selftest/nonce/A-enrol2b");
        dsso_authn_challenge(chal, DSSO_AUTHN_P_ENROL, acctA, d1.id, nonce,
                             CL.set_digest, now, sid, aux);
        dsso_authn_possession_sign(&po, d1.sk, d1.pk, d1.id, chal);
        CHECK(dsso_authn_enrol_device(&ST, sid, &po, d3.id, d3.pk, nonce, now, now) == DSSO_OK,
              "D3 enrol: session + a fresh proof from the CURRENT device enrols the new one");
        CHECK(dsso_authn_session_verify(&ST, sid, now, &loa) == DSSO_OK,
              "D4 enrol: ADDING a device does not invalidate live sessions");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d3, "A-d3-login", now, sid2, &loa)
                  == DSSO_OK && loa == DSSO_LOA_SUBSTANTIAL,
              "D5 enrol: the newly enrolled device logs in at SUBSTANTIAL");
    }

    /* ══ E. revocation invalidates live sessions ═══════════════════════════ */
    printf("\n-- E. revocation, and what happens to concurrent sessions --\n");
    {
        uint8_t nonce[32], aux[32], chal[32];
        dsso_authn_possession po;
        determ_sha256_ctx h;
        const uint8_t ev = DSSO_AUTHN_P_REVOKE;
        const uint8_t dl = (uint8_t)strlen("DSSO-authn-v1-aux");
        mk32(nonce, "dsso-authn-selftest/nonce/A-revoke");
        now += 5;
        CHECK(dsso_authn_session_verify(&ST, sid2, now, &loa) == DSSO_OK,
              "E1 revoke: the live session verifies BEFORE the revocation");
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &ev, 1);
        determ_sha256_update(&h, d3.id, DSSO_AUTHN_ID_LEN);
        determ_sha256_final(&h, aux);
        dsso_authn_challenge(chal, DSSO_AUTHN_P_REVOKE, acctA, d1.id, nonce,
                             CL.set_digest, now, sid2, aux);
        dsso_authn_possession_sign(&po, d1.sk, d1.pk, d1.id, chal);
        {   /* ADVERSARY (iv): a stolen session token, and nothing else. */
            dsso_authn_possession forged = po;
            uint8_t n2[32];
            forged.proof[0] ^= 0x01;
            mk32(n2, "dsso-authn-selftest/nonce/A-revoke-stolen");
            CHECK(dsso_authn_revoke_device(&ST, sid2, &forged, d3.id, n2, now, now) == DSSO_E_CRYPTO,
                  "E1b revoke: a STOLEN SESSION TOKEN without the device revokes nothing");
        }
        CHECK(dsso_authn_revoke_device(&ST, sid2, &po, d3.id, nonce,
                                       now, now) == DSSO_OK,
              "E2 revoke: device 3 is revoked with the session + device 1");
        CHECK(dsso_authn_session_verify(&ST, sid2, now, NULL) == DSSO_E_STATUS,
              "E3 revoke: a session issued BEFORE the revocation STOPS VERIFYING");
        CHECK(dsso_authn_session_verify(&ST, sid, now, NULL) == DSSO_E_STATUS,
              "E4 revoke: EVERY concurrent session for the account dies, not just the caller's");
        CHECK(dsso_authn_assertion_authorize(&ST, sid2, DSSO_LOA_LOW, now) == DSSO_E_STATUS,
              "E5 revoke: the assertion layer refuses the revoked session too");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d3, "A-d3-after-revoke", now,
                    junk, NULL) == DSSO_E_STATUS,
              "E6 revoke: the revoked device can no longer authenticate");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-d1-after-revoke", now,
                    sid, &loa) == DSSO_OK && loa == DSSO_LOA_SUBSTANTIAL,
              "E7 revoke: the surviving device is unaffected");
    }

    /* ══ F. the loss / recovery state machine ══════════════════════════════ */
    printf("\n-- F. loss and recovery: one factor may only REDUCE assurance --\n");
    {
        dsso_authn_evidence e;
        dsso_authn_knowledge kn;
        dsso_authn_possession po;
        dsso_pid_attestation pC;
        uint8_t aux[32], chal[32];
        determ_sha256_ctx h;
        const uint8_t dl = (uint8_t)strlen("DSSO-authn-v1-aux");
        uint8_t evb;

        tdev_new(&dC, "dC");
        tdev_new(&dR, "dR");
        tdev_new(&dN, "dN");
        mk_pid(&pC, "C", "C-enrol", now);
        rc = dsso_authn_enrol_first(&ST, acctC, &pC, dC.id, dC.pk, kvC, now);
        CHECK(rc == DSSO_OK && dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_SUBSTANTIAL,
              "F1 recovery: fixture account C is ACTIVE at SUBSTANTIAL");

        /* refusal first: restore a device on the knowledge factor ALONE */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-restore-nopid");
        e.timestamp = now;
        e.new_device = dR.id; e.new_pk = dR.pk;
        evb = (uint8_t)DSSO_AUTHN_EV_RESTORE_DEVICE;
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &evb, 1);
        determ_sha256_update(&h, dR.id, DSSO_AUTHN_ID_LEN);
        determ_sha256_update(&h, dR.pk, DSSO_AUTHN_PK_LEN);
        determ_sha256_final(&h, aux);
        dsso_authn_knowledge_tag(kn.tag, kvC, DSSO_AUTHN_P_RECOVER, acctC, e.nonce,
                                 CL.set_digest, e.timestamp, aux);
        e.knowledge = &kn;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_DEVICE, &e, now)
                  == DSSO_E_ASSURANCE,
              "F2 recovery: RESTORE_DEVICE on the password ALONE is REFUSED (no second evidence)");

        /* the permitted reduction: declare the device lost, on knowledge only */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-devlost");
        e.timestamp = now;
        evb = (uint8_t)DSSO_AUTHN_EV_DEVICE_LOST;
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &evb, 1);
        determ_sha256_final(&h, aux);
        dsso_authn_knowledge_tag(kn.tag, kvC, DSSO_AUTHN_P_RECOVER, acctC, e.nonce,
                                 CL.set_digest, e.timestamp, aux);
        e.knowledge = &kn;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_DEVICE_LOST, &e, now) == DSSO_OK,
              "F3 recovery: DEVICE_LOST on the knowledge factor alone is ACCEPTED (it only takes capability away)");
        CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_KNOWLEDGE_ONLY &&
              dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_LOW,
              "F4 recovery: the account is KNOWLEDGE_ONLY and the DOWNGRADE TO LOW IS VISIBLE");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctC, kvC, NULL, "C-low-login", now, sidLow, &loa)
                  == DSSO_OK && loa == DSSO_LOA_LOW,
              "F5 recovery: the degraded account still logs in — at LOW, not SUBSTANTIAL");
        CHECK(dsso_authn_assertion_authorize(&ST, sidLow, DSSO_LOA_LOW, now) == DSSO_OK,
              "F6 recovery: the assertion layer accepts that session for a LOW relying party");
        CHECK(dsso_authn_assertion_authorize(&ST, sidLow, DSSO_LOA_SUBSTANTIAL, now)
                  == DSSO_E_ASSURANCE,
              "F7 recovery: the assertion layer REFUSES it for a SUBSTANTIAL relying party");
        {   /* and it cannot enrol its way back to two factors */
            uint8_t nonce[32];
            mk32(nonce, "dsso-authn-selftest/nonce/C-low-enrol");
            CHECK(dsso_authn_enrol_device(&ST, sidLow, NULL, dR.id, dR.pk, nonce, now, now) == DSSO_E_ASSURANCE,
                  "F8 recovery: a LOW session cannot enrol a device (no password-only way back)");
        }
        /* the restoration: knowledge + a fresh PID for the RIGHT subject */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-restore-wrongsubj");
        e.timestamp = now;
        e.new_device = dR.id; e.new_pk = dR.pk;
        evb = (uint8_t)DSSO_AUTHN_EV_RESTORE_DEVICE;
        {   /* aux folds in the presentation id exactly as the module does */
            dsso_pid_attestation wrong;
            mk_pid(&wrong, "B", "C-restore-wrong", now);   /* someone else's PID */
            determ_sha256_init(&h);
            determ_sha256_update(&h, &dl, 1);
            determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
            determ_sha256_update(&h, &evb, 1);
            determ_sha256_update(&h, wrong.presentation_id, DSSO_AUTHN_ID_LEN);
            determ_sha256_update(&h, dR.id, DSSO_AUTHN_ID_LEN);
            determ_sha256_update(&h, dR.pk, DSSO_AUTHN_PK_LEN);
            determ_sha256_final(&h, aux);
            dsso_authn_knowledge_tag(kn.tag, kvC, DSSO_AUTHN_P_RECOVER, acctC,
                                     e.nonce, CL.set_digest, e.timestamp, aux);
            e.knowledge = &kn; e.pid = &wrong;
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_DEVICE, &e, now)
                      == DSSO_E_BINDING,
                  "F9 recovery: a VERIFIED PID for ANOTHER SUBJECT cannot recover this account");
        }
        {
            dsso_pid_attestation right;
            mk_pid(&right, "C", "C-restore", now);
            memset(&e, 0, sizeof e);
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-restore-ok");
                e.timestamp = now;
            e.new_device = dR.id; e.new_pk = dR.pk; e.pid = &right;
            determ_sha256_init(&h);
            determ_sha256_update(&h, &dl, 1);
            determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
            determ_sha256_update(&h, &evb, 1);
            determ_sha256_update(&h, right.presentation_id, DSSO_AUTHN_ID_LEN);
            determ_sha256_update(&h, dR.id, DSSO_AUTHN_ID_LEN);
            determ_sha256_update(&h, dR.pk, DSSO_AUTHN_PK_LEN);
            determ_sha256_final(&h, aux);
            dsso_authn_knowledge_tag(kn.tag, kvC, DSSO_AUTHN_P_RECOVER, acctC,
                                     e.nonce, CL.set_digest, e.timestamp, aux);
            e.knowledge = &kn;
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_DEVICE, &e, now)
                      == DSSO_OK,
                  "F10 recovery: knowledge + a fresh subject-matched PID restores the device");
            CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_ACTIVE &&
                  dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_SUBSTANTIAL,
                  "F11 recovery: the account is ACTIVE at SUBSTANTIAL again");
            CHECK(dsso_authn_session_verify(&ST, sidLow, now, NULL) == DSSO_E_STATUS,
                  "F12 recovery: sessions minted before the recovery stop verifying");
        }
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctC, kvC, &dR, "C-after-restore", now, sid2, &loa)
                  == DSSO_OK && loa == DSSO_LOA_SUBSTANTIAL,
              "F13 recovery: the replacement device authenticates at SUBSTANTIAL");

        /* password forgotten, device held */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-pwlost");
        e.timestamp = now;
        evb = (uint8_t)DSSO_AUTHN_EV_PASSWORD_LOST;
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &evb, 1);
        determ_sha256_final(&h, aux);
        dsso_authn_challenge(chal, DSSO_AUTHN_P_RECOVER, acctC, dR.id, e.nonce,
                             CL.set_digest, e.timestamp, NULL, aux);
        dsso_authn_possession_sign(&po, dR.sk, dR.pk, dR.id, chal);
        e.possession = &po;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_PASSWORD_LOST, &e, now) == DSSO_OK,
              "F14 recovery: PASSWORD_LOST on the possession factor alone is ACCEPTED");
        CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_POSSESSION_ONLY &&
              dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_LOW,
              "F15 recovery: the account is POSSESSION_ONLY and visibly LOW");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctC, NULL, &dR, "C-poss-login", now, sidLow, &loa)
                  == DSSO_OK && loa == DSSO_LOA_LOW,
              "F16 recovery: the device alone logs in at LOW");
        CHECK(dsso_authn_assertion_authorize(&ST, sidLow, DSSO_LOA_SUBSTANTIAL, now)
                  == DSSO_E_ASSURANCE,
              "F17 recovery: and cannot buy a SUBSTANTIAL assertion");
        {   /* SESSION BINDING, ISOLATED. In a two-factor login the knowledge
             * tag already carries the nonce, so a cross-session replay fails
             * even if the challenge itself forgot the nonce. Here there is NO
             * knowledge tag, so the challenge's own session field is the only
             * thing standing between a captured device response and a replay
             * into a fresh session. */
            dsso_authn_possession po2;
            dsso_authn_login_req req2;
            uint8_t na[32], nb[32], ch[32];
            mk32(na, "dsso-authn-selftest/nonce/C-poss-sess-a");
            mk32(nb, "dsso-authn-selftest/nonce/C-poss-sess-b");
            dsso_authn_challenge(ch, DSSO_AUTHN_P_LOGIN, acctC, dR.id, na,
                                 CL.set_digest, now, NULL, NULL);
            dsso_authn_possession_sign(&po2, dR.sk, dR.pk, dR.id, ch);
            memset(&req2, 0, sizeof req2);
            memcpy(req2.account, acctC, 32); memcpy(req2.nonce, nb, 32);
            /* SAME account, SAME timestamp, SAME server set, SAME device — the
             * session nonce is the only field that differs. */
            req2.timestamp = now; req2.possession = &po2;
            dsso_authn_cluster_gossip(&CL, now);
            CHECK(dsso_authn_login(&ST, &CL, SUB012, 3, &req2, now, junk, NULL)
                      == DSSO_E_CRYPTO,
                  "F17b recovery: a captured device response CANNOT be replayed into another session (the challenge itself binds the session)");
        }

        /* restore the password: possession + PID, never possession alone */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-pwrestore-nopid");
        e.timestamp = now;
        e.new_knowledge_verifier = kvC2;
        evb = (uint8_t)DSSO_AUTHN_EV_RESTORE_PASSWORD;
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &evb, 1);
        determ_sha256_update(&h, kvC2, DSSO_AUTHN_ID_LEN);
        determ_sha256_final(&h, aux);
        dsso_authn_challenge(chal, DSSO_AUTHN_P_RECOVER, acctC, dR.id, e.nonce,
                             CL.set_digest, e.timestamp, NULL, aux);
        dsso_authn_possession_sign(&po, dR.sk, dR.pk, dR.id, chal);
        e.possession = &po;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_PASSWORD, &e, now)
                  == DSSO_E_ASSURANCE,
              "F18 recovery: RESTORE_PASSWORD on the device ALONE is REFUSED");
        {
            dsso_pid_attestation pr;
            mk_pid(&pr, "C", "C-pwrestore", now);
            memset(&e, 0, sizeof e);
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-pwrestore-ok");
                e.timestamp = now;
            e.new_knowledge_verifier = kvC2; e.pid = &pr;
            determ_sha256_init(&h);
            determ_sha256_update(&h, &dl, 1);
            determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
            determ_sha256_update(&h, &evb, 1);
            determ_sha256_update(&h, pr.presentation_id, DSSO_AUTHN_ID_LEN);
            determ_sha256_update(&h, kvC2, DSSO_AUTHN_ID_LEN);
            determ_sha256_final(&h, aux);
            dsso_authn_challenge(chal, DSSO_AUTHN_P_RECOVER, acctC, dR.id, e.nonce,
                                 CL.set_digest, e.timestamp, NULL, aux);
            dsso_authn_possession_sign(&po, dR.sk, dR.pk, dR.id, chal);
            e.possession = &po;
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_PASSWORD, &e, now)
                      == DSSO_OK,
                  "F19 recovery: possession + a fresh subject-matched PID restores the password");
            CHECK(dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_SUBSTANTIAL,
                  "F20 recovery: SUBSTANTIAL again");
            now += 10; dsso_authn_cluster_gossip(&CL, now);
            CHECK(login(&ST, &CL, SUB012, 3, acctC, kvC2, &dR, "C-newpw", now, sid2, &loa)
                      == DSSO_OK && loa == DSSO_LOA_SUBSTANTIAL,
                  "F21 recovery: the NEW password + the device authenticate");
            now += 10; dsso_authn_cluster_gossip(&CL, now);
            CHECK(login(&ST, &CL, SUB012, 3, acctC, kvC, &dR, "C-oldpw", now, junk, NULL)
                      == DSSO_E_CRYPTO,
                  "F22 recovery: the OLD password no longer authenticates");
        }

        /* both lost: the panic button, then the PID-only rebuild */
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-bothlost");
        e.timestamp = now;
        evb = (uint8_t)DSSO_AUTHN_EV_BOTH_LOST;
        determ_sha256_init(&h);
        determ_sha256_update(&h, &dl, 1);
        determ_sha256_update(&h, (const uint8_t *)"DSSO-authn-v1-aux", dl);
        determ_sha256_update(&h, &evb, 1);
        determ_sha256_final(&h, aux);
        dsso_authn_knowledge_tag(kn.tag, kvC2, DSSO_AUTHN_P_RECOVER, acctC, e.nonce,
                                 CL.set_digest, e.timestamp, aux);
        e.knowledge = &kn;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_BOTH_LOST, &e, now) == DSSO_OK,
              "F23 recovery: BOTH_LOST is authorised by either surviving factor (it only removes capability)");
        CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_LOCKED &&
              dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_NONE,
              "F24 recovery: the account is LOCKED and reports NONE");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctC, kvC2, &dR, "C-locked", now, junk, NULL)
                  == DSSO_E_STATUS,
              "F25 recovery: a LOCKED account cannot authenticate at all");
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-locked-restore-dev");
        e.timestamp = now; e.new_device = dC.id; e.new_pk = dC.pk;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_DEVICE, &e, now)
                  == DSSO_E_STATUS,
              "F26 recovery: no partial route out of LOCKED — only a full re-proofing");
        memset(&e, 0, sizeof e);
        mk32(e.nonce, "dsso-authn-selftest/nonce/C-restoreboth-nopid");
        e.timestamp = now;
        e.new_device = dN.id; e.new_pk = dN.pk; e.new_knowledge_verifier = kvC;
        CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                  == DSSO_E_ASSURANCE,
              "F27 recovery: RESTORE_BOTH without a PID presentation is REFUSED");
        {
            dsso_pid_attestation pr;
            mk_pid(&pr, "C", "C-restoreboth", now);
            memset(&e, 0, sizeof e);
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-recycle");
                e.timestamp = now;
            e.new_device = dC.id; e.new_pk = dC.pk;   /* an id already enrolled */
            e.new_knowledge_verifier = kvC; e.pid = &pr;
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                      == DSSO_E_REPLAY,
                  "F27b recovery: a device id that was already enrolled is never recycled");
            CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_LOCKED,
                  "F27c recovery: and that refusal left the account exactly as it was");
            e.new_device = dN.id; e.new_pk = dN.pk;
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-restoreboth-ok");
            pc.accept = 0;
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                      == DSSO_E_ASSURANCE,
                  "F28 recovery: a PID the verifier REJECTS does not recover the account");
            pc.accept = 1;
            dsso_authn_set_pid_verifier(&ST, NULL, NULL);
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-restoreboth-unavail");
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                      == DSSO_E_UNAVAILABLE,
                  "F29 recovery: with the PID verifier UNREACHABLE the recovery fails CLOSED");
            dsso_authn_set_pid_verifier(&ST, pid_stub, &pc);
            mk32(e.nonce, "dsso-authn-selftest/nonce/C-restoreboth-final");
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                      == DSSO_OK,
                  "F30 recovery: a fresh subject-matched PID rebuilds both factors");
            CHECK(dsso_authn_account_state(&ST, acctC) == DSSO_ACC_ACTIVE &&
                  dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_SUBSTANTIAL,
                  "F31 recovery: ACTIVE at SUBSTANTIAL after the re-proofed enrolment");
            CHECK(dsso_authn_recover(&ST, acctC, DSSO_AUTHN_EV_RESTORE_BOTH, &e, now)
                      == DSSO_E_REPLAY,
                  "F32 recovery: the same recovery cannot be replayed (single-use nonce)");
        }
    }

    /* ══ G. the aggregate attempt limiter ══════════════════════════════════ */
    printf("\n-- G. the aggregate limiter: subset rotation does not buy attempts --\n");
    {
        uint8_t ids[5][DSSO_AUTHN_ID_LEN];
        dsso_authn_cluster LC;
        char buf[64];
        uint64_t t = T0 + 100000;      /* well inside one window              */
        for (i = 0; i < 5; ++i) {
            snprintf(buf, sizeof buf, "dsso-authn-selftest/server/%d", i);
            mk32(ids[i], buf);
        }
        dsso_authn_cluster_init(&LC, 5, 3, &ids[0][0], CAP, WINDOW, MERGE_AGE, t);
        served = 0;
        for (i = 0; i < 10; ++i) {
            dsso_authn_cluster_gossip(&LC, t);
            if (dsso_authn_cluster_meter(&LC, ROT[i], 3, acctA, t) == DSSO_OK) served++;
        }
        /* cap 12, t = 3 → floor(12/3) = 4 attempts, whatever subsets are used */
        CHECK(served == 4,
              "G1 limiter: an attacker rotating EVERY 3-subset gets exactly floor(cap/t) = 4 attempts");
        dsso_authn_cluster_gossip(&LC, t);
        CHECK(dsso_authn_cluster_meter(&LC, ROT[5], 3, acctA, t) == DSSO_E_RATELIMIT,
              "G2 limiter: the next attempt on a FRESH subset is DSSO_E_RATELIMIT");
        {
            int all12 = 1;
            for (i = 0; i < 5; ++i)
                if (dsso_authn_meter_total(&LC, (uint8_t)i, acctA, t) != CAP) all12 = 0;
            CHECK(all12,
                  "G3 limiter: every server agrees the aggregate is exactly the cap (the counter is shared, not per-server)");
        }
        /* another user is untouched */
        CHECK(dsso_authn_cluster_meter(&LC, ROT[0], 3, acctB, t) == DSSO_OK,
              "G4 limiter: another account's budget is untouched by this one's failures");
        dsso_authn_cluster_gossip(&LC, t);
        CHECK(dsso_authn_meter_total(&LC, 0, acctB, t) == 3,
              "G5 limiter: that account's own counter moved by exactly t");
        /* a stale view refuses to serve rather than serving blind */
        CHECK(dsso_authn_cluster_meter(&LC, ROT[0], 3, acctB, t + MERGE_AGE + 1)
                  == DSSO_E_UNAVAILABLE,
              "G6 limiter: a server whose view is STALE refuses to serve (fail closed, never allow-on-outage)");
        /* a new window starts a new budget */
        dsso_authn_cluster_gossip(&LC, t + WINDOW);
        rc = dsso_authn_cluster_meter(&LC, ROT[0], 3, acctA, t + WINDOW);
        dsso_authn_cluster_gossip(&LC, t + WINDOW);
        CHECK(rc == DSSO_OK &&
              dsso_authn_meter_total(&LC, 0, acctA, t + WINDOW) == 3,
              "G7 limiter: a new window starts a fresh budget (the cap is per window)");
    }
    /* the limiter on the real login path, and the success clear */
    printf("\n-- G'. the limiter on the login path --\n");
    {
        uint8_t ids[5][DSSO_AUTHN_ID_LEN];
        dsso_authn_cluster LC;
        dsso_pid_attestation pD;
        char buf[64];
        uint64_t t = T0 + 200000;
        uint32_t before, after;
        for (i = 0; i < 5; ++i) {
            snprintf(buf, sizeof buf, "dsso-authn-selftest/server/%d", i);
            mk32(ids[i], buf);
        }
        dsso_authn_cluster_init(&LC, 5, 3, &ids[0][0], CAP, WINDOW, MERGE_AGE, t);
        tdev_new(&dD, "dD");
        mk_pid(&pD, "D", "D-enrol", t);
        CHECK(dsso_authn_enrol_first(&ST, acctD, &pD, dD.id, dD.pk, kvD, t) == DSSO_OK,
              "G8 limiter: fixture account D enrolled");
        before = dsso_authn_meter_total(&LC, 0, acctD, t);
        dsso_authn_cluster_gossip(&LC, t);
        CHECK(login(&ST, &LC, SUB012, 3, acctD, kvWrong, &dD, "D-bad-1", t, junk, NULL)
                  == DSSO_E_CRYPTO,
              "G9 limiter: a wrong-password login is rejected");
        dsso_authn_cluster_gossip(&LC, t);
        after = dsso_authn_meter_total(&LC, 0, acctD, t);
        CHECK(before == 0 && after == 3,
              "G10 limiter: the FAILED attempt still cost budget (metering precedes verification)");
        dsso_authn_cluster_gossip(&LC, t);
        (void)login(&ST, &LC, SUB012, 3, acctD, kvWrong, &dD, "D-bad-2", t, junk, NULL);
        dsso_authn_cluster_gossip(&LC, t);
        (void)login(&ST, &LC, SUB013, 3, acctD, kvWrong, &dD, "D-bad-3", t, junk, NULL);
        dsso_authn_cluster_gossip(&LC, t);
        CHECK(dsso_authn_meter_total(&LC, 4, acctD, t) == 9,
              "G11 limiter: three failed attempts across two subsets total 9, seen by a server that served none of them");
        CHECK(login(&ST, &LC, SUB012, 3, acctD, kvD, &dD, "D-good", t, sid2, &loa) == DSSO_OK
                  && loa == DSSO_LOA_SUBSTANTIAL,
              "G12 limiter: the legitimate user is still inside the budget and logs in");
        dsso_authn_cluster_gossip(&LC, t);
        {
            int allzero = 1;
            for (i = 0; i < 5; ++i)
                if (dsso_authn_meter_total(&LC, (uint8_t)i, acctD, t) != 0) allzero = 0;
            CHECK(allzero,
                  "G13 limiter: a successful two-factor login CLEARS the account's budget across the whole set");
        }
        CHECK(dsso_authn_cluster_meter(&LC, ROT[0], 2, acctD, t) == DSSO_OK &&
              dsso_authn_cluster_meter(&LC, ROT[0], 9, acctD, t) == DSSO_E_ARG,
              "G14 limiter: a subset larger than the set is refused as a bad argument");
        {
            uint8_t dup[3]; dup[0] = 1; dup[1] = 1; dup[2] = 2;
            CHECK(dsso_authn_cluster_meter(&LC, dup, 3, acctD, t) == DSSO_E_ARG,
                  "G15 limiter: a 'subset' that names the same server twice is refused (no self-quorum)");
        }
    }

    /* ══ H. what the assertion layer reads ═════════════════════════════════ */
    printf("\n-- H. the assurance report the assertion layer consumes --\n");
    {
        uint8_t unknown[32];
        mk32(unknown, "dsso-authn-selftest/session/unknown");
        CHECK(dsso_authn_account_loa(&ST, acctA) == DSSO_LOA_SUBSTANTIAL &&
              dsso_authn_account_loa(&ST, acctC) == DSSO_LOA_SUBSTANTIAL,
              "H1 report: an ACTIVE account reports SUBSTANTIAL");
        CHECK(dsso_authn_account_loa(&ST, unknown) == DSSO_LOA_NONE &&
              dsso_authn_account_state(&ST, unknown) == DSSO_ACC_NONE,
              "H2 report: an unknown account reports NONE, never a default level");
        CHECK(dsso_authn_session_verify(&ST, unknown, now, NULL) == DSSO_E_BINDING,
              "H3 report: an unknown session token does not verify");
        now += 10; dsso_authn_cluster_gossip(&CL, now);
        CHECK(login(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-final", now, sid, &loa) == DSSO_OK,
              "H4 report: a fresh session for the final checks");
        CHECK(dsso_authn_session_verify(&ST, sid, now + SESSION_TTL, NULL) == DSSO_E_EXPIRED,
              "H5 report: a session past its lifetime does not verify");
        CHECK(dsso_authn_assertion_authorize(&ST, sid, DSSO_LOA_SUBSTANTIAL, now) == DSSO_OK,
              "H6 report: the assertion layer accepts a two-factor session at SUBSTANTIAL");
        CHECK(dsso_authn_assertion_authorize(&ST, sid,
                  (dsso_loa)(DSSO_LOA_SUBSTANTIAL + 1), now) == DSSO_E_ASSURANCE,
              "H7 report: NOTHING here reaches above SUBSTANTIAL — there is no 'high' path");
        CHECK(!strcmp(dsso_loa_name(DSSO_LOA_SUBSTANTIAL), "SUBSTANTIAL") &&
              !strcmp(dsso_loa_name(DSSO_LOA_LOW), "LOW") &&
              !strcmp(dsso_loa_name((dsso_loa)99), "UNKNOWN"),
              "H8 report: levels name themselves for operator logs, unknown is named not dereferenced");
        CHECK(!strcmp(dsso_acc_state_name(DSSO_ACC_KNOWLEDGE_ONLY), "KNOWLEDGE_ONLY") &&
              !strcmp(dsso_acc_state_name((dsso_acc_state)99), "UNKNOWN"),
              "H9 report: account states name themselves too");
        CHECK(!strcmp(dsso_status_name(DSSO_E_RATELIMIT), "DSSO_E_RATELIMIT"),
              "H10 report: the rate-limit status names itself");
        {   /* THE SESSION ID IS A BEARER TOKEN. Account, nonce and timestamp
             * all travel in the login request, so if the id were their hash any
             * observer of that request could mint the token. Two deployments
             * differing ONLY in their server-side session secret must issue
             * different ids for the byte-identical login. */
            uint8_t ssec2[32], sidA[32], sidB[32];
            dsso_pid_attestation p2;
            mk32(ssec2, "dsso-authn-selftest/session-secret-2");
            dsso_authn_init(&ST2, ssec2, SESSION_TTL, SKEW);
            dsso_authn_bind_server_set(&ST2, CL.set_digest);
            dsso_authn_set_pid_verifier(&ST2, pid_stub, &pc);
            mk_pid(&p2, "A", "A-enrol", now);
            CHECK(dsso_authn_enrol_first(&ST2, acctA, &p2, d1.id, d1.pk, kvA, now)
                      == DSSO_OK,
                  "H11 report: a second deployment enrols the same account and device");
            now += 10; dsso_authn_cluster_gossip(&CL, now);
            rc = login(&ST, &CL, SUB012, 3, acctA, kvA, &d1, "A-sid-cmp", now, sidA, NULL);
            dsso_authn_cluster_gossip(&CL, now);
            CHECK(rc == DSSO_OK &&
                  login(&ST2, &CL, SUB012, 3, acctA, kvA, &d1, "A-sid-cmp", now,
                        sidB, NULL) == DSSO_OK &&
                  memcmp(sidA, sidB, 32) != 0,
                  "H12 report: the SAME login yields DIFFERENT session ids under different server secrets (the token is not a function of the request)");
        }
    }

    printf("\n  %s: dsso-authn %s\n", g_fail == 0 ? "PASS" : "FAIL",
           g_fail == 0 ? "all assertions" : "had failures");
    return g_fail == 0 ? 0 : 1;
}
