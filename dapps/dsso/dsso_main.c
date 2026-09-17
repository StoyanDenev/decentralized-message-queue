/* determ-dsso — the DSSO service binary (selftest surface).
 *
 * Every DSSO module registers one `selftest-*` subcommand here; tools/test_*.sh
 * wrappers run them and judge on the single terminal PASS:/FAIL: marker, the same
 * contract the rest of the repository's gates use. Keeping the surface to
 * selftests means this binary has no network listener and no persistent state:
 * an operator deployment composes the modules, and what ships here is the proof
 * that each module behaves as its gate asserts. */
#include <stdio.h>
#include <string.h>

#include "dsso.h"
#include "assertion.h"

int dsso_selftest_core(void);
int dsso_selftest_assertion(void);
int dsso_selftest_pid(void);
int dsso_selftest_authn(void);

static int usage(void) {
    printf("determ-dsso — DSSO service (Sign-In With Determ), off-chain identity DApp\n\n");
    printf("  determ-dsso selftest-core        status codes + constant-time compare\n");
    printf("  determ-dsso selftest-assertion   the §5 RP assertion: issue + verify against\n");
    printf("                                   the IdP's own claim, pairwise subjects,\n");
    printf("                                   freshness, bounded single-use nonce cache\n");
    printf("  determ-dsso selftest-pid         EUDI PID presentations (SD-JWT VC) as a\n");
    printf("                                   Wallet-Relying Party: trust anchors, ES256,\n");
    printf("                                   selective disclosure, holder binding,\n");
    printf("                                   audience/nonce, freshness, status, assurance,\n");
    printf("                                   and the account-binding rules\n");
    printf("  determ-dsso selftest-authn       two-factor login, enrolment/recovery/revocation,\n");
    printf("                                   aggregate attempt limiter (2015/1502 substantial)\n");
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "selftest-core")) return dsso_selftest_core();
    if (!strcmp(argv[1], "selftest-assertion")) return dsso_selftest_assertion();
    if (!strcmp(argv[1], "selftest-pid"))  return dsso_selftest_pid();
    if (!strcmp(argv[1], "selftest-authn")) return dsso_selftest_authn();
    return usage();
}

int dsso_selftest_core(void) {
    int fail = 0;
    /* A gate's own harness must not be the thing under test: check() only
     * reports, and every assertion below is a property of dsso.c. */
    #define CHECK(cond, msg) do { \
        if (cond) printf("  PASS: %s\n", (msg)); \
        else { printf("  FAIL: %s\n", (msg)); fail++; } } while (0)

    static const uint8_t a[4] = {1, 2, 3, 4};
    static const uint8_t b[4] = {1, 2, 3, 4};
    static const uint8_t c[4] = {1, 2, 3, 5};
    CHECK(dsso_ct_equal(a, b, 4) == 1, "ct_equal: equal spans compare equal");
    CHECK(dsso_ct_equal(a, c, 4) == 0, "ct_equal: a difference in the last byte is caught");
    CHECK(dsso_ct_equal(a, c, 3) == 1, "ct_equal: the compare honours the given length");
    CHECK(dsso_ct_equal(NULL, b, 4) == 0, "ct_equal: a NULL operand is not equal to anything");
    CHECK(dsso_ct_equal(a, b, 0) == 1, "ct_equal: an empty compare is vacuously equal");

    CHECK(DSSO_OK == 0, "status: DSSO_OK is 0 and every failure is negative");
    CHECK(DSSO_E_ARG < 0 && DSSO_E_STATUS < 0 && DSSO_E_ASSURANCE < 0,
          "status: the failure codes a caller switches on are all negative");
    CHECK(!strcmp(dsso_status_name(DSSO_E_TRUST), "DSSO_E_TRUST"),
          "status: a code names itself for operator logs");
    CHECK(!strcmp(dsso_status_name((dsso_status)-999), "DSSO_E_UNKNOWN"),
          "status: an unknown code is named, never dereferenced");

    printf("\n  %s: dsso-core %s\n", fail == 0 ? "PASS" : "FAIL",
           fail == 0 ? "all assertions" : "had failures");
    return fail == 0 ? 0 : 1;
    #undef CHECK
}

/* ─────────────────────────────────────────────────────────────────────────────
 * selftest-assertion — the §5 RP assertion module (spec claim C6).
 *
 * Every rejection below fails ON THE UNFIXED RULE, which was
 *     accept iff HMAC(tenant_key, H1'_presented) == H2_presented
 * — a pure function of tenant_key and presenter-chosen bytes, reading neither
 * `sso_key` nor the claim, so any tenant_key holder minted a token for any
 * subject and one honest token authenticated any claim. The fixed rule is
 *     accept iff HMAC(tenant_key, DS_TAG | canon(claim) | binder)
 *                  is one of the reference tags the IdP delivered,
 * with the presenter supplying no tag at all. See dapps/dsso/assertion.h.
 * ───────────────────────────────────────────────────────────────────────────*/

/* Each verifier is ~14 KiB; give them static storage rather than a stack frame. */
static dsso_rp_verifier g_va, g_vb, g_vfill, g_vscratch;
static dsso_idp         g_idp, g_mallory;

static const uint8_t RP_A[]   = "rp.a.example";
static const uint8_t RP_B[]   = "rp.b.example";
static const uint8_t AUD_A[]  = "shop.example";
static const uint8_t AUD_A2[] = "admin.shop.example";
static const uint8_t ISS[]    = "determ-idp";
static const uint8_t SID[]    = "sess-0001";
static const uint8_t SID2[]   = "sess-0002";

#define AS_LEN(x) (sizeof (x) - 1)   /* a string literal without its NUL */

static void fill32(uint8_t out[32], uint8_t seed) {
    int i;
    for (i = 0; i < 32; ++i) out[i] = (uint8_t)(seed ^ (uint8_t)(i * 7 + 3));
}

static void mk_request(dsso_assert_request *r, const uint8_t *rp_id, size_t rp_id_len,
                       const uint8_t *aud, size_t aud_len,
                       const uint8_t *sid, size_t sid_len,
                       uint8_t nonce_seed, uint64_t iat, uint64_t exp) {
    memset(r, 0, sizeof *r);
    r->rp_id = rp_id; r->rp_id_len = rp_id_len;
    r->iss = ISS;     r->iss_len = AS_LEN(ISS);
    r->aud = aud;     r->aud_len = aud_len;
    r->sid = sid;     r->sid_len = sid_len;
    fill32(r->nonce, nonce_seed);
    r->iat = iat; r->exp = exp;
}

int dsso_selftest_assertion(void) {
    int fail = 0;
    #define CHECK(cond, msg) do { \
        if (cond) printf("  PASS: %s\n", (msg)); \
        else { printf("  FAIL: %s\n", (msg)); fail++; } } while (0)

    dsso_rp_binding ba, bb;
    dsso_assert_request req;
    dsso_assertion asrt, asrt2;
    uint8_t tag[DSSO_ASSERT_TAG_LEN], sub[DSSO_ASSERT_SUB_LEN];
    uint8_t sso1[32], sso2[32], mal_sso[32], user_root[32], user_root2[32];
    uint8_t tenant_a[32], tenant_b[32], mal_root[32];
    const uint64_t NOW = 1700000000u, SKEW = 60u, TMAX = 300u;
    dsso_status st;

    printf("=== DSSO §5 RP assertion module (issue / verify / pairwise / freshness) ===\n");

    fill32(sso1, 0x11); fill32(sso2, 0x22); fill32(mal_sso, 0x33);
    fill32(user_root, 0x44); fill32(user_root2, 0x55);
    fill32(tenant_a, 0x66); fill32(tenant_b, 0x77); fill32(mal_root, 0x88);

    memset(&ba, 0, sizeof ba);
    memcpy(ba.rp_id, RP_A, AS_LEN(RP_A)); ba.rp_id_len = AS_LEN(RP_A);
    ba.reg_epoch = 1; ba.key_epoch = 1;
    memcpy(ba.tenant_key, tenant_a, 32);

    memset(&bb, 0, sizeof bb);
    memcpy(bb.rp_id, RP_B, AS_LEN(RP_B)); bb.rp_id_len = AS_LEN(RP_B);
    bb.reg_epoch = 1; bb.key_epoch = 1;
    memcpy(bb.tenant_key, tenant_b, 32);

    CHECK(dsso_idp_init(&g_idp) == DSSO_OK
          && dsso_idp_register_rp(&g_idp, &ba) == DSSO_OK
          && dsso_idp_register_rp(&g_idp, &bb) == DSSO_OK
          && dsso_rp_init(&g_va, &ba, SKEW, TMAX) == DSSO_OK
          && dsso_rp_init(&g_vb, &bb, SKEW, TMAX) == DSSO_OK,
          "setup: two registered relying parties, each with its own tenant_key and verifier");

    /* ── A. the honest flow ───────────────────────────────────────────────── */
    mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
               0x01, NOW, NOW + 120);
    st = dsso_assert_issue(&g_idp, sso1, user_root, &req, &asrt, tag);
    CHECK(st == DSSO_OK, "honest: the IdP issues an assertion for a completed login");
    CHECK(dsso_rp_deliver(&g_va, tag, asrt.claim.iat, NOW) == DSSO_OK,
          "honest: the IdP delivers the reference tag over the registered channel");
    memset(sub, 0, sizeof sub);
    CHECK(dsso_rp_verify(&g_va, &asrt, NOW, SID, AS_LEN(SID), sub) == DSSO_OK
          && dsso_ct_equal(sub, asrt.claim.sub, DSSO_ASSERT_SUB_LEN),
          "honest: the RP accepts and yields the authenticated pairwise subject");

    /* ── B. a tenant_key holder who never completed a login ───────────────── */
    {
        dsso_assertion mal, probe;
        uint8_t mal_tag[DSSO_ASSERT_TAG_LEN], mal_binder[DSSO_ASSERT_BINDER_LEN];

        /* Mallory holds tenant_a — the §5 text put it in every user's hands —
         * and runs the whole IdP algorithm with an sso_key and a user_root of
         * her own. She has completed no login. */
        CHECK(dsso_idp_init(&g_mallory) == DSSO_OK
              && dsso_idp_register_rp(&g_mallory, &ba) == DSSO_OK,
              "forger: a party holding tenant_key can run the IdP algorithm in full");

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID2, AS_LEN(SID2),
                   0x02, NOW, NOW + 120);
        st = dsso_assert_issue(&g_mallory, mal_sso, mal_root, &req, &mal, mal_tag);
        CHECK(st == DSSO_OK, "forger: her mint succeeds locally (she does hold tenant_key)");
        CHECK(dsso_rp_verify(&g_va, &mal, NOW, SID2, AS_LEN(SID2), sub) == DSSO_E_CRYPTO,
              "C6(a): a tenant_key holder who never completed a login CANNOT mint an "
              "accepted token — her tag was never delivered (DSSO_E_CRYPTO)");

        /* Control: the rejection above is the delivered-reference rule and not a
         * broken harness — delivered into a scratch verifier, her own token IS
         * accepted. This is what makes the reference the load-bearing part. */
        CHECK(dsso_rp_init(&g_vscratch, &ba, SKEW, TMAX) == DSSO_OK
              && dsso_rp_deliver(&g_vscratch, mal_tag, mal.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_vscratch, &mal, NOW, SID2, AS_LEN(SID2), sub) == DSSO_OK,
              "control: her token verifies where her own tag was delivered — so the "
              "rejection above is the reference rule, not a broken harness");

        /* The sharper form: she sees the honest CLEARTEXT claim (the RP acts on
         * it, so it is not secret) and recomputes the binder with her own
         * sso_key. Only the login's sso_key reproduces the delivered tag. */
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x03, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &asrt2, tag) == DSSO_OK
              && dsso_rp_deliver(&g_va, tag, asrt2.claim.iat, NOW) == DSSO_OK,
              "setup: a second honest assertion, its reference delivered");
        probe = asrt2;
        CHECK(dsso_assert_binder(mal_sso, &probe.claim, mal_binder) == DSSO_OK,
              "forger: she recomputes the inner leg over the honest cleartext claim");
        memcpy(probe.binder, mal_binder, DSSO_ASSERT_BINDER_LEN);
        CHECK(dsso_rp_verify(&g_va, &probe, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(a): the same claim with a binder from ANOTHER sso_key is rejected — "
              "verification depends on the login's sso_key");
    }

    /* ── C. claim substitution, field by field, against a live reference ──── */
    {
        dsso_assertion t;

        t = asrt2; fill32(t.claim.sub, 0x99);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten SUBJECT is rejected");

        t = asrt2;
        memset(t.claim.aud, 0, sizeof t.claim.aud);
        memcpy(t.claim.aud, AUD_A2, AS_LEN(AUD_A2)); t.claim.aud_len = AS_LEN(AUD_A2);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten AUDIENCE is rejected (the audience is "
              "inside the MAC, not a cleartext string compare)");

        t = asrt2;
        memset(t.claim.sid, 0, sizeof t.claim.sid);
        memcpy(t.claim.sid, SID2, AS_LEN(SID2)); t.claim.sid_len = AS_LEN(SID2);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID2, AS_LEN(SID2), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten SESSION/request id is rejected even by "
              "the verifier completing THAT session (no splicing a token sideways)");
        /* And the other direction: a perfectly valid assertion offered to a
         * verifier completing a different session. Binding sid into the MAC keeps
         * the IdP honest about it; THIS is what stops login-CSRF. */
        CHECK(dsso_rp_verify(&g_va, &asrt2, NOW, SID2, AS_LEN(SID2), sub) == DSSO_E_BINDING,
              "session fixation: a valid assertion minted for session A is rejected by "
              "the verifier completing session B (DSSO_E_BINDING)");

        t = asrt2; fill32(t.claim.nonce, 0xA1);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten NONCE is rejected");

        t = asrt2; t.claim.iat = NOW - 10;          /* still inside the window   */
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten IAT is rejected on the MAC, not merely "
              "on the clock");

        t = asrt2; t.claim.exp = NOW + 119;         /* still inside the window   */
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten EXP is rejected on the MAC, not merely "
              "on the clock");

        t = asrt2;
        memset(t.claim.iss, 0, sizeof t.claim.iss);
        memcpy(t.claim.iss, RP_B, AS_LEN(RP_B)); t.claim.iss_len = AS_LEN(RP_B);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b) substitution: a rewritten ISSUER is rejected");

        t = asrt2; t.binder[0] = (uint8_t)(t.binder[0] ^ 0x01);
        CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "C6(b): a single flipped bit in the binder is rejected");

        /* None of the eight rejections consumed anything: the pristine
         * assertion still verifies. Fail-closed means no state change. */
        CHECK(dsso_rp_verify(&g_va, &asrt2, NOW, SID, AS_LEN(SID), sub) == DSSO_OK,
              "fail-closed: a rejected presentation mutates no state — the pristine "
              "assertion still verifies afterwards");
        CHECK(dsso_rp_verify(&g_va, &asrt2, NOW, SID, AS_LEN(SID), sub) == DSSO_E_REPLAY,
              "replay: the same assertion presented a second time is rejected "
              "(single-use nonce)");
    }

    /* ── D. cross-RP replay ───────────────────────────────────────────────── */
    {
        dsso_assertion a3;
        uint8_t tag3[DSSO_ASSERT_TAG_LEN];
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x04, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &a3, tag3) == DSSO_OK,
              "setup: an assertion issued for relying party A");
        CHECK(dsso_rp_verify(&g_vb, &a3, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "cross-RP: A's assertion presented to B is rejected (B holds a different "
              "tenant_key and a different reference set)");
        CHECK(dsso_rp_deliver(&g_vb, tag3, a3.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_vb, &a3, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "cross-RP: even with A's reference tag injected into B, B rejects — the "
              "tag B recomputes is under B's own tenant_key");
    }

    /* ── E. freshness: expired / not-yet-valid / over-long, plus no clock ──── */
    {
        dsso_assertion e1, e2, e3;
        uint8_t t1[32], t2[32], t3[32];

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x10, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &e1, t1) == DSSO_OK
              && dsso_rp_deliver(&g_va, t1, e1.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_va, &e1, NOW + 200, SID, AS_LEN(SID), sub) == DSSO_E_EXPIRED,
              "freshness: an EXPIRED claim (exp <= now) is rejected after the MAC passes");

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x11, NOW + 200, NOW + 320);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &e2, t2) == DSSO_OK
              && dsso_rp_deliver(&g_va, t2, e2.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_va, &e2, NOW, SID, AS_LEN(SID), sub) == DSSO_E_EXPIRED,
              "freshness: a NOT-YET-VALID claim (iat > now + skew) is rejected");

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x12, NOW, NOW + TMAX + 1);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &e3, t3) == DSSO_OK
              && dsso_rp_deliver(&g_va, t3, e3.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_va, &e3, NOW, SID, AS_LEN(SID), sub) == DSSO_E_EXPIRED,
              "freshness: an OVER-LONG lifetime (exp - iat > T_max) is rejected against "
              "the RP's own policy, whatever the issuer asked for");

        CHECK(dsso_rp_verify(&g_va, &e1, 0, SID, AS_LEN(SID), sub) == DSSO_E_UNAVAILABLE
              && dsso_rp_deliver(&g_va, t1, e1.claim.iat, 0) == DSSO_E_UNAVAILABLE,
              "fail-closed: a clock that cannot be consulted (now == 0) is "
              "DSSO_E_UNAVAILABLE, never an accept");
    }

    /* ── F. unknown relying party, rotated key, previous registration ─────── */
    {
        dsso_assertion u;
        static const uint8_t RP_X[] = "never.registered.example";
        uint8_t tx[32];

        mk_request(&req, RP_X, AS_LEN(RP_X), NULL, 0, SID, AS_LEN(SID),
                   0x20, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &u, tx) == DSSO_E_TRUST,
              "unknown RP: the IdP refuses to assert to a relying party it never "
              "registered (DSSO_E_TRUST)");

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x21, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &u, tx) == DSSO_OK
              && dsso_rp_deliver(&g_va, tx, u.claim.iat, NOW) == DSSO_OK,
              "setup: a valid assertion whose epochs will be tampered with");
        {
            dsso_assertion k = u; k.claim.key_epoch = 2;
            CHECK(dsso_rp_verify(&g_va, &k, NOW, SID, AS_LEN(SID), sub) == DSSO_E_TRUST,
                  "rotation: a claim naming a key_epoch that is not this RP's current one "
                  "is rejected (a rotated-out tenant_key cannot mint)");
        }
        {
            dsso_assertion g = u; g.claim.reg_epoch = 2;
            CHECK(dsso_rp_verify(&g_va, &g, NOW, SID, AS_LEN(SID), sub) == DSSO_E_TRUST,
                  "re-registration: a claim from a previous registration epoch is rejected");
        }
    }

    /* ── G. pairwise subjects ─────────────────────────────────────────────── */
    {
        dsso_assertion pa, pa2, pb;
        uint8_t ta[32], ta2[32], tb[32];
        uint8_t s_reg2[DSSO_ASSERT_SUB_LEN], s_other[DSSO_ASSERT_SUB_LEN];

        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x30, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &pa, ta) == DSSO_OK,
              "pairwise setup: login 1 to relying party A");
        /* A SECOND, DIFFERENT login (a fresh sso_key) for the same user at A. */
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID2, AS_LEN(SID2),
                   0x31, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso2, user_root, &req, &pa2, ta2) == DSSO_OK,
              "pairwise setup: login 2 (a different sso_key) to relying party A");
        mk_request(&req, RP_B, AS_LEN(RP_B), NULL, 0, SID, AS_LEN(SID),
                   0x32, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &pb, tb) == DSSO_OK,
              "pairwise setup: the same user logging in to relying party B");

        CHECK(!dsso_ct_equal(pa.claim.sub, pb.claim.sub, DSSO_ASSERT_SUB_LEN),
              "pairwise: the SAME user yields DIFFERENT subjects to two relying parties "
              "— the two cannot correlate her");
        CHECK(dsso_ct_equal(pa.claim.sub, pa2.claim.sub, DSSO_ASSERT_SUB_LEN)
              && !dsso_ct_equal(sso1, sso2, 32),
              "pairwise: the same user yields the SAME subject to one relying party "
              "across two different logins (stable, though sso_key changed)");

        CHECK(dsso_pairwise_subject(user_root, RP_A, AS_LEN(RP_A), 2, s_reg2) == DSSO_OK
              && !dsso_ct_equal(s_reg2, pa.claim.sub, DSSO_ASSERT_SUB_LEN),
              "pairwise: a RE-REGISTRATION (bumped reg_epoch) rotates the subject — the "
              "new relationship does not inherit the old linkage");
        CHECK(dsso_pairwise_subject(user_root2, RP_A, AS_LEN(RP_A), 1, s_other) == DSSO_OK
              && !dsso_ct_equal(s_other, pa.claim.sub, DSSO_ASSERT_SUB_LEN),
              "pairwise: a different user yields a different subject at the same RP");
    }

    /* ── H. the nonce cache: its bound, and that eviction cannot resurrect ── */
    {
        dsso_assertion f, keep, over;
        uint8_t ft[32], kt[32], ot[32];
        unsigned i;
        int all_ok = 1;
        size_t live_peak = 0;

        CHECK(dsso_rp_init(&g_vfill, &ba, SKEW, TMAX) == DSSO_OK,
              "cache setup: a fresh verifier for the bound + eviction assertions");

        /* Fill NONCE_SLOTS-1 slots at NOW with short-lived claims (retention
         * NOW + T_max + skew = NOW + 360). */
        for (i = 0; i + 1 < DSSO_ASSERT_NONCE_SLOTS; ++i) {
            mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                       0x40, NOW, NOW + 120);
            req.nonce[0] = (uint8_t)(i & 0xff); req.nonce[1] = (uint8_t)(i >> 8);
            if (dsso_assert_issue(&g_idp, sso1, user_root, &req, &f, ft) != DSSO_OK) { all_ok = 0; break; }
            if (dsso_rp_deliver(&g_vfill, ft, f.claim.iat, NOW) != DSSO_OK) { all_ok = 0; break; }
            if (dsso_rp_verify(&g_vfill, &f, NOW, SID, AS_LEN(SID), sub) != DSSO_OK) { all_ok = 0; break; }
            if (dsso_rp_nonce_live(&g_vfill, NOW) > live_peak)
                live_peak = dsso_rp_nonce_live(&g_vfill, NOW);
        }
        CHECK(all_ok && live_peak == (size_t)(DSSO_ASSERT_NONCE_SLOTS - 1),
              "cache: accepted nonces are retained, one slot per accepted assertion");

        /* The last slot goes to a claim issued later and living longer, so it is
         * still inside its window when the short-lived ones have expired. */
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0xC7, NOW + 150, NOW + 150 + TMAX);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &keep, kt) == DSSO_OK
              && dsso_rp_deliver(&g_vfill, kt, keep.claim.iat, NOW + 150) == DSSO_OK
              && dsso_rp_verify(&g_vfill, &keep, NOW + 150, SID, AS_LEN(SID), sub) == DSSO_OK
              && dsso_rp_nonce_live(&g_vfill, NOW + 150) == (size_t)DSSO_ASSERT_NONCE_SLOTS,
              "cache: the cache is now exactly full — DSSO_ASSERT_NONCE_SLOTS live entries");

        /* Full, with every entry live: the next accept FAILS CLOSED. Forgetting a
         * live nonce in order to accept would be accepting a replay. */
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0xC8, NOW + 150, NOW + 150 + TMAX);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &over, ot) == DSSO_OK
              && dsso_rp_deliver(&g_vfill, ot, over.claim.iat, NOW + 150) == DSSO_OK
              && dsso_rp_verify(&g_vfill, &over, NOW + 150, SID, AS_LEN(SID), sub) == DSSO_E_UNAVAILABLE,
              "cache bound: with every slot live the verification is REJECTED "
              "(DSSO_E_UNAVAILABLE) — the cache never grows past its bound and never "
              "forgets a live nonce in order to accept");
        CHECK(dsso_rp_nonce_live(&g_vfill, NOW + 150) == (size_t)DSSO_ASSERT_NONCE_SLOTS,
              "cache bound: the rejected presentation added nothing — the live count is "
              "still exactly at the bound");

        /* Past the short-lived entries' retention (NOW + 360) but not past
         * `keep`'s (NOW + 510). New accepts now evict EXPIRED slots, only those. */
        {
            const uint64_t T2 = NOW + 400;
            unsigned inserted = 0;
            all_ok = 1;
            for (i = 0; i < 16; ++i) {
                mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                           0xD0, T2, T2 + 60);
                req.nonce[0] = 0xEE; req.nonce[1] = (uint8_t)i;
                if (dsso_assert_issue(&g_idp, sso1, user_root, &req, &f, ft) != DSSO_OK) { all_ok = 0; break; }
                if (dsso_rp_deliver(&g_vfill, ft, f.claim.iat, T2) != DSSO_OK) { all_ok = 0; break; }
                if (dsso_rp_verify(&g_vfill, &f, T2, SID, AS_LEN(SID), sub) != DSSO_OK) { all_ok = 0; break; }
                ++inserted;
            }
            CHECK(all_ok && inserted == 16
                  && dsso_rp_nonce_live(&g_vfill, T2) == (size_t)17          /* 16 new + `keep` */
                  && dsso_rp_nonce_live(&g_vfill, T2) <= (size_t)DSSO_ASSERT_NONCE_SLOTS,
                  "cache eviction: once entries are provably outside their window their "
                  "slots are reused — the table is bounded, not growing");
            CHECK(dsso_rp_verify(&g_vfill, &keep, T2, SID, AS_LEN(SID), sub) == DSSO_E_REPLAY,
                  "cache eviction: eviction CANNOT resurrect a used nonce inside its "
                  "window — the still-live entry survived 16 evictions and its replay is "
                  "still rejected");
            /* And the presentation the full cache rejected is accepted now that a
             * slot is free: the fail-closed path really did leave no trace. */
            CHECK(dsso_rp_verify(&g_vfill, &over, T2, SID, AS_LEN(SID), sub) == DSSO_OK,
                  "fail-closed: the assertion the full cache rejected is accepted once a "
                  "slot frees — the rejection consumed nothing");
        }
    }

    /* ── I. the reference table is bounded and fail-closed too ────────────── */
    {
        dsso_assertion r;
        uint8_t rt[32];
        unsigned i;
        int ok = 1;
        dsso_status last = DSSO_OK;
        CHECK(dsso_rp_init(&g_vscratch, &ba, SKEW, TMAX) == DSSO_OK, "ref setup: fresh verifier");
        for (i = 0; i < DSSO_ASSERT_REF_SLOTS + 1; ++i) {
            mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                       0xF0, NOW, NOW + 120);
            req.nonce[0] = (uint8_t)(i & 0xff); req.nonce[1] = (uint8_t)(i >> 8);
            if (dsso_assert_issue(&g_idp, sso1, user_root, &req, &r, rt) != DSSO_OK) { ok = 0; break; }
            last = dsso_rp_deliver(&g_vscratch, rt, r.claim.iat, NOW);
            if (i < DSSO_ASSERT_REF_SLOTS && last != DSSO_OK) { ok = 0; break; }
        }
        CHECK(ok && last == DSSO_E_UNAVAILABLE
              && dsso_rp_ref_live(&g_vscratch, NOW) == (size_t)DSSO_ASSERT_REF_SLOTS,
              "reference table: bounded and fail-closed — a delivery past the bound is "
              "DSSO_E_UNAVAILABLE and no live reference is discarded");
    }

    /* ── J. the tag compare is over the FULL tag ──────────────────────────── */
    {
        dsso_assertion c;
        uint8_t ct[32], tail[32];
        CHECK(dsso_rp_init(&g_vscratch, &ba, SKEW, TMAX) == DSSO_OK, "compare setup");
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x5A, NOW, NOW + 120);
        CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &req, &c, ct) == DSSO_OK,
              "compare setup: an honest assertion");
        memcpy(tail, ct, 32);
        tail[31] = (uint8_t)(tail[31] ^ 0x01);     /* differs ONLY in the last byte */
        CHECK(dsso_rp_deliver(&g_vscratch, tail, c.claim.iat, NOW) == DSSO_OK
              && dsso_rp_verify(&g_vscratch, &c, NOW, SID, AS_LEN(SID), sub) == DSSO_E_CRYPTO,
              "compare: a reference differing from the recomputed tag ONLY in its last "
              "byte is rejected — the compare covers the full tag, not a prefix");
    }

    /* ── K. fail-closed argument handling ─────────────────────────────────── */
    {
        dsso_assertion z;
        uint8_t zt[32] = {0}, zb[32] = {0};
        mk_request(&req, RP_A, AS_LEN(RP_A), AUD_A, AS_LEN(AUD_A), SID, AS_LEN(SID),
                   0x7E, NOW, NOW + 120);
        CHECK(dsso_assert_issue(NULL, sso1, user_root, &req, &z, zt) == DSSO_E_ARG
              && dsso_assert_issue(&g_idp, NULL, user_root, &req, &z, zt) == DSSO_E_ARG
              && dsso_assert_issue(&g_idp, sso1, NULL, &req, &z, zt) == DSSO_E_ARG
              && dsso_assert_issue(&g_idp, sso1, user_root, NULL, &z, zt) == DSSO_E_ARG
              && dsso_assert_issue(&g_idp, sso1, user_root, &req, NULL, zt) == DSSO_E_ARG
              && dsso_assert_issue(&g_idp, sso1, user_root, &req, &z, NULL) == DSSO_E_ARG,
              "fail-closed: every missing input to issue is DSSO_E_ARG");
        CHECK(dsso_rp_verify(NULL, &asrt2, NOW, SID, AS_LEN(SID), sub) == DSSO_E_ARG
              && dsso_rp_verify(&g_va, NULL, NOW, SID, AS_LEN(SID), sub) == DSSO_E_ARG
              && dsso_rp_verify(&g_va, &asrt2, NOW, SID, AS_LEN(SID), NULL) == DSSO_E_ARG
              && dsso_rp_verify(&g_va, &asrt2, NOW, NULL, 0, sub) == DSSO_E_ARG
              && dsso_rp_verify(&g_va, &asrt2, NOW, SID, 0, sub) == DSSO_E_ARG
              && dsso_rp_deliver(NULL, zt, NOW, NOW) == DSSO_E_ARG
              && dsso_rp_deliver(&g_va, NULL, NOW, NOW) == DSSO_E_ARG,
              "fail-closed: every missing input to deliver/verify is DSSO_E_ARG");
        {
            dsso_assert_request bad = req;
            bad.exp = bad.iat;                         /* a zero-length window   */
            CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &bad, &z, zt) == DSSO_E_ARG,
                  "fail-closed: an issue with exp <= iat is DSSO_E_ARG");
            bad = req; bad.sid_len = 0;
            CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &bad, &z, zt) == DSSO_E_ARG,
                  "fail-closed: an issue with no session id is DSSO_E_ARG");
            bad = req; bad.iss_len = DSSO_ASSERT_MAX_ID + 1;
            CHECK(dsso_assert_issue(&g_idp, sso1, user_root, &bad, &z, zt) == DSSO_E_ARG,
                  "fail-closed: a field past its cap is DSSO_E_ARG, never a truncation");
        }
        {
            dsso_assertion t = asrt2;
            t.claim.aud_len = 0;
            CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_ARG,
                  "fail-closed: a presented claim with an empty audience is DSSO_E_ARG");
            t = asrt2; t.claim.sid_len = DSSO_ASSERT_MAX_ID + 1;
            CHECK(dsso_rp_verify(&g_va, &t, NOW, SID, AS_LEN(SID), sub) == DSSO_E_ARG,
                  "fail-closed: a presented claim with an over-long session id is DSSO_E_ARG");
        }
        CHECK(dsso_pairwise_subject(user_root, RP_A, 0, 1, zb) == DSSO_E_ARG
              && dsso_pairwise_subject(user_root, NULL, 4, 1, zb) == DSSO_E_ARG
              && dsso_pairwise_subject(NULL, RP_A, AS_LEN(RP_A), 1, zb) == DSSO_E_ARG,
              "fail-closed: the pairwise derivation rejects a missing or empty RP id");
    }

    printf("\n  %s: dsso-assertion %s\n", fail == 0 ? "PASS" : "FAIL",
           fail == 0 ? "all assertions" : "had failures");
    return fail == 0 ? 0 : 1;
    #undef CHECK
}
