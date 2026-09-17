/* DSSO relying-party assertion — the §5 token, issued by the IdP and verified
 * by the RP (docs/proofs/v2.25-DSSO-DAPP-SPEC.md §5, security claim C6).
 *
 * THE CONSTRUCTION is the paper's dual keyed hash over the login's co-generated
 * key and the RP's registration key — no signature, no FROST, no block co-sign:
 *
 *   binder = HMAC(sso_key,    DS_BINDER | canon(claim))
 *   tag    = HMAC(tenant_key, DS_TAG    | canon(claim) | binder)
 *
 * WHAT THE RP COMPARES, and why it is this and not something simpler. The RP
 * accepts iff the tag it recomputes over the PRESENTED claim and binder is one
 * of the reference tags the IdP delivered to it over the registered channel.
 * The presenter supplies no tag at all. That is the whole repair of C6:
 *
 *  - an accept rule that is a pure function of tenant_key and presenter-supplied
 *    bytes can always be satisfied by a tenant_key holder — it can just run the
 *    honest minting algorithm with an sso_key of its own. The rule shipped in
 *    `determ test-dsso-assertion` was exactly that, so any tenant_key holder
 *    minted a token for any subject. Consulting a reference the IdP delivered is
 *    the only escape that does not introduce a signature scheme (spec §7).
 *  - the outer leg's message includes canon(claim), so the value the RP checks
 *    commits to every field it will act on. The previous rule MAC'd only the
 *    inner hash, so a legitimate user re-presented one token under any claim.
 *
 * CUSTODY. `tenant_key` is held by the IdP and the ONE RP that registered it,
 * never by a user (spec §1; the §5 sentence that had U compute the outer leg is
 * gone). `sso_key` is held by the user and the IdP, per login. `user_root` is
 * held by the IdP alone. This module transports none of them: it takes keys from
 * its caller and uses them only as HMAC keys.
 *
 * FAIL-CLOSED, as everywhere in this binary: every entry point returns a
 * `dsso_status`, 0 is the only success, outputs are untouched on failure, every
 * length is checked before use, and no state is mutated on a rejected path. */
#ifndef DETERM_DSSO_ASSERTION_H
#define DETERM_DSSO_ASSERTION_H

#include <stddef.h>
#include <stdint.h>

#include "dsso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Bounds. Every one of these is a hard cap checked before use; a hostile
 * input can neither allocate nor loop past them. ─────────────────────────── */
#define DSSO_ASSERT_KEY_LEN        32   /* sso_key / tenant_key / user_root     */
#define DSSO_ASSERT_SUB_LEN        32   /* the pairwise subject identifier      */
#define DSSO_ASSERT_NONCE_LEN      32   /* single-use nonce                     */
#define DSSO_ASSERT_TAG_LEN        32   /* the reference tag (outer leg)        */
#define DSSO_ASSERT_BINDER_LEN     32   /* the login binder (inner leg)         */
#define DSSO_ASSERT_MAX_ID         64   /* iss / aud / sid, each                */
#define DSSO_ASSERT_MAX_CANON     512   /* upper bound on canon(claim)          */

/* How many relying parties one IdP context tracks, how many delivered
 * references and accepted nonces one RP verifier retains. All fixed-size; see
 * the eviction rule on `dsso_rp_verify`. */
/* The reference table is deliberately LARGER than the nonce cache: every
 * accepted assertion consumes one slot in each, and the reference table also
 * carries logins the IdP has issued but the user has not presented yet. Sizing
 * it below the nonce cache would make the reference table, not the replay rule,
 * the binding constraint. */
#define DSSO_ASSERT_MAX_RPS         8
#define DSSO_ASSERT_REF_SLOTS     160
#define DSSO_ASSERT_NONCE_SLOTS   128

/* Default RP policy. `skew` absorbs clock disagreement between IdP and RP;
 * `max_lifetime` is the ceiling on `exp - iat` the RP will accept, whatever the
 * issuer put there. Both are per-verifier so a deployment can tighten them. */
#define DSSO_ASSERT_DEFAULT_SKEW_S          60
#define DSSO_ASSERT_DEFAULT_MAX_LIFETIME_S 300

/* ── The claim ────────────────────────────────────────────────────────────────
 * The SIWE-class statement the IdP asserts. `sub` is PAIRWISE — derived per
 * relying party so two RPs cannot correlate one user (see
 * dsso_pairwise_subject). Every field here is inside the MAC the RP checks;
 * nothing in it is read before that check succeeds. */
typedef struct {
    uint8_t  iss[DSSO_ASSERT_MAX_ID];   size_t iss_len;   /* asserting IdP      */
    uint8_t  sub[DSSO_ASSERT_SUB_LEN];                    /* pairwise subject   */
    uint8_t  aud[DSSO_ASSERT_MAX_ID];   size_t aud_len;   /* intended RP        */
    uint8_t  sid[DSSO_ASSERT_MAX_ID];   size_t sid_len;   /* request/session id */
    uint8_t  nonce[DSSO_ASSERT_NONCE_LEN];                /* single-use         */
    uint64_t iat;                                         /* issued at, seconds */
    uint64_t exp;                                         /* expires at         */
    uint64_t reg_epoch;                                   /* RP registration    */
    uint64_t key_epoch;                                   /* tenant_key epoch   */
} dsso_claim;

/* What the USER presents to the RP. It carries no tag: a presenter-supplied tag
 * is exactly what made the old rule forgeable. */
typedef struct {
    dsso_claim claim;
    uint8_t    binder[DSSO_ASSERT_BINDER_LEN];
} dsso_assertion;

/* One registered relying party, as both sides hold it after v2.18
 * DAPP_REGISTER. `reg_epoch` changes only when the relationship is
 * re-established (and then the pairwise subjects change with it); `key_epoch`
 * changes on every `tenant_key` rotation (and the subjects do NOT). */
typedef struct {
    uint8_t  rp_id[DSSO_ASSERT_MAX_ID]; size_t rp_id_len;
    uint64_t reg_epoch;
    uint64_t key_epoch;
    uint8_t  tenant_key[DSSO_ASSERT_KEY_LEN];
} dsso_rp_binding;

/* What the IdP is asked to assert. `sub` is NOT an input: the IdP derives it
 * (dsso_pairwise_subject) so an integrator cannot assert an arbitrary subject.
 * `aud` defaults to `rp_id` when `aud_len` is 0. */
/* INTEGRATOR OBLIGATION. `aud` and `sid` are asserted as given. The IdP must set
 * them from ITS OWN state — the registered audience, and the session id the RP
 * opened — and never from a value an untrusted party chose. The module cannot
 * tell the difference: it authenticates whatever it is asked to assert. */
typedef struct {
    const uint8_t *rp_id;  size_t rp_id_len;   /* which registered RP           */
    const uint8_t *iss;    size_t iss_len;
    const uint8_t *aud;    size_t aud_len;     /* 0 => use rp_id                */
    const uint8_t *sid;    size_t sid_len;     /* the RP's request/session id   */
    uint8_t        nonce[DSSO_ASSERT_NONCE_LEN];
    uint64_t       iat;
    uint64_t       exp;
} dsso_assert_request;

/* The IdP's view: the relying parties it may assert to. Caller-owned, no heap. */
typedef struct {
    dsso_rp_binding rp[DSSO_ASSERT_MAX_RPS];
    size_t          rp_count;
} dsso_idp;

/* The RP's view: its own registration, the reference tags the IdP has delivered
 * for logins not yet presented, and the nonces it has already accepted. Both
 * tables are fixed-size and evict ONLY entries provably outside their window;
 * see dsso_rp_verify. Caller-owned, no heap — 13,960 bytes on LP64 at the slot
 * counts above; give it static storage rather than a stack frame. */
typedef struct {
    uint8_t  tag[DSSO_ASSERT_TAG_LEN];
    uint64_t expires_at;
    uint8_t  used;                       /* 0 = empty slot                      */
} dsso_ref_slot;

typedef struct {
    uint8_t  nonce[DSSO_ASSERT_NONCE_LEN];
    uint64_t expires_at;
    uint8_t  used;                       /* 0 = empty slot                      */
} dsso_nonce_slot;

typedef struct {
    dsso_rp_binding self;                /* this RP's own registration          */
    uint64_t        skew_s;
    uint64_t        max_lifetime_s;
    dsso_ref_slot   ref[DSSO_ASSERT_REF_SLOTS];
    dsso_nonce_slot nonce[DSSO_ASSERT_NONCE_SLOTS];
} dsso_rp_verifier;

/* ── Pairwise subject ─────────────────────────────────────────────────────────
 * sub = HMAC(user_root, DS_SUB | LP(rp_id) | u64(reg_epoch))
 *
 * `user_root` is a 32-byte per-user secret the IdP alone holds, fixed at
 * enrolment; it is NOT derived from `sso_key`, which is per-login and would make
 * the subject unstable. The result is therefore the SAME for one RP across every
 * login, and DIFFERENT across RPs — two relying parties comparing notes learn
 * nothing, because the key is one neither of them holds.
 *
 * A re-registration (bumped `reg_epoch`) deliberately yields a NEW subject: the
 * relationship was re-established, and carrying the identifier across would hand
 * its new holder the old holder's linkage to every user. Rotate `key_epoch`
 * instead when account continuity is wanted.
 *
 * Returns DSSO_E_ARG on a NULL argument or an rp_id longer than
 * DSSO_ASSERT_MAX_ID; `out_sub` is untouched on any failure. */
dsso_status dsso_pairwise_subject(const uint8_t user_root[DSSO_ASSERT_KEY_LEN],
                                  const uint8_t *rp_id, size_t rp_id_len,
                                  uint64_t reg_epoch,
                                  uint8_t out_sub[DSSO_ASSERT_SUB_LEN]);

/* ── IdP side ─────────────────────────────────────────────────────────────── */

/* Zero an IdP context. Always succeeds unless `idp` is NULL. */
dsso_status dsso_idp_init(dsso_idp *idp);

/* Record a relying party. A second registration of the same `rp_id` REPLACES the
 * first (that is how rotation and re-registration land). DSSO_E_ARG on a bad
 * argument, DSSO_E_UNAVAILABLE when the table is full. */
dsso_status dsso_idp_register_rp(dsso_idp *idp, const dsso_rp_binding *b);

/* Issue an assertion for a completed login.
 *
 * `sso_key` is the key the §4-step-5 OPAQUE-3DH handshake co-generated for THIS
 * login; `user_root` is the per-user IdP secret. The subject is derived here,
 * never taken from the caller. `out` receives the claim + binder the user
 * presents; `out_tag` receives the reference the IdP delivers to the RP over the
 * registered channel — it must NOT be given to the user.
 *
 * DSSO_E_TRUST when `req->rp_id` is not a registered relying party (an unknown
 * RP is rejected at the layer that owns the registry). DSSO_E_ARG on a NULL
 * argument, an over-long field, or `exp <= iat`. Outputs untouched on failure. */
dsso_status dsso_assert_issue(const dsso_idp *idp,
                              const uint8_t sso_key[DSSO_ASSERT_KEY_LEN],
                              const uint8_t user_root[DSSO_ASSERT_KEY_LEN],
                              const dsso_assert_request *req,
                              dsso_assertion *out,
                              uint8_t out_tag[DSSO_ASSERT_TAG_LEN]);

/* Recompute the inner leg for a claim. The user holds `sso_key` too (the AKE
 * co-generated it), so a client can derive its own binder rather than be handed
 * one. Useful to a client integrator; used by the gate to stand in the shoes of
 * a party that holds `tenant_key` but not this login's `sso_key`.
 *
 * DSSO_E_ARG on a NULL argument or a claim whose fields exceed their bounds. */
dsso_status dsso_assert_binder(const uint8_t sso_key[DSSO_ASSERT_KEY_LEN],
                               const dsso_claim *claim,
                               uint8_t out_binder[DSSO_ASSERT_BINDER_LEN]);

/* ── RP side ──────────────────────────────────────────────────────────────── */

/* Initialize a verifier from this RP's own registration. `skew_s` and
 * `max_lifetime_s` are its freshness policy; 0 selects the defaults above.
 * DSSO_E_ARG on a NULL argument or a bad rp_id length. */
dsso_status dsso_rp_init(dsso_rp_verifier *v, const dsso_rp_binding *b,
                         uint64_t skew_s, uint64_t max_lifetime_s);

/* Record a reference tag the IdP delivered over the registered channel.
 * `claim_iat` is the claim's `iat`, used ONLY to compute how long to retain the
 * reference (`iat + max_lifetime + skew`); it authenticates nothing, and the
 * claim's real window is checked against the MAC'd copy at verify time.
 *
 * DSSO_E_UNAVAILABLE when `now` is 0 (no usable clock) or every reference slot
 * is still live; DSSO_E_REPLAY when this exact tag is already held. */
dsso_status dsso_rp_deliver(dsso_rp_verifier *v,
                            const uint8_t tag[DSSO_ASSERT_TAG_LEN],
                            uint64_t claim_iat, uint64_t now);

/* Verify a presented assertion. On DSSO_OK the caller may act on `a->claim` and
 * `out_sub` holds the authenticated pairwise subject; on any failure nothing is
 * written and no table is mutated.
 *
 * `expected_sid` is the request/session THIS verifier is completing — the id the
 * RP itself opened, not anything it read from the presentation. Binding the
 * token to `sid` is only half the job: the verifier must also refuse an
 * assertion minted for a DIFFERENT session, or a party who can influence which
 * `sid` the IdP is asked to assert fixates another user's session (login-CSRF).
 * The check runs AFTER the tag, on an authenticated claim.
 *
 * The order of the checks, and the status each produces:
 *   DSSO_E_ARG         a NULL argument, a length out of range, `exp <= iat`
 *   DSSO_E_UNAVAILABLE `now` is 0 — the clock could not be consulted
 *   DSSO_E_TRUST       the claim's key_epoch/reg_epoch are not this RP's current
 *                      ones (a rotated-out key, or a previous registration)
 *   DSSO_E_CRYPTO      the recomputed tag matches no live delivered reference —
 *                      this is the accept rule, and it is what fails for a
 *                      substituted claim, a forged binder, and a cross-RP replay
 *   DSSO_E_BINDING     the authenticated claim's `sid` is not `expected_sid` —
 *                      the session this verifier is completing
 *   DSSO_E_EXPIRED     `iat > now + skew`, `exp <= now`, or
 *                      `exp - iat > max_lifetime`
 *   DSSO_E_REPLAY      this nonce was accepted before and is still retained
 *   DSSO_E_UNAVAILABLE the nonce cache has no free or expired slot
 *
 * NONCE CACHE AND ITS EVICTION RULE. An accepted nonce is retained until
 * `iat + max_lifetime + skew` (saturating), which is at least `exp + skew` for
 * every claim that passed the clock legs — so it is forgotten only once the
 * clock alone already rejects any token carrying it. On insert the module takes
 * an empty slot, else a slot whose retention has elapsed. It NEVER evicts a live
 * entry: if all DSSO_ASSERT_NONCE_SLOTS are live the verification is REJECTED
 * with DSSO_E_UNAVAILABLE, because accepting while unable to remember is
 * accepting a replay. Only assertions the IdP actually issued reach the insert,
 * so the table cannot be flooded by an unauthenticated party; size the build so
 * DSSO_ASSERT_NONCE_SLOTS exceeds peak accepted logins per retention window.
 * The reference table follows the identical discipline.
 *
 * RESIDUAL, stated rather than hidden: an AUTHENTICATED party can still wedge a
 * verifier by completing DSSO_ASSERT_NONCE_SLOTS real logins inside one
 * retention window, after which honest logins fail closed until entries expire.
 * That is the price of never forgetting a live nonce, and it is the right side
 * of the trade — the alternative accepts replays. The levers are deployment
 * ones: size the table above peak, and apply the per-account login rate limit
 * the spec already requires (v2.25-DSSO-DAPP-SPEC.md §6, online-guessing
 * metering). A per-subject slot quota would bound it further and is NOT
 * implemented here. */
dsso_status dsso_rp_verify(dsso_rp_verifier *v, const dsso_assertion *a,
                           uint64_t now,
                           const uint8_t *expected_sid, size_t expected_sid_len,
                           uint8_t out_sub[DSSO_ASSERT_SUB_LEN]);

/* How many nonce / reference slots are live at `now` — the bound
 * DSSO_ASSERT_NONCE_SLOTS / DSSO_ASSERT_REF_SLOTS is never exceeded. For
 * operators and for the gate that asserts the tables cannot grow. */
size_t dsso_rp_nonce_live(const dsso_rp_verifier *v, uint64_t now);
size_t dsso_rp_ref_live(const dsso_rp_verifier *v, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_ASSERTION_H */
