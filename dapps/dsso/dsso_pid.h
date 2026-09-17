/* dsso_pid — DSSO as a WALLET-RELYING PARTY: accept a Person Identification
 * Data presentation from an EUDI Wallet Unit, verify it, and hand the caller a
 * claim set it may act on.
 *
 * ROLE. Regulation (EU) 2024/1183 Art. 5b. DSSO consumes PID presented by a
 * wallet in order to proof identity at enrolment and bind it to a DSSO account
 * (dsso_bind.h). DSSO is NOT a wallet, NOT a wallet provider, NOT a notified
 * electronic identification scheme and NOT a qualified trust service provider;
 * nothing here may be read as any of those.
 *
 * FORMAT CHOICE — SD-JWT VC, and mdoc is NOT implemented.
 * ARF v2.9.0 OIA_03 / OIA_03b / OIA_04 admit two attestation formats for remote
 * presentation over OpenID4VP: the JOSE/JSON profile (SD-JWT VC) and the
 * ISO/IEC 18013-5 mdoc profiled by ISO/IEC TS 18013-7 Annex B. This increment
 * implements the FIRST and only the first. Three reasons, in order of weight:
 *   1. ATTACK SURFACE. The relying party's parser is the service's front door.
 *      SD-JWT VC needs base64url + JSON; mdoc needs CBOR *and* COSE_Sign1 *and*
 *      the mdoc device-engagement/session structures, and its
 *      IssuerSignedItemBytes are CBOR tag-24 byte strings whose canonical form
 *      (CTAP2/deterministic CBOR) has to be enforced byte-exactly or the
 *      digests can be recomputed over a re-encoding. That is a strictly larger
 *      and strictly subtler surface to write fail-closed, and this repository's
 *      rule is the smallest increment that is true.
 *   2. NO NEW PRIMITIVE. SD-JWT VC with a Key Binding JWT composes entirely
 *      from what determ::c99 already ships — SHA-256 and P-256. ES256 itself is
 *      not exposed by the shipped stack, so it is built here on the shipped
 *      scalar/point operations (dsso_jose.h); no dependency is added.
 *   3. HOLDER BINDING IS EXPLICIT. SD-JWT VC carries `cnf` and a KB-JWT that
 *      signs over audience, nonce and a hash of exactly the presented material,
 *      so OIA_02 is checkable with the same signature machinery as the issuer
 *      signature. mdoc's DeviceAuth is equivalent in intent but needs the
 *      session transcript, i.e. the ISO 18013-7 Annex B handshake as well.
 * CONSEQUENCE, STATED PLAINLY: a wallet that can only present ISO/IEC 18013-5
 * mdoc is OUT OF SCOPE for DSSO until a second increment implements it. DSSO
 * does not negotiate down to a weaker check for such a wallet; it refuses.
 *
 * WHAT IS VERIFIED. Nine rules, each separately testable and each with its own
 * status code, applied in this fixed order (the order matters: nothing that an
 * attacker supplies is acted on before the issuer signature over it verifies):
 *   1 structure          — bounded base64url + bounded JSON       DSSO_E_FORMAT
 *   2 issuer trust       — key from the configured PID Provider
 *                          trust anchor list, never from the token DSSO_E_TRUST
 *   3 signature          — ES256 over the exact signing input     DSSO_E_CRYPTO
 *   4 selective disclos. — every disclosure hashes into `_sd`     DSSO_E_FORMAT
 *   5 holder binding     — KB-JWT by the `cnf` key over this
 *                          presentation (OIA_02)                DSSO_E_BINDING
 *   6a audience          — `aud` is DSSO's own RP identifier    DSSO_E_AUDIENCE
 *   6b request binding   — `nonce` is the one DSSO issued for
 *                          THIS request                          DSSO_E_REPLAY
 *   7 freshness          — iat/nbf/exp, bounded skew and age     DSSO_E_EXPIRED
 *   8 status             — Token Status List, fail-closed
 *                          DSSO_E_STATUS / DSSO_E_UNAVAILABLE
 *   9 assurance          — evidence at or above the required
 *                          level                               DSSO_E_ASSURANCE
 *
 * FAIL-CLOSED. A dependency that cannot be consulted — the status token cannot
 * be fetched, or is stale beyond its own `exp` — is DSSO_E_UNAVAILABLE and the
 * verification FAILS. There is no "allow on outage" path and adding one would
 * be a defect, not a feature.
 *
 * WHAT IS NOT DONE HERE. The wallet-relying-party ACCESS CERTIFICATE of
 * ARF RPA_01..RPA_06 — the certificate DSSO would present TO the wallet, issued
 * after registration with a Member State registrar — is EXTERNAL and is NOT
 * obtained. Nothing in this file authenticates DSSO to a wallet. Neither is the
 * OpenID4VP request/response transport (OIA_03): this module verifies a
 * presentation that some transport already delivered. */
#ifndef DETERM_DSSO_PID_H
#define DETERM_DSSO_PID_H

#include "dsso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Levels of assurance of Commission Implementing Regulation (EU) 2015/1502,
 * ordered so that a numeric comparison is the policy test. */
typedef enum {
    DSSO_LOA_NONE        = 0,
    DSSO_LOA_LOW         = 1,
    DSSO_LOA_SUBSTANTIAL = 2,
    DSSO_LOA_HIGH        = 3
} dsso_loa;

/* One entry of the PID Provider trust anchor list — the repository's stand-in
 * for a Member State Trusted List. `iss` and `kid` are matched EXACTLY against
 * the token's `iss` claim and `kid` header parameter; `pk` is the only key that
 * may verify a credential from that issuer.
 *
 * `max_loa` is the highest level this anchor is ENTITLED to assert. The
 * credential also states its own level, and the effective level is the minimum
 * of the two, so a token cannot talk its issuer up. */
typedef struct {
    const char *iss;
    const char *kid;
    uint8_t     pk[65];        /* SEC1 uncompressed P-256 */
    dsso_loa    max_loa;
} dsso_trust_anchor;

typedef struct {
    const dsso_trust_anchor *a;
    size_t                   n;
} dsso_trust_list;

/* OIA_12 lookup. Returns DSSO_OK and sets *out, or DSSO_E_TRUST. */
int dsso_trust_lookup(const dsso_trust_list *tl,
                      const uint8_t *iss, size_t iss_len,
                      const uint8_t *kid, size_t kid_len,
                      const dsso_trust_anchor **out);

/* Status-token fetch, injected. A gate cannot reach a network, and a verifier
 * that embeds its own transport cannot be driven adversarially, so the fetch is
 * a callback: write the compact-serialization status token for `uri` into
 * `out`, set *outlen, return 0. ANY non-zero return — unreachable, too large,
 * refused — becomes DSSO_E_UNAVAILABLE and the verification fails closed. */
typedef int (*dsso_status_fetch_fn)(void *ctx,
                                    const uint8_t *uri, size_t uri_len,
                                    uint8_t *out, size_t cap, size_t *outlen);

typedef struct {
    const char           *rp_id;         /* DSSO's own relying-party identifier */
    const uint8_t        *nonce;         /* the challenge DSSO issued for THIS  */
    size_t                nonce_len;     /* request                             */
    int64_t               now;           /* POSIX seconds                       */
    int64_t               max_skew;      /* clock tolerance, seconds            */
    int64_t               max_pres_age;  /* KB-JWT iat age ceiling, seconds     */
    int64_t               max_cred_age;  /* issuer iat age ceiling, seconds     */
    dsso_loa              required_loa;
    const dsso_trust_list *trust;
    dsso_status_fetch_fn   fetch;
    void                  *fetch_ctx;
} dsso_pid_policy;

/* Caps on one attribute. Both are REJECT boundaries, never truncations: a claim
 * name or a JSON value text longer than these makes the whole presentation
 * DSSO_E_FORMAT, and a deployment whose PID Provider uses longer identifiers
 * or carries longer attribute values raises them rather than losing bytes. The
 * name cap also bounds the issuer identifier, which is why it is not tighter:
 * a real PID Provider URL runs well past 64 characters. */
#define DSSO_PID_MAX_NAME   128
#define DSSO_PID_MAX_VALUE  192

typedef struct {
    uint8_t name[DSSO_PID_MAX_NAME];
    size_t  name_len;
    uint8_t value[DSSO_PID_MAX_VALUE];   /* the claim's JSON text, verbatim */
    size_t  value_len;
} dsso_pid_claim;

typedef struct {
    dsso_pid_claim claims[DSSO_MAX_CLAIMS];
    size_t         n_claims;
    uint8_t        iss[DSSO_PID_MAX_NAME];
    size_t         iss_len;
    dsso_loa       loa;
    int64_t        cred_iat;
    int64_t        cred_exp;
} dsso_pid_result;

/* Verify one presentation. `presentation` is the SD-JWT VC combined format:
 *
 * SCOPE OF RULE 6b, STATED. This function is STATELESS: it enforces that the
 * presentation's `nonce` EQUALS the one the caller issued, not that the nonce
 * has never been seen before. SINGLE-USE is the caller's responsibility, and
 * for account binding it is dsso_bind.h's challenge record, which is consumed
 * on any attempt. A caller that reuses a nonce across two requests reuses the
 * window in which a captured presentation is valid; DSSO's own callers do not.
 *
 *   <issuer-signed JWT> ~ <disclosure>* ~ <KB-JWT>
 * On DSSO_OK, *out holds the disclosed claims and the effective assurance
 * level. On ANY failure *out is zeroed, so a caller that ignores the status
 * cannot read stale claims out of it. */
int dsso_pid_verify(dsso_slice presentation, const dsso_pid_policy *pol,
                    dsso_pid_result *out);

/* ARF OIA_16 — "discard unique elements and timestamps as soon as they are no
 * longer needed". Zero the whole result. Call it as soon as the claims have
 * been consumed; dsso_bind_commit() calls it on the material it derives from. */
void dsso_pid_result_scrub(dsso_pid_result *r);

/* The stable subject material a pseudonym is derived from: `iss` and the PID's
 * `personal_administrative_number` attribute, length-separated. Returns
 * DSSO_E_FORMAT when that attribute was not disclosed — DSSO cannot bind an
 * account to a subject it cannot name.
 *
 * The bytes this writes are the raw national identifier. They are a transient
 * derivation input and MUST NOT be stored: dsso_bind.h's pseudonym is what a
 * database holds, and dsso_bind_commit() scrubs this buffer before returning. */
int dsso_pid_subject_material(const dsso_pid_result *r,
                              uint8_t *out, size_t cap, size_t *outlen);

/* The named claim's verbatim JSON value text, or DSSO_E_FORMAT. */
int dsso_pid_claim_value(const dsso_pid_result *r, const char *name,
                         dsso_slice *out);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_PID_H */
