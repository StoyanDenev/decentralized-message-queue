/* dsso_bind — binding a verified PID subject to a DSSO account, and unbinding
 * it again.
 *
 * WHY THIS IS A SEPARATE, ENFORCED MODULE AND NOT A CONVENTION. Verifying a
 * presentation says "this wallet holds a PID for some person". Binding says
 * "that person is the owner of DSSO account A". Everything that can go wrong in
 * identity systems lives in the second sentence, so the three failure shapes
 * below are enforced here, in code, rather than described in a deployment note.
 *
 *   (i) A SESSION IS NOT AUTHORISATION. Possession of an existing DSSO session
 *       must never, on its own, authorise binding an identity to that account:
 *       an attacker who steals a session cookie would otherwise staple the
 *       VICTIM'S account to the ATTACKER'S identity (or, worse, the attacker's
 *       account to a victim's identity). So a binding needs BOTH a fresh
 *       presentation answering a challenge issued for THIS binding operation,
 *       AND the account holder's own re-authentication, proved to this module
 *       rather than asserted by the caller (dsso_account_auth).
 *
 *  (ii) ONE SUBJECT, ONE ACCOUNT, AND NO SILENT SWAPS. The same PID subject may
 *       not be bound to two accounts, and an account already bound to one
 *       subject may not be re-bound to another: both are DSSO_E_BINDING, and
 *       the only way through is an explicit, separately authorised unbind.
 *
 * (iii) NO REUSE. A binding challenge is single-use and short-lived, and it is
 *       consumed the moment a presentation is offered against it — success or
 *       failure — so a captured presentation buys nothing later.
 *
 * WHAT IS STORED, AND WHY IT IS A PSEUDONYM.
 * The persistent identifier is
 *      pseudonym = HMAC-SHA256(K_pseu, "DSSO-PID-PSEUDONYM-v1" ‖ iss ‖ subject)
 * where `subject` is the PID's personal_administrative_number and `iss` is the
 * issuer, length-separated (dsso_pid_subject_material). The raw identifier is
 * NEVER stored and is scrubbed before this module returns (ARF OIA_16).
 *
 * Why keyed, and not a plain hash: national identifier spaces are small and
 * structured. A Bulgarian ЕГН or an Estonian isikukood is ~10^10 candidates
 * with most of the entropy in a birth date, so a table of plain SHA-256 values
 * is invertible in CPU-hours — a database leak would BE a population-wide
 * identity list. K_pseu lives outside the account database (an HSM or KMS key
 * in a deployment), so a leak of the database alone yields uncorrelatable
 * 32-byte strings.
 *
 * Why NOT per-account salted: rule (ii) requires comparing subjects ACROSS
 * accounts, which a per-account salt makes impossible. This is a deliberate
 * trade: the pseudonym is service-wide and therefore linkable WITHIN DSSO,
 * which is exactly the linkability rule (ii) is built from, and it is keyed so
 * that it is linkable nowhere else. Identifiers DSSO hands to its own relying
 * parties are a different value and stay pairwise (v2.25-DSSO-DAPP-SPEC §5);
 * this one never leaves the service. */
#ifndef DETERM_DSSO_BIND_H
#define DETERM_DSSO_BIND_H

#include "dsso_pid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSSO_BIND_ID_LEN          32
#define DSSO_BIND_NONCE_LEN       32   /* base64url characters, 192 bits */
#define DSSO_BIND_MAX_ACCOUNTS    32
#define DSSO_BIND_MAX_BINDINGS    32

/* How the account holder proved, to THIS operation, that they are present.
 *
 * DSSO_AUTH_SESSION_ONLY names the thing that is explicitly NOT sufficient: "a
 * request arrived on an authenticated session". It exists as a value so that
 * the rejection is a test the code performs, not an omission a reader has to
 * notice. */
typedef enum {
    DSSO_AUTH_SESSION_ONLY = 0,
    DSSO_AUTH_FRESH        = 1
} dsso_auth_kind;

/* mac = HMAC-SHA256(account auth key,
 *                   "DSSO-ACCT-REAUTH-v1" ‖ account_id ‖ be64(at))
 * — the account's own authentication, replayable only inside the re-auth
 * window, which is what a session cookie is not. */
typedef struct {
    dsso_auth_kind kind;
    int64_t        at;
    uint8_t        mac[32];
} dsso_account_auth;

typedef enum {
    DSSO_BIND_PURPOSE_NONE   = 0,
    DSSO_BIND_PURPOSE_BIND   = 1,
    DSSO_BIND_PURPOSE_UNBIND = 2
} dsso_bind_purpose;

typedef struct {
    uint8_t account_id[DSSO_BIND_ID_LEN];
    uint8_t auth_key[32];
    int     in_use;
    /* At most ONE outstanding binding challenge per account: issuing a new one
     * invalidates the previous, so an old challenge cannot be held in reserve. */
    uint8_t           ch_nonce[DSSO_BIND_NONCE_LEN];
    dsso_bind_purpose ch_purpose;
    int64_t           ch_issued_at;
    int               ch_open;
} dsso_bind_account;

typedef struct {
    uint8_t  account_id[DSSO_BIND_ID_LEN];
    uint8_t  pseudonym[32];
    uint8_t  iss[DSSO_PID_MAX_NAME];
    size_t   iss_len;
    dsso_loa loa;
    int64_t  bound_at;
    int      active;
    int      in_use;
} dsso_binding_record;

typedef struct {
    uint8_t             pseudonym_key[32];
    dsso_bind_account   accounts[DSSO_BIND_MAX_ACCOUNTS];
    dsso_binding_record bindings[DSSO_BIND_MAX_BINDINGS];
    int64_t             challenge_ttl;    /* seconds a binding challenge lives */
    int64_t             reauth_max_age;   /* seconds a re-auth proof lives     */
} dsso_bind_ctx;

/* `pseudonym_key` is the service secret described above; it is copied in. */
int dsso_bind_init(dsso_bind_ctx *c, const uint8_t pseudonym_key[32],
                   int64_t challenge_ttl, int64_t reauth_max_age);

int dsso_bind_account_add(dsso_bind_ctx *c,
                          const uint8_t account_id[DSSO_BIND_ID_LEN],
                          const uint8_t auth_key[32]);

/* Open a binding (or unbinding) operation. Requires the account holder's own
 * fresh authentication: DSSO_AUTH_SESSION_ONLY is DSSO_E_BINDING, a proof
 * outside the re-auth window is DSSO_E_EXPIRED, a proof under the wrong key is
 * DSSO_E_BINDING. `nonce` is DSSO_BIND_NONCE_LEN base64url characters drawn
 * from the service CSPRNG; it becomes the `nonce` the presentation must answer. */
int dsso_bind_challenge_new(dsso_bind_ctx *c,
                            const uint8_t account_id[DSSO_BIND_ID_LEN],
                            const dsso_account_auth *auth,
                            dsso_bind_purpose purpose,
                            const uint8_t nonce[DSSO_BIND_NONCE_LEN],
                            int64_t now);

/* Verify `presentation` AGAINST THIS ACCOUNT'S OPEN BINDING CHALLENGE and, if
 * it passes every rule, bind its subject to the account.
 *
 * The challenge nonce is taken from the account record, not from the caller:
 * that is what makes "this presentation answered the challenge issued for this
 * binding of this account" a structural property rather than a convention a
 * caller could get wrong. `base_pol`'s `nonce`/`nonce_len`/`now` fields are
 * ignored and supplied by this function.
 *
 * Returns whatever dsso_pid_verify returned when the presentation is bad, or
 * DSSO_E_BINDING / DSSO_E_REPLAY / DSSO_E_EXPIRED for the binding rules. On
 * DSSO_OK, `pseudonym_out` (optional) receives the stored pseudonym. */
int dsso_bind_commit(dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     dsso_slice presentation,
                     const dsso_pid_policy *base_pol,
                     int64_t now,
                     uint8_t pseudonym_out[32]);

/* Explicit, separately authorised unbind — the ONLY way an account that is
 * bound to one subject can come to be bound to another. Requires the same
 * fresh account authentication as opening a challenge. */
int dsso_bind_unbind(dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     const dsso_account_auth *auth,
                     int64_t now);

/* DSSO_OK and the pseudonym iff the account has an ACTIVE binding. */
int dsso_bind_lookup(const dsso_bind_ctx *c,
                     const uint8_t account_id[DSSO_BIND_ID_LEN],
                     uint8_t pseudonym_out[32]);

/* The derivation itself, exposed so the gate can assert its properties
 * (stability, issuer domain separation, key dependence) directly. */
int dsso_pseudonym_derive(const uint8_t key[32],
                          const uint8_t *material, size_t material_len,
                          uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_BIND_H */
