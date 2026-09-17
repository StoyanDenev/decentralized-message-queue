/* DSSO user authentication — the second factor, its lifecycle, and the
 * aggregate attempt limiter.
 *
 * THE PROBLEM THIS MODULE EXISTS TO FIX. The shipped DSSO login
 * (docs/proofs/v2.25-DSSO-DAPP-SPEC.md §3-§5) blinds the user's password,
 * evaluates it with a t-of-n threshold OPRF, and uses the result to unseal an
 * envelope holding the user's credential secret key. Every value the user needs
 * is therefore a function of the password: the credential key is a stored secret
 * recovered from knowledge, not an independently held object. Commission
 * Implementing Regulation (EU) 2015/1502 Annex §2.2.1 requires, at level
 * SUBSTANTIAL, "at least two authentication factors from different categories",
 * and §2.3.1 requires the release of person identification data to be preceded
 * by a dynamic authentication. n servers are not n factors — they are ONE factor
 * evaluated in a distributed way — so the shipped login is single-factor and
 * cannot be equivalent to substantial. This module adds the missing factor and
 * the lifecycle machinery that the level requires around it.
 *
 * THE SECOND FACTOR. A P-256 key pair generated ON the user's device from
 * device-local entropy. The secret never leaves the device and is NOT derivable
 * from the password, from the OPRF output, or from anything the servers store —
 * the servers hold only the PUBLIC point and enrolment metadata. At every login
 * the device must answer a FRESH challenge that binds the login session nonce,
 * the server set, a timestamp, the device identity, and the knowledge factor's
 * own response for that same login; the two factors are therefore one
 * authentication, not two that can be spliced from different sessions.
 *
 * WHY A DLEQ PROOF AND NOT ECDSA. The brief for this increment named ECDSA.
 * ECDSA-P256 is NOT shipped in this repository (`docs/proofs/CRYPTO-C99-SPEC.md`
 * lists it under "remaining"), and the mission rule is "no new primitive". The
 * possession proof is therefore the shipped RFC 9497 VOPRF discrete-log-equality
 * proof used as a signature of knowledge: the device publishes `pk = sk·G`,
 * answers a challenge `c` with `eval = sk·H2C(c)` plus the RFC 9497 DLEQ proof
 * that `log_G(pk) == log_{H2C(c)}(eval)`. That is a Chaum-Pedersen signature
 * under Fiat-Shamir — publicly verifiable from `pk` alone, unforgeable without
 * `sk` under the same ECDLP assumption the rest of the DSSO stack already makes,
 * and built ONLY from `determ_p256_hash_to_curve` / `_oprf_evaluate` /
 * `_voprf_prove` / `_voprf_verify`, every one of them already KAT-gated against
 * the RFC 9497 A.3 vectors. No new primitive, no new hardness assumption. The
 * proof is additionally made DETERMINISTIC (the nonce is derived from the secret
 * and the challenge, RFC 6979 style) so a gate is reproducible and a nonce is
 * never reused across two challenges.
 *
 * WHAT IS DELIBERATELY NOT CLAIMED. Equivalence to a level, not certification,
 * not notification, and not a wallet. Identity proofing is INHERITED from the
 * PID presentation verified at enrolment and is not re-established by any later
 * login — see docs/proofs/DssoAuthenticationAssurance.md.
 *
 * DETERMINISM. This module reads no clock and draws no randomness. Every entry
 * point takes `now` (seconds) from its caller, the device seed and every nonce
 * are caller-supplied, and the possession proof is a deterministic function of
 * (secret, challenge). That is what makes `determ-dsso selftest-authn`
 * reproducible byte-for-byte.
 *
 * FAIL-CLOSED, as everywhere in this binary: 0 is the only success, outputs are
 * untouched on failure, every buffer carries its length, and a dependency that
 * cannot be consulted (the PID verifier, a stale limiter view) is
 * DSSO_E_UNAVAILABLE and never "allow on outage". */
#ifndef DETERM_DSSO_AUTHN_H
#define DETERM_DSSO_AUTHN_H

#include <stddef.h>
#include <stdint.h>

#include "dsso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Sizes and caps ────────────────────────────────────────────────────────
 * Fixed capacities, no allocation anywhere: a hostile caller cannot make this
 * module allocate or loop unboundedly. A production deployment swaps the
 * containers for a database; the RULES below are what must survive that swap. */
#define DSSO_AUTHN_ID_LEN        32u   /* account / device / server / nonce id */
#define DSSO_AUTHN_PK_LEN        33u   /* SEC1 compressed P-256 point          */
#define DSSO_AUTHN_PROOF_LEN     64u   /* RFC 9497 DLEQ proof: c || s          */
#define DSSO_AUTHN_MAX_SERVERS    8u
#define DSSO_AUTHN_MAX_ACCOUNTS   8u
#define DSSO_AUTHN_MAX_DEVICES    4u
#define DSSO_AUTHN_MAX_SESSIONS  32u
#define DSSO_AUTHN_MAX_SEEN     128u   /* single-use nonce cache, per kind     */

/* ── Assurance, as reported to the assertion layer ─────────────────────────
 * This enum is the module's ONLY statement about assurance and is what the
 * §5 assertion layer consumes before it mints a token: `dsso_authn_session_loa`
 * reports it and `dsso_authn_assertion_authorize` refuses a session below the
 * level the relying party requires. DSSO_LOA_HIGH does not exist — no path in
 * this module can produce it, and the proofing level inherited from a PID does
 * not make a later login "high". */
typedef enum {
    DSSO_LOA_NONE        = 0,  /* nothing may be asserted for this subject     */
    DSSO_LOA_LOW         = 1,  /* exactly one factor is usable — DEGRADED      */
    DSSO_LOA_SUBSTANTIAL = 2   /* two factors, different categories, dynamic   */
} dsso_loa;

/* ── Account state machine ─────────────────────────────────────────────────
 * The binding rule of this module, in one sentence: EVIDENCE OF ONE FACTOR MAY
 * ONLY REDUCE AN ACCOUNT'S ASSURANCE; RESTORING IT NEEDS A SECOND, INDEPENDENT
 * EVIDENCE — in practice a fresh PID presentation. A recovery path that handed
 * back full assurance on one factor would silently make the account single-
 * factor, which is exactly the defect this module exists to close. */
typedef enum {
    DSSO_ACC_NONE             = 0, /* no such account                          */
    DSSO_ACC_ACTIVE           = 1, /* knowledge + >=1 active device → SUBSTANTIAL */
    DSSO_ACC_KNOWLEDGE_ONLY   = 2, /* device lost/revoked            → LOW     */
    DSSO_ACC_POSSESSION_ONLY  = 3, /* password lost/withdrawn        → LOW     */
    DSSO_ACC_LOCKED           = 4  /* neither usable                 → NONE    */
} dsso_acc_state;

/* ── Challenge purposes ────────────────────────────────────────────────────
 * The purpose byte is inside the signed challenge, so a possession proof made
 * for a login can never authorise an enrolment, a revocation or a recovery. */
#define DSSO_AUTHN_P_LOGIN    1u
#define DSSO_AUTHN_P_ENROL    2u
#define DSSO_AUTHN_P_REVOKE   3u
#define DSSO_AUTHN_P_RECOVER  4u

/* ── The identity-proofing seam (a NARROW interface, deliberately) ─────────
 * DSSO does not verify EUDI Wallet PID presentations here. A sibling track
 * implements that verifier (OpenID4VP presentation, OIA_12 trust-list
 * validation of the PID signature, OIA_02 holder binding, Token Status List
 * check). This module consumes only its VERDICT plus two fields it must
 * enforce itself:
 *   - `subject_binding` — the PAIRWISE subject identifier the verifier derived
 *     for this DSSO account. It is not a raw national identifier and it is
 *     compared against the binding recorded at first enrolment, so a valid PID
 *     belonging to someone else cannot recover this account.
 *   - `presentation_id` — unique per presentation; this module enforces SINGLE
 *     USE, so a captured PID presentation cannot be replayed into a second
 *     recovery.
 * DEPENDENCY, stated plainly: with no verifier installed every PID-authorised
 * transition returns DSSO_E_UNAVAILABLE. Nothing here "allows on outage". */
typedef struct {
    uint8_t  subject_binding[DSSO_AUTHN_ID_LEN];
    uint8_t  presentation_id[DSSO_AUTHN_ID_LEN];
    uint64_t verified_at;   /* seconds, the verifier's clock                   */
} dsso_pid_attestation;

/* Returns DSSO_OK iff the presentation was verified and is acceptable NOW.
 * Any negative code is propagated verbatim by this module. */
typedef int (*dsso_pid_verify_fn)(void *ctx, const dsso_pid_attestation *att,
                                  uint64_t now);

/* ── Wire-shaped values ────────────────────────────────────────────────────*/

/* The knowledge factor's response for one authentication. It is HMAC over the
 * server-side secret the shipped threshold-OPRF + OPAQUE-3DH login already
 * co-generates, so it is — by construction and by design — derivable from the
 * password together with t server shares. That is precisely why it cannot be
 * the whole authentication. */
typedef struct { uint8_t tag[DSSO_AUTHN_ID_LEN]; } dsso_authn_knowledge;

/* The possession factor's response: the device's answer to one challenge. */
typedef struct {
    uint8_t device[DSSO_AUTHN_ID_LEN];
    uint8_t eval[DSSO_AUTHN_PK_LEN];      /* sk_dev · H2C(challenge)          */
    uint8_t proof[DSSO_AUTHN_PROOF_LEN];  /* DLEQ(pk_dev; H2C(challenge), eval) */
} dsso_authn_possession;

/* ── Persistent records ────────────────────────────────────────────────────*/

/* What a server stores about a device. NOTHING here lets the server, or any
 * quorum of servers, impersonate the device: `pk` is a public point and the
 * rest is metadata. */
typedef struct {
    uint8_t  id[DSSO_AUTHN_ID_LEN];
    uint8_t  pk[DSSO_AUTHN_PK_LEN];
    uint64_t enrolled_at;
    uint8_t  authority;   /* 0 = PID-proofed first device, 1 = session+device  */
    uint8_t  active;
} dsso_authn_device_rec;

typedef struct {
    uint8_t  id[DSSO_AUTHN_ID_LEN];
    uint8_t  in_use;
    uint8_t  state;                                   /* dsso_acc_state       */
    uint8_t  has_knowledge;
    uint8_t  knowledge_verifier[DSSO_AUTHN_ID_LEN];   /* server-side secret   */
    uint8_t  pid_subject[DSSO_AUTHN_ID_LEN];
    uint64_t auth_epoch;   /* bumped by every change that must kill sessions   */
    dsso_authn_device_rec dev[DSSO_AUTHN_MAX_DEVICES];
} dsso_authn_account;

typedef struct {
    uint8_t  id[DSSO_AUTHN_ID_LEN];
    uint8_t  account[DSSO_AUTHN_ID_LEN];
    uint8_t  device[DSSO_AUTHN_ID_LEN];
    uint64_t issued_at;
    uint64_t expires_at;
    uint64_t epoch;        /* the account's auth_epoch at issue                */
    uint8_t  loa;          /* dsso_loa                                         */
    uint8_t  two_factor;   /* 1 iff BOTH factors were verified for this session */
    uint8_t  in_use;
} dsso_authn_session;

typedef struct {
    uint8_t  scope[DSSO_AUTHN_ID_LEN];   /* account id, or zeros for PID ids   */
    uint8_t  value[DSSO_AUTHN_ID_LEN];
    uint64_t seen_at;
    uint8_t  in_use;
} dsso_authn_seen;

typedef struct {
    dsso_authn_account  acc[DSSO_AUTHN_MAX_ACCOUNTS];
    dsso_authn_session  ses[DSSO_AUTHN_MAX_SESSIONS];
    dsso_authn_seen     seen[DSSO_AUTHN_MAX_SEEN];      /* (account, nonce)    */
    dsso_authn_seen     pid_seen[DSSO_AUTHN_MAX_SEEN];  /* presentation ids    */
    uint64_t session_ttl;   /* seconds a session stays valid                   */
    uint64_t clock_skew;    /* accepted |now - timestamp|                      */
    /* A SERVER-SIDE secret that session ids are keyed by. It must not be
     * derivable from anything the client sends: a session id is a BEARER token,
     * and every other input to it (the account, the login nonce, the timestamp)
     * travels in the login request, so keying it is the only thing that stops
     * an observer of that request from computing the token. Injected by the
     * caller, never drawn here — that is what keeps the gate reproducible. */
    uint8_t  session_secret[32];
    uint64_t session_seq;
    /* WHICH SERVER SET THIS DEPLOYMENT IS. Installed once, by the operator, and
     * read by every in-session operation that has to bind a possession proof.
     * It is not a per-call argument: a binding the caller supplies each time is
     * a convention, and this has to be a rule. `dsso_authn_login` additionally
     * refuses a cluster whose own digest is not this one, so a substituted or
     * misconfigured server set is a DSSO_E_BINDING rather than a login. */
    uint8_t  set_digest[DSSO_AUTHN_ID_LEN];
    uint8_t  set_bound;
    dsso_pid_verify_fn pid_verify;
    void    *pid_ctx;
} dsso_authn_state;

/* ── The aggregate attempt limiter ─────────────────────────────────────────
 * THE DEFECT (spec §6): "with t-of-n the cap must be aggregate ... since an
 * attacker can rotate subsets — deployment choice." A per-server counter is
 * evaded by spreading guesses over different t-subsets, so the deployment
 * choice is the whole security property and leaving it open leaves the online
 * guessing bound undefined.
 *
 * THE MECHANISM. A grow-only counter (a state-based G-Counter CRDT) per
 * account: one slot per server, a server increments ONLY ITS OWN slot, merge is
 * per-slot maximum. Merge is idempotent, commutative and associative, so the
 * servers converge by gossip alone — no consensus rule, no new primitive, no
 * ordering requirement (the same "unordered" property the t-of-n OPRF has). The
 * cap is on the SUM of the slots, which is the number of blind evaluations the
 * whole set has served for that account in the window.
 *
 * THE BOUND. A login needs t servers to serve, so A attempts consume at least
 * (t - b) counter units when b of the serving servers are byzantine and refuse
 * to count. Hence A <= floor(cap / (t - b)) for every b < t, whatever subsets
 * the attacker rotates through. At b >= t the adversary holds an evaluation
 * quorum and can evaluate the OPRF offline: no online limiter of any design
 * bounds that case, and the spec's C1/C3 threshold assumption is what covers it.
 *
 * FAIL-CLOSED STALENESS. A server whose view has not been merged within
 * `merge_max_age` cannot know what the others have served, so it REFUSES to
 * serve (DSSO_E_UNAVAILABLE) rather than serve on a stale view. Partitioning
 * the servers therefore costs the attacker the service, not the bound.
 *
 * NO CROSS-USER LEAK. Counters are per account; one account exhausting its
 * budget cannot lock out another, and a successful two-factor login clears the
 * account's counter (a window/reset epoch that merge prefers wholesale). */
typedef struct {
    uint8_t  account[DSSO_AUTHN_ID_LEN];
    uint8_t  in_use;
    uint64_t window;                            /* now / window_secs           */
    uint64_t reset_seq;                         /* bumped by a successful login */
    uint32_t slot[DSSO_AUTHN_MAX_SERVERS];
} dsso_authn_meter;

typedef struct {
    uint8_t  id[DSSO_AUTHN_ID_LEN];
    uint8_t  index;
    uint64_t merged_at;
    dsso_authn_meter meter[DSSO_AUTHN_MAX_ACCOUNTS];
} dsso_authn_server;

typedef struct {
    uint8_t  n;
    uint8_t  t;
    uint32_t cap;             /* cap on the SUM of the slots, per window       */
    uint64_t window_secs;
    uint64_t merge_max_age;
    uint8_t  set_digest[DSSO_AUTHN_ID_LEN];
    dsso_authn_server srv[DSSO_AUTHN_MAX_SERVERS];
} dsso_authn_cluster;

/* ── Requests ──────────────────────────────────────────────────────────────*/

typedef struct {
    uint8_t  account[DSSO_AUTHN_ID_LEN];
    uint8_t  nonce[DSSO_AUTHN_ID_LEN];   /* single use, per account            */
    uint64_t timestamp;
    const dsso_authn_knowledge  *knowledge;   /* NULL = factor not presented   */
    const dsso_authn_possession *possession;  /* NULL = factor not presented   */
} dsso_authn_login_req;

/* The recovery / loss state-machine events. */
typedef enum {
    DSSO_AUTHN_EV_DEVICE_LOST      = 1, /* knowledge  → KNOWLEDGE_ONLY  (LOW)  */
    DSSO_AUTHN_EV_PASSWORD_LOST    = 2, /* possession → POSSESSION_ONLY (LOW)  */
    DSSO_AUTHN_EV_BOTH_LOST        = 3, /* either one → LOCKED          (NONE) */
    DSSO_AUTHN_EV_RESTORE_DEVICE   = 4, /* knowledge + PID → ACTIVE            */
    DSSO_AUTHN_EV_RESTORE_PASSWORD = 5, /* possession + PID → ACTIVE           */
    DSSO_AUTHN_EV_RESTORE_BOTH     = 6  /* PID → ACTIVE (re-proofed enrolment) */
} dsso_authn_event;

typedef struct {
    const dsso_authn_knowledge  *knowledge;
    const dsso_authn_possession *possession;
    const dsso_pid_attestation  *pid;
    const uint8_t *new_device;              /* DSSO_AUTHN_ID_LEN               */
    const uint8_t *new_pk;                  /* DSSO_AUTHN_PK_LEN               */
    const uint8_t *new_knowledge_verifier;  /* DSSO_AUTHN_ID_LEN               */
    uint8_t  nonce[DSSO_AUTHN_ID_LEN];
    uint64_t timestamp;
} dsso_authn_evidence;

/* ── Device-side primitives (run on the user's device, never on a server) ──*/

/* Generate a device key pair from DEVICE-LOCAL entropy. `seed` is the device's
 * own secret: it must not be, and must not be derived from, the password, the
 * OPRF output, the credential envelope, or anything a server stores. The gate
 * pins that the seed is load-bearing — two seeds give two keys — because a
 * derivation that ignored it would make the "possession" factor recomputable
 * by whoever can call it, which is the collapse this module prevents. */
int dsso_authn_device_keygen(uint8_t sk[32], uint8_t pk[DSSO_AUTHN_PK_LEN],
                             const uint8_t seed[32]);

/* The challenge both sides compute independently. The verifier NEVER accepts a
 * challenge from the client: it rebuilds this from its own view of the account,
 * the session nonce, the server set, the timestamp and the other factor's
 * response, and verifies the signature against THAT. `bind` is the knowledge
 * factor's tag for a login and the session id for an in-session operation;
 * `aux` binds whatever the operation is about (the new device, the revocation
 * target, the PID presentation). Either may be NULL, which means 32 zero bytes. */
int dsso_authn_challenge(uint8_t out[32], uint8_t purpose,
                         const uint8_t account[DSSO_AUTHN_ID_LEN],
                         const uint8_t device[DSSO_AUTHN_ID_LEN],
                         const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                         const uint8_t set_digest[DSSO_AUTHN_ID_LEN],
                         uint64_t timestamp,
                         const uint8_t bind[32], const uint8_t aux[32]);

/* The knowledge factor's response over the same binding material. */
int dsso_authn_knowledge_tag(uint8_t out[32],
                             const uint8_t knowledge_verifier[32],
                             uint8_t purpose,
                             const uint8_t account[DSSO_AUTHN_ID_LEN],
                             const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                             const uint8_t set_digest[DSSO_AUTHN_ID_LEN],
                             uint64_t timestamp, const uint8_t aux[32]);

/* Answer a challenge with the device secret. Deterministic in (sk, challenge). */
int dsso_authn_possession_sign(dsso_authn_possession *out,
                               const uint8_t sk[32],
                               const uint8_t pk[DSSO_AUTHN_PK_LEN],
                               const uint8_t device[DSSO_AUTHN_ID_LEN],
                               const uint8_t challenge[32]);

/* Verify one against the enrolled public key. Public-data operation. */
int dsso_authn_possession_verify(const uint8_t pk[DSSO_AUTHN_PK_LEN],
                                 const dsso_authn_possession *resp,
                                 const uint8_t challenge[32]);

/* ── The limiter ───────────────────────────────────────────────────────────*/

/* `ids` is a FLAT buffer of n * DSSO_AUTHN_ID_LEN bytes — the server identities
 * in the order the set digest fixes them. */
int  dsso_authn_cluster_init(dsso_authn_cluster *c, uint8_t n, uint8_t t,
                             const uint8_t *ids,
                             uint32_t cap, uint64_t window_secs,
                             uint64_t merge_max_age, uint64_t now);
/* All-pairs merge (the heartbeat). Refreshes every view's `merged_at`. */
void dsso_authn_cluster_gossip(dsso_authn_cluster *c, uint64_t now);
/* Ask `k` named servers to serve one attempt for `account`. Meters BEFORE any
 * factor is checked, so a failed guess costs budget. DSSO_E_RATELIMIT when the
 * aggregate cap is reached; DSSO_E_UNAVAILABLE on a stale view. */
int  dsso_authn_cluster_meter(dsso_authn_cluster *c, const uint8_t *subset,
                              uint8_t k, const uint8_t account[DSSO_AUTHN_ID_LEN],
                              uint64_t now);
/* The aggregate as one server sees it (the value the cap is compared against). */
uint32_t dsso_authn_meter_total(const dsso_authn_cluster *c, uint8_t server_index,
                                const uint8_t account[DSSO_AUTHN_ID_LEN],
                                uint64_t now);

/* ── State, enrolment, login, sessions, revocation, recovery ──────────────*/

int  dsso_authn_init(dsso_authn_state *st, const uint8_t session_secret[32],
                     uint64_t session_ttl, uint64_t clock_skew);
void dsso_authn_set_pid_verifier(dsso_authn_state *st, dsso_pid_verify_fn fn,
                                 void *ctx);

/* Install the server set this deployment authenticates against — the digest a
 * `dsso_authn_cluster` computes over (n, t, the ordered identities). Until it
 * is installed every operation that must bind a possession proof to the set
 * fails closed with DSSO_E_UNAVAILABLE. */
int  dsso_authn_bind_server_set(dsso_authn_state *st,
                                const uint8_t set_digest[DSSO_AUTHN_ID_LEN]);

/* FIRST enrolment — authorised by the identity-proofing event alone, because
 * at this moment the user holds nothing else. Records the PID subject binding,
 * the first device public key and the knowledge verifier; result is ACTIVE. */
int dsso_authn_enrol_first(dsso_authn_state *st,
                           const uint8_t account[DSSO_AUTHN_ID_LEN],
                           const dsso_pid_attestation *pid,
                           const uint8_t device[DSSO_AUTHN_ID_LEN],
                           const uint8_t pk[DSSO_AUTHN_PK_LEN],
                           const uint8_t knowledge_verifier[32], uint64_t now);

/* ANY LATER enrolment — an authenticated SUBSTANTIAL session AND a fresh
 * possession proof from an already-active device, bound to the new device's
 * public key. A password alone must never enrol a device: that would let the
 * knowledge factor mint the possession factor and collapse the second factor. */
int dsso_authn_enrol_device(dsso_authn_state *st,
                            const uint8_t session[DSSO_AUTHN_ID_LEN],
                            const dsso_authn_possession *existing,
                            const uint8_t new_device[DSSO_AUTHN_ID_LEN],
                            const uint8_t new_pk[DSSO_AUTHN_PK_LEN],
                            const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                            uint64_t timestamp, uint64_t now);

/* The dynamic authentication (§2.3.1). Meters first, then requires exactly the
 * factors the account's state can still offer, and issues a session carrying
 * the assurance that follows from what was actually verified. */
int dsso_authn_login(dsso_authn_state *st, dsso_authn_cluster *c,
                     const uint8_t *subset, uint8_t k,
                     const dsso_authn_login_req *req, uint64_t now,
                     uint8_t out_session[DSSO_AUTHN_ID_LEN], dsso_loa *out_loa);

/* A session verifies only while the account's auth_epoch is unchanged: every
 * revocation, password change and recovery bumps it, so live sessions die. */
int dsso_authn_session_verify(const dsso_authn_state *st,
                              const uint8_t session[DSSO_AUTHN_ID_LEN],
                              uint64_t now, dsso_loa *out_loa);

/* THE ASSERTION LAYER'S ENTRY POINT. The §5 dual-hash token must not be minted
 * for a session below the level the relying party requires; this is where that
 * is decided, and DSSO_E_ASSURANCE is what a degraded account produces. */
int dsso_authn_assertion_authorize(const dsso_authn_state *st,
                                   const uint8_t session[DSSO_AUTHN_ID_LEN],
                                   dsso_loa required, uint64_t now);

/* Revoke one device: a live SUBSTANTIAL session plus a fresh possession proof
 * from an active device, bound to the target. Bumps auth_epoch, so every live
 * session — including the one that asked — stops verifying. When the last
 * active device goes, the account degrades to KNOWLEDGE_ONLY (LOW). A device
 * the user no longer holds is revoked through DSSO_AUTHN_EV_DEVICE_LOST. */
int dsso_authn_revoke_device(dsso_authn_state *st,
                             const uint8_t session[DSSO_AUTHN_ID_LEN],
                             const dsso_authn_possession *proof,
                             const uint8_t target_device[DSSO_AUTHN_ID_LEN],
                             const uint8_t nonce[DSSO_AUTHN_ID_LEN],
                             uint64_t timestamp, uint64_t now);

/* The loss / recovery state machine. Every transition either REDUCES assurance
 * on one factor's evidence, or RESTORES it on two independent evidences, one of
 * which is always a fresh, single-use, subject-matched PID presentation. */
int dsso_authn_recover(dsso_authn_state *st,
                       const uint8_t account[DSSO_AUTHN_ID_LEN],
                       dsso_authn_event ev, const dsso_authn_evidence *e,
                       uint64_t now);

/* Read-only reports. */
dsso_acc_state dsso_authn_account_state(const dsso_authn_state *st,
                                        const uint8_t account[DSSO_AUTHN_ID_LEN]);
dsso_loa dsso_authn_account_loa(const dsso_authn_state *st,
                                const uint8_t account[DSSO_AUTHN_ID_LEN]);
const char *dsso_loa_name(dsso_loa l);
const char *dsso_acc_state_name(dsso_acc_state s);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_AUTHN_H */
