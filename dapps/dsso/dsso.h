/* DSSO service core — "Sign-In With Determ" off-chain identity service.
 *
 * WHAT THIS IS. The DSSO DApp (docs/proofs/v2.25-DSSO-DAPP-SPEC.md) runs OFF the
 * chain: it consumes external identity evidence (EUDI Wallet PID presentations),
 * authenticates users, and issues assertions to its own relying parties. None of
 * that is a consensus accept rule, so it lives in its own binary that links only
 * determ-crypto-c99 — the same isolation d5rp uses.
 *
 * WHY THE ISOLATION MATTERS. External identity formats are JSON/base64url
 * (SD-JWT VC) and CBOR (ISO mdoc). The repository's canonical-binary rule governs
 * CONSENSUS data; these formats are external interop requirements that a relying
 * party cannot renegotiate. Keeping every byte of them inside this binary is what
 * lets both hold: no consensus path ever parses attacker-supplied JSON or CBOR,
 * and no DSSO code is reachable from src/chain or src/node. The boundary is
 * mechanical, not a promise — determ-dsso links no chain object.
 *
 * FAIL-CLOSED is the house rule here: every parse returns a status, every buffer
 * carries its length, nothing is NUL-terminated by assumption, and a function
 * that cannot complete leaves its outputs untouched and returns non-zero. */
#ifndef DETERM_DSSO_H
#define DETERM_DSSO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. 0 is the ONLY success value; a caller that tests `!= DSSO_OK`
 * is correct, and a caller that tests `< 0` is also correct. Codes are stable:
 * gates and operators match on them. */
typedef enum {
    DSSO_OK                 =  0,
    DSSO_E_ARG              = -1,   /* NULL argument, or a length out of range   */
    DSSO_E_FORMAT           = -2,   /* malformed input (encoding, structure)     */
    DSSO_E_CRYPTO           = -3,   /* a signature/MAC/curve operation failed    */
    DSSO_E_TRUST            = -4,   /* issuer or relying party not trusted       */
    DSSO_E_EXPIRED          = -5,   /* outside its validity window               */
    DSSO_E_REPLAY           = -6,   /* seen before (nonce, jti, status index)    */
    DSSO_E_AUDIENCE         = -7,   /* addressed to someone else                 */
    DSSO_E_BINDING          = -8,   /* holder/device/session binding failed      */
    DSSO_E_STATUS           = -9,   /* revoked or suspended by its status list   */
    DSSO_E_ASSURANCE        = -10,  /* evidence below the required level         */
    DSSO_E_UNAVAILABLE      = -11,  /* a dependency could not be consulted       */
    DSSO_E_RATELIMIT        = -12   /* the aggregate attempt budget is spent     */
} dsso_status;

/* A bounded, non-owning view of caller memory. `p` may be NULL only when
 * `n == 0`; every reader checks that before dereferencing. */
typedef struct { const uint8_t *p; size_t n; } dsso_slice;

/* Upper bounds shared by every module. They exist so a hostile input cannot make
 * this service allocate or loop unboundedly; each is generous for real data and
 * small enough that the worst case is trivially affordable. */
#define DSSO_MAX_TOKEN      16384   /* one presented credential, in bytes        */
#define DSSO_MAX_FIELD       4096   /* one field inside it                       */
#define DSSO_MAX_CLAIMS        64   /* attributes accepted from one presentation */

/* Bounds for the external-format readers (dsso_jose.*) and the PID presentation
 * verifier (dsso_pid.*). They are here, beside the token bounds above, because
 * the rule is the same one: a hostile presentation must not be able to make this
 * service recurse, allocate or loop past a fixed ceiling. Every one of them is a
 * REJECT boundary, never a truncation — a document that exceeds a cap returns
 * DSSO_E_FORMAT with its outputs untouched. */
#define DSSO_JSON_MAX_DEPTH      8  /* nested [ / { levels; also the recursion   */
                                    /* depth of the reader, so the C stack       */
                                    /* footprint is a compile-time constant      */
#define DSSO_JSON_MAX_KEYS     128  /* object member names recorded per document */
                                    /* (the duplicate-key detector's working set)*/
#define DSSO_JSON_MAX_ELEMS    128  /* members of one object / elements of one   */
                                    /* array                                     */
#define DSSO_MAX_PARTS          80  /* `~`-separated parts of one SD-JWT VC      */
                                    /* presentation: issuer JWT + disclosures +  */
                                    /* KB-JWT, so > DSSO_MAX_CLAIMS + 2          */
#define DSSO_MAX_STATUS_BYTES 16384 /* inflated status-list bitstring, in bytes  */

/* Constant-time equality. Returns 1 iff the two spans are equal; the running
 * time depends on `n` alone, never on the contents. Used wherever a comparison
 * is over a secret or over a value an attacker can grind against. */
int dsso_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* Human-readable name of a status code, for operator logs and gate output.
 * Never NULL; an unknown code returns "DSSO_E_UNKNOWN". */
const char *dsso_status_name(dsso_status s);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_H */
