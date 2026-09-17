/* DSSO G4 OPAQUE-3DH AKE core (RFC 9807 §6.4 "3DH") — CRYPTO-C99-SPEC §3.26.
 *
 * The DSSO "Sign-In With Determ" login (v2.25-DSSO-DAPP-SPEC §4-5) co-generates a
 * shared session key `sso_key` between the client wallet and the threshold IdP via
 * an OPAQUE authenticated key exchange. This module is the AKE CORE: the 3DH key
 * schedule + the transcript-MAC mutual authentication. The credential_request /
 * credential_response are OPAQUE transcript blobs here — they are produced by the
 * ALREADY-SHIPPED threshold-OPRF + OPAQUE envelope (G1/G2/G3, test-dsso-threshold-
 * oprf) and threaded in at the login layer (inc.2). So this module proves the AKE
 * in isolation: both parties derive the SAME session_key from the three DH values
 * + the whole transcript, and the two MACs bind that transcript (any tamper flips
 * server_mac_ok / breaks agreement).
 *
 * WHAT v2 FIXED (claim C2, spec §0.0(2); landed 2026-09-17). v1 bound NEITHER
 * static public key into the transcript and took `pk_s` / `pk_c` as bare call
 * arguments, so an attacker holding only the victim's PUBLIC `pk_c` could pick its
 * own `(sk_s', esk_s')`, run the server half, and be accepted by the honest client
 * with an agreeing session key — full IdP impersonation, reproduced end to end
 * before the fix. v2 closes it two ways at once:
 *   1. the transcript carries RFC 9807 §4.1.1 `CleartextCredentials` —
 *      `{server_public_key, client_public_key, server_identity, client_identity}` —
 *      and the preamble (hence every MAC and the session key) commits to it; and
 *   2. the separate `pk_s` / `pk_c` ARGUMENTS ARE GONE. A party has exactly ONE
 *      slot in which a static key can enter, and that slot is MAC-covered: the
 *      client's `dh2` reads `t->server_public_key` (the key the client ANCHORED —
 *      never one the login peer handed it) and the server's `dh3` reads
 *      `t->client_public_key`.
 * TRUST BOUNDARY — binding is not trust. The client's `t->server_public_key` must
 * be an AUTHENTIC `pk_s`: at login it is recovered from the credential envelope,
 * whose AAD is exactly the `CleartextCredentials` bytes this module serializes
 * (see determ_opaque3dh_cleartext_credentials) under a key derived from the user's
 * password plus >= t OPRF responses; at enrolment it comes from the on-chain DSSO
 * registration record via the committee-authenticated light-client read. Both are
 * stated, with the named residual, in v2.25-DSSO-DAPP-SPEC §0.0(2).
 *
 * NO new hardness assumption / NO new primitive. Everything composes from
 * determ::c99: three P-256 scalar mults (the 3DH, determ_p256_point_mul), an
 * RFC-9807/TLS-1.3-style HKDF-Expand-Label schedule over HKDF-SHA256 built on
 * determ_hmac_sha256, and streaming determ_sha256 over the transcript preamble.
 *
 * The 3DH combines, per RFC 9807:
 *   dh1 = client_eph  · server_eph    (esk×epk on both sides)
 *   dh2 = client_eph  · server_static (client sees esk_c·pk_s; server sees sk_s·epk_c)
 *   dh3 = client_static · server_eph  (client sees sk_c·epk_s; server sees esk_s·pk_c)
 *   ikm = compress(dh1) || compress(dh2) || compress(dh3)          (99 bytes)
 * Key schedule (prk = HKDF-Extract(0^32, ikm)):
 *   session_key      = Derive-Secret(prk, "SessionKey",      preamble)
 *   handshake_secret = Derive-Secret(prk, "HandshakeSecret", preamble)
 *   Km2 = Expand-Label(handshake_secret, "ServerMAC", "", 32)  (server auth key)
 *   Km3 = Expand-Label(handshake_secret, "ClientMAC", "", 32)  (client auth key)
 *   server_mac = HMAC(Km2, SHA256(preamble))
 *   client_mac = HMAC(Km3, SHA256(preamble || server_mac))
 * where Derive-Secret(s, L, T) = Expand-Label(s, L, SHA256(T), 32) and
 * Expand-Label(s, L, ctx, n) = HKDF-Expand(s, i2osp(n,2) || i2osp(|prefix|+|L|,1)
 *   || "DTM-DSSO-OPAQUE3DH-v2-" || L || i2osp(|ctx|,1) || ctx, n).
 *
 * CleartextCredentials (RFC 9807 §4.1.1; the house tag and the client's public key
 * are the two Determ additions). The SAME bytes are the AAD under which the login
 * layer seals the credential envelope, so the envelope tag and the transcript MAC
 * commit to one and the same block:
 *   "DTM-DSSO-CLEARCRED-v2-"
 *   || compress(server_public_key)                (33)
 *   || compress(client_public_key)                (33)
 *   || i2osp(|server_identity|,2) || server_identity
 *   || i2osp(|client_identity|,2) || client_identity
 *
 * Transcript preamble (streamed into SHA-256, never materialized):
 *   "DTM-DSSO-OPAQUEv2-"
 *   || i2osp(|context|,2) || context
 *   || CleartextCredentials                       (both static keys + both identities)
 *   || ke1                                        (cred_request || client_nonce(32) || compress(epk_c))
 *   || inner_ke2                                  (cred_response || server_nonce(32) || compress(epk_s))
 *
 * Domain separation: Determ realizes the OPAQUE-3DH CONSTRUCTION for its own DSSO
 * DApp, not wire-interop with other OPAQUE stacks, so the label prefix is the house
 * "DTM-DSSO-OPAQUE3DH-v2-" tag (RFC 9807 uses "OPAQUE-").
 *
 * FAIL-CLOSED edges (return -1, outputs untouched): NULL required args (both static
 * public keys included), an on-wire transcript field longer than
 * DETERM_OPAQUE3DH_MAX_FIELD, or a P-256 op that fails (off-curve/identity DH or an
 * uncompressible static key). Secret scratch (prk, handshake_secret, Km2/Km3, the
 * DH points) is secure-zeroed on every path.
 *
 * PERMANENCE: the domain tags + the encoding are permanent once a DSSO deployment
 * exists (login transcripts must reproduce). Any change is a "-v3" tag, never an
 * in-place edit. The one-time v1 -> v2 replacement (C2) was taken because NO
 * deployment existed, so no login transcript had to reproduce, and retaining the
 * impersonable v1 path would have left a downgrade target compiled in; the v1 KAT
 * is RETIRED. Byte-frozen python-first against tools/verify_opaque3dh.py (the
 * dual-oracle KAT asserted by `determ test-dsso-opaque3dh`). */
#ifndef DETERM_CRYPTO_DSSO_OPAQUE3DH_H
#define DETERM_CRYPTO_DSSO_OPAQUE3DH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_OPAQUE3DH_SK_LEN     32   /* P-256 scalar (big-endian)          */
#define DETERM_OPAQUE3DH_PK_LEN     65   /* uncompressed SEC1 P-256 point      */
#define DETERM_OPAQUE3DH_NONCE_LEN  32   /* per-session nonce                  */
#define DETERM_OPAQUE3DH_OUT_LEN    32   /* session_key / MAC output length    */
#define DETERM_OPAQUE3DH_MAX_FIELD  4096 /* cap on any single transcript field */
/* Upper bound on the serialized CleartextCredentials block: the 22-byte tag, two
 * 33-byte compressed points, and the two length-prefixed identities at their cap. */
#define DETERM_OPAQUE3DH_CLEARCRED_MAX \
    (22 + 33 + 33 + 2 + DETERM_OPAQUE3DH_MAX_FIELD + 2 + DETERM_OPAQUE3DH_MAX_FIELD)

/* Shared transcript inputs — identical on both parties. `*_len` may be 0 (the
 * pointer is then unread). client_nonce / server_nonce are exactly 32 bytes.
 *
 * client_public_key / server_public_key are REQUIRED (NULL -> -1) and are the ONLY
 * way a static public key enters the AKE: they feed the 3DH *and* the preamble, so
 * the MACs cover exactly the keys the DH used. `server_public_key` on the CLIENT is
 * the key the client ANCHORED (envelope AAD / on-chain registration record), never
 * a value taken from the login peer — see the trust-boundary note above. */
typedef struct {
    const uint8_t *context;            size_t context_len;
    const uint8_t *client_identity;    size_t client_identity_len;
    const uint8_t *server_identity;    size_t server_identity_len;
    const uint8_t *client_public_key;  /* DETERM_OPAQUE3DH_PK_LEN bytes, required */
    const uint8_t *server_public_key;  /* DETERM_OPAQUE3DH_PK_LEN bytes, required */
    const uint8_t *cred_request;       size_t cred_request_len;
    const uint8_t *cred_response;      size_t cred_response_len;
    const uint8_t *client_nonce;       /* DETERM_OPAQUE3DH_NONCE_LEN bytes */
    const uint8_t *server_nonce;       /* DETERM_OPAQUE3DH_NONCE_LEN bytes */
} determ_opaque3dh_transcript;

/* Serialize the RFC 9807 §4.1.1 CleartextCredentials block of `t` — the byte-exact
 * block the preamble hashes — into `out` (capacity `out_cap`; at least
 * DETERM_OPAQUE3DH_CLEARCRED_MAX admits any transcript), writing its length to
 * *out_len. This is what the login layer passes as the credential envelope's AAD
 * so the envelope tag and the transcript MAC commit to the same bytes.
 * Returns 0, or -1 fail-closed (NULL arg, over-length identity, an uncompressible
 * static key, or out_cap too small). On failure *out_len is NOT written and the
 * contents of `out` are unspecified — a caller must not use a failed serialization. */
int determ_opaque3dh_cleartext_credentials(const determ_opaque3dh_transcript *t,
                                           uint8_t *out, size_t out_cap,
                                           size_t *out_len);

/* Server side: performs the 3DH from the server's view, runs the key schedule,
 * derives epk_s = esk_s·G, and produces server_mac plus the client_mac it expects
 * the client to return. Returns 0 on success, -1 fail-closed.
 *
 *   sk_s   : server long-term secret scalar (32) — must be the secret for
 *            t->server_public_key, or the client rejects the resulting MAC
 *   esk_s  : server ephemeral secret scalar (32)
 *   epk_c  : client ephemeral public key    (65, uncompressed) — from the client's ke1
 * The client's long-term public key comes from t->client_public_key (dh3).
 * Outputs:
 *   epk_s_out           : server ephemeral public (65) to send in ke2
 *   session_key         : the co-generated sso_key (32)
 *   server_mac          : HMAC(Km2, SHA256(preamble)) (32), sent in ke2
 *   expected_client_mac : the client_mac the server will require (32) */
int determ_opaque3dh_server(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_s[32],
                            const uint8_t esk_s[32], const uint8_t epk_c[65],
                            uint8_t epk_s_out[65],
                            uint8_t session_key[32],
                            uint8_t server_mac[32],
                            uint8_t expected_client_mac[32]);

/* Client side: performs the 3DH from the client's view, runs the key schedule,
 * derives epk_c = esk_c·G, verifies the server_mac, and produces its client_mac.
 * Returns 0 on success (check *server_mac_ok for authentication), -1 fail-closed.
 *
 *   sk_c   : client long-term secret scalar (32)
 *   esk_c  : client ephemeral secret scalar (32)
 *   epk_s  : server ephemeral public key    (65, uncompressed) — from the server's ke2
 *   server_mac : the MAC received in ke2 (32)
 * The server's long-term public key comes from t->server_public_key (dh2) — the
 * ANCHORED key. Putting the peer's own claimed key there re-opens C2; do not.
 * Outputs:
 *   epk_c_out     : client ephemeral public (65) — must equal what went into ke1
 *   session_key   : the co-generated sso_key (32)
 *   client_mac    : HMAC(Km3, SHA256(preamble || server_mac)) (32), sent in ke3
 *   server_mac_ok : 1 iff server_mac matches the client's recomputation — i.e. iff
 *                   the peer holds sk_s for t->server_public_key AND ran the same
 *                   transcript (server authenticated), 0 otherwise. A 0 here is an
 *                   AKE ABORT even though the call returns 0 (success = "ran to
 *                   completion"). */
int determ_opaque3dh_client(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_c[32],
                            const uint8_t esk_c[32], const uint8_t epk_s[65],
                            const uint8_t server_mac[32],
                            uint8_t epk_c_out[65],
                            uint8_t session_key[32],
                            uint8_t client_mac[32],
                            int *server_mac_ok);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_CRYPTO_DSSO_OPAQUE3DH_H */
