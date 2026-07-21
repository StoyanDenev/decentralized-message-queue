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
 *   || "DTM-DSSO-OPAQUE3DH-v1-" || L || i2osp(|ctx|,1) || ctx, n).
 *
 * Transcript preamble (streamed into SHA-256, never materialized):
 *   "DTM-DSSO-OPAQUEv1-"
 *   || i2osp(|context|,2) || context
 *   || i2osp(|client_identity|,2) || client_identity
 *   || ke1                                       (cred_request || client_nonce(32) || compress(epk_c))
 *   || i2osp(|server_identity|,2) || server_identity
 *   || inner_ke2                                 (cred_response || server_nonce(32) || compress(epk_s))
 *
 * Domain separation: Determ realizes the OPAQUE-3DH CONSTRUCTION for its own DSSO
 * DApp, not wire-interop with other OPAQUE stacks, so the label prefix is the house
 * "DTM-DSSO-OPAQUE3DH-v1-" tag (RFC 9807 uses "OPAQUE-").
 *
 * FAIL-CLOSED edges (return -1, outputs untouched): NULL required args, an on-wire
 * transcript field longer than DETERM_OPAQUE3DH_MAX_FIELD, or a P-256 op that fails
 * (off-curve/identity DH). Secret scratch (prk, handshake_secret, Km2/Km3, the DH
 * points) is secure-zeroed on every path.
 *
 * PERMANENCE: the domain tags + the encoding are permanent once a DSSO deployment
 * exists (login transcripts must reproduce). Any change is a "-v2" tag, never an
 * in-place edit. Byte-frozen python-first against tools/verify_opaque3dh.py (the
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

/* Shared transcript inputs — identical on both parties. `*_len` may be 0 (the
 * pointer is then unread). client_nonce / server_nonce are exactly 32 bytes. */
typedef struct {
    const uint8_t *context;          size_t context_len;
    const uint8_t *client_identity;  size_t client_identity_len;
    const uint8_t *server_identity;  size_t server_identity_len;
    const uint8_t *cred_request;     size_t cred_request_len;
    const uint8_t *cred_response;    size_t cred_response_len;
    const uint8_t *client_nonce;     /* DETERM_OPAQUE3DH_NONCE_LEN bytes */
    const uint8_t *server_nonce;     /* DETERM_OPAQUE3DH_NONCE_LEN bytes */
} determ_opaque3dh_transcript;

/* Server side: performs the 3DH from the server's view, runs the key schedule,
 * derives epk_s = esk_s·G, and produces server_mac plus the client_mac it expects
 * the client to return. Returns 0 on success, -1 fail-closed.
 *
 *   sk_s   : server long-term secret scalar (32)
 *   pk_c   : client long-term public key    (65, uncompressed)
 *   esk_s  : server ephemeral secret scalar (32)
 *   epk_c  : client ephemeral public key    (65, uncompressed) — from the client's ke1
 * Outputs:
 *   epk_s_out           : server ephemeral public (65) to send in ke2
 *   session_key         : the co-generated sso_key (32)
 *   server_mac          : HMAC(Km2, SHA256(preamble)) (32), sent in ke2
 *   expected_client_mac : the client_mac the server will require (32) */
int determ_opaque3dh_server(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_s[32],  const uint8_t pk_c[65],
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
 *   pk_s   : server long-term public key    (65, uncompressed)
 *   esk_c  : client ephemeral secret scalar (32)
 *   epk_s  : server ephemeral public key    (65, uncompressed) — from the server's ke2
 *   server_mac : the MAC received in ke2 (32)
 * Outputs:
 *   epk_c_out     : client ephemeral public (65) — must equal what went into ke1
 *   session_key   : the co-generated sso_key (32)
 *   client_mac    : HMAC(Km3, SHA256(preamble || server_mac)) (32), sent in ke3
 *   server_mac_ok : 1 iff server_mac matches the client's recomputation (server
 *                   authenticated), 0 otherwise. A 0 here is an AKE ABORT even
 *                   though the call returns 0 (success = "ran to completion"). */
int determ_opaque3dh_client(const determ_opaque3dh_transcript *t,
                            const uint8_t sk_c[32],  const uint8_t pk_s[65],
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
