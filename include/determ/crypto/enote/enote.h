/* NC-8 encrypted-note delivery (shielded-pool Option A — encrypted output
 * note; owner-decided 2026-07-17). A confidential-tx output carries an
 * ENCRYPTED NOTE so the recipient can SCAN the chain, trial-decrypt, and
 * recover the note secret (value + blinding, and any memo) WITHOUT an
 * out-of-band channel — closing ShieldedPoolSoundness NC-8. It is ALSO how
 * a view-/audit-key holder reads amounts on-chain (the shipped A2 audit
 * layer publishes an opaque key today and can decrypt nothing).
 *
 * SCOPE / non-goals. This adds amount-recipient DELIVERY only. It adds NO
 * graph privacy (inputs are still named, NC-7 unchanged) and does NOT touch
 * the named-input / commitment-as-its-own-nullifier model, so the pool's
 * no-double-spend-by-design property (bounded unspent-commitment set, no
 * nullifier set) is fully preserved. Amount-privacy vs. graph-privacy stays
 * a v1.x non-goal per WHITEPAPER §12.1.
 *
 * CONSTRUCTION — standard ephemeral-static ECIES over NIST P-256, the CT
 * stack's curve in both profiles (MODERN + FIPS). NO new hardness
 * assumption: security reduces to P-256 ECDH + HKDF-SHA256 (RFC 5869) +
 * ChaCha20-Poly1305 AEAD (RFC 8439), all shipped, dual-oracle-frozen c99
 * primitives.
 *
 *   seal(R, pt, e):                         (R = recipient pub, e = ephemeral sk)
 *     E     = e·G                           ephemeral pubkey (33B compressed)
 *     Z     = e·R ; z = Z.x                 ECDH shared secret (32B)
 *     K‖N   = HKDF(salt="determ-enote-v1", ikm=z, info=E33‖R33, L=44)
 *                                           K = AEAD key(32), N = nonce(12)
 *     ct,t  = ChaCha20-Poly1305(K, N, aad=E33, pt)
 *     out   = E33 ‖ ct ‖ t                  (len = ptlen + 49)
 *   open(r, in): Z = r·E, same HKDF, AEAD-decrypt. A verifying tag IS the
 *     "this note is mine" scan gate (constant-time; wrong-key ⇒ -1).
 *
 * DETERMINISM & TESTABILITY. seal is a pure function of (R, pt, e) — the
 * caller supplies a FRESH-per-note ephemeral sk `e`, so the ciphertext is
 * byte-exactly reproducible and dual-oracle-gated (tools/verify_enote.py +
 * tools/vectors/enote.json via `determ test-enote-c99`). Binding: the HKDF
 * info commits to (E, R) and the AEAD AAD commits to E, so a ciphertext
 * cannot be re-pointed to a different recipient or ephemeral key.
 *
 * SAFETY. `e` MUST be unique per note (fresh randomness) — reuse repeats
 * (K,N) and breaks AEAD confidentiality. `e` unique ⇒ (K,N) unique ⇒ the
 * derived nonce is single-use, which is why N is KDF-derived rather than
 * a caller counter. */
#ifndef DETERM_CRYPTO_ENOTE_H
#define DETERM_CRYPTO_ENOTE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_ENOTE_EPH_LEN   33   /* compressed P-256 ephemeral pubkey */
#define DETERM_ENOTE_TAG_LEN   16   /* Poly1305 tag                      */
#define DETERM_ENOTE_OVERHEAD  (DETERM_ENOTE_EPH_LEN + DETERM_ENOTE_TAG_LEN) /* 49 */

/* Seal `pt` (ptlen bytes; ptlen may be 0) to `recipient_pub` (33B compressed
 * P-256) with caller-supplied fresh `eph_sk` (32B, in [1, n-1]). Writes
 * exactly ptlen + DETERM_ENOTE_OVERHEAD bytes to `out` and sets *out_len.
 * Returns 0, or -1 (out/*out_len untouched) on a NULL arg, a bad recipient
 * point, a degenerate/out-of-range `eph_sk`, or internal failure.
 * `out` must have room for ptlen + DETERM_ENOTE_OVERHEAD bytes. */
int determ_enote_seal(const uint8_t recipient_pub[33],
                      const uint8_t *pt, size_t ptlen,
                      const uint8_t eph_sk[32],
                      uint8_t *out, size_t *out_len);

/* Trial-open `in` (in_len bytes, must be >= DETERM_ENOTE_OVERHEAD) with
 * `recipient_sk` (32B). On a verifying tag: writes in_len - DETERM_ENOTE_OVERHEAD
 * plaintext bytes to `pt_out`, sets *pt_len, returns 0. Returns -1 and writes
 * NOTHING if the note is not for this key, is tampered, or is malformed — the
 * -1 path is the scan "not mine" signal (constant-time in the AEAD compare).
 * `pt_out` must have room for in_len - DETERM_ENOTE_OVERHEAD bytes. */
int determ_enote_open(const uint8_t recipient_sk[32],
                      const uint8_t *in, size_t in_len,
                      uint8_t *pt_out, size_t *pt_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_ENOTE_H */
