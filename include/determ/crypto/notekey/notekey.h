/* NC-8 recipient note-key derivation (wiring inc.4) — CRYPTO-C99-SPEC §3.25.
 *
 * A recipient's enote scan/decrypt key is a P-256 keypair derived from a 32-byte
 * secret IKM, so a sender can seal a CONFIDENTIAL_TRANSFER delivery ciphertext to
 * note_pk (determ_enote_seal) and the recipient trial-decrypts with note_sk
 * (determ_enote_open). The derivation is a PURE COMPOSITION of shipped primitives
 * (RFC 9497 hash_to_scalar over P-256 + base mult + SEC1 compress) — NO new
 * hardness assumption.
 *
 *   note_sk = hash_to_scalar( ikm(32)
 *                          || len64_be(chain_id) || chain_id
 *                          || len64_be(addr)     || addr
 *                          || index_u64_be ,
 *                             DST )                      # canonical scalar in [1, n)
 *   note_pk = compress( note_sk · G )                    # 33-byte SEC1 compressed
 *
 * The length-prefixed big-endian encoding is byte-identical to the
 * unshield_spend_ctx_hash / view-key (§3.24) convention: the prefixes kill
 * concatenation ambiguity, so distinct (chain_id, addr, index) tuples never alias.
 *
 * The TWO profiles differ ONLY in the DST + the semantic source of the IKM
 * (src/crypto/notekey/modern, src/crypto/notekey/fips) — both call the shared
 * determ_notekey_from_ikm below:
 *   MODERN (1a): DST "determ-notekey-modern-v1", IKM = an independent note seed
 *                → scan/spend authority separate from the audit layer.
 *   FIPS   (1b): DST "determ-notekey-fips-v1",   IKM = the A2 view_master_sk
 *                (§3.24) → an auditor holding view_master_sk re-derives every
 *                note_sk and reads all deliveries (closes the "opaque audit key
 *                opens nothing" gap; one secret backs audit + note-scan).
 *
 * FAIL-CLOSED edges (return -1, outputs untouched): NULL args, empty chain_id or
 * addr (an ownerless/chain-less key would be replayable), a field longer than
 * DETERM_NOTEKEY_MAX_FIELD, or the (negligible, ~2^-256) zero scalar. The IKM-
 * bearing scratch is secure-zeroed on every path.
 *
 * PERMANENCE: the DSTs + encoding are permanent once accounts exist (no
 * migrations). Any change is a "-v2" DST, never an in-place edit. Byte-frozen
 * python-first against tools/verify_notekey.py + tools/vectors/notekey_*.json. */
#ifndef DETERM_CRYPTO_NOTEKEY_H
#define DETERM_CRYPTO_NOTEKEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_NOTEKEY_SK_LEN     32   /* P-256 scalar (big-endian)            */
#define DETERM_NOTEKEY_PK_LEN     33   /* SEC1 compressed P-256 point          */
#define DETERM_NOTEKEY_MAX_FIELD  256  /* cap on chain_id / addr length        */

/* Shared derivation. `dst` is the profile domain-separation tag. Returns 0 on
 * success (note_sk in [1, n), note_pk its compressed pubkey), -1 fail-closed. */
int determ_notekey_from_ikm(const uint8_t  ikm[32],
                            const uint8_t *dst,      size_t dst_len,
                            const uint8_t *chain_id, size_t chain_id_len,
                            const uint8_t *addr,     size_t addr_len,
                            uint64_t       index,
                            uint8_t note_sk[32], uint8_t note_pk[33]);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_CRYPTO_NOTEKEY_H */
