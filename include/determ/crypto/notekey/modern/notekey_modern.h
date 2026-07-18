/* NC-8 recipient note-key derivation — MODERN profile (1a), CRYPTO-C99-SPEC §3.25.
 *
 * A DEDICATED note key: derived from an INDEPENDENT 32-byte note seed (distinct
 * from the account's audit view-master), so scan/spend authority over delivered
 * notes stays cleanly separate from the A2 audit layer. Thin wrapper over the
 * shared determ_notekey_from_ikm (include/determ/crypto/notekey/notekey.h) with
 * DST "determ-notekey-modern-v1". This is the MODERN-profile recipient key; a
 * sender seals to note_pk, the recipient trial-decrypts with note_sk. */
#ifndef DETERM_CRYPTO_NOTEKEY_MODERN_H
#define DETERM_CRYPTO_NOTEKEY_MODERN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_NOTEKEY_MODERN_DST "determ-notekey-modern-v1"

/* Derive the MODERN dedicated note keypair for (note_seed, chain_id, addr,
 * index). Returns 0 (note_sk[32] + note_pk[33]) or -1 fail-closed. */
int determ_notekey_modern_derive(const uint8_t  note_seed[32],
                                 const uint8_t *chain_id, size_t chain_id_len,
                                 const uint8_t *addr,     size_t addr_len,
                                 uint64_t       index,
                                 uint8_t note_sk[32], uint8_t note_pk[33]);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_CRYPTO_NOTEKEY_MODERN_H */
