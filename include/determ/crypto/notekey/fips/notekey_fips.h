/* NC-8 recipient note-key derivation — FIPS profile (1b), CRYPTO-C99-SPEC §3.25.
 *
 * Derived from the account's A2 view-master SECRET (the same 32-byte
 * view_master_sk that src/crypto/viewkey/viewkey.c §3.24 consumes as its HKDF
 * IKM), so ONE key backs both the audit layer AND note delivery: an auditor who
 * has been disclosed view_master_sk re-derives every note_sk with this function
 * and reads ALL of the account's delivered enotes — closing the "auditor holds
 * an opaque key that opens nothing" gap. Thin wrapper over the shared
 * determ_notekey_from_ikm (include/determ/crypto/notekey/notekey.h) with DST
 * "determ-notekey-fips-v1". A sender seals to note_pk; the recipient — or the
 * auditor — trial-decrypts with note_sk. */
#ifndef DETERM_CRYPTO_NOTEKEY_FIPS_H
#define DETERM_CRYPTO_NOTEKEY_FIPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_NOTEKEY_FIPS_DST "determ-notekey-fips-v1"

/* Derive the FIPS note keypair from the A2 view_master_sk for (chain_id, addr,
 * index). Returns 0 (note_sk[32] + note_pk[33]) or -1 fail-closed. */
int determ_notekey_fips_derive(const uint8_t  view_master_sk[32],
                               const uint8_t *chain_id, size_t chain_id_len,
                               const uint8_t *addr,     size_t addr_len,
                               uint64_t       index,
                               uint8_t note_sk[32], uint8_t note_pk[33]);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_CRYPTO_NOTEKEY_FIPS_H */
