// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// NC-8 recipient note-key derivation — MODERN profile (1a). A dedicated note key
// from an INDEPENDENT seed (scan/spend separate from the audit layer). See
// include/determ/crypto/notekey/modern/notekey_modern.h.
#include <determ/crypto/notekey/modern/notekey_modern.h>
#include <determ/crypto/notekey/notekey.h>
#include <string.h>

int determ_notekey_modern_derive(const uint8_t  note_seed[32],
                                 const uint8_t *chain_id, size_t chain_id_len,
                                 const uint8_t *addr,     size_t addr_len,
                                 uint64_t       index,
                                 uint8_t note_sk[32], uint8_t note_pk[33]) {
    const char *dst = DETERM_NOTEKEY_MODERN_DST;
    return determ_notekey_from_ikm(note_seed,
                                   (const uint8_t *)dst, strlen(dst),
                                   chain_id, chain_id_len,
                                   addr, addr_len,
                                   index,
                                   note_sk, note_pk);
}
