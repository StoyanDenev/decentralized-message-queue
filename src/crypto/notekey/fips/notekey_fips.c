// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// NC-8 recipient note-key derivation — FIPS profile (1b). Derived from the A2
// view_master_sk (§3.24), so an auditor holding it re-derives every note_sk and
// reads all deliveries. See include/determ/crypto/notekey/fips/notekey_fips.h.
#include <determ/crypto/notekey/fips/notekey_fips.h>
#include <determ/crypto/notekey/notekey.h>
#include <string.h>

int determ_notekey_fips_derive(const uint8_t  view_master_sk[32],
                               const uint8_t *chain_id, size_t chain_id_len,
                               const uint8_t *addr,     size_t addr_len,
                               uint64_t       index,
                               uint8_t note_sk[32], uint8_t note_pk[33]) {
    const char *dst = DETERM_NOTEKEY_FIPS_DST;
    return determ_notekey_from_ikm(view_master_sk,
                                   (const uint8_t *)dst, strlen(dst),
                                   chain_id, chain_id_len,
                                   addr, addr_len,
                                   index,
                                   note_sk, note_pk);
}
