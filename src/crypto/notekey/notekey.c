// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// NC-8 recipient note-key derivation — the SHARED base (CRYPTO-C99-SPEC §3.25).
// See include/determ/crypto/notekey/notekey.h for the construction + the two
// profile wrappers (src/crypto/notekey/modern, src/crypto/notekey/fips).
#include <determ/crypto/notekey/notekey.h>
#include <determ/crypto/p256/p256.h>       // hash_to_scalar / base_mul / compress
#include <determ/crypto/secure_zero.h>     // determ_secure_zero
#include <string.h>

/* msg = ikm(32) || u64_be(|chain_id|) || chain_id || u64_be(|addr|) || addr || index_u64_be */
#define NOTEKEY_MSG_MAX (32u + 8u + DETERM_NOTEKEY_MAX_FIELD + 8u + DETERM_NOTEKEY_MAX_FIELD + 8u)

static void put_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) *p++ = (uint8_t)((v >> (i * 8)) & 0xFF);
}

int determ_notekey_from_ikm(const uint8_t  ikm[32],
                            const uint8_t *dst,      size_t dst_len,
                            const uint8_t *chain_id, size_t chain_id_len,
                            const uint8_t *addr,     size_t addr_len,
                            uint64_t       index,
                            uint8_t note_sk[32], uint8_t note_pk[33]) {
    if (ikm == 0 || dst == 0 || note_sk == 0 || note_pk == 0)            return -1;
    if (chain_id == 0 || chain_id_len == 0 ||
        chain_id_len > DETERM_NOTEKEY_MAX_FIELD)                         return -1;
    if (addr == 0 || addr_len == 0 ||
        addr_len > DETERM_NOTEKEY_MAX_FIELD)                            return -1;

    uint8_t msg[NOTEKEY_MSG_MAX];
    size_t  off = 0;
    memcpy(msg + off, ikm, 32);                     off += 32;
    put_u64_be(msg + off, (uint64_t)chain_id_len);  off += 8;
    memcpy(msg + off, chain_id, chain_id_len);      off += chain_id_len;
    put_u64_be(msg + off, (uint64_t)addr_len);      off += 8;
    memcpy(msg + off, addr, addr_len);              off += addr_len;
    put_u64_be(msg + off, index);                   off += 8;

    uint8_t sk[32];
    int rc = determ_p256_hash_to_scalar(sk, msg, off, dst, dst_len);
    determ_secure_zero(msg, sizeof(msg));           // msg carries the secret IKM
    if (rc != 0) { determ_secure_zero(sk, sizeof(sk)); return -1; }

    // Fail-closed on the (negligible) zero scalar — note_sk must be in [1, n-1].
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) acc = (uint8_t)(acc | sk[i]);
    if (acc == 0) { determ_secure_zero(sk, sizeof(sk)); return -1; }

    uint8_t pub65[65];
    if (determ_p256_base_mul(pub65, sk) != 0) {
        determ_secure_zero(sk, sizeof(sk)); return -1;
    }
    if (determ_p256_point_compress(note_pk, pub65) != 0) {
        determ_secure_zero(sk, sizeof(sk)); return -1;
    }
    memcpy(note_sk, sk, 32);
    determ_secure_zero(sk, sizeof(sk));
    return 0;
}
