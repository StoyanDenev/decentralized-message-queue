/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Determ Contributors */
/* D.5 government random-selection — canonical-binary payload codecs for the
 * three DAPP_CALL topics (roster / case-open / result). See
 * docs/proofs/D5-RANDOM-SELECTION-SPEC.md §3/§7. Canonical BINARY only
 * (DECISION-LOG D2 — no JSON on wire/storage); big-endian, length-prefixed,
 * strict (decode rejects truncated, over-cap, or trailing bytes). These are
 * DApp-layer payloads carried inside a DAPP_CALL's opaque ciphertext region;
 * the chain never parses them. Byte-gated against tools/verify_d5_codec.py /
 * tools/vectors/d5_codec.json by `determ test-d5-codec`.
 *
 * Decode is ZERO-COPY: variable-length fields (case_id, member ids) are
 * returned as pointers INTO the caller's `in` buffer, which must outlive the
 * decoded struct. No secret material (all fields are public on-chain content). */
#ifndef DETERM_DAPP_D5CODEC_H
#define DETERM_DAPP_D5CODEC_H

#include <determ/dapp/d5draw.h>   /* D5_MAX_ROSTER, D5_MAX_FIELD, algo version */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define D5_CODEC_FMT_VERSION 1u   /* payload format version (byte 0) */
#define D5_MSG_ROSTER        1u   /* msg_type byte (byte 1) */
#define D5_MSG_CASE_OPEN     2u
#define D5_MSG_RESULT        3u
#define D5_ROSTER_ADD        0u
#define D5_ROSTER_REMOVE     1u

/* ── roster (topic 'roster') ──
 * [u8 fmt=1][u8 type=1][u8 op][u16 count]{ [u16 id_len][id] }*count            */
int d5_roster_encode(uint8_t op,
                     const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                     uint8_t *out, size_t cap, size_t *out_len);
/* Fills the caller's ids[]/id_lens[] (capacity `cap`) with zero-copy pointers
 * into `in`; returns 0, sets *out_op + *out_count. -1 on malformed / over-cap. */
int d5_roster_decode(const uint8_t *in, size_t in_len,
                     uint8_t *out_op,
                     const uint8_t **ids, uint16_t *id_lens, uint16_t cap,
                     uint16_t *out_count);

/* ── case-open (topic 'case-open') ──
 * [u8 fmt=1][u8 type=2][u16 case_id_len][case_id][u64 roster_cutoff_height]
 * [u64 draw_height][u32 n_primary][u32 m_alternate][u8 draw_algo_version]      */
typedef struct {
    const uint8_t *case_id; uint16_t case_id_len;
    uint64_t roster_cutoff_height;
    uint64_t draw_height;
    uint32_t n_primary;
    uint32_t m_alternate;
    uint8_t  draw_algo_version;
} d5_case_open;
int d5_case_open_encode(const d5_case_open *co, uint8_t *out, size_t cap, size_t *out_len);
int d5_case_open_decode(const uint8_t *in, size_t in_len, d5_case_open *co);

/* ── result (topic 'result') ──
 * [u8 fmt=1][u8 type=3][u16 case_id_len][case_id][u64 draw_height]
 * [u64 roster_cutoff_height][seed:32][u8 draw_algo_version]
 * [u32 n_primary][u32 m_alternate]{ [u16 id_len][id] }*(n_primary+m_alternate) */
typedef struct {
    const uint8_t *case_id; uint16_t case_id_len;
    uint64_t draw_height;
    uint64_t roster_cutoff_height;
    uint8_t  seed[32];
    uint8_t  draw_algo_version;
    uint32_t n_primary;
    uint32_t m_alternate;
} d5_result_hdr;
int d5_result_encode(const d5_result_hdr *r,
                     const uint8_t *const *sel_ids, const uint16_t *sel_lens, uint32_t sel_count,
                     uint8_t *out, size_t cap, size_t *out_len);
int d5_result_decode(const uint8_t *in, size_t in_len, d5_result_hdr *r,
                     const uint8_t **sel_ids, uint16_t *sel_lens, uint32_t cap,
                     uint32_t *out_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_DAPP_D5CODEC_H */
