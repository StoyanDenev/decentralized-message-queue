/* SPDX-License-Identifier: BUSL-1.1 */
/* Copyright 2026 Determ Contributors */
/*
 * D.5 reference-RP producer core. See d5rp.h for the trust model. Pure
 * composition over the shipped Apache-2.0 primitives d5codec + d5draw — no new
 * crypto, no consensus authority, no secret material. Fail-closed throughout.
 */
#include "d5rp.h"
#include <stdlib.h>
#include <string.h>

/* DAPP_CALL envelope header = [u8 topic_len][topic][u32 LE ct_len]. */
static int rp_hdr_len(const char *topic, size_t *hdr) {
    if (topic == NULL) return -1;
    size_t tlen = strlen(topic);
    if (tlen == 0 || tlen > 255) return -1;
    *hdr = 1u + tlen + 4u;
    return 0;
}

static void rp_write_hdr(const char *topic, size_t ct_len, uint8_t *out) {
    size_t tlen = strlen(topic);
    out[0] = (uint8_t)tlen;
    memcpy(out + 1, topic, tlen);
    uint32_t cl = (uint32_t)ct_len;
    out[1 + tlen + 0] = (uint8_t)(cl & 0xffu);
    out[1 + tlen + 1] = (uint8_t)((cl >> 8) & 0xffu);
    out[1 + tlen + 2] = (uint8_t)((cl >> 16) & 0xffu);
    out[1 + tlen + 3] = (uint8_t)((cl >> 24) & 0xffu);
}

/* Encode a d5codec payload directly into out+hdr, then backfill the envelope
 * header — a single buffer, no oversized temporary. */
#define RP_FRAME_BEGIN(topic_str)                                    \
    size_t hdr = 0;                                                  \
    if (out == NULL || out_len == NULL) return -1;                   \
    if (rp_hdr_len((topic_str), &hdr) != 0) return -1;               \
    if (cap < hdr) return -1;                                        \
    size_t ct_len = 0;

#define RP_FRAME_END(topic_str)                                      \
    if (ct_len > 0xffffffffu) return -1;                             \
    rp_write_hdr((topic_str), ct_len, out);                          \
    *out_len = hdr + ct_len;                                         \
    return 0;

int d5_rp_build_roster(uint8_t op,
                       const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                       uint8_t *out, size_t cap, size_t *out_len) {
    RP_FRAME_BEGIN(D5_RP_TOPIC_ROSTER)
    if (d5_roster_encode(op, ids, id_lens, count, out + hdr, cap - hdr, &ct_len) != 0)
        return -1;
    RP_FRAME_END(D5_RP_TOPIC_ROSTER)
}

int d5_rp_build_case_open(const uint8_t *case_id, uint16_t case_id_len,
                          uint64_t roster_cutoff_height, uint64_t draw_height,
                          uint32_t n_primary, uint32_t m_alternate, uint8_t draw_algo_version,
                          uint8_t *out, size_t cap, size_t *out_len) {
    d5_case_open co;
    co.case_id = case_id;   co.case_id_len = case_id_len;
    co.roster_cutoff_height = roster_cutoff_height;
    co.draw_height = draw_height;
    co.n_primary = n_primary; co.m_alternate = m_alternate;
    co.draw_algo_version = draw_algo_version;
    RP_FRAME_BEGIN(D5_RP_TOPIC_CASE_OPEN)
    if (d5_case_open_encode(&co, out + hdr, cap - hdr, &ct_len) != 0) return -1;
    RP_FRAME_END(D5_RP_TOPIC_CASE_OPEN)
}

int d5_rp_open_and_draw(const uint8_t seed[32],
                        const uint8_t *domain, size_t domain_len,
                        const uint8_t *case_id, uint16_t case_id_len,
                        uint64_t roster_cutoff_height, uint64_t draw_height,
                        uint8_t draw_algo_version,
                        const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                        uint32_t n_primary, uint32_t m_alternate,
                        size_t *out_sel_idx, uint32_t *out_sel_count,
                        uint8_t *result_out, size_t result_cap, size_t *result_out_len) {
    if (out_sel_idx == NULL || out_sel_count == NULL) return -1;
    if (result_out == NULL || result_out_len == NULL) return -1;
    if (count == 0) return -1;

    /* d5_draw takes size_t id_lens; the codec API is uint16_t — convert. */
    size_t *sidl = (size_t *)malloc((size_t)count * sizeof(*sidl));
    if (sidl == NULL) return -1;
    for (uint16_t i = 0; i < count; i++) sidl[i] = id_lens[i];

    size_t oc = 0;
    int drc = d5_draw(seed, domain, domain_len, case_id, case_id_len,
                      draw_height, roster_cutoff_height, draw_algo_version,
                      ids, sidl, (size_t)count,
                      (size_t)n_primary, (size_t)m_alternate,
                      out_sel_idx, &oc);
    free(sidl);
    if (drc != 0) return -1;                       /* bad params (N+M > count, etc.) */
    *out_sel_count = (uint32_t)oc;

    /* Gather the selected (id, len) pairs in the drawn (ascending-key) order. */
    const uint8_t **sel_ids = (const uint8_t **)malloc(oc * sizeof(*sel_ids));
    uint16_t *sel_lens = (uint16_t *)malloc(oc * sizeof(*sel_lens));
    if (sel_ids == NULL || sel_lens == NULL) { free((void *)sel_ids); free(sel_lens); return -1; }
    for (size_t k = 0; k < oc; k++) {
        size_t idx = out_sel_idx[k];
        sel_ids[k]  = ids[idx];
        sel_lens[k] = id_lens[idx];
    }

    d5_result_hdr r;
    r.case_id = case_id;   r.case_id_len = case_id_len;
    r.draw_height = draw_height;
    r.roster_cutoff_height = roster_cutoff_height;
    memcpy(r.seed, seed, 32);
    r.draw_algo_version = draw_algo_version;
    r.n_primary = n_primary; r.m_alternate = m_alternate;

    /* Encode the result payload into result_out past the envelope header. */
    size_t hdr = 0;
    int rc = -1;
    if (rp_hdr_len(D5_RP_TOPIC_RESULT, &hdr) == 0 && result_cap >= hdr) {
        size_t ct_len = 0;
        if (d5_result_encode(&r, sel_ids, sel_lens, (uint32_t)oc,
                             result_out + hdr, result_cap - hdr, &ct_len) == 0
            && ct_len <= 0xffffffffu) {
            rp_write_hdr(D5_RP_TOPIC_RESULT, ct_len, result_out);
            *result_out_len = hdr + ct_len;
            rc = 0;
        }
    }
    free((void *)sel_ids);
    free(sel_lens);
    return rc;
}
