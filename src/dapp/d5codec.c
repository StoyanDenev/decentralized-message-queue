/* D.5 canonical-binary payload codecs — see include/determ/dapp/d5codec.h for
 * the frozen §3/§7 wire layouts and the strict fail-closed contract. Big-endian,
 * length-prefixed, no JSON (DECISION-LOG D2). Byte-gated against
 * tools/verify_d5_codec.py / tools/vectors/d5_codec.json by `determ test-d5-codec`. */
#include <determ/dapp/d5codec.h>

#include <string.h>

/* ── bounds-checked big-endian writer ── */
typedef struct { uint8_t *p; size_t cap; size_t off; int ok; } d5_wr;
static void w_u8(d5_wr *w, uint8_t v) {
    if (!w->ok || w->off + 1 > w->cap) { w->ok = 0; return; }
    w->p[w->off++] = v;
}
static void w_u16(d5_wr *w, uint16_t v) {
    if (!w->ok || w->off + 2 > w->cap) { w->ok = 0; return; }
    w->p[w->off++] = (uint8_t)(v >> 8); w->p[w->off++] = (uint8_t)v;
}
static void w_u32(d5_wr *w, uint32_t v) {
    if (!w->ok || w->off + 4 > w->cap) { w->ok = 0; return; }
    for (int i = 3; i >= 0; i--) w->p[w->off++] = (uint8_t)(v >> (8 * i));
}
static void w_u64(d5_wr *w, uint64_t v) {
    if (!w->ok || w->off + 8 > w->cap) { w->ok = 0; return; }
    for (int i = 7; i >= 0; i--) w->p[w->off++] = (uint8_t)(v >> (8 * i));
}
static void w_bytes(d5_wr *w, const uint8_t *b, size_t n) {
    if (!w->ok || w->off + n > w->cap) { w->ok = 0; return; }
    if (n) memcpy(w->p + w->off, b, n);
    w->off += n;
}

/* ── bounds-checked big-endian reader ── */
typedef struct { const uint8_t *p; size_t len; size_t off; int ok; } d5_rd;
static uint8_t r_u8(d5_rd *r) {
    if (!r->ok || r->off + 1 > r->len) { r->ok = 0; return 0; }
    return r->p[r->off++];
}
static uint16_t r_u16(d5_rd *r) {
    if (!r->ok || r->off + 2 > r->len) { r->ok = 0; return 0; }
    uint16_t v = (uint16_t)((r->p[r->off] << 8) | r->p[r->off + 1]); r->off += 2; return v;
}
static uint32_t r_u32(d5_rd *r) {
    if (!r->ok || r->off + 4 > r->len) { r->ok = 0; return 0; }
    uint32_t v = 0; for (int i = 0; i < 4; i++) v = (v << 8) | r->p[r->off++]; return v;
}
static uint64_t r_u64(d5_rd *r) {
    if (!r->ok || r->off + 8 > r->len) { r->ok = 0; return 0; }
    uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | r->p[r->off++]; return v;
}
static const uint8_t *r_bytes(d5_rd *r, size_t n) {
    if (!r->ok || r->off + n > r->len) { r->ok = 0; return 0; }
    const uint8_t *b = r->p + r->off; r->off += n; return b;
}

/* ── roster ── */
int d5_roster_encode(uint8_t op,
                     const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                     uint8_t *out, size_t cap, size_t *out_len) {
    if (out == NULL || out_len == NULL || ids == NULL || id_lens == NULL) return -1;
    if (op != D5_ROSTER_ADD && op != D5_ROSTER_REMOVE) return -1;
    if (count == 0 || count > D5_MAX_ROSTER) return -1;
    for (uint16_t i = 0; i < count; i++) {
        if (ids[i] == NULL || id_lens[i] == 0 || id_lens[i] > D5_MAX_FIELD) return -1;
    }
    d5_wr w = { out, cap, 0, 1 };
    w_u8(&w, D5_CODEC_FMT_VERSION);
    w_u8(&w, D5_MSG_ROSTER);
    w_u8(&w, op);
    w_u16(&w, count);
    for (uint16_t i = 0; i < count; i++) { w_u16(&w, id_lens[i]); w_bytes(&w, ids[i], id_lens[i]); }
    if (!w.ok) return -1;
    *out_len = w.off;
    return 0;
}

int d5_roster_decode(const uint8_t *in, size_t in_len,
                     uint8_t *out_op,
                     const uint8_t **ids, uint16_t *id_lens, uint16_t cap,
                     uint16_t *out_count) {
    if (in == NULL || out_op == NULL || ids == NULL || id_lens == NULL || out_count == NULL) return -1;
    d5_rd r = { in, in_len, 0, 1 };
    if (r_u8(&r) != D5_CODEC_FMT_VERSION) return -1;
    if (r_u8(&r) != D5_MSG_ROSTER) return -1;
    uint8_t op = r_u8(&r);
    if (op != D5_ROSTER_ADD && op != D5_ROSTER_REMOVE) return -1;
    uint16_t count = r_u16(&r);
    if (!r.ok || count == 0 || count > D5_MAX_ROSTER || count > cap) return -1;
    for (uint16_t i = 0; i < count; i++) {
        uint16_t l = r_u16(&r);
        if (!r.ok || l == 0 || l > D5_MAX_FIELD) return -1;
        const uint8_t *b = r_bytes(&r, l);
        if (!r.ok) return -1;
        ids[i] = b; id_lens[i] = l;
    }
    if (!r.ok || r.off != in_len) return -1;   /* strict: no trailing bytes */
    *out_op = op; *out_count = count;
    return 0;
}

/* ── case-open ── */
int d5_case_open_encode(const d5_case_open *co, uint8_t *out, size_t cap, size_t *out_len) {
    if (co == NULL || out == NULL || out_len == NULL) return -1;
    if (co->case_id == NULL || co->case_id_len == 0 || co->case_id_len > D5_MAX_FIELD) return -1;
    d5_wr w = { out, cap, 0, 1 };
    w_u8(&w, D5_CODEC_FMT_VERSION);
    w_u8(&w, D5_MSG_CASE_OPEN);
    w_u16(&w, co->case_id_len);
    w_bytes(&w, co->case_id, co->case_id_len);
    w_u64(&w, co->roster_cutoff_height);
    w_u64(&w, co->draw_height);
    w_u32(&w, co->n_primary);
    w_u32(&w, co->m_alternate);
    w_u8(&w, co->draw_algo_version);
    if (!w.ok) return -1;
    *out_len = w.off;
    return 0;
}

int d5_case_open_decode(const uint8_t *in, size_t in_len, d5_case_open *co) {
    if (in == NULL || co == NULL) return -1;
    d5_rd r = { in, in_len, 0, 1 };
    if (r_u8(&r) != D5_CODEC_FMT_VERSION) return -1;
    if (r_u8(&r) != D5_MSG_CASE_OPEN) return -1;
    uint16_t l = r_u16(&r);
    if (!r.ok || l == 0 || l > D5_MAX_FIELD) return -1;
    const uint8_t *cid = r_bytes(&r, l);
    if (!r.ok) return -1;
    co->case_id = cid; co->case_id_len = l;
    co->roster_cutoff_height = r_u64(&r);
    co->draw_height = r_u64(&r);
    co->n_primary = r_u32(&r);
    co->m_alternate = r_u32(&r);
    co->draw_algo_version = r_u8(&r);
    if (!r.ok || r.off != in_len) return -1;
    return 0;
}

/* ── result ── */
int d5_result_encode(const d5_result_hdr *r,
                     const uint8_t *const *sel_ids, const uint16_t *sel_lens, uint32_t sel_count,
                     uint8_t *out, size_t cap, size_t *out_len) {
    if (r == NULL || out == NULL || out_len == NULL || sel_ids == NULL || sel_lens == NULL) return -1;
    if (r->case_id == NULL || r->case_id_len == 0 || r->case_id_len > D5_MAX_FIELD) return -1;
    /* sel_count must equal n_primary+m_alternate (overflow-safe) and be bounded. */
    if (r->n_primary > D5_MAX_ROSTER || r->m_alternate > D5_MAX_ROSTER - r->n_primary) return -1;
    if (sel_count != r->n_primary + r->m_alternate) return -1;
    if (sel_count == 0 || sel_count > D5_MAX_ROSTER) return -1;
    for (uint32_t i = 0; i < sel_count; i++) {
        if (sel_ids[i] == NULL || sel_lens[i] == 0 || sel_lens[i] > D5_MAX_FIELD) return -1;
    }
    d5_wr w = { out, cap, 0, 1 };
    w_u8(&w, D5_CODEC_FMT_VERSION);
    w_u8(&w, D5_MSG_RESULT);
    w_u16(&w, r->case_id_len);
    w_bytes(&w, r->case_id, r->case_id_len);
    w_u64(&w, r->draw_height);
    w_u64(&w, r->roster_cutoff_height);
    w_bytes(&w, r->seed, 32);
    w_u8(&w, r->draw_algo_version);
    w_u32(&w, r->n_primary);
    w_u32(&w, r->m_alternate);
    for (uint32_t i = 0; i < sel_count; i++) { w_u16(&w, sel_lens[i]); w_bytes(&w, sel_ids[i], sel_lens[i]); }
    if (!w.ok) return -1;
    *out_len = w.off;
    return 0;
}

int d5_result_decode(const uint8_t *in, size_t in_len, d5_result_hdr *hdr,
                     const uint8_t **sel_ids, uint16_t *sel_lens, uint32_t cap,
                     uint32_t *out_count) {
    if (in == NULL || hdr == NULL || sel_ids == NULL || sel_lens == NULL || out_count == NULL) return -1;
    d5_rd r = { in, in_len, 0, 1 };
    if (r_u8(&r) != D5_CODEC_FMT_VERSION) return -1;
    if (r_u8(&r) != D5_MSG_RESULT) return -1;
    uint16_t l = r_u16(&r);
    if (!r.ok || l == 0 || l > D5_MAX_FIELD) return -1;
    const uint8_t *cid = r_bytes(&r, l);
    if (!r.ok) return -1;
    hdr->case_id = cid; hdr->case_id_len = l;
    hdr->draw_height = r_u64(&r);
    hdr->roster_cutoff_height = r_u64(&r);
    const uint8_t *sd = r_bytes(&r, 32);
    if (!r.ok) return -1;
    memcpy(hdr->seed, sd, 32);
    hdr->draw_algo_version = r_u8(&r);
    hdr->n_primary = r_u32(&r);
    hdr->m_alternate = r_u32(&r);
    if (!r.ok) return -1;
    if (hdr->n_primary > D5_MAX_ROSTER || hdr->m_alternate > D5_MAX_ROSTER - hdr->n_primary) return -1;
    uint32_t total = hdr->n_primary + hdr->m_alternate;
    if (total == 0 || total > D5_MAX_ROSTER || total > cap) return -1;
    for (uint32_t i = 0; i < total; i++) {
        uint16_t idl = r_u16(&r);
        if (!r.ok || idl == 0 || idl > D5_MAX_FIELD) return -1;
        const uint8_t *b = r_bytes(&r, idl);
        if (!r.ok) return -1;
        sel_ids[i] = b; sel_lens[i] = idl;
    }
    if (!r.ok || r.off != in_len) return -1;   /* strict: no trailing bytes */
    *out_count = total;
    return 0;
}
