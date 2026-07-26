/* D.5 lowest-hash sortition — see include/determ/dapp/d5draw.h for the frozen
 * SPEC §4 construction and the fail-closed contract. Byte-gated against
 * tools/verify_d5_draw.py / tools/vectors/d5_draw.json by `determ test-d5-draw`.
 * Pure C99, no chain/net; SHA-256 is the only dependency. */
#include <determ/dapp/d5draw.h>
#include <determ/crypto/sha2/sha2.h>

#include <stdlib.h>
#include <string.h>

static void put_u64_be(uint8_t out[8], uint64_t v) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}

/* Total order over members: (key asc, then id bytes asc, then shorter id).
 * Returns <0 if a precedes b, >0 if b precedes a, 0 iff a and b are identical
 * (only possible for a duplicated roster entry; the caller dedups upstream). */
static int d5_less(const uint8_t *ka, const uint8_t *ida, size_t la,
                   const uint8_t *kb, const uint8_t *idb, size_t lb) {
    int c = memcmp(ka, kb, 32);
    if (c != 0) return c;
    size_t m = (la < lb) ? la : lb;
    c = memcmp(ida, idb, m);
    if (c != 0) return c;
    if (la != lb) return (la < lb) ? -1 : 1;
    return 0;
}

int d5_draw(const uint8_t seed32[32],
            const uint8_t *domain,  size_t domain_len,
            const uint8_t *case_id, size_t case_id_len,
            uint64_t draw_height,
            uint64_t roster_cutoff_height,
            uint8_t  draw_algo_version,
            const uint8_t *const *ids, const size_t *id_lens, size_t count,
            size_t n_primary, size_t m_alternate,
            size_t *out_indices, size_t *out_count) {
    if (seed32 == NULL || ids == NULL || id_lens == NULL
        || out_indices == NULL || out_count == NULL) return -1;
    if (domain == NULL || domain_len == 0 || domain_len > D5_MAX_FIELD) return -1;
    if (case_id == NULL || case_id_len == 0 || case_id_len > D5_MAX_FIELD) return -1;
    if (draw_algo_version != D5_DRAW_ALGO_LOWEST_HASH) return -1;
    if (count == 0 || count > D5_MAX_ROSTER) return -1;
    /* Overflow-safe want = n_primary + m_alternate, bounded by count. */
    if (n_primary > count) return -1;
    if (m_alternate > count - n_primary) return -1;
    size_t want = n_primary + m_alternate;
    if (want == 0) return -1;
    for (size_t i = 0; i < count; i++) {
        if (ids[i] == NULL || id_lens[i] == 0 || id_lens[i] > D5_MAX_FIELD) return -1;
    }

    /* ctx = SHA256( domain || case_id || H_be64 || cutoff_be64 || algo )
     * — domain-separates the draw to this exact case + height + roster cutoff.
     * Dropping ctx from key() is the SPEC §11 primary falsify mutant. */
    uint8_t ctx[32];
    {
        determ_sha256_ctx c;
        uint8_t be[8];
        uint8_t algo = draw_algo_version;
        determ_sha256_init(&c);
        determ_sha256_update(&c, domain, domain_len);
        determ_sha256_update(&c, case_id, case_id_len);
        put_u64_be(be, draw_height);          determ_sha256_update(&c, be, 8);
        put_u64_be(be, roster_cutoff_height); determ_sha256_update(&c, be, 8);
        determ_sha256_update(&c, &algo, 1);
        determ_sha256_final(&c, ctx);
    }

    uint8_t *keys = (uint8_t *)malloc(count * 32u);
    size_t  *idx  = (size_t  *)malloc(count * sizeof(size_t));
    if (keys == NULL || idx == NULL) { free(keys); free(idx); return -1; }

    for (size_t i = 0; i < count; i++) {
        determ_sha256_ctx c;
        determ_sha256_init(&c);
        determ_sha256_update(&c, seed32, 32);
        determ_sha256_update(&c, ctx, 32);
        determ_sha256_update(&c, ids[i], id_lens[i]);
        determ_sha256_final(&c, keys + 32u * i);
        idx[i] = i;
    }

    /* Partial selection: pull the `want` smallest members to the front of idx[]
     * in ascending order (O(want*count), bounded by D5_MAX_ROSTER). */
    for (size_t k = 0; k < want; k++) {
        size_t best = k;
        for (size_t j = k + 1; j < count; j++) {
            if (d5_less(keys + 32u * idx[j],    ids[idx[j]],    id_lens[idx[j]],
                        keys + 32u * idx[best], ids[idx[best]], id_lens[idx[best]]) < 0) {
                best = j;
            }
        }
        size_t t = idx[k]; idx[k] = idx[best]; idx[best] = t;
    }

    for (size_t k = 0; k < want; k++) out_indices[k] = idx[k];
    *out_count = want;

    free(keys);
    free(idx);
    return 0;
}
