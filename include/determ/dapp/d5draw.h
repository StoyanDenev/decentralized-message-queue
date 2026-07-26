/* D.5 government random-selection — lowest-hash sortition (the sole gated
 * primitive of the D.5 reference DApp). See docs/proofs/D5-RANDOM-SELECTION-SPEC.md
 * §4 (draw construction ratified D1, 2026-07-26). Pure, deterministic,
 * order-independent; keyed on the committee-authenticated cumulative_rand[H]
 * beacon. Apache-2.0 (the citizen-verifier core; §13 D8). Byte-gated against
 * tools/verify_d5_draw.py / tools/vectors/d5_draw.json by `determ test-d5-draw`.
 *
 * No secret material: seed, ctx fields, and roster ids are all public
 * (cumulative_rand is on-chain; the roster is a public DAPP_CALL stream), so
 * there is no timing side channel to protect — this is a public deterministic
 * selection, verifiable by anyone. */
#ifndef DETERM_DAPP_D5DRAW_H
#define DETERM_DAPP_D5DRAW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* draw_algo_version (frozen-once-live; D1 ratified). v1 = lowest-hash sortition. */
#define D5_DRAW_ALGO_LOWEST_HASH 1u

/* Fail-closed bounds for a single draw. D5_MAX_ROSTER bounds the O(want*count)
 * selection + the heap allocation; a government judge/jury pool is far smaller. */
#define D5_MAX_ROSTER 16384u  /* max eligible members per draw */
#define D5_MAX_FIELD  4096u   /* max domain / case_id / member-id length (bytes) */

/* Lowest-hash sortition (SPEC §4):
 *   ctx    = SHA256( domain || case_id || draw_height_be64 ||
 *                    roster_cutoff_height_be64 || draw_algo_version )
 *   key(i) = SHA256( seed32 || ctx || id_i )
 *   select = the (n_primary + m_alternate) members with the SMALLEST key,
 *            ascending (primaries rank 0..N-1, then the alternates); tie-break
 *            on the id bytes (memcmp, shorter id first on a shared prefix).
 *
 * seed32 = cumulative_rand[H] (committee-authenticated by the caller/verifier).
 * ids/id_lens: `count` eligible member identifiers (each in [1, D5_MAX_FIELD]).
 *
 * On success writes n_primary+m_alternate member INDICES (into ids[]) to
 * out_indices[] in selection order and sets *out_count = n_primary+m_alternate;
 * returns 0. ORDER-INDEPENDENT: permuting ids[] permutes only the reported
 * indices, never the selected SET. Returns -1 on any invalid argument (NULL,
 * count==0 or > D5_MAX_ROSTER, an id length ==0 or > D5_MAX_FIELD,
 * n_primary+m_alternate ==0 or > count, an unknown draw_algo_version, or an
 * internal allocation failure); on -1 no output is written. */
int d5_draw(const uint8_t seed32[32],
            const uint8_t *domain,  size_t domain_len,
            const uint8_t *case_id, size_t case_id_len,
            uint64_t draw_height,
            uint64_t roster_cutoff_height,
            uint8_t  draw_algo_version,
            const uint8_t *const *ids, const size_t *id_lens, size_t count,
            size_t n_primary, size_t m_alternate,
            size_t *out_indices, size_t *out_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_DAPP_D5DRAW_H */
