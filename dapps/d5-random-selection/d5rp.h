/* SPDX-License-Identifier: BUSL-1.1 */
/* Copyright 2026 Determ Contributors */
/*
 * D.5 government random-selection — REFERENCE RP (relying-party) PRODUCER core.
 *
 * This is the BUSL-1.1 orchestrator side of D.5 (dapps catalog: the first DApp,
 * founding MOTIVATION.md use case). It PRODUCES the three canonical-binary
 * DAPP_CALL payload streams a court authority publishes for a case — `roster`,
 * `case-open`, `result` — using ONLY the shipped, Apache-2.0 chain primitives
 * (determ-crypto-c99: d5codec + d5draw). It authenticates NOTHING and has NO
 * consensus authority; the chain never parses these payloads. Its correctness is
 * checked ADVERSARIALLY by the independent Apache-2.0 citizen verifier
 * (`determ-light verify-selection`, light/verify_selection.*): given the same
 * committee-authenticated beacon seed and the frozen roster, the citizen
 * re-derives the identical lowest-hash draw and refutes any published `result`
 * that disagrees. See docs/proofs/D5-RANDOM-SELECTION-SPEC.md §1/§11/§12.
 *
 * The RP is the substrate from which the Apache-2.0 RP SDK (`sdk/rp`) is later
 * extracted (DECISION-LOG 2026-07-26, CURRENT FRONT item 3): this producer core
 * is the RP-accept/produce logic the SDK re-exports.
 *
 * All inputs/outputs are PUBLIC on-chain content (non-PII candidate ids) — no
 * secret material, no constant-time obligation. Every function is fail-closed:
 * returns 0 on success, -1 on any malformed input / capacity overrun, and never
 * writes past `cap`.
 */
#ifndef DETERM_DAPP_D5RP_H
#define DETERM_DAPP_D5RP_H

#include <determ/dapp/d5codec.h>   /* d5_roster/case_open/result_{encode,decode} */
#include <determ/dapp/d5draw.h>    /* d5_draw, D5_DRAW_ALGO_LOWEST_HASH, caps    */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical DAPP_CALL topic strings (the tx.to routes to the D.5 domain; the
 * topic selects the stream inside the envelope). Kept byte-identical to the
 * strings the citizen verifier's collect_d5_streams matches on. */
#define D5_RP_TOPIC_ROSTER    "roster"
#define D5_RP_TOPIC_CASE_OPEN "case-open"
#define D5_RP_TOPIC_RESULT    "result"

/* The three producers below each emit a complete DAPP_CALL payload — a d5codec
 * message wrapped in the chain's envelope [u8 topic_len][topic][u32 LE ct_len][ct]
 * (include/determ/chain/block.hpp:150-157) — encoding the codec body in place so
 * no oversized temporary is needed. Topics are D5_RP_TOPIC_* (length 1..255). */

/* Build a `roster` DAPP_CALL payload (envelope over d5_roster_encode). `op` is
 * D5_ROSTER_ADD / D5_ROSTER_REMOVE; ids[]/id_lens[] carry `count` member ids. */
int d5_rp_build_roster(uint8_t op,
                       const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                       uint8_t *out, size_t cap, size_t *out_len);

/* Build a `case-open` DAPP_CALL payload. Freezes the eligible roster as of
 * `roster_cutoff_height` and pre-commits the case parameters BEFORE the
 * strictly-future `draw_height` (anti-grinding; the citizen enforces
 * h_o < draw_height < h_s). */
int d5_rp_build_case_open(const uint8_t *case_id, uint16_t case_id_len,
                          uint64_t roster_cutoff_height, uint64_t draw_height,
                          uint32_t n_primary, uint32_t m_alternate, uint8_t draw_algo_version,
                          uint8_t *out, size_t cap, size_t *out_len);

/* THE reference RP draw. Given the authenticated beacon seed
 * (cumulative_rand[draw_height], obtained + verified out of band) and the frozen
 * eligible roster, compute the canonical lowest-hash selection (thin over
 * d5_draw — bit-identical to what the citizen re-derives) AND build the `result`
 * DAPP_CALL payload committing it. Writes the selected indices (into ids[]) to
 * out_sel_idx[0..*out_sel_count) and the result payload to result_out.
 *
 * `out_sel_idx` must have room for n_primary+m_alternate entries; result_out
 * capacity `result_cap`. Returns -1 on a bad draw (e.g. n_primary+m_alternate >
 * count) or capacity overrun — the RP never publishes a partial/oversized draw. */
int d5_rp_open_and_draw(const uint8_t seed[32],
                        const uint8_t *domain, size_t domain_len,
                        const uint8_t *case_id, uint16_t case_id_len,
                        uint64_t roster_cutoff_height, uint64_t draw_height,
                        uint8_t draw_algo_version,
                        const uint8_t *const *ids, const uint16_t *id_lens, uint16_t count,
                        uint32_t n_primary, uint32_t m_alternate,
                        size_t *out_sel_idx, uint32_t *out_sel_count,
                        uint8_t *result_out, size_t result_cap, size_t *result_out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_DAPP_D5RP_H */
