/* SPDX-License-Identifier: BUSL-1.1 */
/* Copyright 2026 Determ Contributors */
/*
 * d5rp — the D.5 reference-RP producer CLI (BUSL-1.1). Subcommands:
 *
 *   selftest   The FAST offline gate. Produces the three DAPP_CALL streams for a
 *              fixed scenario, strips each envelope, decodes via d5codec, and
 *              INDEPENDENTLY re-derives the lowest-hash draw over the decoded
 *              roster + seed — asserting it equals the PUBLISHED `result`. This
 *              is exactly the contract the Apache-2.0 citizen verifier
 *              (`determ-light verify-selection`) enforces adversarially, so an
 *              honest RP's output is provably re-derivable. A tamper NEG flips
 *              one byte of a published selected id and confirms the round-trip
 *              CATCHES it (the binding is real, not vacuous).
 *              Falsify-on-mutant: mutate d5_rp_open_and_draw to publish a
 *              non-canonical result -> only the CTRL "published == canonical"
 *              assertion flips RED.
 *
 *   emit       Print the demo scenario's three payloads as hex (roster,
 *              case-open, result) — a reference feed for an independent oracle
 *              or a manual DAPP_CALL submission.
 */
#include "d5rp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the fixed demo scenario (shared by selftest + emit) ── */
#define RP_DOMAIN     "d5.court"
#define RP_CASE_ID    "CASE-1"
#define RP_NMEMBERS   12
#define RP_CUTOFF     80u
#define RP_DRAW_H     100u
#define RP_NPRIMARY   3u
#define RP_MALT       2u
/* Decode-array capacity for the selftest scenario (12 members). Deliberately a
 * small constant, NOT D5_MAX_ROSTER(16384) — the latter would put ~750KB of
 * arrays on the stack (fragile on constrained / Minix-portable targets, near the
 * 1MB MSVC main-thread reserve). Ample headroom over RP_NMEMBERS. */
#define RP_DECODE_CAP 256u

static void demo_seed(uint8_t seed[32]) {
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
}

/* Build the demo roster: ids "D5-MEMBER-0".."D5-MEMBER-<N-1>". `store` must
 * hold N * 16 bytes; ids[]/lens[] are filled with pointers into it. */
static void demo_roster(char *store, const uint8_t **ids, uint16_t *lens, uint16_t n) {
    for (uint16_t i = 0; i < n; i++) {
        char *p = store + (size_t)i * 16;
        int m = snprintf(p, 16, "D5-MEMBER-%u", (unsigned)i);
        ids[i]  = (const uint8_t *)p;
        lens[i] = (uint16_t)m;
    }
}

/* Strip the DAPP_CALL envelope [u8 tlen][topic][u32 LE ctlen][ct]; on success
 * point *ct/*ct_len at the ciphertext region and copy the topic. Returns 0. */
static int strip_env(const uint8_t *p, size_t len, char *topic_out, size_t topic_cap,
                     const uint8_t **ct, size_t *ct_len) {
    if (len < 1) return -1;
    size_t off = 0;
    uint8_t tl = p[off++];
    if (tl == 0 || off + tl + 4 > len || (size_t)tl + 1 > topic_cap) return -1;
    memcpy(topic_out, p + off, tl); topic_out[tl] = '\0'; off += tl;
    uint32_t cl = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8)
                | ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
    off += 4;
    if (off + cl != len) return -1;               /* strict: no trailing bytes */
    *ct = cl ? p + off : (const uint8_t *)"";
    *ct_len = cl;
    return 0;
}

static void put_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int cmd_emit(void) {
    uint8_t seed[32]; demo_seed(seed);
    char store[RP_NMEMBERS * 16];
    const uint8_t *ids[RP_NMEMBERS]; uint16_t lens[RP_NMEMBERS];
    demo_roster(store, ids, lens, RP_NMEMBERS);

    uint8_t roster[4096], caseopen[256], result[4096];
    size_t rl = 0, cl = 0, sl = 0;
    size_t sel_idx[RP_NPRIMARY + RP_MALT]; uint32_t sel_n = 0;

    if (d5_rp_build_roster(D5_ROSTER_ADD, ids, lens, RP_NMEMBERS, roster, sizeof roster, &rl) != 0
     || d5_rp_build_case_open((const uint8_t *)RP_CASE_ID, (uint16_t)strlen(RP_CASE_ID),
                              RP_CUTOFF, RP_DRAW_H, RP_NPRIMARY, RP_MALT,
                              D5_DRAW_ALGO_LOWEST_HASH, caseopen, sizeof caseopen, &cl) != 0
     || d5_rp_open_and_draw(seed, (const uint8_t *)RP_DOMAIN, strlen(RP_DOMAIN),
                            (const uint8_t *)RP_CASE_ID, (uint16_t)strlen(RP_CASE_ID),
                            RP_CUTOFF, RP_DRAW_H, D5_DRAW_ALGO_LOWEST_HASH,
                            ids, lens, RP_NMEMBERS, RP_NPRIMARY, RP_MALT,
                            sel_idx, &sel_n, result, sizeof result, &sl) != 0) {
        fprintf(stderr, "emit: producer failed\n");
        return 1;
    }
    printf("# D.5 reference-RP demo: domain=%s case_id=%s draw_height=%u N=%u M=%u\n",
           RP_DOMAIN, RP_CASE_ID, (unsigned)RP_DRAW_H, (unsigned)RP_NPRIMARY, (unsigned)RP_MALT);
    put_hex("roster", roster, rl);
    put_hex("case-open", caseopen, cl);
    put_hex("result", result, sl);
    return 0;
}

static int cmd_selftest(void) {
    int pass = 0, fail = 0;
    #define CHECK(ok, what) do { if (ok) { printf("  PASS: %s\n", (what)); ++pass; } \
                                 else    { printf("  FAIL: %s\n", (what)); ++fail; } } while (0)

    uint8_t seed[32]; demo_seed(seed);
    char store[RP_NMEMBERS * 16];
    const uint8_t *ids[RP_NMEMBERS]; uint16_t lens[RP_NMEMBERS];
    demo_roster(store, ids, lens, RP_NMEMBERS);

    uint8_t roster[4096], caseopen[256], result[4096];
    size_t rl = 0, cl = 0, sl = 0;
    size_t sel_idx[RP_NPRIMARY + RP_MALT]; uint32_t sel_n = 0;

    int produced =
        d5_rp_build_roster(D5_ROSTER_ADD, ids, lens, RP_NMEMBERS, roster, sizeof roster, &rl) == 0
     && d5_rp_build_case_open((const uint8_t *)RP_CASE_ID, (uint16_t)strlen(RP_CASE_ID),
                              RP_CUTOFF, RP_DRAW_H, RP_NPRIMARY, RP_MALT,
                              D5_DRAW_ALGO_LOWEST_HASH, caseopen, sizeof caseopen, &cl) == 0
     && d5_rp_open_and_draw(seed, (const uint8_t *)RP_DOMAIN, strlen(RP_DOMAIN),
                            (const uint8_t *)RP_CASE_ID, (uint16_t)strlen(RP_CASE_ID),
                            RP_CUTOFF, RP_DRAW_H, D5_DRAW_ALGO_LOWEST_HASH,
                            ids, lens, RP_NMEMBERS, RP_NPRIMARY, RP_MALT,
                            sel_idx, &sel_n, result, sizeof result, &sl) == 0;
    CHECK(produced && sel_n == RP_NPRIMARY + RP_MALT,
          "producer emits roster + case-open + result and draws N+M members");
    if (!produced) { printf("\n  %d pass / %d fail\n  FAIL: selftest-d5rp\n", pass, fail); return 1; }

    /* ── strip envelopes + confirm topics ── */
    char t_r[64], t_c[64], t_s[64];
    const uint8_t *ct_r, *ct_c, *ct_s; size_t cl_r, cl_c, cl_s;
    int env_ok = strip_env(roster, rl, t_r, sizeof t_r, &ct_r, &cl_r) == 0
              && strip_env(caseopen, cl, t_c, sizeof t_c, &ct_c, &cl_c) == 0
              && strip_env(result, sl, t_s, sizeof t_s, &ct_s, &cl_s) == 0
              && strcmp(t_r, D5_RP_TOPIC_ROSTER) == 0
              && strcmp(t_c, D5_RP_TOPIC_CASE_OPEN) == 0
              && strcmp(t_s, D5_RP_TOPIC_RESULT) == 0;
    CHECK(env_ok, "each payload carries the DAPP_CALL envelope with the right topic");

    /* ── decode roster + confirm it round-trips the input ── */
    uint8_t rop = 0xff;
    const uint8_t *rids[RP_DECODE_CAP]; uint16_t rlens[RP_DECODE_CAP]; uint16_t rcount = 0;
    int roster_ok = env_ok
        && d5_roster_decode(ct_r, cl_r, &rop, rids, rlens, RP_DECODE_CAP, &rcount) == 0
        && rop == D5_ROSTER_ADD && rcount == RP_NMEMBERS;
    if (roster_ok)
        for (uint16_t i = 0; i < RP_NMEMBERS; i++)
            if (rlens[i] != lens[i] || memcmp(rids[i], ids[i], lens[i]) != 0) { roster_ok = 0; break; }
    CHECK(roster_ok, "roster payload decodes byte-for-byte back to the published roster");

    /* ── decode case-open + confirm the frozen parameters ── */
    d5_case_open dco; memset(&dco, 0, sizeof dco);
    int co_ok = env_ok && d5_case_open_decode(ct_c, cl_c, &dco) == 0
        && dco.case_id_len == strlen(RP_CASE_ID)
        && memcmp(dco.case_id, RP_CASE_ID, dco.case_id_len) == 0
        && dco.roster_cutoff_height == RP_CUTOFF && dco.draw_height == RP_DRAW_H
        && dco.n_primary == RP_NPRIMARY && dco.m_alternate == RP_MALT;
    CHECK(co_ok, "case-open payload decodes to the pre-committed cutoff / draw_height / N,M");

    /* ── decode result ── */
    d5_result_hdr dr; memset(&dr, 0, sizeof dr);
    const uint8_t *sids[RP_DECODE_CAP]; uint16_t slens[RP_DECODE_CAP]; uint32_t scount = 0;
    int res_ok = env_ok && d5_result_decode(ct_s, cl_s, &dr, sids, slens, RP_DECODE_CAP, &scount) == 0
        && scount == sel_n && dr.draw_height == RP_DRAW_H;
    CHECK(res_ok, "result payload decodes to the published selection");

    /* ── THE contract: INDEPENDENTLY re-derive the draw over the DECODED roster +
     *    seed under the DECODED case params, and require it to equal the DECODED
     *    published result (this is verify_selection_core's core check). ── */
    int agree = 0;
    if (roster_ok && co_ok && res_ok) {
        size_t sidl2[RP_DECODE_CAP];
        for (uint16_t i = 0; i < rcount; i++) sidl2[i] = rlens[i];
        size_t re_idx[RP_NPRIMARY + RP_MALT]; size_t re_oc = 0;
        /* Re-derive with the AUTHENTICATED beacon seed `seed` — NOT the result
         * payload's dr.seed field. The citizen (verify_selection_core) never
         * trusts the RP's published seed claim; it uses the S-042-authenticated
         * cumulative_rand[draw_height]. Using dr.seed here would let an RP that
         * writes a fake seed match its own fake-seed draw while the real citizen
         * (authenticated seed) rejects — a gap the honest scenario would hide. */
        int rc = d5_draw(seed, (const uint8_t *)RP_DOMAIN, strlen(RP_DOMAIN),
                         dco.case_id, dco.case_id_len, dco.draw_height,
                         dco.roster_cutoff_height, dco.draw_algo_version,
                         rids, sidl2, rcount, dco.n_primary, dco.m_alternate,
                         re_idx, &re_oc);
        agree = (rc == 0) && (re_oc == scount);
        if (agree)
            for (size_t k = 0; k < re_oc; k++) {
                const uint8_t *canon = rids[re_idx[k]]; uint16_t canl = rlens[re_idx[k]];
                if (canl != slens[k] || memcmp(canon, sids[k], canl) != 0) { agree = 0; break; }
            }
    }
    /* This ordered byte-equality between the published result and the
     * independently re-derived canonical draw IS the SELECTED/NOT-SELECTED
     * semantics — membership is implied, so it is not asserted separately. */
    CHECK(agree, "CTRL: the published result EQUALS the independently re-derived canonical draw");

    /* ── NEG (tamper): flip one content byte of the FIRST published selected id
     *    in the result payload; the round-trip must now DISAGREE with the
     *    canonical re-derivation (the binding catches external tampering). ── */
    int tamper_caught = 0;
    if (res_ok && scount > 0) {
        uint8_t tampered[4096]; memcpy(tampered, result, sl);
        /* Locate the first selected id's first byte inside the (copied) result
         * ciphertext and flip it. sids[0] points into ct_s (== result+hdr..). */
        size_t off = (size_t)(sids[0] - result);
        if (off < sl) {
            tampered[off] ^= 0xff;
            char tt[64]; const uint8_t *tct; size_t tcl;
            d5_result_hdr tr; memset(&tr, 0, sizeof tr);
            const uint8_t *tsids[RP_DECODE_CAP]; uint16_t tslens[RP_DECODE_CAP]; uint32_t tsc = 0;
            if (strip_env(tampered, sl, tt, sizeof tt, &tct, &tcl) == 0
                && d5_result_decode(tct, tcl, &tr, tsids, tslens, RP_DECODE_CAP, &tsc) == 0
                && tsc == scount && roster_ok && co_ok) {
                size_t sidl3[RP_DECODE_CAP];
                for (uint16_t i = 0; i < rcount; i++) sidl3[i] = rlens[i];
                size_t re2[RP_NPRIMARY + RP_MALT]; size_t re2n = 0;
                if (d5_draw(seed, (const uint8_t *)RP_DOMAIN, strlen(RP_DOMAIN),   /* authenticated seed, not tr.seed */
                            dco.case_id, dco.case_id_len, dco.draw_height,
                            dco.roster_cutoff_height, dco.draw_algo_version,
                            rids, sidl3, rcount, dco.n_primary, dco.m_alternate, re2, &re2n) == 0
                    && re2n == tsc) {
                    int mismatch = 0;
                    for (size_t k = 0; k < re2n; k++) {
                        const uint8_t *c = rids[re2[k]]; uint16_t cl2 = rlens[re2[k]];
                        if (cl2 != tslens[k] || memcmp(c, tsids[k], cl2) != 0) { mismatch = 1; break; }
                    }
                    tamper_caught = mismatch;
                }
            }
        }
    }
    CHECK(tamper_caught, "NEG (tamper): a byte-flipped published selected id DISAGREES with the canonical re-derivation");

    printf("\n  %d pass / %d fail\n", pass, fail);
    if (fail == 0) { printf("  PASS: selftest-d5rp\n"); return 0; }
    printf("  FAIL: selftest-d5rp\n");
    return 1;
    #undef CHECK
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "selftest") == 0) return cmd_selftest();
    if (argc >= 2 && strcmp(argv[1], "emit") == 0)     return cmd_emit();
    fprintf(stderr,
        "d5rp — D.5 reference-RP producer (BUSL-1.1)\n"
        "usage:\n"
        "  d5rp selftest   round-trip gate: produce -> decode -> re-derive == published\n"
        "  d5rp emit       print the demo scenario's roster/case-open/result payloads (hex)\n");
    return (argc >= 2) ? 1 : 0;
}
