// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
//
// NC-8 wiring increment 2 — the CONFIDENTIAL_TRANSFER encrypted-note (enote)
// delivery region. This is the ONE shared parse/validate mirror consumed by
// BOTH the validator accept-rule (src/node/validator.cpp) and the chain apply
// path (src/chain/chain.cpp), so the two can never drift on where the DCT1
// bundle ends or what a well-formed enote region is (the S-043 / eligibility_
// floor.hpp "one shared mirror" discipline — two byte-identical copies are a
// consensus-fork landmine).
//
// A CONFIDENTIAL_TRANSFER (TxType=14) payload is a DCT1 bundle, optionally
// followed by a per-output enote region (design §5, owner-decided 3a per-output):
//
//   payload = [ DCT1 bundle : determ_ctx_bundle_len(n_in,m,n) bytes ]
//             [ OPTIONAL enote region                              ]
//   region  = count(1)  then  count * { out_idx(1), enote_len(2 BE), bytes[enote_len] }
//
// The frozen C bundle verifiers (determ_ctx_bundle_header/_verify) require an
// EXACT length, so the caller must feed them only the [0, bundle_len) prefix —
// this helper computes bundle_len from the header's own n_in/m/n bytes (via the
// exported, pure determ_ctx_bundle_len) WITHOUT touching the frozen crypto lib,
// then frames the trailing remainder.
//
// CONSENSUS-INERT CONTRACT (design §2/§5): the enote is NEVER a spend
// precondition. This helper validates STRUCTURE ONLY — count/length/index
// bounds and exact consumption. It never calls the enote primitive and never
// inspects ciphertext content; a structurally-valid but cryptographically
// garbage ciphertext is ACCEPTED (and never decrypted in consensus). Only a
// malformed *frame* rejects the tx. Absence of the region (payload == bundle
// exactly) parses to zero enotes and is byte-identical to a pre-NC-8 tx.
//
#include <cstddef>
#include <cstdint>
#include <vector>
#include <determ/crypto/pedersen/ctxbundle.h>   // determ_ctx_bundle_len (exact bundle size)
#include <determ/crypto/enote/enote.h>           // DETERM_ENOTE_OVERHEAD (min enote wire size)

namespace determ::chain {

// One CONFIDENTIAL_TRANSFER output-note delivery ciphertext.
struct CtxEnote {
    uint8_t              output_index;   // < m; strictly increasing across the region
    std::vector<uint8_t> bytes;          // enote wire E33||ct||tag, len in [MIN, MAX]
};

// Structural bounds (STRUCTURE only — never gates on ciphertext content).
static constexpr std::size_t CTX_ENOTE_MIN =
    static_cast<std::size_t>(DETERM_ENOTE_OVERHEAD);   // 49 = empty-plaintext ciphertext
static constexpr std::size_t CTX_ENOTE_MAX = 512;      // caps per-note wire (value||blinding||memo)
static constexpr std::size_t DCT_HDR_LEN   = 15;       // DCT1 fixed header: MAGIC(4)+n_in+m+n+fee(8)

// Split a CONFIDENTIAL_TRANSFER payload into its DCT1 bundle prefix length and an
// OPTIONAL trailing per-output enote region.
//   returns 0  : well-formed. *bundle_len_out = exact bundle size; *enotes_out
//                filled (possibly empty when no region is present).
//   returns -1 : structurally malformed (caller MUST reject the tx). Covers a
//                bad DCT1 header (invalid n_in/m/n), a truncated bundle, a bad
//                enote frame (zero/over-count, out-of-range or non-increasing
//                index, length out of [MIN,MAX], overrun, or dangling bytes).
// The bundle's range/balance proofs are NOT checked here — the caller runs
// determ_ctx_bundle_verify on the [0, *bundle_len_out) prefix.
inline int ctx_split_enotes(const uint8_t* payload, std::size_t len,
                            std::size_t* bundle_len_out,
                            std::vector<CtxEnote>* enotes_out) {
    if (enotes_out) enotes_out->clear();
    if (payload == nullptr || len < DCT_HDR_LEN) return -1;

    // n_in/m/n live at fixed offsets 4/5/6 (ctxbundle.h wire doc); determ_ctx_
    // bundle_len returns 0 on any invalid param, giving us a total-bundle size.
    const std::size_t n_in = payload[4], m = payload[5], n = payload[6];
    const std::size_t bundle_len = determ_ctx_bundle_len(n_in, m, n);
    if (bundle_len == 0 || len < bundle_len) return -1;
    if (bundle_len_out) *bundle_len_out = bundle_len;

    std::size_t off = bundle_len;
    if (off == len) return 0;                       // no region: byte-identical to pre-NC-8

    const std::size_t count = payload[off++];
    if (count == 0 || count > m) return -1;         // a present region must carry 1..m enotes
    int prev = -1;
    for (std::size_t k = 0; k < count; ++k) {
        if (off + 3 > len) return -1;               // room for out_idx(1)+len(2)
        const std::size_t oi   = payload[off];
        const std::size_t elen = (static_cast<std::size_t>(payload[off + 1]) << 8)
                               |  static_cast<std::size_t>(payload[off + 2]);
        off += 3;
        if (oi >= m)                       return -1;   // index must name a real output
        if (static_cast<int>(oi) <= prev)  return -1;   // strictly increasing → canonical, no dup
        prev = static_cast<int>(oi);
        if (elen < CTX_ENOTE_MIN || elen > CTX_ENOTE_MAX) return -1;
        if (off + elen > len)              return -1;   // no overrun
        if (enotes_out) {
            CtxEnote e;
            e.output_index = static_cast<uint8_t>(oi);
            e.bytes.assign(payload + off, payload + off + elen);
            enotes_out->push_back(std::move(e));
        }
        off += elen;
    }
    if (off != len) return -1;                      // no dangling bytes after the region
    return 0;
}

} // namespace determ::chain
