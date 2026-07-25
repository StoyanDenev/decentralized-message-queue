// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
//
// RpcIngressGateAudit §3 #6 (ING-chain-summary-last_n-uncapped) — the per-request
// page bound for the chain_summary RPC (Node::rpc_chain_summary). It mirrors the
// 256-page anti-DoS cap the sibling history handlers already enforce
// (on_get_chain: "if (count > 256) count = 256"; rpc_headers: HEADERS_PAGE_MAX);
// chain_summary was the lone reader missing it. Without the clamp, a
// client-supplied last_n >= height forces start = 0 — a full-chain rewalk that
// recomputes compute_hash() on EVERY block under the state read lock, a
// per-request-WORK amplification the rate-limiter's token bucket (which meters
// requests, not units of work) does not bound.
//
#include <cstdint>

namespace determ::chain {

// The chain_summary response surfaces at most this many trailing blocks per
// request, matching on_get_chain / rpc_headers. A client last_n above the cap is
// clamped DOWN to it; a last_n at or below the cap is honored exactly.
constexpr uint32_t kChainSummaryPageMax = 256;

// Start index of the half-open block window [start, height) that
// Node::rpc_chain_summary walks, with last_n clamped to kChainSummaryPageMax.
// Pure arithmetic (no block reads): the WORK a caller can request is bounded to
// kChainSummaryPageMax blocks regardless of last_n, so height - start <= 256.
inline uint64_t chain_summary_start(uint64_t height, uint32_t last_n) {
    if (last_n > kChainSummaryPageMax) last_n = kChainSummaryPageMax;
    return (height > last_n) ? height - last_n : 0;
}

}  // namespace determ::chain
