#!/usr/bin/env bash
# RpcIngressGateAudit §3 #6 (ING-chain-summary-last_n-uncapped) — the chain_summary
# per-request page cap.
#
# Node::rpc_chain_summary surfaces the trailing `last_n` blocks. Its sibling
# history handlers all clamp to a 256-page anti-DoS cap (on_get_chain node.cpp:3119
# "if (count > 256) count = 256"; rpc_headers HEADERS_PAGE_MAX), but chain_summary
# walked an UNBOUNDED client-supplied last_n: last_n >= height forced start=0 -> a
# full-chain compute_hash() rewalk under the state read lock (a per-request-WORK
# DoS the rate-limiter's token bucket cannot bound). The clamp now lives in the
# shared chain::chain_summary_start helper that rpc_chain_summary calls for its walk
# bound.
#
# Builds a real >256-block bare chain (genesis + 300 empty blocks) and pins the
# walk length: last_n <= 256 is honored exactly; last_n above the cap (257 / 1000 /
# UINT32_MAX) clamps to a 256-block window (start = height-256, never 0). Falsifies
# on mutant: neuter the clamp in chain_summary.hpp and every huge/over-cap assert
# flips back to the whole chain (see the register).
#
# Run from repo root: bash tools/test_chain_summary_cap.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== chain-summary-cap — the chain_summary 256-page anti-DoS bound ==="
OUT=$($DETERM test-chain-summary-cap 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-chain-summary-cap"; then
  echo ""
  echo "  PASS: chain-summary-cap unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-summary-cap had assertion failures"
  exit 1
fi
