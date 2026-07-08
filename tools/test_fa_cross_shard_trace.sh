#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — increment: cross-shard
# receipt CONSERVATION over a multi-block two-chain TRACE (FA7).
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path.
#
# `determ test-fa-cross-shard-trace` drives a seeded (SplitMix64), reproducible
# 48-block TWO-CHAIN trace: source shard A (ShardId 0) applies real cross-shard
# TRANSFERs through the real apply path; destination shard B (ShardId 1)
# applies the relayed inbound receipts INCLUDING adversarial DUPLICATE
# re-submissions of already-applied receipts and WITHHELD (in-flight) receipts
# delivered a block late. Asserted after every block:
#   - exactly-once credit: B balance + accumulated_inbound == Σ UNIQUE
#     delivered receipt amounts (the applied_inbound_receipts (src_shard,
#     tx_hash) dedup rejects every duplicate);
#   - FA7 no-credit-without-debit: credited on B <= debited on A, EXACT
#     after the final flush delivers all in-flight receipts;
#   - per-chain A1 analogs: A accumulated_outbound == emitted sum, and
#     expected_total == live_total_supply on BOTH chains;
#   - two-chain conservation: live_A + live_B + in_flight == genesis_A +
#     genesis_B every block (exact equality once all delivered);
#   - non-vacuous (real credits, real duplicate rejects, real in-flight);
#   - negative control (event-free blocks on both chains move nothing);
#   - determinism (same seed -> identical final state roots on BOTH chains).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness: cross-shard receipt-conservation two-chain trace (real engine) ==="
OUT=$($DETERM test-fa-cross-shard-trace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-cross-shard-trace all assertions"; then
  echo ""
  echo "  PASS: fa-cross-shard-trace harness"
  exit 0
else
  echo ""
  echo "  FAIL: fa-cross-shard-trace had assertion failures"
  exit 1
fi
