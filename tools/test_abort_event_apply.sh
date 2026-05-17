#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the apply-side
# handling of AbortEvent (Phase-1 suspension slashing per rev.8).
#
# Each `round=1` AbortEvent baked into a finalized block:
#   (a) Deducts SUSPENSION_SLASH from the aborting domain's stake_entry
#       (bounded by available stake — no negative balances).
#   (b) Increments abort_records[domain] (count + last_block) — the
#       S-032 cache that build_from_chain reads instead of walking
#       chain history.
#   (c) Bumps accumulated_slashed_ (A1 unitary-supply counter).
#
# Phase-2 (round=2) AbortEvents are tracked but NOT slashed —
# timing-skew aborts on healthy creators are economically free.
# Required for BFT-mode safety (mirroring registry.cpp's suspension
# policy).
#
# Network-level integration via the multi-node round-1 fail injection
# scripts; this in-process test pins the apply semantics in <1s.
#
# Implementation note: every block in the fixture sets
# `b.creators = {"alice"}` so fees route back and A1 stays balanced
# (see test-chain-apply-block gotcha).
#
# ~12 assertions in six blocks:
#
#   Phase-1 slashing (1):
#     - stake reduced by SUSPENSION_SLASH (default 10)
#
#   S-032 abort_records cache (2):
#     - count incremented
#     - last_block matches apply block index
#
#   Phase-2 no-slashing (2):
#     - stake unchanged
#     - abort_records NOT incremented
#
#   Aborted-without-stake (DOMAIN_INCLUSION) (2):
#     - no crash
#     - abort_records still incremented (cache tracks regardless of stake)
#
#   Stake exhaustion (no negative) (2):
#     - 51 aborts on stake=500/slash=10 → stake floors at 0
#     - abort_records.count == 51 (cache continues tracking)
#
#   A1 supply invariant (3):
#     - accumulated_slashed bumped by exactly SUSPENSION_SLASH
#     - live supply decreases by exactly the slash
#     - expected == live after slash
#
# Run from repo root: bash tools/test_abort_event_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== AbortEvent apply (Phase-1 SUSPENSION_SLASH, S-032 cache, A1) ==="
OUT=$($DETERM test-abort-event-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: abort-event-apply all assertions"; then
  echo ""
  echo "  PASS: abort-event-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: abort-event-apply had assertion failures"
  exit 1
fi
