#!/usr/bin/env bash
# A1 unitary-supply identity FUZZER — randomized stress + snapshot round-trip.
#
# test-supply-lifecycle walks ONE hand-scripted interleaving and
# test-cross-shard-supply-invariant walks a scripted cross-shard cycle.
# This test stress-tests the SAME single-shard invariant
#
#   genesis_total + accumulated_subsidy + accumulated_inbound
#     - accumulated_slashed - accumulated_outbound == live_total_supply
#
# (Chain::expected_total() == Chain::live_total_supply()) across a long
# deterministic pseudo-random sequence of valid TRANSFER / STAKE / UNSTAKE
# blocks, each carrying a fee + minting block subsidy. The in-process PRNG
# is a counter-seeded SplitMix64 (fixed in-code seed, NO random_device /
# time / Math.random), so the run is byte-for-byte reproducible.
#
# The A1 invariant is re-asserted after EVERY applied block. Mid-sequence
# the chain is snapshotted via serialize_state and restored via
# restore_from_snapshot; the test then asserts:
#   - the restored chain satisfies A1,
#   - all 5 A1 counters + live_total_supply + expected_total reproduce the
#     snapshot point exactly,
#   - the restored chain can keep applying blocks with A1 still holding.
#
# This is the uncovered angle vs. test-supply-lifecycle (no fuzz, no
# snapshot), test-cross-shard-supply-invariant (scripted, cross-shard) and
# test-snapshot-roundtrip (single TRANSFER, read-side only).
#
# Run from repo root: bash tools/test_supply_invariant_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A1 unitary-supply invariant — randomized fuzz + snapshot round-trip ==="
OUT=$($DETERM test-supply-invariant-fuzz 2>&1)
echo "$OUT"

if echo "$OUT" | tail -5 | grep -q "PASS: supply-invariant-fuzz all assertions"; then
  echo ""
  echo "  PASS: supply-invariant-fuzz unit test"
  exit 0
else
  echo ""
  echo "  FAIL: supply-invariant-fuzz had assertion failures"
  exit 1
fi
