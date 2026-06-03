#!/usr/bin/env bash
# FA-Apply-2 SnapshotEquivalence at full breadth — comprehensive
# all-namespace snapshot round-trip determinism. Where the narrower
# siblings each pin ONE state-root namespace's round-trip:
#   - test-snapshot-roundtrip        (a:/s:/r:/k:/c: + state_root)
#   - test-applied-receipt-restore   (i:)
#   - test-dapp-registry-determinism (d:)
#   - test-merge-state-determinism   (m:)
#   - test-snapshot-then-apply       (post-restore apply equivalence)
# this test populates EVERY one of the 10 state-root namespaces
# (a: accounts, s: stakes, r: registrants, d: dapp_registry,
#  i: applied-inbound-receipts, b: abort_records, m: merge_state,
#  p: pending_param_changes, k: constants, c: supply counters) in a
# SINGLE chain, then asserts:
#
#   (0) the fixture actually populates all 10 namespaces non-trivially
#       (guards the test from vacuously passing on empty namespaces)
#   (1) serialize_state → restore_from_snapshot → serialize_state is
#       byte-identical across the full namespace set at once
#   (2) compute_state_root() is preserved across the full round-trip
#       (the load-bearing S-033 determinism contract over all 10 ns)
#   (3) per-namespace field-for-field survival (a:/s:/r:/d:/m:/p:
#       key fields + i:/b: presence)
#   (4) double round-trip is idempotent (stable fixed point)
#   (5) every namespace contributes to the root — perturbing one field
#       of each of the 10 namespaces changes compute_state_root()
#       (S-037-class "namespace silently omitted from serialize/restore"
#       guard, all-namespaces edition)
#   (7) A1 unitary-supply invariant holds identically pre/post restore
#
# a:/s:/r:/k:/c: are driven through the real apply path (genesis +
# TRANSFER + STAKE); the five Phase-2A-only namespaces (d:/i:/b:/m:/p:)
# are spliced into the serialized JSON then restored — the same
# technique test-merge-state-determinism uses, since driving all five
# apply state-machines in one fixture is brittle and orthogonal to the
# round-trip-determinism contract under test. The spliced chain is a
# fully-valid restored Chain whose state_root and snapshot equal what
# an apply-built chain in the same state would emit.
#
# A regression that drops ANY namespace on serialize or restore — the
# exact S-037 failure mode (dapp_registry omitted from serialize_state)
# generalized across every namespace — breaks fast-sync bootstrap
# and/or the S-033 state_root verification gate, and is caught here.
#
# 7 assertions. Run from repo root: bash tools/test_snapshot_full_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== comprehensive all-namespace snapshot round-trip determinism ==="
OUT=$($DETERM test-snapshot-full-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-full-determinism all assertions"; then
  echo ""
  echo "  PASS: snapshot-full-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-full-determinism had assertion failures"
  exit 1
fi
