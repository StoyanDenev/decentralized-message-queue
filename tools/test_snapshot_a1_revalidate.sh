#!/usr/bin/env bash
# SnapshotRestoreGateAudit A1-revalidate — restore_from_snapshot re-asserts the
# unitary-balance identity at LOAD.
#
# Chain::restore_from_snapshot (chain.cpp:2390) reconstructs accounts_/stakes_ and
# the A1 supply counters DIRECTLY and never re-asserts the identity apply_transactions
# enforces every block (expected_total() == live_total_supply()). The head_hash /
# state_root self-checks bind each leaf VALUE but not the accounting IDENTITY among
# them, so a snapshot whose genesis_total is supply-inconsistent (yet otherwise
# self-consistent) loads clean and then throws "unitary-balance invariant violated"
# on the FIRST post-restore apply -> a permanent wedge. The restore-side guard
# rejects such a snapshot at LOAD instead.
#
# Builds a real chain, serializes it, bypasses the two self-consistency gates the way
# a legitimate pre-S-033 / headerless snapshot does (zero the head state_root, drop
# head_hash), then tampers genesis_total by +1: restore MUST reject it. Positive
# controls (honest snapshot; self-checks-bypassed but A1-consistent snapshot) still
# restore cleanly. Falsifies on mutant: delete the guard -> the tampered snapshot
# loads clean (the REJECT asserts flip; the positive controls do not).
#
# Run from repo root: bash tools/test_snapshot_a1_revalidate.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== snapshot-a1-revalidate — restore re-asserts the A1 unitary-balance identity ==="
OUT=$($DETERM test-snapshot-a1-revalidate 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-snapshot-a1-revalidate"; then
  echo ""
  echo "  PASS: snapshot-a1-revalidate unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-a1-revalidate had assertion failures"
  exit 1
fi
