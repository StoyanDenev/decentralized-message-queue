#!/usr/bin/env bash
# S-035 Option 1 seed — snapshot version-field rejection.
#
# The restore_from_snapshot path at chain.cpp:1703-1709 requires
# snap.version == 1 and throws on any other value. This test pins
# the version gate so future migrations to version=2 must explicitly
# update the gate (not silently accept old/new formats).
#
# Covered:
#   - version=1: accepted (round-trip from serialize_state(empty))
#   - missing version field: defaults to 0 → rejected with
#     "unsupported snapshot version" diagnostic
#   - version=0: explicitly rejected, error names "0"
#   - version=999 (future): rejected, error names "999"
#   - version=-1 (negative): rejected
#   - Non-object input: rejected with distinct "not a JSON object"
#     diagnostic (fires BEFORE the version check)
#   - JSON null / string / array: all caught by the non-object gate
#   - Wrong-type version field (string instead of integer): rejected
#     via some error path (nlohmann's wrong-type behavior)
#
# Defends against migration drift where a regression would accept
# arbitrary version numbers (silent format change) or break v1.
#
# 10 assertions across 9 scenarios.
#
# Run from repo root: bash tools/test_snapshot_version_rejection.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== snapshot version-field rejection — version=1 accepted, 0/999/-1/missing/wrong-type rejected ==="
OUT=$($DETERM test-snapshot-version-rejection 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-version-rejection all assertions"; then
  echo ""
  echo "  PASS: snapshot-version-rejection unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-version-rejection had assertion failures"
  exit 1
fi
