#!/usr/bin/env bash
# determ-dsso core gate — the status/compare primitives every DSSO module builds on.
#
# The DSSO service is a separate binary (dapps/dsso) linking only the C99 crypto
# library: no chain object is reachable from it. That isolation is what lets DSSO
# parse the JSON/CBOR the EUDI specifications mandate without any consensus path
# touching an external format. This gate pins the shared contract — fail-closed
# status codes and a constant-time compare — so a module that misuses it breaks
# here rather than in a security check.
#
# Run from repo root: bash tools/test_dsso_core.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== determ-dsso core (status codes + constant-time compare) ==="
OUT=$($DETERM_DSSO selftest-core 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dsso-core all assertions"; then
  echo ""
  echo "  PASS: dsso_core"
  exit 0
else
  echo ""
  echo "  FAIL: dsso_core had assertion failures"
  exit 1
fi
