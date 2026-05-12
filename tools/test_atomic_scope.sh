#!/usr/bin/env bash
# A9 Phase 2D — Chain::atomic_scope primitive regression test.
#
# Runs the in-process `determ test-atomic-scope` subcommand which
# exercises the scope semantics over a freshly-constructed in-memory
# Chain. No network, no RPC — just direct method calls against the
# primitive that v2.4 composable txs / v2.5 cross-shard 2PC / v2.6
# smart-contract-lite will build on.
#
# Assertions covered (21 total):
#   - Genesis state correctness (2)
#   - Scope commit (return true): mutations kept (4)
#   - Scope discard (return false): mutations rolled back (4)
#   - Exception in scope: rollback + re-raise (4)
#   - Nested scopes, inner discards: outer's mutations remain (3)
#   - Nested scopes, outer discards: both inner+outer mutations
#     roll back even if inner committed (3)
#
# State coverage per test: accounts balances (alice/bob), chain
# height (blocks_ vector tracked). Exercises both the Phase 1
# state-snapshot path AND the Phase 2D blocks_-size rollback.
#
# Run from repo root: bash tools/test_atomic_scope.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe

echo "=== A9 Phase 2D atomic_scope semantics ==="
OUT=$($DETERM test-atomic-scope 2>&1)
echo "$OUT"

# Pass condition: final line says "PASS: atomic_scope all assertions"
if echo "$OUT" | tail -3 | grep -q "PASS: atomic_scope all assertions"; then
  echo ""
  echo "  PASS: A9 Phase 2D primitive"
  exit 0
else
  echo ""
  echo "  FAIL: atomic_scope had assertion failures"
  exit 1
fi
