#!/usr/bin/env bash
# S-033 / v2.1 state-commitment determinism contract — pin three axes:
#   (a) Replay determinism: a chain built from identical inputs produces
#       the same state_root regardless of process, build, or save-then-
#       load round-trip. K-of-K nodes that diverge here silently fail
#       Phase-2 signature gathering.
#   (b) Insertion-order independence: the chain's state containers are
#       std::map<std::string,...>, which iterate in canonical sorted
#       order; build_state_leaves further sorts (namespace, key, value-
#       hash) before merkle_root.
#   (c) Cross-platform / canonical byte identity: state_root is byte-
#       identical across runs of the same binary on the same input
#       (re-invocation + snapshot round-trip + chain-file round-trip
#       all preserve it).
#
# Companion to:
#   - test-state-root (setter-level k:-namespace algebra)
#   - test-state-root-namespaces (per-namespace mutation sensitivity)
#   - docs/proofs/S033StateRootNamespaceCoverage.md (analytic proof)
#
# 19 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_state_root_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== state_root determinism contract — replay + order + cross-run ==="
OUT=$($DETERM test-state-root-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-root-determinism all assertions"; then
  echo ""
  echo "  PASS: state-root-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-root-determinism had assertion failures"
  exit 1
fi
