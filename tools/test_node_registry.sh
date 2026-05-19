#!/usr/bin/env bash
# S-035 Option 1 seed — NodeRegistry::build_from_chain + eligible_in_region.
# FA8 R2 region-aware committee selection foundation.
#
# Previously this surface was only exercised through end-to-end shell
# tests via the Node fixture; this direct unit test catches drift
# faster and at lower fixture cost.
#
# Covered:
#   - build_from_chain reads (registrants, stakes) from a Chain and
#     produces a sorted-by-domain NodeRegistry
#   - Min-stake gate: domains with stake < chain.min_stake() excluded
#   - eligible_in_region(""): returns full pool (R1 backward compat)
#   - eligible_in_region("us-east"): returns only us-east subset
#   - Region filter is STRICT equality (no prefix match)
#   - Determinism: two rebuilds → same registry
#   - sorted_nodes: lexicographic by domain
#   - Zero-stake boundary: excluded regardless of registry entry
#
# 14 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_node_registry.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NodeRegistry::build_from_chain + eligible_in_region — FA8 R2 foundation ==="
OUT=$($DETERM test-node-registry 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: node-registry all assertions"; then
  echo ""
  echo "  PASS: node-registry unit test"
  exit 0
else
  echo ""
  echo "  FAIL: node-registry had assertion failures"
  exit 1
fi
