#!/usr/bin/env bash
# S-035 Option 1 seed — R1 regional creator coverage.
#
# `test-genesis` and `test-make-genesis-block` already pin
# compute_genesis_hash and make_genesis_block invariants; this test
# fills the R1 region-specific surface:
#
#   - region propagates through GenesisCreator → GenesisAlloc →
#     registry on apply
#   - empty region (the default) stays empty (pre-R1 backward compat)
#   - genesis-hash sensitive to GenesisCreator.region (otherwise an
#     adversary could swap regions silently)
#   - genesis-hash sensitive to GenesisConfig.committee_region (so
#     two shards differing only in committee_region can't collide on
#     chain identity)
#   - default-empty committee_region: deterministic (pre-R1 hash stable)
#   - Snapshot round-trip preserves registrant.region (otherwise
#     restored validators silently lose region claim → broken
#     region-pinned committee selection)
#   - state_root sensitive to registrant.region (r:-namespace coverage)
#   - GenesisConfig JSON round-trip preserves regions
#   - Mixed-region creator set: each retains its own region
#
# 12 assertions across 9 scenarios.
#
# Run from repo root: bash tools/test_genesis_with_region.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== genesis with R1 regions — propagation + hash sensitivity + restore ==="
OUT=$($DETERM test-genesis-with-region 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis-with-region all assertions"; then
  echo ""
  echo "  PASS: genesis-with-region unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis-with-region had assertion failures"
  exit 1
fi
