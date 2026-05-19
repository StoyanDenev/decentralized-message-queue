#!/usr/bin/env bash
# S-035 Option 1 seed — E1 Negative Entry Fee mechanism.
#
# ZEROTH_ADDRESS is a canonical pseudo-account (all-zero pubkey, no
# usable private key) seeded at genesis via GenesisConfig.zeroth_pool_initial.
# On every FIRST-TIME REGISTER, the apply layer transfers HALF the current
# pool balance to the new registrant. Re-registrations (key rotation /
# region update) DO NOT touch the pool. Pool exhausts geometrically.
#
# This is a documented economic primitive with no other unit-test
# coverage. Silent drift here would either:
#   - drain the pool too fast (overspending)
#   - under-credit new domains (NEF not landing → broken incentive)
#   - touch the pool on re-REGISTER (key-churn drain attack)
#
# Covers:
#   - Pool seeded at genesis (zeroth_pool_initial → ZEROTH_ADDRESS.balance)
#   - Empty pool: NEF = 0, no credit
#   - First-time REGISTER: pool halved, registrant gets +50% pool
#   - Re-REGISTER (key rotation): pool UNCHANGED — defends against churn
#   - Region update via re-REGISTER preserves new region
#   - Geometric exhaustion: each first-time REGISTER halves remaining pool
#   - A1 invariant under NEF transfer (NEF is intra-shard transfer, not mint)
#   - state_root sensitive to pool drain (a:-namespace)
#   - Determinism: parallel chains see same drain → same state_root
#
# 18 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_nef_pool_drain.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== E1 Negative Entry Fee — ZEROTH pool drain on first-time REGISTER ==="
OUT=$($DETERM test-nef-pool-drain 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: nef-pool-drain all assertions"; then
  echo ""
  echo "  PASS: nef-pool-drain unit test"
  exit 0
else
  echo ""
  echo "  FAIL: nef-pool-drain had assertion failures"
  exit 1
fi
