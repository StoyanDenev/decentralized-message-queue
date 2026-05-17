#!/usr/bin/env bash
# S-035 Option 1 seed — S-007 overflow-protection paths.
#
# `Chain::apply_transactions` uses `checked_add_u64` on every credit
# path that could otherwise wrap u64:
#   - TRANSFER receiver credit
#   - inbound CrossShardReceipt credit
#   - per-creator subsidy+fee distribution
#   - dust (modulo remainder) to creator[0]
#
# When the addition would overflow, apply throws
# `std::runtime_error("S-007: ...")`. Phase-1's try/catch then
# restores the state snapshot, so the chain remains byte-identical
# to entry. Without these checks, an attacker could wrap a victim's
# balance to 0 by crediting an overflowing amount.
#
# Network-level scenarios don't easily reach UINT64_MAX boundaries
# (would need a real long-lived deployment). This in-process test
# constructs near-UINT64_MAX initial balances to exercise the
# overflow paths in <1s.
#
# 8 assertions in six blocks:
#
#   TRANSFER receiver overflow (1):
#     - apply throws S-007 with "TRANSFER" + diagnostic
#
#   Phase-1 rollback contract (3):
#     - height unchanged (failed apply didn't push block)
#     - sender balance unchanged
#     - state_root byte-identical
#
#   Inbound receipt overflow (1):
#     - apply throws S-007 with "inbound" diagnostic
#
#   Boundary (1):
#     - exact UINT64_MAX is OK (overflow check is strict >, not >=)
#
#   Sanity (1):
#     - normal TRANSFER unaffected by overflow check
#
#   A1 preserved on throw (1):
#     - expected == live after S-007 rollback (invariant preserved)
#
# Run from repo root: bash tools/test_overflow_paths.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-007 overflow-protection apply paths ==="
OUT=$($DETERM test-overflow-paths 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: overflow-paths all assertions"; then
  echo ""
  echo "  PASS: overflow-paths unit test"
  exit 0
else
  echo ""
  echo "  FAIL: overflow-paths had assertion failures"
  exit 1
fi
