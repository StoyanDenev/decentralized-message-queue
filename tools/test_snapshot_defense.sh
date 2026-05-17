#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the S-018
# defense-in-depth hardening applied to Chain::restore_from_snapshot.
#
# Snapshots arrive via SNAPSHOT_RESPONSE gossip (16 MB cap, the only
# unbounded-tier channel) and via operator-pinned files on disk. A
# malicious peer crafting a snapshot with `"accounts": "scalar"` or
# similar wrong-type collection fields would previously throw an
# opaque nlohmann internal type error mid-iteration. After the
# hardening (commits 5841199 + f30ecc0), each optional collection
# field uses json_require_array inside its contains() guard,
# producing a clean "S-018: JSON field 'X' has wrong type"
# diagnostic naming the offending field.
#
# 11 assertions covering each of the 8 optional collection fields:
#
#   1. Baseline: minimal valid snapshot restores without error.
#   2. accounts as scalar → rejected with 'accounts' in error message.
#   3. stakes as number → rejected with 'stakes' in error message.
#   4. registrants as object → rejected.
#   5. applied_inbound_receipts as string → rejected.
#   6. merge_state as number → rejected.
#   7. abort_records as scalar → rejected.
#   8. dapp_registry as scalar → rejected (S-037 surface).
#   9. pending_param_changes as scalar → rejected.
#   10. Wrong version still rejected (preserves pre-defense check).
#   11. Empty optional fields still load (backward-compat with legacy
#       snapshots that omit optional fields).
#
# Run from repo root: bash tools/test_snapshot_defense.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::restore_from_snapshot — S-018 defense-in-depth on collection fields ==="
OUT=$($DETERM test-snapshot-defense 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-defense all assertions"; then
  echo ""
  echo "  PASS: snapshot-defense unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-defense had assertion failures"
  exit 1
fi
