#!/usr/bin/env bash
# S-035 Option 1 seed — Block::from_json minimum-valid input +
# S-018 required-field rejection.
#
# Block::from_json at chain/block.cpp:451 uses json_require<T> /
# json_require_hex / json_require_array for 7 required fields:
# index, prev_hash, timestamp, transactions, creators, cumulative_rand,
# abort_events. All other arrays + hex fields are optional (gated by
# j.contains(...) followed by json_require_array / json_require_hex
# which fires on wrong-type IF present).
#
# Covered:
#   - Minimal valid Block JSON (7 required fields) parses cleanly
#   - Missing each required field → throws with diagnostic naming field
#   - Wrong-type rejection on required fields:
#     transactions = <number>, creators = <object>, prev_hash = short
#   - Compute_hash post-parse (sanity)
#   - Round-trip via to_json → from_json preserves required fields
#
# Defends against drift in the Block::from_json gate that would either
# weaken the required-field enforcement (silent acceptance of malformed
# blocks → safety break) or break v1 by adding/removing required
# fields (existing gossip messages become unparseable).
#
# 16 assertions across 11 scenarios.
#
# Note: this test uses fputs-to-stdout for assertion output instead of
# std::cout, working around an MSVC Release stdout-stream issue
# specific to this test's mix of nlohmann::json operations and
# stream usage (bisected by gradual probe; functional equivalent).
#
# Run from repo root: bash tools/test_block_from_json_minimal.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block::from_json minimum-valid (7 required fields) + S-018 per-field rejection ==="
OUT=$($DETERM test-block-from-json-minimal 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-from-json-minimal all assertions"; then
  echo ""
  echo "  PASS: block-from-json-minimal unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-from-json-minimal had assertion failures"
  exit 1
fi
