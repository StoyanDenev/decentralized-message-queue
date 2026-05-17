#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for four block-internal
# wire types' JSON round-trips:
#
#   * CrossShardReceipt (FA7 / V12 — source-side receipt emission)
#   * AbortEvent        (FA3 — consensus abort certificate)
#   * EquivocationEvent (FA6 — slashing evidence)
#   * GenesisAlloc      (chain-identity genesis allocation)
#
# Each is `to_json` / `from_json` round-trip critical. Blocks gossip
# these as JSON sub-objects via Block::to_json/from_json; any field-
# loss across the round-trip would silently corrupt wire data without
# a parse error. The S-018 helpers (used at the block + envelope level)
# fence against missing required fields at THOSE outer layers, but
# this test goes a level deeper to catch "field present but
# serialized then dropped on read" within each sub-type.
#
# Plus: locks in the S-018 strict-rejection contract on ALL FOUR
# types (CrossShardReceipt's from_json was hardened in the same
# commit that introduced this test — previously it used permissive
# j.value() defaults; now it uses json_require / json_require_hex
# to match the rest of the S-018 surface). Missing required field
# throws with a clear field-name diagnostic; wrong-length hex throws
# too.
#
# 39 assertions in five blocks:
#
#   CrossShardReceipt round-trip (10):
#     1-10. All ten fields preserved through to_json → from_json.
#
#   AbortEvent round-trip (4):
#     12-15. round, aborting_node, timestamp, event_hash preserved.
#
#   EquivocationEvent round-trip (8):
#     16-23. equivocator, block_index, digest_a/b, sig_a/b, shard_id,
#       beacon_anchor_height preserved.
#
#   GenesisAlloc round-trip + R1 backward-compat (7):
#     24-28. All five fields preserved through round-trip.
#     29-30. Empty region (R1 legacy default) + zero stake.
#
#   S-018 strict-rejection lock-in (10):
#     30-31. CrossShardReceipt: throws on missing 'nonce', error
#       message mentions 'nonce' field name (in-session hardening).
#     32-33. AbortEvent: throws on missing 'round', error message
#       mentions 'round' field name.
#     34-35. EquivocationEvent: throws on missing 'digest_a', error
#       message mentions 'digest_a'.
#     36.   EquivocationEvent: throws on wrong-length 'digest_a' hex
#       (json_require_hex length check).
#     37-38. GenesisAlloc: throws on missing 'domain', error message
#       mentions 'domain'.
#
# Run from repo root: bash tools/test_wire_types.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block-internal wire types — CrossShardReceipt + AbortEvent + EquivocationEvent + GenesisAlloc ==="
OUT=$($DETERM test-wire-types 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: wire-types all assertions"; then
  echo ""
  echo "  PASS: wire-types unit test"
  exit 0
else
  echo ""
  echo "  FAIL: wire-types had assertion failures"
  exit 1
fi
