#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the S-018 foundation
# helpers in `include/determ/util/json_validate.hpp`:
#
#   * json_require<T>(j, field)         — typed required-field
#   * json_require_hex(j, field, len)   — typed hex string + length check
#   * json_require_array(j, field)      — required-array (returns ref)
#
# These three helpers are under EVERY S-018-hardened from_json path in
# the codebase: Transaction / Block / AbortEvent / EquivocationEvent /
# GenesisAlloc / CrossShardReceipt / ContribMsg / BlockSigMsg /
# AbortClaimMsg + the gossip-envelope dispatchers (ABORT_EVENT /
# SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE). If json_require<T> ever
# silently allowed a missing field through, every from_json that uses
# it would silently accept missing fields too.
#
# This complements test_s018_json_validation.sh (which exercises a
# few representative S-018-hardened from_json paths end-to-end) by
# exercising the helpers DIRECTLY at the unit level. Locks in the
# error-message contract that operators rely on for triage:
#
#   * missing field → error mentions field name + "S-018" prefix +
#     "missing" keyword
#   * wrong type → error mentions field name + "wrong type" keyword
#     + nlohmann inner detail
#   * wrong hex length → error mentions "wrong hex length" + "expected
#     N" + "got M" counts
#   * wrong array type → error mentions field name + "expected array"
#     + observed type ("got string" / "got object")
#   * empty array → accepted (size=0 is a valid array shape)
#
# 24 assertions covering all three helpers' happy paths, every error
# path, and field-name preservation through unusual identifier chars.
#
# Run from repo root: bash tools/test_json_validate.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== json_require<T> / json_require_hex / json_require_array (S-018 foundation) ==="
OUT=$($DETERM test-json-validate 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: json-validate all assertions"; then
  echo ""
  echo "  PASS: json-validate unit test"
  exit 0
else
  echo ""
  echo "  FAIL: json-validate had assertion failures"
  exit 1
fi
