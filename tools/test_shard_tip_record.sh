#!/usr/bin/env bash
# D3.1 (ShardTipMergeDesign.md §9): the ShardTipRecord canonical codec — the
# on-chain distress-attestation substrate for the S-036 full-closure work.
#
# A pure struct/codec increment (no apply / validator / digest touch), byte-neutral
# for every existing chain. Mirrors the MergeEvent::decode discipline: exact size +
# region-len (<= 32) gates, no semantic checks.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. encode size == 49 + region_len (field layout);
#   2. round-trip preserves all fields byte-for-byte;
#   3-4. empty-region record encodes to 49 bytes + round-trips;
#   5. max-value record (all-0xFF + 32-byte region) round-trips (no truncation);
#   6. encode is deterministic;
#   7. decode rejects a < 49-byte buffer;
#   8. decode rejects region_len > 32;
#   9. decode rejects a size mismatch vs the declared region_len.
#
# Run from repo root: bash tools/test_shard_tip_record.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== shard-tip-record: ShardTipRecord canonical codec (D3.1) ==="
OUT=$($DETERM test-shard-tip-record 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: shard-tip-record all assertions"; then
  echo ""
  echo "  PASS: shard-tip-record unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shard-tip-record had assertion failures"
  exit 1
fi
