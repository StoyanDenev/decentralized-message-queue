#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the MergeEvent
# canonical-binary codec (R4 under-quorum merge wire format).
#
# MergeEvent is the payload of TxType::MERGE_EVENT — emitted by
# beacon when a shard's eligible-validator pool drops below 2K and
# the shard temporarily merges its committee operations with its
# modular-next neighbor (R4 closure). The wire format is bytes
# canonical (LE u32/u64, region-length-prefixed UTF-8); every node
# implementation must round-trip byte-for-byte or the apply path
# diverges across shards.
#
# 19 assertions covering:
#
#   Round-trip + size invariant (3):
#     1-2. BEGIN + END round-trips preserve all six fields including
#          empty-region END default.
#     3.  Size invariant: encode size = 26 + region_len.
#
#   Decode rejection paths (4):
#     4. Payload < 26 bytes rejected.
#     5. Invalid event_type (> 1) rejected.
#     6. Region_len > 32 cap rejected.
#     7. Size mismatch (claimed vs actual region_len) rejected.
#
#   Determinism + field sensitivity (7):
#     8.  Encoding the same event twice yields the same bytes.
#     9-13. Every field affects encoded bytes (event_type, shard_id,
#          partner_id, effective_height, evidence_window_start, region).
#
#   Maximum-region round-trip (1):
#    14. 32-byte region (the documented max) round-trips.
#
# Cross-reference: docs/proofs/UnderQuorumMerge.md +
# docs/proofs/RegionalSharding.md.
#
# Run from repo root: bash tools/test_merge_event_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== MergeEvent::encode + ::decode (R4 wire format) ==="
OUT=$($DETERM test-merge-event-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-event-codec all assertions"; then
  echo ""
  echo "  PASS: merge-event-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-event-codec had assertion failures"
  exit 1
fi
