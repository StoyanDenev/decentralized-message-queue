#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the exact byte
# layout of `MergeEvent::encode` via golden vectors.
#
# R4 wire format (used by TxType::MERGE_EVENT payload — under-quorum
# merge events emitted by beacon, applied to shard chains):
#
#   [event_type: 1 byte u8]                  offset 0   (0=BEGIN, 1=END)
#   [shard_id: 4 bytes little-endian]        offset 1
#   [partner_id: 4 bytes little-endian]      offset 5
#   [effective_height: 8 bytes LE]           offset 9
#   [evidence_window_start: 8 bytes LE]      offset 17
#   [region_len: 1 byte u8]                  offset 25
#   [region: utf-8 bytes (region_len)]       offset 26+
#
# Note: MergeEvent uses LITTLE-ENDIAN — distinct from
# Transaction::signing_bytes which uses big-endian (Preliminaries
# §1.3). The choice is deliberate: tx signing is hash-input (BE for
# cross-platform protocol determinism convention); MergeEvent is a
# wire payload that decodes byte-for-byte (LE matches x86/ARM
# little-endian targets' native memory representation).
#
# test-merge-event-codec covers round-trip + field sensitivity +
# rejection paths. This test locks the EXACT byte layout via
# concrete golden vectors — defends against any future regression
# that flips endianness or shifts offsets.
#
# 48 assertions in seven blocks:
#
#   Empty-region golden (2):
#     - All-zero MergeEvent with empty region: 26 bytes, all zero.
#
#   event_type at offset 0 (2): BEGIN=0x00, END=0x01.
#
#   shard_id at offset 1, 4 bytes LE (8): 0x42 (LSB only) + full
#     pattern 0x12345678 (each byte position verified).
#
#   partner_id at offset 5, 4 bytes LE (4): 0xAB at LSB position.
#
#   effective_height at offset 9, 8 bytes LE (11): 0x42 LSB +
#     full pattern 0x0102030405060708.
#
#   evidence_window_start at offset 17, 8 bytes LE (3): 0x42 LSB.
#
#   region_len + region (10):
#     - region_len byte at offset 25 = region size.
#     - Empty region → region_len byte = 0.
#     - "us-east" content at offsets [26..32] byte-for-byte.
#     - Total size 26 + region_len.
#
#   Combined golden vector (8):
#     - Full populated MergeEvent with every field non-default;
#       comprehensive verification of every byte position together.
#
# Run from repo root: bash tools/test_merge_event_bytes.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== MergeEvent::encode byte-layout invariant (R4 wire format) ==="
OUT=$($DETERM test-merge-event-bytes 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-event-bytes all assertions"; then
  echo ""
  echo "  PASS: merge-event-bytes unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-event-bytes had assertion failures"
  exit 1
fi
