#!/usr/bin/env bash
# S-075 — Snapshot bootstrap with partial header tail preserves chain following.
#
# When a node bootstrapped from a snapshot carrying a partial tail of headers
# (e.g. 16 headers or any count < total height), Chain::height() returned
# blocks_.size() (the count of tail headers retained in memory) instead of the
# true absolute chain height (head().index + 1).
#
# This test verifies that:
# 1. Chain height reflects the absolute height (base_index_ + blocks_.size()).
# 2. base_index() correctly points to the index of the first retained tail header.
# 3. Chain::at(i) maps absolute block index i to the tail slice, or throws out_of_range.
# 4. Chain::has_block(i) accurately indicates whether block i is retained in memory.
# 5. Subsequent blocks can be appended with the correct next index.
# 6. Non-contiguous or hash-broken snapshot tails are rejected at restore/decode time.
#
# Run from repo root: bash tools/test_snapshot_partial_header_tail.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-075: snapshot bootstrap with partial header tail ==="
OUT=$($DETERM test-snapshot-partial-header-tail 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-snapshot-partial-header-tail"; then
  echo ""
  echo "  PASS: test-snapshot-partial-header-tail unit test"
  exit 0
else
  echo ""
  echo "  FAIL: test-snapshot-partial-header-tail had assertion failures"
  exit 1
fi
