#!/usr/bin/env bash
# D3.4 / S-036 (v2.11) — the Block.eligible_count source-committee self-report:
# a SHARD-role producer under EXTENDED writes eligible_in_region(committee_region)
# at its head into the block, and the K-of-K committee signs it (via
# compute_block_digest), so a captured beacon cannot later present a false
# distress count that carries a valid source-committee attestation. This is the
# on-chain artifact the MERGE_BEGIN historical-witness check (D3.6) reads.
#
# The binary test pins: zero-skip wire round-trip (count 0 is ELIDED from JSON —
# every SINGLE/CURRENT/BEACON chain + golden byte-identical), the u32 range guard
# (an oversized value fails closed, never truncates into a SMALLER count that
# could spuriously read as sub-2K distress), hash + committee-digest binding (the
# count is part of block identity AND covered by the K-of-K signed digest), and
# the tamper property (forging the count changes BOTH bindings, so the carried
# signatures no longer verify). The producer/light digest-parity for the new
# conditional append is pinned by tools/test_block_digest_xbinary_parity.sh.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D3.4 Block.eligible_count source self-report ==="
OUT=$($DETERM test-eligible-count 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_eligible_count (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: test-eligible-count"; then
  echo ""
  echo "  PASS: test_eligible_count"
  exit 0
else
  echo ""
  echo "  FAIL: test_eligible_count (missing summary marker)"
  exit 1
fi
