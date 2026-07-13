#!/usr/bin/env bash
# D3.5a / S-036 (v2.11) — the Block.shard_tip_records set (Layer 1 substrate). A
# BEACON producer under EXTENDED folds source-shard distress + sparse-liveness
# attestations (D3.1 ShardTipRecord) into its block; these become `t:` state leaves
# (D3.5b) that the MERGE_BEGIN historical-witness check (D3.6) reads instead of the
# beacon's self-asserted evidence window. This is the byte-neutral field + digest
# binding (the D3.4 eligible_count twin, one increment up).
#
# The binary test pins: zero-skip wire round-trip (empty set ELIDED from JSON — every
# SINGLE/CURRENT/BEACON chain + golden byte-identical); per-record decode fail-closed
# (a malformed record hex throws, never silently dropped); hash + committee-digest
# zero-skip identity + binding (empty ≡ pre-D5a; a record makes both distinct); the
# ORDER-INDEPENDENT root (the digest/hash bind ONE root over the record SET, so
# swapping record order is byte-identical — but stripping/mutating/adding a record
# changes both bindings so the carried K-of-K signatures no longer verify). The
# producer/light digest-parity for the new conditional append is pinned by
# tools/test_block_digest_xbinary_parity.sh (18-token canonical sequence).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D3.5a Block.shard_tip_records set ==="
OUT=$($DETERM test-shard-tip-records 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_shard_tip_records (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: test-shard-tip-records"; then
  echo ""
  echo "  PASS: test_shard_tip_records"
  exit 0
else
  echo ""
  echo "  FAIL: test_shard_tip_records (missing summary marker)"
  exit 1
fi
