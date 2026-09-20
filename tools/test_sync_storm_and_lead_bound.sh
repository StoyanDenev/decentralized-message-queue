#!/usr/bin/env bash
# S-085 / S-080 — Sync safety: bounded lead plausibility and sync storm mitigation.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-085 / S-080: Bounded sync lead and sync storm mitigation ==="
OUT=$("$DETERM" test-sync-storm-and-lead-bound 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-sync-storm-and-lead-bound"; then
  echo "  PASS: test_sync_storm_and_lead_bound"
  exit 0
else
  echo "  FAIL: test_sync_storm_and_lead_bound (exit $rc)"
  exit 1
fi
