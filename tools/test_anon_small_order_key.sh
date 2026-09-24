#!/usr/bin/env bash
# S-072 / D10 — small-order anonymous identities rejected under consensus.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  FAIL: test_anon_small_order_key — determ binary not found"; exit 1; fi

echo "=== S-072 / D10: small-order anonymous keys rejected under consensus ==="
OUT=$("$DETERM" test-anon-small-order-key 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-anon-small-order-key"; then
  echo "  PASS: test_anon_small_order_key"
  exit 0
else
  echo "  FAIL: test_anon_small_order_key (exit $rc)"
  exit 1
fi
