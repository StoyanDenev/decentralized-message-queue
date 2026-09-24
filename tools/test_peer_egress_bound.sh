#!/usr/bin/env bash
# S-082 (D19a) — bounded per-peer egress write queue (Peer::MAX_PEER_WRITE_QUEUE).
# In-process: no network, no daemon. A missing binary is a FAILURE (tools/common.sh
# SKIP convention: fail closed).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  FAIL: test_peer_egress_bound — determ binary not found"; exit 1; fi

echo "=== S-082: bounded peer egress write queue ==="
OUT=$("$DETERM" test-peer-egress-bound 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-peer-egress-bound"; then
  echo "  PASS: test_peer_egress_bound"
  exit 0
else
  echo "  FAIL: test_peer_egress_bound (exit $rc)"
  exit 1
fi
