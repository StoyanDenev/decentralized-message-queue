#!/usr/bin/env bash
# minix in-memory backend contract pins — VirtualEventLoop + LoopTimer +
# VirtualTransport/VirtualNetwork (include/determ/net/virtual_transport.hpp),
# the deterministic backend the FA4 in-process multi-node harness and DSF
# §Q2 injection run on. Everything test_net_native.sh pins for the native
# backends, adapted to the documented in-memory deviations, PLUS the
# surface only this backend exposes:
#
#   * single-thread run() delivers in exact post() order (the determinism
#     property multi-node traces lean on)
#   * two loops + two transports over ONE shared VirtualNetwork — the
#     multi-node cluster shape
#   * BOTH rendezvous orders (accept-then-connect, connect-then-accept)
#   * refused connect on a listener-less port; duplicate-bind throw
#   * write-after-close fails immediately on both ends (the FB71
#     stuck-writer break realized as next-write failure — in-memory
#     writes never block)
#
# Pure std, no OS sockets — identical assertions on every platform.
# In-process, <10s — FAST=1 eligible.
#
# Run from repo root: bash tools/test_net_virtual.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== minix virtual backend: VirtualEventLoop/LoopTimer/VirtualTransport contracts ==="
OUT=$($DETERM test-net-virtual 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: net-virtual"; then
  echo ""
  echo "  PASS: net-virtual unit test"
  exit 0
else
  echo ""
  echo "  FAIL: net-virtual had assertion failures"
  exit 1
fi
