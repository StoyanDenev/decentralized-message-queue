#!/usr/bin/env bash
# FA4 (F-1) liveness on the REAL engine, in process — the multi-node gap
# the injection seam + VirtualTransport were built to close. THREE real
# node::Node instances (full production stack: GossipNet wire codec,
# HELLO/STATUS handshake, contrib/block-sig rounds, committee selection,
# chain apply) run in one process over injected VirtualEventLoop/
# VirtualTransport pairs sharing one VirtualNetwork — no OS sockets, no
# child processes, no ports. Weak-BFT K=2/M=3 (test_weak_3node's shape).
#
# Asserts:
#   * liveness — every node's chain reaches height >= 3
#   * agreement — one genesis hash; finalized blocks 1..3 byte-identical
#     across all nodes (fork-freedom over the real gossip path)
#
# Wall-clock timers still drive the rounds (virtual TIME is the next
# evolution of the backend), so this is hermetic-not-yet-deterministic:
# threshold liveness + prefix agreement, not byte traces. Where the same
# property previously needed a live shell-orchestrated cluster
# (test_weak_3node), this runs as a plain unit test on every platform —
# in-process, <10s typical, FAST=1 eligible.
#
# Run from repo root: bash tools/test_fa_liveness_virtual.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA4 liveness: 3 real Nodes over VirtualTransport (in-process) ==="
OUT=$($DETERM test-fa-liveness-virtual 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-liveness-virtual"; then
  echo ""
  echo "  PASS: fa-liveness-virtual unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fa-liveness-virtual had assertion failures"
  exit 1
fi
