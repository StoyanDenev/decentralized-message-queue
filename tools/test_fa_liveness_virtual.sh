#!/usr/bin/env bash
# FA4 (F-1) liveness on the REAL engine, in process — the multi-node gap
# the injection seam + VirtualTransport were built to close. FIVE real
# node::Node instances (full production stack: GossipNet wire codec,
# HELLO/STATUS handshake, contrib/block-sig rounds, committee selection,
# chain apply, GET_CHAIN sync) run in one process over injected
# VirtualEventLoop/VirtualTransport pairs sharing one VirtualNetwork —
# no OS sockets, no child processes, no ports. Genesis is
# test_weak_3node's LIVE-VALIDATED shape verbatim (M_pool=5,
# K_committee=3 weak BFT, epoch_blocks=1 per-block committees; K=2
# committees wedge by design — S-044). Three phases:
#
#   A. liveness + agreement — all 5 reach height >= 3; one genesis
#      hash; finalized blocks 1..3 byte-identical (fork-freedom over
#      the real gossip path)
#   B. FAILOVER — node4 is destroyed (dtor -> close propagation, the
#      crashed-process model); per-block committee re-derivation + the
#      S-044-fixed abort/reselection must keep the 4 survivors
#      finalizing: >= 3 more blocks past the kill height
#   C. REJOIN — node4's identity restarts on a fresh loop/transport,
#      syncs the survivors' chain (real GET_CHAIN/CHAIN_RESPONSE),
#      catches up past the failover blocks, and agrees byte-for-byte
#      on a block finalized while it was dead (adopted, not forked)
#
# Wall-clock timers still drive the rounds (virtual TIME is the next
# evolution of the backend), so this is hermetic-not-yet-deterministic:
# threshold liveness + prefix agreement, not byte traces. Where these
# properties previously needed a live shell-orchestrated cluster, this
# runs as a plain unit test on every platform. FAST=1 eligible.
#
# Run from repo root: bash tools/test_fa_liveness_virtual.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA4 liveness/failover/rejoin: 5 real Nodes over VirtualTransport (in-process) ==="
OUT=$($DETERM test-fa-liveness-virtual 2>&1)
RC=$?
echo "$OUT"

# Require BOTH the binary's exit code and the PASS marker: a marker with a
# nonzero exit means the assertions passed but teardown crashed after them
# — exactly the failure class this harness's review round surfaced.
if [ "$RC" -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: fa-liveness-virtual"; then
  echo ""
  echo "  PASS: fa-liveness-virtual unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fa-liveness-virtual (exit=$RC or missing PASS marker)"
  exit 1
fi
