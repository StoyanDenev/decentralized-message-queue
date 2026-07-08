#!/usr/bin/env bash
# FA4 liveness under ADVERSARIAL NETWORK conditions, real engine, in process.
# Where test_fa_liveness_virtual.sh stresses node DEATH, this stresses the
# DELIVERY layer: five real node::Node instances (test_weak_3node's 3-of-5
# weak-BFT / per-block-committee shape) run in one process over an injected
# VirtualTransport whose VirtualNetwork drops/gates whole gossip frames.
#
#   Phase 1 — LOSSY LINKS: after steady state, 25% of every gossip frame is
#     dropped on every link. WITHOUT the S-047 retry a single lost
#     claim/contrib/abort wedges the round permanently (a one-shot broadcast
#     is never re-sent); WITH it, each round re-attempts its state every
#     timer tick, so under fair loss every message is eventually delivered
#     and the cluster keeps finalizing (+3 blocks) and agreeing
#     byte-for-byte. Then loss heals and full-rate progress resumes. This is
#     the direct liveness validator for the S-047 fix
#     (RoundStateRetrySoundness.md proves the asymptotic claim; heavier loss
#     converges too, but only beyond a wall-clock gate's budget).
#
#   Phase 2 — PARTITION SAFETY: one node is isolated by a {4}|{1} delivery
#     partition. The 4-node majority keeps finalizing; the isolated node,
#     below the K=3 quorum, FREEZES and never forks — its chain stays a
#     consistent PREFIX of the majority's. Heal does not auto-recover the
#     isolated node (no periodic re-sync probe — an operational boundary,
#     SECURITY.md §S-048); that is printed as a NOTE, not asserted.
#
# In-process, no OS sockets/processes, deterministic-enough to gate: the
# fault model is whole-frame granular (one async_write == one message), so
# framing is never corrupted. FAST=1 eligible (typ. <15s).
#
# Run from repo root: bash tools/test_fa_partition_virtual.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA4 adversarial-network: lossy links + partition (5 real Nodes, in-process) ==="
OUT=$($DETERM test-fa-partition-virtual 2>&1)
RC=$?
echo "$OUT"

# Require BOTH the binary's exit code and the PASS marker (a marker with a
# nonzero exit = assertions passed but teardown crashed — the failure class
# this harness's sibling review round surfaced).
if [ "$RC" -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: fa-partition-virtual"; then
  echo ""
  echo "  PASS: fa-partition-virtual unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fa-partition-virtual (exit=$RC or missing PASS marker)"
  exit 1
fi
