#!/usr/bin/env bash
# A4 / S-048 (BoundedReorgDesign.md A4.2 + A4.3): the DETERMINISTIC S-048
# reorg reproduction that gates the node-side resolve_fork wiring.
#
# A non-producing FOLLOWER node is fed, over the REAL gossip → on_block path,
# a producer's block at the head height and then a same-height competitor; it
# must reorg to Chain::resolve_fork's winner (depth-1) — or keep its head when
# the competitor loses the tie-break or is invalid.
#
# Assertions (in-process, no cluster — FAST-eligible):
#   1. crafted a validly-signed same-height competitor that WINS resolve_fork;
#   2. the follower accepts the producer's block (normal accept path);
#   3. S-048 REORG: the follower replaces its head with the winner;
#   4. DETERMINISTIC producer: identical seed → byte-identical base block;
#   5. REPLAY: the whole fork+reorg replays byte-identically (register gate);
#   6. LOSER competitor is dropped (head unchanged);
#   7-8. INVALID competitor (garbage Phase-1 sig) is rejected after the revert
#        and the old head restored verbatim (fail-closed);
#   9. A4.4 SYNC rejoiner — a same-height winner delivered over the
#      CHAIN_RESPONSE sync path (not gossip) is adopted via the reorg (the
#      restarted-minority-tail convergence path).
#
# Run from repo root: bash tools/test_node_reorg_s048.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== node-reorg-s048: resolve_fork wiring + depth-1 reorg (A4.2/A4.3) ==="
OUT=$($DETERM test-node-reorg-s048 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: node-reorg-s048 all assertions"; then
  echo ""
  echo "  PASS: node-reorg-s048 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: node-reorg-s048 had assertion failures"
  exit 1
fi
