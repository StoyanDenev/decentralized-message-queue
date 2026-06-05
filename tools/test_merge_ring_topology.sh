#!/usr/bin/env bash
# In-process unit test for the R7 under-quorum-merge RING-PAIRING
# TOPOLOGY law (regional sharding merge state machine).
#
# The MERGE_EVENT apply path (chain.cpp) admits a merge only when
#     partner_id == (shard_id + 1) % shard_count
# — a single fixed modular-successor rule. That rule is what makes the
# merge state machine deterministic and collision-free: every shard has
# exactly one valid absorber, the (shard → partner) map is a single
# Hamiltonian cycle over all shards, and the inverse (partner → refugee)
# map is a bijection. test-merge-event-apply spot-checks a couple of
# pairings + one wrong-partner rejection; test-merge-event-codec pins the
# byte layout. NEITHER pins the ring LAW as a whole — this test does.
#
# 9 assertions covering:
#
#   Per-shard uniqueness (1):
#     1. ring(5): each shard admits EXACTLY ONE partner = (s+1)%5.
#
#   Wraparound + direction (2):
#     2. ring(4): wraparound — shard 3 pairs with shard 0.
#     3. ring(4): direction pinned — predecessor rejected, successor
#        admitted.
#
#   Cycle structure (2):
#     4. ring(6): partner pointers form ONE Hamiltonian cycle.
#     5. ring(3): no fixed point — BEGIN(s→s) rejected for every shard.
#
#   Inverse bijection + boundaries (4):
#     6. ring(5): shards_absorbed_by(p) == {(p-1+5)%5} for every p.
#     7. ring(1): single-shard ring admits no merge.
#     8. ring(4): END is ring-gated — unlawful no-op, lawful un-pairs.
#     9. ring(4): topology is salt-independent.
#
# Cross-reference: docs/proofs/UnderQuorumMerge.md +
# docs/proofs/RegionalSharding.md.
#
# Run from repo root: bash tools/test_merge_ring_topology.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== R7 merge ring-pairing topology law (under-quorum merge) ==="
OUT=$($DETERM test-merge-ring-topology 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-ring-topology all assertions"; then
  echo ""
  echo "  PASS: merge-ring-topology unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-ring-topology had assertion failures"
  exit 1
fi
