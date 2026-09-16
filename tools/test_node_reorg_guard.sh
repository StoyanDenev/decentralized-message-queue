#!/usr/bin/env bash
# S-102 (adjudicated + closed 2026-09-16): the A4 depth-1 head reorg is ATOMIC
# over an apply throw.
#
# Node::maybe_reorg_to_locked runs revert_head() -> validate -> append(). The
# block validator never reads state_root and compute_block_digest never covers
# it, so a RELAYER holding no committee key can take the produced head, rewrite
# ONLY state_root to a wrong non-zero value, keep every signature byte-for-byte
# and (grinding that free field for the smaller hash) win resolve_fork. That
# sibling passes validate() against H-1 and its apply throws the S-033
# state_root mismatch AFTER the head was popped. Before the guard the throw
# escaped to the gossip dispatcher and the node silently lost its head.
#
# Assertions (in-process: a real follower Node over VirtualTransport, restarted
# from its own block store between phases — FAST-eligible, no cluster):
#   fixture  the deterministic producer's blocks 1 + 2; the relabelled sibling
#            shares block 1's signatures and committee digest, differs in hash;
#   W        Chain-layer witness: BlockValidator::validate ACCEPTS the sibling
#            at H-1 and Chain::append THROWS "state_root mismatch (S-033)";
#            apply itself is atomic; block 1 still re-applies (the restore);
#   G0-G5    THE GUARD: after the sibling, height / head hash / state_root are
#            unchanged, the logged reason names the apply throw + the restore,
#            the sibling is not adopted, the producer's block 2 still appends,
#            the on-disk block store is byte-identical before/after a rejected
#            attempt (manifest + every block file), and the store restarts;
#   P0-P3    POSITIVE CONTROL: a correctly-rooted, validly re-signed sibling
#            still reorgs over the same restarted-store path, the store's tail
#            file is rewritten to the winner, and a restart loads it.
#
# Mutants (all RED against the rebuilt binary — see the audit record):
#   M1 remove the restore (the pre-fix code)     -> G2/G3/G4/G5 RED
#   M2 drop revert_head's persisted_count_ clamp -> P2/P3 RED
#   M3 swallow the throw, keep the H-1 state     -> G2/G3/G4/G5 RED
#   M4 restore on std::logic_error only          -> G2/G3/G4/G5 RED
#
# Run from repo root: bash tools/test_node_reorg_guard.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== node-reorg-guard: the depth-1 reorg is atomic over an apply throw (S-102) ==="
OUT=$($DETERM test-node-reorg-guard 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: node-reorg-guard all assertions"; then
  echo ""
  echo "  PASS: node-reorg-guard unit test"
  exit 0
else
  echo ""
  echo "  FAIL: node-reorg-guard had assertion failures"
  exit 1
fi
