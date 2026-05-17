#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `Chain::serialize_state`
# + `Chain::restore_from_snapshot` round-trip. The snapshot wire format
# is used by:
#   - `determ snapshot create / inspect / fetch` operator commands
#   - SNAPSHOT_RESPONSE gossip (peer-to-peer fast-bootstrap)
#   - the S-037 / S-038 closure path (dapp_registry + state_root
#     verification gate)
#
# A regression that drops a field on serialize or fails to restore one
# would silently break either fast-sync bootstrap (account / stake /
# registry differences) or the S-033 state-root verification gate
# (every post-restore block validates state_root against the restored
# chain's compute_state_root).
#
# `tools/test_dapp_snapshot.sh` exercises the dapp_registry path
# end-to-end via 3-node gossip; this in-process test pins the core
# round-trip semantics in <1s.
#
# Implementation note: every block in the populated-chain fixture sets
# `b.creators = {"alice"}` so fees route back to alice and the A1
# invariant holds (see test-chain-apply-block gotcha).
#
# 14 assertions in five blocks:
#
#   Basic round-trip (2):
#     - serialize_state returns version=1 JSON object
#     - block_index + head_hash reflect chain tip
#
#   Account / stake / registry state (4):
#     - balance + next_nonce preserved
#     - stake locked preserved
#     - registrant ed_pub + region (R1) preserved
#
#   A1 supply invariants (2):
#     - all 5 A1 counters preserved
#     - A1 invariant (expected == live) holds post-restore
#
#   Genesis-pinned constants (1):
#     - 4 setters (block_subsidy, min_stake, suspension_slash,
#       unstake_delay) round-trip
#
#   S-033/S-037/S-038 central contract (1):
#     - compute_state_root preserved across round-trip
#
#   Rejection + back-compat (3):
#     - unsupported version rejected with clear diagnostic
#     - non-object input rejected
#     - minimal snapshot (version only) loads cleanly with defaults
#       (legacy back-compat path)
#
#   Determinism (1):
#     - same snapshot → same restored state_root
#
# Run from repo root: bash tools/test_snapshot_roundtrip.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::serialize_state + restore_from_snapshot round-trip ==="
OUT=$($DETERM test-snapshot-roundtrip 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-roundtrip all assertions"; then
  echo ""
  echo "  PASS: snapshot-roundtrip unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-roundtrip had assertion failures"
  exit 1
fi
