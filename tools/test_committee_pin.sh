#!/usr/bin/env bash
# D3.3b-read (ShardTipMergeDesign.md §9.4): the shared committee_pool helpers —
# the SINGLE decision point that lets the producer (check_if_selected) and the
# validator (check_creator_selection / check_abort_certs + creator-identity
# sub-checks) resolve the SAME committee POOL and creator IDENTITY from the frozen
# cc: checkpoint on an EXTENDED chain. Any divergence forks state_root or halts
# the shard, so a shared helper is mandatory. This tests the helpers directly;
# the consensus wiring lands in the pin increment.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. committee_pin_active gate: true on EXTENDED + epoch>=1 + checkpoint;
#      false on SINGLE, and false for epoch 0 (never folded);
#   2. NO drift: select_committee_pool == present-head eligible_in_region
#      (byte-identical pool + same domain order — SINGLE stays untouched);
#   3. DRIFT (the case the pin is FOR): after a member drops out of the
#      present-head registry mid-epoch, the frozen pool still selects it AND
#      resolve_committee_member_pubkey / committee_member_registered still
#      resolve it from the frozen ed_pub set (the halt the identity pin avoids);
#   4. frozen-first with present-head fallback (unknown domain -> nullopt);
#   5. epoch 0 falls back to present-head.
#
# Run from repo root: bash tools/test_committee_pin.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== committee-pin: shared committee_pool POOL + IDENTITY helpers (D3.3b-read) ==="
OUT=$($DETERM test-committee-pin 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: committee-pin all assertions"; then
  echo ""
  echo "  PASS: committee-pin unit test"
  exit 0
else
  echo ""
  echo "  FAIL: committee-pin had assertion failures"
  exit 1
fi
