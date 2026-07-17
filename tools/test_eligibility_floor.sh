#!/usr/bin/env bash
# S-051 Option B "eligibility floor" — partial floor, fill to K (owner
# decision 2026-07-17; docs/proofs/EligibilityFloorDesign.md §3-B/§4).
#
# Closes the suspension-pool-exhaustion permanent halt: when fewer than
# K domains pass the full eligibility filter, suspensions are lifted in
# ascending (abort_record.count, last_block, domain) order — exactly
# enough to bring the pool back to K. Dormant (lift set EMPTY, filter
# byte-identical to pre-S-051) whenever >= K domains are eligible.
#
# The ONE shared implementation lives in
# include/determ/chain/eligibility_floor.hpp and is consumed by BOTH
# consensus mirrors:
#   - NodeRegistry::build_from_chain   (node selection + validator input)
#   - Chain::freeze_epoch_committee    (D3.3b frozen `cc:` checkpoints)
# select_committee_pool's pinned path reads the frozen members verbatim.
#
# ~20 assertions in nine blocks:
#
#   Fixture sanity (5):
#     - abort accumulators planted via REAL round-1 AbortEvent apply
#       (dA{2,10}, dB{1,12}, dC{1,11}, dP{1,12}); dP slashed below
#       min_stake
#
#   Suspension-formula regression (5):
#     - exact window boundaries for count=1 and count=2 (len = BASE<<exp),
#       unknown domain never suspended
#
#   Floor semantics (10):
#     - k == 0 disables the floor (pre-fix halt baseline pool {dD,dE})
#     - dormant at the exactly-K boundary
#     - fill-to-K: hand-computed ascending lift order picks dC alone
#       ((1,11,dC) < (1,12,dB) < (2,10,dA)) — the falsify-on-mutant
#       discriminator (a reversed sort would lift dA)
#     - lift candidates must be base-eligible (dP never lifted: stake)
#     - candidate exhaustion leaves the pool short (formation still gates)
#     - natural expiry restores dormancy
#     - three-mirror equivalence at every (K, at_index) + unpinned
#       fallback shape
#     - purity (repeated evaluation bit-identical)
#
# Run from repo root: bash tools/test_eligibility_floor.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-051 eligibility floor (Option B fill-to-K, shared mirrors) ==="
OUT=$($DETERM test-eligibility-floor 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: eligibility-floor all assertions"; then
  echo ""
  echo "  PASS: eligibility-floor unit test"
  exit 0
else
  echo ""
  echo "  FAIL: eligibility-floor had assertion failures"
  exit 1
fi
