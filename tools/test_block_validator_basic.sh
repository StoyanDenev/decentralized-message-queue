#!/usr/bin/env bash
# S-035 Option 1 seed — BlockValidator consensus-validation entry via
# the public validate() API.
#
# validate() runs ~13 sub-checks (check_prev_hash, check_creators_
# registered, check_creator_selection, check_creator_tx_commitments,
# check_creator_dh_secrets, check_abort_certs, check_equivocation_
# events, check_delay, check_block_sigs, check_cumulative_rand,
# check_transactions, check_cross_shard_receipts, check_inbound_
# receipts, check_timestamp) short-circuiting on the first failure.
# All sub-checks are PRIVATE; this test exercises them via validate().
#
# Covered:
#   - validate(genesis): index=0 short-circuits OK (trust via pinned
#     genesis hash, not consensus validation)
#   - validate with mismatched prev_hash → fail with prev_hash
#     diagnostic
#   - validate with unregistered creator → fail with diagnostic
#     naming the offending domain
#   - validate with mixed (valid + unregistered) creators → fails
#     identifying the unregistered one
#   - validate with creator count mismatching k_block_sigs → fail
#     (creator_selection gate)
#   - determinism: identical inputs → identical Result
#   - Default-constructed BlockValidator handles genesis path
#
# Defends against drift in the consensus-entry gate that would either
# accept malformed blocks (catastrophic safety drift) or reject valid
# blocks (catastrophic liveness drift).
#
# 10 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_block_validator_basic.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== BlockValidator basic validation entry — genesis/prev_hash/creators/k-size gates ==="
OUT=$($DETERM test-block-validator-basic 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-validator-basic all assertions"; then
  echo ""
  echo "  PASS: block-validator-basic unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-validator-basic had assertion failures"
  exit 1
fi
