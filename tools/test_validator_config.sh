#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for BlockValidator's
# public configuration API + the validate() short-circuit on
# genesis blocks.
#
# BlockValidator's check_* helpers are private (need Chain +
# NodeRegistry fixtures to exercise meaningfully — the
# full-validate path is exercised by the network-level integration
# tests). But the public API surface — setters + validate() — has
# invariants worth locking in at the unit level:
#
#   * Setters accept their documented value ranges without throwing
#     (no internal bounds-check throws on assignment).
#   * validate() on a genesis block (index 0) returns OK regardless
#     of validator config — genesis trust is anchored in the pinned
#     genesis hash, not in signature checks. This is the documented
#     short-circuit at the top of BlockValidator::validate.
#
# 16 assertions covering:
#
#   Default construction (1):
#     - BlockValidator default-constructs without throwing.
#
#   Setter accept ranges (11):
#     - set_k_block_sigs (K = 1, 3, 7, 100)
#     - set_m_pool (M = 1, 3, 10, 1000)
#     - set_bft_enabled (true/false toggle)
#     - set_bft_escalation_threshold (0..UINT32_MAX)
#     - set_epoch_blocks (1..10000)
#     - set_shard_id (0, 1, 7)
#     - set_committee_region (empty + region tag)
#     - set_sharding_mode (NONE / CURRENT / EXTENDED)
#     - set_governance_mode (0 = uncontrolled, 1 = governed)
#     - set_param_keyholders (empty + 3-element vector)
#     - set_param_threshold (0, 1, 3, 255)
#
#   validate() genesis short-circuit (4):
#     - validate() returns OK on a genesis block (index 0).
#     - validate(genesis) error message is empty.
#     - Short-circuit works with default-constructed validator
#       (no setters called).
#     - Short-circuit works under EXTENDED sharding + BFT-disabled
#       config (defensively unconditional).
#
# Run from repo root: bash tools/test_validator_config.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== BlockValidator setters + validate() genesis short-circuit ==="
OUT=$($DETERM test-validator-config 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: validator-config all assertions"; then
  echo ""
  echo "  PASS: validator-config unit test"
  exit 0
else
  echo ""
  echo "  FAIL: validator-config had assertion failures"
  exit 1
fi
