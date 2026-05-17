#!/usr/bin/env bash
# S-035 Option 1 seed — exhaustive coverage of every state_root
# namespace (per PROTOCOL.md §4.1.1's ten-namespace table).
#
# `Chain::compute_state_root` emits leaves across these namespaces:
#   a:        accounts          (key = "a:" + domain)
#   s:        stakes            (key = "s:" + domain)
#   r:        registrants       (key = "r:" + domain)
#   d:        dapp_registry     (key = "d:" + domain)  (v2.18)
#   i:        applied_inbound_receipts (key = "i:" + src_be8 + tx_hash)
#   b:        abort_records     (key = "b:" + domain)  (S-032)
#   m:        merge_state       (key = "m:" + shard_be4)  (R4)
#   p:        pending_param_changes (key = "p:" + eff_be8 + idx_be4)
#   k:        constants         (genesis-pinned + governance-mutable)
#   k:c:      counters          (A1 supply counters)
#
# The existing `test-state-root` unit covers the `k:`-namespace via
# setter sensitivity (block_subsidy / min_stake / suspension_slash /
# unstake_delay / merge_threshold etc.). THIS test extends to the
# OTHER 8 namespaces by mutating their backing state via apply or
# direct setter and verifying `compute_state_root` changes.
#
# This is the central S-033 invariant — every namespace contributes
# to the state-root commitment. A regression in any namespace
# (forgotten leaf emission, wrong key encoding) would silently fork
# the chain at the state_root verification gate.
#
# 12 assertions covering all 10 namespaces + cross-namespace
# independence + baseline equality:
#
#   Per-namespace mutation changes root (10):
#     - a: TRANSFER → balance change → root changes
#     - s: STAKE → locked change → root changes
#     - r: DEREGISTER → inactive_from change → root changes
#     - b: Phase-1 abort → abort_records[domain].count++ → root changes
#     - d: DAPP_REGISTER → dapp_registry insert → root changes
#     - m: MERGE_BEGIN → merge_state insert → root changes
#     - p: stage_param_change → pending_param_changes insert → root changes
#     - k: set_min_stake → constant change → root changes
#     - k:c: subsidy mint → accumulated_subsidy bump → root changes
#     - i: inbound receipt → applied_inbound_receipts insert → root changes
#
#   Cross-namespace (2):
#     - identical fresh chains have identical roots (baseline equality)
#     - different mutations on different namespaces → distinct roots
#       (no accidental collision across namespaces)
#
# Run from repo root: bash tools/test_state_root_namespaces.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== compute_state_root: 10-namespace exhaustive coverage (S-033) ==="
OUT=$($DETERM test-state-root-namespaces 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-root-namespaces all assertions"; then
  echo ""
  echo "  PASS: state-root-namespaces unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-root-namespaces had assertion failures"
  exit 1
fi
