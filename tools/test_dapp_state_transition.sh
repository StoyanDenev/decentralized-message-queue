#!/usr/bin/env bash
# S-035 Option 1 seed — full DApp registry lifecycle apply test.
# Complements test-dapp-register (which exercises registration
# mechanics) and test-dapp-call (which exercises message delivery).
#
# DAPP_REGISTER tx with op=0 = create OR update of an existing
# entry; op=1 = deactivate. Apply path semantics:
#
#   op=0 create:
#     - dapp_registry[tx.from] inserted with full record (service_pubkey,
#       endpoint_url, topics, retention, metadata)
#     - registered_at = current block height
#     - active_from = current block height (active immediately)
#     - inactive_from = UINT64_MAX (sentinel: active)
#
#   op=0 update (same domain re-registers):
#     - All record fields REPLACED with new values
#     - registered_at PRESERVED (original creation time)
#     - active_from REFRESHED to current height
#     - inactive_from RESET to UINT64_MAX (re-activate if previously deactivated)
#
#   op=1 deactivate:
#     - inactive_from = current_height + DAPP_GRACE_BLOCKS (deferred)
#     - Entry STAYS in dapp_registry — the grace window lets queued
#       DAPP_CALL messages reach the DApp before active-pool checks
#       gate it out.
#
# Network-level: tools/test_dapp_register.sh + test_dapp_call.sh +
# test_dapp_e2e.sh exercise these end-to-end via 3-node gossip;
# this in-process test pins the per-tx apply semantics + state
# transition in <1s.
#
# 22 assertions across five blocks:
#
#   Initial registration op=0 (7):
#     - entry created with all fields preserved
#     - inactive_from sentinel, registered_at = current height
#
#   Update op=0 on same domain (7):
#     - service_pubkey, endpoint_url, topics, retention, metadata replaced
#     - registered_at PRESERVED (not refreshed on update)
#     - inactive_from stays sentinel
#
#   Deactivate op=1 (4):
#     - entry persists (deferred via grace window)
#     - inactive_from set (no longer sentinel) AND > current height
#     - prior fields untouched
#
#   Independent domain (2):
#     - bob can register without affecting alice
#     - alice's deactivated entry preserved
#
#   Registry size + determinism (2):
#     - dapp_registry has 2 entries
#     - replayed lifecycle on second chain → same state_root
#
# Run from repo root: bash tools/test_dapp_state_transition.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DApp registry lifecycle (register → update → deactivate) ==="
OUT=$($DETERM test-dapp-state-transition 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp-state-transition all assertions"; then
  echo ""
  echo "  PASS: dapp-state-transition unit test"
  exit 0
else
  echo ""
  echo "  FAIL: dapp-state-transition had assertion failures"
  exit 1
fi
