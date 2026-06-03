#!/usr/bin/env bash
# FA-Apply-8 (GovernanceParamChange.md, T-G1..T-G8) — in-process unit
# test pinning the DETERMINISM properties of the A5 PARAM_CHANGE
# governance flow. Complements test-pending-param-changes (staging
# read-write surface) and test-param-change-apply (basic stage→activate
# path) by exercising the harder-to-pin determinism guarantees the
# proof series rely on:
#
#   T-G4 — intra-block insertion-order resolution. Two PARAM_CHANGE
#          entries staged at the SAME effective_height, applied in
#          OPPOSITE orders on two chains, converge to identical param
#          state AND identical compute_state_root(). For the same name
#          at the same height, the last bucket entry wins
#          deterministically (apply iterates the per-height vector in
#          push_back order).
#
#   T-G6 — validator-config forwarding (the critical chain/validator
#          sync). A chain-storage param (MIN_STAKE) updates BOTH the
#          chain field AND the Node-installed param_changed_hook (the
#          validator-config mirror); a validator-only param
#          (BFT_ESCALATION_THRESHOLD) forwards via the hook with NO
#          chain mutation. Consensus uses the new value next block.
#
#   T-G2 — off-whitelist name: silently activated as a chain no-op
#          (validator enforces the whitelist at validate time; an
#          unknown name at apply means a future-version chain —
#          fail-soft). No chain-storage field changes; the drained
#          pending entry returns the p: namespace (and root) to baseline.
#
#   T-G5 + T-G7 — snapshot round-trip mid-staging. serialize_state →
#          restore_from_snapshot preserves pending entries across
#          intervening blocks; activation still fires post-restore with
#          the same result an un-snapshotted replay produces (idempotent).
#
#   T-G8 — A1 unitary-supply invariance. PARAM_CHANGE mutates protocol
#          params but touches NO balance/stake/receipt field —
#          live_total_supply() is invariant across the whole flow.
#
#   state_root binding (bonus) — the pending-param-changes p: namespace
#          contributes to compute_state_root; toggling a pending entry
#          changes the root.
#
# Network-level coverage: tools/test_governance_param_change.sh runs
# the full PARAM_CHANGE tx → validator → stage → apply → snapshot path
# across a live 3-node governed cluster. This in-process test pins the
# determinism semantics in <1s with no network/flakes.
#
# 19 assertions in eight blocks (see the handler in src/main.cpp).
#
# Run from repo root: bash tools/test_governance_param_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA-Apply-8 PARAM_CHANGE determinism (insertion-order / validator forwarding / snapshot idempotence / A1) ==="
OUT=$($DETERM test-governance-param-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: governance-param-determinism all assertions"; then
  echo ""
  echo "  PASS: governance-param-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: governance-param-determinism had assertion failures"
  exit 1
fi
