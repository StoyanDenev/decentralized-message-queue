#!/usr/bin/env bash
# S-035 Option 1 seed — nonce-gating contract as the replay-defense
# surface. chain.cpp:739 enforces strict equality:
#   if (tx.nonce != sender.next_nonce) continue;
# Both PAST nonces (replay) and FUTURE nonces (sequence gap) are
# silently skipped.
#
# Covered:
#   - Successful apply bumps nonce (0 → 1)
#   - Replay (stale nonce): silently skipped — alice balance unchanged,
#     bob balance unchanged, nonce stays (NOT re-bumped), no fee charged
#   - Future nonce (gap in sequence): silently skipped
#   - Per-sender nonces are INDEPENDENT (alice's advancement doesn't
#     affect bob's nonce gating)
#   - A1 invariance under repeated replay attempts (supply unchanged)
#   - Determinism: same replay sequence → same state_root
#
# Defends against regressions where strict-equality drifts to `>=`
# (allowing future-nonce TXs) or `>` (allowing replay of past nonces).
#
# 13 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_tx_replay_protection.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== nonce-gating replay defense — stale/future/per-sender/A1 ==="
OUT=$($DETERM test-tx-replay-protection 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-replay-protection all assertions"; then
  echo ""
  echo "  PASS: tx-replay-protection unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-replay-protection had assertion failures"
  exit 1
fi
