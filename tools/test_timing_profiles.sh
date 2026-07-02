#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the TimingProfile
# constants in `include/determ/chain/params.hpp`.
#
# Each named profile (cluster / web / regional / global / tactical
# + their `_test` siblings + single_test) has documented M/K +
# chain_role + sharding_mode values that operators rely on for
# their deployments. A regression that silently changes any of
# these would shift the consensus posture of every chain that pins
# the profile name in its config — operators wouldn't see an error,
# just slower (or worse: different consensus mode) behavior.
#
# Test profiles also have a documented parity invariant: each
# `*_test` profile mirrors its prod sibling's (M, K, chain_role,
# sharding_mode) exactly; only the round-timer triple differs so
# CI exercises the same code paths a production deployment would.
#
# 54 assertions covering:
#
#   Production profiles (20 assertions = 5 profiles × 4 fields):
#     - cluster   = BEACON / CURRENT / M=K=3 (strong MD)
#     - web       = SHARD / EXTENDED / M=4, K=3 (weak hybrid; S-044/S-045 retune)
#     - regional  = SHARD / CURRENT / M=5, K=4
#     - global    = BEACON / EXTENDED / M=7, K=5
#     - tactical  = SHARD / EXTENDED / M=K=3 (strong MD; drone swarm)
#
#   Production round timings (7 assertions):
#     - cluster:   50/50/25 ms
#     - web:       200 ms tx_commit
#     - regional:  300 ms tx_commit
#     - global:    600 ms tx_commit
#     - tactical:  20 ms tx_commit (drone swarm)
#
#   Test profile parity with prod sibling (24 assertions = 6 test
#   profiles × 4 fields, all matching their named prod counterpart
#   except single_test which is SINGLE/NONE/M=K=3):
#     - single_test, cluster_test, web_test, regional_test,
#       global_test, tactical_test
#
#   Test-profile timing invariants (3):
#     - All _test profiles share TEST_TX_COMMIT_MS / _BLOCK_SIG_MS /
#       _ABORT_CLAIM_MS (5/5/3 ms — the sub-30ms CI sentinel).
#     - TEST_TX_COMMIT_MS < 30 (test sentinel below all prod timings).
#     - PROFILE_CLUSTER.tx_commit_ms >= 50 (fastest prod profile
#       still 10× slower than test timings — sanity for the test/
#       prod separation invariant).
#
# Run from repo root: bash tools/test_timing_profiles.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== TimingProfile constants (chain/params.hpp) — documented operator-facing values ==="
OUT=$($DETERM test-timing-profiles 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: timing-profiles all assertions"; then
  echo ""
  echo "  PASS: timing-profiles unit test"
  exit 0
else
  echo ""
  echo "  FAIL: timing-profiles had assertion failures"
  exit 1
fi
