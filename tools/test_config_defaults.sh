#!/usr/bin/env bash
# S-035 Option 1 seed — operator-facing security defaults at
# Config::from_json({}).
#
# The most important pin is S-001's rpc_localhost_only=true default —
# a pre-S-001 config or a bare-minimum new operator's config.json
# must NOT expose RPC on all interfaces. Other defaults pin the
# "out-of-the-box safe" posture.
#
# Covered:
#   - S-001: rpc_localhost_only = true (RPC bound to localhost only)
#   - S-014: rpc_rate_per_sec / rpc_rate_burst = 0 (rate-limit disabled)
#   - S-014: gossip_rate_per_sec / gossip_rate_burst = 0 (same)
#   - bft_enabled = true (auto-escalation enabled)
#   - bft_escalation_threshold = 1 (S-045: default lowered from 5)
#   - m_creators = 3, k_block_sigs = m_creators (strong K-of-K default)
#   - chain_role = SINGLE (unsharded)
#   - sharding_mode = CURRENT (pre-R1 baseline)
#   - shard_id = 0, initial_shard_count = 1
#   - listen_port = 7777, rpc_port = 7778
#   - epoch_blocks = 1000
#   - tx_commit_ms = block_sig_ms = abort_claim_ms = 200ms
#   - region = "" + committee_region = "" (pre-R1 byte-identical)
#   - log_quiet = false
#   - rpc_auth_secret = "" (HMAC auth disabled — opt-in)
#
# Defends against default-drift that would weaken the out-of-the-box
# security posture (the catastrophic case: operator brings up node
# with default config and ends up with all-interfaces RPC binding).
#
# 22 assertions across 11 grouped scenarios.
#
# Run from repo root: bash tools/test_config_defaults.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== operator security defaults — S-001 rpc_localhost_only, S-014 rate-limit, BFT, regions ==="
OUT=$($DETERM test-config-defaults 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-defaults all assertions"; then
  echo ""
  echo "  PASS: config-defaults unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-defaults had assertion failures"
  exit 1
fi
