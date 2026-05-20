#!/usr/bin/env bash
# S-014 token-bucket arithmetic primitives — companion to
# tools/test_rate_limiter.sh.
#
# Where test_rate_limiter.sh pins the net::RateLimiter at the POLICY
# level (disabled-mode bypass, configure() round-trip, first-touch
# full, per-key independence, refill timing, burst-cap invariant),
# this test pins the underlying TOKEN-BUCKET ARITHMETIC that the
# policy is built on:
#
#   * Constructor invariants (default 0/0, getters)
#   * consume() at full / drained / over-cap boundaries
#   * Refill at 0 / brief / long elapsed windows
#   * Saturation at burst (no over-fill regardless of elapsed time)
#   * Zero-rate, zero-capacity disable signals (both ≤ 0 → bypass)
#   * Sustained-rate envelope (rate*window + burst upper bound)
#   * No public reset() — reconfigure() does NOT refill an existing
#     key's bucket (pinned so a future change is deliberate)
#   * Per-key + per-instance independence at scale (100 distinct keys)
#   * steady_clock monotonicity under tight retries
#   * Empty-string key + many-key fan-out defensive pins
#
# 26 assertion blocks (~30 individual checks). The two tests
# intentionally overlap on a few anchor assertions (first-touch full,
# burst cap) so a regression in either layer fails both.
#
# Complements the wire-level tests:
#
#   * tools/test_rpc_rate_limit.sh    — end-to-end RPC throttling
#   * tools/test_gossip_rate_limit.sh — end-to-end gossip throttling
#
# Run from repo root: bash tools/test_rate_limiter_bucket.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== net::RateLimiter S-014 token-bucket arithmetic primitives ==="
OUT=$($DETERM test-rate-limiter-bucket 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: rate-limiter-bucket all assertions"; then
  echo ""
  echo "  PASS: rate-limiter-bucket unit test"
  exit 0
else
  echo ""
  echo "  FAIL: rate-limiter-bucket had assertion failures"
  exit 1
fi
