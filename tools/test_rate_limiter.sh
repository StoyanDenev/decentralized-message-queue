#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the S-014 per-peer-IP
# token-bucket rate limiter (net::RateLimiter).
#
# This is the shared helper used identically by RpcServer and
# GossipNet — both surfaces consume tokens via the same instance, so
# unit-testing the algebra here locks in policy correctness for both
# transports in one place. Complements the wire-level tests:
#
#   * tools/test_rpc_rate_limit.sh    — end-to-end RPC throttling
#   * tools/test_gossip_rate_limit.sh — end-to-end gossip throttling
#
# 16 assertions covering every observable property of the bucket:
#
#   1.  Default-constructed limiter is disabled (rate=0, burst=0)
#   2.  Disabled mode never throttles (1000/1000 pass — bucket
#       allocation is skipped entirely)
#   3.  configure(0, 0) leaves the limiter disabled
#   4-6. configure(>0, >0) enables and exposes values via getters
#   7.  First-touch bucket starts FULL (legitimate callers don't get
#       hit cold)
#   8.  Burst exhaustion: at the same instant, exactly `burst`
#       consumes succeed and the next fails
#   9.  Per-key independence: exhausting key A does NOT throttle
#       key B (the central security property — one abusive peer
#       can't deny service for others)
#  10-12. Reconfigure after creation takes effect on next consume;
#       reconfigure to disabled bypasses bucket entirely
#  13-14. Refill: with rate=20/s and a 100ms sleep, at least one new
#       token becomes available
#  15. Burst cap holds: long sleep at high rate does NOT exceed
#      burst (with burst=3 and a 500ms sleep at rate=100/s, only
#      3 consecutive consumes succeed before fail)
#  16. Scale: 100 distinct keys each consume 2 tokens — all 200 succeed
#
# Run from repo root: bash tools/test_rate_limiter.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== net::RateLimiter (S-014 token bucket) ==="
OUT=$($DETERM test-rate-limiter 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: rate-limiter all assertions"; then
  echo ""
  echo "  PASS: rate-limiter unit test"
  exit 0
else
  echo ""
  echo "  FAIL: rate-limiter had assertion failures"
  exit 1
fi
