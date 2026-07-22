#!/usr/bin/env bash
# RL-2 (register S014RateLimiterSoundness): the S-014 gossip token bucket
# EXEMPTS HELLO so a freshly-attached peer can always complete the handshake
# even when its IP bucket is empty (gossip.cpp:157 `if (msg.type != HELLO)`).
#
# This drives the REAL GossipNet::handle_message over the in-process
# VirtualTransport wire (no OS socket, deterministic run_ready pump): a receiver
# with a burst=1 / near-zero-refill bucket, a sender that never sets a domain
# (so connect() emits no auto-HELLO). Sequence:
#   1. STATUS_REQUEST → consumes the one token, dispatched (on_status_request).
#   2. 2nd STATUS_REQUEST → dropped at the drained bucket (bucket is now EMPTY).
#   3. HELLO on the EMPTY bucket → STILL dispatched (peer domain set) — the
#      exemption. Mutant `if (true)` at :157 makes HELLO consume the (empty)
#      bucket → the HELLO is dropped → domain never set → this assertion flips.
#
# Assertion 2 is the non-vacuity guard: without a provably-empty bucket the
# exemption leg would pass even under the mutant. Pure std, no OS sockets —
# identical on every platform, in-process, <1s — FAST=1 eligible.
#
# Run from repo root: bash tools/test_rl2_hello_exempt.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-014 gossip HELLO-exemption (register RL-2) ==="
OUT=$($DETERM test-rl2-hello-exempt 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: rl2-hello-exempt"; then
  echo ""
  echo "  PASS: rl2-hello-exempt unit test"
  exit 0
else
  echo ""
  echo "  FAIL: rl2-hello-exempt had assertion failures"
  exit 1
fi
