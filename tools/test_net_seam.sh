#!/usr/bin/env bash
# minix net-seam contract pins — net::Timer + net::EventLoop
# (include/determ/net/timer.hpp + event_loop.hpp) over today's asio
# backends (asio_timer.hpp / asio_event_loop.hpp). Pins the INTERFACE
# contract the future native IOCP / epoll/kqueue backends must satisfy
# (docs/proofs/MinixTacticalProfile.md §4):
#
#   * post(fn) runs on a loop thread; stop() releases run()
#   * arm(delay, on_expire) fires ONLY on clean expiry
#   * cancel() before expiry suppresses on_expire (idempotent, safe
#     when not armed)
#   * a re-arm supersedes the previous arm (old callback suppressed)
#   * run() callable concurrently from multiple threads (io_context /
#     IOCP-completion-port model)
#
# All phases are timing-DETERMINISTIC: sequenced through run() returning
# when a callback calls stop(); cancels/re-arms are issued before run()
# starts AND beat 10-minute (unreachable) deadlines, so outcomes are
# ordered by the API, never raced against wall-clock. Fresh
# AsioEventLoop per phase (no stopped-io_context reuse). In-process,
# no network, <5s — FAST=1 eligible.
#
# Run from repo root: bash tools/test_net_seam.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== minix net seam: net::Timer + net::EventLoop contracts ==="
OUT=$($DETERM test-net-seam 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: net-seam all assertions"; then
  echo ""
  echo "  PASS: net-seam unit test"
  exit 0
else
  echo ""
  echo "  FAIL: net-seam had assertion failures"
  exit 1
fi
