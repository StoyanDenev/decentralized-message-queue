#!/usr/bin/env bash
# §Q1 clock-injection increment 2: the injected consensus Clock drives the real
# engine's digest-bound wall time. Two claims, both over the real node::Node:
#
#   (A) BYTE-INVARIANCE of the production default — RealClock.unix_seconds() IS
#       determ::now_unix() (a verbatim delegate), so the default consensus path
#       is unchanged. The goldens (test-consensus-vectors) carry the byte-for-
#       byte proof; this is the runtime spot-check that the two reads track.
#
#   (B) VIRTUAL-TIME CONSENSUS — a single M=K=1 Node built on a VirtualClock,
#       running over the pure-std VirtualEventLoop/VirtualTransport (no OS
#       sockets), self-produces blocks whose committed, digest-bound timestamp
#       EQUALS the injected virtual seconds (a lone proposer_time is the whole
#       lower-median). Advance the injected clock and a later finalized block
#       carries the new value — the freshness gate reads the SAME clock, so the
#       stamp and the validation never disagree.
#
# This is the concrete prerequisite for a fully deterministic virtual-time
# harness (a no-thread scheduler is the remaining piece). In-process, both
# platforms, FAST=1 eligible (typ. <20s). See docs/proofs/ClockInjectionSeam.md.
#
# Run from repo root: bash tools/test_virtual_clock.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== §Q1 virtual-clock: byte-invariance + virtual-time consensus (real Node, in-process) ==="
OUT=$($DETERM test-virtual-clock 2>&1)
RC=$?
echo "$OUT"

# Require BOTH the binary's exit code AND the PASS marker (a marker with a
# nonzero exit = assertions passed but teardown crashed — the failure class the
# sibling FA harness review surfaced).
if [ "$RC" -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: virtual-clock"; then
  echo ""
  echo "  PASS: virtual-clock unit test"
  exit 0
else
  echo ""
  echo "  FAIL: virtual-clock (exit=$RC or missing PASS marker)"
  exit 1
fi
