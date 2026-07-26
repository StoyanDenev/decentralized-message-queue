#!/usr/bin/env bash
# LightVerify WATCH-1 — watch-head must NOT present the tip's own state_root as a
# committee-verified value.
#
# THE GAP: `watch-head` fetches ONLY the chain tip and printed its `state_root`
# (read from the daemon's self-declared header field) next to `sigs_valid=yes`.
# But the committee signature authenticates the block DIGEST
# (light_compute_block_digest), which EXCLUDES state_root, and the tip has NO
# committee-signed successor to anchor it. So a hostile/MITM daemon can swap the
# tip's `state_root` field to a forged value (the digest is unchanged, so the K
# committee sigs still verify) and the operator trusts a root the committee
# never signed.
#
# THE FIX (client-side, no wire/consensus change): the per-tick line renders the
# tip's own state_root under a `tip_state_root(UNVERIFIED)` label — never as a
# verified value — and head_hash as-served; `sigs_valid` reflects only the
# digest quorum. A committee-verified state_root for a non-tip height stays
# available via the `verify-state-root` command (committee-signed-successor
# anchor). The line-formatting decision was factored into a pure
# `format_watch_tick(...)` so the relabel is testable OFFLINE with no daemon.
#
# GATE (FAST, offline; the determ-light `selftest-watch-label` subcommand drives
# format_watch_tick with a forged tip state_root):
#   - the tip state_root is rendered under the UNVERIFIED label (the fix)
#   - the forged value appears ONLY under that label (never as verified)
#   - a valid tick still renders sigs_valid=yes + height + as-served head_hash
# Falsify-on-mutant (revert to a bare `state_root=` label): the two label
# asserts flip; the non-vacuity assert stays green — a clean directional split.
#
# Run from repo root: bash tools/test_light_watch_head_label.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

# The subcommand prints its own PASS/FAIL asserts + a summary and mirrors the
# outcome in its exit code. Capture (never echo raw on success — its own FAIL:
# lines on a failing run would otherwise reach run_all's tail-10 marker scan).
OUT=$("$DETERM_LIGHT" selftest-watch-label 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-watch-label"; then
  echo "  PASS: test_light_watch_head_label"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_watch_head_label"
  exit 1
fi
