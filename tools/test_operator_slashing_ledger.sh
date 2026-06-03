#!/usr/bin/env bash
# test_operator_slashing_ledger.sh — smoke test for
# tools/operator_slashing_ledger.sh.
#
# Strategy: lightweight argument-surface verification. Boots NO node.
# Exercises the script's argument parsing + error-path exit codes +
# --help rendering. The actual RPC integration (supply / abort-records /
# block-range) + the python-heredoc parse/render core is dynamically
# tested by every operator who runs the script against a live daemon.
#
# This follows the operator_*-smoke pattern (see
# tools/test_operator_committee_snapshot.sh as the precedent): a cluster
# boot is heavy and brittle, and the lighter --help / bad-args / no-args
# smoke is sufficient to catch script regressions in CI WITHOUT a
# multi-node cluster. The one "live" probe uses an unreachable port
# (--rpc-port 1) so it returns immediately with exit 1 and never blocks.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

SCRIPT="tools/operator_slashing_ledger.sh"
FAIL_COUNT=0
CHECKS=0
fail() { echo "  FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
ok()   { echo "  ok: $1"; }
chk()  { CHECKS=$((CHECKS + 1)); }

# ── (1) --help renders and exits 0 ────────────────────────────────────────────
echo "=== (1) --help exits 0 + renders usage ==="
chk
OUT=$(bash "$SCRIPT" --help 2>&1)
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "--help should exit 0 (got $RC)"
elif ! echo "$OUT" | grep -q "Usage: operator_slashing_ledger.sh"; then
  fail "--help output missing 'Usage:' header"
else
  ok "--help works"
fi

# ── (2) -h alias exits 0 ──────────────────────────────────────────────────────
echo "=== (2) -h alias exits 0 ==="
chk
bash "$SCRIPT" -h >/dev/null 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "-h should exit 0 (got $RC)"
else
  ok "-h alias works"
fi

# ── (3) missing --rpc-port → exit 1 + diagnostic ─────────────────────────────
echo "=== (3) missing --rpc-port exits 1 ==="
chk
OUT=$(bash "$SCRIPT" 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "missing --rpc-port should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q -- "--rpc-port is required"; then
  fail "missing --rpc-port diagnostic missing 'is required'"
else
  ok "missing --rpc-port exits 1 with diagnostic"
fi

# ── (4) non-numeric --rpc-port → exit 1 ──────────────────────────────────────
echo "=== (4) non-numeric --rpc-port exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port abc 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "non-numeric --rpc-port should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "positive integer"; then
  fail "non-numeric --rpc-port diagnostic missing 'positive integer'"
else
  ok "non-numeric --rpc-port exits 1 with diagnostic"
fi

# ── (5) unknown argument → exit 1 + usage to stderr ──────────────────────────
echo "=== (5) unknown argument exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --bogus 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "unknown argument should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "unknown argument"; then
  fail "unknown argument diagnostic missing"
else
  ok "unknown argument exits 1 with diagnostic"
fi

# ── (6) --from without --with-events → exit 1 ────────────────────────────────
echo "=== (6) --from without --with-events exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --from 0 --to 5 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "--from without --with-events should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "require --with-events"; then
  fail "stray --from/--to diagnostic missing 'require --with-events'"
else
  ok "--from/--to without --with-events exits 1 with diagnostic"
fi

# ── (7) --with-events without --from/--to → exit 1 ───────────────────────────
echo "=== (7) --with-events without --from/--to exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --with-events 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "--with-events without bounds should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "requires both --from and --to"; then
  fail "--with-events bounds diagnostic missing"
else
  ok "--with-events without bounds exits 1 with diagnostic"
fi

# ── (8) --with-events with non-numeric bound → exit 1 ────────────────────────
echo "=== (8) --with-events non-numeric bound exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --with-events --from x --to 5 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "non-numeric --from should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "must be unsigned integers"; then
  fail "non-numeric bound diagnostic missing"
else
  ok "non-numeric bound exits 1 with diagnostic"
fi

# ── (9) --to < --from → exit 1 ───────────────────────────────────────────────
echo "=== (9) inverted window exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --with-events --from 10 --to 5 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "inverted window should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "must be >= --from"; then
  fail "inverted window diagnostic missing"
else
  ok "inverted window exits 1 with diagnostic"
fi

# ── (10) over-cap window → exit 1 (anti-hang bound) ──────────────────────────
echo "=== (10) over-cap window exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --with-events --from 0 --to 999999999 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "over-cap window should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "exceeds cap"; then
  fail "over-cap window diagnostic missing 'exceeds cap'"
else
  ok "over-cap window exits 1 with diagnostic"
fi

# ── (11) unreachable RPC port → exit 1 (fast, never blocks) ──────────────────
# Port 1 is unreachable; the supply RPC fails immediately → exit 1. This is
# the single "live" probe and it returns at once (no daemon, no polling).
echo "=== (11) unreachable RPC port exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 1 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "unreachable RPC should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -qE "RPC error|daemon"; then
  fail "unreachable RPC diagnostic missing 'RPC error' or 'daemon'"
else
  ok "unreachable RPC exits 1 with diagnostic"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "  PASS: tools/operator_slashing_ledger.sh smoke test ($CHECKS checks)"
  exit 0
else
  echo "  FAIL: tools/operator_slashing_ledger.sh smoke test ($FAIL_COUNT/$CHECKS checks failed)"
  exit 1
fi
