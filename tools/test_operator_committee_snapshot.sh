#!/usr/bin/env bash
# test_operator_committee_snapshot.sh — smoke test for
# tools/operator_committee_snapshot.sh.
#
# Strategy: lightweight argument-surface verification. Boots no node;
# instead exercises the script's argument parsing + error-path exit codes
# + --help rendering. The actual RPC integration is dynamically tested
# by every operator who runs the script against a live daemon — the
# core algorithm (parse block JSON, count sigs, check duplicates) is
# pure Python that runs in-process on the script's heredoc.
#
# This follows the operator_*-smoke pattern: a cluster-boot driver is
# heavy and brittle (see tools/test_orphan_check_cluster.sh as the
# precedent); the lighter --help / bad-args smoke is sufficient for
# regression-catching script regressions without needing a multi-node
# cluster in CI.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

SCRIPT="tools/operator_committee_snapshot.sh"
FAIL_COUNT=0
fail() { echo "  FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
ok()   { echo "  ok: $1"; }

# ── (1) --help renders and exits 0 ────────────────────────────────────────────
echo "=== (1) --help exits 0 + renders usage ==="
OUT=$(bash "$SCRIPT" --help 2>&1)
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "--help should exit 0 (got $RC)"
elif ! echo "$OUT" | grep -q "Usage: operator_committee_snapshot.sh"; then
  fail "--help output missing 'Usage:' header"
else
  ok "--help works"
fi

# ── (2) -h alias ──────────────────────────────────────────────────────────────
echo "=== (2) -h alias ==="
bash "$SCRIPT" -h > /dev/null 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "-h should exit 0 (got $RC)"
else
  ok "-h alias works"
fi

# ── (3) missing --rpc-port → exit 1 + diagnostic ─────────────────────────────
echo "=== (3) missing --rpc-port exits 1 ==="
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
OUT=$(bash "$SCRIPT" --rpc-port abc 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "non-numeric --rpc-port should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "positive integer"; then
  fail "non-numeric --rpc-port diagnostic missing 'positive integer'"
else
  ok "non-numeric --rpc-port exits 1 with diagnostic"
fi

# ── (5) non-numeric --height → exit 1 ────────────────────────────────────────
echo "=== (5) non-numeric --height exits 1 ==="
OUT=$(bash "$SCRIPT" --rpc-port 8888 --height xyz 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "non-numeric --height should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "unsigned integer"; then
  fail "non-numeric --height diagnostic missing 'unsigned integer'"
else
  ok "non-numeric --height exits 1 with diagnostic"
fi

# ── (6) unknown argument → exit 1 + usage to stderr ──────────────────────────
echo "=== (6) unknown argument exits 1 ==="
OUT=$(bash "$SCRIPT" --bogus 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "unknown argument should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "unknown argument"; then
  fail "unknown argument diagnostic missing"
else
  ok "unknown argument exits 1 with diagnostic"
fi

# ── (7) unreachable RPC port → exit 1 ─────────────────────────────────────────
# Use a high port unlikely to be in use; the daemon-running check should
# fail cleanly with exit 1 (not a python crash or bare bash error).
echo "=== (7) unreachable RPC port exits 1 ==="
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
  echo "  PASS: tools/operator_committee_snapshot.sh smoke test (7 checks)"
  exit 0
else
  echo "  FAIL: tools/operator_committee_snapshot.sh smoke test ($FAIL_COUNT/7 checks failed)"
  exit 1
fi
