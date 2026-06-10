#!/usr/bin/env bash
# test_light_wait_flag.sh — the OPT-IN --wait <seconds> hold-and-wait flag on the
# determ-light trustless readers (the S-042 head-read fix).
#
# BACKGROUND
# ----------
# S-042 bound state_root to committee sigs by requiring a committee-signed SUCCESSOR
# of the anchor block (the head's state_root is NOT in the signed digest). But the
# daemon's state_proof always serves the CURRENT head, whose successor does not exist
# yet — so the trustless readers fail closed on every current-head read. The fix:
# `committee_bound_state_root(..., max_wait_seconds)` polls for the next block, then
# binds the ALREADY-HELD proof (never re-fetching, which would race a state change).
# Exposed as an OPT-IN `--wait <seconds>` flag on EVERY head-anchored composite —
# the trustless readers PLUS verify-and-submit (embedded nonce read) and
# verify-unstake-eligibility (embedded stake read); default 0 = behaviour
# unchanged (head case fails closed immediately, exactly as before S-042's caveat).
#
# WHAT RUNS HERE (offline, no cluster) vs CI
# ------------------------------------------
#   * OFFLINE (always): the flag exists in help, a bad value is rejected cleanly, and
#     --wait does NOT change the no-daemon failure mode (it only affects the live
#     head-successor case). These pin the flag's contract without a daemon.
#   * CI/WSL2 (cluster): the actual hold-and-wait SUCCESS leg — read the current head
#     balance with --wait N, block for the next block, then bind + report VERIFIED.
#     That needs a live, advancing chain and is documented + SKIPPED here, not faked.
#
# Run from repo root: bash tools/test_light_wait_flag.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

pass=0; fail=0; skip=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
no()   { echo "  FAIL: $1"; fail=$((fail+1)); }
skp()  { echo "  SKIP: $1"; skip=$((skip+1)); }

# ── 1. help lists --wait for the head-anchored readers ──────────────────────────
echo "=== 1. help advertises --wait on the trustless readers ==="
HELP=$($DETERM_LIGHT help 2>&1)
n_wait=$(printf '%s\n' "$HELP" | grep -c -- "--wait")
if [ "$n_wait" -ge 10 ]; then ok "help lists --wait on the readers ($n_wait lines)"
else no "help should list --wait on ~12 readers (got $n_wait)"; fi
# spot-check two representative commands carry it. The usage is multi-line (the
# command on one line, flags incl. [--wait <seconds>] continuing on the next 1-2
# lines), so scan a small window AFTER the command name, not just its own line.
printf '%s\n' "$HELP" | grep -A2 -E "^[[:space:]]*balance-trustless" | grep -q -- "--wait" \
    && ok "balance-trustless usage shows --wait" || no "balance-trustless usage missing --wait"
printf '%s\n' "$HELP" | grep -A2 -E "^[[:space:]]*verify-state-root" | grep -q -- "--wait" \
    && ok "verify-state-root usage shows --wait" || no "verify-state-root usage missing --wait"

# ── 2. a bad --wait value is rejected cleanly (no crash) ─────────────────────────
echo
echo "=== 2. --wait rejects a non-numeric value ==="
set +e
OUT=$($DETERM_LIGHT balance-trustless --rpc-port 59999 --genesis /no/such/genesis.json \
        --domain alice --wait abc 2>&1)
RC=$?
set -e
echo "    $OUT" | head -1
# parse_u64 throws "--wait must be a non-negative integer"; caught by main()'s
# top-level handler (exit 2), same as a bad --rpc-port. Accept any non-zero exit +
# the diagnostic naming --wait.
if [ "$RC" != "0" ] && printf '%s' "$OUT" | grep -qiE "wait must be a non-negative integer|--wait"; then
    ok "--wait abc -> clean rejection naming --wait (rc=$RC, no crash)"
else
    no "--wait abc should be rejected naming --wait (rc=$RC)"
fi

# ── 3. --wait does NOT change the no-daemon failure mode ─────────────────────────
echo
echo "=== 3. --wait only affects the live head-successor case (no-daemon = same failure) ==="
# With no daemon listening, the read fails at the chain-anchor step BEFORE the wait
# loop is ever reached, so --wait 2 must fail just like the default (non-zero), NOT
# hang for 2s waiting (the wait loop is past the live chain walk).
set +e
t0=$SECONDS
OUT=$($DETERM_LIGHT balance-trustless --rpc-port 59999 --genesis /no/such/genesis.json \
        --domain alice --wait 2 2>&1)
RC=$?
elapsed=$((SECONDS - t0))
set -e
if [ "$RC" != "0" ] && [ "$elapsed" -lt 2 ]; then
    ok "--wait 2 with no daemon fails fast (rc=$RC, ${elapsed}s < 2s — wait loop not reached pre-connect)"
else
    no "--wait 2 with no daemon should fail fast, not hang (rc=$RC, ${elapsed}s)"
fi

# ── 4. live hold-and-wait SUCCESS leg — CI/WSL2 cluster only ─────────────────────
echo
echo "=== 4. live hold-and-wait success (read head balance, --wait N, bind next block) ==="
skp "live --wait success leg (needs an advancing cluster: read current head with --wait, block for next block, then VERIFIED) — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
if [ "$fail" = "0" ]; then
    echo "  PASS: test_light_wait_flag (offline flag contract; live success leg is a CI leg)"
    exit 0
else
    echo "  FAIL: test_light_wait_flag"
    exit 1
fi
