#!/usr/bin/env bash
# determ-wallet shamir-verify --threshold non-integer EDGE test.
#
# EDGE UNDER TEST
# ---------------
# `shamir-verify` PARSED its optional --threshold argument with a bare
# std::stoi(argv[++i]) and — unlike its sibling `shamir-rotate`, which
# wraps the same call in try/catch and returns a clean exit 1 — had NO
# exception guard (wallet/main.cpp cmd_shamir_verify, the `--threshold`
# branch).
#
# A --threshold value whose FIRST character is non-numeric (e.g. "abc",
# or an empty string) made std::stoi throw std::invalid_argument, which
# propagated out of main uncaught -> std::terminate -> the process ABORTED
# (a fail-open crash on the operator's share-set sanity gate; on this
# Windows/Git-Bash box the abort surfaced as a non-zero, non-1 shell
# status (127) with no diagnostic on stderr).
#
# FIXED in this round: cmd_shamir_verify's --threshold parse now mirrors
# shamir-rotate (try/catch -> "shamir-verify: --threshold must be an
# integer" on stderr + a clean exit 1). This test guards BOTH the original
# fail-closed contract (never a silent success on an unparseable threshold)
# AND the specific clean-rejection behavior the fix introduced.
#
# Why this matters: shamir-verify is the operator's PRE-DISTRIBUTION /
# PRE-RECONSTRUCTION sanity gate for a Shamir share-set. A scripted
# operator harness that fat-fingers the threshold (or sources it from an
# unvalidated config field) gets an opaque crash instead of a clean,
# diagnosable rejection. The fail-closed contract we assert is the
# minimal correct behavior: the tool must NOT silently report success
# (exit 0 + the "[OK] ... sufficient for reconstruction" line) on a
# threshold value it could not actually parse.
#
# This is DISTINCT from existing coverage:
#   * test_wallet_shamir_rotate.sh #31 covers non-integer --threshold for
#     shamir-ROTATE (which is guarded; clean exit 1). shamir-verify is a
#     SEPARATE code path with no guard.
#   * test_wallet_shamir_verify.sh exercises --threshold only with
#     integer values (3, 99, 2) — never a non-parseable one.
#
# ASSERTIONS
#   1. Control (happy path): --threshold <integer> on a valid share-set
#      exits 0 AND prints the "sufficient for reconstruction" success
#      line — proves the verify path itself works and is reached.
#   2. Edge: --threshold abc (leading non-numeric) does NOT exit 0
#      (fail-closed: the tool must not treat an unparseable threshold as
#      satisfied).
#   3. Edge: --threshold abc does NOT print the success/[OK]-sufficient
#      line (no silent acceptance of an unparseable threshold). This is
#      the layer-distinctness check: the success line appears ONLY in the
#      control, never in the edge case.
#   4. Edge: empty --threshold "" likewise does NOT exit 0 (same
#      std::stoi-throws class, second representative).
#
# The test drives the REAL determ-wallet binary; it does not reimplement
# Shamir, std::stoi, or any parsing oracle. It asserts only on the
# binary's observable exit status and stdout/stderr.
#
# Run from repo root: bash tools/test_wallet_shamir_verify_threshold_noninteger_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (both values: $1)"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in: $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

# ── Build a structurally valid 2-of-4 share-set ───────────────────────────
SECRET="deadbeefcafe0011"
"$WALLET" shamir-split --secret "$SECRET" --threshold 2 --shares 4 --json \
    > "$TMP/valid.json"
if [ ! -s "$TMP/valid.json" ]; then
    echo "  FAIL: shamir-split produced empty output (cannot set up test)"
    exit 1
fi

# ── 1. Control: valid integer --threshold → exit 0 + success line ─────────
echo "=== 1. Control: integer --threshold parses, verify succeeds ==="
set +e
CTRL=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold 2 2>&1)
CTRL_RC=$?
set -e
CTRL=$(echo "$CTRL" | tr -d '\r')
assert_eq "$CTRL_RC" "0" "integer --threshold 2 exits 0"
assert_contains "$CTRL" "sufficient for reconstruction" \
  "integer threshold prints success/[OK]-sufficient line (path is reached)"

# ── 2. Edge: leading non-numeric --threshold must NOT exit 0 ──────────────
# std::stoi("abc") throws std::invalid_argument; shamir-verify has no
# try/catch here, so the process aborts (RC 127 on this box). The
# fail-closed contract: whatever the failure mode, it must NOT be a clean
# success exit.
echo
echo "=== 2. Edge: --threshold abc (leading non-numeric) is NOT a success ==="
set +e
EDGE=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold abc 2>&1)
EDGE_RC=$?
set -e
EDGE=$(echo "$EDGE" | tr -d '\r')
assert_neq "$EDGE_RC" "0" \
  "non-integer --threshold abc does NOT exit 0 (fail-closed)"
# Post-fix regression guards: the fix makes this a CLEAN exit 1 + diagnostic,
# not an abort. These lock in the fix (a reversion to the unguarded crash, or
# removal of the diagnostic, turns them RED).
assert_eq "$EDGE_RC" "1" \
  "non-integer --threshold exits cleanly with 1 (fix: guarded, not an abort/127)"
assert_contains "$EDGE" "must be an integer" \
  "non-integer --threshold prints the clean 'must be an integer' diagnostic (fix)"

# ── 3. Edge: the success line must NOT appear (no silent acceptance) ──────
# Layer-distinctness: "sufficient for reconstruction" appears in the
# control (step 1) but must be ABSENT here. If a future fix routes this to
# a clean exit-1 diagnostic, this assertion still holds; if the guard were
# (wrongly) removed and the value coerced to e.g. 0, this catches the
# silent acceptance.
echo
echo "=== 3. Edge: --threshold abc prints no success/sufficient line ==="
assert_not_contains "$EDGE" "sufficient for reconstruction" \
  "unparseable threshold does NOT print the success/[OK]-sufficient line"

# ── 4. Edge: empty --threshold "" likewise not a success ──────────────────
# Second representative of the same std::stoi-throws class (empty string).
echo
echo "=== 4. Edge: empty --threshold \"\" is NOT a success ==="
set +e
EMPTY=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold "" 2>&1)
EMPTY_RC=$?
set -e
EMPTY=$(echo "$EMPTY" | tr -d '\r')
assert_neq "$EMPTY_RC" "0" \
  "empty --threshold does NOT exit 0 (fail-closed)"
assert_not_contains "$EMPTY" "sufficient for reconstruction" \
  "empty threshold does NOT print the success/[OK]-sufficient line"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet shamir-verify --threshold non-integer edge"
    exit 0
else
    echo "  FAIL"
    exit 1
fi
