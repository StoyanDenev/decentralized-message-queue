#!/usr/bin/env bash
# determ-wallet batch-nonce-assign — u64 NONCE-OVERFLOW boundary edge test.
#
# WHY THIS EXISTS (non-duplication):
#   tools/test_wallet_batch_nonce_assign.sh is the comprehensive functional
#   test (empty array, --start 0/7/100, field preservation, determinism,
#   --force overwrite, non-array / non-object / malformed-JSON / 12abc-junk
#   rejection). It NEVER drives the --start value anywhere near UINT64_MAX,
#   so the command's explicit overflow guard
#
#       const uint64_t last_index = N - 1;
#       if (start > UINT64_MAX - last_index) { ...overflows... return 1; }
#
#   (wallet/main.cpp cmd_batch_nonce_assign, "Overflow guard" block) and the
#   std::stoull out-of-range path ("--start out of range for a 64-bit nonce")
#   are entirely UNCOVERED. grep confirms no wallet test references UINT64,
#   18446744073709551615, "overflows", or the stoull range message:
#       grep -l 'overflow\|UINT64\|18446744' tools/test_wallet_*.sh   # → none
#
#   That guard is load-bearing: nonces are u64 on-chain; a pathological
#   --start near the ceiling with a multi-record batch would otherwise WRAP
#   each record's nonce to a tiny value (e.g. start=MAX-1 with 3 records →
#   MAX-1, MAX, 0) and silently emit replayable / colliding nonces. This
#   test pins the boundary BYTE-FOR-BYTE against the REAL determ-wallet
#   binary so a regression that drops the guard (re-introducing the wrap)
#   turns this RED.
#
# Boundary cases asserted (all against the live binary, no oracle re-impl):
#   A. start = UINT64_MAX, 3 records         → start+2 wraps → REJECT (exit 1),
#                                               diagnostic mentions overflow.
#   B. start = UINT64_MAX-2, 3 records        → EXACT FIT, last nonce == MAX
#                                               → ACCEPT (exit 0); guard must
#                                               NOT off-by-one-reject the fit.
#   C. start = UINT64_MAX-1, 3 records        → overflows by exactly 1 →
#                                               REJECT (exit 1).
#   D. start = UINT64_MAX, EMPTY array        → N==0, guard inert (no last
#                                               index) → ACCEPT (exit 0), 0 recs.
#   E. start = UINT64_MAX, 1 record           → last_index 0, exact fit,
#                                               nonce == MAX → ACCEPT (exit 0).
#   F. start = UINT64_MAX+1 (10^... overflows u64 itself) → stoull out-of-range
#                                               → REJECT (exit 1), distinct
#                                               diagnostic ("out of range").
#
# Pure data transform: no keyfile, no daemon, no network, no crypto. The
# only external dependency is the wallet binary itself. JSON fixtures are
# built with printf (no heredocs — avoids the unterminated-heredoc class of
# breaks) and parsed with grep, so no python is required.
#
# Run from repo root:  bash tools/test_wallet_batch_nonce_assign_overflow_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

TMP="build/test_wallet_batch_nonce_assign_overflow_edge.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if printf '%s' "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

# u64 boundary constants.
MAX=18446744073709551615        # UINT64_MAX
MAX_M1=18446744073709551614     # MAX - 1
MAX_M2=18446744073709551613     # MAX - 2
OVER=18446744073709551616       # MAX + 1 (overflows u64 itself)

# A single canonical TRANSFER record (no nonce — the command assigns it).
REC='{"type":"TRANSFER","from":"a","to":"b","amount":1,"fee":0}'

# Build fixtures with printf (no heredocs).
printf '[%s,%s,%s]\n' "$REC" "$REC" "$REC" > "$TMP/three.json"
printf '[%s]\n'        "$REC"               > "$TMP/one.json"
printf '[]\n'                               > "$TMP/empty.json"

# run <start> <in> <out> : invokes the binary in the MAIN shell (not a
# subshell) so the captured exit code + stderr stay visible. Sets globals
# RC (exit code) and LAST_ERR (stderr text). stdout is discarded.
RC=""
LAST_ERR=""
run() {
  set +e
  "$WALLET" batch-nonce-assign --in "$2" --start "$1" --out "$3" \
      >/dev/null 2>"$TMP/stderr.txt"
  RC=$?
  set -e
  LAST_ERR=$(cat "$TMP/stderr.txt")
}

# Extract the comma-joined nonce list from an output array WITHOUT python:
# grep every "nonce":<digits> occurrence in document order.
nonces_of() {  # nonces_of <file>  → e.g. "18446744073709551613,18446744073709551614,18446744073709551615"
  grep -o '"nonce":[0-9]*' "$1" | sed 's/"nonce"://' | paste -sd, -
}

echo "=== A. start = UINT64_MAX with 3 records → overflow REJECTED ==="
run "$MAX" "$TMP/three.json" "$TMP/oA.json"
assert_eq "$RC" "1" "start=MAX, 3 records: exit 1 (start+2 wraps)"
assert_contains "$LAST_ERR" "overflow" "diagnostic mentions overflow"
if [ -f "$TMP/oA.json" ]; then
  echo "  FAIL: rejected run must NOT have written --out"; fail_count=$((fail_count + 1))
else
  echo "  PASS: rejected run wrote no --out file"; pass_count=$((pass_count + 1))
fi

echo
echo "=== B. start = UINT64_MAX-2 with 3 records → EXACT FIT, accepted ==="
run "$MAX_M2" "$TMP/three.json" "$TMP/oB.json"
assert_eq "$RC" "0" "start=MAX-2, 3 records: exit 0 (exact fit; guard must not off-by-one)"
NB=$(nonces_of "$TMP/oB.json")
assert_eq "$NB" "$MAX_M2,$MAX_M1,$MAX" "nonces are MAX-2, MAX-1, MAX (last == UINT64_MAX exactly)"

echo
echo "=== C. start = UINT64_MAX-1 with 3 records → overflows by 1, REJECTED ==="
run "$MAX_M1" "$TMP/three.json" "$TMP/oC.json"
assert_eq "$RC" "1" "start=MAX-1, 3 records: exit 1 (start+2 overflows by 1)"
assert_contains "$LAST_ERR" "overflow" "diagnostic mentions overflow"

echo
echo "=== D. start = UINT64_MAX with EMPTY array → guard inert, accepted ==="
run "$MAX" "$TMP/empty.json" "$TMP/oD.json"
assert_eq "$RC" "0" "start=MAX, empty array: exit 0 (N==0, no last index to overflow)"
# Output must be an empty JSON array (no nonce fields).
ND=$(nonces_of "$TMP/oD.json")
assert_eq "$ND" "" "empty input → no nonce fields in output"

echo
echo "=== E. start = UINT64_MAX with single record → exact fit, accepted ==="
run "$MAX" "$TMP/one.json" "$TMP/oE.json"
assert_eq "$RC" "0" "start=MAX, 1 record: exit 0 (last_index 0, exact fit)"
NE=$(nonces_of "$TMP/oE.json")
assert_eq "$NE" "$MAX" "single-record nonce is exactly UINT64_MAX"

echo
echo "=== F. start = UINT64_MAX+1 → stoull out-of-range, REJECTED ==="
run "$OVER" "$TMP/three.json" "$TMP/oF.json"
assert_eq "$RC" "1" "start=MAX+1: exit 1 (value itself out of u64 range)"
assert_contains "$LAST_ERR" "out of range" "diagnostic mentions out-of-range (distinct from the add-overflow path)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet batch-nonce-assign overflow edge"; exit 0
else
    echo "  FAIL"; exit 1
fi
