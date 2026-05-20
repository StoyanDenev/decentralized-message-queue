#!/usr/bin/env bash
# determ-wallet shamir-verify structural verification CLI test.
#
# Verifies the diagnostic that checks a Shamir share-set file for
# structural well-formedness WITHOUT reconstructing the secret. Useful
# for operators distributing physical shares: pre-distribution sanity
# check; pre-reconstruction validation before paying the cost of a
# T-of-N combine (which may need T-1 other shares hand-delivered).
#
# Assertions:
#   1. Help line mentions shamir-verify.
#   2. Valid share-set passes (human + JSON modes) and exit 0.
#   3. --threshold T with sufficient count → [OK] line + exit 0.
#   4. --threshold T with insufficient count → [INFO] line + exit 0
#      (informational; not a structural defect).
#   5. Truncated share-set (fewer shares) still PASSES structurally —
#      we don't enforce a minimum count beyond non-empty.
#   6. Duplicate x → exit 2 + [FAIL] distinct-x diagnostic.
#   7. Length-mismatched y_hex → exit 2 + [FAIL] length-consistency.
#   8. x out of [1, 255] (x=0, x=256) → exit 2 + [FAIL] range diag.
#   9. Odd-length y_hex → exit 2.
#  10. Non-hex character in y_hex → exit 2.
#  11. Missing 'x' field → exit 2.
#  12. Missing 'y_hex' field → exit 2.
#  13. Missing --shares file → exit 1.
#  14. Malformed JSON → exit 1.
#  15. Empty shares array → exit 2.
#  16. Top-level not an object → exit 2.
#  17. --json output parseable by python and has expected schema.
#  18. --json valid case has valid=true, errors=[].
#  19. --json invalid case has valid=false, non-empty errors.
#  20. NEVER outputs secret material (no "secret_hex" key in --json).
#
# Run from repo root: bash tools/test_wallet_shamir_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch directory so concurrent runs don't collide.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}
# Run the given command; assert it exits with the given code.
assert_exit_code() {
  set +e
  bash -c "$1" >/dev/null 2>&1
  rc=$?
  set -e 2>/dev/null || true
  if [ "$rc" = "$2" ]; then
    echo "  PASS: $3 (rc=$rc)"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3 (expected rc=$2, got rc=$rc)"; fail_count=$((fail_count + 1))
  fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions shamir-verify ==="
H=$("$WALLET" help 2>&1)
echo "$H" | grep -q "shamir-verify" && {
  echo "  PASS: help mentions shamir-verify"; pass_count=$((pass_count + 1)); } || {
  echo "  FAIL: help missing shamir-verify"; fail_count=$((fail_count + 1)); }

echo
echo "=== Setup: produce a valid share-set via shamir-split ==="
SECRET="deadbeefcafebabe0011223344556677"
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
    > "$TMP/valid.json"
if [ ! -s "$TMP/valid.json" ]; then
    echo "  FAIL: shamir-split produced empty output"; exit 1
fi
echo "  wrote $TMP/valid.json"

echo
echo "=== 2. Valid share-set passes (human mode) ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.json" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 on valid share-set"
assert_contains "$OUT" "Shares present: 5"            "reports 5 shares"
assert_contains "$OUT" "Distinct x values: 5"          "reports 5 distinct x values"
assert_contains "$OUT" "range: 1..5"                   "reports x range 1..5"
assert_contains "$OUT" "y_hex byte-length: 16 bytes"   "reports y byte length"
assert_contains "$OUT" "\[OK\] Structural verification passed" "reports OK"

echo
echo "=== 3. --threshold met → [OK] line ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold 3 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 when threshold met"
assert_contains "$OUT" "\[OK\] Share count (5) >= threshold (3)" "OK on threshold met"

echo
echo "=== 4. --threshold > share count → [INFO] line, still exit 0 ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold 99 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 even when threshold > count (informational)"
assert_contains "$OUT" "\[INFO\] Share count (5) < threshold (99)" "INFO on insufficient count"

echo
echo "=== 5. Truncated share-set (drop 2 shares) still passes structurally ==="
# Take only the first 3 shares — structurally valid; below threshold purely
# informational. shamir-verify must NOT fail just because count < threshold.
$PY - "$TMP/valid.json" "$TMP/truncated.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["shares"] = d["shares"][:3]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
OUT=$("$WALLET" shamir-verify --shares "$TMP/truncated.json" --threshold 3 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "truncated set (3 shares) still passes"
assert_contains "$OUT" "Shares present: 3" "reports 3 shares"
assert_contains "$OUT" "\[OK\] Share count (3) >= threshold (3)" "threshold of 3 met by 3 shares"

# Also test 2 shares with threshold 3 — info but exit 0.
$PY - "$TMP/valid.json" "$TMP/two_shares.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["shares"] = d["shares"][:2]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
OUT=$("$WALLET" shamir-verify --shares "$TMP/two_shares.json" --threshold 3 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "2 shares with threshold=3 (structurally valid, informational)"
assert_contains "$OUT" "\[INFO\]" "INFO line reported for under-threshold"

echo
echo "=== 6. Duplicate x → exit 2, distinct-x diagnostic ==="
$PY - "$TMP/valid.json" "$TMP/dup_x.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Set 2nd share's x to match the 1st — Shamir invariant violation.
d["shares"][1]["x"] = d["shares"][0]["x"]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/dup_x.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on duplicate x"
assert_contains "$ERR" "\[FAIL\]" "[FAIL] marker on duplicate x"
assert_contains "$ERR" "duplicate" "diagnostic mentions duplicate"

echo
echo "=== 7. Length-mismatched y_hex → exit 2, length-consistency diagnostic ==="
$PY - "$TMP/valid.json" "$TMP/len_mismatch.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Truncate one share's y_hex to a different (shorter, but still even) length.
y = d["shares"][2]["y_hex"]
d["shares"][2]["y_hex"] = y[:6]   # 3 bytes; rest are 16 bytes
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/len_mismatch.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on length mismatch"
assert_contains "$ERR" "\[FAIL\]" "[FAIL] marker on length mismatch"
assert_contains "$ERR" "differs" "diagnostic mentions length difference"

echo
echo "=== 8. x out of [1, 255] ==="
# 8a. x = 0
cat > "$TMP/x_zero.json" <<'EOF'
{"shares":[{"x":0,"y_hex":"aabb"},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/x_zero.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on x=0"
assert_contains "$ERR" "out of range" "diagnostic mentions out of range (x=0)"

# 8b. x = 256
cat > "$TMP/x_too_big.json" <<'EOF'
{"shares":[{"x":256,"y_hex":"aabb"},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/x_too_big.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on x=256"
assert_contains "$ERR" "out of range" "diagnostic mentions out of range (x=256)"

echo
echo "=== 9. Odd-length y_hex → exit 2 ==="
cat > "$TMP/odd_y.json" <<'EOF'
{"shares":[{"x":1,"y_hex":"aab"},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/odd_y.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on odd-length y_hex"
assert_contains "$ERR" "odd length" "diagnostic mentions odd length"

echo
echo "=== 10. Non-hex character in y_hex → exit 2 ==="
cat > "$TMP/non_hex.json" <<'EOF'
{"shares":[{"x":1,"y_hex":"aabz"},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/non_hex.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on non-hex character"
assert_contains "$ERR" "non-hex" "diagnostic mentions non-hex"

echo
echo "=== 11. Missing 'x' field → exit 2 ==="
cat > "$TMP/no_x.json" <<'EOF'
{"shares":[{"y_hex":"aabb"},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
"$WALLET" shamir-verify --shares "$TMP/no_x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "exit 2 on missing 'x' field"

echo
echo "=== 12. Missing 'y_hex' field → exit 2 ==="
cat > "$TMP/no_y.json" <<'EOF'
{"shares":[{"x":1},{"x":2,"y_hex":"ccdd"}]}
EOF
set +e
"$WALLET" shamir-verify --shares "$TMP/no_y.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "exit 2 on missing 'y_hex' field"

echo
echo "=== 13. Missing --shares file → exit 1 ==="
set +e
"$WALLET" shamir-verify --shares "$TMP/does_not_exist.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing file"

echo
echo "=== 14. Malformed JSON → exit 1 ==="
echo "not json at all {{{" > "$TMP/malformed.json"
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/malformed.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed JSON"
assert_contains "$ERR" "JSON parse" "diagnostic mentions JSON parse"

echo
echo "=== 15. Empty shares array → exit 2 ==="
echo '{"shares":[]}' > "$TMP/empty.json"
set +e
ERR=$("$WALLET" shamir-verify --shares "$TMP/empty.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on empty shares array"
assert_contains "$ERR" "empty" "diagnostic mentions empty"

echo
echo "=== 16. Top-level not an object → exit 2 ==="
echo '[1,2,3]' > "$TMP/array.json"
set +e
"$WALLET" shamir-verify --shares "$TMP/array.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "exit 2 on top-level array"

echo
echo "=== 17. --json output parseable by python ==="
JSON=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --json | tr -d '\r')
echo "$JSON" | $PY -c "import sys, json; json.loads(sys.stdin.read())" 2>/dev/null
if [ $? = 0 ]; then
    echo "  PASS: --json output is well-formed (json.loads)"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json output is not valid JSON"
    fail_count=$((fail_count + 1))
fi
# Schema check.
$PY - <<PY_EOF
import json
d = json.loads('''$JSON''')
required = {"valid","share_count","distinct_x","x_range","y_byte_length","consistent_lengths","threshold_satisfied","errors"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["valid"] is True
assert d["share_count"] == 5
assert d["distinct_x"] == 5
assert d["x_range"] == [1,5]
assert d["y_byte_length"] == 16
assert d["consistent_lengths"] is True
assert d["threshold_satisfied"] is None  # not supplied
assert d["errors"] == []
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema matches spec"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema doesn't match spec"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== 18. --json with threshold met → threshold_satisfied=true ==="
JSON=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --threshold 3 --json | tr -d '\r')
$PY -c "import json,sys; d=json.loads('''$JSON'''); assert d['threshold_satisfied'] is True; assert d['valid'] is True"
if [ $? = 0 ]; then
    echo "  PASS: threshold_satisfied=true when count >= threshold"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: threshold_satisfied tri-state mishandled"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== 19. --json on invalid input → valid=false + non-empty errors ==="
JSON=$("$WALLET" shamir-verify --shares "$TMP/dup_x.json" --json 2>&1 | tr -d '\r')
# Even on exit 2, the JSON line should be emitted to stdout.
$PY -c "import json,sys; d=json.loads('''$JSON'''); assert d['valid'] is False; assert len(d['errors']) > 0"
if [ $? = 0 ]; then
    echo "  PASS: --json invalid case has valid=false + non-empty errors"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json invalid case malformed"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== 20. NEVER outputs secret material ==="
# The whole point of shamir-verify is to NOT reconstruct. The output must
# not contain "secret_hex" (that's what shamir-combine emits) or any
# reconstructed value. Belt-and-suspenders regression check.
JSON=$("$WALLET" shamir-verify --shares "$TMP/valid.json" --json | tr -d '\r')
assert_not_contains "$JSON" "secret_hex" "no secret_hex in --json output"
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.json" | tr -d '\r')
assert_not_contains "$OUT" "secret_hex" "no secret_hex in human output"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet shamir-verify"; exit 0
else
    echo "  FAIL"; exit 1
fi
