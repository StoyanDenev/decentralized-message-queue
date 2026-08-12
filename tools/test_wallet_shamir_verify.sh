#!/usr/bin/env bash
# determ-wallet shamir-verify — structural verification of a DSS1 share-set.
#
# D2 REWRITE: the at-rest share-set is the canonical binary DSS1 container
# ("DSS1" || count u8 || y_len u32 LE || count x {x u8 || y}; x DISTINCT in
# [1,255]; exact total length). shamir-verify decodes it WITHOUT
# reconstructing the secret and reports share_count / distinct_x / x_range
# / y_byte_length. The old JSON share-file shape is deleted.
#
# Coverage:
#   1.  Help mentions shamir-verify.
#   2.  Valid share-set passes (human mode) with correct metadata.
#   3.  --threshold met → [OK] line, exit 0.
#   4.  --threshold > count → [INFO] line, still exit 0 (informational).
#   5.  Structurally-valid subset still passes.
#   6.  Duplicate x → exit 2 (decoder DISTINCT-x).
#   7.  x = 0 → exit 2.
#   8.  Truncated container → exit 2 (exact-length, short direction).
#   9.  Trailing byte → exit 2 (exact-length, long direction).
#  10.  count=0 → exit 2.
#  11.  y_len=0 → exit 2.
#  12.  Wrong magic → exit 2.
#  13.  Legacy JSON share file → exit 2 (deleted format).
#  14.  Missing file → exit 1.
#  15.  --threshold non-integer → exit 1.
#  16.  --json valid case: parseable, valid=true, errors=[], schema fields.
#  17.  --json invalid case: valid=false, non-empty errors.
#  18.  --json output NEVER contains secret material (no y bytes leaked).
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

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3

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
verify_rc() {  # verify_rc <file> [extra args...] -> echoes exit code
  local f="$1"; shift
  set +e
  "$WALLET" shamir-verify --shares "$f" "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

echo "=== 1. Help text mentions shamir-verify ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
case "$H" in
  *shamir-verify*) echo "  PASS: help mentions shamir-verify"; pass_count=$((pass_count + 1)) ;;
  *) echo "  FAIL: help missing shamir-verify"; fail_count=$((fail_count + 1)) ;;
esac

echo
echo "=== Setup: produce a valid DSS1 share-set via shamir-split --out ==="
SECRET="deadbeefcafebabe0011223344556677"
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 \
    --out "$TMP/valid.dss1" >/dev/null
if [ ! -s "$TMP/valid.dss1" ]; then
    echo "  FAIL: shamir-split produced empty output"; exit 1
fi
echo "  wrote $TMP/valid.dss1"

echo
echo "=== 2. Valid share-set passes (human mode) ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.dss1" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 on valid share-set"
assert_contains "$OUT" "Shares present: 5"            "reports 5 shares"
assert_contains "$OUT" "Distinct x values: 5"          "reports 5 distinct x values"
assert_contains "$OUT" "range: 1..5"                   "reports x range 1..5"
assert_contains "$OUT" "y_hex byte-length: 16"         "reports y byte length"
assert_contains "$OUT" "\[OK\] Structural verification passed" "reports OK"

echo
echo "=== 3. --threshold met → [OK] line ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.dss1" --threshold 3 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 when threshold met"
assert_contains "$OUT" "\[OK\] Share count (5) >= threshold (3)" "OK on threshold met"

echo
echo "=== 4. --threshold > share count → [INFO] line, still exit 0 ==="
OUT=$("$WALLET" shamir-verify --shares "$TMP/valid.dss1" --threshold 99 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 even when threshold > count (informational)"
assert_contains "$OUT" "\[INFO\] Share count (5) < threshold (99)" "INFO on insufficient count"

echo
echo "=== 5. Structurally-valid 3-share subset still passes ==="
$PY - "$TMP/valid.dss1" "$TMP/subset.dss1" <<'PY_EOF'
import sys
d = open(sys.argv[1], "rb").read()
assert d[:4] == b"DSS1"
y_len = int.from_bytes(d[5:9], "little")
recs = []
off = 9
for _ in range(d[4]):
    recs.append(d[off:off + 1 + y_len]); off += 1 + y_len
out = b"DSS1" + bytes([3]) + y_len.to_bytes(4, "little") + b"".join(recs[:3])
open(sys.argv[2], "wb").write(out)
PY_EOF
assert_eq "$(verify_rc "$TMP/subset.dss1")" "0" "3-share subset passes structurally"

echo
echo "=== 6. Duplicate x → exit 2 ==="
$PY - "$TMP/valid.dss1" "$TMP/dupx.dss1" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
y_len = int.from_bytes(d[5:9], "little")
d[9 + (1 + y_len)] = d[9]           # record 2's x := record 1's x
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(verify_rc "$TMP/dupx.dss1")" "2" "duplicate x rejected (exit 2)"

echo
echo "=== 7. x = 0 → exit 2 ==="
$PY - "$TMP/valid.dss1" "$TMP/xzero.dss1" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
d[9] = 0
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(verify_rc "$TMP/xzero.dss1")" "2" "x=0 rejected (exit 2)"

echo
echo "=== 8. Truncated container → exit 2 ==="
SZ=$(wc -c < "$TMP/valid.dss1" | tr -d ' ')
head -c $((SZ - 1)) "$TMP/valid.dss1" > "$TMP/trunc.dss1"
assert_eq "$(verify_rc "$TMP/trunc.dss1")" "2" "truncated container rejected (exit 2)"

echo
echo "=== 9. Trailing byte → exit 2 ==="
cp "$TMP/valid.dss1" "$TMP/long.dss1"; printf '\x00' >> "$TMP/long.dss1"
assert_eq "$(verify_rc "$TMP/long.dss1")" "2" "trailing byte rejected (exit 2)"

echo
echo "=== 10. count=0 → exit 2 ==="
printf 'DSS1\x00\x10\x00\x00\x00' > "$TMP/zero.dss1"
assert_eq "$(verify_rc "$TMP/zero.dss1")" "2" "count=0 rejected (exit 2)"

echo
echo "=== 11. y_len=0 → exit 2 ==="
printf 'DSS1\x01\x00\x00\x00\x00\x01' > "$TMP/ylen0.dss1"
assert_eq "$(verify_rc "$TMP/ylen0.dss1")" "2" "y_len=0 rejected (exit 2)"

echo
echo "=== 12. Wrong magic → exit 2 ==="
$PY - "$TMP/valid.dss1" "$TMP/magic.dss1" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
d[0:4] = b"XSS1"
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(verify_rc "$TMP/magic.dss1")" "2" "wrong magic rejected (exit 2)"

echo
echo "=== 13. Legacy JSON share file → exit 2 (deleted format) ==="
printf '{"shares":[{"x":1,"y_hex":"aabb"},{"x":2,"y_hex":"ccdd"}]}\n' > "$TMP/legacy.json"
assert_eq "$(verify_rc "$TMP/legacy.json")" "2" "legacy JSON share file rejected (exit 2)"

echo
echo "=== 14. Missing file → exit 1 ==="
assert_eq "$(verify_rc "$TMP/does_not_exist.dss1")" "1" "missing file exits 1"

echo
echo "=== 15. --threshold non-integer → exit 1 ==="
assert_eq "$(verify_rc "$TMP/valid.dss1" --threshold abc)" "1" "non-integer --threshold exits 1"

echo
echo "=== 16. --json valid case: schema + valid=true ==="
JSON=$("$WALLET" shamir-verify --shares "$TMP/valid.dss1" --threshold 3 --json | tr -d '\r')
echo "$JSON" | $PY -c '
import json, sys
d = json.loads(sys.stdin.read())
assert d["valid"] is True
assert d["share_count"] == 5
assert d["distinct_x"] == 5
assert d["x_range"] == [1, 5]
assert d["y_byte_length"] == 16
assert d["consistent_lengths"] is True
assert d["threshold_satisfied"] is True
assert d["errors"] == []
'
if [ $? = 0 ]; then
  echo "  PASS: --json valid schema correct"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: --json valid schema wrong"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 17. --json invalid case: valid=false, non-empty errors ==="
set +e
BAD_JSON=$("$WALLET" shamir-verify --shares "$TMP/magic.dss1" --json 2>/dev/null | tr -d '\r')
set -e
echo "$BAD_JSON" | $PY -c '
import json, sys
d = json.loads(sys.stdin.read())
assert d["valid"] is False
assert len(d["errors"]) >= 1
'
if [ $? = 0 ]; then
  echo "  PASS: --json invalid schema correct"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: --json invalid schema wrong"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 18. --json NEVER leaks share y bytes ==="
Y0_HEX=$($PY -c "
d = open('$TMP/valid.dss1','rb').read()
y_len = int.from_bytes(d[5:9], 'little')
print(d[10:10+y_len].hex())")
case "$JSON" in
  *"$Y0_HEX"*) echo "  FAIL: --json output leaks share y bytes"; fail_count=$((fail_count + 1)) ;;
  *) echo "  PASS: --json output does not leak share y bytes"; pass_count=$((pass_count + 1)) ;;
esac

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet shamir-verify"; exit 0
else
    echo "  FAIL: test_wallet_shamir_verify"; exit 1
fi
