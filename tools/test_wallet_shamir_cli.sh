#!/usr/bin/env bash
# Raw-primitive Shamir CLIs: `shamir-split` + `shamir-combine`.
#
# These are operator-facing top-level commands (distinct from the
# pre-existing `shamir {split|combine}` subcommand group that uses the
# colon-separated wire format). The raw CLIs accept flag-style args
# (--secret / --threshold / --shares for split, --shares <file> for
# combine), emit JSON-first output via nlohmann/json, and ship for
# share-distribution workflows that need a clean machine-readable
# transport independent of the recovery envelope.
#
# Assertions:
#   1. Help line shows both new commands.
#   2. Round-trip determinism across multiple secret sizes (16/32/64/1024 B).
#   3. T-of-N completeness: every 3-of-5 subset reconstructs the original
#      (there are C(5,3) = 10 subsets — all checked).
#   4. T-1 insufficiency: 2-share combine produces output != original
#      (information-theoretic property of SSS — combine may "succeed"
#      with garbage; assertion checks output mismatch).
#   5. Validation rejections: T=0, T>N, N>255, duplicate-x in input,
#      length-mismatched shares, missing-field shares, non-hex secret,
#      odd-length-hex secret.
#   6. JSON output is parseable by Python's json.loads (both split + combine).
#   7. Determinism property: same secret split twice produces DIFFERENT
#      share bytes (because SSS uses random polynomial coefficients) but
#      each set still reconstructs the original.
#
# Run from repo root: bash tools/test_wallet_shamir_cli.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

WALLET="$DETERM_WALLET"
if [ -z "$WALLET" ] || [ ! -x "$WALLET" ]; then
  echo "FAIL: cannot locate determ-wallet binary" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then
    echo "  PASS: $3"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"
    echo "       expected: $2"
    echo "       got:      $1"
    fail_count=$((fail_count + 1))
  fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then
    echo "  PASS: $3"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3 (unexpected equality)"
    fail_count=$((fail_count + 1))
  fi
}
assert_nonzero_exit() {
  # Run the given command; assert it exits non-zero.
  set +e
  bash -c "$1" >/dev/null 2>&1
  rc=$?
  set -e 2>/dev/null || true
  if [ "$rc" != "0" ]; then
    echo "  PASS: $2"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $2 (command unexpectedly succeeded)"
    fail_count=$((fail_count + 1))
  fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions both new commands ==="
H=$("$WALLET" help 2>&1)
echo "$H" | grep -q "shamir-split" && {
  echo "  PASS: help mentions shamir-split"; pass_count=$((pass_count + 1)); } || {
  echo "  FAIL: help missing shamir-split"; fail_count=$((fail_count + 1)); }
echo "$H" | grep -q "shamir-combine" && {
  echo "  PASS: help mentions shamir-combine"; pass_count=$((pass_count + 1)); } || {
  echo "  FAIL: help missing shamir-combine"; fail_count=$((fail_count + 1)); }

echo
echo "=== 2. Round-trip across multiple secret sizes ==="
for size in 16 32 64 1024; do
  # Build a hex secret of exactly $size bytes from /dev/urandom.
  SEC=$(head -c "$size" /dev/urandom | od -An -tx1 -v | tr -d ' \n')
  "$WALLET" shamir-split --secret "$SEC" --threshold 3 --shares 5 --json \
    > "$TMP/s_${size}.json"
  REC=$("$WALLET" shamir-combine --shares "$TMP/s_${size}.json")
  assert_eq "$REC" "$SEC" "round-trip ${size}B secret (T=3 N=5, all 5 shares)"
done

echo
echo "=== 3. Every 3-of-5 subset reconstructs original (T=3 N=5) ==="
SECRET="deadbeefcafebabe0011223344556677"
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
  > "$TMP/full.json"
# Enumerate C(5,3) = 10 subsets, write each to its own JSON file via Python.
$PY - "$TMP/full.json" "$TMP" <<'PY_EOF'
import json, sys
from itertools import combinations
full = json.load(open(sys.argv[1]))["shares"]
outdir = sys.argv[2]
for idx, subset in enumerate(combinations(range(len(full)), 3)):
    j = {"shares": [full[i] for i in subset]}
    with open(f"{outdir}/sub_{idx}.json", "w") as f:
        json.dump(j, f)
print(idx + 1)
PY_EOF
for idx in 0 1 2 3 4 5 6 7 8 9; do
  R=$("$WALLET" shamir-combine --shares "$TMP/sub_${idx}.json")
  assert_eq "$R" "$SECRET" "3-of-5 subset #$idx reconstructs original"
done

echo
echo "=== 4. T-1 insufficiency (2 shares for T=3 → != original) ==="
$PY - "$TMP/full.json" "$TMP" <<'PY_EOF'
import json, sys
full = json.load(open(sys.argv[1]))["shares"]
j = {"shares": full[:2]}
with open(f"{sys.argv[2]}/t_minus_1.json", "w") as f:
    json.dump(j, f)
PY_EOF
# combine() may succeed with garbage or signal mismatch — both acceptable.
R_LOW=$("$WALLET" shamir-combine --shares "$TMP/t_minus_1.json" 2>/dev/null || echo "rejected")
assert_neq "$R_LOW" "$SECRET" "2 shares != original (information-theoretic)"

echo
echo "=== 5. Validation rejections ==="
# 5a. threshold = 0
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret deadbeef --threshold 0 --shares 3" \
  "rejects --threshold 0"
# 5b. threshold > shares
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret deadbeef --threshold 5 --shares 3" \
  "rejects --threshold > --shares"
# 5c. shares > 255
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret deadbeef --threshold 1 --shares 256" \
  "rejects --shares > 255"
# 5d. non-hex secret
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret deadbeezz --threshold 2 --shares 3" \
  "rejects non-hex --secret"
# 5e. odd-length hex
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret deadbee --threshold 2 --shares 3" \
  "rejects odd-length-hex --secret"
# 5f. empty secret
assert_nonzero_exit \
  "'$WALLET' shamir-split --secret '' --threshold 2 --shares 3" \
  "rejects empty --secret"
# 5g. duplicate-x shares in combine input
cat > "$TMP/dup_x.json" <<'EOF'
{"shares":[{"x":1,"y_hex":"aa"},{"x":1,"y_hex":"bb"},{"x":2,"y_hex":"cc"}]}
EOF
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/dup_x.json'" \
  "rejects duplicate x in combine input"
# 5h. length-mismatched y values
cat > "$TMP/len_mismatch.json" <<'EOF'
{"shares":[{"x":1,"y_hex":"aabb"},{"x":2,"y_hex":"cc"},{"x":3,"y_hex":"ddee"}]}
EOF
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/len_mismatch.json'" \
  "rejects length-mismatched y values"
# 5i. missing 'x' field
cat > "$TMP/no_x.json" <<'EOF'
{"shares":[{"y_hex":"aa"},{"x":2,"y_hex":"bb"}]}
EOF
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/no_x.json'" \
  "rejects share missing 'x'"
# 5j. missing 'y_hex' field
cat > "$TMP/no_y.json" <<'EOF'
{"shares":[{"x":1},{"x":2,"y_hex":"bb"}]}
EOF
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/no_y.json'" \
  "rejects share missing 'y_hex'"
# 5k. shares file missing entirely
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/does_not_exist.json'" \
  "rejects missing --shares file"
# 5l. empty shares array
echo '{"shares":[]}' > "$TMP/empty.json"
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/empty.json'" \
  "rejects empty shares array"
# 5m. x out of range
cat > "$TMP/x_zero.json" <<'EOF'
{"shares":[{"x":0,"y_hex":"aa"},{"x":1,"y_hex":"bb"}]}
EOF
assert_nonzero_exit \
  "'$WALLET' shamir-combine --shares '$TMP/x_zero.json'" \
  "rejects x = 0"

echo
echo "=== 6. JSON output parseable by Python ==="
$PY - "$TMP/full.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert "shares" in d and isinstance(d["shares"], list) and len(d["shares"]) == 5
for s in d["shares"]:
    assert isinstance(s["x"], int)
    assert isinstance(s["y_hex"], str)
PY_EOF
if [ $? = 0 ]; then
  echo "  PASS: shamir-split --json output parseable + well-formed"
  pass_count=$((pass_count + 1))
else
  echo "  FAIL: shamir-split --json output malformed"
  fail_count=$((fail_count + 1))
fi
COMB_JSON=$("$WALLET" shamir-combine --shares "$TMP/full.json" --json)
echo "$COMB_JSON" | $PY -c 'import json,sys; d=json.loads(sys.stdin.read()); assert d["secret_hex"]'
if [ $? = 0 ]; then
  echo "  PASS: shamir-combine --json output parseable"
  pass_count=$((pass_count + 1))
else
  echo "  FAIL: shamir-combine --json output malformed"
  fail_count=$((fail_count + 1))
fi
# Verify --json secret_hex matches non-JSON output.
PARSED_HEX=$(echo "$COMB_JSON" | $PY -c 'import json,sys; print(json.loads(sys.stdin.read())["secret_hex"])')
assert_eq "$PARSED_HEX" "$SECRET" "--json secret_hex matches original"

echo
echo "=== 7. Determinism: distinct splits produce distinct shares, "
echo "                  but each set reconstructs the original ==="
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
  > "$TMP/a.json"
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
  > "$TMP/b.json"
SET_A=$(cat "$TMP/a.json")
SET_B=$(cat "$TMP/b.json")
assert_neq "$SET_A" "$SET_B" "two splits of same secret produce DIFFERENT share sets"
REC_A=$("$WALLET" shamir-combine --shares "$TMP/a.json")
REC_B=$("$WALLET" shamir-combine --shares "$TMP/b.json")
assert_eq "$REC_A" "$SECRET" "set A reconstructs original"
assert_eq "$REC_B" "$SECRET" "set B reconstructs original"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet shamir-split + shamir-combine raw CLIs"
  exit 0
else
  echo "  FAIL: test_wallet_shamir_cli"
  exit 1
fi
