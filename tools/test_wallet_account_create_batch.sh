#!/usr/bin/env bash
# determ-wallet account-create-batch operator-workflow CLI test.
#
# Verifies the batch keypair-generator that produces N fresh anonymous
# account keypairs in one invocation. Operator use cases:
#   * Cold-storage provisioning (mint a batch of receive addresses).
#   * Faucet bootstrapping (pre-mint addresses to fund + hand out).
#   * Test-fixture generation (build a corpus of accounts).
#
# Each entry: Ed25519 keypair via OpenSSL EVP -> anon-address ("0x" +
# lowercase hex(pubkey)).
#
# Assertions:
#   1. Help line mentions account-create-batch.
#   2. N=1 (smallest batch) prints exactly one Account block (human mode).
#   3. N=5 prints exactly five Account blocks.
#   4. N=100 (larger batch) writes valid JSON with --out (no daemon needed).
#   5. --json (no --out) writes JSON to stdout, parseable + has accounts[] of length N.
#   6. --out <file> writes JSON; stdout shows only "wrote N accounts to <file>".
#   7. Reproducibility: two back-to-back invocations produce DIFFERENT keypairs
#      (fresh CSPRNG draw per call — invariant of EVP_PKEY_keygen + OS RNG).
#   8. Every emitted address is a valid anon-address: 66 chars, "0x" prefix,
#      64 lowercase hex digits.
#   9. Every privkey_hex is exactly 64 lowercase hex chars.
#  10. --count 0 fails (rc=1).
#  11. --count -1 fails (rc=1).
#  12. --count > 10000 fails (rc=1) with diagnostic mentioning the cap.
#  13. --count missing fails (rc=1).
#  14. --out with missing parent directory fails (rc=1).
#  15. --out with existing file refused (rc=1); --force overrides.
#  16. --out + --json: --out wins (file written; stdout is the "wrote N..." line,
#      NOT the JSON document).
#  17. Within a single batch every address is unique (collision probability
#      is cryptographically negligible — this regresses an RNG that
#      accidentally produces correlated draws).
#  18. Within a single batch every privkey_hex is unique (same reasoning).
#
# Run from repo root: bash tools/test_wallet_account_create_batch.sh
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions account-create-batch ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-create-batch"; then
  echo "  PASS: help mentions account-create-batch"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing account-create-batch"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. N=1 (smallest batch) — exactly one Account block ==="
OUT=$("$WALLET" account-create-batch --count 1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on N=1"
n_blocks=$(echo "$OUT" | grep -c "^Account ")
assert_eq "$n_blocks" "1" "N=1 emits exactly 1 'Account' line"
assert_contains "$OUT" "Account 1:"   "labels start at Account 1"
assert_contains "$OUT" "address:"     "human mode shows address: label"
assert_contains "$OUT" "privkey_hex:" "human mode shows privkey_hex: label"

echo
echo "=== 3. N=5 (medium batch) — exactly five Account blocks ==="
OUT=$("$WALLET" account-create-batch --count 5 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on N=5"
n_blocks=$(echo "$OUT" | grep -c "^Account ")
assert_eq "$n_blocks" "5" "N=5 emits exactly 5 'Account' lines"
assert_contains "$OUT" "Account 1:" "first block labeled Account 1"
assert_contains "$OUT" "Account 5:" "last block labeled Account 5"

echo
echo "=== 4. N=100 (larger batch) — written via --out, valid JSON ==="
"$WALLET" account-create-batch --count 100 --out "$TMP/batch100.json" > "$TMP/stdout100.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on N=100 with --out"
STDOUT=$(cat "$TMP/stdout100.txt" | tr -d '\r')
assert_contains "$STDOUT" "wrote 100 accounts to" "stdout reports 100 accounts written"
if [ -s "$TMP/batch100.json" ]; then
    echo "  PASS: --out file is non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file is empty"; fail_count=$((fail_count + 1))
fi
# JSON parseable + array length matches.
LEN=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d['accounts']))" "$TMP/batch100.json")
assert_eq "$LEN" "100" "JSON file has accounts[] of length 100"

echo
echo "=== 5. --json (no --out) — JSON to stdout, parseable, length N ==="
JSON=$("$WALLET" account-create-batch --count 7 --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on --json stdout"
LEN=$(echo "$JSON" | $PY -c "import json,sys; d=json.load(sys.stdin); print(len(d['accounts']))")
assert_eq "$LEN" "7" "--json stdout has accounts[] of length 7"

echo
echo "=== 6. --out alone: stdout is confirmation line only, NOT JSON ==="
"$WALLET" account-create-batch --count 3 --out "$TMP/three.json" > "$TMP/three_stdout.txt" 2>&1
STDOUT=$(cat "$TMP/three_stdout.txt" | tr -d '\r')
assert_contains "$STDOUT" "wrote 3 accounts to" "--out stdout has confirmation"
assert_not_contains "$STDOUT" '"accounts"' "--out stdout does NOT contain JSON document"
assert_not_contains "$STDOUT" "privkey_hex" "--out stdout does NOT leak privkeys to terminal"

echo
echo "=== 7. Fresh-randomness invariant — two calls produce DIFFERENT keypairs ==="
"$WALLET" account-create-batch --count 5 --out "$TMP/run_a.json" >/dev/null 2>&1
"$WALLET" account-create-batch --count 5 --out "$TMP/run_b.json" >/dev/null 2>&1
DIFFER=$($PY - "$TMP/run_a.json" "$TMP/run_b.json" <<'PY_EOF'
import json, sys
a = json.load(open(sys.argv[1]))["accounts"]
b = json.load(open(sys.argv[2]))["accounts"]
# Every address in run B must differ from EVERY address in run A.
a_addrs = {x["address"] for x in a}
b_addrs = {x["address"] for x in b}
if a_addrs & b_addrs:
    print("OVERLAP")
else:
    print("DISJOINT")
PY_EOF
)
assert_eq "$DIFFER" "DISJOINT" "back-to-back batches produce disjoint addresses (RNG is fresh)"

echo
echo "=== 8. Every emitted address is a valid anon-address ==="
# Pull addresses from the 100-batch and validate the shape: 66 chars,
# "0x" prefix, 64 lowercase hex digits.
$PY - "$TMP/batch100.json" <<'PY_EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
shape = re.compile(r"^0x[0-9a-f]{64}$")
bad = [a["address"] for a in d["accounts"] if not shape.match(a["address"])]
if bad:
    print("BAD")
    for b in bad[:3]:
        print(" ", b)
    sys.exit(1)
print("ALL_OK")
PY_EOF
RC=$?
assert_eq "$RC" "0" "every address matches 0x + 64-lowercase-hex (anon-address shape)"

echo
echo "=== 9. Every privkey_hex is 64 lowercase hex chars ==="
$PY - "$TMP/batch100.json" <<'PY_EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
shape = re.compile(r"^[0-9a-f]{64}$")
bad = [a["privkey_hex"] for a in d["accounts"] if not shape.match(a["privkey_hex"])]
if bad:
    print("BAD")
    sys.exit(1)
print("ALL_OK")
PY_EOF
RC=$?
assert_eq "$RC" "0" "every privkey_hex is 64 lowercase hex chars"

echo
echo "=== 10. --count 0 fails ==="
set +e
"$WALLET" account-create-batch --count 0 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --count 0"

echo
echo "=== 11. --count -1 fails ==="
set +e
"$WALLET" account-create-batch --count -1 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --count -1"

echo
echo "=== 12. --count 10001 fails (cap is 10000) ==="
set +e
ERR=$("$WALLET" account-create-batch --count 10001 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --count > 10000"
assert_contains "$ERR" "10000" "diagnostic mentions the 10000 cap"

echo
echo "=== 13. --count missing fails ==="
set +e
"$WALLET" account-create-batch >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --count"

echo
echo "=== 14. --out with missing parent directory fails ==="
set +e
ERR=$("$WALLET" account-create-batch --count 1 --out "$TMP/no_such_dir/file.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out with missing parent dir"
assert_contains "$ERR" "parent directory" "diagnostic mentions parent directory"

echo
echo "=== 15. --out with existing file refused; --force overrides ==="
# File already exists from earlier tests: $TMP/batch100.json
set +e
ERR=$("$WALLET" account-create-batch --count 1 --out "$TMP/batch100.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out with existing file (no --force)"
assert_contains "$ERR" "already exists" "diagnostic mentions file exists"
assert_contains "$ERR" "--force"        "diagnostic suggests --force"

# Now overwrite with --force; should succeed and shrink the file.
"$WALLET" account-create-batch --count 1 --out "$TMP/batch100.json" --force > "$TMP/force_stdout.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 with --force overrides existing file"
LEN=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))['accounts']))" "$TMP/batch100.json")
assert_eq "$LEN" "1" "after --force overwrite file has accounts[] of length 1 (not the old 100)"

echo
echo "=== 16. --out + --json: --out wins, no JSON document on stdout ==="
"$WALLET" account-create-batch --count 2 --out "$TMP/both.json" --json > "$TMP/both_stdout.txt" 2>&1
RC=$?
STDOUT=$(cat "$TMP/both_stdout.txt" | tr -d '\r')
assert_eq "$RC" "0" "exit 0 on --out + --json"
assert_contains "$STDOUT" "wrote 2 accounts to" "stdout has 'wrote ...' line (--out path won)"
assert_not_contains "$STDOUT" '"accounts"' "stdout does NOT contain JSON document (--out won)"
# File exists and is valid JSON.
LEN=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))['accounts']))" "$TMP/both.json")
assert_eq "$LEN" "2" "the --out file has accounts[] of length 2"

echo
echo "=== 17. Within a single batch every address is unique ==="
# Note: $TMP/batch100.json was overwritten in step 15 to N=1; generate a
# fresh 100-batch here to keep the uniqueness assertion meaningful.
"$WALLET" account-create-batch --count 100 --out "$TMP/uniq_check.json" >/dev/null 2>&1
$PY - "$TMP/uniq_check.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
addrs = [a["address"] for a in d["accounts"]]
if len(set(addrs)) != len(addrs):
    print("DUP")
    sys.exit(1)
print("UNIQUE")
PY_EOF
RC=$?
assert_eq "$RC" "0" "100-batch has all unique addresses"

echo
echo "=== 18. Within a single batch every privkey_hex is unique ==="
$PY - "$TMP/uniq_check.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
keys = [a["privkey_hex"] for a in d["accounts"]]
if len(set(keys)) != len(keys):
    print("DUP")
    sys.exit(1)
print("UNIQUE")
PY_EOF
RC=$?
assert_eq "$RC" "0" "100-batch has all unique privkey_hex values"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-create-batch"; exit 0
else
    echo "  FAIL"; exit 1
fi
